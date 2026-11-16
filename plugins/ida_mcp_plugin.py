# Copyright (c) 2026 Google LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""IDA MCP Plugin Entry Point."""

import hashlib
import os
import sys
import threading

import idaapi
import idc

# Ensure the project root is in sys.path
# This handles cases where the file is symlinked to the plugins folder
current_dir = os.path.dirname(os.path.realpath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
  sys.path.insert(0, project_root)

# pylint: disable-next=g-import-not-at-top,g-bad-import-order
from ida_mcp.core import analysis_state
from ida_mcp.core.security import security_manager  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.server import mcp_server_thread  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.server import stop_server  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.tools.execution import clear_persistent_globals  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.tools.info import clear_caches  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.tools.query import close_tables  # pylint: disable=g-import-not-at-top,g-bad-import-order
from shared.config import load_config  # pylint: disable=g-import-not-at-top,g-bad-import-order

_DEFAULT_HOTKEY = "Ctrl-Alt-M"
# How often a pending autostart checks whether auto-analysis has finished.
_AUTOSTART_POLL_MS = 1000
# How long the server waits at shutdown, in seconds, for cancelled tool calls
# to finish. Shorter than the headless server's wait (DEFAULT_SHUTDOWN_GRACE in
# shared/rpc.py): term() blocks IDA's main thread until the server stops, and a
# call waiting for that thread can't finish anyway. 0.5 s still leaves time for
# @jsonrpc's first re-interrupt, 0.25 s after the cancel.
_SHUTDOWN_GRACE = 0.5


def _is_headless() -> bool:
  """Returns True under idalib (headless), False in the GUI and in idat."""
  # Python hosts of idalib, ida_mcp.headless included, import idapro. IDA's
  # own checks can't tell idat from idalib: in both, is_idaq() returns False
  # and is_ida_library() returns True.
  return "idapro" in sys.modules


def _is_batch_mode() -> bool:
  """Returns True in batch mode: with -A or -B, in idat and under idalib."""
  # On IDA 9.4, cvar.batch is False in the GUI and True with -A, in idat with
  # or without -A, and under idalib. IDA_IS_INTERACTIVE can't tell: the GUI
  # sets it to "1" with -A too.
  return bool(getattr(getattr(idaapi, "cvar", None), "batch", False))


def _analysis_finished() -> bool:
  """Returns True once auto-analysis has finished, or if it is disabled."""
  # With analysis disabled (e.g. `ida -a`), the queues never drain and IDA
  # sends no event. inf_is_auto_enabled() is the user's setting; IDA flips
  # the runtime switch, is_auto_enabled(), on its own at times.
  return bool(idaapi.auto_is_ok()) or not idaapi.inf_is_auto_enabled()


def _configured_hotkey() -> str:
  """Returns the `hotkey` option; an empty string means no hotkey."""
  hotkey = load_config().get("hotkey", _DEFAULT_HOTKEY)
  if not isinstance(hotkey, str):
    print(f"[MCP] Invalid hotkey {hotkey!r}, using {_DEFAULT_HOTKEY}")
    return _DEFAULT_HOTKEY
  return hotkey.strip()


class _AutostartHooks(idaapi.UI_Hooks):
  """Starts the MCP server when IDA's UI is ready (`autostart` option)."""

  def __init__(self, plugin):
    super().__init__()
    self._plugin = plugin

  def ready_to_run(self):
    self._plugin.autostart()


class MCP(idaapi.plugin_t):
  """IDA Plugin class for MCP Server."""

  flags = idaapi.PLUGIN_KEEP
  comment = "MCP Plugin"
  help = "MCP"
  wanted_name = "MCP"
  wanted_hotkey = _DEFAULT_HOTKEY  # PLUGIN_ENTRY() applies the `hotkey` option

  def init(self):
    self._server_started = False
    self.server_thread = None
    self.hash_str = None
    self._autostart_hooks = None
    self._autostart_timer = None
    autostart = load_config().get("autostart") and not _is_headless()
    if autostart and _is_batch_mode():
      # A scripted run, e.g., `ida -A -S script.py`: don't open its database
      # to agents unasked. (In idat, which has no event loop, the autostart
      # timer would never fire anyway.)
      print("[MCP] autostart is skipped in batch mode")
    elif autostart:
      hooks = _AutostartHooks(self)
      if hooks.hook():
        self._autostart_hooks = hooks
        print("[MCP] Plugin loaded, the server starts automatically")
        return idaapi.PLUGIN_KEEP
      print("[MCP] autostart failed: could not hook the IDA UI")
    hotkey = MCP.wanted_hotkey.replace("-", "+")
    if sys.platform == "darwin":
      hotkey = hotkey.replace("Alt", "Option")
    shortcut = f" ({hotkey})" if hotkey else ""
    print(
        f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP{shortcut} to start"
        " the server"
    )
    return idaapi.PLUGIN_KEEP

  def autostart(self):
    """Starts the server from IDA's event loop once auto-analysis is done."""
    if self._autostart_timer is not None:
      return
    if not _analysis_finished():
      print("[MCP] The server starts once auto-analysis finishes")
    # Start from a timer even if analysis is done: timers fire only while
    # IDA's event loop runs, and the server needs that loop to serve tool
    # calls. Batch-mode idat (every idat since IDA 9.2) has no such loop.
    self._autostart_timer = idaapi.register_timer(
        _AUTOSTART_POLL_MS, self._autostart_tick
    )

  def _autostart_tick(self) -> int:
    """Starts the server unless auto-analysis is still running.

    Unlike run(), this neither blocks the UI with auto_wait() nor runs the
    analysis if it is disabled.

    Returns:
      The delay in ms before the next check, or -1 when there is nothing left
      to do (the callback protocol of register_timer).
    """
    if not self._server_started and not _analysis_finished():
      return _AUTOSTART_POLL_MS
    self._autostart_timer = None  # Returning -1 ends the timer.
    if not self._server_started:
      try:
        self._start_server()
      except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"[MCP] autostart failed: {e}")
    return -1

  def _stop_autostart(self):
    """Removes the autostart UI hooks and timer, if any."""
    if self._autostart_timer is not None:
      idaapi.unregister_timer(self._autostart_timer)
      self._autostart_timer = None
    if self._autostart_hooks is not None:
      self._autostart_hooks.unhook()
      self._autostart_hooks = None

  def run(self, arg):
    del arg
    if self._server_started:
      print("[Info] The MCP server has already started.")
      return
    if self._autostart_timer is not None and not _analysis_finished():
      print(
          "[MCP] Autostart is on the way: the server starts once auto-analysis"
          " finishes"
      )
      return
    if not idaapi.is_main_thread():
      print(
          "[Error] the plugin isn't running in the main thread, this should"
          " never happen"
      )
      return
    if not idaapi.auto_is_ok():
      print("[>] IDA is performing auto-analysis... please wait.")
      idaapi.auto_wait()
      print("[+] Analysis complete. Resuming script.")
    self._start_server()

  def _start_server(self):
    """Starts the MCP server thread for the open database."""
    # Tool calls reach the main thread through IDA's UI loop in the GUI and
    # idat, but through ida_mcp.headless's own loop under idalib.
    idaapi.is_headless = _is_headless()  # type: ignore
    if not idaapi.auto_is_ok() and not idaapi.inf_is_auto_enabled():
      analysis_state.disable()
    else:
      analysis_state.reset()
    hash_str = hashlib.sha256(
        idaapi.get_path(idaapi.PATH_TYPE_IDB).encode()
    ).hexdigest()[-8:]
    idaapi.idb_path = idc.get_idb_path()  # type: ignore
    self.hash_str = hash_str
    self.server_thread = threading.Thread(
        target=mcp_server_thread,
        args=(hash_str,),
        kwargs={"shutdown_grace": _SHUTDOWN_GRACE},
        daemon=True,
    )

    self.server_thread.start()
    self._server_started = True

  def term(self):
    self._stop_autostart()
    if not self._server_started:
      return

    # 1. Stop the MCP server and join the server thread
    if self.hash_str:
      try:
        stop_server(self.hash_str)
      except Exception as e:
        print(f"[MCP] Error stopping server: {e}")

    if self.server_thread is not None:
      self.server_thread.join(timeout=5.0)
      self.server_thread = None

    # Clear the shared idapython_eval namespace while the database is still
    # open; it may hold SWIG-wrapped IDA objects.
    try:
      clear_persistent_globals()
    except Exception as e:
      print(f"[MCP] Error clearing idapython_eval globals: {e}")

    # 2. Cleanup backend database and worker hooks
    try:
      close_tables()
    except Exception as e:
      print(f"[MCP] Error closing query tables: {e}")

    # 3. Clear iterator pagination caches
    try:
      clear_caches()
    except Exception as e:
      print(f"[MCP] Error clearing caches: {e}")

    # 4. Clear config cache
    try:
      load_config.cache_clear()
    except Exception:
      pass

    # 5. Reset security and analysis state
    try:
      security_manager.reset()
    except Exception:
      pass
    try:
      analysis_state.reset()
    except Exception:
      pass

    # 6. Clear IDB metadata references
    if hasattr(idaapi, "idb_path"):
      try:
        delattr(idaapi, "idb_path")
      except Exception:
        idaapi.idb_path = None  # type: ignore

    self.hash_str = None
    self._server_started = False


def PLUGIN_ENTRY():  # pylint: disable=invalid-name
  # IDA takes wanted_hotkey from the plugin object returned here. Read the
  # config file again, as it may have changed since the last load.
  load_config.cache_clear()
  MCP.wanted_hotkey = _configured_hotkey()
  return MCP()
