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

from ida_mcp.core import change_log  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.core.security import security_manager  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.server import mcp_server_thread  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.server import stop_server  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.tools.info import clear_caches  # pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.tools.query import close_tables  # pylint: disable=g-import-not-at-top,g-bad-import-order
from shared.config import load_config  # pylint: disable=g-import-not-at-top,g-bad-import-order


class MCP(idaapi.plugin_t):
  """IDA Plugin class for MCP Server."""

  flags = idaapi.PLUGIN_KEEP
  comment = "MCP Plugin"
  help = "MCP"
  wanted_name = "MCP"
  wanted_hotkey = "Ctrl-Alt-M"

  def init(self):
    hotkey = MCP.wanted_hotkey.replace("-", "+")
    if sys.platform == "darwin":
      hotkey = hotkey.replace("Alt", "Option")
    print(
        f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start"
        " the server"
    )
    self._server_started = False
    self.server_thread = None
    self.hash_str = None
    return idaapi.PLUGIN_KEEP

  def run(self, arg):
    del arg
    if self._server_started:
      print("[Info] The MCP server has already started.")
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
    idaapi.is_headless = not idaapi.is_idaq()  # type: ignore
    hash_str = hashlib.sha256(
        idaapi.get_path(idaapi.PATH_TYPE_IDB).encode()
    ).hexdigest()[-8:]
    idaapi.idb_path = idc.get_idb_path()  # type: ignore
    self.hash_str = hash_str
    self.server_thread = threading.Thread(
        target=mcp_server_thread,
        args=(hash_str,),
        daemon=True,
    )

    self._server_started = True
    self.server_thread.start()

  def term(self):
    if not self._server_started:
      return

    # 1. Stop the MCP server and join the server thread
    if getattr(self, "hash_str", None):
      try:
        stop_server(self.hash_str)
      except Exception as e:
        print(f"[MCP] Error stopping server: {e}")

    if getattr(self, "server_thread", None) is not None:
      self.server_thread.join(timeout=5.0)
      self.server_thread = None

    # 2. Cleanup backend database and worker hooks
    try:
      close_tables()
    except Exception as e:
      print(f"[MCP] Error closing query tables: {e}")
    try:
      change_log.stop()
    except Exception as e:
      print(f"[MCP] Error stopping the change log: {e}")

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

    # 5. Reset security settings
    try:
      security_manager.reset()
    except Exception:
      pass

    # 6. Clear IDB metadata references
    if hasattr(idaapi, "idb_path"):
      try:
        delattr(idaapi, "idb_path")
      except Exception:
        idaapi.idb_path = None

    self.hash_str = None
    self._server_started = False


def PLUGIN_ENTRY():  # pylint: disable=invalid-name
  return MCP()
