# Copyright (c) 2026 Google LLC
# Copyright (c) 2025 Duncan Ogilvie
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

"""Module for synchronizing with the IDA main thread."""

import asyncio
import enum
import functools
import logging
from typing import Any, Callable

import ida_kernwin
from ida_mcp.core import ida_thread
from ida_mcp.core.decorators import cancellation_profile
from ida_mcp.core.decorators import get_cancellation_token
import idaapi
import idc


class IDASyncError(Exception):
  pass


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# Set to False after the first failed or impossible flush, so the problem is
# logged once instead of on every write.
_flush_available = True


def _flush_after_write() -> None:
  """Flushes IDA's database buffers to disk if `flush_after_write` is set.

  Runs on IDA's main thread after a top-level @idawrite call. The API is probed
  lazily; a missing API or an error is logged once and then ignored, so a flush
  problem never fails the tool call.
  """
  global _flush_available
  if not _flush_available:
    return
  try:
    # pylint: disable=g-import-not-at-top
    from shared.config import load_config

    if not load_config().get("flush_after_write"):
      return
    import ida_loader

    flush_buffers = getattr(ida_loader, "flush_buffers", None)
    if flush_buffers is None:
      _flush_available = False
      logger.error(
          "flush_after_write is set but ida_loader.flush_buffers is not"
          " available in this IDA version; not flushing."
      )
      return
    flush_buffers()
  except Exception as e:  # pylint: disable=broad-exception-caught
    _flush_available = False
    logger.error("flush_after_write: flush_buffers failed, disabling: %r", e)


class IDASafety(enum.IntEnum):
  SAFE_NONE = ida_kernwin.MFF_FAST
  SAFE_READ = ida_kernwin.MFF_READ
  SAFE_WRITE = ida_kernwin.MFF_WRITE


# Delay used to coalesce bursts of write calls into a single view refresh.
_VIEW_REFRESH_DELAY_MS = 200
_view_refresh_disabled = False
_view_refresh_pending = False


def _refresh_pseudocode_views() -> int:
  """Re-decompiles every open Pseudocode-<X> view. Returns the view count.

  Disassembly and list views pick up database changes on their own, but an
  open pseudocode view keeps showing its cached ctree (e.g. old callee names or
  prototypes) until it is refreshed.
  """
  # pylint: disable-next=g-import-not-at-top
  import ida_hexrays

  if not ida_hexrays.init_hexrays_plugin():
    return 0
  refreshed = 0
  for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
    widget = ida_kernwin.find_widget(f"Pseudocode-{letter}")
    if not widget:
      continue
    vdui = ida_hexrays.get_widget_vdui(widget)
    if vdui:
      vdui.refresh_view(True)
      refreshed += 1
  return refreshed


def _run_view_refresh() -> int:
  """Timer callback: performs the pending refresh. Never raises."""
  global _view_refresh_pending, _view_refresh_disabled
  _view_refresh_pending = False
  try:
    _refresh_pseudocode_views()
  except Exception as e:  # pylint: disable=broad-exception-caught
    _view_refresh_disabled = True
    logger.error("Disabling MCP view refresh: %s", e)
  return -1  # One-shot timer.


def _schedule_view_refresh() -> None:
  """Schedules a refresh of open pseudocode views (GUI only, best effort).

  Called after each tool call that may modify the database. Calls arriving
  within `_VIEW_REFRESH_DELAY_MS` share one refresh. Skipped in headless mode
  and when the `gui_refresh_views` option is off. On any error, logs once and
  stops trying for the rest of the session. Never raises.
  """
  global _view_refresh_pending, _view_refresh_disabled
  if (
      _view_refresh_disabled
      or _view_refresh_pending
      or getattr(idaapi, "is_headless", False)
  ):
    return
  try:
    # pylint: disable-next=g-import-not-at-top
    from shared.config import load_config

    if not load_config().get("gui_refresh_views", True):
      return
    register_timer = getattr(ida_kernwin, "register_timer", None)
    if register_timer is None:
      _run_view_refresh()
      return
    _view_refresh_pending = True
    if not register_timer(_VIEW_REFRESH_DELAY_MS, _run_view_refresh):
      _view_refresh_pending = False
      _run_view_refresh()
  except Exception as e:  # pylint: disable=broad-exception-caught
    _view_refresh_pending = False
    _view_refresh_disabled = True
    logger.error("Disabling MCP view refresh: %s", e)


class _IDACall:
  """Helper to execute a callable on IDA's main thread with safety and cancellation checks."""

  def __init__(self, ff: Callable[[], Any], safety_mode: IDASafety):
    if safety_mode not in (IDASafety.SAFE_READ, IDASafety.SAFE_WRITE):
      error_str = "Invalid safety mode {} over function {}".format(
          safety_mode, ff.__name__
      )
      logger.error(error_str)
      raise IDASyncError(error_str)

    token = get_cancellation_token()
    if token is not None and token.is_cancelled:
      raise asyncio.CancelledError("Tool cancelled before execution")

    self.ff = ff
    self.safety_mode = safety_mode
    self.token = token
    self.success = False
    self.result: Any = IDASyncError(
        f"execute_sync silently failed to execute {ff.__name__}"
    )

  def _runned(self) -> None:
    # pylint: disable=broad-exception-caught
    if self.token is not None and self.token.is_cancelled:
      self.success = False
      self.result = asyncio.CancelledError("Tool cancelled before execution")
      return

    old_batch = idc.batch(1)
    try:
      with cancellation_profile(self.token):
        self.result = self.ff()
        self.success = True
    except BaseException as e:
      self.success = False
      self.result = e
    finally:
      if self.safety_mode == IDASafety.SAFE_WRITE:
        _flush_after_write()
      idc.batch(old_batch)
      # Also after failures: a write tool may have applied part of its changes.
      if self.safety_mode == IDASafety.SAFE_WRITE:
        _schedule_view_refresh()

  def run_in_main(self) -> Any:
    old_batch = idc.batch(1)
    try:
      return self.ff()
    finally:
      idc.batch(old_batch)

  def get_result(self) -> Any:
    if not self.success:
      raise self.result
    return self.result

  def execute_sync(self) -> Any:
    if idaapi.is_main_thread():
      return self.run_in_main()

    if getattr(idaapi, "is_headless", False):
      # Headless mode
      ida_thread.execute_sync(self._runned, self.safety_mode)
    else:
      idaapi.execute_sync(self._runned, self.safety_mode)

    return self.get_result()

  async def execute_async(self) -> Any:
    if idaapi.is_main_thread():
      return self.run_in_main()

    if getattr(idaapi, "is_headless", False):
      await ida_thread.execute_async(self._runned, self.safety_mode)
    else:
      await asyncio.to_thread(
          idaapi.execute_sync, self._runned, self.safety_mode
      )

    return self.get_result()


def sync_wrapper(ff: Callable[[], Any], safety_mode: IDASafety) -> Any:
  """Call a function ff with a specific IDA safety_mode synchronously."""
  return _IDACall(ff, safety_mode).execute_sync()


async def async_wrapper(ff: Callable[[], Any], safety_mode: IDASafety) -> Any:
  """Call a function ff with a specific IDA safety_mode asynchronously."""
  return await _IDACall(ff, safety_mode).execute_async()


def _idasync(f: Callable[..., Any], mode: IDASafety) -> Callable[..., Any]:
  """Wraps a callable to execute inside the IDA main thread."""

  @functools.wraps(f)
  def wrapper(*args, **kwargs) -> Any:
    ff = functools.partial(f, *args, **kwargs)
    ff.__name__ = f.__name__  # type: ignore
    try:
      loop = asyncio.get_running_loop()
    except RuntimeError:
      loop = None

    if loop is not None and loop.is_running():
      return async_wrapper(ff, mode)
    return sync_wrapper(ff, mode)

  @functools.wraps(f)
  def sync_call(*args, **kwargs) -> Any:
    ff = functools.partial(f, *args, **kwargs)
    ff.__name__ = f.__name__  # type: ignore
    return sync_wrapper(ff, mode)

  # Python 3.14 compatibility: manually copy annotations and signature
  wrapper.__annotations__ = getattr(f, "__annotations__", {})
  sync_call.__annotations__ = wrapper.__annotations__
  if hasattr(f, "__signature__"):
    wrapper.__signature__ = f.__signature__  # type: ignore
    sync_call.__signature__ = f.__signature__  # type: ignore

  wrapper.is_ida_tool = True  # type: ignore
  wrapper.sync_call = sync_call  # type: ignore
  return wrapper


def idawrite(f: Callable[..., Any]) -> Callable[..., Any]:
  """decorator for marking a function as modifying the IDB."""
  return _idasync(f, IDASafety.SAFE_WRITE)


def idaread(f: Callable[..., Any]) -> Callable[..., Any]:
  """decorator for marking a function as reading from the IDB."""
  return _idasync(f, IDASafety.SAFE_READ)
