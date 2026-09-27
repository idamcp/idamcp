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
from ida_mcp.core import interrupt
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


def _make_interruptible(token) -> interrupt.InterruptibleCall | None:
  """Returns a tracker for asynchronous interruption, or None if not used.

  Used when the call has a cancellation token, the `async_interrupt` option is
  on (default), and CPython exposes PyThreadState_SetAsyncExc. Otherwise only
  the `sys.setprofile` canceller applies, as before.
  """
  if token is None:
    return None
  try:
    # pylint: disable-next=g-import-not-at-top
    from shared.config import load_config

    if not load_config().get("async_interrupt", True):
      return None
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.error("Could not read async_interrupt option: %s", e)
  if not interrupt.is_available():
    return None
  return interrupt.InterruptibleCall()


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
    interruptible = _make_interruptible(self.token)
    try:
      with cancellation_profile(self.token):
        # The injection window is limited to the tool body. exit() clears an
        # undelivered interrupt before the profile hook is restored.
        unregister = None
        try:
          if interruptible is not None:
            interruptible.enter()
            unregister = self.token.register_callback(interruptible.request)
          self.result = self.ff()
          self.success = True
        finally:
          if unregister is not None:
            unregister()
          if interruptible is not None:
            interruptible.exit()
    except interrupt.ToolInterrupt:
      self.success = False
      self.result = interrupt.ToolInterrupt("Tool cancelled")
    except BaseException as e:
      self.success = False
      self.result = e
    finally:
      if self.safety_mode == IDASafety.SAFE_WRITE:
        _flush_after_write()
      idc.batch(old_batch)

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
