# Copyright (c) 2026 Google LLC
# Copyright (c) 2025 Duncan Ogilvie
# Copyright (c) 2026 Hex-Rays SA
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
import contextlib
import enum
import functools
import inspect
import logging
import math
from typing import Any, Callable

import ida_auto
import ida_kernwin
from ida_mcp.core import change_log
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


_undo_points_disabled = False


def _create_undo_point(tool_name: str) -> None:
  """Creates an IDA undo point labeled after the tool (GUI only, best effort).

  Lets the user revert a single agent tool call with Ctrl-Z / Edit -> Undo.
  Skipped in headless mode and when the `gui_undo_points` option is off. If the
  API is missing or has an unexpected signature (it is
  `create_undo_point(action_name, label)` on IDA 9.x), logs once and stops
  trying for the rest of the session. Never raises.

  Args:
    tool_name: Name of the tool about to run; used in the undo label.
  """
  global _undo_points_disabled
  if _undo_points_disabled or getattr(idaapi, "is_headless", False):
    return
  try:
    # pylint: disable-next=g-import-not-at-top
    from shared.config import load_config

    if not load_config().get("gui_undo_points", False):
      return
    # pylint: disable-next=g-import-not-at-top
    import ida_undo

    ida_undo.create_undo_point(f"idamcp:{tool_name}", f"MCP: {tool_name}")
  except Exception as e:  # pylint: disable=broad-exception-caught
    _undo_points_disabled = True
    logger.error("Disabling MCP undo points: %s", e)


class _IDACall:
  """Helper to execute a callable on IDA's main thread with safety and cancellation checks."""

  def __init__(
      self,
      ff: Callable[[], Any],
      safety_mode: IDASafety,
      timeout: float | None = None,
  ):
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
    self.timeout = timeout
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

    if self.safety_mode == IDASafety.SAFE_WRITE:
      _create_undo_point(getattr(self.ff, "__name__", "tool"))

    old_ida_state = None
    if not getattr(idaapi, "is_headless", False):
      with contextlib.suppress(Exception):
        # IDA 9.4 GUI database saves while autoanalysis is disabled can leave
        # IDA's kernel status at st_Work, blocking subsequent MFF_WRITE calls.
        # Adapted from ida-nexus: IDARuntime._run_sync in
        # ida_nexus/_runtime.py.
        old_ida_state = ida_auto.set_ida_state(ida_auto.st_Work)

    old_batch = idc.batch(1)
    ida_kernwin.clr_cancelled()
    try:
      # The time limit starts now, so time spent waiting for IDA's main thread
      # does not count.
      with cancellation_profile(
          self.token, native_ida_cancel=True, timeout=self.timeout
      ), change_log.attribute(
          getattr(self.ff, "__name__", "unknown")
      ):
        self.result = self.ff()
        self.success = True
    except BaseException as e:
      self.success = False
      self.result = e
    finally:
      ida_kernwin.clr_cancelled()
      if self.safety_mode == IDASafety.SAFE_WRITE:
        _flush_after_write()
      idc.batch(old_batch)
      if old_ida_state is not None:
        with contextlib.suppress(Exception):
          ida_auto.set_ida_state(old_ida_state)

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


def sync_wrapper(
    ff: Callable[[], Any],
    safety_mode: IDASafety,
    timeout: float | None = None,
) -> Any:
  """Call a function ff with a specific IDA safety_mode synchronously.

  Args:
    ff: The function to call on IDA's main thread.
    safety_mode: How ff accesses the database.
    timeout: Seconds ff may run on IDA's main thread before it is interrupted
      with ToolTimeoutError, or None for no limit.
  """
  return _IDACall(ff, safety_mode, timeout).execute_sync()


async def async_wrapper(
    ff: Callable[[], Any],
    safety_mode: IDASafety,
    timeout: float | None = None,
) -> Any:
  """Call a function ff with a specific IDA safety_mode asynchronously.

  Args:
    ff: The function to call on IDA's main thread.
    safety_mode: How ff accesses the database.
    timeout: Seconds ff may run on IDA's main thread before it is interrupted
      with ToolTimeoutError, or None for no limit.
  """
  return await _IDACall(ff, safety_mode, timeout).execute_async()


# The parameter through which an @idaread/@idawrite function takes its time
# limit.
_TIMEOUT_PARAMETER = "timeout"


def _validate_timeout(value: Any) -> float | None:
  """Returns a `timeout` argument as seconds, or None for no limit.

  Args:
    value: The argument.

  Raises:
    ValueError: If the argument is neither None nor a positive, finite number.
  """
  if value is None:
    return None
  if (
      isinstance(value, bool)
      or not isinstance(value, (int, float))
      or not math.isfinite(value)
      or value <= 0
  ):
    raise ValueError(
        f"timeout must be a positive, finite number of seconds, got {value!r}"
    )
  return float(value)


def _idasync(f: Callable[..., Any], mode: IDASafety) -> Callable[..., Any]:
  """Wraps a callable to execute inside the IDA main thread.

  If `f` has a `timeout` parameter, its argument, or else its default, limits
  how long a call may run: once it has run that many seconds on IDA's main
  thread, it is interrupted and raises ToolTimeoutError, which the client gets
  as a tool error. Time spent waiting for the main thread does not count, and
  None means no limit. A call made on the main thread itself, e.g., by another
  tool, runs inline under the caller's limit.

  Args:
    f: The function to wrap.
    mode: How `f` accesses the database.

  Returns:
    The wrapper, which returns a coroutine when called with an event loop
    running, and the result otherwise. Its `sync_call` always returns the
    result.
  """
  signature = inspect.signature(f)
  timeout_parameter = signature.parameters.get(_TIMEOUT_PARAMETER)
  has_timeout = timeout_parameter is not None and timeout_parameter.kind not in (
      inspect.Parameter.VAR_POSITIONAL,
      inspect.Parameter.VAR_KEYWORD,
  )

  def bind(args, kwargs) -> tuple[Callable[[], Any], float | None]:
    """Returns the call of `f` with the arguments, and its time limit."""
    timeout = None
    if has_timeout:
      # Binding finds the argument whether it is passed by position or by
      # keyword, or left to its default.
      bound = signature.bind(*args, **kwargs)
      bound.apply_defaults()
      timeout = _validate_timeout(bound.arguments[_TIMEOUT_PARAMETER])
    ff = functools.partial(f, *args, **kwargs)
    ff.__name__ = f.__name__  # type: ignore
    return ff, timeout

  @functools.wraps(f)
  def wrapper(*args, **kwargs) -> Any:
    ff, timeout = bind(args, kwargs)
    try:
      loop = asyncio.get_running_loop()
    except RuntimeError:
      loop = None

    if loop is not None and loop.is_running():
      return async_wrapper(ff, mode, timeout)
    return sync_wrapper(ff, mode, timeout)

  @functools.wraps(f)
  def sync_call(*args, **kwargs) -> Any:
    ff, timeout = bind(args, kwargs)
    return sync_wrapper(ff, mode, timeout)

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
