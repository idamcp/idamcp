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

"""Asynchronous interruption of tool code running on the IDA thread.

The `sys.setprofile` canceller only fires on Python call/return events, so a
loop that makes no calls (`while True: pass`) is never stopped, and a bare
`except:` in user code swallows the `CancelledError` it raises.

`PyThreadState_SetAsyncExc` makes CPython raise an exception in the target
thread at its next periodic check, which includes loop back-edges. Each tool
execution is tracked by an `InterruptibleCall` so an interrupt requested after
the tool finished can never hit whatever the thread runs next.
"""

import ast
import asyncio
import ctypes
import logging
import threading

logger = logging.getLogger(__name__)

# Name under which idapython_eval exposes ToolInterrupt to guarded user code.
INTERRUPT_GLOBAL = "__idamcp_interrupt__"


class ToolInterrupt(asyncio.CancelledError):
  """Raised inside a cancelled tool. A CancelledError, so callers see no change.

  A dedicated subclass lets `protect_handlers` re-raise it past user exception
  handlers without touching `CancelledError`s that user code handles itself.
  """


_set_async_exc = None
_unavailable = False


def _get_set_async_exc():
  """Returns PyThreadState_SetAsyncExc, or None if not available."""
  global _set_async_exc, _unavailable
  if _set_async_exc is None and not _unavailable:
    try:
      func = ctypes.pythonapi.PyThreadState_SetAsyncExc
      func.argtypes = (ctypes.c_ulong, ctypes.c_void_p)
      func.restype = ctypes.c_int
      _set_async_exc = func
    except (AttributeError, OSError) as e:
      _unavailable = True
      logger.error("Asynchronous tool interruption is unavailable: %s", e)
  return _set_async_exc


def is_available() -> bool:
  return _get_set_async_exc() is not None


def _inject(thread_id: int) -> bool:
  func = _get_set_async_exc()
  if func is None:
    return False
  count = func(thread_id, id(ToolInterrupt))
  if count > 1:
    # Impossible for a threading.get_ident() value; undo rather than guess.
    func(thread_id, None)
    return False
  return count == 1


def _clear(thread_id: int) -> None:
  func = _get_set_async_exc()
  if func is not None:
    func(thread_id, None)


class InterruptibleCall:
  """Tracks one tool execution so it can be interrupted from another thread.

  Usage on the executing thread:

    call.enter()
    try:
      ...  # may raise ToolInterrupt once request() is called
    finally:
      call.exit()

  `request()` may be called from any thread, any number of times. It injects at
  most once, and only between `enter()` and `exit()`. `exit()` clears an
  injection that has not been delivered yet, so it cannot escape into code that
  runs after the tool.
  """

  def __init__(self):
    self._lock = threading.Lock()
    self._thread_id: int | None = None
    self._fired = False

  @property
  def fired(self) -> bool:
    return self._fired

  def enter(self) -> None:
    with self._lock:
      self._thread_id = threading.get_ident()

  def request(self) -> None:
    with self._lock:
      if self._thread_id is None or self._fired:
        return
      self._fired = True
      if not _inject(self._thread_id):
        logger.warning("Could not interrupt the IDA thread")

  def exit(self) -> None:
    with self._lock:
      thread_id, self._thread_id = self._thread_id, None
      if self._fired and thread_id is not None:
        _clear(thread_id)


def protect_handlers(module: ast.Module) -> ast.Module:
  """Makes every `try` in user code re-raise ToolInterrupt first.

  Inserts `except __idamcp_interrupt__: raise` ahead of the existing handlers,
  so `except:` / `except BaseException:` in user code cannot swallow a
  cancellation. The caller must bind INTERRUPT_GLOBAL in the exec namespace.

  Args:
    module: Parsed user code; modified in place.

  Returns:
    The same module, for chaining.
  """
  try_star = getattr(ast, "TryStar", None)  # Python 3.11+
  try_types = (ast.Try,) + ((try_star,) if try_star else ())
  for node in ast.walk(module):
    if not isinstance(node, try_types) or not node.handlers:
      continue
    anchor = node.handlers[0]
    exc_type = ast.Name(id=INTERRUPT_GLOBAL, ctx=ast.Load())
    if try_star is not None and isinstance(node, try_star):
      # A bare raise inside except* re-raises an ExceptionGroup; raise a fresh
      # ToolInterrupt instead so the caller sees a plain cancellation.
      reraise = ast.Raise(exc=ast.Name(id=INTERRUPT_GLOBAL, ctx=ast.Load()))
    else:
      reraise = ast.Raise()
    handler = ast.ExceptHandler(type=exc_type, name=None, body=[reraise])
    for new in (exc_type, reraise, handler):
      ast.copy_location(new, anchor)
    if isinstance(reraise.exc, ast.Name):
      ast.copy_location(reraise.exc, anchor)
    node.handlers.insert(0, handler)
  ast.fix_missing_locations(module)
  return module
