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

"""A dedicated thread for IDA Pro operations in headless mode.

IDA Pro 9.4 introduced ida_kernwin.serve() and ida_kernwin.stop_serving() to
make execute_sync work. However, the biggest problem with `serve` is that, it
doesn't respond to the Ctrl-C signal.

We're going to stick with our own implementation before the problem gets fixed.
"""

import asyncio
import contextlib
import logging
import queue
import threading
import time
from typing import Any, Callable
from ida_mcp.core.decorators import _pulse_delays
from ida_mcp.core.decorators import CancellationToken
from ida_mcp.core.decorators import get_cancellation_token
import idaapi

logger = logging.getLogger(__name__)

_loop_running = threading.Event()

# Cancelled by stop(). Long work on the IDA thread that should give way to a
# shutdown (e.g., populating the query tables) runs in a
# cancellation_profile(stop_token) scope, which interrupts it then; a scope
# entered after stop() raises at once. loop() replaces the token when it
# starts, so read it from the module at the time of use.
stop_token = CancellationToken()


def _safe_set_result(fut: asyncio.Future, val: Any) -> None:
  if not fut.done():
    fut.set_result(val)


def _safe_set_exception(fut: asyncio.Future, exc: BaseException) -> None:
  if not fut.done():
    fut.set_exception(exc)


class IDATask:
  """Represents a task to be executed on the IDA main thread."""

  def __init__(
      self,
      func: Callable[[], Any],
      loop: asyncio.AbstractEventLoop | None = None,
      future: asyncio.Future | None = None,
      event: threading.Event | None = None,
  ):
    self.func = func
    self.loop = loop
    self.future = future
    self.event = event
    self.error: BaseException | None = None
    self._lock = threading.Lock()
    self._started = False
    self._aborted = False

  def abort_if_queued(self, exc: BaseException | None = None) -> bool:
    """Aborts the task immediately if it has not yet started on the IDA thread."""
    with self._lock:
      if self._started or self._aborted:
        return False
      self._aborted = True
    err = exc or asyncio.CancelledError("Tool cancelled before execution")
    self.error = err
    if self.loop and self.future:
      self.loop.call_soon_threadsafe(_safe_set_exception, self.future, err)
    if self.event is not None:
      self.event.set()
    return True

  def __call__(self):
    # pylint: disable=broad-exception-caught
    with self._lock:
      if self._aborted or (self.future and self.future.cancelled()):
        self._aborted = True
        if self.event is not None:
          self.event.set()
        return
      self._started = True

    try:
      res = self.func()
      if self.loop and self.future:
        self.loop.call_soon_threadsafe(_safe_set_result, self.future, res)
    except BaseException as e:
      self.error = e
      if self.loop and self.future:
        self.loop.call_soon_threadsafe(_safe_set_exception, self.future, e)
    finally:
      if self.event is not None:
        self.event.set()

  def cancel(self):
    with self._lock:
      self._aborted = True
    err = RuntimeError("IDA worker thread loop stopped.")
    self.error = err
    if self.loop and self.future:
      self.loop.call_soon_threadsafe(_safe_set_exception, self.future, err)
    if self.event is not None:
      self.event.set()


_ida_queue: queue.Queue[IDATask | str] = queue.Queue()


def loop(idle: Callable[[], bool] | None = None):
  """Worker thread loop.

  Args:
    idle: Optional background work for the IDA thread, e.g., a slice of
      auto-analysis. While it is set, the loop calls it whenever the queue is
      empty instead of waiting for the next item, so it should return soon. It
      returns False once it has nothing left to do; the loop then stops
      calling it and waits for items.
  """
  logger.info("IDA worker thread started.")
  if not idaapi.is_main_thread():
    # is_main_thread remembers the first caller thread as the main thread. Thus
    # we'll have to ensure that no other threads have ever called this function
    # before we have done so.
    logger.error("is_main_thread is supposed to be first called by the worker")
    exit(-1)

  global stop_token
  stop_token = CancellationToken()
  _loop_running.set()
  try:
    while True:
      if idle is None:
        item = _ida_queue.get()
      else:
        try:
          item = _ida_queue.get_nowait()
        except queue.Empty:
          if not idle():
            idle = None
          continue
      try:
        if isinstance(item, str):
          if item in ("quit", "exit"):
            logger.info("IDA worker thread received exit signal.")
            break
          continue

        if isinstance(item, IDATask):
          item()
        else:
          logger.warning("Received unknown item in IDA worker thread: %s", item)
      finally:
        _ida_queue.task_done()
  finally:
    _loop_running.clear()
    # Drain the queue and cancel any pending tasks to prevent thread hangs
    while not _ida_queue.empty():
      try:
        item = _ida_queue.get_nowait()
        if isinstance(item, IDATask):
          item.cancel()
        _ida_queue.task_done()
      except queue.Empty:
        break


def _cancel_stop_token(token: CancellationToken) -> None:
  """Cancels `token`, and repeats the interrupt until the loop has ended.

  An interrupt can be swallowed, e.g., inside a C callback, so it is repeated
  like the interrupt of a cancelled tool call. With no scope open on the
  token, cancelling and pulsing it interrupt nothing.
  """
  with contextlib.suppress(BaseException):
    token.cancel()
  for delay in _pulse_delays():
    time.sleep(delay)
    if not _loop_running.is_set() or stop_token is not token:
      return
    token.pulse()


def stop():
  """Stop the IDA worker thread, interrupting work that waits on stop_token."""
  _ida_queue.put("quit")
  token = stop_token
  if not token.is_cancelled:
    # On another thread: stop() also runs in signal handlers, i.e., on the IDA
    # thread itself, where cancelling could deadlock on the lock of a scope
    # that the signal interrupted while it was being entered or left.
    threading.Thread(
        target=_cancel_stop_token,
        args=(token,),
        name="idamcp-stop",
        daemon=True,
    ).start()


def wait_for_loop_event():
  _loop_running.wait(5)


def execute_sync(
    func: Callable[[], Any],
    unused_safety_mode: int = 0,
) -> None:
  """Emulated execute_sync for headless mode.

  Args:
    func: The function to execute in the IDA thread.
    unused_safety_mode: Ignored in headless mode.

  Raises:
    RuntimeError: If the IDA worker thread loop is not running.
    Exception: If the executed function raises an exception.
  """
  del unused_safety_mode
  if not _loop_running.is_set():
    raise RuntimeError("IDA worker thread loop is not running.")
  event = threading.Event()
  task = IDATask(func, event=event)
  token = get_cancellation_token()
  unregister = (
      token.register_callback(task.abort_if_queued)
      if token is not None
      else (lambda: None)
  )
  try:
    _ida_queue.put(task)
    event.wait()
  finally:
    unregister()
  if task.error:
    raise task.error


async def execute_async(
    func: Callable[[], Any],
    unused_safety_mode: int = 0,
) -> Any:
  """Asynchronously executes a task on the IDA worker thread.

  Args:
    func: The function to execute in the IDA thread.
    unused_safety_mode: Ignored in headless mode.

  Returns:
    The return value of the executed function.

  Raises:
    RuntimeError: If the IDA worker thread loop is not running.
    Exception: If the executed function raises an exception.
  """
  del unused_safety_mode
  if not _loop_running.is_set():
    raise RuntimeError("IDA worker thread loop is not running.")

  loop = asyncio.get_running_loop()
  future = loop.create_future()
  task = IDATask(func, loop=loop, future=future)
  token = get_cancellation_token()
  unregister = (
      token.register_callback(task.abort_if_queued)
      if token is not None
      else (lambda: None)
  )
  try:
    _ida_queue.put(task)
    return await future
  finally:
    unregister()
