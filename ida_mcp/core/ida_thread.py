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
import logging
import queue
import threading
from typing import Any, Callable
import idaapi

logger = logging.getLogger(__name__)

_loop_running = threading.Event()


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

  def __call__(self):
    # pylint: disable=broad-exception-caught
    if self.future and self.future.cancelled():
      if self.event is not None:
        self.event.set()
      return

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
    err = RuntimeError("IDA worker thread loop stopped.")
    self.error = err
    if self.loop and self.future:
      self.loop.call_soon_threadsafe(_safe_set_exception, self.future, err)
    if self.event is not None:
      self.event.set()


_ida_queue: queue.Queue[IDATask | str] = queue.Queue()

# Optional background work that loop() runs on the IDA thread while the queue
# is empty (headless deferred auto-analysis). Each call should return within a
# few tens of milliseconds, since queued tasks wait for it. It returns True
# while work remains; after False or an exception it is not called again.
_idle_work: Callable[[], bool] | None = None


def set_idle_work(func: Callable[[], bool] | None) -> None:
  """Sets (or clears, with None) the work loop() runs while idle."""
  global _idle_work
  _idle_work = func


def _run_idle_work() -> None:
  global _idle_work
  work = _idle_work
  if work is None:
    return
  try:
    more = work()
  except Exception:  # pylint: disable=broad-exception-caught
    logger.exception("Idle work failed, not running it again")
    more = False
  if not more and _idle_work is work:
    _idle_work = None


def _next_item() -> IDATask | str:
  """Returns the next queued item, running idle work while there is none."""
  while _idle_work is not None:
    try:
      return _ida_queue.get_nowait()
    except queue.Empty:
      _run_idle_work()
  return _ida_queue.get()


def loop():
  """Worker thread loop."""
  logger.info("IDA worker thread started.")
  if not idaapi.is_main_thread():
    # is_main_thread remembers the first caller thread as the main thread. Thus
    # we'll have to ensure that no other threads have ever called this function
    # before we have done so.
    logger.error("is_main_thread is supposed to be first called by the worker")
    exit(-1)

  _loop_running.set()
  try:
    while True:
      try:
        item = _next_item()
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


def stop():
  """Stop the IDA worker thread."""
  _ida_queue.put("quit")


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
  _ida_queue.put(task)
  event.wait()
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
  _ida_queue.put(task)
  return await future
