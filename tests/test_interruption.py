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

"""Unit tests for cancellation and interruption mechanisms."""

import asyncio
import contextvars
import gc
import itertools
import math
import pathlib
import sqlite3
import sys
import threading
import time
import typing
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

# Mock IDA modules before importing ida_mcp modules
MOCKED_MODULES = [
    "idaapi",
    "ida_auto",
    "ida_bytes",
    "ida_dbg",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idautils",
    "idc",
]
for module in MOCKED_MODULES:
  if module not in sys.modules:
    sys.modules[module] = mock.MagicMock()

# Ensure IDB_Hooks and IDP_Hooks are valid base types when ida_idp is mocked
if not isinstance(getattr(sys.modules["ida_idp"], "IDB_Hooks", None), type):
  sys.modules["ida_idp"].IDB_Hooks = type(
      "IDB_Hooks", (), {"hook": lambda self: True, "unhook": lambda self: True}
  )
if not isinstance(getattr(sys.modules["ida_idp"], "IDP_Hooks", None), type):
  sys.modules["ida_idp"].IDP_Hooks = type(
      "IDP_Hooks", (), {"hook": lambda self: True, "unhook": lambda self: True}
  )

# pylint: disable=g-import-not-at-top
from ida_mcp.core import decorators
from ida_mcp.core import ida_thread
from ida_mcp.core import synchronization
from ida_mcp.core.decorators import _cancel_tls
from ida_mcp.core.decorators import cancellation_profile
from ida_mcp.core.decorators import cancellation_token_var
from ida_mcp.core.decorators import CancellationToken
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import register_cancel_callback
from ida_mcp.core.ida_thread import _safe_set_exception
from ida_mcp.core.ida_thread import _safe_set_result
from ida_mcp.core.ida_thread import IDATask
from ida_mcp.core.synchronization import async_wrapper
from ida_mcp.core.synchronization import idaread
from ida_mcp.core.synchronization import idawrite
from ida_mcp.core.synchronization import IDASafety
from ida_mcp.core.synchronization import IDASyncError
from ida_mcp.core.synchronization import sync_wrapper
from ida_mcp.tools.query import interruptible_sqlite
from shared.rpc import ToolError

# pylint: enable=g-import-not-at-top


class TestCancellationToken(unittest.TestCase):
  """Tests for CancellationToken and callback handling."""

  def test_token_lifecycle(self):
    """Tests cancellation token state changes and callback triggering."""
    token = CancellationToken()
    self.assertFalse(token.is_cancelled)
    self.assertFalse(token.is_set())

    called = []
    token.register_callback(lambda: called.append(1))

    token.cancel()
    self.assertTrue(token.is_cancelled)
    self.assertTrue(token.is_set())
    self.assertEqual(called, [1])

    # Subsequent cancels do nothing
    token.cancel()
    self.assertEqual(called, [1])

    # Callbacks registered after cancel are executed immediately
    late_called = []
    token.register_callback(lambda: late_called.append(2))
    self.assertEqual(late_called, [2])

  def test_unregister_callback(self):
    """Tests unregistering a callback before cancellation."""
    token = CancellationToken()
    called = []
    unregister = token.register_callback(lambda: called.append(1))
    unregister()
    token.cancel()
    self.assertEqual(called, [])

  def test_callback_exception_handling(self):
    """Tests that exceptions in callbacks do not abort subsequent callbacks."""
    token = CancellationToken()
    called = []

    def failing_cb():
      raise ValueError("Boom")

    token.register_callback(failing_cb)
    token.register_callback(lambda: called.append(1))

    # Should not raise despite failing_cb
    token.cancel()
    self.assertEqual(called, [1])

  def test_register_cancel_callback_context_manager(self):
    """Tests register_cancel_callback context manager scope."""
    token = CancellationToken()
    var_token = cancellation_token_var.set(token)
    called = []
    try:
      with register_cancel_callback(lambda: called.append(1)):
        self.assertEqual(called, [])
      # Out of context -> unregistered
      token.cancel()
      self.assertEqual(called, [])
    finally:
      cancellation_token_var.reset(var_token)


class TestSQLiteInterruption(unittest.TestCase):
  """Tests for SQLite query interruption via conn.interrupt()."""

  def test_sqlite_query_interruption(self):
    """Tests that conn.interrupt terminates heavy in-progress SQLite queries."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    token = CancellationToken()
    var_token = cancellation_token_var.set(token)

    query_error = []

    def run_heavy_query():
      try:
        with interruptible_sqlite(conn):
          # Infinite / very slow recursive query
          conn.execute(
              "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM"
              " cnt) SELECT count(*) FROM cnt CROSS JOIN cnt AS b"
          )
      except Exception as e:  # pylint: disable=broad-exception-caught
        query_error.append(e)
      except asyncio.CancelledError as e:
        query_error.append(e)

    ctx = contextvars.copy_context()
    t = threading.Thread(target=ctx.run, args=(run_heavy_query,))
    t.start()

    # Wait briefly for query to start in C code
    time.sleep(0.05)

    # Cancel token (which invokes conn.interrupt())
    token.cancel()
    t.join(timeout=2.0)
    cancellation_token_var.reset(var_token)

    self.assertFalse(t.is_alive(), "Worker thread did not terminate in time")
    self.assertEqual(len(query_error), 1)
    self.assertIsInstance(query_error[0], asyncio.CancelledError)

    # Verify connection remains valid and operational
    cursor = conn.execute("SELECT 42")
    self.assertEqual(cursor.fetchone()[0], 42)
    conn.close()


class TestSyncWrapperCancellation(unittest.TestCase):
  """Tests for sync_wrapper cancellation checks."""

  def test_sync_wrapper_pre_cancelled(self):
    """Verifies sync_wrapper raises if cancelled before execution."""
    token = CancellationToken()
    token.cancel()
    var_token = cancellation_token_var.set(token)
    try:
      executed = []
      with self.assertRaises(asyncio.CancelledError):
        sync_wrapper(lambda: executed.append(1), IDASafety.SAFE_READ)
      self.assertEqual(executed, [])
    finally:
      cancellation_token_var.reset(var_token)


class TestAsyncWrapperCancellation(unittest.IsolatedAsyncioTestCase):
  """Tests for async_wrapper cancellation checks and alias compatibility."""

  async def test_async_wrapper_pre_cancelled(self):
    """Verifies async_wrapper raises if cancelled before execution."""
    token = CancellationToken()
    token.cancel()
    var_token = cancellation_token_var.set(token)
    try:
      executed = []
      with self.assertRaises(asyncio.CancelledError):
        await async_wrapper(lambda: executed.append(1), IDASafety.SAFE_READ)
      self.assertEqual(executed, [])
    finally:
      cancellation_token_var.reset(var_token)

  async def test_invalid_safety_mode(self):
    """Tests that invalid safety modes raise IDASyncError."""
    invalid_mode = typing.cast(IDASafety, 999)
    with self.assertRaises(IDASyncError):
      sync_wrapper(lambda: None, invalid_mode)
    with self.assertRaises(IDASyncError):
      await async_wrapper(lambda: None, invalid_mode)

  async def test_safe_setters_on_cancelled_future(self):
    """Tests _safe_set_result and _safe_set_exception

    Ensure these functions don't raise InvalidStateError on cancelled future.
    """
    loop = asyncio.get_running_loop()
    fut1 = loop.create_future()
    fut1.cancel()
    # Should not raise InvalidStateError
    _safe_set_result(fut1, "value")

    fut2 = loop.create_future()
    fut2.cancel()
    # Should not raise InvalidStateError
    _safe_set_exception(fut2, RuntimeError("error"))

  async def test_idatask_pre_cancelled(self):
    """Tests that IDATask with pre-cancellation.

    IDATask should not execute func if future is cancelled in queue.
    """
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    fut.cancel()

    executed = []
    task = IDATask(lambda: executed.append(1), loop=loop, future=fut)
    task()
    self.assertEqual(executed, [])

  async def test_idasync_dual_behavior_and_sync_call(self):
    """Tests _idasync behavior.

    The wrapper is expected to return coroutine in active loop and sync_call
    returns directly.
    """
    executed = []

    @idaread
    def my_tool(x: int) -> int:
      executed.append(x)
      return x * 2

    # In active asyncio loop, calling my_tool directly returns an awaitable
    # coroutine
    coro = my_tool(5)
    self.assertTrue(asyncio.iscoroutine(coro))

    # Mocking idaapi.is_main_thread to True so run_in_main executes ff()
    with mock.patch("idaapi.is_main_thread", return_value=True):
      res = await coro
      self.assertEqual(res, 10)

      # Calling .sync_call directly executes synchronously even in active loop
      sync_res = my_tool.sync_call(7)
      self.assertEqual(sync_res, 14)

    self.assertEqual(executed, [5, 7])


def _run_until(stop: threading.Event) -> None:
  """Keeps a worker running Python code, interruptibly, until `stop` is set.

  Interrupts raised here propagate to the call site, so the caller's try
  statement sees them. A `while <condition>:` loop in the caller's own frame
  would not do: on Python 3.13, an asynchronous exception raised at the back
  edge of such a loop skips the except and finally blocks of its frame. The
  short sleeps release the GIL, so a busy worker does not delay the event loop
  and skew the timing that the tests measure.

  Args:
    stop: Ends the loop when set.
  """
  while not stop.is_set():
    time.sleep(0.001)


class TestJSONRPCDecoratorCancellation(unittest.IsolatedAsyncioTestCase):
  """Tests for @jsonrpc decorator cancellation flow."""

  async def test_sync_tool_cancellation(self):
    """Tests that a synchronous tool wrapped with @jsonrpc cancels cleanly."""
    stop_event = threading.Event()

    @jsonrpc
    def slow_tool(delay: float) -> str:
      with register_cancel_callback(stop_event.set):
        for _ in range(int(delay * 100)):
          if stop_event.is_set():
            break
          time.sleep(0.01)
        return "done"

    task = asyncio.create_task(slow_tool(delay=1.0))
    await asyncio.sleep(0.05)

    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task
    self.assertTrue(stop_event.is_set())

  async def test_jsonrpc_waits_for_thread_unwind(self):
    """Tests that @jsonrpc awaits worker thread finally cleanup before returning on cancel."""
    started = threading.Event()
    cleanup_done = False

    @jsonrpc
    def tight_loop_with_cleanup() -> str:
      nonlocal cleanup_done
      started.set()
      try:
        x = 0
        while True:
          x += 1
      finally:
        time.sleep(0.05)
        cleanup_done = True

    task = asyncio.create_task(tight_loop_with_cleanup())
    await asyncio.to_thread(started.wait, 2.0)

    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task
    self.assertTrue(
        cleanup_done,
        "jsonrpc returned before worker thread finished finally-block unwind",
    )

  def _record_pulses(self) -> list[float]:
    """Records the time of every CancellationToken.pulse() call."""
    pulse_times: list[float] = []
    original_pulse = CancellationToken.pulse

    def recording_pulse(token: CancellationToken) -> None:
      pulse_times.append(time.monotonic())
      original_pulse(token)

    patcher = mock.patch.object(CancellationToken, "pulse", recording_pulse)
    patcher.start()
    self.addCleanup(patcher.stop)
    return pulse_times

  def _stop_event(self) -> threading.Event:
    """Returns an event, set at cleanup, that ends a failed test's worker."""
    stop = threading.Event()
    self.addCleanup(stop.set)
    return stop

  def _record_asyncio_errors(self) -> list[str]:
    """Records the messages of the errors that asyncio reports on this loop."""
    loop = asyncio.get_running_loop()
    self.addCleanup(loop.set_exception_handler, loop.get_exception_handler())
    errors: list[str] = []
    loop.set_exception_handler(
        lambda _, context: errors.append(context["message"])
    )
    return errors

  def test_pulse_delays_grace_period_then_back_off(self):
    """Pulses wait 250ms so short cleanup can finish, then back off to 1s."""
    self.assertEqual(
        list(itertools.islice(decorators._pulse_delays(), 5)),
        [0.25, 0.5, 1.0, 1.0, 1.0],
    )

  async def test_cleanup_within_grace_period_is_not_reinterrupted(self):
    """Cleanup that outlasts the old 50ms pulse interval runs to completion."""
    pulse_times = self._record_pulses()
    stop = self._stop_event()
    started = threading.Event()
    cleanup_done = False

    @jsonrpc
    def tool_with_slow_cleanup() -> None:
      nonlocal cleanup_done
      try:
        started.set()
        _run_until(stop)
      finally:
        time.sleep(0.15)
        cleanup_done = True

    task = asyncio.create_task(tool_with_slow_cleanup())
    await asyncio.to_thread(started.wait, 2.0)
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await asyncio.wait_for(task, timeout=5)
    self.assertTrue(cleanup_done)
    self.assertEqual(pulse_times, [])

  async def test_swallowed_interrupt_is_retried_after_grace_period(self):
    """A swallowed interrupt is re-sent, but not before the grace period."""
    pulse_times = self._record_pulses()
    stop = self._stop_event()
    started = threading.Event()
    swallowed = 0

    @jsonrpc
    def tool_swallowing_first_interrupt() -> None:
      nonlocal swallowed
      try:
        started.set()
        _run_until(stop)
      except asyncio.CancelledError:
        swallowed += 1  # Like a C/SWIG callback that swallows the interrupt.
      _run_until(stop)

    task = asyncio.create_task(tool_swallowing_first_interrupt())
    await asyncio.to_thread(started.wait, 2.0)
    cancelled_at = time.monotonic()
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await asyncio.wait_for(task, timeout=5)
    self.assertEqual(swallowed, 1)
    self.assertTrue(pulse_times)
    self.assertGreaterEqual(
        pulse_times[0] - cancelled_at, decorators._PULSE_INITIAL_DELAY
    )

  async def test_pulses_back_off_while_operation_keeps_running(self):
    """Each wait between pulses doubles until it reaches the cap."""
    for name, value in (
        ("_PULSE_INITIAL_DELAY", 0.02),
        ("_PULSE_MAX_DELAY", 0.08),
    ):
      patcher = mock.patch.object(decorators, name, value)
      patcher.start()
      self.addCleanup(patcher.stop)
    pulse_times = self._record_pulses()
    stop = self._stop_event()
    started = threading.Event()
    swallowed = 0

    @jsonrpc
    def tool_swallowing_four_interrupts() -> None:
      nonlocal swallowed
      try:
        started.set()
        _run_until(stop)
      except asyncio.CancelledError:
        swallowed += 1
      for _ in range(3):
        try:
          _run_until(stop)
        except asyncio.CancelledError:
          swallowed += 1
      _run_until(stop)

    task = asyncio.create_task(tool_swallowing_four_interrupts())
    await asyncio.to_thread(started.wait, 2.0)
    cancelled_at = time.monotonic()
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await asyncio.wait_for(task, timeout=5)
    self.assertEqual(swallowed, 4)
    self.assertGreaterEqual(len(pulse_times), 4)
    waits = [
        later - earlier
        for earlier, later in itertools.pairwise([cancelled_at, *pulse_times])
    ]
    for actual, minimum in zip(waits, [0.02, 0.04, 0.08, 0.08]):
      self.assertGreaterEqual(actual, minimum)

  async def test_cancelled_call_leaves_no_unretrieved_exception(self):
    """asyncio reports no unretrieved exception for a cancelled call."""
    errors = self._record_asyncio_errors()
    stop = self._stop_event()
    started = threading.Event()

    @jsonrpc
    def tool() -> None:
      started.set()
      _run_until(stop)

    task = asyncio.create_task(tool())
    await asyncio.to_thread(started.wait, 2.0)
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await asyncio.wait_for(task, timeout=5)
    del task
    gc.collect()  # asyncio reports an unretrieved exception at collection.
    self.assertEqual(errors, [])

  async def test_second_cancel_cancels_a_call_waiting_for_the_main_thread(self):
    """A second cancel also cancels a call still waiting for the main thread."""
    errors = self._record_asyncio_errors()
    main_thread_free = self._stop_event()
    queued = threading.Event()
    finished = threading.Event()
    ran = False

    def busy_execute_sync(func, unused_flags):
      # IDA's main thread is busy, e.g., in the plugin's term(), which shuts
      # down the server. The call gets the main thread once term() returns.
      queued.set()
      main_thread_free.wait()
      func()
      finished.set()

    for patcher in (
        mock.patch.object(sys.modules["idaapi"], "is_headless", False),
        mock.patch("idaapi.is_main_thread", return_value=False),
        mock.patch("idaapi.execute_sync", busy_execute_sync),
    ):
      patcher.start()
      self.addCleanup(patcher.stop)

    @jsonrpc
    @idaread
    def tool() -> None:
      nonlocal ran
      ran = True

    task = asyncio.create_task(tool())
    await asyncio.to_thread(queued.wait, 2.0)
    task.cancel()
    await asyncio.sleep(0.05)  # The wrapper now waits for the call.
    task.cancel()  # As RPCServer.close() does after its grace period.
    with self.assertRaises(asyncio.CancelledError):
      await asyncio.wait_for(task, timeout=5)
    await asyncio.sleep(0)  # The call's own task handles its cancel.
    # The server closes its loop without cancelling leftover tasks, and asyncio
    # logs an error when it destroys a task that is still pending.
    self.assertEqual(asyncio.all_tasks() - {asyncio.current_task()}, set())

    main_thread_free.set()
    await asyncio.to_thread(finished.wait, 2.0)
    await asyncio.sleep(0.1)  # The end of the call reaches its future.
    gc.collect()
    self.assertFalse(ran)  # The main thread skips the cancelled call.
    self.assertEqual(errors, [])


class TestCancellationProfileReuse(unittest.TestCase):
  """Tests for zero-overhead cancellation_profile, idempotent reuse, and native IDA cancel."""

  def tearDown(self):
    super().tearDown()
    sys.setprofile(None)

  def test_zero_profile_overhead_and_pure_python_loop_interruption(self):
    """Verifies sys.getprofile is None and tight while-True loops without calls are interrupted."""
    token = CancellationToken()
    started = threading.Event()
    caught = []
    profile_inside = []

    def worker():
      try:
        with cancellation_profile(token):
          profile_inside.append(sys.getprofile())
          started.set()
          x = 0
          while True:
            x += 1
      except asyncio.CancelledError as e:
        caught.append(e)

    t = threading.Thread(target=worker)
    t.start()
    self.assertTrue(started.wait(timeout=2.0))
    time.sleep(0.02)
    token.cancel()
    t.join(timeout=2.0)

    self.assertFalse(t.is_alive(), "Tight pure-Python loop was not interrupted")
    self.assertEqual(profile_inside, [None])
    self.assertEqual(len(caught), 1)
    self.assertIsInstance(caught[0], asyncio.CancelledError)

  def test_native_ida_cancel_headless_and_gui(self):
    """Verifies native_ida_cancel triggers ida_kernwin.set_cancelled and clr_cancelled."""
    kernwin = sys.modules["ida_kernwin"]
    kernwin.set_cancelled.reset_mock()
    kernwin.clr_cancelled.reset_mock()
    kernwin.execute_sync.reset_mock()

    # 1. Headless mode: calls ida_kernwin.set_cancelled() directly
    token1 = CancellationToken()
    started1 = threading.Event()

    def headless_worker():
      with contextlib.suppress(asyncio.CancelledError):
        with cancellation_profile(token1, native_ida_cancel=True):
          started1.set()
          while True:
            pass

    import contextlib  # pylint: disable=g-import-not-at-top

    with mock.patch.object(sys.modules["idaapi"], "is_headless", True):
      t1 = threading.Thread(target=headless_worker)
      t1.start()
      self.assertTrue(started1.wait(timeout=2.0))
      token1.cancel()
      t1.join(timeout=2.0)

    kernwin.set_cancelled.assert_called_once()
    kernwin.clr_cancelled.assert_called_once()

    # 2. GUI mode: marshals set_cancelled via execute_sync with MFF_FAST | MFF_NOWAIT
    kernwin.set_cancelled.reset_mock()
    kernwin.clr_cancelled.reset_mock()
    kernwin.execute_sync.reset_mock()
    token2 = CancellationToken()
    started2 = threading.Event()
    dispatched_callbacks = []

    def _mock_execute_sync(cb, _flags):
      dispatched_callbacks.append(cb)
      # Dispatch while the scope is still active
      return cb()

    kernwin.execute_sync.side_effect = _mock_execute_sync

    def gui_worker():
      with contextlib.suppress(asyncio.CancelledError):
        with cancellation_profile(token2, native_ida_cancel=True):
          started2.set()
          while True:
            pass

    try:
      with mock.patch.object(sys.modules["idaapi"], "is_headless", False):
        t2 = threading.Thread(target=gui_worker)
        t2.start()
        self.assertTrue(started2.wait(timeout=2.0))
        token2.cancel()
        t2.join(timeout=2.0)

      kernwin.execute_sync.assert_called_once()
      kernwin.set_cancelled.assert_called_once()
      kernwin.clr_cancelled.assert_called_once()

      # If a late MFF_NOWAIT callback runs after cancellation_profile exited,
      # it must be a no-op so it does not re-arm the cancel flag after clr_cancelled().
      kernwin.set_cancelled.reset_mock()
      dispatched_callbacks[0]()
      kernwin.set_cancelled.assert_not_called()
    finally:
      kernwin.execute_sync.side_effect = None

  def test_deadline_timeout_interrupts_tight_loop(self):
    """Verifies cancellation_profile(timeout=...) interrupts runaway loops with TimeoutError."""
    caught = []

    def worker():
      try:
        with cancellation_profile(None, timeout=0.05):
          x = 0
          while True:
            x += 1
      except TimeoutError as e:
        caught.append(e)

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=2.0)
    self.assertFalse(t.is_alive(), "Worker thread did not time out in time")
    self.assertEqual(len(caught), 1)
    self.assertIsInstance(caught[0], TimeoutError)

  def test_pulse_reinterrupts_if_first_interrupt_swallowed(self):
    """Verifies token.pulse() re-injects interruption if a C/SWIG callback swallows the first."""
    token = CancellationToken()
    started = threading.Event()
    first_swallowed = threading.Event()
    caught = []

    def worker():
      try:
        with cancellation_profile(token):
          started.set()
          try:
            while True:
              pass
          except BaseException:  # pylint: disable=broad-exception-caught
            # Simulate a SWIG director / C callback swallowing the first async exc
            first_swallowed.set()
          while True:
            pass
      except asyncio.CancelledError as e:
        caught.append(e)

    t = threading.Thread(target=worker)
    t.start()
    self.assertTrue(started.wait(timeout=2.0))
    time.sleep(0.01)
    token.cancel()
    self.assertTrue(first_swallowed.wait(timeout=2.0))
    # First interrupt was swallowed; pulse() re-injects and stops the second loop
    token.pulse()
    t.join(timeout=2.0)
    self.assertFalse(t.is_alive(), "Pulse failed to interrupt second loop")
    self.assertEqual(len(caught), 1)

  def test_idatask_abort_if_queued(self):
    """Verifies IDATask.abort_if_queued aborts unstarted tasks but not running tasks."""
    event = threading.Event()
    executed = []
    task = IDATask(lambda: executed.append(1), event=event)
    self.assertTrue(task.abort_if_queued())
    self.assertTrue(event.is_set())
    self.assertIsInstance(task.error, asyncio.CancelledError)
    # Subsequent call on worker thread is a no-op
    task()
    self.assertEqual(executed, [])

  def test_cancellation_profile_idempotent_reuse(self):
    """Verifies nested cancellation_profile calls reuse the active token idempotently."""
    token = CancellationToken()
    self.assertIsNone(sys.getprofile())
    self.assertIsNone(getattr(_cancel_tls, "active_token", None))

    with cancellation_profile(token):
      self.assertIsNone(sys.getprofile())
      self.assertIs(getattr(_cancel_tls, "active_token", None), token)
      self.assertEqual(len(token._callbacks), 1)

      # Nested scope with same token
      with cancellation_profile(token):
        self.assertIs(getattr(_cancel_tls, "active_token", None), token)
        # Callback must not be duplicated
        self.assertEqual(len(token._callbacks), 1)

      # After nested scope exit, still active with 1 callback
      self.assertIs(getattr(_cancel_tls, "active_token", None), token)
      self.assertEqual(len(token._callbacks), 1)

    # After outer scope exit, token is cleared and callback unregistered
    self.assertIsNone(getattr(_cancel_tls, "active_token", None))
    self.assertEqual(len(token._callbacks), 0)

  def test_cancellation_profile_token_mismatch_stacking(self):
    """Verifies nested calls with different tokens stack and restore."""
    token_ctx = CancellationToken()
    token1 = CancellationToken()
    token2 = CancellationToken()

    var_tok = cancellation_token_var.set(token_ctx)
    try:
      self.assertIs(decorators.get_cancellation_token(), token_ctx)
      with cancellation_profile(token1):
        self.assertIs(getattr(_cancel_tls, "active_token", None), token1)
        self.assertIs(decorators.get_cancellation_token(), token1)

        with cancellation_profile(token2):
          self.assertIs(getattr(_cancel_tls, "active_token", None), token2)
          self.assertIs(decorators.get_cancellation_token(), token2)

        self.assertIs(getattr(_cancel_tls, "active_token", None), token1)
        self.assertIs(decorators.get_cancellation_token(), token1)

      self.assertIsNone(getattr(_cancel_tls, "active_token", None))
      self.assertIs(decorators.get_cancellation_token(), token_ctx)
    finally:
      cancellation_token_var.reset(var_tok)

    self.assertIsNone(decorators.get_cancellation_token())

  def test_nested_idatools_profile_reuse(self):
    """Verifies nested IDA tools retain the outer cancellation token."""
    token = CancellationToken()
    recorded_tokens = []

    @idaread
    def inner_tool():
      recorded_tokens.append(("inner", getattr(_cancel_tls, "active_token", None)))
      return "inner_done"

    @idawrite
    def outer_tool():
      recorded_tokens.append(("outer", getattr(_cancel_tls, "active_token", None)))
      res = inner_tool.sync_call()
      recorded_tokens.append(
          ("after_inner", getattr(_cancel_tls, "active_token", None))
      )
      return f"outer_{res}"

    with mock.patch("idaapi.is_main_thread", return_value=True):
      with cancellation_profile(token):
        result = outer_tool.sync_call()
        self.assertEqual(result, "outer_inner_done")

    self.assertEqual(len(recorded_tokens), 3)
    self.assertIs(recorded_tokens[0][1], token)
    self.assertIs(recorded_tokens[1][1], token)
    self.assertIs(recorded_tokens[2][1], token)
    self.assertIsNone(getattr(_cancel_tls, "active_token", None))

  def test_nested_idatool_cancels_via_outer_profile(self):
    """Verifies nested cancellation propagates through the outer cancellation_profile."""
    token = CancellationToken()

    @idaread
    def inner_tool():
      token.cancel()
      len([1, 2, 3])
      return "should_not_reach"

    @idawrite
    def outer_tool():
      return inner_tool.sync_call()

    with mock.patch("idaapi.is_main_thread", return_value=True):
      with cancellation_profile(token):
        with self.assertRaises(asyncio.CancelledError):
          outer_tool.sync_call()

    self.assertIsNone(getattr(_cancel_tls, "active_token", None))


class TestToolTimeout(unittest.IsolatedAsyncioTestCase):
  """Tests for the `timeout` parameter of @idaread/@idawrite functions."""

  def setUp(self):
    super().setUp()

    async def execute_async(func, unused_safety_mode=0):
      await asyncio.to_thread(func)

    # Dispatch calls as in headless mode, but run them on the calling thread
    # (sync) or on a worker thread (async) instead of IDA's main thread.
    for patcher in (
        mock.patch.object(sys.modules["idaapi"], "is_headless", True),
        mock.patch("idaapi.is_main_thread", return_value=False),
        mock.patch.object(
            ida_thread, "execute_sync", lambda func, unused_mode=0: func()
        ),
        mock.patch.object(ida_thread, "execute_async", execute_async),
    ):
      patcher.start()
      self.addCleanup(patcher.stop)

  def _stop_event(self) -> threading.Event:
    """Returns an event that ends a worker after 3s, so failures cannot hang."""
    stop = threading.Event()
    timer = threading.Timer(3.0, stop.set)
    timer.start()
    self.addCleanup(timer.cancel)
    self.addCleanup(stop.set)
    return stop

  def _assert_no_deadline_left(self, before: set[int]) -> None:
    """Asserts that no deadline was added to the scheduler since `before`."""
    self.assertLessEqual(set(decorators._deadline_scheduler._callbacks), before)

  async def test_timeout_is_read_by_position_keyword_or_default(self):
    """The wrapper finds the timeout however it is passed, as seconds."""
    timeouts = []

    def recording_sync_wrapper(ff, unused_mode, timeout=None):
      timeouts.append(timeout)
      return ff()

    async def recording_async_wrapper(ff, unused_mode, timeout=None):
      timeouts.append(timeout)
      return ff()

    @idaread
    def tool(x: int, timeout: float = 5) -> int:
      return x

    @idaread
    def tool_without_timeout(x: int) -> int:
      return x

    with (
        mock.patch.object(
            synchronization, "sync_wrapper", recording_sync_wrapper
        ),
        mock.patch.object(
            synchronization, "async_wrapper", recording_async_wrapper
        ),
    ):
      tool.sync_call(1)
      tool.sync_call(1, 2)
      tool.sync_call(1, timeout=3)
      await tool(1, timeout=4)
      tool.sync_call(1, timeout=None)
      tool_without_timeout.sync_call(1)

    self.assertEqual(timeouts, [5.0, 2.0, 3.0, 4.0, None, None])
    self.assertIsInstance(timeouts[0], float)

  async def test_invalid_timeout_is_rejected_before_the_call_runs(self):
    """A timeout that is not a positive, finite number fails the call early."""
    executed = []

    @idaread
    def tool(timeout: float = 5) -> None:
      executed.append(timeout)

    for value in (0, -1, math.nan, math.inf, True, "10"):
      with self.subTest(value=value):
        with self.assertRaisesRegex(ValueError, "timeout must be"):
          tool.sync_call(timeout=value)
        with self.assertRaisesRegex(ValueError, "timeout must be"):
          tool(timeout=value)  # Raises before returning a coroutine.
    self.assertEqual(executed, [])

  def test_timeout_interrupts_running_call(self):
    """A call still running after its timeout raises TimeoutError."""
    stop = self._stop_event()
    before = set(decorators._deadline_scheduler._callbacks)

    @idaread
    def spin(timeout: float) -> None:
      del timeout
      _run_until(stop)

    started_at = time.monotonic()
    with self.assertRaisesRegex(TimeoutError, "timed out after 0.10s"):
      spin.sync_call(timeout=0.1)
    self.assertGreaterEqual(time.monotonic() - started_at, 0.1)
    self.assertFalse(stop.is_set(), "The call ran until the watchdog fired")
    self._assert_no_deadline_left(before)

  async def test_timeout_interrupts_running_tool_call(self):
    """A timed-out @jsonrpc tool call fails with a tool error, not a cancel."""
    stop = self._stop_event()

    @jsonrpc
    @idaread
    def spinning_tool(timeout: float = 0.1) -> None:
      del timeout
      _run_until(stop)

    with self.assertRaisesRegex(TimeoutError, "timed out after 0.10s") as ctx:
      await asyncio.wait_for(spinning_tool(), timeout=5)
    # The RPC server reports a ToolError to the client as a tool error.
    self.assertIsInstance(ctx.exception, ToolError)
    self.assertFalse(stop.is_set(), "The call ran until the watchdog fired")

  def test_timeout_error_ends_with_the_notes_of_the_interrupt(self):
    """Notes the call adds to the interrupt end the TimeoutError message."""
    stop = self._stop_event()

    @idaread
    def spin(timeout: float) -> None:
      del timeout
      try:
        _run_until(stop)
      except BaseException as exc:
        # As idapython_eval does with the output printed so far.
        exc.add_note("first note")
        exc.add_note("second note")
        raise

    with self.assertRaises(TimeoutError) as ctx:
      spin.sync_call(timeout=0.1)
    self.assertEqual(
        str(ctx.exception),
        "Operation timed out after 0.10s\n\nfirst note\n\nsecond note",
    )
    self.assertFalse(stop.is_set(), "The call ran until the watchdog fired")

  def test_timeout_reinterrupts_call_that_swallowed_the_interrupt(self):
    """A swallowed timeout interrupt is re-sent on the pulse back-off."""
    for name in ("_PULSE_INITIAL_DELAY", "_PULSE_MAX_DELAY"):
      patcher = mock.patch.object(decorators, name, 0.05)
      patcher.start()
      self.addCleanup(patcher.stop)
    stop = self._stop_event()
    before = set(decorators._deadline_scheduler._callbacks)
    swallowed = 0

    @idaread
    def tool_swallowing_first_interrupt(timeout: float) -> None:
      nonlocal swallowed
      del timeout
      try:
        _run_until(stop)
      except asyncio.CancelledError:
        swallowed += 1  # Like a C/SWIG callback that swallows the interrupt.
      _run_until(stop)

    started_at = time.monotonic()
    with self.assertRaisesRegex(TimeoutError, "timed out"):
      tool_swallowing_first_interrupt.sync_call(timeout=0.1)
    self.assertEqual(swallowed, 1)
    self.assertGreaterEqual(time.monotonic() - started_at, 0.1 + 0.05)
    self.assertFalse(stop.is_set(), "The call ran until the watchdog fired")
    self._assert_no_deadline_left(before)

  def test_call_that_finishes_in_time_is_not_interrupted(self):
    """A call that returns before its timeout leaves no deadline behind."""
    before = set(decorators._deadline_scheduler._callbacks)

    @idaread
    def quick(timeout: float) -> str:
      del timeout
      return "done"

    self.assertEqual(quick.sync_call(timeout=0.05), "done")
    self._assert_no_deadline_left(before)
    interrupted = False
    try:
      time.sleep(0.2)  # Past the deadline; an interrupt would land here.
    except asyncio.CancelledError:
      interrupted = True
    self.assertFalse(interrupted)

  def test_time_waiting_for_the_main_thread_does_not_count(self):
    """The time limit starts when the call starts running, not when queued."""

    def execute_sync_after_queue_wait(func, unused_mode=0):
      time.sleep(0.3)  # Another call holds IDA's main thread meanwhile.
      func()

    @idaread
    def tool(timeout: float) -> str:
      del timeout
      time.sleep(0.05)
      return "done"

    with mock.patch.object(
        ida_thread, "execute_sync", execute_sync_after_queue_wait
    ):
      self.assertEqual(tool.sync_call(timeout=0.2), "done")


if __name__ == "__main__":
  unittest.main()
