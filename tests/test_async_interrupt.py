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

"""Unit tests for asynchronous interruption of tool code (real threads)."""

import ast
import asyncio
import enum
import pathlib
import sys
import threading
import time
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

for _module in ("idaapi", "ida_kernwin", "idc"):
  if _module not in sys.modules:
    sys.modules[_module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.core import decorators
from ida_mcp.core import interrupt
from ida_mcp.core import synchronization
import idaapi

_TIGHT_LOOP = "x = 0\nwhile True:\n  x += 1\n"
_SWALLOWING_LOOP = (
    "x = 0\nwhile True:\n  try:\n    x += 1\n  except BaseException:\n   "
    " pass\n"
)
_BARE_EXCEPT_LOOP = (
    "x = 0\nwhile True:\n  try:\n    x += 1\n  except:\n    pass\n"
)


def _compile_guarded(source):
  tree = interrupt.protect_handlers(ast.parse(source))
  return compile(tree, "<user>", "exec")


class _Runner:
  """Runs `body` in a thread between enter() and exit() of an InterruptibleCall."""

  def __init__(self, body):
    self.call = interrupt.InterruptibleCall()
    self.started = threading.Event()
    self.error = None
    self.finished = threading.Event()
    self.thread = threading.Thread(target=self._run, args=(body,), daemon=True)

  def _run(self, body):
    try:
      try:
        self.call.enter()
        self.started.set()
        body()
      finally:
        self.call.exit()
    except BaseException as e:  # pylint: disable=broad-exception-caught
      self.error = e
    finally:
      self.finished.set()

  def start(self):
    self.thread.start()
    self.assert_started()
    return self

  def assert_started(self):
    if not self.started.wait(5):
      raise AssertionError("runner did not start")


class TestInterruptibleCall(unittest.TestCase):

  def setUp(self):
    if not interrupt.is_available():
      self.skipTest("PyThreadState_SetAsyncExc not available")

  def _run_and_interrupt(self, source):
    code = _compile_guarded(source)
    ns = {interrupt.INTERRUPT_GLOBAL: interrupt.ToolInterrupt}
    runner = _Runner(lambda: exec(code, ns)).start()  # pylint: disable=exec-used
    time.sleep(0.1)
    runner.call.request()
    self.assertTrue(runner.finished.wait(5), "loop was not interrupted")
    return runner

  def test_interrupts_loop_without_calls(self):
    runner = self._run_and_interrupt(_TIGHT_LOOP)
    self.assertIsInstance(runner.error, interrupt.ToolInterrupt)

  def test_guard_defeats_except_base_exception(self):
    runner = self._run_and_interrupt(_SWALLOWING_LOOP)
    self.assertIsInstance(runner.error, interrupt.ToolInterrupt)

  def test_guard_defeats_bare_except(self):
    runner = self._run_and_interrupt(_BARE_EXCEPT_LOOP)
    self.assertIsInstance(runner.error, interrupt.ToolInterrupt)

  def test_tool_interrupt_is_a_cancelled_error(self):
    self.assertTrue(issubclass(interrupt.ToolInterrupt, asyncio.CancelledError))

  def test_request_before_enter_is_noop(self):
    call = interrupt.InterruptibleCall()
    with mock.patch.object(interrupt, "_inject") as inject:
      call.request()
    inject.assert_not_called()
    self.assertFalse(call.fired)

  def test_request_after_exit_does_not_leak(self):
    done = threading.Event()
    leaked = []

    def body():
      pass

    runner = _Runner(body).start()
    self.assertTrue(runner.finished.wait(5))
    runner.call.request()  # Tool already finished.
    self.assertFalse(runner.call.fired)

    def later():
      try:
        end = time.monotonic() + 0.3
        while time.monotonic() < end:
          pass
      except BaseException as e:  # pylint: disable=broad-exception-caught
        leaked.append(e)
      done.set()

    threading.Thread(target=later).start()
    self.assertTrue(done.wait(5))
    self.assertEqual(leaked, [])

  def test_injects_at_most_once(self):
    started = threading.Event()
    release = threading.Event()

    def body():
      started.set()
      release.wait(5)

    runner = _Runner(body)
    with mock.patch.object(interrupt, "_inject", return_value=True) as inject:
      runner.start()
      started.wait(5)
      runner.call.request()
      runner.call.request()
      release.set()
      runner.finished.wait(5)
    inject.assert_called_once()

  def test_exit_clears_pending_interrupt_after_fire(self):
    call = interrupt.InterruptibleCall()
    with mock.patch.object(
        interrupt, "_inject", return_value=True
    ), mock.patch.object(interrupt, "_clear") as clear:
      call.enter()
      call.request()
      call.exit()
    clear.assert_called_once_with(threading.get_ident())

  def test_exit_without_fire_does_not_clear(self):
    call = interrupt.InterruptibleCall()
    with mock.patch.object(interrupt, "_clear") as clear:
      call.enter()
      call.exit()
    clear.assert_not_called()


class TestProtectHandlers(unittest.TestCase):

  def _exec(self, source):
    ns = {interrupt.INTERRUPT_GLOBAL: interrupt.ToolInterrupt}
    exec(_compile_guarded(source), ns)  # pylint: disable=exec-used
    return ns

  def test_ordinary_exceptions_still_handled_by_user_code(self):
    ns = self._exec(
        "try:\n  raise ValueError('x')\nexcept Exception as e:\n  got ="
        " str(e)\n"
    )
    self.assertEqual(ns["got"], "x")

  def test_user_cancelled_error_still_handled(self):
    ns = self._exec(
        "import asyncio\ntry:\n  raise asyncio.CancelledError()\n"
        "except BaseException:\n  got = 1\n"
    )
    self.assertEqual(ns["got"], 1)

  def test_tool_interrupt_passes_through_handlers_and_finally_runs(self):
    with self.assertRaises(interrupt.ToolInterrupt):
      self._exec(
          "try:\n  try:\n    raise __idamcp_interrupt__()\n  except:\n"
          "    swallowed = 1\nfinally:\n  cleaned = 1\n"
      )

  def test_try_without_handlers_untouched(self):
    tree = interrupt.protect_handlers(
        ast.parse("try:\n  pass\nfinally:\n  pass\n")
    )
    self.assertEqual(tree.body[0].handlers, [])

  @unittest.skipIf(sys.version_info < (3, 11), "except* needs Python 3.11+")
  def test_except_star_reraises_plain_interrupt(self):
    with self.assertRaises(interrupt.ToolInterrupt):
      self._exec(
          "try:\n  raise __idamcp_interrupt__()\nexcept* BaseException:\n"
          "  swallowed = 1\n"
      )


class TestProfileHook(unittest.TestCase):

  def test_profile_hook_raises_tool_interrupt(self):
    token = decorators.CancellationToken()
    token.cancel()
    prof = decorators.make_cancellation_profile_func(token)
    with self.assertRaises(interrupt.ToolInterrupt):
      prof(None, "call", None)


class _Safety(enum.IntEnum):
  SAFE_NONE = 0
  SAFE_READ = 1
  SAFE_WRITE = 2


class TestIDACallInterrupt(unittest.TestCase):
  """_IDACall._runned with a real worker thread and a real token."""

  def setUp(self):
    if not interrupt.is_available():
      self.skipTest("PyThreadState_SetAsyncExc not available")
    self.token = decorators.CancellationToken()
    self.config = {}
    self.patches = [
        mock.patch.object(synchronization, "IDASafety", _Safety),
        mock.patch.object(idaapi, "is_headless", True, create=True),
        mock.patch(
            "shared.config.load_config", side_effect=lambda: self.config
        ),
        mock.patch.object(
            synchronization, "get_cancellation_token", return_value=self.token
        ),
    ]
    for p in self.patches:
      p.start()

  def tearDown(self):
    for p in reversed(self.patches):
      p.stop()

  def _run_in_thread(self, ff):
    call = synchronization._IDACall(ff, _Safety.SAFE_WRITE)
    t = threading.Thread(target=call._runned, daemon=True)
    t.start()
    return call, t

  def test_cancel_interrupts_tight_loop(self):
    started = threading.Event()

    def spin():
      started.set()
      while True:
        pass

    call, t = self._run_in_thread(spin)
    self.assertTrue(started.wait(5))
    time.sleep(0.05)
    self.token.cancel()
    t.join(5)
    self.assertFalse(t.is_alive(), "tool thread was not interrupted")
    with self.assertRaises(asyncio.CancelledError) as cm:
      call.get_result()
    self.assertIsInstance(cm.exception, interrupt.ToolInterrupt)
    self.assertEqual(str(cm.exception), "Tool cancelled")

  def test_finished_tool_not_affected_by_late_cancel(self):
    call, t = self._run_in_thread(lambda: 42)
    t.join(5)
    self.token.cancel()  # Late: after the tool returned.
    self.assertEqual(call.get_result(), 42)

  def test_callback_unregistered_after_call(self):
    call, t = self._run_in_thread(lambda: 1)
    t.join(5)
    self.assertEqual(self.token._callbacks, [])
    self.assertEqual(call.get_result(), 1)

  def test_config_off_uses_profile_only(self):
    self.config = {"async_interrupt": False}
    self.assertIsNone(synchronization._make_interruptible(self.token))

  def test_no_token_no_tracker(self):
    self.assertIsNone(synchronization._make_interruptible(None))

  def test_unavailable_api_falls_back(self):
    with mock.patch.object(interrupt, "is_available", return_value=False):
      self.assertIsNone(synchronization._make_interruptible(self.token))


if __name__ == "__main__":
  unittest.main()
