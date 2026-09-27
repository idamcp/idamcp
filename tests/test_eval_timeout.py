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

"""Unit tests for the idapython_eval timeout (real threads, no IDA)."""

import contextlib
import sys
import threading
import time
import unittest
from unittest import mock

for _module in (
    "ida_bytes",
    "ida_dbg",
    "ida_idp",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "idautils",
    "idc",
):
  if _module not in sys.modules:
    sys.modules[_module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top
from ida_mcp.core import interrupt
from ida_mcp.tools import execution

# pylint: enable=g-import-not-at-top

idapython_eval = getattr(
    execution.idapython_eval, "sync_call", execution.idapython_eval
)

_SPIN = "print('started')\nx = 0\nwhile True:\n  x += 1\n"
_SWALLOW = "x = 0\nwhile True:\n  try:\n    x += 1\n  except:\n    pass\n"


@contextlib.contextmanager
def _tool_call():
  """Mimics _IDACall: an InterruptibleCall active on this thread."""
  call = interrupt.InterruptibleCall()
  call.enter()
  try:
    yield call
  finally:
    call.exit()


class TestEvalTimeout(unittest.TestCase):

  def setUp(self):
    if not interrupt.is_available():
      self.skipTest("PyThreadState_SetAsyncExc not available")
    self.config = {}
    patcher = mock.patch(
        "shared.config.load_config", side_effect=lambda: self.config
    )
    patcher.start()
    self.addCleanup(patcher.stop)

  def _assert_no_late_interrupt(self, seconds=0.4):
    end = time.monotonic() + seconds
    while time.monotonic() < end:  # Would raise ToolInterrupt if leaked.
      pass

  def test_timeout_interrupts_loop_and_keeps_output(self):
    start = time.monotonic()
    with _tool_call():
      res = idapython_eval(_SPIN, timeout=0.3)
    elapsed = time.monotonic() - start
    self.assertTrue(res["timed_out"])
    self.assertEqual(res["stdout"], "started\n")
    self.assertIn("TimeoutError: execution exceeded 0.3s", res["stderr"])
    self.assertLess(elapsed, 3)

  def test_timeout_defeats_bare_except(self):
    with _tool_call():
      res = idapython_eval(_SWALLOW, timeout=0.2)
    self.assertTrue(res["timed_out"])

  def test_fast_code_unaffected_and_timer_cancelled(self):
    with _tool_call():
      res = idapython_eval("1 + 1", timeout=0.2)
      self._assert_no_late_interrupt()
    self.assertEqual(res["result"], "2")
    self.assertNotIn("timed_out", res)

  def test_user_error_still_reported_in_stderr(self):
    with _tool_call():
      res = idapython_eval("1 / 0", timeout=5)
    self.assertIn("ZeroDivisionError", res["stderr"])
    self.assertNotIn("timed_out", res)

  def test_config_default_used_when_param_omitted(self):
    self.config = {"eval_timeout": 0.2}
    with _tool_call():
      res = idapython_eval(_SPIN)
    self.assertTrue(res["timed_out"])

  def test_param_overrides_config(self):
    self.config = {"eval_timeout": 0.1}
    with _tool_call():
      res = idapython_eval("import time\ntime.sleep(0.3)\n'ok'", timeout=5)
    self.assertEqual(res["result"], "ok")

  def test_no_timeout_works_without_interruptible(self):
    res = idapython_eval("2 + 2")
    self.assertEqual(res["result"], "4")

  def test_timeout_without_interruptible_is_an_error(self):
    with self.assertRaises(RuntimeError):
      idapython_eval("1", timeout=1)

  def test_invalid_timeouts_rejected(self):
    for bad in (0, -1, float("nan"), float("inf")):
      with self.subTest(timeout=bad), _tool_call():
        with self.assertRaises(ValueError):
          idapython_eval("1", timeout=bad)

  def test_client_cancel_is_not_reported_as_timeout(self):
    with _tool_call() as call:
      threading.Timer(0.2, call.request).start()
      with self.assertRaises(interrupt.ToolInterrupt):
        idapython_eval(_SPIN, timeout=30)


if __name__ == "__main__":
  unittest.main()
