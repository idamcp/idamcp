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

"""Tests for headless deferred auto-analysis and ida_thread idle work."""

import pathlib
import sys
import threading
import types
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

MOCKED_MODULES = [
    "idapro",
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
    "ida_idd",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_loader",
    "ida_moves",
    "ida_nalt",
    "ida_name",
    "ida_netnode",
    "ida_segment",
    "ida_struct",
    "ida_typeinf",
    "ida_xref",
    "idautils",
    "idc",
]
for module in MOCKED_MODULES:
  if module not in sys.modules:
    sys.modules[module] = mock.MagicMock()

if not isinstance(getattr(sys.modules["ida_idp"], "IDB_Hooks", None), type):
  sys.modules["ida_idp"].IDB_Hooks = type(
      "IDB_Hooks", (), {"hook": lambda self: True, "unhook": lambda self: True}
  )
if not isinstance(getattr(sys.modules["ida_idp"], "IDP_Hooks", None), type):
  sys.modules["ida_idp"].IDP_Hooks = type(
      "IDP_Hooks", (), {"hook": lambda self: True, "unhook": lambda self: True}
  )

# pylint: disable=g-import-not-at-top
from ida_mcp import headless
from ida_mcp.core import ida_thread

# pylint: enable=g-import-not-at-top


class _LoopThread:
  """Runs ida_thread.loop() in a background thread."""

  def __enter__(self):
    self.thread = threading.Thread(target=ida_thread.loop, daemon=True)
    with mock.patch("idaapi.is_main_thread", return_value=True):
      self.thread.start()
      ida_thread.wait_for_loop_event()
    return self

  def __exit__(self, *exc):
    ida_thread.set_idle_work(None)
    ida_thread.stop()
    self.thread.join(timeout=5)
    assert not self.thread.is_alive()


class TestIdleWork(unittest.TestCase):
  """ida_thread runs idle work only while no task is queued."""

  def tearDown(self):
    ida_thread.set_idle_work(None)
    super().tearDown()

  def test_runs_until_false_then_stops(self):
    calls = []
    done = threading.Event()

    def work():
      calls.append(1)
      if len(calls) == 5:
        done.set()
        return False
      return True

    ida_thread.set_idle_work(work)
    with _LoopThread():
      self.assertTrue(done.wait(5))
      # The loop blocks on the queue now; a task still runs.
      ida_thread.execute_sync(lambda: None)
      self.assertEqual(len(calls), 5)
      self.assertIsNone(ida_thread._idle_work)

  def test_tasks_run_while_work_remains(self):
    started = threading.Event()

    def work():
      started.set()
      return True  # Never finishes.

    ida_thread.set_idle_work(work)
    with _LoopThread():
      self.assertTrue(started.wait(5))
      results = []
      for i in range(3):
        ida_thread.execute_sync(lambda i=i: results.append(i))
      self.assertEqual(results, [0, 1, 2])
      self.assertIs(ida_thread._idle_work, work)

  def test_exception_clears_work_and_loop_keeps_serving(self):
    calls = []

    def work():
      calls.append(1)
      raise RuntimeError("boom")

    with _LoopThread():
      with self.assertLogs(ida_thread.logger, "ERROR"):
        ida_thread.set_idle_work(work)
        # Wake the loop so it picks up the work, then wait for it to fail.
        ida_thread.execute_sync(lambda: None)
        for _ in range(100):
          if ida_thread._idle_work is None:
            break
          ida_thread.execute_sync(lambda: None)
      ida_thread.execute_sync(lambda: None)
      self.assertEqual(len(calls), 1)
      self.assertIsNone(ida_thread._idle_work)

  def test_quit_while_work_remains(self):
    ida_thread.set_idle_work(lambda: True)
    loop = _LoopThread()
    loop.__enter__()
    ida_thread.stop()
    loop.thread.join(timeout=5)
    self.assertFalse(loop.thread.is_alive())

  def test_no_idle_work_by_default(self):
    self.assertIsNone(ida_thread._idle_work)


class TestAnalysisStep(unittest.TestCase):
  """headless._analysis_step drives ida_auto in bounded slices."""

  def _auto(self, **attrs):
    auto = types.SimpleNamespace(
        is_auto_enabled=lambda: True, auto_make_step=lambda *a: True
    )
    for k, v in attrs.items():
      setattr(auto, k, v)
    return mock.patch.dict(sys.modules, {"ida_auto": auto})

  def test_returns_false_when_drained(self):
    with self._auto(auto_make_step=lambda *a: False):
      self.assertFalse(headless._analysis_step())

  def test_returns_true_when_slice_ends_with_work_left(self):
    steps = []

    def step(*a):
      steps.append(a)
      return True

    with self._auto(auto_make_step=step), mock.patch.object(
        headless, "_ANALYSIS_SLICE_S", 0.01
    ):
      self.assertTrue(headless._analysis_step())
    self.assertGreater(len(steps), 0)

  def test_stops_if_auto_disabled(self):
    step = mock.Mock(return_value=True)
    with self._auto(is_auto_enabled=lambda: False, auto_make_step=step):
      self.assertFalse(headless._analysis_step())
    step.assert_not_called()

  def test_supported_probe(self):
    with self._auto():
      self.assertTrue(headless._deferred_analysis_supported())
    with mock.patch.dict(
        sys.modules, {"ida_auto": types.SimpleNamespace(auto_is_ok=bool)}
    ):
      self.assertFalse(headless._deferred_analysis_supported())


class TestMainWiring(unittest.TestCase):
  """headless.main() opens without analysis and registers idle work."""

  def _run_main(self, deferred, supported=True):
    open_db = mock.Mock(return_value=0)
    set_idle = mock.Mock()
    with (
        mock.patch.object(sys, "argv", ["headless", __file__]),
        mock.patch.object(headless.idapro, "open_database", open_db),
        mock.patch.object(headless.idapro, "close_database"),
        mock.patch.object(
            headless,
            "load_config",
            return_value={"headless_deferred_analysis": deferred},
        ),
        mock.patch.object(
            headless, "_deferred_analysis_supported", return_value=supported
        ),
        mock.patch.object(headless.ida_thread, "set_idle_work", set_idle),
        mock.patch.object(headless.ida_thread, "loop"),
        mock.patch.object(headless, "stop_server"),
        mock.patch.object(headless.threading, "Thread"),
        mock.patch.object(headless.signal, "signal"),
        mock.patch.object(headless.idaapi, "get_path", return_value="/x.i64"),
    ):
      headless.main()
    return open_db, set_idle

  def test_default_analyzes_before_serving(self):
    open_db, set_idle = self._run_main(deferred=False)
    self.assertIs(open_db.call_args.kwargs["run_auto_analysis"], True)
    set_idle.assert_not_called()

  def test_deferred(self):
    open_db, set_idle = self._run_main(deferred=True)
    self.assertIs(open_db.call_args.kwargs["run_auto_analysis"], False)
    set_idle.assert_called_once_with(headless._analysis_step)

  def test_deferred_unsupported_falls_back(self):
    with self.assertLogs(headless.logger, "WARNING"):
      open_db, set_idle = self._run_main(deferred=True, supported=False)
    self.assertIs(open_db.call_args.kwargs["run_auto_analysis"], True)
    set_idle.assert_not_called()


if __name__ == "__main__":
  unittest.main()
