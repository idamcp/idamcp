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

"""Unit tests for analysis status in get_metadata and wait_for_analysis."""

import sys
import types
import unittest
from unittest import mock

for _module in (
    "ida_auto",
    "ida_bytes",
    "ida_idp",
    "ida_funcs",
    "ida_frame",
    "ida_gdl",
    "ida_hexrays",
    "ida_kernwin",
    "ida_moves",
    "ida_nalt",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "ida_ida",
    "idautils",
    "idc",
    "ida_name",
):
  if _module not in sys.modules:
    sys.modules[_module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top
from ida_mcp.tools import info
from shared.rpc import ToolError

# pylint: enable=g-import-not-at-top

wait_for_analysis = info.wait_for_analysis.sync_call


class _FakeIDA:
  """Scripted analysis state: `pending` steps left until auto_is_ok()."""

  def __init__(self, pending, headless):
    self.pending = pending
    self.headless = headless
    self.slices = []
    self.sleeps = []

  def status(self):
    return {"complete": self.pending <= 0, "auto_enabled": True}

  def run_slice(self, seconds):
    self.slices.append(seconds)
    self.pending -= 1
    return self.pending <= 0

  def sleep(self, seconds):
    self.sleeps.append(seconds)
    self.pending -= 1  # The GUI idle loop makes progress meanwhile.


class TestWaitForAnalysis(unittest.TestCase):

  def _run(self, fake, **kwargs):
    with mock.patch.object(
        info, "_analysis_status", types.SimpleNamespace(sync_call=fake.status)
    ), mock.patch.object(
        info, "_analysis_slice", types.SimpleNamespace(sync_call=fake.run_slice)
    ), mock.patch.object(
        info.idaapi, "is_headless", fake.headless, create=True
    ), mock.patch.object(
        info.time, "sleep", fake.sleep
    ):
      return wait_for_analysis(**kwargs)

  def test_already_complete_returns_immediately(self):
    fake = _FakeIDA(pending=0, headless=True)
    res = self._run(fake)
    self.assertTrue(res["complete"])
    self.assertFalse(res["timed_out"])
    self.assertEqual(fake.slices, [])

  def test_headless_runs_slices_until_complete(self):
    fake = _FakeIDA(pending=3, headless=True)
    res = self._run(fake)
    self.assertTrue(res["complete"])
    self.assertEqual(len(fake.slices), 3)
    self.assertEqual(fake.sleeps, [])

  def test_gui_polls_without_driving_analysis(self):
    fake = _FakeIDA(pending=2, headless=False)
    res = self._run(fake)
    self.assertTrue(res["complete"])
    self.assertEqual(fake.slices, [])
    self.assertEqual(len(fake.sleeps), 2)

  def test_timeout_reports_incomplete(self):
    fake = _FakeIDA(pending=10**9, headless=False)
    fake.sleep = lambda s: None  # No progress at all.
    res = self._run(fake, timeout=0.05)
    self.assertFalse(res["complete"])
    self.assertTrue(res["timed_out"])
    self.assertGreaterEqual(res["waited_s"], 0.05)

  def test_drained_but_not_ok_does_not_spin(self):
    fake = _FakeIDA(pending=5, headless=True)
    fake.run_slice = lambda s: True  # Queue empty, auto_is_ok() still false.
    res = self._run(fake, timeout=5)
    self.assertFalse(res["complete"])
    self.assertFalse(res["timed_out"])

  def test_invalid_timeout(self):
    for bad in (0, -1, float("nan"), float("inf")):
      with self.subTest(timeout=bad), self.assertRaises(ValueError):
        self._run(_FakeIDA(0, True), timeout=bad)

  def test_missing_auto_is_ok_is_an_error(self):
    fake = _FakeIDA(0, True)
    fake.status = lambda: {"complete": None, "auto_enabled": None}
    with self.assertRaises(ToolError):
      self._run(fake)


class TestAnalysisHelpers(unittest.TestCase):

  def test_metadata_field_present_when_api_exists(self):
    with mock.patch.object(
        sys.modules["ida_auto"], "auto_is_ok", return_value=0
    ):
      self.assertEqual(
          info._analysis_complete_field(), {"analysis_complete": False}
      )

  def test_metadata_field_absent_without_api(self):
    fake_auto = types.SimpleNamespace()
    with mock.patch.dict(sys.modules, {"ida_auto": fake_auto}):
      self.assertEqual(info._analysis_complete_field(), {})

  def test_slice_restores_disabled_auto_and_reports_drained(self):
    fake_auto = mock.MagicMock()
    fake_auto.enable_auto.return_value = False  # Was disabled.
    fake_auto.auto_make_step.side_effect = [True, True, False]
    with mock.patch.dict(sys.modules, {"ida_auto": fake_auto}):
      drained = info._analysis_slice.sync_call(5.0)
    self.assertTrue(drained)
    self.assertEqual(
        fake_auto.enable_auto.call_args_list,
        [mock.call(True), mock.call(False)],
    )

  def test_slice_keeps_enabled_auto(self):
    fake_auto = mock.MagicMock()
    fake_auto.enable_auto.return_value = True
    fake_auto.auto_make_step.return_value = False
    with mock.patch.dict(sys.modules, {"ida_auto": fake_auto}):
      info._analysis_slice.sync_call(5.0)
    fake_auto.enable_auto.assert_called_once_with(True)


if __name__ == "__main__":
  unittest.main()
