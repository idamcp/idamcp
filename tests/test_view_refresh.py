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

"""Unit tests for refreshing GUI pseudocode views after write tool calls."""

import enum
import pathlib
import sys
import types
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

for _module in ("idaapi", "ida_kernwin", "idc"):
  if _module not in sys.modules:
    sys.modules[_module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top,g-bad-import-order
from ida_mcp.core import synchronization
import idaapi


class _Safety(enum.IntEnum):
  """Distinct values; the real enum can alias when ida_kernwin is mocked."""

  SAFE_NONE = 0
  SAFE_READ = 1
  SAFE_WRITE = 2


class TestGuiViewRefresh(unittest.TestCase):
  """Tests for _schedule_view_refresh and its call site in _IDACall._runned."""

  def setUp(self):
    self.timers = []
    self.views = {"Pseudocode-A": mock.Mock(), "Pseudocode-C": mock.Mock()}
    self.hexrays = types.SimpleNamespace(
        init_hexrays_plugin=mock.Mock(return_value=True),
        get_widget_vdui=lambda w: w,
    )
    self.config = {}
    self.patches = [
        mock.patch.object(synchronization, "IDASafety", _Safety),
        mock.patch.object(synchronization, "_view_refresh_disabled", False),
        mock.patch.object(synchronization, "_view_refresh_pending", False),
        mock.patch.object(idaapi, "is_headless", False, create=True),
        mock.patch.dict(sys.modules, {"ida_hexrays": self.hexrays}),
        mock.patch.object(
            synchronization.ida_kernwin,
            "register_timer",
            side_effect=lambda ms, cb: self.timers.append((ms, cb)) or object(),
            create=True,
        ),
        mock.patch.object(
            synchronization.ida_kernwin,
            "find_widget",
            side_effect=self.views.get,
            create=True,
        ),
        mock.patch(
            "shared.config.load_config", side_effect=lambda: self.config
        ),
        mock.patch.object(
            synchronization, "get_cancellation_token", return_value=None
        ),
    ]
    for p in self.patches:
      p.start()

  def tearDown(self):
    for p in reversed(self.patches):
      p.stop()

  def _run(self, mode, exc=None, result="ok"):
    def my_tool():
      if exc is not None:
        raise exc
      return result

    call = synchronization._IDACall(my_tool, mode)
    call._runned()
    return call

  def _fire_timers(self):
    timers, self.timers = self.timers, []
    return [cb() for _, cb in timers]

  def _refresh_counts(self):
    return [v.refresh_view.call_count for v in self.views.values()]

  def test_write_schedules_refresh_of_all_open_pseudocode_views(self):
    call = self._run(_Safety.SAFE_WRITE)
    self.assertEqual(call.get_result(), "ok")
    self.assertEqual(len(self.timers), 1)
    self.assertEqual(self._refresh_counts(), [0, 0])  # Deferred, not inline.
    self.assertEqual(self._fire_timers(), [-1])  # One-shot timer.
    for view in self.views.values():
      view.refresh_view.assert_called_once_with(True)

  def test_burst_of_writes_coalesces_into_one_refresh(self):
    for _ in range(5):
      self._run(_Safety.SAFE_WRITE)
    self.assertEqual(len(self.timers), 1)
    self._fire_timers()
    self.assertEqual(self._refresh_counts(), [1, 1])
    self._run(_Safety.SAFE_WRITE)  # After the refresh ran, schedule again.
    self.assertEqual(len(self.timers), 1)

  def test_refresh_scheduled_even_if_tool_raises(self):
    call = self._run(_Safety.SAFE_WRITE, exc=ValueError("partial"))
    with self.assertRaises(ValueError):
      call.get_result()
    self.assertEqual(len(self.timers), 1)

  def test_read_call_does_not_refresh(self):
    self._run(_Safety.SAFE_READ)
    self.assertEqual(self.timers, [])

  def test_headless_does_not_refresh(self):
    with mock.patch.object(idaapi, "is_headless", True, create=True):
      self._run(_Safety.SAFE_WRITE)
    self.assertEqual(self.timers, [])

  def test_config_off_does_not_refresh(self):
    self.config = {"gui_refresh_views": False}
    self._run(_Safety.SAFE_WRITE)
    self.assertEqual(self.timers, [])

  def test_no_decompiler_refreshes_nothing(self):
    self.hexrays.init_hexrays_plugin.return_value = False
    self._run(_Safety.SAFE_WRITE)
    self._fire_timers()
    self.assertEqual(self._refresh_counts(), [0, 0])
    self.assertFalse(synchronization._view_refresh_disabled)

  def test_refresh_error_disables_and_logs_once(self):
    self.views["Pseudocode-A"].refresh_view.side_effect = RuntimeError("boom")
    with self.assertLogs(synchronization.logger, level="ERROR") as logs:
      self._run(_Safety.SAFE_WRITE)
      self._fire_timers()
      self._run(_Safety.SAFE_WRITE)
    self.assertEqual(len(logs.records), 1)
    self.assertTrue(synchronization._view_refresh_disabled)
    self.assertEqual(self.timers, [])

  def test_timer_registration_failure_refreshes_inline(self):
    synchronization.ida_kernwin.register_timer.side_effect = lambda ms, cb: None
    self._run(_Safety.SAFE_WRITE)
    self.assertEqual(self._refresh_counts(), [1, 1])
    self.assertFalse(synchronization._view_refresh_pending)

  def test_nested_call_on_main_thread_does_not_refresh(self):
    with mock.patch.object(idaapi, "is_main_thread", return_value=True):
      synchronization._IDACall(lambda: 1, _Safety.SAFE_WRITE).execute_sync()
    self.assertEqual(self.timers, [])


if __name__ == "__main__":
  unittest.main()
