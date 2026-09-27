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

"""Unit tests for the plugin's opt-in gui_autostart."""

import types
import unittest
from unittest import mock

# Reuses the IDA module mocks installed by test_plugin_lifecycle.
import test_plugin_lifecycle  # pylint: disable=unused-import
import idaapi
from plugins import ida_mcp_plugin
from plugins.ida_mcp_plugin import MCP


class _FakeTimers:
  """Records register_timer calls and lets tests fire the callback."""

  def __init__(self):
    self.registered = []
    self.unregistered = []

  def register(self, interval, callback):
    handle = object()
    self.registered.append((interval, callback, handle))
    return handle

  def unregister(self, handle):
    self.unregistered.append(handle)
    return True


class TestGuiAutostart(unittest.TestCase):
  """Tests for MCP._schedule_autostart and its timer callback."""

  def setUp(self):
    self.timers = _FakeTimers()
    self.auto_ok = True
    self.patches = [
        mock.patch.object(
            idaapi, "register_timer", self.timers.register, create=True
        ),
        mock.patch.object(
            idaapi, "unregister_timer", self.timers.unregister, create=True
        ),
        mock.patch.object(idaapi, "is_idaq", lambda: True, create=True),
        mock.patch.object(
            idaapi, "cvar", types.SimpleNamespace(batch=0), create=True
        ),
        mock.patch.object(idaapi, "auto_is_ok", lambda: self.auto_ok),
    ]
    for p in self.patches:
      p.start()

  def tearDown(self):
    for p in reversed(self.patches):
      p.stop()

  def _plugin(self, config):
    with mock.patch.object(ida_mcp_plugin, "load_config", return_value=config):
      plugin = MCP()
      plugin.init()
    return plugin

  def test_off_by_default(self):
    plugin = self._plugin({})
    self.assertEqual(self.timers.registered, [])
    self.assertIsNone(plugin._autostart_timer)

  def test_not_scheduled_outside_interactive_gui(self):
    with mock.patch.object(idaapi, "is_idaq", lambda: False):
      self._plugin({"gui_autostart": True})
    with mock.patch.object(idaapi, "cvar", types.SimpleNamespace(batch=1)):
      self._plugin({"gui_autostart": True})
    self.assertEqual(self.timers.registered, [])

  def test_not_scheduled_without_register_timer(self):
    with mock.patch.object(idaapi, "register_timer", None):
      plugin = self._plugin({"gui_autostart": True})
    self.assertIsNone(plugin._autostart_timer)

  def test_waits_for_auto_analysis_then_runs_once(self):
    plugin = self._plugin({"gui_autostart": True})
    self.assertEqual(len(self.timers.registered), 1)
    _, tick, _ = self.timers.registered[0]
    with mock.patch.object(plugin, "run") as run:
      self.auto_ok = False
      self.assertEqual(tick(), ida_mcp_plugin._AUTOSTART_POLL_MS)
      run.assert_not_called()
      self.auto_ok = True
      self.assertEqual(tick(), -1)
      run.assert_called_once_with(0)
    self.assertIsNone(plugin._autostart_timer)

  def test_manual_start_first_stops_timer(self):
    plugin = self._plugin({"gui_autostart": True})
    _, tick, _ = self.timers.registered[0]
    plugin._server_started = True
    with mock.patch.object(plugin, "run") as run:
      self.assertEqual(tick(), -1)
      run.assert_not_called()
    plugin._server_started = False

  def test_run_exception_does_not_escape_timer(self):
    plugin = self._plugin({"gui_autostart": True})
    _, tick, _ = self.timers.registered[0]
    with mock.patch.object(plugin, "run", side_effect=RuntimeError("boom")):
      self.assertEqual(tick(), -1)

  def test_term_unregisters_pending_timer(self):
    plugin = self._plugin({"gui_autostart": True})
    handle = self.timers.registered[0][2]
    plugin.term()
    self.assertEqual(self.timers.unregistered, [handle])
    self.assertIsNone(plugin._autostart_timer)


if __name__ == "__main__":
  unittest.main()
