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

"""Unit tests for HeadlessManager spawned instances tracking and forwarder."""

import asyncio
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _global_database_id_to_pid
from gateway.forward import _headless_manager
from gateway.forward import forward_to
from gateway.forward import HeadlessManager
from gateway.forward import idalib_headless_close


class TestHeadlessManager(unittest.IsolatedAsyncioTestCase):
  """Tests for HeadlessManager spawned instances tracking and quota."""

  async def asyncSetUp(self):
    self.manager = HeadlessManager(max_instances=3)
    _global_client_state.clear()
    _global_database_id_to_pid.clear()

  async def asyncTearDown(self):
    _global_client_state.clear()
    _global_database_id_to_pid.clear()

  def test_register_adds_to_spawned_instances(self):
    """Test registering adds an instance to spawned_instances and pid map."""
    self.manager.register("db1", 1001)
    self.assertIn("db1", self.manager.spawned_instances)
    self.assertEqual(_global_database_id_to_pid.get("db1"), 1001)

  async def test_unregister_removes_from_spawned_instances(self):
    """Test that unregistering removes an instance from spawned_instances."""
    self.manager.register("db1", 1001)
    self.assertIn("db1", self.manager.spawned_instances)

    with mock.patch("gateway.forward._is_process_running", return_value=False):
      await self.manager.unregister("db1")

    self.assertNotIn("db1", self.manager.spawned_instances)
    self.assertNotIn("db1", _global_database_id_to_pid)

  async def test_close_calls_disconnect_backend(self):
    """Test that close delegates to disconnect_backend."""
    with mock.patch("gateway.forward.disconnect_backend") as mock_disconnect:
      await self.manager.close("db1")
      mock_disconnect.assert_called_once_with("db1")

  async def test_spawn_raises_error_when_limit_reached(self):
    """Test that spawn raises ToolError when max_instances limit is reached."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)

    with (
        mock.patch("os.path.abspath", return_value="/fake/path/bin"),
        mock.patch("os.path.exists", return_value=True),
    ):
      with self.assertRaises(ToolError) as ctx:
        await self.manager.spawn("/fake/path/bin")

      self.assertIn(
          "Maximum number of headless IDA instances (3) reached",
          str(ctx.exception),
      )
      self.assertIn("idalib_headless_close", str(ctx.exception))

  async def test_spawn_succeeds_after_closing_instance(self):
    """Test that closing an instance frees capacity to spawn again."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.manager.register("db3", 1003)
    self.assertEqual(len(self.manager.spawned_instances), 3)

    # Unregister db1 (simulate close)
    with mock.patch("gateway.forward._is_process_running", return_value=False):
      await self.manager.unregister("db1")

    self.assertEqual(len(self.manager.spawned_instances), 2)

  async def test_forward_to_succeeds(self):
    """Test that forward_to forwards tool calls to client successfully."""
    mock_client = mock.AsyncMock()
    mock_client.call.return_value = {"status": "ok"}
    _global_clients["test_db"] = mock_client

    result = await forward_to("test_db", "ping", {})
    self.assertEqual(result, {"status": "ok"})

  async def test_close_discards_spawned_instances_early(self):
    """Test that close immediately discards from spawned_instances."""
    self.manager.register("db1", 1001)
    self.assertIn("db1", self.manager.spawned_instances)

    disconnect_started = asyncio.Event()

    async def slow_disconnect(db_id):
      del db_id
      # Verify that db1 has already been discarded from spawned_instances
      self.assertNotIn("db1", self.manager.spawned_instances)
      disconnect_started.set()

    with mock.patch(
        "gateway.forward.disconnect_backend", side_effect=slow_disconnect
    ):
      await self.manager.close("db1")

    self.assertTrue(disconnect_started.is_set())
    self.assertNotIn("db1", self.manager.spawned_instances)

  async def test_pending_spawns_prevents_overspawning(self):
    """Test that _pending_spawns prevents exceeding max_instances."""
    self.manager.register("db1", 1001)
    self.manager.register("db2", 1002)
    self.assertEqual(len(self.manager.spawned_instances), 2)

    # 1 slot remaining (max=3), but 1 pending spawn in-flight
    self.manager._pending_spawns = 1

    with (
        mock.patch("os.path.abspath", return_value="/fake/path/bin"),
        mock.patch("os.path.exists", return_value=True),
    ):
      with self.assertRaises(ToolError) as ctx:
        await self.manager.spawn("/fake/path/bin")

      self.assertIn(
          "Maximum number of headless IDA instances (3) reached",
          str(ctx.exception),
      )

  async def test_idalib_headless_close_discards_early_and_skips_closed(self):
    """Test idalib_headless_close discards early and guards against re-entrance."""
    _global_database_id_to_pid["db1"] = 1001
    _headless_manager.max_instances = 1
    _headless_manager.spawned_instances.add("db1")

    with mock.patch(
        "gateway.forward.disconnect_backend", new_callable=mock.AsyncMock
    ) as mock_disconnect:
      await idalib_headless_close("db1")
      self.assertNotIn("db1", _headless_manager.spawned_instances)
      mock_disconnect.assert_called_once_with("db1")

      # Mark is_closed to simulate completed close
      _global_client_state["db1"].is_closed = True
      mock_disconnect.reset_mock()

      # Calling it again should be a no-op
      await idalib_headless_close("db1")
      mock_disconnect.assert_not_called()

  async def test_unregister_spawns_background_kill_task(self):
    """Test that unregister spawns _kill_process_gracefully in background."""
    self.manager.register("db1", 1001)

    with (
        mock.patch("gateway.forward._is_process_running", return_value=True),
        mock.patch("gateway.forward._create_background_task") as mock_bg_task,
    ):
      mock_bg_task.side_effect = lambda coro: coro.close()
      await self.manager.unregister("db1")

      self.assertNotIn("db1", self.manager.spawned_instances)
      self.assertNotIn("db1", _global_database_id_to_pid)
      mock_bg_task.assert_called_once()

  async def test_disconnect_backend_skips_unregister_when_reopened(self):
    """Test that disconnect_backend skips unregister if reopened during wait."""
    from gateway.forward import disconnect_backend

    _global_database_id_to_pid["db1"] = 1001
    _headless_manager.max_instances = 1
    _headless_manager.spawned_instances.add("db1")
    _global_client_state["db1"].number_of_ongoing_calls = 1

    async def simulate_reopen():
      await asyncio.sleep(0.01)
      _headless_manager.register("db1", 1001)
      async with _global_client_state["db1"].condition:
        _global_client_state["db1"].is_closed = False
        _global_client_state["db1"].number_of_ongoing_calls = 0
        _global_client_state["db1"].condition.notify_all()

    with mock.patch(
        "gateway.forward._headless_manager.unregister"
    ) as mock_unregister:
      reopen_task = asyncio.create_task(simulate_reopen())
      await disconnect_backend("db1", unregister=True)
      await reopen_task

      mock_unregister.assert_not_called()
      self.assertIn("db1", _headless_manager.spawned_instances)
