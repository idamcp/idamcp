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

"""Unit tests for lease-based headless lifetime (no IDA)."""

import asyncio
import contextvars
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

# pylint: disable=g-import-not-at-top
from gateway import forward
from ida_mcp.core import lease
from ida_mcp.core.backend_registry import RegistryManager
from shared import protocol
from shared import rpc

# pylint: enable=g-import-not-at-top


class FakeClock:

  def __init__(self):
    self.now = 1000.0

  def __call__(self) -> float:
    return self.now


class TestLeaseManager(unittest.TestCase):
  """Tests for lease.LeaseManager with a fake clock."""

  def setUp(self):
    self.clock = FakeClock()
    self.expired = []

  def _manager(self, grace=10.0, idle_timeout=0.0):
    return lease.LeaseManager(
        grace, idle_timeout, self.expired.append, clock=self.clock
    )

  def test_grace_runs_from_startup(self):
    manager = self._manager()
    self.clock.now += 9.9
    self.assertFalse(manager.check())
    self.clock.now += 0.1
    self.assertTrue(manager.check())
    self.assertEqual(len(self.expired), 1)
    self.assertIn("lease", self.expired[0])

  def test_held_lease_prevents_exit(self):
    manager = self._manager()
    manager.acquire(1)
    self.clock.now += 3600
    self.assertFalse(manager.check())

  def test_grace_restarts_when_last_lease_ends(self):
    manager = self._manager()
    manager.acquire(1)
    manager.acquire(2)
    self.clock.now += 100
    self.assertTrue(manager.release(1))
    self.clock.now += 100
    self.assertFalse(manager.check())
    manager.connection_closed(2)
    self.clock.now += 9
    self.assertFalse(manager.check())
    self.clock.now += 1
    self.assertTrue(manager.check())

  def test_new_lease_during_grace_cancels_exit(self):
    manager = self._manager()
    manager.acquire(1)
    manager.release(1)
    self.clock.now += 5
    manager.acquire(2)
    self.clock.now += 100
    self.assertFalse(manager.check())

  def test_acquire_is_idempotent_per_connection(self):
    manager = self._manager()
    manager.acquire(1)
    manager.acquire(1)
    self.assertEqual(manager.lease_count, 1)
    self.assertTrue(manager.release(1))
    self.assertFalse(manager.release(1))

  def test_release_without_lease_does_not_restart_grace(self):
    manager = self._manager()
    manager.acquire(1)
    self.clock.now += 100
    self.assertFalse(manager.release(2))
    self.assertFalse(manager.check())

  def test_idle_timeout(self):
    manager = self._manager(idle_timeout=60)
    manager.acquire(1)
    self.clock.now += 59
    self.assertFalse(manager.check())
    self.clock.now += 1
    self.assertTrue(manager.check())
    self.assertIn("tool call", self.expired[0])

  def test_running_call_is_not_idle(self):
    manager = self._manager(idle_timeout=60)
    manager.acquire(1)
    manager.call_started()
    self.clock.now += 600
    self.assertFalse(manager.check())
    manager.call_finished()
    self.clock.now += 59
    self.assertFalse(manager.check())
    self.clock.now += 1
    self.assertTrue(manager.check())

  def test_idle_timeout_off_by_default(self):
    manager = self._manager()
    manager.acquire(1)
    self.clock.now += 10**6
    self.assertFalse(manager.check())

  def test_explicit_release_of_last_lease_exits_now(self):
    manager = self._manager()
    manager.acquire(1)
    manager.acquire(2)
    self.assertEqual(manager.release_explicitly(1), (True, 1))
    self.assertEqual(self.expired, [])
    self.assertEqual(manager.release_explicitly(2), (True, 0))
    self.assertEqual(len(self.expired), 1)
    self.assertIn("last lease was released", self.expired[0])
    self.assertTrue(manager.check())
    self.assertEqual(len(self.expired), 1)

  def test_explicit_release_without_lease_does_not_exit(self):
    manager = self._manager()
    self.assertEqual(manager.release_explicitly(1), (False, 0))
    self.assertEqual(self.expired, [])

  def test_expires_only_once(self):
    manager = self._manager(grace=0)
    self.assertTrue(manager.check())
    self.assertTrue(manager.check())
    self.assertEqual(len(self.expired), 1)

  def test_watch_returns_after_expiry(self):
    manager = self._manager()
    self.clock.now += 10
    asyncio.run(asyncio.wait_for(manager.watch(interval=0), 5))
    self.assertEqual(len(self.expired), 1)


class TestConfigure(unittest.TestCase):
  """Tests for lease.configure and the per-connection helpers."""

  def tearDown(self):
    lease._manager = None

  def test_spawner_and_non_headless_have_no_manager(self):
    stop = mock.Mock()
    self.assertIsNone(lease.configure({}, True, stop))
    self.assertIsNone(
        lease.configure({"headless_lifetime": "spawner"}, True, stop)
    )
    self.assertIsNone(
        lease.configure({"headless_lifetime": "lease"}, False, stop)
    )
    self.assertIsNone(lease.current())

  def test_unknown_lifetime_warns_once(self):
    lease._warned_lifetime.discard("forever")
    with self.assertLogs(lease.logger, "WARNING") as cm:
      self.assertIsNone(
          lease.configure({"headless_lifetime": "forever"}, True, mock.Mock())
      )
      lease.configure({"headless_lifetime": "forever"}, True, mock.Mock())
    self.assertEqual(len(cm.output), 1)

  def test_lease_mode_uses_config_values(self):
    manager = lease.configure(
        {
            "headless_lifetime": "LEASE",
            "headless_lease_grace": 5,
            "headless_idle_timeout": 60,
        },
        True,
        mock.Mock(),
    )
    self.assertIs(lease.current(), manager)
    self.assertEqual((manager.grace, manager.idle_timeout), (5.0, 60.0))

  def test_current_connection_helpers(self):
    manager = lease.configure({"headless_lifetime": "lease"}, True, mock.Mock())

    def as_connection(connection, func):
      context = contextvars.copy_context()
      context.run(rpc._connection_var.set, connection)
      return context.run(func)

    self.assertFalse(lease.acquire_current())  # Not an RPC call.
    self.assertTrue(as_connection(7, lease.acquire_current))
    self.assertEqual(manager.lease_count, 1)
    self.assertEqual(
        as_connection(8, lease.release_current),
        {"released": False, "remaining": 1},
    )
    self.assertEqual(
        as_connection(7, lease.release_current),
        {"released": True, "remaining": 0},
    )
    self.assertEqual(manager.lease_count, 0)

  def test_helpers_without_lease_mode(self):
    context = contextvars.copy_context()
    context.run(rpc._connection_var.set, 7)
    self.assertFalse(context.run(lease.acquire_current))
    self.assertEqual(
        context.run(lease.release_current), {"released": False, "remaining": 0}
    )


class TestLeaseOverRPC(unittest.IsolatedAsyncioTestCase):
  """Leases held by real RPC connections."""

  async def asyncSetUp(self):
    self.manager = lease.configure(
        {"headless_lifetime": "lease"}, True, mock.Mock()
    )
    self.addCleanup(setattr, lease, "_manager", None)

    async def lease_acquire():
      return lease.acquire_current()

    async def lease_release():
      return lease.release_current()

    self.rpc_server = rpc.RPCServer(
        {"lease_acquire": lease_acquire, "lease_release": lease_release}
    )
    self.server = await self.rpc_server.start_tcp("127.0.0.1", 0)
    self.port = self.server.sockets[0].getsockname()[1]
    self.addAsyncCleanup(self._stop_server)

  async def _stop_server(self):
    self.server.close()
    await self.server.wait_closed()

  async def _client(self) -> rpc.RPCClient:
    client = rpc.RPCClient()
    await client.connect_tcp("127.0.0.1", self.port)
    return client

  async def _wait_for_count(self, count: int) -> None:
    for _ in range(200):
      if self.manager.lease_count == count:
        return
      await asyncio.sleep(0.01)
    self.assertEqual(self.manager.lease_count, count)

  async def test_closing_connection_releases_lease(self):
    first = await self._client()
    second = await self._client()
    self.assertTrue(await first.call("lease_acquire", {}))
    self.assertTrue(await second.call("lease_acquire", {}))
    self.assertEqual(self.manager.lease_count, 2)
    await first.close()
    await self._wait_for_count(1)
    await second.close()
    await self._wait_for_count(0)

  async def test_release_ends_only_own_lease(self):
    first = await self._client()
    second = await self._client()
    await first.call("lease_acquire", {})
    await second.call("lease_acquire", {})
    self.assertEqual(
        await first.call("lease_release", {}),
        {"released": True, "remaining": 1},
    )
    self.assertEqual(
        await first.call("lease_release", {}),
        {"released": False, "remaining": 1},
    )
    self.assertEqual(self.manager.lease_count, 1)
    await first.close()
    await second.close()


class TestRegistryRecord(unittest.TestCase):

  def test_instance_capability_is_advertised(self):
    with tempfile.TemporaryDirectory() as tmp_dir:
      registry = RegistryManager(tmp_dir)
      path = registry.register(
          "uds", "/tmp/db.sock", name="db1", capabilities=(lease.CAPABILITY,)
      )
      try:
        record = json.loads(path.read_text(encoding="utf-8"))
      finally:
        registry.cleanup()
    self.assertEqual(
        record["capabilities"],
        sorted(set(protocol.BACKEND_CAPABILITIES) | {"headless_lease"}),
    )

  def test_no_instance_capability_by_default(self):
    self.assertNotIn(
        protocol.HEADLESS_LEASE, protocol.record_fields()["capabilities"]
    )


class TestGatewayLeases(unittest.IsolatedAsyncioTestCase):
  """Tests for the gateway's handling of lease backends."""

  async def asyncSetUp(self):
    self._clear()
    self.addCleanup(self._clear)
    self._tmp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp_dir.cleanup)
    patcher = mock.patch("gateway.forward.RPCClient")
    self.client = patcher.start().return_value
    self.addCleanup(patcher.stop)
    self.client.connect_uds = mock.AsyncMock()
    self.client.close = mock.AsyncMock()
    self.client.call = mock.AsyncMock(return_value=True)
    for name, value in (
        ("_is_process_running", True),
        ("_kill_process_gracefully", None),
    ):
      patcher = mock.patch.object(
          forward,
          name,
          mock.AsyncMock() if value is None else mock.Mock(return_value=value),
      )
      setattr(self, name, patcher.start())
      self.addCleanup(patcher.stop)

  def _clear(self):
    for state in (
        forward._global_clients,
        forward._global_metadata,
        forward._global_capabilities,
        forward._incompatible_backends,
        forward._global_client_state,
        forward._global_database_id_to_pid,
        forward._backend_events,
        forward._leased,
    ):
      state.clear()
    forward._headless_manager.spawned_instances.clear()

  async def _connect(self, backend_id, capabilities, spawned):
    if spawned:
      forward._headless_manager.register(backend_id, 4242)
    record = {
        "pid": 4242,
        "channel": "uds",
        "address": "/nonexistent/test.sock",
        "name": backend_id,
        "metadata": {},
        "protocol_version": protocol.PROTOCOL_VERSION,
        "capabilities": capabilities,
    }
    path = pathlib.Path(self._tmp_dir.name) / f"{backend_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    await forward.connect_to_backend(path)
    self.assertIn(backend_id, forward._global_clients)

  def _methods(self):
    return [c.kwargs.get("method") for c in self.client.call.await_args_list]

  async def test_spawner_takes_lease_on_connect(self):
    await self._connect("db", ["headless_lease"], spawned=True)
    self.assertEqual(self._methods(), ["lease_acquire"])
    self.assertIn("db", forward._leased)

  async def test_other_gateway_takes_lease_on_first_call(self):
    await self._connect("db", ["headless_lease"], spawned=False)
    self.assertEqual(self._methods(), [])
    await forward.forward_to("db", "get_metadata", {})
    await forward.forward_to("db", "get_metadata", {})
    self.assertEqual(
        self._methods(), ["lease_acquire", "get_metadata", "get_metadata"]
    )

  async def test_failed_acquire_does_not_fail_the_call(self):
    await self._connect("db", ["headless_lease"], spawned=False)

    async def call(method, params, **kwargs):
      del params, kwargs
      if method == "lease_acquire":
        raise rpc.RPCError("Method not found")
      return "ok"

    self.client.call.side_effect = call
    with self.assertLogs(level="WARNING"):
      self.assertEqual(await forward.forward_to("db", "get_metadata", {}), "ok")
    self.assertNotIn("db", forward._leased)

  async def test_no_lease_without_capability(self):
    await self._connect("db", [], spawned=True)
    await forward.forward_to("db", "get_metadata", {})
    self.assertEqual(self._methods(), ["get_metadata"])

  async def test_disconnect_leaves_lease_backend_running(self):
    await self._connect("db", ["headless_lease"], spawned=True)
    await forward.disconnect_backend("db")
    self.assertNotIn("close_database", self._methods())
    self.client.close.assert_awaited()
    self._kill_process_gracefully.assert_not_called()
    self.assertNotIn("db", forward._headless_manager.spawned_instances)
    self.assertNotIn("db", forward._global_database_id_to_pid)

  async def test_disconnect_closes_spawner_backend_as_before(self):
    await self._connect("db", [], spawned=True)
    await forward.disconnect_backend("db")
    await asyncio.gather(*forward._background_tasks)
    self.assertIn("close_database", self._methods())
    self._kill_process_gracefully.assert_awaited_once_with(4242)

  async def test_reconnect_takes_lease_again(self):
    await self._connect("db", ["headless_lease"], spawned=False)
    await forward.forward_to("db", "get_metadata", {})
    await self._connect("db", ["headless_lease"], spawned=False)
    self.assertEqual(
        self._methods(), ["lease_acquire", "get_metadata", "lease_acquire"]
    )

  async def test_removed_backend_forgets_lease(self):
    await self._connect("db", ["headless_lease"], spawned=True)
    await forward._backend_removed("db")
    self.assertNotIn("db", forward._leased)

  def _release_returns(self, remaining):
    async def call(method, params, **kwargs):
      del params, kwargs
      if method == "lease_release":
        return {"released": True, "remaining": remaining}
      return True

    self.client.call.side_effect = call

  async def test_headless_close_leaves_shared_instance_open(self):
    await self._connect("db", ["headless_lease"], spawned=True)
    self._release_returns(1)
    await forward.idalib_headless_close("db")
    self.assertEqual(self._methods(), ["lease_acquire", "lease_release"])
    self.assertIn("db", forward._global_clients)
    self.assertNotIn("db", forward._leased)
    self.assertNotIn("db", forward._headless_manager.spawned_instances)
    self._kill_process_gracefully.assert_not_called()

  async def test_headless_close_of_last_lease_waits_for_exit(self):
    await self._connect("db", ["headless_lease"], spawned=True)
    self._release_returns(0)
    self._is_process_running.reset_mock()
    self._is_process_running.side_effect = [True, True, False]
    await forward.idalib_headless_close("db")
    self.assertEqual(self._methods(), ["lease_acquire", "lease_release"])
    self.assertEqual(self._is_process_running.call_count, 3)
    self.assertNotIn("db", forward._global_clients)
    self._kill_process_gracefully.assert_not_called()

  async def test_headless_close_reports_instance_that_does_not_exit(self):
    await self._connect("db", ["headless_lease"], spawned=True)
    self._release_returns(0)
    with mock.patch.object(forward, "_LEASE_EXIT_TIMEOUT", 0.2):
      with self.assertRaisesRegex(Exception, "has not exited"):
        await forward.idalib_headless_close("db")
    self._kill_process_gracefully.assert_not_called()

  async def test_headless_close_without_lease_is_a_no_op(self):
    await self._connect("db", ["headless_lease"], spawned=False)
    await forward.idalib_headless_close("db")
    self.assertEqual(self._methods(), [])


if __name__ == "__main__":
  unittest.main()
