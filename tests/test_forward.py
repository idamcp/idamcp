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
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import fastmcp.exceptions
from fastmcp.exceptions import ToolError
import pydantic
from gateway import forward
from gateway.forward import _backend_events
from gateway.forward import _background_tasks
from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _global_database_id_to_pid
from gateway.forward import _global_metadata
from gateway.forward import _headless_manager
from gateway.forward import _is_watcher_active
from gateway.forward import available_databases
from gateway.forward import connect_to_backend
from gateway.forward import forward_to
from gateway.forward import HeadlessManager
from gateway.forward import idalib_headless_close
from gateway.forward import lifespan
from gateway.forward import list_available_databases
from shared.rpc import RPCServer

# FastMCP 4 wraps a rejected argument in its own ValidationError; FastMCP 3
# lets pydantic's through.
_VALIDATION_ERRORS = (
    fastmcp.exceptions.ValidationError,
    pydantic.ValidationError,
)


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

  def test_build_mcp_transforms_hybrid(self):
    """Test _build_mcp_transforms returns BM25SearchTransform for hybrid."""
    from gateway.forward import _build_mcp_transforms
    from gateway.forward import _serialize_search_results
    from fastmcp.server.transforms.search import BM25SearchTransform
    from shared.config import _DEFAULT_ALWAYS_VISIBLE_TOOLS

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "hybrid"}):
      transforms = _build_mcp_transforms()
      self.assertEqual(len(transforms), 1)
      self.assertIsInstance(transforms[0], BM25SearchTransform)
      self.assertEqual(
          set(transforms[0]._always_visible),
          set(_DEFAULT_ALWAYS_VISIBLE_TOOLS),
      )
      self.assertIs(
          transforms[0]._search_result_serializer, _serialize_search_results
      )

  def test_serialize_search_results(self):
    """Test search results end with the note, also when no tool matched."""
    from gateway.forward import _SEARCH_RESULTS_NOTE
    from gateway.forward import _serialize_search_results
    from fastmcp.tools import Tool

    def rename_addresses(names: list[str]) -> None:
      """Renames addresses."""
      del names

    tool = Tool.from_function(rename_addresses)
    for tools, first_line in (
        ([tool], "### rename_addresses"),
        ([], "No tools matched the query."),
    ):
      with self.subTest(first_line=first_line):
        result = _serialize_search_results(tools)
        self.assertTrue(result.startswith(f"{first_line}\n"))
        self.assertTrue(result.endswith(f"\n\n{_SEARCH_RESULTS_NOTE}"))

  def test_build_mcp_transforms_hybrid_custom_always_visible(self):
    """Test _build_mcp_transforms respects custom always_visible_tools."""
    from gateway.forward import _build_mcp_transforms
    from fastmcp.server.transforms.search import BM25SearchTransform

    custom_tools = ["list_available_databases", "sql_query", "patch_assembly"]
    with mock.patch(
        "gateway.forward.CONFIG",
        {"tool_mode": "hybrid", "always_visible_tools": custom_tools},
    ):
      transforms = _build_mcp_transforms()
      self.assertEqual(len(transforms), 1)
      self.assertIsInstance(transforms[0], BM25SearchTransform)
      self.assertEqual(set(transforms[0]._always_visible), set(custom_tools))

  def test_build_mcp_transforms_code_mode(self):
    """Test _build_mcp_transforms returns CodeMode for code_mode."""
    from gateway.forward import _build_mcp_transforms
    from fastmcp.experimental.transforms.code_mode import CodeMode

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "code_mode"}):
      transforms = _build_mcp_transforms()
      self.assertEqual(len(transforms), 1)
      self.assertIsInstance(transforms[0], CodeMode)

  def test_build_mcp_transforms_full(self):
    """Test _build_mcp_transforms returns empty list for full mode."""
    from gateway.forward import _build_mcp_transforms

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "full"}):
      transforms = _build_mcp_transforms()
      self.assertEqual(transforms, [])

  def test_build_mcp_instructions_hybrid(self):
    """Test hybrid-mode instructions point to search_tools."""
    from gateway.forward import _build_mcp_instructions

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "hybrid"}):
      instructions = _build_mcp_instructions() or ""
    self.assertIn("`search_tools`", instructions)
    self.assertIn("`sql_query`", instructions)

  def test_build_mcp_instructions_full(self):
    """Test full-mode instructions don't mention search_tools."""
    from gateway.forward import _build_mcp_instructions

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "full"}):
      instructions = _build_mcp_instructions() or ""
    self.assertNotIn("search_tools", instructions)
    self.assertIn("`sql_query`", instructions)

  def test_build_mcp_instructions_code_mode(self):
    """Test code_mode gets no instructions."""
    from gateway.forward import _build_mcp_instructions

    with mock.patch("gateway.forward.CONFIG", {"tool_mode": "code_mode"}):
      self.assertIsNone(_build_mcp_instructions())

  def test_shutdown_clients_ignores_sigterm(self):
    """Test shutdown_clients sets SIGTERM handler to SIG_IGN."""
    import signal
    from gateway.forward import shutdown_clients

    _global_clients.clear()
    with mock.patch("signal.signal") as mock_signal:
      shutdown_clients()
      if hasattr(signal, "SIGTERM"):
        mock_signal.assert_called_once_with(signal.SIGTERM, signal.SIG_IGN)


_DB = "c0ffee00"
# Not real processes: the tests mock _is_process_running and
# _kill_process_gracefully, so nothing is signalled.
_OLD_PID = 4_999_991
_NEW_PID = 4_999_993


class TestSpawnWithBackends(unittest.IsolatedAsyncioTestCase):
  """Tests HeadlessManager.spawn() against in-process RPC backends."""

  async def asyncSetUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.tmp = pathlib.Path(tmp.name)
    self.target = self.tmp / "target.bin"
    self.target.write_bytes(b"\0" * 16)
    self.record = self.tmp / f"{_DB}.json"
    self.manager = HeadlessManager(max_instances=4)
    self.alive: set[int] = set()
    self.servers: list[RPCServer] = []
    self.kill = mock.AsyncMock(name="_kill_process_gracefully")
    for patcher in (
        mock.patch("gateway.forward.REGISTRY_DIR", self.tmp),
        mock.patch("gateway.forward._headless_manager", self.manager),
        mock.patch(
            "gateway.forward._is_process_running", self.alive.__contains__
        ),
        mock.patch("gateway.forward._kill_process_gracefully", self.kill),
    ):
      patcher.start()
      self.addCleanup(patcher.stop)
    self._clear_gateway_state()

  async def asyncTearDown(self):
    for client in list(_global_clients.values()):
      await client.close()
    for server in self.servers:
      await server.close()
    await asyncio.gather(*_background_tasks, return_exceptions=True)
    self._clear_gateway_state()

  def _clear_gateway_state(self):
    _global_clients.clear()
    _global_metadata.clear()
    _global_database_id_to_pid.clear()
    _global_client_state.clear()
    _backend_events.clear()

  async def _start_backend(self, name: str, pid: int) -> RPCServer:
    """Starts a backend whose whoami returns name, and writes its record."""
    server = RPCServer({"whoami": lambda: name})
    tcp_server = await server.start_tcp("127.0.0.1", 0)
    self.servers.append(server)
    self.alive.add(pid)
    record = {
        "pid": pid,
        "channel": "tcp",
        "address": tcp_server.sockets[0].getsockname()[1],
        "name": _DB,
        "metadata": {"filepath": str(self.target)},
    }
    self.record.write_text(json.dumps(record), encoding="utf-8")
    return server

  async def _start_new_instance(self) -> None:
    """Starts the new backend, then connects as the watchdog would."""
    await self._start_backend("new", _NEW_PID)
    await connect_to_backend(self.record)

  def _patch_exec(self, before_metadata=None):
    """Patches the process start; the process prints [MCP_JSON] for _DB.

    Args:
      before_metadata: An optional coroutine function, awaited before spawn()
        gets the [MCP_JSON] line.
    """
    line = f"[MCP_JSON] {json.dumps({'database_id': _DB})}\n".encode()

    async def readline():
      if before_metadata is not None:
        await before_metadata()
      return line

    process = mock.Mock(
        pid=_NEW_PID, stdout=mock.Mock(readline=readline), stderr=None
    )
    return mock.patch(
        "asyncio.create_subprocess_exec", mock.AsyncMock(return_value=process)
    )

  async def _assert_new_instance_kept(self):
    self.kill.assert_not_called()
    self.assertEqual(_global_database_id_to_pid, {_DB: _NEW_PID})
    self.assertEqual(self.manager.spawned_instances, {_DB})
    self.assertEqual(await forward_to(_DB, "whoami", {}), "new")

  async def _crash_old_instance(self):
    """Connects an old instance of _DB, then crashes it; returns its client.

    The connection ends, but the record and the gateway state stay.
    """
    old_server = await self._start_backend("old", _OLD_PID)
    self.manager.register(_DB, _OLD_PID)
    await connect_to_backend(self.record)
    old_client = _global_clients[_DB]
    self.servers.remove(old_server)
    await old_server.close()
    self.alive.discard(_OLD_PID)
    async with asyncio.timeout(5):
      while not old_client.is_closed:
        await asyncio.sleep(0.01)
    return old_client

  async def _reopen(self, path: str) -> None:
    """Runs spawn(path); the new instance registers after [MCP_JSON]."""
    # As in a real start, the new instance writes its record after it has
    # printed [MCP_JSON], i.e. after spawn() has registered its PID.
    register = self.manager.register
    tasks = []

    def register_then_start(database_id, pid):
      register(database_id, pid)
      tasks.append(asyncio.create_task(self._start_new_instance()))

    with (
        self._patch_exec(),
        mock.patch.object(
            self.manager, "register", side_effect=register_then_start
        ),
    ):
      async with asyncio.timeout(5):
        await self.manager.spawn(path)
        await asyncio.gather(*tasks)

  async def test_reopen_after_crash_keeps_new_instance(self):
    """Test reopening a crashed instance without closing it first."""
    old_client = await self._crash_old_instance()
    with mock.patch.object(
        old_client, "call", wraps=old_client.call
    ) as old_client_call:
      await self._reopen(str(self.target))

    await self._assert_new_instance_kept()
    # No close_database request goes over the dead connection either.
    old_client_call.assert_not_called()

  async def test_reopen_after_crash_frees_quota(self):
    """Test that a crashed instance doesn't count against max_instances."""
    self.manager.max_instances = 1
    await self._crash_old_instance()
    await self._reopen(str(self.target))
    await self._assert_new_instance_kept()

  async def test_reopen_after_crash_by_another_path(self):
    """Test reopening a crashed instance by a path the records don't name."""
    link = self.tmp / "link.bin"
    try:
      link.symlink_to(self.target)
    except OSError as e:
      self.skipTest(f"cannot create a symlink: {e}")
    await self._crash_old_instance()
    await self._reopen(str(link))
    await self._assert_new_instance_kept()

  async def test_spawn_connected_before_reading_metadata(self):
    """Test spawn() when it connects before it reads [MCP_JSON]."""
    # The gateway's loop was busy while the instance printed [MCP_JSON] and
    # wrote its record, so connect_to_backend ran first.
    with self._patch_exec(before_metadata=self._start_new_instance):
      async with asyncio.timeout(5):
        await self.manager.spawn(str(self.target))

    await self._assert_new_instance_kept()

  async def test_concurrent_connects_share_one_client(self):
    """Test concurrent connect_to_backend calls for one record don't race."""
    await self._start_backend("new", _NEW_PID)
    self.manager.register(_DB, _NEW_PID)
    with mock.patch(
        "gateway.forward.RPCClient", wraps=forward.RPCClient
    ) as client_cls:
      await asyncio.gather(*(connect_to_backend(self.record) for _ in range(3)))
      first_client = _global_clients[_DB]
      # A later call for the same record is a no-op.
      await connect_to_backend(self.record)

    self.assertIs(_global_clients[_DB], first_client)
    # Only the winner's client was created; the others returned before
    # connecting, so nothing was leaked or disconnected.
    self.assertEqual(client_cls.call_count, 1)
    await self._assert_new_instance_kept()

  async def test_record_with_new_pid_replaces_connection(self):
    """Test that a record rewritten by a new process replaces the client."""
    await self._start_backend("old", _OLD_PID)
    await connect_to_backend(self.record)
    old_client = _global_clients[_DB]
    await self._start_backend("new", _NEW_PID)
    await connect_to_backend(self.record)

    self.assertIsNot(_global_clients[_DB], old_client)
    self.assertTrue(old_client.is_closed)
    self.assertEqual(await forward_to(_DB, "whoami", {}), "new")


class TestWatcherFallback(unittest.IsolatedAsyncioTestCase):
  """Tests for filesystem watcher failure handling and fallback scanning."""

  async def asyncSetUp(self):
    self.tmp_dir = tempfile.TemporaryDirectory()
    self.registry_dir = pathlib.Path(self.tmp_dir.name)
    self.servers: list[RPCServer] = []
    _global_clients.clear()
    _global_metadata.clear()
    _global_database_id_to_pid.clear()
    _global_client_state.clear()
    _backend_events.clear()

  async def asyncTearDown(self):
    for client in list(_global_clients.values()):
      await client.close()
    for server in self.servers:
      await server.close()
    await asyncio.gather(*_background_tasks, return_exceptions=True)
    _global_clients.clear()
    _global_metadata.clear()
    _global_database_id_to_pid.clear()
    _global_client_state.clear()
    _backend_events.clear()
    self.tmp_dir.cleanup()

  async def _create_test_backend(self, db_id: str, pid: int = 12345):
    server = RPCServer({"whoami": lambda: db_id})
    tcp_server = await server.start_tcp("127.0.0.1", 0)
    self.servers.append(server)
    port = tcp_server.sockets[0].getsockname()[1]
    record = {
        "pid": pid,
        "channel": "tcp",
        "address": port,
        "name": db_id,
        "metadata": {"filepath": f"/fake/{db_id}.i64"},
    }
    reg_file = self.registry_dir / f"{db_id}.json"
    reg_file.write_text(json.dumps(record), encoding="utf-8")
    return server

  async def test_lifespan_survives_watcher_start_failure(self):
    """Test that lifespan enters and exits cleanly when Observer.start fails."""
    with (
        mock.patch("gateway.forward.REGISTRY_DIR", self.registry_dir),
        mock.patch(
            "gateway.forward.Observer.start",
            side_effect=OSError(28, "No space left on device"),
        ),
    ):
      async with lifespan(None):
        self.assertFalse(_is_watcher_active())

  async def test_list_available_databases_scans_when_watcher_inactive(self):
    """Test list_available_databases connects new backends when inactive."""
    await self._create_test_backend("db_fallback_1")
    with (
        mock.patch("gateway.forward.REGISTRY_DIR", self.registry_dir),
        mock.patch("gateway.forward._is_process_running", return_value=True),
        mock.patch("gateway.forward._watcher_active", False),
        mock.patch("gateway.forward._observer", None),
    ):
      self.assertNotIn("db_fallback_1", _global_clients)
      dbs = await list_available_databases()
      self.assertIn("db_fallback_1", _global_clients)
      db_ids = [d["database_id"] for d in dbs]
      self.assertIn("db_fallback_1", db_ids)

  async def test_available_databases_resource_scans_when_watcher_inactive(self):
    """Test ida://databases resource connects new backends when inactive."""
    await self._create_test_backend("db_fallback_2")
    with (
        mock.patch("gateway.forward.REGISTRY_DIR", self.registry_dir),
        mock.patch("gateway.forward._is_process_running", return_value=True),
        mock.patch("gateway.forward._watcher_active", False),
        mock.patch("gateway.forward._observer", None),
    ):
      self.assertNotIn("db_fallback_2", _global_clients)
      res_str = await available_databases()
      self.assertIn("db_fallback_2", _global_clients)
      res_data = json.loads(res_str)
      db_ids = [d["database_id"] for d in res_data]
      self.assertIn("db_fallback_2", db_ids)

  async def test_list_available_databases_skips_scan_when_watcher_active(self):
    """Test list_available_databases does not scan disk when watcher active."""
    await self._create_test_backend("db_watcher_active")
    with (
        mock.patch("gateway.forward.REGISTRY_DIR", self.registry_dir),
        mock.patch("gateway.forward._is_process_running", return_value=True),
        mock.patch("gateway.forward._watcher_active", True),
        mock.patch(
            "gateway.forward._connect_unconnected_backends"
        ) as mock_connect,
    ):
      with self.assertRaises(ToolError):
        await list_available_databases()
      mock_connect.assert_not_called()
      self.assertNotIn("db_watcher_active", _global_clients)

  def test_is_watcher_active_detects_dead_observer(self):
    """Test _is_watcher_active returns False when observer thread dies."""
    mock_obs = mock.Mock()
    mock_obs.is_alive.return_value = False
    with (
        mock.patch("gateway.forward._watcher_active", True),
        mock.patch("gateway.forward._observer", mock_obs),
    ):
      self.assertFalse(_is_watcher_active())


_DATABASE_ID_KEYS = ("database_id", "database", "db", "db_id", "id")
_ADDRESS_KEYS = ("address", "ea", "addr")
_SQL_KEYS = ("sql", "query", "queries", "sqls")


class TestParameterAliases(unittest.IsolatedAsyncioTestCase):
  """Tests that tools accept parameter aliases."""

  async def asyncSetUp(self):
    # pylint: disable=g-import-not-at-top
    import gateway.patcher  # pylint: disable=unused-import
    import gateway.proxy  # pylint: disable=unused-import
    import gateway.query  # pylint: disable=unused-import

    # pylint: enable=g-import-not-at-top
    self.mcp_server = forward.mcp_server

  async def test_sql_query_accepts_aliases(self):
    """Test sql_query binds every database_id and sql alias."""
    with mock.patch(
        "gateway.query.forward_to",
        new_callable=mock.AsyncMock,
        return_value=[{"rows": []}],
    ) as mock_forward:
      for db_key in _DATABASE_ID_KEYS:
        for sql_key in _SQL_KEYS:
          with self.subTest(db_key=db_key, sql_key=sql_key):
            mock_forward.reset_mock()
            await self.mcp_server.call_tool(
                "sql_query", {db_key: "db1", sql_key: "SELECT 1"}
            )
            mock_forward.assert_awaited_once()
            self.assertEqual(mock_forward.await_args.args[0], "db1")
            self.assertEqual(mock_forward.await_args.args[1], "sql_query")

  async def test_proxied_tool_accepts_database_id_and_address_aliases(self):
    """Test a generated proxy tool binds every database_id and address alias."""
    with mock.patch(
        "gateway.proxy.forward_to",
        new_callable=mock.AsyncMock,
        return_value="int main() {}",
    ) as mock_forward:
      for db_key in _DATABASE_ID_KEYS:
        for addr_key in _ADDRESS_KEYS:
          with self.subTest(db_key=db_key, addr_key=addr_key):
            mock_forward.reset_mock()
            await self.mcp_server.call_tool(
                "decompile_function", {db_key: "db1", addr_key: "0x1000"}
            )
            target, tool_name, args = mock_forward.await_args.args
            self.assertEqual(target, "db1")
            self.assertEqual(tool_name, "decompile_function")
            self.assertEqual(args["database_id"], "db1")
            self.assertEqual(args["address"], "0x1000")
            self.assertEqual(
                set(args), {"database_id", "address", "include_line_prefix"}
            )

  async def test_patch_assembly_accepts_database_id_aliases(self):
    """Test patch_assembly binds every database_id alias."""
    with mock.patch(
        "gateway.patcher.forward_to",
        new_callable=mock.AsyncMock,
        return_value=[],
    ) as mock_forward:
      for db_key in _DATABASE_ID_KEYS:
        with self.subTest(db_key=db_key):
          mock_forward.reset_mock()
          await self.mcp_server.call_tool(
              "patch_assembly", {db_key: "db1", "reqs": []}
          )
          self.assertEqual(mock_forward.await_args.args[0], "db1")

  async def test_idalib_headless_close_accepts_database_id_aliases(self):
    """Test idalib_headless_close binds every database_id alias."""
    for db_key in _DATABASE_ID_KEYS:
      with self.subTest(db_key=db_key):
        _global_database_id_to_pid["db1"] = 1001
        _global_client_state["db1"].is_closed = False
        with mock.patch.object(
            _headless_manager, "close", new_callable=mock.AsyncMock
        ) as mock_close:
          await self.mcp_server.call_tool(
              "idalib_headless_close", {db_key: "db1"}
          )
          mock_close.assert_awaited_once_with("db1")
    _global_database_id_to_pid.clear()
    _global_client_state.clear()

  async def test_idalib_headless_open_accepts_path_aliases(self):
    """Test idalib_headless_open binds every path alias."""
    fake_info = {
        "database_id": "db1",
        "pid": 1001,
        "filepath": "/tmp/test.bin",
        "database_path": "/tmp/test.bin.i64",
        "imagebase": "0x400000",
        "imagesize": "0x1000",
        "sha256": "0" * 64,
        "filesize": "0x1000",
        "filetype": "ELF",
        "bitness": 64,
        "procname": "metapc",
        "is_headless": True,
    }
    path_keys = (
        "path",
        "idb_path",
        "file_path",
        "input_path",
        "filepath",
        "file",
    )
    with mock.patch.object(
        _headless_manager,
        "spawn",
        new_callable=mock.AsyncMock,
        return_value=fake_info,
    ) as mock_spawn:
      for path_key in path_keys:
        with self.subTest(path_key=path_key):
          mock_spawn.reset_mock()
          await self.mcp_server.call_tool(
              "idalib_headless_open", {path_key: "/tmp/test.bin"}
          )
          mock_spawn.assert_awaited_once()
          self.assertEqual(mock_spawn.await_args.args[0], "/tmp/test.bin")

  async def test_hexdump_accepts_aliases(self):
    """Test hexdump binds every database_id, address, and length alias."""
    with mock.patch(
        "gateway.proxy.forward_to",
        new_callable=mock.AsyncMock,
        return_value="00400000: 90",
    ) as mock_forward:
      for db_key in _DATABASE_ID_KEYS:
        for addr_key in _ADDRESS_KEYS:
          for len_key in ("length", "size"):
            with self.subTest(
                db_key=db_key, addr_key=addr_key, len_key=len_key
            ):
              mock_forward.reset_mock()
              await self.mcp_server.call_tool(
                  "hexdump",
                  {db_key: "db1", addr_key: "0x400000", len_key: 64},
              )
              target, tool_name, args = mock_forward.await_args.args
              self.assertEqual(target, "db1")
              self.assertEqual(tool_name, "hexdump")
              self.assertEqual(
                  args,
                  {
                      "database_id": "db1",
                      "address": "0x400000",
                      "length": 64,
                  },
              )

  def test_all_proxied_address_tools_use_address_aliases(self):
    """Test every proxied address parameter uses ADDRESS_ALIASES."""
    # pylint: disable=g-import-not-at-top
    import inspect
    from typing import get_args
    import gateway.proxy
    from shared import types as shared_types

    # pylint: enable=g-import-not-at-top

    checked = 0
    for name, obj in inspect.getmembers(
        gateway.proxy, inspect.iscoroutinefunction
    ):
      sig = inspect.signature(obj)
      if "address" not in sig.parameters:
        continue
      checked += 1
      with self.subTest(tool=name):
        extras = get_args(sig.parameters["address"].annotation)[1:]
        aliases = [
            getattr(m, "validation_alias", None)
            for m in extras
            if getattr(m, "validation_alias", None) is not None
        ]
        self.assertEqual(aliases, [shared_types.ADDRESS_ALIASES])
    self.assertEqual(checked, 38)

  def test_shared_types_fallback_without_pydantic(self):
    """Test shared.types defines dummy Field/AliasChoices without pydantic."""
    # pylint: disable=g-import-not-at-top
    import importlib.util
    import sys
    from typing import Annotated, get_args, get_origin
    from shared import types as shared_types

    # pylint: enable=g-import-not-at-top

    spec = importlib.util.spec_from_file_location(
        "_shared_types_no_pydantic", shared_types.__file__
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {"pydantic": None}):
      spec.loader.exec_module(mod)

    self.assertEqual(mod.ADDRESS_ALIASES, ("address", "ea", "addr"))
    self.assertIs(get_origin(mod.AddressValue), Annotated)
    self.assertIs(get_args(mod.AddressValue)[0], str)
    ann = Annotated[mod.Address, mod.Field(description="desc")]
    self.assertIs(get_origin(ann), Annotated)
    self.assertIs(get_args(ann)[0], str)


class TestIntegerAddresses(unittest.IsolatedAsyncioTestCase):
  """Tests integer address coercion and 53-bit precision bounds."""

  async def asyncSetUp(self):
    # pylint: disable=g-import-not-at-top
    import gateway.patcher  # pylint: disable=unused-import
    import gateway.proxy  # pylint: disable=unused-import
    import gateway.query  # pylint: disable=unused-import

    # pylint: enable=g-import-not-at-top
    self.mcp_server = forward.mcp_server

  async def test_address_tools_accept_safe_integers(self):
    """Test Address parameters accept 0..2^53-1 ints and normalize to hex."""
    # pylint: disable=g-import-not-at-top
    from shared.types import MAX_SAFE_JSON_INT

    # pylint: enable=g-import-not-at-top
    cases = (
        (0, "0x0"),
        (0x401000, "0x401000"),
        (MAX_SAFE_JSON_INT, "0x1fffffffffffff"),
    )
    with mock.patch(
        "gateway.proxy.forward_to",
        new_callable=mock.AsyncMock,
        return_value="int main() {}",
    ) as mock_forward:
      for addr_key in _ADDRESS_KEYS:
        for int_val, expected_hex in cases:
          with self.subTest(addr_key=addr_key, int_val=int_val):
            mock_forward.reset_mock()
            await self.mcp_server.call_tool(
                "decompile_function", {"database_id": "db1", addr_key: int_val}
            )
            _, _, args = mock_forward.await_args.args
            self.assertEqual(args["address"], expected_hex)

  async def test_address_tools_reject_invalid_or_unsafe_integers(self):
    """Test booleans, floats, negative ints, and ints >= 2^53 are rejected."""
    # pylint: disable=g-import-not-at-top
    from shared.types import MAX_SAFE_JSON_INT

    # pylint: enable=g-import-not-at-top
    for bad in (True, False, 4198400.0, -1):
      with self.subTest(bad=bad):
        with self.assertRaises(_VALIDATION_ERRORS):
          await self.mcp_server.call_tool(
              "decompile_function", {"database_id": "db1", "address": bad}
          )

    for unsafe_int in (MAX_SAFE_JSON_INT + 1, 0xFFFFFFFF81000001):
      with self.subTest(unsafe_int=unsafe_int):
        with self.assertRaisesRegex(_VALIDATION_ERRORS, "0x1fffffffffffff"):
          await self.mcp_server.call_tool(
              "decompile_function",
              {"database_id": "db1", "address": unsafe_int},
          )

    # Strings above 2^53-1 remain accepted without precision loss.
    with mock.patch(
        "gateway.proxy.forward_to",
        new_callable=mock.AsyncMock,
        return_value="void kmain() {}",
    ) as mock_forward:
      await self.mcp_server.call_tool(
          "decompile_function",
          {"database_id": "db1", "address": "0xffffffff81000001"},
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["address"], "0xffffffff81000001")

  async def test_range_and_base_address_parameters_accept_integers(self):
    """Test start_ea, end_ea, and base_address accept safe integers."""
    # pylint: disable=g-import-not-at-top
    from shared.load_options import LoadOptions
    from shared.types import MAX_SAFE_JSON_INT

    # pylint: enable=g-import-not-at-top
    with mock.patch(
        "gateway.proxy.forward_to",
        new_callable=mock.AsyncMock,
    ) as mock_forward:
      mock_forward.return_value = "nop"
      await self.mcp_server.call_tool(
          "get_ida_view",
          {"database_id": "db1", "start_ea": 0x401000, "end_ea": 0x401020},
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["start_ea"], "0x401000")
      self.assertEqual(args["end_ea"], "0x401020")

      mock_forward.return_value = {"nodes": [], "edges": []}
      await self.mcp_server.call_tool(
          "get_call_graph_between",
          {"database_id": "db1", "start_ea": 0x401000, "end_ea": 0x402000},
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["start_ea"], "0x401000")
      self.assertEqual(args["end_ea"], "0x402000")

      mock_forward.return_value = {"addresses": []}
      await self.mcp_server.call_tool(
          "search_binary",
          {
              "database_id": "db1",
              "pattern": "90",
              "start_ea": 0x401000,
              "end_ea": 0x402000,
          },
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["start_ea"], "0x401000")
      self.assertEqual(args["end_ea"], "0x402000")

      await self.mcp_server.call_tool(
          "search_text",
          {
              "database_id": "db1",
              "text": "hello",
              "start_ea": 0x401000,
              "end_ea": None,
          },
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["start_ea"], "0x401000")
      self.assertIsNone(args["end_ea"])

      mock_forward.return_value = "success"
      await self.mcp_server.call_tool(
          "make_strings",
          {"database_id": "db1", "start_ea": 0x401000, "end_ea": 0x401010},
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["start_ea"], "0x401000")
      self.assertEqual(args["end_ea"], "0x401010")

      await self.mcp_server.call_tool(
          "make_strings", {"database_id": "db1", "start_ea": 0x401000}
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["start_ea"], "0x401000")
      self.assertEqual(args["end_ea"], "")

    fake_info = {
        "database_id": "db1",
        "pid": 1001,
        "filepath": "/tmp/test.bin",
        "database_path": "/tmp/test.bin.i64",
        "imagebase": "0x10000",
        "imagesize": "0x1000",
        "sha256": "0" * 64,
        "filesize": "0x1000",
        "filetype": "Binary file",
        "bitness": 32,
        "procname": "arm",
        "is_headless": True,
    }
    with mock.patch.object(
        _headless_manager,
        "spawn",
        new_callable=mock.AsyncMock,
        return_value=fake_info,
    ) as mock_spawn:
      await self.mcp_server.call_tool(
          "idalib_headless_open",
          {"path": "/tmp/test.bin", "base_address": 0x10000},
      )
      self.assertEqual(
          mock_spawn.await_args.args[1], LoadOptions(base_address=0x10000)
      )

    with self.assertRaisesRegex(_VALIDATION_ERRORS, "0x1fffffffffffff"):
      await self.mcp_server.call_tool(
          "idalib_headless_open",
          {"path": "/tmp/test.bin", "base_address": MAX_SAFE_JSON_INT + 1},
      )

  async def test_batch_request_addresses_accept_integers(self):
    """Test list and dataclass request address fields accept safe integers."""
    # pylint: disable=g-import-not-at-top
    from shared.types import MAX_SAFE_JSON_INT

    # pylint: enable=g-import-not-at-top
    with mock.patch(
        "gateway.proxy.forward_to",
        new_callable=mock.AsyncMock,
    ) as mock_forward:
      mock_forward.return_value = [{"success": True, "value": "0x1"}]
      await self.mcp_server.call_tool(
          "get_global_variable_value_at_address",
          {"database_id": "db1", "reqs": [0x401000, "0x402000"]},
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["reqs"], ["0x401000", "0x402000"])

      await self.mcp_server.call_tool(
          "read_data",
          {
              "database_id": "db1",
              "reqs": [{"address": 0x401000, "data_type": "dword"}],
          },
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["reqs"][0].address, "0x401000")

      mock_forward.return_value = "success"
      await self.mcp_server.call_tool(
          "rename_addresses",
          {
              "database_id": "db1",
              "reqs": [{"address": 0x401000, "new_name": "main_fn"}],
          },
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["reqs"][0].address, "0x401000")

      await self.mcp_server.call_tool(
          "convert_to_offsets",
          {
              "database_id": "db1",
              "reqs": [{"address": 0x401000, "base": 0x400000}],
          },
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["reqs"][0].address, "0x401000")
      self.assertEqual(args["reqs"][0].base, "0x400000")

    with mock.patch(
        "gateway.patcher.forward_to",
        new_callable=mock.AsyncMock,
        side_effect=[
            [{
                "address": "0x401000",
                "procname": "metapc",
                "bitness": 64,
                "is_be": False,
                "is_thumb": False,
                "symbols": {},
            }],
            "success",
        ],
    ) as mock_patch_forward:
      await self.mcp_server.call_tool(
          "patch_assembly",
          {
              "database_id": "db1",
              "reqs": [{"address": 0x401000, "instructions": "nop"}],
          },
      )
      ctx_args = mock_patch_forward.await_args_list[0].args[2]
      self.assertEqual(ctx_args["reqs"][0].address, "0x401000")

    with self.assertRaisesRegex(_VALIDATION_ERRORS, "0x1fffffffffffff"):
      await self.mcp_server.call_tool(
          "rename_addresses",
          {
              "database_id": "db1",
              "reqs": [
                  {"address": MAX_SAFE_JSON_INT + 1, "new_name": "bad_ea"}
              ],
          },
      )


class TestResponseSizeLimitMiddleware(unittest.IsolatedAsyncioTestCase):
  """Unit tests for ResponseSizeLimitMiddleware on mcp_server."""

  async def asyncSetUp(self):
    self.mcp_server = forward.mcp_server
    self.limit = forward.CONFIG["max_tool_response_bytes"]
    self.assertEqual(self.limit, 8 * 1024 * 1024)
    self.db_id = "test_mw_db"
    self.mock_client = mock.AsyncMock()
    _global_clients[self.db_id] = self.mock_client

  async def asyncTearDown(self):
    _global_clients.pop(self.db_id, None)

  async def test_large_request_is_forwarded(self):
    """Test that requests are not limited, however large."""
    huge_code = "X" * (self.limit + 4096)
    self.mock_client.call.return_value = {
        "result": "", "result_type": "", "stdout": "", "stderr": ""
    }
    res = await self.mcp_server.call_tool(
        "idapython_eval",
        {"database_id": self.db_id, "code": huge_code},
    )
    self.assertFalse(res.is_error)
    self.mock_client.call.assert_awaited_once()
    call_kwargs = self.mock_client.call.await_args.kwargs
    self.assertEqual(call_kwargs["method"], "idapython_eval")
    self.assertEqual(call_kwargs["params"]["code"], huge_code)

  async def test_oversized_string_response_rejected(self):
    """Test that string responses above the limit are rejected."""
    big_s = "A" * (self.limit + 4096)
    self.mock_client.call.return_value = big_s

    res = await self.mcp_server.call_tool(
        "decompile_function",
        {"database_id": self.db_id, "address": "0x1000"},
    )
    self.assertTrue(res.is_error)
    self.assertIn("response payload size", res.content[0].text)

  async def test_oversized_structured_dict_response_rejected(self):
    """Test that dict responses above the limit are rejected."""
    payload = {
        "result": "R" * (self.limit // 2),
        "result_type": "str",
        "stdout": "O" * (self.limit // 2),
        "stderr": "E" * (self.limit // 2),
    }
    self.mock_client.call.return_value = payload

    res = await self.mcp_server.call_tool(
        "idapython_eval",
        {"database_id": self.db_id, "code": "pass"},
    )
    self.assertTrue(res.is_error)
    self.assertIn("response payload size", res.content[0].text)

  async def test_oversized_list_response_rejected(self):
    """Test that list responses above the limit are rejected."""
    # Each item serializes to about 40 characters.
    count = self.limit // 20
    payload = [{"address": hex(i * 4), "type": "call"} for i in range(count)]
    self.mock_client.call.return_value = payload

    res = await self.mcp_server.call_tool(
        "get_xrefs_from",
        {"database_id": self.db_id, "address": "0x1000"},
    )
    self.assertTrue(res.is_error)
    self.assertIn("response payload size", res.content[0].text)

  async def test_batched_sql_query_oversized_rejected(self):
    """Test that a batched sql_query response above the limit is rejected."""
    # Each row serializes to about 35 characters.
    count = self.limit // 16
    payload = [{"rows": [{"id": i, "name": f"func_{i}"} for i in range(count)]}]
    self.mock_client.call.return_value = payload

    res = await self.mcp_server.call_tool(
        "sql_query",
        {"database_id": self.db_id, "sql": "SELECT * FROM functions"},
    )
    self.assertTrue(res.is_error)
    self.assertIn("response payload size", res.content[0].text)

  async def test_idapython_eval_at_the_stdout_limit_passes_middleware(self):
    """Test that idapython_eval with 1 MiB of stdout passes the middleware."""
    payload = {
        "result": "42",
        "result_type": "int",
        "stdout": "O" * (1024 * 1024),
        "stderr": "",
    }
    self.mock_client.call.return_value = payload

    res = await self.mcp_server.call_tool(
        "idapython_eval",
        {"database_id": self.db_id, "code": "print('big')"},
    )
    self.assertFalse(res.is_error)
    self.assertEqual(res.structured_content["result"], "42")

  async def test_all_outputs_at_their_limits_pass_middleware_when_escaped(
      self,
  ):
    """Test that the largest allowed idapython_eval result fits once escaped."""
    # Lines of quotes double in size when JSON-escaped; the backend allows up
    # to 1 MiB in each of stdout, stderr, and result.
    line = '"' * 79 + "\n"
    at_limit = line * (1024 * 1024 // len(line))
    payload = {
        "result": at_limit,
        "result_type": "str",
        "stdout": at_limit,
        "stderr": at_limit,
    }
    self.mock_client.call.return_value = payload

    res = await self.mcp_server.call_tool(
        "idapython_eval",
        {"database_id": self.db_id, "code": "print('big')"},
    )
    self.assertFalse(res.is_error)
    self.assertEqual(res.structured_content["stdout"], at_limit)

  async def test_output_schema_intact_with_middleware(self):
    """Test that tool output_schema is not modified or stripped."""
    tool_dec = await self.mcp_server.get_tool("decompile_function")
    self.assertIsNotNone(tool_dec.output_schema)
    tool_eval = await self.mcp_server.get_tool("idapython_eval")
    self.assertIsNotNone(tool_eval.output_schema)

  async def test_limit_comes_from_max_tool_response_bytes(self):
    """Test that the middleware is installed once with the configured limit."""
    installed = [
        m
        for m in self.mcp_server.middleware
        if isinstance(m, forward.ResponseSizeLimitMiddleware)
    ]
    self.assertEqual(len(installed), 1)
    self.assertEqual(installed[0].limit, self.limit)

    self.mock_client.call.return_value = "A" * 4096
    with mock.patch.object(installed[0], "limit", 1024):
      res = await self.mcp_server.call_tool(
          "decompile_function",
          {"database_id": self.db_id, "address": "0x1000"},
      )
    self.assertTrue(res.is_error)
    self.assertIn(
        "size (at least 4 KiB) exceeded the 1 KiB limit"
        " (max_tool_response_bytes)",
        res.content[0].text,
    )

  def test_zero_limit_installs_no_middleware(self):
    """Test that max_tool_response_bytes 0 leaves the middleware out."""
    # A fresh interpreter is required: the gateway installs the middleware
    # when it is imported.
    with tempfile.TemporaryDirectory() as tmp_dir:
      config_path = pathlib.Path(tmp_dir) / "config.json"
      config_path.write_text(
          json.dumps({
              "registry_dir": f"{tmp_dir}/registry",
              "uds_dir": f"{tmp_dir}/uds",
              "max_tool_response_bytes": 0,
          })
      )
      code = (
          "from gateway import forward\n"
          "print([type(m).__name__ for m in forward.mcp_server.middleware])\n"
      )
      proc = subprocess.run(
          [sys.executable, "-c", code],
          env=dict(os.environ, IDAMCP_CONFIG=str(config_path)),
          cwd=pathlib.Path(__file__).resolve().parent.parent,
          capture_output=True,
          text=True,
          timeout=120,
          check=False,
      )
    self.assertEqual(proc.returncode, 0, proc.stderr)
    self.assertNotIn("ResponseSizeLimitMiddleware", proc.stdout)


if __name__ == "__main__":
  unittest.main()
