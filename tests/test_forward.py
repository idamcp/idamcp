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
from gateway.forward import _analysis_events
from gateway.forward import _backend_events
from gateway.forward import _background_tasks
from gateway.forward import _global_backend_id_to_instance_id
from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _global_database_id_to_pid
from gateway.forward import _global_instance_id_to_backend_id
from gateway.forward import _global_metadata
from gateway.forward import _global_started_at
from gateway.forward import _headless_manager
from gateway.forward import _is_watcher_active
from gateway.forward import _on_record_deleted
from gateway.forward import available_databases
from gateway.forward import connect_to_backend
from gateway.forward import forward_to
from gateway.forward import HeadlessManager
from gateway.forward import idalib_headless_close
from gateway.forward import lifespan
from gateway.forward import list_available_databases
from shared import registry
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

    with mock.patch("gateway.forward.is_process_running", return_value=False):
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
    with mock.patch("gateway.forward.is_process_running", return_value=False):
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
        mock.patch("gateway.forward.is_process_running", return_value=True),
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

  def test_serialize_search_results_lists_object_fields(self):
    """Test the fields of a request object are listed with descriptions."""
    from gateway.forward import _serialize_search_results
    from fastmcp.tools import Tool
    from shared.types import ReadDataRequest

    def read_data(reqs: list[ReadDataRequest], limit: int = 1) -> None:
      """Reads data."""
      del reqs, limit

    result = _serialize_search_results([Tool.from_function(read_data)])
    self.assertIn("- `reqs` (object[], required)", result)
    self.assertIn("**Fields of each `reqs` item**", result)
    self.assertIn(
        "- `address` (string, required): Address (hex string) of the memory"
        " value to be read",
        result,
    )
    self.assertIn('- `data_type` ("byte" | "word" | "dword"', result)
    self.assertIn("- `size` (integer, default 1): Number of bytes", result)
    # A parameter that isn't an object gets no section.
    self.assertNotIn("`limit` item", result)

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
# Not real processes: the tests mock is_process_running and
# _kill_process_gracefully, so nothing is signalled.
_OLD_PID = 4_999_991
_NEW_PID = 4_999_993


def _iid(label: str) -> str:
  """Returns a well-formed instance ID that stands for a readable label."""
  return label.encode().hex()[:16].ljust(16, "0")


class _BackendTestCase(unittest.IsolatedAsyncioTestCase):
  """Base of the tests that run against in-process RPC backends."""

  async def asyncSetUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.tmp = pathlib.Path(tmp.name)
    self.target = self.tmp / "target.bin"
    self.target.write_bytes(b"\0" * 16)
    # The record of the backend started last; records are named after the
    # instance, so each backend has its own.
    self.record = self.tmp / "none.json"
    self.manager = HeadlessManager(max_instances=4)
    self.alive: set[int] = set()
    self.servers: list[RPCServer] = []
    # The started_at of the backend started last; each one starts later.
    self.started_at = 1000.0
    # A kill ends the process, as the real one does.
    self.kill = mock.AsyncMock(
        name="_kill_process_gracefully", side_effect=self.alive.discard
    )
    for patcher in (
        mock.patch("gateway.forward.REGISTRY_DIR", self.tmp),
        mock.patch("gateway.forward.UDS_DIR", self.tmp),
        mock.patch("gateway.forward._headless_manager", self.manager),
        mock.patch(
            "gateway.forward.is_process_running", self.alive.__contains__
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
    try:
      # The two instance maps mirror each other and cover the connections.
      self.assertEqual(
          _global_instance_id_to_backend_id,
          {iid: db for db, iid in _global_backend_id_to_instance_id.items()},
      )
      self.assertEqual(
          set(_global_backend_id_to_instance_id), set(_global_metadata)
      )
    finally:
      self._clear_gateway_state()

  def _clear_gateway_state(self):
    _global_clients.clear()
    _global_metadata.clear()
    _global_backend_id_to_instance_id.clear()
    _global_instance_id_to_backend_id.clear()
    _global_database_id_to_pid.clear()
    _global_client_state.clear()
    _backend_events.clear()
    _analysis_events.clear()
    _global_started_at.clear()

  async def _start_backend(
      self,
      name: str,
      pid: int,
      in_progress: bool = False,
      disabled: bool = False,
      started_at: float | None = None,
  ) -> RPCServer:
    """Starts a backend whose whoami returns name, and writes its record.

    Args:
      name: What whoami returns; the backend's instance ID is
        _iid(name).
      pid: The PID in the record.
      in_progress: Whether the record says auto-analysis is still running.
      disabled: Whether the record says auto-analysis was disabled.
      started_at: The start time in the record; by default, later than that
        of the backends started before.
    """
    if started_at is None:
      self.started_at += 1.0
      started_at = self.started_at
    server = RPCServer({"whoami": lambda: name, "close_database": lambda: None})
    tcp_server = await server.start_tcp("127.0.0.1", 0)
    self.servers.append(server)
    self.alive.add(pid)
    record = {
        "pid": pid,
        "channel": "tcp",
        "address": tcp_server.sockets[0].getsockname()[1],
        "database_id": _DB,
        "started_at": started_at,
        "auto_analysis_disabled": disabled,
        "metadata": {"filepath": str(self.target)},
    }
    self.record = self.tmp / registry.record_name(
        _iid(name), in_progress
    )
    self.record.write_text(json.dumps(record), encoding="utf-8")
    return server

  def _promote(self) -> pathlib.Path:
    """Renames the in-progress record as a backend does after its analysis."""
    instance_id, in_progress = registry.parse_record_name(self.record.name)
    self.assertTrue(in_progress)
    promoted = self.tmp / registry.record_name(instance_id, False)
    os.replace(self.record, promoted)
    self.record = promoted
    return promoted

  async def _start_new_instance(self) -> None:
    """Starts the new backend, then connects as the watchdog would."""
    await self._start_backend("new", _NEW_PID)
    await connect_to_backend(self.record)

  def _patch_exec(
      self, before_metadata=None, instance_id: str = _iid("new")
  ):
    """Patches the process start; the process prints [MCP_JSON] for _DB.

    Args:
      before_metadata: An optional coroutine function, awaited before spawn()
        gets the [MCP_JSON] line.
      instance_id: The instance_id emitted in [MCP_JSON].
    """
    payload = {"database_id": _DB, "instance_id": instance_id}
    line = f"[MCP_JSON] {json.dumps(payload)}\n".encode()

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

  def _patch_connect(self, hold: asyncio.Event, failures: int = 0):
    """Patches the TCP connect: its first call waits, and some calls fail.

    Args:
      hold: The first call waits for it, so that a connect_to_backend stays
        in the middle of connecting.
      failures: How many of the first calls fail.
    """
    real_connect = forward.RPCClient.connect_tcp
    self.connect_calls = 0

    async def connect_tcp(client, host, port):
      self.connect_calls += 1
      if self.connect_calls == 1:
        await hold.wait()
      if self.connect_calls <= failures:
        raise ConnectionRefusedError
      await real_connect(client, host, port)

    return mock.patch.object(forward.RPCClient, "connect_tcp", connect_tcp)

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

    def register_then_start(database_id, pid, instance_id=None):
      register(database_id, pid, instance_id)
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


class TestSpawnWithBackends(_BackendTestCase):
  """Tests HeadlessManager.spawn() against in-process RPC backends."""

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

  async def test_reopen_after_crash_removes_the_old_record(self):
    """Test that the crashed instance's record doesn't stay behind."""
    await self._crash_old_instance()
    old_record = self.record
    self.assertTrue(old_record.exists())
    await self._reopen(str(self.target))

    # Nothing overwrites it: the new instance's record has another name.
    self.assertNotEqual(self.record, old_record)
    self.assertEqual(list(self.tmp.glob("*.json")), [self.record])
    await self._assert_new_instance_kept()

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

  async def test_lookup_waits_for_a_connect_in_progress(self):
    """Test a second connect for an instance waits for the one under way."""
    await self._start_backend("new", _NEW_PID)
    self.manager.register(_DB, _NEW_PID, _iid("new"))
    hold = asyncio.Event()
    with self._patch_connect(hold):
      # E.g., the watcher's call, then spawn()'s own look at the record.
      first = asyncio.create_task(connect_to_backend(self.record))
      async with asyncio.timeout(5):
        while not self.connect_calls:
          if first.done():
            await first  # Shows why it ended without connecting.
          await asyncio.sleep(0)
      second = asyncio.create_task(forward._connect_to_instance(_iid("new")))
      for _ in range(10):
        await asyncio.sleep(0)
      self.assertFalse(second.done())
      self.assertNotIn(_DB, _global_clients)
      hold.set()
      await asyncio.gather(first, second)

    self.assertEqual(self.connect_calls, 1)
    await self._assert_new_instance_kept()

  async def test_spawn_fails_when_a_failed_connect_gave_the_instance_up(self):
    """Test spawn() doesn't return an instance that is being killed."""
    hold = asyncio.Event()
    register = self.manager.register
    real_connect_to_backend = forward.connect_to_backend
    real_sleep = asyncio.sleep
    calls = 0
    tasks = []

    async def counted_connect_to_backend(record):
      nonlocal calls
      calls += 1
      if calls == 2:
        # spawn() has found the record too; it now waits for the first call.
        hold.set()
      await real_connect_to_backend(record)

    async def watcher_event():
      await self._start_backend("new", _NEW_PID)
      await forward.connect_to_backend(self.record)

    def register_then_start(database_id, pid, instance_id=None):
      register(database_id, pid, instance_id)
      tasks.append(asyncio.create_task(watcher_event()))

    with (
        # The first call's three attempts fail; spawn()'s then succeed.
        self._patch_connect(hold, failures=3),
        self._patch_exec(),
        mock.patch.object(
            self.manager, "register", side_effect=register_then_start
        ),
        mock.patch(
            "gateway.forward.connect_to_backend", counted_connect_to_backend
        ),
        mock.patch(
            "gateway.forward.asyncio.sleep", lambda delay: real_sleep(0)
        ),
    ):
      async with asyncio.timeout(5):
        with self.assertRaisesRegex(ToolError, "Failed to connect"):
          await self.manager.spawn(str(self.target))
        await asyncio.gather(*tasks)
    await asyncio.gather(*_background_tasks, return_exceptions=True)

    self.assertEqual(self.connect_calls, 4)
    self.kill.assert_awaited_once_with(_NEW_PID)
    self.assertNotIn(_DB, _global_clients)
    self.assertEqual(self.manager.spawned_instances, set())

  async def test_reopen_while_a_disconnect_waits_for_calls(self):
    """Test the old instance is forgotten when a new one takes its place."""
    await self._start_backend("old", _OLD_PID)
    old_record = self.record
    await connect_to_backend(old_record)
    old_client = _global_clients[_DB]
    self.addAsyncCleanup(old_client.close)
    state = _global_client_state[_DB]
    state.number_of_ongoing_calls = 1
    disconnect = asyncio.create_task(forward.disconnect_backend(_DB))
    async with asyncio.timeout(5):
      while not state.is_closed:
        await asyncio.sleep(0)

    await self._start_new_instance()
    self.assertEqual(_global_instance_id_to_backend_id, {_iid("new"): _DB})
    async with state.condition:
      state.number_of_ongoing_calls = 0
      state.condition.notify_all()
    await disconnect

    # The old instance's record doesn't stand for the connection any more.
    old_record.unlink()
    await _on_record_deleted(old_record)
    self.assertEqual(await forward_to(_DB, "whoami", {}), "new")

  async def test_instance_id_is_not_shown_to_clients(self):
    """Test neither the open result nor the listing names the instance."""
    with self._patch_exec(before_metadata=self._start_new_instance):
      async with asyncio.timeout(5):
        info = await self.manager.spawn(str(self.target))
    listed = await list_available_databases()
    resource = json.loads(await available_databases())

    self.assertEqual(_global_backend_id_to_instance_id, {_DB: _iid("new")})
    self.assertEqual([entry["database_id"] for entry in listed], [_DB])
    for shown in (info, *listed, *resource):
      self.assertNotIn("instance_id", shown)
      self.assertNotIn(_iid("new"), json.dumps(shown))

  async def test_record_of_new_instance_replaces_connection(self):
    """Test that the record of a new instance replaces the client."""
    await self._start_backend("old", _OLD_PID)
    await connect_to_backend(self.record)
    old_client = _global_clients[_DB]
    await self._start_backend("new", _NEW_PID)
    await connect_to_backend(self.record)

    self.assertIsNot(_global_clients[_DB], old_client)
    self.assertTrue(old_client.is_closed)
    self.assertEqual(await forward_to(_DB, "whoami", {}), "new")

  async def test_stale_record_of_old_instance_keeps_new_connection(self):
    """Test that a dead instance's record doesn't disconnect its successor."""
    await self._start_backend("old", _OLD_PID)
    old_record = self.record
    self.alive.discard(_OLD_PID)
    await self._start_new_instance()
    new_client = _global_clients[_DB]

    await connect_to_backend(old_record)  # E.g., the fallback scan.
    self.assertFalse(old_record.exists())  # Cleaned up as stale.
    await _on_record_deleted(old_record)

    self.assertIs(_global_clients[_DB], new_client)
    self.assertFalse(new_client.is_closed)
    self.assertTrue(self.record.exists())
    self.assertEqual(await forward_to(_DB, "whoami", {}), "new")

  async def test_reopen_when_dead_old_client_not_yet_closed(self):
    """Test reopening when the dead instance's client hasn't noticed EOF yet."""
    await self._start_backend("old", _OLD_PID)
    self.manager.register(_DB, _OLD_PID)
    await connect_to_backend(self.record)
    old_client = _global_clients[_DB]
    # The old process died, but the TCP client has not seen EOF yet.
    self.alive.discard(_OLD_PID)
    self.assertFalse(old_client.is_closed)

    with mock.patch.object(
        old_client, "call", wraps=old_client.call
    ) as old_client_call:
      await self._reopen(str(self.target))

    await self._assert_new_instance_kept()
    self.assertTrue(old_client.is_closed)
    old_client_call.assert_not_called()

  async def test_failed_spawn_cleans_up_instance_record_and_socket(self):
    """Test a failed spawn kills the process and removes its record and sock."""
    iid = _iid("failed")
    record_file = self.tmp / registry.record_name(iid, True)
    sock_file = self.tmp / f"{iid}.sock"
    record_file.write_text("{}", encoding="utf-8")
    sock_file.write_text("", encoding="utf-8")
    self.alive.add(_NEW_PID)

    with (
        self._patch_exec(instance_id=iid),
        mock.patch("gateway.forward._SPAWN_CONNECT_TIMEOUT", 0.02),
    ):
      with self.assertRaisesRegex(ToolError, "timeout"):
        await self.manager.spawn(str(self.target))
      await asyncio.gather(*_background_tasks, return_exceptions=True)

    self.kill.assert_awaited_once_with(_NEW_PID)
    self.assertFalse(record_file.exists())
    self.assertFalse(sock_file.exists())

  async def test_older_record_does_not_replace_a_live_instance(self):
    """Test a leftover record of an earlier instance changes nothing."""
    await self._start_backend("new", _NEW_PID)
    self.manager.register(_DB, _NEW_PID, _iid("new"))
    await connect_to_backend(self.record)
    new_client = _global_clients[_DB]
    new_record = self.record
    # Its process looks alive (e.g., the PID was reused), and it would even
    # answer, but it started earlier.
    await self._start_backend("ghost", _OLD_PID, started_at=1.0)

    with mock.patch(
        "gateway.forward.RPCClient", wraps=forward.RPCClient
    ) as client_cls:
      await connect_to_backend(self.record)
      await asyncio.gather(*_background_tasks, return_exceptions=True)

    client_cls.assert_not_called()
    self.assertIs(_global_clients[_DB], new_client)
    self.assertFalse(new_client.is_closed)
    self.assertTrue(new_record.exists())
    self.record = new_record
    await self._assert_new_instance_kept()

  async def test_newer_record_replaces_a_dead_or_older_instance(self):
    """Test a later start, or a dead connected instance, is replaced."""
    await self._start_backend("old", _OLD_PID, started_at=5.0)
    await connect_to_backend(self.record)
    # An earlier start replaces the connection once the old process is gone.
    self.alive.discard(_OLD_PID)
    await self._start_backend("new", _NEW_PID, started_at=1.0)
    await connect_to_backend(self.record)
    self.assertEqual(await forward_to(_DB, "whoami", {}), "new")
    self.assertEqual(_global_started_at[_DB], 1.0)

    await self._start_backend("newer", _OLD_PID, started_at=2.0)
    await connect_to_backend(self.record)
    self.assertEqual(await forward_to(_DB, "whoami", {}), "newer")

  async def test_failing_record_of_another_instance_keeps_spawned_one(self):
    """Test a record that can't be connected doesn't kill another instance."""
    # The spawned instance has registered its PID but not connected yet.
    self.alive.add(_NEW_PID)
    self.manager.register(_DB, _NEW_PID, _iid("new"))
    # A leftover record of the same database: its PID is alive, but nothing
    # listens at its address.
    server = await self._start_backend("ghost", _OLD_PID)
    self.servers.remove(server)
    await server.close()
    ghost_record = self.record

    with mock.patch("gateway.forward.asyncio.sleep", mock.AsyncMock()):
      await connect_to_backend(ghost_record)
    await asyncio.gather(*_background_tasks, return_exceptions=True)

    self.kill.assert_not_called()
    self.assertEqual(self.manager.spawned_instances, {_DB})
    self.assertEqual(_global_database_id_to_pid, {_DB: _NEW_PID})
    self.assertFalse(ghost_record.exists())  # Removed as unusable.

  async def test_record_without_address_is_removed(self):
    """Test a record that names no address is removed without connecting."""
    await self._start_backend("new", _NEW_PID)
    entry = json.loads(self.record.read_text(encoding="utf-8"))
    del entry["address"]
    self.record.write_text(json.dumps(entry), encoding="utf-8")

    with (
        mock.patch.object(forward.RPCClient, "connect_tcp") as connect_tcp,
        self.assertLogs(level="ERROR") as logs,
    ):
      await connect_to_backend(self.record)

    self.assertIn("the record has no address", "\n".join(logs.output))
    connect_tcp.assert_not_called()
    self.assertNotIn(_DB, _global_clients)
    self.assertFalse(self.record.exists())

  async def test_unregister_ignores_another_instance(self):
    """Test unregister() acts only for the registered instance."""
    self.alive.add(_NEW_PID)
    self.manager.register(_DB, _NEW_PID, _iid("new"))
    self.assertTrue(self.manager.owns(_DB, _iid("new")))
    self.assertTrue(self.manager.owns(_DB, None))
    self.assertFalse(self.manager.owns(_DB, _iid("other")))
    self.assertTrue(self.manager.owns("unknown_db", _iid("other")))

    await self.manager.unregister(_DB, _iid("other"))
    self.assertEqual(self.manager.spawned_instances, {_DB})
    self.assertEqual(_global_database_id_to_pid, {_DB: _NEW_PID})

    await self.manager.unregister(_DB, _iid("new"))
    await asyncio.gather(*_background_tasks, return_exceptions=True)
    self.assertEqual(self.manager.spawned_instances, set())
    self.kill.assert_awaited_once_with(_NEW_PID)
    # Nothing is remembered: a later instance may register under the name.
    self.assertTrue(self.manager.owns(_DB, _iid("other")))

    # With instance_id omitted, unregister cleans up the registered instance.
    sock_file = self.tmp / f"{_iid('unnamed')}.sock"
    sock_file.write_text("", encoding="utf-8")
    self.alive.add(_NEW_PID)
    self.kill.reset_mock()
    self.manager.register(_DB, _NEW_PID, _iid("unnamed"))
    await self.manager.unregister(_DB)
    await asyncio.gather(*_background_tasks, return_exceptions=True)
    self.kill.assert_awaited_once_with(_NEW_PID)
    self.assertFalse(sock_file.exists())

  async def test_record_without_start_time_is_not_used(self):
    """Test a record that lacks started_at is treated as unreadable."""
    await self._start_backend("new", _NEW_PID)
    data = json.loads(self.record.read_text())
    del data["started_at"]
    self.record.write_text(json.dumps(data), encoding="utf-8")
    with self.assertLogs(level="ERROR"):
      await connect_to_backend(self.record)
    self.assertNotIn(_DB, _global_clients)

  async def test_spawn_finds_the_record_without_a_watcher_event(self):
    """Test spawn() connects by itself when no event announces the record."""

    async def start():  # Writes the record; nobody calls connect_to_backend.
      await self._start_backend("new", _NEW_PID)

    with self._patch_exec(before_metadata=start):
      async with asyncio.timeout(5):
        info = await self.manager.spawn(str(self.target))

    self.assertEqual(info["auto_analysis_status"], "done")
    await self._assert_new_instance_kept()

  async def test_spawn_reports_the_backend_stderr(self):
    """Test a failed connection reports what the backend printed."""
    self.alive.add(_NEW_PID)
    stderr = mock.Mock(read=mock.AsyncMock(return_value=b"idalib: no license"))
    payload = json.dumps({"database_id": _DB, "instance_id": _iid("new")})
    line = f"[MCP_JSON] {payload}\n".encode()
    process = mock.Mock(
        pid=_NEW_PID,
        stdout=mock.Mock(readline=mock.AsyncMock(return_value=line)),
        stderr=stderr,
    )

    async def fail_to_connect(database_id, pid, instance_id=None):
      # As connect_to_backend does when the record can't be used.
      del pid
      await self.manager.unregister(database_id, instance_id)

    register = self.manager.register

    def register_then_fail(database_id, pid, instance_id=None):
      register(database_id, pid, instance_id)
      asyncio.get_running_loop().create_task(
          fail_to_connect(database_id, pid, instance_id)
      )

    with (
        mock.patch(
            "asyncio.create_subprocess_exec",
            mock.AsyncMock(return_value=process),
        ),
        mock.patch.object(
            self.manager, "register", side_effect=register_then_fail
        ),
    ):
      with self.assertRaisesRegex(ToolError, "stderr: idalib: no license"):
        async with asyncio.timeout(5):
          await self.manager.spawn(str(self.target))

  async def test_spawn_fails_fast_when_process_exits_before_registering(self):
    """Test spawn() breaks early with stderr if the process exits right away."""
    sock_file = self.tmp / f"{_iid('crashed')}.sock"
    sock_file.write_text("", encoding="utf-8")
    stderr = mock.Mock(read=mock.AsyncMock(return_value=b"AF_UNIX too long"))
    payload = json.dumps(
        {"database_id": _DB, "instance_id": _iid("crashed")}
    )
    line = f"[MCP_JSON] {payload}\n".encode()
    process = mock.Mock(
        pid=_NEW_PID,
        returncode=1,
        stdout=mock.Mock(readline=mock.AsyncMock(return_value=line)),
        stderr=stderr,
    )
    with mock.patch(
        "asyncio.create_subprocess_exec", mock.AsyncMock(return_value=process)
    ):
      with self.assertRaisesRegex(ToolError, "stderr: AF_UNIX too long"):
        async with asyncio.timeout(2):
          await self.manager.spawn(str(self.target))

    self.assertEqual(self.manager.spawned_instances, set())
    self.assertFalse(sock_file.exists())

  def test_cleanup_stale_instance_removes_socket_without_record(self):
    """Test _cleanup_stale_instance unlinks <iid>.sock without a record."""
    sock_file = self.tmp / f"{_iid('orphan')}.sock"
    sock_file.write_text("", encoding="utf-8")
    forward._cleanup_stale_instance(_iid("orphan"))
    self.assertFalse(sock_file.exists())


class TestAutoAnalysisStatus(_BackendTestCase):
  """Tests how the gateway tracks a backend's auto-analysis."""

  def _status(self) -> str:
    return _global_metadata[_DB]["auto_analysis_status"]

  def test_record_names(self):
    """Test record names round-trip, and what else is in the directory."""
    iid = "0123456789abcdef"
    self.assertEqual(registry.record_name(iid, False), f"ida-{iid}.json")
    self.assertEqual(registry.record_name(iid, True), f"analyzing-{iid}.json")
    for in_progress in (False, True):
      name = registry.record_name(iid, in_progress)
      self.assertTrue(registry.is_record_name(name))
      self.assertEqual(registry.parse_record_name(name), (iid, in_progress))
    # Other files in the registry directory, e.g., the temporary file that a
    # record is written to, a record of an old naming, or an ID that no
    # backend generates.
    for name in (
        "tmpk3_x9a",
        f"{iid}.json",
        f"ida_{iid}.json",
        "notes.json",
        "ida-.json",
        "analyzing-.json",
        f"ida-{iid}.json.bak",
        f"ida-{iid}",
        f"ida-{iid[:15]}.json",
        f"ida-{iid}0.json",
        "ida-0123456789abcdeg.json",
        f"ida-{iid}.json\n",
        f"ida-{iid.upper()}.json",
        f"IDA-{iid}.json",
        f"ANALYZING-{iid}.json",
        f"other-{iid}.json",
    ):
      self.assertFalse(registry.is_record_name(name), name)
      with self.assertRaises(ValueError):
        registry.parse_record_name(name)
    # Only records are listed, and only files.
    listed = [registry.record_name(iid, True), registry.record_name(iid, False)]
    for name in (*listed, "notes.json", "tmpk3_x9a"):
      (self.tmp / name).write_text("{}", encoding="utf-8")
    (self.tmp / registry.record_name("f" * 16, False)).mkdir()
    self.assertEqual(
        [p.name for p in registry.list_records(self.tmp)], sorted(listed)
    )
    self.assertEqual(registry.list_records(self.tmp / "missing"), [])

  async def test_status_follows_the_record(self):
    """Test the status for a plain, a prefixed, and a disabled record."""
    for kwargs, expected in (
        ({}, "done"),
        ({"in_progress": True}, "in_progress"),
        ({"disabled": True}, "disabled"),
    ):
      with self.subTest(kwargs=kwargs):
        await self._start_backend(expected, _NEW_PID, **kwargs)
        await connect_to_backend(self.record)
        self.assertEqual(self._status(), expected)
        self.assertEqual(
            _global_backend_id_to_instance_id[_DB], _iid(expected)
        )
        self.assertEqual(await forward_to(_DB, "whoami", {}), expected)

  async def test_promotion_updates_status_without_reconnecting(self):
    """Test a renamed record ends the analysis on the same connection."""
    await self._start_backend("new", _NEW_PID, in_progress=True)
    with mock.patch(
        "gateway.forward.RPCClient", wraps=forward.RPCClient
    ) as client_cls:
      await connect_to_backend(self.record)
      client = _global_clients[_DB]
      self.assertEqual(self._status(), "in_progress")
      old_record = self.record

      await connect_to_backend(self._promote())
      self.assertEqual(self._status(), "done")
      # A late event for the old name changes nothing.
      await connect_to_backend(old_record)
      await _on_record_deleted(old_record)

    self.assertEqual(self._status(), "done")
    self.assertIs(_global_clients[_DB], client)
    self.assertFalse(client.is_closed)
    self.assertEqual(client_cls.call_count, 1)

  async def test_deleted_record_disconnects_its_instance_only(self):
    """Test only the connected instance's last record disconnects it."""
    await self._start_backend("new", _NEW_PID, in_progress=True)
    await connect_to_backend(self.record)
    client = _global_clients[_DB]

    await _on_record_deleted(
        self.tmp / registry.record_name(_iid("other"), False)
    )
    self.assertIs(_global_clients.get(_DB), client)

    self.alive.discard(_NEW_PID)  # Nothing to signal.
    self.record.unlink()
    await _on_record_deleted(self.record)
    self.assertNotIn(_DB, _global_clients)
    self.assertTrue(client.is_closed)

  async def test_database_is_listed_as_busy_while_in_progress(self):
    """Test the listing shows a database as busy until its analysis ends."""
    await self._start_backend("new", _NEW_PID, in_progress=True)
    await connect_to_backend(self.record)

    dbs = await list_available_databases()
    self.assertEqual(
        [(d["auto_analysis_status"], d.get("busy")) for d in dbs],
        [("in_progress", True)],
    )
    (shown,) = json.loads(await available_databases())
    self.assertIs(shown["busy"], True)

    self._promote()
    dbs = await list_available_databases()
    self.assertEqual(
        [(d["auto_analysis_status"], d.get("busy")) for d in dbs],
        [("done", False)],
    )

  async def test_only_an_in_progress_record_counts_as_renamed(self):
    """Test a plain record that is gone isn't taken for a renamed one."""
    for name, gone in (
        ("connect_to_backend", connect_to_backend),
        ("_on_record_deleted", _on_record_deleted),
    ):
      with self.subTest(name):
        await self._start_backend("new", _NEW_PID)
        await connect_to_backend(self.record)
        client = _global_clients[_DB]
        # Not something a backend does: its record never goes back to the
        # in-progress name.
        stray = self.tmp / registry.record_name(_iid("new"), True)
        stray.write_text("{}", encoding="utf-8")
        self.alive.discard(_NEW_PID)  # Nothing to signal.
        self.record.unlink()

        await gone(self.record)

        self.assertNotIn(_DB, _global_clients)
        self.assertTrue(client.is_closed)
        stray.unlink(missing_ok=True)

  async def test_fallback_scan_picks_up_promotion(self):
    """Test the scan visits a connected instance whose record was renamed."""
    await self._start_backend("new", _NEW_PID, in_progress=True)
    with (
        mock.patch("gateway.forward._watcher_active", False),
        mock.patch("gateway.forward._observer", None),
    ):
      dbs = await list_available_databases()
      self.assertEqual(
          [d["auto_analysis_status"] for d in dbs], ["in_progress"]
      )
      client = _global_clients[_DB]
      self._promote()
      dbs = await list_available_databases()
    self.assertEqual([d["auto_analysis_status"] for d in dbs], ["done"])
    self.assertIs(_global_clients[_DB], client)

  async def _spawn(self, wait: float, **start_kwargs):
    """Runs spawn() for a backend that registers before [MCP_JSON]."""

    async def start():
      await self._start_backend("new", _NEW_PID, **start_kwargs)
      await connect_to_backend(self.record)

    with (
        self._patch_exec(before_metadata=start) as exec_mock,
        mock.patch.dict(forward.CONFIG, {"headless_analysis_wait": wait}),
    ):
      async with asyncio.timeout(5):
        info = await self.manager.spawn(
            str(self.target),
            disable_auto_analysis=start_kwargs.get("disabled", False),
        )
    await_args = exec_mock.await_args
    assert await_args is not None
    return info, await_args.args

  async def test_spawn_passes_disable_auto_analysis(self):
    """Test spawn() passes the option on and reports the status."""
    info, argv = await self._spawn(5.0, disabled=True)
    self.assertIn("--disable-auto-analysis", argv)
    self.assertEqual(info["auto_analysis_status"], "disabled")
    self.assertIs(info.get("busy"), False)

    await self.manager.close(_DB)
    info, argv = await self._spawn(5.0)
    self.assertNotIn("--disable-auto-analysis", argv)
    self.assertEqual(info["auto_analysis_status"], "done")

  async def test_spawn_waits_for_a_short_analysis(self):
    """Test spawn() returns "done" if the analysis ends within the wait."""

    async def promote_later():
      while _DB not in _analysis_events:
        await asyncio.sleep(0.01)
      await connect_to_backend(self._promote())

    task = asyncio.create_task(promote_later())
    info, _ = await self._spawn(5.0, in_progress=True)
    await task
    self.assertEqual(info["auto_analysis_status"], "done")
    self.assertIs(info.get("busy"), False)
    self.assertNotIn(_DB, _analysis_events)

  async def test_spawn_sees_the_rename_without_a_watcher_event(self):
    """Test spawn() notices the end of the analysis with no event for it."""

    async def promote_later():
      while _DB not in _analysis_events:
        await asyncio.sleep(0.01)
      self._promote()  # Only the rename: nobody calls connect_to_backend.

    task = asyncio.create_task(promote_later())
    info, _ = await self._spawn(5.0, in_progress=True)
    await task
    self.assertEqual(info["auto_analysis_status"], "done")

  async def test_list_sees_the_rename_while_the_watcher_runs(self):
    """Test listing re-checks in-progress backends even with a watcher."""
    await self._start_backend("new", _NEW_PID, in_progress=True)
    await connect_to_backend(self.record)
    client = _global_clients[_DB]
    self._promote()  # The watcher missed this event.
    with (
        mock.patch("gateway.forward._watcher_active", True),
        mock.patch("gateway.forward._observer", mock.Mock()),
        mock.patch(
            "gateway.forward._connect_unconnected_backends"
        ) as fallback_scan,
    ):
      dbs = await list_available_databases()
    fallback_scan.assert_not_called()
    self.assertEqual([d["auto_analysis_status"] for d in dbs], ["done"])
    self.assertIs(_global_clients[_DB], client)

  async def test_spawn_returns_during_a_long_analysis(self):
    """Test spawn() returns "in_progress" after the wait, or with no wait."""
    for wait in (0.05, 0):
      with self.subTest(wait=wait):
        info, _ = await self._spawn(wait, in_progress=True)
        self.assertEqual(info["auto_analysis_status"], "in_progress")
        # Busy, as in the listing, until the analysis ends.
        self.assertIs(info.get("busy"), True)
        self.assertNotIn(_DB, _analysis_events)
        self.assertEqual(await forward_to(_DB, "whoami", {}), "new")
        await self.manager.close(_DB)
        self.record.unlink()

  async def test_spawn_fails_if_the_backend_exits_while_waiting(self):
    """Test spawn() doesn't return a database that has gone away."""

    async def disconnect_later():
      while _DB not in _analysis_events:
        await asyncio.sleep(0.01)
      await forward.disconnect_backend(_DB)

    task = asyncio.create_task(disconnect_later())
    with self.assertRaisesRegex(ToolError, "exited while"):
      await self._spawn(5.0, in_progress=True)
    await task

  async def test_spawn_fails_if_the_backend_crashes_during_analysis(self):
    """Test spawn() detects a crash during analysis with no delete event."""

    async def crash_later():
      while _DB not in _analysis_events:
        await asyncio.sleep(0.01)
      server = self.servers.pop()
      await server.close()
      self.alive.discard(_NEW_PID)

    task = asyncio.create_task(crash_later())
    with self.assertRaisesRegex(ToolError, "exited while"):
      await self._spawn(10.0, in_progress=True)
    await task
    self.assertNotIn(_DB, _global_clients)
    self.assertNotIn(_DB, _global_metadata)
    self.assertEqual(self.manager.spawned_instances, set())
    self.assertFalse(self.record.exists())

  async def test_watcher_events_are_filtered_by_record_name(self):
    """Test only moved and deleted events of record names are acted on."""
    # pylint: disable=g-import-not-at-top
    from watchdog.events import FileCreatedEvent
    from watchdog.events import FileDeletedEvent
    from watchdog.events import FileMovedEvent
    from watchdog.events import FileSystemEventHandler

    # pylint: enable=g-import-not-at-top

    handler = forward.RegistryEventHandler(asyncio.get_running_loop())
    connects: list[pathlib.Path] = []
    deletes: list[pathlib.Path] = []

    async def record_connect(path):
      connects.append(path)

    async def record_delete(path):
      deletes.append(path)

    async def settle():
      for _ in range(5):
        await asyncio.sleep(0.01)

    await self._start_backend("new", _NEW_PID, in_progress=True)
    in_progress_record = self.record
    tmp_file = self.tmp / "tmpk3_x9a"
    other_json = self.tmp / "notes.json"
    other_json.write_text("{}", encoding="utf-8")
    with (
        mock.patch("gateway.forward.connect_to_backend", record_connect),
        mock.patch("gateway.forward._on_record_deleted", record_delete),
    ):
      # A registration: the temporary file is renamed to the record.
      handler.on_moved(FileMovedEvent(str(tmp_file), str(in_progress_record)))
      # A promotion: the record is renamed to its plain name.
      promoted = self._promote()
      handler.on_moved(FileMovedEvent(str(in_progress_record), str(promoted)))
      # Not records: ignored whatever the event.
      handler.on_moved(FileMovedEvent(str(tmp_file), str(other_json)))
      handler.on_moved(FileMovedEvent(str(promoted), str(tmp_file)))
      handler.on_deleted(FileDeletedEvent(str(other_json)))
      handler.on_deleted(FileDeletedEvent(str(tmp_file)))
      # A record that no longer exists when the event is handled.
      gone = self.tmp / registry.record_name(_iid("gone"), False)
      handler.on_moved(FileMovedEvent(str(tmp_file), str(gone)))
      # Created events aren't handled at all, even for a record's name.
      self.assertIs(
          type(handler).on_created, FileSystemEventHandler.on_created
      )
      handler.dispatch(FileCreatedEvent(str(promoted)))
      handler.on_deleted(FileDeletedEvent(str(promoted)))
      await settle()

    self.assertEqual(connects, [in_progress_record, promoted])
    self.assertEqual(deletes, [promoted])


class TestKillAndCleanUp(unittest.IsolatedAsyncioTestCase):
  """Tests the cleanup after a real process had to be killed."""

  async def test_force_killed_instance_files_are_removed(self):
    """Test the record and socket of a process that ignores SIGTERM go."""
    if sys.platform == "win32":
      self.skipTest("needs a process that ignores SIGTERM")
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    tmp_path = pathlib.Path(tmp.name)
    child = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        " print('ready', flush=True); time.sleep(600)",
        stdout=asyncio.subprocess.PIPE,
    )
    self.addAsyncCleanup(child.wait)
    self.addCleanup(lambda: child.returncode is None and child.kill())
    assert child.stdout is not None
    await child.stdout.readline()
    record = tmp_path / registry.record_name(_iid("killed"), True)
    sock = tmp_path / f"{_iid('killed')}.sock"
    record.write_text("{}", encoding="utf-8")
    sock.write_text("", encoding="utf-8")

    with (
        mock.patch("gateway.forward.REGISTRY_DIR", tmp_path),
        mock.patch("gateway.forward.UDS_DIR", tmp_path),
        mock.patch("gateway.forward._KILL_GRACE_SECONDS", 1),
    ):
      async with asyncio.timeout(10):
        await forward._kill_and_clean_up(child.pid, _iid("killed"))

    # The process was still listed right after the kill; the cleanup waited
    # for it to go.
    self.assertFalse(forward.is_process_running(child.pid))
    self.assertFalse(record.exists())
    self.assertFalse(sock.exists())


class TestWatcherFallback(unittest.IsolatedAsyncioTestCase):
  """Tests for filesystem watcher failure handling and fallback scanning."""

  async def asyncSetUp(self):
    self.tmp_dir = tempfile.TemporaryDirectory()
    self.registry_dir = pathlib.Path(self.tmp_dir.name)
    self.servers: list[RPCServer] = []
    _global_clients.clear()
    _global_metadata.clear()
    _global_backend_id_to_instance_id.clear()
    _global_instance_id_to_backend_id.clear()
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
    _global_backend_id_to_instance_id.clear()
    _global_instance_id_to_backend_id.clear()
    _global_database_id_to_pid.clear()
    _global_client_state.clear()
    _backend_events.clear()
    self.tmp_dir.cleanup()

  async def _create_test_backend(self, db_id: str, pid: int = 12345):
    server = RPCServer({"whoami": lambda: db_id})
    tcp_server = await server.start_tcp("127.0.0.1", 0)
    self.servers.append(server)
    port = tcp_server.sockets[0].getsockname()[1]
    instance_id = _iid(db_id)
    record = {
        "pid": pid,
        "channel": "tcp",
        "address": port,
        "database_id": db_id,
        "started_at": 1000.0,
        "auto_analysis_disabled": False,
        "metadata": {"filepath": f"/fake/{db_id}.i64"},
    }
    reg_file = self.registry_dir / registry.record_name(instance_id, False)
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
        mock.patch("gateway.forward.is_process_running", return_value=True),
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
        mock.patch("gateway.forward.is_process_running", return_value=True),
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
        mock.patch("gateway.forward.is_process_running", return_value=True),
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
    self.assertEqual(checked, 39)

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
          {"database_id": "db1", "address": 0x401000, "count": 4},
      )
      _, _, args = mock_forward.await_args.args
      self.assertEqual(args["address"], "0x401000")
      self.assertEqual(args["count"], 4)

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
      # Not IDAMCP_NO_USER_CONFIG, which tests/test_tools.py sets when it is
      # imported: with it, the gateway would ignore IDAMCP_CONFIG.
      env = dict(os.environ, IDAMCP_CONFIG=str(config_path))
      env.pop("IDAMCP_NO_USER_CONFIG", None)
      proc = subprocess.run(
          [sys.executable, "-c", code],
          env=env,
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
