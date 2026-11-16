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

"""Unit tests for IDA MCP plugin lifecycle, database teardown, and cache cleanup."""

import asyncio
import contextlib
import importlib
import io
import json
import os
import pathlib
import signal
import sqlite3
import sys
import tempfile
import threading
import time
import types
from typing import Any
import unittest
from unittest import mock

# Mock IDA modules before importing query and plugin modules
MOCKED_MODULES = [
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
    "idaapi",
    "idautils",
    "idc",
]

module_mocks = {}
for module in MOCKED_MODULES:
  if module in sys.modules:
    module_mocks[module] = sys.modules[module]
  else:
    module_mocks[module] = mock.MagicMock()
sys.modules.update(module_mocks)

# Ensure IDB_Hooks, IDP_Hooks, and plugin_t are valid base types
setattr(
    sys.modules["ida_idp"],
    "IDB_Hooks",
    type(
        "IDB_Hooks",
        (),
        {"hook": lambda self: True, "unhook": lambda self: True},
    ),
)
setattr(
    sys.modules["ida_idp"],
    "IDP_Hooks",
    type(
        "IDP_Hooks",
        (),
        {"hook": lambda self: True, "unhook": lambda self: True},
    ),
)
setattr(
    sys.modules["idaapi"],
    "UI_Hooks",
    type(
        "UI_Hooks",
        (),
        {"hook": lambda self: True, "unhook": lambda self: True},
    ),
)
setattr(sys.modules["idaapi"], "plugin_t", object)
setattr(sys.modules["idaapi"], "PLUGIN_KEEP", 2)
setattr(sys.modules["idaapi"], "idb_path", None)
setattr(sys.modules["idaapi"], "is_main_thread", lambda: True)
setattr(sys.modules["idaapi"], "auto_is_ok", lambda: True)
setattr(sys.modules["idaapi"], "inf_is_auto_enabled", lambda: True)
setattr(sys.modules["idaapi"], "is_idaq", lambda: True)
setattr(sys.modules["idaapi"], "get_path", lambda *args: "/tmp/dummy.i64")
setattr(sys.modules["idaapi"], "get_input_file_path", lambda: "/tmp/dummy.bin")
setattr(sys.modules["idc"], "get_idb_path", lambda: "/tmp/dummy.i64")
setattr(sys.modules["ida_netnode"].netnode, "exist", lambda *args: False)
setattr(sys.modules["ida_segment"], "get_segm_qty", lambda: 0)

# Ensure project root is in sys.path
repo_root = pathlib.Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
  sys.path.insert(0, str(repo_root))

from ida_mcp import server as ida_mcp_server
from ida_mcp.core import analysis_state
from ida_mcp.core import ida_thread
from ida_mcp.core import backend_registry
from ida_mcp.core.backend_registry import RegistryManager
from ida_mcp.core.decorators import CancellationToken
from ida_mcp.core.decorators import cancellation_profile
from ida_mcp.core.security import security_manager
from ida_mcp.server import mcp_server_thread, stop_server
from ida_mcp.tools import info
from ida_mcp.tools import query
from ida_mcp.utils import helper
from plugins import ida_mcp_plugin
from plugins.ida_mcp_plugin import _is_batch_mode
from plugins.ida_mcp_plugin import _is_headless
from plugins.ida_mcp_plugin import MCP
import idaapi
from shared import registry
from shared.config import load_config
from shared.rpc import DEFAULT_SHUTDOWN_GRACE
from shared.rpc import RPCClient
from shared.rpc import RPCError
from shared.rpc import RPCServer

MOCK_METADATA = {
    "filepath": "/tmp/dummy.bin",
    "module": "dummy",
    "database_path": "/tmp/dummy.i64",
    "imagebase": "0x400000",
    "imagesize": "0x1000",
    "sha256": "abcdef",
    "filesize": "0x1000",
    "filetype": "ELF",
    "bitness": 64,
    "procname": "metapc",
    "is_headless": False,
}


# A well-formed instance ID for the tests that name a record themselves.
_IID = "0123456789abcdef"


def _wait_for_record(prefix: str = "") -> pathlib.Path | None:
  """Returns the server's registry record once it exists, else None.

  Records are named after the server's instance ID, which is new on every
  start, so the tests look for the one record in their scratch registry.

  Args:
    prefix: The start of the record's name, e.g., the in-progress prefix.
  """
  registry_dir = pathlib.Path(load_config()["registry_dir"])
  for _ in range(50):
    records = [
        f
        for f in registry_dir.glob(f"{prefix}*.json")
        if prefix or not f.name.startswith(registry._IN_PROGRESS_PREFIX)
    ]
    if records:
      return records[0]
    time.sleep(0.1)
  return None


def _is_connection_open(conn: sqlite3.Connection) -> bool:
  try:
    conn.total_changes
    return True
  except (sqlite3.ProgrammingError, sqlite3.OperationalError):
    return False


class TestPluginLifecycle(unittest.TestCase):
  """Tests for plugin initialization, termination, database closing, and cache clearing."""

  def setUp(self):
    helper.get_segments = lambda: []
    # A scratch config keeps the servers these tests start out of the user's
    # registry and socket directories, and keeps sqlite_persistent off so no
    # .db file is written next to the (fake) IDB paths.
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    registry_dir = pathlib.Path(tmp.name) / "registry"
    uds_dir = pathlib.Path(tmp.name) / "uds"
    registry_dir.mkdir()
    uds_dir.mkdir()
    config_path = pathlib.Path(tmp.name) / "idamcp.json"
    config_path.write_text(
        json.dumps({"registry_dir": str(registry_dir), "uds_dir": str(uds_dir)})
    )
    self.addCleanup(load_config.cache_clear)
    env_patch = mock.patch.dict(os.environ, IDAMCP_CONFIG=str(config_path))
    env_patch.start()
    self.addCleanup(env_patch.stop)
    os.environ.pop("IDAMCP_NO_USER_CONFIG", None)  # Restored by patch.dict.
    os.environ.pop("SQLITE_PERSISTENT", None)
    load_config.cache_clear()
    query.close_tables()
    info.clear_caches()
    security_manager.reset()
    analysis_state.reset()

  def tearDown(self):
    query.close_tables()
    info.clear_caches()
    security_manager.reset()
    analysis_state.reset()
    load_config.cache_clear()

  def test_clear_caches(self):
    """Verifies that clear_caches clears all pagination iterator caches."""
    info._function_iterator_cache[(0, "", "")] = iter([1, 2, 3])
    info._global_iterator_cache[(0, "")] = iter([4, 5])
    info._import_iterator_cache[(0,)] = iter([6])
    info._string_iterator_cache[(0, "", "")] = iter([7, 8])

    self.assertGreater(len(info._function_iterator_cache), 0)
    self.assertGreater(len(info._global_iterator_cache), 0)
    self.assertGreater(len(info._import_iterator_cache), 0)
    self.assertGreater(len(info._string_iterator_cache), 0)

    info.clear_caches()

    self.assertEqual(len(info._function_iterator_cache), 0)
    self.assertEqual(len(info._global_iterator_cache), 0)
    self.assertEqual(len(info._import_iterator_cache), 0)
    self.assertEqual(len(info._string_iterator_cache), 0)

  def test_close_tables_lifecycle(self):
    """Verifies that close_tables unhooks hooks, stops the worker thread, and resets state."""
    res = query.init_tables()
    self.assertTrue(res)
    self.assertTrue(query._db_initialized)
    self.assertIsNotNone(query._worker_thread)
    self.assertTrue(query._worker_thread.is_alive())
    self.assertIsNotNone(query._db_hooks)
    self.assertIsNotNone(query._db_idp_hooks)

    rw_conn = query._get_rw_conn()
    self.assertIsNotNone(rw_conn)
    self.assertTrue(_is_connection_open(rw_conn))
    scratch_dir = query._scratch_dir
    self.assertIsNotNone(scratch_dir)
    self.assertTrue((scratch_dir / "idamcp.db").is_file())

    query.close_tables()

    self.assertFalse(query._db_initialized)
    self.assertIsNone(query._worker_thread)
    self.assertIsNone(query._db_hooks)
    self.assertIsNone(query._db_idp_hooks)
    self.assertEqual(len(query._populated_tables), 0)
    self.assertEqual(len(query._db_local.connections), 0)
    self.assertFalse(_is_connection_open(rw_conn))
    self.assertIsNone(query._scratch_dir)
    self.assertFalse(scratch_dir.exists())

    # Idempotent second call should not raise
    query.close_tables()

    # Re-initialization should work cleanly after teardown
    res_reinit = query.init_tables()
    self.assertTrue(res_reinit)
    self.assertTrue(query._db_initialized)
    self.assertIsNotNone(query._worker_thread)
    query.close_tables()

  def test_sqlite_connection_local(self):
    """Verifies SQLiteConnectionLocal tracks connections and thread-local state across threads."""
    tl = query.SQLiteConnectionLocal()
    conn1 = sqlite3.connect(":memory:", check_same_thread=False)
    tl.rw_conn = conn1
    self.assertIn(conn1, tl.connections)
    self.assertTrue(_is_connection_open(conn1))

    conn2_ref = []
    worker_hasattr = []

    ready = threading.Event()
    proceed = threading.Event()

    def worker():
      c = sqlite3.connect(":memory:", check_same_thread=False)
      conn2_ref.append(c)
      tl.ro_conn = c
      ready.set()
      proceed.wait()
      worker_hasattr.append(hasattr(tl, "ro_conn"))

    t = threading.Thread(target=worker)
    t.start()
    ready.wait()

    self.assertEqual(len(conn2_ref), 1)
    conn2 = conn2_ref[0]
    self.assertIn(conn2, tl.connections)
    self.assertEqual(len(tl.connections), 2)
    # Attributes stay per-thread; only the tracking state is shared.
    self.assertFalse(hasattr(tl, "ro_conn"))

    # Close all connections across threads
    tl.close_all_connections()

    self.assertFalse(_is_connection_open(conn1))
    self.assertFalse(_is_connection_open(conn2))
    self.assertFalse(hasattr(tl, "rw_conn"))
    self.assertEqual(len(tl.connections), 0)

    proceed.set()
    t.join()

    # Worker thread should see ro_conn cleared from its thread dict
    self.assertEqual(worker_hasattr, [False])

  def test_security_manager_reset(self):
    """Verifies that security_manager.reset clears enabled tools."""
    security_manager.enable_all_unsafe_tools = True
    security_manager.enabled_unsafe_tools.add("patch_assembly")
    self.assertTrue(security_manager.enable_all_unsafe_tools)
    self.assertIn("patch_assembly", security_manager.enabled_unsafe_tools)

    security_manager.reset()
    self.assertFalse(security_manager.enable_all_unsafe_tools)
    self.assertEqual(len(security_manager.enabled_unsafe_tools), 0)

  @mock.patch("ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA)
  def test_mcp_server_thread_start_and_stop(self, _mock_meta):
    """Verifies mcp_server_thread starts and cleanly shuts down via stop_server."""
    test_id = "test_lifecycle_id"

    # Start server in thread
    t = threading.Thread(target=mcp_server_thread, args=(test_id,), daemon=True)
    t.start()

    # Wait for registry file to appear
    reg_file = _wait_for_record()
    assert reg_file is not None, "Registry file should be created on start"
    entry = json.loads(reg_file.read_text())
    instance_id, in_progress = registry.parse_record_name(reg_file.name)
    self.assertFalse(in_progress)
    self.assertEqual(entry["database_id"], test_id)
    self.assertAlmostEqual(entry["started_at"], time.time(), delta=60)
    self.assertFalse(entry["auto_analysis_disabled"])
    # The record's name carries the instance ID and the status, not its
    # content.
    self.assertNotIn("instance_id", entry["metadata"])
    self.assertNotIn("auto_analysis_status", entry["metadata"])
    if entry["channel"] == "uds":
      self.assertEqual(
          pathlib.Path(entry["address"]).name, f"{instance_id}.sock"
      )

    # Stop the server
    stop_server(test_id)
    t.join(timeout=5.0)
    self.assertFalse(t.is_alive(), "Server thread should terminate cleanly")
    self.assertFalse(reg_file.exists(), "Registry file should be removed on shutdown")

  @mock.patch(
      "ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA
  )
  def test_mcp_server_thread_passes_shutdown_grace(self, _mock_meta):
    """Verifies the RPC server gets mcp_server_thread's shutdown grace."""
    test_id = "test_shutdown_grace_id"
    servers = []

    class RecordingServer(RPCServer):

      def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        servers.append(self)

    # The headless server passes no grace; the plugin passes a shorter one.
    for kwargs, expected in (
        ({}, DEFAULT_SHUTDOWN_GRACE),
        ({"shutdown_grace": 0.3}, 0.3),
    ):
      with self.subTest(kwargs=kwargs):
        servers.clear()
        with mock.patch.object(ida_mcp_server, "RPCServer", RecordingServer):
          t = threading.Thread(
              target=mcp_server_thread,
              args=(test_id,),
              kwargs=kwargs,
              daemon=True,
          )
          t.start()
          _wait_for_record()
          stop_server(test_id)
          t.join(timeout=5.0)
        self.assertFalse(t.is_alive(), "Server thread should terminate")
        self.assertEqual([s.shutdown_grace for s in servers], [expected])

  @mock.patch(
      "ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA
  )
  def test_close_database_replies_before_the_server_stops(self, _mock_meta):
    """Verifies close_database replies even if the server stops right away."""
    test_id = "test_close_database_id"

    t = threading.Thread(target=mcp_server_thread, args=(test_id,), daemon=True)
    t.start()
    reg_file = _wait_for_record()
    assert reg_file is not None, "Registry file should be created"
    entry = json.loads(reg_file.read_text())

    async def call_close_database():
      client = RPCClient()
      if entry["channel"] == "tcp":
        await client.connect_tcp("127.0.0.1", entry["address"])
      else:
        await client.connect_uds(entry["address"])
      try:
        return await client.call("close_database", {})
      finally:
        await client.close()

    def stop():
      # Like the IDA thread when it wins the race: stops the server, then gives
      # it time to shut down before close_database returns. If close_database
      # ran on another thread, the server would close the connection first.
      stop_server(test_id)
      time.sleep(0.1)

    with mock.patch.object(ida_thread, "stop", stop):
      try:
        result = asyncio.run(call_close_database())
      except RPCError as e:
        self.fail(f"close_database got no reply: {e}")

    self.assertIsNone(result)
    t.join(timeout=5.0)
    self.assertFalse(t.is_alive(), "Server thread should terminate cleanly")
    self.assertFalse(reg_file.exists(), "Registry file should be removed")

  @mock.patch("ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA)
  def test_mcp_plugin_term_cleanup(self, _mock_meta):
    """Verifies that MCP.term cleans up all state when database is closed."""
    plugin = MCP()
    plugin.init()

    # Set mock IDB state
    idaapi.idb_path = "/tmp/test.i64"
    info._function_iterator_cache[(0, "", "")] = iter([1])
    query.init_tables()

    # Start a server thread
    test_id = "test_plugin_term_id"

    plugin.hash_str = test_id
    plugin.server_thread = threading.Thread(
        target=mcp_server_thread, args=(test_id,), daemon=True
    )
    plugin._server_started = True
    plugin.server_thread.start()

    # Wait for server to start
    reg_file = _wait_for_record()
    assert reg_file is not None
    self.assertTrue(plugin._server_started)

    # Call term() as IDA would when user closes database
    plugin.term()

    self.assertFalse(plugin._server_started)
    self.assertIsNone(plugin.server_thread)
    self.assertIsNone(plugin.hash_str)
    self.assertFalse(reg_file.exists())
    self.assertFalse(query._db_initialized)
    self.assertEqual(len(info._function_iterator_cache), 0)
    self.assertFalse(hasattr(idaapi, "idb_path") and idaapi.idb_path is not None)

  def test_headless_main_closes_tables_before_closing_database(self):
    """Verifies headless.main cleans up query tables before closing IDA."""
    fake_idapro = mock.MagicMock()
    fake_idapro.open_database.return_value = 0
    order: list[str] = []
    scratch_seen: list[pathlib.Path | None] = []
    handled_signals = (signal.SIGINT, signal.SIGTERM)
    handlers_before = {sig: signal.getsignal(sig) for sig in handled_signals}
    for sig, handler in handlers_before.items():
      if handler is not None:
        self.addCleanup(signal.signal, sig, handler)
    handlers_in_loop: dict[signal.Signals, object] = {}
    loop_idle: list[object] = []

    def on_loop(idle=None):
      loop_idle.append(idle)
      query._get_rw_conn()
      scratch_seen.append(query._scratch_dir)
      handlers_in_loop.update(
          (sig, signal.getsignal(sig)) for sig in handled_signals
      )

    def on_close_db():
      order.append("close_database")
      self.assertIsNone(query._scratch_dir)

    fake_idapro.close_database.side_effect = on_close_db

    with tempfile.NamedTemporaryFile() as bin_file:
      with mock.patch.dict(sys.modules, {"idapro": fake_idapro}):
        sys.modules.pop("ida_mcp.headless", None)
        try:
          headless = importlib.import_module("ida_mcp.headless")
          real_close = query.close_tables

          def wrapped_close():
            order.append("close_tables")
            real_close()

          with (
              mock.patch.object(sys, "argv", ["headless", bin_file.name]),
              mock.patch.object(headless, "_server_thread"),
              mock.patch.object(headless, "stop_server"),
              mock.patch.object(headless, "clear_persistent_globals"),
              mock.patch.object(headless, "close_tables", wrapped_close),
              mock.patch.object(headless.ida_thread, "loop", on_loop),
              mock.patch.object(idaapi, "is_headless", None),
              mock.patch.object(idaapi, "idb_path", None, create=True),
          ):
            headless.main()
        finally:
          sys.modules.pop("ida_mcp.headless", None)

    self.assertEqual(len(scratch_seen), 1)
    self.assertIsNotNone(scratch_seen[0])
    self.assertFalse(scratch_seen[0].exists())
    self.assertEqual(order, ["close_tables", "close_database"])
    # The analysis is left to the loop, which had nothing to run: the mocked
    # database is fully analysed.
    self.assertFalse(
        fake_idapro.open_database.call_args.kwargs["run_auto_analysis"]
    )
    self.assertEqual(loop_idle, [None])
    # main() owned the signals while the loop ran and handed them back after.
    for sig in handled_signals:
      self.assertNotEqual(handlers_in_loop[sig], handlers_before[sig])
    self.assertEqual(
        {sig: signal.getsignal(sig) for sig in handled_signals},
        handlers_before,
    )

  def _import_headless(self, fake_idapro):
    """Imports ida_mcp.headless with a fake idapro; undone at cleanup."""
    patcher = mock.patch.dict(sys.modules, {"idapro": fake_idapro})
    patcher.start()
    self.addCleanup(patcher.stop)
    sys.modules.pop("ida_mcp.headless", None)
    self.addCleanup(sys.modules.pop, "ida_mcp.headless", None)
    return importlib.import_module("ida_mcp.headless")

  def _run_headless_main(self, argv, auto_is_ok):
    """Runs headless.main() with a mocked loop; returns the loop's idle."""
    fake_idapro = mock.MagicMock()
    fake_idapro.open_database.return_value = 0
    headless = self._import_headless(fake_idapro)
    for sig in (signal.SIGINT, signal.SIGTERM):
      if (handler := signal.getsignal(sig)) is not None:
        self.addCleanup(signal.signal, sig, handler)
    loop = mock.Mock()
    with tempfile.NamedTemporaryFile() as bin_file:
      with (
          mock.patch.object(sys, "argv", ["headless", bin_file.name, *argv]),
          mock.patch.object(headless, "_server_thread"),
          mock.patch.object(headless, "stop_server"),
          mock.patch.object(headless, "clear_persistent_globals"),
          mock.patch.object(headless.ida_thread, "loop", loop),
          mock.patch.object(
              headless.ida_auto, "auto_is_ok", return_value=auto_is_ok
          ),
          mock.patch.object(idaapi, "is_headless", None),
          mock.patch.object(idaapi, "idb_path", None, create=True),
      ):
        headless.main()
    loop.assert_called_once()
    return headless, loop.call_args.args[0]

  def test_headless_main_runs_analysis_in_the_loop(self):
    """Verifies main() marks a pending analysis and gives it to the loop."""
    headless, idle = self._run_headless_main([], auto_is_ok=False)
    self.assertIsInstance(idle, headless._AnalysisIdle)
    self.assertEqual(analysis_state.status(), analysis_state.IN_PROGRESS)

  def test_headless_main_skips_analysis_of_an_analysed_database(self):
    """Verifies main() has nothing to run for a database already analysed."""
    for argv in ([], ["--disable-auto-analysis"]):
      with self.subTest(argv=argv):
        analysis_state.reset()
        _, idle = self._run_headless_main(argv, auto_is_ok=True)
        self.assertIsNone(idle)
        self.assertEqual(analysis_state.status(), analysis_state.DONE)

  def test_headless_main_with_disable_auto_analysis(self):
    """Verifies --disable-auto-analysis runs no analysis and records it."""
    _, idle = self._run_headless_main(
        ["--disable-auto-analysis"], auto_is_ok=False
    )
    self.assertIsNone(idle)
    self.assertEqual(analysis_state.status(), analysis_state.DISABLED)

  def _reset_ida_thread(self):
    """Undoes ida_thread.stop(): drops queued items and the cancelled token."""
    while not ida_thread._ida_queue.empty():
      ida_thread._ida_queue.get_nowait()
      ida_thread._ida_queue.task_done()
    ida_thread.stop_token = CancellationToken()

  def test_analysis_slice(self):
    """Verifies a slice steps until its time is up or the analysis ends."""
    headless = self._import_headless(mock.MagicMock())
    ida_auto = headless.ida_auto

    # More to do: the slice ends when its time is up.
    step = mock.Mock(return_value=True)
    with (
        mock.patch.object(ida_auto, "auto_make_step", step),
        mock.patch.object(headless, "_ANALYSIS_SLICE_SECONDS", 0.01),
    ):
      self.assertTrue(headless._analysis_slice())
      self.assertGreater(step.call_count, 0)

    # Nothing left to step through, and the queues are final.
    with (
        mock.patch.object(ida_auto, "auto_make_step", return_value=False),
        mock.patch.object(ida_auto, "auto_is_ok", return_value=True),
        mock.patch.object(ida_auto, "auto_wait") as auto_wait,
    ):
      self.assertFalse(headless._analysis_slice())
      auto_wait.assert_not_called()

    # Nothing left to step through, but the queues aren't final: IDA finishes
    # in one call, which is logged since nothing can interrupt it.
    with (
        mock.patch.object(ida_auto, "auto_make_step", return_value=False),
        mock.patch.object(ida_auto, "auto_is_ok", return_value=False),
        mock.patch.object(ida_auto, "auto_wait") as auto_wait,
        self.assertLogs(headless.logger, level="WARNING") as logs,
    ):
      self.assertFalse(headless._analysis_slice())
      auto_wait.assert_called_once_with()
    self.assertIn("auto_wait() ran for", logs.output[0])

  def test_analysis_idle_sets_up_tables_in_a_step_of_its_own(self):
    """Verifies the loop gets to check its queue before the table setup."""
    headless = self._import_headless(mock.MagicMock())
    self.addCleanup(self._reset_ida_thread)
    analysis_state.begin()
    order = []
    analysis_state.set_on_done(lambda: order.append("done"))
    idle = headless._AnalysisIdle()
    slices = mock.Mock(side_effect=[True, False])
    with (
        mock.patch.object(headless, "_analysis_slice", slices),
        mock.patch.object(
            headless,
            "init_tables",
            side_effect=lambda: order.append("init_tables"),
        ),
        mock.patch.dict(os.environ, POPULATE_TABLES_ON_STARTUP="true"),
    ):
      load_config.cache_clear()
      self.assertTrue(idle())  # More analysis to do.
      # The analysis has ended, but the idle work hasn't: the loop checks its
      # queue once more before the tables are set up.
      self.assertTrue(idle())
      self.assertEqual(order, [])
      self.assertTrue(analysis_state.is_in_progress())
      # Tables first, then the tools are let through.
      self.assertFalse(idle())
    self.assertEqual(order, ["init_tables", "done"])
    self.assertEqual(analysis_state.status(), analysis_state.DONE)

  def test_analysis_slice_failure_unlocks_the_tools(self):
    """Verifies a failing analysis step doesn't leave the tools locked."""
    headless = self._import_headless(mock.MagicMock())
    self.addCleanup(self._reset_ida_thread)
    analysis_state.begin()
    idle = headless._AnalysisIdle()
    with mock.patch.object(
        headless.ida_auto, "auto_make_step", side_effect=RuntimeError("boom")
    ):
      with self.assertLogs(headless.logger, level="ERROR"):
        self.assertTrue(idle())
    self.assertFalse(idle())
    self.assertEqual(analysis_state.status(), analysis_state.DONE)

  def test_stop_cancels_the_stop_token(self):
    """Verifies stop() cancels stop_token, which loop() then replaces."""
    self.addCleanup(self._reset_ida_thread)
    self._reset_ida_thread()
    token = ida_thread.stop_token
    ida_thread.stop()
    for _ in range(100):
      if token.is_cancelled:
        break
      time.sleep(0.01)
    self.assertTrue(token.is_cancelled)
    # A scope entered after the stop doesn't start its work.
    with self.assertRaises(asyncio.CancelledError):
      with cancellation_profile(token):
        self.fail("The scope should not be entered")
    # The queued quit ends the next loop at once; the loop has a new token.
    ida_thread.loop()
    self.assertIsNot(ida_thread.stop_token, token)
    self.assertFalse(ida_thread.stop_token.is_cancelled)

  def test_table_setup_is_skipped_after_a_stop_request(self):
    """Verifies a stop requested before the table setup leaves it out."""
    headless = self._import_headless(mock.MagicMock())
    self.addCleanup(self._reset_ida_thread)
    self._reset_ida_thread()
    analysis_state.begin()
    done = mock.Mock()
    analysis_state.set_on_done(done)
    ida_thread.stop_token.cancel()
    with (
        mock.patch.object(headless, "init_tables") as init_tables,
        mock.patch.dict(os.environ, POPULATE_TABLES_ON_STARTUP="true"),
    ):
      load_config.cache_clear()
      headless._on_analysis_done()
    init_tables.assert_not_called()
    # The server is going away: the tools stay locked and the record keeps
    # its in-progress name.
    done.assert_not_called()
    self.assertTrue(analysis_state.is_in_progress())

  def test_table_setup_is_interrupted_by_a_stop_request(self):
    """Verifies stop() interrupts a table setup that is already running."""
    headless = self._import_headless(mock.MagicMock())
    self.addCleanup(self._reset_ida_thread)
    self._reset_ida_thread()
    analysis_state.begin()
    done = mock.Mock()
    analysis_state.set_on_done(done)
    rows = []

    def populate_rows():
      # Like a populator: a Python loop that checks nothing.
      deadline = time.monotonic() + 10
      while time.monotonic() < deadline:
        rows.append(len(rows))

    def slow_init_tables():
      populate_rows()
      self.fail("The table setup ran to its end")

    threading.Timer(0.1, ida_thread.stop).start()
    started = time.monotonic()
    with (
        mock.patch.object(headless, "init_tables", slow_init_tables),
        mock.patch.dict(os.environ, POPULATE_TABLES_ON_STARTUP="true"),
    ):
      load_config.cache_clear()
      headless._on_analysis_done()
    self.assertLess(time.monotonic() - started, 5)
    self.assertTrue(rows)
    done.assert_not_called()
    self.assertTrue(analysis_state.is_in_progress())

  @mock.patch(
      "ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA
  )
  def test_startup_table_setup_gives_way_to_a_stop_request(self, _mock_meta):
    """Verifies a stopping headless server doesn't populate or register."""
    self.addCleanup(self._reset_ida_thread)
    self._reset_ida_thread()
    ida_thread.stop_token.cancel()
    with (
        mock.patch.dict(os.environ, POPULATE_TABLES_ON_STARTUP="true"),
        mock.patch.object(idaapi, "is_headless", True),
        mock.patch.object(query, "_populate_tables") as populate,
    ):
      load_config.cache_clear()
      t = threading.Thread(
          target=mcp_server_thread, args=("test_stop_id",), daemon=True
      )
      t.start()
      t.join(timeout=5.0)
      self.addCleanup(stop_server, "test_stop_id")
      self.assertFalse(t.is_alive(), "The server thread should have ended")
    populate.assert_not_called()
    registry_dir = pathlib.Path(load_config()["registry_dir"])
    self.assertEqual(list(registry_dir.glob("*.json")), [])

  def test_ida_thread_loop_runs_idle_between_tasks(self):
    """Verifies loop() serves the queue first and idles until told to stop."""
    events = []
    task_done = threading.Event()

    def task():
      events.append("task")
      task_done.set()

    def idle():
      events.append("idle")
      if len(events) == 2:
        # Queued while idling: served before the next idle call.
        ida_thread._ida_queue.put(ida_thread.IDATask(task, event=task_done))
      if events.count("idle") == 3:
        threading.Timer(0.2, ida_thread.stop).start()
        return False
      return True

    ida_thread._ida_queue.put(ida_thread.IDATask(task))
    ida_thread.loop(idle)
    # After idle() returned False, the loop waited for the quit item rather
    # than calling it again.
    self.assertEqual(events, ["task", "idle", "task", "idle", "idle"])
    self.assertFalse(ida_thread._loop_running.is_set())

  def test_ida_thread_loop_stops_while_idle_work_remains(self):
    """Verifies a stop request ends a loop whose idle work never finishes."""
    # Adapted from test_quit_while_work_remains in PR #22.
    calls = 0

    def idle():
      nonlocal calls
      calls += 1
      if calls == 3:
        ida_thread.stop()
      return True  # More to do, always.

    ida_thread.loop(idle)
    # The stop request was served before the next idle call.
    self.assertEqual(calls, 3)
    self.assertFalse(ida_thread._loop_running.is_set())

  def test_instance_id_is_eight_random_bytes(self):
    """Verifies an instance ID is 16 hex characters, new on every call."""
    ids = {registry.new_instance_id() for _ in range(50)}
    self.assertEqual(len(ids), 50)
    for instance_id in ids:
      self.assertRegex(instance_id, r"^[0-9a-f]{16}$")
      # The names made from it are record names.
      for in_progress in (False, True):
        name = registry.record_name(instance_id, in_progress)
        self.assertEqual(
            registry.parse_record_name(name), (instance_id, in_progress)
        )

  def test_mcp_json_line_names_the_instance(self):
    """Verifies [MCP_JSON] adds the instance ID to the metadata it prints."""
    metadata: Any = dict(MOCK_METADATA, is_headless=True)
    tty = mock.Mock(isatty=mock.Mock(return_value=True))
    with (
        mock.patch("builtins.print") as mock_print,
        mock.patch.object(sys, "stdout", tty),
        mock.patch.object(sys, "stderr", tty),
    ):
      ida_mcp_server._print_metadata(metadata, "db", _IID)

    (line,) = [call.args[0] for call in mock_print.call_args_list]
    self.assertTrue(line.startswith("[MCP_JSON] "), line)
    self.assertEqual(
        json.loads(line.removeprefix("[MCP_JSON] ")),
        {**metadata, "database_id": "db", "instance_id": _IID},
    )
    # The metadata itself is left alone.
    self.assertNotIn("instance_id", metadata)

  @unittest.skipIf(sys.platform == "win32", "Windows uses TCP")
  @mock.patch(
      "ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA
  )
  def test_server_rejects_a_uds_dir_too_long_for_a_socket(self, mock_meta):
    """Verifies an over-long socket path is reported, and nothing registers."""
    config = load_config()
    registry_dir = pathlib.Path(config["registry_dir"])
    # 21 characters go to "/<instance id>.sock"; the OS limit is ~100.
    long_uds_dir = registry_dir.parent / ("u" * 110)
    config_path = registry_dir.parent / "long_uds.json"
    config_path.write_text(
        json.dumps({
            "registry_dir": str(registry_dir),
            "uds_dir": str(long_uds_dir),
            "communication_channel": "uds",
        })
    )
    with mock.patch.dict(os.environ, IDAMCP_CONFIG=str(config_path)):
      load_config.cache_clear()
      with self.assertLogs(ida_mcp_server.logger, level="ERROR") as logs:
        # Returns instead of serving: there is no thread to stop.
        mcp_server_thread("test_long_uds_id")
    load_config.cache_clear()
    self.assertIn("uds_dir is too long for a Unix socket", logs.output[0])
    self.assertIn(f"a socket in {long_uds_dir} takes", logs.output[0])
    # The socket's file name is the instance ID, which stays internal.
    self.assertNotIn(".sock", logs.output[0])
    self.assertEqual(list(registry_dir.glob("*.json")), [])
    self.assertEqual(os.listdir(long_uds_dir), [])
    # Reported before the metadata is printed, i.e., before a headless
    # server redirects its output away from the gateway.
    mock_meta.assert_not_called()

  def test_registry_manager_promote(self):
    """Verifies promote() renames an in-progress record, and only that."""
    with tempfile.TemporaryDirectory() as tmp:
      manager = RegistryManager(tmp)
      self.addCleanup(manager.cleanup)
      path = manager.register(
          "tcp",
          1234,
          database_id="db",
          instance_id=_IID,
          started_at=12.5,
          in_progress=True,
      )
      assert path is not None
      self.assertEqual(path.name, f"analyzing-{_IID}.json")
      promoted = manager.promote()
      assert promoted is not None
      self.assertEqual(promoted.name, f"ida-{_IID}.json")
      self.assertFalse(path.exists())
      entry = json.loads(promoted.read_text())
      self.assertEqual(entry["database_id"], "db")
      self.assertEqual(entry["started_at"], 12.5)
      self.assertIsNone(manager.promote())  # Already plain.
      manager.cleanup()
      self.assertEqual(os.listdir(tmp), [])
      self.assertIsNone(manager.promote())  # Nothing registered.

      path = manager.register(
          "tcp",
          1234,
          database_id="db",
          instance_id=_IID,
          started_at=12.5,
          auto_analysis_disabled=True,
      )
      assert path is not None
      self.assertEqual(path.name, f"ida-{_IID}.json")
      self.assertTrue(json.loads(path.read_text())["auto_analysis_disabled"])

  def test_registry_manager_promote_retries_the_rename(self):
    """Verifies promote() gets past a rename that fails for a moment."""
    with tempfile.TemporaryDirectory() as tmp:
      manager = RegistryManager(tmp)
      self.addCleanup(manager.cleanup)
      real_replace = os.replace
      for failures, promoted_name in (
          (2, f"ida-{_IID}.json"),
          (backend_registry._PROMOTE_ATTEMPTS, None),
      ):
        with self.subTest(failures=failures):
          path = manager.register(
              "tcp",
              1234,
              database_id="db",
              instance_id=_IID,
              started_at=1.0,
              in_progress=True,
          )
          assert path is not None
          # E.g., on Windows while another process has the record open.
          calls = []

          def flaky_replace(src, dst, failures=failures, calls=calls):
            calls.append(src)
            if len(calls) <= failures:
              raise PermissionError("in use")
            real_replace(src, dst)

          with (
              mock.patch.object(backend_registry.os, "replace", flaky_replace),
              mock.patch.object(backend_registry.time, "sleep") as sleep,
              self.assertLogs(level="ERROR")
              if promoted_name is None
              else contextlib.nullcontext(),
          ):
            promoted = manager.promote()
          if promoted_name is None:
            self.assertIsNone(promoted)
            self.assertTrue(path.exists())  # Still under its old name.
          else:
            assert promoted is not None
            self.assertEqual(promoted.name, promoted_name)
            self.assertEqual(sleep.call_count, failures)
          manager.cleanup()

  def test_registry_manager_cleanup_retries_transient_unlink_failure(self):
    """Verifies cleanup() retries unlink() when another process holds file."""
    with tempfile.TemporaryDirectory() as tmp:
      manager = RegistryManager(tmp)
      path = manager.register(
          "tcp", 1234, database_id="db", instance_id=_IID, started_at=1.0
      )
      assert path is not None
      real_unlink = pathlib.Path.unlink
      calls = []

      def flaky_unlink(self_path):
        calls.append(self_path)
        if len(calls) <= 2:
          raise PermissionError("in use")
        real_unlink(self_path)

      with (
          mock.patch.object(pathlib.Path, "unlink", flaky_unlink),
          mock.patch.object(backend_registry.time, "sleep") as sleep,
      ):
        manager.cleanup()
      self.assertFalse(path.exists())
      self.assertEqual(sleep.call_count, 2)

  def test_superseded_stop_token_pulser_exits_when_new_loop_starts(self):
    """Verifies _cancel_stop_token exits if a new loop replaced stop_token."""
    old_token = ida_mcp_server.ida_thread.CancellationToken()
    old_token.pulse = mock.Mock()
    ida_thread._loop_running.set()
    try:
      with mock.patch.object(ida_thread.time, "sleep"):
        ida_thread._cancel_stop_token(old_token)
      self.assertTrue(old_token.is_cancelled)
      old_token.pulse.assert_not_called()
    finally:
      ida_thread._loop_running.clear()

  def _call_tools(self, entry, *methods):
    """Calls RPC methods on a running server; returns results or errors."""

    async def call():
      client = RPCClient()
      if entry["channel"] == "tcp":
        await client.connect_tcp("127.0.0.1", entry["address"])
      else:
        await client.connect_uds(entry["address"])
      results = []
      try:
        for method in methods:
          try:
            results.append(await client.call(method, {}))
          except RPCError as e:
            results.append(e)
      finally:
        await client.close()
      return results

    return asyncio.run(call())

  @mock.patch(
      "ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA
  )
  def test_tools_are_rejected_until_analysis_is_done(self, _mock_meta):
    """Verifies only allowed tools run while auto-analysis is in progress."""
    test_id = "test_analysis_gate_id"
    analysis_state.begin()
    t = threading.Thread(target=mcp_server_thread, args=(test_id,), daemon=True)
    t.start()
    self.addCleanup(t.join, 5.0)
    self.addCleanup(stop_server, test_id)
    reg_file = _wait_for_record(registry._IN_PROGRESS_PREFIX)
    assert reg_file is not None, "An in-progress record should be created"
    entry = json.loads(reg_file.read_text())

    with mock.patch.object(ida_thread, "stop") as stop:
      rejected, config, unsafe_tools, closed = self._call_tools(
          entry,
          "configure_unsafe_tools",
          "get_security_config",
          "list_unsafe_tools",
          "close_database",
      )
    # The read-only security tools answer, e.g., for the dashboard.
    self.assertIn("enabled_unsafe_tools", config)
    self.assertIsInstance(unsafe_tools, list)
    self.assertIsInstance(rejected, RPCError)
    self.assertEqual(
        str(rejected), "auto analysis is still in progress, please wait."
    )
    self.assertEqual(rejected.data, -32001)  # A tool error.
    self.assertIsNone(closed)
    stop.assert_called_once_with()

    analysis_state.finish()
    instance_id, _ = registry.parse_record_name(reg_file.name)
    promoted = reg_file.with_name(registry.record_name(instance_id, False))
    self.assertTrue(promoted.exists())
    self.assertFalse(reg_file.exists())
    (config,) = self._call_tools(entry, "get_security_config")
    self.assertIn("enabled_unsafe_tools", config)

    stop_server(test_id)
    t.join(timeout=5.0)
    self.assertFalse(promoted.exists(), "The record is removed on shutdown")

  @mock.patch(
      "ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA
  )
  def test_server_registers_plain_record_after_analysis(self, _mock_meta):
    """Verifies a server started after the analysis, or without, is plain."""
    for prepare, disabled in (
        (lambda: (analysis_state.begin(), analysis_state.finish()), False),
        (analysis_state.disable, True),
    ):
      with self.subTest(disabled=disabled):
        analysis_state.reset()
        prepare()
        test_id = "test_plain_record_id"
        t = threading.Thread(
            target=mcp_server_thread, args=(test_id,), daemon=True
        )
        t.start()
        reg_file = _wait_for_record()
        try:
          assert reg_file is not None
          entry = json.loads(reg_file.read_text())
          self.assertEqual(entry["auto_analysis_disabled"], disabled)
          (config,) = self._call_tools(entry, "get_security_config")
          self.assertIn("enabled_unsafe_tools", config)
        finally:
          stop_server(test_id)
          t.join(timeout=5.0)

  def test_jsonrpc_copies_allow_during_auto_analysis(self):
    """Verifies @jsonrpc copies allow_during_auto_analysis to wrappers."""
    from ida_mcp.core.decorators import allow_during_auto_analysis
    from ida_mcp.core.decorators import jsonrpc
    from ida_mcp.core.rpc_registry import rpc_registry

    @jsonrpc
    @allow_during_auto_analysis
    def sync_allowed(x: int) -> int:
      return x

    @jsonrpc
    @allow_during_auto_analysis
    async def async_allowed(x: int) -> int:
      return x

    try:
      self.assertTrue(sync_allowed.allow_during_auto_analysis)
      self.assertTrue(async_allowed.allow_during_auto_analysis)
    finally:
      rpc_registry.methods.discard(sync_allowed)
      rpc_registry.methods.discard(async_allowed)

  @mock.patch(
      "ida_mcp.tools.info.get_metadata.sync_call", return_value=MOCK_METADATA
  )
  def test_server_continues_when_init_tables_fails_on_startup(self, _mock_meta):
    """Verifies an init_tables() error on startup is logged, not fatal."""
    test_id = "test_init_tables_error_id"
    with (
        mock.patch.dict(os.environ, POPULATE_TABLES_ON_STARTUP="true"),
        mock.patch.object(
            query, "init_tables", side_effect=RuntimeError("db error")
        ),
        self.assertLogs(ida_mcp_server.logger, level="ERROR"),
    ):
      load_config.cache_clear()
      t = threading.Thread(
          target=mcp_server_thread, args=(test_id,), daemon=True
      )
      t.start()
      reg_file = _wait_for_record()
      try:
        self.assertIsNotNone(reg_file)
      finally:
        stop_server(test_id)
        t.join(timeout=5.0)

  def test_plugin_server_waits_less_at_shutdown(self):
    """Verifies the plugin's server waits less at shutdown than the default.

    term() blocks IDA's main thread until the server has stopped, and a tool
    call waiting for that thread can't finish in the meantime.
    """
    plugin = MCP()
    # Not create=True for is_headless: on exit, that deletes it from the mocked
    # idaapi, and later patches of it (test_interruption's) fail.
    with (
        mock.patch.object(ida_mcp_plugin, "mcp_server_thread") as server,
        mock.patch.object(idaapi, "is_headless", None),
        mock.patch.object(idaapi, "idb_path", None, create=True),
    ):
      plugin._start_server()
      plugin.server_thread.join(timeout=5.0)
    server.assert_called_once_with(
        plugin.hash_str, shutdown_grace=ida_mcp_plugin._SHUTDOWN_GRACE
    )
    self.assertLess(ida_mcp_plugin._SHUTDOWN_GRACE, DEFAULT_SHUTDOWN_GRACE)


class TestPluginAutostart(unittest.TestCase):
  """Tests for the plugin's `autostart` and `hotkey` options."""

  def setUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.config_path = pathlib.Path(tmp.name) / "idamcp.json"
    self._patch(
        mock.patch.dict(os.environ, IDAMCP_CONFIG=str(self.config_path))
    )
    for name in ("IDAMCP_NO_USER_CONFIG", "AUTOSTART", "HOTKEY"):
      os.environ.pop(name, None)  # Restored by patch.dict.
    self.addCleanup(setattr, MCP, "wanted_hotkey", MCP.wanted_hotkey)
    self.addCleanup(load_config.cache_clear)
    load_config.cache_clear()
    # IDA's interactive GUI (neither idalib nor batch mode) with auto-analysis
    # enabled and finished, unless a test says otherwise.
    self.headless = self._patch(
        mock.patch.object(ida_mcp_plugin, "_is_headless", return_value=False)
    )
    # Unpatched, it would read the mocked idaapi's cvar.batch: a truthy mock.
    self.batch_mode = self._patch(
        mock.patch.object(ida_mcp_plugin, "_is_batch_mode", return_value=False)
    )
    self.auto_is_ok = self._patch(
        mock.patch.object(idaapi, "auto_is_ok", return_value=True)
    )
    self.auto_enabled = self._patch(
        mock.patch.object(idaapi, "inf_is_auto_enabled", return_value=True)
    )
    self.register_timer = self._patch(
        mock.patch.object(
            idaapi, "register_timer", return_value="timer", create=True
        )
    )
    self.unregister_timer = self._patch(
        mock.patch.object(idaapi, "unregister_timer", create=True)
    )

  def _patch(self, patcher):
    value = patcher.start()
    self.addCleanup(patcher.stop)
    return value

  def _write_config(self, **options):
    self.config_path.write_text(json.dumps(options))
    load_config.cache_clear()

  def _init_plugin(self, mock_start=True):
    """Returns an initialized plugin and init()'s output.

    Args:
      mock_start: Whether to mock _start_server(), which starts the server.
    """
    plugin = MCP()
    if mock_start:
      self._patch(mock.patch.object(plugin, "_start_server"))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
      self.assertEqual(plugin.init(), idaapi.PLUGIN_KEEP)
    return plugin, out.getvalue()

  def test_plugin_entry_applies_the_hotkey_option(self):
    """Verifies PLUGIN_ENTRY rereads the config and sets wanted_hotkey."""
    self._write_config(hotkey="Ctrl-Shift-J")
    self.assertEqual(load_config()["hotkey"], "Ctrl-Shift-J")
    self.config_path.write_text(json.dumps({"hotkey": " Ctrl-Shift-K "}))
    plugin = ida_mcp_plugin.PLUGIN_ENTRY()
    self.assertIsInstance(plugin, MCP)
    self.assertEqual(MCP.wanted_hotkey, "Ctrl-Shift-K")
    _, out = self._init_plugin()
    self.assertIn("Edit -> Plugins -> MCP (Ctrl+Shift+K) to start", out)

  def test_empty_hotkey_means_none_and_invalid_falls_back(self):
    """Verifies an empty hotkey disables it and a non-string one is ignored."""
    self._write_config(hotkey="")
    ida_mcp_plugin.PLUGIN_ENTRY()
    self.assertEqual(MCP.wanted_hotkey, "")
    _, out = self._init_plugin()
    self.assertIn("Edit -> Plugins -> MCP to start", out)

    self._write_config(hotkey=7)
    with contextlib.redirect_stdout(io.StringIO()):
      ida_mcp_plugin.PLUGIN_ENTRY()
    self.assertEqual(MCP.wanted_hotkey, "Ctrl-Alt-M")

  def test_is_headless(self):
    """Verifies only an idalib host is headless, never the GUI or idat."""
    self.assertNotIn("idapro", sys.modules)
    # is_idaq() and is_ida_library() as measured in IDA 9.3/9.4's GUI and idat.
    for is_idaq, is_ida_library in ((True, False), (False, True)):
      with (
          mock.patch.object(idaapi, "is_idaq", return_value=is_idaq),
          mock.patch.object(
              idaapi, "is_ida_library", return_value=is_ida_library, create=True
          ),
      ):
        self.assertFalse(_is_headless())
    sys.modules["idapro"] = mock.MagicMock()
    try:
      self.assertTrue(_is_headless())
    finally:
      del sys.modules["idapro"]

  def test_is_batch_mode(self):
    """Verifies batch mode follows cvar.batch and is off if IDA lacks it."""
    # A bool: in IDA 9.4, False in the GUI, True with -A, in idat and idalib.
    for batch in (False, True):
      cvar = types.SimpleNamespace(batch=batch)
      with mock.patch.object(idaapi, "cvar", cvar, create=True):
        self.assertIs(_is_batch_mode(), batch)
    with mock.patch.object(idaapi, "cvar", None, create=True):
      self.assertFalse(_is_batch_mode())

  def test_autostart_starts_the_server_from_a_timer(self):
    """Verifies autostart starts from IDA's event loop, even when analyzed."""
    self._write_config(autostart=True)
    plugin, out = self._init_plugin()
    self.assertIn("the server starts automatically", out)
    self.assertIsNotNone(plugin._autostart_hooks)

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
      plugin._autostart_hooks.ready_to_run()
    self.assertEqual(out.getvalue(), "")  # Nothing to wait for.
    self.register_timer.assert_called_once_with(1000, plugin._autostart_tick)
    plugin._start_server.assert_not_called()  # Not before the timer fires.

    self.assertEqual(plugin._autostart_tick(), -1)
    plugin._start_server.assert_called_once_with()
    self.assertIsNone(plugin._autostart_timer)

  def test_autostart_waits_for_auto_analysis_without_blocking(self):
    """Verifies autostart polls auto_is_ok() instead of calling auto_wait()."""
    self._write_config(autostart=True)
    plugin, _ = self._init_plugin()
    self.auto_is_ok.return_value = False
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
      plugin._autostart_hooks.ready_to_run()
    self.assertIn("starts once auto-analysis finishes", out.getvalue())
    self.register_timer.assert_called_once_with(1000, plugin._autostart_tick)
    self.assertEqual(plugin._autostart_timer, "timer")

    self.assertEqual(plugin._autostart_tick(), 1000)
    plugin._start_server.assert_not_called()

    self.auto_is_ok.return_value = True
    self.assertEqual(plugin._autostart_tick(), -1)
    plugin._start_server.assert_called_once_with()
    self.assertIsNone(plugin._autostart_timer)

  def test_autostart_skips_disabled_analysis(self):
    """Verifies autostart neither waits for nor runs a disabled analysis."""
    # E.g. `ida -a`: the analysis queues never drain.
    self._write_config(autostart=True)
    plugin, _ = self._init_plugin()
    self.auto_is_ok.return_value = False
    self.auto_enabled.return_value = False
    auto_wait = self._patch(
        mock.patch.object(idaapi, "auto_wait", create=True)
    )
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
      plugin._autostart_hooks.ready_to_run()
      self.assertEqual(plugin._autostart_tick(), -1)
    self.assertNotIn("auto-analysis", out.getvalue())
    plugin._start_server.assert_called_once_with()
    auto_wait.assert_not_called()

  def test_plugin_records_disabled_analysis_and_resets_on_term(self):
    """Verifies GUI disabled analysis sets DISABLED and term() resets it."""
    self.auto_is_ok.return_value = False
    self.auto_enabled.return_value = False
    plugin, _ = self._init_plugin(mock_start=False)
    with (
        mock.patch.object(ida_mcp_plugin, "mcp_server_thread"),
        mock.patch.object(idaapi, "is_headless", None),
        mock.patch.object(idaapi, "idb_path", None, create=True),
    ):
      plugin._start_server()
      assert plugin.server_thread is not None
      plugin.server_thread.join(timeout=5.0)
      self.assertEqual(analysis_state.status(), analysis_state.DISABLED)
      plugin.term()
      self.assertEqual(analysis_state.status(), analysis_state.DONE)

  def test_hotkey_during_a_pending_autostart(self):
    """Verifies the hotkey reports an autostart waiting for analysis only."""
    self._write_config(autostart=True)
    plugin, _ = self._init_plugin(mock_start=False)
    self.auto_is_ok.return_value = False
    with contextlib.redirect_stdout(io.StringIO()):
      plugin._autostart_hooks.ready_to_run()
    self.assertEqual(plugin._autostart_timer, "timer")
    # idat: the old check, `not is_idaq()`, marked it as headless.
    self._patch(mock.patch.object(idaapi, "is_idaq", return_value=False))
    # Not create=True: see test_plugin_server_waits_less_at_shutdown.
    self._patch(mock.patch.object(idaapi, "is_headless", None))
    self._patch(mock.patch.object(idaapi, "idb_path", None, create=True))
    server = self._patch(mock.patch.object(ida_mcp_plugin, "mcp_server_thread"))
    auto_wait = self._patch(
        mock.patch.object(idaapi, "auto_wait", create=True)
    )

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
      plugin.run(0)  # The hotkey, or Edit -> Plugins -> MCP.
    self.assertIn("[MCP] Autostart is on the way", out.getvalue())
    self.assertIsNone(plugin.server_thread)

    # Analysis has finished, but the timer hasn't fired yet: start now.
    self.auto_is_ok.return_value = True
    plugin.run(0)
    self.assertTrue(plugin._server_started)
    plugin.server_thread.join(timeout=5.0)
    server.assert_called_once_with(
        plugin.hash_str, shutdown_grace=ida_mcp_plugin._SHUTDOWN_GRACE
    )
    self.assertIs(idaapi.is_headless, False)
    auto_wait.assert_not_called()
    # The timer then just ends.
    self.assertEqual(plugin._autostart_tick(), -1)
    self.assertIsNone(plugin._autostart_timer)
    server.assert_called_once_with(
        plugin.hash_str, shutdown_grace=ida_mcp_plugin._SHUTDOWN_GRACE
    )

  def test_no_autostart_by_default_or_when_headless(self):
    """Verifies autostart is off by default and has no effect when headless."""
    self._write_config()
    plugin, out = self._init_plugin()
    self.assertIn("to start the server", out)
    self.assertIsNone(plugin._autostart_hooks)

    self._write_config(autostart=True)
    self.headless.return_value = True
    plugin, out = self._init_plugin()
    self.assertIn("to start the server", out)
    self.assertIsNone(plugin._autostart_hooks)
    plugin._start_server.assert_not_called()

  def test_no_autostart_in_batch_mode(self):
    """Verifies autostart is skipped in batch mode, and run() still works."""
    # E.g. `ida -A -S script.py`.
    self._write_config(autostart=True)
    self.batch_mode.return_value = True
    plugin, out = self._init_plugin()
    self.assertIn("[MCP] autostart is skipped in batch mode", out)
    self.assertIn("to start the server", out)
    self.assertIsNone(plugin._autostart_hooks)
    self.register_timer.assert_not_called()
    plugin.run(0)  # The hotkey, or a script.
    plugin._start_server.assert_called_once_with()

    # No such message under idalib, which is in batch mode too, nor without
    # autostart.
    self.headless.return_value = True
    _, out = self._init_plugin()
    self.assertNotIn("batch mode", out)
    self.headless.return_value = False
    self._write_config()
    _, out = self._init_plugin()
    self.assertNotIn("batch mode", out)

  def test_term_cancels_an_autostart_whose_timer_never_fired(self):
    """Verifies term() unhooks and stops the timer if the server never ran."""
    # The database is closed before the timer fires, e.g., during analysis.
    self._write_config(autostart=True)
    plugin, _ = self._init_plugin()
    plugin._autostart_hooks.ready_to_run()
    with mock.patch.object(ida_mcp_plugin._AutostartHooks, "unhook") as unhook:
      plugin.term()
    unhook.assert_called_once_with()
    self.unregister_timer.assert_called_once_with("timer")
    self.assertIsNone(plugin._autostart_hooks)
    self.assertIsNone(plugin._autostart_timer)
    plugin._start_server.assert_not_called()


if __name__ == "__main__":
  unittest.main()
