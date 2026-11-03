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
import io
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import threading
import time
import types
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
from ida_mcp.core import ida_thread
from ida_mcp.core.backend_registry import RegistryManager
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
    query.close_tables()
    info.clear_caches()
    security_manager.reset()
    load_config.cache_clear()

  def tearDown(self):
    query.close_tables()
    info.clear_caches()
    security_manager.reset()
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

    query.close_tables()

    self.assertFalse(query._db_initialized)
    self.assertIsNone(query._worker_thread)
    self.assertIsNone(query._db_hooks)
    self.assertIsNone(query._db_idp_hooks)
    self.assertEqual(len(query._populated_tables), 0)
    self.assertEqual(len(query._db_local.connections), 0)
    self.assertFalse(_is_connection_open(rw_conn))

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
    config = load_config()
    registry_dir = pathlib.Path(config["registry_dir"])
    reg_file = registry_dir / f"{test_id}.json"

    # Start server in thread
    t = threading.Thread(target=mcp_server_thread, args=(test_id,), daemon=True)
    t.start()

    # Wait for registry file to appear
    for _ in range(50):
      if reg_file.exists():
        break
      time.sleep(0.1)

    self.assertTrue(reg_file.exists(), "Registry file should be created on start")

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
    reg_file = pathlib.Path(load_config()["registry_dir"]) / f"{test_id}.json"
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
          for _ in range(50):
            if reg_file.exists():
              break
            time.sleep(0.1)
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
    config = load_config()
    reg_file = pathlib.Path(config["registry_dir"]) / f"{test_id}.json"

    t = threading.Thread(target=mcp_server_thread, args=(test_id,), daemon=True)
    t.start()
    for _ in range(50):
      if reg_file.exists():
        break
      time.sleep(0.1)
    self.assertTrue(reg_file.exists(), "Registry file should be created")
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
    config = load_config()
    reg_file = pathlib.Path(config["registry_dir"]) / f"{test_id}.json"

    plugin.hash_str = test_id
    plugin.server_thread = threading.Thread(
        target=mcp_server_thread, args=(test_id,), daemon=True
    )
    plugin._server_started = True
    plugin.server_thread.start()

    # Wait for server to start
    for _ in range(50):
      if reg_file.exists():
        break
      time.sleep(0.1)

    self.assertTrue(reg_file.exists())
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
        mock.patch.object(
            idaapi, "inf_is_auto_enabled", return_value=True, create=True
        )
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
