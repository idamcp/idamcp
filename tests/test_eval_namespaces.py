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

"""Unit tests for per-session idapython_eval namespaces (no IDA)."""

import asyncio
import contextvars
import enum
import json
import pathlib
import sys
import threading
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

MOCKED_MODULES = [
    "ida_bytes",
    "ida_dbg",
    "ida_idp",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "idautils",
    "idc",
]
for module in MOCKED_MODULES:
  if module not in sys.modules:
    sys.modules[module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top
from gateway import forward
from ida_mcp.core import synchronization
from ida_mcp.tools import execution
from shared import protocol
from shared import rpc

# pylint: enable=g-import-not-at-top

_real_mcp_session_id = forward._mcp_session_id

idapython_eval = getattr(
    execution.idapython_eval, "sync_call", execution.idapython_eval
)


def _scope(scope: str):
  return mock.patch.object(
      execution,
      "load_config",
      return_value={"eval_namespace_scope": scope},
  )


def _as_request(connection, meta):
  """Returns a context that looks like an RPC request to execution."""
  context = contextvars.copy_context()
  context.run(rpc._connection_var.set, connection)
  context.run(rpc._meta_var.set, meta)
  return context


class TestRPCMeta(unittest.IsolatedAsyncioTestCase):
  """Tests for the request metadata and connection id in shared.rpc."""

  async def asyncSetUp(self):
    self.closed = []
    self.listener = self.closed.append
    rpc.add_connection_close_listener(self.listener)
    self.addCleanup(rpc._connection_close_listeners.remove, self.listener)
    self.rpc_server = rpc.RPCServer({
        "whoami": lambda: {
            "connection": rpc.current_connection(),
            "meta": rpc.current_meta(),
        },
    })
    self.server = await self.rpc_server.start_tcp("127.0.0.1", 0)
    self.port = self.server.sockets[0].getsockname()[1]
    # Registered before any client, so it runs after the clients are closed:
    # wait_closed() waits for open connections on Python 3.12+.
    self.addAsyncCleanup(self._stop_server)

  async def _stop_server(self):
    self.server.close()
    await self.server.wait_closed()

  async def _client(self) -> rpc.RPCClient:
    client = rpc.RPCClient()
    await client.connect_tcp("127.0.0.1", self.port)
    self.addAsyncCleanup(client.close)
    return client

  async def test_meta_reaches_the_method(self):
    client = await self._client()
    result = await client.call("whoami", {}, meta={"session": "s1"})
    self.assertEqual(result["meta"], {"session": "s1"})
    self.assertIsNotNone(result["connection"])

  async def test_no_meta_is_empty_and_not_sent(self):
    client = await self._client()
    result = await client.call("whoami", {})
    self.assertEqual(result["meta"], {})

  async def test_invalid_meta_is_ignored(self):
    reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
    request = {
        "jsonrpc": "2.0",
        "method": "whoami",
        "params": {},
        "id": 1,
        "meta": "not-an-object",
    }
    writer.write(json.dumps(request).encode() + b"\n")
    await writer.drain()
    response = json.loads(await asyncio.wait_for(reader.readline(), 5))
    writer.close()
    await writer.wait_closed()
    self.assertEqual(response["result"]["meta"], {})

  async def test_connections_have_distinct_ids(self):
    first = await (await self._client()).call("whoami", {})
    second = await (await self._client()).call("whoami", {})
    self.assertNotEqual(first["connection"], second["connection"])

  async def test_close_listener_gets_connection_id(self):
    client = rpc.RPCClient()
    await client.connect_tcp("127.0.0.1", self.port)
    connection = (await client.call("whoami", {}))["connection"]
    await client.close()
    for _ in range(100):
      if connection in self.closed:
        break
      await asyncio.sleep(0.01)
    self.assertIn(connection, self.closed)

  async def test_meta_does_not_leak_to_server_context(self):
    client = await self._client()
    await client.call("whoami", {}, meta={"session": "s1"})
    self.assertEqual(rpc.current_meta(), {})
    self.assertIsNone(rpc.current_connection())


class TestNamespaces(unittest.TestCase):
  """Tests for execution._current_namespace and idapython_eval."""

  def setUp(self):
    execution._init_session_globals()
    execution._session_namespaces.clear()
    self.addCleanup(execution._session_namespaces.clear)
    execution._session_globals.pop("ns_var", None)
    self.addCleanup(execution._session_globals.pop, "ns_var", None)

  def _eval(self, code, connection=None, meta=None):
    context = _as_request(connection, meta or {})
    return context.run(idapython_eval, code)

  def test_process_scope_shares_one_namespace(self):
    with _scope("process"):
      self._eval("ns_var = 1", connection=1, meta={"session": "a"})
      result = self._eval("ns_var", connection=2, meta={"session": "b"})
    self.assertEqual(result["result"], "1")
    self.assertEqual(execution._session_namespaces, {})

  def test_session_scope_isolates_sessions(self):
    with _scope("session"):
      self._eval("ns_var = 'a'", connection=1, meta={"session": "a"})
      self._eval("ns_var = 'b'", connection=1, meta={"session": "b"})
      result_a = self._eval("ns_var", connection=1, meta={"session": "a"})
      result_b = self._eval("ns_var", connection=1, meta={"session": "b"})
    self.assertEqual(result_a["result"], "a")
    self.assertEqual(result_b["result"], "b")
    self.assertNotIn("ns_var", execution._session_globals)

  def test_session_scope_without_meta_uses_connection(self):
    with _scope("session"):
      self._eval("ns_var = 1", connection=1)
      same = self._eval("ns_var", connection=1)
      other = self._eval("ns_var", connection=2)
    self.assertEqual(same["result"], "1")
    self.assertIn("NameError", other["stderr"])

  def test_session_namespace_has_ida_modules(self):
    with _scope("session"):
      result = self._eval(
          "idc is not None and callable(get_function)",
          connection=1,
          meta={"session": "a"},
      )
    self.assertEqual(result["result"], "True")

  def test_new_session_does_not_see_process_variables(self):
    with _scope("process"):
      self._eval("ns_var = 1")
    with _scope("session"):
      result = self._eval("ns_var", connection=1, meta={"session": "a"})
    self.assertIn("NameError", result["stderr"])

  def test_session_scope_outside_rpc_uses_process_namespace(self):
    with _scope("session"):
      self._eval("ns_var = 7")
    self.assertEqual(execution._session_globals["ns_var"], 7)

  def test_unknown_scope_warns_once_and_uses_process(self):
    execution._warned_scope.discard("bogus")
    with _scope("bogus"), self.assertLogs(execution.logger, "WARNING") as cm:
      self._eval("ns_var = 3", connection=1, meta={"session": "a"})
      self._eval("ns_var", connection=1, meta={"session": "a"})
    self.assertEqual(len(cm.output), 1)
    self.assertEqual(execution._session_globals["ns_var"], 3)

  def test_least_recently_used_namespace_is_dropped(self):
    limit = execution._MAX_SESSION_NAMESPACES
    with _scope("session"):
      self._eval("ns_var = 'first'", connection=1, meta={"session": "s0"})
      for i in range(1, limit):
        self._eval("pass", connection=1, meta={"session": f"s{i}"})
      # Touch s0 so s1 becomes the least recently used one.
      self._eval("pass", connection=1, meta={"session": "s0"})
      self._eval("pass", connection=1, meta={"session": "new"})
      kept = self._eval("ns_var", connection=1, meta={"session": "s0"})
    self.assertEqual(len(execution._session_namespaces), limit)
    self.assertNotIn((1, "s1"), execution._session_namespaces)
    self.assertEqual(kept["result"], "first")

  def test_closed_connection_drops_its_namespaces(self):
    with _scope("session"):
      self._eval("pass", connection=1, meta={"session": "a"})
      self._eval("pass", connection=1)
      self._eval("pass", connection=2, meta={"session": "a"})
    execution._drop_connection_namespaces(1)
    self.assertEqual(list(execution._session_namespaces), [(2, "a")])

  def test_close_listener_is_registered(self):
    self.assertIn(
        execution._drop_connection_namespaces,
        rpc._connection_close_listeners,
    )


class IDASafety(enum.IntEnum):
  SAFE_NONE = 0
  SAFE_READ = 1
  SAFE_WRITE = 2


class TestIDACallContext(unittest.TestCase):
  """Tests that _IDACall runs the function in the caller's context."""

  def setUp(self):
    patcher = mock.patch.object(synchronization, "IDASafety", IDASafety)
    patcher.start()
    self.addCleanup(patcher.stop)

  def test_context_reaches_other_thread(self):
    def build_call():
      rpc._meta_var.set({"session": "s1"})
      return synchronization._IDACall(rpc.current_meta, IDASafety.SAFE_READ)

    call = contextvars.copy_context().run(build_call)
    thread = threading.Thread(target=call._runned)
    thread.start()
    thread.join()
    self.assertEqual(call.get_result(), {"session": "s1"})
    self.assertEqual(rpc.current_meta(), {})


class TestGatewayMeta(unittest.IsolatedAsyncioTestCase):
  """Tests that the gateway sends the session id only when supported."""

  def setUp(self):
    self.client = mock.AsyncMock()
    self.client.call.return_value = "ok"
    forward._global_clients["db"] = self.client
    self.addCleanup(forward._global_clients.pop, "db", None)
    self.addCleanup(forward._global_capabilities.pop, "db", None)
    self.addCleanup(forward._global_client_state.pop, "db", None)
    patcher = mock.patch.object(
        forward, "_mcp_session_id", return_value="session-1"
    )
    self.session_id = patcher.start()
    self.addCleanup(patcher.stop)

  def test_backend_advertises_capability(self):
    self.assertIn("eval_namespaces", protocol.BACKEND_CAPABILITIES)

  async def test_meta_sent_with_capability(self):
    forward._global_capabilities["db"] = frozenset({"eval_namespaces"})
    await forward.forward_to("db", "idapython_eval", {"code": "1"})
    self.client.call.assert_awaited_once_with(
        method="idapython_eval",
        params={"code": "1"},
        meta={"session": "session-1"},
    )

  async def test_no_meta_without_capability(self):
    await forward.forward_to("db", "idapython_eval", {"code": "1"})
    self.client.call.assert_awaited_once_with(
        method="idapython_eval", params={"code": "1"}
    )

  async def test_no_meta_without_session(self):
    forward._global_capabilities["db"] = frozenset({"eval_namespaces"})
    self.session_id.return_value = None
    await forward.forward_to("db", "idapython_eval", {"code": "1"})
    self.client.call.assert_awaited_once_with(
        method="idapython_eval", params={"code": "1"}
    )

  def test_session_id_outside_mcp_request_is_none(self):
    # No FastMCP request context is active in this test.
    self.assertIsNone(_real_mcp_session_id())


if __name__ == "__main__":
  unittest.main()
