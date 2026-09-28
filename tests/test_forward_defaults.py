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

"""Tests for forwarding only non-default arguments to backends.

Covers a newer gateway talking to an IDA instance that still runs an older
plugin, whose tools lack parameters the gateway knows about.
"""

import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway import forward
from gateway.forward import _drop_default_arguments
from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _is_default_value
from gateway.forward import _register_tool_defaults
from gateway.forward import _TOOL_DEFAULTS
from gateway.forward import forward_to
from ida_mcp.core.decorators import adapt_arguments
from shared.rpc import RPCClient
from shared.rpc import RPCError
from shared.rpc import RPCServer


# Signature as known by a newer gateway (generated proxy).
async def fake_tool(
    database_id: str,
    address: str,
    count: int = 0,
    flag: bool = False,
    name: str | None = None,
    mode: str = "down",
    new_option: bool = False,
) -> str:
  del database_id, address, count, flag, name, mode, new_option
  return ""


# Same tool as implemented by an older plugin: no `new_option`.
def old_backend_fake_tool(
    address: str,
    count: int = 0,
    flag: bool = False,
    name: str | None = None,
    mode: str = "down",
) -> dict[str, object]:
  return {
      "address": address,
      "count": count,
      "flag": flag,
      "name": name,
      "mode": mode,
  }


def _proxy_args(**overrides):
  """Builds the `locals()` dict the generated proxy would forward."""
  args = {
      "database_id": "db",
      "address": "0x1000",
      "count": 0,
      "flag": False,
      "name": None,
      "mode": "down",
      "new_option": False,
  }
  args.update(overrides)
  return args


class TestDefaultHelpers(unittest.TestCase):
  """Tests for the default-dropping helpers."""

  def setUp(self):
    self._saved = dict(_TOOL_DEFAULTS)
    _register_tool_defaults(fake_tool)

  def tearDown(self):
    _TOOL_DEFAULTS.clear()
    _TOOL_DEFAULTS.update(self._saved)

  def test_register_records_only_parameters_with_defaults(self):
    self.assertEqual(
        _TOOL_DEFAULTS["fake_tool"],
        {
            "count": 0,
            "flag": False,
            "name": None,
            "mode": "down",
            "new_option": False,
        },
    )

  def test_is_default_value_is_type_strict(self):
    self.assertTrue(_is_default_value(False, False))
    self.assertTrue(_is_default_value(0, 0))
    self.assertTrue(_is_default_value(None, None))
    self.assertTrue(_is_default_value("down", "down"))
    self.assertFalse(_is_default_value(0, False))
    self.assertFalse(_is_default_value(False, 0))
    self.assertFalse(_is_default_value(1, True))
    self.assertFalse(_is_default_value("", None))
    self.assertFalse(_is_default_value(None, ""))
    self.assertFalse(_is_default_value(0.0, 0))
    self.assertFalse(_is_default_value("up", "down"))

  def test_all_defaults_are_dropped(self):
    self.assertEqual(
        _drop_default_arguments("fake_tool", _proxy_args()),
        {"address": "0x1000"},
    )

  def test_non_default_values_are_kept(self):
    self.assertEqual(
        _drop_default_arguments(
            "fake_tool",
            _proxy_args(count=5, flag=True, name="", mode="up"),
        ),
        {
            "address": "0x1000",
            "count": 5,
            "flag": True,
            "name": "",
            "mode": "up",
        },
    )

  def test_database_id_is_never_forwarded(self):
    self.assertNotIn(
        "database_id", _drop_default_arguments("fake_tool", _proxy_args())
    )

  def test_unknown_tool_forwards_everything(self):
    args = _proxy_args()
    expected = {k: v for k, v in args.items() if k != "database_id"}
    self.assertEqual(_drop_default_arguments("unknown_tool", args), expected)

  def test_internal_calls_are_forwarded_as_is(self):
    # Gateway-internal calls (e.g. gateway/query.py -> backend sql_query) do
    # not pass database_id and must not be filtered, even when a gateway tool
    # with the same name has defaults.
    args = {"count": 0, "flag": False}
    self.assertEqual(_drop_default_arguments("fake_tool", args), args)


class TestMixedVersionForwarding(unittest.IsolatedAsyncioTestCase):
  """End-to-end: new gateway -> RPC -> backend running an older tool."""

  async def asyncSetUp(self):
    self._saved = dict(_TOOL_DEFAULTS)
    _register_tool_defaults(fake_tool)
    # Same wrapper the plugin applies to every @jsonrpc tool.
    self.rpc_server = RPCServer(
        {"fake_tool": adapt_arguments(old_backend_fake_tool)}
    )
    self.server = await self.rpc_server.start_tcp("127.0.0.1", 0)
    port = self.server.sockets[0].getsockname()[1]
    self.client = RPCClient()
    await self.client.connect_tcp("127.0.0.1", port)
    _global_clients["db"] = self.client
    _global_client_state.pop("db", None)

  async def asyncTearDown(self):
    _global_clients.pop("db", None)
    _global_client_state.pop("db", None)
    await self.client.close()
    self.server.close()
    await self.server.wait_closed()
    _TOOL_DEFAULTS.clear()
    _TOOL_DEFAULTS.update(self._saved)

  async def test_new_parameter_left_at_default_works(self):
    result = await forward_to("db", "fake_tool", _proxy_args(count=3))
    self.assertEqual(
        result,
        {
            "address": "0x1000",
            "count": 3,
            "flag": False,
            "name": None,
            "mode": "down",
        },
    )

  async def test_new_parameter_used_reports_old_plugin(self):
    with self.assertRaises(ToolError) as ctx:
      await forward_to("db", "fake_tool", _proxy_args(new_option=True))
    message = str(ctx.exception)
    self.assertIn("does not support parameter 'new_option'", message)
    self.assertIn("fake_tool", message)
    self.assertIn("restart IDA", message)

  async def test_without_dropping_old_backend_rejects_call(self):
    # Documents the pre-existing failure mode this change avoids.
    with mock.patch.object(
        forward,
        "_drop_default_arguments",
        side_effect=lambda _, a: {
            k: v for k, v in a.items() if k != "database_id"
        },
    ):
      with self.assertRaises(ToolError) as ctx:
        await forward_to("db", "fake_tool", _proxy_args())
    self.assertIn("'new_option'", str(ctx.exception))

  async def test_other_backend_errors_are_unchanged(self):
    with mock.patch.object(
        self.client, "call", side_effect=RPCError("boom", -32603)
    ):
      with self.assertRaises(ToolError) as ctx:
        await forward_to("db", "fake_tool", _proxy_args())
    self.assertEqual(str(ctx.exception), "Backend tool error: boom")


if __name__ == "__main__":
  unittest.main()
