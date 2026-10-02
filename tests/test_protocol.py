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

"""Unit tests for the gateway <-> backend protocol version check."""

import json
import pathlib
import tempfile
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway import forward
from ida_mcp.core.backend_registry import RegistryManager
from shared import liveness
from shared import protocol

# Keys that gateways from before the protocol check read from a record.
_LEGACY_KEYS = ("pid", "channel", "address", "name", "metadata")


class ProtocolCheckTest(unittest.TestCase):
  """Tests for the pure functions in shared.protocol."""

  def test_record_fields_contain_current_version(self):
    """Test that backends advertise the current version and capabilities."""
    fields = protocol.record_fields()
    self.assertEqual(fields["protocol_version"], protocol.PROTOCOL_VERSION)
    self.assertEqual(
        fields["capabilities"], sorted(protocol.BACKEND_CAPABILITIES)
    )

  def test_legacy_record_is_compatible(self):
    """Test that a record without protocol_version is accepted."""
    record = {"pid": 1, "channel": "uds", "address": "/tmp/x.sock"}
    self.assertTrue(protocol.is_legacy_record(record))
    self.assertIsNone(protocol.incompatibility_reason(record))

  def test_current_record_is_compatible(self):
    """Test that a record from the current backend is accepted."""
    record = protocol.record_fields()
    self.assertFalse(protocol.is_legacy_record(record))
    self.assertIsNone(protocol.incompatibility_reason(record))

  def test_older_backend_asks_to_restart_ida(self):
    """Test that a too-old backend version asks for an IDA restart."""
    with (
        mock.patch.object(protocol, "PROTOCOL_VERSION", 3),
        mock.patch.object(protocol, "MIN_BACKEND_PROTOCOL_VERSION", 2),
    ):
      reason = protocol.incompatibility_reason({"protocol_version": 1})
    self.assertIsNotNone(reason)
    self.assertIn("Restart IDA", reason)

  def test_newer_backend_asks_to_restart_client(self):
    """Test that a too-new backend version asks for a gateway restart."""
    reason = protocol.incompatibility_reason(
        {"protocol_version": protocol.PROTOCOL_VERSION + 1}
    )
    self.assertIsNotNone(reason)
    self.assertIn("Restart the MCP client", reason)

  def test_invalid_version_is_rejected(self):
    """Test that non-integer versions are rejected, including booleans."""
    for value in ("1", 1.0, True, None, [1]):
      with self.subTest(value=value):
        reason = protocol.incompatibility_reason({"protocol_version": value})
        self.assertIsNotNone(reason)
        self.assertIn("invalid protocol_version", reason)

  def test_parse_capabilities(self):
    """Test that only string entries of a list are used as capabilities."""
    self.assertEqual(
        protocol.parse_capabilities({"capabilities": ["b", "a", 3]}),
        frozenset({"a", "b"}),
    )
    self.assertEqual(protocol.parse_capabilities({}), frozenset())
    self.assertEqual(
        protocol.parse_capabilities({"capabilities": "a"}), frozenset()
    )


class RegistryRecordTest(unittest.TestCase):
  """Tests for the registry record written by the backend."""

  def test_record_keeps_legacy_keys_and_adds_protocol_fields(self):
    """Test that older gateways still find every key they read."""
    with tempfile.TemporaryDirectory() as tmp_dir:
      registry = RegistryManager(tmp_dir)
      path = registry.register(
          "UDS", "/tmp/db.sock", name="db1", metadata={"module": "m"}
      )
      self.assertIsNotNone(path)
      try:
        record = json.loads(path.read_text(encoding="utf-8"))
      finally:
        registry.cleanup()

    self.assertEqual(record["channel"], "uds")
    self.assertEqual(record["address"], "/tmp/db.sock")
    self.assertEqual(record["name"], "db1")
    self.assertEqual(record["metadata"], {"module": "m"})
    self.assertIsInstance(record["pid"], int)
    expected_keys = set(_LEGACY_KEYS) | {"protocol_version", "capabilities"}
    if liveness.supported():
      expected_keys.add(liveness.RECORD_FIELD)
    self.assertEqual(set(record), expected_keys)
    self.assertEqual(record["protocol_version"], protocol.PROTOCOL_VERSION)
    self.assertEqual(
        record["capabilities"], sorted(protocol.BACKEND_CAPABILITIES)
    )


class GatewayProtocolCheckTest(unittest.IsolatedAsyncioTestCase):
  """Tests for how the gateway handles backend protocol versions."""

  async def asyncSetUp(self):
    self._clear_gateway_state()
    self._tmp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp_dir.cleanup)
    rpc_client_patcher = mock.patch("gateway.forward.RPCClient")
    self.rpc_client_cls = rpc_client_patcher.start()
    self.addCleanup(rpc_client_patcher.stop)
    client = self.rpc_client_cls.return_value
    client.connect_uds = mock.AsyncMock()
    client.close = mock.AsyncMock()
    running_patcher = mock.patch(
        "gateway.forward._is_process_running", return_value=True
    )
    running_patcher.start()
    self.addCleanup(running_patcher.stop)

  async def asyncTearDown(self):
    self._clear_gateway_state()

  def _clear_gateway_state(self):
    forward._global_clients.clear()
    forward._global_metadata.clear()
    forward._global_capabilities.clear()
    forward._incompatible_backends.clear()
    forward._global_client_state.clear()
    forward._global_database_id_to_pid.clear()
    forward._backend_events.clear()

  def _write_record(self, backend_id: str, **fields) -> pathlib.Path:
    record = {
        "pid": 4242,
        "channel": "uds",
        "address": "/nonexistent/idamcp_test.sock",
        "name": backend_id,
        "metadata": {"module": "m"},
        **fields,
    }
    path = pathlib.Path(self._tmp_dir.name) / f"{backend_id}.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path

  async def test_legacy_record_connects_without_capabilities(self):
    """Test that a backend from before the check connects as before."""
    path = self._write_record("test-protocol-legacy")
    with self.assertLogs(level="WARNING") as logs:
      await forward.connect_to_backend(path)

    self.assertIn("test-protocol-legacy", forward._global_clients)
    self.assertEqual(
        forward.backend_capabilities("test-protocol-legacy"), frozenset()
    )
    self.assertNotIn("test-protocol-legacy", forward._incompatible_backends)
    self.assertTrue(
        any("did not report a protocol version" in line for line in logs.output)
    )

  async def test_current_record_connects_with_capabilities(self):
    """Test that advertised capabilities are available after connecting."""
    path = self._write_record(
        "test-protocol-current",
        protocol_version=protocol.PROTOCOL_VERSION,
        capabilities=["feature_x"],
    )
    await forward.connect_to_backend(path)

    self.assertIn("test-protocol-current", forward._global_clients)
    self.assertEqual(
        forward.backend_capabilities("test-protocol-current"),
        frozenset({"feature_x"}),
    )

  async def test_incompatible_record_is_not_connected(self):
    """Test that a version mismatch blocks the backend with a clear error."""
    path = self._write_record(
        "test-protocol-newer",
        protocol_version=protocol.PROTOCOL_VERSION + 1,
    )
    with self.assertLogs(level="ERROR"):
      await forward.connect_to_backend(path)

    self.assertNotIn("test-protocol-newer", forward._global_clients)
    self.assertIn("test-protocol-newer", forward._incompatible_backends)
    self.rpc_client_cls.return_value.connect_uds.assert_not_awaited()
    # The backend process is alive, so its registry file must stay.
    self.assertTrue(path.exists())

    with self.assertRaisesRegex(ToolError, "Restart the MCP client"):
      await forward.forward_to("test-protocol-newer", "get_metadata", {})
    with self.assertRaisesRegex(
        ToolError, r"\[test-protocol-newer\].*Restart the MCP client"
    ):
      await forward.list_available_databases()

  async def test_reregistering_compatible_backend_clears_mismatch(self):
    """Test that a restarted backend with a matching version connects."""
    with self.assertLogs(level="ERROR"):
      await forward.connect_to_backend(
          self._write_record("test-protocol-restart", protocol_version=0)
      )
    self.assertIn("test-protocol-restart", forward._incompatible_backends)

    await forward.connect_to_backend(
        self._write_record(
            "test-protocol-restart", protocol_version=protocol.PROTOCOL_VERSION
        )
    )
    self.assertIn("test-protocol-restart", forward._global_clients)
    self.assertNotIn("test-protocol-restart", forward._incompatible_backends)

  async def test_disconnect_clears_protocol_state(self):
    """Test that disconnecting removes capabilities and mismatch entries."""
    await forward.connect_to_backend(
        self._write_record(
            "test-protocol-connected",
            protocol_version=protocol.PROTOCOL_VERSION,
            capabilities=["feature_x"],
        )
    )
    forward._incompatible_backends["test-protocol-gone"] = "reason"

    await forward.disconnect_backend("test-protocol-connected")
    await forward.disconnect_backend("test-protocol-gone")

    self.assertEqual(
        forward.backend_capabilities("test-protocol-connected"), frozenset()
    )
    self.assertNotIn("test-protocol-gone", forward._incompatible_backends)


if __name__ == "__main__":
  unittest.main()
