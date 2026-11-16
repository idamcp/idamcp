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

"""Unit tests for the Security Dashboard backend discovery and RPC routing."""

import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import fastapi
from frontend import security_dashboard
from shared import registry
from shared.rpc import RPCServer
from shared.rpc import ToolError

_DEAD_PID = 4_999_991
_LIVE_PID = 4_999_993


def _iid(label: str) -> str:
  """Returns a well-formed instance ID that stands for a readable label."""
  return label.encode().hex()[:16].ljust(16, "0")


class TestSecurityDashboard(unittest.IsolatedAsyncioTestCase):
  """Tests security_dashboard endpoints with instance-named registry records."""

  async def asyncSetUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.tmp = pathlib.Path(tmp.name)
    self.alive: set[int] = set()
    self.servers: list[RPCServer] = []
    for patcher in (
        mock.patch.object(security_dashboard, "REGISTRY_DIR", self.tmp),
        mock.patch.object(
            security_dashboard, "is_process_running", self.alive.__contains__
        ),
    ):
      patcher.start()
      self.addCleanup(patcher.stop)

  async def asyncTearDown(self):
    for server in self.servers:
      await server.close()

  async def _start_backend(
      self,
      db_id: str,
      instance_id: str,
      pid: int,
      in_progress: bool = False,
      started_at: float = 1000.0,
  ) -> tuple[pathlib.Path, dict[str, bool]]:
    def get_config():
      return {"enable_all_unsafe_tools": False, "enabled_unsafe_tools": []}

    def configure(**_kwargs):
      if state["in_progress"]:
        raise ToolError("auto analysis is still in progress, please wait.")
      return "Security settings updated."

    state = {"in_progress": in_progress}
    server = RPCServer({
        "get_security_config": get_config,
        "configure_unsafe_tools": configure,
    })
    tcp_server = await server.start_tcp("127.0.0.1", 0)
    self.servers.append(server)
    self.alive.add(pid)
    record = {
        "pid": pid,
        "channel": "tcp",
        "address": tcp_server.sockets[0].getsockname()[1],
        "database_id": db_id,
        "started_at": started_at,
        "auto_analysis_disabled": False,
        "metadata": {"module": "target.bin"},
    }
    path = self.tmp / registry.record_name(instance_id, in_progress)
    path.write_text(json.dumps(record), encoding="utf-8")
    return path, state

  async def test_call_rpc_routes_by_database_name_across_promotion(self):
    """Test call_rpc finds instance-named records before and after promotion."""
    in_progress_path, state = await self._start_backend(
        "db_hash", _iid("iid_1"), _LIVE_PID, in_progress=True
    )
    backends = await security_dashboard.get_backends()
    self.assertEqual([b["database_id"] for b in backends], ["db_hash"])

    # Read-only security config works during auto-analysis; writes fail.
    res = await security_dashboard.call_rpc(
        "db_hash", security_dashboard.RpcRequest(method="get_security_config")
    )
    self.assertFalse(res["isError"])
    res = await security_dashboard.call_rpc(
        "db_hash",
        security_dashboard.RpcRequest(method="configure_unsafe_tools"),
    )
    self.assertTrue(res["isError"])
    self.assertIn(
        "auto analysis is still in progress", res["content"][0]["text"]
    )

    # Promote the record and lift the error.
    promoted = self.tmp / registry.record_name(_iid("iid_1"), False)
    os.replace(in_progress_path, promoted)
    state["in_progress"] = False
    res = await security_dashboard.call_rpc(
        "db_hash",
        security_dashboard.RpcRequest(method="configure_unsafe_tools"),
    )
    self.assertFalse(res["isError"])
    self.assertEqual(
        json.loads(res["content"][0]["text"]), "Security settings updated."
    )

  async def test_read_record_follows_a_promotion_only(self):
    """Test _read_record finds a renamed record, and only in that direction."""
    in_progress_path, _ = await self._start_backend(
        "db_hash", _iid("iid_1"), _LIVE_PID, in_progress=True
    )
    promoted = self.tmp / registry.record_name(_iid("iid_1"), False)
    # Renamed after the directory was listed.
    os.replace(in_progress_path, promoted)
    data = security_dashboard._read_record(in_progress_path)
    assert data is not None
    self.assertEqual(data["pid"], _LIVE_PID)

    # A plain record that is gone was removed: a backend never renames its
    # record back to the in-progress name.
    os.replace(promoted, in_progress_path)
    self.assertIsNone(security_dashboard._read_record(promoted))

  async def test_dead_backend_cleanup_and_successor_routing(self):
    """Test dead records and UDS sockets are cleaned up without hiding live."""
    stale_sock = self.tmp / f"{_iid('dead_iid')}.sock"
    stale_sock.write_text("", encoding="utf-8")
    stale_record = self.tmp / registry.record_name(_iid("dead_iid"), False)
    stale_record.write_text(
        json.dumps({
            "pid": _DEAD_PID,
            "channel": "uds",
            "address": str(stale_sock),
            "database_id": "db_hash",
            "started_at": 500.0,
            "metadata": {},
        }),
        encoding="utf-8",
    )
    await self._start_backend("db_hash", _iid("live_iid"), _LIVE_PID)

    # Even before get_backends cleans up stale_record, call_rpc skips dead_iid.
    res = await security_dashboard.call_rpc(
        "db_hash", security_dashboard.RpcRequest(method="get_security_config")
    )
    self.assertFalse(res["isError"])

    backends = await security_dashboard.get_backends()
    self.assertEqual(len(backends), 1)
    self.assertEqual(backends[0]["pid"], _LIVE_PID)
    self.assertFalse(stale_record.exists())
    self.assertFalse(stale_sock.exists())

  async def test_busy_live_backend_record_is_not_deleted(self):
    """Test a live process whose ping fails keeps its registry record."""
    self.alive.add(_LIVE_PID)
    busy_record = self.tmp / registry.record_name(_iid("busy_iid"), False)
    busy_record.write_text(
        json.dumps({
            "pid": _LIVE_PID,
            "channel": "uds",
            "address": str(self.tmp / "nonexistent.sock"),
            "database_id": "db_busy",
            "started_at": 1000.0,
            "metadata": {},
        }),
        encoding="utf-8",
    )
    backends = await security_dashboard.get_backends()
    self.assertEqual(backends, [])
    self.assertTrue(busy_record.exists())

  async def test_get_backends_deduplicates_by_database_id(self):
    """Test two live records sharing a database ID return a single backend."""
    await self._start_backend("db_hash", _iid("iid_1"), _LIVE_PID)
    await self._start_backend("db_hash", _iid("iid_2"), _LIVE_PID + 1)
    backends = await security_dashboard.get_backends()
    self.assertEqual(len(backends), 1)
    self.assertEqual(backends[0]["database_id"], "db_hash")
    self.assertEqual(backends[0]["pid"], _LIVE_PID)

  async def test_newest_instance_is_listed_and_called(self):
    """Test listing and calls both use the instance that started last."""
    # The later instance sorts second by file name.
    await self._start_backend(
        "db_hash", _iid("aaaa_old"), _LIVE_PID, started_at=1.0
    )
    await self._start_backend(
        "db_hash", _iid("zzzz_new"), _LIVE_PID + 1, started_at=2.0
    )
    backends = await security_dashboard.get_backends()
    self.assertEqual([b["pid"] for b in backends], [_LIVE_PID + 1])
    info = security_dashboard._find_backend_info("db_hash")
    assert info is not None
    self.assertEqual(info["pid"], _LIVE_PID + 1)

  async def test_leftover_record_with_reused_pid_does_not_shadow(self):
    """Test a leftover whose PID is alive doesn't take the calls."""
    self.alive.add(_DEAD_PID)  # Reused by an unrelated process.
    leftover = self.tmp / registry.record_name(_iid("0000_leftover"), False)
    leftover.write_text(
        json.dumps({
            "pid": _DEAD_PID,
            "channel": "uds",
            "address": str(self.tmp / f"{_iid('0000_leftover')}.sock"),
            "database_id": "db_hash",
            "started_at": 1.0,
            "metadata": {},
        }),
        encoding="utf-8",
    )
    await self._start_backend(
        "db_hash", _iid("ffff_live"), _LIVE_PID, started_at=2.0
    )

    backends = await security_dashboard.get_backends()
    self.assertEqual([b["pid"] for b in backends], [_LIVE_PID])
    res = await security_dashboard.call_rpc(
        "db_hash", security_dashboard.RpcRequest(method="get_security_config")
    )
    self.assertFalse(res["isError"])

  async def test_call_rpc_missing_backend_returns_404(self):
    """Test call_rpc raises 404 when no live record matches backend_name."""
    with self.assertRaises(fastapi.HTTPException) as ctx:
      await security_dashboard.call_rpc(
          "missing_db",
          security_dashboard.RpcRequest(method="get_security_config"),
      )
    self.assertEqual(ctx.exception.status_code, 404)

  def test_index_html_checks_is_error_and_reverts_failed_updates(self):
    """Test index.html surfaces RPC errors and reverts failed config writes."""
    html = (
        pathlib.Path(security_dashboard.__file__).parent / "index.html"
    ).read_text(encoding="utf-8")
    self.assertIn("data.isError", html)
    self.assertIn("currentConfig = prevConfig;", html)
    self.assertIn("renderTools();", html)


if __name__ == "__main__":
  unittest.main()
