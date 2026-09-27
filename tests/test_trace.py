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

"""Unit tests for the gateway JSONL trace."""

import contextlib
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway import forward
from gateway import trace
from shared.rpc import RPCError


def _read_records(path: pathlib.Path) -> list[dict]:
  return [json.loads(line) for line in path.read_text().splitlines()]


class TestJsonable(unittest.TestCase):
  """Tests for trace.jsonable."""

  def test_scalars_unchanged(self):
    for value in (None, True, 3, 1.5, "short"):
      self.assertEqual(trace.jsonable(value), value)

  def test_long_string_truncated(self):
    out = trace.jsonable("a" * (trace.MAX_STR_CHARS + 10))
    self.assertTrue(out.startswith("a" * trace.MAX_STR_CHARS))
    self.assertTrue(out.endswith("...(+10 chars)"))

  def test_bytes_replaced_by_size(self):
    self.assertEqual(trace.jsonable(b"\x00" * 7), "<7 bytes>")

  def test_list_capped(self):
    out = trace.jsonable(list(range(trace.MAX_ITEMS + 5)))
    self.assertEqual(len(out), trace.MAX_ITEMS + 1)
    self.assertEqual(out[-1], "...+5 items")

  def test_dict_capped(self):
    out = trace.jsonable({str(i): i for i in range(trace.MAX_ITEMS + 2)})
    self.assertEqual(out["..."], "+2 items")

  def test_depth_capped(self):
    nested = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    out = trace.jsonable(nested)
    self.assertEqual(out["a"]["b"]["c"]["d"], "<dict>")

  def test_unknown_object_uses_repr(self):
    self.assertEqual(
        trace.jsonable(pathlib.PurePosixPath("/x")), "PurePosixPath('/x')"
    )


class TestTraceLogger(unittest.TestCase):
  """Tests for TraceLogger file output."""

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.trace_dir = pathlib.Path(self.tmp.name) / "traces"

  def test_no_file_until_first_emit(self):
    logger = trace.TraceLogger(self.trace_dir)
    self.assertFalse(self.trace_dir.exists())
    logger.emit("tool_call", tool="x")
    self.assertTrue(logger.path.is_file())

  def test_record_fields_and_permissions(self):
    logger = trace.TraceLogger(self.trace_dir)
    logger.emit("tool_call", tool="decompile_function", args={"ea": "0x401000"})
    logger.emit("tool_call", tool="list_functions")
    records = _read_records(logger.path)
    self.assertEqual(len(records), 2)
    first = records[0]
    self.assertEqual(first["schema"], trace.TRACE_SCHEMA)
    self.assertEqual(first["server_id"], logger.server_id)
    self.assertEqual(first["pid"], os.getpid())
    self.assertEqual(first["event"], "tool_call")
    self.assertEqual(first["tool"], "decompile_function")
    self.assertEqual(first["args"], {"ea": "0x401000"})
    self.assertIn("ts", first)
    self.assertTrue(logger.path.name.startswith("gateway-"))
    self.assertTrue(logger.path.name.endswith(f"-{logger.server_id}.jsonl"))
    if sys.platform != "win32":
      self.assertEqual(stat.S_IMODE(logger.path.stat().st_mode), 0o600)
      self.assertEqual(stat.S_IMODE(self.trace_dir.stat().st_mode), 0o700)

  def test_write_failure_disables_without_raising(self):
    blocker = pathlib.Path(self.tmp.name) / "not_a_dir"
    blocker.write_text("")
    logger = trace.TraceLogger(blocker)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
      logger.emit("tool_call", tool="x")
      logger.emit("tool_call", tool="y")
    self.assertFalse(logger.enabled)
    self.assertEqual(err.getvalue().count("[WARNING] idamcp trace disabled"), 1)

  def test_from_config(self):
    self.assertIsNone(trace.trace_logger_from_config({}))
    self.assertIsNone(trace.trace_logger_from_config({"trace_dir": ""}))
    logger = trace.trace_logger_from_config({"trace_dir": str(self.trace_dir)})
    self.assertIsInstance(logger, trace.TraceLogger)


class TestForwardToTrace(unittest.IsolatedAsyncioTestCase):
  """Tests that forward_to records one line per call when tracing is on."""

  async def asyncSetUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.logger = trace.TraceLogger(pathlib.Path(self.tmp.name))
    forward._global_client_state.clear()
    forward._global_clients.clear()
    self.client = mock.AsyncMock()
    forward._global_clients["db1"] = self.client

  async def asyncTearDown(self):
    forward._global_client_state.clear()
    forward._global_clients.clear()

  async def test_disabled_writes_nothing(self):
    self.client.call.return_value = {"ok": 1}
    with mock.patch.object(forward, "TRACE", None):
      self.assertEqual(
          await forward.forward_to("db1", "ping", {"database_id": "db1"}),
          {"ok": 1},
      )
    self.assertFalse(self.logger.path.exists())

  async def test_ok_call(self):
    self.client.call.return_value = {"ok": 1}
    with mock.patch.object(forward, "TRACE", self.logger):
      result = await forward.forward_to(
          "db1", "decompile_function", {"database_id": "db1", "ea": "0x10"}
      )
    self.assertEqual(result, {"ok": 1})
    (record,) = _read_records(self.logger.path)
    self.assertEqual(record["tool"], "decompile_function")
    self.assertEqual(record["database_id"], "db1")
    self.assertEqual(record["args"], {"ea": "0x10"})
    self.assertEqual(record["outcome"], "ok")
    self.assertIsInstance(record["duration_ms"], float)
    self.assertEqual(len(record["call_id"]), 12)
    self.assertNotIn("error", record)

  async def test_error_call(self):
    self.client.call.side_effect = RPCError("boom")
    with mock.patch.object(forward, "TRACE", self.logger):
      with self.assertRaises(ToolError):
        await forward.forward_to("db1", "rename", {"database_id": "db1"})
    (record,) = _read_records(self.logger.path)
    self.assertEqual(record["outcome"], "error")
    self.assertIn("boom", record["error"])

  async def test_unknown_database_is_traced(self):
    with mock.patch.object(forward, "TRACE", self.logger):
      with self.assertRaises(ToolError):
        await forward.forward_to("missing", "ping", {})
    (record,) = _read_records(self.logger.path)
    self.assertEqual(record["database_id"], "missing")
    self.assertEqual(record["outcome"], "error")


if __name__ == "__main__":
  unittest.main()
