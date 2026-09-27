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

"""Tests for idalib_headless_open resolving files already open elsewhere."""

import asyncio
import os
import tempfile
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway import forward
from gateway.forward import _database_in_use_message
from gateway.forward import _find_open_database
from gateway.forward import _global_client_state
from gateway.forward import _global_clients
from gateway.forward import _global_metadata
from gateway.forward import _same_file
from gateway.forward import _unpacked_database_exists
from gateway.forward import HeadlessManager


class _Files(unittest.TestCase):
  """Creates a binary, its .i64 and a symlink in a temp dir."""

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.dir = self._tmp.name
    self.binary = os.path.join(self.dir, "sample.bin")
    self.idb = self.binary + ".i64"
    self.link = os.path.join(self.dir, "link.bin")
    for p in (self.binary, self.idb):
      with open(p, "wb") as f:
        f.write(b"x")
    os.symlink(self.binary, self.link)

  def tearDown(self):
    self._tmp.cleanup()


class TestHelpers(_Files):
  """Tests for the path helpers."""

  def test_same_file(self):
    self.assertTrue(_same_file(self.binary, self.binary))
    self.assertTrue(_same_file(self.link, self.binary))
    self.assertTrue(
        _same_file(os.path.join(self.dir, "x", "..", "sample.bin"), self.binary)
    )
    self.assertFalse(_same_file(self.idb, self.binary))
    self.assertFalse(_same_file(None, self.binary))
    self.assertFalse(_same_file("", self.binary))

  def test_same_file_missing_path_falls_back_to_realpath(self):
    missing = os.path.join(self.dir, "gone.bin")
    self.assertFalse(_same_file(missing, self.binary))
    self.assertTrue(_same_file(missing, missing))

  def test_unpacked_database_exists(self):
    self.assertFalse(_unpacked_database_exists(self.binary))
    self.assertFalse(_unpacked_database_exists(self.idb))
    open(self.binary + ".id0", "wb").close()
    self.assertTrue(_unpacked_database_exists(self.binary))
    self.assertTrue(_unpacked_database_exists(self.idb))
    self.assertTrue(_unpacked_database_exists(self.binary + ".IDB"))

  def test_in_use_message_mentions_gui_and_recovery(self):
    msg = _database_in_use_message(self.binary)
    self.assertIn("open in another IDA process", msg)
    self.assertIn("Ctrl-Alt-M", msg)
    self.assertIn("crashed", msg)


class TestFindOpenDatabase(_Files):
  """Tests for _find_open_database."""

  def setUp(self):
    super().setUp()
    _global_metadata.clear()
    _global_clients.clear()
    _global_client_state.clear()
    self.running = mock.patch.object(
        forward, "_is_process_running", return_value=True
    )
    self.running.start()

  def tearDown(self):
    self.running.stop()
    _global_metadata.clear()
    _global_clients.clear()
    _global_client_state.clear()
    super().tearDown()

  def _connect(self, db_id, **metadata):
    metadata.setdefault("pid", 1234)
    _global_metadata[db_id] = {"database_id": db_id, **metadata}
    _global_clients[db_id] = mock.Mock()

  def test_matches_input_file_idb_and_symlink(self):
    self._connect("gui1", filepath=self.binary, database_path=self.idb)
    for path in (self.binary, self.idb, self.link):
      info = _find_open_database(path)
      self.assertIsNotNone(info, path)
      self.assertEqual(info["database_id"], "gui1")
      self.assertTrue(info["already_open"])
    # The stored metadata is not modified.
    self.assertNotIn("already_open", _global_metadata["gui1"])

  def test_no_match(self):
    self._connect("gui1", filepath=self.binary, database_path=self.idb)
    other = os.path.join(self.dir, "other.bin")
    open(other, "wb").close()
    self.assertIsNone(_find_open_database(other))

  def test_skips_dead_closed_or_disconnected(self):
    self._connect("dead", filepath=self.binary)
    with mock.patch.object(forward, "_is_process_running", return_value=False):
      self.assertIsNone(_find_open_database(self.binary))
    _global_metadata.clear()
    self._connect("closed", filepath=self.binary)
    _global_client_state["closed"].is_closed = True
    self.assertIsNone(_find_open_database(self.binary))
    _global_metadata.clear()
    self._connect("noclient", filepath=self.binary)
    del _global_clients["noclient"]
    self.assertIsNone(_find_open_database(self.binary))
    _global_metadata.clear()
    self._connect("nopid", filepath=self.binary, pid=None)
    self.assertIsNone(_find_open_database(self.binary))


class TestSpawn(_Files):
  """Tests for HeadlessManager.spawn with an already-open file."""

  def setUp(self):
    super().setUp()
    _global_metadata.clear()
    _global_clients.clear()
    _global_client_state.clear()

  def tearDown(self):
    _global_metadata.clear()
    _global_clients.clear()
    _global_client_state.clear()
    super().tearDown()

  async def _spawn(self, manager, path):
    return await manager.spawn(path)

  def test_returns_existing_without_spawning(self):
    _global_metadata["gui1"] = {
        "database_id": "gui1",
        "pid": 1234,
        "filepath": self.binary,
        "database_path": self.idb,
    }
    _global_clients["gui1"] = mock.Mock()
    manager = HeadlessManager(max_instances=0)
    with (
        mock.patch.object(forward, "_is_process_running", return_value=True),
        mock.patch(
            "asyncio.create_subprocess_exec", new_callable=mock.AsyncMock
        ) as spawn_proc,
    ):
      info = asyncio.run(self._spawn(manager, self.link))
    spawn_proc.assert_not_called()
    self.assertEqual(info["database_id"], "gui1")
    self.assertTrue(info["already_open"])
    # max_instances=0 did not block returning an existing database.

  def test_load_options_with_existing_raises(self):
    _global_metadata["gui1"] = {
        "database_id": "gui1",
        "pid": 1234,
        "filepath": self.binary,
    }
    _global_clients["gui1"] = mock.Mock()
    manager = HeadlessManager(max_instances=1)
    with (
        mock.patch.object(forward, "_is_process_running", return_value=True),
        mock.patch(
            "asyncio.create_subprocess_exec", new_callable=mock.AsyncMock
        ) as spawn_proc,
    ):
      with self.assertRaisesRegex(ToolError, "already open in gui1"):
        asyncio.run(
            manager.spawn(
                self.binary, forward.load_options.LoadOptions(processor="arm")
            )
        )
    spawn_proc.assert_not_called()

  def test_in_use_error_when_backend_emits_no_metadata(self):
    open(self.binary + ".id0", "wb").close()

    class _Proc:
      pid = 4321
      stderr = None

      def __init__(self):
        self.stdout = mock.Mock()
        self.stdout.readline = mock.AsyncMock(return_value=b"")

      def terminate(self):
        pass

    manager = HeadlessManager(max_instances=1)
    with mock.patch(
        "asyncio.create_subprocess_exec",
        new_callable=mock.AsyncMock,
        return_value=_Proc(),
    ):
      with self.assertRaises(ToolError) as ctx:
        asyncio.run(self._spawn(manager, self.binary))
    self.assertIn("open in another IDA process", str(ctx.exception))
    self.assertEqual(manager._pending_spawns, 0)

  def test_generic_error_without_unpacked_files(self):
    class _Proc:
      pid = 4321
      stderr = None

      def __init__(self):
        self.stdout = mock.Mock()
        self.stdout.readline = mock.AsyncMock(return_value=b"")

      def terminate(self):
        pass

    manager = HeadlessManager(max_instances=1)
    with mock.patch(
        "asyncio.create_subprocess_exec",
        new_callable=mock.AsyncMock,
        return_value=_Proc(),
    ):
      with self.assertRaises(ToolError) as ctx:
        asyncio.run(self._spawn(manager, self.binary))
    self.assertEqual(str(ctx.exception), "metadata is None")


if __name__ == "__main__":
  unittest.main()
