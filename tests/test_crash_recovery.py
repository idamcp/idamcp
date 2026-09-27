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

"""Tests for gateway.crash_recovery (fixture files, no IDA)."""

import asyncio
import fcntl
import os
import tempfile
import unittest
from unittest import mock

from fastmcp.exceptions import ToolError
from gateway import crash_recovery
from gateway import forward

_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")


def _header(dirty=1, signature=b"B-tree v2"):
  return b"\0" * 18 + bytes([dirty]) + signature + b"\0" * 64


class _Dir(unittest.TestCase):
  """A temp dir with a binary and helpers to create leftovers."""

  def setUp(self):
    super().setUp()
    self._tmp = tempfile.TemporaryDirectory()
    self.dir = self._tmp.name
    self.binary = os.path.join(self.dir, "sample.bin")
    self.i64 = self.binary + ".i64"
    with open(self.binary, "wb") as f:
      f.write(b"bin")
    self.fs = mock.patch.object(
        crash_recovery, "_network_filesystem", return_value=False
    )
    self.fs.start()

  def tearDown(self):
    self.fs.stop()
    self._tmp.cleanup()
    super().tearDown()

  def leftovers(self, header=None, packed=True):
    if packed:
      with open(self.i64, "wb") as f:
        f.write(b"packed")
    for s in _SUFFIXES:
      with open(self.binary + s, "wb") as f:
        f.write(header if (s == ".id0" and header is not None) else s.encode())
    if header is None:
      with open(self.binary + ".id0", "wb") as f:
        f.write(_header())

  def backups(self):
    return [d for d in os.listdir(self.dir) if ".crash-" in d]


class TestProbe(_Dir):

  def test_none(self):
    self.assertEqual(crash_recovery.probe(self.binary)["state"], "none")

  def test_crashed_from_binary_and_i64_paths(self):
    self.leftovers()
    for path in (self.binary, self.i64):
      p = crash_recovery.probe(path)
      self.assertEqual(p["state"], "crashed", path)
      self.assertEqual(p["id0_path"], self.binary + ".id0")
      self.assertEqual(p["packed_path"], self.i64)
      self.assertEqual(len(p["unpacked_files"]), 5)

  def test_clean_unpacked(self):
    self.leftovers(header=_header(dirty=0))
    self.assertEqual(crash_recovery.probe(self.binary)["state"], "unpacked")

  def test_in_use(self):
    self.leftovers()
    fd = os.open(self.binary + ".id0", os.O_RDONLY)
    try:
      fcntl.flock(fd, fcntl.LOCK_EX)
      self.assertEqual(crash_recovery.probe(self.binary)["state"], "in_use")
    finally:
      os.close(fd)

  def test_unknown_cases(self):
    cases = {
        "signature": _header(signature=b"B-tree v3"),
        "isTreeOpen": _header(dirty=7),
        "truncated": b"\0" * 20,
    }
    for name, header in cases.items():
      self.leftovers(header=header)
      p = crash_recovery.probe(self.binary)
      self.assertEqual(p["state"], "unknown", name)
      self.assertIn(name, p["error"])

  def test_components_without_id0(self):
    open(self.binary + ".id1", "wb").close()
    p = crash_recovery.probe(self.binary)
    self.assertEqual(p["state"], "unknown")

  def test_network_filesystem_is_unknown(self):
    self.leftovers()
    with mock.patch.object(
        crash_recovery, "_network_filesystem", return_value=True
    ):
      p = crash_recovery.probe(self.binary)
    self.assertEqual(p["state"], "unknown")
    self.assertIn("network", p["error"])

  def test_mountinfo_parsing(self):
    self.fs.stop()
    try:
      info = (
          "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
          "40 22 0:50 / /mnt/share rw - nfs4 srv:/x rw\n"
          "41 22 0:51 / /mnt/with\\040space rw - cifs //s/y rw\n"
      )
      with (
          mock.patch.object(crash_recovery.sys, "platform", "linux"),
          mock.patch("builtins.open", mock.mock_open(read_data=info)),
          mock.patch.object(os.path, "realpath", side_effect=lambda p: p),
      ):
        nfs = crash_recovery._network_filesystem
        self.assertIs(nfs("/mnt/share/a/b.id0"), True)
        self.assertIs(nfs("/mnt/with space/b.id0"), True)
        self.assertIs(nfs("/home/u/b.id0"), False)
      with mock.patch.object(crash_recovery.sys, "platform", "darwin"):
        self.assertIsNone(crash_recovery._network_filesystem("/x"))
    finally:
      self.fs.start()


class TestPrepare(_Dir):

  def test_nothing_to_do(self):
    self.assertEqual(
        crash_recovery.prepare(self.binary, "backup"), (self.binary, None)
    )
    self.leftovers(header=_header(dirty=0))
    self.assertEqual(
        crash_recovery.prepare(self.binary, "backup"), (self.binary, None)
    )
    self.assertEqual(self.backups(), [])

  def test_off(self):
    self.leftovers()
    self.assertEqual(
        crash_recovery.prepare(self.binary, "off"), (self.binary, None)
    )
    self.assertEqual(self.backups(), [])

  def test_backup_with_packed(self):
    self.leftovers()
    with self.assertLogs(level="WARNING"):
      path, report = crash_recovery.prepare(self.i64, "backup")
    self.assertEqual(path, self.i64)
    self.assertEqual(report["action"], "backup")
    self.assertEqual(report["packed_database"], self.i64)
    self.assertIn("discards the changes", report["message"])
    backup = report["backup_path"]
    self.assertEqual(
        sorted(os.listdir(backup)), sorted("sample.bin" + s for s in _SUFFIXES)
    )
    with open(os.path.join(backup, "sample.bin.id0"), "rb") as f:
      self.assertEqual(f.read(), _header())
    # Originals are untouched.
    self.assertTrue(os.path.isfile(self.i64))
    self.assertTrue(os.path.isfile(self.binary + ".id0"))
    self.assertEqual(os.stat(backup).st_mode & 0o777, 0o700)

  def test_backup_without_packed(self):
    self.leftovers(packed=False)
    with self.assertLogs(level="WARNING"):
      path, report = crash_recovery.prepare(self.binary, "backup")
    self.assertEqual(path, self.binary)
    self.assertEqual(report["action"], "backup")
    self.assertNotIn("packed_database", report)
    self.assertIn("keeps the unsaved changes", report["message"])

  def test_prefer_unpacked_moves_packed(self):
    for requested, expected in (
        (self.i64, lambda: self.binary + ".id0"),
        (self.binary, lambda: self.binary),
    ):
      self.leftovers()
      with self.assertLogs(level="WARNING"):
        path, report = crash_recovery.prepare(requested, "prefer_unpacked")
      self.assertEqual(path, expected())
      self.assertEqual(report["action"], "prefer_unpacked")
      self.assertFalse(os.path.exists(self.i64))
      self.assertTrue(
          os.path.isfile(os.path.join(report["backup_path"], "sample.bin.i64"))
      )

  def test_prefer_unpacked_needs_checkable_fs(self):
    self.leftovers()
    with (
        mock.patch.object(
            crash_recovery,
            "_network_filesystem",
            side_effect=lambda p: None if p == self.i64 else False,
        ),
        self.assertLogs(level="WARNING"),
    ):
      path, report = crash_recovery.prepare(self.i64, "prefer_unpacked")
    self.assertEqual(path, self.i64)
    self.assertEqual(report["action"], "backup")
    self.assertIn("using backup", report["message"])
    self.assertTrue(os.path.isfile(self.i64))

  def test_invalid_mode_uses_backup(self):
    self.leftovers()
    with self.assertLogs(level="WARNING") as logs:
      _, report = crash_recovery.prepare(self.binary, "yolo")
    self.assertEqual(report["action"], "backup")
    self.assertTrue(any("Unknown crash_recovery" in l for l in logs.output))

  def test_unknown_state_is_left_alone(self):
    self.leftovers(header=_header(signature=b"nope!!!!!"))
    with self.assertLogs(level="WARNING"):
      self.assertEqual(
          crash_recovery.prepare(self.binary, "prefer_unpacked"),
          (self.binary, None),
      )
    self.assertTrue(os.path.isfile(self.i64))
    self.assertEqual(self.backups(), [])

  def test_backup_failure_refuses(self):
    self.leftovers()
    os.remove(self.binary + ".nam")
    os.symlink(self.binary, self.binary + ".nam")
    with self.assertRaisesRegex(
        crash_recovery.RecoveryError, "backing them up failed"
    ):
      crash_recovery.prepare(self.binary, "backup")

  def test_taken_during_recovery(self):
    self.leftovers()
    states = iter(["crashed", "in_use"])
    real = crash_recovery.probe

    def fake(path):
      p = real(path)
      p["state"] = next(states)
      return p

    with mock.patch.object(crash_recovery, "probe", side_effect=fake):
      with self.assertRaisesRegex(crash_recovery.RecoveryError, "Another IDA"):
        crash_recovery.prepare(self.binary, "backup")

  def test_two_backups_same_second(self):
    self.leftovers()
    with (
        mock.patch.object(crash_recovery.time, "strftime", return_value="T"),
        self.assertLogs(level="WARNING"),
    ):
      a = crash_recovery.prepare(self.binary, "backup")[1]["backup_path"]
      b = crash_recovery.prepare(self.binary, "backup")[1]["backup_path"]
    self.assertNotEqual(a, b)


class TestSpawnIntegration(_Dir):

  def test_recovery_error_is_tool_error_and_nothing_spawns(self):
    manager = forward.HeadlessManager(max_instances=1)
    with (
        mock.patch.object(
            crash_recovery,
            "prepare",
            side_effect=crash_recovery.RecoveryError("nope"),
        ),
        mock.patch(
            "asyncio.create_subprocess_exec", new_callable=mock.AsyncMock
        ) as spawn,
    ):
      with self.assertRaisesRegex(ToolError, "nope"):
        asyncio.run(manager.spawn(self.binary))
    spawn.assert_not_called()

  def test_spawn_uses_prepared_path(self):
    manager = forward.HeadlessManager(max_instances=1)
    spawn = mock.AsyncMock(side_effect=RuntimeError("stop here"))
    with (
        mock.patch.object(
            crash_recovery,
            "prepare",
            return_value=("/prepared.id0", None),
        ) as prepare,
        mock.patch("asyncio.create_subprocess_exec", spawn),
    ):
      with self.assertRaisesRegex(RuntimeError, "stop here"):
        asyncio.run(manager.spawn(self.binary))
    self.assertEqual(prepare.call_args.args[0], self.binary)
    self.assertEqual(spawn.call_args.args[3], "/prepared.id0")


if __name__ == "__main__":
  unittest.main()
