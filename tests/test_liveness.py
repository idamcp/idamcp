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

"""Unit tests for lock-file backend liveness (no IDA)."""

import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

# pylint: disable=g-import-not-at-top
from gateway import forward
from ida_mcp.core.backend_registry import RegistryManager
from shared import liveness
from shared import protocol

# pylint: enable=g-import-not-at-top

_HOLDER = """
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
print("locked", flush=True)
time.sleep(600)
"""


@unittest.skipUnless(liveness.supported(), "flock() is POSIX-only")
class TestLifetimeLock(unittest.TestCase):
  """Tests for LifetimeLock and lock_state."""

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.path = os.path.join(self._tmp.name, "db.lock")

  def test_held_then_released(self):
    lock = liveness.LifetimeLock(self.path)
    self.assertTrue(lock.acquire())
    self.assertTrue(lock.held)
    self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
    self.assertIs(liveness.lock_state(self.path), liveness.LockState.HELD)
    lock.release()
    self.assertFalse(lock.held)
    self.assertIs(liveness.lock_state(self.path), liveness.LockState.MISSING)

  def test_unlocked_file_is_free(self):
    pathlib.Path(self.path).touch()
    self.assertIs(liveness.lock_state(self.path), liveness.LockState.FREE)

  def test_second_lock_on_same_file_fails(self):
    first = liveness.LifetimeLock(self.path)
    self.assertTrue(first.acquire())
    self.addCleanup(first.release)
    second = liveness.LifetimeLock(self.path)
    self.assertFalse(second.acquire(attempts=2, delay=0))
    self.assertFalse(second.held)

  def test_state_check_does_not_take_the_lock(self):
    pathlib.Path(self.path).touch()
    liveness.lock_state(self.path)
    lock = liveness.LifetimeLock(self.path)
    self.assertTrue(lock.acquire(attempts=1))
    lock.release()

  def test_acquire_retries_until_holder_releases(self):
    holder = liveness.LifetimeLock(self.path)
    self.assertTrue(holder.acquire())
    timer = threading.Timer(0.05, holder.release)
    timer.start()
    self.addCleanup(timer.cancel)
    lock = liveness.LifetimeLock(self.path)
    self.assertTrue(lock.acquire(attempts=50, delay=0.01))
    self.addCleanup(lock.release)
    # The holder unlinked the file it held; the new lock is on a new file at
    # the same path.
    self.assertIs(liveness.lock_state(self.path), liveness.LockState.HELD)

  def test_lock_of_killed_process_is_free(self):
    proc = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, self.path],
        stdout=subprocess.PIPE,
        text=True,
    )
    self.addCleanup(proc.stdout.close)
    self.addCleanup(proc.wait)
    self.addCleanup(proc.kill)
    self.assertEqual(proc.stdout.readline().strip(), "locked")
    self.assertIs(liveness.lock_state(self.path), liveness.LockState.HELD)
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait()
    self.assertIs(liveness.lock_state(self.path), liveness.LockState.FREE)


class TestRecordAlive(unittest.TestCase):
  """Tests for liveness.record_alive."""

  def setUp(self):
    self.pid_alive = mock.Mock(return_value=True)

  def _alive(self, state, **record):
    with mock.patch.object(liveness, "lock_state", return_value=state):
      return liveness.record_alive(record, self.pid_alive)

  def test_held_lock_is_alive_without_pid_check(self):
    self.pid_alive.return_value = False
    self.assertTrue(
        self._alive(liveness.LockState.HELD, pid=1, lock_file="/r/db.lock")
    )
    self.pid_alive.assert_not_called()

  def test_free_lock_is_dead_even_if_pid_is_in_use(self):
    self.assertFalse(
        self._alive(liveness.LockState.FREE, pid=1, lock_file="/r/db.lock")
    )
    self.pid_alive.assert_not_called()

  def test_missing_or_unknown_lock_uses_pid(self):
    for state in (liveness.LockState.MISSING, liveness.LockState.UNKNOWN):
      self.pid_alive.reset_mock()
      self.assertTrue(self._alive(state, pid=1, lock_file="/r/db.lock"))
      self.pid_alive.assert_called_once_with(1)

  def test_record_without_lock_uses_pid(self):
    self.pid_alive.return_value = False
    self.assertFalse(liveness.record_alive({"pid": 1}, self.pid_alive))
    self.pid_alive.assert_called_once_with(1)

  def test_invalid_lock_field_is_ignored(self):
    for value in ("relative/db.lock", 3, None):
      self.pid_alive.reset_mock()
      self.assertTrue(
          liveness.record_alive({"pid": 1, "lock_file": value}, self.pid_alive)
      )
      self.pid_alive.assert_called_once_with(1)

  def test_no_lock_and_no_pid_is_dead(self):
    self.assertFalse(liveness.record_alive({}, self.pid_alive))

  def test_unsupported_platform_uses_pid(self):
    with mock.patch.object(liveness, "supported", return_value=False):
      self.assertIs(
          liveness.lock_state("/r/db.lock"), liveness.LockState.UNKNOWN
      )
      self.assertTrue(
          liveness.record_alive(
              {"pid": 1, "lock_file": "/r/db.lock"}, self.pid_alive
          )
      )
      self.assertFalse(liveness.LifetimeLock("/r/db.lock").acquire())


@unittest.skipUnless(liveness.supported(), "flock() is POSIX-only")
class TestRegistryLock(unittest.TestCase):
  """Tests for the lock taken by RegistryManager."""

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)

  def _register(self, registry, name="db1"):
    path = registry.register("uds", "/tmp/db.sock", name=name)
    self.addCleanup(registry.cleanup)
    return json.loads(path.read_text(encoding="utf-8"))

  def test_record_names_a_held_lock(self):
    record = self._register(RegistryManager(self._tmp.name))
    lock_file = record["lock_file"]
    self.assertEqual(lock_file, os.path.join(self._tmp.name, "db1.lock"))
    self.assertIs(liveness.lock_state(lock_file), liveness.LockState.HELD)
    self.assertTrue(liveness.record_alive(record, lambda pid: False))

  def test_cleanup_removes_record_and_lock(self):
    registry = RegistryManager(self._tmp.name)
    record = self._register(registry)
    registry.cleanup()
    self.assertFalse(os.path.exists(record["lock_file"]))
    self.assertEqual(os.listdir(self._tmp.name), [])

  def test_second_instance_with_same_name_falls_back_to_pid(self):
    self._register(RegistryManager(self._tmp.name))
    with self.assertLogs(level="WARNING") as cm:
      with mock.patch.object(
          liveness.LifetimeLock, "acquire", return_value=False
      ):
        record = self._register(RegistryManager(self._tmp.name))
    self.assertNotIn("lock_file", record)
    self.assertTrue(any("by PID" in line for line in cm.output))

  def test_re_register_keeps_the_same_lock(self):
    registry = RegistryManager(self._tmp.name)
    first = self._register(registry)
    second = self._register(registry)
    self.assertEqual(first["lock_file"], second["lock_file"])
    self.assertIs(
        liveness.lock_state(first["lock_file"]), liveness.LockState.HELD
    )


@unittest.skipUnless(liveness.supported(), "flock() is POSIX-only")
class TestGatewayLiveness(unittest.IsolatedAsyncioTestCase):
  """Tests for the gateway's use of lock files."""

  async def asyncSetUp(self):
    self._clear()
    self.addCleanup(self._clear)
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    patcher = mock.patch("gateway.forward.RPCClient")
    self.client = patcher.start().return_value
    self.addCleanup(patcher.stop)
    self.client.connect_uds = mock.AsyncMock()
    self.client.close = mock.AsyncMock()
    self.client.call = mock.AsyncMock(return_value=None)
    self.client.ping = mock.AsyncMock(side_effect=TimeoutError)
    patcher = mock.patch.object(forward, "_is_process_running")
    self.pid_alive = patcher.start()
    self.addCleanup(patcher.stop)
    patcher = mock.patch.object(
        forward, "_kill_process_gracefully", mock.AsyncMock()
    )
    self.kill = patcher.start()
    self.addCleanup(patcher.stop)

  def _clear(self):
    for state in (
        forward._global_clients,
        forward._global_metadata,
        forward._global_capabilities,
        forward._global_records,
        forward._incompatible_backends,
        forward._global_client_state,
        forward._global_database_id_to_pid,
        forward._backend_events,
    ):
      state.clear()

  def _lock_file(self, held: bool) -> str:
    path = os.path.join(self._tmp.name, "db.lock")
    if held:
      lock = liveness.LifetimeLock(path)
      self.assertTrue(lock.acquire())
      self.addCleanup(lock.release)
    else:
      pathlib.Path(path).touch()
    return path

  def _write_record(self, lock_file: str) -> pathlib.Path:
    record = {
        "pid": 4242,
        "channel": "uds",
        "address": "/nonexistent/db.sock",
        "name": "db",
        "metadata": {},
        "protocol_version": protocol.PROTOCOL_VERSION,
        "capabilities": [],
        "lock_file": lock_file,
    }
    path = pathlib.Path(self._tmp.name) / "db.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path

  async def test_free_lock_is_stale_even_if_pid_is_reused(self):
    self.pid_alive.return_value = True
    path = self._write_record(self._lock_file(held=False))
    await forward.connect_to_backend(path)
    self.assertNotIn("db", forward._global_clients)
    self.assertFalse(path.exists())
    self.client.connect_uds.assert_not_awaited()

  async def test_held_lock_connects(self):
    self.pid_alive.return_value = False
    path = self._write_record(self._lock_file(held=True))
    await forward.connect_to_backend(path)
    self.assertIn("db", forward._global_clients)

  async def test_unregister_does_not_signal_a_reused_pid(self):
    self.pid_alive.return_value = True
    lock_file = self._lock_file(held=True)
    await forward.connect_to_backend(self._write_record(lock_file))
    forward._headless_manager.register("db", 4242)
    # The backend died without cleanup (lock file left, unlocked) and another
    # process now has PID 4242.
    self.assertEqual(forward._global_records["db"]["lock_file"], lock_file)
    with mock.patch.object(
        liveness, "lock_state", return_value=liveness.LockState.FREE
    ):
      await forward._headless_manager.unregister("db")
    self.kill.assert_not_called()

  async def test_unregister_signals_live_backend(self):
    self.pid_alive.return_value = True
    await forward.connect_to_backend(
        self._write_record(self._lock_file(held=True))
    )
    forward._headless_manager.register("db", 4242)
    await forward._headless_manager.unregister("db")
    await forward.asyncio.gather(*forward._background_tasks)
    self.kill.assert_awaited_once_with(4242)

  async def test_list_reports_busy_backend_by_lock(self):
    self.pid_alive.return_value = False
    await forward.connect_to_backend(
        self._write_record(self._lock_file(held=True))
    )
    databases = await forward.list_available_databases()
    self.assertEqual([d["database_id"] for d in databases], ["db"])
    self.assertTrue(databases[0]["busy"])

  async def test_list_drops_backend_with_free_lock(self):
    self.pid_alive.return_value = True
    lock_file = self._lock_file(held=True)
    await forward.connect_to_backend(self._write_record(lock_file))
    with mock.patch.object(
        liveness, "lock_state", return_value=liveness.LockState.FREE
    ):
      with self.assertRaises(forward.ToolError):
        await forward.list_available_databases()
    self.assertNotIn("db", forward._global_clients)

  async def test_already_open_check_uses_lock(self):
    self.pid_alive.return_value = True
    binary = os.path.join(self._tmp.name, "target")
    pathlib.Path(binary).touch()
    await forward.connect_to_backend(
        self._write_record(self._lock_file(held=True))
    )
    forward._global_metadata["db"]["filepath"] = binary
    with self.assertRaisesRegex(forward.ToolError, "already connected"):
      await forward._headless_manager.spawn(binary)
    with mock.patch.object(
        liveness, "lock_state", return_value=liveness.LockState.FREE
    ):
      with mock.patch.object(
          forward.asyncio,
          "create_subprocess_exec",
          side_effect=RuntimeError("spawned"),
      ):
        with self.assertRaisesRegex(RuntimeError, "spawned"):
          await forward._headless_manager.spawn(binary)


if __name__ == "__main__":
  unittest.main()
