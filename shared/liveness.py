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

"""Backend liveness through a lock file held for the process lifetime.

A backend takes an exclusive flock() on <registry_dir>/<name>.lock before it
writes its registry record, and keeps it until the process ends. The kernel
releases the lock on every kind of exit, including SIGKILL, so the lock state
tells whether the backend is alive even after its PID has been reused by an
unrelated process.

Gateways only read the lock state and never delete lock files: a lock file left
behind by a killed backend is reused by the next backend with the same name.

A lock file that exists but is not locked means the backend died; the gateway
then treats it as dead even if its PID is in use again. A held lock means
alive. In all other cases (no lock file in the record, the file was removed
during a clean shutdown, or the state can't be read) the PID check decides, as
before.

The record names the file in "lock_file". Records without it (backends from
before this change, or where the lock could not be taken) are checked by PID
as before. flock() is POSIX-only; on Windows no lock is taken and the PID check
stays in use.
"""

import contextlib
import enum
import errno
import logging
import os
import sys
import time
from typing import Any, Callable, Mapping

try:
  import fcntl  # pylint: disable=g-import-not-at-top
except ImportError:  # Windows
  fcntl = None

logger = logging.getLogger(__name__)

# Registry record field that holds the lock file path.
RECORD_FIELD = "lock_file"


def supported() -> bool:
  return fcntl is not None and sys.platform != "win32"


class LockState(enum.Enum):
  HELD = "held"  # A live process holds the lock.
  FREE = "free"  # The file exists but nobody holds the lock.
  MISSING = "missing"  # The file does not exist.
  UNKNOWN = "unknown"  # The state could not be determined.


class LifetimeLock:
  """An exclusive lock on a file, held until release() or process exit."""

  def __init__(self, path: str | os.PathLike[str]):
    self.path = os.fspath(path)
    self._fd: int | None = None

  @property
  def held(self) -> bool:
    return self._fd is not None

  def acquire(self, attempts: int = 10, delay: float = 0.02) -> bool:
    """Takes the lock without blocking; returns False if it is unavailable.

    Retries briefly, because a gateway checking a dead backend with the same
    name holds a shared lock on the file for a moment.

    Args:
      attempts: How many times to try.
      delay: Seconds between attempts.

    Returns:
      True if the lock is now held by this process.
    """
    if self._fd is not None:
      return True
    if not supported():
      return False
    for attempt in range(attempts):
      try:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
      except OSError as e:
        logger.warning("Cannot create lock file %s: %s", self.path, e)
        return False
      try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      except OSError as e:
        os.close(fd)
        if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
          logger.warning("Cannot lock %s: %s", self.path, e)
          return False
        if attempt + 1 < attempts:
          time.sleep(delay)
        continue
      # The previous holder unlinks the file before it releases the lock. If
      # that happened after we opened it, we hold a lock on a file nobody can
      # find: open the path again.
      if not _same_file(fd, self.path):
        os.close(fd)
        continue
      self._fd = fd
      return True
    return False

  def release(self) -> None:
    """Removes the lock file and releases the lock."""
    if self._fd is None:
      return
    # Unlink first, so no checker sees the file unlocked while it still exists.
    with contextlib.suppress(OSError):
      os.unlink(self.path)
    with contextlib.suppress(OSError):
      os.close(self._fd)
    self._fd = None


def _same_file(fd: int, path: str) -> bool:
  try:
    fd_stat = os.fstat(fd)
    path_stat = os.stat(path)
  except OSError:
    return False
  return (fd_stat.st_dev, fd_stat.st_ino) == (
      path_stat.st_dev,
      path_stat.st_ino,
  )


def lock_state(path: str) -> LockState:
  """Checks whether some process holds the lock on path, without keeping it."""
  if not supported():
    return LockState.UNKNOWN
  try:
    fd = os.open(path, os.O_RDONLY)
  except FileNotFoundError:
    return LockState.MISSING
  except OSError:
    return LockState.UNKNOWN
  try:
    try:
      fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError as e:
      if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
        return LockState.HELD
      return LockState.UNKNOWN
    fcntl.flock(fd, fcntl.LOCK_UN)
    return LockState.FREE
  finally:
    os.close(fd)


def record_alive(
    record: Mapping[str, Any], pid_alive: Callable[[int], bool]
) -> bool:
  """Returns whether the backend of a registry record is alive.

  Args:
    record: The parsed registry record.
    pid_alive: The PID check used for records without a usable lock file.

  Returns:
    True if the lock is held, False if the lock file exists but nobody holds
    it (the backend died without cleaning up). Otherwise the PID check (False
    if the record has no PID either). A missing lock file also falls back to
    the PID check: a backend removes it during a clean shutdown, before it
    has finished saving the database.
  """
  path = record.get(RECORD_FIELD)
  if isinstance(path, str) and os.path.isabs(path):
    state = lock_state(path)
    if state is LockState.HELD:
      return True
    if state is LockState.FREE:
      return False
  pid = record.get("pid")
  return bool(pid) and pid_alive(pid)
