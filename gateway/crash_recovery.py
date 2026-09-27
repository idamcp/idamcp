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

"""Detects IDA crash leftovers before a headless open and backs them up.

When IDA exits without closing a database, the unpacked files (.id0, .id1,
.id2, .nam, .til) stay next to it with the .id0 B-tree "isTreeOpen" byte set.
idalib 9.4 handles them on the next open like this:

* a packed .i64/.idb exists: it restores the packed database and deletes the
  unpacked files, silently discarding everything since the last save;
* no packed database: it repairs the unpacked files and keeps the changes.

This module runs in the gateway, before the headless backend is spawned. It
never opens the database. The .id0 checks (isTreeOpen byte at offset 18,
"B-tree v2" signature at 19, exclusive lock = live session) follow ida-nexus
database_state.py (MIT, Copyright (c) 2026 Hex-Rays SA).
"""

import logging
import os
import shutil
import sys
import time
from typing import Literal, NotRequired, TypedDict

MODES = ("off", "backup", "prefer_unpacked")
DEFAULT_MODE = "backup"

UNPACKED_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til")
DATABASE_SUFFIXES = (".idb", ".i64")

_DIRTY_OFFSET = 18
_SIGNATURE_OFFSET = 19
_SIGNATURE = b"B-tree v2"
_HEADER_SIZE = _SIGNATURE_OFFSET + len(_SIGNATURE)

# Filesystems where advisory locks don't reliably show another host's session.
_NETWORK_FILESYSTEMS = frozenset({
    "9p",
    "afs",
    "ceph",
    "cifs",
    "fuse.sshfs",
    "glusterfs",
    "nfs",
    "nfs4",
    "smb3",
    "smbfs",
})

State = Literal["none", "in_use", "crashed", "unpacked", "unknown"]


class CrashRecovery(TypedDict):
  """What was done about crash leftovers found before opening."""

  action: Literal["backup", "prefer_unpacked"]
  backup_path: str
  packed_database: NotRequired[str]
  message: str


class RecoveryError(Exception):
  """Crash leftovers were found but could not be handled safely."""


class Probe(TypedDict):
  state: State
  base: str
  id0_path: str
  packed_path: str | None
  unpacked_files: list[str]
  error: str | None


def _base_path(path: str) -> str:
  """Returns the path IDA derives unpacked file names from."""
  if path.lower().endswith(DATABASE_SUFFIXES):
    return path[: -len(".i64")]
  return path


def _packed_path(path: str, base: str) -> str | None:
  if path.lower().endswith(DATABASE_SUFFIXES):
    return path if os.path.isfile(path) else None
  for suffix in (".i64", ".idb"):
    if os.path.isfile(base + suffix):
      return base + suffix
  return None


def _network_filesystem(path: str) -> bool | None:
  """True/False on Linux (from /proc/self/mountinfo), None if unknown."""
  if not sys.platform.startswith("linux"):
    return None
  target = os.path.realpath(path)
  best: tuple[int, str] | None = None
  try:
    with open("/proc/self/mountinfo", encoding="utf-8") as f:
      lines = f.readlines()
  except OSError:
    return None
  for line in lines:
    try:
      mount, fs = line.split(" - ", 1)
      mount_point = mount.split()[4]
      for esc, ch in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n")):
        mount_point = mount_point.replace(esc, ch)
      mount_point = mount_point.replace("\\134", "\\")
      if os.path.commonpath((target, mount_point)) != mount_point:
        continue
      if best is None or len(mount_point) > best[0]:
        best = (len(mount_point), fs.split()[0])
    except (IndexError, ValueError):
      continue
  if best is None:
    return None
  return best[1] in _NETWORK_FILESYSTEMS


def _read_header(id0: str) -> tuple[bool | None, bytes | None, str | None]:
  """Returns (locked, header, error). Reads only while holding the lock."""
  import fcntl  # pylint: disable=g-import-not-at-top

  try:
    fd = os.open(id0, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
  except OSError as e:
    return None, None, str(e)
  try:
    try:
      fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      return True, None, None
    except OSError as e:
      return None, None, str(e)
    try:
      return False, os.read(fd, _HEADER_SIZE), None
    finally:
      fcntl.flock(fd, fcntl.LOCK_UN)
  finally:
    os.close(fd)


def probe(path: str) -> Probe:
  """Classifies the unpacked database files next to path. Never modifies them.

  Args:
    path: the binary or .i64/.idb path about to be opened (absolute).

  Returns:
    The probe result. state is "unknown" (with error) whenever the files can't
    be classified with confidence; callers must then leave them alone.
  """
  base = _base_path(path)
  id0 = base + ".id0"
  result = Probe(
      state="unknown",
      base=base,
      id0_path=id0,
      packed_path=_packed_path(path, base),
      unpacked_files=[
          base + s for s in UNPACKED_SUFFIXES if os.path.lexists(base + s)
      ],
      error=None,
  )
  if not os.path.lexists(id0):
    if result["unpacked_files"]:
      result["error"] = "unpacked database files exist without an .id0"
      return result
    result["state"] = "none"
    return result
  if os.name == "nt":
    result["error"] = "crash detection is not implemented on Windows"
    return result
  if _network_filesystem(id0) is True:
    result["error"] = "network filesystem; file locks are not reliable"
    return result
  locked, header, error = _read_header(id0)
  if locked:
    result["state"] = "in_use"
    return result
  if header is None:
    result["error"] = error or "could not read the .id0 header"
    return result
  if len(header) < _HEADER_SIZE:
    result["error"] = "the .id0 header is truncated"
    return result
  if header[_SIGNATURE_OFFSET:_HEADER_SIZE] != _SIGNATURE:
    result["error"] = "unrecognized .id0 signature"
    return result
  dirty = header[_DIRTY_OFFSET]
  if dirty not in (0, 1):
    result["error"] = f"unexpected .id0 isTreeOpen value {dirty}"
    return result
  result["state"] = "crashed" if dirty else "unpacked"
  return result


def _backup(found: Probe) -> str:
  """Copies the unpacked files into a new <base>.crash-<time>-<pid> dir."""
  stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
  prefix = f"{found['base']}.crash-{stamp}-{os.getpid()}"
  backup = prefix
  for n in range(1, 100):
    try:
      os.mkdir(backup, 0o700)
      break
    except FileExistsError:
      backup = f"{prefix}-{n}"
  else:
    raise OSError(f"could not create a backup directory next to {prefix}")
  for source in found["unpacked_files"]:
    if os.path.islink(source) or not os.path.isfile(source):
      raise OSError(f"not a regular file: {source}")
    dest = os.path.join(backup, os.path.basename(source))
    with open(source, "rb") as src, open(dest, "xb") as dst:
      shutil.copyfileobj(src, dst, 1024 * 1024)
      dst.flush()
      os.fsync(dst.fileno())
    shutil.copystat(source, dest)
  return backup


def prepare(path: str, mode: str) -> tuple[str, CrashRecovery | None]:
  """Handles crash leftovers for path before a headless open.

  Args:
    path: absolute path of the binary or database to open.
    mode: "off" (do nothing), "backup" (copy the leftovers aside, then let IDA
      do what it does), or "prefer_unpacked" (also move the packed database
      into the backup dir, so IDA keeps the unsaved changes).

  Returns:
    (path to pass to the backend, report or None if nothing was done).

  Raises:
    RecoveryError: leftovers were found but backing them up failed, or another
      IDA took the database while this ran.
  """
  if mode not in MODES:
    logging.warning(
        "[Gateway] Unknown crash_recovery %r, using %r", mode, DEFAULT_MODE
    )
    mode = DEFAULT_MODE
  if mode == "off":
    return path, None
  found = probe(path)
  if found["state"] == "unknown":
    logging.warning(
        "[Gateway] Not checking %s for crash leftovers: %s",
        found["id0_path"],
        found["error"],
    )
    return path, None
  if found["state"] != "crashed":
    return path, None

  try:
    backup = _backup(found)
  except OSError as e:
    raise RecoveryError(
        f"{path} has crash leftovers ({found['id0_path']} was not closed"
        f" cleanly), and backing them up failed: {e}. Not opening it, so IDA"
        " doesn't discard or rewrite them. Copy the files aside and retry, or"
        ' set crash_recovery to "off".'
    ) from e
  if probe(path)["state"] == "in_use":
    raise RecoveryError(
        f"Another IDA opened {path} during crash recovery. A copy of the"
        f" leftovers is in {backup}."
    )

  packed = found["packed_path"]
  if packed is None:
    report = CrashRecovery(
        action="backup",
        backup_path=backup,
        message=(
            f"{found['id0_path']} was not closed cleanly (IDA crashed or was"
            " killed). There is no saved .i64/.idb, so IDA repairs the"
            " unpacked database and keeps the unsaved changes. A copy of the"
            f" files before the repair is in {backup}."
        ),
    )
    logging.warning("[Gateway] %s", report["message"])
    return path, report

  if mode == "prefer_unpacked" and _network_filesystem(packed) is False:
    os.replace(packed, os.path.join(backup, os.path.basename(packed)))
    report = CrashRecovery(
        action="prefer_unpacked",
        backup_path=backup,
        packed_database=packed,
        message=(
            f"{found['id0_path']} was not closed cleanly (IDA crashed or was"
            f" killed). The last saved database {packed} was moved to"
            f" {backup}, so IDA repairs the unpacked database and keeps the"
            " changes made since that save. A copy of the files before the"
            " repair is in the same directory."
        ),
    )
    logging.warning("[Gateway] %s", report["message"])
    # The backend refuses a path that doesn't exist; IDA opens the unpacked
    # database from its .id0 just as from the (moved) .i64 path.
    spawn_path = found["id0_path"] if path == packed else path
    return spawn_path, report

  note = ""
  if mode == "prefer_unpacked":
    note = (
        " (prefer_unpacked needs a local filesystem that can be checked; using"
        " backup)"
    )
  report = CrashRecovery(
      action="backup",
      backup_path=backup,
      packed_database=packed,
      message=(
          f"{found['id0_path']} was not closed cleanly (IDA crashed or was"
          f" killed). IDA reopens the last saved database {packed} and"
          " discards the changes made since that save. They are preserved in"
          f" {backup}{note}. To continue from them instead: close this"
          f" database, copy the files from {backup} next to {packed}, move"
          f" {packed} away and open again."
      ),
  )
  logging.warning("[Gateway] %s", report["message"])
  return path, report
