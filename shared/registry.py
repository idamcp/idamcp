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


"""Names of the registry records that backends write for the gateway.

A backend writes one JSON record, named after its instance ID, to the registry
directory. While its auto-analysis is still running, the record is named
`analyzing-<instance_id>.json`; when the analysis finishes, the backend
renames it to `ida-<instance_id>.json`. Anything else in the directory, such
as the temporary file a record is written to first, is not a record. This
module only uses the standard library.
"""

import pathlib
import re
import secrets

_RECORD_PREFIX = "ida"
_IN_PROGRESS_PREFIX = "analyzing"
_SUFFIX = ".json"
# Bytes of randomness in an instance ID. The ID names the registry record and
# the Unix socket, whose path the OS limits to about 100 bytes, so it is kept
# short. Two instances clash only if they draw the same 64 bits while both
# have files in the registry.
_INSTANCE_ID_BYTES = 8
# A record's whole file name.
_RECORD_NAME_RE = re.compile(
    rf"(?P<prefix>{_RECORD_PREFIX}|{_IN_PROGRESS_PREFIX})-"
    rf"(?P<instance_id>[0-9a-f]{{{_INSTANCE_ID_BYTES * 2}}})"
    rf"{re.escape(_SUFFIX)}"
)


def new_instance_id() -> str:
  """Returns the ID for a backend instance that is starting.

  The ID is internal: the backend, the gateway, and the dashboard tell the
  instances of a database apart by it. MCP clients only see the database ID.
  """
  return secrets.token_hex(_INSTANCE_ID_BYTES)


def record_name(instance_id: str, in_progress: bool) -> str:
  """Returns the registry file name for a backend instance.

  Args:
    instance_id: the backend's instance ID.
    in_progress: whether the backend's auto-analysis is still running.
  """
  prefix = _IN_PROGRESS_PREFIX if in_progress else _RECORD_PREFIX
  return f"{prefix}-{instance_id}{_SUFFIX}"


def is_record_name(name: str) -> bool:
  """Returns whether a file name, without its directory, names a record."""
  return _RECORD_NAME_RE.fullmatch(name) is not None


def parse_record_name(name: str) -> tuple[str, bool]:
  """Returns (instance_id, in_progress) for a record's file name.

  Args:
    name: the file name, without its directory; see is_record_name().

  Raises:
    ValueError: if the name is not a record's.
  """
  m = _RECORD_NAME_RE.fullmatch(name)
  if m is None:
    raise ValueError(f"Not a valid record name: {name}")
  return m.group("instance_id"), m.group("prefix") == _IN_PROGRESS_PREFIX


def list_records(registry_dir: pathlib.Path) -> list[pathlib.Path]:
  """Returns the records in a registry directory, sorted by name."""
  try:
    return sorted(
        path
        for path in registry_dir.iterdir()
        if path.is_file() and is_record_name(path.name)
    )
  except FileNotFoundError:
    return []
