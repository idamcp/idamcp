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

"""Optional JSONL trace of tool calls forwarded by the gateway.

Enabled by setting the `trace_dir` config option. Each gateway process writes
one file, `<trace_dir>/gateway-<UTC timestamp>-<server_id>.jsonl`, created on
the first traced call. Each line is one JSON object:

  {"schema": 1, "ts": "...", "server_id": "...", "pid": 123,
   "event": "tool_call", "call_id": "...", "tool": "decompile_function",
   "database_id": "...", "args": {...}, "duration_ms": 12.3,
   "outcome": "ok" | "error" | "cancelled", "error": "..."}

String arguments are truncated and results are not recorded. A write failure
disables tracing for the rest of the process; it never fails a tool call.

This module only uses the standard library.
"""

import datetime
import json
import os
import pathlib
import sys
import threading
from typing import Any
import uuid

TRACE_SCHEMA = 1
MAX_STR_CHARS = 256
MAX_ITEMS = 50
MAX_DEPTH = 4


def _truncate(value: str, limit: int) -> str:
  if len(value) <= limit:
    return value
  return f"{value[:limit]}...(+{len(value) - limit} chars)"


def jsonable(value: Any, depth: int = 0) -> Any:
  """Returns a JSON-serializable copy of value with strings and sizes capped."""
  if value is None or isinstance(value, (bool, int, float)):
    return value
  if isinstance(value, str):
    return _truncate(value, MAX_STR_CHARS)
  if isinstance(value, (bytes, bytearray)):
    return f"<{len(value)} bytes>"
  if depth >= MAX_DEPTH:
    return f"<{type(value).__name__}>"
  if isinstance(value, dict):
    out = {}
    for i, (k, v) in enumerate(value.items()):
      if i >= MAX_ITEMS:
        out["..."] = f"+{len(value) - MAX_ITEMS} items"
        break
      out[_truncate(str(k), MAX_STR_CHARS)] = jsonable(v, depth + 1)
    return out
  if isinstance(value, (list, tuple, set, frozenset)):
    items = list(value)
    out = [jsonable(v, depth + 1) for v in items[:MAX_ITEMS]]
    if len(items) > MAX_ITEMS:
      out.append(f"...+{len(items) - MAX_ITEMS} items")
    return out
  return _truncate(repr(value), MAX_STR_CHARS)


class TraceLogger:
  """Appends one JSON line per event to a per-process file in trace_dir."""

  def __init__(self, trace_dir: str | os.PathLike[str]):
    self.server_id = uuid.uuid4().hex[:12]
    self.trace_dir = pathlib.Path(
        os.path.expandvars(os.fspath(trace_dir))
    ).expanduser()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    self.path = self.trace_dir / f"gateway-{stamp}-{self.server_id}.jsonl"
    self._lock = threading.Lock()
    self._created = False
    self.enabled = True

  def new_call_id(self) -> str:
    return uuid.uuid4().hex[:12]

  def _append(self, line: str) -> None:
    if not self._created:
      self.trace_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
      f.write(line)
    self._created = True

  def emit(self, event: str, **fields: Any) -> None:
    """Writes one record. Never raises."""
    if not self.enabled:
      return
    try:
      record = {
          "schema": TRACE_SCHEMA,
          "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "server_id": self.server_id,
          "pid": os.getpid(),
          "event": event,
          **fields,
      }
      line = (
          json.dumps(
              jsonable(record), ensure_ascii=False, separators=(",", ":")
          )
          + "\n"
      )
      with self._lock:
        self._append(line)
    except Exception as e:  # pylint: disable=broad-exception-caught
      self.enabled = False
      print(
          f"[WARNING] idamcp trace disabled: cannot write {self.path}: {e!r}",
          file=sys.stderr,
      )


def trace_logger_from_config(config: dict[str, Any]) -> TraceLogger | None:
  """Returns a TraceLogger if config sets a non-empty trace_dir, else None."""
  trace_dir = config.get("trace_dir")
  if not trace_dir:
    return None
  return TraceLogger(trace_dir)
