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
#
# Portions of this file (the ZIP writing helpers, the temporary-file handling
# and the command-line messages) are adapted from IDA MCP
# (https://github.com/HexRaysSA/ida-mcp, ida_mcp/logs.py),
# Copyright (c) 2026 Hex-Rays SA, used under the MIT License, whose terms are
# the same as those above.

"""Collects idamcp logs and state into one ZIP for bug reports.

  python3 -m gateway.logs [-o OUTPUT] [--force] [TRACE_FILE ...]

The archive contains:

  traces/            gateway JSONL traces (all files in `trace_dir`, or the
                     files given on the command line)
  backend-logs/      `<tmp>/idamcp_backend_*.log` of headless backends
  registry/          backend registry entries (`registry_dir/*.json`)
  idamcp-logs.json   table of contents: every file with its source path, size
                     and sha256, the effective configuration (known options
                     only) and environment information

It runs without the gateway or IDA and only uses the standard library and
`shared.config`. Files are read as they are; they can contain file paths,
tool arguments and backend output, so review the archive before sharing it.
"""

import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import platform
import stat
import subprocess
import sys
import tempfile
from typing import Any, Sequence
import uuid
import zipfile

from shared import config as config_module

ARCHIVE_FORMAT = "idamcp-logs"
ARCHIVE_SCHEMA = 1
TOC_NAME = "idamcp-logs.json"
TRACE_GLOB = "gateway-*.jsonl"
BACKEND_LOG_GLOB = "idamcp_backend_*.log"
REPO_DIR = pathlib.Path(__file__).resolve().parent.parent


class LogArchiveError(Exception):
  """The archive cannot be created."""


@dataclasses.dataclass(frozen=True)
class LogArchiveResult:
  output: pathlib.Path
  counts: dict[str, int]
  warnings: tuple[str, ...]


def _files(directory: pathlib.Path, pattern: str) -> list[pathlib.Path]:
  """Regular files in directory matching pattern; symlinks are skipped."""
  try:
    if not directory.is_dir():
      return []
    candidates = sorted(directory.glob(pattern))
  except OSError:
    return []
  files = []
  for path in candidates:
    try:
      if path.is_symlink() or not path.is_file():
        continue
    except OSError:
      continue
    files.append(path.resolve())
  return files


def _jsonable_config(config: dict[str, Any]) -> dict[str, Any]:
  """Known options only: user config files can hold unrelated keys."""
  known = {}
  for key in config_module._DEFAULT_CONFIG:  # pylint: disable=protected-access
    if key not in config:
      continue
    value = config[key]
    if isinstance(value, os.PathLike):
      value = os.fspath(value)
    elif isinstance(value, (set, frozenset, tuple)):
      value = sorted(value)
    known[key] = value
  return known


def _git_commit() -> str | None:
  if not (REPO_DIR / ".git").exists():
    return None
  try:
    out = subprocess.run(
        ["git", "-C", str(REPO_DIR), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
  except (OSError, subprocess.SubprocessError):
    return None
  return out.stdout.strip() or None


def _environment() -> dict[str, Any]:
  return {
      "python": sys.version,
      "python_executable": sys.executable,
      "platform": platform.platform(),
      "idamcp_dir": str(REPO_DIR),
      "idamcp_commit": _git_commit(),
  }


def _timestamp() -> str:
  return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _zip_info(name: str) -> zipfile.ZipInfo:
  info = zipfile.ZipInfo(
      name, datetime.datetime.now().timetuple()[:6]  # local time, as zip does
  )
  info.compress_type = zipfile.ZIP_DEFLATED
  info.external_attr = (stat.S_IFREG | 0o600) << 16
  return info


def _write_file(
    archive: zipfile.ZipFile, source: pathlib.Path, member: str
) -> tuple[int, str]:
  digest = hashlib.sha256()
  size = 0
  with source.open("rb") as src, archive.open(_zip_info(member), "w") as dst:
    while chunk := src.read(1024 * 1024):
      dst.write(chunk)
      digest.update(chunk)
      size += len(chunk)
  return size, digest.hexdigest()


def _member(folder: str, path: pathlib.Path, used: set[str]) -> str:
  name = f"{folder}/{path.name}"
  if name in used:
    suffix = hashlib.sha256(str(path).encode()).hexdigest()[:8]
    name = f"{folder}/{path.stem}.{suffix}{path.suffix}"
  used.add(name)
  return name


def create_log_archive(
    output: pathlib.Path,
    trace_files: Sequence[pathlib.Path] | None = None,
    *,
    config: dict[str, Any] | None = None,
    backend_log_dir: pathlib.Path | None = None,
    overwrite: bool = False,
) -> LogArchiveResult:
  """Writes the archive to output and returns what it contains."""
  if config is None:
    config = config_module.load_config()
  if backend_log_dir is None:
    backend_log_dir = pathlib.Path(tempfile.gettempdir())
  output = output.expanduser().resolve()
  if output.exists() and not overwrite:
    raise LogArchiveError(f"output already exists (use --force): {output}")

  warnings: list[str] = []
  if trace_files:
    traces = []
    for requested in trace_files:
      path = requested.expanduser()
      if not path.is_file():
        raise LogArchiveError(f"trace file does not exist: {requested}")
      traces.append(path.resolve())
  else:
    trace_dir = config.get("trace_dir")
    if trace_dir:
      trace_path = pathlib.Path(os.path.expandvars(str(trace_dir))).expanduser()
      traces = _files(trace_path, TRACE_GLOB)
      if not traces:
        warnings.append(f"no gateway traces found in {trace_path}")
    else:
      traces = []
      warnings.append("trace_dir is not set: no gateway traces collected")

  groups = [
      ("trace", "traces", traces),
      (
          "backend_log",
          "backend-logs",
          _files(backend_log_dir.expanduser(), BACKEND_LOG_GLOB),
      ),
      (
          "registry_entry",
          "registry",
          _files(pathlib.Path(config["registry_dir"]).expanduser(), "*.json"),
      ),
  ]

  output.parent.mkdir(parents=True, exist_ok=True)
  temporary = output.parent / f".{output.name}.tmp-{uuid.uuid4().hex}"
  entries: list[dict[str, Any]] = []
  counts = {kind: 0 for kind, _, _ in groups}
  used: set[str] = set()
  try:
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w+b") as archive_file, zipfile.ZipFile(
        archive_file, "w", allowZip64=True
    ) as archive:
      for kind, folder, paths in groups:
        for path in paths:
          if path == output:
            continue
          member = _member(folder, path, used)
          try:
            size, digest = _write_file(archive, path, member)
          except OSError as e:
            # A backend can delete its registry entry or log meanwhile.
            used.discard(member)
            warnings.append(f"skipped {path}: {e}")
            continue
          counts[kind] += 1
          entries.append({
              "kind": kind,
              "source_path": str(path),
              "archive_path": member,
              "size": size,
              "sha256": digest,
          })
      toc = {
          "format": ARCHIVE_FORMAT,
          "schema": ARCHIVE_SCHEMA,
          "created_at": _timestamp(),
          "environment": _environment(),
          "config": _jsonable_config(config),
          "files": entries,
          "warnings": warnings,
      }
      archive.writestr(
          _zip_info(TOC_NAME),
          json.dumps(toc, ensure_ascii=False, indent=2, default=str) + "\n",
      )
    os.replace(temporary, output)
  except BaseException:
    try:
      temporary.unlink()
    except OSError:
      pass
    raise
  return LogArchiveResult(output, counts, tuple(warnings))


def _default_output() -> pathlib.Path:
  stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
  return pathlib.Path.cwd() / f"idamcp-logs-{stamp}.zip"


def main(argv: Sequence[str] | None = None) -> int:
  parser = argparse.ArgumentParser(
      prog="python3 -m gateway.logs",
      description=(
          "Create a ZIP with idamcp gateway traces, headless backend logs,"
          " registry entries, the effective configuration and environment"
          " information, for bug reports."
      ),
  )
  parser.add_argument(
      "trace_files",
      nargs="*",
      type=pathlib.Path,
      help="Gateway trace files to include (default: all files in trace_dir)",
  )
  parser.add_argument(
      "-o",
      "--output",
      type=pathlib.Path,
      help="Output ZIP (default: ./idamcp-logs-<timestamp>.zip)",
  )
  parser.add_argument(
      "--force", action="store_true", help="Replace an existing output file"
  )
  args = parser.parse_args(argv)

  try:
    result = create_log_archive(
        args.output or _default_output(),
        args.trace_files or None,
        overwrite=args.force,
    )
  except (LogArchiveError, OSError, zipfile.BadZipFile) as e:
    print(f"idamcp logs: error: {e}", file=sys.stderr)
    return 2
  for warning in result.warnings:
    print(f"idamcp logs: warning: {warning}", file=sys.stderr)
  print(f"created {result.output}")
  print(
      f"included traces: {result.counts['trace']}, backend logs:"
      f" {result.counts['backend_log']}, registry entries:"
      f" {result.counts['registry_entry']}."
      " Review the archive before sharing it: it can contain file paths,"
      " tool arguments and backend output."
  )
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
