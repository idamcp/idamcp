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

"""Unit tests for the log archive (gateway/logs.py)."""

import contextlib
import hashlib
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from gateway import logs
from shared import config as config_module

REPO_DIR = pathlib.Path(__file__).resolve().parent.parent


class LogArchiveTestBase(unittest.TestCase):

  def setUp(self):
    super().setUp()
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.root = pathlib.Path(tmp.name)
    self.trace_dir = self.root / "traces"
    self.backend_dir = self.root / "tmp"
    self.registry_dir = self.root / "registry"
    for d in (self.trace_dir, self.backend_dir, self.registry_dir):
      d.mkdir()
    self.output = self.root / "out" / "bundle.zip"
    self.config = dict(config_module._DEFAULT_CONFIG)  # pylint: disable=protected-access
    self.config["registry_dir"] = self.registry_dir
    self.config["trace_dir"] = str(self.trace_dir)

  def write(self, path: pathlib.Path, text: str) -> pathlib.Path:
    path.write_text(text, encoding="utf-8")
    return path

  def create(self, trace_files=None, **kwargs):
    return logs.create_log_archive(
        self.output,
        trace_files,
        config=kwargs.pop("config", self.config),
        backend_log_dir=self.backend_dir,
        **kwargs,
    )

  def toc(self) -> dict:
    with zipfile.ZipFile(self.output) as z:
      return json.loads(z.read(logs.TOC_NAME))

  def members(self) -> list[str]:
    with zipfile.ZipFile(self.output) as z:
      return sorted(z.namelist())


class TestCollection(LogArchiveTestBase):

  def test_collects_traces_backend_logs_and_registry(self):
    self.write(self.trace_dir / "gateway-1-a.jsonl", '{"event":"tool_call"}\n')
    self.write(self.trace_dir / "notes.txt", "not a trace")
    self.write(self.backend_dir / "idamcp_backend_db1.log", "backend output")
    self.write(self.backend_dir / "other.log", "unrelated")
    self.write(self.registry_dir / "db1.json", '{"pid": 1}')

    result = self.create()

    self.assertEqual(
        self.members(),
        [
            "backend-logs/idamcp_backend_db1.log",
            logs.TOC_NAME,
            "registry/db1.json",
            "traces/gateway-1-a.jsonl",
        ],
    )
    self.assertEqual(
        result.counts, {"trace": 1, "backend_log": 1, "registry_entry": 1}
    )
    self.assertEqual(result.warnings, ())

  def test_toc_sizes_and_hashes_match_members(self):
    trace = self.write(self.trace_dir / "gateway-1-a.jsonl", "x" * 5000)
    self.create()
    toc = self.toc()
    self.assertEqual(toc["format"], "idamcp-logs")
    self.assertEqual(toc["schema"], 1)
    (entry,) = toc["files"]
    self.assertEqual(entry["kind"], "trace")
    self.assertEqual(entry["source_path"], str(trace.resolve()))
    with zipfile.ZipFile(self.output) as z:
      data = z.read(entry["archive_path"])
    self.assertEqual(entry["size"], len(data))
    self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
    self.assertEqual(data, trace.read_bytes())

  def test_explicit_trace_files_replace_trace_dir(self):
    self.write(self.trace_dir / "gateway-1-a.jsonl", "in trace_dir")
    explicit = self.write(self.root / "picked.jsonl", "picked")
    self.create([explicit])
    self.assertIn("traces/picked.jsonl", self.members())
    self.assertNotIn("traces/gateway-1-a.jsonl", self.members())

  def test_missing_explicit_trace_file_is_an_error(self):
    with self.assertRaisesRegex(logs.LogArchiveError, "does not exist"):
      self.create([self.root / "missing.jsonl"])
    self.assertFalse(self.output.exists())

  def test_same_basename_gets_distinct_members(self):
    (self.root / "a").mkdir()
    (self.root / "b").mkdir()
    one = self.write(self.root / "a" / "t.jsonl", "one")
    two = self.write(self.root / "b" / "t.jsonl", "two")
    self.create([one, two])
    traces = [m for m in self.members() if m.startswith("traces/")]
    self.assertEqual(len(traces), 2)
    self.assertIn("traces/t.jsonl", traces)

  def test_trace_dir_not_set_warns_and_still_writes(self):
    self.config["trace_dir"] = ""
    self.write(self.registry_dir / "db1.json", "{}")
    result = self.create()
    self.assertTrue(self.output.is_file())
    self.assertEqual(result.counts["registry_entry"], 1)
    self.assertIn("trace_dir is not set", result.warnings[0])
    self.assertEqual(self.toc()["warnings"], list(result.warnings))

  def test_empty_trace_dir_warns(self):
    result = self.create()
    self.assertIn("no gateway traces found", result.warnings[0])

  def test_missing_directories_are_empty(self):
    self.config["trace_dir"] = str(self.root / "nope")
    self.config["registry_dir"] = self.root / "nope2"
    self.backend_dir = self.root / "nope3"
    result = self.create()
    self.assertEqual(
        result.counts, {"trace": 0, "backend_log": 0, "registry_entry": 0}
    )
    self.assertEqual(self.members(), [logs.TOC_NAME])

  @unittest.skipIf(sys.platform == "win32", "symlinks need privileges")
  def test_symlinks_are_skipped(self):
    target = self.write(self.root / "secret.txt", "outside")
    os.symlink(target, self.trace_dir / "gateway-link.jsonl")
    os.symlink(target, self.registry_dir / "link.json")
    self.create()
    self.assertEqual(self.members(), [logs.TOC_NAME])

  def test_file_that_vanishes_is_skipped_with_warning(self):
    self.write(self.registry_dir / "gone.json", "{}")
    self.write(self.registry_dir / "kept.json", "{}")
    real = logs._write_file  # pylint: disable=protected-access

    def flaky(archive, source, member):
      if source.name == "gone.json":
        raise FileNotFoundError("removed")
      return real(archive, source, member)

    with mock.patch.object(logs, "_write_file", side_effect=flaky):
      result = self.create()
    self.assertEqual(result.counts["registry_entry"], 1)
    self.assertIn("registry/kept.json", self.members())
    self.assertTrue(any("gone.json" in w for w in result.warnings))


class TestConfigAndEnvironment(LogArchiveTestBase):

  def test_only_known_config_keys_are_recorded(self):
    self.config["some_api_key"] = "do-not-copy"
    self.create()
    recorded = self.toc()["config"]
    self.assertNotIn("some_api_key", recorded)
    self.assertNotIn("do-not-copy", json.dumps(self.toc()))
    self.assertEqual(recorded["registry_dir"], str(self.registry_dir))
    self.assertEqual(recorded["trace_dir"], str(self.trace_dir))
    self.assertEqual(
        set(recorded),
        set(config_module._DEFAULT_CONFIG),  # pylint: disable=protected-access
    )

  def test_environment(self):
    with mock.patch.object(logs, "_git_commit", return_value="abc123"):
      self.create()
    env = self.toc()["environment"]
    self.assertEqual(env["idamcp_commit"], "abc123")
    self.assertEqual(env["python"], sys.version)
    self.assertIn("platform", env)

  def test_git_commit_without_git(self):
    with mock.patch.object(
        logs.subprocess, "run", side_effect=FileNotFoundError("git")
    ):
      self.assertIsNone(logs._git_commit())  # pylint: disable=protected-access


class TestOutput(LogArchiveTestBase):

  def test_existing_output_needs_overwrite(self):
    self.output.parent.mkdir()
    self.write(self.output, "old")
    with self.assertRaisesRegex(logs.LogArchiveError, "--force"):
      self.create()
    self.assertEqual(self.output.read_text(), "old")
    self.create(overwrite=True)
    self.assertIn(logs.TOC_NAME, self.members())

  @unittest.skipIf(sys.platform == "win32", "POSIX modes")
  def test_modes_are_private(self):
    self.write(self.registry_dir / "db1.json", "{}")
    self.create()
    self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
    with zipfile.ZipFile(self.output) as z:
      for info in z.infolist():
        self.assertEqual(stat.S_IMODE(info.external_attr >> 16), 0o600)

  def test_failure_leaves_no_files(self):
    self.write(self.registry_dir / "db1.json", "{}")
    with mock.patch.object(
        logs, "_write_file", side_effect=RuntimeError("boom")
    ):
      with self.assertRaises(RuntimeError):
        self.create()
    self.assertEqual(list(self.output.parent.iterdir()), [])


class TestMain(LogArchiveTestBase):

  def test_main_writes_and_reports(self):
    self.write(self.trace_dir / "gateway-1-a.jsonl", "{}")
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(
        config_module, "load_config", return_value=self.config
    ), mock.patch.object(
        logs.tempfile, "gettempdir", return_value=str(self.backend_dir)
    ), contextlib.redirect_stdout(
        out
    ), contextlib.redirect_stderr(
        err
    ):
      code = logs.main(["-o", str(self.output)])
    self.assertEqual(code, 0)
    self.assertIn(f"created {self.output.resolve()}", out.getvalue())
    self.assertIn("traces: 1", out.getvalue())
    self.assertIn("Review the archive", out.getvalue())
    self.assertEqual(err.getvalue(), "")

  def test_main_error_exit_code(self):
    err = io.StringIO()
    with mock.patch.object(
        config_module, "load_config", return_value=self.config
    ), contextlib.redirect_stderr(err):
      code = logs.main(["-o", str(self.output), str(self.root / "missing")])
    self.assertEqual(code, 2)
    self.assertIn("idamcp logs: error:", err.getvalue())


class TestCommandLine(unittest.TestCase):
  """Runs the real entry points in a subprocess with an isolated HOME/TMPDIR."""

  def setUp(self):
    super().setUp()
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.root = pathlib.Path(tmp.name)
    (self.root / "tmp").mkdir()
    (self.root / "traces").mkdir()
    (self.root / "traces" / "gateway-1-a.jsonl").write_text("{}\n")
    self.env = dict(
        os.environ,
        HOME=str(self.root),
        USERPROFILE=str(self.root),
        TMPDIR=str(self.root / "tmp"),
        IDAMCP_NO_USER_CONFIG="1",
        TRACE_DIR=str(self.root / "traces"),
        PYTHONPATH=str(REPO_DIR),
    )

  def run_cli(self, *args):
    return subprocess.run(
        [sys.executable, *args],
        cwd=REPO_DIR,
        env=self.env,
        capture_output=True,
        text=True,
        timeout=120,
    )

  def test_install_py_logs_forwards_arguments(self):
    output = self.root / "via_install.zip"
    proc = self.run_cli("install.py", "logs", "-o", str(output))
    self.assertEqual(proc.returncode, 0, proc.stderr)
    with zipfile.ZipFile(output) as z:
      self.assertIn("traces/gateway-1-a.jsonl", z.namelist())

  def test_module_does_not_import_the_gateway_server(self):
    proc = self.run_cli(
        "-c",
        "import sys, gateway.logs;"
        " print(sorted(m for m in ('fastmcp', 'gateway.forward')"
        " if m in sys.modules))",
    )
    self.assertEqual(proc.returncode, 0, proc.stderr)
    self.assertEqual(proc.stdout.strip(), "[]")


if __name__ == "__main__":
  unittest.main()
