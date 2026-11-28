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

"""Gateway forwarder module."""

import asyncio
import atexit
import collections
import contextlib
import json
import logging
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
from typing import Annotated, Any, Mapping, NotRequired, Sequence

from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext
from fastmcp.server.middleware import Middleware
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.server.transforms.search import BM25SearchTransform
from fastmcp.server.transforms.search import serialize_tools_for_output_markdown
from fastmcp.tools import Tool
from fastmcp.tools import ToolResult

from gateway.trace import trace_logger_from_config
from gateway.trace import TraceLogger

try:
  # FastMCP 4 ships the MCP types as mcp_types; FastMCP 3 uses the mcp SDK,
  # which in both cases provides the same classes under mcp.types.
  from mcp_types import CallToolRequestParams
  from mcp_types import TextContent
except ImportError:
  from mcp.types import CallToolRequestParams
  from mcp.types import TextContent
from pydantic import AliasChoices
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from shared import load_options
from shared import registry
from shared.config import load_config
from shared.process import is_process_running
from shared.rpc import RPCClient
from shared.rpc import RPCError
from shared.types import AddressValue
from shared.types import Metadata
from watchdog.events import (
    DirDeletedEvent,
    DirMovedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

logging.basicConfig(level=logging.ERROR)

# Load configuration
CONFIG = load_config()
REGISTRY_DIR = pathlib.Path(CONFIG["registry_dir"])
UDS_DIR = pathlib.Path(CONFIG["uds_dir"])
# JSONL trace of forwarded tool calls; None unless `trace_dir` is configured.
TRACE: TraceLogger | None = trace_logger_from_config(CONFIG)


def _cleanup_stale_registry_file(
    registry_file: pathlib.Path,
    data: Mapping[str, Any] | None = None,
) -> None:
  """Remove stale registry file and any associated UDS socket."""
  if data is None and registry_file.exists():
    with contextlib.suppress(Exception):
      with open(registry_file, "r", encoding="utf-8") as f:
        data = json.load(f)

  with contextlib.suppress(OSError):
    if registry_file.exists():
      registry_file.unlink()
      logging.info("Removed stale registry file: %s", registry_file)

  if data and data.get("channel") == "uds" and data.get("address"):
    with contextlib.suppress(OSError):
      uds_path = pathlib.Path(data["address"])
      if uds_path.exists():
        uds_path.unlink()
        logging.info("Removed stale UDS socket: %s", uds_path)


def _cleanup_stale_instance(instance_id: str | None) -> None:
  """Remove an instance's stale registry file and any associated UDS socket."""
  if not instance_id:
    return
  for in_progress in (True, False):
    _cleanup_stale_registry_file(
        REGISTRY_DIR / registry.record_name(instance_id, in_progress)
    )
  with contextlib.suppress(OSError):
    uds_path = UDS_DIR / f"{instance_id}.sock"
    if uds_path.exists():
      uds_path.unlink()
      logging.info("Removed stale UDS socket: %s", uds_path)


class DatabaseInfo(Metadata):
  """Information about a connected IDA database."""

  database_id: Annotated[str, "The unique ID of the target IDA database"]
  pid: Annotated[int, "Process ID of the IDA instance"]
  busy: NotRequired[
      Annotated[
          bool,
          "Whether the database is currently busy executing a tool or"
          " running its auto-analysis",
      ]
  ]


DATABASE_ID_ALIASES = AliasChoices(
    "database_id", "database", "db", "db_id", "id"
)

DatabaseId = Annotated[
    str,
    Field(
        validation_alias=DATABASE_ID_ALIASES,
        description=(
            "The unique identifier for the target IDA database. You can obtain"
            " this ID by calling list_available_databases, reading the"
            " ida://databases resource, or by opening a new database via"
            " idalib_headless_open."
        ),
    ),
]


class ClientState(BaseModel):
  # Allow complex types like asyncio.Condition
  model_config = ConfigDict(arbitrary_types_allowed=True)

  # Use default_factory so each instance gets a unique Condition
  condition: asyncio.Condition = Field(default_factory=asyncio.Condition)
  number_of_ongoing_calls: int = 0
  is_closed: bool = False
  is_broken: bool = False


_global_clients: dict[str, RPCClient] = {}
_global_metadata: dict[str, DatabaseInfo] = {}
# The instance that is connected for each database, and the reverse. Both
# change only together with _global_metadata. The instance ID stays out of
# the metadata, which MCP clients get to see: only the gateway needs it, and
# a client would confuse it with the database ID.
_global_backend_id_to_instance_id: dict[str, str] = {}
_global_instance_id_to_backend_id: dict[str, str] = {}
_global_database_id_to_pid: dict[str, int] = {}
_global_client_state: dict[str, ClientState] = collections.defaultdict(
    ClientState
)
_backend_events: dict[str, asyncio.Event] = collections.defaultdict(
    asyncio.Event
)
# Set when a backend's auto-analysis is no longer in progress, or when the
# backend is disconnected. An entry exists only while spawn() waits for it.
_analysis_events: dict[str, asyncio.Event] = {}
# When each connected instance started (its record's started_at): of two live
# instances of a database, the gateway keeps the newer.
_global_started_at: dict[str, float] = {}
# How long spawn() waits, in seconds, for the new instance to register.
_SPAWN_CONNECT_TIMEOUT = 15.0
# How long a process gets to exit, in seconds, after it is asked to, before
# it is killed.
_KILL_GRACE_SECONDS = 20
_background_tasks: set[asyncio.Task] = set()
_watcher_active: bool = False
_observer: Observer | None = None
_connect_lock: asyncio.Lock = asyncio.Lock()


def _is_watcher_active() -> bool:
  """Check if the filesystem watcher is active and running."""
  global _watcher_active
  if _watcher_active and _observer is not None and not _observer.is_alive():
    _watcher_active = False
  return _watcher_active


def _create_background_task(coro) -> asyncio.Task:
  """Create a background task and hold a strong reference until done."""
  task = asyncio.create_task(coro)
  _background_tasks.add(task)
  task.add_done_callback(_background_tasks.discard)
  return task


async def _kill_process_gracefully(pid: int) -> None:
  """Terminate a process gracefully or force kill if unresponsive."""
  try:
    # On Windows, try CTRL_BREAK_EVENT for graceful shutdown if available
    if sys.platform == "win32" and hasattr(signal, "CTRL_BREAK_EVENT"):
      try:
        logging.info(
            "[HeadlessManager] Sending CTRL_BREAK_EVENT to PID %d", pid
        )
        os.kill(pid, signal.CTRL_BREAK_EVENT)
      except Exception:
        # On Windows, the SIGTERM signal terminates the target process
        # immediately. The logic here is that if CTRL_BREAK_EVENT failed
        # somehow, we're not going to wait for a grace period.
        sig = getattr(signal, "SIGTERM", 15)
        logging.info(
            "[HeadlessManager] CTRL_BREAK_EVENT failed, sending SIGTERM to"
            " PID %d",
            pid,
        )
        os.kill(pid, sig)
        return
    else:
      # Use SIGTERM if available (Graceful on Unix)
      sig = getattr(signal, "SIGTERM", 15)
      logging.info("[HeadlessManager] Sending SIGTERM to PID %d", pid)
      os.kill(pid, sig)

    # Wait a bit for graceful shutdown
    for _ in range(_KILL_GRACE_SECONDS):
      if not is_process_running(pid):
        logging.info("[HeadlessManager] Process %d exited gracefully", pid)
        break
      await asyncio.sleep(1)
    else:
      # Still running, force kill
      logging.warning(
          "[Gateway] Process %d did not exit gracefully, sending force kill",
          pid,
      )
      sig = getattr(signal, "SIGKILL", 9)
      logging.info("[HeadlessManager] Sending SIGKILL to PID %d", pid)
      os.kill(pid, sig)
  except (ProcessLookupError, PermissionError):
    logging.info(
        "[HeadlessManager] Process %d already dead (Lookup/Permission error)",
        pid,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logging.warning("Failed to kill process %s: %s", pid, e)


async def _kill_and_clean_up(pid: int, instance_id: str | None) -> None:
  """Terminates a process, then removes the files it left if it was killed."""
  await _kill_process_gracefully(pid)
  # A process that exits by itself removes its record and socket; one that
  # had to be killed doesn't, and nothing else would ever name them again.
  # A killed process counts as running until it has been reaped, so it gets
  # a moment to go.
  for _ in range(100):
    if not is_process_running(pid):
      _cleanup_stale_instance(instance_id)
      return
    await asyncio.sleep(0.05)


def _process_exited(process: Any) -> bool:
  """Whether a spawned subprocess has exited."""
  return isinstance(process.returncode, int)


class HeadlessManager:
  """Manages headless IDA instances."""

  def __init__(self, max_instances: int):
    self.max_instances = max_instances
    self.spawned_instances: set[str] = set()
    self._pending_spawns: int = 0
    # The instance spawned for each database, where known.
    self._instance_ids: dict[str, str] = {}

  def register(
      self, database_id: str, pid: int, instance_id: str | None = None
  ):
    """Register a new active headless instance."""
    self.spawned_instances.add(database_id)
    _global_database_id_to_pid[database_id] = pid
    if instance_id:
      self._instance_ids[database_id] = instance_id
    else:
      self._instance_ids.pop(database_id, None)

  def owns(self, database_id: str, instance_id: str | None) -> bool:
    """Whether instance_id is, or may be, the one registered for database_id.

    False only if another instance is known to be registered: cleaning up
    after some other instance of the database (a leftover record, a replaced
    connection) must not unregister or signal the spawned one.
    """
    registered = self._instance_ids.get(database_id)
    return not (instance_id and registered and instance_id != registered)

  async def unregister(self, database_id: str, instance_id: str | None = None):
    """Unregister a headless instance.

    Args:
      database_id: The database that the instance serves.
      instance_id: The instance's ID if known. Nothing happens if another
        instance is registered for the database; otherwise it names the registry
        record and socket to remove if the process has to be killed.
    """
    if not self.owns(database_id, instance_id):
      logging.info(
          "[HeadlessManager] not unregistering %s: instance %s isn't the"
          " registered one",
          database_id,
          instance_id,
      )
      return
    logging.info("[HeadlessManager] unregister started for %s", database_id)
    self.spawned_instances.discard(database_id)
    registered_id = self._instance_ids.pop(database_id, None)
    pid = _global_database_id_to_pid.pop(database_id, None)
    if pid is not None:
      if is_process_running(pid):
        _create_background_task(
            _kill_and_clean_up(pid, instance_id or registered_id)
        )
      else:
        _cleanup_stale_instance(instance_id or registered_id)

  async def close(self, database_id: str) -> None:
    """Close a specific headless instance gracefully."""
    self.spawned_instances.discard(database_id)
    await disconnect_backend(database_id)

  async def spawn(
      self,
      path: str,
      options: load_options.LoadOptions | None = None,
      disable_auto_analysis: bool = False,
  ) -> DatabaseInfo:
    """Spawn a headless instance, optionally with validated load options.

    Returns once the instance has loaded the file and registered. If its
    auto-analysis is still running then, waits up to `headless_analysis_wait`
    seconds for it; the returned auto_analysis_status tells whether it
    finished.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
      raise ToolError(f"{path} doesn't exist.")
    if options is None:
      options = load_options.LoadOptions()
    try:
      load_options.check_applicable(path, options)
    except load_options.LoadOptionsError as e:
      raise ToolError(str(e)) from e

    for db_id, metadata in list(_global_metadata.items()):
      if (
          metadata.get("database_path") == path
          or metadata.get("filepath") == path
      ):
        pid = metadata.get("pid")
        if pid and is_process_running(pid):
          raise ToolError(
              f"Database {path} is already connected (ID: {db_id}). DO NOT"
              " attempt to open it again; use the existing ID to access it"
              " directly.",
          )
        if db_id in _global_clients:
          # The instance died without cleaning up (crash, kill -9), possibly
          # before the client's read loop noticed EOF. Drop it now, so that it
          # doesn't count against max_instances below, and so that its later
          # cleanup can't pop the new process's PID entry.
          await disconnect_backend(db_id)

    if len(self.spawned_instances) + self._pending_spawns >= self.max_instances:
      raise ToolError(
          f"Cannot open '{path}': Maximum number of headless IDA instances"
          f" ({self.max_instances}) reached. Please close an unused instance"
          " using idalib_headless_close before opening a new one."
      )

    self._pending_spawns += 1
    try:
      # Determine command
      python_path = CONFIG.get("python_path", sys.executable)

      # Run as module from repo root
      current_dir = pathlib.Path(__file__).resolve().parent
      repo_root = current_dir.parent

      # Prepare creation flags for Windows
      if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
      else:
        creationflags = 0

      new_env = os.environ.copy()
      env_pythonpath = new_env.get("PYTHONPATH", "")
      new_env["PYTHONPATH"] = str(repo_root)
      if env_pythonpath:
        new_env["PYTHONPATH"] += os.pathsep + env_pythonpath

      process = await asyncio.create_subprocess_exec(
          python_path,
          "-m",
          "ida_mcp.headless",
          path,
          *options.to_cli(),
          *(["--disable-auto-analysis"] if disable_auto_analysis else []),
          stdin=asyncio.subprocess.DEVNULL,
          stdout=asyncio.subprocess.PIPE,
          stderr=asyncio.subprocess.PIPE,
          cwd=repo_root,
          env=new_env,
          creationflags=creationflags,
      )

      metadata: DatabaseInfo | None = None

      # Wait for JSON metadata with timeout
      try:
        if process.stdout is None:
          raise ToolError("Failed to open stdout pipe")

        # We check line by line
        while True:
          line_bytes = await asyncio.wait_for(
              process.stdout.readline(),
              timeout=CONFIG.get("headless_open_timeout", 600.0),  # type: ignore
          )
          if not line_bytes:
            break
          line = line_bytes.decode("utf-8", errors="replace").strip()

          if line.startswith("[MCP_JSON] "):
            json_str = line[len("[MCP_JSON] ") :]
            metadata = json.loads(json_str)  # type: ignore
            break
      except json.JSONDecodeError as e:
        raise ToolError("Failed to parse metadata JSON") from e
      except asyncio.TimeoutError as e:
        process.terminate()
        raise ToolError("Timeout waiting for IDA to start/emit metadata") from e
      except asyncio.CancelledError:
        with contextlib.suppress(Exception):
          process.terminate()
        raise

      if not metadata:
        with contextlib.suppress(Exception):
          process.terminate()

        if process.stderr:
          stderr_str = ""
          with contextlib.suppress(Exception, asyncio.TimeoutError):
            stderr_bytes = await asyncio.wait_for(
                process.stderr.read(65535), timeout=0.2
            )
            stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()

          if stderr_str:
            raise ToolError(f"metadata is None. stderr: {stderr_str}")
        raise ToolError("metadata is None")

      db_id = metadata["database_id"]
      # The line also names the instance, for the gateway only: it is not
      # part of the result.
      instance_id: str = metadata.pop("instance_id")  # type: ignore
      # Ensure pid matches what we spawned (for tracking)
      metadata["pid"] = process.pid
      # The check above may have missed a dead instance of this database if
      # the path was spelled differently (symlink, relative path); the id
      # comes from the backend, so catch it here. Disconnect it before
      # registering the new process; otherwise connect_to_backend disconnects
      # it once the new record arrives, and that cleanup pops and signals the
      # new process's PID entry.
      if (
          db_id in _global_clients
          and _global_backend_id_to_instance_id.get(db_id) != instance_id
      ):
        await disconnect_backend(db_id)
      async with _global_client_state[db_id].condition:
        self.register(db_id, process.pid, instance_id)
    finally:
      self._pending_spawns -= 1
    try:
      # Look for the instance's record here too, rather than only wait for
      # the watcher: the watcher may not be running, or may miss the event.
      deadline = time.monotonic() + _SPAWN_CONNECT_TIMEOUT
      while (
          not _is_connected_to_instance(db_id, instance_id)
          and db_id in self.spawned_instances
      ):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
          raise TimeoutError
        event = _backend_events[db_id]
        event.clear()
        await _connect_to_instance(instance_id)
        if (
            _is_connected_to_instance(db_id, instance_id)
            or db_id not in self.spawned_instances
            or _process_exited(process)
        ):
          break
        with contextlib.suppress(asyncio.TimeoutError):
          await asyncio.wait_for(event.wait(), timeout=min(0.1, remaining))
    except TimeoutError as e:
      async with _global_client_state[db_id].condition:
        await self.unregister(db_id, instance_id)
      raise ToolError(
          "Backend process started, but it never registered (timeout)."
      ) from e
    finally:
      _backend_events.pop(db_id, None)
    if (
        not _is_connected_to_instance(db_id, instance_id)
        # A connect_to_backend that failed meanwhile gave the instance up,
        # and it is being killed, even if a later attempt then connected.
        or db_id not in self.spawned_instances
        or _process_exited(process)
    ):
      if _global_instance_id_to_backend_id.get(instance_id) == db_id:
        await disconnect_backend(db_id)
      else:
        async with _global_client_state[db_id].condition:
          await self.unregister(db_id, instance_id)
      stderr_str = ""
      if process.stderr:
        with contextlib.suppress(Exception):
          stderr_bytes = await asyncio.wait_for(
              process.stderr.read(65535), timeout=0.2
          )
          stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()
      if stderr_str:
        raise ToolError(
            f"Failed to connect to headless backend. stderr: {stderr_str}"
        )
      raise ToolError("Failed to connect to headless backend.")

    await self._wait_for_analysis(db_id, instance_id, process)
    info = _global_metadata.get(db_id)
    if (
        not _is_connected_to_instance(db_id, instance_id)
        or _process_exited(process)
        or info is None
    ):
      if _global_instance_id_to_backend_id.get(instance_id) == db_id:
        await disconnect_backend(db_id)
      else:
        async with _global_client_state[db_id].condition:
          await self.unregister(db_id, instance_id)
      raise ToolError(
          "The headless backend exited while its auto-analysis was running."
      )
    metadata["auto_analysis_status"] = info["auto_analysis_status"]
    # As in list_available_databases: no tool call is under way yet, so the
    # database is busy only while it is still being analysed.
    metadata["busy"] = info["auto_analysis_status"] == "in_progress"
    return metadata

  async def _wait_for_analysis(
      self, db_id: str, instance_id: str, process: Any
  ) -> None:
    """Waits a while for a connected instance's auto-analysis to finish.

    Returns when the analysis is no longer in progress, when the instance is
    disconnected or exits, or after `headless_analysis_wait` seconds. Checks
    for the renamed record itself, so it doesn't depend on a watcher event.
    """
    timeout = float(CONFIG.get("headless_analysis_wait") or 0)
    deadline = time.monotonic() + timeout
    event = _analysis_events.setdefault(db_id, asyncio.Event())
    try:
      while True:
        info = _global_metadata.get(db_id)
        if (
            not _is_connected_to_instance(db_id, instance_id)
            or _process_exited(process)
            or info is None
            or info.get("auto_analysis_status") != "in_progress"
        ):
          return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
          return
        with contextlib.suppress(asyncio.TimeoutError):
          await asyncio.wait_for(event.wait(), timeout=min(0.2, remaining))
        if not event.is_set():
          await _connect_to_instance(instance_id)
    finally:
      _analysis_events.pop(db_id, None)


_headless_manager = HeadlessManager(CONFIG.get("max_headless_instances", 4))


def _is_connected_to_instance(backend_id: str, instance_id: str) -> bool:
  """Whether a live client for this instance of backend_id exists.

  Call it under _global_client_state[backend_id].condition.
  """
  client = _global_clients.get(backend_id)
  return (
      client is not None
      and not client.is_closed
      and not _global_client_state[backend_id].is_closed
      and _global_backend_id_to_instance_id.get(backend_id) == instance_id
  )


async def _connect_to_instance(instance_id: str) -> None:
  """Connects to an instance, or updates its status, from its own record.

  Looks the record up by name instead of waiting for a watcher event. Does
  nothing for a connected instance whose record still has its in-progress
  name.
  """
  plain = REGISTRY_DIR / registry.record_name(instance_id, False)
  if plain.exists():
    await connect_to_backend(plain)
    return
  if instance_id not in _global_instance_id_to_backend_id:
    in_progress = REGISTRY_DIR / registry.record_name(instance_id, True)
    if in_progress.exists():
      await connect_to_backend(in_progress)


def _analysis_status(in_progress: bool, data: Mapping[str, Any]) -> str:
  """Returns the auto_analysis_status that a registry record stands for.

  Args:
    in_progress: Whether the record's name has the in-progress prefix.
    data: The record's content.
  """
  if in_progress:
    return "in_progress"
  return "disabled" if data.get("auto_analysis_disabled") else "done"


def _update_analysis_status(backend_id: str, status: str) -> None:
  """Records a connected instance's status from another of its records."""
  info = _global_metadata[backend_id]
  # The status only moves on: a late event for the in-progress record must
  # not undo the rename that ended the analysis.
  if status == "in_progress" or info.get("auto_analysis_status") == status:
    return
  info["auto_analysis_status"] = status  # type: ignore
  logging.info("[Gateway] Backend %s auto-analysis: %s", backend_id, status)
  if (event := _analysis_events.get(backend_id)) is not None:
    event.set()


async def connect_to_backend(registry_file: pathlib.Path) -> None:
  """Connect to a backend.

  The record's name gives the instance ID and whether the instance's
  auto-analysis is still running (see shared.registry); its content names the
  database. Idempotent for a record of the instance we are already connected
  to: concurrent calls for it (watcher event, initial scan, fallback scan,
  spawn) end up with a single connection, and its renamed record only updates
  the auto-analysis status. A record of another instance of the same database
  replaces the existing connection.
  """
  instance_id, in_progress = registry.parse_record_name(registry_file.name)
  logging.info("[Gateway] connect_to_backend triggered for %s", registry_file)

  data = None
  # Read registry file with retry logic (in case it's being written)
  with contextlib.suppress(Exception):
    if registry_file.exists():
      with open(registry_file, "r", encoding="utf-8") as f:
        content = f.read().strip()
        if content:
          data = json.loads(content)
  backend_id = data.get("database_id") if isinstance(data, dict) else None
  started_at = data.get("started_at") if isinstance(data, dict) else None
  if (
      not data
      or not isinstance(backend_id, str)
      or isinstance(started_at, bool)
      or not isinstance(started_at, (int, float))
  ):
    if in_progress:
      # Nothing is lost if the instance has just renamed this record. The
      # only rename is from the in-progress name to the plain one.
      plain_record = registry_file.with_name(
          registry.record_name(instance_id, False)
      )
      if plain_record.exists():
        return
    logging.error("[Gateway] Could not read registry file %s", registry_file)
    connected_id = _global_instance_id_to_backend_id.get(instance_id)
    if connected_id is not None:
      await disconnect_backend(connected_id)
    return

  try:
    channel = data.get("channel")
    address = data.get("address")
    pid = data.get("pid")
    status = _analysis_status(in_progress, data)
    if pid and not is_process_running(pid):
      logging.info("Cleaning up stale registry file: %s", registry_file)
      if _global_instance_id_to_backend_id.get(instance_id) == backend_id:
        await disconnect_backend(backend_id)
      _cleanup_stale_registry_file(registry_file, data)
      return

    async with _global_client_state[backend_id].condition:
      if _is_connected_to_instance(backend_id, instance_id):
        logging.info(
            "[Gateway] Already connected to backend %s (instance %s)",
            backend_id,
            instance_id,
        )
        _update_analysis_status(backend_id, status)
        return
    current = _global_clients.get(backend_id)
    if current is not None:
      # Another instance of this database is connected. Records are named
      # after the instance, so nothing says that this one is the newer: it
      # may be a leftover of an earlier instance. Only a later start, or the
      # death of the connected instance, replaces the connection.
      current_pid = _global_metadata.get(backend_id, {}).get("pid")
      if (
          not current.is_closed
          and (not current_pid or is_process_running(current_pid))
          and started_at <= _global_started_at.get(backend_id, 0.0)
      ):
        logging.warning(
            "[Gateway] Ignoring %s: a newer instance of %s is connected",
            registry_file,
            backend_id,
        )
        return
      await disconnect_backend(backend_id)

    metadata = data.get("metadata", {})
    # Ensure database_id is present in the metadata
    metadata["database_id"] = backend_id
    metadata["pid"] = pid
    metadata["auto_analysis_status"] = status

    if address is None:
      raise ValueError("the record has no address")
    client = RPCClient()
    async with _global_client_state[backend_id].condition:
      # Another connect_to_backend for this instance may have finished while
      # we were waiting for the lock.
      if _is_connected_to_instance(backend_id, instance_id):
        logging.info(
            "[Gateway] Backend %s (instance %s) was connected concurrently",
            backend_id,
            instance_id,
        )
        _update_analysis_status(backend_id, status)
        return
      # Retry connection logic
      for i in range(3):
        try:
          if channel == "tcp":
            logging.info(
                "[Gateway] Connecting to backend %s via TCP 127.0.0.1:%s"
                " (attempt %d)",
                backend_id,
                address,
                i + 1,
            )
            await client.connect_tcp("127.0.0.1", int(address))
          elif channel == "uds":
            logging.info(
                "[Gateway] Connecting to backend %s via UDS %s (attempt %d)",
                backend_id,
                address,
                i + 1,
            )
            await client.connect_uds(address)
          else:
            logging.error(
                "[Gateway] Unknown channel %s for %s", channel, backend_id
            )
            return
          break
        except Exception as e:  # pylint: disable=broad-exception-caught
          if i == 2:
            raise e
          await asyncio.sleep(0.5)

      # Reset the closed state for new connections under the same ID
      replaced = _global_backend_id_to_instance_id.get(backend_id)
      if replaced is not None:
        # A disconnect of the previous instance is still waiting for its
        # calls: see "reopened during wait" in disconnect_backend.
        _global_instance_id_to_backend_id.pop(replaced, None)
      _global_clients[backend_id] = client
      _global_metadata[backend_id] = metadata  # type: ignore
      _global_backend_id_to_instance_id[backend_id] = instance_id
      _global_instance_id_to_backend_id[instance_id] = backend_id
      _global_started_at[backend_id] = started_at
      _global_client_state[backend_id].is_closed = False
      _global_client_state[backend_id].is_broken = False
      logging.info("[Gateway] Successfully connected to backend %s", backend_id)

  except Exception as e:  # pylint: disable=broad-exception-caught
    logging.error(
        "[Gateway] Failed to connect to backend %s: %s", backend_id, e
    )

    async with _global_client_state[backend_id].condition:
      await _headless_manager.unregister(backend_id, instance_id)
      _cleanup_stale_registry_file(registry_file, data)
  finally:
    if _backend_events.get(backend_id) is not None:
      _backend_events.get(backend_id).set()  # type: ignore


async def _on_record_deleted(registry_file: pathlib.Path) -> None:
  """Disconnects the instance whose registry record was deleted."""
  instance_id, in_progress = registry.parse_record_name(registry_file.name)
  if in_progress:
    # An in-progress record also goes away when the analysis ends: it was
    # renamed, not removed, if the instance's plain record exists.
    plain_record = registry_file.with_name(
        registry.record_name(instance_id, False)
    )
    if plain_record.exists():
      return
  # A record of an instance we are not connected to, e.g., one that was
  # replaced by a newer instance of the same database, changes nothing.
  backend_id = _global_instance_id_to_backend_id.get(instance_id)
  if backend_id is not None:
    await disconnect_backend(backend_id)


async def disconnect_backend(backend_id: str, unregister: bool = True) -> None:
  """Disconnect from a backend."""
  logging.info(
      "[Gateway] disconnect_backend started for %s, unregister=%s",
      backend_id,
      unregister,
  )
  client = None
  info: Mapping[str, Any] = {}
  instance_id: str | None = None
  with contextlib.suppress(Exception):
    async with _global_client_state[backend_id].condition:
      if _global_client_state[backend_id].is_closed:
        logging.info(
            "[Gateway] disconnect_backend: database %s is already closed",
            backend_id,
        )
        return
      _global_client_state[backend_id].is_closed = True
      # Whether the connected instance is the one spawned for this database,
      # rather than, e.g., an earlier one that a newly spawned one replaces.
      owned = _headless_manager.owns(
          backend_id, _global_backend_id_to_instance_id.get(backend_id)
      )
      if unregister and owned:
        _headless_manager.spawned_instances.discard(backend_id)
      if _global_client_state[backend_id].number_of_ongoing_calls:
        logging.info(
            "[Gateway] disconnect_backend: waiting for %d ongoing calls to"
            " finish for %s",
            _global_client_state[backend_id].number_of_ongoing_calls,
            backend_id,
        )
        await _global_client_state[backend_id].condition.wait()
        logging.info(
            "[Gateway] disconnect_backend: finished waiting for %s", backend_id
        )
        if not _global_client_state[backend_id].is_closed:
          # the database has been reopened.
          logging.info(
              "[Gateway] disconnect_backend: database %s was reopened during"
              " wait",
              backend_id,
          )
          return
      client = _global_clients.pop(backend_id, None)
      info = _global_metadata.pop(backend_id, None) or {}
      instance_id = _global_backend_id_to_instance_id.pop(backend_id, None)
      if instance_id is not None:
        _global_instance_id_to_backend_id.pop(instance_id, None)
      _global_started_at.pop(backend_id, None)
      if (event := _analysis_events.get(backend_id)) is not None:
        event.set()
    try:
      if client:
        # If it is a live headless instance opened by us and still connected,
        # request graceful shutdown first
        spawned_pid = _global_database_id_to_pid.get(backend_id)
        if (
            owned
            and spawned_pid is not None
            and is_process_running(spawned_pid)
            and not client.is_closed
        ):
          try:
            logging.info(
                "[Gateway] Requesting graceful database close for %s",
                backend_id,
            )
            await asyncio.wait_for(
                client.call(method="close_database", params={}),
                timeout=5.0,
            )
          except Exception as e:
            logging.exception(
                "[Gateway] Failed to request close_database for %s: %s",
                backend_id,
                e,
            )

        logging.info("[Gateway] Closing RPC client for %s", backend_id)
        await client.close()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception(
          "[Gateway] Error disconnecting from backend %s: %s", backend_id, e
      )
    finally:
      if unregister and _global_client_state[backend_id].is_closed:
        logging.info("[Gateway] Calling unregister for %s", backend_id)
        await _headless_manager.unregister(backend_id, instance_id)
      # An instance that crashed or was killed left its record and socket
      # behind. They are named after the instance, so no later instance
      # overwrites them.
      record_pid = info.get("pid")
      if record_pid and not is_process_running(record_pid):
        _cleanup_stale_instance(instance_id)


# --- The Watchdog Handler ---


def _event_path(path: str | bytes) -> pathlib.Path:
  """Returns a watchdog event's path as a Path."""
  return pathlib.Path(os.fsdecode(path))


class RegistryEventHandler(FileSystemEventHandler):
  """Handles registry file system events.

  A backend registers and promotes its record with a rename and removes it
  with an unlink, so only moved and deleted events matter, and only those
  whose file is named like a record (see shared.registry): the directory also
  sees the temporary file a record is written to before it is renamed.
  Created events are not handled: a record never appears under its name
  before it is complete.
  """

  def __init__(self, loop):
    super().__init__()
    self.loop = loop

  def on_moved(self, event: DirMovedEvent | FileMovedEvent) -> None:
    if event.is_directory:
      return

    logging.debug("on_moved: %s -> %s", event.src_path, event.dest_path)
    # The destination names the record. The source is the temporary file of
    # a registration, or the in-progress name of a promotion.
    path = _event_path(event.dest_path)
    if registry.is_record_name(path.name) and path.is_file():
      asyncio.run_coroutine_threadsafe(connect_to_backend(path), self.loop)

  def on_deleted(self, event: DirDeletedEvent | FileDeletedEvent):
    if event.is_directory:
      return

    logging.debug("on_deleted: %s", event.src_path)
    path = _event_path(event.src_path)
    if registry.is_record_name(path.name):
      asyncio.run_coroutine_threadsafe(_on_record_deleted(path), self.loop)


async def forward_to(target: str, tool_name: str, args: dict[str, Any]) -> Any:
  """Forwards a tool call to the running backend server."""
  trace = TRACE
  if trace is None:
    return await _forward_to_backend(target, tool_name, args)

  call_id = trace.new_call_id()
  start = time.monotonic()
  fields = {
      "call_id": call_id,
      "tool": tool_name,
      "database_id": target,
      "args": {k: v for k, v in args.items() if k != "database_id"},
  }
  try:
    result = await _forward_to_backend(target, tool_name, args)
  except asyncio.CancelledError:
    trace.emit(
        "tool_call",
        **fields,
        duration_ms=round((time.monotonic() - start) * 1000, 1),
        outcome="cancelled",
    )
    raise
  except Exception as e:
    trace.emit(
        "tool_call",
        **fields,
        duration_ms=round((time.monotonic() - start) * 1000, 1),
        outcome="error",
        error=str(e),
    )
    raise
  trace.emit(
      "tool_call",
      **fields,
      duration_ms=round((time.monotonic() - start) * 1000, 1),
      outcome="ok",
  )
  return result


async def _forward_to_backend(
    target: str, tool_name: str, args: dict[str, Any]
) -> Any:
  """Sends a tool call to the backend over RPC and maps errors to ToolError."""
  logging.info(
      "[Gateway] forward_to started for target=%s, tool=%s", target, tool_name
  )
  async with _global_client_state[target].condition:
    if _global_client_state[target].is_closed:
      logging.info("[Gateway] forward_to: database %s is closed", target)
      raise ToolError("Error: Backend database has been closed")

    if _global_client_state[target].is_broken:
      logging.info("[Gateway] forward_to: connection to %s is broken", target)
      raise ToolError(
          f"Error: the connection to backend database {target} is broken, you"
          " may have to close and reopen the database."
      )
    _global_client_state[target].number_of_ongoing_calls += 1
  try:
    client = _global_clients.get(target)
    if client is None:
      logging.info("[Gateway] forward_to: client for %s not found", target)
      raise ToolError(f"Error: Backend database {target} not found")

    call_arguments = {k: v for k, v in args.items() if k != "database_id"}

    try:
      logging.info(
          "[Gateway] Sending RPC call to backend %s: %s", target, tool_name
      )
      result = await client.call(method=tool_name, params=call_arguments)
      logging.info(
          "[Gateway] RPC call to backend %s: %s succeeded", target, tool_name
      )
      return result
    except RPCError as e:
      logging.info("[Gateway] RPCError in forward_to for %s: %s", target, e)
      if "Connection is closed" in str(e) or "Connection closed" in str(e):
        logging.error(
            "[Gateway] Detected broken connection for %s: %s", target, e
        )
        _global_client_state[target].is_broken = True
        raise ToolError(
            f"Connection to backend {target} was lost. You may have to close"
            " the database and reopen it to continue."
        ) from e
      if e.data == -32001:
        raise ToolError(str(e)) from e
      raise ToolError(f"Backend tool error: {e}") from e
    except asyncio.CancelledError as e:
      logging.info(
          "[Gateway] CancelledError in forward_to for %s: %s (re-raising)",
          target,
          e,
      )
      raise
    except Exception as e:
      logging.info("[Gateway] Exception in forward_to for %s: %s", target, e)
      raise ToolError(f"Tool call failed with error {repr(e)}") from e
  finally:
    async with _global_client_state[target].condition:
      _global_client_state[target].number_of_ongoing_calls -= 1
      logging.info(
          "[Gateway] forward_to finally for %s, ongoing_calls=%d",
          target,
          _global_client_state[target].number_of_ongoing_calls,
      )
      if _global_client_state[target].number_of_ongoing_calls == 0:
        _global_client_state[target].condition.notify_all()


def shutdown_clients() -> None:
  logging.info("[Gateway] shutdown_clients triggered")
  if hasattr(signal, "SIGTERM"):
    with contextlib.suppress(Exception):
      signal.signal(signal.SIGTERM, signal.SIG_IGN)
  if not _global_clients:
    logging.info("[Gateway] shutdown_clients: no active clients to disconnect")
    return
  # Check if the loop is still running; if not, create a temporary one
  try:
    loop = asyncio.get_event_loop()
    if loop.is_running():
      logging.info("[Gateway] shutdown_clients: loop is running, creating task")
      # This is tricky if the loop is already busy shutting down
      loop.create_task(cleanup_logic())
    else:
      logging.info(
          "[Gateway] shutdown_clients: loop is not running, run_until_complete"
      )
      loop.run_until_complete(cleanup_logic())
  except RuntimeError:
    logging.info("[Gateway] shutdown_clients: no event loop, asyncio.run")
    asyncio.run(cleanup_logic())


async def cleanup_logic():
  logging.info("[Gateway] cleanup_logic started")
  # Your original logic wrapped in a task
  for name in list(_global_clients):
    await disconnect_backend(name)
  if _background_tasks:
    await asyncio.gather(*_background_tasks, return_exceptions=True)


original_handlers = {}


# Setup signal handlers for clean exit
def _signal_handler(sig, frame):
  shutdown_clients()
  handler = original_handlers.get(sig, None)
  if handler is not None and callable(handler):
    return handler(sig, frame)
  else:
    exit(0)


for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
  if (sig_id := getattr(signal, sig_name, None)) is not None:
    try:
      original_handlers[sig_id] = signal.signal(sig_id, _signal_handler)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception(
          "Could not register handler for signal %s: %s", sig_id, e
      )


# --- Lifecycle & Entry Point ---
@contextlib.asynccontextmanager
async def lifespan(app):
  """Manage gateway lifespan."""
  del app
  global _watcher_active, _observer
  REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
  observer = None
  try:
    loop = asyncio.get_running_loop()
    try:
      observer = Observer()
      logging.info("observing: %s", REGISTRY_DIR)
      observer.schedule(
          RegistryEventHandler(loop), str(REGISTRY_DIR), recursive=False
      )
      observer.start()
      _watcher_active = True
      _observer = observer
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.warning(
          "Failed to start filesystem watcher for %s: %s", REGISTRY_DIR, e
      )
      observer = None
      _observer = None
      _watcher_active = False

    atexit.register(shutdown_clients)
    # Initial Scan
    for registry_file in registry.list_records(REGISTRY_DIR):
      _ = asyncio.create_task(connect_to_backend(registry_file))

    yield

    if observer is not None:
      logging.info("stopping observer")
      with contextlib.suppress(Exception):
        observer.stop()
        observer.join()
  finally:
    _observer = None
    _watcher_active = False
    # Disconnect all clients
    await cleanup_logic()


def _tool_mode() -> str:
  return str(CONFIG.get("tool_mode", "hybrid")).lower().strip()


# Appended to search_tools results, where the agent is choosing a tool,
# because agents don't always read the server instructions.
_SEARCH_RESULTS_NOTE = (
    "Note: prefer `sql_query` for lookups (it runs concurrently) and one"
    " `idapython_eval` script to batch main-thread edits. Read this server's"
    " instructions first if you haven't."
)


def _schema_label(schema: Any) -> str:
  """Returns a short label for the type that a JSON schema describes."""
  if not isinstance(schema, dict):
    return "any"
  if "enum" in schema:
    return " | ".join(json.dumps(value) for value in schema["enum"])
  if "$ref" in schema:
    return schema["$ref"].rsplit("/", 1)[-1]
  for key in ("anyOf", "oneOf"):
    if key in schema:
      return " | ".join(_schema_label(branch) for branch in schema[key])
  if schema.get("type") == "array":
    return f"{_schema_label(schema.get('items'))}[]"
  return schema.get("type") or "any"


def _referenced_definition(schema: Any) -> tuple[str, bool] | None:
  """Finds the `$defs` entry that a parameter's schema refers to.

  Args:
    schema: the JSON schema of one parameter.

  Returns:
    The name of the entry and whether the parameter is a list of such
    objects, or None if the schema refers to no entry.
  """
  if not isinstance(schema, dict):
    return None
  if "$ref" in schema:
    return schema["$ref"].rsplit("/", 1)[-1], False
  if schema.get("type") == "array":
    found = _referenced_definition(schema.get("items"))
    return (found[0], True) if found else None
  for key in ("anyOf", "oneOf"):
    for branch in schema.get(key, ()):
      if found := _referenced_definition(branch):
        return found
  return None


def _object_fields_sections(tool: Tool) -> list[str]:
  """Lists the fields of the objects that the tool's parameters take.

  fastmcp's Markdown shows such a parameter as `object` or `object[]`, which
  doesn't tell the caller what to put into the object.
  """
  parameters = tool.parameters
  if not isinstance(parameters, dict):
    return []
  definitions = parameters.get("$defs") or {}
  lines = []
  for name, schema in (parameters.get("properties") or {}).items():
    found = _referenced_definition(schema)
    if found is None or found[0] not in definitions:
      continue
    definition = definitions[found[0]]
    required = set(definition.get("required") or ())
    if lines:
      lines.append("")
    if found[1]:
      lines.append(f"**Fields of each `{name}` item**")
    else:
      lines.append(f"**Fields of `{name}`**")
    for field, field_schema in (definition.get("properties") or {}).items():
      label = _schema_label(field_schema)
      if field in required:
        label += ", required"
      elif isinstance(field_schema, dict) and "default" in field_schema:
        label += f", default {json.dumps(field_schema['default'])}"
      line = f"- `{field}` ({label})"
      if isinstance(field_schema, dict) and field_schema.get("description"):
        line += f": {field_schema['description']}"
      lines.append(line)
  return lines


def _serialize_search_results(tools: Sequence[Tool]) -> str:
  """Serializes search_tools results to Markdown and appends the note."""
  if tools:
    blocks = []
    for tool in tools:
      block = serialize_tools_for_output_markdown([tool])
      if fields := _object_fields_sections(tool):
        block = "\n".join([block, "", *fields])
      blocks.append(block)
    markdown = "\n\n".join(blocks)
  else:
    markdown = serialize_tools_for_output_markdown(tools)
  return f"{markdown}\n\n{_SEARCH_RESULTS_NOTE}"


def _build_mcp_transforms() -> list[Any]:
  mode = _tool_mode()
  if mode == "hybrid":
    from shared.config import _DEFAULT_ALWAYS_VISIBLE_TOOLS  # pylint: disable=g-import-not-at-top

    always_visible = CONFIG.get(
        "always_visible_tools", _DEFAULT_ALWAYS_VISIBLE_TOOLS
    )
    return [
        BM25SearchTransform(
            max_results=6,
            always_visible=always_visible,
            search_result_serializer=_serialize_search_results,
        )
    ]
  elif mode == "code_mode":
    from fastmcp.experimental.transforms.code_mode import CodeMode  # pylint: disable=g-import-not-at-top

    return [CodeMode()]
  return []


# Server instructions: the first paragraph depends on tool_mode (see
# _build_mcp_instructions), the rest is shared.
_HYBRID_INSTRUCTIONS_INTRO = """\
This server exposes many tools; some are visible by default, the rest can be
found with `search_tools`. An existing tool is not always the best choice:
use your own judgment whether to call a tool or to run code through
`idapython_eval`. The goal is to complete the task efficiently.
"""

_FULL_INSTRUCTIONS_INTRO = """\
This server exposes many tools. An existing tool is not always the best choice:
use your own judgment whether to call a tool or to run code through
`idapython_eval`. The goal is to complete the task efficiently.
"""

_INSTRUCTIONS_BODY = """\
Two facts should guide that judgment. `idapython_eval` (and most other tools)
run on IDA's main thread, one at a time, blocking the GUI and every other
caller until they return -- so make each script count: gather everything you
need in one, or apply all your renames and comments in one, rather than many
small calls. `sql_query` runs off the main thread against an indexed SQLite
mirror and serves requests concurrently, so for relational analysis
(functions, strings, xrefs, callers/callees, imports, counts) it is almost
always the better option, and never the wrong one to try first.

In `idapython_eval`, `ida_domain` is pre-imported alongside the classic
`ida_*`/`idc`/`idautils` modules; assume it is available and prefer its
object API (`db = ida_domain.Database()`, then `db.functions`, `db.xrefs`,
`db.names`, ...). It is not guaranteed to exist: the name is None when the
package is not installed, and methods differ between versions. If it is None
or a call fails, fall back to the classic modules rather than retrying.
"""


def _build_mcp_instructions() -> str | None:
  """Returns the server instructions for the configured tool_mode.

  None for code_mode, whose clients see only CodeMode's search, get_schema
  and execute tools rather than the tools that the instructions refer to.
  """
  mode = _tool_mode()
  if mode == "hybrid":
    return f"{_HYBRID_INSTRUCTIONS_INTRO}\n{_INSTRUCTIONS_BODY}"
  if mode == "code_mode":
    return None
  return f"{_FULL_INSTRUCTIONS_INTRO}\n{_INSTRUCTIONS_BODY}"


# The response limit comes from the max_tool_response_bytes option (8 MiB by
# default; 0 for no limit). The backend limits idapython_eval's stdout,
# stderr, and result to max_eval_output_bytes each (1 MiB by default), so a
# response from a call within those limits must always fit: 8 MiB leaves room
# for JSON escaping, which can double or treble escape-heavy text. The limit
# is a safety net for responses nothing else bounds, such as an unbounded
# SELECT. Requests are not limited: whatever a client can send, the backend
# can take.
_RESPONSE_LIMIT_OPTION = "max_tool_response_bytes"


def _content_size(content: Sequence[Any], limit: int) -> int:
  """Returns the size of a tool result's content blocks, in characters.

  Stops counting once the total passes `limit`. FastMCP serializes a tool's
  return value into the text block itself, so measuring the blocks covers
  structured results too, with no extra serialization.
  """
  total = 0
  for block in content:
    text = getattr(block, "text", None)
    data = getattr(block, "data", None)
    resource = getattr(block, "resource", None)
    if isinstance(text, str):
      total += len(text)
    elif isinstance(data, (str, bytes)):
      total += len(data)
    elif resource is not None:
      resource_text = getattr(resource, "text", None)
      resource_blob = getattr(resource, "blob", None)
      if isinstance(resource_text, str):
        total += len(resource_text)
      elif isinstance(resource_blob, (str, bytes)):
        total += len(resource_blob)
    else:
      total += 64
    if total > limit:
      break
  return total


def _format_size(num_bytes: int) -> str:
  """Formats a byte count for an error message, e.g. "8 MiB" or "1.5 KiB"."""
  for unit, size in (("MiB", 1 << 20), ("KiB", 1 << 10)):
    if num_bytes >= size:
      return f"{num_bytes / size:.3g} {unit}"
  return f"{num_bytes} bytes"


class ResponseSizeLimitMiddleware(Middleware):
  """Replaces tool responses above a size limit with an error.

  Clients hold a tool result in the model's context, so an oversized one is
  useless there and may break the client. The error tells the model how to
  ask for less instead.
  """

  def __init__(self, limit: int):
    """Initializes the middleware.

    Args:
      limit: The largest response passed on, in characters of content.
    """
    super().__init__()
    self.limit = limit

  async def on_call_tool(
      self,
      context: MiddlewareContext[CallToolRequestParams],
      call_next: CallNext[CallToolRequestParams, ToolResult],
  ) -> ToolResult:
    result = await call_next(context)
    size = _content_size(result.content or (), self.limit)
    if size <= self.limit:
      return result
    error_msg = (
        f"Error: Tool '{context.message.name}' response payload size"
        f" (at least {_format_size(size)}) exceeded the"
        f" {_format_size(self.limit)} limit (max_tool_response_bytes). Please"
        " narrow your query, paginate with LIMIT/OFFSET, or write output to a"
        " file."
    )
    return ToolResult(
        content=[TextContent(type="text", text=error_msg)],
        is_error=True,
    )


mcp_server = FastMCP(
    "IDA Dynamic Proxy Gateway",
    instructions=_build_mcp_instructions(),
    lifespan=lifespan,
    transforms=_build_mcp_transforms(),
)
# The option can't change while the gateway runs, so read it once, and with
# no limit (0) don't install the middleware at all.
_response_limit = CONFIG[_RESPONSE_LIMIT_OPTION]
if _response_limit:
  mcp_server.add_middleware(ResponseSizeLimitMiddleware(_response_limit))


def mcp_tool(func=None, *args, **kwargs):
  """Decorator to add a tool to the MCP server if it's not disabled."""

  def decorator(f):
    disabled_tools = CONFIG.get("disabled_tools", [])
    for pattern in disabled_tools:
      if re.search(pattern, f.__name__, re.IGNORECASE):
        logging.info("Skipping disabled tool: %s", f.__name__)
        return f
    return mcp_server.tool(*args, **kwargs)(f)

  if func is not None and callable(func):
    return decorator(func)
  return decorator


async def _connect_unconnected_backends() -> None:
  """Scan registry directory for unconnected backends and connect to them."""
  try:
    if not REGISTRY_DIR.exists():
      return
    async with _connect_lock:
      tasks = []
      for registry_file in registry.list_records(REGISTRY_DIR):
        instance_id, _ = registry.parse_record_name(registry_file.name)
        backend_id = _global_instance_id_to_backend_id.get(instance_id)
        client = _global_clients.get(backend_id) if backend_id else None
        if client is None or client.is_closed:
          tasks.append(connect_to_backend(registry_file))
      if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logging.warning(
        "Failed to scan for new backends in %s: %s", REGISTRY_DIR, e
    )


@mcp_tool
async def list_available_databases() -> list[DatabaseInfo]:
  """List all available IDA database connection IDs.

  Active databases returned by this tool do not need to be opened again; they
  are ready to accept queries using their database_id, unless their
  auto_analysis_status is "in_progress": such a database rejects every tool
  until IDA's auto-analysis has finished, so check again later.
  """
  if not _is_watcher_active():
    await _connect_unconnected_backends()
  # Whether or not the watcher runs: an agent polls this tool for the end of
  # the analysis, so a missed rename event must not leave the status stale.
  for db_id, instance_id in list(_global_backend_id_to_instance_id.items()):
    info = _global_metadata.get(db_id)
    if info and info.get("auto_analysis_status") == "in_progress":
      await _connect_to_instance(instance_id)

  available = []
  stale_ids = []

  for db_id, client in list(_global_clients.items()):
    async with _global_client_state[db_id].condition:
      if _global_client_state[db_id].number_of_ongoing_calls:
        info = dict(_global_metadata[db_id])
        info["busy"] = True
        available.append(info)  # type: ignore
        continue

    try:
      # Lightweight check to ensure the backend is still responding
      ret = await asyncio.wait_for(client.ping(), timeout=2.0)
      if not ret:
        # Ping returned False (e.g. failed internally). Check PID.
        pid = (
            _global_metadata[db_id].get("pid")
            if db_id in _global_metadata
            else None
        )
        if pid and is_process_running(pid):
          info = dict(_global_metadata[db_id])
          info["busy"] = True
          available.append(info)  # type: ignore
        else:
          stale_ids.append(db_id)
      elif db_id in _global_metadata:
        info = dict(_global_metadata[db_id])
        # A backend that is still analysing answers the ping, but rejects
        # tool calls.
        info["busy"] = info.get("auto_analysis_status") == "in_progress"
        available.append(info)  # type: ignore
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Ping timed out or raised exception (could be GIL starved or dead)
      pid = (
          _global_metadata[db_id].get("pid")
          if db_id in _global_metadata
          else None
      )
      if pid and is_process_running(pid):
        logging.info(
            "Backend %s is busy (ping failed but process is running)", db_id
        )
        info = dict(_global_metadata[db_id])
        info["busy"] = True
        available.append(info)  # type: ignore
      else:
        logging.warning("Backend %s seems stale/dead: %s", db_id, e)
        stale_ids.append(db_id)

  # Clean up stale connections
  for db_id in stale_ids:
    instance_id = _global_backend_id_to_instance_id.get(db_id)
    await disconnect_backend(db_id)
    _cleanup_stale_instance(instance_id)
  if not available:
    raise ToolError(
        "It looks like there are currently no available IDA databases. If"
        " you've just closed them or haven't opened any yet, you might need to"
        " open your target binary in IDA first, or launch a headless instance"
        " if you want to operate without the UI."
    )
  return available


@mcp_server.resource(
    uri="ida://databases",
    description="Provides all the available IDA database info",
    mime_type="application/json",
)
async def available_databases() -> str:
  try:
    l = await list_available_databases()
  except ToolError as e:
    raise ResourceError(str(e))
  return json.dumps(l)


@mcp_tool
async def idalib_headless_open(
    path: Annotated[
        str,
        Field(
            validation_alias=AliasChoices(
                "path",
                "idb_path",
                "file_path",
                "input_path",
                "filepath",
                "file",
            ),
            description="Path to the target binary or database",
        ),
    ],
    processor: Annotated[
        str | None,
        "Optional IDA processor module (IDA's -p), e.g. 'metapc', 'arm',"
        " 'arm:ARMv7-M', 'mipsb'. Only for new binaries; needs IDA 9.1+",
    ] = None,
    loader: Annotated[
        str | None,
        "Optional file type name or prefix as IDA lists it (IDA's -T), e.g."
        " 'Binary file'. Only for new binaries; needs IDA 9.1+",
    ] = None,
    base_address: Annotated[
        AddressValue | None,
        "Optional 16-byte aligned load address (IDA's -b), e.g. '0x10000'."
        " Only for new binaries; needs IDA 9.1+",
    ] = None,
    disable_auto_analysis: Annotated[
        bool,
        "Skip IDA's auto-analysis, e.g., for a very large binary. The"
        " database then holds only what the loader created",
    ] = False,
) -> DatabaseInfo:
  """Open a binary in a new headless IDA instance.

  Returns once the file is loaded. IDA's auto-analysis may still be running
  then: check auto_analysis_status in the result. While it is "in_progress",
  every tool call for this database fails with "auto analysis is still in
  progress, please wait."; call list_available_databases later to see when it
  is "done". The database can be closed at any time.

  If the database is already open, this tool will raise an error containing
  the existing session ID. It is recommended to call list_available_databases
  first to check for active sessions, or use the existing ID returned in the
  error if you attempt to open an already-open database.

  processor/loader/base_address are for raw firmware or other files IDA can't
  identify on its own; leave them unset to let IDA pick.
  """
  try:
    options = load_options.parse_load_options(processor, loader, base_address)
  except load_options.LoadOptionsError as e:
    raise ToolError(str(e)) from e
  return await _headless_manager.spawn(path, options, disable_auto_analysis)


@mcp_tool
async def idalib_headless_close(
    database_id: Annotated[str, Field(validation_alias=DATABASE_ID_ALIASES)],
) -> None:
  """Close a headless IDA instance."""
  # Only close the database opened by us and not already closed.
  if (
      _global_database_id_to_pid.get(database_id, None) is not None
      and not _global_client_state[database_id].is_closed
  ):
    await _headless_manager.close(database_id)
