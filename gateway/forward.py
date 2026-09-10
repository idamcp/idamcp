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
from typing import Annotated, Any, Mapping, NotRequired

from fastmcp import FastMCP
from fastmcp.exceptions import ResourceError
from fastmcp.exceptions import ToolError
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from shared.config import load_config
from shared.rpc import RPCClient
from shared.rpc import RPCError
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


def _is_process_running(pid: int) -> bool:
  """Detect whether the process is still alive."""
  if sys.platform == "win32":
    with contextlib.suppress(Exception):
      import ctypes  # pylint: disable=g-import-not-at-top

      kernel32 = ctypes.windll.kernel32
      # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
      kernel32.OpenProcess.restype = ctypes.c_void_p
      handle = kernel32.OpenProcess(0x1000, False, pid)
      if handle:
        kernel32.CloseHandle(handle)
        return True
    return False
  else:
    try:
      os.kill(pid, 0)
      return True
    except OSError:
      return False


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


def _cleanup_stale_registry_by_id(
    database_id: str,
    data: Mapping[str, Any] | None = None,
) -> None:
  """Remove stale registry file by database ID and any associated UDS socket."""
  _cleanup_stale_registry_file(REGISTRY_DIR / f"{database_id}.json", data)


class DatabaseInfo(Metadata):
  """Information about a connected IDA database."""

  database_id: Annotated[str, "The unique ID of the target IDA database"]
  pid: Annotated[int, "Process ID of the IDA instance"]
  busy: NotRequired[
      Annotated[bool, "Whether the database is currently busy executing a tool"]
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
_global_database_id_to_pid: dict[str, int] = {}
_global_client_state: dict[str, ClientState] = collections.defaultdict(
    ClientState
)
_backend_events: dict[str, asyncio.Event] = collections.defaultdict(
    asyncio.Event
)
_background_tasks: set[asyncio.Task] = set()


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
    for _ in range(20):
      if not _is_process_running(pid):
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


class HeadlessManager:
  """Manages headless IDA instances."""

  def __init__(self, max_instances: int):
    self.max_instances = max_instances
    self.spawned_instances: set[str] = set()
    self._pending_spawns: int = 0

  def register(self, database_id: str, pid: int):
    """Register a new active headless instance."""
    self.spawned_instances.add(database_id)
    _global_database_id_to_pid[database_id] = pid

  async def unregister(self, database_id: str):
    """Unregister a headless instance."""
    logging.info("[HeadlessManager] unregister started for %s", database_id)
    self.spawned_instances.discard(database_id)
    pid = _global_database_id_to_pid.pop(database_id, None)
    if pid is not None and _is_process_running(pid):
      _create_background_task(_kill_process_gracefully(pid))

  async def close(self, database_id: str) -> None:
    """Close a specific headless instance gracefully."""
    self.spawned_instances.discard(database_id)
    await disconnect_backend(database_id)

  async def spawn(self, path: str) -> DatabaseInfo:
    """Spawn a headless instance."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
      raise ToolError(f"{path} doesn't exist.")

    for db_id, metadata in list(_global_metadata.items()):
      if (
          metadata.get("database_path") == path
          or metadata.get("filepath") == path
      ):
        pid = metadata.get("pid")
        if pid and _is_process_running(pid):
          raise ToolError(
              f"Database {path} is already connected (ID: {db_id}). DO NOT"
              " attempt to open it again; use the existing ID to access it"
              " directly.",
          )

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
      # Ensure pid matches what we spawned (for tracking)
      metadata["pid"] = process.pid
      async with _global_client_state[db_id].condition:
        self.register(db_id, process.pid)
    finally:
      self._pending_spawns -= 1
    try:
      await asyncio.wait_for(_backend_events[db_id].wait(), timeout=15.0)
    except asyncio.TimeoutError:
      async with _global_client_state[db_id].condition:
        await self.unregister(db_id)
      raise ToolError(
          "Backend process started, but registry event was never received"
          " (timeout)."
      )
    finally:
      if db_id in _backend_events:
        del _backend_events[db_id]
    if db_id not in _global_clients:
      async with _global_client_state[db_id].condition:
        await self.unregister(db_id)
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

    return metadata


_headless_manager = HeadlessManager(CONFIG.get("max_headless_instances", 4))


async def connect_to_backend(registry_file: pathlib.Path) -> None:
  """Connect to a backend."""
  backend_id = registry_file.stem
  logging.info("[Gateway] connect_to_backend triggered for %s", backend_id)
  if backend_id in _global_clients:
    await disconnect_backend(backend_id)

  data = None
  try:
    # Read registry file with retry logic (in case it's being written)
    with contextlib.suppress(Exception):
      if registry_file.exists():
        with open(registry_file, "r", encoding="utf-8") as f:
          content = f.read().strip()
          if content:
            data = json.loads(content)
    if not data:
      logging.error("[Gateway] Could not read registry file %s", registry_file)
      return

    channel = data.get("channel")
    address = data.get("address")
    pid = data.get("pid")
    if pid and not _is_process_running(pid):
      logging.info("Cleaning up stale registry file: %s", registry_file)
      _cleanup_stale_registry_file(registry_file, data)
      return

    metadata = data.get("metadata", {})
    # Ensure database_id is present in the metadata
    metadata["database_id"] = backend_id
    metadata["pid"] = pid

    client = RPCClient()
    async with _global_client_state[backend_id].condition:
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
      _global_clients[backend_id] = client
      _global_metadata[backend_id] = metadata  # type: ignore
      _global_client_state[backend_id].is_closed = False
      _global_client_state[backend_id].is_broken = False
      logging.info("[Gateway] Successfully connected to backend %s", backend_id)

  except Exception as e:  # pylint: disable=broad-exception-caught
    logging.error(
        "[Gateway] Failed to connect to backend %s: %s", backend_id, e
    )

    async with _global_client_state[backend_id].condition:
      await _headless_manager.unregister(backend_id)
      _cleanup_stale_registry_by_id(backend_id, data)
  finally:
    if _backend_events.get(backend_id) is not None:
      _backend_events.get(backend_id).set()  # type: ignore


async def disconnect_backend(backend_id: str, unregister: bool = True) -> None:
  """Disconnect from a backend."""
  logging.info(
      "[Gateway] disconnect_backend started for %s, unregister=%s",
      backend_id,
      unregister,
  )
  client = None
  with contextlib.suppress(Exception):
    async with _global_client_state[backend_id].condition:
      if _global_client_state[backend_id].is_closed:
        logging.info(
            "[Gateway] disconnect_backend: database %s is already closed",
            backend_id,
        )
        return
      _global_client_state[backend_id].is_closed = True
      if unregister:
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
      _global_metadata.pop(backend_id, None)
    try:
      if client:
        # If it is a headless instance opened by us, request graceful shutdown
        # first
        if _global_database_id_to_pid.get(backend_id) is not None:
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
        await _headless_manager.unregister(backend_id)


# --- The Watchdog Handler ---


class RegistryEventHandler(FileSystemEventHandler):
  """Handles registry file system events."""

  def __init__(self, loop):
    super().__init__()
    self.loop = loop

  def _handle_event_by_path(self, path: str) -> None:
    if path.endswith(".json") and os.path.isfile(path):
      asyncio.run_coroutine_threadsafe(
          connect_to_backend(pathlib.Path(path)), self.loop
      )

  def on_moved(self, event: DirMovedEvent | FileMovedEvent) -> None:
    if event.is_directory:
      return

    logging.debug("on_moved: %s -> %s", event.src_path, event.dest_path)
    if isinstance(event.dest_path, bytes):
      path = event.dest_path.decode()
    else:
      path = event.dest_path

    self._handle_event_by_path(path)

  def on_deleted(self, event: DirDeletedEvent | FileDeletedEvent):
    if event.is_directory:
      return

    if isinstance(event.src_path, bytes):
      src_path = event.src_path.decode()
    else:
      src_path = event.src_path
    logging.debug("on_deleted: %s", event.src_path)
    if src_path.endswith(".json"):
      asyncio.run_coroutine_threadsafe(
          disconnect_backend(pathlib.Path(src_path).stem), self.loop
      )


async def forward_to(target: str, tool_name: str, args: dict[str, Any]) -> Any:
  """Forwards a tool call to the running backend server."""
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
  REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
  try:
    loop = asyncio.get_running_loop()
    observer = Observer()
    logging.info("observing: %s", REGISTRY_DIR)
    observer.schedule(
        RegistryEventHandler(loop), str(REGISTRY_DIR), recursive=False
    )
    observer.start()

    atexit.register(shutdown_clients)
    # Initial Scan
    for registry_file in REGISTRY_DIR.glob("*.json"):
      _ = asyncio.create_task(connect_to_backend(registry_file))

    yield

    logging.info("stopping observer")
    observer.stop()
    observer.join()
  finally:
    # Disconnect all clients
    await cleanup_logic()


mcp_server = FastMCP("IDA Dynamic Proxy Gateway", lifespan=lifespan)


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


@mcp_tool
async def list_available_databases() -> list[DatabaseInfo]:
  """List all available IDA database connection IDs.

  Active databases returned by this tool do not need to be opened again; they
  are ready to accept queries using their database_id.
  """
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
        if pid and _is_process_running(pid):
          info = dict(_global_metadata[db_id])
          info["busy"] = True
          available.append(info)  # type: ignore
        else:
          stale_ids.append(db_id)
      elif db_id in _global_metadata:
        info = dict(_global_metadata[db_id])
        info["busy"] = False
        available.append(info)  # type: ignore
    except Exception as e:  # pylint: disable=broad-exception-caught
      # Ping timed out or raised exception (could be GIL starved or dead)
      pid = (
          _global_metadata[db_id].get("pid")
          if db_id in _global_metadata
          else None
      )
      if pid and _is_process_running(pid):
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
    metadata = _global_metadata.get(db_id)
    await disconnect_backend(db_id)
    _cleanup_stale_registry_by_id(db_id, metadata)
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
    path: Annotated[str, "Path to the target binary or database"],
) -> DatabaseInfo:
  """Open a binary in a new headless IDA instance.

  If the database is already open, this tool will raise an error containing
  the existing session ID. It is recommended to call list_available_databases
  first to check for active sessions, or use the existing ID returned in the
  error if you attempt to open an already-open database.
  """
  return await _headless_manager.spawn(path)


@mcp_tool
async def idalib_headless_close(database_id: str) -> None:
  """Close a headless IDA instance."""
  # Only close the database opened by us and not already closed.
  if (
      _global_database_id_to_pid.get(database_id, None) is not None
      and not _global_client_state[database_id].is_closed
  ):
    await _headless_manager.close(database_id)
