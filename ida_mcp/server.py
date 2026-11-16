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

"""MCP Server implementation."""

import contextlib
import functools
import inspect
import json
import logging
import os
import pathlib
import sys
import tempfile
import threading
import time

# Add project root to sys.path if needed to find gateway
root_dir = pathlib.Path(__file__).resolve().parent.parent
sys.path = [str(root_dir)] + [p for p in sys.path if p != str(root_dir)]

import asyncio
import idaapi
from shared.rpc import DEFAULT_SHUTDOWN_GRACE
from shared.rpc import RPCServer
from ida_mcp.core import analysis_state
from ida_mcp.core import ida_thread
from ida_mcp.core.backend_registry import RegistryManager
from ida_mcp.core.decorators import cancellation_token_var
from ida_mcp.core.rpc_registry import rpc_registry
from ida_mcp.core.security import security_manager
from shared.rpc import ToolError
import ida_mcp.tools.analysis
import ida_mcp.tools.config
import ida_mcp.tools.debug
import ida_mcp.tools.edit
import ida_mcp.tools.execution
import ida_mcp.tools.export
import ida_mcp.tools.info
from ida_mcp.tools.info import get_metadata
import ida_mcp.tools.memory
import ida_mcp.tools.query
import ida_mcp.tools.types

from shared.config import load_config
from shared.registry import new_instance_id
from shared.types import Metadata

# Ensure they are marked as used (for side effects)
_ = ida_mcp.tools.analysis
_ = ida_mcp.tools.debug
_ = ida_mcp.tools.edit
_ = ida_mcp.tools.execution
_ = ida_mcp.tools.export
_ = ida_mcp.tools.info
_ = ida_mcp.tools.memory
_ = ida_mcp.tools.types
_ = ida_mcp.tools.config
_ = ida_mcp.tools.query


class Unbuffered:

  def __init__(self, stream):
    self.stream = stream

  def write(self, data):
    self.stream.write(data)
    self.stream.flush()

  def writelines(self, datas):
    self.stream.writelines(datas)
    self.stream.flush()

  def __getattr__(self, attr):
    return getattr(self.stream, attr)


logger = logging.getLogger(__name__)

# Size of sockaddr_un.sun_path, the limit of a Unix socket path including its
# terminating NUL: 104 bytes on macOS, 108 on Linux.
_SUN_PATH_SIZE = 104 if sys.platform == "darwin" else 108

_running_servers: dict[str, tuple[asyncio.AbstractEventLoop, asyncio.Event]] = (
    {}
)
_servers_lock = threading.Lock()


def stop_server(identifier: str | None = None) -> None:
  """Signals running MCP server(s) to shut down cleanly."""
  with _servers_lock:
    if identifier:
      entry = _running_servers.pop(identifier, None)
      targets = [entry] if entry else []
    else:
      targets = list(_running_servers.values())
      _running_servers.clear()

  for loop, stop_event in targets:
    if loop.is_running() and not stop_event.is_set():
      loop.call_soon_threadsafe(stop_event.set)


def _print_metadata(
    metadata: Metadata, identifier: str, instance_id: str
) -> None:

  # Emit metadata for synchronous capture (e.g. by Gateway spawner)
  if metadata and metadata["is_headless"]:
    try:
      metadata_json = dict(metadata)
      metadata_json["database_id"] = identifier
      # For the gateway, which finds this instance's record by it. It is not
      # part of the metadata: MCP clients only see the database ID.
      metadata_json["instance_id"] = instance_id
      print(f"[MCP_JSON] {json.dumps(metadata_json)}", flush=True)
    except Exception:
      pass

    # Redirect stdout and stderr to a log file if they are connected to a pipe
    # (not a TTY).  When the gateway spawns this process, it captures output
    # via subprocess.PIPE.  If these pipe buffers fill up because the parent
    # process is no longer reading from them, any further output will block,
    # causing the headless IDA instance to hang indefinitely.
    if not sys.stdout.isatty() or not sys.stderr.isatty():
      log_path = os.path.join(
          tempfile.gettempdir(), f"idamcp_backend_{identifier}.log"
      )
      log_file = open(log_path, "w", encoding="utf-8")
      sys.stderr.write(f"DEBUG: Redirecting backend output to {log_path}\n")
      sys.stdout.flush()
      sys.stderr.flush()

      # Redirect OS-level file descriptors to suppress C/C++ extension output
      # (e.g., IDA kernel)
      os.dup2(log_file.fileno(), sys.stdout.fileno())
      os.dup2(log_file.fileno(), sys.stderr.fileno())

      # Redirect Python-level stdout/stderr
      sys.stdout = Unbuffered(log_file)
      sys.stderr = Unbuffered(log_file)


def mcp_server_thread(
    identifier: str, shutdown_grace: float = DEFAULT_SHUTDOWN_GRACE
):
  """Start the MCP server thread.

  Args:
    identifier: The database ID: names the server in its registry record and
      in stop_server() calls.
    shutdown_grace: How long the server waits at shutdown, in seconds, for
      cancelled tool calls to finish before it cancels them again.
  """
  config = load_config()
  security_manager.load_defaults(config)
  security_manager.load_from_netnode()
  registry = RegistryManager(config["registry_dir"])
  # Names the registry record and the Unix socket, so that this server never
  # shares them with another process serving the same database.
  instance_id = new_instance_id()
  # Lets the gateway tell which of two instances of a database is the newer.
  started_at = time.time()

  channel = config["communication_channel"]

  socket_path = ""
  if channel != "tcp" and sys.platform != "win32":
    socket_path = os.path.join(config["uds_dir"], f"{instance_id}.sock")
    path_size = len(os.fsencode(socket_path))
    if path_size >= _SUN_PATH_SIZE:
      # Checked here, before a headless server prints its metadata and
      # redirects its output to a log file, so that the gateway can report
      # the reason; binding the socket later would only fail in that log.
      logger.error(
          "uds_dir is too long for a Unix socket: a socket in %s takes %d"
          " bytes, and the limit is %d. Set a shorter uds_dir in the"
          " configuration.",
          config["uds_dir"],
          path_size,
          _SUN_PATH_SIZE - 1,
      )
      return

  # While auto-analysis is running, ida_mcp.headless sets up the tables once
  # it has finished.
  if (
      config.get("populate_tables_on_startup")
      and not analysis_state.is_in_progress()
  ):
    # Under the headless loop's stop token, so that a shutdown request (e.g.,
    # SIGTERM) interrupts the table population instead of waiting for it.
    var_token = cancellation_token_var.set(
        ida_thread.stop_token
        if getattr(idaapi, "is_headless", False)
        else None
    )
    try:
      import ida_mcp.tools.query

      ida_mcp.tools.query.init_tables()
    except asyncio.CancelledError:
      logger.info("Query table setup interrupted: the server is stopping.")
      return
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.exception("Error initializing query tables: %s", e)
    finally:
      cancellation_token_var.reset(var_token)

  if sys.platform == "win32" and channel != "tcp":
    print("[MCP] Windows detected, forcing usage of TCP instead of UDS.")
    channel = "tcp"

  # Fetch metadata to register with the service
  try:
    metadata = Metadata(**get_metadata.sync_call())
  except Exception as e:
    print(f"[MCP] Failed to fetch metadata for registration: {e}")
    return
  metadata["auto_analysis_status"] = analysis_state.status()

  def create_wrapper(tool_func):
    allowed_during_analysis = getattr(
        tool_func, "allow_during_auto_analysis", False
    )

    @functools.wraps(tool_func)
    async def wrapper(*args, **kwargs):
      if analysis_state.is_in_progress() and not allowed_during_analysis:
        raise ToolError("auto analysis is still in progress, please wait.")
      if not security_manager.is_allowed(tool_func.__name__, tool_func.unsafe):
        raise ToolError(
            f"Tool '{tool_func.__name__}' is unsafe and not enabled."
        )
      result = tool_func(*args, **kwargs)
      if inspect.isawaitable(result):
        result = await result
      return result

    # Python 3.14 uses __annotate__ instead of __annotations__ in
    # WRAPPER_ASSIGNMENTS, so we must manually copy __annotations__ since it
    # might have been manually set.
    wrapper.__annotations__ = getattr(tool_func, "__annotations__", {})
    if hasattr(tool_func, "__signature__"):
      wrapper.__signature__ = tool_func.__signature__  # type: ignore

    return wrapper

  methods = {}
  for rpc_func in rpc_registry.methods:
    logger.debug("adding tool: %s: %s", rpc_func.__name__, rpc_func)
    methods[rpc_func.__name__] = create_wrapper(rpc_func)

  print(f"[MCP] Starting server channel={channel} identifier={identifier}")

  _print_metadata(metadata, identifier, instance_id)

  def register(channel: str, address: str | int) -> None:
    """Writes the registry record; its name tells whether analysis is done."""
    # The gateway derives the status from the record's name, so the record
    # itself doesn't carry it.
    record_metadata = {
        k: v for k, v in metadata.items() if k != "auto_analysis_status"
    }
    # Under the lock, so that the analysis can't finish between writing an
    # in-progress record and setting the function that renames it.
    with analysis_state.lock:
      registry.register(
          channel,
          address,
          database_id=identifier,
          instance_id=instance_id,
          started_at=started_at,
          metadata=record_metadata,
          in_progress=analysis_state.is_in_progress(),
          auto_analysis_disabled=(
              analysis_state.status() == analysis_state.DISABLED
          ),
      )
      analysis_state.set_on_done(registry.promote)

  async def main():
    server = None
    stop_event = asyncio.Event()

    with _servers_lock:
      _running_servers[identifier] = (loop, stop_event)

    try:
      server = RPCServer(methods, shutdown_grace=shutdown_grace)
      if channel == "tcp":
        srv = await server.start_tcp("127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        register("tcp", port)
      else:
        if os.path.exists(socket_path):
          with contextlib.suppress(OSError):
            os.unlink(socket_path)
        await server.start_uds(socket_path)
        register("uds", socket_path)

      await stop_event.wait()
    except asyncio.CancelledError:
      pass
    finally:
      with _servers_lock:
        _running_servers.pop(identifier, None)
      if server is not None:
        await server.close()
      with analysis_state.lock:
        analysis_state.set_on_done(None)
        registry.cleanup()
      if socket_path and os.path.exists(socket_path):
        with contextlib.suppress(OSError):
          os.unlink(socket_path)

  loop = asyncio.new_event_loop()
  asyncio.set_event_loop(loop)
  try:
    loop.run_until_complete(main())
  finally:
    loop.close()
