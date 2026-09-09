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

import functools
import inspect
import json
import logging
import os
import pathlib
import sys
import tempfile

# Add project root to sys.path if needed to find gateway
root_dir = pathlib.Path(__file__).resolve().parent.parent
sys.path = [str(root_dir)] + [p for p in sys.path if p != str(root_dir)]

import asyncio
from shared.rpc import RPCServer
from ida_mcp.core.backend_registry import RegistryManager
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

from ida_mcp.utils import helper
from shared.config import load_config
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


def _print_metadata(metadata: Metadata, identifier: str) -> None:

  # Emit metadata for synchronous capture (e.g. by Gateway spawner)
  if metadata and metadata["is_headless"]:
    try:
      metadata_json = dict(metadata)
      metadata_json["database_id"] = identifier
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


def mcp_server_thread(identifier: str):
  """Start the MCP server thread."""
  config = load_config()
  security_manager.load_defaults(config)
  security_manager.load_from_netnode()
  registry = RegistryManager(config["registry_dir"])

  channel = config["communication_channel"]

  if config.get("populate_tables_on_startup"):
    try:
      import ida_mcp.tools.query

      ida_mcp.tools.query.init_tables()
    except (ImportError, AttributeError):
      pass

  if sys.platform == "win32" and channel != "tcp":
    print("[MCP] Windows detected, forcing usage of TCP instead of UDS.")
    channel = "tcp"

  # Fetch metadata to register with the service
  try:
    metadata = get_metadata.sync_call()
  except Exception as e:
    print(f"[MCP] Failed to fetch metadata for registration: {e}")
    return

  def create_wrapper(tool_func):
    @functools.wraps(tool_func)
    async def wrapper(*args, **kwargs):

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

  _print_metadata(metadata, identifier)

  async def main():
    server = RPCServer(methods)
    if channel == "tcp":
      srv = await server.start_tcp("127.0.0.1", 0)
      port = srv.sockets[0].getsockname()[1]
      registry.register("tcp", port, name=identifier, metadata=metadata)
    else:
      uds_dir = config["uds_dir"]
      socket_path = os.path.join(uds_dir, f"{identifier}.sock")
      if os.path.exists(socket_path):
        try:
          os.unlink(socket_path)
        except OSError:
          pass
      await server.start_uds(socket_path)
      registry.register("uds", socket_path, name=identifier, metadata=metadata)

    try:
      await asyncio.Event().wait()
    except asyncio.CancelledError:
      await server.close()

  loop = asyncio.new_event_loop()
  asyncio.set_event_loop(loop)
  try:
    loop.run_until_complete(main())
  finally:
    loop.close()
