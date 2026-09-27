# Copyright (c) 2026 Google LLC
# Copyright (c) 2025 Duncan Ogilvie
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


"""Configuration and management for IDA Pro MCP tools."""

import logging
from typing import Any, Dict, List
from ida_mcp.core import ida_thread
from ida_mcp.core import lease
from ida_mcp.core.decorators import internal, jsonrpc
from ida_mcp.core.rpc_registry import rpc_registry
from ida_mcp.core.security import security_manager


@internal
@jsonrpc
def list_unsafe_tools() -> List[str]:
  """Returns a list of all unsafe tool names."""
  return sorted(list(rpc_registry.unsafe))


@internal
@jsonrpc
def configure_unsafe_tools(
    enable_all_unsafe_tools: bool,
    persistent: bool,
    enabled_unsafe_tools: List[str],
) -> str:
  """Configures which unsafe tools are allowed to run.

  Args:
      enable_all_unsafe_tools: If True, all unsafe tools are allowed.
      persistent: If True, saves the configuration to the IDA database.
      enabled_unsafe_tools: A list of unsafe tool names to allow if enable_all
        is False.
  """
  security_manager.update(enable_all_unsafe_tools, enabled_unsafe_tools)

  if persistent:
    security_manager.save_to_netnode()
    return "Security settings updated and saved to database."

  return "Security settings updated (session only)."


@internal
@jsonrpc
def get_security_config() -> Dict[str, Any]:
  """Returns the current security configuration."""
  return {
      "enable_all_unsafe_tools": security_manager.enable_all_unsafe_tools,
      "enabled_unsafe_tools": list(security_manager.enabled_unsafe_tools),
  }


@internal
@jsonrpc
def close_database() -> None:
  """Closes the current database gracefully and exits the headless instance."""
  logging.getLogger("ida_mcp.tools.config").info(
      "Received close_database RPC call. Stopping loop..."
  )
  ida_thread.stop()


@internal
@jsonrpc
async def lease_acquire() -> bool:
  """Gives the calling connection a lease on this headless instance.

  Only effective on headless instances with headless_lifetime "lease"; returns
  False elsewhere. The lease ends with lease_release or when the connection
  closes.
  """
  return lease.acquire_current()


@internal
@jsonrpc
async def lease_release() -> Dict[str, Any]:
  """Ends the calling connection's lease.

  Returns {"released": bool, "remaining": int}. When the last lease is
  released, the instance saves and exits right away.
  """
  return lease.release_current()
