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

"""Dumps the MCP metadata advertised by the gateway to a JSON file.

The output is what an MCP client sees after connecting to the gateway: the
initialize result and the tools, resources, resource templates and prompts
lists. test_mcp_metadata.py compares it with golden_mcp_metadata.json, so a
change to a tool name, description or schema shows up as a diff in review.

No IDA installation is needed. The gateway is imported with a throwaway config
(temporary registry and UDS directories, no user config file, no config
environment variables), so the output does not depend on the local setup.
Version strings that come from installed libraries are replaced with a
placeholder, and fields that depend on the installed FastMCP version rather
than on the gateway are left out, so the output is the same under FastMCP 3
and 4.

Regenerate the golden file after an intended change with:

  python3 tests/dump_mcp_metadata.py
"""

import argparse
import asyncio
import importlib
import inspect
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
_REPO_DIR = _TESTS_DIR.parent
GOLDEN_PATH = _TESTS_DIR / "golden_mcp_metadata.json"

# Optional imports of the generated gateway/proxy.py. When one fails, the proxy
# only prints a warning and its tools are missing, so fail loudly instead.
_OPTIONAL_GATEWAY_MODULES = ("gateway.patcher", "gateway.query")

_VERSION_PLACEHOLDER = "<version>"


def _isolate_config(tmp_dir: pathlib.Path) -> None:
  """Points the gateway at a config that only sets temporary directories."""
  from shared import config  # pylint: disable=g-import-not-at-top

  # load_config() lets env vars named after options (e.g. DISABLED_TOOLS)
  # override the config file.
  for option in config._DEFAULT_CONFIG:  # pylint: disable=protected-access
    os.environ.pop(option.upper(), None)
  os.environ.pop("IDAMCP_NO_USER_CONFIG", None)
  config_path = tmp_dir / "config.json"
  config_path.write_text(
      json.dumps(
          {
              "registry_dir": str(tmp_dir / "registry"),
              "uds_dir": str(tmp_dir / "uds"),
              "tool_mode": "full",
          }
      ),
      encoding="utf-8",
  )
  os.environ["IDAMCP_CONFIG"] = str(config_path)


def _dump_model(model: Any) -> dict[str, Any]:
  return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def _drop_version_dependent_fields(metadata: dict[str, Any]) -> None:
  """Removes what differs between FastMCP versions for the same gateway."""
  # FastMCP 3 declares empty experimental and extensions capabilities.
  capabilities = metadata["initialize"].get("capabilities", {})
  for key in ("experimental", "extensions"):
    capabilities.pop(key, None)
  # FastMCP 4 gives a tool without a title one derived from its name.
  for tool in metadata["tools"]:
    if tool.get("title") == tool["name"].replace("_", " ").title():
      del tool["title"]


async def _collect() -> dict[str, Any]:
  """Connects an in-memory MCP client to the gateway and lists its metadata."""
  # The gateway reads its config and registers tools at import time, so these
  # imports must run after _isolate_config().
  # pylint: disable=g-import-not-at-top
  import fastmcp
  import gateway.proxy  # pylint: disable=unused-import
  from gateway.forward import mcp_server

  # pylint: enable=g-import-not-at-top

  # FastMCP 4 negotiates a newer protocol era unless pinned to the classic
  # initialize handshake, which is all FastMCP 3 has.
  client_options = {}
  if "mode" in inspect.signature(fastmcp.Client.__init__).parameters:
    client_options["mode"] = "legacy"
  async with fastmcp.Client(mcp_server, **client_options) as client:
    initialize = _dump_model(client.initialize_result)
    tools = await client.list_tools()
    resources = await client.list_resources()
    templates = await client.list_resource_templates()
    prompts = await client.list_prompts()

  initialize["protocolVersion"] = _VERSION_PLACEHOLDER
  initialize["serverInfo"]["version"] = _VERSION_PLACEHOLDER
  metadata = {
      "initialize": initialize,
      "tools": sorted(map(_dump_model, tools), key=lambda t: t["name"]),
      "resources": sorted(map(_dump_model, resources), key=lambda r: r["uri"]),
      "resource_templates": sorted(
          map(_dump_model, templates), key=lambda r: r["uriTemplate"]
      ),
      "prompts": sorted(map(_dump_model, prompts), key=lambda p: p["name"]),
  }
  _drop_version_dependent_fields(metadata)
  return metadata


def dump(output_path: pathlib.Path) -> None:
  """Writes the gateway's MCP metadata to output_path as formatted JSON."""
  # Import this checkout's gateway, not one found through PYTHONPATH.
  sys.path.insert(0, str(_REPO_DIR))
  with tempfile.TemporaryDirectory(prefix="idamcp_metadata_") as tmp_dir:
    _isolate_config(pathlib.Path(tmp_dir))
    import_errors = {}
    for module_name in _OPTIONAL_GATEWAY_MODULES:
      try:
        importlib.import_module(module_name)
      except ImportError as e:
        import_errors[module_name] = str(e)
    if import_errors:
      sys.exit(
          "Optional gateway modules failed to import, so their tools would be"
          f" missing (install requirements.txt): {import_errors}"
      )
    metadata = asyncio.run(_collect())
  output_path.write_text(
      json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
      encoding="utf-8",
  )


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Dump the gateway's MCP metadata to a JSON file."
  )
  parser.add_argument(
      "output",
      nargs="?",
      type=pathlib.Path,
      default=GOLDEN_PATH,
      help="Output path (default: tests/golden_mcp_metadata.json)",
  )
  dump(parser.parse_args().output)


if __name__ == "__main__":
  main()
