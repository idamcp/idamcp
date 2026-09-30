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

"""Generates a proxy for the IDA MCP."""

import ast
import bisect
import glob
import io
import os
import tokenize
from typing import Any, Dict, List, Optional


def extract_with_ast(
    file_path: str, decorator_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
  """Extracts function info using Python built-in AST and tokenize.

  Args:
      file_path: Path to the python file.
      decorator_filter: Optional decorator prefix to filter by.

  Returns:
      A list of dictionaries containing function details.
  """
  with open(file_path, 'r', encoding='utf-8') as f:
    source = f.read()

  tree = ast.parse(source)

  # Pre-collect all colon tokens for fast O(log N) lookup
  colon_ends = []
  for tok in tokenize.generate_tokens(io.StringIO(source).readline):
    if tok.type == tokenize.OP and tok.string == ':':
      colon_ends.append((tok.start, tok.end))

  results = []
  lines = source.splitlines(keepends=True)

  # Collect and sort function definitions in document order
  func_nodes = [
      node
      for node in ast.walk(tree)
      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
  ]
  func_nodes.sort(key=lambda n: (n.lineno, n.col_offset))

  for node in func_nodes:
    # Extract decorators and jsonrpc description
    decorators = []
    jsonrpc_description = ''
    for dec_node in node.decorator_list:
      dec_seg = ast.get_source_segment(source, dec_node)
      if dec_seg:
        dec_text = '@' + dec_seg.strip()
        decorators.append(dec_text)
        if dec_text.startswith('@jsonrpc'):
          jsonrpc_description = dec_text[8:]

    # Filter if needed
    if decorator_filter and not any(
        d.startswith(decorator_filter) for d in decorators
    ):
      continue

    name = node.name

    # Extract argument names
    arg_names = []
    for arg in getattr(node.args, 'posonlyargs', []):
      arg_names.append(arg.arg)
    for arg in node.args.args:
      arg_names.append(arg.arg)
    if node.args.vararg:
      arg_names.append(node.args.vararg.arg)
    for arg in node.args.kwonlyargs:
      arg_names.append(arg.arg)
    if node.args.kwarg:
      arg_names.append(node.args.kwarg.arg)

    # Extract prototype text: from function start (def / async def) to the ':' before body[0]
    func_start = (node.lineno, node.col_offset)
    body_start = (node.body[0].lineno, node.body[0].col_offset)

    idx = bisect.bisect_right(colon_ends, (body_start, (0, 0)))
    colon_end = None
    for i in range(idx - 1, -1, -1):
      c_start, c_end = colon_ends[i]
      if c_start >= func_start and c_end <= body_start:
        colon_end = c_end
        break
      if c_start < func_start:
        break

    if colon_end:
      end_line, end_col = colon_end
      start_line, start_col = func_start

      if start_line == end_line:
        proto_without_dec = lines[start_line - 1][start_col:end_col]
      else:
        proto_lines = [lines[start_line - 1][start_col:]]
        proto_lines.extend(lines[start_line : end_line - 1])
        proto_lines.append(lines[end_line - 1][:end_col])
        proto_without_dec = ''.join(proto_lines)
    else:
      proto_without_dec = ''

    # Docstring
    docstring = ast.get_docstring(node, clean=False)

    results.append({
        'name': name,
        'args': arg_names,
        'prototype_without_decorator': proto_without_dec,
        'decorators': decorators,
        'jsonrpc_description': jsonrpc_description,
        'docstring': docstring,
    })

  return results


FIRST_PART = """# Copyright (c) 2026 Google LLC
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

# WARNING: This file is generated, DO NOT edit it directly.
import argparse
import contextlib
from typing import Annotated, Any, Dict, List, Literal
from gateway.forward import forward_to, mcp_server, mcp_tool
from gateway.forward import warn_if_not_loopback
from shared.config import load_config
from shared.types import *

try:
  import gateway.patcher
  _ = gateway.patcher
except ImportError as e:
  print(
      f"[WARNING] Failed to load gateway.patcher: {e}. 'patch_assembly' tool"
      " will not be available."
  )

try:
  import gateway.query
  _ = gateway.query
except ImportError as e:
  print(
      f"[WARNING] Failed to load gateway.query: {e}. 'sql_query' tool will"
      " not be available."
  )
"""

LAST_PART = """
if __name__ == "__main__":
  config = load_config()
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "--transport", default="sse", choices=["sse", "stdio", "http"]
  )
  parser.add_argument(
      "--host", type=str, help="Host to listen on (for SSE/HTTP transport)"
  )
  parser.add_argument(
      "--port", type=int, help="Port to listen on (for SSE/HTTP transport)"
  )
  args = parser.parse_args()

  if args.transport in ["sse", "http"]:
    host = (
        args.host
        if args.host is not None
        else config.get("proxy_host", "localhost")
    )
    port = (
        args.port if args.port is not None else config.get("proxy_port", 8000)
    )
    warn_if_not_loopback(host, port)
    with contextlib.suppress(KeyboardInterrupt):
      mcp_server.run(transport=args.transport, host=host, port=port)
  else:
    with contextlib.suppress(KeyboardInterrupt):
      mcp_server.run(transport="stdio")
"""


def main():
  # 1. Parse Gateway Tools
  gateway_tools = set()
  for gateway_file in sorted(glob.glob("gateway/*.py")):
    if gateway_file.endswith(("proxy.py", "__init__.py")):
      continue
    print(f'Processing {gateway_file}...')
    gateway_items = extract_with_ast(gateway_file, decorator_filter='@mcp_tool')
    gateway_tools.update(item['name'] for item in gateway_items)
  print(f'Found gateway tools: {gateway_tools}')

  # 2. Parse Backend Tools
  tools_dir = "ida_mcp/tools"
  tool_files = glob.glob(os.path.join(tools_dir, "*.py"))
  tool_files.sort()
  results = []
  for tool_file in tool_files:
    if tool_file.endswith("__init__.py"):
      continue
    print(f"Processing {tool_file}...")
    # Extract @jsonrpc tools from backend
    results.extend(extract_with_ast(tool_file, decorator_filter='@jsonrpc'))
  # 3. Generate Proxy
  with open("gateway/proxy.py", "w") as f:
    f.write(FIRST_PART)
    for item in results:
      # Skip if defined in gateway
      if item["name"] in gateway_tools:
        print(
            f"Skipping proxy generation for {item['name']} (defined in gateway)"
        )
        continue

      # Skip tools marked as internal or skip_proxy
      if any(
          d.startswith(("@internal", "@skip_proxy")) for d in item["decorators"]
      ):
        print(
            f"Skipping proxy generation for {item['name']} (marked as internal)"
        )
        continue

      description_arg = ""
      if item["jsonrpc_description"]:
        description_arg = item["jsonrpc_description"]

      prototype_part1, prototype_part2 = item[
          "prototype_without_decorator"
      ].split("(", maxsplit=1)
      instance_str = (
          'database_id: Annotated[str, "The unique identifier for the target'
          " IDA database. You can obtain this ID by calling"
          " list_available_databases, reading the ida://databases resource, or"
          ' by opening a new database via idalib_headless_open."], '
      )

      prototype = prototype_part1 + "(" + instance_str + prototype_part2

      forward_call = (
          f"  return await forward_to(database_id, \"{item['name']}\","
          " locals())"
      )

      func_body = forward_call
      if item["docstring"]:
        ds = item["docstring"]
        # Handle triple quotes in docstring
        ds = ds.replace('"""', '\\"\\"\\"')
        func_body = f'  """{ds}"""\n{forward_call}'

      if not prototype.strip().startswith("async "):
        prototype = prototype.replace("def ", "async def ", 1)

      f.write(
          f"@mcp_tool{description_arg}\n"
          + prototype
          + "\n"
          + func_body
          + "\n\n"
      )

    f.write(LAST_PART)


if __name__ == "__main__":
  main()
