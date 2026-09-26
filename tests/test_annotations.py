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

"""Tests for gateway/annotations.py (MCP tool annotations)."""

import ast
import asyncio
import pathlib
import unittest

import fastmcp
from gateway import annotations
from gateway import forward

_REPO = pathlib.Path(__file__).resolve().parent.parent
_SETS = {
    "READ_ONLY": annotations.READ_ONLY,
    "LOCAL_CHANGE": annotations.LOCAL_CHANGE,
    "OPEN_WORLD": annotations.OPEN_WORLD,
}


def _decorator_names(func: ast.AST) -> set[str]:
  names = set()
  for dec in func.decorator_list:
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Name):
      names.add(node.id)
    elif isinstance(node, ast.Attribute):
      names.add(node.attr)
  return names


def _functions(path: pathlib.Path):
  tree = ast.parse(path.read_text(encoding="utf-8"))
  for node in tree.body:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
      yield node.name, _decorator_names(node)


def _gateway_tools() -> set[str]:
  """Every @mcp_tool function in the gateway, including the generated proxy."""
  tools = set()
  for path in sorted((_REPO / "gateway").glob("*.py")):
    tools |= {n for n, d in _functions(path) if "mcp_tool" in d}
  return tools


def _backend_decorators() -> dict[str, set[str]]:
  """Decorators of every @jsonrpc backend tool, by name."""
  result = {}
  for path in sorted((_REPO / "ida_mcp" / "tools").glob("*.py")):
    for name, decs in _functions(path):
      if "jsonrpc" in decs:
        result[name] = decs
  return result


class AnnotationsTest(unittest.TestCase):

  def test_sets_are_disjoint(self):
    items = list(_SETS.items())
    for i, (name_a, a) in enumerate(items):
      for name_b, b in items[i + 1 :]:
        self.assertEqual(sorted(a & b), [], f"{name_a} & {name_b}")

  def test_every_gateway_tool_is_classified(self):
    classified = frozenset().union(*_SETS.values())
    tools = _gateway_tools()
    self.assertGreater(len(tools), 50)
    self.assertEqual(sorted(tools - classified), [], "unclassified tools")
    self.assertEqual(sorted(classified - tools), [], "stale entries")

  def test_backend_writers_are_not_read_only(self):
    # @idaread does not imply read-only (e.g. dbg_start_process), but
    # @idawrite and @unsafe tools must never be marked read-only.
    for name, decs in _backend_decorators().items():
      if decs & {"idawrite", "unsafe"} and name in annotations.READ_ONLY:
        if name.startswith("dbg_get_") or name == "dbg_list_breakpoints":
          continue  # @unsafe (debugger access) but only reads state.
        self.fail(f"{name} is {sorted(decs)} but marked READ_ONLY")

  def test_hints(self):
    self.assertEqual(
        annotations.annotations_for("decompile_function"),
        {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
    )
    self.assertEqual(
        annotations.annotations_for("rename_addresses"),
        {"readOnlyHint": False, "openWorldHint": False},
    )
    self.assertEqual(
        annotations.annotations_for("idapython_eval"),
        {"readOnlyHint": False, "openWorldHint": True},
    )
    self.assertIsNone(annotations.annotations_for("no_such_tool"))

  def test_clients_receive_annotations(self):
    from gateway import proxy  # pylint: disable=g-import-not-at-top,unused-import

    async def list_tools():
      async with fastmcp.Client(forward.mcp_server) as client:
        return {t.name: t for t in await client.list_tools()}

    tools = asyncio.run(list_tools())
    if "list_available_databases" not in tools:
      self.skipTest("disabled by local config")
    ann = tools["list_available_databases"].annotations
    self.assertIsNotNone(ann)
    self.assertTrue(ann.readOnlyHint)
    self.assertFalse(ann.openWorldHint)


if __name__ == "__main__":
  unittest.main()
