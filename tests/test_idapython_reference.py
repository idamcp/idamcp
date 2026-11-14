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

"""Unit tests for the IDAPython reference index and tool (no IDA)."""

import inspect
import os
import pathlib
import sys
import tempfile
import textwrap
import types
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

# pylint: disable=g-import-not-at-top
from ida_mcp.tools import reference as reference_tool
from ida_mcp.utils import idapython_reference as ref

# pylint: enable=g-import-not-at-top

_FILES = {
    "ida_funcs.py": (
        '''
        """Routines for working with functions."""
        import _ida_funcs

        def get_func(ea: 'ea_t') -> 'func_t *':
            """Get pointer to function structure by address."""
            return _ida_funcs.get_func(ea)

        def get_func(ea):
            """Second definition of the same name (SWIG overload)."""

        def set_func_cmt(pfn, cmt: str, repeatable: bool) -> bool:
            """Set function comment."""

        def _private_helper():
            pass

        class func_t(object):
            """A function."""

            def __init__(self, *args):
                """Create a function object."""

            def contains(self, ea) -> bool:
                """Is address inside the function?"""

            def _hidden(self):
                pass

        FUNC_NORET = _ida_funcs.FUNC_NORET
        """Function doesn't return."""
        FUNC_FAR = 2
        lowercase_name = 3
        '''
    ),
    "idautils.py": (
        '''
        def XrefsTo(ea, flags=0):
            """Return all references to address 'ea'."""

        def Segments():
            """Get list of segments."""
        '''
    ),
    "idaapi.py": (
        '''
        def get_func(ea):
            """Re-exported."""
        '''
    ),
    "ida_broken.py": "def (:\n",
    "init.py": "def not_indexed():\n    pass\n",
    "examples/disassembler/list_funcs.py": (
        '''
        """
        summary: list all functions in the database

        description:
          Iterates over functions.
        """
        import idautils
        '''
    ),
    "examples/misc/no_doc.py": "print('xrefs')\n",
}


def _make_python_dir(root: str) -> str:
  for rel, content in _FILES.items():
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
      f.write(textwrap.dedent(content).lstrip("\n"))
  return root


class TestIndex(unittest.TestCase):
  """Tests for build_index."""

  @classmethod
  def setUpClass(cls):
    cls._tmp = tempfile.TemporaryDirectory()
    cls.index = ref.build_index(_make_python_dir(cls._tmp.name))

  @classmethod
  def tearDownClass(cls):
    cls._tmp.cleanup()

  def _entries(self, qualname):
    return [e for e in self.index.entries if e.qualname == qualname]

  def test_modules(self):
    self.assertEqual(
        self.index.modules, {"ida_funcs", "idautils", "idaapi"}
    )  # the broken file and init.py are not modules in the index

  def test_function_signature_and_doc(self):
    entry = self._entries("ida_funcs.get_func")[0]
    self.assertEqual(entry.kind, "function")
    self.assertEqual(entry.signature, "(ea: 'ea_t') -> 'func_t *'")
    self.assertEqual(entry.doc, "Get pointer to function structure by address.")
    self.assertEqual(entry.file, "ida_funcs.py")
    self.assertEqual(entry.line, 4)

  def test_private_names_are_skipped(self):
    names = {e.qualname for e in self.index.entries}
    self.assertNotIn("ida_funcs._private_helper", names)
    self.assertNotIn("ida_funcs.func_t._hidden", names)
    self.assertNotIn("ida_funcs.lowercase_name", names)

  def test_class_and_methods_without_self(self):
    self.assertEqual(self._entries("ida_funcs.func_t")[0].kind, "class")
    init = self._entries("ida_funcs.func_t.__init__")[0]
    self.assertEqual(init.signature, "(*args)")
    contains = self._entries("ida_funcs.func_t.contains")[0]
    self.assertEqual(contains.kind, "method")
    self.assertEqual(contains.signature, "(ea) -> bool")

  def test_constants_with_and_without_doc(self):
    noret = self._entries("ida_funcs.FUNC_NORET")[0]
    self.assertEqual(noret.kind, "constant")
    self.assertEqual(noret.doc, "Function doesn't return.")
    self.assertEqual(self._entries("ida_funcs.FUNC_FAR")[0].doc, "")

  def test_module_doc(self):
    module = self._entries("ida_funcs")[0]
    self.assertEqual(module.kind, "module")
    self.assertEqual(module.doc, "Routines for working with functions.")

  def test_examples(self):
    by_name = {x.name: x for x in self.index.examples}
    self.assertEqual(set(by_name), {"disassembler/list_funcs", "misc/no_doc"})
    example = by_name["disassembler/list_funcs"]
    self.assertEqual(example.summary, "list all functions in the database")
    self.assertEqual(example.path, "examples/disassembler/list_funcs.py")
    self.assertIn("import idautils", example.content)
    self.assertEqual(by_name["misc/no_doc"].summary, "")

  def test_missing_examples_dir(self):
    with tempfile.TemporaryDirectory() as tmp:
      pathlib.Path(tmp, "idc.py").write_text("def f():\n  pass\n")
      index = ref.build_index(tmp)
    self.assertEqual(index.examples, [])
    self.assertEqual(index.modules, {"idc"})


class TestSearch(unittest.TestCase):
  """Tests for search."""

  @classmethod
  def setUpClass(cls):
    cls._tmp = tempfile.TemporaryDirectory()
    cls.index = ref.build_index(_make_python_dir(cls._tmp.name))

  @classmethod
  def tearDownClass(cls):
    cls._tmp.cleanup()

  def _names(self, query, **kwargs):
    return [
        r["name"] for r in ref.search(self.index, query, **kwargs)["results"]
    ]

  def test_exact_name_first_and_overloads_deduplicated(self):
    names = self._names("get_func")
    self.assertEqual(names[0], "ida_funcs.get_func")
    self.assertEqual(names.count("ida_funcs.get_func"), 1)
    # idaapi re-exports rank below the defining module.
    self.assertLess(
        names.index("ida_funcs.get_func"), names.index("idaapi.get_func")
    )

  def test_qualified_name(self):
    self.assertEqual(
        self._names("ida_funcs.func_t.contains")[0], "ida_funcs.func_t.contains"
    )

  def test_result_fields(self):
    result = ref.search(self.index, "get_func", max_results=1)
    self.assertEqual(
        result["results"],
        [{
            "kind": "function",
            "name": "ida_funcs.get_func",
            "doc": "Get pointer to function structure by address.",
            "source": "ida_funcs.py:4",
            "signature": "(ea: 'ea_t') -> 'func_t *'",
        }],
    )
    self.assertEqual(result["python_dir"], self.index.python_dir)
    self.assertGreater(result["total_matches"], 1)

  def test_words_match_api_abbreviations(self):
    self.assertEqual(
        self._names("set function comment")[0], "ida_funcs.set_func_cmt"
    )

  def test_adjacent_words_match_a_camel_case_name(self):
    self.assertEqual(self._names("xrefs to address")[0], "idautils.XrefsTo")

  def test_constant(self):
    self.assertEqual(self._names("FUNC_NORET")[0], "ida_funcs.FUNC_NORET")

  def test_max_results_is_clamped(self):
    self.assertEqual(len(self._names("func", max_results=0)), 1)
    self.assertLessEqual(
        len(self._names("func", max_results=10**6)), ref.MAX_RESULTS
    )

  def test_empty_query(self):
    with self.assertRaises(ValueError):
      ref.search(self.index, "   ")

  def test_no_match(self):
    result = ref.search(self.index, "zzzqqq")
    self.assertEqual(result["results"], [])
    self.assertEqual(result["total_matches"], 0)
    self.assertNotIn("example", result)

  def test_example_matched_by_summary(self):
    result = ref.search(self.index, "list functions")
    self.assertEqual(result["example"]["name"], "disassembler/list_funcs")
    self.assertEqual(
        result["example"]["summary"], "list all functions in the database"
    )
    self.assertNotIn(
        "example",
        ref.search(self.index, "list functions", include_example=False),
    )

  def test_example_not_picked_by_code_only(self):
    # misc/no_doc mentions "xrefs" only in its code.
    self.assertNotIn("example", ref.search(self.index, "xrefs"))

  def test_notes_for_missing_modules(self):
    notes = ref.search(self.index, "ida_struct add member")["notes"]
    self.assertEqual(notes, [ref.REMOVED_MODULES["ida_struct"]])
    notes = ref.search(self.index, "ida_nothere.foo")["notes"]
    self.assertEqual(
        notes, ["Module ida_nothere does not exist in this IDA version."]
    )
    self.assertNotIn("notes", ref.search(self.index, "ida_funcs.get_func"))

  def test_long_docs_are_truncated(self):
    entry = ref.Entry("function", "m", "m.f", "f", "m.py", 1, "x" * 5000)
    index = ref.Index("/d", frozenset({"m"}), [entry], [])
    doc = ref.search(index, "f")["results"][0]["doc"]
    self.assertEqual(len(doc), ref.MAX_DOC_CHARS + len(" [...]"))


class TestCache(unittest.TestCase):

  def test_index_is_built_once_per_directory(self):
    with tempfile.TemporaryDirectory() as tmp:
      _make_python_dir(tmp)
      with mock.patch.object(
          ref, "build_index", wraps=ref.build_index
      ) as build:
        first = ref.get_index(tmp)
        second = ref.get_index(tmp)
      self.assertIs(first, second)
      self.assertEqual(build.call_count, 1)
      ref._cache.pop(tmp, None)


class TestTool(unittest.TestCase):
  """Tests for the idapython_reference tool body."""

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.python_dir = os.path.realpath(_make_python_dir(self._tmp.name))
    self.addCleanup(ref._cache.pop, self.python_dir, None)
    kernwin = types.ModuleType("ida_kernwin")
    kernwin.__file__ = os.path.join(self.python_dir, "ida_kernwin.py")
    pro = types.SimpleNamespace(IDA_SDK_VERSION=940)
    patcher = mock.patch.dict(
        sys.modules, {"ida_kernwin": kernwin, "ida_pro": pro}
    )
    patcher.start()
    self.addCleanup(patcher.stop)
    self.tool = inspect.unwrap(reference_tool.idapython_reference)

  def test_uses_the_loaded_ida_modules_directory(self):
    result = self.tool("get_func", max_results=2)
    self.assertEqual(result["python_dir"], self.python_dir)
    self.assertEqual(result["ida_version"], "9.4")
    self.assertEqual(result["results"][0]["name"], "ida_funcs.get_func")

  def test_unknown_version(self):
    sys.modules["ida_pro"] = types.SimpleNamespace()
    self.assertEqual(self.tool("get_func")["ida_version"], "unknown")

  def test_missing_ida_modules(self):
    with mock.patch.dict(
        sys.modules, {"ida_kernwin": None, "ida_idaapi": None, "idc": None}
    ):
      with self.assertRaisesRegex(Exception, "python directory") as cm:
        self.tool("get_func")
    self.assertEqual(type(cm.exception).__name__, "ToolError")

  def test_empty_query_is_a_tool_error(self):
    with self.assertRaises(Exception) as cm:
      self.tool("  ")
    self.assertEqual(type(cm.exception).__name__, "ToolError")

  def test_tool_is_registered_and_safe(self):
    self.assertEqual(
        reference_tool.idapython_reference.__name__, "idapython_reference"
    )
    self.assertFalse(reference_tool.idapython_reference.unsafe)


if __name__ == "__main__":
  unittest.main()
