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

"""Unit tests for query database update hooks and worker synchronization."""

import asyncio
import functools
import importlib
import inspect
import queue
import sys
import threading
import unittest
from unittest import mock

# Mock IDA modules before importing query module
MOCKED_MODULES = [
    "ida_auto",
    "ida_bytes",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_gdl",
    "ida_hexrays",
    "ida_ida",
    "ida_idp",
    "ida_kernwin",
    "ida_loader",
    "ida_moves",
    "ida_nalt",
    "ida_name",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "idautils",
    "idc",
]

module_mocks = {}
for module in MOCKED_MODULES:
  if module in sys.modules:
    module_mocks[module] = sys.modules[module]
  else:
    module_mocks[module] = mock.MagicMock()
sys.modules.update(module_mocks)

# Ensure IDB_Hooks and IDP_Hooks are valid base types
setattr(
    sys.modules["ida_idp"],
    "IDB_Hooks",
    type(
        "IDB_Hooks",
        (),
        {"hook": lambda self: True, "unhook": lambda self: True},
    ),
)
setattr(
    sys.modules["ida_idp"],
    "IDP_Hooks",
    type(
        "IDP_Hooks",
        (),
        {"hook": lambda self: True, "unhook": lambda self: True},
    ),
)
# Prevent fallback file paths from MagicMock string conversions
setattr(sys.modules["idaapi"], "idb_path", None)
sys.modules["ida_loader"].get_path.return_value = None
sys.modules["ida_nalt"].get_strtype_bpu.return_value = 1

# pylint: disable=g-import-not-at-top
from ida_mcp.tools import query

if not isinstance(getattr(query, "DBUpdateHooks", None), type):
  importlib.reload(query)
# pylint: enable=g-import-not-at-top


def _drain_queue():
  """Drains query._db_update_queue and marks all items task_done."""
  while True:
    try:
      query._db_update_queue.get_nowait()
      query._db_update_queue.task_done()
    except queue.Empty:
      break


class TestDBUpdateHooks(unittest.TestCase):
  """Tests verifying that DBUpdateHooks pushes correct events to _db_update_queue."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    self.hooks = query.DBUpdateHooks()
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute("DROP TABLE IF EXISTS __internal_strings")
      conn.execute("""
        CREATE TABLE __internal_strings (
          start_ea INTEGER,
          end_ea INTEGER,
          length INTEGER,
          string TEXT
        )
      """)
      conn.execute("""
        CREATE VIEW IF NOT EXISTS strings as SELECT start_ea AS address, length,
          string from __internal_strings
                   """)
      conn.execute(
          "CREATE INDEX IF NOT EXISTS idx_strings_range ON __internal_strings"
          " (start_ea, end_ea, length)"
      )
      query._populated_tables.add("strings")
      query._populated_tables.add("__internal_strings")

  def tearDown(self):
    _drain_queue()
    with query._db_write_lock:
      conn = query._get_rw_conn()
      conn.execute("DROP TABLE IF EXISTS __internal_strings")
      conn.execute("DROP VIEW IF EXISTS strings")
      query._populated_tables.discard("strings")
      query._populated_tables.discard("__internal_strings")
    super().tearDown()

  def test_set_func_start_enqueues_when_changed(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_start(pfn, 0x1010)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("set_func_start", 0x1000, 0x1050, 0x1010))

  def test_set_func_start_skips_when_unchanged(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_start(pfn, 0x1000)
    self.assertTrue(query._db_update_queue.empty())

  def test_set_func_end_enqueues_when_changed(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_end(pfn, 0x1040)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("set_func_end", 0x1000, 0x1050, 0x1040))

  def test_set_func_end_skips_when_unchanged(self):
    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.set_func_end(pfn, 0x1050)
    self.assertTrue(query._db_update_queue.empty())

  @mock.patch.object(query, "_get_func_info")
  def test_func_added_enqueues_with_bounds(self, mock_get_info):
    dummy_info = query.FuncInfo(
        0x1000, 0x1050, "test_func", None, None, 0x50, 0
    )
    mock_get_info.return_value = dummy_info

    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.func_added(pfn)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("func_added", 0x1000, 0x1050, dummy_info))

  def test_func_deleted_enqueues_ea(self):
    self.hooks.func_deleted(0x1000)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("func_deleted", 0x1000))

  @mock.patch.object(query, "_get_func_info")
  def test_func_updated_enqueues_info(self, mock_get_info):
    dummy_info = query.FuncInfo(
        0x1000, 0x1050, "renamed_func", None, None, 0x50, 0
    )
    mock_get_info.return_value = dummy_info

    pfn = mock.MagicMock()
    pfn.start_ea = 0x1000
    pfn.end_ea = 0x1050

    self.hooks.func_updated(pfn)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("func_updated", 0x1000, dummy_info))

  def test_byte_patched_in_function_ignored(self):
    sys.modules["idc"].get_func_attr.return_value = (
        0x1000  # belongs to a function
    )
    self.hooks.byte_patched(ea=0x1004, old_value=0x90)
    self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_not_in_strings_table_ignored(self):
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    query._strings_dirty = False
    with mock.patch.object(
        query,
        "load_config",
        return_value={"rebuild_strings_on_data_patch": False},
    ):
      self.hooks.byte_patched(ea=0x2000, old_value=0x41)
    self.assertFalse(query._strings_dirty)
    self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_not_in_strings_table_marks_dirty_when_enabled(self):
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    query._strings_dirty = False
    with mock.patch.object(
        query,
        "load_config",
        return_value={"rebuild_strings_on_data_patch": True},
    ):
      self.hooks.byte_patched(ea=0x2000, old_value=0x41)
    self.assertTrue(query._strings_dirty)
    self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_in_strings_table_enqueues_string_updated(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200B),
              11,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    sys.modules["ida_bytes"].get_strlit_contents.return_value = b"hello world"
    self.hooks.byte_patched(ea=0x2005, old_value=0x6F)

    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(
        event, ("string_updated", 0x2000, 0x200B, "hello world", 11)
    )

  def test_byte_patched_length_changed_marks_strings_dirty(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200B),
              11,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    query._strings_dirty = False
    sys.modules["ida_bytes"].get_strlit_contents.return_value = b""
    self.hooks.byte_patched(ea=0x2000, old_value=0x41)

    self.assertTrue(query._strings_dirty)
    self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_strtype_none_uses_default_strtype(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200B),
              11,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    sys.modules["idc"].get_str_type.return_value = None
    sys.modules["ida_bytes"].get_strlit_contents.return_value = b"hello world"
    self.hooks.byte_patched(ea=0x2005, old_value=0x6F)

    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(
        event, ("string_updated", 0x2000, 0x200B, "hello world", 11)
    )
    sys.modules["ida_bytes"].get_strlit_contents.assert_called_with(0x2000, 11, 0)
    # Reset mock
    sys.modules["idc"].get_str_type.return_value = 0

  def test_byte_patched_none_marks_strings_dirty(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200B),
              11,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    query._strings_dirty = False

    sys.modules["ida_bytes"].get_strlit_contents.return_value = None
    self.hooks.byte_patched(ea=0x2000, old_value=0x41)

    self.assertTrue(query._strings_dirty)
    self.assertTrue(query._db_update_queue.empty())


class TestDBWorkerFunctionAndXrefSync(unittest.TestCase):
  """Tests for the SQLite updates that _db_worker makes for events."""

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    _drain_queue()
    cls.conn = query._get_rw_conn()
    cls.worker = threading.Thread(target=query._db_worker, daemon=True)
    cls.worker.start()

  @classmethod
  def tearDownClass(cls):
    query._db_update_queue.put(("quit",))
    cls.worker.join(timeout=2.0)
    super().tearDownClass()

  def setUp(self):
    super().setUp()
    with query._db_write_lock:
      self.conn.execute("DROP TABLE IF EXISTS functions")
      self.conn.execute("DROP TABLE IF EXISTS xrefs")
      self.conn.execute("""
        CREATE TABLE functions (
          start_ea INTEGER PRIMARY KEY,
          end_ea INTEGER,
          name TEXT,
          demangled_name TEXT,
          prototype TEXT,
          size INTEGER,
          is_lib INTEGER
        )
      """)
      self.conn.execute("""
        CREATE TABLE xrefs (
          from_ea INTEGER,
          to_ea INTEGER,
          type TEXT,
          from_function_ea INTEGER,
          UNIQUE(from_ea, to_ea, type)
        )
      """)
      query._populated_tables.add("functions")
      query._populated_tables.add("xrefs")

  def test_set_func_start_shrink_and_expand(self):
    # Seed initial function 0x1000..0x1050 and xrefs
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'func1', NULL, NULL, 80, 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4120, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4150, 8000, 'call', 4096)")

    # Shrink start from 4096 to 4110
    query._db_update_queue.put(("set_func_start", 4096, 4176, 4110))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    row = cursor.fetchone()
    self.assertEqual(row, (4110, 4176, 66))

    # Verify xrefs: 4100 is outside, 4120 & 4150 are inside
    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, None), (4120, 4110), (4150, 4110)])

    # Expand start back to 4096
    query._db_update_queue.put(("set_func_start", 4110, 4176, 4096))
    query._db_update_queue.join()

    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4176, 80))

    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4120, 4096), (4150, 4096)])

  def test_set_func_end_shrink_and_expand(self):
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'func1', NULL, NULL, 80, 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4120, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4170, 8000, 'call', 4096)")

    # Shrink end from 4176 to 4150
    query._db_update_queue.put(("set_func_end", 4096, 4176, 4150))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4150, 54))

    # xref at 4170 should now have from_function_ea = NULL
    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4120, 4096), (4170, None)])

    # Expand end back to 4176
    query._db_update_queue.put(("set_func_end", 4096, 4150, 4176))
    query._db_update_queue.join()

    cursor.execute("SELECT start_ea, end_ea, size FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4176, 80))

    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4120, 4096), (4170, 4096)])

  def test_func_updated_only_updates_functions(self):
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'old_name', NULL, NULL, 80,"
        " 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")

    info = query.FuncInfo(
        4096, 4176, "new_name", "demangled", "void new_name()", 80, 0
    )
    query._db_update_queue.put(("func_updated", 4096, info))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT name, demangled_name, prototype FROM functions")
    self.assertEqual(
        cursor.fetchone(), ("new_name", "demangled", "void new_name()")
    )

    # Xrefs untouched
    cursor.execute("SELECT from_ea, from_function_ea FROM xrefs")
    self.assertEqual(cursor.fetchall(), [(4100, 4096)])

  def test_func_updated_without_info_deletes_function(self):
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'func1', NULL, NULL, 80, 0)"
    )

    query._db_update_queue.put(("func_updated", 4096, None))
    query._db_update_queue.join()

    count = self.conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    self.assertEqual(count, 0)

  def test_renamed_replaces_or_deletes_name(self):
    with query._db_write_lock:
      self.conn.execute("DROP TABLE IF EXISTS names")
      self.conn.execute(
          "CREATE TABLE names (address INTEGER PRIMARY KEY, name TEXT)"
      )
      self.conn.execute("INSERT INTO names VALUES (4096, 'old_name')")
    query._populated_tables.add("names")
    self.addCleanup(query._populated_tables.discard, "names")

    query._db_update_queue.put(("renamed", 4096, "new_name", None, "old_name"))
    query._db_update_queue.join()
    rows = self.conn.execute("SELECT address, name FROM names").fetchall()
    self.assertEqual(rows, [(4096, "new_name")])

    query._db_update_queue.put(("renamed", 4096, "", None, "new_name"))
    query._db_update_queue.join()
    rows = self.conn.execute("SELECT address, name FROM names").fetchall()
    self.assertEqual(rows, [])

  def test_local_type_changed_replaces_or_deletes_row(self):
    with query._db_write_lock:
      self.conn.execute("DROP TABLE IF EXISTS local_types")
      self.conn.execute(
          "CREATE TABLE local_types (ordinal INTEGER PRIMARY KEY, name TEXT,"
          " declaration TEXT)"
      )
      self.conn.executemany(
          "INSERT INTO local_types VALUES (?, ?, ?)",
          [(1, "TypeA", "struct TypeA;"), (2, "TypeB", "struct TypeB;")],
      )
    query._populated_tables.add("local_types")
    self.addCleanup(query._populated_tables.discard, "local_types")

    for event in (
        ("local_type_changed", 1, query.LocalTypeInfo(1, "A2", "struct A2;")),
        ("local_type_changed", 3, query.LocalTypeInfo(3, "C", "struct C;")),
        ("local_type_changed", 2, None),
    ):
      query._db_update_queue.put(event)
    query._db_update_queue.join()

    rows = self.conn.execute(
        "SELECT ordinal, name, declaration FROM local_types ORDER BY ordinal"
    ).fetchall()
    self.assertEqual(rows, [(1, "A2", "struct A2;"), (3, "C", "struct C;")])

  def test_func_deleted_clears_functions_and_xrefs(self):
    self.conn.execute(
        "INSERT INTO functions VALUES (4096, 4176, 'func1', NULL, NULL, 80, 0)"
    )
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', 4096)")
    self.conn.execute("INSERT INTO xrefs VALUES (4150, 8000, 'call', 4096)")

    query._db_update_queue.put(("func_deleted", 4096))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM functions WHERE start_ea = 4096")
    self.assertEqual(cursor.fetchone()[0], 0)

    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, None), (4150, None)])

  def test_func_added_inserts_function_and_attaches_xrefs(self):
    # xrefs initially detached (from_function_ea is NULL)
    self.conn.execute("INSERT INTO xrefs VALUES (4100, 8000, 'call', NULL)")
    self.conn.execute("INSERT INTO xrefs VALUES (4150, 8000, 'call', NULL)")
    self.conn.execute("INSERT INTO xrefs VALUES (5000, 8000, 'call', NULL)")

    info = query.FuncInfo(4096, 4176, "added_func", None, None, 80, 0)
    query._db_update_queue.put(("func_added", 4096, 4176, info))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT start_ea, end_ea, name FROM functions")
    self.assertEqual(cursor.fetchone(), (4096, 4176, "added_func"))

    # Only xrefs in [4096, 4176) should be attached to 4096
    cursor.execute(
        "SELECT from_ea, from_function_ea FROM xrefs ORDER BY from_ea"
    )
    rows = cursor.fetchall()
    self.assertEqual(rows, [(4100, 4096), (4150, 4096), (5000, None)])

  def test_func_boundary_straddling_sign_boundary(self):
    # Unsigned addresses crossing 0x8000_0000_0000_0000 (signed positive -> negative)
    # start: 0x7FFF_FFFF_FFFF_FFF0, end: 0x8000_0000_0000_0010 (size = 32 bytes)
    start_ea = 0x7FFFFFFFFFFFFFF0
    end_ea = 0x8000000000000010
    signed_start = query._to_signed_64(start_ea)
    signed_end = query._to_signed_64(end_ea)

    self.assertGreaterEqual(signed_start, 0)
    self.assertLess(signed_end, 0)

    # 1. xref below function (0x1000)
    ea_below = query._to_signed_64(0x1000)
    # 2. xref inside function (positive half)
    ea_in_pos = query._to_signed_64(0x7FFFFFFFFFFFFFF5)
    # 3. xref inside function (negative half)
    ea_in_neg = query._to_signed_64(0x8000000000000005)
    # 4. xref above function (0x8000_0000_0000_0020)
    ea_above = query._to_signed_64(0x8000000000000020)

    self.conn.execute(
        "INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_below,)
    )
    self.conn.execute(
        "INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_in_pos,)
    )
    self.conn.execute(
        "INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_in_neg,)
    )
    self.conn.execute(
        "INSERT INTO xrefs VALUES (?, 8000, 'call', NULL)", (ea_above,)
    )

    info = query.FuncInfo(
        signed_start, signed_end, "straddle_func", None, None, 32, 0
    )
    query._db_update_queue.put(("func_added", start_ea, end_ea, info))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute("SELECT from_ea, from_function_ea FROM xrefs")
    xref_map = dict(cursor.fetchall())

    self.assertIsNone(xref_map[ea_below])
    self.assertEqual(xref_map[ea_in_pos], signed_start)
    self.assertEqual(xref_map[ea_in_neg], signed_start)
    self.assertIsNone(xref_map[ea_above])

  def test_string_updated_updates_string_table(self):
    with query._db_write_lock:
      self.conn.execute("DROP VIEW IF EXISTS strings")
      self.conn.execute("DROP TABLE IF EXISTS __internal_strings")
      self.conn.execute("""
        CREATE TABLE __internal_strings (
          start_ea INTEGER,
          end_ea INTEGER,
          length INTEGER,
          string TEXT
        )
      """)
      self.conn.execute("""
        CREATE VIEW IF NOT EXISTS strings AS SELECT start_ea AS address,
          length, string FROM __internal_strings
      """)
      query._populated_tables.add("strings")
      query._populated_tables.add("__internal_strings")
      self.conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x2005),
              5,
              "hello",
          ),
      )

    query._db_update_queue.put(
        ("string_updated", 0x2000, 0x200D, "world_updated", 13)
    )
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute(
        "SELECT start_ea, end_ea, length, string FROM __internal_strings WHERE"
        " start_ea = ?",
        (query._to_signed_64(0x2000),),
    )
    row = cursor.fetchone()
    self.assertEqual(
        row,
        (
            query._to_signed_64(0x2000),
            query._to_signed_64(0x200D),
            13,
            "world_updated",
        ),
    )
    cursor.execute(
        "SELECT address, length, string FROM strings WHERE address = ?",
        (query._to_signed_64(0x2000),),
    )
    row_view = cursor.fetchone()
    self.assertEqual(
        row_view,
        (
            query._to_signed_64(0x2000),
            13,
            "world_updated",
        ),
    )

  def test_string_updated_empty_string_deletes_row(self):
    with query._db_write_lock:
      self.conn.execute("DROP VIEW IF EXISTS strings")
      self.conn.execute("DROP TABLE IF EXISTS __internal_strings")
      self.conn.execute("""
        CREATE TABLE __internal_strings (
          start_ea INTEGER,
          end_ea INTEGER,
          length INTEGER,
          string TEXT
        )
      """)
      self.conn.execute("""
        CREATE VIEW IF NOT EXISTS strings AS SELECT start_ea AS address,
          length, string FROM __internal_strings
      """)
      query._populated_tables.add("strings")
      query._populated_tables.add("__internal_strings")
      self.conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x2005),
              5,
              "hello",
          ),
      )

    query._db_update_queue.put(("string_updated", 0x2000, 0x2000, "", 0))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute(
        "SELECT start_ea, length, string FROM __internal_strings WHERE"
        " start_ea = ?",
        (query._to_signed_64(0x2000),),
    )
    row = cursor.fetchone()
    self.assertIsNone(row)


class TestDBUpdateIDPHooks(unittest.TestCase):
  """Tests verifying that DBUpdateIDPHooks filters and pushes events."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    setattr(sys.modules["idaapi"], "fl_F", 21)
    self.hooks = query.DBUpdateIDPHooks()

  def tearDown(self):
    _drain_queue()
    super().tearDown()

  def test_ev_add_cref_skips_flow(self):
    res = self.hooks.ev_add_cref(_from=0x1000, to=0x1004, xref_type=21)
    self.assertEqual(res, 0)
    self.assertTrue(query._db_update_queue.empty())

  @mock.patch.object(query.helper, "get_func_bounds")
  def test_ev_add_cref_enqueues_non_flow(self, mock_bounds):
    mock_pfn = mock.MagicMock()
    mock_pfn.start_ea = 0x1000
    mock_bounds.return_value = mock_pfn

    res = self.hooks.ev_add_cref(_from=0x1010, to=0x2000, xref_type=17)
    self.assertEqual(res, 0)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("cref_added", 0x1010, 0x2000, 17, 0x1000))

  @mock.patch.object(query.helper, "get_func_bounds")
  def test_ev_add_and_del_dref_enqueues_tid(self, mock_bounds):
    mock_pfn = mock.MagicMock()
    mock_pfn.start_ea = 0x1000
    mock_bounds.return_value = mock_pfn
    tid = 0xFF00000000000001
    from_tid = 0xFF00000000000002

    res = self.hooks.ev_add_dref(_from=0x1010, to=tid, xref_type=1)
    self.assertEqual(res, 0)
    self.assertEqual(
        query._db_update_queue.get_nowait(),
        ("dref_added", 0x1010, tid, 1, 0x1000),
    )
    query._db_update_queue.task_done()

    res = self.hooks.ev_del_dref(_from=0x1010, to=tid)
    self.assertEqual(res, 0)
    self.assertEqual(
        query._db_update_queue.get_nowait(),
        ("dref_deleted", 0x1010, tid),
    )
    query._db_update_queue.task_done()

    mock_bounds.reset_mock()
    self.assertEqual(
        self.hooks.ev_add_dref(_from=from_tid, to=tid, xref_type=1), 0
    )
    self.assertEqual(self.hooks.ev_del_dref(_from=from_tid, to=tid), 0)
    self.assertTrue(query._db_update_queue.empty())
    mock_bounds.assert_not_called()


class TestSkipIfRebasing(unittest.TestCase):
  """Tests for the skip_if_rebasing decorator."""

  def test_preserves_arg_count_for_ida_swig_directors(self):
    # IDAPython's get_callable_arg_count() in _ida_idp.so checks
    # len(getfullargspec().args) to choose an event's signature, e.g., > 1
    # for local_types_changed, > 3 for segm_deleted and > 4 for renamed.
    # With fewer, IDA calls the older signature without the newer arguments.
    decorated = [
        (cls, name)
        for cls in (query.DBUpdateHooks, query.DBUpdateIDPHooks)
        for name, attr in vars(cls).items()
        if hasattr(attr, "__wrapped__")
    ]
    self.assertIn((query.DBUpdateHooks, "local_types_changed"), decorated)
    for cls, name in decorated:
      with self.subTest(method=f"{cls.__name__}.{name}"):
        method = getattr(cls(), name)
        self.assertGreater(len(inspect.getfullargspec(method).args), 4)


class TestDBWorkerSegmentsSync(unittest.TestCase):
  """Tests for the segments update by _db_worker."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    self.conn = query._get_rw_conn()
    with query._db_write_lock:
      self.conn.execute("DROP TABLE IF EXISTS segments")
      self.conn.execute(
          "CREATE TABLE segments (name TEXT, class TEXT, start_ea INTEGER,"
          " end_ea INTEGER, size INTEGER, permissions TEXT)"
      )
      self.conn.execute(
          "CREATE INDEX idx_segments_start ON segments (start_ea, end_ea)"
      )
      self.conn.execute(
          "INSERT INTO segments VALUES ('.old', 'CODE', 4096, 8192, 4096,"
          " 'r-x')"
      )
    query._populated_tables.add("segments")
    self.worker = threading.Thread(target=query._db_worker, daemon=True)
    self.worker.start()

  def tearDown(self):
    query._db_update_queue.put(("quit",))
    self.worker.join(timeout=2.0)
    with query._db_write_lock:
      self.conn.execute("DROP TABLE IF EXISTS segments")
    query._populated_tables.discard("segments")
    super().tearDown()

  def test_segment_changed_replaces_rows_and_keeps_index(self):
    new_rows = [
        (".text", "CODE", 4096, 8192, 4096, "r-x"),
        (".data", "DATA", 8192, 12288, 4096, "rw-"),
    ]
    query._db_update_queue.put(("segment_changed", new_rows))
    query._db_update_queue.join()

    rows = self.conn.execute(
        "SELECT * FROM segments ORDER BY start_ea"
    ).fetchall()
    self.assertEqual(rows, new_rows)
    indexes = [
        r[0]
        for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND"
            " tbl_name='segments'"
        )
    ]
    self.assertIn("idx_segments_start", indexes)


class TestLocalTypesSync(unittest.TestCase):
  """Tests for keeping local_types in sync with IDA."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    self.hooks = query.DBUpdateHooks()
    query._local_types_dirty = False

  def tearDown(self):
    _drain_queue()
    query._local_types_dirty = False
    super().tearDown()

  def _create_local_types(self, rows):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute("DROP TABLE IF EXISTS local_types")
      conn.execute(
          "CREATE TABLE local_types (ordinal INTEGER PRIMARY KEY, name TEXT,"
          " declaration TEXT)"
      )
      conn.execute(
          "CREATE INDEX idx_local_types_name ON local_types (name, ordinal)"
      )
      conn.executemany("INSERT INTO local_types VALUES (?, ?, ?)", rows)
    query._populated_tables.add("local_types")
    self.addCleanup(query._populated_tables.discard, "local_types")
    return conn

  @mock.patch.object(query, "_get_local_type_info")
  def test_local_types_changed_with_ordinal_enqueues_single_update(
      self, mock_get_info
  ):
    dummy_info = query.LocalTypeInfo(
        23, "MyStruct", "struct MyStruct {int a;};"
    )
    mock_get_info.return_value = dummy_info

    self.hooks.local_types_changed(1, 23, "MyStruct")
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("local_type_changed", 23, dummy_info))
    mock_get_info.assert_called_once_with(23)
    self.assertFalse(query._local_types_dirty)

  @mock.patch.object(query, "_get_local_type_info")
  def test_local_types_changed_without_ordinal_marks_table_dirty(
      self, mock_get_info
  ):
    # IDA 7.7 passes no arguments. Later versions pass ordinal 0 when they
    # don't know which type changed; IDA 9.4 sends (7, 0, None) when a TIL is
    # unloaded.
    with self.subTest("no arguments"):
      self.hooks.local_types_changed()
      self.assertTrue(query._local_types_dirty)
    query._local_types_dirty = False
    with self.subTest("ordinal 0"):
      self.hooks.local_types_changed(7, 0, None)
      self.assertTrue(query._local_types_dirty)
    self.assertTrue(query._db_update_queue.empty())
    mock_get_info.assert_not_called()

  def test_refresh_local_types_updates_rows_in_place(self):
    conn = self._create_local_types([
        (1, "KeepType", "struct KeepType { int a; };"),
        (2, "ModType", "struct ModType { int old; };"),
        (3, "DelType", "struct DelType { int gone; };"),
    ])
    ida_types = [
        (1, "KeepType", "struct KeepType { int a; };"),
        (2, "ModTypeRenamed", "struct ModTypeRenamed { int new_field; };"),
        (4, "AddedType", "struct AddedType { long x; };"),
    ]
    query._local_types_dirty = True
    with mock.patch.object(
        query, "_iter_local_types_info", return_value=iter(ida_types)
    ):
      query.refresh_local_types()

    rows = conn.execute(
        "SELECT ordinal, name, declaration FROM local_types ORDER BY ordinal"
    ).fetchall()
    self.assertEqual(rows, ida_types)
    self.assertFalse(query._local_types_dirty)
    # Updated in place: the table kept its index.
    indexes = [
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND"
            " tbl_name='local_types'"
        )
    ]
    self.assertIn("idx_local_types_name", indexes)

  def test_sql_query_refreshes_dirty_local_types_before_reading(self):
    self._create_local_types([(1, "TypeA", "struct TypeA;")])
    query._local_types_dirty = True
    with (
        mock.patch.object(query, "_db_initialized", True),
        mock.patch.object(query, "refresh_local_types") as mock_refresh,
    ):
      results = asyncio.run(
          query.sql_query([{"sql": "SELECT name FROM local_types"}])
      )
    mock_refresh.assert_called_once_with()
    self.assertEqual(results[0]["rows"], [{"name": "TypeA"}])


class TestUnsigned64BitPopulation(unittest.TestCase):
  """Tests SQLite population and querying for uint64 values >= 2**63."""

  def test_populate_entries_handles_high_uint64_ordinals(self):
    # pylint: disable=g-import-not-at-top
    from gateway.query import adjust_query
    import sqlglot

    # pylint: enable=g-import-not-at-top

    entries = [
        (0, 0x0, 0x0, "start"),
        (1, 0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFFFFF0, "start"),
        (2, 0x8000000000000000, 0x8000000000001000, "high_ep"),
    ]
    badaddr = 0xFFFFFFFFFFFFFFFF

    def fake_get_name_ea(_, name):
      return 0x0 if name == "start" else badaddr

    with (
        mock.patch.object(query.idautils, "Entries", return_value=entries),
        mock.patch.object(query.idaapi, "BADADDR", badaddr),
        mock.patch.object(
            query.ida_name, "get_name_ea", side_effect=fake_get_name_ea
        ),
        mock.patch.object(query, "_db_initialized", True),
    ):
      query.populate_entries()

      eq_sql = adjust_query(
          sqlglot.parse_one(
              "SELECT index_id, ordinal, address, name FROM entries"
              " WHERE ordinal = 0xfffffffffffffff0",
              read="sqlite",
          )
      )
      ge_sql = adjust_query(
          sqlglot.parse_one(
              "SELECT ordinal, name FROM entries"
              " WHERE ordinal >= 0x8000000000000000 ORDER BY index_id",
              read="sqlite",
          )
      )
      results = asyncio.run(
          query.sql_query([
              {"sql": eq_sql},
              {"sql": ge_sql},
          ])
      )

    self.assertEqual(
        results[0]["rows"],
        [{
            "index_id": "0x1",
            "ordinal": "0xfffffffffffffff0",
            "address": "0x0",
            "name": "start",
        }],
    )
    self.assertEqual(
        results[1]["rows"],
        [
            {"ordinal": "0xfffffffffffffff0", "name": "start"},
            {"ordinal": "0x8000000000000000", "name": "high_ep"},
        ],
    )

  def test_populate_segments_handles_high_uint64_size(self):
    seg = mock.Mock()
    seg.name = "flat64"
    seg.sclass = "CODE"
    seg.start_ea = 0x0
    seg.end_ea = 0x8000000000001000
    seg.perm = 0

    with (
        mock.patch.object(query.helper, "get_segments", return_value=[seg]),
        mock.patch.object(
            query.helper, "ida_segment_perm2str", return_value="rwx"
        ),
        mock.patch.object(query, "_db_initialized", True),
    ):
      query.populate_segments()
      results = asyncio.run(
          query.sql_query(
              [{"sql": "SELECT name, start_ea, end_ea, size FROM segments"}]
          )
      )

    self.assertEqual(
        results[0]["rows"],
        [{
            "name": "flat64",
            "start_ea": "0x0",
            "end_ea": "0x8000000000001000",
            "size": "0x8000000000001000",
        }],
    )


class TestDirtyStringsRebuild(unittest.TestCase):
  """Tests automatic strings rebuild without GUI popup in sql_query."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    query._strings_dirty = False

  def tearDown(self):
    query._strings_dirty = False
    super().tearDown()

  def _create_strings_table(self, text: str = "stale") -> None:
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute("DROP VIEW IF EXISTS strings")
      conn.execute("DROP TABLE IF EXISTS __internal_strings")
      conn.execute(
          "CREATE TABLE __internal_strings (start_ea INTEGER, end_ea INTEGER,"
          " length INTEGER, string TEXT)"
      )
      conn.execute(
          "CREATE VIEW strings AS SELECT start_ea AS address, length, string"
          " FROM __internal_strings"
      )
      conn.execute(
          "INSERT INTO __internal_strings VALUES (4096, 4101, 5, ?)", (text,)
      )
    query._populated_tables.add("strings")
    query._populated_tables.add("__internal_strings")
    self.addCleanup(query._populated_tables.discard, "strings")
    self.addCleanup(query._populated_tables.discard, "__internal_strings")

  def test_sql_query_dirty_strings_rebuilds_directly_without_popup(self):
    self._create_strings_table("stale")
    query._strings_dirty = True

    def fake_populate_strings():
      conn = query._get_rw_conn()
      with query._db_write_lock:
        conn.execute("UPDATE __internal_strings SET string = 'fresh'")
      query._strings_dirty = False

    with (
        mock.patch.object(query, "_db_initialized", True),
        mock.patch.object(query.idaapi, "is_headless", False),
        mock.patch.dict(query.POPULATORS, {"strings": fake_populate_strings}),
    ):
      results = asyncio.run(
          query.sql_query([{"sql": "SELECT string FROM strings"}])
      )

    self.assertFalse(query._strings_dirty)
    self.assertEqual(results[0]["rows"], [{"string": "fresh"}])

  def test_sql_query_clean_strings_skips_rebuild(self):
    self._create_strings_table("existing")
    query._strings_dirty = False
    pop = mock.MagicMock()

    with (
        mock.patch.object(query, "_db_initialized", True),
        mock.patch.object(query.idaapi, "is_headless", False),
        mock.patch.dict(query.POPULATORS, {"strings": pop}),
    ):
      results = asyncio.run(
          query.sql_query([{"sql": "SELECT string FROM strings"}])
      )

    pop.assert_not_called()
    self.assertEqual(results[0]["rows"], [{"string": "existing"}])


class TestAuthorizerTableExtraction(unittest.TestCase):
  """Tests compile-time SQLite authorizer table extraction and RO hardening."""

  def setUp(self):
    super().setUp()
    _drain_queue()
    query.close_tables()
    conn = query._get_rw_conn()
    with query._db_write_lock:
      query._check_and_migrate_db(conn)

  def tearDown(self):
    _drain_queue()
    query.close_tables()
    super().tearDown()

  def test_upfront_schemas_and_zero_populator_pragma_introspection(self):
    pop_funcs = mock.MagicMock()
    with (
        mock.patch.object(query, "_db_initialized", True),
        mock.patch.dict(query.POPULATORS, {"functions": pop_funcs}),
    ):
      results = asyncio.run(
          query.sql_query([
              {"sql": "PRAGMA table_info('functions')"},
              {"sql": "SELECT name FROM pragma_table_info('functions')"},
              {
                  "sql": (
                      "SELECT name FROM sqlite_master WHERE type IN ('table',"
                      " 'view')"
                  )
              },
          ])
      )

    pop_funcs.assert_not_called()
    self.assertEqual(
        [r["name"] for r in results[0]["rows"]],
        [
            "start_ea",
            "end_ea",
            "name",
            "demangled_name",
            "prototype",
            "size",
            "is_lib",
        ],
    )
    self.assertEqual(
        [r["name"] for r in results[1]["rows"]],
        [
            "start_ea",
            "end_ea",
            "name",
            "demangled_name",
            "prototype",
            "size",
            "is_lib",
        ],
    )
    master_names = {r["name"] for r in results[2]["rows"]}
    self.assertTrue(
        {
            "functions",
            "strings",
            "__internal_strings",
            "names",
            "imports",
            "segments",
            "local_types",
            "xrefs",
            "entries",
        }.issubset(master_names)
    )

  def _run_with_recording_populators(self, sql):
    """Runs `sql` with populators that only record their name."""
    calls: list[str] = []
    fakes = {
        name: functools.partial(calls.append, name) for name in query.POPULATORS
    }
    with (
        mock.patch.object(query, "_db_initialized", True),
        mock.patch.dict(query.POPULATORS, fakes),
    ):
      results = asyncio.run(query.sql_query([{"sql": sql}]))
    return results[0], sorted(calls)

  def test_query_populates_exactly_the_tables_it_reads(self):
    for sql, expected in (
        (
            (
                "WITH c AS (SELECT to_ea FROM xrefs) SELECT f.name FROM"
                " functions f JOIN c ON f.start_ea = c.to_ea"
            ),
            ["functions", "xrefs"],
        ),
        ("SELECT COUNT(*) FROM imports", ["imports"]),
        (
            "SELECT name FROM segments WHERE EXISTS (SELECT 1 FROM entries)",
            ["entries", "segments"],
        ),
        ("SELECT address, string FROM strings", ["strings"]),
        ("SELECT start_ea FROM __internal_strings", ["strings"]),
        ("SELECT name FROM sqlite_master", []),
    ):
      with self.subTest(sql=sql):
        result, populated = self._run_with_recording_populators(sql)
        self.assertNotIn("error", result)
        self.assertEqual(populated, expected)

  def test_cte_named_like_a_table_is_not_populated(self):
    result, populated = self._run_with_recording_populators(
        "WITH RECURSIVE functions(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM"
        " functions WHERE x < 3) SELECT x FROM functions"
    )
    self.assertNotIn("error", result)
    self.assertEqual(populated, [])
    self.assertEqual(result["rows"], [{"x": "0x1"}, {"x": "0x2"}, {"x": "0x3"}])

  def test_compile_error_after_unpopulated_table_populates_nothing(self):
    # The denied compile stops at xrefs, before SQLite gets to f.typo_col.
    result, populated = self._run_with_recording_populators(
        "SELECT x.from_ea, f.typo_col FROM xrefs x JOIN functions f"
        " ON f.start_ea = x.to_ea"
    )
    self.assertIn("no such column: f.typo_col", result["error"])
    self.assertEqual(populated, [])

  def test_ready_tables_run_the_statement_once(self):
    with mock.patch.object(
        query.idautils, "Names", return_value=[(0x1000, "f")]
    ):
      query.populate_names()
    conn = query._get_ro_conn()
    statements: list[str] = []
    conn.set_trace_callback(statements.append)
    try:
      rows, columns = query._fetch_ro(conn, "SELECT name FROM names")
    finally:
      conn.set_trace_callback(None)
    self.assertEqual((rows, columns), ([("f",)], ["name"]))
    self.assertEqual(statements, ["SELECT name FROM names"])

  def test_first_read_populates_then_runs_the_statement_once(self):
    conn = query._get_ro_conn()
    statements: list[str] = []
    conn.set_trace_callback(statements.append)
    try:
      # populate_names swaps the table (DROP + RENAME) on the RW connection
      # between the denied compile and the retry, in shared-cache mode.
      with mock.patch.object(
          query.idautils, "Names", return_value=[(0x1000, "f")]
      ):
        rows, _ = query._fetch_ro(conn, "SELECT name FROM names")
    finally:
      conn.set_trace_callback(None)
    self.assertEqual(rows, [("f",)])
    self.assertIn("names", query._populated_tables)
    # Neither the denied compile nor the EXPLAIN compile check runs a VDBE
    # program (the statement trace fires from OP_Init), so the statement is
    # seen running exactly once.
    self.assertEqual(statements, ["SELECT name FROM names"])

  def test_ro_authorizer_blocks_unsafe_functions_and_pragmas(self):
    with mock.patch.object(query, "_db_initialized", True):
      results = asyncio.run(
          query.sql_query([
              {"sql": "SELECT load_extension('evil.so')"},
              {"sql": "PRAGMA writable_schema = ON"},
              {"sql": "PRAGMA user_version = 1"},
              {"sql": "PRAGMA user_version"},
              # FLAG pragmas apply at prepare time, so the getter that follows
              # also proves the denied setter never took effect.
              {"sql": "PRAGMA foreign_keys = ON"},
              {"sql": "PRAGMA foreign_keys"},
              {"sql": "PRAGMA index_list('functions')"},
          ])
      )

    self.assertIn("not authorized", (results[0]["error"] or "").lower())
    self.assertIn("not authorized", (results[1]["error"] or "").lower())
    self.assertIn("not authorized", (results[2]["error"] or "").lower())
    self.assertNotIn("error", results[3])
    self.assertEqual(results[3]["rows"], [{"user_version": "0x8"}])
    self.assertIn("not authorized", (results[4]["error"] or "").lower())
    self.assertNotIn("error", results[5])
    self.assertEqual(results[5]["rows"], [{"foreign_keys": "0x0"}])
    self.assertNotIn("error", results[6])
    self.assertEqual(
        {r["name"] for r in results[6]["rows"]},
        {"idx_functions_end", "idx_functions_name", "idx_functions_is_lib"},
    )

  def test_gateway_explain_query_plan_rewrites_and_populates(self):
    # pylint: disable=g-import-not-at-top
    from gateway import query as gw_query

    # pylint: enable=g-import-not-at-top

    def fake_populate_names():
      conn = query._get_rw_conn()
      with query._db_write_lock:
        conn.execute(
            "INSERT INTO names VALUES (-9223372036854775808, 'hi_sym')"
        )
        query._populated_tables.add("names")

    async def fake_forward(_db_id, _method, params):
      return await query.sql_query(params["queries"])

    with (
        mock.patch.object(query, "_db_initialized", True),
        mock.patch.dict(query.POPULATORS, {"names": fake_populate_names}),
        mock.patch.object(gw_query, "forward_to", side_effect=fake_forward),
    ):
      res = asyncio.run(
          gw_query.sql_query(
              database_id="db1",
              sql=(
                  "EXPLAIN QUERY PLAN SELECT name FROM names WHERE address >="
                  " 0x8000000000000000"
              ),
          )
      )

    self.assertNotIn("error", res)
    self.assertGreater(len(res["rows"]), 0)
    self.assertIn("names", query._populated_tables)

  def test_populated_tables_persisted_across_check_and_migrate(self):
    with mock.patch.object(
        query.idautils, "Names", return_value=[(0x1000, "f")]
    ):
      query.populate_names()

    self.assertIn("names", query._populated_tables)
    self.assertNotIn("functions", query._populated_tables)

    # Simulate session reload where user_version and image_min_ea match
    query._populated_tables.clear()
    query._db_version_checked = False
    conn = query._get_rw_conn()
    self.assertIsNotNone(conn)
    self.assertEqual(query._populated_tables, {"names"})

  def test_explain_compile_error_after_unpopulated_table_populates_nothing(
      self,
  ):
    for prefix in ("EXPLAIN", "EXPLAIN QUERY PLAN", "/* c */ EXPLAIN"):
      with self.subTest(prefix=prefix):
        result, populated = self._run_with_recording_populators(
            f"{prefix} SELECT x.from_ea, f.typo_col FROM xrefs x"
            " JOIN functions f ON f.start_ea = x.to_ea"
        )
        self.assertIn("no such column: f.typo_col", result["error"])
        self.assertEqual(populated, [])

  def test_check_and_migrate_prunes_dropped_tables_and_partial_strings(self):
    s = mock.Mock(ea=0x1000, length=3, strtype=0)
    s.__str__ = lambda self=s: "abc"
    with (
        mock.patch.object(
            query.idautils, "Names", return_value=[(0x1000, "n")]
        ),
        mock.patch.object(query.helper, "iter_function_addresses", list),
        mock.patch.object(query.idautils, "Strings", return_value=[s]),
        mock.patch.object(query.ida_nalt, "get_strtype_bpu", return_value=1),
    ):
      query.populate_names()
      query.populate_functions()
      query.populate_strings()

    conn = query._get_rw_conn()
    with query._db_write_lock:
      # Drop functions and __internal_strings (leaving VIEW strings behind).
      conn.execute("DROP TABLE functions")
      conn.execute("DROP TABLE __internal_strings")

    query._populated_tables.clear()
    query._db_version_checked = False
    conn = query._get_rw_conn()
    self.assertEqual(query._populated_tables, {"names"})
    self.assertEqual(query._load_populated_tables(conn), {"names"})

  def test_healing_dropped_tables_reconciles_all_and_heals_inside_explain(self):
    with (
        mock.patch.object(
            query.idautils, "Names", return_value=[(0x1000, "n1")]
        ),
        mock.patch.object(
            query.helper, "iter_function_addresses", return_value=[0x1000]
        ),
        mock.patch.object(
            query,
            "_get_func_info",
            return_value=query.FuncInfo(
                0x1000, 0x1010, "fn1", None, None, 0x10, 0
            ),
        ),
    ):
      query.populate_names()
      query.populate_functions()

    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute("DROP TABLE functions")
      conn.execute("DROP TABLE names")

    # Query with a bad column heals both dropped schemas and persists metadata
    # even though compilation fails before any populator runs.
    with mock.patch.object(query, "_db_initialized", True):
      bad = asyncio.run(
          query.sql_query([{"sql": "SELECT typo_col FROM functions"}])
      )
    self.assertIn("no such column: typo_col", bad[0]["error"])
    self.assertEqual(query._populated_tables, set())
    self.assertEqual(query._load_populated_tables(conn), set())

    # Also heal when the first table in a join is unpopulated (xrefs) and the
    # second table (functions) was dropped externally and hit during EXPLAIN.
    with query._db_write_lock:
      conn.execute("DROP TABLE functions")
      query._populated_tables.add("functions")

    def fake_populate_xrefs():
      with query._db_write_lock:
        conn.execute("INSERT INTO xrefs VALUES (4096, 4096, 'call', 4096)")
        query._populated_tables.add("xrefs")

    def fake_populate_functions():
      with query._db_write_lock:
        conn.execute(
            "INSERT INTO functions VALUES (4096, 4112, 'fn1', NULL, NULL,"
            " 16, 0)"
        )
        query._populated_tables.add("functions")

    with (
        mock.patch.object(query, "_db_initialized", True),
        mock.patch.dict(
            query.POPULATORS,
            {
                "xrefs": fake_populate_xrefs,
                "functions": fake_populate_functions,
            },
        ),
    ):
      joined = asyncio.run(
          query.sql_query([{
              "sql": (
                  "SELECT f.name FROM xrefs x JOIN functions f"
                  " ON f.start_ea = x.to_ea"
              )
          }])
      )
    self.assertNotIn("error", joined[0])
    self.assertEqual(joined[0]["rows"], [{"name": "fn1"}])

  def test_check_compiles_retries_when_shared_cache_schema_is_locked(self):
    # Exercise both: (1) creating a fresh RO connection while DDL holds the
    # shared-cache schema lock, and (2) _check_compiles on an existing RO
    # connection while DDL holds the shared-cache schema lock.
    for prewarm_ro in (False, True):
      with self.subTest(prewarm_ro=prewarm_ro):
        query.close_tables()
        conn = query._get_rw_conn()
        with query._db_write_lock:
          query._check_and_migrate_db(conn)
        if prewarm_ro:
          query._get_ro_conn()

        locked_entered = threading.Event()
        release_lock = threading.Event()

        def hold_ddl_lock(entered=locked_entered, release=release_lock):
          rw = query._get_rw_conn()
          with query._db_write_lock:
            rw.execute("BEGIN TRANSACTION")
            rw.execute("CREATE TABLE _lock_probe (x INT)")
            entered.set()
            release.wait(timeout=5.0)
            rw.execute("ROLLBACK")

        holder = threading.Thread(target=hold_ddl_lock, daemon=True)
        holder.start()
        self.assertTrue(locked_entered.wait(timeout=2.0))

        releaser = threading.Timer(0.05, release_lock.set)
        releaser.start()
        try:
          result, populated = self._run_with_recording_populators(
              "SELECT name FROM names"
          )
        finally:
          release_lock.set()
          releaser.cancel()
          holder.join(timeout=2.0)

        self.assertNotIn("error", result)
        self.assertEqual(populated, ["names"])

  def test_gateway_intersect_and_commented_explain_rewrite(self):
    # pylint: disable=g-import-not-at-top
    from gateway import query as gw_query

    # pylint: enable=g-import-not-at-top

    captured: list[dict[str, str]] = []

    async def fake_forward(_db_id, _method, params):
      captured.extend(params["queries"])
      return [{"rows": []} for _ in params["queries"]]

    with mock.patch.object(gw_query, "forward_to", side_effect=fake_forward):
      res = asyncio.run(
          gw_query.sql_query(
              database_id="db1",
              sql=[
                  (
                      "SELECT start_ea FROM functions WHERE start_ea >="
                      " 0x8000000000000000 INTERSECT SELECT address FROM names"
                  ),
                  "EXPLAIN /* c */ QUERY PLAN SELECT name FROM names",
              ],
          )
      )

    self.assertEqual(len(res), 2)
    self.assertNotIn("error", res[0])
    self.assertNotIn("error", res[1])
    self.assertIn("INTERSECT", captured[0]["sql"])
    self.assertTrue(captured[1]["sql"].startswith("EXPLAIN QUERY PLAN SELECT"))


if __name__ == "__main__":
  unittest.main()
