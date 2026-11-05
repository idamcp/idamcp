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
import dis
import functools
import importlib
import inspect
import logging
import queue
import sqlite3
import sys
import threading
import time
from typing import Any
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
sys.modules["ida_nalt"].STRTYPE_DECOMP = 16

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
    query._strings_dirty = False
    self.hooks = query.DBUpdateHooks()
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute("DROP VIEW IF EXISTS strings")
      conn.execute("DROP TABLE IF EXISTS __internal_strings")
      conn.execute(
          "CREATE TABLE __internal_strings"
          f" ({query.TABLE_SCHEMAS['__internal_strings']})"
      )
      conn.execute(query.STRINGS_VIEW_DDL)
      for index_ddl in query.TABLE_INDEXES["__internal_strings"]:
        conn.execute(index_ddl)
      query._populated_tables.add("strings")
      query._populated_tables.add("__internal_strings")

  def tearDown(self):
    _drain_queue()
    query._strings_dirty = False
    with query._db_write_lock:
      conn = query._get_rw_conn()
      conn.execute("DROP VIEW IF EXISTS strings")
      conn.execute("DROP TABLE IF EXISTS __internal_strings")
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
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200C),
              12,
              0,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    sys.modules["ida_bytes"].get_max_strlit_length.return_value = 12
    sys.modules["ida_bytes"].get_strlit_contents.return_value = b"jello world"
    self.hooks.byte_patched(ea=0x2000, old_value=0x68)

    self.assertFalse(query._strings_dirty)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("string_updated", 0x2000, "jello world"))
    sys.modules["ida_bytes"].get_max_strlit_length.assert_called_with(0x2000, 0)
    sys.modules["ida_bytes"].get_strlit_contents.assert_called_with(
        0x2000, 12, 0
    )

  def test_byte_patched_undefined_wide_string_uses_stored_strtype(self):
    wide_strtype = 0x2000001
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?, ?)",
          (
              query._to_signed_64(0x2010),
              query._to_signed_64(0x2022),
              18,
              wide_strtype,
              "WideTest",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    sys.modules["idc"].get_str_type.return_value = None
    sys.modules["ida_bytes"].get_max_strlit_length.return_value = 18
    sys.modules["ida_bytes"].get_strlit_contents.return_value = b"SideTest"
    try:
      self.hooks.byte_patched(ea=0x2010, old_value=0x57)
    finally:
      sys.modules["idc"].get_str_type.return_value = 0

    self.assertFalse(query._strings_dirty)
    self.assertFalse(query._db_update_queue.empty())
    event = query._db_update_queue.get_nowait()
    query._db_update_queue.task_done()
    self.assertEqual(event, ("string_updated", 0x2010, "SideTest"))
    sys.modules["ida_bytes"].get_max_strlit_length.assert_called_with(
        0x2010, wide_strtype
    )
    sys.modules["ida_bytes"].get_strlit_contents.assert_called_with(
        0x2010, 18, wide_strtype
    )

  def test_byte_patched_embedded_nul_marks_strings_dirty(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200C),
              12,
              0,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    sys.modules["ida_bytes"].get_max_strlit_length.return_value = 4
    sys.modules["ida_bytes"].get_strlit_contents.return_value = b"helo world"
    self.hooks.byte_patched(ea=0x2003, old_value=0x6C)

    self.assertTrue(query._strings_dirty)
    self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_nul_terminator_overwrite_marks_strings_dirty(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200C),
              12,
              0,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    sys.modules["ida_bytes"].get_max_strlit_length.return_value = 20
    with mock.patch.object(
        query,
        "load_config",
        return_value={"rebuild_strings_on_data_patch": False},
    ):
      self.hooks.byte_patched(ea=0x200B, old_value=0x00)

    self.assertTrue(query._strings_dirty)
    self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_empty_or_none_content_marks_strings_dirty(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200C),
              12,
              0,
              "hello world",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    sys.modules["ida_bytes"].get_max_strlit_length.return_value = 12

    for empty_raw in (None, b""):
      query._strings_dirty = False
      sys.modules["ida_bytes"].get_strlit_contents.return_value = empty_raw
      self.hooks.byte_patched(ea=0x2000, old_value=0x41)
      self.assertTrue(query._strings_dirty)
      self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_decomp_strtype_marks_strings_dirty(self):
    conn = query._get_rw_conn()
    with query._db_write_lock:
      conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200C),
              12,
              16,
              "decomp_str",
          ),
      )
    sys.modules["idc"].get_func_attr.return_value = sys.modules["idc"].BADADDR
    self.hooks.byte_patched(ea=0x2000, old_value=0x41)
    self.assertTrue(query._strings_dirty)
    self.assertTrue(query._db_update_queue.empty())

  def test_byte_patched_skips_when_already_dirty(self):
    query._strings_dirty = True
    sys.modules["ida_bytes"].get_max_strlit_length.reset_mock()
    self.hooks.byte_patched(ea=0x2000, old_value=0x41)
    self.assertTrue(query._strings_dirty)
    sys.modules["ida_bytes"].get_max_strlit_length.assert_not_called()
    self.assertTrue(query._db_update_queue.empty())

  def test_populate_strings_stores_exact_byte_span_and_strtype(self):
    ascii_item = mock.Mock(ea=0x2000, length=12, strtype=0)
    ascii_item.__str__ = lambda self=ascii_item: "hello world"
    wide_item = mock.Mock(ea=0x2010, length=18, strtype=0x2000001)
    wide_item.__str__ = lambda self=wide_item: "WideTest"

    query._strings_dirty = True
    with mock.patch.object(
        query.idautils, "Strings", return_value=[ascii_item, None, wide_item]
    ):
      query.populate_strings()

    self.assertFalse(query._strings_dirty)
    conn = query._get_ro_conn()
    internal_rows = conn.execute(
        "SELECT start_ea, end_ea, length, strtype, string FROM"
        " __internal_strings ORDER BY start_ea"
    ).fetchall()
    self.assertEqual(
        internal_rows,
        [
            (0x2000, 0x200C, 12, 0, "hello world"),
            (0x2010, 0x2022, 18, 0x2000001, "WideTest"),
        ],
    )
    view_rows = conn.execute(
        "SELECT address, length, string FROM strings ORDER BY address"
    ).fetchall()
    self.assertEqual(
        view_rows,
        [
            (0x2000, 12, "hello world"),
            (0x2010, 18, "WideTest"),
        ],
    )


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
      self.conn.execute(
          "CREATE TABLE __internal_strings"
          f" ({query.TABLE_SCHEMAS['__internal_strings']})"
      )
      self.conn.execute(query.STRINGS_VIEW_DDL)
      query._populated_tables.add("strings")
      query._populated_tables.add("__internal_strings")
      self.conn.execute(
          "INSERT INTO __internal_strings VALUES (?, ?, ?, ?, ?)",
          (
              query._to_signed_64(0x2000),
              query._to_signed_64(0x200C),
              12,
              0x2000001,
              "hello world",
          ),
      )

    query._db_update_queue.put(("string_updated", 0x2000, "jello world"))
    query._db_update_queue.join()

    cursor = self.conn.cursor()
    cursor.execute(
        "SELECT start_ea, end_ea, length, strtype, string FROM"
        " __internal_strings WHERE start_ea = ?",
        (query._to_signed_64(0x2000),),
    )
    row = cursor.fetchone()
    self.assertEqual(
        row,
        (
            query._to_signed_64(0x2000),
            query._to_signed_64(0x200C),
            12,
            0x2000001,
            "jello world",
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
            12,
            "jello world",
        ),
    )


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
          "CREATE TABLE __internal_strings"
          f" ({query.TABLE_SCHEMAS['__internal_strings']})"
      )
      conn.execute(query.STRINGS_VIEW_DDL)
      conn.execute(
          "INSERT INTO __internal_strings VALUES (4096, 4102, 6, 0, ?)", (text,)
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
      # between the denied compile and the retry, which re-prepares the
      # statement against the new schema.
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

  def test_concurrent_first_reads_populate_once(self):
    # Queries whose first read of a table arrives while another query is
    # still populating it must wait for that run and reuse it: on a large
    # binary a populator takes seconds on IDA's main thread.
    populator_threads: list[int] = []

    def fake_populate_names():
      populator_threads.append(threading.get_ident())
      time.sleep(0.2)  # Let every other thread reach the refresh lock.
      conn = query._get_rw_conn()
      with query._db_write_lock:
        conn.execute("INSERT INTO names VALUES (4096, 'f')")
        query._populated_tables.add("names")

    results: list[list[tuple[Any, ...]]] = []
    errors: list[Exception] = []

    def read_names():
      try:
        rows, _ = query._fetch_ro(
            query._get_ro_conn(), "SELECT name FROM names"
        )
        results.append(rows)
      except Exception as e:  # pylint: disable=broad-exception-caught
        errors.append(e)

    with mock.patch.dict(query.POPULATORS, {"names": fake_populate_names}):
      threads = [threading.Thread(target=read_names) for _ in range(16)]
      for t in threads:
        t.start()
      for t in threads:
        t.join(timeout=10)

    self.assertEqual(errors, [])
    self.assertEqual(len(populator_threads), 1)
    self.assertEqual(results, [[("f",)]] * 16)

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

  def test_reader_is_not_blocked_by_an_open_write_transaction(self):
    # A WAL reader sees the last committed snapshot, so the query runs while
    # the RW connection holds a transaction that already changed the schema,
    # whether the RO connection is created during that transaction or before
    # it. The writer holds _db_write_lock the whole time and commits only
    # once the query has returned; a reader that waited for it would see the
    # committed row.
    for prewarm_ro in (False, True):
      with self.subTest(prewarm_ro=prewarm_ro):
        query.close_tables()
        query._get_rw_conn()
        if prewarm_ro:
          query._get_ro_conn()

        entered = threading.Event()
        release = threading.Event()

        def hold_write_transaction(entered=entered, release=release):
          rw = query._get_rw_conn()
          with query._db_write_lock:
            rw.execute("BEGIN TRANSACTION")
            rw.execute("CREATE TABLE _lock_probe (x INT)")
            rw.execute("INSERT INTO names VALUES (4096, 'pending')")
            entered.set()
            release.wait(timeout=10.0)
            rw.execute("COMMIT")

        holder = threading.Thread(target=hold_write_transaction, daemon=True)
        holder.start()
        self.assertTrue(entered.wait(timeout=2.0))
        try:
          result, populated = self._run_with_recording_populators(
              "SELECT name FROM names"
          )
        finally:
          release.set()
          holder.join(timeout=2.0)

        self.assertNotIn("error", result)
        self.assertEqual(result["rows"], [])
        self.assertEqual(populated, ["names"])

  def test_concurrent_first_connections_initialize_wal_safely(self):
    # Simultaneous _get_rw_conn and _get_ro_conn calls on a fresh database
    # must not deadlock switching to WAL mode or unlink live -wal/-shm files.
    for seed_stale_wal in (False, True):
      for _ in range(5):
        query.close_tables()
        if seed_stale_wal:
          db_path, _ = query._get_db_path()
          for suffix in ("-wal", "-shm"):
            with open(db_path + suffix, "wb") as f:
              f.write(b"stale")

        barrier = threading.Barrier(6)
        errors: list[BaseException] = []
        table_sets: list[set[str]] = []
        lock = threading.Lock()

        def worker(idx: int, bar=barrier, errs=errors, seen=table_sets):
          try:
            bar.wait(timeout=5.0)
            if idx % 2 == 0:
              conn = query._get_rw_conn()
            else:
              conn = query._get_ro_conn()
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            with lock:
              seen.append({r[0] for r in rows})
          except BaseException as exc:  # pylint: disable=broad-exception-caught
            with lock:
              errs.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i,), daemon=True)
            for i in range(6)
        ]
        for t in threads:
          t.start()
        for t in threads:
          t.join(timeout=5.0)

        self.assertEqual(errors, [])
        self.assertEqual(len(table_sets), 6)
        for names in table_sets:
          self.assertTrue(set(query.TABLE_SCHEMAS).issubset(names))

  def test_concurrent_dirty_local_types_reads_wait_for_commit(self):
    # _local_types_dirty must stay set until refresh_local_types commits;
    # otherwise a concurrent WAL reader skips _refresh_locks["local_types"]
    # and reads the pre-refresh snapshot.
    rw = query._get_rw_conn()
    with query._db_write_lock:
      rw.execute("INSERT INTO local_types VALUES (1, 'old_t', 'struct old_t;')")
      query._populated_tables.add("local_types")
    query._local_types_dirty = True

    in_refresh = threading.Event()
    allow_finish = threading.Event()
    calls: list[int] = []

    def slow_iter():
      calls.append(1)
      in_refresh.set()
      allow_finish.wait(timeout=5.0)
      yield (1, "new_t", "struct new_t;")

    results: list[list[tuple[Any, ...]]] = []
    errors: list[BaseException] = []

    def read_local_types():
      try:
        rows, _ = query._fetch_ro(
            query._get_ro_conn(), "SELECT name FROM local_types"
        )
        results.append(rows)
      except BaseException as exc:  # pylint: disable=broad-exception-caught
        errors.append(exc)

    with mock.patch.object(query, "_iter_local_types_info", slow_iter):
      t1 = threading.Thread(target=read_local_types, daemon=True)
      t2 = threading.Thread(target=read_local_types, daemon=True)
      t1.start()
      self.assertTrue(in_refresh.wait(timeout=2.0))
      t2.start()
      time.sleep(0.05)
      self.assertTrue(t2.is_alive())
      allow_finish.set()
      t1.join(timeout=5.0)
      t2.join(timeout=5.0)

    self.assertEqual(errors, [])
    self.assertEqual(len(calls), 1)
    self.assertEqual(results, [[("new_t",)], [("new_t",)]])
    self.assertFalse(query._local_types_dirty)

  def test_cancelled_migration_and_refresh_roll_back_wal_write_lock(self):
    # CancelledError inherits from BaseException, not Exception; an aborted
    # write transaction must still roll back so its thread-local rw_conn does
    # not keep holding SQLite's WAL write lock.
    query.close_tables()
    orig_ensure = query._ensure_empty_schemas

    def cancel_mid_migration(conn):
      orig_ensure(conn)
      raise asyncio.CancelledError("cancelled during migration")

    t1_errors: list[BaseException] = []

    def run_cancelled_init():
      try:
        with mock.patch.object(
            query, "_ensure_empty_schemas", side_effect=cancel_mid_migration
        ):
          query._get_ro_conn()
      except BaseException as exc:  # pylint: disable=broad-exception-caught
        t1_errors.append(exc)

    t1 = threading.Thread(target=run_cancelled_init, daemon=True)
    t1.start()
    t1.join(timeout=5.0)
    self.assertEqual(len(t1_errors), 1)
    self.assertIsInstance(t1_errors[0], asyncio.CancelledError)

    # A fresh thread must be able to initialize and write without hitting
    # OperationalError("database is locked").
    rw = query._get_rw_conn()
    with query._db_write_lock:
      rw.execute("INSERT INTO local_types VALUES (1, 'old_t', 'struct old_t;')")
      query._populated_tables.add("local_types")
    query._local_types_dirty = True

    class _CancelOnBind:

      def __conform__(self, _protocol):
        raise asyncio.CancelledError("cancelled mid-refresh")

    def cancelling_iter():
      yield (1, "mid_t", "struct mid_t;")
      yield (2, _CancelOnBind(), "struct never;")

    t2_errors: list[BaseException] = []

    def run_cancelled_refresh():
      try:
        with mock.patch.object(
            query, "_iter_local_types_info", cancelling_iter
        ):
          query._fetch_ro(query._get_ro_conn(), "SELECT name FROM local_types")
      except BaseException as exc:  # pylint: disable=broad-exception-caught
        t2_errors.append(exc)

    t2 = threading.Thread(target=run_cancelled_refresh, daemon=True)
    t2.start()
    t2.join(timeout=5.0)
    self.assertEqual(len(t2_errors), 1)
    self.assertIsInstance(t2_errors[0], asyncio.CancelledError)
    self.assertTrue(query._local_types_dirty)

    with mock.patch.object(
        query,
        "_iter_local_types_info",
        lambda: iter([(1, "final_t", "struct final_t;")]),
    ):
      rows, _ = query._fetch_ro(
          query._get_ro_conn(), "SELECT name FROM local_types"
      )
    self.assertEqual(rows, [("final_t",)])
    self.assertFalse(query._local_types_dirty)

  def test_rollback_if_open_retries_only_an_interrupted_rollback(self):
    # A cancel that lands during cleanup interrupts the ROLLBACK itself; the
    # helper must try again, but must not spin on other errors or on a
    # connection that is already closed.
    interrupted = sqlite3.OperationalError("interrupted")
    interrupted.sqlite_errorcode = sqlite3.SQLITE_INTERRUPT

    class FakeConn:

      def __init__(self, failures):
        self.failures = list(failures)
        self.in_transaction = True
        self.rollbacks = 0

      def execute(self, sql):
        assert sql == "ROLLBACK"
        self.rollbacks += 1
        if self.failures:
          raise self.failures.pop(0)
        self.in_transaction = False

    conn = FakeConn([interrupted, interrupted])
    query._rollback_if_open(conn)
    self.assertEqual((conn.rollbacks, conn.in_transaction), (3, False))

    conn = FakeConn([sqlite3.OperationalError("disk I/O error")])
    query._rollback_if_open(conn)
    self.assertEqual((conn.rollbacks, conn.in_transaction), (1, True))

    closed = sqlite3.connect(":memory:")
    closed.close()
    query._rollback_if_open(closed)  # in_transaction raises; must return

    real = sqlite3.connect(":memory:", isolation_level=None)
    real.execute("BEGIN")
    query._rollback_if_open(real)
    self.assertFalse(real.in_transaction)
    real.close()

  def test_dual_cancellation_during_select_in_write_txn_rolls_back(self):
    # pylint: disable=g-import-not-at-top
    from ida_mcp.core.decorators import CancellationToken
    from ida_mcp.core.decorators import cancellation_profile
    from ida_mcp.core.decorators import cancellation_token_var

    # pylint: enable=g-import-not-at-top

    # SQLite does not auto-rollback an explicit transaction on SQLITE_INTERRUPT
    # during a SELECT, and CPython keeps PyThreadState_SetAsyncExc armed when a
    # C call raises OperationalError("interrupted"). Exercise both on a thread
    # where only cancellation_profile(token) is set (like IDA's main thread).
    query.close_tables()
    query._get_rw_conn()

    select_started = threading.Event()
    retry_ready = threading.Event()
    outcomes: dict[str, Any] = {}
    token = CancellationToken()

    def main_thread_runner():
      outcomes["ctx_token"] = cancellation_token_var.get()
      rw = query._get_rw_conn()
      with query._db_write_lock:
        rw.execute(
            "INSERT INTO local_types VALUES (1, 'old_t', 'struct old_t;')"
        )
        query._populated_tables.add("local_types")
      query._local_types_dirty = True

      rw.create_function(
          "notify_started", 0, lambda: (select_started.set(), 1)[1]
      )
      rw.execute(
          "CREATE TEMP VIEW local_types AS "
          "WITH RECURSIVE r(n) AS ("
          "  SELECT notify_started() "
          "  UNION ALL "
          "  SELECT n + 1 FROM r WHERE n < 50000000"
          ") "
          "SELECT 1 AS ordinal, 't' AS name, CAST(sum(n) AS TEXT) AS"
          " declaration FROM r"
      )
      try:
        with mock.patch.object(
            query,
            "_iter_local_types_info",
            lambda: iter([(1, "new_t", "struct new_t;")]),
        ):
          with cancellation_profile(token):
            query.refresh_local_types.sync_call()
      except BaseException as exc:  # pylint: disable=broad-exception-caught
        outcomes["exc"] = exc
      outcomes["in_txn_after_cancel"] = rw.in_transaction
      outcomes["dirty_after_cancel"] = query._local_types_dirty

      retry_ready.wait(timeout=5.0)
      rw.execute("DROP VIEW temp.local_types")
      with mock.patch.object(
          query,
          "_iter_local_types_info",
          lambda: iter([(1, "new_t", "struct new_t;")]),
      ):
        query.refresh_local_types.sync_call()
      outcomes["in_txn_after_retry"] = rw.in_transaction

    worker = threading.Thread(target=main_thread_runner, daemon=True)
    t0 = time.perf_counter()
    worker.start()
    try:
      self.assertTrue(select_started.wait(timeout=2.0))
      time.sleep(0.005)
      token.cancel()
    finally:
      retry_ready.set()
      worker.join(timeout=2.0)
    elapsed = time.perf_counter() - t0

    self.assertFalse(worker.is_alive())
    self.assertIsNone(outcomes["ctx_token"])
    self.assertLess(elapsed, 1.5)
    self.assertIsInstance(outcomes.get("exc"), asyncio.CancelledError)
    self.assertFalse(outcomes["in_txn_after_cancel"])
    self.assertTrue(outcomes["dirty_after_cancel"])
    self.assertFalse(outcomes["in_txn_after_retry"])
    self.assertFalse(query._local_types_dirty)
    rows, _ = query._fetch_ro(
        query._get_ro_conn(), "SELECT name FROM local_types"
    )
    self.assertEqual(rows, [("new_t",)])

  def test_write_transaction_frames_and_loop_cancellation_do_not_leak(self):
    # pylint: disable=g-import-not-at-top
    from ida_mcp.core.decorators import CancellationToken
    from ida_mcp.core.decorators import cancellation_profile

    # pylint: enable=g-import-not-at-top

    # Python 3.13 omits exception-table entries on conditional loop back-edges,
    # so frames holding _db_write_lock or interruptible_sqlite must not contain
    # uncovered backward jumps.
    if hasattr(dis, "_parse_exception_table"):
      for fn in (
          query._run_write_transaction,
          query._check_and_migrate_db,
          query._recreate_and_insert,
          inspect.unwrap(query.refresh_local_types),
      ):
        co = fn.__code__
        entries = list(dis._parse_exception_table(co))
        handlers_at = lambda off, es=entries: [
            e for e in es if e.start <= off < e.end
        ]
        uncovered = [
            ins.offset
            for ins in dis.get_instructions(co)
            if "JUMP_BACKWARD" in ins.opname
            and len(handlers_at(ins.offset)) < len(handlers_at(ins.argval))
        ]
        self.assertEqual(uncovered, [], co.co_name)

    query.close_tables()
    rw = query._get_rw_conn()
    rows_data = [(i, f"t{i}", "int x;") for i in range(1, 30001)]
    with query._db_write_lock:
      rw.executemany("INSERT INTO local_types VALUES (?, ?, ?)", rows_data)
      query._populated_tables.add("local_types")

    for _ in range(8):
      query._local_types_dirty = True
      entered = threading.Event()
      token = CancellationToken()

      class _FirstRow:

        def __eq__(self, _other, ev=entered):
          ev.set()
          return True

      iter_rows = [(1, _FirstRow(), "int x;")] + rows_data[1:]

      def run_refresh(tok=token):
        with mock.patch.object(
            query, "_iter_local_types_info", lambda r=iter_rows: iter(r)
        ):
          try:
            with cancellation_profile(tok):
              query.refresh_local_types.sync_call()
          except BaseException:  # pylint: disable=broad-exception-caught
            pass

      t = threading.Thread(target=run_refresh, daemon=True)
      t.start()
      self.assertTrue(entered.wait(timeout=2.0))
      token.cancel()
      t.join(timeout=2.0)
      self.assertFalse(t.is_alive())

      acquired = query._db_write_lock.acquire(blocking=False)
      self.assertTrue(acquired)
      query._db_write_lock.release()
      for conn in query._db_local.connections:
        self.assertFalse(conn.in_transaction)

    for _ in range(8):
      entered = threading.Event()
      token = CancellationToken()

      def row_gen(ev=entered):
        ev.set()
        for i in range(30000):
          yield (i, f"n{i}")

      def run_insert(tok=token, gen=row_gen):
        try:
          with cancellation_profile(tok):
            query._recreate_and_insert(
                table_name="names",
                schema=query.TABLE_SCHEMAS["names"],
                data=gen(),
                column_count=2,
                batch_size=100000,
            )
        except BaseException:  # pylint: disable=broad-exception-caught
          pass

      t = threading.Thread(target=run_insert, daemon=True)
      t.start()
      self.assertTrue(entered.wait(timeout=2.0))
      token.cancel()
      t.join(timeout=2.0)
      self.assertFalse(t.is_alive())

      acquired = query._db_write_lock.acquire(blocking=False)
      self.assertTrue(acquired)
      query._db_write_lock.release()
      for conn in query._db_local.connections:
        self.assertFalse(conn.in_transaction)

  def test_migration_logs_exception_failures_but_not_interrupts(self):
    # pylint: disable=g-import-not-at-top
    from ida_mcp.core.decorators import ToolTimeoutError
    from ida_mcp.core.decorators import cancellation_profile

    # pylint: enable=g-import-not-at-top

    query.close_tables()
    orig_ensure = query._ensure_empty_schemas

    def cancel_mid_migration(conn):
      orig_ensure(conn)
      raise asyncio.CancelledError("cancelled during migration")

    with self.assertNoLogs(level=logging.ERROR):
      with mock.patch.object(
          query, "_ensure_empty_schemas", side_effect=cancel_mid_migration
      ):
        with self.assertRaises(asyncio.CancelledError):
          query._get_rw_conn()

    def hang_mid_migration(conn):
      orig_ensure(conn)
      time.sleep(1.0)

    timeout_errs: list[BaseException] = []

    def run_timed_out_migration():
      try:
        with mock.patch.object(
            query, "_ensure_empty_schemas", side_effect=hang_mid_migration
        ):
          with cancellation_profile(None, timeout=0.02):
            query._get_rw_conn()
      except BaseException as exc:  # pylint: disable=broad-exception-caught
        timeout_errs.append(exc)

    with self.assertNoLogs(level=logging.ERROR):
      t = threading.Thread(target=run_timed_out_migration, daemon=True)
      t.start()
      t.join(timeout=2.0)
    self.assertFalse(t.is_alive())
    self.assertEqual(len(timeout_errs), 1)
    self.assertIsInstance(timeout_errs[0], ToolTimeoutError)

    def fail_mid_migration(conn):
      orig_ensure(conn)
      raise sqlite3.OperationalError("disk I/O error")

    with self.assertLogs(level=logging.ERROR) as cm:
      with mock.patch.object(
          query, "_ensure_empty_schemas", side_effect=fail_mid_migration
      ):
        with self.assertRaisesRegex(sqlite3.OperationalError, "disk I/O error"):
          query._get_rw_conn()
    self.assertTrue(
        any("Failed to migrate database" in msg for msg in cm.output)
    )

    rw = query._get_rw_conn()
    self.assertFalse(rw.in_transaction)

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


def tearDownModule():
  query.close_tables()


if __name__ == "__main__":
  unittest.main()
