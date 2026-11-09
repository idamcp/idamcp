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


"""Module for SQL-based queries on IDA Pro database using SQLite."""

import asyncio
import contextlib
import dataclasses
import functools
import json
import logging
import os
import pathlib
import queue
import re
import shutil
import signal
import sqlite3
import tempfile
import threading
import time
import traceback
from typing import Any, Callable, Iterable, Iterator
import weakref
import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_idp
from ida_mcp.core.decorators import get_cancellation_token
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import register_cancel_callback
from ida_mcp.core.synchronization import idaread
from ida_mcp.utils import helper
import ida_nalt
import ida_name
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc
from shared.config import load_config
from shared.rpc import ToolError
from shared.types import QueryResult

_image_min_ea = 0
_is_rebasing = False
_db_version_checked = False
_populated_tables: set[str] = set()

TARGET_DB_VERSION = 8

TABLE_SCHEMAS: dict[str, str] = {
    "functions": (
        "start_ea INTEGER PRIMARY KEY, end_ea INTEGER, name TEXT,"
        " demangled_name TEXT, prototype TEXT, size INTEGER, is_lib INTEGER"
    ),
    "__internal_strings": (
        "start_ea INTEGER, end_ea INTEGER, length INTEGER, strtype INTEGER,"
        " string TEXT"
    ),
    "names": "address INTEGER PRIMARY KEY, name TEXT",
    "imports": "address INTEGER, name TEXT, module TEXT",
    "segments": (
        "name TEXT, class TEXT, start_ea INTEGER, end_ea INTEGER, size"
        " INTEGER, permissions TEXT"
    ),
    "local_types": "ordinal INTEGER PRIMARY KEY, name TEXT, declaration TEXT",
    "xrefs": (
        "from_ea INTEGER, to_ea INTEGER, type TEXT, from_function_ea"
        " INTEGER, UNIQUE(from_ea, to_ea, type)"
    ),
    "entries": "index_id INTEGER, ordinal INTEGER, address INTEGER, name TEXT",
}

STRINGS_VIEW_DDL = (
    "CREATE VIEW IF NOT EXISTS strings AS SELECT start_ea AS address,"
    " length, string FROM __internal_strings"
)

TABLE_INDEXES: dict[str, tuple[str, ...]] = {
    "functions": (
        "CREATE INDEX IF NOT EXISTS idx_functions_end ON functions (end_ea)",
        (
            "CREATE INDEX IF NOT EXISTS idx_functions_name ON functions"
            " (name, start_ea, size)"
        ),
        "CREATE INDEX IF NOT EXISTS idx_functions_is_lib ON functions (is_lib)",
    ),
    "__internal_strings": (
        (
            "CREATE INDEX IF NOT EXISTS idx_strings_range ON"
            " __internal_strings (start_ea, end_ea, length, strtype)"
        ),
    ),
    "names": (
        "CREATE INDEX IF NOT EXISTS idx_names_name ON names (name, address)",
    ),
    "imports": (
        "CREATE INDEX IF NOT EXISTS idx_imports_address ON imports (address)",
        (
            "CREATE INDEX IF NOT EXISTS idx_imports_name ON imports (name,"
            " module, address)"
        ),
    ),
    "segments": (
        (
            "CREATE INDEX IF NOT EXISTS idx_segments_start ON segments"
            " (start_ea, end_ea)"
        ),
    ),
    "local_types": (
        (
            "CREATE INDEX IF NOT EXISTS idx_local_types_name ON local_types"
            " (name, ordinal)"
        ),
    ),
    "xrefs": (
        "CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs (from_ea)",
        "CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs (to_ea)",
        (
            "CREATE INDEX IF NOT EXISTS idx_xrefs_from_func ON xrefs"
            " (from_function_ea)"
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_xrefs_from_func_cov ON xrefs"
            " (from_function_ea, to_ea, type)"
        ),
        (
            "CREATE INDEX IF NOT EXISTS idx_xrefs_to_cov ON xrefs (to_ea,"
            " from_ea, type, from_function_ea)"
        ),
    ),
    "entries": (
        "CREATE INDEX IF NOT EXISTS idx_entries_address ON entries (address)",
        "CREATE INDEX IF NOT EXISTS idx_entries_name ON entries (name)",
        "CREATE INDEX IF NOT EXISTS idx_entries_ordinal ON entries (ordinal)",
    ),
}

POPULATOR_ALIASES: dict[str, str] = {
    "functions": "functions",
    "strings": "strings",
    "__internal_strings": "strings",
    "names": "names",
    "imports": "imports",
    "segments": "segments",
    "local_types": "local_types",
    "xrefs": "xrefs",
    "entries": "entries",
}

# Schema introspection pragmas whose argument is a table or index name.
_INTROSPECTION_PRAGMAS = frozenset({
    "foreign_key_list",
    "index_info",
    "index_list",
    "index_xinfo",
    "table_info",
    "table_list",
    "table_xinfo",
})

# Pragmas allowed only in their argument-less getter form. The setter form
# (`PRAGMA x = v`) is denied: FLAG pragmas such as foreign_keys take effect at
# prepare time and would change the state of the long-lived RO connection.
_GETTER_PRAGMAS = frozenset({
    "compile_options",
    "data_version",
    "database_list",
    "foreign_keys",
    "function_list",
    "module_list",
    "pragma_list",
    "user_version",
})

_DENIED_RO_FUNCTIONS = frozenset({
    "edit",
    "fts3_tokenizer",
    "load_extension",
    "readfile",
    "writefile",
})


@contextlib.contextmanager
def interruptible_sqlite(conn: sqlite3.Connection):
  """Registers a SQLite connection for cancellation interruption."""
  with register_cancel_callback(conn.interrupt):
    try:
      yield conn
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
      token = get_cancellation_token()
      if token is not None and token.is_cancelled:
        raise asyncio.CancelledError("SQL query was interrupted.") from e
      raise


def _rollback_if_open(conn: sqlite3.Connection) -> None:
  """Rolls back the transaction open on `conn`, if any.

  A cancel that lands during cleanup interrupts the ROLLBACK itself; once no
  other statement is active on `conn` (callers materialize SELECT results with
  fetchall()), SQLite clears the interrupt flag when that statement halts, so
  a retry goes through (bounded, in case interrupts keep coming). Any other
  SQLite error ends the attempt: the transaction is gone already or the
  connection is closed.

  Callers run this in a loop that catches async interrupts: an interrupt
  pending from PyThreadState_SetAsyncExc may fire on any Python call, this one
  included, and the rollback must still happen afterwards.
  """
  for _ in range(3):
    try:
      if not conn.in_transaction:
        return
      conn.execute("ROLLBACK")
    except sqlite3.OperationalError as exc:
      if getattr(exc, "sqlite_errorcode", None) != sqlite3.SQLITE_INTERRUPT:
        return
    except sqlite3.Error:
      return


def _run_write_transaction(
    conn: sqlite3.Connection,
    body: Callable[[sqlite3.Connection], None],
    *,
    on_commit: Callable[[], None] | None = None,
) -> None:
  """Runs `body(conn)` inside an interrupt-safe BEGIN/COMMIT write transaction.

  Kept free of loops in the `with`/`try` block: on Python 3.13 an asynchronous
  exception landing on a conditional loop back-edge in `body` skips `body`'s
  own cleanup, so `interruptible_sqlite` and the `finally` rollback must live
  in this outer frame. `on_commit`, if given, must be idempotent; it runs
  whenever SQLite committed, even if an async interrupt fires as COMMIT
  returns.
  """
  with interruptible_sqlite(conn):
    committed = False
    commit_started = False
    try:
      conn.execute("BEGIN TRANSACTION")
      body(conn)
      commit_started = conn.in_transaction
      conn.execute("COMMIT")
      committed = True
    except Exception:
      commit_started = False
      raise
    finally:
      # Repeat the rollback and post-commit hook until they complete: an
      # interrupt pending from PyThreadState_SetAsyncExc fires on the first
      # Python call it meets.
      late_interrupt: BaseException | None = None
      checked_commit = False
      while True:
        try:
          if not checked_commit:
            if commit_started:
              try:
                if not conn.in_transaction:
                  committed = True
              except sqlite3.Error:
                pass
            checked_commit = True
          _rollback_if_open(conn)
          if committed and on_commit is not None:
            on_commit()
            on_commit = None
          break
        except Exception:
          raise
        # pylint: disable-next=broad-exception-caught
        except BaseException as exc:
          late_interrupt = exc
      if late_interrupt is not None:
        raise late_interrupt


class SQLiteConnectionLocal(threading.local):
  """A thread-local container that tracks SQLite connections.

  threading.local invokes __init__() once per thread when the thread first
  accesses an attribute on this instance. SQLiteConnectionLocal leverages this
  to record every thread's local namespace dictionary, and intercepts
  __setattr__() to automatically record any sqlite3.Connection stored on it.

  The tracking state is kept in __slots__: threading.local makes only __dict__
  per-thread, so slot values are shared by all threads.
  """

  __slots__ = ("_lock", "_thread_dicts", "_connections")

  _class_lock = threading.Lock()
  _all_instances: weakref.WeakSet["SQLiteConnectionLocal"] = weakref.WeakSet()

  def __new__(cls, *args, **kwargs):
    inst = super().__new__(cls)
    # Bypass the __setattr__ override below, which reads _lock. Not via
    # object.__setattr__: before Python 3.13 it raises TypeError ("can't apply
    # this __setattr__ to SQLiteConnectionLocal object").
    threading.local.__setattr__(inst, "_lock", threading.Lock())
    threading.local.__setattr__(inst, "_thread_dicts", [])
    threading.local.__setattr__(inst, "_connections", set())
    with cls._class_lock:
      cls._all_instances.add(inst)
    return inst

  def __init__(self):
    super().__init__()
    # __init__ runs once per thread when that thread first accesses this
    # instance.
    self._ensure_tracked_thread_dict()

  def _ensure_tracked_thread_dict(self) -> None:
    """Ensures the calling thread's local namespace dictionary is tracked."""
    lock = object.__getattribute__(self, "_lock")
    thread_dicts = object.__getattribute__(self, "_thread_dicts")
    with lock:
      if not any(d is self.__dict__ for d in thread_dicts):
        thread_dicts.append(self.__dict__)

  def __setattr__(self, name: str, value: Any) -> None:
    super().__setattr__(name, value)
    self._ensure_tracked_thread_dict()
    if isinstance(value, sqlite3.Connection):
      self.track_connection(value)

  def track_connection(self, conn: sqlite3.Connection) -> None:
    """Records a SQLite connection under tracking."""
    lock = object.__getattribute__(self, "_lock")
    connections = object.__getattribute__(self, "_connections")
    with lock:
      connections.add(conn)

  @property
  def connections(self) -> set[sqlite3.Connection]:
    """Returns a snapshot of currently tracked SQLite connections."""
    lock = object.__getattribute__(self, "_lock")
    connections = object.__getattribute__(self, "_connections")
    with lock:
      return set(connections)

  def close_all_connections(self) -> None:
    """Closes all tracked SQLite connections and clears thread-local state."""
    lock = object.__getattribute__(self, "_lock")
    connections = object.__getattribute__(self, "_connections")
    thread_dicts = object.__getattribute__(self, "_thread_dicts")
    with lock:
      conns = list(connections)
      connections.clear()
      for d in thread_dicts:
        d.clear()
      thread_dicts.clear()
    for conn in conns:
      with contextlib.suppress(Exception):
        conn.close()

  @classmethod
  def close_all(cls) -> None:
    """Closes connections across all tracked SQLiteConnectionLocal instances."""
    with cls._class_lock:
      instances = list(cls._all_instances)
    for inst in instances:
      inst.close_all_connections()


# Global SQLite connections (scratch file or persistent)
_db_local = SQLiteConnectionLocal()
_db_write_lock = threading.RLock()

# Per-session directory holding the scratch database; see _get_db_path.
_scratch_dir: pathlib.Path | None = None
_scratch_dir_lock = threading.Lock()


def _is_tid(n: int) -> bool:
  """Check if a number is a TID."""
  return (n & 0xFFFFFFFF00000000) == 0xFF00000000000000


def _ro_authorizer(action, arg1, arg2, dbname, source):
  """Intercepts and denies write or unsafe operations for the RO connection."""
  del source  # Unused
  if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_RECURSIVE):
    return sqlite3.SQLITE_OK
  if action == sqlite3.SQLITE_READ:
    if dbname not in (None, "main", "temp"):
      return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK
  if action == sqlite3.SQLITE_FUNCTION:
    if arg2 and arg2.lower() in _DENIED_RO_FUNCTIONS:
      return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK
  if action == sqlite3.SQLITE_PRAGMA:
    pragma_name = arg1.lower() if arg1 else ""
    if pragma_name in _INTROSPECTION_PRAGMAS:
      return sqlite3.SQLITE_OK
    if pragma_name in _GETTER_PRAGMAS and arg2 is None:
      return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY
  # Deny everything else (INSERT, UPDATE, DROP, ATTACH, etc.)
  return sqlite3.SQLITE_DENY


def _get_db_path() -> tuple[str, bool]:
  """Returns the SQLite database path and whether it outlives the session.

  With sqlite_persistent the database lives next to the IDB. Otherwise it is
  a scratch file in a per-session temporary directory, which close_tables
  removes. Either way it is a file opened in WAL mode: a reader then sees the
  last committed snapshot while a populator or the DB worker writes, whereas
  a shared-cache memory database fails every concurrent reader with
  SQLITE_LOCKED, which the busy handler cannot wait out.
  """
  global _scratch_dir
  if load_config().get("sqlite_persistent") and (
      idb_path := getattr(idaapi, "idb_path", None)
  ):
    return str(pathlib.Path(idb_path).with_suffix(".db")), True

  with _scratch_dir_lock:
    if _scratch_dir is None:
      _scratch_dir = pathlib.Path(
          tempfile.mkdtemp(prefix=f"idamcp-{os.getpid()}-")
      )
    return str(_scratch_dir / "idamcp.db"), False


def _remove_scratch_dir() -> None:
  """Deletes the scratch database directory, if one was created."""
  global _scratch_dir
  with _scratch_dir_lock:
    scratch_dir, _scratch_dir = _scratch_dir, None
  if scratch_dir is not None:
    shutil.rmtree(scratch_dir, ignore_errors=True)


def _to_signed_64(val: int) -> int:
  if val < -0x8000000000000000 or val > 0xFFFFFFFFFFFFFFFF:
    raise ValueError(f"Integer {val} exceeds 64-bit integer limit")
  return val if val < 0x8000000000000000 else val - 0x10000000000000000


def _from_signed_64(val: int) -> int:
  return val if val >= 0 else val + 0x10000000000000000


def _ea_range_clause(
    col: str, start_ea: int, end_ea: int
) -> tuple[str, tuple[int, int]]:
  """Generates a SQL range clause [start_ea, end_ea) for 64-bit addresses.

  Handles wrap-around when the unsigned address range straddles the 64-bit
  signed integer boundary (0x7fff_ffff_ffff_ffff -> 0x8000_0000_0000_0000).
  """
  signed_start = _to_signed_64(start_ea)
  signed_end = _to_signed_64(end_ea)
  if start_ea < end_ea and signed_start >= signed_end:
    return f"({col} >= ? OR {col} < ?)", (signed_start, signed_end)
  return f"{col} >= ? AND {col} < ?", (signed_start, signed_end)


def _create_connection(
    read_only: bool = False, *, unlink_stale_wal: bool = False
):
  """Creates a SQLite connection."""
  path, persistent = _get_db_path()
  if unlink_stale_wal and not pathlib.Path(path).exists():
    for suffix in ("-wal", "-shm"):
      aux_file = pathlib.Path(path + suffix)
      if aux_file.exists():
        with contextlib.suppress(OSError):
          aux_file.unlink()

  conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
  try:
    # Performance pragmas
    conn.execute("PRAGMA cache_size = -65536")  # 64MB page cache
    conn.execute("PRAGMA journal_mode = WAL")  # Readers never wait for writers
    # Only the persistent database has to survive a crash.
    conn.execute(f"PRAGMA synchronous = {'NORMAL' if persistent else 'OFF'}")
    conn.execute("PRAGMA mmap_size = 4294967296")  # 4GB memory-mapped I/O
    # A populator commits one transaction as large as its table, which the
    # WAL file keeps until the next checkpoint truncates it to this size.
    conn.execute("PRAGMA journal_size_limit = 67108864")  # 64MB

    if read_only:
      conn.set_authorizer(_ro_authorizer)
  except BaseException:
    conn.close()
    raise

  return conn


def _ensure_metadata_table(conn: sqlite3.Connection) -> None:
  conn.execute(
      "CREATE TABLE IF NOT EXISTS _db_metadata (key TEXT PRIMARY KEY, value"
      " TEXT)"
  )


def _set_stored_min_ea(conn: sqlite3.Connection, min_ea: int) -> None:
  _ensure_metadata_table(conn)
  conn.execute(
      "INSERT OR REPLACE INTO _db_metadata (key, value) VALUES"
      " ('image_min_ea', ?)",
      (hex(min_ea),),
  )


def _get_stored_min_ea(conn: sqlite3.Connection) -> int | None:
  with contextlib.suppress(sqlite3.OperationalError):
    cursor = conn.execute(
        "SELECT value FROM _db_metadata WHERE key = 'image_min_ea'"
    )
    row = cursor.fetchone()
    if row and row[0] is not None:
      return int(row[0], 0)
  return None


def _save_populated_tables(
    conn: sqlite3.Connection, tables: Iterable[str]
) -> None:
  _ensure_metadata_table(conn)
  conn.execute(
      "INSERT OR REPLACE INTO _db_metadata (key, value) VALUES"
      " ('populated_tables', ?)",
      (json.dumps(sorted({t.lower() for t in tables})),),
  )


def _load_populated_tables(conn: sqlite3.Connection) -> set[str]:
  with contextlib.suppress(sqlite3.OperationalError, json.JSONDecodeError):
    cursor = conn.execute(
        "SELECT value FROM _db_metadata WHERE key = 'populated_tables'"
    )
    row = cursor.fetchone()
    if row and row[0]:
      parsed = json.loads(row[0])
      if isinstance(parsed, list):
        return {str(t).lower() for t in parsed}
  return set()


def _existing_canonical_names(conn: sqlite3.Connection) -> set[str]:
  """Returns canonical table and view names whose schemas currently exist."""
  existing = {
      (row[0].lower(), row[1].lower())
      for row in conn.execute(
          "SELECT type, name FROM sqlite_master WHERE type IN ('table', 'view')"
      ).fetchall()
  }
  valid = {name for name in TABLE_SCHEMAS if ("table", name) in existing}
  if "__internal_strings" in valid and ("view", "strings") in existing:
    valid.add("strings")
  else:
    valid.discard("__internal_strings")
  return valid


def _ensure_empty_schemas(conn: sqlite3.Connection) -> None:
  """Ensures all canonical tables, views, and indexes exist in SQLite."""
  _ensure_metadata_table(conn)
  for table_name, schema in TABLE_SCHEMAS.items():
    conn.execute(f'CREATE TABLE IF NOT EXISTS "{table_name}" ({schema})')
    for index_ddl in TABLE_INDEXES.get(table_name, ()):
      conn.execute(index_ddl)
  conn.execute(STRINGS_VIEW_DDL)


def _check_and_migrate_db(conn: sqlite3.Connection) -> None:
  """Checks user_version and image_min_ea; migrates (recreates) DB if outdated.

  Version 8.0 (represented as integer 8) anchors the upfront table schemas and
  persisted `populated_tables` metadata. If current_version is older than 8 or
  if the recorded image_min_ea has changed, all tables are dropped and empty
  schemas are re-created from scratch.

  Args:
    conn: SQLite connection to inspect and migrate.
  """
  with _db_write_lock:
    cursor = conn.execute("PRAGMA user_version")
    row = cursor.fetchone()
    current_version = row[0] if row else 0

    target_version = TARGET_DB_VERSION
    stored_min_ea = _get_stored_min_ea(conn)

    needs_migration = (
        current_version < target_version or stored_min_ea != _image_min_ea
    )

    if needs_migration:
      logging.info(
          "Database migration needed: version=%d (target=%d), stored_min_ea=%s"
          " (current=%s). Re-creating from scratch.",
          current_version,
          target_version,
          hex(stored_min_ea) if stored_min_ea is not None else "None",
          hex(_image_min_ea),
      )

      def _recreate_schema(rw_conn: sqlite3.Connection) -> None:
        entities = rw_conn.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN ('table',"
            " 'view') AND name NOT LIKE 'sqlite_%'"
        ).fetchall()

        for ent_type, name in entities:
          if ent_type == "view":
            rw_conn.execute(f'DROP VIEW IF EXISTS "{name}"')
          elif ent_type == "table":
            rw_conn.execute(f'DROP TABLE IF EXISTS "{name}"')

        rw_conn.execute(f"PRAGMA user_version = {target_version}")
        _set_stored_min_ea(rw_conn, _image_min_ea)
        _save_populated_tables(rw_conn, ())
        _ensure_empty_schemas(rw_conn)

      try:
        _run_write_transaction(
            conn, _recreate_schema, on_commit=_populated_tables.clear
        )
      except Exception:
        logging.exception("Failed to migrate database")
        raise
      logging.info(
          "Database re-created, version set to %d, image_min_ea recorded as"
          " %s.",
          target_version,
          hex(_image_min_ea),
      )
    else:
      existing = _existing_canonical_names(conn)
      loaded = _load_populated_tables(conn)
      valid = loaded & existing
      if "strings" in valid or "__internal_strings" in valid:
        valid.update(("strings", "__internal_strings"))

      def _sync_existing_schema(rw_conn: sqlite3.Connection) -> None:
        if valid != loaded:
          _save_populated_tables(rw_conn, valid)
        _ensure_empty_schemas(rw_conn)

      _populated_tables.intersection_update(valid)
      _run_write_transaction(
          conn,
          _sync_existing_schema,
          on_commit=lambda: _populated_tables.update(valid),
      )


def _get_rw_conn():
  """Returns a read-write SQLite connection."""
  global _db_version_checked
  db_local = _db_local
  if not _db_version_checked:
    with _db_write_lock:
      db_local = _db_local
      if not _db_version_checked:
        if not hasattr(db_local, "rw_conn"):
          db_local.rw_conn = _create_connection(
              read_only=False, unlink_stale_wal=True
          )
        _check_and_migrate_db(db_local.rw_conn)
        _db_version_checked = True
  if not hasattr(db_local, "rw_conn"):
    db_local.rw_conn = _create_connection(read_only=False)
  return db_local.rw_conn


def _get_ro_conn():
  """Returns a read-only SQLite connection enforced by an authorizer."""
  db_local = _db_local
  if not _db_version_checked:
    _get_rw_conn()
  if not hasattr(db_local, "ro_conn"):
    db_local.ro_conn = _create_connection(read_only=True)
  return db_local.ro_conn


# Xref type mapping
XREF_TYPE_MAP = {
    idaapi.fl_CF: "call",
    idaapi.fl_CN: "call",
    idaapi.fl_JF: "jmp",
    idaapi.fl_JN: "jmp",
    idaapi.fl_F: "flow",
    idaapi.dr_R: "read",
    idaapi.dr_W: "write",
    idaapi.dr_O: "offset",
    idaapi.dr_T: "text",
    idaapi.dr_I: "informational",
    idaapi.dr_S: "enum_member",
}


def _get_xref_type_name(xref_type):
  """Converts IDA xref type to string name."""
  return XREF_TYPE_MAP.get(xref_type, "other")


def _recreate_and_insert(
    table_name: str,
    schema: str,
    data: Iterable[tuple[Any, ...]],
    column_count: int,
    batch_size: int = 1000,
    indexes: Iterable[str] = (),
    drop_views: Iterable[str] = (),
    create_views: Iterable[tuple[str, str]] = (),
):
  """Recreates a table and inserts data atomically using the RW connection."""
  marked: set[str] = set()

  def _insert_rows(conn: sqlite3.Connection) -> None:
    tmp_table = f"{table_name}_tmp"
    conn.execute(f'DROP TABLE IF EXISTS "{tmp_table}"')
    conn.execute(f'CREATE TABLE "{tmp_table}" ({schema})')

    batch = []
    placeholders = ", ".join(["?"] * column_count)
    sql_insert = f'INSERT INTO "{tmp_table}" VALUES ({placeholders})'

    for item in data:
      batch.append(item)
      if len(batch) >= batch_size:
        conn.executemany(sql_insert, batch)
        batch.clear()

    if batch:
      conn.executemany(sql_insert, batch)

    for view_name in drop_views:
      conn.execute(f'DROP VIEW IF EXISTS "{view_name}"')
    conn.execute(f'DROP TABLE IF EXISTS "{table_name}"')
    conn.execute(f'ALTER TABLE "{tmp_table}" RENAME TO "{table_name}"')
    for index_ddl in indexes:
      conn.execute(index_ddl)
    for _, view_ddl in create_views:
      conn.execute(view_ddl)

    marked.update((
        table_name.lower(),
        *(name.lower() for name, _ in create_views),
    ))
    _save_populated_tables(conn, _populated_tables | marked)

  with _db_write_lock:
    conn = _get_rw_conn()
    _run_write_transaction(
        conn,
        _insert_rows,
        on_commit=lambda: _populated_tables.update(marked),
    )


def _is_table_populated(table_name: str) -> bool:
  """Checks if a table has been populated with IDA data."""
  if not _db_version_checked:
    _get_rw_conn()
  return table_name.lower() in _populated_tables


@dataclasses.dataclass
class FuncInfo:
  start_ea: int
  end_ea: int
  name: str
  demangled_name: str | None
  prototype: str | None
  size: int
  is_lib: int


@idaread
def _get_func_info(func_ea: int) -> FuncInfo | None:
  """Retrieves function metadata.

  Validates that `func_ea` is the starting address (entry point) of a function.
  If valid, extracts its boundaries, name, demangled name, type prototype, and
  size.

  Args:
    func_ea: Absolute effective address of the function entry point.

  Returns:
    A `FuncInfo` object containing function metadata if `func_ea` is the start
    address of a function, or `None` if it is not a function entry point.
  """
  bounds = helper.get_func_bounds(func_ea)
  if bounds is None or bounds.start_ea != func_ea:
    return None

  func_size = bounds.end_ea - bounds.start_ea

  func_name = idaapi.get_func_name(bounds.start_ea)
  if func_name is not None:
    demangled = ida_name.demangle_name(func_name, ida_name.MNG_NODEFINIT)
  else:
    func_name = "<unknown>"
    demangled = None

  tif = ida_typeinf.tinfo_t()
  if ida_nalt.get_tinfo(tif, bounds.start_ea):
    proto = tif.dstr()
  else:
    proto = idc.get_type(bounds.start_ea)

  flags = helper.get_func_flags(bounds.start_ea)
  is_lib = 1 if flags and (flags & ida_funcs.FUNC_LIB) else 0

  return FuncInfo(
      start_ea=_to_signed_64(bounds.start_ea),
      end_ea=_to_signed_64(bounds.end_ea),
      name=func_name,
      demangled_name=demangled or None,
      prototype=proto or None,
      size=_to_signed_64(func_size),
      is_lib=is_lib,
  )


def _time_populator(func):
  """Decorator to measure and print execution time of populator functions."""

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    start = time.perf_counter()
    try:
      return func(*args, **kwargs)
    finally:
      duration = time.perf_counter() - start
      print(f"[>] {func.__name__} took {duration:.4f}s", flush=True)

  return wrapper


@_time_populator
@idaread
def populate_functions():
  """Populates the functions table."""

  def _gen():
    for address in helper.iter_function_addresses():
      info: FuncInfo | None = _get_func_info(address)
      if info is not None:
        yield (
            info.start_ea,
            info.end_ea,
            info.name,
            info.demangled_name,
            info.prototype,
            info.size,
            info.is_lib,
        )

  _recreate_and_insert(
      "functions",
      TABLE_SCHEMAS["functions"],
      _gen(),
      column_count=7,
      indexes=TABLE_INDEXES["functions"],
  )


@_time_populator
@idaread
def populate_strings():
  """Populates the strings table."""
  global _strings_dirty

  def _gen():
    for item in idautils.Strings():
      if item is None:
        continue
      end_ea = item.ea + item.length
      yield (
          _to_signed_64(item.ea),
          _to_signed_64(end_ea),
          item.length,
          item.strtype,
          str(item),
      )

  _recreate_and_insert(
      "__internal_strings",
      TABLE_SCHEMAS["__internal_strings"],
      _gen(),
      column_count=5,
      indexes=TABLE_INDEXES["__internal_strings"],
      drop_views=("strings",),
      create_views=(("strings", STRINGS_VIEW_DDL),),
  )
  _strings_dirty = False


@_time_populator
@idaread
def populate_names():
  """Populates the names table."""

  def _gen():
    for addr, name in idautils.Names():
      if name:
        yield (_to_signed_64(addr), name)

  _recreate_and_insert(
      "names",
      TABLE_SCHEMAS["names"],
      _gen(),
      column_count=2,
      indexes=TABLE_INDEXES["names"],
  )


@_time_populator
@idaread
def populate_imports():
  """Populates the imports table."""

  def _gen():
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
      module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
      module_imports = []

      # Callback closure.
      # pylint: disable=cell-var-from-loop
      def imp_cb(ea, name, ordinal):
        symbol_name = name or f"#{ordinal}"
        module_imports.append((
            _to_signed_64(ea),
            symbol_name,
            module_name,
        ))
        return True

      # pylint: disable=cell-var-from-loop
      ida_nalt.enum_import_names(i, imp_cb)
      yield from module_imports

  _recreate_and_insert(
      "imports",
      TABLE_SCHEMAS["imports"],
      _gen(),
      column_count=3,
      indexes=TABLE_INDEXES["imports"],
  )


def _get_segments_info_inner():
  """Retrieves inner segments information."""
  data = []
  for seg in helper.get_segments():
    data.append((
        seg.name,
        seg.sclass,
        _to_signed_64(seg.start_ea),
        _to_signed_64(seg.end_ea),
        _to_signed_64(seg.end_ea - seg.start_ea),
        helper.ida_segment_perm2str(seg.perm),
    ))
  return data


@_time_populator
@idaread
def populate_segments():
  """Populates the segments table."""
  data = _get_segments_info_inner()
  _recreate_and_insert(
      "segments",
      TABLE_SCHEMAS["segments"],
      data,
      column_count=6,
      indexes=TABLE_INDEXES["segments"],
  )


@dataclasses.dataclass
class LocalTypeInfo:
  ordinal: int
  name: str
  declaration: str | None


def _get_local_type_info(ordinal: int) -> LocalTypeInfo | None:
  """Retrieves local type info."""
  idati = ida_typeinf.get_idati()
  tif = ida_typeinf.tinfo_t()
  if not tif.get_numbered_type(idati, ordinal):
    return None
  type_name = tif.get_type_name()
  if not type_name:
    type_name = f"anonymous_type_{ordinal}"

  c_decl_flags = (
      ida_typeinf.PRTYPE_MULTI
      | ida_typeinf.PRTYPE_TYPE
      | ida_typeinf.PRTYPE_SEMI
      | ida_typeinf.PRTYPE_DEF
      | ida_typeinf.PRTYPE_METHODS
      | (ida_typeinf.PRTYPE_OFFSETS if idaapi.is_idaq() else 0)
  )
  # Accessing protected member _print to generate C declaration.
  # pylint: disable=protected-access
  # The method declaration says the return value is `boolean` , while in fact
  # it is a string.
  c_decl_output = tif._print(str(type_name), c_decl_flags)
  return LocalTypeInfo(
      ordinal=ordinal,
      name=type_name,
      declaration=c_decl_output or None,  # type: ignore[arg-type]
  )


def _iter_local_types_info() -> Iterator[tuple[int, str, str | None]]:
  """Yields (ordinal, name, declaration) for each local type."""
  idati = ida_typeinf.get_idati()
  for ordinal in range(1, helper.get_ordinal_limit(idati)):
    try:
      info = _get_local_type_info(ordinal)
    except Exception:  # pylint: disable=broad-exception-caught
      continue
    if info:
      yield (info.ordinal, info.name, info.declaration)


@_time_populator
@idaread
def populate_local_types():
  """Populates the local_types table."""
  global _local_types_dirty
  _recreate_and_insert(
      "local_types",
      TABLE_SCHEMAS["local_types"],
      _iter_local_types_info(),
      column_count=3,
      indexes=TABLE_INDEXES["local_types"],
  )
  _local_types_dirty = False


@_time_populator
@idaread
def refresh_local_types() -> None:
  """Updates local_types in place to match IDA's local types.

  sql_query calls this before it reads local_types if IDA reported a change
  without saying which type changed (see DBUpdateHooks.local_types_changed).
  It runs on IDA's main thread, so no hook can queue a newer row between
  reading the types and writing them.
  """
  global _local_types_dirty
  rows = list(_iter_local_types_info())

  def _apply_local_types(conn: sqlite3.Connection) -> None:
    existing = {
        ordinal: (name, declaration)
        for ordinal, name, declaration in conn.execute(
            "SELECT ordinal, name, declaration FROM local_types"
        ).fetchall()
    }
    for ordinal, name, declaration in rows:
      if existing.pop(ordinal, None) != (name, declaration):
        conn.execute(
            "INSERT OR REPLACE INTO local_types VALUES (?, ?, ?)",
            (ordinal, name, declaration),
        )
    # The rows left in existing are types that IDA no longer has.
    conn.executemany(
        "DELETE FROM local_types WHERE ordinal = ?",
        [(ordinal,) for ordinal in existing],
    )

  def _clear_local_types_dirty() -> None:
    global _local_types_dirty
    _local_types_dirty = False

  with _db_write_lock:
    conn = _get_rw_conn()
    _run_write_transaction(
        conn, _apply_local_types, on_commit=_clear_local_types_dirty
    )


@_time_populator
@idaread
def populate_xrefs() -> None:
  """Populates the xrefs table."""

  def _gen():
    xb = ida_xref.xrefblk_t()
    flags = 0
    for attr_name in ("XREF_FAR", "XREF_NOFLOW"):
      flags |= getattr(ida_xref, attr_name, 0)

    current_start = 0
    current_end = 0
    from_func_ea = None

    for head in idautils.Heads():
      if not (current_start <= head < current_end):
        pfn = helper.get_func_bounds(head)
        if pfn:
          current_start = pfn.start_ea
          current_end = pfn.end_ea
          from_func_ea = _to_signed_64(current_start)
        else:
          current_start = head
          next_pfn = helper.get_next_func_bounds(head)
          current_end = (
              next_pfn.start_ea if next_pfn else idaapi.inf_get_max_ea()
          )
          from_func_ea = None

      if xb.first_from(head, flags):
        yield (
            _to_signed_64(head),
            _to_signed_64(xb.to),
            _get_xref_type_name(xb.type),
            from_func_ea,
        )
        while xb.next_from():
          yield (
              _to_signed_64(head),
              _to_signed_64(xb.to),
              _get_xref_type_name(xb.type),
              from_func_ea,
          )

  _recreate_and_insert(
      "xrefs",
      TABLE_SCHEMAS["xrefs"],
      _gen(),
      column_count=4,
      indexes=TABLE_INDEXES["xrefs"],
  )


_entries_fingerprint: tuple[int, tuple[tuple[int, int], ...]] | None = None


@idaread
def _is_entries_dirty() -> bool:
  """Checks if entry points in IDA have changed."""
  global _entries_fingerprint
  if _entries_fingerprint is None:
    return True

  expected_qty, expected_items = _entries_fingerprint
  actual_qty = ida_entry.get_entry_qty()
  if actual_qty != expected_qty:
    return True

  for i in range(actual_qty):
    ord_val = ida_entry.get_entry_ordinal(i)
    ea = ida_entry.get_entry(ord_val)
    expected_ord, expected_ea = expected_items[i]
    if ord_val != expected_ord or ea != expected_ea:
      return True

  return False


@_time_populator
@idaread
def populate_entries():
  """Populates the entries table from idautils.Entries()."""
  global _entries_fingerprint

  fingerprint_items: list[tuple[int, int]] = []

  def _gen():
    for item in idautils.Entries():
      idx, ordinal, ea, name = item
      fingerprint_items.append((ordinal, ea))
      if name:
        # idautils.Entries() fetches EA via get_entry(ordinal). In formats like
        # ELF without native export ordinals, ordinals are invariant and do not
        # relocate on rebase, causing get_entry() to return un-rebased/desynced
        # EAs that mismatch functions. Resolve via namelist to get the true EA.
        name_ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if name_ea != idaapi.BADADDR:
          ea = name_ea

      yield (
          _to_signed_64(idx),
          _to_signed_64(ordinal),
          _to_signed_64(ea),
          name,
      )

  _recreate_and_insert(
      "entries",
      TABLE_SCHEMAS["entries"],
      _gen(),
      column_count=4,
      indexes=TABLE_INDEXES["entries"],
  )

  _entries_fingerprint = (len(fingerprint_items), tuple(fingerprint_items))


POPULATORS = {
    "functions": populate_functions,
    "strings": populate_strings,
    "names": populate_names,
    "imports": populate_imports,
    "segments": populate_segments,
    "local_types": populate_local_types,
    "xrefs": populate_xrefs,
    "entries": populate_entries,
}

# One lock per table, held by _refresh_table while it populates or refreshes
# the table for a query. Concurrent queries that need the same table wait here
# and then find it ready instead of each running the populator again.
_refresh_locks: dict[str, threading.Lock] = {
    name: threading.Lock() for name in POPULATORS
}

_strings_dirty = False
# Set when IDA reports a local type change without saying which type changed;
# sql_query then calls refresh_local_types before it reads local_types.
_local_types_dirty = False


def _execute_ro(
    conn: sqlite3.Connection, sql: str
) -> tuple[list[tuple[Any, ...]], list[str]]:
  """Runs `sql` on the RO connection and returns (rows, column names)."""
  with interruptible_sqlite(conn):
    with contextlib.closing(conn.execute(sql)) as cursor:
      if not cursor.description:
        return [], []
      return cursor.fetchall(), [desc[0] for desc in cursor.description]


def _refresh_table(
    table_name: str, entries_check_enabled: Callable[[], bool]
) -> None:
  """Populates or refreshes `table_name` so that a query can read it.

  The checks run under the table's refresh lock, so a query that waited for
  another query's populator re-checks and skips the work that was just done.
  Nothing on IDA's main thread or holding _db_write_lock takes this lock, so a
  populator can wait for both while holding it.
  """
  with _refresh_locks[table_name]:
    if not _is_table_populated(table_name):
      POPULATORS[table_name]()
    elif table_name == "strings" and _strings_dirty:
      POPULATORS[table_name]()
    elif table_name == "local_types" and _local_types_dirty:
      refresh_local_types()
    elif (
        table_name == "entries"
        and entries_check_enabled()
        and _is_entries_dirty()
    ):
      populate_entries()


def _missing_populator_table(message: str) -> str | None:
  """Returns the populator table named by a "no such table" error, if any."""
  _, found, rest = message.lower().partition("no such table:")
  if not found:
    return None
  name = rest.strip().split(".")[-1].strip("\"'`")
  return name if name in POPULATOR_ALIASES else None


def _recreate_missing_schemas() -> None:
  """Re-creates any externally dropped schemas and marks them unpopulated."""

  def _heal_schemas(rw_conn: sqlite3.Connection) -> None:
    _save_populated_tables(rw_conn, _populated_tables)
    _ensure_empty_schemas(rw_conn)

  with _db_write_lock:
    conn = _get_rw_conn()
    existing = _existing_canonical_names(conn)
    _populated_tables.intersection_update(existing)
    _run_write_transaction(conn, _heal_schemas)


_EXPLAIN_PREFIX = re.compile(
    r"(?:\s|--[^\n]*(?:\n|$)|/\*.*?\*/)*EXPLAIN\b",
    re.IGNORECASE | re.DOTALL,
)


def _check_compiles(
    conn: sqlite3.Connection, sql: str, healed: set[str]
) -> None:
  """Raises the error `sql` fails to compile with, without reading any row.

  SQLite compiles an EXPLAIN statement exactly like the statement itself but
  only lists its program instead of running it, so this costs one compile and
  touches no table.
  """
  explain_sql = sql if _EXPLAIN_PREFIX.match(sql) else f"EXPLAIN {sql}"
  while True:
    try:
      with interruptible_sqlite(conn):
        with contextlib.closing(conn.execute(explain_sql)):
          pass
      return
    except sqlite3.OperationalError as e:
      missing = _missing_populator_table(str(e))
      if missing is None or missing in healed:
        raise
      healed.add(missing)
      _recreate_missing_schemas()


def _fetch_ro(
    conn: sqlite3.Connection, sql: str
) -> tuple[list[tuple[Any, ...]], list[str]]:
  """Runs `sql` on the RO connection, populating the tables it reads first.

  While SQLite compiles the statement, the authorizer receives a SQLITE_READ
  for every table the statement touches. A read of a table that still needs
  populating (or refreshing) is denied, which fails the compile before any
  row is read; the table is then populated and the statement compiled again.
  A query whose tables are all ready therefore runs exactly once.

  set_authorizer also expires the prepared statements SQLite has cached, so
  the check is not skipped for a statement Python already prepared earlier.
  """
  settled: set[str] = set()  # Tables refreshed for this query.
  healed: set[str] = set()  # Tables whose schema was re-created.
  pending: set[str] = set()  # Tables denied by the last compile.
  compile_checked = False
  check_entries: bool | None = None

  def _entries_check_enabled() -> bool:
    nonlocal check_entries
    if check_entries is None:
      check_entries = bool(load_config().get("check_entries_freshness"))
    return check_entries

  def _authorizer(action, arg1, arg2, dbname, source):
    verdict = _ro_authorizer(action, arg1, arg2, dbname, source)
    if verdict != sqlite3.SQLITE_OK or action != sqlite3.SQLITE_READ:
      return verdict
    table_name = POPULATOR_ALIASES.get(arg1.lower()) if arg1 else None
    if table_name is None or table_name in settled:
      return verdict
    # This runs inside SQLite's compile step: never use a connection or call
    # into IDA here.
    if (
        table_name not in _populated_tables
        or (table_name == "strings" and _strings_dirty)
        or (table_name == "local_types" and _local_types_dirty)
        or (table_name == "entries" and _entries_check_enabled())
    ):
      pending.add(table_name)
      return sqlite3.SQLITE_DENY
    return verdict

  while True:
    pending.clear()
    conn.set_authorizer(_authorizer)
    try:
      return _execute_ro(conn, sql)
    except sqlite3.OperationalError as e:
      missing = _missing_populator_table(str(e))
      if missing is None or missing in healed:
        raise
      healed.add(missing)
      _recreate_missing_schemas()
    except sqlite3.DatabaseError:
      if not pending:
        raise
    finally:
      conn.set_authorizer(_ro_authorizer)

    if pending and not compile_checked:
      # The denied compile stopped at the first table that needs populating.
      # Make sure the rest of the statement compiles before spending seconds
      # in a populator for a query that would fail anyway.
      _check_compiles(conn, sql, healed)
      compile_checked = True

    for table_name in sorted(pending):
      _refresh_table(table_name, _entries_check_enabled)
      settled.add(table_name)


@jsonrpc
def sql_query(
    queries: list[dict[str, Any]],
) -> list[QueryResult]:
  """Executes pre-rewritten read-only SQL queries against IDA Pro using SQLite.

  Args:
    queries: A list of dicts, each with a 'sql' key holding the rewritten SQL
      query string.

  Returns:
    A list of QueryResult objects (one per input query in the batch).
  """
  if _is_rebasing:
    raise ToolError(
        "Database is currently undergoing rebase and auto-analysis. Please wait"
        " for reanalysis to complete before querying."
    )

  if _db_initialized or not init_tables():
    _db_update_queue.join()

  results: list[QueryResult] = []
  for item in queries:
    q = item.get("sql", "").strip()
    if not q:
      continue
    try:
      rows, columns = _fetch_ro(_get_ro_conn(), q)
      if not columns:
        results.append(QueryResult(rows=[]))
        continue

      res = []
      for row in rows:
        row_dict = dict(zip(columns, row))
        for k, v in row_dict.items():
          if isinstance(v, int):
            row_dict[k] = f"{v & 0xFFFFFFFFFFFFFFFF:#x}"
        res.append(row_dict)
      results.append(QueryResult(rows=res))
    except Exception as e:
      results.append(
          QueryResult(
              error=f"Error executing SQL: {str(e)}\n{traceback.format_exc()}"
          )
      )

  return results


_db_update_queue: queue.Queue[tuple[Any, ...]] = queue.Queue()


def _populate_tables() -> None:
  print("[>] Populating all tables, please wait...", flush=True)
  for table_name, populator in POPULATORS.items():
    if not _is_table_populated(table_name):
      try:
        populator()
      except Exception as e:  # pylint: disable=broad-exception-caught
        logging.exception("Failed to repopulate table %s: %s", table_name, e)
  print("[+] All tables are ready...", flush=True)


def _db_worker():
  """Background worker to update SQLite from IDA event queue."""
  dirty_tables: dict[str, Any] = {}
  conn = None
  while True:
    event = _db_update_queue.get()
    try:
      action = event[0]
      if action == "quit":
        break

      if conn is None:
        conn = _get_rw_conn()

      if action == "rebase_invalidation":
        with _db_write_lock:
          try:
            conn.execute("BEGIN TRANSACTION")
            entities = conn.execute(
                "SELECT type, name FROM sqlite_master WHERE type IN ('table',"
                " 'view') AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
            for ent_type, name in entities:
              if ent_type == "view":
                conn.execute(f'DROP VIEW IF EXISTS "{name}"')
              elif ent_type == "table":
                conn.execute(f'DROP TABLE IF EXISTS "{name}"')
            _save_populated_tables(conn, ())
            _ensure_empty_schemas(conn)
            conn.execute("COMMIT")
            _populated_tables.clear()
          except Exception as e:  # pylint: disable=broad-exception-caught
            if conn.in_transaction:
              with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            logging.exception("Error during rebase_invalidation: %s", e)
        continue

      if action == "rebase_completed":
        with _db_write_lock:
          _set_stored_min_ea(conn, _image_min_ea)
        continue

      if action == "repopulate_tables":
        _populate_tables()
        logging.info(
            "Table repopulation complete after rebase. Database is ready."
        )
        continue

      with _db_write_lock:
        cursor = conn.cursor()
        try:
          # Each statement commits on its own, so replace a row with one
          # INSERT OR REPLACE: after a DELETE, readers would find it missing
          # until the INSERT.
          match action:
            case "renamed":
              func_info: FuncInfo | None
              ea, new_name, func_info = event[1:4]
              old_name = event[4] if len(event) > 4 else ""
              signed_ea = _to_signed_64(ea)
              if _is_table_populated("names"):
                if new_name:
                  cursor.execute(
                      "INSERT OR REPLACE INTO names (address, name) VALUES"
                      " (?, ?)",
                      (signed_ea, new_name),
                  )
                else:
                  cursor.execute(
                      "DELETE FROM names WHERE address = ?", (signed_ea,)
                  )

              if _is_table_populated("functions"):
                cursor.execute(
                    "UPDATE functions SET name = ? WHERE start_ea = ?",
                    (new_name, signed_ea),
                )
                if func_info is not None:
                  cursor.execute(
                      "UPDATE functions SET demangled_name = ?, prototype = ?,"
                      " is_lib = ? WHERE start_ea = ?",
                      (
                          func_info.demangled_name,
                          func_info.prototype,
                          func_info.is_lib,
                          signed_ea,
                      ),
                  )

              if _is_table_populated("entries"):
                # Constrain by old_name when available to avoid clobbering
                # multiple distinct export aliases sharing the same address.
                if old_name:
                  cursor.execute(
                      "UPDATE entries SET name = ? WHERE address = ? AND name ="
                      " ?",
                      (new_name, signed_ea, old_name),
                  )
                else:
                  cursor.execute(
                      "UPDATE entries SET name = ? WHERE address = ?",
                      (new_name, signed_ea),
                  )
            case "set_func_start":
              old_start_ea, end_ea, new_start_ea = event[1:4]
              signed_old_start = _to_signed_64(old_start_ea)
              signed_new_start = _to_signed_64(new_start_ea)
              signed_end = _to_signed_64(end_ea)
              new_size = _to_signed_64(end_ea - new_start_ea)

              if _is_table_populated("functions"):
                cursor.execute(
                    """
                    UPDATE functions
                    SET start_ea = ?, size = ?
                    WHERE start_ea = ? AND end_ea = ?
                    """,
                    (signed_new_start, new_size, signed_old_start, signed_end),
                )
                if cursor.rowcount == 0:
                  cursor.execute(
                      """
                      UPDATE functions
                      SET start_ea = ?, size = ?
                      WHERE start_ea = ?
                      """,
                      (signed_new_start, new_size, signed_old_start),
                  )

              if _is_table_populated("xrefs"):
                cursor.execute(
                    "UPDATE xrefs SET from_function_ea = NULL WHERE"
                    " from_function_ea = ?",
                    (signed_old_start,),
                )
                range_clause, params = _ea_range_clause(
                    "from_ea", new_start_ea, end_ea
                )
                cursor.execute(
                    f"""
                    UPDATE xrefs
                    SET from_function_ea = ?
                    WHERE {range_clause}
                    """,
                    (signed_new_start, *params),
                )

            case "set_func_end":
              start_ea, old_end_ea, new_end_ea = event[1:4]
              signed_start = _to_signed_64(start_ea)
              signed_old_end = _to_signed_64(old_end_ea)
              signed_new_end = _to_signed_64(new_end_ea)
              new_size = _to_signed_64(new_end_ea - start_ea)

              if _is_table_populated("functions"):
                cursor.execute(
                    """
                    UPDATE functions
                    SET end_ea = ?, size = ?
                    WHERE start_ea = ? AND end_ea = ?
                    """,
                    (signed_new_end, new_size, signed_start, signed_old_end),
                )
                if cursor.rowcount == 0:
                  cursor.execute(
                      """
                      UPDATE functions
                      SET end_ea = ?, size = ?
                      WHERE start_ea = ?
                      """,
                      (signed_new_end, new_size, signed_start),
                  )

              if _is_table_populated("xrefs"):
                if new_end_ea < old_end_ea:
                  range_clause, params = _ea_range_clause(
                      "from_ea", new_end_ea, old_end_ea
                  )
                  cursor.execute(
                      f"""
                      UPDATE xrefs
                      SET from_function_ea = NULL
                      WHERE {range_clause} AND from_function_ea = ?
                      """,
                      (*params, signed_start),
                  )
                elif new_end_ea > old_end_ea:
                  range_clause, params = _ea_range_clause(
                      "from_ea", old_end_ea, new_end_ea
                  )
                  cursor.execute(
                      f"""
                      UPDATE xrefs
                      SET from_function_ea = ?
                      WHERE {range_clause}
                      """,
                      (signed_start, *params),
                  )

            case "func_added":
              func_info: FuncInfo | None
              start_ea, end_ea, func_info = event[1:4]
              signed_start = _to_signed_64(start_ea)
              signed_end = _to_signed_64(end_ea)
              if _is_table_populated("functions"):
                if func_info is None:
                  cursor.execute(
                      "DELETE FROM functions WHERE start_ea = ?",
                      (signed_start,),
                  )
                else:
                  cursor.execute(
                      "INSERT OR REPLACE INTO functions"
                      " VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (
                          func_info.start_ea,
                          func_info.end_ea,
                          func_info.name,
                          func_info.demangled_name,
                          func_info.prototype,
                          func_info.size,
                          func_info.is_lib,
                      ),
                  )

              if _is_table_populated("xrefs"):
                range_clause, params = _ea_range_clause(
                    "from_ea", start_ea, end_ea
                )
                cursor.execute(
                    f"""
                    UPDATE xrefs
                    SET from_function_ea = ?
                    WHERE {range_clause}
                    """,
                    (signed_start, *params),
                )

            case "func_updated":
              func_info: FuncInfo | None
              ea, func_info = event[1:3]
              signed_ea = _to_signed_64(ea)
              if _is_table_populated("functions"):
                if func_info is None:
                  cursor.execute(
                      "DELETE FROM functions WHERE start_ea = ?", (signed_ea,)
                  )
                else:
                  cursor.execute(
                      "INSERT OR REPLACE INTO functions"
                      " VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (
                          func_info.start_ea,
                          func_info.end_ea,
                          func_info.name,
                          func_info.demangled_name,
                          func_info.prototype,
                          func_info.size,
                          func_info.is_lib,
                      ),
                  )

            case "func_deleted":
              ea = event[1]
              signed_ea = _to_signed_64(ea)
              if _is_table_populated("functions"):
                cursor.execute(
                    "DELETE FROM functions WHERE start_ea = ?",
                    (signed_ea,),
                )

              if _is_table_populated("xrefs"):
                cursor.execute(
                    "UPDATE xrefs SET from_function_ea = NULL WHERE"
                    " from_function_ea = ?",
                    (signed_ea,),
                )

            case "local_type_changed":
              info: LocalTypeInfo | None
              ordinal, info = event[1:3]
              if _is_table_populated("local_types"):
                if info is None:
                  cursor.execute(
                      "DELETE FROM local_types WHERE ordinal = ?", (ordinal,)
                  )
                else:
                  cursor.execute(
                      "INSERT OR REPLACE INTO local_types VALUES (?, ?, ?)",
                      (info.ordinal, info.name, info.declaration),
                  )

            case "segment_changed":
              dirty_tables["segments"] = event[1]

            case "cref_added" | "dref_added":
              from_ea, to_ea, type_val, from_function_ea = event[1:5]
              if _is_table_populated("xrefs"):
                cursor.execute(
                    "INSERT OR IGNORE INTO xrefs (from_ea,"
                    " to_ea, type, from_function_ea)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        _to_signed_64(from_ea),
                        _to_signed_64(to_ea),
                        _get_xref_type_name(type_val),
                        (
                            _to_signed_64(from_function_ea)
                            if from_function_ea is not None
                            else None
                        ),
                    ),
                )

            case "cref_deleted":
              from_ea, to_ea = event[1:3]
              if _is_table_populated("xrefs"):
                cursor.execute(
                    "DELETE FROM xrefs WHERE from_ea = ? AND"
                    " to_ea = ? AND type IN ('call', 'jmp', 'other')",
                    (
                        _to_signed_64(from_ea),
                        _to_signed_64(to_ea),
                    ),
                )

            case "dref_deleted":
              from_ea, to_ea = event[1:3]
              if _is_table_populated("xrefs"):
                cursor.execute(
                    """
                    DELETE FROM xrefs
                    WHERE from_ea = ? AND to_ea = ?
                      AND type IN ('read', 'write', 'offset', 'informational',
                        'text', 'enum_member', 'other')
                    """,
                    (
                        _to_signed_64(from_ea),
                        _to_signed_64(to_ea),
                    ),
                )

            case "string_updated":
              start_ea, new_content = event[1:3]
              if _is_table_populated("__internal_strings"):
                cursor.execute(
                    "UPDATE __internal_strings SET string = ? WHERE"
                    " start_ea = ?",
                    (new_content, _to_signed_64(start_ea)),
                )
        except Exception as e:  # pylint: disable=broad-exception-caught
          logging.exception("DB update error for event %s: %s", action, e)
        finally:
          cursor.close()

      if _db_update_queue.empty() and dirty_tables:
        if "segments" in dirty_tables and _is_table_populated("segments"):
          with _db_write_lock:
            conn.execute("BEGIN TRANSACTION")
            try:
              conn.execute("DELETE FROM segments")
              conn.executemany(
                  "INSERT INTO segments VALUES (?, ?, ?, ?, ?, ?)",
                  dirty_tables["segments"],
              )
              conn.execute("COMMIT")
            except Exception:
              if conn.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                  conn.execute("ROLLBACK")
              raise
        dirty_tables.clear()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception("DB worker error: %s", e)
    finally:
      _db_update_queue.task_done()


_MISSING = object()


def skip_if_rebasing(func=None, *, default_return=None):
  """Decorator to skip hook callbacks when the database is rebasing.

  IDAPython's C++ get_callable_arg_count() calls inspect.getfullargspec()
  (which does not follow __wrapped__) and checks len(spec.args) in _ida_idp.so
  (e.g. local_types_changed checks > 1, segm_deleted checks > 3, renamed
  checks > 4). Defining 5 explicit positional parameters with a sentinel
  default ensures get_callable_arg_count() returns 5 (> 4) while forwarding
  only the arguments actually passed by IDA.
  """

  def decorator(f):
    @functools.wraps(f)
    def wrapper(
        self,
        a1=_MISSING,
        a2=_MISSING,
        a3=_MISSING,
        a4=_MISSING,
        *args,
        **kwargs,
    ):
      if _is_rebasing:
        return default_return
      call_args = [x for x in (a1, a2, a3, a4) if x is not _MISSING]
      call_args.extend(args)
      return f(self, *call_args, **kwargs)

    return wrapper

  if func is not None:
    return decorator(func)
  return decorator


def _trigger_rebase_invalidation() -> None:
  """Invalidates database tables and flushes pending queue upon rebase/move."""
  global _is_rebasing, _entries_fingerprint
  _is_rebasing = True
  _entries_fingerprint = None

  while not _db_update_queue.empty():
    try:
      _db_update_queue.get_nowait()
      _db_update_queue.task_done()
    except queue.Empty:
      break

  _db_update_queue.put(("rebase_invalidation",))


def _complete_rebase_if_auto_ok() -> bool:
  """Completes rebase process if auto-analysis is finished."""
  global _is_rebasing, _image_min_ea
  if _is_rebasing and (not ida_auto.is_auto_enabled() or ida_auto.auto_is_ok()):
    _image_min_ea = idaapi.inf_get_min_ea()
    _is_rebasing = False
    config = load_config()
    if config.get("populate_tables_on_startup"):
      _db_update_queue.put(("repopulate_tables",))
    _db_update_queue.put(("rebase_completed",))
    return True
  return False


class DBUpdateHooks(ida_idp.IDB_Hooks):
  """IDA IDB hooks to track changes."""

  # pylint: disable=invalid-name, redefined-builtin

  @skip_if_rebasing
  def renamed(
      self,
      ea: "idaapi.ea_t",
      new_name: str,
      local_name: bool = False,
      old_name: str = "",
      *args: Any,
  ) -> None:
    del local_name, args
    func_info = _get_func_info(ea)
    _db_update_queue.put((
        "renamed",
        ea,
        new_name,
        func_info,
        old_name,
    ))

  @skip_if_rebasing
  def local_types_changed(
      self, ltc=None, ordinal: int = 0, name: str | None = None, *args: Any
  ) -> None:
    global _local_types_dirty
    del ltc, name, args
    if ordinal > 0:
      info = _get_local_type_info(ordinal)
      _db_update_queue.put(("local_type_changed", ordinal, info))
    else:
      # IDA 7.7 passes no arguments, and later versions pass ordinal 0 when
      # they don't know which type changed, e.g., when a TIL is unloaded.
      _local_types_dirty = True

  @skip_if_rebasing
  def local_type_renamed(
      self, ordinal: int = 0, oldname: str = "", newname: str = "", *args: Any
  ) -> None:
    del oldname, newname, args
    info = _get_local_type_info(ordinal)
    _db_update_queue.put(("local_type_changed", ordinal, info))

  @skip_if_rebasing
  def func_added(self, pfn: idaapi.func_t, *args: Any) -> None:
    del args
    info = _get_func_info(pfn.start_ea)
    _db_update_queue.put(("func_added", pfn.start_ea, pfn.end_ea, info))

  @skip_if_rebasing
  def func_deleted(self, func_ea: "idaapi.ea_t", *args: Any) -> None:
    del args
    _db_update_queue.put(("func_deleted", func_ea))

  @skip_if_rebasing
  def set_func_start(
      self, pfn: idaapi.func_t, new_start: "idaapi.ea_t" = 0, *args: Any
  ) -> None:
    del args
    if pfn.start_ea != new_start:
      _db_update_queue.put(
          ("set_func_start", pfn.start_ea, pfn.end_ea, new_start)
      )

  @skip_if_rebasing
  def set_func_end(
      self, pfn: idaapi.func_t, new_end: "idaapi.ea_t" = 0, *args: Any
  ) -> None:
    del args
    if pfn.end_ea != new_end:
      _db_update_queue.put(("set_func_end", pfn.start_ea, pfn.end_ea, new_end))

  @skip_if_rebasing
  def func_updated(self, pfn: idaapi.func_t, *args: Any) -> None:
    del args
    info = _get_func_info(pfn.start_ea)
    _db_update_queue.put(("func_updated", pfn.start_ea, info))

  @skip_if_rebasing
  def segm_added(self, s: idaapi.segment_t, *args: Any) -> None:
    del s, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def segm_deleted(
      self,
      start_ea: "idaapi.ea_t" = 0,
      end_ea: "idaapi.ea_t" = 0,
      flags: int = 0,
      *args: Any,
  ) -> None:
    del start_ea, end_ea, flags, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def segm_name_changed(
      self, s: idaapi.segment_t, name: str = "", *args: Any
  ) -> None:
    del s, name, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def segm_moved(
      self,
      from_ea: "idaapi.ea_t" = 0,
      to: "idaapi.ea_t" = 0,
      size: int = 0,
      changed_netmap: bool = False,
      *args: Any,
  ) -> None:
    del from_ea, to, size, changed_netmap, args
    _trigger_rebase_invalidation()

  @skip_if_rebasing
  def segm_class_changed(
      self, s: idaapi.segment_t, sclass: str = "", *args: Any
  ) -> None:
    del s, sclass, args
    _db_update_queue.put(("segment_changed", _get_segments_info_inner()))

  @skip_if_rebasing
  def byte_patched(
      self, ea: "idaapi.ea_t" = 0, old_value: int = 0, *args: Any
  ) -> None:
    del old_value, args
    global _strings_dirty
    if _strings_dirty or not _is_table_populated("__internal_strings"):
      return

    if idc.get_func_attr(ea, idc.FUNCATTR_START) != idc.BADADDR:
      return

    # A string may not be a defined item, we can't use ida_bytes.get_item_head
    # to get the start address of the string.
    signed_ea = _to_signed_64(ea)
    try:
      with contextlib.closing(_get_ro_conn().cursor()) as cursor:
        cursor.execute(
            "SELECT start_ea, end_ea, strtype FROM __internal_strings WHERE"
            " start_ea <= ? AND end_ea > ? ORDER BY start_ea DESC LIMIT 1",
            (signed_ea, signed_ea),
        )
        row = cursor.fetchone()
    except (sqlite3.OperationalError, sqlite3.DatabaseError):
      _strings_dirty = True
      return

    if not row:
      if load_config().get("rebuild_strings_on_data_patch"):
        _strings_dirty = True
      return

    start_ea, end_ea, strtype = row
    start_ea = _from_signed_64(start_ea)
    end_ea = _from_signed_64(end_ea)
    byte_len = end_ea - start_ea
    if (
        strtype == getattr(ida_nalt, "STRTYPE_DECOMP", None)
        or ida_bytes.get_max_strlit_length(start_ea, strtype) != byte_len
    ):
      _strings_dirty = True
      return
    raw = ida_bytes.get_strlit_contents(start_ea, byte_len, strtype)
    if not raw:
      _strings_dirty = True
      return

    new_content = raw.decode("utf-8", "replace")
    _db_update_queue.put(("string_updated", start_ea, new_content))

  def allsegs_moved(self, info=None, *args: Any) -> None:
    del info, args
    _complete_rebase_if_auto_ok()

  # pylint: enable=invalid-name, redefined-builtin


class DBUpdateIDPHooks(ida_idp.IDP_Hooks):
  """IDA IDP hooks to track changes."""

  # pylint: disable=invalid-name, redefined-builtin

  @skip_if_rebasing(default_return=0)
  def ev_add_cref(
      self, _from: int = 0, to: int = 0, xref_type: int = 0, *args: Any
  ) -> int:
    del args
    if xref_type == idaapi.fl_F:
      return 0
    bounds = helper.get_func_bounds(_from)
    from_function_ea = bounds.start_ea if bounds else None
    _db_update_queue.put(("cref_added", _from, to, xref_type, from_function_ea))
    return 0

  @skip_if_rebasing(default_return=0)
  def ev_add_dref(
      self, _from: int = 0, to: int = 0, xref_type: int = 0, *args: Any
  ) -> int:
    del args
    if not _is_tid(_from):
      bounds = helper.get_func_bounds(_from)
      from_function_ea = bounds.start_ea if bounds else None
      _db_update_queue.put(
          ("dref_added", _from, to, xref_type, from_function_ea)
      )
    return 0

  @skip_if_rebasing(default_return=0)
  def ev_del_cref(
      self, _from: int = 0, to: int = 0, expand: bool = False, *args: Any
  ) -> int:
    del expand, args
    _db_update_queue.put(("cref_deleted", _from, to))
    return 0

  @skip_if_rebasing(default_return=0)
  def ev_del_dref(self, _from: int = 0, to: int = 0, *args: Any) -> int:
    del args
    if not _is_tid(_from):
      _db_update_queue.put(("dref_deleted", _from, to))
    return 0

  def ev_auto_queue_empty(self, _type: int | None = None, *args: Any) -> int:
    """One analysis queue is empty."""
    del _type, args
    _complete_rebase_if_auto_ok()
    return 0

  # pylint: enable=invalid-name, redefined-builtin


_db_initialized = False
_db_hooks = None
_db_idp_hooks = None
_worker_thread = None
_handlers = {}


def _signal_handler(sig, frame):
  """Signals the background worker to quit."""
  _db_update_queue.put(("quit",))
  if sig in _handlers and _handlers[sig]:
    _handlers[sig](sig, frame)


@idaread
def init_tables() -> bool:
  """Initializes the background worker and IDB hooks.

  Returns:
    True if the tables and hooks were newly initialized by this call, or False
    if initialization was already completed.
  """
  global _db_initialized, _db_hooks, _db_idp_hooks, _worker_thread
  global _image_min_ea

  if _db_initialized:
    return False

  _image_min_ea = idaapi.inf_get_min_ea()
  _worker_thread = threading.Thread(target=_db_worker, daemon=True)
  _worker_thread.start()

  signals_to_handle = [signal.SIGINT]
  if hasattr(signal, "SIGTERM"):
    signals_to_handle.append(signal.SIGTERM)
  # SIGBREAK is not always available on all platforms (e.g. Linux).
  if hasattr(signal, "SIGBREAK"):
    signals_to_handle.append(signal.SIGBREAK)  # type: ignore

  for sig in signals_to_handle:
    try:
      _handlers[sig] = signal.signal(sig, _signal_handler)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception("Could not register handler for signal %s: %s", sig, e)

  _db_hooks = DBUpdateHooks()
  _db_hooks.hook()
  _db_idp_hooks = DBUpdateIDPHooks()
  _db_idp_hooks.hook()

  config = load_config()
  if config.get("populate_tables_on_startup"):
    _populate_tables()

  _db_initialized = True
  return True


def close_tables() -> None:
  """Shuts down the background DB worker, unhooks IDA hooks, and closes SQLite connections."""
  global _db_initialized, _db_hooks, _db_idp_hooks, _worker_thread, _db_local
  global _db_version_checked, _populated_tables, _strings_dirty, _comments_dirty
  global _entries_fingerprint, _image_min_ea, _is_rebasing, _local_types_dirty

  # 1. Unhook IDA IDB/IDP hooks
  if _db_hooks is not None:
    with contextlib.suppress(Exception):
      _db_hooks.unhook()
    _db_hooks = None

  if _db_idp_hooks is not None:
    with contextlib.suppress(Exception):
      _db_idp_hooks.unhook()
    _db_idp_hooks = None

  # 2. Terminate background worker thread
  if _worker_thread is not None and _worker_thread.is_alive():
    _db_update_queue.put(("quit",))
    _worker_thread.join(timeout=2.0)
  _worker_thread = None

  # 3. Drain any remaining queued events
  while not _db_update_queue.empty():
    try:
      _db_update_queue.get_nowait()
      _db_update_queue.task_done()
    except (queue.Empty, ValueError):
      break

  # 4. Restore signal handlers
  for sig, handler in list(_handlers.items()):
    try:
      if handler is not None:
        signal.signal(sig, handler)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception("Could not restore signal handler for %s: %s", sig, e)
  _handlers.clear()

  # 5. Close all SQLite connections across all threads and reset module state
  # before deleting the scratch database (Windows cannot delete open files).
  with _db_write_lock:
    _db_local.close_all_connections()
    _db_local = SQLiteConnectionLocal()
    _populated_tables.clear()
    _db_initialized = False
    _db_version_checked = False
    _strings_dirty = False
    _comments_dirty = False
    _local_types_dirty = False
    _entries_fingerprint = None
    _image_min_ea = 0
    _is_rebasing = False
  _remove_scratch_dir()
