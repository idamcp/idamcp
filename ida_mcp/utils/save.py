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

"""Saves the current IDA database, probing which save API is available.

The IDA modules are passed in rather than imported so the selection logic can
be unit-tested without IDA. Only the standard library is imported here.
"""

from typing import Any


def save_current_database(
    ida_loader: Any, idc: Any, ida_kernwin: Any
) -> dict[str, Any]:
  """Saves the open database in place and returns what was done.

  In the IDA GUI this triggers the "SaveBase" UI action (the same as
  File > Save), so IDA's own save logic and UI state apply. In headless
  (idalib) mode it calls `ida_loader.save_database(path, 0)`, falling back to
  `idc.save_database(path, 0)` if the former is missing. Flags 0 keep the
  database's current flags.

  Args:
    ida_loader: the `ida_loader` module.
    idc: the `idc` module.
    ida_kernwin: the `ida_kernwin` module.

  Returns:
    A dict with `saved` (always True), `database_path` and `method`.

  Raises:
    RuntimeError: if no database is open, the GUI database is temporary, no
      save API is available, or IDA reports that the save failed.
  """
  path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
  if not path:
    raise RuntimeError("No database is currently open.")

  is_gui = bool(getattr(ida_kernwin, "is_idaq", lambda: False)())
  if is_gui:
    is_database_flag = getattr(ida_loader, "is_database_flag", None)
    dbfl_temp = getattr(ida_loader, "DBFL_TEMP", None)
    if (
        is_database_flag is not None
        and dbfl_temp is not None
        and is_database_flag(dbfl_temp)
    ):
      raise RuntimeError(
          "The database is temporary. Use File > Save as in the IDA GUI first."
      )
    method = "ui_action"
    saved = bool(ida_kernwin.process_ui_action("SaveBase"))
  elif hasattr(ida_loader, "save_database"):
    method = "ida_loader"
    saved = bool(ida_loader.save_database(path, 0))
  elif hasattr(idc, "save_database"):
    method = "idc"
    saved = bool(idc.save_database(path, 0))
  else:
    raise RuntimeError("No database save API is available in this IDA build.")

  if not saved:
    raise RuntimeError(f"IDA failed to save the database ({method}): {path}")
  return {"saved": True, "database_path": path, "method": method}
