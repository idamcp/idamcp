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

"""Unit tests for the save API selection in ida_mcp.utils.save (no IDA)."""

import types
import unittest

from ida_mcp.utils import save

_IDB = "/work/sample.i64"
_PATH_TYPE_IDB = 3
_DBFL_TEMP = 0x40


def _loader(path=_IDB, save_ok=True, has_save=True, temp=False, calls=None):
  ns = types.SimpleNamespace(
      PATH_TYPE_IDB=_PATH_TYPE_IDB,
      DBFL_TEMP=_DBFL_TEMP,
      get_path=lambda pt: path if pt == _PATH_TYPE_IDB else "",
      is_database_flag=lambda flag: temp and flag == _DBFL_TEMP,
  )
  if has_save:

    def save_database(outfile, flags):
      calls.append(("ida_loader", outfile, flags))
      return save_ok

    ns.save_database = save_database
  return ns


def _idc(save_ok=True, has_save=True, calls=None):
  ns = types.SimpleNamespace()
  if has_save:

    def save_database(idbname, flags):
      calls.append(("idc", idbname, flags))
      return 1 if save_ok else 0

    ns.save_database = save_database
  return ns


def _kernwin(gui=False, action_ok=True, calls=None):

  def process_ui_action(name):
    calls.append(("ui_action", name))
    return action_ok

  return types.SimpleNamespace(
      is_idaq=lambda: gui, process_ui_action=process_ui_action
  )


class TestSaveCurrentDatabase(unittest.TestCase):
  """Tests for save.save_current_database."""

  def setUp(self):
    self.calls = []

  def run_save(self, loader=None, idc=None, kernwin=None):
    return save.save_current_database(
        loader or _loader(calls=self.calls),
        idc or _idc(calls=self.calls),
        kernwin or _kernwin(calls=self.calls),
    )

  def test_headless_uses_ida_loader_in_place(self):
    result = self.run_save()
    self.assertEqual(
        result, {"saved": True, "database_path": _IDB, "method": "ida_loader"}
    )
    self.assertEqual(self.calls, [("ida_loader", _IDB, 0)])

  def test_headless_falls_back_to_idc(self):
    result = self.run_save(loader=_loader(has_save=False, calls=self.calls))
    self.assertEqual(result["method"], "idc")
    self.assertEqual(self.calls, [("idc", _IDB, 0)])

  def test_headless_no_api(self):
    with self.assertRaisesRegex(RuntimeError, "No database save API"):
      self.run_save(
          loader=_loader(has_save=False, calls=self.calls),
          idc=_idc(has_save=False, calls=self.calls),
      )

  def test_headless_save_failure(self):
    with self.assertRaisesRegex(RuntimeError, "failed to save"):
      self.run_save(loader=_loader(save_ok=False, calls=self.calls))

  def test_gui_uses_save_action(self):
    result = self.run_save(kernwin=_kernwin(gui=True, calls=self.calls))
    self.assertEqual(result["method"], "ui_action")
    self.assertEqual(self.calls, [("ui_action", "SaveBase")])

  def test_gui_action_failure(self):
    with self.assertRaisesRegex(RuntimeError, "failed to save"):
      self.run_save(
          kernwin=_kernwin(gui=True, action_ok=False, calls=self.calls)
      )

  def test_gui_temporary_database_refused(self):
    with self.assertRaisesRegex(RuntimeError, "temporary"):
      self.run_save(
          loader=_loader(temp=True, calls=self.calls),
          kernwin=_kernwin(gui=True, calls=self.calls),
      )
    self.assertEqual(self.calls, [])

  def test_gui_without_temp_flag_api_still_saves(self):
    loader = _loader(calls=self.calls)
    del loader.is_database_flag
    result = self.run_save(
        loader=loader, kernwin=_kernwin(gui=True, calls=self.calls)
    )
    self.assertEqual(result["method"], "ui_action")

  def test_no_database_open(self):
    with self.assertRaisesRegex(RuntimeError, "No database"):
      self.run_save(loader=_loader(path="", calls=self.calls))
    self.assertEqual(self.calls, [])

  def test_missing_is_idaq_treated_as_headless(self):
    kernwin = _kernwin(calls=self.calls)
    del kernwin.is_idaq
    self.assertEqual(self.run_save(kernwin=kernwin)["method"], "ida_loader")


if __name__ == "__main__":
  unittest.main()
