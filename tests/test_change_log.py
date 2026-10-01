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

"""Unit tests for the database change log and get_changes_since (no IDA)."""

import enum
import inspect
import pathlib
import sys
import types
import unittest
from unittest import mock

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
  sys.path.insert(0, str(root_dir))

for module in ("ida_kernwin", "idaapi", "idc", "ida_idaapi"):
  if module not in sys.modules:
    sys.modules[module] = mock.MagicMock()

# pylint: disable=g-import-not-at-top
from ida_mcp.core import change_log
from ida_mcp.core import synchronization
from ida_mcp.tools import changes

# pylint: enable=g-import-not-at-top


def _edit(name="x"):
  return {"event": "renamed", "source": "tool", "tool": "t", "name": name}


def _analysis():
  return {"event": "code_created", "source": "analysis"}


class TestChangeLog(unittest.TestCase):
  """Tests for ChangeLog.record / since."""

  def test_revisions_increase_and_since_returns_later_events(self):
    log = change_log.ChangeLog()
    self.assertEqual([log.record(_edit(n)) for n in "abc"], [1, 2, 3])
    result = log.since(1)
    self.assertEqual([e["name"] for e in result["events"]], ["b", "c"])
    self.assertEqual([e["revision"] for e in result["events"]], [2, 3])
    self.assertEqual(result["revision"], 3)
    self.assertEqual(result["latest_revision"], 3)
    self.assertFalse(result["has_more"])
    self.assertFalse(result["truncated"])
    self.assertEqual(result["log_id"], log.log_id)

  def test_empty_log(self):
    result = change_log.ChangeLog().since(0)
    self.assertEqual(result["events"], [])
    self.assertEqual(result["revision"], 0)
    self.assertFalse(result["truncated"])

  def test_limit_pages_without_gaps(self):
    log = change_log.ChangeLog()
    for i in range(5):
      log.record(_edit(str(i)))
    first = log.since(0, limit=2)
    self.assertTrue(first["has_more"])
    self.assertEqual(first["revision"], 2)
    second = log.since(first["revision"], limit=2)
    third = log.since(second["revision"], limit=2)
    names = [e["name"] for r in (first, second, third) for e in r["events"]]
    self.assertEqual(names, ["0", "1", "2", "3", "4"])
    self.assertFalse(third["has_more"])

  def test_limit_is_clamped(self):
    log = change_log.ChangeLog()
    for _ in range(3):
      log.record(_edit())
    self.assertEqual(len(log.since(0, limit=0)["events"]), 1)
    self.assertEqual(len(log.since(0, limit=10**9)["events"]), 3)

  def test_analysis_events_are_filtered_by_default(self):
    log = change_log.ChangeLog()
    log.record(_edit("a"))
    log.record(_analysis())
    log.record(_edit("b"))
    log.record(_analysis())
    default = log.since(0)
    self.assertEqual([e["revision"] for e in default["events"]], [1, 3])
    # The trailing analysis event is skipped, not re-read next time.
    self.assertEqual(default["revision"], 4)
    everything = log.since(0, include_analysis=True)
    self.assertEqual(
        [e["revision"] for e in everything["events"]], [1, 2, 3, 4]
    )

  def test_analysis_flood_does_not_push_out_edits(self):
    log = change_log.ChangeLog(max_events=3)
    log.record(_edit("keep"))
    for _ in range(10):
      log.record(_analysis())
    result = log.since(0)
    self.assertEqual([e["name"] for e in result["events"]], ["keep"])
    self.assertFalse(result["truncated"])
    self.assertTrue(log.since(0, include_analysis=True)["truncated"])

  def test_dropped_edits_are_reported(self):
    log = change_log.ChangeLog(max_events=2)
    for i in range(4):
      log.record(_edit(str(i)))
    old = log.since(0)
    self.assertTrue(old["truncated"])
    self.assertEqual([e["name"] for e in old["events"]], ["2", "3"])
    self.assertFalse(log.since(2)["truncated"])

  def test_revision_from_another_log_starts_over(self):
    log = change_log.ChangeLog()
    log.record(_edit("a"))
    for stale in (50, -1):
      result = log.since(stale)
      self.assertTrue(result["truncated"])
      self.assertEqual([e["name"] for e in result["events"]], ["a"])

  def test_returned_events_are_copies(self):
    log = change_log.ChangeLog()
    log.record(_edit("a"))
    log.since(0)["events"][0]["name"] = "changed"
    self.assertEqual(log.since(0)["events"][0]["name"], "a")


class TestAttribution(unittest.TestCase):
  """Tests for attribute / current_source."""

  def setUp(self):
    auto = types.SimpleNamespace(AU_NONE=0, get_auto_state=lambda: 0)
    self.auto = auto
    patcher = mock.patch.dict(sys.modules, {"ida_auto": auto})
    patcher.start()
    self.addCleanup(patcher.stop)

  def test_outside_a_tool_call_the_source_is_ida(self):
    self.assertEqual(change_log.current_source(), {"source": "ida"})

  def test_inside_a_tool_call(self):
    with change_log.attribute("set_name"):
      self.assertEqual(
          change_log.current_source(), {"source": "tool", "tool": "set_name"}
      )
    self.assertIsNone(change_log.active_tool())

  def test_nested_calls_keep_the_outer_tool(self):
    with change_log.attribute("outer"):
      with change_log.attribute("inner"):
        self.assertEqual(change_log.active_tool(), "outer")
      self.assertEqual(change_log.active_tool(), "outer")
    self.assertIsNone(change_log.active_tool())

  def test_reset_after_exception(self):
    with self.assertRaises(ValueError):
      with change_log.attribute("t"):
        raise ValueError()
    self.assertIsNone(change_log.active_tool())

  def test_running_analysis_wins(self):
    self.auto.get_auto_state = lambda: 3
    with change_log.attribute("idapython_eval"):
      self.assertEqual(change_log.current_source(), {"source": "analysis"})

  def test_missing_auto_api_means_no_analysis(self):
    del self.auto.get_auto_state
    self.assertEqual(change_log.current_source(), {"source": "ida"})


class IDASafety(enum.IntEnum):
  """Distinct values; see tests/test_flush.py."""

  SAFE_NONE = 0
  SAFE_READ = 1
  SAFE_WRITE = 2


class TestIDACallAttribution(unittest.TestCase):
  """Changes made inside a tool call on the main thread name that tool."""

  def setUp(self):
    patchers = (
        mock.patch.object(synchronization, "IDASafety", IDASafety),
        mock.patch.object(synchronization, "_flush_after_write"),
        mock.patch.dict(
            sys.modules,
            {"ida_auto": types.SimpleNamespace(AU_NONE=0, get_auto_state=int)},
        ),
    )
    for patcher in patchers:
      patcher.start()
      self.addCleanup(patcher.stop)

  def test_tool_name_is_active_during_the_call(self):
    seen = []

    def rename_thing():
      seen.append(change_log.current_source())
      return "ok"

    call = synchronization._IDACall(rename_thing, IDASafety.SAFE_WRITE)
    call._runned()
    self.assertEqual(call.get_result(), "ok")
    self.assertEqual(seen, [{"source": "tool", "tool": "rename_thing"}])
    self.assertIsNone(change_log.active_tool())

  def test_cleared_when_the_tool_raises(self):
    def failing_tool():
      raise ValueError("bad")

    call = synchronization._IDACall(failing_tool, IDASafety.SAFE_READ)
    call._runned()
    with self.assertRaises(ValueError):
      call.get_result()
    self.assertIsNone(change_log.active_tool())


class _Hooks:
  """Stand-in for ida_idp.IDB_Hooks."""

  def __init__(self, *args, **kwargs):
    del args, kwargs
    self.hooked = False

  def hook(self):
    self.hooked = True
    return True

  def unhook(self):
    self.hooked = False
    return True


def _fake_ida(**overrides):
  funcs = {0x1010: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1100)}
  modules = {
      "ida_idp": types.SimpleNamespace(
          IDB_Hooks=_Hooks, LTC_ADDED=1, LTC_DELETED=2, LTC_EDITED=3
      ),
      "ida_auto": types.SimpleNamespace(AU_NONE=0, get_auto_state=int),
      "ida_bytes": types.SimpleNamespace(
          is_mapped=lambda ea: ea < 0x10000,
          get_cmt=lambda ea, rpt: f"cmt@{ea:#x}/{int(rpt)}",
          get_byte=lambda ea: 0x90,
      ),
      "ida_funcs": types.SimpleNamespace(get_func=funcs.get),
      "ida_name": types.SimpleNamespace(get_name=lambda ea: f"sub_{ea:X}"),
      "ida_range": types.SimpleNamespace(
          RANGE_KIND_FUNC=1, RANGE_KIND_SEGMENT=2
      ),
      "ida_segment": types.SimpleNamespace(get_segm_name=lambda s: ".text"),
      "idc": types.SimpleNamespace(get_type=lambda ea: "int __cdecl(void)"),
  }
  modules.update(overrides)
  return mock.patch.dict(sys.modules, modules)


class TestHook(unittest.TestCase):
  """Tests for the events the IDB hook records."""

  def setUp(self):
    patcher = _fake_ida()
    patcher.start()
    self.addCleanup(patcher.stop)
    self.events = []
    self.hook = change_log.make_hook(self.events.append)

  def test_rename_inside_a_function(self):
    self.hook.renamed(0x1010, "new", False, "old")
    self.assertEqual(
        self.events,
        [{
            "event": "renamed",
            "source": "ida",
            "address": "0x1010",
            "name": "new",
            "old_name": "old",
            "function": "0x1000",
        }],
    )

  def test_rename_attributed_to_the_running_tool(self):
    with change_log.attribute("rename_address"):
      self.hook.renamed(0x2000, "g", False, "")
    self.assertEqual(self.events[0]["source"], "tool")
    self.assertEqual(self.events[0]["tool"], "rename_address")
    self.assertNotIn("function", self.events[0])
    self.assertNotIn("old_name", self.events[0])

  def test_rename_of_a_type_id_is_skipped(self):
    self.hook.renamed(0xFF00000000000010, "field", False, "")
    self.assertEqual(self.events, [])

  def test_rename_with_older_signature(self):
    self.hook.renamed(0x1010, "new", True)
    self.assertTrue(self.events[0]["local"])
    self.assertNotIn("old_name", self.events[0])

  def test_comment(self):
    self.hook.cmt_changed(0x1010, True)
    self.assertEqual(self.events[0]["event"], "comment_changed")
    self.assertEqual(self.events[0]["comment"], "cmt@0x1010/1")
    self.assertTrue(self.events[0]["repeatable"])

  def test_function_and_segment_comments(self):
    rng = types.SimpleNamespace(start_ea=0x1000)
    self.hook.range_cmt_changed(1, rng, "f", False)
    self.hook.range_cmt_changed(2, rng, "s", True)
    self.hook.range_cmt_changed(0, rng, "?", True)
    self.assertEqual(
        [(e["event"], e["comment"]) for e in self.events],
        [("function_comment_changed", "f"), ("segment_comment_changed", "s")],
    )

  def test_function_deleted_keeps_the_old_name(self):
    pfn = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
    self.hook.func_added(pfn)
    self.hook.deleting_func(pfn)
    self.hook.func_deleted(0x1000)
    self.assertEqual(
        self.events[0],
        {
            "event": "function_added",
            "source": "ida",
            "address": "0x1000",
            "end": "0x1100",
        },
    )
    self.assertEqual(self.events[1]["event"], "function_deleted")
    self.assertEqual(self.events[1]["name"], "sub_1000")

  def test_function_bounds_only_when_changed(self):
    pfn = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
    self.hook.set_func_start(pfn, 0x1000)
    self.hook.set_func_end(pfn, 0x1100)
    self.assertEqual(self.events, [])
    self.hook.set_func_start(pfn, 0x1004)
    self.hook.set_func_end(pfn, 0x1200)
    self.assertEqual(self.events[0]["new_start"], "0x1004")
    self.assertEqual(self.events[1]["new_end"], "0x1200")

  def test_type_operand_and_local_types(self):
    self.hook.ti_changed(0x1010, b"", b"")
    self.hook.op_type_changed(0x1010, 1)
    self.hook.local_types_changed(3, 7, "MY_STRUCT")
    self.hook.local_types_changed()  # IDA versions without arguments
    self.assertEqual(self.events[0]["type"], "int __cdecl(void)")
    self.assertEqual(self.events[0]["function"], "0x1000")
    self.assertEqual(self.events[1]["operand"], 1)
    self.assertEqual(
        self.events[2],
        {
            "event": "local_type_changed",
            "source": "ida",
            "change": "edited",
            "ordinal": 7,
            "type_name": "MY_STRUCT",
        },
    )
    self.assertEqual(
        self.events[3], {"event": "local_type_changed", "source": "ida"}
    )

  def test_patch_and_item_changes(self):
    self.hook.byte_patched(0x1010, 0xCC)
    self.hook.make_code(types.SimpleNamespace(ea=0x1010, size=2))
    self.hook.make_data(0x3000, 0, 0, 8)
    self.hook.destroyed_items(0x3000, 0x3008, False)
    self.assertEqual(self.events[0]["old_value"], 0xCC)
    self.assertEqual(self.events[0]["new_value"], 0x90)
    self.assertEqual(
        [(e["event"], e["address"]) for e in self.events[1:]],
        [
            ("code_created", "0x1010"),
            ("data_created", "0x3000"),
            ("items_undefined", "0x3000"),
        ],
    )

  def test_segments_and_stack_variables(self):
    seg = types.SimpleNamespace(start_ea=0x1000, end_ea=0x2000)
    self.hook.segm_added(seg)
    self.hook.segm_name_changed(seg, ".code")
    self.hook.segm_end_changed(seg, 0x1800)
    self.hook.segm_deleted(0x1000, 0x2000, 0)
    self.hook.segm_moved(0x1000, 0x5000, 0x1000, False)
    self.hook.frame_udm_renamed(
        0x1000, types.SimpleNamespace(name="count"), "var_4"
    )
    self.assertEqual(
        [e["event"] for e in self.events],
        [
            "segment_added",
            "segment_renamed",
            "segment_bounds_changed",
            "segment_deleted",
            "segment_moved",
            "stack_variable_renamed",
        ],
    )
    self.assertEqual(self.events[1]["segment"], ".code")
    self.assertEqual(self.events[4]["new_address"], "0x5000")
    self.assertEqual(self.events[5]["old_name"], "var_4")

  def test_analysis_events_skip_the_function_lookup(self):
    with _fake_ida(
        ida_auto=types.SimpleNamespace(AU_NONE=0, get_auto_state=lambda: 5),
        ida_funcs=types.SimpleNamespace(get_func=mock.Mock()),
    ):
      self.hook.renamed(0x1010, "new", False, "old")
      sys.modules["ida_funcs"].get_func.assert_not_called()
    self.assertEqual(self.events[0]["source"], "analysis")
    self.assertNotIn("function", self.events[0])

  def test_hook_errors_do_not_reach_ida(self):
    def fail(event):
      raise RuntimeError(event)

    hook = change_log.make_hook(fail)
    hook.cmt_changed(0x1010, False)  # does not raise


class TestStartStop(unittest.TestCase):
  """Tests for start / stop / changes_since."""

  def setUp(self):
    patcher = _fake_ida()
    patcher.start()
    self.addCleanup(patcher.stop)
    self.addCleanup(change_log.stop)
    change_log.stop()

  def test_start_installs_once(self):
    self.assertTrue(change_log.start())
    self.assertTrue(change_log._hook.hooked)
    self.assertFalse(change_log.start())

  def test_events_reach_the_log(self):
    change_log.start()
    change_log._hook.cmt_changed(0x1010, False)
    result = change_log.changes_since(0, 10, False)
    self.assertEqual(result["events"][0]["event"], "comment_changed")

  def test_stop_unhooks_and_restarts_with_a_new_log(self):
    change_log.start()
    hook, log_id = change_log._hook, change_log._log.log_id
    change_log.stop()
    self.assertFalse(hook.hooked)
    with self.assertRaises(RuntimeError):
      change_log.changes_since(0, 10, False)
    change_log.start()
    self.assertNotEqual(change_log._log.log_id, log_id)

  def test_refused_hook(self):
    class Refusing(_Hooks):

      def hook(self):
        return False

    sys.modules["ida_idp"].IDB_Hooks = Refusing
    with self.assertRaisesRegex(RuntimeError, "refused"):
      change_log.start()
    self.assertIsNone(change_log._hook)


class TestTool(unittest.TestCase):
  """Tests for the get_changes_since tool body."""

  def setUp(self):
    patcher = _fake_ida()
    patcher.start()
    self.addCleanup(patcher.stop)
    self.addCleanup(change_log.stop)
    change_log.stop()
    self.tool = inspect.unwrap(changes.get_changes_since)

  def test_first_call_starts_recording(self):
    first = self.tool()
    self.assertTrue(first["started"])
    self.assertEqual(first["events"], [])
    change_log._hook.renamed(0x1010, "a", False, "b")
    second = self.tool(revision=first["revision"])
    self.assertNotIn("started", second)
    self.assertEqual([e["name"] for e in second["events"]], ["a"])
    self.assertEqual(self.tool(revision=second["revision"])["events"], [])

  def test_refused_hook_is_a_tool_error(self):
    with mock.patch.object(
        change_log, "start", side_effect=RuntimeError("refused")
    ):
      with self.assertRaisesRegex(Exception, "refused") as cm:
        self.tool()
    self.assertEqual(type(cm.exception).__name__, "ToolError")

  def test_tool_is_registered(self):
    self.assertEqual(changes.get_changes_since.__name__, "get_changes_since")
    self.assertFalse(changes.get_changes_since.unsafe)


if __name__ == "__main__":
  unittest.main()
