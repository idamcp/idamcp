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

"""In-memory log of database changes, read with get_changes_since.

Nothing is recorded until the first get_changes_since call installs the IDB
hook, so databases that never use the tool pay nothing. Each change gets a
revision number that increases by one per change. Changes made while an MCP
tool call runs on IDA's main thread are attributed to that tool; changes made
while the auto-analyzer is working are attributed to analysis; everything else
(the GUI user, plugins, scripts run from IDA) is attributed to "ida".

IDA modules are imported lazily, so this module can be imported without IDA.
"""

import collections
import contextlib
import functools
import heapq
import logging
import threading
from typing import Any, Callable, Iterator
import uuid

logger = logging.getLogger(__name__)

# Events kept per stream (edits and analysis are kept separately, so a
# reanalysis cannot push edits out of the log).
MAX_EVENTS = 10000
MAX_LIMIT = 1000

SOURCE_TOOL = "tool"
SOURCE_IDA = "ida"
SOURCE_ANALYSIS = "analysis"

# Name of the MCP tool running on IDA's main thread, if any. Only the main
# thread sets it, and IDA runs one request at a time there.
_active_tool: str | None = None


@contextlib.contextmanager
def attribute(tool_name: str) -> Iterator[None]:
  """Attributes changes made inside the block to tool_name.

  Nested calls keep the outermost tool.

  Args:
    tool_name: Name of the MCP tool being executed.

  Yields:
    None.
  """
  global _active_tool
  if _active_tool is not None:
    yield
    return
  _active_tool = tool_name
  try:
    yield
  finally:
    _active_tool = None


def active_tool() -> str | None:
  return _active_tool


class _Stream:
  """A bounded, revision-ordered list of events."""

  def __init__(self, max_events: int):
    self.events: collections.deque[dict[str, Any]] = collections.deque(
        maxlen=max_events
    )
    # Highest revision pushed out of this stream because it was full.
    self.dropped_upto = 0

  def append(self, event: dict[str, Any]) -> None:
    if len(self.events) == self.events.maxlen and self.events:
      self.dropped_upto = self.events[0]["revision"]
    self.events.append(event)


class ChangeLog:
  """Revision-numbered change events, kept in memory."""

  def __init__(self, max_events: int = MAX_EVENTS):
    self._lock = threading.Lock()
    self._revision = 0
    self._edits = _Stream(max_events)
    self._analysis = _Stream(max_events)
    # Changes when the log restarts (new process, plugin reload), so a client
    # can tell that its saved revision belongs to another log.
    self.log_id = uuid.uuid4().hex[:12]

  @property
  def revision(self) -> int:
    with self._lock:
      return self._revision

  def record(self, event: dict[str, Any]) -> int:
    """Adds an event and returns its revision."""
    with self._lock:
      self._revision += 1
      stored = {"revision": self._revision, **event}
      if event.get("source") == SOURCE_ANALYSIS:
        self._analysis.append(stored)
      else:
        self._edits.append(stored)
      return self._revision

  def since(
      self,
      revision: int,
      limit: int = 200,
      include_analysis: bool = False,
  ) -> dict[str, Any]:
    """Returns the events after revision, oldest first.

    Args:
      revision: The revision returned by the previous call (0 for all kept
        events).
      limit: Maximum number of events to return.
      include_analysis: Whether to include changes made by the auto-analyzer.

    Returns:
      A dict with log_id, revision (pass it to the next call), latest_revision,
      events, has_more and truncated.
    """
    limit = max(1, min(int(limit), MAX_LIMIT))
    revision = int(revision)
    with self._lock:
      latest = self._revision
      streams = [self._edits]
      if include_analysis:
        streams.append(self._analysis)
      # A revision from the future belongs to another log: start over.
      restarted = revision > latest or revision < 0
      start = 0 if restarted else revision
      truncated = restarted or any(s.dropped_upto > start for s in streams)
      merged = heapq.merge(
          *(s.events for s in streams), key=lambda e: e["revision"]
      )
      events = []
      has_more = False
      for event in merged:
        if event["revision"] <= start:
          continue
        if len(events) == limit:
          has_more = True
          break
        events.append(dict(event))
      next_revision = events[-1]["revision"] if has_more else latest
    return {
        "log_id": self.log_id,
        "revision": next_revision,
        "latest_revision": latest,
        "events": events,
        "has_more": has_more,
        "truncated": truncated,
    }


def _analysis_running() -> bool:
  """Whether the auto-analyzer is processing an item right now."""
  try:
    import ida_auto  # pylint: disable=g-import-not-at-top

    return ida_auto.get_auto_state() != ida_auto.AU_NONE
  except Exception:  # pylint: disable=broad-exception-caught
    return False


def current_source() -> dict[str, str]:
  """Source fields for an event that happens now."""
  if _analysis_running():
    return {"source": SOURCE_ANALYSIS}
  tool = _active_tool
  if tool is not None:
    return {"source": SOURCE_TOOL, "tool": tool}
  return {"source": SOURCE_IDA}


def _hex(ea: Any) -> str:
  return hex(int(ea))


def _safe(method: Callable[..., None]) -> Callable[..., None]:
  """Keeps a failing hook from raising into IDA."""

  @functools.wraps(method)
  def wrapper(self, *args: Any) -> None:
    try:
      method(self, *args)
    except Exception:  # pylint: disable=broad-exception-caught
      logger.debug("change log hook %s failed", method.__name__, exc_info=True)

  return wrapper


def _function_of(ea: int) -> str | None:
  import ida_funcs  # pylint: disable=g-import-not-at-top

  pfn = ida_funcs.get_func(ea)
  return _hex(pfn.start_ea) if pfn is not None else None


def _local_type_change_name(ltc: Any) -> str | None:
  import ida_idp  # pylint: disable=g-import-not-at-top

  for name in (
      "ADDED",
      "DELETED",
      "EDITED",
      "ALIASED",
      "COMPILER",
      "TIL_LOADED",
      "TIL_UNLOADED",
      "TIL_COMPACTED",
  ):
    value = getattr(ida_idp, f"LTC_{name}", None)
    if value is not None and ltc == value:
      return name.lower()
  return None


def make_hook(sink: Callable[[dict[str, Any]], Any]) -> Any:
  """Creates the IDB hook that sends change events to sink.

  Methods for events that an IDA version doesn't have are never called, so the
  same class works across versions. Arguments that older versions don't pass
  have defaults.

  Args:
    sink: Called with each event dict (event, source, and event fields).

  Returns:
    An unhooked ida_idp.IDB_Hooks instance.
  """
  import ida_idp  # pylint: disable=g-import-not-at-top

  class ChangeHooks(ida_idp.IDB_Hooks):
    """Records user-visible database changes."""

    # pylint: disable=invalid-name

    def __init__(self):
      super().__init__()
      self._deleting_names: dict[int, str] = {}

    def _emit(self, event: str, with_function: int | None = None, **fields):
      source = current_source()
      record = {"event": event, **source}
      record.update({k: v for k, v in fields.items() if v is not None})
      # Skip the function lookup for analysis events: there can be many.
      if with_function is not None and source["source"] != SOURCE_ANALYSIS:
        func = _function_of(with_function)
        if func is not None:
          record["function"] = func
      sink(record)

    @_safe
    def renamed(self, ea=0, new_name="", local_name=False, old_name="", *_):
      import ida_bytes  # pylint: disable=g-import-not-at-top

      # Type and member ids are renamed through this event too; those changes
      # are reported by local_types_changed.
      if not ida_bytes.is_mapped(ea):
        return
      self._emit(
          "renamed",
          with_function=ea,
          address=_hex(ea),
          name=new_name or "",
          old_name=old_name or None,
          local=bool(local_name) or None,
      )

    @_safe
    def cmt_changed(self, ea=0, repeatable_cmt=False, *_):
      import ida_bytes  # pylint: disable=g-import-not-at-top

      self._emit(
          "comment_changed",
          with_function=ea,
          address=_hex(ea),
          comment=ida_bytes.get_cmt(ea, bool(repeatable_cmt)) or "",
          repeatable=bool(repeatable_cmt),
      )

    @_safe
    def extra_cmt_changed(self, ea=0, line_idx=0, cmt="", *_):
      self._emit(
          "extra_comment_changed",
          address=_hex(ea),
          line=int(line_idx),
          comment=cmt or "",
      )

    @_safe
    def range_cmt_changed(
        self, kind=None, a=None, cmt="", repeatable=False, *_
    ):
      import ida_range  # pylint: disable=g-import-not-at-top

      if a is None:
        return
      if kind == getattr(ida_range, "RANGE_KIND_FUNC", None):
        event = "function_comment_changed"
      elif kind == getattr(ida_range, "RANGE_KIND_SEGMENT", None):
        event = "segment_comment_changed"
      else:
        return
      self._emit(
          event,
          address=_hex(a.start_ea),
          comment=cmt or "",
          repeatable=bool(repeatable),
      )

    @_safe
    def func_added(self, pfn=None, *_):
      if pfn is None:
        return
      self._emit(
          "function_added", address=_hex(pfn.start_ea), end=_hex(pfn.end_ea)
      )

    @_safe
    def deleting_func(self, pfn=None, *_):
      import ida_name  # pylint: disable=g-import-not-at-top

      if pfn is not None:
        self._deleting_names[pfn.start_ea] = ida_name.get_name(pfn.start_ea)

    @_safe
    def func_deleted(self, func_ea=0, *_):
      name = self._deleting_names.pop(func_ea, None)
      self._emit("function_deleted", address=_hex(func_ea), name=name or None)

    @_safe
    def set_func_start(self, pfn=None, new_start=0, *_):
      if pfn is None or pfn.start_ea == new_start:
        return
      self._emit(
          "function_start_changed",
          address=_hex(pfn.start_ea),
          new_start=_hex(new_start),
      )

    @_safe
    def set_func_end(self, pfn=None, new_end=0, *_):
      if pfn is None or pfn.end_ea == new_end:
        return
      self._emit(
          "function_end_changed",
          address=_hex(pfn.start_ea),
          new_end=_hex(new_end),
      )

    @_safe
    def ti_changed(self, ea=0, *_):
      import idc  # pylint: disable=g-import-not-at-top

      self._emit(
          "type_changed",
          with_function=ea,
          address=_hex(ea),
          type=idc.get_type(ea) or "",
      )

    @_safe
    def op_type_changed(self, ea=0, n=0, *_):
      self._emit(
          "operand_type_changed",
          with_function=ea,
          address=_hex(ea),
          operand=int(n),
      )

    @_safe
    def local_types_changed(self, ltc=None, ordinal=0, name=None, *_):
      self._emit(
          "local_type_changed",
          change=_local_type_change_name(ltc),
          ordinal=int(ordinal) or None,
          type_name=name or None,
      )

    @_safe
    def byte_patched(self, ea=0, old_value=0, *_):
      import ida_bytes  # pylint: disable=g-import-not-at-top

      self._emit(
          "byte_patched",
          with_function=ea,
          address=_hex(ea),
          old_value=int(old_value),
          new_value=ida_bytes.get_byte(ea),
      )

    @_safe
    def make_code(self, insn=None, *_):
      if insn is None:
        return
      self._emit("code_created", address=_hex(insn.ea), size=int(insn.size))

    @_safe
    def make_data(self, ea=0, flags=0, tid=0, length=0, *_):
      del flags, tid
      self._emit("data_created", address=_hex(ea), size=int(length))

    @_safe
    def destroyed_items(self, ea1=0, ea2=0, *_):
      self._emit("items_undefined", address=_hex(ea1), end=_hex(ea2))

    def _segment_fields(self, s) -> dict[str, Any]:
      import ida_segment  # pylint: disable=g-import-not-at-top

      return {
          "address": _hex(s.start_ea),
          "end": _hex(s.end_ea),
          "segment": ida_segment.get_segm_name(s) or None,
      }

    @_safe
    def segm_added(self, s=None, *_):
      if s is not None:
        self._emit("segment_added", **self._segment_fields(s))

    @_safe
    def segm_deleted(self, start_ea=0, end_ea=0, *_):
      self._emit("segment_deleted", address=_hex(start_ea), end=_hex(end_ea))

    @_safe
    def segm_name_changed(self, s=None, name="", *_):
      if s is not None:
        fields = self._segment_fields(s)
        fields["segment"] = name or fields["segment"]
        self._emit("segment_renamed", **fields)

    @_safe
    def segm_start_changed(self, s=None, *_):
      if s is not None:
        self._emit("segment_bounds_changed", **self._segment_fields(s))

    @_safe
    def segm_end_changed(self, s=None, *_):
      if s is not None:
        self._emit("segment_bounds_changed", **self._segment_fields(s))

    @_safe
    def segm_moved(self, from_ea=0, to_ea=0, size=0, *_):
      self._emit(
          "segment_moved",
          address=_hex(from_ea),
          new_address=_hex(to_ea),
          size=int(size),
      )

    @_safe
    def frame_udm_renamed(self, func_ea=0, udm=None, oldname="", *_):
      self._emit(
          "stack_variable_renamed",
          function=_hex(func_ea),
          name=getattr(udm, "name", None) or None,
          old_name=oldname or None,
      )

    # pylint: enable=invalid-name

  return ChangeHooks()


_state_lock = threading.Lock()
_log: ChangeLog | None = None
_hook: Any = None


def start() -> bool:
  """Installs the IDB hook if needed. Returns True if this call installed it.

  Must run on IDA's main thread.

  Raises:
    RuntimeError: IDA refused the hook.
  """
  global _log, _hook
  with _state_lock:
    if _hook is not None:
      return False
    log = ChangeLog()
    hook = make_hook(log.record)
    if not hook.hook():
      raise RuntimeError("IDA refused the change log hook")
    _log, _hook = log, hook
    return True


def stop() -> None:
  """Removes the hook and forgets the log (plugin unload)."""
  global _log, _hook
  with _state_lock:
    if _hook is not None:
      with contextlib.suppress(Exception):
        _hook.unhook()
    _log, _hook = None, None


def changes_since(
    revision: int, limit: int, include_analysis: bool
) -> dict[str, Any]:
  """Reads the log; start() must have been called."""
  with _state_lock:
    log = _log
  if log is None:
    raise RuntimeError("change log is not started")
  return log.since(revision, limit, include_analysis)
