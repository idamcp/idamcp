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

"""IDA 9.4 specific helper functions."""

from typing import Iterator
import ida_frame
import ida_funcs
import ida_hexrays
from ida_mcp.utils.helper_common import CalleeVisitor
from ida_mcp.utils.helper_common import FuncBounds
from ida_mcp.utils.helper_common import SegmentInfo
import ida_segment
import ida_typeinf
import idaapi
import idc
from shared.rpc import ToolError
from shared.types import Function


def get_callees(func_start: int) -> list[Function]:
  """Get all functions called by the function at func_start."""
  if not ida_hexrays.init_hexrays_plugin():
    raise ToolError("Hex-Rays decompiler is not available/loaded.")

  if not get_func_bounds(func_start):
    raise ToolError(f"No function found containing address {func_start:#x}")

  hf = ida_hexrays.hexrays_failure_t()
  dcr = ida_hexrays.decomp_ranges_t(func_start)
  mba = ida_hexrays.gen_microcode(
      dcr,
      hf,
      ida_hexrays.mlist_t(),
      ida_hexrays.DECOMP_WARNINGS,
      ida_hexrays.MMAT_LVARS,
  )

  if not mba:
    raise ToolError(f"Failed to generate microcode: {hf.desc()}")

  visitor = CalleeVisitor()
  mba.for_all_insns(visitor)

  return visitor.callees


def get_func(ea: int) -> "ida_funcs.func_entry_info_t | None":
  """Get function entry structure."""
  fi = ida_funcs.func_entry_info_t()
  if ida_funcs.get_func_entry_info(fi, ea):
    return fi
  return None


get_func_start = ida_funcs.get_func_start


def get_func_bounds(ea: int) -> FuncBounds | None:
  """Get FuncBounds of function containing ea, or None."""
  if (start_ea := ida_funcs.get_func_start(ea)) == idaapi.BADADDR:
    return None
  end_ea = idc.get_func_attr(start_ea, idc.FUNCATTR_END)
  return FuncBounds(start_ea, end_ea)


def get_next_func_bounds(ea: int) -> FuncBounds | None:
  """Get FuncBounds of the next function, or None."""
  if (start_ea := ida_funcs.get_next_func_ea(ea)) == idaapi.BADADDR:
    return None

  end_ea = idc.get_func_attr(start_ea, idc.FUNCATTR_END)
  return FuncBounds(start_ea, end_ea)


def get_func_flags(ea: int) -> int | None:
  """Get function flags without triggering deprecation."""
  if (start_ea := ida_funcs.get_func_start(ea)) != idaapi.BADADDR:
    return ida_funcs.get_func_flags(start_ea)
  return None


def get_func_frame(out_tif: ida_typeinf.tinfo_t, ea: int) -> bool:
  """Get function stack frame tinfo_t without triggering deprecations."""
  return ida_frame.get_func_frame_ea(out_tif, ea)


def is_funcarg_off(ea: int, frameoff: int) -> bool:
  """Check if frame offset belongs to an argument without deprecations."""
  return ida_frame.is_funcarg_off_ea(ea, frameoff)


def soff_to_fpoff(ea: int, soff: int) -> int:
  """Convert stack offset to frame pointer offset without deprecations."""
  return ida_frame.soff_to_fpoff_ea(ea, soff)


def define_stkvar(
    ea: int, name: str, off: int, tif: ida_typeinf.tinfo_t
) -> bool:
  """Define a stack variable without triggering deprecations."""
  return ida_frame.define_stkvar_ea(ea, name, off, tif)


def set_frame_member_type(
    ea: int, offset: int, tif: ida_typeinf.tinfo_t
) -> bool:
  """Set stack frame member type without triggering deprecations."""
  return ida_frame.set_frame_member_type_ea(ea, offset, tif)


def delete_frame_members(ea: int, start_offset: int, end_offset: int) -> bool:
  """Delete frame members without triggering deprecations."""
  return ida_frame.delete_frame_members_ea(ea, start_offset, end_offset)


def iter_function_addresses() -> Iterator[int]:
  """Iterate start addresses of all functions without triggering deprecations."""
  qty = ida_funcs.get_func_qty()
  for i in range(qty):
    yield ida_funcs.get_func_ea_by_num(i)


def get_segments() -> list[SegmentInfo]:
  """Retrieves all segments in a backward-compatible manner without deprecations."""
  segs = []
  qty = ida_segment.get_segm_qty()
  si = ida_segment.segment_info_t()
  for i in range(qty):
    if ida_segment.get_segment_info_by_num(
        si, i, ida_segment.GSI_NAME | ida_segment.GSI_SCLASS
    ):
      segs.append(
          SegmentInfo(
              start_ea=si.start_ea,
              end_ea=si.end_ea,
              name=si.get_name(),
              sclass=si.get_sclass(),
              perm=si.get_perm(),
          )
      )
  return segs


def get_segm_name(ea: int) -> str:
  """Get segment name for an address without triggering deprecations."""
  return ida_segment.get_segment_name(ea)


def iter_func_items(ea: int) -> Iterator[int]:
  """Iterate function items without triggering deprecations."""
  fii = ida_funcs.function_item_iterator_t()
  if fii.set(ea) and fii.first():
    yield fii.current()
    while fii.next_addr():
      yield fii.current()


def update_func_flags(
    ea: int, set_flags: int = 0, clear_flags: int = 0
) -> bool:
  """Update function flags safely across IDA SDK versions."""
  fi = ida_funcs.func_entry_info_t()
  if not ida_funcs.get_func_entry_info(fi, ea):
    return False
  cur_flags = fi.get_flags()
  new_flags = (cur_flags | set_flags) & ~clear_flags
  fi.set_flags(new_flags)
  return ida_funcs.set_func_entry_info(fi)


__all__ = [
    "define_stkvar",
    "delete_frame_members",
    "get_callees",
    "get_func",
    "get_func_bounds",
    "get_next_func_bounds",
    "get_func_flags",
    "get_func_frame",
    "get_func_start",
    "get_segments",
    "get_segm_name",
    "is_funcarg_off",
    "iter_func_items",
    "iter_function_addresses",
    "set_frame_member_type",
    "soff_to_fpoff",
    "update_func_flags",
]
