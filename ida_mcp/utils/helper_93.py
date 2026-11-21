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

"""IDA 9.3 specific helper functions."""

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
import idautils
from shared.rpc import ToolError
from shared.types import Function

get_func = ida_funcs.get_func


def get_callees(func_start: int) -> list[Function]:
  """Get all functions called by the function at func_start."""
  if not ida_hexrays.init_hexrays_plugin():
    raise ToolError("Hex-Rays decompiler is not available/loaded.")

  if not get_func_bounds(func_start):
    raise ToolError(f"No function found containing address {func_start:#x}")

  hf = ida_hexrays.hexrays_failure_t()
  func = get_func(func_start)
  if not func:
    raise ToolError(f"No function found containing address {func_start:#x}")
  mbr = ida_hexrays.mba_ranges_t(func)
  mba = ida_hexrays.gen_microcode(
      mbr,
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


def get_func_start(ea: int) -> int:
  """Get start address of function containing ea, or BADADDR."""
  if (func := get_func(ea)) is not None:
    return func.start_ea
  return idaapi.BADADDR


def get_func_bounds(ea: int) -> FuncBounds | None:
  """Get FuncBounds of function containing ea, or None."""
  if (func := get_func(ea)) is not None:
    return FuncBounds(func.start_ea, func.end_ea)
  return None


def get_next_func_bounds(ea: int) -> FuncBounds | None:
  """Get FuncBounds of the next function, or None."""
  if (func := ida_funcs.get_next_func(ea)) is not None:
    return FuncBounds(func.start_ea, func.end_ea)
  return None


def get_func_flags(ea: int) -> int | None:
  """Get function flags without triggering deprecation."""
  if (func := get_func(ea)) is not None:
    return func.flags  # type: ignore
  return None


def get_func_frame(out_tif: ida_typeinf.tinfo_t, ea: int) -> bool:
  """Get function stack frame tinfo_t without triggering deprecations."""
  if (func := get_func(ea)) is not None:
    if hasattr(ida_frame, "get_func_frame"):
      return ida_frame.get_func_frame(out_tif, func)
  return False


def is_funcarg_off(ea: int, frameoff: int) -> bool:
  """Check if frame offset belongs to an argument without deprecations."""
  if (func := get_func(ea)) is not None:
    if hasattr(ida_frame, "is_funcarg_off"):
      return ida_frame.is_funcarg_off(func, frameoff)
  return False


def soff_to_fpoff(ea: int, soff: int) -> int:
  """Convert stack offset to frame pointer offset without deprecations."""
  if (func := get_func(ea)) is not None:
    if hasattr(ida_frame, "soff_to_fpoff"):
      return ida_frame.soff_to_fpoff(func, soff)
  return 0


def define_stkvar(
    ea: int, name: str, off: int, tif: ida_typeinf.tinfo_t
) -> bool:
  """Define a stack variable without triggering deprecations."""
  if (func := get_func(ea)) is not None:
    if hasattr(ida_frame, "define_stkvar"):
      return ida_frame.define_stkvar(func, name, off, tif)
  return False


def set_frame_member_type(
    ea: int, offset: int, tif: ida_typeinf.tinfo_t
) -> bool:
  """Set stack frame member type without triggering deprecations."""
  if (func := get_func(ea)) is not None:
    if hasattr(ida_frame, "set_frame_member_type"):
      return ida_frame.set_frame_member_type(func, offset, tif)
  return False


def delete_frame_members(ea: int, start_offset: int, end_offset: int) -> bool:
  """Delete frame members without triggering deprecations."""
  if (func := get_func(ea)) is not None:
    if hasattr(ida_frame, "delete_frame_members"):
      return ida_frame.delete_frame_members(func, start_offset, end_offset)
  return False


def iter_function_addresses() -> Iterator[int]:
  """Iterate start addresses of all functions without triggering deprecations."""
  yield from idautils.Functions()


def get_segments() -> list[SegmentInfo]:
  """Retrieves all segments in a backward-compatible manner without deprecations."""
  segs = []
  qty = ida_segment.get_segm_qty()
  for i in range(qty):
    seg = ida_segment.getnseg(i)
    if seg is not None:
      segs.append(
          SegmentInfo(
              start_ea=seg.start_ea,
              end_ea=seg.end_ea,
              name=ida_segment.get_segm_name(seg),
              sclass=ida_segment.get_segm_class(seg) or "UNK",
              perm=seg.perm,
          )
      )
  return segs


def get_segm_name(ea: int) -> str:
  """Get segment name for an address without triggering deprecations."""
  if (seg := ida_segment.getseg(ea)) is not None:
    return ida_segment.get_segm_name(seg) or ""
  return ""


def iter_func_items(ea: int) -> Iterator[int]:
  """Iterate function items without triggering deprecations."""
  yield from idautils.FuncItems(ea)


def update_func_flags(
    ea: int, set_flags: int = 0, clear_flags: int = 0
) -> bool:
  """Update function flags safely across IDA SDK versions."""
  if (func := get_func(ea)) is not None:
    func.flags = (func.flags | set_flags) & ~clear_flags
    return ida_funcs.update_func(func)
  return False


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
