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

"""Helper module.

This module implements various helper functions.
"""

from collections import defaultdict
from typing import (
    Annotated,
    Literal,
    overload,
)

import ida_funcs
import ida_mcp.utils.helper_common as _helper_common
import idaapi
import idautils
import idc
from shared.rpc import ToolError
from shared.types import Caller, Function

# Expose helper_common functions
FuncBounds = _helper_common.FuncBounds
SegmentInfo = _helper_common.SegmentInfo
check_address = _helper_common.check_address
compile_regex = _helper_common.compile_regex
convert_regex_flags = _helper_common.convert_regex_flags
decompile_checked = _helper_common.decompile_checked
set_showing_opcode_internal = _helper_common.set_showing_opcode_internal
get_ida_version = _helper_common.get_ida_version
get_image_size = _helper_common.get_image_size
get_prototype = _helper_common.get_prototype
get_type_by_name = _helper_common.get_type_by_name
ida_segment_perm2str = _helper_common.ida_segment_perm2str
is_window_active = _helper_common.is_window_active
parse_and_check_ea = _helper_common.parse_and_check_ea
refresh_decompiler_ctext = _helper_common.refresh_decompiler_ctext
refresh_decompiler_widget = _helper_common.refresh_decompiler_widget
is_address_valid = _helper_common.is_address_valid
parse_int = _helper_common.parse_int
refresh_decompiler = _helper_common.refresh_decompiler
get_ordinal_limit = _helper_common.get_ordinal_limit


# Choose implementation
if _helper_common.get_ida_version() >= (9, 4):
  import ida_mcp.utils.helper_94 as _helper_94

  _impl = _helper_94
else:
  import ida_mcp.utils.helper_93 as _helper_93

  _impl = _helper_93

# Expose version-specific functions
define_stkvar = _impl.define_stkvar
delete_frame_members = _impl.delete_frame_members
get_callees = _impl.get_callees
get_func = _impl.get_func
get_func_bounds = _impl.get_func_bounds
get_next_func_bounds = _impl.get_next_func_bounds
get_func_flags = _impl.get_func_flags
get_func_frame = _impl.get_func_frame
get_func_start = _impl.get_func_start
get_segments = _impl.get_segments
get_segm_name = _impl.get_segm_name
is_funcarg_off = _impl.is_funcarg_off
iter_func_items = _impl.iter_func_items
iter_function_addresses = _impl.iter_function_addresses
set_frame_member_type = _impl.set_frame_member_type
soff_to_fpoff = _impl.soff_to_fpoff
update_func_flags = _impl.update_func_flags


@overload
def get_function(address: int, *, raise_error: Literal[True]) -> Function:
  ...


@overload
def get_function(address: int) -> Function:
  ...


@overload
def get_function(
    address: int, *, raise_error: Literal[False]
) -> Function | None:
  ...


def get_function(address, *, raise_error=True):
  """Get a function by its address.

  Args:
    address: The address of the function to get.
    raise_error: Whether to raise an error if the function is not found.

  Returns:
    The function object or None if the function is not found and raise_error is
    False.
  """
  address = check_address(address, raise_error)
  if address is None:
    return None

  bounds = get_func_bounds(address)
  if bounds is None:
    if raise_error:
      raise ToolError(f"No function found at address {address:#x}")
    return None

  name = ida_funcs.get_func_name(bounds.start_ea) or f"sub_{bounds.start_ea:x}"
  return Function(
      address=hex(address),
      name=name,
      size=hex(bounds.end_ea - bounds.start_ea),
  )


def get_callers(
    function_address: Annotated[int, "Address of the function to get callers"],
) -> list[Caller]:
  """Get all callers of the given address."""
  func_ea = idc.get_func_attr(function_address, idc.FUNCATTR_START)
  func_name = idaapi.get_func_name(function_address)
  if not func_ea or not func_name:
    raise ToolError(f"Address {function_address:#x} belongs to no function")
  callers = defaultdict(list)
  insn = idaapi.insn_t()
  for xref in idautils.XrefsTo(func_ea):
    if not idaapi.is_code(idaapi.get_flags(xref.frm)):  # type: ignore
      continue

    ret = idaapi.decode_insn(insn, xref.frm)  # type: ignore
    if ret == 0 or not idaapi.is_call_insn(insn):
      continue
    from_func_ea = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)  # type: ignore
    callers[from_func_ea].append(xref.frm)  # type: ignore

  all_callers = []
  for func_ea, call_sites in callers.items():
    call_sites.sort()
    call_sites = list(map(hex, call_sites))
    if func_ea == idc.BADADDR:
      all_callers.append(Caller(call_sites=call_sites))
    else:
      all_callers.append(
          Caller(call_sites=call_sites, function=get_function(func_ea))
      )

  return all_callers


__all__ = [
    "get_callees",
    "get_callers",
    "get_function",
    "get_image_size",
    "get_prototype",
    "parse_and_check_ea",
    "get_type_by_name",
    "compile_regex",
    "convert_regex_flags",
    "is_window_active",
    "ida_segment_perm2str",
    "decompile_checked",
    "refresh_decompiler_ctext",
    "refresh_decompiler_widget",
    "set_showing_opcode_internal",
    "FuncBounds",
    "SegmentInfo",
    "get_segments",
    "iter_function_addresses",
    "get_func_start",
    "get_func",
    "get_func_bounds",
    "update_func_flags",
    "get_segm_name",
    "iter_func_items",
    "get_func_frame",
    "get_func_flags",
    "is_funcarg_off",
    "soff_to_fpoff",
    "define_stkvar",
    "set_frame_member_type",
    "delete_frame_members",
    "get_ordinal_limit",
]
