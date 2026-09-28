# Copyright (c) 2026 Google LLC
# Copyright (c) 2025 Duncan Ogilvie
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


"""Tools for editing the IDA database."""

from typing import Annotated, List
import ida_bytes
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_idp
import ida_kernwin
import ida_loader
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.synchronization import idawrite
from ida_mcp.utils import helper
from ida_mcp.utils import save
import ida_typeinf
import idaapi
import idc
from shared.rpc import ToolError
from shared.types import (
    AddEntryPointRequest,
    ConvertToOffsetRequest,
    LocalVariableRename,
    LocalVariableTypeChange,
    MakeDataRequest,
    PatchBytesRequest,
    RenameAddressRequest,
    SaveDatabaseResult,
    SetColorRequest,
    SetCommentResult,
    SetTypeRequest,
    StackFrameVariableCreate,
    StackFrameVariableRename,
    StackFrameVariableTypeChange,
)


@jsonrpc
@idawrite
def save_database() -> SaveDatabaseResult:
  """Saves the IDA database so renames, comments, types and patches persist.

  Saves in place to the current .idb/.i64 path. In the IDA GUI this is the same
  as File > Save. Headless databases are also saved when they are closed.
  """
  try:
    return SaveDatabaseResult(
        **save.save_current_database(ida_loader, idc, ida_kernwin)
    )
  except RuntimeError as e:
    raise ToolError(str(e)) from e


@jsonrpc
@idawrite
def jump_to_address(
    address: Annotated[str, "The target address to jump to"],
) -> str:
  """Navigates the IDA UI (IDA View/Pseudocode) to the specified address."""
  try:
    ea = helper.parse_and_check_ea(address)
  except Exception as e:
    return f"Failed to parse address '{address}': {e}"

  if ida_kernwin.jumpto(ea):
    return "success"
  return f"Failed to jump to {address}"


@jsonrpc
@idawrite
def set_colors(
    reqs: Annotated[List[SetColorRequest], "List of color setting requests"],
) -> str:
  """Sets the background color of items at specified addresses."""
  errors = []
  successes = []
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      errors.append(f"Failed to parse address '{req.address}': {e}")
      continue

    if req.item_type not in ("CIC_ITEM", "CIC_FUNC", "CIC_SEGM"):
      errors.append(f"Invalid item_type: {req.item_type} for {req.address}")
      continue

    if isinstance(req.color, str):
      try:
        color_val = int(req.color, 0)
      except ValueError:
        errors.append(f"Invalid color value: {req.color} for {req.address}")
        continue
    else:
      color_val = req.color

    res = idc.set_color(ea, getattr(idc, req.item_type), color_val)
    if res is True or (req.item_type == "CIC_ITEM" and res is None):
      successes.append(f"Successfully set color at {req.address}")
    else:
      errors.append(f"Failed to set color at {req.address}")

  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def set_comment(
    address: Annotated[str, "Address to set the comment for"],
    comment: Annotated[str, "Comment text"],
) -> SetCommentResult:
  """Sets a comment at the specified address in both disassembly and pseudocode.

  This function sets a comment in the disassembly view. If the address is
  within a function that can be decompiled, it also attempts to set the comment
  in the pseudocode view:
  - As a function comment if the address is the entry point.
  - At the nearest mapped location in the pseudocode tree otherwise.

  Args:
    address: The target address.
    comment: The comment text.

  Returns:
    SetCommentResult indicating success/failure for both views.
  """
  ea = helper.parse_and_check_ea(address)
  if not idaapi.set_cmt(ea, comment, False):
    return SetCommentResult(
        disassembly_comment_status="failed",
        disassembly_comment_error=f"idaapi.set_cmt failed at address {ea:#x}.",
        pseudocode_comment_status="not_applicable",
    )

  cfunc = None
  decompilation_error = None
  try:
    cfunc = helper.decompile_checked(ea)
  except ToolError as e:
    decompilation_error = str(e)

  if cfunc is None:
    # Decompilation failed or is not applicable; return disassembly success only.
    return SetCommentResult(
        disassembly_comment_status="success",
        pseudocode_comment_status="not_applicable",
        pseudocode_comment_error=decompilation_error or "unknown",
    )

  if ea == cfunc.entry_ea:
    idc.set_func_cmt(ea, comment, True)
    cfunc.refresh_func_ctext()
    return SetCommentResult(
        disassembly_comment_status="success",
        pseudocode_comment_status="success",
    )

  eamap = cfunc.get_eamap()
  if ea not in eamap or not eamap[ea]:
    return SetCommentResult(
        disassembly_comment_status="success",
        pseudocode_comment_status="failed",
        pseudocode_comment_error=(
            f"Address {ea:#x} does not map to any pseudocode."
        ),
    )
  nearest_ea = eamap[ea][0].ea

  if cfunc.has_orphan_cmts():
    cfunc.del_orphan_cmts()
    cfunc.save_user_cmts()

  tl = idaapi.treeloc_t()
  tl.ea = nearest_ea
  for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
    tl.itp = itp
    cfunc.set_user_cmt(tl, comment)
    cfunc.save_user_cmts()
    cfunc.refresh_func_ctext()
    if not cfunc.has_orphan_cmts():
      return SetCommentResult(
          disassembly_comment_status="success",
          pseudocode_comment_status="success",
      )
    cfunc.del_orphan_cmts()
    cfunc.save_user_cmts()
  return SetCommentResult(
      disassembly_comment_status="success",
      pseudocode_comment_status="failed",
      pseudocode_comment_error=(
          f"Could not place comment at address {ea:#x} without generating"
          " orphan comments."
      ),
  )


@jsonrpc
@idawrite
def rename_local_variables(
    address: Annotated[str, "Address of the function containing the variables"],
    renames: Annotated[
        List[LocalVariableRename], "List of variable renames to apply"
    ],
) -> str:
  """Rename local variables in a function."""
  ea = helper.parse_and_check_ea(address)
  start_ea = helper.get_func_start(ea)
  if start_ea == idaapi.BADADDR:
    return f"No function found at address {address}"

  errors = []
  successes = []
  for rename in renames:
    if not ida_hexrays.rename_lvar(start_ea, rename.old_name, rename.new_name):
      errors.append(
          f"Failed to rename local variable {rename.old_name} in function"
          f" {start_ea:#x}"
      )
    else:
      successes.append(
          f"Successfully renamed local variable {rename.old_name} to"
          f" {rename.new_name} in function {start_ea:#x}"
      )
  if successes:
    helper.refresh_decompiler_ctext(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def rename_addresses(
    reqs: Annotated[
        List[RenameAddressRequest], "List of requests of address renaming"
    ],
) -> str:
  """Set or delete name of items at the specified addresses."""
  errors = []
  successes = []
  refresh_eas = set()
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      errors.append(f"Failed to parse address '{req.address}': {e}")
      continue

    flags = (
        idaapi.SN_FORCE
        | getattr(idaapi, "SN_MULTI", 0)
        | getattr(idaapi, "SN_MULTI_FORCE", 0)
    )
    if not idaapi.set_name(
        ea,
        req.new_name,
        flags,
    ):
      errors.append(f"Failed to rename address {req.address} to {req.new_name}")
    else:
      refresh_eas.add(ea)
      successes.append(
          f"Successfully renamed address {req.address} to {req.new_name}"
      )
  for ea in refresh_eas:
    helper.refresh_decompiler(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


class my_modifier_t(ida_hexrays.user_lvar_modifier_t):  # pylint: disable=invalid-name
  """User lvar modifier."""

  def __init__(self, var_name: str, new_type: ida_typeinf.tinfo_t):
    ida_hexrays.user_lvar_modifier_t.__init__(self)
    self.var_name = var_name
    self.new_type = new_type

  def modify_lvars(self, lvinf):
    for lvar_saved in lvinf.lvvec:
      lvar_saved: ida_hexrays.lvar_saved_info_t
      if lvar_saved.name == self.var_name:
        lvar_saved.type = self.new_type
        return True
    return False


@jsonrpc
@idawrite
def set_local_variable_types(
    address: Annotated[str, "Address of the function containing the variables"],
    type_changes: Annotated[
        List[LocalVariableTypeChange], "List of variable type changes to apply"
    ],
) -> str:
  """Set local variables' types."""
  ea = helper.parse_and_check_ea(address)

  start_ea = helper.get_func_start(ea)
  if start_ea == idaapi.BADADDR:
    return f"No function found at address {address}"

  errors = []
  successes = []
  for type_change in type_changes:
    new_tif = helper.get_type_by_name(type_change.new_type)
    if not ida_hexrays.rename_lvar(
        start_ea, type_change.variable_name, type_change.variable_name
    ):
      errors.append(
          f"Failed to find local variable: {type_change.variable_name} in"
          f" function {address}"
      )
      continue
    modifier = my_modifier_t(type_change.variable_name, new_tif)
    if not ida_hexrays.modify_user_lvars(start_ea, modifier):
      errors.append(
          f"Failed to modify local variable: {type_change.variable_name} in"
          f" function {address}"
      )
    else:
      successes.append(
          "Successfully set local variable type for"
          f" {type_change.variable_name} in function {address}"
      )
  if successes:
    helper.refresh_decompiler_ctext(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def rename_stack_frame_variables(
    address: Annotated[str, "Address of the function containing the variables"],
    renames: Annotated[
        List[StackFrameVariableRename], "List of variable renames"
    ],
) -> str:
  """Change the name of stack variables for IDA functions."""
  if helper.get_ida_version()[0] < 9:
    raise ToolError("This tool requires IDA Pro version to be >= 9.0")

  ea = helper.parse_and_check_ea(address)
  frame_tif = ida_typeinf.tinfo_t()
  if not helper.get_func_frame(frame_tif, ea):
    return f"No frame returned for function {address}."

  errors = []
  successes = []
  for rename in renames:
    idx, udm = frame_tif.get_udm(rename.old_name)  # type: ignore
    if not udm or idx == -1:
      errors.append(f"{rename.old_name} not found in function {address}.")
      continue

    tid = frame_tif.get_udm_tid(idx)  # type: ignore
    if ida_frame.is_special_frame_member(tid):
      errors.append(
          f"{rename.old_name} is a special frame member of function"
          f" {address}, skipped."
      )
      continue

    udm = ida_typeinf.udm_t()
    frame_tif.get_udm_by_tid(udm, tid)
    offset = udm.offset // 8
    if helper.is_funcarg_off(ea, offset):
      errors.append(
          f"{rename.old_name} is an argument member of function"
          f" {address}, skipped"
      )
      continue

    sval = helper.soff_to_fpoff(ea, offset)
    if not helper.define_stkvar(ea, rename.new_name, sval, udm.type):
      errors.append(
          f"Failed to rename stack frame variable {rename.old_name} of"
          f" function {address}"
      )
    else:
      successes.append(
          f"Successfully renamed stack frame variable {rename.old_name} to"
          f" {rename.new_name} in function {address}"
      )

  if successes:
    helper.refresh_decompiler_ctext(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def create_stack_frame_variables(
    address: Annotated[str, "Address of the function containing the variables"],
    creations: Annotated[
        List[StackFrameVariableCreate], "List of variable creations"
    ],
) -> str:
  """Creates stack variables for given functions."""
  if helper.get_ida_version()[0] < 9:
    raise ToolError("This tool requires IDA Pro version to be >= 9.0")

  ea = helper.parse_and_check_ea(address)
  frame_tif = ida_typeinf.tinfo_t()
  if not helper.get_func_frame(frame_tif, ea):
    return f"No frame returned for function {address}."

  errors = []
  successes = []
  for creation in creations:
    try:
      offset_ea = helper.parse_int(creation.offset)
    except Exception as e:
      errors.append(
          f"Failed to parse offset '{creation.offset}' (function"
          f" {address}): {e}"
      )
      continue

    tif = helper.get_type_by_name(creation.type_name)
    if not helper.define_stkvar(ea, creation.variable_name, offset_ea, tif):
      errors.append(
          f"Failed to define stack frame variable {creation.variable_name} in"
          f" function {address}"
      )
    else:
      successes.append(
          "Successfully defined stack frame variable"
          f" {creation.variable_name} in function {address}"
      )

  if successes:
    helper.refresh_decompiler_ctext(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def set_stack_frame_variable_types(
    address: Annotated[
        str, "The hex address of the target function, e.g. '0x40000'"
    ],
    type_changes: Annotated[
        List[StackFrameVariableTypeChange], "List of variable type changes"
    ],
) -> str:
  """Updates the types for the variables within a function's stack frame."""
  if helper.get_ida_version()[0] < 9:
    raise ToolError("This tool requires IDA Pro version to be >= 9.0")

  ea = helper.parse_and_check_ea(address)

  frame_tif = ida_typeinf.tinfo_t()
  if not helper.get_func_frame(frame_tif, ea):
    return f"No frame returned for function {address}."

  errors = []
  successes = []
  for type_change in type_changes:
    idx, udm = frame_tif.get_udm(type_change.variable_name)  # type: ignore
    if not udm or idx == -1:
      errors.append(
          f"{type_change.variable_name} not found in function {address}."
      )
      continue

    tid = frame_tif.get_udm_tid(idx)  # type: ignore
    udm = ida_typeinf.udm_t()
    frame_tif.get_udm_by_tid(udm, tid)
    offset = udm.offset // 8

    tif = helper.get_type_by_name(type_change.type_name)
    if not helper.set_frame_member_type(ea, offset, tif):
      errors.append(
          "Failed to set stack frame variable type for"
          f" {type_change.variable_name} in function {address}"
      )
    else:
      successes.append(
          "Successfully set stack frame variable type for"
          f" {type_change.variable_name} in function {address}"
      )

  if successes:
    helper.refresh_decompiler_ctext(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def delete_stack_frame_variables(
    address: Annotated[
        str, "The hex address of the target function, e.g. '0x40000'"
    ],
    variable_names: Annotated[List[str], "List of variable names to delete"],
) -> str:
  """Delete the named stack variables for given functions."""
  if helper.get_ida_version()[0] < 9:
    raise ToolError("This tool requires IDA Pro version to be >= 9.0")

  ea = helper.parse_and_check_ea(address)

  frame_tif = ida_typeinf.tinfo_t()
  if not helper.get_func_frame(frame_tif, ea):
    return f"No frame returned for function {address}."

  errors = []
  successes = []
  for variable_name in variable_names:
    idx, udm = frame_tif.get_udm(variable_name)  # type: ignore
    if not udm or idx == -1:
      errors.append(f"{variable_name} not found in function {address}.")
      continue

    tid = frame_tif.get_udm_tid(idx)  # type: ignore
    if ida_frame.is_special_frame_member(tid):
      errors.append(
          f"{variable_name} is a special frame member of function"
          f" {address}. Will not delete it"
      )
      continue

    udm = ida_typeinf.udm_t()
    frame_tif.get_udm_by_tid(udm, tid)
    offset = udm.offset // 8
    size = udm.size // 8
    if helper.is_funcarg_off(ea, offset):
      errors.append(
          f"{variable_name} is an argument member of {address}. Will not"
          " delete at"
      )
      continue

    if not helper.delete_frame_members(ea, offset, offset + size):
      errors.append(
          f"failed to delete stack frame variable {variable_name} of function"
          f" {address}"
      )
    else:
      successes.append(
          f"Successfully deleted stack frame variable {variable_name} of"
          f" function {address}"
      )

  if successes:
    helper.refresh_decompiler_ctext(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def set_functions_noret(
    address: Annotated[str, "Address of the function"],
    is_noret: Annotated[bool, "True to mark as non-returning, False otherwise"],
) -> str:
  """Set or unset the non-returning flag for functions."""
  ea = helper.parse_and_check_ea(address)

  start_ea = helper.get_func_start(ea)
  if start_ea == idaapi.BADADDR:
    return f"Address {address} does not belong to a function."

  set_flags = ida_funcs.FUNC_NORET if is_noret else 0
  clear_flags = 0 if is_noret else ida_funcs.FUNC_NORET
  if not helper.update_func_flags(start_ea, set_flags, clear_flags):
    return f"Failed to set the non-ret flag for {address}"
  return "success"


@jsonrpc
@idawrite
def set_types(
    reqs: Annotated[List[SetTypeRequest], "List of set type requests"],
) -> str:
  """Set type of functions/variables."""
  errors = []
  successes = []
  for req in reqs:
    ea = idaapi.get_name_ea(idaapi.BADADDR, req.address)
    if ea == idaapi.BADADDR:
      try:
        ea = helper.parse_and_check_ea(req.address)
      except Exception as e:
        errors.append(f"Failed to parse address '{req.address}': {e}")
        continue

    if idc.SetType(ea, req.new_type.strip().rstrip(";") + ";") is None:
      errors.append(f"new_type `{req.new_type}` is invalid at {req.address}")
    else:
      successes.append(
          f"Successfully set type `{req.new_type}` at {req.address}"
      )
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def add_entry_points(
    reqs: Annotated[
        List[AddEntryPointRequest], "List of add entry point requests"
    ],
) -> str:
  """Add entry points to the list of entry points."""
  errors = []
  successes = []
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      errors.append(f"Failed to parse address '{req.address}': {e}")
      continue

    if not ida_entry.add_entry(req.ordinal, ea, req.name, req.makecode, 0):
      errors.append(f"Failed to add entry point {req.name} at {req.address}")
    else:
      successes.append(
          f"Successfully added entry point {req.name} at {req.address}"
      )
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def patch_bytes(
    reqs: Annotated[List[PatchBytesRequest], "List of patch bytes requests"],
) -> str:
  """Patch bytes directly in memory."""
  errors = []
  successes = []
  refresh_eas = set()
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      errors.append(f"Failed to parse address '{req.address}': {e}")
      continue

    try:
      patch_data = bytes.fromhex(req.hex_string)
    except ValueError:
      errors.append(f"Invalid hex string format for {req.address}")
      continue

    length = min(0x1000, len(patch_data))
    length = min(length, idaapi.inf_get_max_ea() - ea)
    patch_data = patch_data[:length]
    ida_bytes.patch_bytes(ea, patch_data)
    refresh_eas.add(ea)
    successes.append(f"Successfully patched {length:#x} bytes at {req.address}")
  for ea in refresh_eas:
    helper.refresh_decompiler(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def apply_enums_to_operands(
    address: Annotated[str, "Address of the instruction"],
    op_index: Annotated[int, "Operand index (0-based)"],
    enum_name: Annotated[str, "Name of the enum to apply"],
) -> str:
  """Replace imm-values in instructions with named Enum symbolic constants."""
  ea = helper.parse_and_check_ea(address)

  enum_id = idc.get_enum(enum_name)
  if enum_id == idc.BADADDR:
    return f"Enum '{enum_name}' not found for {address}"

  if not ida_bytes.op_enum(ea, op_index, enum_id, 0):
    return (
        f"Failed to apply enum '{enum_name}' to operand {op_index} at {ea:#x}"
    )
  helper.refresh_decompiler(ea)
  return "success"


@jsonrpc
@idawrite
def convert_to_offsets(
    reqs: Annotated[
        List[ConvertToOffsetRequest], "List of convert to offset requests"
    ],
) -> str:
  """Convert a number constant to an offset."""
  errors = []
  successes = []
  refresh_eas = set()
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      errors.append(f"Failed to parse address '{req.address}': {e}")
      continue

    try:
      base_ea = int(req.base, 0)
    except Exception:
      errors.append(
          f"Failed to parse base address {req.base} for {req.address}"
      )
      continue

    if base_ea != 0 and not helper.is_address_valid(base_ea):
      errors.append(f"Invalid base {base_ea} for {req.address}")
      continue

    if idaapi.op_plain_offset(ea, req.op_index, base_ea):
      refresh_eas.add(ea)
      successes.append(
          f"Successfully converted item to offset at {req.address}"
      )
    else:
      errors.append(f"Failed to convert item at {ea:#x} to an offset")
  for ea in refresh_eas:
    helper.refresh_decompiler(ea)
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def make_data_batch(
    reqs: Annotated[List[MakeDataRequest], "List of make data requests"],
) -> str:
  """Convert the current item to a primitive data type (byte, word, etc.)."""
  errors = []
  successes = []
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      errors.append(f"Failed to parse address '{req.address}': {e}")
      continue

    dt = req.data_type.lower()
    success = False

    match dt:
      case "byte":
        success = ida_bytes.create_byte(ea, 1)
      case "word":
        success = ida_bytes.create_word(ea, 2)
      case "dword":
        success = ida_bytes.create_dword(ea, 4)
      case "qword":
        success = ida_bytes.create_qword(ea, 8)
      case "oword":
        success = ida_bytes.create_oword(ea, 16)
      case "yword":
        success = ida_bytes.create_yword(ea, 32)
      case "float":
        success = ida_bytes.create_float(ea, 4)
      case "double":
        success = ida_bytes.create_double(ea, 8)
      case "tbyte" | "pack_real":
        size = ida_idp.ph_get_tbyte_size()
        if dt == "tbyte":
          success = ida_bytes.create_tbyte(ea, size)
        else:
          success = ida_bytes.create_packed_real(ea, size)
      case _:
        errors.append(
            f"Unsupported data type: {req.data_type} for {req.address}"
        )
        continue

    if not success:
      errors.append(f"Failed to create {req.data_type} at {ea:#x}")
    else:
      successes.append(f"Successfully created {req.data_type} at {req.address}")
  helper.refresh_decompiler_widget()
  if not errors:
    return "success"
  return "\n".join(errors + successes)


@jsonrpc
@idawrite
def make_structs(
    address: Annotated[str, "Address to create structure instance at"],
    struct_name: Annotated[str, "Name of the structure type"],
    size: Annotated[
        int,
        "Structure size in bytes. Use -1 for automatic calculation (default).",
    ] = -1,
) -> str:
  """Convert the current item to a structure instance."""
  ea = helper.parse_and_check_ea(address)

  if not idc.create_struct(ea, size, struct_name):
    return f"Failed to create structure '{struct_name}' at {address}"
  helper.refresh_decompiler_widget()
  return "success"


@jsonrpc
@idawrite
def make_strings(
    start_ea: Annotated[str, "Address to create string at"],
    end_ea: Annotated[
        str,
        (
            "Ending address of the string (exclusive). If empty (default),"
            " length will be calculated automatically."
        ),
    ] = "",
) -> str:
  """Create a string literal at the specified address."""
  ea = helper.parse_and_check_ea(start_ea)
  if not end_ea or end_ea.upper() == "BADADDR":
    endea = idaapi.BADADDR
  else:
    endea = min(helper.parse_int(end_ea), idaapi.inf_get_max_ea())

  if ea >= endea and endea != idaapi.BADADDR:
    return f"Invalid start address and end address: {start_ea} >= {endea:#x}"

  if not idc.create_strlit(ea, endea):
    return f"Failed to create string literal at {start_ea}"
  helper.refresh_decompiler_widget()
  return "success"


@jsonrpc
@idawrite
def make_arrays(
    address: Annotated[str, "Address to create array at"],
    count: Annotated[int, "Number of items in the array"],
) -> str:
  """Create an array of items starting at the specified address."""
  ea = helper.parse_and_check_ea(address)
  if not idc.make_array(ea, count):
    return f"Failed to create array of {count} items at {address}"
  helper.refresh_decompiler_widget()
  return "success"
