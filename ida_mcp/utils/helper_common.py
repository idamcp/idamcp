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

"""Common helper functions for IDA integration."""

import contextlib
import dataclasses
import functools
import re
import struct
from typing import Any, NamedTuple

import ida_hexrays
import ida_ida
import ida_idp
import ida_kernwin
from ida_mcp.core.synchronization import idaread
import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc
from shared.config import load_config
from shared.rpc import ToolError
from shared.types import Function


@dataclasses.dataclass
class SegmentInfo:
  """Portable representation of an IDA segment across SDK versions."""

  start_ea: int
  end_ea: int
  name: str
  sclass: str
  perm: int


class FuncBounds(NamedTuple):
  """Portable representation of function bounds."""

  start_ea: int
  end_ea: int


@functools.cache
def get_ida_version() -> tuple[int, int]:
  """Return (major, minor) IDA version tuple, e.g. (9, 4)."""
  with contextlib.suppress(AttributeError, TypeError, ValueError):
    ver = idaapi.get_kernel_version()
    if isinstance(ver, str):
      if match := re.match(r"^(\d+)\.(\d+)", ver):
        return (int(match.group(1)), int(match.group(2)))
  return (0, 0)


def get_ordinal_limit(ti: Any = None) -> int:
  """Portable get_ordinal_limit across IDA versions (7.x, 8.x, 9.x)."""
  if ti is None:
    ti = ida_typeinf.get_idati()
  if hasattr(ida_typeinf, "get_ordinal_limit"):
    try:
      return ida_typeinf.get_ordinal_limit(ti)
    except TypeError:
      return ida_typeinf.get_ordinal_limit()
  if hasattr(ida_typeinf, "get_ordinal_qty"):
    return ida_typeinf.get_ordinal_qty(ti) + 1
  return 0


class CalleeVisitor(ida_hexrays.minsn_visitor_t):
  """Visitor to find callee functions in microcode."""

  def __init__(self):
    super().__init__()
    self.callees: list[Function] = []
    self._callee_addresses = set()

  def visit_minsn(self) -> int:
    insn = self.curins
    if insn.opcode == ida_hexrays.m_call:
      # The 'l' operand of m_call contains the target
      target_op = insn.l

      # Handle cases where the call target is the result of another
      # instruction
      if target_op.t == ida_hexrays.mop_d:
        def_insn = target_op.d
        # Example: low call - the call operand is the result of a 'low'
        # instruction
        if def_insn.opcode == ida_hexrays.m_low:
          target_op = def_insn.l

      target_addr = 0
      func_name = None
      is_helper = False

      if target_op.t == ida_hexrays.mop_v:
        # Global variable/address (direct call)
        target_addr = target_op.g
        func_name = idc.get_name(target_addr)
      elif target_op.t == ida_hexrays.mop_h:
        # Helper function (named, often external or intrinsic)
        func_name = target_op.helper
        is_helper = True
        # Helpers don't usually have a database address
        target_addr = 0

      # Add if we resolved a name or address
      if func_name or target_addr:
        if not func_name:
          func_name = "<unknown>"

        func = Function(
            address=hex(target_addr),
            name=func_name,
        )
        if is_helper:
          func["is_helper_function"] = True
        if func["address"] not in self._callee_addresses:
          self._callee_addresses.add(func["address"])
          self.callees.append(func)

    return 0  # Continue traversal


def refresh_decompiler_widget():
  if not idaapi.is_idaq():
    return

  widget = ida_kernwin.get_current_widget()
  if widget is None:
    return

  vu = ida_hexrays.get_widget_vdui(widget)
  if vu is not None:
    vu.refresh_ctext()


def refresh_decompiler_ctext(address: int):
  with contextlib.suppress(ToolError):
    error = ida_hexrays.hexrays_failure_t()
    cfunc = decompile_func(address, error)
    if cfunc is not None:
      cfunc.refresh_func_ctext()


def is_address_valid(address: int) -> bool:
  return idaapi.inf_get_min_ea() <= address < idaapi.inf_get_max_ea()


def check_address(address: int, raise_error=True) -> int | None:
  if not is_address_valid(address):
    if raise_error:
      raise ToolError(
          f"Address {address:#x} doesn't fall within the valid range"
          f" [{idaapi.inf_get_min_ea():#x}, {idaapi.inf_get_max_ea():#x})"
      )
    else:
      return None
  return address


def parse_int(n: str | int) -> int:
  if isinstance(n, int):
    return n
  try:
    return int(n, 0)
  except ValueError as e:
    raise ToolError(f"Failed to parse integer: {n}") from e


def parse_and_check_ea(address: str | int) -> int:
  return check_address(parse_int(address))  # type: ignore


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
  """Gets a type by its name.

  Args:
    type_name: The name of the type to get.

  Returns:
    The type information object.
  """
  with contextlib.suppress(Exception):
    # Some versions of IDA (9.x) support this constructor
    tif = ida_typeinf.tinfo_t(type_name, None, ida_typeinf.PT_SIL)
    if hasattr(tif, "empty") and not tif.empty():
      return tif

  new_tif = ida_typeinf.tinfo_t()
  pt_flags = (
      ida_typeinf.PT_SIL
      | getattr(ida_typeinf, "PT_EMPTY", 0)
      | getattr(ida_typeinf, "PT_TYP", 0)
  )
  decl_typ = type_name.strip().rstrip(";") + ";"
  parsed = ida_typeinf.parse_decl(new_tif, None, decl_typ, pt_flags)
  if parsed is None or (hasattr(new_tif, "empty") and new_tif.empty()):
    raise ToolError(f"Failed to parse type: {type_name}")
  return new_tif


def compile_regex(pattern: str, flags: int = 0) -> re.Pattern:
  """Compiles a regular expression pattern.

  Args:
    pattern: regular expression pattern.
    flags: regex flags.

  Returns:
    A pattern object.

  Raises:
    ToolError on invalid syntax.
  """
  try:
    return re.compile(pattern, flags)
  except re.error as e:
    raise ToolError(f"Invalid regular expression '{pattern}': {e}") from e


def convert_regex_flags(regex_flags: str) -> int:
  """Converts a string of regex flags to an int.

  Args:
    regex_flags: A string of comma-separated or bar-separated regex flags.

  Returns:
    The integer representation of the regex flags.
  """
  if not regex_flags:
    return re.IGNORECASE

  flags = 0
  for flag in re.split(r",|\|", regex_flags):
    flag = flag.strip().upper()
    match flag:
      case "IGNORECASE":
        flags |= re.IGNORECASE
      case "MULTILINE":
        flags |= re.MULTILINE
      case "DOTALL":
        flags |= re.DOTALL
  return flags


def is_window_active():
  """Returns whether IDA is currently active."""
  try:
    from PyQt5.QtWidgets import QApplication  # pylint: disable=g-import-not-at-top
  except (ImportError, NotImplementedError):
    return False

  app = QApplication.instance()
  if app is None:
    return False

  for widget in app.topLevelWidgets():
    if widget.isActiveWindow():
      return True
  return False


def ida_segment_perm2str(perm: int) -> str:
  perms = "r" if perm & ida_segment.SEGPERM_READ else "-"
  perms += "w" if perm & ida_segment.SEGPERM_WRITE else "-"
  perms += "x" if perm & ida_segment.SEGPERM_EXEC else "-"

  return perms


def decompile_func(
    address: int, error: ida_hexrays.hexrays_failure_t
) -> ida_hexrays.cfunc_t | None:
  """Decompile a function.

  ida_hexrays.decompile_func` has been marked as deprecated since IDA Pro 9.4.
  This function aims to conceal API differences between versions prior to 9.3
  and version 9.3 or later.


  Args:
    address: an address belonging to a function.

  Returns:
    The decompiled function if successful, otherwise None.

  Raises:
    ToolError if hexrays plugin has been initialized or the address doesn't
    belong to any function.
  """
  if not ida_hexrays.init_hexrays_plugin():
    raise ToolError("Hex-Rays decompiler is not available")
  start_ea = idc.get_func_attr(address, idc.FUNCATTR_START)
  if start_ea == idc.BADADDR:
    raise ToolError(
        f"Can't decompile at address {address:#x} because it doesn't belong to"
        " any function"
    )
  # IDA Pro 9.4 has deprecated decompile_func, and introduced a new method
  # decompile_function
  if hasattr(ida_hexrays, "decompile_function"):
    return ida_hexrays.decompile_function(  # type: ignore (SWIG issue)
        start_ea,
        error,
        ida_hexrays.DECOMP_WARNINGS | ida_hexrays.DECOMP_NO_WAIT,
    )
  else:
    # ida_hexrays.decompile_func can in fact accept either an address within a
    # function or a func_t *. Technically idaapi.get_func is not necessary
    # here, we pass a func_t * because the type hints of this method explicitly
    # say it expects a `func_t *`.
    return ida_hexrays.decompile_func(  # type: ignore (SWIG issue)
        idaapi.get_func(start_ea),
        error,
        ida_hexrays.DECOMP_WARNINGS | ida_hexrays.DECOMP_NO_WAIT,
    )


def decompile_checked(address: int) -> ida_hexrays.cfunc_t:
  """Decompiles a function, checking for hexrays availability and license.

  Args:
    address: The address of the function to decompile.

  Returns:
    The decompiled function.
  """

  error = ida_hexrays.hexrays_failure_t()
  cfunc = decompile_func(address, error)
  if cfunc is not None:
    return cfunc

  # cfunc is None
  if error.code == ida_hexrays.MERR_LICENSE:
    raise ToolError(
        "Decompiler license is not available. Use `disassemble_function` to"
        " get the assembly code instead."
    )

  message = f"Decompilation failed for function at {address:#x}"
  if error.str:
    message += f": {error.str}"
  if error.errea != idaapi.BADADDR:
    message += f" (error address: {error.errea:#x})"
  raise ToolError(message)


def refresh_decompiler(address: int) -> None:
  if idaapi.is_code(idaapi.get_flags(address)):
    refresh_decompiler_ctext(address)
  else:
    refresh_decompiler_widget()


def get_image_size() -> int:
  """Returns the size of the image.

  This is a heuristic, and may not be accurate.
  """
  # Try to extract it from the PE header
  header = idautils.peutils_t().header()
  if header and header.startswith(b"PE\0\0") and len(header) >= 0x54:
    return struct.unpack("<I", header[0x50:0x54])[0]

  if hasattr(idaapi, "get_inf_structure"):
    # https://www.hex-rays.com/products/ida/support/sdkdoc/structidainfo.html
    info = idaapi.get_inf_structure()  # type: ignore
    omin_ea = info.omin_ea
    omax_ea = info.omax_ea
  else:
    omin_ea = ida_ida.inf_get_omin_ea()
    omax_ea = ida_ida.inf_get_omax_ea()

  # Bad heuristic for image size (bad if the relocations are the last section)
  return omax_ea - omin_ea


def get_prototype(fn: "idaapi.func_t") -> str | None:
  """Gets the prototype of a function.

  Args:
    fn: The function to get the prototype of.

  Returns:
    The prototype of the function as a string, or None if it could not be
    retrieved.
  """
  if hasattr(fn, "get_prototype"):
    prototype: ida_typeinf.tinfo_t | None = fn.get_prototype()
    if prototype is None:
      return None
    return str(prototype)

  if hasattr(idc, "get_type"):
    return idc.get_type(fn.start_ea)

  tif = ida_typeinf.tinfo_t()
  if ida_nalt.get_tinfo(tif, fn.start_ea):
    return str(tif)
  return None


@contextlib.contextmanager
def set_showing_opcode_internal(enabled: bool = False):
  """Context manager to set showing opcode bytes and restore original setting on exit."""
  orig_size = ida_ida.inf_get_bin_prefix_size()
  target_size = load_config()["opcode_bytes"] if enabled else 0
  if orig_size == target_size:
    yield
  else:
    ida_idp.process_config_directive(f"OPCODE_BYTES={target_size}")
    try:
      yield
    finally:
      ida_idp.process_config_directive(f"OPCODE_BYTES={orig_size}")


__all__ = [
    "FuncBounds",
    "SegmentInfo",
    "check_address",
    "compile_regex",
    "convert_regex_flags",
    "decompile_checked",
    "set_showing_opcode_internal",
    "get_ida_version",
    "get_image_size",
    "get_prototype",
    "get_type_by_name",
    "ida_segment_perm2str",
    "is_window_active",
    "parse_and_check_ea",
    "refresh_decompiler_ctext",
    "refresh_decompiler_widget",
    "is_address_valid",
    "parse_int",
    "refresh_decompiler",
]
