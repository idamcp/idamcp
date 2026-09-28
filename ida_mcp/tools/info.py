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


"""Module for retrieving information from IDA Pro."""

import contextlib
import math
import re
import time
from typing import Annotated, Any, List
import ida_bytes
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_ida
import ida_kernwin
from ida_mcp.core.decorators import internal, jsonrpc
from ida_mcp.core.synchronization import idaread
from ida_mcp.core.synchronization import idawrite
from ida_mcp.utils import helper
from ida_mcp.utils.caching import IteratorCache
import ida_moves
import ida_nalt
import ida_name
import ida_typeinf
import idaapi
import idautils
import idc
from shared.rpc import ToolError
from shared.types import AnalysisStatus
from shared.types import AssemblyContextItem
from shared.types import AssemblyContextRequest
from shared.types import BasicBlock
from shared.types import Bookmark
from shared.types import Function
from shared.types import FunctionFlags
from shared.types import Global
from shared.types import Import
from shared.types import Metadata
from shared.types import Operand
from shared.types import Page
from shared.types import PatchedByte
from shared.types import Segment
from shared.types import String

_FILETYPES = (
    ("f_EXE_old", "MS DOS EXE File."),
    ("f_COM_old", "MS DOS COM File."),
    ("f_BIN", "Binary File."),
    ("f_DRV", "MS DOS Driver."),
    ("f_WIN", "New Executable (NE)"),
    ("f_HEX", "Intel Hex Object File."),
    ("f_MEX", "MOS Technology Hex Object File."),
    ("f_LX", "Linear Executable (LX)"),
    ("f_LE", "Linear Executable (LE)"),
    ("f_NLM", "Netware Loadable Module (NLM)"),
    ("f_COFF", "Common Object File Format (COFF)"),
    ("f_PE", "Portable Executable (PE)"),
    ("f_OMF", "Object Module Format."),
    ("f_SREC", "Motorola SREC (S-record)"),
    ("f_ZIP", "ZIP file (this file is never loaded to IDA database)"),
    ("f_OMFLIB", "Library of OMF Modules."),
    ("f_AR", "ar library"),
    ("f_LOADER", "file is loaded using LOADER DLL"),
    ("f_ELF", "Executable and Linkable Format (ELF)"),
    ("f_W32RUN", "Watcom DOS32 Extender (W32RUN)"),
    ("f_AOUT", "Linux a.out (AOUT)"),
    ("f_PRC", "PalmPilot program file."),
    ("f_EXE", "MS DOS EXE File."),
    ("f_COM", "MS DOS COM File."),
    ("f_AIXAR", "AIX ar library."),
    ("f_MACHO", "Mac OS X Mach-O."),
    ("f_PSXOBJ", "Sony Playstation PSX object file."),
    ("f_MD1IMG", "Mediatek Firmware Image."),
)

# f_MD1IMG doesn't exist in the older IDA Pro
_FILETYPE_MAPPING = {
    val: desc
    for name, desc in _FILETYPES
    if (val := getattr(idaapi, name, None)) is not None
}


def _get_file_type_desc() -> str:
  return _FILETYPE_MAPPING.get(idaapi.inf_get_filetype(), "unknown file type")


@jsonrpc
@idaread
def get_comment(
    address: Annotated[str, "Address to retrieve the comment from"],
) -> str:
  """Retrieves the comment associated with a specific address."""
  ea = helper.parse_and_check_ea(address)
  # Get both regular and repeatable comments
  cmt = idaapi.get_cmt(ea, False)
  rcmt = idaapi.get_cmt(ea, True)

  # Also check for function comments if it's the start of a function
  func_cmt = idc.get_func_cmt(ea, False)
  func_rcmt = idc.get_func_cmt(ea, True)

  comments = []
  if cmt:
    comments.append(f"Comment: {cmt}")
  if rcmt:
    comments.append(f"Repeatable Comment: {rcmt}")
  if func_cmt:
    comments.append(f"Function Comment: {func_cmt}")
  if func_rcmt:
    comments.append(f"Function Repeatable Comment: {func_rcmt}")

  # Check for decompiler comments
  if ida_hexrays.init_hexrays_plugin():
    with contextlib.suppress(Exception):
      cfunc = helper.decompile_checked(ea)
      if cfunc and cfunc.user_cmts:
        ucmt: idaapi.citem_cmt_t
        for tl, ucmt in cfunc.user_cmts.items():
          if tl.ea == ea:
            comments.append(f"Decompiler Comment: {ucmt.c_str()}")

  if not comments:
    return "No comment found at this address."

  return "\n".join(comments)


@jsonrpc
@idaread
def get_metadata() -> Metadata:
  """Get metadata about the current IDB."""

  # Fat Mach-O binaries can return a None hash:
  # https://github.com/mrexodia/ida-pro-mcp/issues/26
  def calc_hash(f):
    try:
      return f().hex()
    except Exception:  # pylint: disable=broad-except
      return ""

  return Metadata(
      filepath=idaapi.get_input_file_path() or "<unknown>",
      module=idaapi.get_root_filename() or "<unknown>",
      database_path=idaapi.get_path(idaapi.PATH_TYPE_IDB),
      imagebase=hex(idaapi.get_imagebase()),
      imagesize=hex(helper.get_image_size()),
      sha256=calc_hash(ida_nalt.retrieve_input_file_sha256),
      filesize=hex(ida_nalt.retrieve_input_file_size()),
      filetype=_get_file_type_desc(),
      bitness=idaapi.inf_get_app_bitness(),
      procname=idaapi.inf_get_procname() or "<unknown>",
      is_headless=not idaapi.is_idaq(),
      **_analysis_complete_field(),
  )


def _auto_is_ok() -> bool | None:
  """Returns ida_auto.auto_is_ok(), or None if this IDA lacks it."""
  # pylint: disable-next=g-import-not-at-top
  import ida_auto

  auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
  return None if auto_is_ok is None else bool(auto_is_ok())


def _analysis_complete_field() -> dict[str, bool]:
  complete = _auto_is_ok()
  return {} if complete is None else {"analysis_complete": complete}


@idaread
def _analysis_status() -> dict[str, Any]:
  is_auto_enabled = getattr(ida_ida, "inf_is_auto_enabled", None)
  return {
      "complete": _auto_is_ok(),
      "auto_enabled": (
          None if is_auto_enabled is None else bool(is_auto_enabled())
      ),
  }


# One analysis slice in headless mode. Short enough that other tool calls can
# run between slices.
_ANALYSIS_SLICE_S = 0.25


@idawrite
def _analysis_slice(max_seconds: float) -> bool:
  """Runs pending auto-analysis steps (headless). Returns True when drained."""
  # pylint: disable-next=g-import-not-at-top
  import ida_auto

  previously_enabled = ida_auto.enable_auto(True)
  try:
    deadline = time.monotonic() + max_seconds
    while time.monotonic() < deadline:
      if not ida_auto.auto_make_step(0, idaapi.BADADDR):
        return True
    return False
  finally:
    if not previously_enabled:
      ida_auto.enable_auto(False)


@jsonrpc
def wait_for_analysis(
    timeout: Annotated[
        float | None,
        "Maximum seconds to wait. Omit to wait until analysis finishes.",
    ] = None,
) -> AnalysisStatus:
  """Wait until IDA's auto-analysis has finished.

  Returns immediately if it already has. Use it before relying on function
  lists, xrefs or names in a database whose get_metadata shows
  analysis_complete=false (e.g. a binary just opened in the IDA GUI). In the
  GUI this waits for IDA's own analysis; headless, it runs the pending
  analysis steps. Other tool calls can run while it waits.
  """
  if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
    raise ValueError("timeout must be a positive number of seconds")
  headless = bool(getattr(idaapi, "is_headless", False))
  start = time.monotonic()
  deadline = None if timeout is None else start + timeout
  timed_out = False
  drained = False
  while True:
    status = _analysis_status.sync_call()
    if status["complete"] is None:
      raise ToolError("This IDA version does not provide ida_auto.auto_is_ok")
    if status["complete"] or drained:
      # drained: auto_make_step found nothing left to do, but auto_is_ok()
      # is still false. Report that instead of spinning.
      break
    remaining = None if deadline is None else deadline - time.monotonic()
    if remaining is not None and remaining <= 0:
      timed_out = True
      break
    step = (
        _ANALYSIS_SLICE_S
        if remaining is None
        else min(_ANALYSIS_SLICE_S, remaining)
    )
    if headless:
      drained = _analysis_slice.sync_call(step)
    else:
      time.sleep(step)  # The GUI analyzes in its own idle loop.
  return AnalysisStatus(
      complete=status["complete"],
      auto_enabled=status["auto_enabled"],
      timed_out=timed_out,
      waited_s=round(time.monotonic() - start, 3),
  )


@jsonrpc
@idaread
def get_function_by_address(
    address: Annotated[str, "Address of the function to get"],
) -> Function:
  """Get a function by its address."""
  return helper.get_function(helper.parse_and_check_ea(address))


@jsonrpc
@idaread
def get_current_address() -> str:
  """Get the address currently selected by the user."""
  screen_ea = idaapi.get_screen_ea()
  if not helper.is_address_valid(screen_ea):
    return "Current screen EA doesn't exist"
  return hex(screen_ea)


@jsonrpc
@idaread
def get_current_function() -> Function | str:
  """Get the function currently selected by the user."""
  screen_ea = idaapi.get_screen_ea()
  if not helper.is_address_valid(screen_ea):
    return "Current screen EA doesn't exist"
  return helper.get_function(screen_ea)


@jsonrpc
@idaread
def get_basic_block(
    address: Annotated[str, "Address inside the basic block"],
) -> BasicBlock | str:
  """Get the basic block containing the specified address."""
  ea = helper.parse_and_check_ea(address)
  bounds = helper.get_func_bounds(ea)
  if not bounds:
    return f"{address} isn't in a function"

  fc = ida_gdl.FlowChart(bounds=(bounds.start_ea, bounds.end_ea))
  for block in fc:
    if block.start_ea <= ea < block.end_ea:
      succs = [s.id for s in block.succs()]
      preds = [p.id for p in block.preds()]

      return BasicBlock(
          id=block.id,
          start=hex(block.start_ea),
          end=hex(block.end_ea),
          successors=succs,
          predecessors=preds,
      )
  return f"Failed to find the block containing address {address}"


_FUNCTION_FLAGS = (
    (
        "FUNC_NORET",
        FunctionFlags(
            flag="FUNC_NORET", description="Function doesn't return."
        ),
    ),
    ("FUNC_FAR", FunctionFlags(flag="FUNC_FAR", description="Far function.")),
    (
        "FUNC_LIB",
        FunctionFlags(flag="FUNC_LIB", description="Library function."),
    ),
    (
        "FUNC_STATICDEF",
        FunctionFlags(flag="FUNC_STATICDEF", description="Static function."),
    ),
    (
        "FUNC_FRAME",
        FunctionFlags(
            flag="FUNC_FRAME",
            description="Function uses frame pointer (BP)",
        ),
    ),
    (
        "FUNC_USERFAR",
        FunctionFlags(
            flag="FUNC_USERFAR",
            description="User has specified far-ness of the function",
        ),
    ),
    (
        "FUNC_HIDDEN",
        FunctionFlags(
            flag="FUNC_HIDDEN", description="A hidden function chunk."
        ),
    ),
    (
        "FUNC_THUNK",
        FunctionFlags(flag="FUNC_THUNK", description="Thunk (jump) function."),
    ),
    (
        "FUNC_BOTTOMBP",
        FunctionFlags(
            flag="FUNC_BOTTOMBP",
            description="BP points to the bottom of the stack frame.",
        ),
    ),
    (
        "FUNC_NORET_PENDING",
        FunctionFlags(
            flag="FUNC_NORET_PENDING",
            description=(
                "Function 'non-return' analysis must be performed. This flag is"
                " verified upon func_does_return()"
            ),
        ),
    ),
    (
        "FUNC_SP_READY",
        FunctionFlags(
            flag="FUNC_SP_READY",
            description=(
                "SP-analysis has been performed. If this flag is on, the stack"
                " change points should not be not modified anymore. Currently"
                " this analysis is performed only for PC"
            ),
        ),
    ),
    (
        "FUNC_FUZZY_SP",
        FunctionFlags(
            flag="FUNC_FUZZY_SP",
            description=(
                "Function changes SP in untraceable way, for example: and esp,"
                " 0FFFFFFF0h"
            ),
        ),
    ),
    (
        "FUNC_PROLOG_OK",
        FunctionFlags(
            flag="FUNC_PROLOG_OK",
            description=(
                "Prolog analysis has been performed by last SP-analysis"
            ),
        ),
    ),
    (
        "FUNC_PURGED_OK",
        FunctionFlags(
            flag="FUNC_PURGED_OK",
            description=(
                "'argsize' field has been validated. If this bit is clear and"
                " 'argsize' is 0, then we do not known the real number of bytes"
                " removed from the stack. This bit is handled by the processor"
                " module."
            ),
        ),
    ),
    (
        "FUNC_TAIL",
        FunctionFlags(
            flag="FUNC_TAIL",
            description=(
                "This is a function tail. Other bits must be clear (except"
                " FUNC_HIDDEN)."
            ),
        ),
    ),
    (
        "FUNC_LUMINA",
        FunctionFlags(
            flag="FUNC_LUMINA",
            description="Function info is provided by Lumina.",
        ),
    ),
    (
        "FUNC_OUTLINE",
        FunctionFlags(
            flag="FUNC_OUTLINE",
            description="Outlined code, not a real function.",
        ),
    ),
    (
        "FUNC_REANALYZE",
        FunctionFlags(
            flag="FUNC_REANALYZE",
            description=(
                "Function frame changed, request to reanalyze the function"
                " after the last insn is analyzed."
            ),
        ),
    ),
    (
        "FUNC_UNWIND",
        FunctionFlags(
            flag="FUNC_UNWIND",
            description="function is an exception unwind handler",
        ),
    ),
    (
        "FUNC_CATCH",
        FunctionFlags(
            flag="FUNC_CATCH",
            description="function is an exception catch handler",
        ),
    ),
)

_FUNCTION_FLAG_DESCS = {
    val: desc
    for name, desc in _FUNCTION_FLAGS
    if (val := getattr(ida_funcs, name, None)) is not None
}


@jsonrpc
@idaread
def get_function_flags(
    address: Annotated[str, "Address to check"],
) -> list[FunctionFlags]:
  """Check if the address belongs to a library function (FLIRT)."""
  ea = helper.parse_and_check_ea(address)
  flags_val = helper.get_func_flags(ea)
  if flags_val is None:
    raise ToolError(f"Address {address} does not belong to a function.")
  flags = []
  for flag, flag_desc in _FUNCTION_FLAG_DESCS.items():
    if flag & flags_val:
      flags.append(flag_desc)

  return flags


_function_iterator_cache: IteratorCache[tuple[int, str, str], Any] = (
    IteratorCache()
)


@jsonrpc
@idaread
def list_functions(
    offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0,
    count: Annotated[
        int,
        "Number of functions to list (100 is a good default, 0 means "
        + "remainder)",
    ] = 0,
    regex_filter: Annotated[str, "Regular expression filter"] = "",
    regex_flags: Annotated[
        str,
        "A comma-separated list of flag strings, a flag can be 'IGNORECASE', "
        + "'MULTILINE', 'DOTALL'. Default flag is 'IGNORECASE'.",
    ] = "IGNORECASE",
) -> Page[Function]:
  """List matching functions in the database (paginated, filtered)."""
  func_qty = idaapi.get_func_qty()
  if func_qty == 0:
    raise ToolError("The module contains no function")

  if offset >= func_qty:
    raise ToolError(f"Invalid offset {offset:#x}: expected < {func_qty:#x}")

  if count == 0:
    count = func_qty - offset

  if regex_filter:
    regex = helper.compile_regex(
        regex_filter.replace("_", r"[\W_]"),
        helper.convert_regex_flags(regex_flags),
    )
  else:
    regex = None

  key = (offset, regex_filter, regex_flags)
  it = _function_iterator_cache.pop(key, None)
  if it is None:

    def _generator():
      for address in helper.iter_function_addresses():
        func_name = idaapi.get_func_name(address)
        if func_name and (regex is None or regex.search(func_name)):
          func_size = idc.get_func_attr(address, idc.FUNCATTR_END) - address
          yield Function(
              address=hex(address), name=func_name, size=hex(func_size)
          )

    it = _generator()
    # Skip offset
    try:
      for _ in range(offset):
        next(it)
    except StopIteration:
      return Page(data=[])

  functions: list[Function] = []
  try:
    for _ in range(count):
      functions.append(next(it))
  except StopIteration:
    return Page(data=functions)

  next_offset = offset + len(functions)

  if func_qty <= next_offset:
    return Page(data=functions)

  _function_iterator_cache[(next_offset, regex_filter, regex_flags)] = it
  return Page(data=functions, next_offset=next_offset)


_global_iterator_cache: IteratorCache[tuple[int, str], Any] = IteratorCache()


@jsonrpc
@idaread
def list_globals(
    offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0,
    count: Annotated[
        int,
        "Number of globals to list (100 is a good default, 0 means remainder)",
    ] = 0,
    regex_filter: Annotated[
        str,
        "A regular expression used to filter the list (matching is always "
        + "case-insensitive). This parameter is required; pass an empty string"
        + "to bypass filtering.",
    ] = "",
) -> Page[Global]:
  """List matching global variables in the database (paginated, filtered).

  Note: This list excludes dummy names (e.g., off_, loc_, byte_, sub_) to focus
  on user-defined or imported symbols.
  """
  if count == 0:
    count = idaapi.get_nlist_size()

  if regex_filter:
    regex = helper.compile_regex(
        regex_filter.replace("_", r"[\W_]"), re.IGNORECASE
    )
  else:
    regex = None

  key = (offset, regex_filter)
  it = _global_iterator_cache.pop(key, None)

  if it is None:

    def _generator():
      for addr, name in idautils.Names():
        # Skip functions and none
        if name is not None and idaapi.is_func(idaapi.get_flags(addr)):
          continue

        if name and (regex is None or regex.search(name)):
          yield Global(address=hex(addr), name=name)

    it = _generator()
    try:
      for _ in range(offset):
        next(it)
    except StopIteration:
      return Page(data=[])

  globals_list: list[Global] = []
  try:
    for _ in range(count):
      globals_list.append(next(it))
  except StopIteration:
    # We hit the end of the generator, no more items
    return Page(data=globals_list)

  next_offset = offset + len(globals_list)
  _global_iterator_cache[(next_offset, regex_filter)] = it
  return Page(data=globals_list, next_offset=next_offset)


_import_iterator_cache: IteratorCache[tuple[int, ...], Any] = IteratorCache()


@jsonrpc
@idaread
def list_imports(
    offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0,
    count: Annotated[
        int,
        "Number of imports to list (100 is a good default, 0 means remainder)",
    ] = 0,
) -> Page[Import]:
  """List all imported symbols with their name and module (paginated)."""
  import_module_qty = ida_nalt.get_import_module_qty()
  if import_module_qty == 0:
    raise ToolError("The module has no import")

  if count == 0:
    count = 10000  # Default large count to exhaust remainder

  key = (offset,)
  it = _import_iterator_cache.pop(key, None)

  if it is None:

    class ImportCallback:
      """Callback for enumerating imports."""

      def __init__(self):
        self.imports = []

      def __call__(self, ea, name, ordinal):
        self.imports.append((ea, name, ordinal))
        return True

    def _generator():
      nimps = ida_nalt.get_import_module_qty()
      for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"

        cb = ImportCallback()
        ida_nalt.enum_import_names(i, cb)

        for ea, name, ordinal in cb.imports:
          symbol_name = name if name else f"#{ordinal}"
          yield Import(
              address=hex(ea),
              imported_name=symbol_name,
              module=module_name,
          )

    it = _generator()
    try:
      for _ in range(offset):
        next(it)
    except StopIteration:
      return Page(data=[])

  rv: list[Import] = []
  try:
    for _ in range(count):
      rv.append(next(it))
  except StopIteration:
    return Page(data=rv)

  if len(rv) < count:
    return Page(data=rv)

  next_offset = offset + len(rv)
  _import_iterator_cache[(next_offset,)] = it
  return Page(data=rv, next_offset=next_offset)


_string_iterator_cache: IteratorCache[tuple[int, str, str], Any] = (
    IteratorCache()
)


@jsonrpc
@idaread
def list_strings(
    offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0,
    count: Annotated[
        int,
        "Number of strings to list (100 is a good default, 0 means remainder)",
    ] = 0,
    regex_filter: Annotated[str, "Regular expresssion filter"] = "",
    regex_flags: Annotated[
        str,
        "A comma-separated list of flag strings, a flag can be 'IGNORECASE', "
        + "'MULTILINE', 'DOTALL'. Default flag is 'IGNORECASE'.",
    ] = "IGNORECASE",
) -> Page[String]:
  """List matching strings in the database (paginated, filtered)."""
  if regex_filter:
    regex = helper.compile_regex(
        regex_filter, helper.convert_regex_flags(regex_flags)
    )
  else:
    regex = None

  key = (offset, regex_filter, regex_flags)
  it = _string_iterator_cache.pop(key, None)

  if it is None:

    def _generator(all_strings: idautils.Strings):
      for item in all_strings:
        if item is None:
          continue
        string_val = str(item)
        if string_val and (regex is None or regex.search(string_val)):
          yield String(
              address=hex(item.ea), length=item.length, string=string_val
          )

    all_strings = idautils.Strings()
    strlist_qty = all_strings.size
    if strlist_qty == 0:
      raise ToolError("The module contains no string")
    if offset >= strlist_qty:
      raise ToolError(
          f"Invalid offset {offset:#x}: expected < {strlist_qty:#x}"
      )
    it = _generator(all_strings)
    try:
      for _ in range(offset):
        next(it)
    except StopIteration:
      return Page(data=[])
  else:
    strlist_qty = idaapi.get_strlist_qty()
    if strlist_qty == 0:
      raise ToolError("The module contains no string")
    if offset >= strlist_qty:
      raise ToolError(
          f"Invalid offset {offset:#x}: expected < {strlist_qty:#x}"
      )

  if count == 0:
    count = strlist_qty - offset

  strings: list[String] = []
  try:
    for _ in range(count):
      strings.append(next(it))
  except StopIteration:
    return Page(data=strings)

  next_offset = offset + len(strings)
  if strlist_qty <= next_offset:
    return Page(data=strings)

  _string_iterator_cache[(next_offset, regex_filter, regex_flags)] = it
  return Page(data=strings, next_offset=next_offset)


def clear_caches() -> None:
  """Clears all iterator pagination caches."""
  _function_iterator_cache.clear()
  _global_iterator_cache.clear()
  _import_iterator_cache.clear()
  _string_iterator_cache.clear()


@jsonrpc
@idaread
def list_segments() -> list[Segment]:
  """List all segments in the binary."""
  segments = []
  for seg in helper.get_segments():
    segments.append(
        Segment(
            name=seg.name,
            start=hex(seg.start_ea),
            end=hex(seg.end_ea),
            size=hex(seg.end_ea - seg.start_ea),
            permissions=helper.ida_segment_perm2str(seg.perm),
        )
    )
  return segments


@jsonrpc
@idaread
def list_local_types(
    name_pattern: Annotated[
        str | None,
        "A regular expression used to filter the list (matching is always "
        + "case-insensitive). Return all types if this parameter is None or an"
        " empty string.",
    ] = None,
) -> str:
  """List Local types in the database."""
  if name_pattern:
    regex = helper.compile_regex(
        name_pattern.replace("_", r"[\W_]"),
        re.IGNORECASE,
    )
  else:
    regex = None
  idati = ida_typeinf.get_idati()
  type_count = helper.get_ordinal_limit(idati)
  if type_count == 0:
    raise ToolError("The module contains no type.")
  out = ""
  for ordinal in range(1, type_count):
    try:
      tif = ida_typeinf.tinfo_t()
      if not tif.get_numbered_type(idati, ordinal):
        if regex is None:
          out += f"tif.get_numbered_type failed for type ordinal #{ordinal}\n\n"
        continue
      # Though the method prototype says tif.get_type_name returns a bool, in
      # fact it returns the type name as the method name suggests.
      type_name = tif.get_type_name()
      if not type_name:
        type_name = f"anonymous_type_{ordinal}>"
      if regex and not regex.search(type_name):  # type: ignore
        continue
      out += f"Type Ordinal #{ordinal} is "
      if tif.is_udt():
        # headless mode prints wrong offsets.
        c_decl_flags = (
            ida_typeinf.PRTYPE_MULTI
            | ida_typeinf.PRTYPE_TYPE
            | ida_typeinf.PRTYPE_SEMI
            | ida_typeinf.PRTYPE_DEF
            | ida_typeinf.PRTYPE_METHODS
            | (ida_typeinf.PRTYPE_OFFSETS if idaapi.is_idaq() else 0)
        )
        c_decl_output = tif._print(type_name, c_decl_flags)  # type: ignore # pylint: disable=protected-access
        if c_decl_output:
          out += f"a declaration:\n{c_decl_output}\n"
      else:
        simple_decl = tif._print(  # pylint: disable=protected-access
            type_name,  # type: ignore
            ida_typeinf.PRTYPE_1LINE
            | ida_typeinf.PRTYPE_TYPE
            | ida_typeinf.PRTYPE_SEMI,
        )
        if simple_decl:
          out += f"an incomplete(forward) declaration:\n{simple_decl}\n\n"
    except Exception:  # pylint: disable=broad-except
      continue
  return out.strip()


@jsonrpc
@idaread
def list_patched_bytes() -> list[PatchedByte]:
  """List all patched bytes in the database."""
  result = []

  class PatchedBytesVisitor(object):
    """Visitor for patched bytes."""

    def __call__(self, ea, fpos, o, v):
      result.append(
          PatchedByte(
              address=hex(ea),
              fpos=fpos,
              original_value=o,
              patched_value=v,
          )
      )
      return 0

  ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, PatchedBytesVisitor())
  return result


@jsonrpc
@idaread
def list_bookmarks() -> list[Bookmark]:
  """List all bookmarks in the database."""
  bookmarks = []
  v = ida_kernwin.get_current_viewer()
  if v and hasattr(ida_moves, "bookmarks_t"):
    with contextlib.suppress(AttributeError, TypeError):
      for i, (loc, desc) in enumerate(ida_moves.bookmarks_t(v)):  # type: ignore
        bookmarks.append(
            Bookmark(
                index=i,
                address=hex(loc.place().toea()),
                description=desc if desc else "",
            )
        )
      return bookmarks

  # Fallback for IDA 7.x / when no GUI viewer is available
  for i, ea in enumerate(map(idc.get_bookmark, range(1024))):
    if ea != idaapi.BADADDR:
      desc = idc.get_bookmark_desc(i)
      bookmarks.append(
          Bookmark(
              index=i,
              address=hex(ea),
              description=desc if desc else "",
          )
      )
  return bookmarks


_OPERAND_TYPE_DESCRIPTIONS = {
    idaapi.o_void: "Void",
    idaapi.o_reg: "Register",
    idaapi.o_mem: "Memory Reference",
    idaapi.o_phrase: "Base + Index",
    idaapi.o_displ: "Base + Index + Displacement",
    idaapi.o_imm: "Immediate Value",
    idaapi.o_far: "Far Address",
    idaapi.o_near: "Near Address",
    idaapi.o_idpspec0: "Processor Specific",
    idaapi.o_idpspec1: "Processor Specific",
    idaapi.o_idpspec2: "Processor Specific",
    idaapi.o_idpspec3: "Processor Specific",
    idaapi.o_idpspec4: "Processor Specific",
    idaapi.o_idpspec5: "Processor Specific",
}


@jsonrpc
@idaread
def get_operand(
    address: Annotated[str, "Address of the instruction"],
    op_index: Annotated[int, "Operand index (0-based)"],
) -> Operand:
  """Get the operand of an instruction."""
  ea = helper.parse_and_check_ea(address)

  insn = idaapi.insn_t()
  if not idaapi.decode_insn(insn, ea):
    raise ToolError(f"Failed to decode instruction at {ea:#x}")

  if op_index < 0 or op_index >= idaapi.UA_MAXOP:
    raise ToolError(f"Invalid operand index: {op_index}")

  op: idaapi.op_t = insn.ops[op_index]  # type: ignore
  op_type = op.type

  value: str | int = idc.print_operand(ea, op_index)

  type_str = _OPERAND_TYPE_DESCRIPTIONS.get(op_type, "Unknown")

  if op_type in (idaapi.o_mem, idaapi.o_imm, idaapi.o_far, idaapi.o_near):
    value = idc.get_operand_value(ea, op_index)
  else:
    value = idc.print_operand(ea, op_index)

  return Operand(type=type_str, value=value)


@internal
@jsonrpc
@idaread
def get_assembly_context(
    reqs: Annotated[
        List[AssemblyContextRequest],
        "List of requests to resolve assembly context",
    ],
) -> list[AssemblyContextItem]:
  """Returns processor info, segment registers, and resolved symbols."""
  procname = ida_ida.inf_get_procname()
  procname = procname.lower() if procname else "unknown"
  bitness = ida_ida.inf_get_app_bitness()
  is_be = ida_ida.inf_is_be()
  is_arm = procname.startswith("arm")

  results = []
  for req in reqs:
    try:
      ea = helper.parse_and_check_ea(req.address)
    except Exception as e:
      results.append(
          AssemblyContextItem(
              address=req.address,
              procname=procname,
              bitness=bitness,
              is_be=is_be,
              is_thumb=False,
              symbols={},
              error=f"Failed to parse address '{req.address}': {e}",
          )
      )
      continue

    is_thumb = bool(is_arm and bitness != 64 and idc.get_sreg(ea, "T") == 1)

    resolved_symbols = {}
    for sym in req.symbols:
      val = ida_name.get_name_ea(idc.BADADDR, sym)
      if val != idc.BADADDR:
        resolved_symbols[sym] = f"0x{val:X}"

    results.append(
        AssemblyContextItem(
            address=hex(ea),
            procname=procname,
            bitness=bitness,
            is_be=is_be,
            is_thumb=is_thumb,
            symbols=resolved_symbols,
        )
    )
  return results
