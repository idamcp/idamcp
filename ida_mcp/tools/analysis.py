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

"""This module provides analysis tools for IDA Pro."""

import contextlib
import json
import logging
from typing import Annotated, Literal

import ida_bytes
import ida_entry
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_kernwin
import ida_lines
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.synchronization import idaread
from ida_mcp.core.synchronization import idawrite
from ida_mcp.utils import helper
from ida_mcp.utils.address_range import AddressRangeManager
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc
from shared.rpc import ToolError
from shared.types import BasicBlock
from shared.types import Caller
from shared.types import CallGraph
from shared.types import CallGraphEdge
from shared.types import CallGraphNode
from shared.types import ControlFlowGraph
from shared.types import Function
from shared.types import SearchResult
from shared.types import Xref


@jsonrpc
@idaread
def get_xrefs_from(
    address: Annotated[str, "Address to get cross-references from"],
) -> list[Xref]:
  """Retrieves all cross-references originating from a specific address."""
  ea = helper.parse_and_check_ea(address)
  rv = []
  for xref in idautils.XrefsFrom(ea):
    xr = Xref(
        address=hex(xref.to),  # type: ignore
        type="code" if xref.iscode else "data",  # type: ignore
    )
    if (function := helper.get_function(xref.to, raise_error=False)) is not None:  # type: ignore
      xr["function"] = function
    rv.append(xr)
  return rv


@jsonrpc
@idaread
def decompile_function(
    address: Annotated[str, "Address of the function to decompile"],
    include_line_prefix: Annotated[
        bool,
        "Whether to include the line prefix (line numbers and addresses) in the"
        " decompiled output",
    ] = True,
) -> str:
  """Decompile a function at the given address."""
  start = helper.parse_and_check_ea(address)
  cfunc = helper.decompile_checked(start)

  sv = cfunc.get_pseudocode()
  if not include_line_prefix:
    return "\n".join(ida_lines.tag_remove(sl.line) for sl in sv)

  lines = []
  for i, sl in enumerate(sv):
    sl: ida_kernwin.simpleline_t
    item = ida_hexrays.ctree_item_t()
    addr = None if i > 0 else cfunc.entry_ea
    if cfunc.get_line_item(sl.line, 0, False, None, item, None):  # type: ignore (IDA SDK type hint wrong)
      if (
          hasattr(item, "get_ea")
          and (item_ea := item.get_ea()) != idaapi.BADADDR
      ):
        addr = item_ea
      if (
          addr is None
          and hasattr(item, "dstr")
          and (dstr := item.dstr()) is not None
      ):
        ds = dstr.split(": ")
        if len(ds) == 2:
          with contextlib.suppress(ValueError):
            addr = int(ds[0], 16)

    lines.append((addr, ida_lines.tag_remove(sl.line)))
  valid_addrs = [u[0] for u in lines if u[0] is not None]
  max_addr_hex_len = len(hex(max(valid_addrs, default=cfunc.entry_ea)))
  max_line_no_len = len(str(len(lines) + 1))

  final_lines = []
  for line_no, (addr, line) in enumerate(lines, 1):
    if addr is None:
      addr_str = f"{'-' * max_addr_hex_len}"
    else:
      addr_str = f"{addr:#0{max_addr_hex_len}x}"
    final_lines.append(f"[L:{line_no:<{max_line_no_len}}][{addr_str}]| {line}")

  return "\n".join(final_lines)


@jsonrpc
@idaread
def disassemble_code(
    address: Annotated[str, "Address to disassemble code"],
    count: Annotated[int, "Number of instructions to disassemble"] = 1,
) -> str:
  """Disassemble instructions starting at the given address.

  This function always treats the data at the address as code (forcing
  disassembly), making it suitable for analyzing irregular code, obfuscated
  code, or code starting at arbitrary offsets.

  For standard code analysis where you want to see IDA's full disassembly view
  (including data, directives, and formatted comments), 'get_ida_view' is
  preferred.
  """
  if count <= 0:
    raise ToolError(f"Invalid count {count}: expected > 0")

  ea = helper.parse_and_check_ea(address)
  address_length = idaapi.inf_get_app_bitness() // 4
  lines: list[str] = []
  failed = False
  for _ in range(count):
    insn = idaapi.insn_t()
    # Force decoding even if not marked as code in the database
    length = idaapi.decode_insn(insn, ea)
    if length <= 0:
      failed = True
      break

    segment = helper.get_segm_name(ea) or "<unknown>"
    prefix = f"{segment}:{ea:0{address_length}x}"

    # Label at this address
    name = idc.get_name(ea)
    if name:
      if idc.get_func_attr(ea, idc.FUNCATTR_START) == ea:
        label_text = f"{name}: ; function start"
      else:
        label_text = name + ":"

      label_line = f"{prefix}"
      label_line += "             " + label_text
      lines.append(label_line)
    # Instruction line
    disasm = idc.generate_disasm_line(
        ea, idc.GENDSM_FORCE_CODE | idc.GENDSM_MULTI_LINE
    )
    disasm = ida_lines.tag_remove(disasm)

    # Get opcode bytes
    opcode_bytes = ida_bytes.get_bytes(ea, length)
    bytes_str = (
        " ".join(f"{b:02X}" for b in opcode_bytes[:8])
        if opcode_bytes[:8]
        else ""
    )

    line_start = f"{prefix} {bytes_str}"
    line = line_start + " " * max(1, 55 - len(line_start)) + disasm
    lines.append(line)
    opcode_bytes = opcode_bytes[8:]
    while opcode_bytes:
      bytes_str = (
          " ".join(f"{b:02X}" for b in opcode_bytes[:8])
          if opcode_bytes[:8]
          else ""
      )
      line_start = f"{prefix} {bytes_str}"
      lines.append(line_start)
      opcode_bytes = opcode_bytes[8:]

    ea += length

  if not lines:
    return f"; Can't disassemble at {ea:#x}"

  segment: str | None = helper.get_segm_name(ea) or None

  address_str = f"{ea:0{address_length}x}"
  if segment:
    prefix = segment + f":{address_str}"
  else:
    prefix = "<unknown seg>" + f":{address_str}"
  if failed:
    lines.append(
        prefix
        + f"                         ; Failed to disassemble at address {ea:#x}"
    )
  lines.append(
      prefix
      + "                         "
      "; ------------------------------------------------------------------"
  )
  return "\n".join(lines)


def _generate_disassembly(ea: "idaapi.ea_t") -> list[str]:
  """Get the disassembly lines at the specific ea."""
  max_lines = 1000
  cur_lines = []
  while max_lines < 16000:
    res = ida_lines.generate_disassembly(ea, max_lines, False, True)
    if res is None:
      return []

    line_no, cur_lines = res
    if (
        line_no == 1
        and len(cur_lines) >= 1
        and cur_lines[-1].startswith(
            ".ERROR 'too many lines (more than MAX_ITEM_LINES="
        )
    ):
      max_lines *= 2
      continue
    else:
      return cur_lines
  # This should never happen since it is not likely one single EA has more than
  # 16000 lines of text
  return cur_lines


def _custom_gen_disasm_text(
    start_ea: "idaapi.ea_t", end_ea: "idaapi.ea_t"
) -> list[str]:
  """Custom implementation of gen_disasm_text for headless mode."""
  lines = []
  curr = start_ea
  while curr < end_ea:
    lines.extend(_generate_disassembly(curr))
    curr += idaapi.get_item_size(curr)
  return lines


def _gen_disasm_text(
    start_ea: "idaapi.ea_t", end_ea: "idaapi.ea_t"
) -> list[str]:
  """Cross-platform gen_disasm_text that works in both GUI and headless modes."""
  if getattr(idaapi, "is_headless", False):
    return _custom_gen_disasm_text(start_ea, end_ea)

  disasm_text = ida_kernwin.disasm_text_t()
  ida_kernwin.gen_disasm_text(disasm_text, start_ea, end_ea, False)
  lines = []
  for line_info in disasm_text:
    lines.append(ida_lines.tag_remove(line_info.line))
  return lines


def _get_ida_view(start_ea: "idaapi.ea_t", end_ea: "idaapi.ea_t") -> str:
  if idaapi.BADADDR in (start_ea, end_ea) or start_ea >= end_ea:
    raise ToolError(f"Invalid address range: [{start_ea:#x}, {end_ea:#x})")
  lines = _gen_disasm_text(start_ea, end_ea)
  return "\n".join(lines)


@jsonrpc
@idaread
def get_ida_view(
    start_ea: Annotated[str, "Start address of the view"],
    end_ea: Annotated[str, "End address of the view"],
) -> str:
  """Retrieves the formatted text view directly from IDA Pro's 'IDA View-A'.

  CRITICAL: Use this tool (NOT disassemble_code) when inspecting data segments,
  global variables, arrays, or applied C-structures. It accurately renders data
  directives (DCB/DCD/DCQ), strings, cross-references, and applied struct
  formatting (e.g., my_struct_t <1, 2>). It is also the preferred tool for
  reading standard assembly code with inline comments.
  """
  start_addr = max(helper.parse_int(start_ea), idaapi.inf_get_min_ea())
  end_addr = min(helper.parse_int(end_ea), idaapi.inf_get_max_ea())

  if start_addr > end_addr:
    raise ToolError(
        f"range [{start_ea}, {end_ea}) is invalid, the start_ea is supposed to"
        " be less than the end_ea"
    )

  max_view_limit = 0x10000
  if end_addr - start_addr > max_view_limit:
    raise ToolError(
        "Requested disassembly range is too large (maximum allowed size is"
        f" {max_view_limit:#x} bytes)."
    )

  if start_addr == end_addr:
    # We accept this edge case
    end_addr += 1

  helper.enable_showing_opcode_internal()
  return _get_ida_view(start_addr, end_addr)


def _get_func_block_ranges(
    address: int,
) -> AddressRangeManager:
  """Get the basic block containing the specified address."""
  bounds = helper.get_func_bounds(address)
  if not bounds:
    raise ToolError(f"{address} isn't in a function")
  addr_range = AddressRangeManager()
  fc = ida_gdl.FlowChart(bounds=(bounds.start_ea, bounds.end_ea))
  for block in fc:
    addr_range.add(block.start_ea, block.end_ea)

  return addr_range


@jsonrpc
@idaread
def disassemble_function(
    address: Annotated[str, "Address of the function to disassemble"],
) -> str:
  """Get assembly code for a function (API-compatible with older IDA builds)."""
  ea = helper.parse_and_check_ea(address)
  addr_range = _get_func_block_ranges(ea)

  if not addr_range:
    return (
        f"; Failed to get function blocks for address {address}, unable to"
        " disassemble"
    )

  helper.enable_showing_opcode_internal()
  func_text = []
  for start_ea, end_ea in addr_range:
    text = _get_ida_view(start_ea, end_ea)
    if text:
      func_text.append(text)

  if func_text:
    return "\n".join(func_text)

  return f"; Failed to disassemble function for address {address}."


@jsonrpc
@idaread
def get_xrefs_to(
    address: Annotated[str, "Address to get cross references to"],
) -> list[Xref]:
  """Get all cross references to the given address."""
  xrefs = []
  xref: ida_xref.xrefblk_t
  for xref in idautils.XrefsTo(helper.parse_int(address)):  # type: ignore (IDA SDK type hints are incorrect)
    xr = Xref(
        address=hex(xref.frm),
        type="code" if xref.iscode else "data",
    )

    if (
        function := helper.get_function(xref.frm, raise_error=False)
    ) is not None:
      xr["function"] = function
    xrefs.append(xr)
  return xrefs


@jsonrpc
@idaread
def get_xrefs_to_field(
    struct_name: Annotated[
        str, "Name of the struct (type) containing the field"
    ],
    field_name: Annotated[str, "Name of the field (member) to get xrefs to"],
) -> list[Xref]:
  """Get all cross references to a named struct field (member)."""

  # Get the type library
  til = ida_typeinf.get_idati()
  if not til:
    raise ToolError("Failed to retrieve type library.")

  # Get the structure type info
  tif = ida_typeinf.tinfo_t()
  if not tif.get_named_type(
      til, struct_name, ida_typeinf.BTF_STRUCT, True, False
  ):
    logging.info(f"Structure '{struct_name}' not found.")
    return []

  # Get the type identifier
  tid = idaapi.BADADDR
  if hasattr(ida_typeinf, "get_udm_by_fullname"):
    idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)  # type: ignore (IDA SDK type hints are incorrect)
    if idx != -1 and hasattr(tif, "get_udm_tid"):
      tid = tif.get_udm_tid(idx)

  if tid == idaapi.BADADDR:
    # Fallback to ida_struct for IDA 7.x
    with contextlib.suppress(Exception):
      import ida_struct  # pylint: disable=g-import-not-at-top

      if (
          (sid := ida_struct.get_struc_id(struct_name)) != idaapi.BADADDR
          and (sptr := ida_struct.get_struc(sid)) is not None
          and (mptr := ida_struct.get_member_by_name(sptr, field_name))
          is not None
      ):
        tid = mptr.id

  if tid == idaapi.BADADDR:
    logging.info(
        f"Field '{field_name}' not found in structure '{struct_name}'."
    )
    return []

  # Get xrefs to the tid
  xrefs = []
  xref: ida_xref.xrefblk_t
  for xref in idautils.XrefsTo(tid):  # type: ignore (IDA SDK type hints are incorrect)
    xr = Xref(
        address=hex(xref.frm),
        type="code" if xref.iscode else "data",
    )
    if (
        function := helper.get_function(xref.frm, raise_error=False)
    ) is not None:
      xr["function"] = function
    xrefs.append(xr)
  return xrefs


@jsonrpc
@idaread
def get_callees(
    address: Annotated[str, "Address of the function to get callee functions"],
) -> list[Function]:
  """Get all callees of a function."""
  return helper.get_callees(helper.parse_and_check_ea(address))


@jsonrpc
@idaread
def get_callers(
    address: Annotated[str, "Address of the function to get callers"],
) -> list[Caller]:
  """Get all callers of the given address."""
  return helper.get_callers(helper.parse_and_check_ea(address))


@jsonrpc
@idaread
def get_entry_points() -> list[Function]:
  """Get all entry points in the database."""
  result = []
  for i in range(ida_entry.get_entry_qty()):
    ordinal = ida_entry.get_entry_ordinal(i)
    address = ida_entry.get_entry(ordinal)
    func = helper.get_function(address, raise_error=False)
    if func is not None:
      result.append(func)
  return result


@jsonrpc
@idaread
def get_start_ea() -> str:
  """Get the start entry point of the binary."""
  return hex(idaapi.inf_get_start_ea())


@jsonrpc
@idaread
def get_call_graph_from(
    address: Annotated[str, "Address of the function to start from"],
    depth: Annotated[int, "Traversal depth"] = 2,
    max_nodes: Annotated[int, "Maximum number of nodes to return"] = 50,
) -> CallGraph:
  """Get the forward call graph from a function."""
  start_ea = helper.parse_and_check_ea(address)
  queue: list[tuple[int, int]] = [(start_ea, 0)]
  visited = {start_ea}

  nodes_map = {}  # ea -> node info
  edges_set = set()  # (src, dst)

  # Helper to add node
  def add_node(ea):
    if ea in nodes_map:
      return
    is_external = helper.get_func_start(ea) == idaapi.BADADDR
    name = idc.get_name(ea) or f"sub_{ea:x}"
    nodes_map[ea] = CallGraphNode(
        address=hex(ea), function_name=name, is_external=is_external
    )

  add_node(start_ea)

  while queue:
    curr_ea, curr_depth = queue.pop(0)

    if curr_depth >= depth:
      continue

    if len(nodes_map) >= max_nodes:
      break

    # Find callees logic using Xrefs
    if helper.get_func_start(curr_ea) == idaapi.BADADDR:
      continue  # Can't trace from external

    for head in helper.iter_func_items(curr_ea):
      for xref in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
        if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:  # type: ignore
          target = xref.to  # type: ignore
          if target not in nodes_map:
            if len(nodes_map) < max_nodes:
              add_node(target)
              if target not in visited:
                visited.add(target)
                queue.append((target, curr_depth + 1))

          if target in nodes_map:
            edges_set.add((curr_ea, target))

  return CallGraph(
      nodes=list(nodes_map.values()),
      edges=[CallGraphEdge(source=hex(s), target=hex(d)) for s, d in edges_set],
  )


@jsonrpc
@idaread
def get_call_graph_to(
    address: Annotated[str, "Address of the function to start from"],
    depth: Annotated[int, "Traversal depth"] = 2,
    max_nodes: Annotated[int, "Maximum number of nodes to return"] = 50,
) -> CallGraph:
  """Get the backward call graph to a function."""
  start_ea = helper.parse_and_check_ea(address)
  queue: list[tuple[int, int]] = [(start_ea, 0)]
  visited = {start_ea}

  nodes_map = {}
  edges_set = set()

  def add_node(ea):
    if ea in nodes_map:
      return
    is_external = helper.get_func_start(ea) == idaapi.BADADDR
    name = idc.get_name(ea) or f"sub_{ea:x}"
    nodes_map[ea] = CallGraphNode(
        address=hex(ea), function_name=name, is_external=is_external
    )

  add_node(start_ea)

  while queue:
    curr_ea, curr_depth = queue.pop(0)

    if curr_depth >= depth:
      continue

    if len(nodes_map) >= max_nodes:
      break

    # Find callers logic
    # idautils.CodeRefsTo(curr_ea, 0) gives addresses of instructions calling
    # curr_ea
    for ref_ea in idautils.CodeRefsTo(curr_ea, False):
      # Get function containing the call
      caller_ea = helper.get_func_start(ref_ea)
      if caller_ea == idaapi.BADADDR:
        continue

      if caller_ea not in nodes_map:
        if len(nodes_map) < max_nodes:
          add_node(caller_ea)
          if caller_ea not in visited:
            visited.add(caller_ea)
            queue.append((caller_ea, curr_depth + 1))

      if caller_ea in nodes_map:
        edges_set.add((caller_ea, curr_ea))

  return CallGraph(
      nodes=list(nodes_map.values()),
      edges=[CallGraphEdge(source=hex(s), target=hex(d)) for s, d in edges_set],
  )


@jsonrpc
@idaread
def get_call_graph_between(
    start_ea: Annotated[str, "Address of the start function"],
    end_ea: Annotated[str, "Address of the destination function"],
    max_depth: Annotated[int, "Maximum call depth"] = 5,
    max_paths: Annotated[int, "Maximum number of paths to return"] = 10,
) -> CallGraph:
  """Find paths between functions in the call graph."""
  start = helper.parse_and_check_ea(start_ea)
  end = helper.parse_and_check_ea(end_ea)

  source = helper.get_func_start(start)
  sink = helper.get_func_start(end)

  if source == idaapi.BADADDR:
    raise ToolError(f"Start address {start_ea} is not in a function")
  if sink == idaapi.BADADDR:
    raise ToolError(f"End address {end_ea} is not in a function")

  if source == sink:
    return CallGraph(nodes=[], edges=[])

  class PathFinder:
    """Finds paths between two functions."""

    def __init__(self):
      self.s1 = []  # main stack: list[ea_t]
      self.s2 = []  # neighbor stack: list[set[ea_t]]
      self.visited = {}

    def get_neighbors(self, node: "idaapi.ea_t") -> set[int]:
      neighbors = set()
      for xref in idautils.XrefsTo(node, False):
        caller_ea = helper.get_func_start(xref.frm)  # type: ignore
        if caller_ea != idaapi.BADADDR:
          neighbors.add(caller_ea)
      return neighbors

    def build_dual(self, node: "idaapi.ea_t") -> None:
      """Builds the dual stack for the path finding algorithm."""
      self.s1.append(node)
      self.visited[node] = True

      if len(self.s1) > max_depth:
        self.s2.append(set())
        return

      neighbors = self.get_neighbors(node)
      filtered_neighbors = set()
      for n_ea in neighbors:
        if not self.visited.get(n_ea):
          filtered_neighbors.add(n_ea)
      self.s2.append(filtered_neighbors)

    def cut_dual(self) -> None:
      self.s2.pop()
      node = self.s1.pop()
      self.visited[node] = False

    def find(self) -> list[list[int]]:
      """Finds all paths from source to sink."""
      paths_found = []
      self.s1.clear()
      self.s2.clear()
      self.visited.clear()
      self.build_dual(sink)

      while len(self.s1) > 0:
        if len(paths_found) >= max_paths:
          break

        neighbors = self.s2.pop()

        if self.s1[-1] == source:
          paths_found.append(list(reversed(self.s1)))
          self.s2.append(neighbors)
          self.cut_dual()
          continue

        if neighbors and len(neighbors) > 0:
          new_node = neighbors.pop()
          self.s2.append(neighbors)
          self.build_dual(new_node)
        else:
          self.s2.append(None)
          self.cut_dual()
          continue

      return paths_found

  finder = PathFinder()
  raw_paths = finder.find()

  nodes_map = {}
  edges_set = set()

  for path in raw_paths:
    for i in range(len(path)):
      ea = path[i]
      if ea not in nodes_map:
        name = idc.get_name(ea) or f"sub_{ea:x}"
        nodes_map[ea] = CallGraphNode(address=hex(ea), function_name=name)

      if i < len(path) - 1:
        next_ea = path[i + 1]
        edges_set.add((ea, next_ea))

  return CallGraph(
      nodes=list(nodes_map.values()),
      edges=[CallGraphEdge(source=hex(s), target=hex(d)) for s, d in edges_set],
  )


@jsonrpc
@idaread
def get_function_cfg(
    address: Annotated[str, "Address of the function to analyze"],
) -> ControlFlowGraph:
  """Get the Control Flow Graph (CFG) of a function."""
  ea = helper.parse_and_check_ea(address)
  bounds = helper.get_func_bounds(ea)
  if not bounds:
    raise ToolError(f"No function found at address {address}")

  fc = ida_gdl.FlowChart(bounds=(bounds.start_ea, bounds.end_ea))
  blocks = []

  for block in fc:
    succs = [s.id for s in block.succs()]
    preds = [p.id for p in block.preds()]

    blocks.append(
        BasicBlock(
            id=block.id,
            start=hex(block.start_ea),
            end=hex(block.end_ea),
            successors=succs,
            predecessors=preds,
        )
    )

  return ControlFlowGraph(function_address=hex(bounds.start_ea), blocks=blocks)


def _search_binary(
    pattern: Annotated[
        str, "Hex pattern to search for (e.g. '55 8B EC' or '55 8B ??')"
    ],
    start_ea: Annotated[
        str | None,
        (
            "Low address bound for the search range. Defaults to the minimum"
            " address of the binary if omitted."
        ),
    ] = None,
    end_ea: Annotated[
        str | None,
        (
            "High address bound for the search range. Defaults to the maximum"
            " address of the binary if omitted."
        ),
    ] = None,
    direction: Annotated[
        Literal["up", "down"],
        "Direction: 'up' or 'down'. Defaults to 'down' if omitted.",
    ] = "down",
    case_sensitive: bool = False,
) -> SearchResult:
  """Helper function to search for a binary pattern in the database."""
  if not pattern:
    raise ToolError("`pattern` parameter must be a non-empty string")
  max_ea = idaapi.inf_get_max_ea()
  min_ea = idaapi.inf_get_min_ea()
  if start_ea is not None:
    start = max(helper.parse_int(start_ea), min_ea)
  else:
    start = min_ea

  if end_ea is not None:
    end = min(helper.parse_int(end_ea), max_ea)
  else:
    end = max_ea

  if end <= start:
    raise ToolError(
        "Search range is invalid: start_ea must be strictly less than end_ea."
    )

  # Get segments and sort them based on direction
  segs = []
  for seg in helper.get_segments():
    segs.append((seg.start_ea, seg.end_ea))

  if direction == "down":
    segs.sort()
  else:
    segs.sort(key=lambda x: x[0], reverse=True)

  flags = (
      ida_bytes.BIN_SEARCH_FORWARD
      if direction == "down"
      else ida_bytes.BIN_SEARCH_BACKWARD
  ) | ida_bytes.BIN_SEARCH_NOSHOW

  if case_sensitive:
    flags |= getattr(ida_bytes, "BIN_SEARCH_CASE", 0x01)
  else:
    flags |= getattr(ida_bytes, "BIN_SEARCH_NOCASE", 0x00)

  results = []
  max_results = 50
  remaining_range = None
  next_search_addr = start if direction == "down" else end

  pt = ida_bytes.compiled_binpat_vec_t()
  if ida_bytes.parse_binpat_str(pt, start, pattern, 16):
    raise ToolError(f"Invalid pattern: {pattern}")

  for seg_start, seg_end in segs:
    if len(results) >= max_results:
      break

    if seg_end <= start or seg_start >= end:
      continue
    curr_start = max(seg_start, start)
    curr_end = min(seg_end, end)

    current = curr_start if direction == "down" else curr_end
    next_search_addr = current

    while len(results) < max_results:
      # Note: ida_bytes.bin_search always expects the range as [low_address,
      # high_address) When searching forward, we start at 'current' (which
      # moves up) and end at 'curr_end' When searching backward, 'current' is
      # the high bound (exclusive).
      search_start = current if direction == "down" else curr_start
      search_end = curr_end if direction == "down" else current

      res = ida_bytes.bin_search(search_start, search_end, pt, flags)
      found = res[0] if isinstance(res, tuple) else res
      if found == idaapi.BADADDR:
        break

      if found not in results:
        results.append(found)

      if direction == "down":
        current = found + 1
        next_search_addr = current
        if current >= curr_end:
          break
      else:
        current = found
        next_search_addr = current
        if current <= curr_start:
          break

  if len(results) >= max_results:
    if direction == "down":
      if next_search_addr < end:
        remaining_range = [hex(next_search_addr), hex(end)]
    else:
      if next_search_addr > start:
        remaining_range = [hex(start), hex(next_search_addr)]

  if remaining_range:
    return SearchResult(
        addresses=[hex(addr) for addr in results],
        remaining_range=remaining_range,
    )
  else:
    return SearchResult(addresses=[hex(addr) for addr in results])


@jsonrpc
@idaread
def search_binary(
    pattern: Annotated[
        str, "Hex pattern to search for (e.g. '55 8B EC' or '55 8B ??')"
    ],
    start_ea: Annotated[
        str | None,
        (
            "Low address bound for the search range. Defaults to the minimum"
            " address of the binary if omitted."
        ),
    ] = None,
    end_ea: Annotated[
        str | None,
        (
            "High address bound for the search range. Defaults to the maximum"
            " address of the binary if omitted."
        ),
    ] = None,
    direction: Annotated[
        Literal["up", "down"],
        "Direction: 'up' or 'down'. Defaults to 'down' if omitted.",
    ] = "down",
) -> SearchResult:
  """Search for binary pattern within a specified memory range.

  The search operates within the bounds defined by `start_ea` (low address) and
  `end_ea` (high address).
  - When the direction is 'down', the search progresses from `start_ea`
  ascending towards `end_ea`.
  - When the direction is 'up', the search progresses from `end_ea` descending
  towards `start_ea`.

  Note: Results are capped at a maximum of 50 matches per call.

  Args:
    pattern: Hex pattern to search for (e.g. '55 8B EC' or '55 8B ??').
    start_ea: Low address bound for the search range. Defaults to the minimum
      address of the binary if omitted.
    end_ea: High address bound for the search range. Defaults to the maximum
      address of the binary if omitted.
    direction: Direction: 'up' or 'down'. Defaults to 'down' if omitted.

  Returns:
    A SearchResult dict containing:
      - `addresses`: list of matched addresses.
      - `remaining_range`: the address range [start, end] that has not been
        searched yet if the 50-match cap was reached, or None if the search
        completed.
  """
  return _search_binary(pattern, start_ea, end_ea, direction)


@jsonrpc
@idaread
def search_text(
    text: Annotated[str, "Text to search for"],
    start_ea: Annotated[
        str | None,
        (
            "Low address bound for the search range. Defaults to the minimum"
            " address of the binary if omitted."
        ),
    ] = None,
    end_ea: Annotated[
        str | None,
        (
            "High address bound for the search range. Defaults to the maximum"
            " address of the binary if omitted."
        ),
    ] = None,
    direction: Annotated[
        Literal["up", "down"],
        "Direction: 'up' or 'down'. Defaults to 'down' if omitted.",
    ] = "down",
    case_sensitive: Annotated[
        bool,
        "Whether the search is case-sensitive (default: False).",
    ] = False,
) -> SearchResult:
  """Search for a text string within a specified memory range.

  The search operates within the bounds defined by `start_ea` (low address) and
  `end_ea` (high address).
  - When the direction is 'down', the search progresses from `start_ea`
  ascending towards `end_ea`.
  - When the direction is 'up', the search progresses from `end_ea` descending
  towards `start_ea`.

  Note: The results are capped at a maximum of 50 matches per call.

  Args:
    text: Text to search for.
    start_ea: Low address bound for the search range. Defaults to the minimum
      address of the binary if omitted.
    end_ea: High address bound for the search range. Defaults to the maximum
      address of the binary if omitted.
    direction: Direction: 'up' or 'down'. Defaults to 'down' if omitted.
    case_sensitive: Whether the search is case-sensitive (default: False).

  Returns:
    A SearchResult dict containing:
      - `addresses`: list of matched addresses.
      - `remaining_range`: the address range [start, end] that has not been
        searched yet if the 50-match cap was reached, or None if the search
        completed.
  """
  pattern = json.dumps(text)
  return _search_binary(pattern, start_ea, end_ea, direction, case_sensitive)


@jsonrpc
@idawrite
def undefine(
    address: Annotated[str, "Address to undefine"],
    size: Annotated[int, "Number of bytes to undefine"] = 1,
) -> str:
  """Clear code/data definitions in a range (GUI: 'U')."""

  ea = helper.parse_and_check_ea(address)
  size = min(size, idaapi.inf_get_max_ea() - ea)
  if ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size):
    return f"Successfully undefined range [{address}, {ea + size:#x})"
  return f"Failed to undefine range [{address}, {ea + size:#x})"


def _make_code(ea: int) -> bool:
  # We don't check the result of del_items, because if the item has been
  # undefined, del_items returns failure.
  ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 1)
  return idc.create_insn(ea) != 0


@jsonrpc
@idawrite
def make_code(
    address: Annotated[str, "Address to convert to instructions"],
) -> str:
  """Convert raw bytes to instructions at an address (GUI: 'C').

  This operation automatically undefines (GUI: 'U') any existing item at the
  specified address to allow for the creation of a new instruction.
  """
  ea = helper.parse_and_check_ea(address)

  if _make_code(ea):
    return f"Successfully created code at {address}"
  return f"Failed to make code at {address}"


@jsonrpc
@idawrite
def make_function(
    address: Annotated[str, "Address to define function"],
) -> str:
  """Define a function at a code location (GUI: 'P').

  To ensure success, this operation first undefines (GUI: 'U') any existing
  item at the address and converts it to code before establishing the function
  definition.
  """
  ea = helper.parse_and_check_ea(address)
  if _make_code(ea) and ida_funcs.add_func(ea):
    return f"Successfully created function at {ea:#x}"
  return f"Failed to create function at {ea:#x}"


@jsonrpc
@idaread
def get_data_xrefs_from(
    address: Annotated[str, "Address to get data xrefs from"],
) -> list[str]:
  """Retrieve the addresses pointed to by the data at a specific location."""
  ea = helper.parse_and_check_ea(address)
  xrefs = []
  for xref in idautils.DataRefsFrom(ea):
    xrefs.append(hex(xref))
  return xrefs
