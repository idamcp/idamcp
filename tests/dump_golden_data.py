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


"""Golden Data Extractor inside native IDA Pro.

Extracts absolute ground-truth database representations directly from the
native C++ SDK and dumps them to a unified JSON file for unit-test assertions.

This script is intended to be run within IDA. You can run it with idat:

idat -B -Stests/dump_golden_data.py tests/test_binary
"""

import collections
import json
import logging
import os
import struct

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_gdl
import ida_hexrays
import ida_ida
import ida_idp
import ida_lines
from ida_mcp.utils import helper
import ida_nalt
import ida_pro
import ida_segment
import ida_typeinf
import ida_xref
import idaapi
import idautils
import idc

# Setup basic logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("dump_golden_data")

# --- Constant Mappings ---

_FILETYPE_MAPPING = {
    idaapi.f_EXE_old: "MS DOS EXE File.",
    idaapi.f_COM_old: "MS DOS COM File.",
    idaapi.f_BIN: "Binary File.",
    idaapi.f_DRV: "MS DOS Driver.",
    idaapi.f_WIN: "New Executable (NE)",
    idaapi.f_HEX: "Intel Hex Object File.",
    idaapi.f_MEX: "MOS Technology Hex Object File.",
    idaapi.f_LX: "Linear Executable (LX)",
    idaapi.f_LE: "Linear Executable (LE)",
    idaapi.f_NLM: "Netware Loadable Module (NLM)",
    idaapi.f_COFF: "Common Object File Format (COFF)",
    idaapi.f_PE: "Portable Executable (PE)",
    idaapi.f_OMF: "Object Module Format.",
    idaapi.f_SREC: "Motorola SREC (S-record)",
    idaapi.f_ZIP: "ZIP file (this file is never loaded to IDA database)",
    idaapi.f_OMFLIB: "Library of OMF Modules.",
    idaapi.f_AR: "ar library",
    idaapi.f_LOADER: "file is loaded using LOADER DLL",
    idaapi.f_ELF: "Executable and Linkable Format (ELF)",
    idaapi.f_W32RUN: "Watcom DOS32 Extender (W32RUN)",
    idaapi.f_AOUT: "Linux a.out (AOUT)",
    idaapi.f_PRC: "PalmPilot program file.",
    idaapi.f_EXE: "MS DOS EXE File.",
    idaapi.f_COM: "MS DOS COM File.",
    idaapi.f_AIXAR: "AIX ar library.",
    idaapi.f_MACHO: "Mac OS X Mach-O.",
    idaapi.f_PSXOBJ: "Sony Playstation PSX object file.",
    idaapi.f_MD1IMG: "Mediatek Firmware Image.",
}

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

_FUNCTION_FLAG_DESCS = {
    ida_funcs.FUNC_NORET: {
        "flag": "FUNC_NORET",
        "description": "Function doesn't return.",
    },
    ida_funcs.FUNC_FAR: {"flag": "FUNC_FAR", "description": "Far function."},
    ida_funcs.FUNC_LIB: {
        "flag": "FUNC_LIB",
        "description": "Library function.",
    },
    ida_funcs.FUNC_STATICDEF: {
        "flag": "FUNC_STATICDEF",
        "description": "Static function.",
    },
    ida_funcs.FUNC_FRAME: {
        "flag": "FUNC_FRAME",
        "description": "Function uses frame pointer (BP)",
    },
    ida_funcs.FUNC_USERFAR: {
        "flag": "FUNC_USERFAR",
        "description": "User has specified far-ness of the function",
    },
    ida_funcs.FUNC_HIDDEN: {
        "flag": "FUNC_HIDDEN",
        "description": "A hidden function chunk.",
    },
    ida_funcs.FUNC_THUNK: {
        "flag": "FUNC_THUNK",
        "description": "Thunk (jump) function.",
    },
    ida_funcs.FUNC_BOTTOMBP: {
        "flag": "FUNC_BOTTOMBP",
        "description": "BP points to the bottom of the stack frame.",
    },
    ida_funcs.FUNC_NORET_PENDING: {
        "flag": "FUNC_NORET_PENDING",
        "description": (
            "Function 'non-return' analysis must be performed. This flag is"
            " verified upon func_does_return()"
        ),
    },
    ida_funcs.FUNC_SP_READY: {
        "flag": "FUNC_SP_READY",
        "description": (
            "SP-analysis has been performed. If this flag is on, the stack"
            " change points should not be not modified anymore. Currently this"
            " analysis is performed only for PC"
        ),
    },
    ida_funcs.FUNC_FUZZY_SP: {
        "flag": "FUNC_FUZZY_SP",
        "description": (
            "Function changes SP in untraceable way, for example: and esp,"
            " 0FFFFFFF0h"
        ),
    },
    ida_funcs.FUNC_PROLOG_OK: {
        "flag": "FUNC_PROLOG_OK",
        "description": "Prolog analysis has been performed by last SP-analysis",
    },
    ida_funcs.FUNC_PURGED_OK: {
        "flag": "FUNC_PURGED_OK",
        "description": (
            "'argsize' field has been validated. If this bit is clear and"
            " 'argsize' is 0, then we do not known the real number of bytes"
            " removed from the stack. This bit is handled by the processor"
            " module."
        ),
    },
    ida_funcs.FUNC_TAIL: {
        "flag": "FUNC_TAIL",
        "description": (
            "This is a function tail. Other bits must be clear (except"
            " FUNC_HIDDEN)."
        ),
    },
    ida_funcs.FUNC_LUMINA: {
        "flag": "FUNC_LUMINA",
        "description": "Function info is provided by Lumina.",
    },
    ida_funcs.FUNC_OUTLINE: {
        "flag": "FUNC_OUTLINE",
        "description": "Outlined code, not a real function.",
    },
    ida_funcs.FUNC_REANALYZE: {
        "flag": "FUNC_REANALYZE",
        "description": (
            "Function frame changed, request to reanalyze the function after"
            " the last insn is analyzed."
        ),
    },
    ida_funcs.FUNC_UNWIND: {
        "flag": "FUNC_UNWIND",
        "description": "function is an exception unwind handler",
    },
    ida_funcs.FUNC_CATCH: {
        "flag": "FUNC_CATCH",
        "description": "function is an exception catch handler",
    },
}


# --- Helper Classes & Functions ---


def _calc_hash(hash_func) -> str:
  """Calculates input file hashes."""
  try:
    return hash_func().hex()
  except Exception:  # pylint: disable=broad-exception-caught
    return ""


def _get_image_size() -> int:
  """Extracts active PE header or unmapped min/max address ranges."""
  header = idautils.peutils_t().header()
  if header and header.startswith(b"PE\0\0") and len(header) >= 0x54:
    return struct.unpack("<I", header[0x50:0x54])[0]
  omin_ea = ida_ida.inf_get_omin_ea()
  omax_ea = ida_ida.inf_get_omax_ea()
  return omax_ea - omin_ea


def _get_file_type_desc() -> str:
  """Extracts descriptive target file types."""
  return _FILETYPE_MAPPING.get(idaapi.inf_get_filetype(), "unknown file type")


def _get_permissions_str(perm: int) -> str:
  """Calculates segment permissions flags."""
  perms = "r" if perm & ida_segment.SEGPERM_READ else "-"
  perms += "w" if perm & ida_segment.SEGPERM_WRITE else "-"
  perms += "x" if perm & ida_segment.SEGPERM_EXEC else "-"
  return perms


class ImportCallback:
  """Custom import callback to aggregate dynamic symbols."""

  def __init__(self):
    self.imports = []

  def __call__(self, ea: int, name: str, ordinal: int) -> bool:
    self.imports.append((ea, name, ordinal))
    return True


class CalleeVisitor(ida_hexrays.minsn_visitor_t):
  """Hex-Rays microcode visitor to harvest functional call targets."""

  def __init__(self):
    super().__init__()
    self.callees = []
    self._callee_addresses = set()

  def visit_minsn(self) -> int:
    insn = self.curins
    if insn.opcode == ida_hexrays.m_call:
      target_op = insn.l
      if target_op.t == ida_hexrays.mop_d:
        def_insn = target_op.d
        if def_insn.opcode == ida_hexrays.m_low:
          target_op = def_insn.l
      target_addr = 0
      func_name = None
      is_helper = False
      if target_op.t == ida_hexrays.mop_v:
        target_addr = target_op.g
      elif target_op.t == ida_hexrays.mop_h:
        func_name = target_op.helper
        is_helper = True
      elif target_op.t == ida_hexrays.mop_a:
        target_addr = target_op.a.toea()
      elif target_op.t == ida_hexrays.mop_r:
        pass
      if target_addr != 0 or func_name:
        if target_addr != 0:
          func_ea = idc.get_func_attr(target_addr, idc.FUNCATTR_START)
          if func_ea != idaapi.BADADDR:
            func_name = idaapi.get_func_name(func_ea)
            target_addr = func_ea
          else:
            func_name = idaapi.get_name(target_addr)
        if not func_name:
          func_name = f"sub_{target_addr:X}"

        func = {
            "address": hex(target_addr),
            "name": func_name,
        }
        if is_helper:
          func["is_helper_function"] = True
        if func["address"] not in self._callee_addresses:
          self._callee_addresses.add(func["address"])
          self.callees.append(func)
    return 0


class PathFinder:
  """Graph traversal class to find route paths between two functions."""

  def __init__(self, source: int, sink: int):
    self.source = source
    self.sink = sink
    self.s1 = []
    self.s2 = []
    self.visited = {}

  def get_neighbors(self, node: int) -> set[int]:
    neighbors = set()
    for xref in idautils.XrefsTo(node, False):
      caller_ea = helper.get_func_start(xref.frm)
      if caller_ea != idaapi.BADADDR:
        neighbors.add(caller_ea)
    return neighbors

  def build_dual(self, node: int) -> None:
    self.s1.append(node)
    self.visited[node] = True
    if len(self.s1) > 5:
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

  def find_paths(self) -> list[list[int]]:
    paths_found = []
    self.s1.clear()
    self.s2.clear()
    self.visited.clear()
    self.build_dual(self.sink)
    while self.s1:
      if len(paths_found) >= 10:
        break
      neighbors = self.s2.pop()
      if self.s1[-1] == self.source:
        paths_found.append(list(reversed(self.s1)))
        self.s2.append(neighbors)
        self.cut_dual()
        continue
      if neighbors:
        new_node = neighbors.pop()
        self.s2.append(neighbors)
        self.build_dual(new_node)
      else:
        self.s2.append(None)
        self.cut_dual()
        continue
    return paths_found


# --- Individual Section Dumpers ---


def dump_metadata() -> dict:
  """Extracts basic file metadata."""
  return {
      "filepath": os.path.basename(idaapi.get_input_file_path()),
      "module": os.path.basename(idaapi.get_root_filename()),
      "database_path": os.path.basename(idaapi.get_path(idaapi.PATH_TYPE_IDB)),
      "imagebase": hex(idaapi.get_imagebase()),
      "imagesize": hex(_get_image_size()),
      "sha256": _calc_hash(ida_nalt.retrieve_input_file_sha256),
      "filesize": hex(ida_nalt.retrieve_input_file_size()),
      "filetype": _get_file_type_desc(),
      "bitness": idaapi.inf_get_app_bitness(),
      "procname": idaapi.inf_get_procname(),
      "is_headless": not idaapi.is_idaq(),
  }


def dump_functions() -> list:
  """Extracts all analysed functions."""
  functions = []
  for address in helper.iter_function_addresses():
    func_name = idaapi.get_func_name(address)
    if func_name:
      func_size = idc.get_func_attr(address, idc.FUNCATTR_END) - address
      functions.append(
          {"address": hex(address), "name": func_name, "size": hex(func_size)}
      )
  return functions


def dump_globals() -> list:
  """Extracts global variable symbols."""
  globals_list = []
  for addr, name in idautils.Names():
    if name is not None and idaapi.is_func(idaapi.get_flags(addr)):
      continue
    if name:
      globals_list.append({"address": hex(addr), "name": name})
  return globals_list


def dump_segments() -> list:
  """Extracts segment tables."""
  segments = []
  for seg in helper.get_segments():
    segments.append({
        "name": seg.name,
        "start": hex(seg.start_ea),
        "end": hex(seg.end_ea),
        "size": hex(seg.end_ea - seg.start_ea),
        "permissions": _get_permissions_str(seg.perm),
    })
  return segments


def dump_imports() -> list:
  """Extracts dynamic library import symbols."""
  imports = []
  nimps = ida_nalt.get_import_module_qty()
  for i in range(nimps):
    module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
    cb = ImportCallback()
    ida_nalt.enum_import_names(i, cb)
    for ea, name, ordinal in cb.imports:
      symbol_name = name if name else f"#{ordinal}"
      imports.append({
          "address": hex(ea),
          "imported_name": symbol_name,
          "module": module_name,
      })
  return imports


def dump_strings() -> list:
  """Extracts static string literals."""
  strings = []
  for item in idautils.Strings(default_setup=True):
    if item is None:
      continue
    string_val = str(item)
    if string_val:
      strings.append(
          {"address": hex(item.ea), "length": item.length, "string": string_val}
      )
  return strings


def dump_operands() -> dict:
  """Extracts instruction operand types."""
  operands_dump = {}
  target_eas = [0x11C8]
  for ea in target_eas:
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea):
      ops = []
      for op_index in range(idaapi.UA_MAXOP):
        op = insn.ops[op_index]
        if op.type == idaapi.o_void:
          continue
        type_str = _OPERAND_TYPE_DESCRIPTIONS.get(op.type, "Unknown")
        if op.type in (idaapi.o_mem, idaapi.o_imm, idaapi.o_far, idaapi.o_near):
          value = idc.get_operand_value(ea, op_index)
        else:
          value = idc.print_operand(ea, op_index)
        ops.append({"type": type_str, "value": value})
      operands_dump[hex(ea)] = ops
  return operands_dump


def dump_basic_blocks() -> dict:
  """Extracts basic block boundaries and control flow mappings."""
  bb_dump = {}
  target_bb_eas = [0x1240]
  for ea in target_bb_eas:
    bounds = helper.get_func_bounds(ea)
    if bounds:
      fc = ida_gdl.FlowChart(bounds=(bounds.start_ea, bounds.end_ea))
      for block in fc:
        if block.start_ea <= ea < block.end_ea:
          succs = [s.id for s in block.succs()]
          preds = [p.id for p in block.preds()]
          bb_dump[hex(ea)] = {
              "id": block.id,
              "start": hex(block.start_ea),
              "end": hex(block.end_ea),
              "successors": succs,
              "predecessors": preds,
          }
          break
  return bb_dump


def dump_function_flags() -> dict:
  """Extracts native function flags and properties."""
  ff_dump = {}
  target_ff_eas = [0x1240]
  for ea in target_ff_eas:
    flags_val = helper.get_func_flags(ea)
    if flags_val is not None:
      flags = []
      for flag, flag_desc in _FUNCTION_FLAG_DESCS.items():
        if flag & flags_val:
          flags.append(flag_desc)
      ff_dump[hex(ea)] = flags
  return ff_dump


def dump_xrefs_from() -> dict:
  """Extracts dynamic outward code and data references."""
  xrefs_from_dump = {}
  target_xrefs_from_eas = [0x1251]
  for ea in target_xrefs_from_eas:
    rv = []
    for xref in idautils.XrefsFrom(ea):
      bounds = helper.get_func_bounds(xref.to)
      func_dict = None
      if bounds:
        func_name = idaapi.get_func_name(bounds.start_ea)
        func_dict = {
            "address": hex(xref.to),
            "name": func_name,
            "size": hex(bounds.end_ea - bounds.start_ea),
        }
      rv.append({
          "address": hex(xref.to),
          "type": "code" if xref.iscode else "data",
          "function": func_dict,
      })
    xrefs_from_dump[hex(ea)] = rv
  return xrefs_from_dump


def dump_xrefs_to() -> dict:
  """Extracts dynamic inward code references."""
  xrefs_to_dump = {}
  target_xrefs_to_eas = [0x11E0]
  for ea in target_xrefs_to_eas:
    rv = []
    for xref in idautils.XrefsTo(ea):
      bounds = helper.get_func_bounds(xref.frm)
      func_dict = None
      if bounds:
        func_name = idaapi.get_func_name(bounds.start_ea)
        func_dict = {
            "address": hex(xref.frm),
            "name": func_name,
            "size": hex(bounds.end_ea - bounds.start_ea),
        }
      rv.append({
          "address": hex(xref.frm),
          "type": "code" if xref.iscode else "data",
          "function": func_dict,
      })
    xrefs_to_dump[hex(ea)] = rv
  return xrefs_to_dump


def dump_data_xrefs_from() -> dict:
  """Extracts data reference targets."""
  data_xrefs_from_dump = {}
  target_data_xrefs_from_eas = [0x4098]
  for ea in target_data_xrefs_from_eas:
    rv = []
    for xref in idautils.DataRefsFrom(ea):
      rv.append(hex(xref))
    data_xrefs_from_dump[hex(ea)] = rv
  return data_xrefs_from_dump


def dump_xrefs_to_field() -> dict:
  """Extracts references directed to structure fields."""
  xrefs_to_field_dump = {}
  struct_name = "TestStruct"
  field_name = "a"
  tif = ida_typeinf.tinfo_t()
  if tif.get_named_type(None, struct_name):
    idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
    if idx != -1:
      tid = tif.get_udm_tid(idx)
      rv = []
      for xref in idautils.XrefsTo(tid):
        bounds = helper.get_func_bounds(xref.frm)
        func_dict = None
        if bounds:
          func_name = idaapi.get_func_name(bounds.start_ea)
          func_dict = {
              "address": hex(xref.frm),
              "name": func_name,
              "size": hex(bounds.end_ea - bounds.start_ea),
          }
        rv.append({
            "address": hex(xref.frm),
            "type": "code" if xref.iscode else "data",
            "function": func_dict,
        })
      xrefs_to_field_dump[f"{struct_name}.{field_name}"] = rv
  return xrefs_to_field_dump


def dump_callees() -> dict:
  """Extracts callers decompilation call sites."""
  callees_dump = {}
  target_callees_eas = [0x1240]
  if ida_hexrays.init_hexrays_plugin():
    for ea in target_callees_eas:
      if helper.get_func_bounds(ea):
        hf = ida_hexrays.hexrays_failure_t()
        if helper.get_ida_version() >= (9, 4):
          dcr = ida_hexrays.decomp_ranges_t(ea)
          mba = ida_hexrays.gen_microcode(
              dcr,
              hf,
              ida_hexrays.mlist_t(),
              ida_hexrays.DECOMP_WARNINGS,
              ida_hexrays.MMAT_LVARS,
          )
        else:
          func = helper.get_func(ea)
          if not func:
            continue
        mbr = ida_hexrays.mba_ranges_t(func)
        mba = ida_hexrays.gen_microcode(
            mbr,
            hf,
            ida_hexrays.mlist_t(),
            ida_hexrays.DECOMP_WARNINGS,
            ida_hexrays.MMAT_LVARS,
        )
        if mba:
          visitor = CalleeVisitor()
          mba.for_all_insns(visitor)
          callees_dump[hex(ea)] = visitor.callees
  return callees_dump


def dump_callers() -> dict:
  """Extracts target function inward callers."""
  callers_dump = {}
  target_callers_eas = [0x11E0]
  for ea in target_callers_eas:
    func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    callers = collections.defaultdict(list)
    insn = idaapi.insn_t()
    for xref in idautils.XrefsTo(func_ea):
      if not idaapi.is_code(idaapi.get_flags(xref.frm)):
        continue
      ret = idaapi.decode_insn(insn, xref.frm)
      if ret == 0 or not idaapi.is_call_insn(insn):
        continue
      from_func_ea = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
      callers[from_func_ea].append(xref.frm)

    all_callers = []
    for f_ea, call_sites in sorted(callers.items()):
      call_sites.sort()
      call_sites = list(map(hex, call_sites))
      func_dict = None
      if f_ea != idc.BADADDR:
        f_name = idaapi.get_func_name(f_ea)
        func_dict = {
            "address": hex(f_ea),
            "name": f_name,
            "size": hex(idc.get_func_attr(f_ea, idc.FUNCATTR_END) - f_ea),
        }
      all_callers.append({"call_sites": call_sites, "function": func_dict})
    callers_dump[hex(ea)] = all_callers
  return callers_dump


def dump_entry_points() -> list:
  """Extracts exported binary entry points."""
  entry_points_dump = []
  for i in range(ida_entry.get_entry_qty()):
    ordinal = ida_entry.get_entry_ordinal(i)
    address = ida_entry.get_entry(ordinal)
    bounds = helper.get_func_bounds(address)
    if bounds:
      func_name = idaapi.get_func_name(bounds.start_ea)
      entry_points_dump.append({
          "address": hex(address),
          "name": func_name,
          "size": hex(bounds.end_ea - bounds.start_ea),
      })
  return entry_points_dump


def dump_call_graph_from() -> dict:
  """Extracts call graph nodes cascading forward."""
  cg_from_dump = {}
  target_cg_from_eas = [0x1240]
  for ea in target_cg_from_eas:
    start_ea = ea
    queue = [(start_ea, 0)]
    visited = {start_ea}
    nodes_map = {}
    edges_set = set()

    def add_node(node_ea):
      if node_ea in nodes_map:
        return
      is_external = helper.get_func_start(node_ea) == idaapi.BADADDR
      name = idc.get_name(node_ea) or f"sub_{node_ea:x}"
      nodes_map[node_ea] = {
          "address": hex(node_ea),
          "function_name": name,
          "is_external": is_external,
      }

    add_node(start_ea)
    while queue:
      curr_ea, curr_depth = queue.pop(0)
      if curr_depth >= 1:
        continue
      if helper.get_func_start(curr_ea) == idaapi.BADADDR:
        continue
      for head in helper.iter_func_items(curr_ea):
        for xref in idautils.XrefsFrom(head, ida_xref.XREF_FAR):
          if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
            target = xref.to
            if target not in nodes_map:
              add_node(target)
              if target not in visited:
                visited.add(target)
                queue.append((target, curr_depth + 1))
            if target in nodes_map:
              edges_set.add((curr_ea, target))

    cg_from_dump[hex(ea)] = {
        "nodes": list(nodes_map.values()),
        "edges": [
            {"source": hex(s), "target": hex(d)} for s, d in sorted(edges_set)
        ],
    }
  return cg_from_dump


def dump_call_graph_to() -> dict:
  """Extracts call graph nodes cascading backwards."""
  cg_to_dump = {}
  target_cg_to_eas = [0x11E0]
  for ea in target_cg_to_eas:
    start_ea = ea
    queue = [(start_ea, 0)]
    visited = {start_ea}
    nodes_map = {}
    edges_set = set()

    def add_node(node_ea):
      if node_ea in nodes_map:
        return
      is_external = helper.get_func_start(node_ea) == idaapi.BADADDR
      name = idc.get_name(node_ea) or f"sub_{node_ea:x}"
      nodes_map[node_ea] = {
          "address": hex(node_ea),
          "function_name": name,
          "is_external": is_external,
      }

    add_node(start_ea)
    while queue:
      curr_ea, curr_depth = queue.pop(0)
      if curr_depth >= 1:
        continue
      for ref_ea in idautils.CodeRefsTo(curr_ea, False):
        caller_ea = helper.get_func_start(ref_ea)
        if caller_ea == idaapi.BADADDR:
          continue
        if caller_ea not in nodes_map:
          add_node(caller_ea)
          if caller_ea not in visited:
            visited.add(caller_ea)
            queue.append((caller_ea, curr_depth + 1))
        if caller_ea in nodes_map:
          edges_set.add((caller_ea, curr_ea))

    cg_to_dump[hex(ea)] = {
        "nodes": list(nodes_map.values()),
        "edges": [
            {"source": hex(s), "target": hex(d)} for s, d in sorted(edges_set)
        ],
    }
  return cg_to_dump


def dump_call_graph_between() -> dict:
  """Extracts call routes linking start and destination functions."""
  cg_between_dump = {}
  start_ea = 0x1710
  end_ea = 0x11E0
  source = helper.get_func_start(start_ea)
  sink = helper.get_func_start(end_ea)
  if source != idaapi.BADADDR and sink != idaapi.BADADDR:
    finder = PathFinder(source, sink)
    raw_paths = finder.find_paths()
    nodes_map = {}
    edges_set = set()
    for path in raw_paths:
      for i in range(len(path)):
        ea = path[i]
        if ea not in nodes_map:
          name = idc.get_name(ea) or f"sub_{ea:x}"
          nodes_map[ea] = {"address": hex(ea), "function_name": name}
        if i < len(path) - 1:
          next_ea = path[i + 1]
          edges_set.add((ea, next_ea))

    cg_between_dump[f"{hex(start_ea)}_{hex(end_ea)}"] = {
        "nodes": list(nodes_map.values()),
        "edges": [
            {"source": hex(s), "target": hex(d)} for s, d in sorted(edges_set)
        ],
    }
  return cg_between_dump


def dump_cfgs() -> dict:
  """Extracts functional basic block nodes mapping CFGs."""
  cfg_dump = {}
  target_cfg_eas = [0x1240]
  for ea in target_cfg_eas:
    bounds = helper.get_func_bounds(ea)
    if bounds:
      fc = ida_gdl.FlowChart(bounds=(bounds.start_ea, bounds.end_ea))
      blocks = []
      for block in fc:
        succs = [s.id for s in block.succs()]
        preds = [p.id for p in block.preds()]
        blocks.append({
            "id": block.id,
            "start": hex(block.start_ea),
            "end": hex(block.end_ea),
            "successors": succs,
            "predecessors": preds,
        })
      cfg_dump[hex(bounds.start_ea)] = {
          "function_address": hex(bounds.start_ea),
          "blocks": blocks,
      }
  return cfg_dump


def dump_decompiled() -> dict:
  """Extracts decompiled pseudocode string mappings."""
  decomp_dump = {}
  target_decomp_eas = [0x11E0]
  if ida_hexrays.init_hexrays_plugin():
    for ea in target_decomp_eas:
      start = idc.get_func_attr(ea, idc.FUNCATTR_START)
      cfunc = ida_hexrays.decompile(start)
      if cfunc:
        cfunc.refresh_func_ctext()
        sv = cfunc.get_pseudocode()
        lines = []
        for i, sl in enumerate(sv):
          item = ida_hexrays.ctree_item_t()
          addr = None if i > 0 else cfunc.entry_ea
          if cfunc.get_line_item(sl.line, 0, False, None, item, None):
            dstr = item.dstr()
            if dstr:
              ds = dstr.split(": ")
              if len(ds) == 2:
                try:
                  addr = int(ds[0], 16)
                except ValueError:
                  pass
          lines.append((addr, ida_lines.tag_remove(sl.line)))

        max_addr_hex_len = len(
            hex(max(u[0] for u in lines if u[0] is not None))
        )
        max_line_no_len = len(str(len(lines) + 1))
        final_lines = []
        for line_no, (addr, line) in enumerate(lines, 1):
          if addr is None:
            addr_str = f"{'-' * max_addr_hex_len}"
          else:
            addr_str = f"{addr:#0{max_addr_hex_len}x}"
          final_lines.append(
              f"[L:{line_no:<{max_line_no_len}}][{addr_str}]| {line}"
          )
        decomp_dump[hex(start)] = "\n".join(final_lines)
  return decomp_dump


def dump_disasm() -> dict:
  """Extracts formatted disassembly strings."""
  disasm_dump = {}
  ea = 0x1240
  count = 2
  address_length = idaapi.inf_get_app_bitness() // 4
  lines = []
  failed = False
  for _ in range(count):
    insn = idaapi.insn_t()
    length = idaapi.decode_insn(insn, ea)
    if length <= 0:
      failed = True
      break
    segment = helper.get_segm_name(ea) or "<unknown>"
    prefix = f"{segment}:{ea:0{address_length}x}"
    name = idc.get_name(ea)
    if name:
      if idc.get_func_attr(ea, idc.FUNCATTR_START) == ea:
        label_text = f"{name}: ; function start"
      else:
        label_text = name + ":"
      label_line = f"{prefix}             {label_text}"
      lines.append(label_line)
    disasm = idc.generate_disasm_line(
        ea, idc.GENDSM_FORCE_CODE | idc.GENDSM_MULTI_LINE
    )
    disasm = ida_lines.tag_remove(disasm)
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

  if not failed:
    segment = helper.get_segm_name(ea) or None
    address_str = f"{ea:0{address_length}x}"
    if segment:
      prefix = segment + f":{address_str}"
    else:
      prefix = "<unknown seg>" + f":{address_str}"
    lines.append(
        prefix
        + "                         ;"
        " ------------------------------------------------------------------"
    )
    disasm_dump["0x1240_2"] = "\n".join(lines)
  return disasm_dump


def _generate_disassembly(ea: idaapi.ea_t) -> list[str]:
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
    start_ea: idaapi.ea_t, end_ea: idaapi.ea_t
) -> list[str]:
  """Custom implementation of gen_disasm_text for headless mode."""
  lines = []
  curr = start_ea
  while curr < end_ea:
    lines.extend(_generate_disassembly(curr))
    curr += idaapi.get_item_size(curr)
  return lines


def dump_ida_view() -> dict:
  """Extracts opcode and disassembly columns in standard IDA view formats."""
  ida_view_dump = {}
  ranges = [
      (0x11E0, 0x120E),
      (0x1240, 0x125B),
      (0x40E0, 0x40EE),
  ]

  # Set OPCODE_BYTES=8 to dump with opcode bytes
  old_size = ida_ida.inf_get_bin_prefix_size()
  if old_size != 8:
    ida_idp.process_config_directive("OPCODE_BYTES=8")

  try:
    for start, end in ranges:
      lines = _custom_gen_disasm_text(start, end)
      key = f"{hex(start)}_{hex(end)}"
      ida_view_dump[key] = "\n".join(lines)
  finally:
    if old_size != 8:
      ida_idp.process_config_directive(f"OPCODE_BYTES={old_size}")
  return ida_view_dump


def dump_disassemble_function() -> dict[str, str]:
  """Extracts disassembly for functions (range disassembly)."""
  disasm_func_dump = {}
  start_addr = 0x11E0
  end_addr = 0x1208

  old_size = ida_ida.inf_get_bin_prefix_size()
  if old_size != 8:
    ida_idp.process_config_directive("OPCODE_BYTES=8")

  try:
    lines = _custom_gen_disasm_text(start_addr, end_addr)
    disasm_func_dump["0x11e0"] = "\n".join(lines)
  finally:
    if old_size != 8:
      ida_idp.process_config_directive(f"OPCODE_BYTES={old_size}")
  return disasm_func_dump


def dump_stack_vars() -> dict:
  """Extracts analysed function local stack frame structure variables."""
  stack_vars_dump = {}
  target_stack_vars_eas = [0x1270]
  for ea in target_stack_vars_eas:
    bounds = helper.get_func_bounds(ea)
    if bounds:
      tif = ida_typeinf.tinfo_t()
      if helper.get_func_frame(tif, ea) and tif.is_udt():
        udt = ida_typeinf.udt_type_data_t()
        tif.get_udt_details(udt)
        rv = []
        for udm in udt:
          if not udm.is_gap():
            rv.append({
                "name": udm.name,
                "offset": hex(udm.offset // 8),
                "size": hex(udm.size // 8),
                "type": str(udm.type),
            })
        stack_vars_dump[hex(bounds.start_ea)] = rv
  return stack_vars_dump


def dump_struct_at_address() -> dict:
  """Extracts structural object field boundaries rebased at target addresses."""
  struct_at_addr_dump = {}
  address = 0x4078
  struct_name = "TestStruct"
  tif = ida_typeinf.tinfo_t()
  if tif.get_named_type(None, struct_name):
    udt_data = ida_typeinf.udt_type_data_t()
    if tif.get_udt_details(udt_data):
      rv = []
      for member in udt_data:
        offset = member.begin() // 8
        member_addr = address + offset
        member_size = member.type.get_size()
        if member_size == 1:
          val = idaapi.get_byte(member_addr)
          val_str = f"0x{val:02X} ({val})"
        elif member_size == 2:
          val = idaapi.get_word(member_addr)
          val_str = f"0x{val:04X} ({val})"
        elif member_size == 4:
          val = idaapi.get_dword(member_addr)
          val_str = f"0x{val:08X} ({val})"
        elif member_size == 8:
          val = idaapi.get_qword(member_addr)
          val_str = f"0x{val:016X} ({val})"
        else:
          val_str = f"<size {member_size}>"
        rv.append({
            "offset": f"0x{offset:08X}",
            "type": member.type._print(),
            "name": member.name,
            "value": val_str,
        })
      struct_at_addr_dump[f"{hex(address)}_{struct_name}"] = {
          "struct_name": struct_name,
          "address": hex(address),
          "members": rv,
      }
  return struct_at_addr_dump


# --- Main Orchestration Entry Point ---


def decompile_all():
  """Decompile all functions to force type resolution for local variables."""
  logger.info("Decompiling all functions to resolve local types...")
  if ida_hexrays.init_hexrays_plugin():
    for func_ea in idautils.Functions():
      try:
        # decompile() will trigger full analysis of the function
        ida_hexrays.decompile(func_ea)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.debug("Failed to decompile function at %x: %s", func_ea, e)


def main():
  """Orchestrates extraction of golden ground truth."""
  # Block until IDA's automatic background analysis is fully complete
  ida_auto.auto_wait()

  # Force decompilation of all functions to resolve local types before dumping
  decompile_all()

  logger.info(
      "Auto-analysis complete. Initiating ground-truth golden data dump..."
  )

  # Master dictionary mapping sections
  golden_data = {}

  # Setup dynamic execution list with detailed logger prints
  module_dumpers = {
      "metadata": dump_metadata,
      "functions": dump_functions,
      "globals": dump_globals,
      "segments": dump_segments,
      "imports": dump_imports,
      "strings": dump_strings,
      "operands": dump_operands,
      "basic_blocks": dump_basic_blocks,
      "function_flags": dump_function_flags,
      "xrefs_from": dump_xrefs_from,
      "xrefs_to": dump_xrefs_to,
      "data_xrefs_from": dump_data_xrefs_from,
      "xrefs_to_field": dump_xrefs_to_field,
      "callees": dump_callees,
      "callers": dump_callers,
      "entry_points": dump_entry_points,
      "call_graph_from": dump_call_graph_from,
      "call_graph_to": dump_call_graph_to,
      "call_graph_between": dump_call_graph_between,
      "cfgs": dump_cfgs,
      "decompiled": dump_decompiled,
      "disasm": dump_disasm,
      "ida_view": dump_ida_view,
      "disassemble_function": dump_disassemble_function,
      "stack_vars": dump_stack_vars,
      "struct_at_address": dump_struct_at_address,
  }

  for name, dumper_func in module_dumpers.items():
    try:
      logger.info("Dumping %s...", name)
      golden_data[name] = dumper_func()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.exception(
          "FAIL: Section '%s' failed to dump due to error: %s", name, e
      )

  # Output file target resolution
  output_file = os.environ.get("GOLDEN_OUTPUT", "tests/golden_data.json")
  try:
    with open(output_file, "w", encoding="utf-8") as f:
      json.dump(golden_data, f, indent=2)
    logger.info(
        "SUCCESS: Golden ground-truth data successfully written to %s",
        output_file,
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.exception("FATAL: Failed to write golden output file: %s", e)

  # Safely exit native IDA environment
  ida_pro.qexit(0)


if __name__ == "__main__":
  main()
