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

# WARNING: This file is generated, DO NOT edit it directly.
import argparse
import contextlib
from typing import Annotated, Any, Dict, List, Literal
from gateway.forward import forward_to, mcp_server, mcp_tool
from shared.config import load_config
from shared.types import *

try:
  import gateway.patcher

  _ = gateway.patcher
except ImportError as e:
  print(
      f"[WARNING] Failed to load gateway.patcher: {e}. 'patch_assembly' tool"
      " will not be available."
  )

try:
  import gateway.query

  _ = gateway.query
except ImportError as e:
  print(
      f"[WARNING] Failed to load gateway.query: {e}. 'sql_query' tool will"
      " not be available."
  )


@mcp_tool
async def get_xrefs_from(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to get cross-references from"],
) -> list[Xref]:
  """Retrieves all cross-references originating from a specific address."""
  return await forward_to(database_id, "get_xrefs_from", locals())


@mcp_tool
async def decompile_function(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to decompile"],
    include_line_prefix: Annotated[
        bool,
        "Whether to include the line prefix (line numbers and addresses) in the"
        " decompiled output",
    ] = False,
) -> str:
  """Decompile a function at the given address."""
  return await forward_to(database_id, "decompile_function", locals())


@mcp_tool
async def disassemble_code(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to disassemble code"],
    count: Annotated[int, "Number of instructions to disassemble"] = 1,
    include_bytes: Annotated[
        bool, "Whether to include opcode bytes in the disassembly output"
    ] = False,
) -> str:
  """Disassemble instructions starting at the given address.

  This function always treats the data at the address as code (forcing
  disassembly), making it suitable for analyzing irregular code, obfuscated
  code, or code starting at arbitrary offsets.

  For standard code analysis where you want to see IDA's full disassembly view
  (including data, directives, and formatted comments), 'get_ida_view' is
  preferred.
  """
  return await forward_to(database_id, "disassemble_code", locals())


@mcp_tool
async def get_ida_view(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    start_ea: Annotated[str, "Start address of the view"],
    end_ea: Annotated[str, "End address of the view"],
    include_bytes: Annotated[
        bool, "Whether to include opcode or data bytes in the view output"
    ] = False,
) -> str:
  """Retrieves the formatted text view directly from IDA Pro's 'IDA View-A'.

  CRITICAL: Use this tool (NOT disassemble_code) when inspecting data segments,
  global variables, arrays, or applied C-structures. It accurately renders data
  directives (DCB/DCD/DCQ), strings, cross-references, and applied struct
  formatting (e.g., my_struct_t <1, 2>). It is also the preferred tool for
  reading standard assembly code with inline comments.
  """
  return await forward_to(database_id, "get_ida_view", locals())


@mcp_tool
async def disassemble_function(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to disassemble"],
    include_bytes: Annotated[
        bool, "Whether to include opcode bytes in the disassembly output"
    ] = False,
) -> str:
  """Get assembly code for a function (API-compatible with older IDA builds)."""
  return await forward_to(database_id, "disassemble_function", locals())


@mcp_tool
async def get_xrefs_to(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to get cross references to"],
) -> list[Xref]:
  """Get all cross references to the given address."""
  return await forward_to(database_id, "get_xrefs_to", locals())


@mcp_tool
async def get_xrefs_to_field(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    struct_name: Annotated[
        str, "Name of the struct (type) containing the field"
    ],
    field_name: Annotated[str, "Name of the field (member) to get xrefs to"],
) -> list[Xref]:
  """Get all cross references to a named struct field (member)."""
  return await forward_to(database_id, "get_xrefs_to_field", locals())


@mcp_tool
async def get_callees(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to get callee functions"],
) -> list[Function]:
  """Get all callees of a function."""
  return await forward_to(database_id, "get_callees", locals())


@mcp_tool
async def get_callers(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to get callers"],
) -> list[Caller]:
  """Get all callers of the given address."""
  return await forward_to(database_id, "get_callers", locals())


@mcp_tool
async def get_entry_points(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> list[Function]:
  """Get all entry points in the database."""
  return await forward_to(database_id, "get_entry_points", locals())


@mcp_tool
async def get_start_ea(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> str:
  """Get the start entry point of the binary."""
  return await forward_to(database_id, "get_start_ea", locals())


@mcp_tool
async def get_call_graph_from(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to start from"],
    depth: Annotated[int, "Traversal depth"] = 2,
    max_nodes: Annotated[int, "Maximum number of nodes to return"] = 50,
) -> CallGraph:
  """Get the forward call graph from a function."""
  return await forward_to(database_id, "get_call_graph_from", locals())


@mcp_tool
async def get_call_graph_to(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to start from"],
    depth: Annotated[int, "Traversal depth"] = 2,
    max_nodes: Annotated[int, "Maximum number of nodes to return"] = 50,
) -> CallGraph:
  """Get the backward call graph to a function."""
  return await forward_to(database_id, "get_call_graph_to", locals())


@mcp_tool
async def get_call_graph_between(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    start_ea: Annotated[str, "Address of the start function"],
    end_ea: Annotated[str, "Address of the destination function"],
    max_depth: Annotated[int, "Maximum call depth"] = 5,
    max_paths: Annotated[int, "Maximum number of paths to return"] = 10,
) -> CallGraph:
  """Find paths between functions in the call graph."""
  return await forward_to(database_id, "get_call_graph_between", locals())


@mcp_tool
async def get_function_cfg(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to analyze"],
) -> ControlFlowGraph:
  """Get the Control Flow Graph (CFG) of a function."""
  return await forward_to(database_id, "get_function_cfg", locals())


@mcp_tool
async def search_binary(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
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
  return await forward_to(database_id, "search_binary", locals())


@mcp_tool
async def search_text(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
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
  return await forward_to(database_id, "search_text", locals())


@mcp_tool
async def undefine(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to undefine"],
    size: Annotated[int, "Number of bytes to undefine"] = 1,
) -> str:
  """Clear code/data definitions in a range (GUI: 'U')."""
  return await forward_to(database_id, "undefine", locals())


@mcp_tool
async def make_code(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to convert to instructions"],
) -> str:
  """Convert raw bytes to instructions at an address (GUI: 'C').

  This operation automatically undefines (GUI: 'U') any existing item at the
  specified address to allow for the creation of a new instruction.
  """
  return await forward_to(database_id, "make_code", locals())


@mcp_tool
async def make_function(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to define function"],
) -> str:
  """Define a function at a code location (GUI: 'P').

  To ensure success, this operation first undefines (GUI: 'U') any existing
  item at the address and converts it to code before establishing the function
  definition.
  """
  return await forward_to(database_id, "make_function", locals())


@mcp_tool
async def get_data_xrefs_from(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to get data xrefs from"],
) -> list[str]:
  """Retrieve the addresses pointed to by the data at a specific location."""
  return await forward_to(database_id, "get_data_xrefs_from", locals())


@mcp_tool
async def dbg_get_all_registers_for_all_threads(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> list[ThreadRegisters]:
  """Get all registers and their values.

  This function is only available when debugging.
  """
  return await forward_to(
      database_id, "dbg_get_all_registers_for_all_threads", locals()
  )


@mcp_tool
async def dbg_get_all_registers_for_thread(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    thread_id: Annotated[int, "ID of the thread to get registers for"],
) -> ThreadRegisters:
  """Get registers and their values for a specific thread."""
  return await forward_to(
      database_id, "dbg_get_all_registers_for_thread", locals()
  )


@mcp_tool
async def dbg_get_all_registers_for_current_thread(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> ThreadRegisters:
  """Get registers for the current thread."""
  return await forward_to(
      database_id, "dbg_get_all_registers_for_current_thread", locals()
  )


@mcp_tool
async def dbg_get_registers_for_thread(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    thread_id: Annotated[int, "ID of the thread to get specific registers for"],
    register_names: Annotated[
        str, "A comma-separated list of register names to retrieve"
    ],
) -> ThreadRegisters:
  """Get specific registers and their values for a given thread."""
  return await forward_to(database_id, "dbg_get_registers_for_thread", locals())


@mcp_tool
async def dbg_get_registers_for_current_thread(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    register_names: Annotated[
        str, "A comma-separated list of register names to retrieve"
    ],
) -> ThreadRegisters:
  """Get specific registers for the thread currently paused in the debugger."""
  return await forward_to(
      database_id, "dbg_get_registers_for_current_thread", locals()
  )


@mcp_tool
async def dbg_get_call_stack(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> list[dict[str, str]]:
  """Get the current call stack."""
  return await forward_to(database_id, "dbg_get_call_stack", locals())


@mcp_tool
async def dbg_list_breakpoints(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
):
  """List all breakpoints in the program."""
  return await forward_to(database_id, "dbg_list_breakpoints", locals())


@mcp_tool
async def dbg_start_process(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
):
  """Start the debugger, returns the current instruction pointer."""
  return await forward_to(database_id, "dbg_start_process", locals())


@mcp_tool
async def dbg_exit_process(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
):
  """Exit the debugger."""
  return await forward_to(database_id, "dbg_exit_process", locals())


@mcp_tool
async def dbg_continue_process(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> str:
  """Continue the debugger, returns the current instruction pointer."""
  return await forward_to(database_id, "dbg_continue_process", locals())


@mcp_tool
async def dbg_run_to(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Run the debugger to the specified address"],
):
  """Run the debugger to the specified address."""
  return await forward_to(database_id, "dbg_run_to", locals())


@mcp_tool
async def dbg_set_breakpoint(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Set a breakpoint at the specified address"],
):
  """Set a breakpoint at the specified address."""
  return await forward_to(database_id, "dbg_set_breakpoint", locals())


@mcp_tool
async def dbg_step_into(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
):
  """Step into the current instruction."""
  return await forward_to(database_id, "dbg_step_into", locals())


@mcp_tool
async def dbg_step_over(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
):
  """Step over the current instruction."""
  return await forward_to(database_id, "dbg_step_over", locals())


@mcp_tool
async def dbg_delete_breakpoint(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "del a breakpoint at the specified address"],
):
  """Delete a breakpoint at the specified address."""
  return await forward_to(database_id, "dbg_delete_breakpoint", locals())


@mcp_tool
async def dbg_enable_breakpoint(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[
        str, "Enable or disable a breakpoint at the specified address"
    ],
    enable: Annotated[bool, "Enable or disable a breakpoint"],
):
  """Enable or disable a breakpoint at the specified address."""
  return await forward_to(database_id, "dbg_enable_breakpoint", locals())


@mcp_tool
async def jump_to_address(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "The target address to jump to"],
) -> str:
  """Navigates the IDA UI (IDA View/Pseudocode) to the specified address."""
  return await forward_to(database_id, "jump_to_address", locals())


@mcp_tool
async def set_colors(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[List[SetColorRequest], "List of color setting requests"],
) -> str:
  """Sets the background color of items at specified addresses."""
  return await forward_to(database_id, "set_colors", locals())


@mcp_tool
async def set_comment(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
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
  return await forward_to(database_id, "set_comment", locals())


@mcp_tool
async def rename_local_variables(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function containing the variables"],
    renames: Annotated[
        List[LocalVariableRename], "List of variable renames to apply"
    ],
) -> str:
  """Rename local variables in a function."""
  return await forward_to(database_id, "rename_local_variables", locals())


@mcp_tool
async def rename_addresses(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[
        List[RenameAddressRequest], "List of requests of address renaming"
    ],
) -> str:
  """Set or delete name of items at the specified addresses."""
  return await forward_to(database_id, "rename_addresses", locals())


@mcp_tool
async def set_local_variable_types(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function containing the variables"],
    type_changes: Annotated[
        List[LocalVariableTypeChange], "List of variable type changes to apply"
    ],
) -> str:
  """Set local variables' types."""
  return await forward_to(database_id, "set_local_variable_types", locals())


@mcp_tool
async def rename_stack_frame_variables(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function containing the variables"],
    renames: Annotated[
        List[StackFrameVariableRename], "List of variable renames"
    ],
) -> str:
  """Change the name of stack variables for IDA functions."""
  return await forward_to(database_id, "rename_stack_frame_variables", locals())


@mcp_tool
async def create_stack_frame_variables(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function containing the variables"],
    creations: Annotated[
        List[StackFrameVariableCreate], "List of variable creations"
    ],
) -> str:
  """Creates stack variables for given functions."""
  return await forward_to(database_id, "create_stack_frame_variables", locals())


@mcp_tool
async def set_stack_frame_variable_types(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[
        str, "The hex address of the target function, e.g. '0x40000'"
    ],
    type_changes: Annotated[
        List[StackFrameVariableTypeChange], "List of variable type changes"
    ],
) -> str:
  """Updates the types for the variables within a function's stack frame."""
  return await forward_to(
      database_id, "set_stack_frame_variable_types", locals()
  )


@mcp_tool
async def delete_stack_frame_variables(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[
        str, "The hex address of the target function, e.g. '0x40000'"
    ],
    variable_names: Annotated[List[str], "List of variable names to delete"],
) -> str:
  """Delete the named stack variables for given functions."""
  return await forward_to(database_id, "delete_stack_frame_variables", locals())


@mcp_tool
async def set_functions_noret(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function"],
    is_noret: Annotated[bool, "True to mark as non-returning, False otherwise"],
) -> str:
  """Set or unset the non-returning flag for functions."""
  return await forward_to(database_id, "set_functions_noret", locals())


@mcp_tool
async def set_types(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[List[SetTypeRequest], "List of set type requests"],
) -> str:
  """Set type of functions/variables."""
  return await forward_to(database_id, "set_types", locals())


@mcp_tool
async def add_entry_points(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[
        List[AddEntryPointRequest], "List of add entry point requests"
    ],
) -> str:
  """Add entry points to the list of entry points."""
  return await forward_to(database_id, "add_entry_points", locals())


@mcp_tool
async def patch_bytes(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[List[PatchBytesRequest], "List of patch bytes requests"],
) -> str:
  """Patch bytes directly in memory."""
  return await forward_to(database_id, "patch_bytes", locals())


@mcp_tool
async def apply_enums_to_operands(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the instruction"],
    op_index: Annotated[int, "Operand index (0-based)"],
    enum_name: Annotated[str, "Name of the enum to apply"],
) -> str:
  """Replace imm-values in instructions with named Enum symbolic constants."""
  return await forward_to(database_id, "apply_enums_to_operands", locals())


@mcp_tool
async def convert_to_offsets(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[
        List[ConvertToOffsetRequest], "List of convert to offset requests"
    ],
) -> str:
  """Convert a number constant to an offset."""
  return await forward_to(database_id, "convert_to_offsets", locals())


@mcp_tool
async def make_data_batch(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[List[MakeDataRequest], "List of make data requests"],
) -> str:
  """Convert the current item to a primitive data type (byte, word, etc.)."""
  return await forward_to(database_id, "make_data_batch", locals())


@mcp_tool
async def make_structs(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to create structure instance at"],
    struct_name: Annotated[str, "Name of the structure type"],
    size: Annotated[
        int,
        "Structure size in bytes. Use -1 for automatic calculation (default).",
    ] = -1,
) -> str:
  """Convert the current item to a structure instance."""
  return await forward_to(database_id, "make_structs", locals())


@mcp_tool
async def make_strings(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
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
  return await forward_to(database_id, "make_strings", locals())


@mcp_tool
async def make_arrays(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to create array at"],
    count: Annotated[int, "Number of items in the array"],
) -> str:
  """Create an array of items starting at the specified address."""
  return await forward_to(database_id, "make_arrays", locals())


@mcp_tool
async def idapython_eval(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    code: Annotated[str, "Python code to execute"],
) -> Dict[str, Any]:
  """Execute Python code in IDA context.

  Returns dict with result/stdout/stderr. Has access to all IDA API modules.
  Supports Jupyter-style evaluation (returns the value of the last expression).
  Maintains persistent state across calls.
  """
  return await forward_to(database_id, "idapython_eval", locals())


@mcp_tool
async def export_file(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    file_type: Annotated[
        Literal["map", "exe", "idc", "lst", "asm", "dif", "c"],
        "Output file type: map, exe, idc, lst, asm, dif, c",
    ],
    output_path: Annotated[str | None, "Optional output file path"] = None,
    always_regenerate: Annotated[
        bool, "Regenerate even if file exists"
    ] = False,
) -> str:
  """Export the database to various file formats.

  The tool produces the same files as from the GUI menu File -> Produce Files.
  You can further process the generated file with other tools like
  ripgrep/grep/awk, etc.

  Returns:
      The path to the generated file.
  """
  return await forward_to(database_id, "export_file", locals())


@mcp_tool
async def get_comment(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to retrieve the comment from"],
) -> str:
  """Retrieves the comment associated with a specific address."""
  return await forward_to(database_id, "get_comment", locals())


@mcp_tool
async def get_metadata(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> Metadata:
  """Get metadata about the current IDB."""
  return await forward_to(database_id, "get_metadata", locals())


@mcp_tool
async def get_function_by_address(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the function to get"],
) -> Function:
  """Get a function by its address."""
  return await forward_to(database_id, "get_function_by_address", locals())


@mcp_tool
async def get_current_address(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> str:
  """Get the address currently selected by the user."""
  return await forward_to(database_id, "get_current_address", locals())


@mcp_tool
async def get_current_function(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> Function | str:
  """Get the function currently selected by the user."""
  return await forward_to(database_id, "get_current_function", locals())


@mcp_tool
async def get_basic_block(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address inside the basic block"],
) -> BasicBlock | str:
  """Get the basic block containing the specified address."""
  return await forward_to(database_id, "get_basic_block", locals())


@mcp_tool
async def get_function_flags(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to check"],
) -> list[FunctionFlags]:
  """Check if the address belongs to a library function (FLIRT)."""
  return await forward_to(database_id, "get_function_flags", locals())


@mcp_tool
async def list_functions(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
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
  return await forward_to(database_id, "list_functions", locals())


@mcp_tool
async def list_globals(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
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
  return await forward_to(database_id, "list_globals", locals())


@mcp_tool
async def list_imports(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    offset: Annotated[int, "Offset to start listing from (start at 0)"] = 0,
    count: Annotated[
        int,
        "Number of imports to list (100 is a good default, 0 means remainder)",
    ] = 0,
) -> Page[Import]:
  """List all imported symbols with their name and module (paginated)."""
  return await forward_to(database_id, "list_imports", locals())


@mcp_tool
async def list_strings(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
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
  return await forward_to(database_id, "list_strings", locals())


@mcp_tool
async def list_segments(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> list[Segment]:
  """List all segments in the binary."""
  return await forward_to(database_id, "list_segments", locals())


@mcp_tool
async def list_local_types(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    name_pattern: Annotated[
        str | None,
        "A regular expression used to filter the list (matching is always "
        + "case-insensitive). Return all types if this parameter is None or an"
        " empty string.",
    ] = None,
) -> str:
  """List Local types in the database."""
  return await forward_to(database_id, "list_local_types", locals())


@mcp_tool
async def list_patched_bytes(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> list[PatchedByte]:
  """List all patched bytes in the database."""
  return await forward_to(database_id, "list_patched_bytes", locals())


@mcp_tool
async def list_bookmarks(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
) -> list[Bookmark]:
  """List all bookmarks in the database."""
  return await forward_to(database_id, "list_bookmarks", locals())


@mcp_tool
async def get_operand(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address of the instruction"],
    op_index: Annotated[int, "Operand index (0-based)"],
) -> Operand:
  """Get the operand of an instruction."""
  return await forward_to(database_id, "get_operand", locals())


@mcp_tool
async def get_global_variable_value_by_name(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[List[str], "List of names of global variables"],
) -> List[BatchResponseItem]:
  """Read global variables' values (if known at compile-time).

  Prefer this function over the `read_*` functions.
  """
  return await forward_to(
      database_id, "get_global_variable_value_by_name", locals()
  )


@mcp_tool
async def get_global_variable_value_at_address(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[List[str], "List of addresses of global variables"],
) -> List[BatchResponseItem]:
  """Read global variables' values by their addresses (if known at compile-time).

  Prefer this function over the `read_*` functions.
  """
  return await forward_to(
      database_id, "get_global_variable_value_at_address", locals()
  )


@mcp_tool
async def read_data(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    reqs: Annotated[List[ReadDataRequest], "List of read data requests"],
) -> List[BatchResponseItem]:
  """Read formatted data from memory at given addresses."""
  return await forward_to(database_id, "read_data", locals())


@mcp_tool
async def hexdump(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address (e.g., '0x400000') to start the hexdump"],
    length: Annotated[
        int, "Length of the memory region to dump in bytes, max 0x1000 per call"
    ],
) -> str:
  """Get a formatted hexadecimal dump of memory at the specified address.

  Each request is limited to a maximum of 0x1000 bytes. This tool is useful for
  examining raw memory contents, such as unknown data structures, encrypted
  payloads, or inline strings.
  """
  return await forward_to(database_id, "hexdump", locals())


@mcp_tool
async def list_enums(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    name_pattern: Annotated[
        str,
        "Optional case-insensitive regular expression pattern to match"
        ' enum names (default: "", matches all).',
    ] = "",
    include_members: Annotated[
        bool,
        "Whether to include the list of members for each enum (default: True).",
    ] = True,
) -> list[EnumDefinition]:
  """Lists all defined enums (enumerated types) in the IDA database."""
  return await forward_to(database_id, "list_enums", locals())


@mcp_tool
async def declare_type(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    c_decl: Annotated[
        str,
        (
            "C declaration of the type. Examples include: typedef int foo_t; "
            "struct bar { int a; bool b; };"
        ),
    ],
) -> str:
  """Create or update a local type from a C declaration."""
  return await forward_to(database_id, "declare_type", locals())


@mcp_tool
async def list_structs(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    name_pattern: Annotated[
        str,
        "Optional case-insensitive regular expression pattern to match"
        ' structure names (default: "", matches all).',
    ] = "",
) -> list[StructureDefinition]:
  """Get structures with detailed member information.

  Optionally filter by name pattern.
  """
  return await forward_to(database_id, "list_structs", locals())


@mcp_tool
async def get_struct_at_address(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[str, "Address to analyze structure at"],
    struct_name: Annotated[str, "Name of the structure"],
) -> dict[str, Any]:
  """Get structure field values at a specific address."""
  return await forward_to(database_id, "get_struct_at_address", locals())


@mcp_tool
async def get_stack_frame_variables(
    database_id: Annotated[
        str,
        "The unique identifier for the target IDA database. You can obtain this"
        " ID by calling list_available_databases, reading the ida://databases"
        " resource, or by opening a new database via idalib_headless_open.",
    ],
    address: Annotated[
        str,
        (
            "Address of the disassembled function to retrieve the stack frame"
            " variables"
        ),
    ],
) -> list[StackFrameVariable]:
  """Retrieve the stack frame variables for a given function."""
  return await forward_to(database_id, "get_stack_frame_variables", locals())


if __name__ == "__main__":
  config = load_config()
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "--transport", default="sse", choices=["sse", "stdio", "http"]
  )
  parser.add_argument(
      "--host", type=str, help="Host to listen on (for SSE/HTTP transport)"
  )
  parser.add_argument(
      "--port", type=int, help="Port to listen on (for SSE/HTTP transport)"
  )
  args = parser.parse_args()

  if args.transport in ["sse", "http"]:
    host = (
        args.host
        if args.host is not None
        else config.get("proxy_host", "localhost")
    )
    port = (
        args.port if args.port is not None else config.get("proxy_port", 8000)
    )
    with contextlib.suppress(KeyboardInterrupt):
      mcp_server.run(transport=args.transport, host=host, port=port)
  else:
    with contextlib.suppress(KeyboardInterrupt):
      mcp_server.run(transport="stdio")
