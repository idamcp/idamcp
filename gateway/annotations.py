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

"""MCP tool annotations (behavior hints) for gateway tools.

Clients use these hints to decide, for example, which calls may run without a
confirmation prompt. They are hints only; they do not enforce anything.

The classification is explicit rather than derived from @idaread/@idawrite:
those decorators select the IDA thread synchronization mode, not whether a
tool changes state (e.g. dbg_start_process is @idaread).

Every tool the gateway registers must appear in exactly one set below;
tests/test_annotations.py enforces this.
"""

from typing import Any

# Reads the database or debugger state only. Repeating the call has no effect.
READ_ONLY = frozenset({
    # Gateway
    "list_available_databases",
    "sql_query",
    # Analysis
    "decompile_function",
    "disassemble_code",
    "disassemble_function",
    "get_basic_block",
    "get_call_graph_between",
    "get_call_graph_from",
    "get_call_graph_to",
    "get_callees",
    "get_callers",
    "get_comment",
    "get_current_address",
    "get_current_function",
    "get_data_xrefs_from",
    "get_entry_points",
    "get_function_by_address",
    "get_function_cfg",
    "get_function_flags",
    "get_global_variable_value_at_address",
    "get_global_variable_value_by_name",
    "get_ida_view",
    "get_metadata",
    "get_operand",
    "get_stack_frame_variables",
    "get_start_ea",
    "get_struct_at_address",
    "get_xrefs_from",
    "get_xrefs_to",
    "get_xrefs_to_field",
    "hexdump",
    "list_bookmarks",
    "list_enums",
    "list_functions",
    "list_globals",
    "list_imports",
    "list_local_types",
    "list_patched_bytes",
    "list_segments",
    "list_strings",
    "list_structs",
    "read_data",
    "search_binary",
    "search_text",
    # Debugger state
    "dbg_get_all_registers_for_all_threads",
    "dbg_get_all_registers_for_current_thread",
    "dbg_get_all_registers_for_thread",
    "dbg_get_call_stack",
    "dbg_get_registers_for_current_thread",
    "dbg_get_registers_for_thread",
    "dbg_list_breakpoints",
})

# Changes the database, the IDA UI, the debugger state or local files, but
# does not run the target binary or arbitrary code.
LOCAL_CHANGE = frozenset({
    # Gateway
    "idalib_headless_close",
    "idalib_headless_open",
    "patch_assembly",
    # Database
    "add_entry_points",
    "apply_enums_to_operands",
    "convert_to_offsets",
    "create_stack_frame_variables",
    "declare_type",
    "delete_stack_frame_variables",
    "make_arrays",
    "make_code",
    "make_data_batch",
    "make_function",
    "make_strings",
    "make_structs",
    "patch_bytes",
    "rename_addresses",
    "rename_local_variables",
    "rename_stack_frame_variables",
    "set_colors",
    "set_comment",
    "set_functions_noret",
    "set_local_variable_types",
    "set_stack_frame_variable_types",
    "set_types",
    "undefine",
    # UI
    "jump_to_address",
    # Writes a file on the host
    "export_file",
    # Debugger state, without running the target
    "dbg_delete_breakpoint",
    "dbg_enable_breakpoint",
    "dbg_exit_process",
    "dbg_set_breakpoint",
})

# Runs the target binary or arbitrary Python, so the effects are not limited
# to the database.
OPEN_WORLD = frozenset({
    "idapython_eval",
    "dbg_start_process",
    "dbg_continue_process",
    "dbg_run_to",
    "dbg_step_into",
    "dbg_step_over",
})


def annotations_for(tool_name: str) -> dict[str, Any] | None:
  """Returns MCP ToolAnnotations fields for a tool, or None if unclassified.

  destructiveHint is left unset for non-read-only tools, so clients apply the
  MCP default (true).
  """
  if tool_name in READ_ONLY:
    return {
        "readOnlyHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    }
  if tool_name in LOCAL_CHANGE:
    return {"readOnlyHint": False, "openWorldHint": False}
  if tool_name in OPEN_WORLD:
    return {"readOnlyHint": False, "openWorldHint": True}
  return None
