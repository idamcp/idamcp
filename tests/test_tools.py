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


import asyncio
import contextlib
import json
import logging
import os
import pathlib
import shlex
import signal
import sys
import tempfile
import time
import traceback
import typing
import unittest
import mcp
import mcp.client.stdio
from shared.config import load_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("asyncio").setLevel(logging.WARNING)


def _is_process_running(pid: int) -> bool:
  if sys.platform == "win32":
    try:
      import ctypes  # pylint: disable=g-import-not-at-top

      kernel32 = ctypes.windll.kernel32
      # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
      handle = kernel32.OpenProcess(0x1000, False, pid)
      if handle:
        kernel32.CloseHandle(handle)
        return True
      return False
    except Exception:  # pylint: disable=broad-exception-caught
      return False
  else:
    try:
      os.kill(pid, 0)
      return True
    except OSError:
      return False


def normalize_text(text: str) -> str:
  text = text.replace("\r\n", "\n")
  for cc in ["__cdecl", "__stdcall", "__fastcall", "__thiscall"]:
    text = text.replace(cc + " ", "").replace(cc, "")
  for i in range(1, 10):
    text = text.replace(f"a{i}: ", "")
  lines = []
  for line in text.split("\n"):
    lines.append(" ".join(line.split()))
  return "\n".join(lines).strip()


class TestIDAMCP(unittest.IsolatedAsyncioTestCase):
  session = None
  db_id = None
  exit_stack = None
  current_filepath = None

  async def setup_shared_resources(self):
    self.exit_stack = contextlib.AsyncExitStack()

    # Ensure clean state
    for binary in ["test_binary", "test_binary_arm64"]:
      for ext in [".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".db"]:
        f = os.path.join("tests", binary + ext)
        if os.path.exists(f):
          try:
            os.remove(f)
          except OSError:
            pass

    # Clean up registry and UDS directories
    config = load_config()
    for dir_key in ["registry_dir", "uds_dir"]:
      if dir_path := config.get(dir_key):
        p = pathlib.Path(dir_path)
        if p.exists():
          for child in p.iterdir():
            if child.is_file():
              try:
                child.unlink()
              except OSError:
                pass

    cmds = [sys.executable, "gateway/proxy.py", "--transport", "stdio"]
    server_params = mcp.StdioServerParameters(
        command=cmds[0],
        args=cmds[1:],
        env=dict(
            os.environ,
            PYTHONPATH=".",
            ENABLED_UNSAFE_TOOLS="idapython_eval",
            ENABLE_ALL_UNSAFE_TOOLS="true",
        ),
    )

    print("Connecting to gateway...")
    read, write = await self.exit_stack.enter_async_context(
        mcp.client.stdio.stdio_client(server_params)
    )
    print("Connected. Creating session...")
    self.session = await self.exit_stack.enter_async_context(
        mcp.ClientSession(read, write)
    )
    print("Initializing session...")
    await self.session.initialize()

    print("Opening database...")
    self.current_filepath = "tests/test_binary"
    abs_path = os.path.abspath(self.current_filepath)
    open_resp = await self.session.call_tool(
        "idalib_headless_open", {"path": abs_path}
    )
    if open_resp.isError:
      raise RuntimeError(f"Failed to open database: {open_resp}")
    self.db_id = open_resp.structuredContent["database_id"]
    print(f"Database opened, ID: {self.db_id}")

    print("Waiting for database to be available...")
    for _ in range(50):
      dbs_resp = await self.session.call_tool("list_available_databases", {})
      if not dbs_resp.isError:
        db_list = json.loads(dbs_resp.content[0].text)
        if self.db_id in {db["database_id"] for db in db_list}:
          print("Database is available!")
          break
      await asyncio.sleep(0.1)
    else:
      raise RuntimeError(
          "Failed to open database and find it in available list"
      )

  async def teardown_shared_resources(self):
    print("Tearing down resources...")
    try:
      if self.db_id and self.session:
        await self.session.call_tool(
            "idalib_headless_close", {"database_id": self.db_id}
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
      print(f"Error closing database: {e}")
    finally:
      await self.exit_stack.aclose()
      if self.current_filepath:
        base_path = os.path.abspath(self.current_filepath)
        for ext in [".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".db"]:
          f = base_path + ext
          if os.path.exists(f):
            try:
              os.remove(f)
              print(f"Cleaned up temporary file: {f}")
            except OSError as e:
              print(f"Warning: failed to remove temporary file {f}: {e}")
      print("Teardown complete.")

  async def run_tool(self, tool_name: str, **kwargs) -> dict[str, typing.Any]:
    kwargs["database_id"] = self.db_id
    resp = await self.session.call_tool(tool_name, kwargs)
    if resp.isError:
      raise RuntimeError(
          f"Tool {tool_name} failed:"
          f" {resp.content[0].text if resp.content else ''}"
      )

    # Unpack content if it is text and JSON
    if resp.content and resp.content[0].type == "text":
      try:
        return json.loads(resp.content[0].text)
      except json.JSONDecodeError:
        return resp.content[0].text

    if resp.structuredContent and "result" in resp.structuredContent:
      return resp.structuredContent["result"]

    return resp.structuredContent

  async def switch_database(self, binary_name: str) -> str:
    # Close current if any
    if self.db_id:
      print(f"Closing current database {self.db_id}...")
      try:
        metadata = await self.run_tool("get_metadata")
        filepath = metadata.get("filepath", "")
        pid = metadata.get("pid")
      except Exception as e:
        print(f"Warning: failed to get metadata before closing: {e}")
        filepath = ""
        pid = None

      db_id_to_close = self.db_id
      await self.session.call_tool(
          "idalib_headless_close",
          {"database_id": db_id_to_close},
      )
      self.db_id = None

      # Wait for backend process to exit
      if pid:
        print(f"Waiting for backend process {pid} to exit...")
        for _ in range(100):
          if not _is_process_running(pid):
            print("Process exited!")
            break
          await asyncio.sleep(0.1)
        else:
          print(f"Warning: Process {pid} did not exit in time, killing it...")
          try:
            sig = getattr(signal, "SIGKILL", getattr(signal, "SIGTERM", 15))
            os.kill(pid, sig)
          except OSError:
            pass
          await asyncio.sleep(0.5)

      # Manually delete registry file to trigger gateway unregister immediately
      # and avoid any late exit deletion races.
      registry_path = os.path.join(
          tempfile.gettempdir(), "ida_mcp", f"{db_id_to_close}.json"
      )
      if os.path.exists(registry_path):
        try:
          os.remove(registry_path)
          print(f"Manually removed registry file: {registry_path}")
        except OSError as e:
          print(f"Warning: failed to remove registry file {registry_path}: {e}")

      # Small extra sleep to ensure gateway has processed the deletion
      await asyncio.sleep(0.5)

      # Clean up files for the closed database
      if filepath:
        base_path = os.path.abspath(filepath)
        for ext in [".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".db"]:
          f = base_path + ext
          if os.path.exists(f):
            try:
              os.remove(f)
              print(f"Cleaned up temporary file: {f}")
            except OSError as e:
              print(f"Warning: failed to remove temporary file {f}: {e}")

    print(f"Opening database {binary_name}...")
    self.current_filepath = binary_name
    abs_path = os.path.abspath(self.current_filepath)
    open_resp = await self.session.call_tool(
        "idalib_headless_open", {"path": abs_path}
    )
    if open_resp.isError:
      raise RuntimeError(f"Failed to open database {binary_name}: {open_resp}")
    self.db_id = open_resp.structuredContent["database_id"]
    print(f"Database opened, ID: {self.db_id}")

    print("Waiting for database to be available...")
    for _ in range(50):
      dbs_resp = await self.session.call_tool("list_available_databases", {})
      if not dbs_resp.isError:
        db_list = json.loads(dbs_resp.content[0].text)
        if self.db_id in {db["database_id"] for db in db_list}:
          print("Database is available!")
          break
      await asyncio.sleep(0.1)
    else:
      raise RuntimeError("Failed to find database in available list")

    return self.db_id

  async def test_all(self):
    await self.setup_shared_resources()

    tests = [
        self.verify_get_metadata,
        self.verify_get_function_by_address,
        self.verify_list_functions,
        self.verify_list_globals,
        self.verify_list_segments,
        self.verify_list_imports,
        self.verify_list_strings,
        self.verify_get_operand,
        self.verify_get_comment,
        self.verify_set_comment,
        self.verify_get_basic_block,
        self.verify_get_function_flags,
        self.verify_list_bookmarks,
        self.verify_list_enums,
        self.verify_list_structs,
        self.verify_get_xrefs_from,
        self.verify_get_xrefs_to,
        self.verify_get_data_xrefs_from,
        self.verify_get_xrefs_to_field,
        self.verify_get_xrefs_to_tid,
        self.verify_get_callees,
        self.verify_get_callers,
        self.verify_get_entry_points,
        self.verify_get_start_ea,
        self.verify_get_call_graph_from,
        self.verify_get_call_graph_to,
        self.verify_get_call_graph_between,
        self.verify_get_function_cfg,
        self.verify_decompile_function,
        self.verify_disassemble_code,
        self.verify_disassemble_function,
        self.verify_get_ida_view,
        self.verify_get_stack_frame_variables,
        self.verify_stack_frame_variables_lifecycle,
        self.verify_local_variables_lifecycle,
        self.verify_get_struct_at_address,
        self.verify_patching_lifecycle,
        self.verify_code_and_function_lifecycle,
        self.verify_types_and_patching_lifecycle,
        self.verify_memory_and_search_lifecycle,
        self.verify_misc_write_lifecycle,
        self.verify_invalid_addresses_corner_cases,
        self.verify_malformed_inputs_corner_cases,
        self.verify_type_declaration_error_cases,
        self.verify_sql_query_advanced,
        self.verify_xrefs_lifecycle,
        self.verify_sql_entries_table,
        self.verify_safe_eval,
        self.verify_safe_eval_via_patch_assembly,
        self.verify_timeout_busy_handling,
        self.verify_timeout_gil_starvation_handling,
        self.verify_xrefs_offset_issue,
        self.verify_db_versioning_and_migration,
        self.verify_lock_reentrancy_no_deadlock,
        self.verify_sql_query_cancellation_and_recovery,
    ]

    errors = []
    for test in tests:
      try:
        print(f"\n--- Running {test.__name__} ---")
        await test()
        print(f"--- {test.__name__} PASSED ---")
      except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"--- {test.__name__} FAILED: {e} ---")

        traceback.print_exc()
        errors.append((test.__name__, e))

    await self.teardown_shared_resources()

    if errors:
      self.fail(f"Some tests failed: {[name for name, _ in errors]}")

  # --- Actual Tests ---

  async def verify_get_metadata(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["metadata"]

    result = await self.run_tool("get_metadata")

    # Assertions
    self.assertTrue(
        result["filepath"].replace("\\", "/").endswith("tests/test_binary")
    )
    self.assertTrue(
        result["database_path"]
        .replace("\\", "/")
        .endswith("tests/test_binary.i64")
    )

    self.assertEqual(result["module"], golden["module"])
    self.assertEqual(result["imagebase"], golden["imagebase"])
    self.assertEqual(result["imagesize"], golden["imagesize"])
    self.assertEqual(result["sha256"], golden["sha256"])
    self.assertEqual(result["filesize"], golden["filesize"])
    self.assertEqual(result["filetype"], golden["filetype"])
    self.assertEqual(result["bitness"], golden["bitness"])
    self.assertEqual(result["procname"], golden["procname"])
    self.assertEqual(result["is_headless"], golden["is_headless"])

  async def verify_get_function_by_address(self):
    result = await self.run_tool("get_function_by_address", address="0x1240")
    self.assertIsInstance(result, dict)
    self.assertEqual(int(result["address"], 16), 0x1240)
    self.assertEqual(result["name"], "_Z11caller_funci")
    self.assertEqual(int(result["size"], 16), 0x28)

  async def verify_list_functions(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["functions"]

    # 1. Test default listing (all functions)
    result = await self.run_tool("list_functions")
    self.assertIsInstance(result, dict)
    self.assertIn("data", result)
    # The default listing might have a default count limit in some cases,
    # but in proxy.py/info.py count=0 means remainder, which should be all.
    # Let's verify we get all of them.
    self.assertEqual(len(result["data"]), len(golden))
    for i, func in enumerate(result["data"]):
      self.assertEqual(func["address"], golden[i]["address"])
      self.assertEqual(func["name"], golden[i]["name"])
      self.assertEqual(func["size"], golden[i]["size"])

    # 2. Test pagination
    offset = 5
    count = 5
    result_paginated = await self.run_tool(
        "list_functions", offset=offset, count=count
    )
    self.assertEqual(len(result_paginated["data"]), count)
    for i, func in enumerate(result_paginated["data"]):
      self.assertEqual(func["address"], golden[offset + i]["address"])
      self.assertEqual(func["name"], golden[offset + i]["name"])
      self.assertEqual(func["size"], golden[offset + i]["size"])

    # 3. Test filtering
    result_filtered = await self.run_tool(
        "list_functions", regex_filter="call.*c"
    )
    # We know from golden data that only 2 functions match
    expected_names = {"_Z11callee_funcv", "_Z11caller_funci"}
    self.assertEqual(len(result_filtered["data"]), 2)
    for func in result_filtered["data"]:
      self.assertIn(func["name"], expected_names)

  async def verify_list_globals(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["globals"]

    # 1. Test default listing
    result = await self.run_tool("list_globals")
    self.assertIsInstance(result, dict)
    self.assertIn("data", result)
    self.assertNotIn(
        "next_offset", result
    )  # Should not be present because we exhausted it (count=100000)
    self.assertEqual(len(result["data"]), len(golden))
    for i, glob in enumerate(result["data"]):
      self.assertEqual(glob["address"], golden[i]["address"])
      self.assertEqual(glob["name"], golden[i]["name"])

    # 2. Test pagination
    offset = 5
    count = 5
    result_paginated = await self.run_tool(
        "list_globals", offset=offset, count=count
    )
    self.assertEqual(len(result_paginated["data"]), count)
    self.assertIn("next_offset", result_paginated)
    self.assertEqual(result_paginated["next_offset"], offset + count)
    for i, glob in enumerate(result_paginated["data"]):
      self.assertEqual(glob["address"], golden[offset + i]["address"])
      self.assertEqual(glob["name"], golden[offset + i]["name"])

    # 3. Test filtering
    result_filtered = await self.run_tool(
        "list_globals", regex_filter="^global_"
    )
    expected_names = {
        "global_int",
        "global_char",
        "global_short",
        "global_double",
        "global_string",
        "global_string2",
        "global_struct",
    }
    self.assertEqual(len(result_filtered["data"]), 7)
    self.assertNotIn("next_offset", result_filtered)  # Exhausted (count=100000)
    for glob in result_filtered["data"]:
      self.assertIn(glob["name"], expected_names)

  async def verify_list_segments(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["segments"]

    result = await self.run_tool("list_segments")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))
    for i, seg in enumerate(result):
      self.assertEqual(seg["name"], golden[i]["name"])
      self.assertEqual(seg["start"], golden[i]["start"])
      self.assertEqual(seg["end"], golden[i]["end"])
      self.assertEqual(seg["size"], golden[i]["size"])
      self.assertEqual(seg["permissions"], golden[i]["permissions"])

  async def verify_list_imports(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["imports"]

    # 1. Test default listing
    result = await self.run_tool("list_imports")
    self.assertIsInstance(result, dict)
    self.assertIn("data", result)
    self.assertEqual(len(result["data"]), len(golden))
    for i, imp in enumerate(result["data"]):
      self.assertEqual(imp["address"], golden[i]["address"])
      self.assertEqual(imp["imported_name"], golden[i]["imported_name"])
      self.assertEqual(imp["module"], golden[i]["module"])

    # 2. Test pagination
    offset = 5
    count = 5
    result_paginated = await self.run_tool(
        "list_imports", offset=offset, count=count
    )
    self.assertEqual(len(result_paginated["data"]), count)
    for i, imp in enumerate(result_paginated["data"]):
      self.assertEqual(imp["address"], golden[offset + i]["address"])
      self.assertEqual(
          imp["imported_name"], golden[offset + i]["imported_name"]
      )
      self.assertEqual(imp["module"], golden[offset + i]["module"])

  async def verify_list_strings(self):
    # Save original string options and set to default
    save_code = (
        "import ida_strlist\nimport idautils\nopt ="
        " ida_strlist.get_strlist_options()\n_saved_strlist_opt = {\n   "
        " 'strtypes': list(opt.strtypes),\n    'minlen': opt.minlen,\n   "
        " 'only_7bit': opt.only_7bit,\n    'display_only_existing_strings':"
        " opt.display_only_existing_strings,\n    'ignore_heads':"
        " opt.ignore_heads,\n}\nidautils.Strings(default_setup=True)\n"
    )
    await self.run_tool("idapython_eval", code=save_code)

    try:
      # Load golden data
      golden_path = os.path.join("tests", "golden_data.json")
      with open(golden_path, "r") as f:
        golden = json.load(f)["strings"]

      # 1. Test default listing
      result = await self.run_tool("list_strings")
      self.assertIsInstance(result, dict)
      self.assertIn("data", result)
      self.assertEqual(len(result["data"]), len(golden))
      for i, s in enumerate(result["data"]):
        self.assertEqual(s["address"], golden[i]["address"])
        self.assertEqual(s["length"], golden[i]["length"])
        self.assertEqual(s["string"], golden[i]["string"])

      # 2. Test pagination
      offset = 5
      count = 5
      result_paginated = await self.run_tool(
          "list_strings", offset=offset, count=count
      )
      self.assertEqual(len(result_paginated["data"]), count)
      for i, s in enumerate(result_paginated["data"]):
        self.assertEqual(s["address"], golden[offset + i]["address"])
        self.assertEqual(s["length"], golden[offset + i]["length"])
        self.assertEqual(s["string"], golden[offset + i]["string"])

      # 3. Test filtering
      result_filtered = await self.run_tool("list_strings", regex_filter="lib")
      expected_strings = {
          "/lib64/ld-linux-x86-64.so.2",
          "_ZSt21ios_base_library_initv",
          "__libc_start_main",
          "libstdc++.so.6",
          "libm.so.6",
          "libgcc_s.so.1",
          "libc.so.6",
          "GLIBCXX_3.4.32",
          "GLIBCXX_3.4",
          "GLIBC_2.14",
          "GLIBC_2.34",
          "GLIBC_2.2.5",
      }
      self.assertEqual(len(result_filtered["data"]), 12)
      for s in result_filtered["data"]:
        self.assertIn(s["string"], expected_strings)
    finally:
      restore_code = (
          "import ida_strlist\n"
          "if '_saved_strlist_opt' in globals():\n"
          "    opt = ida_strlist.get_strlist_options()\n"
          "    opt.strtypes = _saved_strlist_opt['strtypes']\n"
          "    opt.minlen = _saved_strlist_opt['minlen']\n"
          "    opt.only_7bit = _saved_strlist_opt['only_7bit']\n"
          "    opt.display_only_existing_strings ="
          " _saved_strlist_opt['display_only_existing_strings']\n"
          "    opt.ignore_heads = _saved_strlist_opt['ignore_heads']\n"
          "    ida_strlist.build_strlist()\n"
      )
      await self.run_tool("idapython_eval", code=restore_code)

  async def verify_get_operand(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["operands"]["0x11c8"]

    # Test Op 0
    result0 = await self.run_tool("get_operand", address="0x11c8", op_index=0)
    self.assertIsInstance(result0, dict)
    self.assertEqual(result0["type"], golden[0]["type"])
    self.assertEqual(result0["value"], golden[0]["value"])

    # Test Op 1
    result1 = await self.run_tool("get_operand", address="0x11c8", op_index=1)
    self.assertIsInstance(result1, dict)
    self.assertEqual(result1["type"], golden[1]["type"])
    self.assertEqual(result1["value"], golden[1]["value"])

  async def verify_get_comment(self):
    # We found that 0x10e4 has comment "main / None" (regular comment "main")
    result = await self.run_tool("get_comment", address="0x10e4")
    self.assertIsInstance(result, str)
    self.assertIn("Comment: main", result)

  async def verify_set_comment(self):
    target_addr = "0x1240"  # caller_func
    test_comment = "This is a test comment by unit tests"

    # 1. Set comment
    set_result = await self.run_tool(
        "set_comment", address=target_addr, comment=test_comment
    )
    self.assertIsInstance(set_result, dict)
    self.assertEqual(set_result.get("disassembly_comment_status"), "success")
    self.assertEqual(set_result.get("pseudocode_comment_status"), "success")

    # 2. Get comment to verify
    get_result = await self.run_tool("get_comment", address=target_addr)
    self.assertIn(test_comment, get_result)

    # 3. Clear comment (set to empty)
    clear_result = await self.run_tool(
        "set_comment", address=target_addr, comment=""
    )
    self.assertIsInstance(clear_result, dict)
    self.assertEqual(clear_result.get("disassembly_comment_status"), "success")
    self.assertEqual(clear_result.get("pseudocode_comment_status"), "success")

    # 4. Verify it is cleared
    get_cleared = await self.run_tool("get_comment", address=target_addr)
    self.assertNotIn(test_comment, get_cleared)

    # 5. Test set_comment on non-function address (should succeed for disassembly, N/A for pseudocode with error)
    non_func_addr = "0x2000"
    non_func_comment = "Non-function comment"
    set_non_func_result = await self.run_tool(
        "set_comment", address=non_func_addr, comment=non_func_comment
    )
    self.assertIsInstance(set_non_func_result, dict)
    self.assertEqual(
        set_non_func_result.get("disassembly_comment_status"), "success"
    )
    self.assertEqual(
        set_non_func_result.get("pseudocode_comment_status"), "not_applicable"
    )
    self.assertIn(
        "doesn't belong to any function",
        set_non_func_result.get("pseudocode_comment_error", ""),
    )

    # 6. Verify comment was set in disassembly
    get_non_func = await self.run_tool("get_comment", address=non_func_addr)
    self.assertIn(non_func_comment, get_non_func)

    # 7. Clear comment
    await self.run_tool("set_comment", address=non_func_addr, comment="")

  async def verify_get_basic_block(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["basic_blocks"]["0x1240"]

    # 1. Test valid basic block
    result = await self.run_tool("get_basic_block", address="0x1240")
    self.assertIsInstance(result, dict)
    self.assertEqual(result["id"], golden["id"])
    self.assertEqual(result["start"], golden["start"])
    self.assertEqual(result["end"], golden["end"])
    self.assertEqual(result["successors"], golden["successors"])
    self.assertEqual(result["predecessors"], golden["predecessors"])

    # 2. Test address not in function (should return string)
    result_invalid = await self.run_tool("get_basic_block", address="0x1268")
    self.assertIsInstance(result_invalid, str)
    self.assertIn("isn't in a function", result_invalid)

  async def verify_get_function_flags(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["function_flags"]["0x1240"]

    result = await self.run_tool("get_function_flags", address="0x1240")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))

    expected_flags = {f["flag"] for f in golden}
    for flag_item in result:
      self.assertIn(flag_item["flag"], expected_flags)

  async def verify_list_bookmarks(self):
    # In headless mode, list_bookmarks is expected to return empty list because there is no GUI viewer
    result = await self.run_tool("list_bookmarks")
    self.assertIsInstance(result, list)
    self.assertEqual(result, [])

  async def verify_list_enums(self):
    # 1. Verify list_enums is initially empty (or at least doesn't have TestEnum)
    initial = await self.run_tool("list_enums")
    self.assertIsInstance(initial, list)
    self.assertFalse(any(e["name"] == "TestEnum" for e in initial))

    # 2. Declare the enum type
    # We must use a valid C declaration for enum
    c_decl = "enum TestEnum { TEST_MEMBER_A = 1, TEST_MEMBER_B = 2 };"
    decl_result = await self.run_tool("declare_type", c_decl=c_decl)
    self.assertIsInstance(decl_result, str)
    self.assertIn("success", decl_result.lower())

    # 3. Verify it is now listed by list_enums
    after = await self.run_tool("list_enums")
    self.assertIsInstance(after, list)

    test_enum = next((e for e in after if e["name"] == "TestEnum"), None)
    self.assertIsNotNone(test_enum)
    self.assertEqual(test_enum["member_count"], 2)
    # size is returned as integer (usually 4 bytes for enum in x86_64)
    self.assertEqual(test_enum["size"], 4)

    self.assertIn("members", test_enum)
    members = test_enum["members"]
    self.assertEqual(len(members), 2)

    # Member values are returned as hex strings
    self.assertEqual(members[0]["name"], "TEST_MEMBER_A")
    self.assertEqual(int(members[0]["value"], 16), 1)
    self.assertEqual(members[1]["name"], "TEST_MEMBER_B")
    self.assertEqual(int(members[1]["value"], 16), 2)

  async def verify_list_structs(self):
    # 1. Verify list_structs is initially empty (or doesn't have TestStructNew)
    initial = await self.run_tool("list_structs")
    self.assertIsInstance(initial, list)
    self.assertFalse(any(s["name"] == "TestStructNew" for s in initial))

    # 2. Declare the struct type
    c_decl = "struct TestStructNew { int field_a; char field_b; };"
    decl_result = await self.run_tool("declare_type", c_decl=c_decl)
    self.assertIsInstance(decl_result, str)
    self.assertIn("success", decl_result.lower())

    # 3. Verify it is now listed by list_structs
    after = await self.run_tool("list_structs")
    self.assertIsInstance(after, list)

    test_struct = next((s for s in after if s["name"] == "TestStructNew"), None)
    self.assertIsNotNone(test_struct)
    self.assertEqual(test_struct["member_count"], 2)
    # size is 6 in this environment (int is 4, char is 1, padded to 6 due to alignment)
    self.assertEqual(test_struct["size"], 6)
    self.assertEqual(test_struct["udt_type"], "Struct")

    self.assertIn("members", test_struct)
    members = test_struct["members"]
    self.assertEqual(len(members), 2)

    self.assertEqual(members[0]["name"], "field_a")
    self.assertEqual(members[0]["offset"], 0)
    self.assertEqual(members[0]["size"], 4)
    self.assertEqual(members[0]["type"], "int")

    self.assertEqual(members[1]["name"], "field_b")
    self.assertEqual(members[1]["offset"], 4)
    self.assertEqual(members[1]["size"], 1)
    self.assertEqual(members[1]["type"], "char")

  async def verify_get_xrefs_from(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["xrefs_from"]["0x1251"]

    result = await self.run_tool("get_xrefs_from", address="0x1251")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))

    # Map golden list to a dict by target address for easy comparison
    golden_map = {x["address"]: x for x in golden}
    for xref in result:
      self.assertIn(xref["address"], golden_map)
      expected = golden_map[xref["address"]]
      self.assertEqual(xref["type"], expected["type"])
      if expected["function"]:
        self.assertIsNotNone(xref["function"])
        self.assertEqual(
            xref["function"]["address"], expected["function"]["address"]
        )
        self.assertEqual(xref["function"]["name"], expected["function"]["name"])
        self.assertEqual(xref["function"]["size"], expected["function"]["size"])
      else:
        self.assertIsNone(xref["function"])

  async def verify_get_xrefs_to(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["xrefs_to"]["0x11e0"]

    result = await self.run_tool("get_xrefs_to", address="0x11e0")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))

    golden_map = {x["address"]: x for x in golden}
    for xref in result:
      self.assertIn(xref["address"], golden_map)
      expected = golden_map[xref["address"]]
      self.assertEqual(xref["type"], expected["type"])
      if expected["function"]:
        self.assertIsNotNone(xref["function"])
        self.assertEqual(
            xref["function"]["address"], expected["function"]["address"]
        )
        self.assertEqual(xref["function"]["name"], expected["function"]["name"])
        self.assertEqual(xref["function"]["size"], expected["function"]["size"])
      else:
        self.assertIsNone(xref["function"])

  async def verify_get_data_xrefs_from(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["data_xrefs_from"]["0x4098"]

    result = await self.run_tool("get_data_xrefs_from", address="0x4098")
    self.assertIsInstance(result, list)
    self.assertEqual(result, golden)

  async def verify_get_xrefs_to_field(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["xrefs_to_field"]["TestStruct.a"]

    result = await self.run_tool(
        "get_xrefs_to_field", struct_name="TestStruct", field_name="a"
    )
    self.assertIsInstance(result, list)
    print("get_xrefs_to_field", result)
    self.assertTrue(len(result) >= len(golden))

    golden_map = {x["address"]: x for x in golden}
    result_map = {x["address"]: x for x in result}
    for address, expected in golden_map.items():
      self.assertIn(address, result_map)
      xref = result_map[address]
      self.assertEqual(xref["type"], expected["type"])
      if expected["function"]:
        self.assertIsNotNone(xref["function"])
        self.assertEqual(
            xref["function"]["address"], expected["function"]["address"]
        )
        self.assertEqual(xref["function"]["name"], expected["function"]["name"])
        self.assertEqual(xref["function"]["size"], expected["function"]["size"])

  async def verify_get_xrefs_to_tid(self):
    # Retrieve tid for TestStruct.a
    eval_tid_code = """
import ida_typeinf
tif = ida_typeinf.tinfo_t()
tid = None
if tif.get_named_type(None, "TestStruct"):
  if hasattr(ida_typeinf, "get_udm_by_fullname"):
    idx = ida_typeinf.get_udm_by_fullname(None, "TestStruct.a")
    if idx != -1 and hasattr(tif, "get_udm_tid"):
      tid = tif.get_udm_tid(idx)
if tid is None:
  try:
    import ida_struct
    sid = ida_struct.get_struc_id("TestStruct")
    sptr = ida_struct.get_struc(sid)
    mptr = ida_struct.get_member_by_name(sptr, "a")
    tid = mptr.id
  except ImportError:
    pass
hex(tid) if tid is not None else ""
"""
    eval_res = await self.run_tool("idapython_eval", code=eval_tid_code)
    tid_hex = eval_res["result"].strip("'\"")
    self.assertTrue(tid_hex.startswith("0x"))

    # Load golden data for TestStruct.a
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["xrefs_to_field"]["TestStruct.a"]

    # Verify get_xrefs_to with hex tid
    result_hex = await self.run_tool("get_xrefs_to", address=tid_hex)
    self.assertIsInstance(result_hex, list)
    self.assertTrue(len(result_hex) >= len(golden))

    golden_map = {x["address"]: x for x in golden}
    result_map = {x["address"]: x for x in result_hex}
    for address, expected in golden_map.items():
      self.assertIn(address, result_map)
      xref = result_map[address]
      self.assertEqual(xref["type"], expected["type"])
      if expected["function"]:
        self.assertIsNotNone(xref["function"])
        self.assertEqual(
            xref["function"]["address"], expected["function"]["address"]
        )
        self.assertEqual(xref["function"]["name"], expected["function"]["name"])
        self.assertEqual(xref["function"]["size"], expected["function"]["size"])

    # Verify get_xrefs_to with decimal tid
    tid_dec = str(int(tid_hex, 16))
    result_dec = await self.run_tool("get_xrefs_to", address=tid_dec)
    self.assertEqual(result_dec, result_hex)

  async def verify_get_callees(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["callees"]["0x1240"]

    result = await self.run_tool("get_callees", address="0x1240")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))

    golden_map = {c["address"]: c for c in golden}
    for func in result:
      self.assertIn(func["address"], golden_map)
      expected = golden_map[func["address"]]
      self.assertEqual(func["name"], expected["name"])

  async def verify_get_callers(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["callers"]["0x11e0"]

    result = await self.run_tool("get_callers", address="0x11e0")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))

    # Map golden list to a dict by calling function address for easy comparison
    golden_map = {c["function"]["address"]: c for c in golden}
    for caller in result:
      self.assertIsNotNone(caller["function"])
      self.assertIn(caller["function"]["address"], golden_map)
      expected = golden_map[caller["function"]["address"]]
      self.assertEqual(caller["call_sites"], expected["call_sites"])
      self.assertEqual(caller["function"]["name"], expected["function"]["name"])
      self.assertEqual(caller["function"]["size"], expected["function"]["size"])

  async def verify_get_entry_points(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["entry_points"]

    result = await self.run_tool("get_entry_points")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))

    golden_map = {e["address"]: e for e in golden}
    for ep in result:
      self.assertIn(ep["address"], golden_map)
      expected = golden_map[ep["address"]]
      self.assertEqual(ep["name"], expected["name"])
      self.assertEqual(ep["size"], expected["size"])

  async def verify_get_start_ea(self):
    result = await self.run_tool("get_start_ea")
    self.assertIsInstance(result, str)
    # _start is at 0x10d0
    self.assertEqual(int(result, 16), 0x10D0)

  async def verify_get_call_graph_from(self):
    # Load golden data (depth 1)
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["call_graph_from"]["0x1240"]

    result = await self.run_tool(
        "get_call_graph_from", address="0x1240", depth=1
    )
    self.assertIsInstance(result, dict)
    self.assertIn("nodes", result)
    self.assertIn("edges", result)

    self.assertEqual(len(result["nodes"]), len(golden["nodes"]))
    self.assertEqual(len(result["edges"]), len(golden["edges"]))

    # Compare nodes
    golden_nodes = {n["address"]: n for n in golden["nodes"]}
    for node in result["nodes"]:
      self.assertIn(node["address"], golden_nodes)
      self.assertEqual(
          node["function_name"], golden_nodes[node["address"]]["function_name"]
      )
      self.assertEqual(
          node["is_external"], golden_nodes[node["address"]]["is_external"]
      )

    # Compare edges
    golden_edges = {(e["source"], e["target"]) for e in golden["edges"]}
    result_edges = {(e["source"], e["target"]) for e in result["edges"]}
    self.assertEqual(result_edges, golden_edges)

  async def verify_get_call_graph_to(self):
    # Load golden data (depth 1)
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["call_graph_to"]["0x11e0"]

    result = await self.run_tool("get_call_graph_to", address="0x11e0", depth=1)
    self.assertIsInstance(result, dict)
    self.assertIn("nodes", result)
    self.assertIn("edges", result)

    self.assertEqual(len(result["nodes"]), len(golden["nodes"]))
    self.assertEqual(len(result["edges"]), len(golden["edges"]))

    # Compare nodes
    golden_nodes = {n["address"]: n for n in golden["nodes"]}
    for node in result["nodes"]:
      self.assertIn(node["address"], golden_nodes)
      self.assertEqual(
          node["function_name"], golden_nodes[node["address"]]["function_name"]
      )
      self.assertEqual(
          node["is_external"], golden_nodes[node["address"]]["is_external"]
      )

    # Compare edges
    golden_edges = {(e["source"], e["target"]) for e in golden["edges"]}
    result_edges = {(e["source"], e["target"]) for e in result["edges"]}
    self.assertEqual(result_edges, golden_edges)

  async def verify_get_call_graph_between(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["call_graph_between"]["0x1710_0x11e0"]

    result = await self.run_tool(
        "get_call_graph_between", start_ea="0x1710", end_ea="0x11e0"
    )
    self.assertIsInstance(result, dict)
    self.assertIn("nodes", result)
    self.assertIn("edges", result)

    self.assertEqual(len(result["nodes"]), len(golden["nodes"]))
    self.assertEqual(len(result["edges"]), len(golden["edges"]))

    # Compare nodes
    golden_nodes = {n["address"]: n for n in golden["nodes"]}
    for node in result["nodes"]:
      self.assertIn(node["address"], golden_nodes)
      self.assertEqual(
          node["function_name"], golden_nodes[node["address"]]["function_name"]
      )

    # Compare edges
    golden_edges = {(e["source"], e["target"]) for e in golden["edges"]}
    result_edges = {(e["source"], e["target"]) for e in result["edges"]}
    self.assertEqual(result_edges, golden_edges)

  async def verify_get_function_cfg(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["cfgs"]["0x1240"]

    result = await self.run_tool("get_function_cfg", address="0x1240")
    self.assertIsInstance(result, dict)
    self.assertEqual(result["function_address"], golden["function_address"])
    self.assertIn("blocks", result)
    self.assertEqual(len(result["blocks"]), len(golden["blocks"]))

    # Map golden blocks by ID for easy comparison
    golden_blocks = {b["id"]: b for b in golden["blocks"]}
    for block in result["blocks"]:
      self.assertIn(block["id"], golden_blocks)
      expected = golden_blocks[block["id"]]
      self.assertEqual(block["start"], expected["start"])
      self.assertEqual(block["end"], expected["end"])
      self.assertEqual(block["successors"], expected["successors"])
      self.assertEqual(block["predecessors"], expected["predecessors"])

  async def verify_decompile_function(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["decompiled"]["0x11e0"]

    # Default include_line_prefix is False
    expected_no_prefix = "\n".join(
        line.split("| ", 1)[1] if "| " in line else ""
        for line in golden.splitlines()
    )
    result = await self.run_tool("decompile_function", address="0x11e0")
    self.assertIsInstance(result, str)
    self.assertEqual(normalize_text(result), normalize_text(expected_no_prefix))

    # Test with explicit include_line_prefix=True
    result_with_prefix = await self.run_tool(
        "decompile_function", address="0x11e0", include_line_prefix=True
    )
    self.assertEqual(normalize_text(result_with_prefix), normalize_text(golden))

    # Test with explicit include_line_prefix=False
    result_no_prefix = await self.run_tool(
        "decompile_function", address="0x11e0", include_line_prefix=False
    )
    self.assertIsInstance(result_no_prefix, str)
    self.assertEqual(
        normalize_text(result_no_prefix), normalize_text(expected_no_prefix)
    )

  async def verify_disassemble_code(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["disasm"]["0x1240_2"]

    # Explicit include_bytes=True matches golden
    result_with_bytes = await self.run_tool(
        "disassemble_code", address="0x1240", count=2, include_bytes=True
    )
    self.assertEqual(result_with_bytes, golden)

    # Default include_bytes is False
    result = await self.run_tool("disassemble_code", address="0x1240", count=2)
    self.assertIsInstance(result, str)
    self.assertIn("_Z11caller_funci:", result)
    self.assertIn("push    rbp", result)
    self.assertIn("mov     rbp, rsp", result)
    self.assertNotIn(" 55 ", result)
    self.assertNotIn(" 48 89 E5 ", result)

    # Explicit include_bytes=False matches default
    result_no_bytes = await self.run_tool(
        "disassemble_code", address="0x1240", count=2, include_bytes=False
    )
    self.assertEqual(result_no_bytes, result)

  async def verify_disassemble_function(self):
    # Load golden data (callee_func is 0x11e0 to 0x1208)
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["disassemble_function"]["0x11e0"]

    # Explicit include_bytes=True matches golden
    result_with_bytes = await self.run_tool(
        "disassemble_function", address="0x11e0", include_bytes=True
    )
    self.assertEqual(normalize_text(result_with_bytes), normalize_text(golden))

    # Default include_bytes is False
    result = await self.run_tool("disassemble_function", address="0x11e0")
    self.assertIsInstance(result, str)
    self.assertIn("push    rbp", result)
    self.assertIn("mov     rbp, rsp", result)
    self.assertNotIn(" 55 ", result)
    self.assertNotIn(" 48 89 E5 ", result)

    # Explicit include_bytes=False matches default
    result_no_bytes = await self.run_tool(
        "disassemble_function", address="0x11e0", include_bytes=False
    )
    self.assertEqual(normalize_text(result_no_bytes), normalize_text(result))

    # Verify opcode setting is restored after include_bytes=False
    restored = await self.run_tool(
        "disassemble_function", address="0x11e0", include_bytes=True
    )
    self.assertEqual(normalize_text(restored), normalize_text(golden))

  async def verify_get_ida_view(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["ida_view"]["0x11e0_0x120e"]

    # Explicit include_bytes=True matches golden
    result_with_bytes = await self.run_tool(
        "get_ida_view", start_ea="0x11e0", end_ea="0x120e", include_bytes=True
    )
    self.assertIsInstance(result_with_bytes, str)
    self.assertEqual(normalize_text(result_with_bytes), normalize_text(golden))

    # Default include_bytes is False
    result = await self.run_tool(
        "get_ida_view", start_ea="0x11e0", end_ea="0x120e"
    )
    self.assertIsInstance(result, str)
    self.assertIn("push    rbp", result)
    self.assertNotIn(" 55 ", result)

    # Explicit include_bytes=False matches default
    result_no_bytes = await self.run_tool(
        "get_ida_view", start_ea="0x11e0", end_ea="0x120e", include_bytes=False
    )
    self.assertEqual(normalize_text(result_no_bytes), normalize_text(result))

    # Verify opcode/bytes setting is restored after include_bytes=False
    restored = await self.run_tool(
        "get_ida_view", start_ea="0x11e0", end_ea="0x120e", include_bytes=True
    )
    self.assertEqual(normalize_text(restored), normalize_text(golden))

  async def verify_get_stack_frame_variables(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["stack_vars"]["0x1270"]

    result = await self.run_tool("get_stack_frame_variables", address="0x1270")
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), len(golden))

    golden_map = {v["offset"]: v for v in golden}
    for var in result:
      self.assertIn(var["offset"], golden_map)
      expected = golden_map[var["offset"]]
      self.assertEqual(var["name"], expected["name"])
      self.assertEqual(var["size"], expected["size"])
      self.assertEqual(var["type"], expected["type"])

  async def verify_stack_frame_variables_lifecycle(self):
    # 1. Verify initial stack vars don't contain test_var at offset 0x8
    initial = await self.run_tool("get_stack_frame_variables", address="0x1270")
    self.assertIsInstance(initial, list)
    self.assertFalse(
        any(v["offset"] == "0x8" or v["name"] == "test_var" for v in initial)
    )

    # 2. Create stack frame variable
    creations = [
        {"offset": "-0x68", "type_name": "int", "variable_name": "test_var"}
    ]
    create_result = await self.run_tool(
        "create_stack_frame_variables", address="0x1270", creations=creations
    )
    self.assertIsInstance(create_result, str)
    self.assertIn("success", create_result.lower())

    # 3. Verify it was created successfully
    after_create = await self.run_tool(
        "get_stack_frame_variables", address="0x1270"
    )
    test_var = next((v for v in after_create if v["offset"] == "0x8"), None)
    self.assertIsNotNone(test_var)
    self.assertEqual(test_var["name"], "test_var")
    self.assertEqual(test_var["size"], "0x4")
    self.assertTrue(
        "int" in test_var["type"].lower() or "dword" in test_var["type"].lower()
    )

    # 4. Rename stack frame variable
    renames = [{"old_name": "test_var", "new_name": "test_var_renamed"}]
    rename_result = await self.run_tool(
        "rename_stack_frame_variables", address="0x1270", renames=renames
    )
    self.assertIsInstance(rename_result, str)
    self.assertIn("success", rename_result.lower())

    # 5. Verify it was renamed successfully
    after_rename = await self.run_tool(
        "get_stack_frame_variables", address="0x1270"
    )
    self.assertFalse(any(v["name"] == "test_var" for v in after_rename))
    test_var_renamed = next(
        (v for v in after_rename if v["offset"] == "0x8"), None
    )
    self.assertIsNotNone(test_var_renamed)
    self.assertEqual(test_var_renamed["name"], "test_var_renamed")

    # 6. Set stack frame variable type to 'char *' (pointer)
    type_changes = [
        {"variable_name": "test_var_renamed", "type_name": "char *"}
    ]
    type_result = await self.run_tool(
        "set_stack_frame_variable_types",
        address="0x1270",
        type_changes=type_changes,
    )
    self.assertIsInstance(type_result, str)
    self.assertIn("success", type_result.lower())

    # 7. Verify type changed (pointer has size 8 in x86_64)
    after_type = await self.run_tool(
        "get_stack_frame_variables", address="0x1270"
    )
    test_var_type = next((v for v in after_type if v["offset"] == "0x8"), None)
    self.assertIsNotNone(test_var_type)
    self.assertEqual(test_var_type["size"], "0x8")  # char * is 8 bytes
    self.assertTrue(
        "char *" in test_var_type["type"] or "QWORD" in test_var_type["type"]
    )

    # 8. Delete stack frame variable
    delete_result = await self.run_tool(
        "delete_stack_frame_variables",
        address="0x1270",
        variable_names=["test_var_renamed"],
    )
    self.assertIsInstance(delete_result, str)
    self.assertIn("success", delete_result.lower())

    # 9. Verify it was deleted successfully (offset 0x8 is empty again)
    final = await self.run_tool("get_stack_frame_variables", address="0x1270")
    self.assertIsInstance(final, list)
    self.assertFalse(
        any(
            v["offset"] == "0x8" or v["name"] == "test_var_renamed"
            for v in final
        )
    )

  async def verify_local_variables_lifecycle(self):
    # 1. Verify initial decompilation contains 'v0' of type '__int64'
    initial = await self.run_tool("decompile_function", address="0x11e0")
    self.assertIsInstance(initial, str)
    self.assertIn("v0", initial)
    self.assertIn("__int64 v0;", initial)
    self.assertNotIn("my_cout_stream", initial)

    # 2. Rename local variable 'v0' to 'my_cout_stream'
    renames = [{"old_name": "v0", "new_name": "my_cout_stream"}]
    rename_result = await self.run_tool(
        "rename_local_variables", address="0x11e0", renames=renames
    )
    self.assertIsInstance(rename_result, str)
    self.assertIn("success", rename_result.lower())

    # 3. Verify renamed in decompilation
    after_rename = await self.run_tool("decompile_function", address="0x11e0")
    self.assertIsInstance(after_rename, str)
    self.assertNotIn("__int64 v0;", after_rename)
    self.assertIn("my_cout_stream", after_rename)
    self.assertIn("__int64 my_cout_stream;", after_rename)

    # 4. Change type of 'my_cout_stream' to 'int'
    type_changes = [{"variable_name": "my_cout_stream", "new_type": "int"}]
    type_result = await self.run_tool(
        "set_local_variable_types", address="0x11e0", type_changes=type_changes
    )
    self.assertIsInstance(type_result, str)
    self.assertIn("success", type_result.lower())

    # 5. Verify type changed to 'int' in decompilation
    after_type = await self.run_tool("decompile_function", address="0x11e0")
    self.assertIsInstance(after_type, str)
    self.assertNotIn("__int64 my_cout_stream;", after_type)
    self.assertIn("int my_cout_stream;", after_type)

  async def verify_get_struct_at_address(self):
    # Load golden data
    golden_path = os.path.join("tests", "golden_data.json")
    with open(golden_path, "r") as f:
      golden = json.load(f)["struct_at_address"]["0x4078_TestStruct"]

    result = await self.run_tool(
        "get_struct_at_address", address="0x4078", struct_name="TestStruct"
    )
    self.assertIsInstance(result, dict)
    self.assertEqual(result["struct_name"], golden["struct_name"])
    self.assertEqual(int(result["address"], 16), int(golden["address"], 16))
    self.assertIn("members", result)
    self.assertEqual(len(result["members"]), len(golden["members"]))

    golden_map = {m["offset"]: m for m in golden["members"]}
    for member in result["members"]:
      self.assertIn(member["offset"], golden_map)
      expected = golden_map[member["offset"]]
      self.assertEqual(member["name"], expected["name"])
      self.assertEqual(member["type"], expected["type"])
      self.assertEqual(member["value"], expected["value"])

  async def verify_patching_lifecycle(self):
    # 1. Verify initial instruction is 'push rbp' (55)
    initial = await self.run_tool(
        "disassemble_code", address="0x1240", count=1, include_bytes=True
    )
    self.assertIsInstance(initial, str)
    self.assertIn("55", initial)
    self.assertIn("push    rbp", initial)

    # 2. Patch it with '90' (nop) using patch_bytes
    patch_req = [{"address": "0x1240", "hex_string": "90"}]
    patch_bytes_result = await self.run_tool("patch_bytes", reqs=patch_req)
    self.assertIsInstance(patch_bytes_result, str)
    self.assertIn("success", patch_bytes_result.lower())

    # 3. Verify patched to 'nop' (90)
    patched = await self.run_tool(
        "disassemble_code", address="0x1240", count=1, include_bytes=True
    )
    self.assertIsInstance(patched, str)
    self.assertIn("90", patched)
    self.assertIn("nop", patched)

    # 4. Patch it back using patch_assembly via Gateway Keystone engine
    assembly_req = [{"address": "0x1240", "instructions": "push rbp"}]
    assembly_result = await self.run_tool("patch_assembly", reqs=assembly_req)
    self.assertIsInstance(assembly_result, str)
    self.assertEqual(assembly_result, "success")

    # 5. Restore it back to 'push rbp' (55) using patch_bytes to keep DB clean
    restore_req = [{"address": "0x1240", "hex_string": "55"}]
    restore_result = await self.run_tool("patch_bytes", reqs=restore_req)
    self.assertIsInstance(restore_result, str)
    self.assertIn("success", restore_result.lower())

    # 6. Verify restored to 'push rbp' (55)
    final = await self.run_tool(
        "disassemble_code", address="0x1240", count=1, include_bytes=True
    )
    self.assertIsInstance(final, str)
    self.assertIn("55", final)
    self.assertIn("push    rbp", final)

  async def verify_code_and_function_lifecycle(self):
    # 1. Verify initial state: 0x1240 is a function
    func_initial = await self.run_tool(
        "get_function_by_address", address="0x1240"
    )
    self.assertIsInstance(func_initial, dict)
    self.assertEqual(func_initial["name"], "_Z11caller_funci")

    try:
      # 2. Delete the function definition using idapython_eval
      # We run a short python script to delete the function at 0x1240
      eval_code = "import ida_funcs; ida_funcs.del_func(0x1240)"
      eval_result = await self.run_tool("idapython_eval", code=eval_code)
      self.assertIsInstance(eval_result, dict)
      self.assertEqual(
          eval_result["result"], "True"
      )  # del_func returns True on success

      # 3. Verify it is no longer a function
      # get_function_by_address should now return an error or say it's not a function
      # Wait, the tool might raise ToolError which run_tool wraps in RuntimeError
      with self.assertRaises(RuntimeError) as ctx:
        await self.run_tool("get_function_by_address", address="0x1240")
      self.assertIn("no function found", str(ctx.exception).lower())

      # 4. Undefine the range [0x1240, 0x1241) to clear the instruction
      undefine_result = await self.run_tool(
          "undefine", address="0x1240", size=1
      )
      self.assertIsInstance(undefine_result, str)
      self.assertIn("success", undefine_result.lower())

      # 5. Verify it is undefined (should show 'db' instead of 'push rbp' in ida view)
      view_undef = await self.run_tool(
          "get_ida_view", start_ea="0x1240", end_ea="0x1241"
      )
      self.assertIsInstance(view_undef, str)
      self.assertIn("db", view_undef.lower())
      self.assertNotIn("push", view_undef.lower())

      # 6. Convert bytes back to instruction using make_code
      make_code_result = await self.run_tool("make_code", address="0x1240")
      self.assertIsInstance(make_code_result, str)
      self.assertIn("success", make_code_result.lower())

      # 7. Verify instruction re-created (should show 'push rbp' again)
      view_code = await self.run_tool(
          "get_ida_view", start_ea="0x1240", end_ea="0x1241"
      )
      self.assertIsInstance(view_code, str)
      self.assertIn("push", view_code.lower())
      self.assertIn("rbp", view_code.lower())

      # 8. Re-create the function definition using make_function
      make_func_result = await self.run_tool("make_function", address="0x1240")
      self.assertIsInstance(make_func_result, str)
      self.assertIn("success", make_func_result.lower())
    finally:
      # Attempt to restore state
      try:
        await self.run_tool("make_code", address="0x1240")
        await self.run_tool("make_function", address="0x1240")
        await self.run_tool(
            "rename_addresses",
            reqs=[{"address": "0x1240", "new_name": "_Z11caller_funci"}],
        )
      except Exception as e:
        print(f"Warning: failed to restore function at 0x1240: {e}")

    # 9. Verify it is a function again!
    func_final = await self.run_tool(
        "get_function_by_address", address="0x1240"
    )
    self.assertIsInstance(func_final, dict)
    # The name might be auto-generated (e.g., sub_1240) because we deleted the original name
    # when we deleted the function (or maybe the name was preserved in the database as a label).
    # Actually, del_func does not delete the label name if it was a global name, but let's check.
    # We can just assert it is a function.
    self.assertIsNotNone(func_final["name"])

  async def verify_types_and_patching_lifecycle(self):
    # === Part A: Structs, Arrays, Strings, Offsets, Data Batch, Undefine ===
    # Address used: 0x40e0 (in .bss segment: bss_buffer)

    # 1. Patch bytes to write 'Hello\0' (48 65 6c 6c 6f 00)
    patch_str = [{"address": "0x40e0", "hex_string": "48656c6c6f00"}]
    res = await self.run_tool("patch_bytes", reqs=patch_str)
    self.assertIn("success", res.lower())

    # 2. Convert to string using make_strings
    res = await self.run_tool(
        "make_strings", start_ea="0x40e0", end_ea="0x40e6"
    )
    self.assertIn("success", res.lower())

    # 3. Verify it is rendered as string "Hello"
    view = await self.run_tool(
        "get_ida_view", start_ea="0x40e0", end_ea="0x40e6"
    )
    self.assertIn("hello", view.lower())

    # 4. Undefine the range [0x40e0, 0x40e6)
    res = await self.run_tool("undefine", address="0x40e0", size=6)
    self.assertIn("success", res.lower())

    # 5. Patch bytes to write 58400000 (little-endian 0x4058: global_int)
    patch_addr = [{"address": "0x40e0", "hex_string": "58400000"}]
    res = await self.run_tool("patch_bytes", reqs=patch_addr)
    self.assertIn("success", res.lower())

    # 6. Make it a dword using make_data_batch
    make_data_req = [{"address": "0x40e0", "data_type": "dword"}]
    res = await self.run_tool("make_data_batch", reqs=make_data_req)
    self.assertIn("success", res.lower())

    # 7. Verify it shows 'dd 4058h' or 'dd 4058'
    view = await self.run_tool(
        "get_ida_view", start_ea="0x40e0", end_ea="0x40e4"
    )
    self.assertIn("4058", view)
    self.assertNotIn("offset", view.lower())

    # 8. Convert it to offset pointing to global_int (base 0)
    convert_req = [{"address": "0x40e0", "base": "0", "op_index": 0}]
    res = await self.run_tool("convert_to_offsets", reqs=convert_req)
    self.assertIn("success", res.lower())

    # 9. Verify it shows 'dd offset global_int'
    view = await self.run_tool(
        "get_ida_view", start_ea="0x40e0", end_ea="0x40e4"
    )
    self.assertIn("offset global_int", view.lower())

    # 10. Undefine range [0x40e0, 0x40e4)
    res = await self.run_tool("undefine", address="0x40e0", size=4)
    self.assertIn("success", res.lower())

    # 11. Make it a byte first
    make_byte_req = [{"address": "0x40e0", "data_type": "byte"}]
    res = await self.run_tool("make_data_batch", reqs=make_byte_req)
    self.assertIn("success", res.lower())

    # 12. Make it an array of 4 bytes using make_arrays
    res = await self.run_tool("make_arrays", address="0x40e0", count=4)
    self.assertIn("success", res.lower())

    # 13. Verify it shows 'db 4 dup(...)' or 'db 4' array representation
    view = await self.run_tool(
        "get_ida_view", start_ea="0x40e0", end_ea="0x40e4"
    )
    self.assertTrue("db" in view and "4" in view)

    # 14. Undefine [0x40e0, 0x40e4)
    res = await self.run_tool("undefine", address="0x40e0", size=4)
    self.assertIn("success", res.lower())

    # 15. Make it a structure instance of TestStruct using make_structs
    res = await self.run_tool(
        "make_structs", address="0x40e0", struct_name="TestStruct"
    )
    self.assertIn("success", res.lower())

    # 16. Verify it shows 'TestStruct' structure rendering
    view = await self.run_tool(
        "get_ida_view", start_ea="0x40e0", end_ea="0x40f0"
    )
    self.assertIn("teststruct", view.lower())

    # === Part B: Enums ===
    # Instruction used: 0x13ab ('sub eax, 2Ah' which is 42)

    # 17. Declare Enum42 dynamically
    c_decl = "enum Enum42 { VAL_42 = 42 };"
    res = await self.run_tool("declare_type", c_decl=c_decl)
    self.assertIn("success", res.lower())

    # 18. Apply Enum42 to immediate operand 1 of instruction 0x13ab
    res = await self.run_tool(
        "apply_enums_to_operands",
        address="0x13ab",
        op_index=1,
        enum_name="Enum42",
    )
    self.assertIn("success", res.lower())

    # 19. Verify it is rendered as 'VAL_42' in ida view
    view = await self.run_tool(
        "get_ida_view", start_ea="0x13ab", end_ea="0x13af"
    )
    self.assertIn("val_42", view.lower())
    self.assertNotIn("2ah", view.lower())

  async def verify_memory_and_search_lifecycle(self):
    # Dynamically resolve rebased addresses to handle ASLR rebasing
    globals_info = await self.run_tool(
        "list_globals", regex_filter="global_int"
    )
    global_int_ea_str = globals_info["data"][0]["address"]

    # Resolve string address
    strings_info = await self.run_tool(
        "list_strings", regex_filter="Inside callee_func"
    )
    string_ea_str = strings_info["data"][0]["address"]
    string_ea = int(string_ea_str, 16)

    # Resolve caller_func address
    result_filtered = await self.run_tool(
        "list_functions", regex_filter="_Z11caller_funci"
    )
    rebased_caller_func = int(result_filtered["data"][0]["address"], 16)

    # 1. get_global_variable_value_by_name
    res = await self.run_tool(
        "get_global_variable_value_by_name", reqs=["global_int"]
    )
    self.assertIsInstance(res, list)
    self.assertEqual(len(res), 1)
    self.assertTrue(res[0]["success"])
    self.assertEqual(res[0]["value"], "0x2a")

    # 2. get_global_variable_value_at_address
    res = await self.run_tool(
        "get_global_variable_value_at_address", reqs=[global_int_ea_str]
    )
    self.assertIsInstance(res, list)
    self.assertEqual(len(res), 1)
    self.assertTrue(res[0]["success"])
    self.assertEqual(res[0]["value"], "0x2a")

    # 3. read_data (dword primitive)
    req = [{"address": global_int_ea_str, "data_type": "dword"}]
    res = await self.run_tool("read_data", reqs=req)
    self.assertIsInstance(res, list)
    self.assertTrue(res[0]["success"])
    self.assertEqual(res[0]["value"], "0x2a")

    # 4. read_data (string literal)
    req = [{"address": string_ea_str, "data_type": "string"}]
    res = await self.run_tool("read_data", reqs=req)
    self.assertTrue(res[0]["success"])
    self.assertEqual(res[0]["value"], "Inside callee_func")

    # 5. hexdump
    dump = await self.run_tool("hexdump", address=global_int_ea_str, length=8)
    self.assertIsInstance(dump, str)
    # Hexdump should contain address and hex '2a 00 00 00' (little-endian dword 42)
    self.assertIn(global_int_ea_str[2:].lower(), dump.lower())
    self.assertIn("2A 00 00 00", dump)

    # 6. search_binary (search for push rbp; mov rbp, rsp -> 55 48 89 E5)
    # Search down without range (default)
    search_res = await self.run_tool("search_binary", pattern="55 48 89 E5")
    self.assertIsInstance(search_res, dict)
    self.assertIn("addresses", search_res)
    self.assertTrue(
        any(
            int(addr, 16) == rebased_caller_func
            for addr in search_res["addresses"]
        )
    )

    # Search down with range
    start_ea_str = hex(rebased_caller_func)
    end_ea_str = hex(rebased_caller_func + 0x10)
    search_res_down = await self.run_tool(
        "search_binary",
        pattern="55 48 89 E5",
        start_ea=start_ea_str,
        end_ea=end_ea_str,
        direction="down",
    )
    self.assertTrue(
        any(
            int(addr, 16) == rebased_caller_func
            for addr in search_res_down["addresses"]
        )
    )

    # Search up with range
    search_res_up = await self.run_tool(
        "search_binary",
        pattern="55 48 89 E5",
        start_ea=start_ea_str,
        end_ea=end_ea_str,
        direction="up",
    )
    self.assertTrue(
        any(
            int(addr, 16) == rebased_caller_func
            for addr in search_res_up["addresses"]
        )
    )

    # Search out of range (should not find it)
    start_ea_out_str = hex(rebased_caller_func + 4)
    search_res_out = await self.run_tool(
        "search_binary",
        pattern="55 48 89 E5",
        start_ea=start_ea_out_str,
        end_ea=end_ea_str,
        direction="down",
    )
    self.assertEqual(len(search_res_out["addresses"]), 0)

    # Search with limit reached (should return remaining_range)
    search_res_limit = await self.run_tool("search_binary", pattern="00")
    self.assertEqual(len(search_res_limit["addresses"]), 50)
    self.assertIn("remaining_range", search_res_limit)
    self.assertIsNotNone(search_res_limit["remaining_range"])
    self.assertEqual(len(search_res_limit["remaining_range"]), 2)
    start_remaining = int(search_res_limit["remaining_range"][0], 16)
    end_remaining = int(search_res_limit["remaining_range"][1], 16)
    self.assertTrue(start_remaining < end_remaining)

    # 7. search_text ("Inside callee_func")
    # Search down without range (default, case-insensitive)
    search_txt_res = await self.run_tool(
        "search_text", text="Inside callee_func"
    )
    self.assertIsInstance(search_txt_res, dict)
    self.assertTrue(
        any(int(addr, 16) == string_ea for addr in search_txt_res["addresses"])
    )

    # Search down with range (case-insensitive)
    str_start_str = hex(string_ea)
    str_end_str = hex(string_ea + 20)
    search_txt_down = await self.run_tool(
        "search_text",
        text="Inside callee_func",
        start_ea=str_start_str,
        end_ea=str_end_str,
        direction="down",
    )
    self.assertTrue(
        any(int(addr, 16) == string_ea for addr in search_txt_down["addresses"])
    )

    # Search up with range (case-insensitive)
    search_txt_up = await self.run_tool(
        "search_text",
        text="Inside callee_func",
        start_ea=str_start_str,
        end_ea=str_end_str,
        direction="up",
    )
    self.assertTrue(
        any(int(addr, 16) == string_ea for addr in search_txt_up["addresses"])
    )

    # Search out of range
    str_start_out_str = hex(string_ea + 1)
    search_txt_out = await self.run_tool(
        "search_text",
        text="Inside callee_func",
        start_ea=str_start_out_str,
        end_ea=str_end_str,
        direction="down",
    )
    self.assertEqual(len(search_txt_out["addresses"]), 0)

    # Search text with limit reached
    search_txt_limit = await self.run_tool("search_text", text="a")
    self.assertEqual(len(search_txt_limit["addresses"]), 50)
    self.assertIn("remaining_range", search_txt_limit)
    self.assertIsNotNone(search_txt_limit["remaining_range"])
    self.assertEqual(len(search_txt_limit["remaining_range"]), 2)
    start_remaining_txt = int(search_txt_limit["remaining_range"][0], 16)
    end_remaining_txt = int(search_txt_limit["remaining_range"][1], 16)
    self.assertTrue(start_remaining_txt < end_remaining_txt)

    # --- Case Sensitivity Tests ---
    # A. Case-insensitive search with mismatched case (should FIND)
    search_case_insens = await self.run_tool(
        "search_text",
        text="inside callee_func",
        case_sensitive=False,
    )
    self.assertTrue(
        any(
            int(addr, 16) == string_ea
            for addr in search_case_insens["addresses"]
        )
    )

    # B. Case-sensitive search with mismatched case (should NOT FIND)
    search_case_sens_fail = await self.run_tool(
        "search_text",
        text="inside callee_func",
        case_sensitive=True,
    )
    self.assertEqual(len(search_case_sens_fail["addresses"]), 0)

    # C. Case-sensitive search with exact case (should FIND)
    search_case_sens_success = await self.run_tool(
        "search_text",
        text="Inside callee_func",
        case_sensitive=True,
    )
    self.assertTrue(
        any(
            int(addr, 16) == string_ea
            for addr in search_case_sens_success["addresses"]
        )
    )

    # 8. get_current_address & get_current_function (verify headless execution safety)
    curr_addr = await self.run_tool("get_current_address")
    self.assertIsInstance(curr_addr, str)

    curr_func = await self.run_tool("get_current_function")
    self.assertTrue(isinstance(curr_func, dict) or isinstance(curr_func, str))

  async def verify_misc_write_lifecycle(self):
    # Dynamically resolve rebased addresses to handle ASLR rebasing
    globals_info = await self.run_tool(
        "list_globals", regex_filter="global_int"
    )
    global_int_ea_str = globals_info["data"][0]["address"]
    global_int_ea = int(global_int_ea_str, 16)

    # Resolve caller_func address
    result_filtered = await self.run_tool(
        "list_functions", regex_filter="_Z11caller_funci"
    )
    rebased_caller_func = int(result_filtered["data"][0]["address"], 16)
    rebased_caller_func_str = hex(rebased_caller_func)

    # 1. list_patched_bytes (should not contain global_int_ea_str initially)
    initial_patches = await self.run_tool("list_patched_bytes")
    self.assertIsInstance(initial_patches, list)
    self.assertFalse(
        any(int(p["address"], 16) == global_int_ea for p in initial_patches)
    )

    # 2. patch_bytes to write 90 at global_int_ea_str (global_int)
    patch_req = [{"address": global_int_ea_str, "hex_string": "90"}]
    await self.run_tool("patch_bytes", reqs=patch_req)

    # 3. list_patched_bytes again to verify it is listed!
    after_patches = await self.run_tool("list_patched_bytes")
    patch_item = next(
        (p for p in after_patches if int(p["address"], 16) == global_int_ea),
        None,
    )
    self.assertIsNotNone(patch_item)
    self.assertEqual(patch_item["original_value"], 0x2A)
    self.assertEqual(patch_item["patched_value"], 0x90)

    # Restore it back to 2a to keep DB clean
    restore_req = [{"address": global_int_ea_str, "hex_string": "2a"}]
    await self.run_tool("patch_bytes", reqs=restore_req)

    # 4. set_colors (set caller_func to blue: 0x0000ff using CIC_FUNC)
    color_req = [{
        "address": rebased_caller_func_str,
        "item_type": "CIC_FUNC",
        "color": "0x0000ff",
    }]
    res = await self.run_tool("set_colors", reqs=color_req)
    self.assertIn("success", res.lower())

    # Verify color set correctly using idapython_eval
    color_val = await self.run_tool(
        "idapython_eval",
        code=(
            f"import idc; idc.get_color({rebased_caller_func_str},"
            " idc.CIC_FUNC)"
        ),
    )
    # 0x0000ff is 255 in decimal (little-endian or RGB depending on IDA, but it should match)
    self.assertEqual(int(color_val["result"]), 255)

    # Test CIC_ITEM
    color_req_item = [{
        "address": rebased_caller_func_str,
        "item_type": "CIC_ITEM",
        "color": "0x00ff00",
    }]
    res_item = await self.run_tool("set_colors", reqs=color_req_item)
    self.assertIn("success", res_item.lower())

    color_val_item = await self.run_tool(
        "idapython_eval",
        code=(
            f"import idc; idc.get_color({rebased_caller_func_str},"
            " idc.CIC_ITEM)"
        ),
    )
    self.assertEqual(int(color_val_item["result"]), 0x00FF00)

    # Restore color to default
    restore_color_req = [{
        "address": rebased_caller_func_str,
        "item_type": "CIC_ITEM",
        "color": "0xffffffff",
    }]
    await self.run_tool("set_colors", reqs=restore_color_req)

    # 5. set_functions_noret (non-returning flag)
    # Initially FUNC_NORET (0x1) is NOT set on caller_func
    flags = await self.run_tool(
        "get_function_flags", address=rebased_caller_func_str
    )
    self.assertFalse(any(f["flag"] == "FUNC_NORET" for f in flags))

    # Set it to True
    res = await self.run_tool(
        "set_functions_noret", address=rebased_caller_func_str, is_noret=True
    )
    self.assertIn("success", res.lower())

    # Verify it is set
    flags_after = await self.run_tool(
        "get_function_flags", address=rebased_caller_func_str
    )
    self.assertTrue(any(f["flag"] == "FUNC_NORET" for f in flags_after))

    # Restore it back
    await self.run_tool(
        "set_functions_noret", address=rebased_caller_func_str, is_noret=False
    )

    # 6. set_types (set global_int to char)
    # Initially type is int
    type_before = await self.run_tool(
        "idapython_eval", code=f"import idc; idc.get_type({global_int_ea_str})"
    )
    # Default/implicit int types might return empty string in get_type
    self.assertTrue(
        not type_before["result"] or "int" in type_before["result"].lower()
    )

    type_req = [{"address": global_int_ea_str, "new_type": "char"}]
    res = await self.run_tool("set_types", reqs=type_req)
    self.assertIn("success", res.lower())

    # Verify type changed
    type_after = await self.run_tool(
        "idapython_eval", code=f"import idc; idc.get_type({global_int_ea_str})"
    )
    self.assertIn("char", type_after["result"].lower())

    # 7. declare_type and list_local_types
    c_decl = "struct TestLocalType { int val; };"
    await self.run_tool("declare_type", c_decl=c_decl)

    local_types = await self.run_tool(
        "list_local_types", name_pattern="TestLocalType"
    )
    self.assertIn("TestLocalType", local_types)

    # 8. add_entry_points
    # Initially verify test_entry is not listed
    entries = await self.run_tool("get_entry_points")
    self.assertFalse(any(e["name"] == "test_entry" for e in entries))

    # Add entry point at caller_func named 'test_entry'
    add_req = [{
        "address": rebased_caller_func_str,
        "ordinal": 100,
        "name": "test_entry",
        "makecode": True,
    }]
    res = await self.run_tool("add_entry_points", reqs=add_req)
    self.assertIn("success", res.lower())

    # Verify it is listed
    entries_after = await self.run_tool("get_entry_points")
    self.assertTrue(
        any(
            e["name"] == "test_entry"
            and int(e["address"], 16) == rebased_caller_func
            for e in entries_after
        )
    )

    # Clean up test_entry to keep IDB clean for subsequent tests
    await self.run_tool(
        "idapython_eval", code="import ida_entry; ida_entry.del_entry(100)"
    )

    # 9. jump_to_address (expected to fail in headless batch mode due to lack of GUI)
    res = await self.run_tool(
        "jump_to_address", address=rebased_caller_func_str
    )
    self.assertIn("failed to jump to", res.lower())

    # 10. export_file (produceidc)
    export_path = "tests/exported.idc"
    res_path = await self.run_tool(
        "export_file",
        file_type="idc",
        output_path=export_path,
        always_regenerate=True,
    )
    self.assertEqual(res_path, export_path)
    self.assertTrue(os.path.exists(export_path))
    self.assertGreater(os.path.getsize(export_path), 0)
    # Clean up exported file
    os.remove(export_path)

    # 10.5 rename_addresses (rename caller_func dynamically)
    rename_req = [
        {"address": rebased_caller_func_str, "new_name": "caller_func_renamed"}
    ]
    res = await self.run_tool("rename_addresses", reqs=rename_req)
    self.assertIn("success", res.lower())

    # Verify renamed successfully
    result_filtered = await self.run_tool(
        "list_functions", regex_filter="caller_func_renamed"
    )
    self.assertEqual(
        int(result_filtered["data"][0]["address"], 16), rebased_caller_func
    )

    # Restore it back to original caller_func to keep DB clean
    restore_rename_req = [
        {"address": rebased_caller_func_str, "new_name": "caller_func"}
    ]
    await self.run_tool("rename_addresses", reqs=restore_rename_req)

    # 11. Defensive check for sql_query tool (Gracefully handle if unavailable)
    tools_resp = await self.session.list_tools()
    tools = [t.name for t in tools_resp.tools]
    if "sql_query" in tools:
      # Exists on gateway, but might be missing on backend
      try:
        sql_res = await self.run_tool(
            "sql_query", sql="SELECT * FROM functions LIMIT 1"
        )
        self.assertIsInstance(sql_res, dict)
        self.assertIn("rows", sql_res)
        self.assertNotIn("error", sql_res)
        self.assertIsInstance(sql_res["rows"], list)
      except RuntimeError as e:
        if "unknown tool" in str(e).lower():
          print(
              "\n--- Skipping sql_query execution (unknown tool in backend) ---"
          )
        else:
          raise
    else:
      print(
          "\n--- Skipping sql_query test (sqlglot not installed on gateway) ---"
      )

  async def verify_invalid_addresses_corner_cases(self):
    # Test invalid addresses (0x0, 0xffffffffffffffff, unmapped)

    # 1. get_function_by_address on invalid address
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("get_function_by_address", address="0x0")
    self.assertIn("no function found", str(ctx.exception).lower())

    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool(
          "get_function_by_address", address="0xffffffffffffffff"
      )
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "no function found" in err_msg
        or "valid range" in err_msg
        or "out of bounds" in err_msg
    )

    # 2. hexdump on invalid address
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("hexdump", address="0xffffffffffffffff", length=16)
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "valid range" in err_msg
        or "out of bounds" in err_msg
    )

    # 3. patch_assembly at invalid address
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool(
          "patch_assembly", address="0xffffffffffffffff", assembly="nop"
      )
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "valid range" in err_msg
        or "out of bounds" in err_msg
        or "invalid address" in err_msg
    )

    # 4. disassemble_code at invalid address (out of bounds range)
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool(
          "disassemble_code",
          start_address="0xffffffffffffffff",
          end_address="0xfffffffffffffffa",
      )
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "valid range" in err_msg
        or "out of bounds" in err_msg
        or "invalid address" in err_msg
    )

    # 5. undefine at invalid address
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("undefine", address="0xffffffffffffffff", size=1)
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "valid range" in err_msg
        or "out of bounds" in err_msg
        or "invalid address" in err_msg
    )

    # 6. get_basic_block at invalid address
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("get_basic_block", address="0xffffffffffffffff")
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "valid range" in err_msg
        or "out of bounds" in err_msg
        or "no function" in err_msg
    )

  async def verify_malformed_inputs_corner_cases(self):
    result_filtered = await self.run_tool(
        "list_functions", regex_filter="non_existent_function_xyz"
    )
    self.assertEqual(len(result_filtered["data"]), 0)

    # 2. rename_addresses with malformed input (invalid address format)
    result = await self.run_tool(
        "rename_addresses",
        reqs=[{"address": "invalid_addr", "new_name": "xyz"}],
    )
    self.assertIsInstance(result, str)
    self.assertIn("failed to parse address", result.lower())

    # 3. set_comment with empty/invalid address
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool(
          "set_comment", address="not_an_address", comment="hello"
      )
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "invalid" in err_msg
        or "parse" in err_msg
        or "error" in err_msg
    )

    # 4. rename_local_variables on an out-of-bounds address
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool(
          "rename_local_variables",
          address="0x999999",  # Out of bounds
          renames=[{"old_name": "some_lvar", "new_name": "var1"}],
      )
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "valid range" in err_msg
        or "out of bounds" in err_msg
        or "does not fall" in err_msg
    )

    # 5. rename_local_variables on a valid address but no function (e.g. 0x0)
    result = await self.run_tool(
        "rename_local_variables",
        address="0x0",
        renames=[{"old_name": "some_lvar", "new_name": "var1"}],
    )
    self.assertIsInstance(result, str)
    self.assertIn("no function found", result.lower())

    # 6. sql_query with syntax errors (if sql_query is available)
    tools_resp = await self.session.list_tools()
    tools = [t.name for t in tools_resp.tools]
    if "sql_query" in tools:
      # Test syntax error
      result = await self.run_tool("sql_query", sql="SELECT FROM;")
      self.assertIsInstance(result, dict)
      self.assertIn("error", result)
      self.assertNotIn("rows", result)
      err = result["error"].lower()
      self.assertTrue("error" in err or "syntax" in err)

      # Test write attempt (read-only block)
      result = await self.run_tool("sql_query", sql="DROP TABLE functions;")
      self.assertIsInstance(result, dict)
      self.assertIn("error", result)
      self.assertNotIn("rows", result)
      err = result["error"].lower()
      self.assertTrue("error" in err or "only read-only" in err)

      # Test integers exceeding 64-bit limit
      result = await self.run_tool(
          "sql_query", sql="SELECT 0x10000000000000000;"
      )
      self.assertIsInstance(result, dict)
      self.assertIn("error", result)
      self.assertNotIn("rows", result)
      err = result["error"].lower()
      self.assertTrue("error" in err and "64-bit" in err)

      result = await self.run_tool(
          "sql_query", sql="SELECT 18446744073709551616;"
      )
      self.assertIsInstance(result, dict)
      self.assertIn("error", result)
      self.assertNotIn("rows", result)
      err = result["error"].lower()
      self.assertTrue("error" in err and "64-bit" in err)

      result = await self.run_tool(
          "sql_query",
          sql="SELECT * FROM functions WHERE start_ea = 0x10000000000000000;",
      )
      self.assertIsInstance(result, dict)
      self.assertIn("error", result)
      self.assertNotIn("rows", result)
      err = result["error"].lower()
      self.assertTrue("error" in err and "64-bit" in err)

      result = await self.run_tool(
          "sql_query", sql="SELECT -0x8000000000000001;"
      )
      self.assertIsInstance(result, dict)
      self.assertIn("error", result)
      self.assertNotIn("rows", result)
      err = result["error"].lower()
      self.assertTrue("error" in err and "64-bit" in err)

    # 7. list_strings with invalid regex
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("list_strings", regex_filter="[")
    self.assertIn("invalid regular expression", str(ctx.exception).lower())

    # 8. list_functions with invalid regex
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("list_functions", regex_filter="[")
    self.assertIn("invalid regular expression", str(ctx.exception).lower())

    # 9. list_enums with invalid regex (e.g. repetition error at position 0)
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("list_enums", name_pattern="*")
    self.assertIn("invalid regular expression", str(ctx.exception).lower())

    # 10. list_structs with invalid regex
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("list_structs", name_pattern="*")
    self.assertIn("invalid regular expression", str(ctx.exception).lower())

    # 11. list_globals with invalid regex
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("list_globals", regex_filter="[")
    self.assertIn("invalid regular expression", str(ctx.exception).lower())

    # 12. list_local_types with invalid regex
    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool("list_local_types", name_pattern="[")
    self.assertIn("invalid regular expression", str(ctx.exception).lower())

  async def verify_type_declaration_error_cases(self):
    # 1. declare_type with syntax error (e.g. missing brace)
    result = await self.run_tool(
        "declare_type", c_decl="struct BadStruct { int a;"
    )
    self.assertIsInstance(result, str)
    self.assertIn("failed to parse", result.lower())

    # 2. set_local_variable_types with invalid declaration

    result_filtered = await self.run_tool(
        "list_functions", regex_filter="caller_func"
    )
    rebased_caller_func = int(result_filtered["data"][0]["address"], 16)

    with self.assertRaises(RuntimeError) as ctx:
      await self.run_tool(
          "set_local_variable_types",
          address=rebased_caller_func,
          type_changes=[
              {"variable_name": "x", "new_type": "bad_type_name_abc!!!"}
          ],
      )
    err_msg = str(ctx.exception).lower()
    self.assertTrue(
        "fail" in err_msg
        or "syntax" in err_msg
        or "error" in err_msg
        or "parse" in err_msg
        or "type" in err_msg
    )

  async def verify_sql_query_advanced(self):
    # 1. Check if sql_query is available
    tools_resp = await self.session.list_tools()
    tools = [t.name for t in tools_resp.tools]
    if "sql_query" not in tools:
      print("\n--- Skipping advanced sql_query tests (not installed) ---")
      return

    async def run_sql(sql_input: str | list[str]):
      res = await self.run_tool("sql_query", sql=sql_input)
      if isinstance(res, list):
        for item in res:
          self.assertNotIn("error", item, f"Query failed: {item.get('error')}")
          self.assertIn("rows", item)
        return [item["rows"] for item in res]
      self.assertNotIn("error", res, f"Query failed: {res.get('error')}")
      self.assertIn("rows", res)
      return res["rows"]

    # 2. Verify system table queries (sqlite_master / PRAGMA schema verification)
    tables = await run_sql("SELECT name FROM sqlite_master WHERE type='table'")
    self.assertIsInstance(tables, list)
    table_names = {t["name"].lower() for t in tables}
    self.assertTrue({"functions", "segments", "names"}.issubset(table_names))

    # Verify pragma_table_info works
    columns = await run_sql("SELECT * FROM pragma_table_info('functions')")
    self.assertIsInstance(columns, list)
    col_names = {c["name"].lower() for c in columns}
    self.assertTrue(
        {
            "start_ea",
            "end_ea",
            "name",
            "demangled_name",
            "size",
            "is_lib",
        }.issubset(col_names)
    )

    # Verify is_lib in functions
    func_lib_rows = await run_sql(
        "SELECT start_ea, is_lib FROM functions LIMIT 5"
    )
    self.assertIsInstance(func_lib_rows, list)
    for row in func_lib_rows:
      self.assertIn("is_lib", row)
      self.assertIn(row["is_lib"], ("0x0", "0x1"))

    # Verify address column across strings, names, and imports
    for tbl, required_cols in [
        ("strings", {"address", "length", "string"}),
        ("names", {"address", "name"}),
        ("imports", {"address", "name", "module"}),
    ]:
      tbl_cols = await run_sql(f"SELECT * FROM pragma_table_info('{tbl}')")
      self.assertIsInstance(tbl_cols, list)
      col_names = {c["name"].lower() for c in tbl_cols}
      self.assertTrue(
          required_cols.issubset(col_names),
          f"Missing columns in {tbl}: {required_cols - col_names}",
      )

      # Query table and verify address is valid
      tbl_rows = await run_sql(f"SELECT address FROM {tbl} LIMIT 5")
      self.assertIsInstance(tbl_rows, list)
      self.assertGreater(len(tbl_rows), 0, f"No rows returned from {tbl}")
      for row in tbl_rows:
        self.assertIn("address", row)
        self.assertTrue(row["address"].startswith("0x"))

    # 3. Verify Hexadecimal Literals parser (e.g. WHERE address = 0x1240)
    # Let's get rebased address of 'caller_func' first

    result_filtered = await self.run_tool(
        "list_functions", regex_filter="caller_func"
    )
    rebased_caller_func_str = result_filtered["data"][0]["address"]
    rebased_caller_func = int(rebased_caller_func_str, 16)

    # Now run a SELECT with a raw hex literal in the SQL string!
    hex_query = (
        f"SELECT * FROM functions WHERE start_ea = {rebased_caller_func_str}"
    )
    sql_res = await run_sql(hex_query)
    self.assertIsInstance(sql_res, list)
    self.assertEqual(len(sql_res), 1)
    self.assertIn(sql_res[0]["name"], ("caller_func", "_Z11caller_funci"))

    # 4. Verify Large Address (unsigned 64-bit) support by querying a huge hex address range
    large_addr_query = (
        "SELECT * FROM functions WHERE start_ea > 0x7fffffffffffffff"
    )
    sql_res = await run_sql(large_addr_query)
    self.assertIsInstance(sql_res, list)
    self.assertEqual(len(sql_res), 0)

    # 5. Verify multi-query string execution (separated by ';')
    multi_query = (
        "SELECT name FROM functions LIMIT 1; SELECT name FROM segments LIMIT 1"
    )
    sql_res = await self.run_tool("sql_query", sql=multi_query)
    self.assertIsInstance(sql_res, list)
    self.assertEqual(len(sql_res), 2)
    self.assertIn("rows", sql_res[0])
    self.assertNotIn("error", sql_res[0])
    self.assertIsInstance(sql_res[0]["rows"], list)
    self.assertIn("rows", sql_res[1])
    self.assertNotIn("error", sql_res[1])
    self.assertIsInstance(sql_res[1]["rows"], list)

    # 6. Verify list of queries execution
    multi_list = [
        "SELECT name FROM functions LIMIT 1",
        "SELECT name FROM segments LIMIT 1",
    ]
    sql_res = await self.run_tool("sql_query", sql=multi_list)
    self.assertIsInstance(sql_res, list)
    self.assertEqual(len(sql_res), 2)
    self.assertIn("rows", sql_res[0])
    self.assertNotIn("error", sql_res[0])
    self.assertIsInstance(sql_res[0]["rows"], list)
    self.assertIn("rows", sql_res[1])
    self.assertNotIn("error", sql_res[1])
    self.assertIsInstance(sql_res[1]["rows"], list)

    # 6b. Verify mixed valid and invalid queries preserve statement ordering
    mixed_sql = (
        "SELECT name FROM functions LIMIT 1; DROP TABLE functions; SELECT name"
        " FROM segments LIMIT 1;"
    )
    mixed_res = await self.run_tool("sql_query", sql=mixed_sql)
    self.assertIsInstance(mixed_res, list)
    self.assertEqual(len(mixed_res), 3)
    self.assertIn("rows", mixed_res[0])
    self.assertNotIn("error", mixed_res[0])
    self.assertIsInstance(mixed_res[0]["rows"], list)
    self.assertIn("error", mixed_res[1])
    self.assertNotIn("rows", mixed_res[1])
    self.assertIn("only read-only", (mixed_res[1].get("error") or "").lower())
    self.assertIn("rows", mixed_res[2])
    self.assertNotIn("error", mixed_res[2])
    self.assertIsInstance(mixed_res[2]["rows"], list)

    # 7. Verify Address Arithmetic & UDF (IDA_COMPUTE / IDA_COMPARE)
    rebased_caller_plus_four = hex(rebased_caller_func + 4)
    rebased_caller_minus_four = hex(rebased_caller_func - 4)

    # Test addition: WHERE address + 4 = rebased_caller_plus_four
    arith_res = await run_sql(
        "SELECT name FROM functions WHERE start_ea + 4 ="
        f" {rebased_caller_plus_four}"
    )
    self.assertIsInstance(arith_res, list)
    self.assertEqual(len(arith_res), 1)
    self.assertIn(arith_res[0]["name"], ("caller_func", "_Z11caller_funci"))

    # Test subtraction: WHERE address - 4 = rebased_caller_minus_four
    arith_res = await run_sql(
        "SELECT name FROM functions WHERE start_ea - 4 ="
        f" {rebased_caller_minus_four}"
    )
    self.assertIsInstance(arith_res, list)
    self.assertEqual(len(arith_res), 1)
    self.assertIn(arith_res[0]["name"], ("caller_func", "_Z11caller_funci"))

    # Test bitwise AND: WHERE address & 0xF000 = page_base
    page_base = hex(rebased_caller_func & 0xF000)
    arith_res = await run_sql(
        f"SELECT name FROM functions WHERE (start_ea & 0xF000) = {page_base}"
    )
    self.assertIsInstance(arith_res, list)
    names = {f["name"] for f in arith_res}
    self.assertTrue({"caller_func", "_Z11caller_funci"} & names)

    # 8. Verify xrefs query with to_ea filter
    # Let's query callers of 'callee_func'
    result_filtered = await self.run_tool(
        "list_functions", regex_filter="_Z11callee_funcv"
    )
    rebased_callee_str = result_filtered["data"][0]["address"]

    # Query xrefs to callee_func
    xref_query = f"SELECT * FROM xrefs WHERE to_ea = {rebased_callee_str}"
    xref_res = await run_sql(xref_query)
    self.assertIsInstance(xref_res, list)
    self.assertTrue(len(xref_res) >= 1)
    # Check that caller function address is correct
    caller_func_eas = {x["from_function_ea"] for x in xref_res}
    self.assertIn(rebased_caller_func_str, caller_func_eas)

    # 9. Verify xrefs table range and set operators (>=, <=, >, <, BETWEEN, IN)
    sample_xrefs = await run_sql(
        "SELECT from_ea, to_ea FROM xrefs WHERE from_ea >= 0x1000 AND to_ea >="
        " 0x1000 LIMIT 10"
    )
    self.assertIsInstance(sample_xrefs, list)
    self.assertGreaterEqual(len(sample_xrefs), 2)

    from_addrs = sorted({int(x["from_ea"], 16) for x in sample_xrefs})
    to_addrs = sorted({int(x["to_ea"], 16) for x in sample_xrefs})
    min_from, max_from = from_addrs[0], from_addrs[-1]
    min_to, max_to = to_addrs[0], to_addrs[-1]

    # from_ea: >= and <=
    res_gte_lte = await run_sql(
        "SELECT from_ea, to_ea FROM xrefs WHERE from_ea >="
        f" {hex(min_from)} AND from_ea <= {hex(max_from)}"
    )
    self.assertIsInstance(res_gte_lte, list)
    self.assertGreater(len(res_gte_lte), 0)
    for r in res_gte_lte:
      self.assertTrue(min_from <= int(r["from_ea"], 16) <= max_from)

    # from_ea: BETWEEN ... AND ...
    res_between = await run_sql(
        "SELECT from_ea, to_ea FROM xrefs WHERE from_ea"
        f" BETWEEN {hex(min_from)} AND {hex(max_from)}"
    )
    self.assertIsInstance(res_between, list)
    self.assertEqual(len(res_between), len(res_gte_lte))

    # from_ea: > and <
    res_gt_lt = await run_sql(
        "SELECT from_ea, to_ea FROM xrefs WHERE from_ea >"
        f" {hex(min_from)} AND from_ea < {hex(max_from)}"
    )
    self.assertIsInstance(res_gt_lt, list)
    for r in res_gt_lt:
      self.assertTrue(min_from < int(r["from_ea"], 16) < max_from)

    # from_ea: IN (...)
    sample_from_tuple = f"({hex(from_addrs[0])}, {hex(from_addrs[1])})"
    res_in = await run_sql(
        f"SELECT from_ea FROM xrefs WHERE from_ea IN {sample_from_tuple}"
    )
    self.assertIsInstance(res_in, list)
    self.assertGreater(len(res_in), 0)
    for r in res_in:
      self.assertIn(int(r["from_ea"], 16), {from_addrs[0], from_addrs[1]})

    # to_ea: >= and <=
    res_to_gte_lte = await run_sql(
        "SELECT from_ea, to_ea FROM xrefs WHERE to_ea >="
        f" {hex(min_to)} AND to_ea <= {hex(max_to)}"
    )
    self.assertIsInstance(res_to_gte_lte, list)
    self.assertGreater(len(res_to_gte_lte), 0)
    for r in res_to_gte_lte:
      self.assertTrue(min_to <= int(r["to_ea"], 16) <= max_to)

    # to_ea: BETWEEN ... AND ...
    res_to_between = await run_sql(
        "SELECT from_ea, to_ea FROM xrefs WHERE to_ea"
        f" BETWEEN {hex(min_to)} AND {hex(max_to)}"
    )
    self.assertIsInstance(res_to_between, list)
    self.assertEqual(len(res_to_between), len(res_to_gte_lte))

    # to_ea: > and <
    res_to_gt_lt = await run_sql(
        "SELECT from_ea, to_ea FROM xrefs WHERE to_ea >"
        f" {hex(min_to)} AND to_ea < {hex(max_to)}"
    )
    self.assertIsInstance(res_to_gt_lt, list)
    for r in res_to_gt_lt:
      self.assertTrue(min_to < int(r["to_ea"], 16) < max_to)

    # to_ea: IN (...)
    sample_to_tuple = f"({hex(to_addrs[0])}, {hex(to_addrs[1])})"
    res_to_in = await run_sql(
        f"SELECT to_ea FROM xrefs WHERE to_ea IN {sample_to_tuple}"
    )
    self.assertIsInstance(res_to_in, list)
    self.assertGreater(len(res_to_in), 0)
    for r in res_to_in:
      self.assertIn(int(r["to_ea"], 16), {to_addrs[0], to_addrs[1]})

    # 8. Verify PRAGMA statements (regression test for rewrite bug)
    pragma_res = await self.run_tool(
        "sql_query", sql="PRAGMA foreign_keys = ON"
    )
    self.assertIsInstance(pragma_res, dict)
    self.assertIn("rows", pragma_res)
    self.assertNotIn("error", pragma_res)
    self.assertEqual(pragma_res["rows"], [])

    pragma_val = await run_sql("PRAGMA foreign_keys")
    self.assertIsInstance(pragma_val, list)
    self.assertEqual(pragma_val[0]["foreign_keys"], "0x1")

    # 9. Verify NOT IN with subquery (regression test for rewrite bug)
    notin_res = await run_sql(
        "SELECT name, start_ea FROM functions WHERE start_ea NOT IN"
        " (SELECT DISTINCT to_ea FROM xrefs WHERE type = 'call')"
    )
    self.assertIsInstance(notin_res, list)
    names = {r["name"] for r in notin_res}
    self.assertIn("_start", names)
    self.assertNotIn(".abort", names)

    # 10. Verify address arithmetic alias (end_ea - start_ea as size)
    res_size = await run_sql(
        "select start_ea, size from functions order by start_ea;"
    )
    res_sub_end_start = await run_sql(
        "select start_ea, end_ea - start_ea as size from functions order by"
        " start_ea;"
    )
    self.assertIsInstance(res_size, list)
    self.assertGreater(len(res_size), 0)
    self.assertEqual(res_sub_end_start, res_size)

    # Verify compound subtraction with scalar offset
    res_sub_offset = await run_sql(
        "select start_ea, end_ea - start_ea - 10 as adj_size from functions"
        " where end_ea - start_ea - 10 > 0 order by start_ea;"
    )
    self.assertIsInstance(res_sub_offset, list)
    self.assertGreater(len(res_sub_offset), 0)
    for row in res_sub_offset:
      self.assertGreater(int(row["adj_size"], 16), 0)

    # 11. Verify unsigned 64-bit address range comparison
    res_range = await run_sql(
        "select start_ea from functions where start_ea > 0 AND start_ea <"
        " 0x8f00000000000000 order by start_ea;"
    )
    res_between_range = await run_sql(
        "select start_ea from functions where start_ea between 0 and"
        " 0x8f00000000000000-1 order by start_ea;"
    )
    res_all_start_ea = await run_sql(
        "select start_ea from functions order by start_ea;"
    )
    self.assertIsInstance(res_range, list)
    self.assertGreater(len(res_range), 0)
    self.assertEqual(res_range, res_all_start_ea)
    self.assertIsInstance(res_between_range, list)
    self.assertEqual(res_between_range, res_all_start_ea)

    # 12. Verify unaliased vs aliased aggregate functions on address columns
    res_min_alias = await run_sql(
        "select min(start_ea) as min_ea from functions;"
    )
    res_min_no_alias = await run_sql("select min(start_ea) from functions;")
    self.assertEqual(len(res_min_alias), 1)
    self.assertEqual(len(res_min_no_alias), 1)
    min_alias_val = list(res_min_alias[0].values())[0]
    min_no_alias_val = list(res_min_no_alias[0].values())[0]
    self.assertEqual(min_alias_val, min_no_alias_val)

    res_max_alias = await run_sql(
        "select max(start_ea) as max_ea from functions;"
    )
    res_max_no_alias = await run_sql("select max(start_ea) from functions;")
    self.assertEqual(len(res_max_alias), 1)
    self.assertEqual(len(res_max_no_alias), 1)
    max_alias_val = list(res_max_alias[0].values())[0]
    max_no_alias_val = list(res_max_no_alias[0].values())[0]
    self.assertEqual(max_alias_val, max_no_alias_val)

    # 13. Verify address formatting functions (printf, format, cast, concat)
    printf_res = await run_sql(
        "SELECT printf('0x%X', f.start_ea) AS func_addr, f.name AS"
        " func_name FROM functions f WHERE f.start_ea ="
        f" {rebased_caller_func_str}"
    )
    self.assertIsInstance(printf_res, list)
    self.assertEqual(len(printf_res), 1)
    self.assertEqual(
        printf_res[0]["func_addr"].lower(), rebased_caller_func_str.lower()
    )

    fmt_fn_res = await run_sql(
        "SELECT format('0x%x', f.start_ea) AS fmt_ea, cast(f.start_ea AS"
        " text) AS cast_ea, f.start_ea || '_sub' AS cat_ea FROM functions"
        f" f WHERE f.start_ea = {rebased_caller_func_str}"
    )
    self.assertIsInstance(fmt_fn_res, list)
    self.assertEqual(len(fmt_fn_res), 1)
    self.assertEqual(
        fmt_fn_res[0]["fmt_ea"].lower(), rebased_caller_func_str.lower()
    )
    self.assertEqual(
        hex(int(fmt_fn_res[0]["cast_ea"])).lower(),
        rebased_caller_func_str.lower(),
    )
    self.assertTrue(fmt_fn_res[0]["cat_ea"].endswith("_sub"))
    self.assertEqual(
        hex(int(fmt_fn_res[0]["cat_ea"].replace("_sub", ""))).lower(),
        rebased_caller_func_str.lower(),
    )

    # 14. Comprehensive 64-bit Unsigned Comparison Matrix & BETWEEN tests Using
    # CTE with values spanning signed 64-bit positive and negative boundaries:
    # 0x0, 0x1000, 0x7fffffffffffffff, 0x8000000000000000, 0x8000000000001000,
    # 0xffffffffffffffff
    cte_table = """
    WITH sample(id, a, b) AS (
      VALUES
        (1, 0x0, 0x1000),
        (2, 0x1000, 0x7fffffffffffffff),
        (3, 0x7fffffffffffffff, 0x8000000000000000),
        (4, 0x8000000000000000, 0x8000000000001000),
        (5, 0x8000000000001000, 0xffffffffffffffff),
        (6, 0xffffffffffffffff, 0xffffffffffffffff)
    )
    """

    # Test dynamic column-vs-column comparisons: a < b, a <= b, a > b, a >= b
    res_lt = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a < b ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_lt], [1, 2, 3, 4, 5])

    res_lte = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a <= b ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_lte], [1, 2, 3, 4, 5, 6])

    res_gt = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE b > a ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_gt], [1, 2, 3, 4, 5])

    res_gte = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE b >= a ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_gte], [1, 2, 3, 4, 5, 6])

    # Test column-vs-constant on right across sign boundaries:
    res_gt_high = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a > 0x7fffffffffffffff"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_gt_high], [4, 5, 6])

    res_gte_high = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a >= 0x8000000000000000"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_gte_high], [4, 5, 6])

    res_lt_high = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a < 0x8000000000000000"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_lt_high], [1, 2, 3])

    res_lte_high = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a <= 0x7fffffffffffffff"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_lte_high], [1, 2, 3])

    # Test constant on left across sign boundaries:
    res_const_l_lte = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE 0x8000000000000000 <= a"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_const_l_lte], [4, 5, 6])

    res_const_l_lt = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE 0x7fffffffffffffff < a"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_const_l_lt], [4, 5, 6])

    res_const_l_gt = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE 0x8000000000000000 > a"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_const_l_gt], [1, 2, 3])

    res_const_l_gte = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE 0x7fffffffffffffff >= a"
        " ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_const_l_gte], [1, 2, 3])

    # Test BETWEEN across 64-bit sign boundaries:
    res_btw_cross = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a BETWEEN 0x1000 AND"
        " 0x8000000000000000 ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_btw_cross], [2, 3, 4])

    res_btw_high = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a BETWEEN"
        " 0x8000000000000000 AND 0xffffffffffffffff ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_btw_high], [4, 5, 6])

    res_not_btw = await run_sql(
        f"{cte_table} SELECT id FROM sample WHERE a NOT BETWEEN 0x1000"
        " AND 0x8000000000001000 ORDER BY id"
    )
    self.assertEqual([int(r["id"], 16) for r in res_not_btw], [1, 6])

    # Test dynamic column-vs-column comparisons on actual populated tables:
    func_cmp = await run_sql(
        "SELECT name FROM functions WHERE end_ea > start_ea"
    )
    self.assertGreater(len(func_cmp), 0)

    func_cmp_inv = await run_sql(
        "SELECT name FROM functions WHERE start_ea >= end_ea"
    )
    self.assertEqual(len(func_cmp_inv), 0)

  async def verify_xrefs_lifecycle(self):
    """Verifies pre-population and dynamic add/del of xrefs."""
    res = await self.run_tool(
        "sql_query", sql="SELECT COUNT(*) as cnt FROM xrefs"
    )
    self.assertIsInstance(res, dict)
    self.assertIn("rows", res)
    self.assertNotIn("error", res)
    self.assertEqual(len(res["rows"]), 1)
    initial_count = int(res["rows"][0]["cnt"], 16)
    self.assertGreater(initial_count, 0)

    funcs = await self.run_tool(
        "sql_query", sql="SELECT start_ea FROM functions LIMIT 2"
    )
    self.assertIsInstance(funcs, dict)
    self.assertIn("rows", funcs)
    self.assertNotIn("error", funcs)
    if len(funcs["rows"]) < 2:
      self.skipTest("Need at least 2 functions to test xref lifecycle")

    abs_addr1 = int(funcs["rows"][0]["start_ea"], 16)
    abs_addr2 = int(funcs["rows"][1]["start_ea"], 16)

    eval_code = f"""
import idc
import idaapi
res = idc.add_cref({abs_addr1}, {abs_addr2}, idaapi.fl_JN)
"""
    await self.run_tool("idapython_eval", code=eval_code)

    query = (
        f"SELECT * FROM xrefs WHERE from_ea = {hex(abs_addr1)} AND"
        f" to_ea = {hex(abs_addr2)}"
    )
    res = await self.run_tool("sql_query", sql=query)
    self.assertIsInstance(res, dict)
    self.assertIn("rows", res)
    self.assertNotIn("error", res)
    self.assertEqual(len(res["rows"]), 1)
    self.assertEqual(int(res["rows"][0]["from_ea"], 16), abs_addr1)
    self.assertEqual(int(res["rows"][0]["to_ea"], 16), abs_addr2)
    self.assertEqual(res["rows"][0]["type"], "jmp")
    self.assertEqual(int(res["rows"][0]["from_function_ea"], 16), abs_addr1)

    eval_code_del = f"""
import idc
res = idc.del_cref({abs_addr1}, {abs_addr2}, 0)
"""
    await self.run_tool("idapython_eval", code=eval_code_del)

    res = await self.run_tool("sql_query", sql=query)
    self.assertIsInstance(res, dict)
    self.assertIn("rows", res)
    self.assertNotIn("error", res)
    self.assertEqual(len(res["rows"]), 0)

    abs_addr3 = abs_addr1 + 1
    eval_code_dref = f"""
import idc
import idaapi
res = idc.add_dref({abs_addr1}, {abs_addr3}, idaapi.dr_W)
"""
    await self.run_tool("idapython_eval", code=eval_code_dref)

    query_dref = (
        f"SELECT * FROM xrefs WHERE from_ea = {hex(abs_addr1)} AND"
        f" to_ea = {hex(abs_addr3)}"
    )
    res = await self.run_tool("sql_query", sql=query_dref)
    self.assertIsInstance(res, dict)
    self.assertIn("rows", res)
    self.assertNotIn("error", res)
    self.assertEqual(len(res["rows"]), 1)
    self.assertEqual(int(res["rows"][0]["from_ea"], 16), abs_addr1)
    self.assertEqual(int(res["rows"][0]["to_ea"], 16), abs_addr3)
    self.assertEqual(res["rows"][0]["type"], "write")

    eval_code_dref_del = f"""
import idc
res = idc.del_dref({abs_addr1}, {abs_addr3})
"""
    await self.run_tool("idapython_eval", code=eval_code_dref_del)

    res = await self.run_tool("sql_query", sql=query_dref)
    self.assertIsInstance(res, dict)
    self.assertIn("rows", res)
    self.assertNotIn("error", res)
    self.assertEqual(len(res["rows"]), 0)

  async def verify_sql_entries_table(self):
    """Verifies sql_query with entries table freshness checking."""
    # 1. Query all entries
    res = await self.run_tool(
        "sql_query", sql="SELECT * FROM entries ORDER BY address"
    )
    self.assertIsInstance(res, dict)
    self.assertIn("rows", res)
    self.assertNotIn("error", res)
    rows = res["rows"]
    self.assertGreater(len(rows), 0)

    # Verify column presence
    first_row = rows[0]
    self.assertIn("index_id", first_row)
    self.assertIn("ordinal", first_row)
    self.assertIn("address", first_row)
    self.assertIn("name", first_row)

    # Check for main entry point
    main_entry = next((r for r in rows if r["name"] == "main"), None)
    self.assertIsNotNone(
        main_entry, "Expected 'main' entry point in entries table"
    )
    main_addr = int(main_entry["address"], 16)

    # 2. Join entries with functions table
    join_query = (
        "SELECT e.address, e.name, f.size FROM entries e "
        "JOIN functions f ON e.address = f.start_ea "
        "WHERE e.name = 'main'"
    )
    join_res = await self.run_tool("sql_query", sql=join_query)
    self.assertIsInstance(join_res, dict)
    self.assertIn("rows", join_res)
    self.assertEqual(len(join_res["rows"]), 1)
    self.assertEqual(join_res["rows"][0]["name"], "main")
    self.assertIn("size", join_res["rows"][0])

    # 3. Test rename reflection in entries table
    new_name = "test_renamed_main_entry"
    rename_code = f"""
import ida_name
ida_name.set_name({main_addr}, "{new_name}")
"""
    await self.run_tool("idapython_eval", code=rename_code)
    await asyncio.sleep(0.3)

    renamed_query = f"SELECT name FROM entries WHERE address = {hex(main_addr)}"
    renamed_res = await self.run_tool("sql_query", sql=renamed_query)
    self.assertIsInstance(renamed_res, dict)
    self.assertIn("rows", renamed_res)
    self.assertEqual(len(renamed_res["rows"]), 1)
    self.assertEqual(renamed_res["rows"][0]["name"], new_name)

    # Restore original name
    restore_code = f"""
import ida_name
ida_name.set_name({main_addr}, "main")
"""
    await self.run_tool("idapython_eval", code=restore_code)
    await asyncio.sleep(0.3)

    # 4. Test freshness check configuration
    # Ensure baseline table is synced with IDA before testing freshness
    sync_code = """
from ida_mcp.tools.query import populate_entries
populate_entries()
"""
    await self.run_tool("idapython_eval", code=sync_code)

    # Count before adding
    count_res = await self.run_tool(
        "sql_query", sql="SELECT COUNT(*) as cnt FROM entries"
    )
    cnt_before = int(count_res["rows"][0]["cnt"], 16)

    # Add a new entry point without freshness check enabled (default: False)
    add_ep_code = f"""
import ida_entry
ida_entry.add_entry(8888, {main_addr}, "extra_test_ep", 1, 0)
"""
    await self.run_tool("idapython_eval", code=add_ep_code)

    # Query with default config (freshness check disabled): count should be cached (unchanged)
    cached_res = await self.run_tool(
        "sql_query", sql="SELECT COUNT(*) as cnt FROM entries"
    )
    self.assertEqual(int(cached_res["rows"][0]["cnt"], 16), cnt_before)

    # Enable check_entries_freshness in config
    enable_fresh_code = """
from shared.config import load_config
load_config()["check_entries_freshness"] = True
"""
    await self.run_tool("idapython_eval", code=enable_fresh_code)

    # Query again: should detect dirty and repopulate, reflecting the added entry
    fresh_res = await self.run_tool(
        "sql_query", sql="SELECT COUNT(*) as cnt FROM entries"
    )
    self.assertEqual(int(fresh_res["rows"][0]["cnt"], 16), cnt_before + 1)

    # Verify the new entry is directly selectable
    find_res = await self.run_tool(
        "sql_query",
        sql="SELECT ordinal, name FROM entries WHERE name = 'extra_test_ep'",
    )
    self.assertEqual(len(find_res["rows"]), 1)
    self.assertEqual(int(find_res["rows"][0]["ordinal"], 16), 8888)

    # Clean up added entry point and restore config
    cleanup_code = """
import ida_entry
ida_entry.del_entry(8888)
from shared.config import load_config
load_config()["check_entries_freshness"] = False
"""
    await self.run_tool("idapython_eval", code=cleanup_code)

  async def verify_safe_eval(self):
    from gateway.patcher import _safe_eval_math

    # Basic arithmetic
    self.assertEqual(_safe_eval_math("1 + 1"), 2)
    self.assertEqual(_safe_eval_math("5 - 3"), 2)
    self.assertEqual(_safe_eval_math("2 * 3"), 6)
    self.assertEqual(_safe_eval_math("8 / 2"), 4)
    self.assertEqual(_safe_eval_math("5 // 2"), 2)
    self.assertEqual(_safe_eval_math("2 ** 3"), 8)

    # Bitwise operations
    self.assertEqual(_safe_eval_math("1 | 2"), 3)
    self.assertEqual(_safe_eval_math("3 & 1"), 1)
    self.assertEqual(_safe_eval_math("1 ^ 3"), 2)
    self.assertEqual(_safe_eval_math("1 << 2"), 4)
    self.assertEqual(_safe_eval_math("4 >> 1"), 2)
    self.assertEqual(_safe_eval_math("~1"), -2)

    # Unary operations
    self.assertEqual(_safe_eval_math("-5"), -5)
    self.assertEqual(_safe_eval_math("+5"), 5)

    # Complex expressions
    self.assertEqual(_safe_eval_math("(1 + 2) * 3"), 9)
    self.assertEqual(_safe_eval_math("1 + 2 * 3"), 7)
    self.assertEqual(_safe_eval_math("0x10 + 0x20"), 0x30)
    self.assertEqual(_safe_eval_math("0X10 + 0X20"), 0x30)

    # Forbidden characters
    with self.assertRaises(ValueError):
      _safe_eval_math("1 + a")
    with self.assertRaises(ValueError):
      _safe_eval_math("import os")
    with self.assertRaises(ValueError):
      _safe_eval_math("__import__('os').system('ls')")
    with self.assertRaises(ValueError):
      _safe_eval_math("5 % 2")

    # Unsupported nodes
    with self.assertRaises(ValueError):
      _safe_eval_math("()")
    with self.assertRaises(ValueError):
      _safe_eval_math("1 < 2")
    with self.assertRaises(ValueError):
      _safe_eval_math("1 < 2 < 3")
    with self.assertRaises(ValueError):
      _safe_eval_math("1 + (2 < 3)")

    print("Safe Eval Unit Tests passed successfully.")

  async def verify_safe_eval_via_patch_assembly(self):
    # 1. Switch to ARM64 database
    orig_db_id = self.db_id
    try:
      await self.switch_database("tests/test_binary_arm64")
      # 2. Get start address
      start_ea = await self.run_tool("get_start_ea")

      # 3. Patch with math expression
      # LDR W0, [X1, #(2+2)] -> should be fixed to LDR W0, [X1, #4]
      patch_req = [
          {"address": start_ea, "instructions": "LDR W0, [X1, #(2+2)]"}
      ]
      patch_res = await self.run_tool("patch_assembly", reqs=patch_req)
      self.assertEqual(patch_res, "success")

      # 4. Verify patch
      disasm = await self.run_tool(
          "disassemble_code", address=start_ea, count=1
      )
      self.assertIn("ldr", disasm.lower())
      self.assertIn("w0", disasm.lower())
      self.assertIn("x1", disasm.lower())
      self.assertIn("4", disasm.lower())

      # 5. Test multi-instruction with literal backslash escapes, whitespace, mixed case, and multiple semicolons
      multi_patch_req = [{
          "address": start_ea,
          "instructions": (
              r"   \t  mOv   w0,   #0XFF   \t  ;;  \r\n  mov w0, #0X20 ; ; ;"
              r" ret ; ;"
          ),
      }]
      multi_patch_res = await self.run_tool(
          "patch_assembly", reqs=multi_patch_req
      )
      self.assertEqual(multi_patch_res, "success")
      disasm_multi = await self.run_tool(
          "disassemble_code", address=start_ea, count=3
      )
      self.assertIn("mov", disasm_multi.lower())
      self.assertIn("ret", disasm_multi.lower())

      # 6. Test invalid math in patch_assembly (should fail)
      # LDR W0, [X1, #(2+a)] -> fails regex, passed to keystone as is, keystone
      # should fail to assemble
      invalid_patch_req = [
          {"address": start_ea, "instructions": "LDR W0, [X1, #(2+a)]"}
      ]
      invalid_patch_res = await self.run_tool(
          "patch_assembly", reqs=invalid_patch_req
      )
      self.assertNotEqual(invalid_patch_res, "success")
      self.assertIn("failed to patch", invalid_patch_res.lower())
      self.assertIn("keystone error", invalid_patch_res.lower())

    finally:
      # 6. Switch back to original database to keep state clean
      await self.switch_database("tests/test_binary")

  async def verify_timeout_busy_handling(self):
    print("--- Running verify_timeout_busy_handling (Client-side timeout) ---")
    # Start a long-running call in the background.
    # time.sleep(10) releases the GIL.
    eval_task = asyncio.create_task(
        self.run_tool("idapython_eval", code="import time; time.sleep(10)")
    )
    # Wait a bit to ensure the server starts executing it
    await asyncio.sleep(1.0)

    # Try to call another tool, but with a client-side timeout of 2s.
    start_time = time.time()
    try:
      await asyncio.wait_for(self.run_tool("get_metadata"), timeout=2.0)
      self.fail("Expected get_metadata to timeout and fail")
    except asyncio.TimeoutError:
      duration = time.time() - start_time
      print(f"Call timed out after {duration:.2f}s as expected")
      self.assertGreaterEqual(duration, 2.0)
      self.assertLess(duration, 4.0)

    # Wait for the background task to finish (should succeed since we didn't cancel it)
    eval_res = await eval_task
    print(f"Background eval task finished: {eval_res}")

    # Call get_metadata again, it should succeed now
    meta_resp = await self.run_tool("get_metadata")
    self.assertIn("sha256", meta_resp)

  async def verify_timeout_gil_starvation_handling(self):
    print(
        "--- Running verify_timeout_gil_starvation_handling (Client-side"
        " timeout) ---"
    )
    # Start a CPU-bound call in the background.
    busy_code = (
        "import time\nt_end = time.time() + 8.0\nx = 0\nwhile time.time() <"
        " t_end:\n    x += 1\n"
    )
    eval_task = asyncio.create_task(
        self.run_tool("idapython_eval", code=busy_code)
    )
    # Wait a bit to ensure the server starts executing it
    await asyncio.sleep(1.0)

    # Try to call another tool, but with a client-side timeout of 2s.
    start_time = time.time()
    try:
      await asyncio.wait_for(self.run_tool("get_metadata"), timeout=2.0)
      self.fail("Expected get_metadata to timeout and fail")
    except asyncio.TimeoutError:
      duration = time.time() - start_time
      print(f"Call timed out after {duration:.2f}s as expected")
      self.assertGreaterEqual(duration, 2.0)
      self.assertLess(duration, 4.0)

    # Wait for the background task to finish (should succeed)
    eval_res = await eval_task
    print(f"Background eval task finished: {eval_res}")

    # Call get_metadata again, it should succeed now
    meta_resp = await self.run_tool("get_metadata")
    self.assertIn("sha256", meta_resp)

  async def verify_xrefs_offset_issue(self):
    """Verifies that SELECT * FROM xrefs returns absolute addresses when image base is non-zero."""
    # Rebase the program by 0x400000
    rebase_code = """
import ida_auto
import idaapi
from ida_mcp.tools import query
rc = idaapi.rebase_program(0x400000, 0)
ida_auto.auto_wait()
print(f"REBASE RESULT: {rc}")
"""
    await self.run_tool("idapython_eval", code=rebase_code)

    meta = await self.run_tool("get_metadata")
    imagebase = int(meta["imagebase"], 16)
    print(f"DEBUG: Rebased imagebase = {hex(imagebase)}")
    self.assertEqual(imagebase, 0x400000)

    # Now get a function address (should be rebased) using an alias
    funcs_res = await self.run_tool(
        "sql_query",
        sql=(
            "SELECT start_ea AS dd FROM functions WHERE name ="
            " '_Z11caller_funci'"
        ),
    )
    self.assertIsInstance(funcs_res, dict)
    self.assertIn("rows", funcs_res)
    self.assertNotIn("error", funcs_res)
    funcs = funcs_res["rows"]
    self.assertEqual(len(funcs), 1)
    main_addr = int(funcs[0]["dd"], 16)
    print(f"DEBUG: Rebased caller_func_addr (via dd) = {hex(main_addr)}")
    # '_Z11caller_funci' (caller_func) was at 0x1240. Rebased should be 0x401240
    self.assertEqual(main_addr, 0x401240)

    # Let's check xrefs.
    # Query all xrefs from 'caller_func' (0x401240).
    query = f"SELECT * FROM xrefs WHERE from_function_ea = {hex(main_addr)}"
    res_dict = await self.run_tool("sql_query", sql=query)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertGreater(len(res), 0)

    # Check if returned addresses are absolute (should be >= 0x400000)
    for row in res:
      from_ea = int(row["from_ea"], 16)
      to_ea = int(row["to_ea"], 16)
      from_func = int(row["from_function_ea"], 16)

      print(
          f"DEBUG: xref row: from={hex(from_ea)}, to={hex(to_ea)},"
          f" func={hex(from_func)}"
      )

      self.assertGreaterEqual(from_ea, 0x400000)
      self.assertGreaterEqual(from_func, 0x400000)

    # Test subquery with SELECT *
    subquery = (
        "SELECT * FROM (SELECT * FROM xrefs) WHERE from_function_ea ="
        f" {hex(main_addr)}"
    )
    res_dict = await self.run_tool("sql_query", sql=subquery)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertGreater(len(res), 0)
    for row in res:
      from_ea = int(row["from_ea"], 16)
      from_func = int(row["from_function_ea"], 16)
      print(
          f"DEBUG: subquery xref row: from={hex(from_ea)},"
          f" func={hex(from_func)}"
      )
      self.assertGreaterEqual(from_ea, 0x400000)
      self.assertGreaterEqual(from_func, 0x400000)

    # Test CTE with SELECT *
    cte_query = (
        "WITH my_cte AS (SELECT * FROM xrefs) SELECT * FROM my_cte WHERE"
        f" from_function_ea = {hex(main_addr)}"
    )
    res_dict = await self.run_tool("sql_query", sql=cte_query)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertGreater(len(res), 0)
    for row in res:
      from_ea = int(row["from_ea"], 16)
      from_func = int(row["from_function_ea"], 16)
      print(f"DEBUG: CTE xref row: from={hex(from_ea)}, func={hex(from_func)}")
      self.assertGreaterEqual(from_ea, 0x400000)
      self.assertGreaterEqual(from_func, 0x400000)

    # Test CTE with alias SELECT from_ea AS xx_ea
    cte_alias_query = (
        "WITH my_cte AS (SELECT * FROM xrefs) SELECT from_ea AS xx_ea FROM"
        f" my_cte WHERE from_function_ea = {hex(main_addr)}"
    )
    res_dict = await self.run_tool("sql_query", sql=cte_alias_query)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertGreater(len(res), 0)
    for row in res:
      xx_ea = int(row["xx_ea"], 16)
      print(f"DEBUG: CTE alias xref row: xx_ea={hex(xx_ea)}")
      self.assertGreaterEqual(xx_ea, 0x400000)

    # Test CTE with multiple aliases
    cte_multi_alias = (
        "WITH my_cte AS (SELECT from_ea AS f_ea, from_function_ea AS f_func_ea"
        " FROM xrefs) SELECT f_ea FROM my_cte WHERE f_func_ea ="
        f" {hex(main_addr)}"
    )
    res_dict = await self.run_tool("sql_query", sql=cte_multi_alias)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertGreater(len(res), 0)
    for row in res:
      f_ea = int(row["f_ea"], 16)
      print(f"DEBUG: CTE multi alias xref row: f_ea={hex(f_ea)}")
      self.assertGreaterEqual(f_ea, 0x400000)

    # Test Nested CTEs
    nested_cte_query = (
        "WITH cte1 AS (SELECT start_ea AS addr1, name FROM functions),"
        " cte2 AS (SELECT addr1 AS addr2, name FROM cte1 WHERE addr1 >"
        f" {hex(main_addr - 0x1000)}) SELECT addr2 FROM cte2"
    )
    res_dict = await self.run_tool("sql_query", sql=nested_cte_query)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertGreater(len(res), 0)
    for row in res:
      addr2 = int(row["addr2"], 16)
      self.assertGreater(addr2, main_addr - 0x1000)

    # Test Union query with address columns
    union_query = (
        "SELECT start_ea AS addr FROM functions WHERE name ="
        " '_Z11caller_funci' UNION SELECT to_ea AS addr FROM xrefs WHERE"
        f" from_function_ea = {hex(main_addr)}"
    )
    res_dict = await self.run_tool("sql_query", sql=union_query)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertGreater(len(res), 0)
    for row in res:
      addr = int(row["addr"], 16)
      self.assertGreaterEqual(addr, 0x400000)

    # Test Subquery in SELECT list
    subquery_in_select = (
        "SELECT name, (SELECT to_ea FROM xrefs WHERE from_function_ea ="
        " start_ea LIMIT 1) AS called_addr FROM functions WHERE name ="
        " '_Z11caller_funci'"
    )
    res_dict = await self.run_tool("sql_query", sql=subquery_in_select)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertEqual(len(res), 1)
    self.assertIsNotNone(res[0]["called_addr"])
    called_addr = int(res[0]["called_addr"], 16)
    self.assertGreaterEqual(called_addr, 0x400000)

    # Test Aggregate function with alias
    agg_query = (
        "SELECT MIN(start_ea) AS min_addr FROM functions WHERE start_ea >"
        f" {hex(main_addr - 0x1000)}"
    )
    res_dict = await self.run_tool("sql_query", sql=agg_query)
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertEqual(len(res), 1)
    self.assertIsNotNone(res[0]["min_addr"])
    min_addr = int(res[0]["min_addr"], 16)
    self.assertGreater(min_addr, main_addr - 0x1000)

  async def verify_db_versioning_and_migration(self):
    """Verifies that DB version is set and database is migrated if version is old."""
    # 1. Verify current version is 4 (target version)
    res_dict = await self.run_tool("sql_query", sql="PRAGMA user_version")
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertEqual(len(res), 1)
    self.assertIn("user_version", res[0])
    self.assertEqual(res[0]["user_version"], "0x4")

    # Verify functions table exists and has data (triggered population)
    funcs_res = await self.run_tool(
        "sql_query", sql="SELECT COUNT(*) as cnt FROM functions"
    )
    self.assertIsInstance(funcs_res, dict)
    self.assertIn("rows", funcs_res)
    self.assertNotIn("error", funcs_res)
    funcs = funcs_res["rows"]
    self.assertGreater(int(funcs[0]["cnt"], 16), 0)

    # 2. Manually set version to 1 and create legacy schema (__internal_xrefs
    # table and xrefs view)
    migrate_code = """
import ida_mcp.tools.query as q
conn = q._get_rw_conn()
conn.execute("PRAGMA user_version = 1")
conn.execute("CREATE TABLE IF NOT EXISTS __internal_xrefs (from_ea INT, to_ea INT, type TEXT)")
conn.execute("DROP TABLE IF EXISTS xrefs")
conn.execute("CREATE VIEW IF NOT EXISTS xrefs AS SELECT from_ea, to_ea, type FROM __internal_xrefs")
print("DEBUG: Force set version to 1 and created legacy view/table")
"""
    await self.run_tool("idapython_eval", code=migrate_code)

    # Verify version was set to 1 (does not trigger migration yet)
    res_dict = await self.run_tool("sql_query", sql="PRAGMA user_version")
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertEqual(res[0]["user_version"], "0x1")

    # Now reset _db_version_checked and _created_tables to force migration on
    # next query
    reset_code = """
import ida_mcp.tools.query as q
q._db_version_checked = False
q._created_tables.clear()
print("DEBUG: Reset checked flag")
"""
    await self.run_tool("idapython_eval", code=reset_code)

    # 3. Trigger a query. This should trigger migration (drop tables and views,
    # set version to 4). We query sqlite_master to verify tables and views were
    # dropped.
    entities_res = await self.run_tool(
        "sql_query",
        sql=(
            "SELECT type, name FROM sqlite_master WHERE type IN ('table',"
            " 'view') AND name NOT LIKE 'sqlite_%'"
        ),
    )
    self.assertIsInstance(entities_res, dict)
    self.assertIn("rows", entities_res)
    self.assertNotIn("error", entities_res)
    entities = entities_res["rows"]
    entity_names = [e["name"] for e in entities]
    print(f"DEBUG: Entities after migration trigger: {entity_names}")
    for ent in [
        "functions",
        "strings",
        "names",
        "imports",
        "segments",
        "local_types",
        "xrefs",
        "__internal_xrefs",
    ]:
      self.assertNotIn(ent, entity_names)

    # Now verify version is back to 4
    res_dict = await self.run_tool("sql_query", sql="PRAGMA user_version")
    self.assertIsInstance(res_dict, dict)
    self.assertIn("rows", res_dict)
    self.assertNotIn("error", res_dict)
    res = res_dict["rows"]
    self.assertEqual(res[0]["user_version"], "0x4")

    # Now query functions again, it should trigger re-population and succeed
    funcs_res = await self.run_tool(
        "sql_query", sql="SELECT COUNT(*) as cnt FROM functions"
    )
    self.assertIsInstance(funcs_res, dict)
    self.assertIn("rows", funcs_res)
    self.assertNotIn("error", funcs_res)
    funcs = funcs_res["rows"]
    self.assertGreater(int(funcs[0]["cnt"], 16), 0)

    # Verify tables exist again
    tables_res = await self.run_tool(
        "sql_query", sql="SELECT name FROM sqlite_master WHERE type='table'"
    )
    self.assertIsInstance(tables_res, dict)
    self.assertIn("rows", tables_res)
    self.assertNotIn("error", tables_res)
    tables_after = tables_res["rows"]
    table_names_after = [t["name"] for t in tables_after]
    print(f"DEBUG: Tables after re-population: {table_names_after}")
    self.assertIn("functions", table_names_after)

    # 4. Verify _db_metadata recorded image_min_ea
    meta_res = await self.run_tool(
        "sql_query",
        sql="SELECT value FROM _db_metadata WHERE key = 'image_min_ea'",
    )
    self.assertIsInstance(meta_res, dict)
    self.assertIn("rows", meta_res)
    self.assertNotIn("error", meta_res)
    meta_rows = meta_res["rows"]
    self.assertEqual(len(meta_rows), 1)
    stored_ea = int(meta_rows[0]["value"], 16)
    print(f"DEBUG: Stored image_min_ea in metadata: {hex(stored_ea)}")

    # 5. Simulate image_min_ea change in metadata while version is 4
    corrupt_min_ea_code = """
import ida_mcp.tools.query as q
conn = q._get_rw_conn()
conn.execute("UPDATE _db_metadata SET value = '0x12345' WHERE key = 'image_min_ea'")
q._db_version_checked = False
q._created_tables.clear()
print("DEBUG: Corrupted image_min_ea to 0x12345 and reset checked flag")
"""
    await self.run_tool("idapython_eval", code=corrupt_min_ea_code)

    # Trigger a query. Since stored image_min_ea != current_min_ea, all tables should be dropped and re-created
    entities_res = await self.run_tool(
        "sql_query",
        sql=(
            "SELECT type, name FROM sqlite_master WHERE type IN ('table',"
            " 'view') AND name NOT LIKE 'sqlite_%'"
        ),
    )
    self.assertIsInstance(entities_res, dict)
    self.assertIn("rows", entities_res)
    self.assertNotIn("error", entities_res)
    entities_after_ea_change = entities_res["rows"]
    ea_entity_names = [e["name"] for e in entities_after_ea_change]
    print(
        "DEBUG: Entities after image_min_ea mismatch migration:"
        f" {ea_entity_names}"
    )
    for ent in [
        "functions",
        "strings",
        "names",
        "imports",
        "segments",
        "local_types",
        "xrefs",
    ]:
      self.assertNotIn(ent, ea_entity_names)

    # Verify metadata was updated back to current image_min_ea
    meta_res_updated = await self.run_tool(
        "sql_query",
        sql="SELECT value FROM _db_metadata WHERE key = 'image_min_ea'",
    )
    self.assertIsInstance(meta_res_updated, dict)
    self.assertIn("rows", meta_res_updated)
    self.assertNotIn("error", meta_res_updated)
    meta_rows_updated = meta_res_updated["rows"]
    self.assertEqual(len(meta_rows_updated), 1)
    updated_stored_ea = int(meta_rows_updated[0]["value"], 16)
    self.assertEqual(updated_stored_ea, stored_ea)

  async def verify_lock_reentrancy_no_deadlock(self):
    """Verifies that acquiring _db_write_lock recursively does not deadlock."""
    # Reset checked flag to force migration on next connection
    reset_code = """
import ida_mcp.tools.query as q
q._db_version_checked = False
print("DEBUG: Reset checked flag for deadlock test")
"""
    await self.run_tool("idapython_eval", code=reset_code)

    # Code to simulate _recreate_and_insert calling _get_rw_conn while holding lock
    deadlock_test_code = """
import ida_mcp.tools.query as q
print("DEBUG: Acquiring lock manually...")
with q._db_write_lock:
  print("DEBUG: Lock acquired. Calling _get_rw_conn (should trigger migration)...")
  conn = q._get_rw_conn()
  print("DEBUG: _get_rw_conn returned successfully!")
"""
    try:
      # Run with a 5 second timeout. If it deadlocks, it will timeout.
      await asyncio.wait_for(
          self.run_tool("idapython_eval", code=deadlock_test_code), timeout=5.0
      )
    except asyncio.TimeoutError:
      self.fail("Deadlock detected! The operation timed out.")

  async def verify_sql_query_cancellation_and_recovery(self):
    """Verifies cancelling an in-flight SQL query and recovering tools."""
    heavy_sql = (
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt)"
        " SELECT count(*) FROM cnt CROSS JOIN cnt AS b"
    )
    req_id = self.session._request_id
    query_task = asyncio.create_task(self.run_tool("sql_query", sql=heavy_sql))
    # Wait briefly for query execution to start in SQLite C code
    await asyncio.sleep(0.1)

    # Cancel the in-flight query by sending MCP CancelledNotification
    start_time = time.time()
    await self.session.send_notification(
        mcp.types.CancelledNotification(
            params=mcp.types.CancelledNotificationParams(
                requestId=req_id, reason="Test cancellation"
            )
        )
    )
    try:
      await query_task
    except Exception as e:  # pylint: disable=broad-exception-caught
      print(f"DEBUG: Cancelled query response: {e}")
    duration = time.time() - start_time
    print(f"Query cancelled and aborted in {duration:.2f}s")
    self.assertLess(duration, 2.0, "SQL cancellation took too long to abort")

    # Verify that sql_query works immediately after cancellation
    res = await self.run_tool("sql_query", sql="SELECT 1 AS test_val")
    self.assertIsInstance(res, dict)
    self.assertIn("rows", res)
    self.assertNotIn("error", res)
    self.assertEqual(len(res["rows"]), 1)
    self.assertEqual(res["rows"][0]["test_val"], "0x1")

    # Verify that other tools still function cleanly
    meta = await self.run_tool("get_metadata")
    self.assertIn("sha256", meta)


if __name__ == "__main__":
  unittest.main()
