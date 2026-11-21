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


"""Module for exporting IDA Pro data to files."""

import contextlib
import os
from typing import Annotated, Literal

import ida_hexrays
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.synchronization import idaread
import idaapi
import idc
from shared.rpc import ToolError


@jsonrpc
@idaread
def export_file(
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
  # OFILE constants from IDA
  type_map = {
      "map": idc.OFILE_MAP,
      "exe": idc.OFILE_EXE,
      "idc": idc.OFILE_IDC,
      "lst": idc.OFILE_LST,
      "asm": idc.OFILE_ASM,
      "dif": idc.OFILE_DIF,
  }

  if file_type not in type_map and file_type != "c":
    raise ToolError(
        f"Unsupported file type: {file_type}. Supported types: "
        f"{', '.join(type_map.keys())}, c"
    )

  if output_path is None:
    idb_path = idc.get_idb_path()
    if not idb_path:
      raise ToolError("Could not determine IDB path")
    output_path = f"{idb_path}.{file_type}"

  # A path in a directory that doesn't exist can't be written.
  output_dir = os.path.dirname(os.path.abspath(output_path))
  if not os.path.isdir(output_dir):
    raise ToolError(
        f"Failed to generate {file_type} file at {output_path}: the directory"
        f" {output_dir} doesn't exist"
    )

  # An empty file is what a failed run leaves behind, so it isn't reused.
  if (
      not always_regenerate
      and os.path.exists(output_path)
      and os.path.getsize(output_path) > 0
  ):
    return output_path

  if file_type == "c":
    if not ida_hexrays.init_hexrays_plugin():
      raise ToolError("Hex-Rays decompiler is not available")

    # decompile_many(outfile, func, flags)
    # outfile: output file name
    # func: None for all functions
    # flags: 0
    if not ida_hexrays.decompile_many(
        output_path, None, ida_hexrays.VDRUN_NEWFILE | ida_hexrays.VDRUN_SILENT
    ):
      raise ToolError(f"Failed to decompile to {output_path}")
  else:
    match file_type:
      case "asm" | "lst":
        flags = idc.GENFLG_ASMTYPE
      case "map":
        flags = (
            idc.GENFLG_MAPSEG
            | idc.GENFLG_MAPNAME
            | idc.GENFLG_MAPDMNG
            | idc.GENFLG_MAPLOC
        )
      case _:
        flags = 0
    # idc.gen_file returns the number of lines it wrote, 0 if IDA can't
    # produce this kind of file for the database, and -1 if the file can't be
    # created.
    ret = idc.gen_file(
        type_map[file_type],
        output_path,
        idaapi.inf_get_min_ea(),
        idaapi.inf_get_max_ea(),
        flags,
    )
    if ret <= 0:
      # IDA creates the file before it finds out that it has nothing to write.
      with contextlib.suppress(OSError):
        if os.path.getsize(output_path) == 0:
          os.remove(output_path)
      reason = (
          "the file can't be created"
          if ret < 0
          else f"IDA can't produce a {file_type} file for this database"
      )
      raise ToolError(
          f"Failed to generate {file_type} file at {output_path}: {reason}"
      )

  return output_path
