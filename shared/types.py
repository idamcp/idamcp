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

"""Type definitions for IDA-related data structures."""

from dataclasses import dataclass, field
from typing import (
    Annotated,
    Any,
    Generic,
    List,
    Literal,
    NotRequired,
    TypeVar,
    TypedDict,
)


class Argument(TypedDict):
  name: str
  type: str


class StackFrameVariable(TypedDict):
  name: str
  offset: str
  size: str
  type: str


class ConvertedNumber(TypedDict):
  decimal: str
  hexadecimal: str
  bytes: str
  ascii: str | None
  binary: str


class Function(TypedDict):
  address: str
  name: str
  size: NotRequired[str]
  is_helper_function: NotRequired[bool]


class Caller(TypedDict):
  call_sites: Annotated[list[str], "Addresses of the call instructions"]
  function: NotRequired[
      Annotated[Function, "The enclosing function that makes the call(s)"]
  ]


class Global(TypedDict):
  address: str
  name: str


class Metadata(TypedDict):
  filepath: Annotated[str, "The absolute path to the input binary file"]
  module: NotRequired[Annotated[str, "The root filename of the binary"]]
  database_path: Annotated[
      str, "The absolute path to the IDA database file (typically .idb or .i64)"
  ]
  root_filename: NotRequired[
      Annotated[str, "The root filename of the input file"]
  ]
  imagebase: Annotated[str, "The base address of the image in hexadecimal"]
  imagesize: Annotated[str, "The estimated image size in hexadecimal"]
  md5: NotRequired[Annotated[str, "The MD5 hash of the input file"]]
  sha256: Annotated[str, "The SHA256 hash of the input file"]
  crc32: NotRequired[
      Annotated[str, "The CRC32 of the input file in hexadecimal"]
  ]
  filesize: Annotated[str, "The size of the input file in hexadecimal"]
  filetype: Annotated[str, "File type description"]
  bitness: Annotated[int, "Application bitness"]
  procname: Annotated[str, "Name of the processor the file is targeted for"]
  is_headless: Annotated[
      bool, "Whether the instance is running in headless mode"
  ]


T = TypeVar("T")


class Page(TypedDict, Generic[T]):
  data: list[T]
  next_offset: NotRequired[int]


class String(TypedDict):
  address: str
  length: int
  string: str


class Import(TypedDict):
  address: str
  imported_name: str
  module: str


class Segment(TypedDict):
  name: str
  start: str
  end: str
  size: str
  permissions: str


class Xref(TypedDict):
  address: str
  type: str
  function: NotRequired[Function]


class CallGraphNode(TypedDict):
  address: str
  function_name: str
  is_external: NotRequired[bool]


class CallGraphEdge(TypedDict):
  source: str
  target: str


class CallGraph(TypedDict):
  nodes: list[CallGraphNode]
  edges: list[CallGraphEdge]


class StructureMember(TypedDict):
  index: int
  name: str
  offset: int
  size: int
  type: str


class StructureDefinition(TypedDict):
  name: str
  type: str
  size: int
  is_udt: bool
  ordinal: int
  member_count: int
  udt_type: str
  members: NotRequired[list[StructureMember]]


class RegisterValue(TypedDict):
  name: str
  value: str


class ThreadRegisters(TypedDict):
  thread_id: int
  registers: list[RegisterValue]


class Breakpoint(TypedDict):
  ea: str
  enabled: bool
  condition: NotRequired[str]


class BasicBlock(TypedDict):
  id: int
  start: str
  end: str
  successors: list[int]
  predecessors: list[int]


class ControlFlowGraph(TypedDict):
  function_address: str
  blocks: list[BasicBlock]


class SearchResult(TypedDict):
  addresses: Annotated[list[str], "List of matched addresses in hexadecimal"]
  remaining_range: NotRequired[
      Annotated[
          list[str],
          (
              "The remaining address range [start, end] to search if the match"
              " cap was reached, or None if the search completed."
          ),
      ]
  ]


class PatchedByte(TypedDict):
  address: str
  fpos: int
  original_value: int
  patched_value: int


class Bookmark(TypedDict):
  index: int
  address: str
  description: str


class IdapythonReference(TypedDict):
  ida_version: Annotated[str, "IDA version the reference was built from"]
  python_dir: Annotated[str, "IDA's python directory that was indexed"]
  results: Annotated[
      list[dict[str, Any]],
      "Best matches first. Each has `kind` (module, function, class, method"
      " or constant), `name` (qualified), `doc`, `source` (file:line) and,"
      " for functions and methods, `signature`.",
  ]
  total_matches: Annotated[int, "Number of entries that matched the query"]
  example: NotRequired[
      Annotated[
          dict[str, Any],
          "Best matching example script shipped with IDA: `name`, `path`,"
          " `summary` and `content`.",
      ]
  ]
  notes: NotRequired[
      Annotated[
          list[str],
          "Warnings, e.g. a module named in the query that doesn't exist in"
          " this IDA version.",
      ]
  ]


class Operand(TypedDict):
  type: str
  value: str | int


class FunctionFlags(TypedDict):
  flag: str
  description: str


class EnumMember(TypedDict):
  name: str
  value: str


class EnumDefinition(TypedDict):
  name: str
  member_count: int
  members: NotRequired[list[EnumMember]]
  size: NotRequired[int]
  ordinal: NotRequired[int]


class SetCommentResult(TypedDict):
  disassembly_comment_status: Annotated[
      Literal["success", "failed"],
      "Status of setting the comment in the disassembly view",
  ]
  disassembly_comment_error: Annotated[
      NotRequired[str],
      "Error message if setting the disassembly comment failed",
  ]
  pseudocode_comment_status: Annotated[
      Literal["success", "failed", "not_applicable"],
      "Status of setting the comment in the pseudocode view",
  ]
  pseudocode_comment_error: Annotated[
      NotRequired[str],
      "Error message if setting the pseudocode comment failed",
  ]


@dataclass
class RenameAddressRequest:
  address: Annotated[
      str,
      "Linear address. do nothing if address is not valid. tail bytes can't"
      " have names.",
  ]
  new_name: Annotated[str, "New name for the address"]


@dataclass
class SetColorRequest:
  address: Annotated[str, "The address of the item to color"]
  color: Annotated[
      str | int,
      "new color code in RGB (hex 0xBBGGRR) (hex string or integer)",
  ]
  item_type: Annotated[
      str,
      "type of the item, can only be CIC_ITEM, CIC_FUNC, or CIC_SEGM, default"
      " is CIC_ITEM",
  ] = "CIC_ITEM"


@dataclass
class PatchAssemblyRequest:
  address: Annotated[str, "Starting Address to apply patch"]
  instructions: Annotated[str, "Assembly instructions separated by ';'"]
  syntax: Annotated[
      Literal["intel", "nasm", "att"] | None,
      "Syntax (e.g. 'intel', 'nasm', 'att')",
  ] = None


@dataclass
class AssemblyContextRequest:
  address: Annotated[str, "Address to check segment registers and validate"]
  symbols: Annotated[List[str], "List of symbol names to resolve"] = field(
      default_factory=list
  )


class AssemblyContextItem(TypedDict):
  address: str
  procname: str
  bitness: int
  is_be: bool
  is_thumb: bool
  symbols: dict[str, str]
  error: NotRequired[str]


@dataclass
class LocalVariableRename:
  old_name: Annotated[str, "Current name of the variable"]
  new_name: Annotated[
      str, "New name for the variable (empty for a default name)"
  ]


@dataclass
class LocalVariableTypeChange:
  variable_name: Annotated[str, "Name of the variable"]
  new_type: Annotated[str, "New type for the variable"]


@dataclass
class StackFrameVariableRename:
  old_name: Annotated[str, "Current name of the variable"]
  new_name: Annotated[
      str, "New name for the variable (empty for a default name)"
  ]


@dataclass
class StackFrameVariableCreate:
  offset: Annotated[str, "Offset of the stack frame variable"]
  variable_name: Annotated[str, "Name of the stack variable"]
  type_name: Annotated[str, "Type of the stack variable"]


@dataclass
class StackFrameVariableTypeChange:
  variable_name: Annotated[str, "Name of the stack variable"]
  type_name: Annotated[str, "Type of the stack variable"]


@dataclass
class SetTypeRequest:
  address: Annotated[str, "Address or name of object to set type"]
  new_type: Annotated[
      str,
      (
          "The type string in C declaration form (e.g. 'int x;', 'char *'). "
          "If empty, the type is removed."
      ),
  ]


@dataclass
class AddEntryPointRequest:
  address: Annotated[str, "Linear address of the entry point"]
  name: Annotated[
      str,
      "name of entry point. If the specified location already has a name, the"
      " old name will be appended to the regular comment.",
  ]
  ordinal: Annotated[
      int,
      "ordinal number if ordinal number is equal to 'address' then ordinal is"
      " not used",
  ] = 0
  makecode: Annotated[
      bool, "Should the kernel convert bytes to instructions"
  ] = True


@dataclass
class PatchBytesRequest:
  address: Annotated[str, "Address to patch bytes at"]
  hex_string: Annotated[
      str,
      "Hex string of bytes to patch (e.g. '90 90' or '9090'), max 0x1000"
      " bytes per call",
  ]


@dataclass
class ConvertToOffsetRequest:
  address: Annotated[str, "Address of the instruction or global variable"]
  op_index: Annotated[
      int,
      "Operand index (0-based). Use 0 (default) for data items/global"
      " variables.",
  ] = 0
  base: Annotated[str, "Base address for the offset (default '0')"] = "0"


@dataclass
class MakeDataRequest:
  address: Annotated[str, "Address to create data at"]
  data_type: Annotated[
      str,
      (
          "Type of data to create ('byte', 'word', 'dword', 'qword', 'oword',"
          " 'yword', 'float', 'double', 'tbyte', 'pack_real')"
      ),
  ]


@dataclass
class ReadDataRequest:
  address: Annotated[str, "Address (hex string) of the memory value to be read"]
  data_type: Annotated[
      Literal["byte", "word", "dword", "qword", "string", "bytes"],
      "The type of data to read ('byte', 'word', 'dword', 'qword', 'string',"
      " 'bytes')",
  ]
  size: Annotated[
      int, "Number of bytes to read (only used when data_type is 'bytes')"
  ] = 1


class BatchResponseItem(TypedDict):
  success: Annotated[bool, "Whether the request was successful"]
  error: NotRequired[Annotated[str, "Error message if the request failed"]]
  value: NotRequired[
      Annotated[Any, "The result value if the request was successful"]
  ]


class QueryResult(TypedDict):
  rows: NotRequired[
      Annotated[
          list[dict[str, Any]], "The query result rows (empty list if no rows)"
      ]
  ]
  error: NotRequired[
      Annotated[str, "Error message if the query failed (omitted on success)"]
  ]
