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

"""Tool for looking up the IDAPython API of the running IDA."""

import os
import sys
from typing import Annotated

from ida_mcp.core.decorators import jsonrpc
from ida_mcp.utils import idapython_reference as reference_index
from shared.rpc import ToolError
from shared.types import IdapythonReference


def _python_dir() -> str:
  """IDA's python directory, found from an IDA module that is loaded."""
  for name in ("ida_kernwin", "ida_idaapi", "idc"):
    module = sys.modules.get(name)
    path = getattr(module, "__file__", None)
    if path:
      directory = os.path.dirname(os.path.realpath(path))
      if os.path.isdir(directory):
        return directory
  raise ToolError("Cannot locate IDA's python directory")


def _ida_version() -> str:
  # A module constant: reading it doesn't call into IDA from this thread.
  sdk = getattr(sys.modules.get("ida_pro"), "IDA_SDK_VERSION", None)
  if isinstance(sdk, int) and sdk > 0:
    return f"{sdk // 100}.{sdk % 100 // 10}"
  return "unknown"


@jsonrpc
def idapython_reference(
    query: Annotated[
        str,
        "A name ('get_func', 'ida_typeinf.tinfo_t', 'FUNC_NORET') or a short"
        " description ('add stack frame member', 'xrefs to address')",
    ],
    max_results: Annotated[
        int, "Maximum number of API entries to return (1-50)"
    ] = 10,
    include_example: Annotated[
        bool, "Also return the best matching example script from IDA"
    ] = True,
) -> IdapythonReference:
  """Looks up the IDAPython API of the running IDA: signatures and docs.

  Searches the `ida_*` modules, `idc`, `idautils` and the example scripts that
  ship with this IDA installation, so the results match its version. Use it
  before writing code for `idapython_eval` when unsure a function exists or
  how it is called; APIs change between IDA versions (e.g. `ida_struct` and
  `ida_enum` were removed in IDA 9.0). The index is built on the first call
  (about a second) from IDA's files, which are parsed and not imported.
  """
  python_dir = _python_dir()
  try:
    index = reference_index.get_index(python_dir)
    result = reference_index.search(index, query, max_results, include_example)
  except (OSError, ValueError) as e:
    raise ToolError(str(e)) from e
  result["ida_version"] = _ida_version()
  return result  # type: ignore[return-value]
