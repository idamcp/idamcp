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

"""Tool for reading the database change log."""

from typing import Annotated

from ida_mcp.core import change_log
from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.synchronization import idaread
from shared.rpc import ToolError
from shared.types import ChangesSince


@jsonrpc
@idaread
def get_changes_since(
    revision: Annotated[
        int,
        "The `revision` returned by your previous call. Use 0 on the first"
        " call.",
    ] = 0,
    limit: Annotated[int, "Maximum number of changes to return (1-1000)"] = 200,
    include_analysis: Annotated[
        bool,
        "Also return changes made by IDA's auto-analyzer (can be many).",
    ] = False,
) -> ChangesSince:
  """Lists changes made to the database since a revision.

  Covers renames, comments, types and prototypes, operand types, local types,
  functions added/deleted/resized, byte patches, code/data definitions,
  segments and stack variable renames. Use it to notice edits made by the IDA
  user or another agent since you last looked, instead of relying on earlier
  results. Recording starts with the first call to this tool on a database;
  that call returns `started: true` and no earlier changes. Each change says
  who made it: an MCP tool (`source` 'tool' and `tool`), the IDA user or a
  script run inside IDA ('ida'), or the auto-analyzer ('analysis').
  Decompiler-only edits (local variable names and types, decompiler comments)
  are not recorded.
  """
  try:
    started = change_log.start()
  except RuntimeError as e:
    raise ToolError(str(e)) from e
  result = change_log.changes_since(revision, limit, include_analysis)
  if started:
    result["started"] = True
  return result  # type: ignore[return-value]
