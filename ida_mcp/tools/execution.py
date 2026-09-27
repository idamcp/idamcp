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

"""Module for executing Python code in the IDA Pro environment."""

import ast
import collections
import contextlib
import io
import logging
import sys
import threading
import traceback
from typing import Annotated, Any, Dict, Hashable

from ida_mcp.core.decorators import jsonrpc
from ida_mcp.core.decorators import unsafe
from ida_mcp.core.synchronization import idawrite
from ida_mcp.utils import helper
from shared import rpc
from shared.config import load_config

logger = logging.getLogger(__name__)

# Persistent global scope for the session
_session_globals: Dict[str, Any] = {}


def _lazy_import(module_name):
  try:
    return __import__(module_name)
  except ImportError:
    return None


def _init_session_globals():
  """Initialize the global scope with IDA modules and helpers."""
  if _session_globals:
    return

  # Standard IDA modules
  modules = [
      "ida_allins",
      "ida_auto",
      "ida_bitrange",
      "ida_bytes",
      "ida_dbg",
      "ida_dirtree",
      "ida_diskio",
      "ida_entry",
      "ida_expr",
      "ida_fixup",
      "ida_fpro",
      "ida_frame",
      "ida_funcs",
      "ida_gdl",
      "ida_graph",
      "ida_hexrays",
      "ida_ida",
      "ida_idd",
      "ida_idp",
      "ida_ieee",
      "ida_kernwin",
      "ida_libfuncs",
      "ida_lines",
      "ida_loader",
      "ida_merge",
      "ida_mergemod",
      "ida_moves",
      "ida_nalt",
      "ida_name",
      "ida_netnode",
      "ida_offset",
      "ida_pro",
      "ida_problems",
      "ida_range",
      "ida_regfinder",
      "ida_registry",
      "ida_search",
      "ida_segment",
      "ida_segregs",
      "ida_srclang",
      "ida_strlist",
      "ida_struct",
      "ida_tryblks",
      "ida_typeinf",
      "ida_ua",
      "ida_undo",
      "ida_xref",
      "ida_enum",
      "idaapi",
      "idc",
      "idautils",
  ]

  for name in modules:
    # Some modules might be already imported, some might need lazy import
    if name in sys.modules:
      _session_globals[name] = sys.modules[name]
    else:
      _session_globals[name] = _lazy_import(name)

  # Builtins and helpers
  _session_globals["__builtins__"] = __builtins__
  _session_globals["parse_and_check_ea"] = helper.parse_and_check_ea
  _session_globals["get_function"] = helper.get_function
  _base_globals.update(_session_globals)


# Pristine copy of the initial scope, used to start per-session namespaces.
_base_globals: Dict[str, Any] = {}

# Per-session namespaces for eval_namespace_scope "session", most recently used
# last. Keys are (connection id, gateway session id).
_MAX_SESSION_NAMESPACES = 32
_session_namespaces: collections.OrderedDict[Hashable, Dict[str, Any]] = (
    collections.OrderedDict()
)
_namespaces_lock = threading.Lock()
_warned_scope: set[str] = set()


def _drop_connection_namespaces(connection_id: int) -> None:
  """Forgets the namespaces of an RPC connection that closed."""
  with _namespaces_lock:
    for key in [k for k in _session_namespaces if k[0] == connection_id]:
      del _session_namespaces[key]


rpc.add_connection_close_listener(_drop_connection_namespaces)


def _namespace_scope() -> str:
  scope = str(load_config().get("eval_namespace_scope", "process")).lower()
  if scope not in ("process", "session"):
    if scope not in _warned_scope:
      _warned_scope.add(scope)
      logger.warning("Unknown eval_namespace_scope %r; using 'process'.", scope)
    return "process"
  return scope


def _current_namespace() -> Dict[str, Any]:
  """Returns the globals idapython_eval runs the code in.

  With eval_namespace_scope "process" (default) all callers share one
  namespace. With "session" each MCP session gets its own: the gateway sends
  its session id in the request metadata, and callers that send none (older
  gateways, direct RPC clients) get one namespace per connection. Calls that do
  not come through RPC use the process namespace.
  """
  if _namespace_scope() != "session":
    return _session_globals
  session = rpc.current_meta().get("session")
  key = (
      rpc.current_connection(),
      session if isinstance(session, str) else None,
  )
  if key == (None, None):
    return _session_globals
  with _namespaces_lock:
    namespace = _session_namespaces.get(key)
    if namespace is not None:
      _session_namespaces.move_to_end(key)
      return namespace
    namespace = dict(_base_globals)
    _session_namespaces[key] = namespace
    while len(_session_namespaces) > _MAX_SESSION_NAMESPACES:
      evicted, _ = _session_namespaces.popitem(last=False)
      logger.info("Dropped the idapython_eval namespace of %r", evicted)
    return namespace


@jsonrpc
@unsafe
@idawrite
def idapython_eval(
    code: Annotated[str, "Python code to execute"],
) -> Dict[str, Any]:
  """Execute Python code in IDA context.

  Returns dict with result/stdout/stderr. Has access to all IDA API modules.
  Supports Jupyter-style evaluation (returns the value of the last expression).
  Maintains persistent state across calls; the server can be configured to
  keep separate state per MCP session.
  """
  _init_session_globals()
  namespace = _current_namespace()

  stdout_capture = io.StringIO()
  stderr_capture = io.StringIO()
  result_value = None

  # Use context managers to redirect stdout/stderr safely
  try:
    with (
        contextlib.redirect_stdout(stdout_capture),
        contextlib.redirect_stderr(stderr_capture),
    ):
      # 1. Parse the code into an AST
      try:
        tree = ast.parse(code)
      except SyntaxError:
        # If parsing fails, just exec it to let Python generate the standard
        # syntax error in stderr.
        #
        # The use of exec is intentional here, as this function is meant to
        # execute arbitrary Python code in the IDA Pro environment.
        # pylint: disable=exec-used
        exec(code, namespace)
        return {  # Should not be reached if exec raises
            "result": "",
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue(),
        }

      # 2. Analyze the AST to handle Jupyter-style last-expression logic
      last_node = None
      if tree.body and isinstance(tree.body[-1], ast.Expr):
        # The last statement is an expression. We want to evaluate it and return
        # its result.
        last_node = tree.body.pop()

      # 3. Compile and execute the statement part
      if tree.body:
        # compile(tree, ...) works on a Module with a list of statements
        code_obj = compile(tree, filename="<string>", mode="exec")
        # The use of exec is intentional here, as this function is meant to
        # execute arbitrary Python code in the IDA Pro environment.
        # pylint: disable=exec-used
        exec(code_obj, namespace)

      # 4. Compile and evaluate the last expression
      if last_node is not None:
        # Convert the Expr node back to an Expression object for eval mode
        expr = ast.Expression(last_node.value)  # type: ignore
        expr_code = compile(expr, filename="<string>", mode="eval")
        # The use of eval is intentional here, as this function is meant to
        # evaluate arbitrary Python code in the IDA Pro environment.
        # pylint: disable=eval-used
        result_value = eval(expr_code, namespace)

  except Exception:  # pylint: disable=broad-exception-caught
    # The broad exception is intentional here to catch any error during the
    # execution of the user-provided code.
    # Capture traceback into stderr
    print(traceback.format_exc(), file=stderr_capture)

  return {
      "result": str(result_value) if result_value is not None else "",
      "stdout": stdout_capture.getvalue(),
      "stderr": stderr_capture.getvalue(),
  }
