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

"""Gateway SQL Query Tool and Query Rewriter."""

import logging
import re
import traceback
from typing import Annotated, Any, List, Union

from gateway.forward import DatabaseId
from gateway.forward import forward_to
from gateway.forward import mcp_tool
from pydantic import AliasChoices
from pydantic import Field
from shared.types import QueryResult
import sqlglot
from sqlglot import exp
from sqlglot.optimizer.simplify import simplify

logging.getLogger("sqlglot").setLevel(logging.ERROR)


def _to_signed_64(val: int) -> int:
  if val < -0x8000000000000000 or val > 0xFFFFFFFFFFFFFFFF:
    raise ValueError(f"Integer {val} exceeds 64-bit integer limit")
  return val if val < 0x8000000000000000 else val - 0x10000000000000000


def adjust_query(parsed: Any) -> str:
  """Normalizes hex literals and 64-bit integers for SQLite execution."""

  def make_literal(val: int) -> exp.Expression:
    sv = _to_signed_64(val)
    if sv < 0:
      return exp.Neg(this=exp.Literal.number(-sv))
    return exp.Literal.number(sv)

  def _hex_to_int(node: Any) -> Any:
    if isinstance(node, exp.HexString):
      val = int(node.name, 16)
      if isinstance(node.parent, exp.Neg):
        if val > 0x8000000000000000:
          raise ValueError(
              f"Integer literal -0x{node.name} exceeds 64-bit integer limit"
          )
      elif val > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(
            f"Integer literal 0x{node.name} exceeds 64-bit integer limit"
        )
      return exp.Literal.number(val)
    if isinstance(node, exp.Literal) and not node.args.get("is_string"):
      v_str = str(node.name).lower()
      if v_str.startswith("0x"):
        val = int(v_str, 16)
        if isinstance(node.parent, exp.Neg):
          if val > 0x8000000000000000:
            raise ValueError(
                f"Integer literal -{node.name} exceeds 64-bit integer limit"
            )
        elif val > 0xFFFFFFFFFFFFFFFF:
          raise ValueError(
              f"Integer literal {node.name} exceeds 64-bit integer limit"
          )
        return exp.Literal.number(val)
    return node

  def _enforce_signed_64(node: Any) -> Any:
    if isinstance(node, exp.Literal) and not node.args.get("is_string"):
      v_str = str(node.name).lower()
      if isinstance(node.parent, exp.Neg):
        if v_str.isdigit():
          v_int = int(v_str)
          if v_int > 0x8000000000000000:
            raise ValueError(
                f"Negative integer literal -{v_str} exceeds 64-bit integer"
                " limit"
            )
        return node
      if v_str.isdigit():
        v_int = int(v_str)
        if v_int > 0xFFFFFFFFFFFFFFFF:
          raise ValueError(
              f"Integer literal {v_str} exceeds 64-bit integer limit"
          )
        return make_literal(v_int)
    return node

  def get_literal_val(n):
    if isinstance(n, exp.Neg):
      val = get_literal_val(n.this)
      return -val if val is not None else None
    if isinstance(n, exp.Literal) and not n.args.get("is_string"):
      try:
        return int(n.name)
      except ValueError:
        return None
    return None

  def _build_unsigned_cmp(
      op_cls: type[exp.GT | exp.GTE | exp.LT | exp.LTE],
      left: exp.Expression,
      right: exp.Expression,
  ) -> exp.Expression:
    """Translates a signed comparison into an unsigned comparison in SQLite.

    SQLite integers are signed 64-bit two's complement values, so linear
    addresses >= 0x8000000000000000 are stored as negative numbers.
    This function rewrites comparison operators (LT, LTE, GT, GTE) into
    equivalent native SQLite boolean expressions:
      - Constant folding: If both operands are known literals, evaluates the
        comparison directly at parse time.
      - Constant on one side: Uses sign-partitioned clauses (e.g. for `x < C`
        where `C < 0`, `(x >= 0 OR x < C)`).
      - Dynamic comparison: Uses cross-sign and same-sign partitioning
        `(x >= 0 AND y < 0) OR ((x >= 0) = (y >= 0) AND x < y)`.

    All compound boolean expressions are wrapped in `exp.Paren` to guarantee
    correct operator precedence in the SQL AST.

    Args:
      op_cls: The sqlglot AST operator class (exp.LT, exp.LTE, exp.GT, exp.GTE).
      left: The left operand AST expression.
      right: The right operand AST expression.

    Returns:
      A sqlglot expression representing the unsigned comparison logic.
    """
    l_val = get_literal_val(left)
    r_val = get_literal_val(right)
    zero = exp.Literal.number(0)

    # Both constants
    if l_val is not None and r_val is not None:
      u_l = l_val & 0xFFFFFFFFFFFFFFFF
      u_r = r_val & 0xFFFFFFFFFFFFFFFF
      if op_cls == exp.LT:
        res = u_l < u_r
      elif op_cls == exp.LTE:
        res = u_l <= u_r
      elif op_cls == exp.GT:
        res = u_l > u_r
      elif op_cls == exp.GTE:
        res = u_l >= u_r
      else:
        res = False
      return exp.Literal.number(1 if res else 0)

    def _paren(e: exp.Expression) -> exp.Expression:
      return exp.Paren(this=e)

    # Right is constant
    if r_val is not None:
      signed_r = _to_signed_64(r_val)
      r_lit = make_literal(r_val)
      x = left

      if op_cls in (exp.LT, exp.LTE):
        connector_cls = exp.Or if signed_r < 0 else exp.And
        bound_cls = exp.GTE
      elif op_cls in (exp.GT, exp.GTE):
        connector_cls = exp.And if signed_r < 0 else exp.Or
        bound_cls = exp.LT

      return _paren(
          connector_cls(
              this=bound_cls(this=x.copy(), expression=zero),
              expression=op_cls(this=x.copy(), expression=r_lit),
          )
      )

    # Left is constant
    if l_val is not None:
      signed_l = _to_signed_64(l_val)
      l_lit = make_literal(l_val)
      y = right

      if op_cls in (exp.LT, exp.LTE):
        connector_cls = exp.And if signed_l < 0 else exp.Or
        bound_cls = exp.LT
      elif op_cls in (exp.GT, exp.GTE):
        connector_cls = exp.Or if signed_l < 0 else exp.And
        bound_cls = exp.GTE

      return _paren(
          connector_cls(
              this=bound_cls(this=y.copy(), expression=zero),
              expression=op_cls(this=l_lit, expression=y.copy()),
          )
      )

    # Both dynamic (neither is constant)
    x = left
    y = right
    if op_cls in (exp.LT, exp.LTE):
      term1 = exp.And(
          this=exp.GTE(this=x.copy(), expression=zero),
          expression=exp.LT(this=y.copy(), expression=zero),
      )
      same_sign = exp.EQ(
          this=exp.GTE(this=x.copy(), expression=zero),
          expression=exp.GTE(this=y.copy(), expression=zero),
      )
      term2 = exp.And(
          this=same_sign, expression=op_cls(this=x.copy(), expression=y.copy())
      )
      return _paren(exp.Or(this=term1, expression=term2))

    elif op_cls in (exp.GT, exp.GTE):
      term1 = exp.And(
          this=exp.LT(this=x.copy(), expression=zero),
          expression=exp.GTE(this=y.copy(), expression=zero),
      )
      same_sign = exp.EQ(
          this=exp.GTE(this=x.copy(), expression=zero),
          expression=exp.GTE(this=y.copy(), expression=zero),
      )
      term2 = exp.And(
          this=same_sign, expression=op_cls(this=x.copy(), expression=y.copy())
      )
      return _paren(exp.Or(this=term1, expression=term2))

  def rewrite(node: Any) -> Any:
    """Recursively rewrites the SQL AST to support unsigned 64-bit comparisons.

    This function walks the sqlglot AST and transforms comparison and range
    operators that would otherwise yield incorrect results under SQLite's signed
    64-bit integer semantics:

      1. Relational Operators (LT, LTE, GT, GTE):
         Intercepted and delegated to `_build_unsigned_cmp`, which converts
         signed two's complement integer comparisons into sign-partitioned
         boolean logic respecting unsigned 64-bit ordering.

      2. BETWEEN Expressions (`this BETWEEN low AND high`): Expanded into
         compound range conjunctions `(this >= low AND this <= high)` where each
         bound comparison is individually rewritten via `_build_unsigned_cmp`.
         Properly handles negated ranges (`NOT BETWEEN`) by wrapping the
         conjunction in an `exp.Not`.

      3. Recursive AST Traversal:
         Recursively transforms all child expressions and argument lists
         (e.g., subqueries, CTEs, SELECT columns, JOIN conditions, WHERE
         clauses).

    Args:
      node: The current sqlglot AST expression node to transform.

    Returns:
      The rewritten AST expression node with unsigned comparison semantics.
    """
    if not isinstance(node, exp.Expression):
      return node

    if isinstance(node, (exp.GT, exp.LT, exp.GTE, exp.LTE)):
      return _build_unsigned_cmp(
          type(node), rewrite(node.left), rewrite(node.right)
      )

    if isinstance(node, exp.Between):
      low_node = rewrite(node.args.get("low"))
      high_node = rewrite(node.args.get("high"))
      this_node = rewrite(node.this)
      cmp1 = _build_unsigned_cmp(exp.GTE, this_node.copy(), low_node)
      cmp2 = _build_unsigned_cmp(exp.LTE, this_node.copy(), high_node)
      res = exp.And(this=cmp1, expression=cmp2)
      if node.args.get("is_not"):
        return exp.Not(this=res)
      return res

    for k, v in node.args.items():
      if isinstance(v, list):
        node.set(k, [rewrite(i) for i in v])
      elif isinstance(v, exp.Expression):
        node.set(k, rewrite(v))

    return node

  normalized = parsed.transform(_hex_to_int)
  simplified = simplify(normalized)
  renormalized = simplified.transform(_enforce_signed_64)
  rewritten = rewrite(renormalized)
  return rewritten.sql(dialect="sqlite")


_LEADING_SQL_COMMENTS = re.compile(
    r"^(?:\s|--[^\n]*(?:\n|$)|/\*.*?\*/)+", re.DOTALL
)


def _rewrite_explain(node: exp.Command) -> str | None:
  """Rewrites an EXPLAIN [QUERY PLAN] statement wrapping a read-only query.

  Returns None if the explained statement is not a SELECT-like query.
  """
  if str(node.this).upper() != "EXPLAIN" or not node.expression:
    return None
  body = _LEADING_SQL_COMMENTS.sub("", node.expression.name).strip()
  match = re.match(
      r"^QUERY\s+PLAN\b(.*)$", body, flags=re.IGNORECASE | re.DOTALL
  )
  if match:
    prefix = "EXPLAIN QUERY PLAN"
    inner_sql = match.group(1).strip()
  else:
    prefix = "EXPLAIN"
    inner_sql = body
  if not inner_sql:
    return None
  inner_node = sqlglot.parse_one(inner_sql, read="sqlite")
  if not isinstance(inner_node, exp.Query):
    return None
  return f"{prefix} {adjust_query(inner_node)}"


def _to_query_result(res: dict[str, Any]) -> QueryResult:
  """Constructs a QueryResult from a dictionary received over RPC."""
  if res.get("error"):
    return QueryResult(error=str(res["error"]))
  return QueryResult(rows=res.get("rows", []))


@mcp_tool
async def sql_query(
    database_id: DatabaseId,
    sql: Annotated[
        Union[List[str], str],
        Field(
            validation_alias=AliasChoices("sql", "query", "queries", "sqls"),
            description=(
                "SQL query or queries to execute. Supports multiple queries"
                " (in a list or separated by ';')."
            ),
        ),
    ],
) -> Union[QueryResult, List[QueryResult]]:
  """Executes read-only SQL queries against IDA Pro using SQLite.

  Tables ('functions', 'strings', 'names', 'imports', 'segments', 'local_types',
  'xrefs', 'entries') are automatically populated from IDA on first use and
  kept in sync automatically via event hooks.

  ### Available Tables & Schemas
  - functions (start_ea INTEGER, end_ea INTEGER, name TEXT, demangled_name
    TEXT, prototype TEXT, size INTEGER, is_lib INTEGER)
  - strings (address INTEGER, length INTEGER, string TEXT)
  - names (address INTEGER, name TEXT)
  - imports (address INTEGER, name TEXT, module TEXT)
  - segments (name TEXT, class TEXT, start_ea INTEGER, end_ea INTEGER,
  size INTEGER, permissions TEXT)
  - local_types (ordinal INTEGER, name TEXT, declaration TEXT)
  - xrefs (from_ea INTEGER, to_ea INTEGER, type TEXT, from_function_ea INTEGER)
  - entries (index_id INTEGER, ordinal INTEGER, address INTEGER, name TEXT)

  It supports standard SQL SELECT statements. You can provide multiple
  queries in a list or separated by ';'.

  ### Extended SQLite Support
  This tool provides an enhanced SQLite interface for reverse engineering:
  - **Hexadecimal Literals:** You can use `0x` prefixed hexadecimal numbers
    directly in your queries for any integer types (e.g., `WHERE address >
    0x401000`, `WHERE size = 0x40`).
  - **Automatic Hex Formatting in Final Output:** All integer columns and values
    in the final query results (the returned dictionaries) are automatically
    formatted as lowercase `0x...` hexadecimal strings (e.g., `0x401240`,
    `0x20`), eliminating the need to manually call `printf('0x%X', ...)` for
    selected output columns.
  - **Intermediate Evaluation in SQLite:** Inside the SQL engine, expressions
    and columns remain numeric integer values. If coerced to text within a
    query (e.g. via `LIKE`, `CAST(... AS TEXT)`, or string concatenation
    `||`), SQLite uses standard base-10 decimal representation. To perform
    hex pattern matching inside the query itself, explicitly use
    `printf('0x%x', address) LIKE '0x401%'` or prefer numeric comparisons
    (`WHERE address BETWEEN 0x401000 AND 0x402000`).
  - **Large Address Support:** All address columns are automatically treated
    as unsigned 64-bit integers (`uint64`).

  ### Notes on Querying
  - To see available tables or their schemas dynamically:
    - `SELECT name FROM sqlite_master WHERE type='table'`
    - `PRAGMA table_info('functions')`
  - **'xrefs' table:** Contains code and data cross-references between memory
    addresses and type IDs (excluding ordinary sequential instruction flow).
    Reference types include `call`, `jmp`, `read`, `write`, and 'offset'. The
    `from_function_ea` column contains the start address of the
    function containing `from_ea` (or NULL if outside any function).
    Supports all comparison and set operators (`=`, `!=`, `<`, `<=`, `>`, `>=`,
    `BETWEEN ... AND ...`, `IN (...)`) on `from_ea` and `to_ea`.

  Args:
    sql: SQL query or queries to execute. Supports multiple queries (in a list
      or separated by ';').

  Returns:
    A QueryResult object if a single query was provided, or a list of
    QueryResult objects (one per input query). Each QueryResult contains 'rows'
    (list of dicts with hexadecimal string formatting for integers) on success,
    or 'error' (error message string) if the query failed.
  """
  queries_input = sql if isinstance(sql, list) else [sql]
  results: list[QueryResult] = []

  for q in queries_input:
    q = q.strip()
    if not q:
      continue
    try:
      parsed_list = sqlglot.parse(q, read="sqlite")
      batch = []
      batch_indices = []
      current_results: list[QueryResult | None] = []

      for node in parsed_list:
        if not node:
          continue
        rewritten_sql: str | None = None
        if isinstance(node, exp.Pragma):
          rewritten_sql = node.sql(dialect="sqlite")
        elif isinstance(node, exp.Command):
          rewritten_sql = _rewrite_explain(node)
        elif isinstance(node, (exp.Query, exp.Describe)):
          rewritten_sql = adjust_query(node)

        if rewritten_sql is None:
          current_results.append(
              QueryResult(
                  error=(
                      "Error: Only read-only queries (SELECT, DESCRIBE, etc.)"
                      " are allowed."
                  )
              )
          )
          continue

        batch_indices.append(len(current_results))
        current_results.append(None)
        batch.append({"sql": rewritten_sql})

      if batch:
        backend_results = await forward_to(
            database_id, "sql_query", {"queries": batch}
        )
        for idx, res in zip(batch_indices, backend_results):
          current_results[idx] = _to_query_result(res)

      for item in current_results:
        if item is not None:
          results.append(item)
    except Exception as e:
      results.append(
          QueryResult(
              error=f"Error executing SQL: {str(e)}\n{traceback.format_exc()}"
          )
      )

  return (
      results[0] if len(results) == 1 and not isinstance(sql, list) else results
  )


__all__ = ["sql_query"]
