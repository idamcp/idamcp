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
#
# The approach of this module (an AST index of IDA's own python modules and
# example scripts, searched by name and description) and parts of the indexing
# and search code are adapted from IDA Nexus
# (https://github.com/HexRaysSA/ida-nexus, ida_nexus/reference.py),
# Copyright (c) 2026 Hex-Rays SA, used under the MIT License, whose terms are
# the same as those above.

"""Searchable reference of the IDAPython API shipped with the running IDA.

The index is built from IDA's own `python/` directory (the `ida_*` modules,
`idc`, `idautils` and the bundled examples) by parsing the sources with `ast`,
without importing them. So it matches the IDA version that is running: for
example `ida_struct` and `ida_enum` are absent on IDA 9.x. The approach
follows the `reference` tool of IDA Nexus, which indexes ida-domain the same
way.

No IDA imports; the caller passes the directory.
"""

import ast
import dataclasses
import functools
import os
import re
import threading
from typing import Any

MAX_DOC_CHARS = 1500
MAX_RESULTS = 50

# Modules removed in IDA 9.0, and what replaced them. Models trained on older
# scripts still call them.
REMOVED_MODULES = {
    "ida_struct": (
        "ida_struct was removed in IDA 9.0; structures are types now: use"
        " ida_typeinf (tinfo_t, udt_type_data_t, udm_t) and ida_frame for"
        " stack frames."
    ),
    "ida_enum": (
        "ida_enum was removed in IDA 9.0; enums are types now: use ida_typeinf"
        " (tinfo_t, enum_type_data_t, edm_t)."
    ),
}

_STOPWORDS = frozenset(
    "a an and at by do does for from get how i ida idapython in is it me my"
    " of on the to use using what with".split()
)

# Words from a question, and the abbreviations IDA's API names use for them.
_ABBREVIATIONS = {
    "address": ("ea",),
    "comment": ("cmt",),
    "function": ("func",),
    "instruction": ("insn",),
    "local": ("lvar",),
    "operand": ("op",),
    "reference": ("ref", "xref"),
    "segment": ("seg", "segm"),
    "string": ("str", "strlit"),
    "structure": ("struc", "udt"),
    "struct": ("struc", "udt"),
    "type": ("tinfo",),
    "variable": ("var", "lvar"),
}


@dataclasses.dataclass
class Entry:
  kind: str  # module, function, class, method, constant
  module: str
  qualname: str
  name: str
  file: str
  line: int
  doc: str = ""
  signature: str = ""


@dataclasses.dataclass
class Example:
  name: str
  path: str
  summary: str
  doc: str
  content: str


@dataclasses.dataclass
class Index:
  python_dir: str
  modules: frozenset[str]
  entries: list[Entry]
  examples: list[Example]


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
  args = ast.unparse(node.args)
  if args.startswith("self, "):
    args = args[len("self, ") :]
  elif args == "self":
    args = ""
  sig = f"({args})"
  if node.returns is not None:
    sig += f" -> {ast.unparse(node.returns)}"
  return sig


def _clean_doc(doc: str | None) -> str:
  if not doc:
    return ""
  return "\n".join(line.rstrip() for line in doc.strip().splitlines())


def _is_public(name: str) -> bool:
  return not name.startswith("_")


def _constant_docs(body: list[ast.stmt]) -> dict[int, str]:
  """Maps the index of `NAME = ...` statements to the string that follows."""
  docs = {}
  for i, node in enumerate(body[:-1]):
    nxt = body[i + 1]
    if (
        isinstance(node, ast.Assign)
        and isinstance(nxt, ast.Expr)
        and isinstance(nxt.value, ast.Constant)
        and isinstance(nxt.value.value, str)
    ):
      docs[i] = nxt.value.value
  return docs


def _index_module(path: str, module: str) -> list[Entry]:
  with open(path, encoding="utf-8", errors="replace") as f:
    tree = ast.parse(f.read(), filename=path)
  file = os.path.basename(path)
  entries = [
      Entry(
          "module",
          module,
          module,
          module,
          file,
          1,
          _clean_doc(ast.get_docstring(tree)),
      )
  ]
  const_docs = _constant_docs(tree.body)
  for i, node in enumerate(tree.body):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
      if _is_public(node.name):
        entries.append(
            Entry(
                "function",
                module,
                f"{module}.{node.name}",
                node.name,
                file,
                node.lineno,
                _clean_doc(ast.get_docstring(node)),
                _signature(node),
            )
        )
    elif isinstance(node, ast.ClassDef):
      if not _is_public(node.name):
        continue
      entries.append(
          Entry(
              "class",
              module,
              f"{module}.{node.name}",
              node.name,
              file,
              node.lineno,
              _clean_doc(ast.get_docstring(node)),
          )
      )
      for child in node.body:
        if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
          continue
        if not _is_public(child.name) and child.name != "__init__":
          continue
        entries.append(
            Entry(
                "method",
                module,
                f"{module}.{node.name}.{child.name}",
                child.name,
                file,
                child.lineno,
                _clean_doc(ast.get_docstring(child)),
                _signature(child),
            )
        )
    elif isinstance(node, ast.Assign) and len(node.targets) == 1:
      target = node.targets[0]
      if (
          isinstance(target, ast.Name)
          and _is_public(target.id)
          and target.id.isupper()
      ):
        entries.append(
            Entry(
                "constant",
                module,
                f"{module}.{target.id}",
                target.id,
                file,
                node.lineno,
                _clean_doc(const_docs.get(i)),
            )
        )
  return entries


def _example_summary(doc: str) -> str:
  match = re.search(r"^summary:\s*(.+)$", doc, re.MULTILINE)
  if match:
    return match.group(1).strip()
  return doc.strip().splitlines()[0] if doc.strip() else ""


def _index_examples(examples_dir: str) -> list[Example]:
  examples = []
  for root, dirs, files in os.walk(examples_dir):
    dirs[:] = sorted(d for d in dirs if d != "__pycache__")
    for name in sorted(files):
      if not name.endswith(".py"):
        continue
      path = os.path.join(root, name)
      try:
        with open(path, encoding="utf-8", errors="replace") as f:
          content = f.read()
        doc = ast.get_docstring(ast.parse(content, filename=path)) or ""
      except (OSError, SyntaxError, ValueError):
        continue
      rel = os.path.relpath(path, examples_dir).replace(os.sep, "/")
      examples.append(
          Example(
              name=rel[: -len(".py")],
              path=f"examples/{rel}",
              summary=_example_summary(doc),
              doc=doc,
              content=content,
          )
      )
  return examples


def build_index(python_dir: str) -> Index:
  """Parses IDA's python directory. Files that fail to parse are skipped."""
  names = sorted(os.listdir(python_dir))
  module_files = [
      n
      for n in names
      if n.endswith(".py")
      and (n.startswith("ida_") or n in ("idc.py", "idautils.py", "idaapi.py"))
  ]
  entries: list[Entry] = []
  modules = set()
  for name in module_files:
    module = name[: -len(".py")]
    try:
      entries.extend(_index_module(os.path.join(python_dir, name), module))
    except (OSError, SyntaxError, ValueError):
      continue
    modules.add(module)
  examples_dir = os.path.join(python_dir, "examples")
  examples = (
      _index_examples(examples_dir) if os.path.isdir(examples_dir) else []
  )
  return Index(python_dir, frozenset(modules), entries, examples)


def _tokens(query: str) -> list[str]:
  tokens = re.findall(r"[a-z0-9_]+", query.casefold())
  return [t for t in tokens if t not in _STOPWORDS] or tokens


@functools.lru_cache(maxsize=64)
def _joined_phrases(query: str) -> frozenset[str]:
  """Adjacent query words written as one name: 'xrefs to' -> 'xrefsto'."""
  words = re.findall(r"[a-z0-9]+", query)
  pairs = zip(words, words[1:])
  return frozenset(sep.join(p) for p in pairs for sep in ("", "_"))


def _score(
    names: str, name: str, body: str, query: str, tokens: list[str]
) -> int:
  score = 0
  if query == name or query in names.split():
    score += 200
  elif query in names:
    score += 60
  elif len(tokens) > 1 and query in body:
    score += 40
  score += 150 * sum(p in name for p in _joined_phrases(query))
  parts = set(re.split(r"[._\s]+", names))
  covered = 0
  for token in tokens:
    variants = {token, token.removesuffix("s")} - {""}
    if name in variants:
      score += 50
    in_names = sum(v in names for v in variants)
    # Abbreviations are short, so they only count as whole name parts.
    in_names += sum(a in parts for a in _ABBREVIATIONS.get(token, ()))
    covered += bool(in_names)
    score += 12 * in_names
    score += 2 * sum(v in body for v in variants)
  # Prefer entries whose name covers several words of the query.
  if covered > 1:
    score += 25 * covered * covered
  return score


def _entry_score(entry: Entry, query: str, tokens: list[str]) -> int:
  name = entry.name.casefold()
  names = f"{name} {entry.qualname.casefold()}"
  body = entry.doc.casefold()
  score = _score(names, name, body, query, tokens)
  # idaapi re-exports everything; prefer the defining module.
  if score and entry.module == "idaapi":
    score //= 2
  return score


def _example_score(example: Example, query: str, tokens: list[str]) -> int:
  name = example.name.casefold()
  names = f"{name} {example.summary.casefold()}"
  # Only examples whose name or summary mention the query; code mentions of a
  # common function would otherwise pick unrelated scripts.
  if not any(t in names or t.removesuffix("s") in names for t in tokens):
    return 0
  body = example.doc.casefold()
  score = _score(names, os.path.basename(name), body, query, tokens)
  content = example.content.casefold()
  return score + sum(t in content for t in tokens)


def _notes(index: Index, query: str) -> list[str]:
  notes = []
  for module in dict.fromkeys(
      re.findall(r"\bida_[a-z0-9_]+", query.casefold())
  ):
    if module in index.modules:
      continue
    if module in REMOVED_MODULES:
      notes.append(REMOVED_MODULES[module])
    else:
      notes.append(f"Module {module} does not exist in this IDA version.")
  return notes


def _truncate(text: str, limit: int = MAX_DOC_CHARS) -> str:
  return text if len(text) <= limit else text[:limit].rstrip() + " [...]"


def search(
    index: Index,
    query: str,
    max_results: int = 10,
    include_example: bool = True,
) -> dict[str, Any]:
  """Returns the best matching API entries and, optionally, one example."""
  query = query.strip()
  if not query:
    raise ValueError("query must not be empty")
  max_results = max(1, min(int(max_results), MAX_RESULTS))
  q = query.casefold()
  tokens = _tokens(q)

  scored = [(_entry_score(e, q, tokens), e) for e in index.entries]
  scored = [item for item in scored if item[0] > 0]
  scored.sort(key=lambda item: (-item[0], item[1].qualname))
  # SWIG modules sometimes define a name twice (overloads); keep the first.
  seen = set()
  unique = []
  for item in scored:
    if item[1].qualname not in seen:
      seen.add(item[1].qualname)
      unique.append(item)
  scored = unique
  results = []
  for _, entry in scored[:max_results]:
    item = {
        "kind": entry.kind,
        "name": entry.qualname,
        "doc": _truncate(entry.doc),
        "source": f"{entry.file}:{entry.line}",
    }
    if entry.signature:
      item["signature"] = entry.signature
    results.append(item)

  result: dict[str, Any] = {
      "python_dir": index.python_dir,
      "results": results,
      "total_matches": len(scored),
  }
  if include_example:
    examples = [(_example_score(x, q, tokens), x) for x in index.examples]
    examples = [item for item in examples if item[0] > 0]
    if examples:
      examples.sort(key=lambda item: (-item[0], item[1].name))
      best = examples[0][1]
      result["example"] = {
          "name": best.name,
          "path": best.path,
          "summary": best.summary,
          "content": best.content,
      }
  notes = _notes(index, query)
  if notes:
    result["notes"] = notes
  return result


_cache_lock = threading.Lock()
_cache: dict[str, Index] = {}


def get_index(python_dir: str) -> Index:
  """Builds the index for python_dir once and caches it."""
  with _cache_lock:
    index = _cache.get(python_dir)
    if index is None:
      index = build_index(python_dir)
      _cache[python_dir] = index
    return index
