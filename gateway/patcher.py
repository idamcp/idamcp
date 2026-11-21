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

"""Gateway Patch Assembly Tool powered by Keystone."""

import ast
import dataclasses
import operator
import re
import sys
from typing import Annotated, List, Tuple

from gateway.forward import DatabaseId
from gateway.forward import forward_to
from gateway.forward import mcp_tool
from keystone import (
    KS_ARCH_ARM,
    KS_ARCH_ARM64,
    KS_ARCH_MIPS,
    KS_ARCH_PPC,
    KS_ARCH_SPARC,
    KS_ARCH_SYSTEMZ,
    KS_ARCH_X86,
    KS_MODE_16,
    KS_MODE_32,
    KS_MODE_64,
    KS_MODE_ARM,
    KS_MODE_BIG_ENDIAN,
    KS_MODE_LITTLE_ENDIAN,
    KS_MODE_MIPS32,
    KS_MODE_MIPS64,
    KS_MODE_PPC32,
    KS_MODE_PPC64,
    KS_MODE_SPARC32,
    KS_MODE_SPARC64,
    KS_MODE_THUMB,
    KS_OPT_SYNTAX_ATT,
    KS_OPT_SYNTAX_INTEL,
    KS_OPT_SYNTAX_NASM,
    Ks,
    KsError,
)
from shared.types import (
    AssemblyContextRequest,
    PatchAssemblyRequest,
    PatchBytesRequest,
)

SYNTAX_MAP = {
    "intel": KS_OPT_SYNTAX_INTEL,
    "nasm": KS_OPT_SYNTAX_NASM,
    "att": KS_OPT_SYNTAX_ATT,
}


_SEGMENT_REGISTERS = frozenset({"cs", "ds", "es", "fs", "gs", "ss"})
_COMMON_KEYWORDS = frozenset({
    "byte",
    "near",
    "short",
    "word",
    "dword",
    "qword",
    "ptr",
    "offset",
    "far",
})


def get_keystone_mode(
    procname: str,
    bitness: int,
    is_be: bool,
    is_thumb: bool,
) -> Tuple[int, int]:
  """Maps IDA processor info to Keystone arch and mode constants."""
  arch = KS_ARCH_X86
  mode = KS_MODE_32

  if procname == "metapc":
    arch = KS_ARCH_X86
    if bitness == 64:
      mode = KS_MODE_64
    elif bitness == 32:
      mode = KS_MODE_32
    else:
      mode = KS_MODE_16
  elif procname.startswith("arm"):
    if bitness == 64:
      arch = KS_ARCH_ARM64
      mode = KS_MODE_BIG_ENDIAN if is_be else KS_MODE_LITTLE_ENDIAN
    else:
      arch = KS_ARCH_ARM
      mode = KS_MODE_THUMB if is_thumb else KS_MODE_ARM
      if is_be:
        mode |= KS_MODE_BIG_ENDIAN
      else:
        mode |= KS_MODE_LITTLE_ENDIAN
  elif procname.startswith("sparc"):
    arch = KS_ARCH_SPARC
    mode = KS_MODE_SPARC64 if bitness == 64 else KS_MODE_SPARC32
    mode |= KS_MODE_BIG_ENDIAN if is_be else KS_MODE_LITTLE_ENDIAN
  elif procname.startswith("ppc"):
    arch = KS_ARCH_PPC
    mode = KS_MODE_PPC64 if bitness == 64 else KS_MODE_PPC32
    # do not support Little Endian mode for PPC
    mode |= KS_MODE_BIG_ENDIAN
  elif procname.startswith("mips"):
    arch = KS_ARCH_MIPS
    mode = KS_MODE_MIPS64 if bitness == 64 else KS_MODE_MIPS32
    mode |= KS_MODE_BIG_ENDIAN if is_be else KS_MODE_LITTLE_ENDIAN
  elif procname.startswith("systemz") or procname.startswith("s390x"):
    arch = KS_ARCH_SYSTEMZ
    mode = KS_MODE_BIG_ENDIAN

  return arch, mode


def extract_candidate_symbols(assembly: str) -> list[str]:
  """Extract candidate IDA symbol tokens from assembly string."""
  tokens = re.findall(r"[$a-zA-Z_][$a-zA-Z0-9_:\.]*", assembly)
  symbols = set()
  for token in tokens:
    if token.lower() in _COMMON_KEYWORDS:
      continue
    sym = token
    if ":" in token:
      parts = token.partition(":")
      if parts[0].lower() in _SEGMENT_REGISTERS and not parts[2].startswith(
          ":"
      ):
        sym = parts[2]
    symbols.add(sym)
  return list(symbols)


def replace_symbols(assembly: str, resolved_symbols: dict[str, str]) -> str:
  """Replace resolved symbols with hex addresses in assembly string."""

  def replace_names(match):
    token = match.group(0)
    if token.lower() in _COMMON_KEYWORDS:
      return token
    sym = token
    prefix = ""
    # Handle segment registers like fs:var_10 but avoid C++ namespaces like
    # std::string::clear
    if ":" in token:
      parts = token.partition(":")
      if parts[0].lower() in _SEGMENT_REGISTERS and not parts[2].startswith(
          ":"
      ):
        prefix = parts[0] + parts[1]
        sym = parts[2]
    if sym in resolved_symbols:
      return f"{prefix}{resolved_symbols[sym]}"
    return token

  return re.sub(r"[$a-zA-Z_][$a-zA-Z0-9_:\.]*", replace_names, assembly)


# Safe operators for basic arithmetic and bitwise operations
_SAFE_OP_MAP = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.Invert: operator.invert,
}


def _safe_eval_ast(node) -> int:
  """Recursively evaluate mathematical AST nodes safely."""
  if isinstance(node, ast.Constant):
    if isinstance(node.value, (int, float)):
      return int(node.value)
  elif sys.version_info[:2] < (3, 8) and isinstance(
      node, ast.Num
  ):  # Fallback for Python < 3.8
    if isinstance(node.n, (int, float)):
      return int(node.n)
  elif isinstance(node, ast.BinOp):
    left = _safe_eval_ast(node.left)
    right = _safe_eval_ast(node.right)
    op_type = type(node.op)
    if op_type in _SAFE_OP_MAP:
      return int(_SAFE_OP_MAP[op_type](left, right))
  elif isinstance(node, ast.UnaryOp):
    operand = _safe_eval_ast(node.operand)
    op_type = type(node.op)
    if op_type in _SAFE_OP_MAP:
      return int(_SAFE_OP_MAP[op_type](operand))
  raise ValueError(f"Unsupported AST node: {type(node)}")


def _safe_eval_math(expr: str) -> int:
  """Parse and evaluate a mathematical expression safely using AST."""
  expr = expr.strip()
  # Defensive character regex to reject obviously malicious input before parsing
  if not re.match(r"^[0-9a-fA-FxX\s\+\-\*\/\(\)\&\^\|\<\>\~]+$", expr):
    raise ValueError("Forbidden characters in math expression")
  tree = ast.parse(expr, mode="eval")
  return _safe_eval_ast(tree.body)


def _eval_math_match(match: re.Match[str]) -> str:
  """Evaluate arithmetic equation in a regex match."""
  prefix = match.group(1)
  expr = match.group(2)
  try:
    val = _safe_eval_math(expr)
    if val > 0x80000000:
      val = 0xFFFFFFFF - val + 1
      val = -val
    return f"{prefix}{hex(val)}"
  except (ValueError, SyntaxError, TypeError, NameError):
    return match.group(0)


def fix_ida_syntax(assembly: str, arch: int, mode: int) -> str:
  """Normalize assembly code and fix some IDA-specific syntax."""
  # Unescape common whitespace escape sequences that may be passed literally
  assembly = (
      assembly.replace("\\t", "\t").replace("\\r", "\r").replace("\\n", "\n")
  )

  # Remove extraneous whitespace line-by-line to preserve newlines in
  # multi-instruction patches
  assembly = "\n".join(
      " ".join(line.split()) for line in assembly.splitlines() if line.strip()
  )

  # Convert Intel hex suffixes to 0x prefix for x86/x64
  if arch == KS_ARCH_X86:
    # Match Intel-style hex constant, e.g., 0bh, 12abH, avoiding
    # labels/registers
    assembly = re.sub(
        r"\b([0-9][0-9a-fA-F]*)[hH]\b",
        lambda m: "0x" + m.group(1),
        assembly,
    )

  # '0X' must be '0x' for Keystone
  assembly = assembly.replace("0X", "0x")

  # PPC: Remove 'r' prefix from registers
  if arch == KS_ARCH_PPC:
    # Match 'r' followed by 1 or 2 digits (0-31)
    # But only when used as an operand
    assembly = re.sub(r"(?<=[,\s\(])r([0-9]{1,2})\b", r"\1", assembly)

  # x86: Remove unsupported IDA modifiers
  if arch == KS_ARCH_X86:
    assembly = re.sub(r"\bRETN\b", "RET", assembly, flags=re.IGNORECASE)
    assembly = re.sub(r"\bOFFSET\s+", " ", assembly, flags=re.IGNORECASE)
    assembly = re.sub(
        r"\b(CALL|JMP|LOOP[A-Z]*)\s+NEAR\s+PTR\s+",
        r"\1 ",
        assembly,
        flags=re.IGNORECASE,
    )
    assembly = re.sub(
        r"\b(J[A-Z]{0,2})\s+SHORT\s+", r"\1 ", assembly, flags=re.IGNORECASE
    )

  # ARM / ARM64 / PPC: Bracket math evaluation and UAL fixes
  elif arch in (KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_PPC):

    if arch == KS_ARCH_ARM and mode == KS_MODE_THUMB:
      assembly = re.sub(r"\bmovt\.w\b", "movt", assembly, flags=re.IGNORECASE)

    # ARM: Convert pre-UAL to UAL (e.g., streqb -> strbeq)
    if arch == KS_ARCH_ARM:
      conds = r"(cc|eq|ne|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)"
      pattern = rf"\b(ldr|str){conds}([sbhd])\b"
      assembly = re.sub(pattern, r"\1\3\2", assembly, flags=re.IGNORECASE)

    if arch in (KS_ARCH_ARM, KS_ARCH_ARM64):
      # Match # followed by a math expression before ]
      assembly = re.sub(r"(#)([^\]!]+)(?=\])", _eval_math_match, assembly)
      # Fix "+0x0]" which can be generated by IDA
      assembly = re.sub(r"\+0x0\s*\]", "]", assembly)

    elif arch == KS_ARCH_PPC:
      # Evaluate math between , and ( for memory instructions
      assembly = re.sub(r"(,\s*)([^\(]+)(?=\()", _eval_math_match, assembly)

  return assembly


@mcp_tool
async def patch_assembly(
    database_id: DatabaseId,
    reqs: Annotated[
        List[PatchAssemblyRequest],
        "List of patch addresses assembles requests",
    ],
) -> str:
  """Patch multiple assembly instructions at given addresses.

  You can provide multiple assembly instructions separated by ';'.
  The assembler is aware of the IDA Pro database context, which means you can
  directly use label names, function names, and global variable names
  in your assembly instructions (e.g., 'call my_function' or 'mov eax, my_var').

  The architecture and bitness (e.g., x86, ARM Thumb, MIPS) are automatically
  inferred from the current IDA database.
  """
  context_reqs = [
      AssemblyContextRequest(
          address=req.address,
          symbols=extract_candidate_symbols(req.instructions),
      )
      for req in reqs
  ]

  context_items = await forward_to(
      database_id, "get_assembly_context", {"reqs": context_reqs}
  )

  errors = []
  successes = []
  patch_bytes_reqs = []

  for idx, item in enumerate(context_items):
    orig_req = reqs[idx]
    if "error" in item and item["error"]:
      errors.append(item["error"])
      continue

    current_ea = int(item["address"], 16)
    syntax_val = orig_req.syntax
    syntax_key = syntax_val.lower() if syntax_val else "intel"
    ks_syntax = SYNTAX_MAP.get(syntax_key, KS_OPT_SYNTAX_INTEL)
    assembled_bytes = bytearray()
    req_errors = []

    ks_arch, ks_mode = get_keystone_mode(
        procname=item.get("procname", "metapc"),
        bitness=item.get("bitness", 32),
        is_be=item.get("is_be", False),
        is_thumb=item.get("is_thumb", False),
    )

    assembles = orig_req.instructions.split(";")
    for assemble_str in assembles:
      assemble_str = assemble_str.strip()
      if not assemble_str:
        continue

      # 1. Resolve IDA symbol names
      assemble_str = replace_symbols(assemble_str, item.get("symbols", {}))

      # 2. Normalize IDA syntax and evaluate bracket math
      assemble_str = fix_ida_syntax(assemble_str, ks_arch, ks_mode)

      # 3. Assemble via Keystone
      try:
        ks = Ks(ks_arch, ks_mode)
        if ks_arch == KS_ARCH_X86:
          ks.syntax = ks_syntax
        encoding, _ = ks.asm(assemble_str, current_ea)
        if encoding is None:
          raise RuntimeError(
              f"Failed to assemble: {assemble_str} (arch={ks_arch},"
              f" mode={ks_mode}, syntax={ks_syntax})"
          )
        assembled_bytes.extend(encoding)
        current_ea += len(encoding)
      except KsError as e:
        req_repr = dataclasses.asdict(orig_req)
        req_errors.append(
            f"Failed to patch {assemble_str} at {current_ea:#x}: Keystone"
            f" error: {e} while assembling '{assemble_str}' (arch={ks_arch},"
            f" mode={ks_mode}, syntax={ks_syntax}) (req={req_repr})"
        )
        break
      except Exception as e:
        req_repr = dataclasses.asdict(orig_req)
        req_errors.append(
            f"Failed to patch {assemble_str} at {current_ea:#x}: {e}"
            f" (req={req_repr})"
        )
        break

    if req_errors:
      errors.extend(req_errors)
    else:
      patch_bytes_reqs.append(
          PatchBytesRequest(
              address=item["address"],
              hex_string=assembled_bytes.hex(),
          )
      )
      orig_address = orig_req.address
      successes.append(f"Successfully patched instructions at {orig_address}")

  if patch_bytes_reqs:
    res = await forward_to(
        database_id, "patch_bytes", {"reqs": patch_bytes_reqs}
    )
    # The backend returns exactly "success" when every patch was applied. Any
    # other text lists what failed and what was patched.
    if res != "success":
      return "\n".join(errors + [res])

  if not errors:
    return "success"
  return "\n".join(errors + successes)
