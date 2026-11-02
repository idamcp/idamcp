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

"""Configuration loader for IDA MCP."""

import functools
import json
import logging
import os
import pathlib
import re
import sys
import tempfile
from typing import Any

_DEFAULT_UDS_DIR = pathlib.Path(tempfile.gettempdir()) / "ida_mcp_uds"
_DEFAULT_REGISTRY_DIR = pathlib.Path.home() / ".ida_mcp_registry"
_DEFAULT_CHANNEL = "tcp" if sys.platform == "win32" else "uds"
_DEFAULT_ALWAYS_VISIBLE_TOOLS = [
    "list_available_databases",
    "idalib_headless_open",
    "idalib_headless_close",
    "sql_query",
    "decompile_function",
    "disassemble_function",
    "disassemble_code",
    "get_ida_view",
    "hexdump",
    "idapython_eval",
]
_DEFAULT_CONFIG = {
    "communication_channel": _DEFAULT_CHANNEL,
    "registry_dir": _DEFAULT_REGISTRY_DIR,
    "uds_dir": _DEFAULT_UDS_DIR,
    "max_headless_instances": 4,
    "headless_open_timeout": 600.0,
    "python_path": sys.executable,
    "enable_all_unsafe_tools": False,
    "enabled_unsafe_tools": [],
    "opcode_bytes": 8,
    "populate_tables_on_startup": False,
    "sqlite_persistent": False,
    "check_entries_freshness": False,
    "rebuild_strings_on_data_patch": False,
    "disabled_tools": [],
    "flush_after_write": False,
    "gui_undo_points": False,
    "autostart": False,
    "hotkey": "Ctrl-Alt-M",
    "tool_mode": "hybrid",  # "full" | "hybrid" | "code_mode"
    "always_visible_tools": _DEFAULT_ALWAYS_VISIBLE_TOOLS,
    "show_decompiler_warnings": False,
    # Hex-Rays warnings that decompile_function leaves out. "Using guessed
    # type" notes come with most calls, and "possibly undefined" ones mostly
    # flag call arguments that the pseudocode already shows as never set.
    "omitted_decompiler_warnings": ["WARN_GUESSED_TYPE", "WARN_UNDEF_LVAR"],
    # Size limits, as bytes or a string with a unit (see _parse_size); 0 means
    # no limit. The gateway replaces a larger tool response with an error, and
    # the backend stops idapython_eval code whose stdout, stderr, or result
    # grows past the limit.
    "max_tool_response_bytes": "8m",
    "max_eval_output_bytes": "1m",
}
_SIZE_OPTIONS = ("max_tool_response_bytes", "max_eval_output_bytes")
# Binary multiples, as in most size settings ("8m" is 8 MiB).
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "k": 1 << 10,
    "kb": 1 << 10,
    "kib": 1 << 10,
    "m": 1 << 20,
    "mb": 1 << 20,
    "mib": 1 << 20,
    "g": 1 << 30,
    "gb": 1 << 30,
    "gib": 1 << 30,
}
_SIZE_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([a-z]*)")


def _parse_size(value: Any) -> int | None:
  """Returns a size setting in bytes, or None if `value` is not a size.

  Args:
    value: A non-negative integer number of bytes, or a string of a number and
      an optional unit, case-insensitive: b, k, kb, kib, m, mb, mib, g, gb, or
      gib, e.g. "8m", "512 KiB", or "1.5mb". Units are binary multiples.
  """
  if isinstance(value, bool):
    return None
  if isinstance(value, int):
    return value if value >= 0 else None
  if isinstance(value, str):
    match = _SIZE_RE.fullmatch(value.strip().lower())
    if match and match.group(2) in _SIZE_UNITS:
      return int(float(match.group(1)) * _SIZE_UNITS[match.group(2)])
  return None


def _set_option_from_env(
    config: dict, option_name: str, env_name: str | None = None
) -> None:
  """Set config option from environment variable.

  Args:
    config: the configuration dictionary.
    option_name: the name of the option.
    env_name: the name of the environment variable. Use option_name.upper() when
      omitted.

  Returns:
    None
  """
  if env_name is None:
    env_name = option_name.upper()

  if (env_val := os.environ.get(env_name)) is None:
    return
  env_val = env_val.strip()
  default_option = _DEFAULT_CONFIG.get(option_name)
  if isinstance(default_option, bool):
    config[option_name] = env_val.lower() in (
        "true",
        "1",
        "yes",
    )
  elif isinstance(default_option, float):
    config[option_name] = float(env_val.lower())
  elif isinstance(default_option, int):
    config[option_name] = int(env_val.lower())
  elif isinstance(default_option, list):
    items = list(filter(len, map(str.strip, env_val.split(","))))
    if default_option:
      config[option_name] = list(dict.fromkeys(items))
    else:
      config[option_name].extend(items)
      config[option_name] = list(set(config[option_name]))
  elif isinstance(default_option, str):
    config[option_name] = env_val
  elif isinstance(default_option, pathlib.Path):
    env_val = os.path.expandvars(env_val)
    config[option_name] = pathlib.Path(env_val).expanduser()


@functools.lru_cache(maxsize=1)
def load_config(config_path: str | None = None) -> dict[str, Any]:
  """Loads the configuration from a JSON file.

  Args:
    config_path: Path to the configuration file. If None, uses ~/.idamcp.json.

  Returns:
    A dictionary containing the configuration.
  """

  if config_path is None:
    if os.environ.get("IDAMCP_NO_USER_CONFIG", "").lower() in (
        "1",
        "true",
        "yes",
    ):
      path = None
    elif env_config := os.environ.get("IDAMCP_CONFIG"):
      path = pathlib.Path(env_config).expanduser()
    else:
      path = pathlib.Path("~/.idamcp.json").expanduser()
      if not path.is_file():
        for legacy_name in (
            "~/.idamcp.toml",
            "~/.idamcp.yml",
            "~/.idamcp.yaml",
        ):
          legacy_path = pathlib.Path(legacy_name).expanduser()
          if legacy_path.is_file():
            path = legacy_path
            break
  else:
    path = pathlib.Path(config_path).expanduser()

  config = {
      k: list(v) if isinstance(v, list) else v
      for k, v in _DEFAULT_CONFIG.items()
  }

  if path is not None and path.is_file():
    try:
      with open(path, "r") as f:
        config_str = f.read()
        if path.suffix in (".yml", ".yaml"):
          try:
            import yaml  # pylint: disable=g-import-not-at-top

            user_config = yaml.safe_load(config_str)
          except ImportError:
            logging.warning("PyYAML not installed, cannot read %s", path)
            user_config = None
        elif path.suffix == ".toml":
          try:
            import tomllib  # pylint: disable=g-import-not-at-top

            user_config = tomllib.loads(config_str)
          except ImportError:
            logging.warning("tomllib not available, cannot read %s", path)
            user_config = None
        else:
          user_config = json.loads(config_str)
        if user_config:
          config.update(user_config)
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.exception(
          "Failed to load config from %s: %s. Using default.", path, e
      )

  _set_option_from_env(config, "populate_tables_on_startup")
  _set_option_from_env(config, "headless_open_timeout")
  _set_option_from_env(config, "enabled_unsafe_tools")
  _set_option_from_env(config, "enable_all_unsafe_tools")
  _set_option_from_env(config, "disabled_tools")
  _set_option_from_env(config, "sqlite_persistent")
  _set_option_from_env(config, "check_entries_freshness")
  _set_option_from_env(config, "rebuild_strings_on_data_patch")
  _set_option_from_env(config, "flush_after_write")
  _set_option_from_env(config, "gui_undo_points")
  _set_option_from_env(config, "autostart")
  _set_option_from_env(config, "hotkey")
  _set_option_from_env(config, "tool_mode")
  _set_option_from_env(config, "always_visible_tools")
  _set_option_from_env(config, "show_decompiler_warnings")
  _set_option_from_env(config, "omitted_decompiler_warnings")

  # Size options take a string with a unit, so they are read from the
  # environment as is and parsed together with the config file's value. They
  # end up as a number of bytes; 0 means no limit.
  for option in _SIZE_OPTIONS:
    if (env_val := os.environ.get(option.upper())) is not None:
      config[option] = env_val
    size = _parse_size(config[option])
    if size is None:
      logging.warning(
          "Invalid %s %r: expected a size such as 8388608, \"8m\", or"
          ' "512kb". Using %r.',
          option,
          config[option],
          _DEFAULT_CONFIG[option],
      )
      size = _parse_size(_DEFAULT_CONFIG[option])
    config[option] = size

  # Expand registry_dir path
  config["registry_dir"] = pathlib.Path(config["registry_dir"]).expanduser()
  config["uds_dir"] = pathlib.Path(config["uds_dir"]).expanduser()
  config["communication_channel"] = config["communication_channel"].lower()

  # Force TCP on Windows
  if sys.platform == "win32" and config["communication_channel"] != "tcp":
    logging.warning("UDS is not supported on Windows. Falling back to TCP.")
    config["communication_channel"] = "tcp"

  # Create directories
  for dir in map(config.get, ("uds_dir", "registry_dir")):
    try:
      assert dir is not None
      dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
      logging.exception("Failed to create directory %s: %s", dir, e)

  return config
