#!/usr/bin/env python3
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

"""IDA MCP Plugin Installer / Loader Generator."""

import argparse
import contextlib
import datetime
import json
import os
import pathlib
import shutil
import sys
from typing import Literal
import unittest

# Try to import generators, but handle failure gracefully if dependencies
# missing.
try:
  from generators import generate_proxy  # pylint: disable=g-import-not-at-top
except ImportError:
  generate_proxy = None

# Try to import tomllib (Python 3.11+ standard library or tomli) and tomli_w
# for Codex support.
try:
  import tomllib  # pylint: disable=g-import-not-at-top
except ImportError:
  try:
    import tomli as tomllib  # pylint: disable=g-import-not-at-top
  except ImportError:
    tomllib = None

try:
  import tomli_w  # pylint: disable=g-import-not-at-top
except ImportError:
  tomli_w = None


def is_running_in_ida() -> bool:
  try:
    __import__("idaapi")
    return True
  except ImportError:
    return False


def get_default_target_dir() -> pathlib.Path:
  """Returns the default user plugins directory based on platform."""
  if is_running_in_ida():
    import idaapi  # pylint: disable=g-import-not-at-top

    # get_user_idadir returns the user directory
    # (e.g. %APPDATA%/Hex-Rays/IDA Pro)
    # We assume 'plugins' subdirectory.
    return pathlib.Path(idaapi.get_user_idadir()) / "plugins"

  # CLI Heuristics
  if sys.platform == "win32":
    # Standard location for IDA 7/8/9
    appdata = os.environ.get("APPDATA")
    if appdata:
      return pathlib.Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins"
    return pathlib.Path(
        os.path.expandvars(r"%APPDATA%\Hex-Rays\IDA Pro\plugins")
    )
  else:  # darwin or linux
    return pathlib.Path("~/.idapro/plugins").expanduser()


def ask_user_for_dir(default_path: pathlib.Path) -> pathlib.Path | None:
  """Prompts the user for the directory."""
  prompt_msg = (
      f"IDA plugins directory not found at default: {default_path}\n"
      "Please enter the full path to your IDA 'plugins' directory:"
  )

  if is_running_in_ida():
    import ida_kernwin  # pylint: disable=g-import-not-at-top

    # ask_str(defval, hist, prompt)
    res = ida_kernwin.ask_str(str(default_path), 0, prompt_msg)
    return pathlib.Path(res) if res else None
  else:
    # Python 3
    try:
      res = input(f"{prompt_msg}\n> ").strip()
      return pathlib.Path(res) if res else None
    except EOFError:
      return None


def build() -> None:
  """Runs the build process (generates proxy)."""
  repo_dir = pathlib.Path(__file__).resolve().parent
  print("[*] Building proxy...")
  if generate_proxy is None:
    print("[!] Error: Could not import 'generators.generate_proxy'.")
    print("    Please ensure you have installed the requirements:")
    print("    pip install -r requirements.txt")
    raise ImportError("Could not import generators.generate_proxy")

  with contextlib.chdir(repo_dir):
    print("cwd", pathlib.Path.cwd())
    generate_proxy.main()
    print("[+] Build complete: gateway/proxy.py generated.")


def run_tests() -> None:
  """Runs all unit tests."""
  print("[*] Running tests...")
  loader = unittest.TestLoader()
  repo_dir = pathlib.Path(__file__).resolve().parent
  start_dir = repo_dir / "tests"
  suite = loader.discover(str(start_dir))

  runner = unittest.TextTestRunner()
  result = runner.run(suite)

  if not result.wasSuccessful():
    sys.exit(1)
  print("[+] All tests passed.")


def install(target_dir_arg: str | None = None) -> None:
  """Main installation routine."""
  # 1. Determine Repo Path (Absolute path to this script's directory)
  repo_dir = pathlib.Path(__file__).resolve().parent

  # 2. Determine Target Directory
  if target_dir_arg:
    target_dir = pathlib.Path(target_dir_arg).resolve()
  else:
    target_dir = get_default_target_dir()

  # 3. Check existence and Prompt if missing
  if not target_dir.exists():
    print(f"[!] Default directory does not exist: {target_dir}")
    if not sys.stdin.isatty() and not is_running_in_ida():
      print(
          "[x] Error: Non-interactive environment and target directory does not"
          " exist."
      )
      return

    user_path = ask_user_for_dir(target_dir)

    if not user_path:
      print("[-] Operation cancelled.")
      return

    target_dir = user_path.resolve()

    if not target_dir.exists():
      print(
          f"[x] Error: The directory '{target_dir}' does not exist. Please"
          " create it or install IDA first."
      )
      return

  # 4. Create the Shim Content
  # We use a raw string for the path to handle Windows backslashes correctly
  shim_code = f"""# IDA MCP Loader Shim
# Generated by install.py
import os
import sys

# 1. Add the repository to sys.path so Python can find 'ida_mcp', 'gateway', and 'ida_plugin'
REPO_PATH = r"{repo_dir}"

if REPO_PATH not in sys.path:
  # Insert at the beginning to take precedence
  sys.path.insert(0, REPO_PATH)

print(f"[IDA MCP] Loading from: {{REPO_PATH}}")

try:
  # 2. Import the actual plugin entry point from the repository
  # The file is now at plugins/ida_mcp_plugin.py
  from plugins import ida_mcp_plugin

  # 3. Expose the PLUGIN_ENTRY for IDA
  def PLUGIN_ENTRY():
    return ida_mcp_plugin.PLUGIN_ENTRY()

except ImportError as e:
  import traceback

  print(
      "[IDA MCP] CRITICAL ERROR: Could not import plugin. Ensure the"
      " repository path is valid."
  )
  traceback.print_exc()

  def PLUGIN_ENTRY():
    # Return a dummy plugin so IDA doesn't complain too much, or just return None
    return None
"""

  # 5. Write the Shim
  shim_path = target_dir / "ida_mcp_loader.py"

  try:
    with open(shim_path, "w") as f:
      f.write(shim_code)
    print(f"[+] Success! Loader installed to: {shim_path}")
    print(
        f"[+] You can now edit files in '{repo_dir}' and simply restart IDA to"
        " see changes."
    )
  except PermissionError:
    print(
        f"[x] Permission denied writing to {shim_path}. Try running as"
        " Administrator."
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    print(f"[x] An error occurred: {e}")


def install_server(
    name: Literal["gemini", "agy", "jetski", "claude", "codex"] = "gemini",
) -> None:
  """Installs the IDA MCP server configuration for Gemini CLI."""

  # 1. Get VIRTUAL_ENV
  venv = os.environ.get("VIRTUAL_ENV")
  if not venv:
    print("[?] VIRTUAL_ENV not found in environment.")
    if sys.stdin.isatty():
      try:
        venv = input(
            "    Please enter the path to your python virtual"
            " environment(Optional): "
        ).strip()
      except EOFError:
        pass
    else:
      print("[i] Non-interactive environment, proceeding without VIRTUAL_ENV.")

  # 2. Get PYTHONPATH (Project Root)
  repo_dir = pathlib.Path(__file__).resolve().parent
  env_vars = {"PYTHONPATH": str(repo_dir)}
  if venv:
    env_vars["VIRTUAL_ENV"] = venv

  # 3. Modify settings file
  home = pathlib.Path.home()
  match name:
    case "gemini":
      settings_path = home / ".gemini" / "settings.json"
    case "agy" | "jetski":
      settings_path = home / ".gemini" / "config" / "mcp_config.json"
    case "claude":
      settings_path = home / ".claude.json"
    case "codex":
      settings_path = home / ".codex" / "config.toml"

  if name == "codex":
    if tomllib is None:
      print(
          "[x] Error: 'tomllib' (Python 3.11+) or 'tomli' library is required"
          " to configure Codex."
      )
      print("    Please install it with: pip install tomli")
      return

    if tomli_w is None:
      print(
          "[x] Error: 'tomli-w' library is required to write Codex"
          " configuration."
      )
      print("    Please install it with: pip install tomli-w")
      return

    settings = {}
    if settings_path.exists():
      try:
        with open(settings_path, "rb") as f:
          settings = tomllib.load(f)
      except Exception as e:  # pylint: disable=broad-exception-caught
        print(
            "[x] Error: Failed to parse existing configuration at"
            f" {settings_path}: {e}"
        )
        return

      if not isinstance(settings, dict):
        print(
            f"[x] Error: Configuration root in {settings_path} must be a table"
            f" (dict), got {type(settings).__name__}."
        )
        return

      # Make a backup with timestamp for the original configuration
      timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
      backup_path = (
          settings_path.parent / f"{settings_path.name}.{timestamp}.bak"
      )
      try:
        shutil.copy2(settings_path, backup_path)
        print(f"[+] Backed up original configuration to: {backup_path}")
      except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"[x] Error: Failed to create backup at {backup_path}: {e}")
        return
    else:
      settings_path.parent.mkdir(parents=True, exist_ok=True)

    if "mcp_servers" not in settings:
      settings["mcp_servers"] = {}

    settings["mcp_servers"]["idamcp"] = {
        "command": sys.executable,
        "args": ["-m", "gateway.proxy", "--transport", "stdio"],
        "env": env_vars,
    }

    try:
      with open(settings_path, "wb") as f:
        tomli_w.dump(settings, f)
      print(
          "[+] Codex MCP server 'idamcp' configured successfully in"
          f" {settings_path}."
      )
    except Exception as e:  # pylint: disable=broad-exception-caught
      print(f"[!] Failed to save settings to {settings_path}: {e}")
    return

  # JSON path (gemini, agy, jetski, claude)
  settings = {}
  if settings_path.exists():
    try:
      with open(settings_path, "r") as f:
        settings = json.load(f)
    except Exception as e:  # pylint: disable=broad-exception-caught
      print(
          "[x] Error: Failed to parse existing configuration at"
          f" {settings_path}: {e}"
      )
      return

    if not isinstance(settings, dict):
      print(
          f"[x] Error: Configuration root in {settings_path} must be a JSON"
          f" object (dict), got {type(settings).__name__}."
      )
      return

    # Make a backup with timestamp for the original configuration
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = settings_path.parent / f"{settings_path.name}.{timestamp}.bak"
    try:
      shutil.copy2(settings_path, backup_path)
      print(f"[+] Backed up original configuration to: {backup_path}")
    except Exception as e:  # pylint: disable=broad-exception-caught
      print(f"[x] Error: Failed to create backup at {backup_path}: {e}")
      return
  else:
    settings_path.parent.mkdir(parents=True, exist_ok=True)

  if "mcpServers" not in settings:
    settings["mcpServers"] = {}

  settings["mcpServers"]["idamcp"] = {
      "command": sys.executable,
      "args": ["-m", "gateway.proxy", "--transport", "stdio"],
      "env": env_vars,
      "description": (
          "IDA Pro MCP Server for reverse engineering and binary analysis"
      ),
  }

  try:
    with open(settings_path, "w") as f:
      json.dump(settings, f, indent=2)
    print(
        f"[+] {name.capitalize()} MCP server 'idamcp' configured successfully"
        f" in {settings_path}."
    )
  except Exception as e:  # pylint: disable=broad-exception-caught
    print(f"[!] Failed to save settings to {settings_path}: {e}")


if __name__ == "__main__":
  if is_running_in_ida():
    install()
  elif sys.argv[1:2] == ["logs"]:
    # Forwards the remaining arguments (see `install.py logs --help`).
    from gateway import logs  # pylint: disable=g-import-not-at-top

    sys.exit(logs.main(sys.argv[2:]))
  else:
    parser = argparse.ArgumentParser(
        description="IDA MCP Installer & Build Tool"
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="plugin",
        choices=[
            "plugin",
            "build",
            "test",
            "logs",
            "gemini",
            "agy",
            "jetski",
            "claude",
            "codex",
        ],
        help="Command to run (default: install)",
    )
    parser.add_argument(
        "--ida-plugins-dir",
        help="Path to IDA plugins directory (overrides default)",
    )
    args = parser.parse_args()

    match args.command:
      case "build":
        build()
      case "test":
        run_tests()
      case "logs":
        from gateway import logs  # pylint: disable=g-import-not-at-top

        sys.exit(logs.main([]))
      case "gemini" | "agy" | "jetski" | "claude" | "codex":
        install_server(args.command)
      case "plugin":
        install(args.ida_plugins_dir)
