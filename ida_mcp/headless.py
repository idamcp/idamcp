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

"""Headless IDA Pro MCP Server."""

import argparse
import contextlib
import hashlib
import inspect
import logging
import pathlib
import signal
import sys
import threading

# fmt: off
# idapro must go first to initialize idalib
try:
  import idapro  # pylint: disable=g-bad-import-order
except ImportError:
  sys.exit("[Error] Can't import idapro, please install idalib first.")

import idaapi
from ida_mcp.core import ida_thread
from ida_mcp.server import mcp_server_thread
from ida_mcp.server import stop_server
from ida_mcp.tools.execution import clear_persistent_globals
from ida_mcp.tools.query import close_tables
from shared import load_options
# fmt: on


logger = logging.getLogger(__name__)


def _server_thread(hash_str: str) -> None:
  logger.info("Starting MCP server...")
  ida_thread.wait_for_loop_event()
  try:
    mcp_server_thread(hash_str)
  finally:
    logger.info("Server stopped, closing database...")
    ida_thread.stop()


def main():
  parser = argparse.ArgumentParser(description="Headless IDA Pro MCP Server")
  parser.add_argument(
      "input_path", type=pathlib.Path, help="Path to the binary file to analyze"
  )
  parser.add_argument("--processor", help="IDA processor module (-p)")
  parser.add_argument("--loader", help="IDA file type name or prefix (-T)")
  parser.add_argument(
      "--base-address", help="Load address, 16-byte aligned (-b)"
  )
  args = parser.parse_args()

  # Configure logging
  logging.basicConfig(level=logging.INFO)

  if not args.input_path.exists():
    logger.error("Input file not found: %s", args.input_path)
    sys.exit(1)

  try:
    options = load_options.parse_load_options(
        args.processor, args.loader, args.base_address
    )
    load_options.check_applicable(str(args.input_path), options)
  except load_options.LoadOptionsError as e:
    logger.error("%s", e)
    sys.exit(1)

  open_kwargs = {}
  if not options.is_empty():
    # idapro.open_database() only accepts `args` from IDA 9.1 on.
    try:
      has_args = "args" in inspect.signature(idapro.open_database).parameters
    except (TypeError, ValueError):
      has_args = False
    if not has_args:
      logger.error(
          "Load options (processor/loader/base_address) need IDA 9.1 or"
          " newer: this idalib's open_database() has no 'args' parameter."
      )
      sys.exit(1)
    open_kwargs["args"] = options.to_ida_args()

  logger.info(
      "Initializing idalib and opening %s %s...",
      args.input_path,
      open_kwargs.get("args", ""),
  )

  try:
    ret = idapro.open_database(
        str(args.input_path), run_auto_analysis=True, **open_kwargs
    )
    if ret != 0:
      logger.error(
          "Failed to open database, error code: %#x%s",
          ret,
          f" (load options: {open_kwargs['args']})" if open_kwargs else "",
      )
      sys.exit(1)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.exception("Failed to open database, exception: %s", e)
    sys.exit(1)

  idb_path = None
  with contextlib.suppress(Exception):
    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)

  if not idb_path:
    # Fallback
    idb_path = str(args.input_path)
  idaapi.idb_path = idb_path  # type: ignore
  idaapi.is_headless = True  # type: ignore
  hash_str = hashlib.sha256(idb_path.encode()).hexdigest()[-8:]

  logger.info("Session identifier: %s", hash_str)
  original_handlers = {}

  # Setup signal handlers for clean exit
  def signal_handler(sig, frame):
    logger.info("Received signal: %d, Shutting down...", sig)
    ida_thread.stop()
    handler = original_handlers.get(sig, None)
    if handler and callable(handler):
      handler(sig, frame)

  for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
    if (sig := getattr(signal, sig_name, None)) != None:
      try:
        original_handlers[sig] = signal.signal(sig, signal_handler)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Could not register handler for signal %s: %s", sig, e)

  server_thread = threading.Thread(
      target=_server_thread,
      args=(hash_str,),
      daemon=True,
  )
  server_thread.start()
  try:
    ida_thread.loop()
  finally:
    stop_server(hash_str)
    if server_thread.is_alive():
      server_thread.join(timeout=5.0)
    # This is the IDA thread; clear the shared idapython_eval namespace (which
    # may hold SWIG-wrapped IDA objects) while the database is still open.
    try:
      clear_persistent_globals()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.exception("Error clearing idapython_eval globals: %s", e)
    try:
      close_tables()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.exception("Error closing query tables: %s", e)
    try:
      idapro.close_database()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.exception("Error closing database: %s", e)
    # Hand the signals back to the handlers that were installed before main()
    # replaced them; close_tables() has already restored ours.
    for sig, handler in original_handlers.items():
      if handler is None:
        continue
      try:
        signal.signal(sig, handler)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("Could not restore handler for signal %s: %s", sig, e)


if __name__ == "__main__":
  main()
