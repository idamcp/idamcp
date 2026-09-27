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
import time

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
from shared import load_options
from shared.config import load_config
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


# Target length of one run of deferred auto-analysis between tool calls. The
# deadline is checked between auto_make_step calls, so a single long step can
# overrun it (up to ~1.2 s seen on a 11 MB binary with IDA 9.4).
_ANALYSIS_SLICE_S = 0.05


def _deferred_analysis_supported() -> bool:
  """Whether this idalib can run auto-analysis step by step."""
  # pylint: disable-next=g-import-not-at-top
  import ida_auto

  return all(
      callable(getattr(ida_auto, name, None))
      for name in ("auto_make_step", "is_auto_enabled")
  )


def _analysis_step() -> bool:
  """Runs auto-analysis for up to one slice. Returns True while work remains."""
  # pylint: disable-next=g-import-not-at-top
  import ida_auto

  # A tool may have disabled auto-analysis (ida_auto.enable_auto(False));
  # respect that instead of forcing it back on.
  if not ida_auto.is_auto_enabled():
    logger.info("Auto-analysis was disabled, stopping deferred analysis.")
    return False
  deadline = time.monotonic() + _ANALYSIS_SLICE_S
  while time.monotonic() < deadline:
    if not ida_auto.auto_make_step(0, idaapi.BADADDR):
      logger.info("Deferred auto-analysis finished.")
      return False
  return True


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

  deferred = bool(load_config().get("headless_deferred_analysis"))
  if deferred and not _deferred_analysis_supported():
    logger.warning(
        "headless_deferred_analysis is set, but this idalib lacks"
        " ida_auto.auto_make_step/is_auto_enabled. Analyzing before serving."
    )
    deferred = False

  logger.info(
      "Initializing idalib and opening %s %s...",
      args.input_path,
      open_kwargs.get("args", ""),
  )

  try:
    ret = idapro.open_database(
        str(args.input_path), run_auto_analysis=not deferred, **open_kwargs
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

  if deferred:
    # Serve right away and analyze on the IDA thread between tool calls.
    logger.info("Auto-analysis deferred; it runs while no tool call is queued.")
    ida_thread.set_idle_work(_analysis_step)

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
    try:
      idapro.close_database()
    except Exception as e:  # pylint: disable=broad-exception-caught
      logger.exception("Error closing database: %s", e)


if __name__ == "__main__":
  main()
