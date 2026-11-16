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
import asyncio
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

import ida_auto
import idaapi
from ida_mcp.core import analysis_state
from ida_mcp.core import ida_thread
from ida_mcp.core.decorators import cancellation_profile
from ida_mcp.server import mcp_server_thread
from ida_mcp.server import stop_server
from ida_mcp.tools.execution import clear_persistent_globals
from ida_mcp.tools.query import close_tables
from ida_mcp.tools.query import init_tables
from shared import load_options
from shared.config import load_config
# fmt: on


logger = logging.getLogger(__name__)

# How long one slice of auto-analysis runs, in seconds, before the IDA thread
# checks its queue again (e.g., for the request to close the database).
# ida_auto.auto_wait() would run the whole analysis in one call, and it keeps
# the GIL, so the RPC server could not answer until it returned.
_ANALYSIS_SLICE_SECONDS = 0.05


def _on_analysis_done() -> None:
  """Sets up the query tables, then lets tool calls through.

  The table setup gives way to a shutdown: if the IDA thread has been asked to
  stop, before or during the setup, the tools stay locked and the record
  keeps its in-progress name, since the server is about to go away.
  """
  try:
    if load_config().get("populate_tables_on_startup"):
      with cancellation_profile(ida_thread.stop_token, native_ida_cancel=True):
        init_tables()
  except asyncio.CancelledError:
    logger.info("Query table setup interrupted: the server is stopping.")
    return
  except Exception as e:  # pylint: disable=broad-exception-caught
    logger.exception("Error initializing query tables: %s", e)
  analysis_state.finish()
  logger.info("Auto-analysis finished.")


def _analysis_slice() -> bool:
  """Runs auto-analysis for one time slice on the IDA thread.

  Returns:
    False once the analysis has finished, True while there is more to do.
  """
  try:
    deadline = time.monotonic() + _ANALYSIS_SLICE_SECONDS
    while time.monotonic() < deadline:
      if ida_auto.auto_make_step(0, idaapi.BADADDR):
        continue
      if not ida_auto.auto_is_ok():
        # Nothing left to step through, but the queues aren't final yet. This
        # call can't be interrupted, and the RPC server can't answer while it
        # runs, so leave a trace of how long it took.
        started = time.monotonic()
        ida_auto.auto_wait()
        logger.warning(
            "Auto-analysis could not be finished in slices; auto_wait() ran"
            " for %.1fs.",
            time.monotonic() - started,
        )
      return False
    return True
  except Exception as e:  # pylint: disable=broad-exception-caught
    # Don't leave the tools locked for good.
    logger.exception("Auto-analysis failed: %s", e)
    return False


class _AnalysisIdle:
  """The IDA thread's idle work: the analysis slices, then the table setup.

  The table setup is a step of its own, so that the loop checks its queue
  (e.g., for a close request) between the last slice and the setup.
  """

  def __init__(self) -> None:
    self._analysed = False

  def __call__(self) -> bool:
    if not self._analysed:
      self._analysed = not _analysis_slice()
      return True
    _on_analysis_done()
    return False


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
  parser.add_argument(
      "--disable-auto-analysis",
      action="store_true",
      help="Don't run IDA's auto-analysis",
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
    # The analysis runs later, in slices in ida_thread.loop(), so that the
    # server can register and take a close request in the meantime.
    ret = idapro.open_database(
        str(args.input_path), run_auto_analysis=False, **open_kwargs
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

  idle = None
  if ida_auto.auto_is_ok():
    pass
  elif args.disable_auto_analysis:
    analysis_state.disable()
  else:
    # Before the server thread starts, so that it registers as in progress.
    analysis_state.begin()
    idle = _AnalysisIdle()
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
    ida_thread.loop(idle)
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
