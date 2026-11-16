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


"""Process-wide state of the backend's auto-analysis.

The headless server registers with the gateway before IDA's auto-analysis has
finished. This module records how far the analysis is, so that the RPC server
can reject tool calls until it is done. It imports no IDA module.
"""

from collections.abc import Callable
import threading
from typing import Final, Literal

Status = Literal["in_progress", "done", "disabled"]

IN_PROGRESS: Final = "in_progress"
DONE: Final = "done"
DISABLED: Final = "disabled"

# Held while the status changes and while the server registers, so that the
# record's name always matches the status.
lock = threading.RLock()

# "done" unless ida_mcp.headless says otherwise: in the GUI, the plugin starts
# the server only after the analysis.
_status: Status = DONE
# What it returns is ignored.
_on_done: Callable[[], object] | None = None


def status() -> Status:
  """Returns IN_PROGRESS, DONE, or DISABLED."""
  return _status


def is_in_progress() -> bool:
  return _status == IN_PROGRESS


def begin() -> None:
  """Marks the auto-analysis as running."""
  global _status
  with lock:
    _status = IN_PROGRESS


def disable() -> None:
  """Marks the auto-analysis as skipped for this process."""
  global _status
  with lock:
    _status = DISABLED


def set_on_done(callback: Callable[[], object] | None) -> None:
  """Sets the function that finish() calls, or None to clear it."""
  global _on_done
  with lock:
    _on_done = callback


def finish() -> None:
  """Marks a running auto-analysis as done and calls the on-done function."""
  global _status, _on_done
  with lock:
    if _status != IN_PROGRESS:
      return
    _status = DONE
    callback, _on_done = _on_done, None
    if callback is not None:
      callback()


def reset() -> None:
  """Restores the initial state. For tests and plugin teardown."""
  global _status, _on_done
  with lock:
    _status = DONE
    _on_done = None
