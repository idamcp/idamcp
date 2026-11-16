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


"""Process helpers shared by the gateway, the dashboard, and the tests.

This module only uses the standard library.
"""

import contextlib
import os
import sys


def is_process_running(pid: int) -> bool:
  """Returns whether the process with `pid` is still alive."""
  if sys.platform == "win32":
    with contextlib.suppress(Exception):
      import ctypes  # pylint: disable=g-import-not-at-top

      kernel32 = ctypes.windll.kernel32
      # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
      kernel32.OpenProcess.restype = ctypes.c_void_p
      handle = kernel32.OpenProcess(0x1000, False, pid)
      if handle:
        kernel32.CloseHandle(handle)
        return True
    return False
  try:
    os.kill(pid, 0)
    return True
  except OSError:
    return False
