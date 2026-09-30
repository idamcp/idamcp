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

"""Unit tests for the non-loopback bind warning."""

import contextlib
import io
import unittest

from gateway.forward import is_loopback_host
from gateway.forward import warn_if_not_loopback


class TestLoopback(unittest.TestCase):
  """Tests for is_loopback_host and warn_if_not_loopback."""

  def test_loopback_hosts(self):
    for host in (
        "localhost",
        "LocalHost",
        "127.0.0.1",
        "127.1.2.3",
        "::1",
        "[::1]",
        " localhost ",
    ):
      with self.subTest(host=host):
        self.assertTrue(is_loopback_host(host))

  def test_non_loopback_hosts(self):
    for host in (
        "0.0.0.0",
        "::",
        "[::]",
        "192.168.1.1",
        "10.0.0.1",
        "example.com",
        "",
    ):
      with self.subTest(host=host):
        self.assertFalse(is_loopback_host(host))

  def test_no_warning_on_loopback(self):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
      self.assertFalse(warn_if_not_loopback("localhost", 8000))
    self.assertEqual(buf.getvalue(), "")

  def test_warning_on_wildcard(self):
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
      self.assertTrue(warn_if_not_loopback("0.0.0.0", 8000))
    out = buf.getvalue()
    self.assertIn("[WARNING]", out)
    self.assertIn("0.0.0.0:8000", out)
    self.assertIn("no authentication", out)


if __name__ == "__main__":
  unittest.main()
