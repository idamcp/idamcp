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

"""Unit tests for the execution module."""

import sys
import unittest
from unittest import mock

# Mock IDA modules before importing the module under test
MOCKED_MODULES = [
    "ida_bytes",
    "ida_dbg",
    "ida_idp",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_kernwin",
    "ida_lines",
    "ida_nalt",
    "ida_name",
    "ida_segment",
    "ida_typeinf",
    "ida_xref",
    "idaapi",
    "idautils",
    "idc",
]

module_mocks = {}
for module in MOCKED_MODULES:
  if module in sys.modules:
    module_mocks[module] = sys.modules[module]
  else:
    module_mocks[module] = mock.MagicMock()
sys.modules.update(module_mocks)

# Import the module under test
# Note: This import must happen AFTER the mocking above
# pylint: disable=g-import-not-at-top
from ida_mcp.tools.execution import idapython_eval as _idapython_eval

# pylint: enable=g-import-not-at-top

idapython_eval = getattr(_idapython_eval, "sync_call", _idapython_eval)


class TestPyEval(unittest.TestCase):
  """Tests for the idapython_eval function."""

  def test_simple_expression(self):
    """Test evaluating a simple mathematical expression."""
    result = idapython_eval("1 + 1")
    self.assertEqual(result["result"], "2")
    self.assertEqual(result["stderr"], "")

  def test_variable_assignment_and_persistence(self):
    """Test that variables defined in one call are available in the next."""
    idapython_eval("x_var = 42")
    result = idapython_eval("x_var")
    self.assertEqual(result["result"], "42")

  def test_stdout_capture(self):
    """Test capturing standard output."""
    result = idapython_eval("print('Hello, World!')")
    self.assertEqual(result["stdout"].strip(), "Hello, World!")

  def test_syntax_error(self):
    """Test handling of syntax errors."""
    result = idapython_eval("if True")  # Missing colon
    # The exact error message depends on python version, but it should be in
    # stderr
    self.assertIn("SyntaxError", result["stderr"])
    self.assertEqual(result["result"], "")

  def test_runtime_error(self):
    """Test handling of runtime errors."""
    result = idapython_eval("1 / 0")
    self.assertIn("ZeroDivisionError", result["stderr"])

  def test_function_definition(self):
    """Test defining and calling a function."""
    code = """
def add_func(a, b):
    return a + b
"""
    idapython_eval(code)
    result = idapython_eval("add_func(10, 20)")
    self.assertEqual(result["result"], "30")

  def test_ida_api_call(self):
    """Test interacting with mocked IDA API."""
    # Configure the mock return value
    sys.modules["idc"].get_screen_ea.return_value = 0x1234

    result = idapython_eval("idc.get_screen_ea()")
    self.assertEqual(result["result"], str(0x1234))

  def test_multi_statement_with_expression(self):
    """Test a block with statements ending in an expression."""
    code = """
a = 5
b = 6
a * b
"""
    result = idapython_eval(code)
    self.assertEqual(result["result"], "30")

  def test_complex_logic_persistence(self):
    """Test complex logic spanning multiple calls."""
    idapython_eval("my_list = []")
    idapython_eval("for i in range(3): my_list.append(i)")
    result = idapython_eval("my_list")
    self.assertEqual(result["result"], "[0, 1, 2]")

  def eval_json(self, code):
    """Runs idapython_eval with the eval_result_json option on."""
    with mock.patch(
        "shared.config.load_config", return_value={"eval_result_json": True}
    ):
      return idapython_eval(code)

  def test_result_type(self):
    """result_type is the last expression's type name, or "" if none."""
    self.assertEqual(idapython_eval("1 + 1")["result_type"], "int")
    self.assertEqual(idapython_eval("[1, 2]")["result_type"], "list")
    self.assertEqual(idapython_eval("None")["result_type"], "NoneType")
    self.assertEqual(idapython_eval("rt_x = 1")["result_type"], "")
    self.assertEqual(idapython_eval("1 / 0")["result_type"], "")
    self.assertEqual(idapython_eval("if True")["result_type"], "")

  def test_result_json_off_by_default(self):
    """With eval_result_json unset the output only gains result_type."""
    result = idapython_eval("{'a': 1}")
    self.assertEqual(set(result), {"result", "stdout", "stderr", "result_type"})
    self.assertEqual(result["result"], "{'a': 1}")

  def test_result_json_native_value(self):
    """eval_result_json adds the value as JSON; result stays a string."""
    result = self.eval_json(
        "{'name': 'main', 'ea': 4096, 'args': (1, 2), 3: None}"
    )
    self.assertIsInstance(result["result"], str)
    self.assertEqual(
        result["result_json"],
        {"name": "main", "ea": 4096, "args": [1, 2], "3": None},
    )
    self.assertNotIn("result_json_error", result)

  def test_result_json_none_value(self):
    result = self.eval_json("None")
    self.assertIn("result_json", result)
    self.assertIsNone(result["result_json"])

  def test_result_json_not_serializable(self):
    """Non-JSON values give result_json_error instead of result_json."""
    result = self.eval_json("object()")
    self.assertNotIn("result_json", result)
    self.assertIn("TypeError", result["result_json_error"])
    self.assertEqual(result["result_type"], "object")

  def test_result_json_nan_rejected(self):
    result = self.eval_json("float('nan')")
    self.assertNotIn("result_json", result)
    self.assertIn("ValueError", result["result_json_error"])

  def test_result_json_without_expression(self):
    """No last expression -> neither result_json nor result_json_error."""
    result = self.eval_json("rj_x = 5")
    self.assertNotIn("result_json", result)
    self.assertNotIn("result_json_error", result)

  def test_return_json_param_enables(self):
    """return_json=True works with the config option off."""
    with mock.patch(
        "shared.config.load_config", return_value={"eval_result_json": False}
    ) as cfg:
      result = idapython_eval("[1, 2]", return_json=True)
    self.assertEqual(result["result_json"], [1, 2])
    cfg.assert_not_called()

  def test_return_json_param_disables(self):
    """return_json=False overrides the config option being on."""
    with mock.patch(
        "shared.config.load_config", return_value={"eval_result_json": True}
    ) as cfg:
      result = idapython_eval("[1, 2]", return_json=False)
    self.assertNotIn("result_json", result)
    self.assertNotIn("result_json_error", result)
    cfg.assert_not_called()

  def test_return_json_omitted_uses_config(self):
    """return_json=None (omitted) falls back to eval_result_json."""
    result = self.eval_json("[1, 2]")
    self.assertEqual(result["result_json"], [1, 2])
    result = idapython_eval("[1, 2]", return_json=None)
    self.assertNotIn("result_json", result)


if __name__ == "__main__":
  unittest.main()
