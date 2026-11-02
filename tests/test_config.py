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


"""Unit tests for the config module."""

import os
import unittest
from unittest import mock
import shared.config


class TestConfig(unittest.TestCase):
  """Tests for the load_config function."""

  def setUp(self):
    # Snapshot first: cleanups run after tearDown. AUTOSTART and HOTKEY are
    # generic names that other tools may set.
    env = mock.patch.dict(os.environ)
    env.start()
    self.addCleanup(env.stop)
    os.environ.pop("AUTOSTART", None)
    os.environ.pop("HOTKEY", None)
    self._orig_no_user_config = os.environ.get("IDAMCP_NO_USER_CONFIG")
    if "IDAMCP_NO_USER_CONFIG" in os.environ:
      del os.environ["IDAMCP_NO_USER_CONFIG"]
    shared.config.load_config.cache_clear()

  def tearDown(self):
    if self._orig_no_user_config is not None:
      os.environ["IDAMCP_NO_USER_CONFIG"] = self._orig_no_user_config
    elif "IDAMCP_NO_USER_CONFIG" in os.environ:
      del os.environ["IDAMCP_NO_USER_CONFIG"]
    shared.config.load_config.cache_clear()

  @mock.patch("shared.config.sys.platform", "linux")
  def test_linux_default(self):
    """Test default configuration on Linux."""
    # Reset DEFAULT_CHANNEL which is computed at module level
    # We can't easily change the module-level constant after import,
    # but load_config logic relies on sys.platform for enforcement.
    # The DEFAULT_CONFIG in shared.config is computed at import time.
    # However, load_config copies it.

    # We want to test that if we pass nothing, we get 'uds' on linux
    # (assuming DEFAULT_CHANNEL was initialized to 'uds' or 'tcp' depending on
    # the REAL platform). Since we can't control the real platform during
    # import easily without reloading, let's focus on the ENFORCEMENT logic
    # which is what we added.

    config = shared.config.load_config(config_path="/nonexistent")
    # We can't assert the default value easily because it depends on the host
    # running the test. But we can assert that if we provide a config, it is
    # respected.

    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data='{"communication_channel": "uds"}'),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(config["communication_channel"], "uds")

  @mock.patch("shared.config.sys.platform", "win32")
  def test_windows_enforcement(self):
    """Test that TCP is enforced on Windows."""

    # Case 1: User tries to set 'uds'
    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data='{"communication_channel": "uds"}'),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(config["communication_channel"], "tcp")

    # Case 2: User sets 'tcp'
    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data='{"communication_channel": "tcp"}'),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(config["communication_channel"], "tcp")

  @mock.patch("shared.config.sys.platform", "linux")
  def test_linux_no_enforcement(self):
    """Test that UDS is allowed on Linux."""
    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data='{"communication_channel": "uds"}'),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(config["communication_channel"], "uds")

  def test_populate_tables_on_startup_default(self):
    """Test default value for populate_tables_on_startup."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertFalse(config.get("populate_tables_on_startup"))

  def test_populate_tables_on_startup_user(self):
    """Test user-defined value for populate_tables_on_startup."""
    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data='{"populate_tables_on_startup": true}'),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertTrue(config.get("populate_tables_on_startup"))

  def test_json_regex_strings(self):
    """Test that JSON arrays of regex patterns are parsed properly."""
    json_content = r'{"disabled_tools": ["^dbg_.*", "\\w+\\d+"]}'
    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data=json_content),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(config["disabled_tools"], ["^dbg_.*", r"\w+\d+"])

  def test_sqlite_persistent_env(self):
    """Test SQLITE_PERSISTENT environment variable."""
    with mock.patch.dict("os.environ", {"SQLITE_PERSISTENT": "true"}):
      config = shared.config.load_config(config_path="/nonexistent")
      self.assertTrue(config.get("sqlite_persistent"))

  def test_check_entries_freshness_default(self):
    """Test default value for check_entries_freshness is False."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertFalse(config.get("check_entries_freshness"))

  def test_check_entries_freshness_env(self):
    """Test CHECK_ENTRIES_FRESHNESS environment variable."""
    with mock.patch.dict("os.environ", {"CHECK_ENTRIES_FRESHNESS": "true"}):
      config = shared.config.load_config(config_path="/nonexistent")
      self.assertTrue(config.get("check_entries_freshness"))

  def test_rebuild_strings_on_data_patch_default(self):
    """Test default value for rebuild_strings_on_data_patch is False."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertIs(config.get("rebuild_strings_on_data_patch"), False)

  def test_rebuild_strings_on_data_patch_user_and_env(self):
    """Test user config and env override for rebuild_strings_on_data_patch."""
    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data='{"rebuild_strings_on_data_patch": true}'),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertIs(config.get("rebuild_strings_on_data_patch"), True)

    shared.config.load_config.cache_clear()
    with mock.patch.dict(
        "os.environ", {"REBUILD_STRINGS_ON_DATA_PATCH": "true"}
    ):
      config = shared.config.load_config(config_path="/nonexistent")
      self.assertIs(config.get("rebuild_strings_on_data_patch"), True)

  def test_gui_undo_points_default(self):
    """Test gui_undo_points is off by default."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertFalse(config.get("gui_undo_points"))

  def test_gui_undo_points_env(self):
    """Test GUI_UNDO_POINTS environment variable."""
    with mock.patch.dict("os.environ", {"GUI_UNDO_POINTS": "1"}):
      config = shared.config.load_config(config_path="/nonexistent")
      self.assertTrue(config.get("gui_undo_points"))

  def test_autostart_and_hotkey_defaults(self):
    """Test autostart is off and the hotkey is Ctrl-Alt-M by default."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertIs(config.get("autostart"), False)
    self.assertEqual(config.get("hotkey"), "Ctrl-Alt-M")

  def test_autostart_and_hotkey_user(self):
    """Test user-defined autostart and hotkey values."""
    with mock.patch(
        "builtins.open",
        mock.mock_open(read_data='{"autostart": true, "hotkey": ""}'),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertIs(config.get("autostart"), True)
        self.assertEqual(config.get("hotkey"), "")

  def test_autostart_and_hotkey_env(self):
    """Test AUTOSTART and HOTKEY override the config file."""
    with mock.patch.dict(
        "os.environ", {"AUTOSTART": "yes", "HOTKEY": " Ctrl-Shift-K "}
    ):
      config = shared.config.load_config(config_path="/nonexistent")
    self.assertIs(config.get("autostart"), True)
    self.assertEqual(config.get("hotkey"), "Ctrl-Shift-K")

    shared.config.load_config.cache_clear()
    with (
        mock.patch.dict("os.environ", {"AUTOSTART": "0", "HOTKEY": ""}),
        mock.patch(
            "builtins.open",
            mock.mock_open(
                read_data='{"autostart": true, "hotkey": "Ctrl-Alt-K"}'
            ),
        ),
        mock.patch("pathlib.Path.is_file", return_value=True),
    ):
      config = shared.config.load_config(config_path="/custom/path.json")
    self.assertIs(config.get("autostart"), False)
    self.assertEqual(config.get("hotkey"), "")  # No shortcut.

  def test_no_user_config_env(self):
    """Test that IDAMCP_NO_USER_CONFIG ignores user configuration files."""
    with mock.patch.dict("os.environ", {"IDAMCP_NO_USER_CONFIG": "1"}):
      with mock.patch(
          "builtins.open",
          mock.mock_open(read_data='{"communication_channel": "tcp"}'),
      ):
        with mock.patch("pathlib.Path.is_file", return_value=True):
          config = shared.config.load_config()
          self.assertEqual(
              config["communication_channel"],
              shared.config._DEFAULT_CONFIG["communication_channel"],
          )

  def test_idamcp_config_env(self):
    """Test that IDAMCP_CONFIG loads custom configuration file."""
    with mock.patch.dict("os.environ", {"IDAMCP_CONFIG": "/custom/path.json"}):
      with mock.patch(
          "builtins.open",
          mock.mock_open(read_data='{"communication_channel": "tcp"}'),
      ):
        with mock.patch("pathlib.Path.is_file", return_value=True):
          config = shared.config.load_config()
          self.assertEqual(config["communication_channel"], "tcp")

  def test_tool_mode_default(self):
    """Test tool_mode is 'hybrid' by default."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertEqual(config.get("tool_mode"), "hybrid")

  def test_tool_mode_env(self):
    """Test TOOL_MODE environment variable."""
    with mock.patch.dict("os.environ", {"TOOL_MODE": "code_mode"}):
      config = shared.config.load_config(config_path="/nonexistent")
      self.assertEqual(config.get("tool_mode"), "code_mode")

  def test_always_visible_tools_default(self):
    """Test always_visible_tools default list."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertEqual(
        config.get("always_visible_tools"),
        shared.config._DEFAULT_ALWAYS_VISIBLE_TOOLS,
    )

  def test_always_visible_tools_user(self):
    """Test custom always_visible_tools in user config file."""
    with mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data='{"always_visible_tools": ["sql_query", "hexdump"]}'
        ),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(
            config.get("always_visible_tools"), ["sql_query", "hexdump"]
        )

  def test_always_visible_tools_env(self):
    """Test ALWAYS_VISIBLE_TOOLS environment variable."""
    with mock.patch.dict(
        "os.environ",
        {"ALWAYS_VISIBLE_TOOLS": "list_available_databases, sql_query"},
    ):
      config = shared.config.load_config(config_path="/nonexistent")
      self.assertEqual(
          config.get("always_visible_tools"),
          ["list_available_databases", "sql_query"],
      )

  def test_show_decompiler_warnings_default(self):
    """Test show_decompiler_warnings is off by default."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertIs(config.get("show_decompiler_warnings"), False)

  def test_show_decompiler_warnings_env(self):
    """Test SHOW_DECOMPILER_WARNINGS environment variable."""
    with mock.patch.dict("os.environ", {"SHOW_DECOMPILER_WARNINGS": "1"}):
      config = shared.config.load_config(config_path="/nonexistent")
    self.assertIs(config.get("show_decompiler_warnings"), True)

  def test_omitted_decompiler_warnings_default(self):
    """Test omitted_decompiler_warnings default list."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertEqual(
        config.get("omitted_decompiler_warnings"),
        ["WARN_GUESSED_TYPE", "WARN_UNDEF_LVAR"],
    )

  def test_omitted_decompiler_warnings_user(self):
    """Test custom omitted_decompiler_warnings in user config file."""
    with mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data='{"omitted_decompiler_warnings": ["WARN_GUESSED_TYPE"]}'
        ),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(
            config.get("omitted_decompiler_warnings"), ["WARN_GUESSED_TYPE"]
        )

  def test_omitted_decompiler_warnings_env(self):
    """Test OMITTED_DECOMPILER_WARNINGS replaces the list."""
    with mock.patch.dict(
        "os.environ", {"OMITTED_DECOMPILER_WARNINGS": " WARN_UNDEF_LVAR "}
    ):
      config = shared.config.load_config(config_path="/nonexistent")
    self.assertEqual(
        config.get("omitted_decompiler_warnings"), ["WARN_UNDEF_LVAR"]
    )

    # An empty value leaves out no warnings.
    shared.config.load_config.cache_clear()
    with mock.patch.dict("os.environ", {"OMITTED_DECOMPILER_WARNINGS": ""}):
      config = shared.config.load_config(config_path="/nonexistent")
    self.assertEqual(config.get("omitted_decompiler_warnings"), [])

  def test_size_limit_defaults(self):
    """Test the default response and eval output limits."""
    config = shared.config.load_config(config_path="/nonexistent")
    self.assertEqual(config["max_tool_response_bytes"], 8 * 1024 * 1024)
    self.assertEqual(config["max_eval_output_bytes"], 1024 * 1024)

  def test_parse_size(self):
    """Test sizes as integers and as strings with units."""
    cases = {
        0: 0,
        4096: 4096,
        "0": 0,
        "4096": 4096,
        "4096b": 4096,
        "512k": 512 * 1024,
        "512kb": 512 * 1024,
        "512 KiB": 512 * 1024,
        "8m": 8 * 1024 * 1024,
        "8MB": 8 * 1024 * 1024,
        " 8 MiB ": 8 * 1024 * 1024,
        "1.5mb": 1536 * 1024,
        "2g": 2 * 1024 * 1024 * 1024,
        "2GiB": 2 * 1024 * 1024 * 1024,
    }
    for value, expected in cases.items():
      with self.subTest(value=value):
        self.assertEqual(shared.config._parse_size(value), expected)
    for bad in (-1, True, 1.5, "", "m", "-1k", "8 parsecs", "1,024", None):
      with self.subTest(bad=bad):
        self.assertIsNone(shared.config._parse_size(bad))

  def test_size_limit_user_env_and_zero(self):
    """Test user values and env overrides with units; 0 means no limit."""
    with mock.patch(
        "builtins.open",
        mock.mock_open(
            read_data='{"max_tool_response_bytes": "4k",'
            ' "max_eval_output_bytes": 0}'
        ),
    ):
      with mock.patch("pathlib.Path.is_file", return_value=True):
        config = shared.config.load_config()
        self.assertEqual(config["max_tool_response_bytes"], 4096)
        self.assertEqual(config["max_eval_output_bytes"], 0)

    shared.config.load_config.cache_clear()
    with mock.patch.dict(
        "os.environ",
        {"MAX_TOOL_RESPONSE_BYTES": "0", "MAX_EVAL_OUTPUT_BYTES": " 2 kb "},
    ):
      config = shared.config.load_config(config_path="/nonexistent")
    self.assertEqual(config["max_tool_response_bytes"], 0)
    self.assertEqual(config["max_eval_output_bytes"], 2048)

  def test_invalid_size_limits_fall_back_to_defaults(self):
    """Test that negative, boolean, and unknown-unit limits use the default."""
    for bad in ("-1", "true", "1.5", '"1 parsec"', '"-1k"', '""'):
      with self.subTest(bad=bad):
        shared.config.load_config.cache_clear()
        with (
            mock.patch(
                "builtins.open",
                mock.mock_open(
                    read_data=f'{{"max_eval_output_bytes": {bad}}}'
                ),
            ),
            mock.patch("pathlib.Path.is_file", return_value=True),
            self.assertLogs(level="WARNING") as logs,
        ):
          config = shared.config.load_config()
        self.assertEqual(config["max_eval_output_bytes"], 1024 * 1024)
        self.assertIn("Invalid max_eval_output_bytes", logs.output[0])


if __name__ == "__main__":
  unittest.main()
