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

"""Registry manager for IDA MCP backends."""

import atexit
import contextlib
import json
import logging
import os
import pathlib
import tempfile
import time
from typing import Any

from shared import registry


# How often promote() tries its rename, and the wait in seconds between tries.
_PROMOTE_ATTEMPTS = 5
_PROMOTE_RETRY_DELAY = 0.05


class RegistryManager:
  """Manages registration of MCP backends."""

  def __init__(self, registry_dir: str):
    self.registry_dir = pathlib.Path(registry_dir)
    self.registry_dir.mkdir(parents=True, exist_ok=True)
    self.current_file = None

  def register(
      self,
      channel: str,
      address: str | int,
      database_id: str,
      instance_id: str,
      started_at: float,
      metadata: dict[str, Any] | None = None,
      in_progress: bool = False,
      auto_analysis_disabled: bool = False,
  ) -> pathlib.Path | None:
    """Register a backend.

    The record is named after instance_id, with a prefix while in_progress
    (see shared.registry); promote() removes the prefix.

    Args:
      channel: 'tcp' or 'uds'
      address: port number (int) for tcp, or path (str) for uds.
      database_id: the ID of the database that this server serves.
      instance_id: the ID of this server instance.
      started_at: when this server started, in seconds since the epoch. The
        gateway keeps the newest instance of a database.
      metadata: Optional dictionary containing database metadata.
      in_progress: Whether auto-analysis is still running.
      auto_analysis_disabled: Whether the database was opened without
        auto-analysis.

    Returns:
      Path to the registry file created, or None if failed.
    """
    channel = channel.lower()

    data = {
        "pid": os.getpid(),
        "channel": channel,
        "address": address,
        "database_id": database_id,
        "started_at": started_at,
        "auto_analysis_disabled": auto_analysis_disabled,
        "metadata": metadata or {},
    }
    file_path = self.registry_dir / registry.record_name(
        instance_id, in_progress
    )
    temp_path = ""
    try:
      with tempfile.NamedTemporaryFile(
          mode="w", dir=str(self.registry_dir), delete=False
      ) as temp_file:
        temp_path = temp_file.name
        json.dump(data, temp_file)
      os.replace(temp_path, file_path)
    except Exception as e:
      logging.exception("Failed to write registry file: %s", str(e))
      return None
    finally:
      if temp_path and os.path.isfile(temp_path):
        with contextlib.suppress(OSError):
          os.unlink(temp_path)
    self.current_file = file_path

    # Register cleanup
    atexit.register(self.cleanup)
    return file_path

  def promote(self) -> pathlib.Path | None:
    """Renames an in-progress record to its plain name.

    Call it when auto-analysis has finished. A single rename, so the gateway
    always finds one record of this instance.

    Returns:
      The record's new path, or None if there is no in-progress record or the
      rename failed.
    """
    current = self.current_file
    if current is None:
      return None
    instance_id, in_progress = registry.parse_record_name(current.name)
    if not in_progress:
      return None
    file_path = self.registry_dir / registry.record_name(instance_id, False)
    # On Windows the rename fails while another process (the gateway, the
    # dashboard) has the record open, which it only has for a moment.
    for attempt in range(_PROMOTE_ATTEMPTS):
      try:
        os.replace(current, file_path)
        break
      except OSError as e:
        if attempt == _PROMOTE_ATTEMPTS - 1:
          logging.exception("Failed to rename registry file: %s", str(e))
          return None
        time.sleep(_PROMOTE_RETRY_DELAY)
    self.current_file = file_path
    return file_path

  def cleanup(self) -> None:
    """Removes the registry file."""
    with contextlib.suppress(Exception):
      atexit.unregister(self.cleanup)
    if self.current_file and self.current_file.exists():
      for attempt in range(_PROMOTE_ATTEMPTS):
        try:
          self.current_file.unlink()
          logging.info("Removed registry file: %s", str(self.current_file))
          break
        except FileNotFoundError:
          break
        except Exception as e:  # pylint: disable=broad-exception-caught
          if attempt == _PROMOTE_ATTEMPTS - 1:
            logging.exception("Failed to remove registry file: %s", str(e))
          else:
            time.sleep(_PROMOTE_RETRY_DELAY)
    self.current_file = None
