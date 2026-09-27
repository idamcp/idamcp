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
from typing import Any, Iterable

from shared import protocol


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
      name: str,
      metadata: dict[str, Any] | None = None,
      capabilities: Iterable[str] = (),
  ) -> pathlib.Path | None:
    """Register a backend.

    Args:
      channel: 'tcp' or 'uds'
      address: port number (int) for tcp, or path (str) for uds.
      name: the identifier name.
      metadata: Optional dictionary containing database metadata.
      capabilities: Capabilities of this backend instance, advertised in
        addition to protocol.BACKEND_CAPABILITIES.

    Returns:
      Path to the registry file created, or None if failed.
    """
    channel = channel.lower()

    data = {
        "pid": os.getpid(),
        "channel": channel,
        "address": address,
        "name": name,
        "metadata": metadata or {},
        # Gateways from before the protocol check ignore these keys.
        **protocol.record_fields(capabilities),
    }
    file_path = self.registry_dir / f"{name}.json"
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

  def cleanup(self) -> None:
    """Removes the registry file."""
    with contextlib.suppress(Exception):
      atexit.unregister(self.cleanup)
    if self.current_file and self.current_file.exists():
      try:
        self.current_file.unlink()
        logging.info("Removed registry file: %s", str(self.current_file))
      except Exception as e:  # pylint: disable=broad-exception-caught
        logging.exception("Failed to remove registry file: %s", str(e))
      finally:
        self.current_file = None
    else:
      self.current_file = None
