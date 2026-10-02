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

"""Protocol version and capabilities exchanged by the gateway and backends.

Each backend writes PROTOCOL_VERSION and BACKEND_CAPABILITIES into its registry
record. The gateway checks the record before it connects:

*   No protocol_version field: the backend runs an idamcp plugin from before
    this check existed. The gateway connects as before and assumes the backend
    has no capabilities.
*   A version outside [MIN_BACKEND_PROTOCOL_VERSION, PROTOCOL_VERSION]: the
    gateway does not connect, and reports which process has to be restarted.

IDA keeps the plugin code it loaded at startup, so a gateway and a backend
from different idamcp versions can meet after an update. Bump PROTOCOL_VERSION
only for changes that an older peer cannot handle. For anything else, add a
capability and have the peer check for it before using the feature.
"""

from typing import Any, Mapping

# Version of the gateway <-> backend protocol implemented by this checkout.
PROTOCOL_VERSION = 1

# Oldest backend protocol version the gateway still connects to.
MIN_BACKEND_PROTOCOL_VERSION = 1

# Optional features of this backend, advertised in its registry record.
BACKEND_CAPABILITIES: tuple[str, ...] = ()


def record_fields() -> dict[str, Any]:
  """Returns the protocol fields a backend adds to its registry record."""
  return {
      "protocol_version": PROTOCOL_VERSION,
      "capabilities": sorted(BACKEND_CAPABILITIES),
  }


def is_legacy_record(record: Mapping[str, Any]) -> bool:
  """Returns True for records written before protocol versions existed."""
  return "protocol_version" not in record


def parse_capabilities(record: Mapping[str, Any]) -> frozenset[str]:
  """Returns the capabilities in a registry record, ignoring invalid entries."""
  capabilities = record.get("capabilities")
  if not isinstance(capabilities, list):
    return frozenset()
  return frozenset(c for c in capabilities if isinstance(c, str))


def incompatibility_reason(record: Mapping[str, Any]) -> str | None:
  """Checks the protocol version in a backend's registry record.

  Args:
    record: The parsed registry record.

  Returns:
    None if the gateway can connect to the backend, including legacy records
    without a version. Otherwise, a message that tells the user what to do.
  """
  if is_legacy_record(record):
    return None
  version = record["protocol_version"]
  if not isinstance(version, int) or isinstance(version, bool):
    return f"The registry record has an invalid protocol_version: {version!r}."
  if version < MIN_BACKEND_PROTOCOL_VERSION:
    return (
        f"The IDA plugin uses protocol version {version}, but this gateway"
        f" requires at least version {MIN_BACKEND_PROTOCOL_VERSION}. Restart"
        " IDA so it loads the updated idamcp plugin."
    )
  if version > PROTOCOL_VERSION:
    return (
        f"The IDA plugin uses protocol version {version}, but this gateway"
        f" supports up to version {PROTOCOL_VERSION}. Restart the MCP client"
        " so it starts the updated gateway."
    )
  return None
