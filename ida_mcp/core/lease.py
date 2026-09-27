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

"""Lease-based lifetime for headless backends (headless_lifetime "lease").

A lease is held by an RPC connection that called lease_acquire. It ends with
lease_release or when the connection closes, which also happens when the
client process dies, so no heartbeat is needed. The backend shuts down the same
way close_database does, which saves the database:

*   right away when lease_release ends the last lease (the last client is
    done),
*   when no lease is held for headless_lease_grace seconds (connections that
    dropped, or nobody connected after startup), or
*   when no tool call ran for headless_idle_timeout seconds, if set.

The module has no IDA imports; the shutdown action is passed in.
"""

import asyncio
import logging
import threading
import time
from typing import Any, Callable, Mapping

from shared import protocol
from shared import rpc

logger = logging.getLogger(__name__)

# Capability advertised in the registry record of a backend in lease mode.
CAPABILITY = protocol.HEADLESS_LEASE

LIFETIMES = ("spawner", "lease")


class LeaseManager:
  """Tracks the leases of one headless backend and decides when it exits."""

  def __init__(
      self,
      grace: float,
      idle_timeout: float,
      on_expire: Callable[[str], None],
      clock: Callable[[], float] = time.monotonic,
  ):
    self.grace = max(0.0, grace)
    self.idle_timeout = max(0.0, idle_timeout)
    self._on_expire = on_expire
    self._clock = clock
    self._lock = threading.Lock()
    self._leases: set[int] = set()
    self._in_flight = 0
    now = clock()
    # The grace period also runs from startup, so a backend that nobody ever
    # acquires does not stay around.
    self._zero_since: float | None = now
    self._last_activity = now
    self._expired = False

  @property
  def lease_count(self) -> int:
    with self._lock:
      return len(self._leases)

  def acquire(self, connection: int) -> None:
    with self._lock:
      self._leases.add(connection)
      self._zero_since = None

  def release(self, connection: int) -> bool:
    """Releases a connection's lease; returns False if it held none."""
    with self._lock:
      if connection not in self._leases:
        return False
      self._leases.discard(connection)
      if not self._leases:
        self._zero_since = self._clock()
      return True

  def release_explicitly(self, connection: int) -> tuple[bool, int]:
    """Handles lease_release; shuts down right away if no lease is left.

    Args:
      connection: The id of the connection that asked.

    Returns:
      Whether the connection held a lease, and how many leases remain.
    """
    released = self.release(connection)
    remaining = self.lease_count
    if released and remaining == 0:
      self._expire("the last lease was released")
    return released, remaining

  def connection_closed(self, connection: int) -> None:
    if self.release(connection):
      logger.info("Lease released: connection closed")

  def call_started(self) -> None:
    with self._lock:
      self._in_flight += 1
      self._last_activity = self._clock()

  def call_finished(self) -> None:
    with self._lock:
      self._in_flight = max(0, self._in_flight - 1)
      self._last_activity = self._clock()

  def expired_reason(self) -> str | None:
    """Returns why the backend should exit now, or None."""
    with self._lock:
      now = self._clock()
      if self._zero_since is not None and now - self._zero_since >= self.grace:
        return f"no client has held a lease for {self.grace:g} s"
      if (
          self.idle_timeout
          and self._in_flight == 0
          and now - self._last_activity >= self.idle_timeout
      ):
        return f"no tool call for {self.idle_timeout:g} s"
      return None

  def _expire(self, reason: str) -> None:
    with self._lock:
      if self._expired:
        return
      self._expired = True
    logger.info("Shutting down headless backend: %s", reason)
    self._on_expire(reason)

  def check(self) -> bool:
    """Calls on_expire once if the backend should exit; returns True if so."""
    if self._expired:
      return True
    reason = self.expired_reason()
    if reason is None:
      return False
    self._expire(reason)
    return True

  async def watch(self, interval: float = 1.0) -> None:
    """Checks periodically until the backend expires."""
    while not self.check():
      await asyncio.sleep(interval)


_manager: LeaseManager | None = None
_warned_lifetime: set[str] = set()


def lifetime_from_config(config: Mapping[str, Any]) -> str:
  lifetime = str(config.get("headless_lifetime", "spawner")).lower()
  if lifetime not in LIFETIMES:
    if lifetime not in _warned_lifetime:
      _warned_lifetime.add(lifetime)
      logger.warning("Unknown headless_lifetime %r; using 'spawner'.", lifetime)
    return "spawner"
  return lifetime


def configure(
    config: Mapping[str, Any],
    is_headless: bool,
    on_expire: Callable[[str], None],
) -> LeaseManager | None:
  """Creates the backend's lease manager if lease mode applies, else None."""
  global _manager
  _manager = None
  if not is_headless or lifetime_from_config(config) != "lease":
    return None
  _manager = LeaseManager(
      grace=float(config.get("headless_lease_grace", 30.0)),
      idle_timeout=float(config.get("headless_idle_timeout", 0.0)),
      on_expire=on_expire,
  )
  logger.info(
      "Lease mode: exiting %g s after the last lease ends%s.",
      _manager.grace,
      f" or after {_manager.idle_timeout:g} s without tool calls"
      if _manager.idle_timeout
      else "",
  )
  return _manager


def current() -> LeaseManager | None:
  return _manager


def _connection_closed(connection: int) -> None:
  if _manager is not None:
    _manager.connection_closed(connection)


rpc.add_connection_close_listener(_connection_closed)


def acquire_current() -> bool:
  """Gives the calling RPC connection a lease; False if not in lease mode."""
  connection = rpc.current_connection()
  if _manager is None or connection is None:
    return False
  _manager.acquire(connection)
  logger.info("Lease acquired (%d held)", _manager.lease_count)
  return True


def release_current() -> dict[str, Any]:
  """Ends the calling RPC connection's lease.

  Returns:
    {"released": whether the connection held a lease, "remaining": leases
    still held}. With no lease left the backend shuts down right away.
  """
  connection = rpc.current_connection()
  if _manager is None or connection is None:
    return {"released": False, "remaining": 0}
  released, remaining = _manager.release_explicitly(connection)
  if released:
    logger.info("Lease released (%d held)", remaining)
  return {"released": released, "remaining": remaining}
