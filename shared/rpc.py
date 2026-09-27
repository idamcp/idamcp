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

"""Simple JSON-RPC implementation over TCP/UDS."""

import asyncio
import contextvars
import dataclasses
import json
import logging
import socket
import sys
from typing import Any, Callable, Dict
import uuid

logger = logging.getLogger(__name__)


class RPCJSONEncoder(json.JSONEncoder):
  """JSON encoder that supports dataclasses, Pydantic models, and custom objects."""

  def default(self, o):
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
      return dataclasses.asdict(o)
    if hasattr(o, "model_dump"):
      return o.model_dump(mode="json")
    return super().default(o)


class RPCError(Exception):
  """Raised when an RPC call returns an error."""

  def __init__(self, message: str, data: Any = None):
    super().__init__(message)
    self.data = data


class ToolError(Exception):
  """Raised when a tool execution fails inside the backend."""

  pass


def set_keepalive(sock):
  if sock is None:
    return
  try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if sys.platform == "win32" and hasattr(socket, "SIO_KEEPALIVE_VALS"):
      # asyncio TransportSocket wraps the real socket in _sock and doesn't expose ioctl.
      ioctl_sock = getattr(sock, "_sock", sock)
      if ioctl_sock and hasattr(ioctl_sock, "ioctl"):
        # Windows: (onoff, timeout_ms, interval_ms)
        ioctl_sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 10000, 5000))
    elif sys.platform == "darwin":
      # macOS
      TCP_KEEPALIVE = 0x10
      sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, 10)
    elif hasattr(socket, "TCP_KEEPIDLE"):
      # Linux specific keepalive settings
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 10)  # 10s idle
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)  # 5s intvl
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)  # 3 failures
  except Exception as e:
    logger.warning("Failed to set keepalive: %s", e)


# Per-request context set by RPCServer for the method it runs. The optional
# "meta" object of a request carries caller information that is not a method
# parameter (for example the gateway's MCP session id), so methods don't have
# to declare it and servers that predate it simply ignore it.
_connection_var: contextvars.ContextVar[int | None] = contextvars.ContextVar(
    "rpc_connection", default=None
)
_meta_var: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "rpc_meta", default={}
)
_connection_close_listeners: list[Callable[[int], None]] = []


def current_connection() -> int | None:
  """Returns an id for the connection of the running RPC request, or None."""
  return _connection_var.get()


def current_meta() -> dict[str, Any]:
  """Returns the "meta" object of the running RPC request ({} if none)."""
  return _meta_var.get()


def add_connection_close_listener(listener: Callable[[int], None]) -> None:
  """Calls listener(connection_id) whenever an RPCServer connection closes."""
  if listener not in _connection_close_listeners:
    _connection_close_listeners.append(listener)


class RPCServer:
  """Simple JSON-RPC server."""

  def __init__(self, methods: Dict[str, Callable]):
    self.methods = methods
    self.active_connections = set()
    self.running_tasks: Dict[
        asyncio.WriteTransport, Dict[Any, asyncio.Task]
    ] = {}
    self._server = None

  async def handle_connection(
      self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
  ):
    transport = writer.transport
    self.active_connections.add(transport)
    self.running_tasks[transport] = {}

    # Set keepalive for TCP connections
    sock = transport.get_extra_info("socket")
    if sock and sock.family in (socket.AF_INET, socket.AF_INET6):
      set_keepalive(sock)

    try:
      while True:
        line = await reader.readline()
        if not line:
          break  # EOF

        try:
          request = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
          logger.error("Failed to decode JSON: %r", line)
          continue

        await self.process_request(request, writer)
    except asyncio.CancelledError:
      pass
    except Exception as e:
      logger.exception("Error handling connection: %s", e)
    finally:
      if transport in self.active_connections:
        self.active_connections.remove(transport)
      tasks = self.running_tasks.pop(transport, {})
      for task in tasks.values():
        task.cancel()
      writer.close()
      try:
        await writer.wait_closed()
      except Exception:
        pass
      for listener in list(_connection_close_listeners):
        try:
          listener(id(transport))
        except Exception:  # pylint: disable=broad-exception-caught
          logger.exception("Connection close listener failed")
      logger.info("Connection closed")

  async def process_request(self, request: dict, writer: asyncio.StreamWriter):
    transport = writer.transport
    req_id = request.get("id")
    method = request.get("method")

    if method == "$/cancelRequest":
      target_id = request.get("params", {}).get("id")
      if target_id is not None:
        task = self.running_tasks[transport].get(target_id)
        if task:
          logger.info("Cancelling task %s", target_id)
          task.cancel()
      return

    if method == "ping":
      await self.send_result(writer, req_id, "pong")
      return

    if req_id is None:
      # Notification, not supported for now
      return

    if not method:
      await self.send_error(writer, req_id, -32600, "Invalid Request")
      return

    if method not in self.methods:
      await self.send_error(
          writer, req_id, -32601, f"Method not found: {method}"
      )
      return

    params = request.get("params", {})
    meta = request.get("meta")

    # Spawn task to handle the request. The task copies the current context,
    # so the method sees this request's connection and meta.
    connection_token = _connection_var.set(id(transport))
    meta_token = _meta_var.set(meta if isinstance(meta, dict) else {})
    try:
      task = asyncio.create_task(
          self.execute_method(req_id, method, params, writer)
      )
    finally:
      _meta_var.reset(meta_token)
      _connection_var.reset(connection_token)
    self.running_tasks[transport][req_id] = task
    task.add_done_callback(
        lambda _: self.running_tasks[transport].pop(req_id, None)
        if transport in self.running_tasks
        else None
    )

  async def execute_method(
      self,
      req_id: Any,
      method_name: str,
      params: Any,
      writer: asyncio.StreamWriter,
  ):
    method = self.methods[method_name]
    try:
      if params is None:
        result = method()
      elif isinstance(params, dict):
        result = method(**params)
      elif isinstance(params, list):
        result = method(*params)
      else:
        result = method(params)

      if asyncio.iscoroutine(result):
        result = await result

      await self.send_result(writer, req_id, result)
    except asyncio.CancelledError:
      logger.info("Method %s (id %s) cancelled", method_name, req_id)
      await self.send_error(writer, req_id, -32000, "Canceled")
    except ToolError as e:
      logger.warning("Tool execution error in %s: %s", method_name, e)
      await self.send_error(writer, req_id, -32001, str(e))
    except Exception as e:
      logger.exception("Error executing %s: %s", method_name, e)
      await self.send_error(writer, req_id, -32603, str(e))

  async def send_result(
      self, writer: asyncio.StreamWriter, req_id: Any, result: Any
  ):
    response = {"jsonrpc": "2.0", "result": result, "id": req_id}
    await self.send_response(writer, response)

  async def send_error(
      self, writer: asyncio.StreamWriter, req_id: Any, code: int, message: str
  ):
    response = {
        "jsonrpc": "2.0",
        "error": {"code": code, "message": message},
        "id": req_id,
    }
    await self.send_response(writer, response)

  async def send_response(self, writer: asyncio.StreamWriter, response: dict):
    if writer.is_closing():
      return
    try:
      data = json.dumps(response, cls=RPCJSONEncoder).encode("utf-8") + b"\n"
      writer.write(data)
      await writer.drain()
    except Exception as e:
      logger.error("Failed to send response: %s", e)

  async def start_tcp(
      self, host: str, port: int, limit: int = 100 * 1024 * 1024
  ):
    self._server = await asyncio.start_server(
        self.handle_connection, host, port, limit=limit
    )
    return self._server

  async def start_uds(self, path: str, limit: int = 100 * 1024 * 1024):
    self._server = await asyncio.start_unix_server(
        self.handle_connection, path, limit=limit
    )
    return self._server

  async def close(self):
    if self._server:
      self._server.close()

      # Collect and cancel all tasks before connection handlers remove them
      all_tasks = []
      for transport_tasks in self.running_tasks.values():
        all_tasks.extend(transport_tasks.values())
      for task in all_tasks:
        task.cancel()

      # Close all active connections so their handlers can exit
      for transport in list(self.active_connections):
        transport.close()

      await self._server.wait_closed()

      if all_tasks:
        await asyncio.gather(*all_tasks, return_exceptions=True)


class RPCClient:
  """Simple JSON-RPC client."""

  def __init__(self):
    self.reader = None
    self.writer = None
    self.pending_requests: Dict[str, asyncio.Future[Any]] = {}
    self.reader_task = None
    self._closed = False

  async def connect_tcp(
      self, host: str, port: int, limit: int = 100 * 1024 * 1024
  ):
    self.reader, self.writer = await asyncio.open_connection(
        host, port, limit=limit
    )
    sock = self.writer.get_extra_info("socket")
    if sock and sock.family in (socket.AF_INET, socket.AF_INET6):
      set_keepalive(sock)
    self.reader_task = asyncio.create_task(self.read_loop())
    self._closed = False

  async def connect_uds(self, path: str, limit: int = 100 * 1024 * 1024):
    self.reader, self.writer = await asyncio.open_unix_connection(
        path, limit=limit
    )
    self.reader_task = asyncio.create_task(self.read_loop())
    self._closed = False

  async def read_loop(self):
    try:
      while True:
        line = await self.reader.readline()  # type: ignore
        if not line:
          break  # EOF
        try:
          response = json.loads(line.decode("utf-8"))
          self.handle_response(response)
        except json.JSONDecodeError:
          logger.error("Failed to decode response: %r", line)
    except asyncio.CancelledError:
      pass
    except Exception as e:
      logger.exception("Error in client read loop: %s", e)
    finally:
      self._closed = True
      self.close_all_pending(RPCError("Connection closed"))

  def handle_response(self, response: dict):
    req_id = response.get("id")
    if req_id in self.pending_requests:
      future = self.pending_requests.pop(req_id)
      if not future.done():
        if (err := response.get("error")) is not None:
          future.set_exception(RPCError(err.get("message"), err.get("code")))
        else:
          future.set_result(response.get("result"))

  def close_all_pending(self, exc):
    for future in list(self.pending_requests.values()):
      if not future.done():
        future.set_exception(exc)
    self.pending_requests.clear()

  async def call(
      self,
      method: str,
      params: Any = None,
      meta: dict[str, Any] | None = None,
  ) -> Any:
    if self._closed or not self.writer:
      raise RPCError("Connection is closed")

    req_id = str(uuid.uuid4())
    future = asyncio.get_running_loop().create_future()
    self.pending_requests[req_id] = future

    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": req_id,
    }
    if meta:
      request["meta"] = meta

    try:
      data = json.dumps(request, cls=RPCJSONEncoder).encode("utf-8") + b"\n"
      self.writer.write(data)
      await self.writer.drain()
    except Exception as e:
      logger.exception("Failed to send request due to exception")
      self.pending_requests.pop(req_id, None)
      raise RPCError("Failed to send request") from e

    try:
      return await future
    except asyncio.CancelledError:
      self.pending_requests.pop(req_id, None)
      # Send cancel request
      if not self._closed and self.writer:
        cancel_request = {
            "jsonrpc": "2.0",
            "method": "$/cancelRequest",
            "params": {"id": req_id},
        }
        try:
          data = json.dumps(cancel_request).encode("utf-8") + b"\n"
          self.writer.write(data)
          await self.writer.drain()
        except Exception as e:
          logger.warning("Failed to send cancel request: %s", e)
      raise

  async def ping(self) -> bool:
    try:
      res = await self.call("ping")
      return res == "pong"
    except Exception:
      return False

  async def close(self):
    self._closed = True
    if self.reader_task:
      self.reader_task.cancel()
      try:
        await self.reader_task
      except asyncio.CancelledError:
        pass
    if self.writer:
      self.writer.close()
      try:
        await self.writer.wait_closed()
      except Exception:
        pass
    self.close_all_pending(RPCError("Connection closed by client"))
