# Copyright (c) 2026 Google LLC
# Copyright (c) 2026 Hex-Rays SA
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

"""Decorators and cancellation support for JSON-RPC methods."""

import asyncio
from collections.abc import Collection
from collections.abc import Iterable
from collections.abc import Iterator
from collections.abc import Mapping
from collections.abc import MutableSequence
from collections.abc import Sequence
from collections.abc import Set
import contextlib
import contextvars
import ctypes
import dataclasses
import functools
import heapq
import inspect
import logging
import math
import threading
import time
import types
import typing
from typing import (
    Annotated,
    Any,
    Callable,
    Literal,
    Union,
    get_args,
    get_origin,
)
import ida_kernwin
from ida_mcp.core.rpc_registry import rpc_registry
import idaapi
from shared.rpc import ToolError

logger = logging.getLogger(__name__)


# Adapted from ida-nexus: _OperationInterrupt in ida_nexus/_runtime.py.
class _OperationInterrupt(asyncio.CancelledError):
  """Asynchronous exception used to interrupt running Python/IDA tool threads."""


class ToolTimeoutError(ToolError, TimeoutError):
  """Raised when a tool call runs longer than its timeout.

  As a ToolError, the RPC server reports it to the client like other tool
  errors: with just its message, and without logging a traceback.
  """


def _with_notes(message: str, error: BaseException) -> str:
  """Returns `message` followed by the notes of `error`, one paragraph each."""
  return "\n\n".join([message, *map(str, getattr(error, "__notes__", ()))])


# Adapted from ida-nexus: _DeadlineScheduler in ida_nexus/_runtime.py.
class _DeadlineScheduler:
  """Single reusable daemon thread for operation execution deadlines."""

  def __init__(self) -> None:
    self._condition = threading.Condition()
    self._deadlines: list[tuple[float, int]] = []
    self._callbacks: dict[int, Callable[[], None]] = {}
    self._next_token = 0
    self._thread: threading.Thread | None = None

  def schedule(self, delay: float, callback: Callable[[], None]) -> int:
    deadline = time.monotonic() + delay
    with self._condition:
      self._next_token += 1
      token = self._next_token
      self._callbacks[token] = callback
      heapq.heappush(self._deadlines, (deadline, token))
      if self._thread is None or not self._thread.is_alive():
        self._thread = threading.Thread(
            target=self._run,
            name="idamcp-deadlines",
            daemon=True,
        )
        self._thread.start()
      self._condition.notify()
      return token

  def cancel(self, token: int) -> None:
    with self._condition:
      if self._callbacks.pop(token, None) is not None:
        self._condition.notify()

  def _run(self) -> None:
    while True:
      callback: Callable[[], None] | None = None
      with self._condition:
        while callback is None:
          while (
              self._deadlines and self._deadlines[0][1] not in self._callbacks
          ):
            heapq.heappop(self._deadlines)
          if not self._deadlines:
            self._condition.wait()
            continue
          deadline, token = self._deadlines[0]
          delay = deadline - time.monotonic()
          if delay > 0:
            self._condition.wait(delay)
            continue
          heapq.heappop(self._deadlines)
          callback = self._callbacks.pop(token, None)
      if callback is not None:
        try:
          callback()
        except BaseException as e:  # pylint: disable=broad-exception-caught
          logger.warning("Deadline callback failed: %s", e)


_deadline_scheduler = _DeadlineScheduler()


class CancellationToken:
  """Thread-safe token managing cancellation state and callbacks."""

  def __init__(self):
    self._is_cancelled = False
    self._callbacks: list[Callable[[], Any]] = []
    self._pulse_callbacks: list[Callable[[], Any]] = []
    self._lock = threading.Lock()

  @property
  def is_cancelled(self) -> bool:
    return self._is_cancelled

  def is_set(self) -> bool:
    """Compatibility method matching asyncio.Event / threading.Event."""
    return self._is_cancelled

  def register_callback(
      self, cb: Callable[[], Any], *, repeatable: bool = False
  ) -> Callable[[], None]:
    """Registers a cancellation callback.

    If the token is already cancelled, the callback is invoked immediately.

    Args:
      cb: The zero-argument callback to invoke on cancellation.
      repeatable: If True, also retain `cb` for `pulse()` re-notifications until
        unregistered.

    Returns:
      A cleanup function that unregisters the callback.
    """
    with self._lock:
      is_cancelled = self._is_cancelled
      if not is_cancelled:
        self._callbacks.append(cb)
      if repeatable:
        self._pulse_callbacks.append(cb)

    def unregister() -> None:
      with self._lock:
        if cb in self._callbacks:
          self._callbacks.remove(cb)
        if cb in self._pulse_callbacks:
          self._pulse_callbacks.remove(cb)

    if is_cancelled:
      try:
        cb()
      except (asyncio.CancelledError, _OperationInterrupt):
        raise
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Error invoking immediate cancellation callback: %s", e)
      return unregister

    return unregister

  def cancel(self) -> None:
    """Cancels the token and invokes all registered callbacks."""
    with self._lock:
      if self._is_cancelled:
        return
      self._is_cancelled = True
      callbacks = list(self._callbacks)
      self._callbacks.clear()

    cancelled_exc: BaseException | None = None
    for cb in callbacks:
      try:
        cb()
      except (asyncio.CancelledError, _OperationInterrupt) as e:
        cancelled_exc = e
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("Error invoking cancellation callback: %s", e)
    if cancelled_exc is not None:
      raise cancelled_exc

  def pulse(self) -> None:
    """Re-invokes repeatable interruption callbacks if still active."""
    with self._lock:
      if not self._is_cancelled:
        return
      callbacks = list(self._pulse_callbacks)
    for cb in callbacks:
      with contextlib.suppress(Exception, asyncio.CancelledError, _OperationInterrupt):
        cb()

  def set(self) -> None:
    """Alias for cancel() to match asyncio.Event interface."""
    self.cancel()


cancellation_token_var: contextvars.ContextVar[CancellationToken | None] = (
    contextvars.ContextVar("cancellation_token", default=None)
)

# Backwards compatibility alias
cancel_event_var = cancellation_token_var


_cancel_tls = threading.local()


def get_cancellation_token() -> CancellationToken | None:
  """Retrieves the active cancellation token for the current context."""
  return getattr(_cancel_tls, "active_token", None) or (
      cancellation_token_var.get()
  )


@contextlib.contextmanager
def register_cancel_callback(cb: Callable[[], Any]):
  """Context manager to register a cancellation callback for a scope."""
  token = get_cancellation_token()
  if token is not None:
    unregister = token.register_callback(cb)
    try:
      yield token
    finally:
      unregister()
  else:
    yield None


# Adapted from ida-nexus: _set_async_exc in ida_nexus/_runtime.py.
_set_async_exc = ctypes.pythonapi.PyThreadState_SetAsyncExc
_set_async_exc.argtypes = (ctypes.c_ulong, ctypes.py_object)
_set_async_exc.restype = ctypes.c_int


def _inject_async_exc(tid: int, exc_type: type[BaseException]) -> int:
  return _set_async_exc(tid, ctypes.py_object(exc_type))


# Waits between the re-interrupts of a cancelled or timed-out operation while it
# keeps running: pulse()s after a cancel, repeated deadlines after a timeout. A
# re-interrupt is needed when the first interrupt was swallowed, e.g., raised
# inside a C/SWIG callback that reports it via PyErr_WriteUnraisable and returns
# to the caller's loop. But a re-interrupt that lands in cleanup code (finally
# blocks, context managers) cuts it short, so the first wait lets short cleanup
# finish; later waits double, capped so that a swallowed interrupt is still
# retried at least once a second.
_PULSE_INITIAL_DELAY = 0.25
_PULSE_MAX_DELAY = 1.0


def _pulse_delays() -> Iterator[float]:
  """Yields the waits between re-interrupts of a cancelled or timed-out call."""
  delay = _PULSE_INITIAL_DELAY
  while True:
    yield delay
    delay = min(delay * 2, _PULSE_MAX_DELAY)


@contextlib.contextmanager
def cancellation_profile(
    token: CancellationToken | None,
    *,
    native_ida_cancel: bool = False,
    timeout: float | None = None,
):
  """Zero-overhead cancellation scope using PyThreadState_SetAsyncExc.

  Interrupts the thread that entered the scope when `token` is cancelled, and
  again on each `token.pulse()`; the scope then raises asyncio.CancelledError.
  With a `timeout`, also interrupts the thread once the scope has run that long,
  and again after each of the `_pulse_delays()` while it keeps running, in case
  an interrupt was swallowed; the scope then raises ToolTimeoutError, unless the
  token was cancelled as well. Its message ends with the notes (__notes__) that
  the interrupted code added to the interrupt while it unwound.

  Caveat for cleanup code: on Python 3.13 an asynchronous exception that lands
  on a loop back-edge (`while` or `for`, e.g., when a loop body ends with an
  `if` branch) can skip that frame's own `except`, `finally`, and `with`
  cleanup (blocking calls are not affected; 3.11 and 3.12 behave). The
  exception still propagates, so the callers of that frame, this scope
  included, see it. Cleanup that must run after a cancel or timeout therefore
  belongs in a loop-free frame that calls the looping code, as the SQLite
  write transactions in tools/query.py do.

  Args:
    token: Token whose cancellation interrupts the scope, or None.
    native_ida_cancel: Whether an interrupt also sets IDA's cancel flag, which
      long-running IDA functions poll.
    timeout: Seconds the scope may run before it is interrupted, or None for no
      limit.

  Yields:
    None.
  """
  if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
    raise ValueError("timeout must be a positive finite number")
  if token is None and timeout is None:
    yield
    return
  if token is not None and token.is_cancelled:
    raise asyncio.CancelledError("Tool cancelled")

  prev_token = getattr(_cancel_tls, "active_token", None)
  if token is not None and prev_token is token and timeout is None:
    # Idempotent reuse for nested scopes on the same thread and token
    yield
    return
  if token is not None:
    _cancel_tls.active_token = token
  tid = threading.get_ident()

  state_lock = threading.Lock()
  active = True
  timed_out = False
  deadline_token: int | None = None
  retry_delays = _pulse_delays()

  def _interrupt(*, is_timeout: bool = False) -> None:
    nonlocal timed_out
    with state_lock:
      if not active:
        return
      if is_timeout:
        timed_out = True
      if native_ida_cancel and getattr(idaapi, "is_headless", False):
        ida_kernwin.set_cancelled()
      _inject_async_exc(tid, _OperationInterrupt)

    if native_ida_cancel and not getattr(idaapi, "is_headless", False):
      # In GUI mode, set_cancelled() marshals to the main thread.
      # Queue outside state_lock with MFF_NOWAIT so we never deadlock, and
      # re-check `active` when IDA dispatches the callback so a late callback
      # cannot set the cancel flag after clr_cancelled() has already run.
      # Adapted from ida-nexus: IDARuntime._interrupt_active in
      # ida_nexus/_runtime.py.
      def _cancel_native() -> int:
        with state_lock:
          if active:
            ida_kernwin.set_cancelled()
        return 1

      ida_kernwin.execute_sync(
          _cancel_native,
          ida_kernwin.MFF_FAST | ida_kernwin.MFF_NOWAIT,
      )

  def _on_cancel() -> None:
    _interrupt(is_timeout=False)

  def _on_timeout() -> None:
    nonlocal deadline_token
    _interrupt(is_timeout=True)
    # Interrupt again later if the scope is still running, like the pulse()s
    # after a cancel.
    with state_lock:
      if active:
        deadline_token = _deadline_scheduler.schedule(
            next(retry_delays), _on_timeout
        )

  unregister = (
      token.register_callback(_on_cancel, repeatable=True)
      if token is not None
      else (lambda: None)
  )
  try:
    try:
      if timeout is not None:
        # Hold state_lock so that the interrupt cannot land inside schedule(),
        # and _on_timeout cannot replace deadline_token before it is set.
        with state_lock:
          deadline_token = _deadline_scheduler.schedule(timeout, _on_timeout)
      yield
    except asyncio.CancelledError as exc:
      # Usually our _OperationInterrupt, but asyncio can replace it with a plain
      # CancelledError: if the interrupt lands in a task that is awaited through
      # asyncio.shield(), the awaiter gets a new CancelledError instead.
      if timed_out and (token is None or not token.is_cancelled):
        # Include the notes that the interrupted code added while unwinding,
        # e.g., the output that idapython_eval captured before the timeout.
        raise ToolTimeoutError(
            _with_notes(f"Operation timed out after {timeout:.2f}s", exc)
        ) from exc
      if isinstance(exc, _OperationInterrupt):
        raise asyncio.CancelledError("Tool cancelled") from exc
      raise
  finally:
    # A cancellation/timeout callback on another thread may have called
    # PyThreadState_SetAsyncExc just before we acquired state_lock. Loop until
    # each cleanup step completes so a late _OperationInterrupt delivered inside
    # finally cannot abort cleanup mid-way.
    late_interrupt = False
    while True:
      try:
        with state_lock:
          active = False
        break
      except _OperationInterrupt:
        late_interrupt = True
    while True:
      try:
        if deadline_token is not None:
          _deadline_scheduler.cancel(deadline_token)
        break
      except _OperationInterrupt:
        late_interrupt = True
    while True:
      try:
        unregister()
        break
      except _OperationInterrupt:
        late_interrupt = True
    if native_ida_cancel:
      while True:
        try:
          with contextlib.suppress(Exception):
            ida_kernwin.clr_cancelled()
          break
        except _OperationInterrupt:
          late_interrupt = True
    if token is not None:
      _cancel_tls.active_token = prev_token
    if late_interrupt:
      if timed_out and (token is None or not token.is_cancelled):
        raise ToolTimeoutError(f"Operation timed out after {timeout:.2f}s")
      raise asyncio.CancelledError("Tool cancelled")


def _unwrap_annotated(tp: Any) -> Any:
  """Unwrap Annotated types to retrieve underlying target type."""
  while get_origin(tp) is Annotated:
    args = get_args(tp)
    if not args:
      break
    tp = args[0]
  return tp


@functools.cache
def _get_dataclass_init_types(cls: type[Any]) -> dict[str, Any]:
  """Cache resolved type hints for dataclass fields where init=True."""
  try:
    hints = typing.get_type_hints(cls)
  except Exception:
    hints = {}
  return {
      f.name: hints.get(f.name, f.type)
      for f in dataclasses.fields(cls)
      if f.init
  }


@functools.cache
def _get_collection_builder(origin: type[Any]) -> Callable[[Any], Any]:
  """Return constructor/builder for sequence and collection types."""
  if issubclass(origin, tuple):
    return tuple
  if issubclass(origin, frozenset):
    return frozenset
  if issubclass(origin, (set, Set)):
    return set
  if not inspect.isabstract(origin) and origin not in (
      Sequence,
      MutableSequence,
      Iterable,
      Collection,
  ):
    with contextlib.suppress(Exception):
      _ = origin([])
      return origin
  return list


def _coerce_dataclass_value(expected_type: Any, value: Any) -> Any:
  """Recursively coerce dicts/sequences into dataclass instances."""
  if value is None:
    return None

  tp = _unwrap_annotated(expected_type)
  origin = get_origin(tp) or tp
  args = get_args(tp)

  # 1. Handle Unions & Optionals
  if origin in (Union, types.UnionType):
    for arg in args:
      try:
        coerced = _coerce_dataclass_value(arg, value)
        if coerced is not value:
          return coerced
      except Exception:
        continue
    return value

  # 2. Handle Literal validation
  if origin is Literal:
    if value in args:
      return value
    raise ValueError(f"Value {value!r} is not one of {args!r}")

  # 3. Handle Dataclass instances (with init=False and ClassVar filtering)
  if dataclasses.is_dataclass(target := tp) and isinstance(target, type):
    if isinstance(value, dict):
      field_types = _get_dataclass_init_types(target)
      return target(**{
          k: _coerce_dataclass_value(field_types[k], v)
          for k, v in value.items()
          if k in field_types
      })
    return value

  # 4. Handle Sequences, Iterables, and Collections
  if (
      isinstance(origin, type)
      and issubclass(origin, Iterable)
      and not issubclass(origin, (str, bytes, bytearray, Mapping))
  ):
    if isinstance(value, Iterable) and not isinstance(
        value, (str, bytes, bytearray, Mapping)
    ):
      # Handle Fixed-length tuples (e.g. tuple[int, str], tuple[Item, int])
      if issubclass(origin, tuple) and args and args[-1] is not Ellipsis:
        val_list = list(value)
        if len(val_list) != len(args):
          raise ValueError(
              f"Expected {len(args)} items for tuple, got {len(val_list)}"
          )
        return tuple(
            _coerce_dataclass_value(arg_tp, item)
            for arg_tp, item in zip(args, val_list)
        )

      # Handle Variable-length sequences (list[T], tuple[T, ...], set[T],
      # frozenset[T], Iterable[T], deque[T], etc.)
      item_type = args[0] if args and args[0] is not Ellipsis else Any
      coerced_items = [
          _coerce_dataclass_value(item_type, item) for item in value
      ]

      builder = _get_collection_builder(origin)
      if builder in (set, frozenset):
        try:
          return builder(coerced_items)
        except TypeError:
          # Graceful fallback for unhashable items (e.g. mutable @dataclass)
          return coerced_items
      return builder(coerced_items)
    return value

  # 5. Handle Mappings (dict, Mapping) with key and value coercion
  if (
      isinstance(origin, type)
      and issubclass(origin, Mapping)
      and isinstance(value, Mapping)
  ):
    key_type = args[0] if len(args) >= 1 else Any
    val_type = args[1] if len(args) >= 2 else Any
    return {
        _coerce_dataclass_value(key_type, k): _coerce_dataclass_value(
            val_type, v
        )
        for k, v in value.items()
    }

  return value


def adapt_arguments(func: Callable[..., Any]) -> Callable[..., Any]:
  """Coerce incoming arguments using resolved runtime type hints."""
  sig = inspect.signature(func)

  # Resolves string annotations when `from __future__ import annotations` is
  # used
  try:
    type_hints = typing.get_type_hints(func)
  except TypeError:
    type_hints = {
        k: v.annotation
        for k, v in sig.parameters.items()
        if v.annotation is not inspect.Parameter.empty
    }

  if not type_hints:
    return func

  @functools.wraps(func)
  def wrapper(*args: Any, **kwargs: Any) -> Any:
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    for name, value in bound.arguments.items():
      if name in type_hints:
        bound.arguments[name] = _coerce_dataclass_value(type_hints[name], value)
    return func(*bound.args, **bound.kwargs)

  wrapper.__signature__ = sig  # type: ignore
  wrapper.__annotations__ = getattr(func, "__annotations__", {})
  return wrapper


def _retrieve_exception(future: asyncio.Future[Any]) -> None:
  """Retrieves a done future's exception, if any, so asyncio won't log it."""
  if not future.cancelled():
    future.exception()


def jsonrpc(func: Callable[..., Any]) -> Callable[..., Any]:
  """Decorator to register a function as a JSON-RPC method."""
  func.unsafe = getattr(func, "unsafe", False)

  if inspect.iscoroutinefunction(func):
    validated_func = adapt_arguments(func)
    validated_func.unsafe = func.unsafe
    # Coroutine functions can be canceled directly, we don't need to wrap it.
    return rpc_registry.register(validated_func)
  if getattr(func, "is_ida_tool", False):
    rpc_func = func
  else:

    @functools.wraps(func)
    def _func(*args, **kwargs) -> Any:
      token = get_cancellation_token()
      with cancellation_profile(token):
        return func(*args, **kwargs)

    _func.__signature__ = inspect.signature(func)  # type: ignore
    _func.__annotations__ = getattr(func, "__annotations__", {})
    rpc_func = _func

  validated_rpc_func = adapt_arguments(rpc_func)

  @functools.wraps(rpc_func)
  async def wrapper(*args, **kwargs):
    cancel_token = CancellationToken()
    var_token = cancellation_token_var.set(cancel_token)
    if getattr(rpc_func, "is_ida_tool", False):
      result = validated_rpc_func(*args, **kwargs)
      if not inspect.isawaitable(result):
        cancellation_token_var.reset(var_token)
        return result
      op_future = asyncio.ensure_future(result)
    else:
      loop = asyncio.get_running_loop()
      ctx = contextvars.copy_context()
      op_future = loop.run_in_executor(
          None, functools.partial(ctx.run, validated_rpc_func, *args, **kwargs)
      )
    try:
      return await asyncio.shield(op_future)
    except asyncio.CancelledError:
      # asyncio logs exceptions that are never retrieved, and a cancelled
      # shield() stops tracking op_future. Retrieve op_future's exception when
      # it ends, even if it ends just as a second cancel cuts the wait short.
      op_future.add_done_callback(_retrieve_exception)
      cancel_token.cancel()
      try:
        for delay in _pulse_delays():
          done, _ = await asyncio.wait((op_future,), timeout=delay)
          if done:
            break
          cancel_token.pulse()
      except asyncio.CancelledError:
        # Cancelled again, e.g., by RPCServer.close() at shutdown: stop
        # waiting, and cancel op_future. That doesn't stop the call, but a
        # task left waiting for IDA's main thread would stay pending, and
        # asyncio logs an error when a pending task is destroyed.
        op_future.cancel()
        raise
      raise
    finally:
      cancellation_token_var.reset(var_token)

  wrapper.__signature__ = inspect.signature(func)  # type: ignore
  wrapper.__annotations__ = getattr(func, "__annotations__", {})
  wrapper.unsafe = func.unsafe  # type: ignore
  wrapper.sync_call = getattr(func, "sync_call", func)  # type: ignore

  return rpc_registry.register(wrapper)


def unsafe(func: Callable[..., Any]) -> Callable[..., Any]:
  func.unsafe = True
  return func


def internal(func: Callable[..., Any]) -> Callable[..., Any]:
  """Marks a tool as internal to prevent proxy generator from exposing it."""
  func.is_internal = True
  return func


skip_proxy = internal
