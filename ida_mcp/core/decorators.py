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

"""Decorators and cancellation support for JSON-RPC methods."""

import asyncio
from collections.abc import Collection
from collections.abc import Iterable
from collections.abc import Mapping
from collections.abc import MutableSequence
from collections.abc import Sequence
from collections.abc import Set
import contextlib
import contextvars
import dataclasses
import functools
import inspect
import logging
import sys
import threading
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
from ida_mcp.core.interrupt import ToolInterrupt
from ida_mcp.core.rpc_registry import rpc_registry

logger = logging.getLogger(__name__)


class CancellationToken:
  """Thread-safe token managing cancellation state and callbacks."""

  def __init__(self):
    self._is_cancelled = False
    self._callbacks: list[Callable[[], Any]] = []
    self._lock = threading.Lock()

  @property
  def is_cancelled(self) -> bool:
    return self._is_cancelled

  def is_set(self) -> bool:
    """Compatibility method matching asyncio.Event / threading.Event."""
    return self._is_cancelled

  def register_callback(self, cb: Callable[[], Any]) -> Callable[[], None]:
    """Registers a cancellation callback.

    If the token is already cancelled, the callback is invoked immediately.

    Args:
      cb: The zero-argument callback to invoke on cancellation.

    Returns:
      A cleanup function that unregisters the callback.
    """
    with self._lock:
      is_cancelled = self._is_cancelled
      if not is_cancelled:
        self._callbacks.append(cb)

    if is_cancelled:
      try:
        cb()
      except (Exception, asyncio.CancelledError) as e:  # pylint: disable=broad-exception-caught
        logger.warning("Error invoking immediate cancellation callback: %s", e)
      return lambda: None

    def unregister() -> None:
      with self._lock:
        if cb in self._callbacks:
          self._callbacks.remove(cb)

    return unregister

  def cancel(self) -> None:
    """Cancels the token and invokes all registered callbacks."""
    with self._lock:
      if self._is_cancelled:
        return
      self._is_cancelled = True
      callbacks = list(self._callbacks)
      self._callbacks.clear()

    for cb in callbacks:
      try:
        cb()
      except (Exception, asyncio.CancelledError) as e:  # pylint: disable=broad-exception-caught
        logger.warning("Error invoking cancellation callback: %s", e)

  def set(self) -> None:
    """Alias for cancel() to match asyncio.Event interface."""
    self.cancel()


cancellation_token_var: contextvars.ContextVar[CancellationToken | None] = (
    contextvars.ContextVar("cancellation_token", default=None)
)

# Backwards compatibility alias
cancel_event_var = cancellation_token_var


def get_cancellation_token() -> CancellationToken | None:
  """Retrieves the active cancellation token for the current context."""
  return cancellation_token_var.get()


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


def make_cancellation_profile_func(
    token: CancellationToken,
) -> Callable[[Any, str, Any], None]:
  """Creates a profile function tagged as an ida_mcp canceller."""

  def _profile_func(unused_frame, unused_event, unused_arg) -> None:
    if token.is_cancelled:
      # Raising an exception automatically sets the profile function to None.
      # ToolInterrupt is a CancelledError that guarded user code re-raises.
      raise ToolInterrupt("Tool cancelled")

  _profile_func.is_ida_mcp_canceller = True  # type: ignore
  _profile_func.token = token  # type: ignore
  return _profile_func


def is_ida_mcp_canceller(
    func: Any, token: CancellationToken | None = None
) -> bool:
  """Fast check using direct attribute access."""
  try:
    return (
        func is not None
        and func.is_ida_mcp_canceller
        and (token is None or func.token is token)
    )
  except AttributeError:
    return False


@contextlib.contextmanager
def cancellation_profile(token: CancellationToken | None):
  """Context manager that installs a cancellation profile hook idempotently."""
  if token is None:
    yield
    return

  curr = sys.getprofile()
  if is_ida_mcp_canceller(curr, token):
    # Already protected by an active cancellation hook for this exact token
    yield
    return

  prof_func = make_cancellation_profile_func(token)
  sys.setprofile(prof_func)
  try:
    yield
  finally:
    sys.setprofile(curr)


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
    try:
      if getattr(rpc_func, "is_ida_tool", False):
        result = validated_rpc_func(*args, **kwargs)
        if inspect.isawaitable(result):
          return await result
        return result
      return await asyncio.to_thread(validated_rpc_func, *args, **kwargs)
    except asyncio.CancelledError:
      cancel_token.cancel()
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
