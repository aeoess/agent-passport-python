"""Strict new-write I-JSON validation followed by RFC 8785 canonicalization."""

from __future__ import annotations

import math
import json

from ..canonical import canonicalize_jcs


class IJsonValidationError(TypeError):
    """An in-memory value cannot be represented as an APS new-write I-JSON value."""


def _assert_scalar_string(value: str, path: str) -> None:
    for char in value:
        if 0xD800 <= ord(char) <= 0xDFFF:
            raise IJsonValidationError(f"{path}: unpaired UTF-16 surrogate")


class _IJsonWalkExit:
    """Stack marker for leaving a list or dict during `assert_i_json`."""

    __slots__ = ("identity",)

    def __init__(self, identity: int) -> None:
        self.identity = identity


def assert_i_json(value, path: str = "$", ancestors: set[int] | None = None) -> None:
    """Validate without converting custom objects, keys, dates, or missing values.

    Iterative, with an explicit stack, rather than one Python call per nesting
    level: a receipt result several hundred levels deep exhausted the call
    stack here before this check ever reached a schema. A dict's own key is
    validated at the moment its value is about to be visited, and the exit
    marker below removes a container's id from `ancestors` only after every
    one of its own children has been visited, so a document with more than
    one fault still names the same first fault this function found before,
    in the same left-to-right, depth-first order a recursive walk visits it.
    """
    if ancestors is None:
        ancestors = set()

    stack: list = []

    def visit(current, current_path: str) -> None:
        if current is None or type(current) is bool:
            return
        if type(current) is str:
            _assert_scalar_string(current, current_path)
            return
        if type(current) is int:
            if abs(current) > 9_007_199_254_740_991:
                raise IJsonValidationError(f"{current_path}: integer exceeds the interoperable IEEE 754 range")
            return
        if type(current) is float:
            if not math.isfinite(current):
                raise IJsonValidationError(f"{current_path}: non-finite number")
            if current.is_integer() and abs(current) > 9_007_199_254_740_991:
                raise IJsonValidationError(f"{current_path}: integer exceeds the interoperable IEEE 754 range")
            return
        if type(current) not in (list, dict):
            raise IJsonValidationError(f"{current_path}: unsupported {type(current).__name__}")
        identity = id(current)
        if identity in ancestors:
            raise IJsonValidationError(f"{current_path}: cyclic value")
        ancestors.add(identity)
        stack.append(_IJsonWalkExit(identity))
        if type(current) is list:
            for index, item in reversed(list(enumerate(current))):
                stack.append(("value", item, f"{current_path}[{index}]"))
        else:
            for key, item in reversed(list(current.items())):
                stack.append(("dict_item", key, item, current_path))

    visit(value, path)
    while stack:
        item = stack.pop()
        if type(item) is _IJsonWalkExit:
            ancestors.discard(item.identity)
            continue
        if item[0] == "value":
            _, sub, sub_path = item
            visit(sub, sub_path)
        else:
            _, key, sub, parent_path = item
            if not isinstance(key, str):
                raise IJsonValidationError(f"{parent_path}: object key is not a string")
            _assert_scalar_string(key, f"{parent_path} key")
            visit(sub, f"{parent_path}.{key}")


def strict_jcs(value) -> str:
    assert_i_json(value)
    return canonicalize_jcs(value)


def parse_strict_i_json(raw: str, max_utf8_bytes: int = 1_048_576, max_depth: int = 128):
    """Parse bounded raw JSON while rejecting decoded duplicate member names."""
    if type(raw) is not str:
        raise IJsonValidationError("$: raw JSON string required")
    if type(max_utf8_bytes) is not int or max_utf8_bytes < 1 or len(raw.encode("utf-8", "surrogatepass")) > max_utf8_bytes:
        raise IJsonValidationError("$: raw JSON size limit exceeded")
    if type(max_depth) is not int or max_depth < 1:
        raise IJsonValidationError("$: invalid depth limit")

    def pairs_hook(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise IJsonValidationError("$: duplicate object member")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw,
            object_pairs_hook=pairs_hook,
            parse_constant=lambda token: (_ for _ in ()).throw(IJsonValidationError(f"$: invalid number {token}")),
        )
    except IJsonValidationError:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise IJsonValidationError("$: invalid JSON") from exc

    def check_depth(item, depth=1):
        if depth > max_depth:
            raise IJsonValidationError("$: JSON nesting limit exceeded")
        if type(item) is list:
            for child in item:
                check_depth(child, depth + 1)
        elif type(item) is dict:
            for child in item.values():
                check_depth(child, depth + 1)

    check_depth(value)
    assert_i_json(value)
    return value


def assert_exact_keys(value: dict, allowed: set[str], required: set[str], name: str) -> None:
    if not isinstance(value, dict):
        raise IJsonValidationError(f"{name}: object required")
    unknown = set(value) - allowed
    if unknown:
        raise IJsonValidationError(f"{name}: unknown field {sorted(unknown)[0]}")
    missing = required - set(value)
    if missing:
        raise IJsonValidationError(f"{name}: missing field {sorted(missing)[0]}")
