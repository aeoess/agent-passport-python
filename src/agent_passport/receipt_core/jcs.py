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


def assert_i_json(value, path: str = "$", ancestors: set[int] | None = None) -> None:
    """Validate without converting custom objects, keys, dates, or missing values."""
    if ancestors is None:
        ancestors = set()
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        _assert_scalar_string(value, path)
        return
    if type(value) is int:
        if abs(value) > 9_007_199_254_740_991:
            raise IJsonValidationError(f"{path}: integer exceeds the interoperable IEEE 754 range")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise IJsonValidationError(f"{path}: non-finite number")
        if value.is_integer() and abs(value) > 9_007_199_254_740_991:
            raise IJsonValidationError(f"{path}: integer exceeds the interoperable IEEE 754 range")
        return
    if type(value) not in (list, dict):
        raise IJsonValidationError(f"{path}: unsupported {type(value).__name__}")
    identity = id(value)
    if identity in ancestors:
        raise IJsonValidationError(f"{path}: cyclic value")
    ancestors.add(identity)
    if type(value) is list:
        for index, item in enumerate(value):
            assert_i_json(item, f"{path}[{index}]", ancestors)
    else:
        for key, item in value.items():
            if not isinstance(key, str):
                raise IJsonValidationError(f"{path}: object key is not a string")
            _assert_scalar_string(key, f"{path} key")
            assert_i_json(item, f"{path}.{key}", ancestors)
    ancestors.remove(identity)


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
