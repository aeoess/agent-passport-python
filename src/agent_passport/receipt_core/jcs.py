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


class _SnapshotListFrame:
    __slots__ = ("identity", "items", "index", "out")

    def __init__(self, items: list) -> None:
        self.identity = id(items)
        self.items = items
        self.index = 0
        self.out: list = []


class _SnapshotDictFrame:
    __slots__ = ("identity", "keys", "obj", "index", "out", "pending_key")

    def __init__(self, obj: dict) -> None:
        self.identity = id(obj)
        self.keys = list(obj.keys())
        self.obj = obj
        self.index = 0
        self.out: dict = {}
        self.pending_key: object = None


_SNAPSHOT_MISSING = object()


def snapshot_i_json_shape(value):
    """Return an independent copy of `value`, rebuilding only the container
    shapes I-JSON admits (exact `list` and exact `dict`). Anything else,
    including a `list` or `dict` subclass, is returned by reference rather
    than copied: it is not one of the shapes this function reconstructs, the
    same way `assert_i_json`'s exact-type dispatch does not walk into it, and
    whatever calls this alongside `assert_i_json` rejects it regardless, so
    aliasing it here changes nothing observable.

    Iterative, with an explicit stack, in place of `copy.deepcopy`, which
    recurses once per nesting level. A receipt or supporting record whose
    result or body nests a few hundred levels deep overflowed the call stack
    here, the same way `assert_i_json` and `canonicalize_jcs` did before they
    were made iterative, and independently of that fix: this function runs
    before either of them in `receipt_core.receipt.create_receipt_v1`, and
    after both in `receipt_id_payload_v1` and its neighbours, but never
    through them.

    Detects a genuine cycle (a container that contains itself, directly or
    through another container) the same way `assert_i_json` does, and raises
    the same `IJsonValidationError`: a cyclic value was always going to be
    rejected by the I-JSON check that runs beside every caller of this
    function, so this only moves where that rejection happens, never what it
    is.
    """
    if type(value) not in (list, dict):
        return value
    ancestors: set[int] = set()
    root_frame = _SnapshotListFrame(value) if type(value) is list else _SnapshotDictFrame(value)
    ancestors.add(root_frame.identity)
    stack: list = [root_frame]
    result_from_child = _SNAPSHOT_MISSING
    while stack:
        frame = stack[-1]
        if isinstance(frame, _SnapshotListFrame):
            if result_from_child is not _SNAPSHOT_MISSING:
                frame.out.append(result_from_child)
                result_from_child = _SNAPSHOT_MISSING
            if frame.index >= len(frame.items):
                stack.pop()
                ancestors.discard(frame.identity)
                result_from_child = frame.out
                continue
            item = frame.items[frame.index]
            frame.index += 1
            if type(item) in (list, dict):
                item_id = id(item)
                if item_id in ancestors:
                    raise IJsonValidationError("$: cyclic value")
                ancestors.add(item_id)
                stack.append(_SnapshotListFrame(item) if type(item) is list else _SnapshotDictFrame(item))
            else:
                frame.out.append(item)
        else:
            if result_from_child is not _SNAPSHOT_MISSING:
                frame.out[frame.pending_key] = result_from_child
                frame.pending_key = None
                result_from_child = _SNAPSHOT_MISSING
            if frame.index >= len(frame.keys):
                stack.pop()
                ancestors.discard(frame.identity)
                result_from_child = frame.out
                continue
            key = frame.keys[frame.index]
            frame.index += 1
            item = frame.obj[key]
            if type(item) in (list, dict):
                item_id = id(item)
                if item_id in ancestors:
                    raise IJsonValidationError("$: cyclic value")
                ancestors.add(item_id)
                frame.pending_key = key
                stack.append(_SnapshotListFrame(item) if type(item) is list else _SnapshotDictFrame(item))
            else:
                frame.out[key] = item
    return result_from_child


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
