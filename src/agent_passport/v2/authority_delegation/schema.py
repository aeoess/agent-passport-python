# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Closed-schema shape validation and the two canonical-value predicates.

Python port of the TypeScript SDK's src/v2/authority-delegation/schema.ts.

Every JSON type test below is exact (``type(v) is str``, ``type(v) is int``,
``type(v) is list``, ``type(v) is dict``) rather than ``isinstance``, so that a
Python ``bool`` (a subclass of ``int``) or ``float`` never passes as one of
this schema's integers: ``depth.remaining`` written as ``2.0`` or
``reputation.ceiling`` written as ``80.0`` or ``True`` is rejected. The
TypeScript SDK also rejects ``true`` where an integer is required, but has
no way to see the difference between an integer-valued float such as
``80.0`` and the integer ``80`` (a JavaScript number carries no separate
integer/float tag). For that one case this is a deliberate, fail-closed
difference from the TypeScript SDK's ``Number.isInteger`` check, kept
because Python happens to be able to tell the difference, not because the
draft asks for it.

``_has_non_i_json_value`` below applies the same exact-type rule to the
whole record, recursively: the values it checks are exactly the values RFC
8785 JCS canonicalizes and Ed25519 signs, so a dict, list or str subclass
(``collections.OrderedDict``, a tuple, a custom str subclass, and so on) is
not plain JSON data and is rejected wherever it appears, not walked as the
object, array or string it merely resembles.

No timestamp in this module is ever parsed with ``datetime``: canonical
timestamps are validated and compared as strings, using integer calendar
arithmetic for the day-of-month bound.
"""

from __future__ import annotations

import math
import re

from .scope import grants_are_canonical
from .types import (
    AUTHORITY_DELEGATION_RECORD_TYPE,
    AUTHORITY_DELEGATION_VERSION,
    REPUTATION_PROFILE_V1,
    REVERSIBILITY_PROFILE_V1,
    SCOPE_PROFILE_V1,
    VALUES_PROFILE_V1,
    AuthorityFailure,
)

_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_128 = re.compile(r"^[0-9a-f]{128}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_MAX_QUANTITY = 9223372036854775807

# RFC 3339 exact UTC-millisecond form. Group 1 = year, 2 = month, 3 = day,
# 4 = hour, 5 = minute, 6 = second. A second of 60 is valid only at 23:59 on
# the last day of its month, in the proleptic Gregorian calendar: RFC 3339
# section 5.7 admits time-second 60 only for a leap second, and Appendix D
# writes one as "YYYY-MM-DDT23:59:60Z". That restriction is checked below
# with integer arithmetic on these captured digits, never datetime; every
# other second stays 00 through 59, already bounded by this pattern.
_CANONICAL_TIMESTAMP = re.compile(
    r"^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)\.[0-9]{3}Z$"
)
_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_leap_year(year: int) -> bool:
    """Proleptic Gregorian leap year, so year 0000 is a leap year."""
    return (year % 4 == 0 and year % 100 != 0) or year % 400 == 0


def _record(value) -> dict | None:
    return value if type(value) is dict else None


def _exact_keys(value: dict, expected) -> bool:
    """True when value's key set is exactly expected.

    Compares as sets, not sorted lists: a dict built directly in Python (as
    opposed to one decoded from JSON, whose keys are always strings) can carry
    a non-string key, and sorting a mix of strings and other hashable types
    raises TypeError. A structurally malformed object like that should fail
    this check the same way a normal extra or missing key would, not crash
    the caller, so the comparison here only ever hashes and compares for
    equality, never orders.
    """
    return set(value) == set(expected)


def _is_surrogate_or_noncharacter(code_point: int) -> bool:
    """True for a UTF-16 surrogate or an RFC 7493 section 2.1 noncharacter.

    Noncharacters are U+FDD0 through U+FDEF, plus every code point whose low
    16 bits are FFFE or FFFF (one pair per plane, 17 planes: U+FFFE, U+FFFF,
    U+1FFFE, U+1FFFF, ... U+10FFFE, U+10FFFF), 66 code points in total.

    This is a per-code-point predicate, not a per-string one: it replaces the
    old well-formed-Unicode check (which walked UTF-16 code units, because
    JavaScript strings are UTF-16 sequences) with the building block the
    whole-record walk in validate_authority_delegation_shape uses instead. A
    surrogate code point can never legitimately occur in a value json.loads
    produced (a well-formed \\uD800\\uDC00 escape pair is combined into its
    single astral code point before this ever runs, and a lone \\uD800 has no
    other source there), but a plain Python str can still be built outside a
    JSON decoder by, for instance, concatenating chr(0xD800) and chr(0xDC00)
    as two separate code points rather than the one combined code point a
    decoder would have produced from the same pair. This code-point-by-code-point
    scan cannot tell that apart from a genuinely unpaired surrogate the way the
    TypeScript SDK's UTF-16 pair walk can, so it fails closed: such a string is
    rejected here even where the TypeScript SDK, walking UTF-16 code units,
    would see a valid pair and accept it.
    """
    return (
        0xD800 <= code_point <= 0xDFFF
        or 0xFDD0 <= code_point <= 0xFDEF
        or (code_point & 0xFFFE) == 0xFFFE
    )


class _LeaveContainer:
    """Legacy internal-marker type, kept only as an ordinary unrecognized
    type for _has_non_i_json_value's walk to reject, never again as a
    control signal.

    Before this fix, an exit signal was a fresh instance of this class,
    identified on the walk's own stack by type(current) is _LeaveContainer.
    A value of that exact type, placed anywhere in a record wherever an
    ordinary value is walked, was then popped as if it were the walk's own
    signal to leave a container, which could clear a real container's id
    from path_ids while that container's subtree was still being walked,
    defeating cycle detection and making the walk loop forever on a
    self-referential container.

    The walk below no longer inspects any value's type against this class
    at all; its exit signal is tracked out of band instead, as a (payload,
    is_exit) pair never taken from the record. An instance of this class
    therefore now carries no special meaning: met as a value, it falls to
    the walk's catch-all case, exactly like a set or a bytes object.
    """

    __slots__ = ("container_id",)

    def __init__(self, container_id: int) -> None:
        self.container_id = container_id


def _has_non_i_json_value(value) -> bool:
    """True if value, or anything nested inside it, is not plain JSON data.

    The values this checks are exactly the values RFC 8785 JCS canonicalizes
    and Ed25519 signs, so every one of them is tested by its exact runtime
    type, never by what it merely behaves like, can be iterated as, or can
    be read through: a value counts as an object, an array, a string, a
    number or a boolean only when ``type(v) is dict``, ``type(v) is list``,
    ``type(v) is str``, ``type(v) is int``/``type(v) is float``, or
    ``type(v) is bool`` says so. A dict, list or str subclass
    (``collections.OrderedDict``, a tuple, a custom str subclass, and so on)
    is not plain JSON data and stops the walk right there, exactly as a set
    or a bytes object does; the walk never falls back to isinstance and
    never reads such a value as the object, array or string it resembles.
    A dict's own keys are held to the same rule: a key is only ever examined
    as a string when ``type(key) is str``.

    A string is not plain JSON data if it contains a UTF-16 surrogate or an
    RFC 7493 section 2.1 noncharacter code point (checked per string, at any
    depth, including inside a nested object whose own "profile" field names
    a profile this package does not support: an unsupported profile does
    not stop this walk from covering the rest of that object). A float is
    not plain JSON data unless it is finite. An int is not plain JSON data
    if converting it to float overflows (``float(value)`` raising
    ``OverflowError``): every JSON number this package signs is
    canonicalized as an IEEE 754 double, so an integer literal too large for
    that (for example a 400-digit number, which an unbounded-precision JSON
    parser would otherwise decode exactly) is rejected here rather than
    signed as a value no other implementation would derive the same bytes
    from. ``None`` is plain JSON data (JSON null).

    The walk is iterative, using an explicit stack rather than recursion. It
    tracks, in ``path_ids``, the id() of every dict or list currently on the
    walk's own path from the root, pushing an exit signal right after
    entering one and discarding its id when that signal is popped back off:
    a container that contains itself at any depth (its id is still on the
    path when the walk reaches it again) is not plain JSON data.

    A container reached a second time off the current path (through a
    second reference held elsewhere in the record, not through a cycle) is
    not walked again: once a container's own exit signal has popped with no
    failure found anywhere in its subtree, its id() is recorded in
    ``clean``, and any later reference to that same object, found while its
    id is not on the current path, is accepted without visiting its members
    a second time. This is safe only because every container this walk
    still holds a reference to (on the stack, or nested inside a container
    still on the stack) stays alive for the whole call, so no id() can be
    reused by an unrelated object before the walk finishes with it. Without
    this, a record built from repeated sharing (``node_i = [node_(i-1),
    node_(i-1)]``, plain JSON, no cycle) has as many distinct containers as
    its depth but a number of root-to-leaf paths that doubles with every
    level, and re-walking every reference from scratch costs time and
    memory exponential in that depth; remembering each container already
    walked clean makes the cost linear in the number of distinct containers
    and their members instead.

    A string reached more than once is checked only the first time, whether
    it is reached as a value or as a dict key. Unlike a dict or a list, a
    string is never pushed back onto the stack as its own exit signal, so
    there is no path/clean distinction for it: once a string's id() has
    been checked and found well formed, it is recorded in
    ``checked_strings``, and any later reference to that same object, found
    anywhere else in the record, skips the character scan entirely (a string
    cannot contain itself, so there is no cycle to detect the way a
    container needs one). pickle keeps a repeated str as one object
    referenced from every slot that held it, so a value held by 10,000
    references to the same 100,000-character string, or 10,000 dicts that
    all use that same string as a key, used to cost one full scan of that
    string per reference, because a string is not a container and so never
    earned the container id() memo above; remembering the id() of every
    string already checked, key or value, makes the cost of this walk
    linear in the number of distinct string objects and their combined
    length instead. This is safe for the same reason the container memo
    above is: every string this walk has ever seen is still reachable from
    ``value``, the record this call was given, for the whole call, so no
    id() it records can be reused by an unrelated string before the walk
    finishes.

    That exit signal is kept out of band, never mixed into the stack as a
    value that could be confused with one from the record. Every stack entry
    is a ``(payload, is_exit)`` pair: a value taken from the record itself is
    always pushed as ``(item, False)``, and the only ``(payload, True)``
    pairs on the stack are the ones this function pushes itself, right after
    entering a dict or list, with that container's own id() as payload. A
    value from the record is therefore only ever inspected from the
    ``is_exit`` False side of that pair, whatever it is shaped like,
    including a dict or list that itself holds something that looks like one
    of this walk's own exit signals (an id paired with ``True``): such a
    thing is just a value nested one level deeper, read out as ``(that
    tuple, False)``, and it falls to the catch-all case below, rejected as
    not plain data the same as a set or a bytes object, never mistaken for a
    signal that pops a path id. It never raises.
    """

    def is_ill_formed_string(text) -> bool:
        return any(_is_surrogate_or_noncharacter(ord(ch)) for ch in text)

    stack: list[tuple] = [(value, False)]
    path_ids: set[int] = set()
    clean: set[int] = set()
    checked_strings: set[int] = set()
    while stack:
        current, is_exit = stack.pop()
        if is_exit:
            path_ids.discard(current)
            clean.add(current)
            continue
        if type(current) is str:
            identity = id(current)
            if identity in checked_strings:
                continue
            if is_ill_formed_string(current):
                return True
            checked_strings.add(identity)
        elif type(current) is dict:
            identity = id(current)
            if identity in path_ids:
                return True
            if identity in clean:
                continue
            path_ids.add(identity)
            stack.append((identity, True))
            for key, item in current.items():
                if type(key) is not str:
                    return True
                key_identity = id(key)
                if key_identity not in checked_strings:
                    if is_ill_formed_string(key):
                        return True
                    checked_strings.add(key_identity)
                stack.append((item, False))
        elif type(current) is list:
            identity = id(current)
            if identity in path_ids:
                return True
            if identity in clean:
                continue
            path_ids.add(identity)
            stack.append((identity, True))
            for item in current:
                stack.append((item, False))
        elif type(current) is bool:
            pass
        elif type(current) is int:
            try:
                float(current)
            except OverflowError:
                return True
        elif type(current) is float:
            if not math.isfinite(current):
                return True
        elif current is None:
            pass
        else:
            return True
    return False


def _has_non_str_key(value) -> bool:
    """True if a dict anywhere in value carries a key whose type is not exactly str.

    This runs before validate_authority_delegation_shape does anything else
    with the record: a Python dict lookup (``top.get(...)``, the exact-keys
    set comparison, a facet's own ``.get(...)``) hashes the probe key and,
    only on a hash collision, compares it against whatever key is already
    stored in that slot. A caller-supplied key built to hash like a real
    field name (for instance "record_type" or "profile") while raising from
    its own ``__eq__`` can therefore make an ordinary lookup raise instead of
    returning a defined result. This walk finds such a key first, so the
    function can return a coded SCHEMA_INVALID failure before any of that
    happens.

    The walk is iterative, using an explicit stack rather than recursion, and
    it only ever descends into a value whose type is exactly dict or exactly
    list, exactly like _has_non_i_json_value above. It reads each dict's own
    keys with ``for key, item in current.items()``, which returns the keys a
    dict already holds without hashing or comparing any of them again, so
    this walk cannot itself raise from a hostile ``__eq__`` or ``__hash__``.
    A container already visited is not visited again. That bookkeeping keeps
    the walk from looping forever on a self-referential dict or list, and it
    keeps the walk's cost linear on a record built from shared references
    (``node_i = [node_(i-1), node_(i-1)]``), which would otherwise be walked
    once per path, a number that doubles with every level. Deciding whether
    a cycle itself makes the record invalid is _has_non_i_json_value's job,
    run afterward, once this walk has already found every dict lookup in the
    rest of this function safe to perform.
    """
    stack: list = [value]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if type(current) is dict:
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for key, item in current.items():
                if type(key) is not str:
                    return True
                stack.append(item)
        elif type(current) is list:
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for item in current:
                stack.append(item)
    return False


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8", "surrogatepass"))


def is_canonical_timestamp(value) -> bool:
    """RFC 3339 canonical UTC milliseconds, with second 60 valid only at
    23:59 on the last day of a month (RFC 3339 section 5.7; Appendix D).

    A second of 60 is valid only when the hour is 23, the minute is 59, and
    the day is the last day of its month in the proleptic Gregorian
    calendar (RFC 3339 section 5.7; Appendix D's "YYYY-MM-DDT23:59:60Z").
    Every other second-60 timestamp is invalid. Checked with integer
    arithmetic on the captured digits, never datetime.
    """
    if type(value) is not str:
        return False
    match = _CANONICAL_TIMESTAMP.fullmatch(value)
    if not match:
        return False
    year = int(match.group(1))
    month = int(match.group(2))
    day = int(match.group(3))
    hour = match.group(4)
    minute = match.group(5)
    second = match.group(6)
    max_day = 29 if (month == 2 and _is_leap_year(year)) else _DAYS_IN_MONTH[month - 1]
    if day > max_day:
        return False
    if second == "60":
        return hour == "23" and minute == "59" and day == max_day
    return True


def compare_canonical_timestamps(a: str, b: str) -> int:
    """String-order comparison of two canonical timestamps.

    RFC 3339 section 5.1: timestamps in the same format (all UTC "Z", same
    number of fractional digits) sort as strings into time order, so this
    compares the strings directly rather than parsing them into a datetime
    (which has no representation for a leap-second ":60" value: a second of
    60 is valid only at 23:59 on the last day of a month, RFC 3339 section
    5.7 and Appendix D). Defined only for values that have already passed
    is_canonical_timestamp.
    """
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def is_canonical_quantity(value) -> bool:
    if type(value) is not str or not _DECIMAL.fullmatch(value):
        return False
    try:
        return int(value) <= _MAX_QUANTITY
    except ValueError:
        return False


def _is_admissible_identifier(value) -> bool:
    """Any non-empty string, for a spend unit or a values.required entry.

    Draft line 547 calls a values identifier profile-defined, and the draft states no
    grammar for a bounded spend's unit either (line 466 shows one example value,
    "iso4217:USD:minor"). This package previously required both to match the same
    identifier pattern, which made an SDK grammar into a protocol rejection: a record
    carrying a unit or an identifier the draft permits was reported invalid. Both are
    now any non-empty string that the record-wide I-JSON check already admits; a
    profile that wants a narrower form is where that belongs.
    """
    return type(value) is str and len(value) > 0


def _failure(code: str, message: str) -> AuthorityFailure:
    return AuthorityFailure(code=code, message=message)


def validate_authority_delegation_shape(value) -> list[AuthorityFailure]:
    """Closed-schema and canonical-value validation for an in-memory decoded record."""
    top = _record(value)
    if top is None:
        return [_failure("SCHEMA_INVALID", "delegation must be an exact closed v1 object")]

    # Every dict lookup below, starting with the very next line, hashes a
    # fixed literal key and, on a collision, compares it against whatever key
    # is already stored in that slot. This walk finds a non-str key first, so
    # a caller-supplied key that hashes like a real field name while raising
    # from its own __eq__ gets a coded SCHEMA_INVALID failure here rather
    # than an exception out of top.get, the exact-keys comparison, or a
    # facet's own .get.
    if _has_non_str_key(top):
        return [_failure(
            "SCHEMA_INVALID", "record must be I-JSON: no unpaired surrogates, noncharacters, or non-JSON values",
        )]

    # Recognition comes first, and nothing the v1 body schema says is applied to a
    # record this schema does not claim. A non-string record_type or version is
    # invalid, because no recognition is possible at all. A string record_type that is
    # not this one, or this record_type with any other string version, is unsupported,
    # and the record is returned unjudged: no exact-keys check, no facet checks, not
    # even the record-wide I-JSON check, which is part of evaluating the v1 body.
    #
    # Both halves are ruled. Recognition preceding v1 schema evaluation inside the
    # first phase of the draft's order at line 580 is one ruling; an unknown string
    # record_type being unsupported where a non-string one is invalid is another. This
    # module previously judged an unrecognised record_type by the v1 schema and
    # reported an I-JSON failure ahead of an unsupported version, both of which said
    # more than recognition can.
    record_type_value = top.get("record_type")
    version_value = top.get("version")
    if type(record_type_value) is not str or type(version_value) is not str:
        return [_failure("SCHEMA_INVALID", "record_type and version must be strings")]
    if record_type_value != AUTHORITY_DELEGATION_RECORD_TYPE:
        return [_failure(
            "UNSUPPORTED_RECORD_TYPE", "record_type names another record, not judged by this schema",
        )]
    if version_value != AUTHORITY_DELEGATION_VERSION:
        return [_failure("UNSUPPORTED_VERSION", "unsupported authority-delegation version")]

    failures: list[AuthorityFailure] = []
    if not _exact_keys(top, (
        "record_type", "version", "delegation_id", "parent_delegation_id", "issuer",
        "subject", "verification_method", "issued_at", "nonce", "authority", "signature",
    )):
        return [_failure("SCHEMA_INVALID", "delegation must be an exact closed v1 object")]

    if _has_non_i_json_value(top):
        failures.append(_failure(
            "SCHEMA_INVALID", "record must be I-JSON: no unpaired surrogates, noncharacters, or non-JSON values",
        ))

    if type(top["delegation_id"]) is not str or not _ID.fullmatch(top["delegation_id"]):
        failures.append(_failure("SCHEMA_INVALID", "delegation_id must be sha256:<64 lowercase hex>"))
    if top["parent_delegation_id"] is not None and (
        type(top["parent_delegation_id"]) is not str or not _ID.fullmatch(top["parent_delegation_id"])
    ):
        failures.append(_failure("SCHEMA_INVALID", "parent_delegation_id must be null or a delegation digest"))
    # The draft states no maximum length for issuer, subject or verification_method.
    # This 1024 UTF-8 byte cap is this implementation's own ceiling, not a protocol
    # rule: a record that exceeds it is one this implementation declines to judge,
    # reported as RESOURCE_LIMIT and mapped to indeterminate rather than as a schema
    # failure (before this rule, exceeding it was reported as SCHEMA_INVALID, the same
    # as absence or the wrong type, which still is). Absence or the wrong type is still
    # SCHEMA_INVALID.
    for key in ("issuer", "subject", "verification_method"):
        item = top[key]
        if type(item) is not str or len(item) == 0:
            failures.append(_failure("SCHEMA_INVALID", f"{key} must be a non-empty string"))
        elif _utf8_len(item) > 1024:
            failures.append(_failure("RESOURCE_LIMIT", f"{key} exceeds this implementation's 1024-byte ceiling"))
    if not is_canonical_timestamp(top["issued_at"]):
        failures.append(_failure("NONCANONICAL_VALUE", "issued_at must be canonical UTC milliseconds"))
    if type(top["nonce"]) is not str or not _HEX_32.fullmatch(top["nonce"]):
        failures.append(_failure("NONCANONICAL_VALUE", "nonce must be 32 lowercase hex characters"))
    if type(top["signature"]) is not str or not _HEX_128.fullmatch(top["signature"]):
        failures.append(_failure("SCHEMA_INVALID", "signature must be 128 lowercase hex characters"))

    authority = _record(top["authority"])
    if authority is None or not _exact_keys(
        authority, ("scope", "spend", "depth", "time", "reputation", "values", "reversibility")
    ):
        failures.append(_failure("SCHEMA_INVALID", "authority must carry exactly all seven facets"))
        return failures

    scope = _record(authority["scope"])
    if scope is None or type(scope.get("profile")) is not str:
        failures.append(_failure("SCHEMA_INVALID", "scope must contain profile and grants"))
    elif scope["profile"] != SCOPE_PROFILE_V1:
        failures.append(_failure("UNSUPPORTED_PROFILE", "unsupported scope profile"))
    elif (
        not _exact_keys(scope, ("profile", "grants"))
        or type(scope.get("grants")) is not list
        or not all(type(item) is str for item in scope["grants"])
    ):
        failures.append(_failure("SCHEMA_INVALID", "scope must contain profile and grants"))
    elif not grants_are_canonical(scope["grants"]):
        failures.append(_failure("NONCANONICAL_VALUE", "scope grants must be valid, sorted, unique, and irredundant"))

    spend = _record(authority["spend"])
    if spend is None or type(spend.get("mode")) is not str:
        failures.append(_failure("SCHEMA_INVALID", "spend must be a tagged object"))
    elif spend["mode"] == "unbounded":
        if not _exact_keys(spend, ("mode",)):
            failures.append(_failure("SCHEMA_INVALID", "unbounded spend has no other fields"))
    elif spend["mode"] == "bounded":
        if (
            not _exact_keys(spend, ("mode", "unit", "per_action", "cumulative"))
            or not _is_admissible_identifier(spend.get("unit"))
            or not is_canonical_quantity(spend.get("per_action"))
            or not is_canonical_quantity(spend.get("cumulative"))
        ):
            failures.append(_failure("NONCANONICAL_VALUE", "bounded spend fields are malformed"))
        elif int(spend["per_action"]) > int(spend["cumulative"]):
            failures.append(_failure("SCHEMA_INVALID", "spend per_action cannot exceed cumulative"))
    else:
        failures.append(_failure("SCHEMA_INVALID", "unknown spend mode"))

    depth = _record(authority["depth"])
    if (
        depth is None
        or not _exact_keys(depth, ("remaining",))
        or type(depth.get("remaining")) is not int
        or depth["remaining"] < 0
        or depth["remaining"] > 255
    ):
        failures.append(_failure("SCHEMA_INVALID", "depth.remaining must be an integer from 0 through 255"))

    time_facet = _record(authority["time"])
    if (
        time_facet is None
        or not _exact_keys(time_facet, ("not_before", "not_after"))
        or not is_canonical_timestamp(time_facet.get("not_before"))
        or not is_canonical_timestamp(time_facet.get("not_after"))
    ):
        failures.append(_failure("NONCANONICAL_VALUE", "time bounds must be canonical UTC milliseconds"))
    elif time_facet["not_before"] >= time_facet["not_after"]:
        failures.append(_failure("SCHEMA_INVALID", "time window must be non-empty"))
    elif (
        top["parent_delegation_id"] is not None
        and is_canonical_timestamp(top.get("issued_at"))
        and time_facet["not_before"] < top["issued_at"]
    ):
        # The rule binds a delegated child only (draft section 3.2 lines
        # 536-537): "A child's not_before MUST NOT predate its issued_at". A
        # record with a null parent_delegation_id is a root, which the draft
        # does not constrain this way, so it is exempt.
        failures.append(_failure("SCHEMA_INVALID", "time.not_before cannot predate issued_at"))

    reputation = _record(authority["reputation"])
    if reputation is None or type(reputation.get("profile")) is not str:
        failures.append(_failure("SCHEMA_INVALID", "reputation ceiling must be an integer from 0 through 100"))
    elif reputation["profile"] != REPUTATION_PROFILE_V1:
        failures.append(_failure("UNSUPPORTED_PROFILE", "unsupported reputation profile"))
    elif (
        not _exact_keys(reputation, ("profile", "ceiling"))
        or type(reputation.get("ceiling")) is not int
        or reputation["ceiling"] < 0
        or reputation["ceiling"] > 100
    ):
        failures.append(_failure("SCHEMA_INVALID", "reputation ceiling must be an integer from 0 through 100"))

    values = _record(authority["values"])
    if values is None or type(values.get("profile")) is not str:
        failures.append(_failure("SCHEMA_INVALID", "values.required must contain valid identifiers"))
    elif values["profile"] != VALUES_PROFILE_V1:
        failures.append(_failure("UNSUPPORTED_PROFILE", "unsupported values profile"))
    elif (
        not _exact_keys(values, ("profile", "required"))
        or type(values.get("required")) is not list
        or not all(_is_admissible_identifier(item) for item in values["required"])
    ):
        failures.append(_failure("SCHEMA_INVALID", "values.required must contain valid identifiers"))
    else:
        required = values["required"]
        if any(i > 0 and required[i - 1] >= item for i, item in enumerate(required)):
            failures.append(_failure("NONCANONICAL_VALUE", "values.required must be sorted and unique"))

    reversibility = _record(authority["reversibility"])
    if reversibility is None or type(reversibility.get("profile")) is not str:
        failures.append(_failure("SCHEMA_INVALID", "reversibility facet is malformed"))
    elif reversibility["profile"] != REVERSIBILITY_PROFILE_V1:
        failures.append(_failure("UNSUPPORTED_PROFILE", "unsupported reversibility profile"))
    elif (
        not _exact_keys(reversibility, ("profile", "ceiling"))
        or type(reversibility.get("ceiling")) is not str
        or reversibility["ceiling"] not in ("tentative", "compensable", "irreversible")
    ):
        failures.append(_failure("SCHEMA_INVALID", "reversibility facet is malformed"))

    return failures


def is_authority_delegation_v1(value) -> bool:
    return len(validate_authority_delegation_shape(value)) == 0
