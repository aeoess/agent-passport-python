# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Closed-schema shape validation and the two canonical-value predicates.

Python port of the TypeScript SDK's src/v2/authority-delegation/schema.ts.

Every JSON type test below is exact (``type(v) is str``, ``type(v) is int``,
``type(v) is list``, ``type(v) is dict``) rather than ``isinstance``, so that a
Python ``bool`` (a subclass of ``int``) or ``float`` never passes as one of
this schema's integers: ``depth.remaining`` written as ``2.0`` or
``reputation.ceiling`` written as ``80.0`` or ``True`` is rejected, even
though the TypeScript SDK has no way to see that distinction (a JavaScript
number carries no separate integer/float tag). This is a deliberate,
fail-closed difference from the TypeScript SDK's ``Number.isInteger`` check,
kept because Python happens to be able to tell the difference, not because
the draft asks for it.

The one exception is ``_has_non_i_json_value`` below, which uses
``isinstance`` on purpose: its job is to catch a value that only an
in-memory Python caller (never JSON.parse or json.loads) could produce, so
it must recognize a subclass of dict, list or str as the object, array or
string it is impersonating, not let the subclass slip past unexamined.

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
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
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


def _has_non_i_json_value(value) -> bool:
    """True if value, or anything nested inside it, is not I-JSON.

    RFC 7493 section 2.1 (I-JSON) forbids a surrogate or a noncharacter code
    point in a string, and RFC 8259 admits only finite numbers; anything
    that is not a string, a finite number, a bool, null, an object or an
    array is not JSON at all. This walks the whole value looking for a
    violation of any of that, at any depth, including inside a nested object
    whose own "profile" field names a profile this package does not support
    (an unsupported profile does not stop this walk from covering the rest
    of that object).

    Because this can be handed an arbitrary in-memory Python value rather
    than only the output of json.loads, it uses isinstance rather than this
    module's usual exact-type checks: a dict subclass such as
    collections.OrderedDict is still walked as an object (and every one of
    its keys must be a str instance, itself checked for a surrogate or
    noncharacter), a list or a tuple is walked as an array, and a str
    subclass is still checked as a string. A float that is NaN or infinite
    is not I-JSON. A value of any other type at all, other than int, float,
    bool or None, for example a set or a bytes object, is not I-JSON either
    and stops the walk right there.

    The walk is iterative, using an explicit stack rather than recursion,
    and tracks the id() of every dict, list or tuple it has already queued
    so a value holding a reference cycle terminates instead of looping
    forever. It never raises.
    """

    def is_ill_formed_string(text) -> bool:
        return any(_is_surrogate_or_noncharacter(ord(ch)) for ch in text)

    stack = [value]
    seen_container_ids: set[int] = set()
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            if is_ill_formed_string(current):
                return True
        elif isinstance(current, dict):
            identity = id(current)
            if identity in seen_container_ids:
                continue
            seen_container_ids.add(identity)
            for key, item in current.items():
                if not isinstance(key, str) or is_ill_formed_string(key):
                    return True
                stack.append(item)
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen_container_ids:
                continue
            seen_container_ids.add(identity)
            stack.extend(current)
        elif isinstance(current, float):
            if not math.isfinite(current):
                return True
        elif isinstance(current, bool) or isinstance(current, int) or current is None:
            pass
        else:
            return True
    return False


def _utf8_len(value: str) -> int:
    return len(value.encode("utf-8", "surrogatepass"))


def is_canonical_timestamp(value) -> bool:
    """RFC 3339 canonical UTC milliseconds, with second 60 restricted to a
    real leap-second position.

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
    (which has no representation for a leap-second ":60" value). Defined only
    for values that have already passed is_canonical_timestamp.
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


def _failure(code: str, message: str) -> AuthorityFailure:
    return AuthorityFailure(code=code, message=message)


def validate_authority_delegation_shape(value) -> list[AuthorityFailure]:
    """Closed-schema and canonical-value validation for an in-memory decoded record."""
    failures: list[AuthorityFailure] = []
    top = _record(value)
    if top is None or not _exact_keys(top, (
        "record_type", "version", "delegation_id", "parent_delegation_id", "issuer",
        "subject", "verification_method", "issued_at", "nonce", "authority", "signature",
    )):
        return [_failure("SCHEMA_INVALID", "delegation must be an exact closed v1 object")]

    if _has_non_i_json_value(top):
        failures.append(_failure(
            "SCHEMA_INVALID", "record must be I-JSON: no unpaired surrogates, noncharacters, or non-JSON values",
        ))

    # Provisional: a record_type or version that is not a string at all (an
    # int, a list, and so on) is reported the same way as a string that names
    # some other version, namely UNSUPPORTED_VERSION rather than SCHEMA_INVALID.
    # The draft does not say which of the two a wrongly typed field should be;
    # this is kept identical to the TypeScript SDK, which also compares the
    # raw value against the expected string without checking its type first.
    if top["record_type"] != AUTHORITY_DELEGATION_RECORD_TYPE or top["version"] != AUTHORITY_DELEGATION_VERSION:
        failures.append(_failure("UNSUPPORTED_VERSION", "unsupported authority-delegation record_type or version"))
    if type(top["delegation_id"]) is not str or not _ID.fullmatch(top["delegation_id"]):
        failures.append(_failure("SCHEMA_INVALID", "delegation_id must be sha256:<64 lowercase hex>"))
    if top["parent_delegation_id"] is not None and (
        type(top["parent_delegation_id"]) is not str or not _ID.fullmatch(top["parent_delegation_id"])
    ):
        failures.append(_failure("SCHEMA_INVALID", "parent_delegation_id must be null or a delegation digest"))
    for key in ("issuer", "subject", "verification_method"):
        item = top[key]
        if type(item) is not str or len(item) == 0 or _utf8_len(item) > 1024:
            failures.append(_failure("SCHEMA_INVALID", f"{key} must be a non-empty string of at most 1024 UTF-8 bytes"))
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
        # Provisional: the draft does not state a grammar for spend.unit. This
        # requires the same identifier pattern used for values.required entries
        # (letters, digits, and ".", "_", ":", "-", up to 128 characters,
        # starting with a letter or digit), kept identical to the TypeScript
        # SDK rather than accepting an arbitrary non-empty string.
        if (
            not _exact_keys(spend, ("mode", "unit", "per_action", "cumulative"))
            or type(spend.get("unit")) is not str
            or not _IDENTIFIER.fullmatch(spend["unit"])
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
    elif is_canonical_timestamp(top.get("issued_at")) and time_facet["not_before"] < top["issued_at"]:
        # Provisional: this check runs for every record, including a root. The
        # draft states the not_before-cannot-predate-issued_at rule for a
        # child only; whether it also binds a root is not settled. This is
        # kept identical to the TypeScript SDK, which applies the same
        # per-record shape check regardless of the record's position in a
        # chain, rather than special-casing the root.
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
        or not all(type(item) is str and _IDENTIFIER.fullmatch(item) for item in values["required"])
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
