# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Strict untrusted-wire entry point.

Python port of the TypeScript SDK's src/v2/authority-delegation/parse.ts.

This does not reuse agent_passport.receipt_core.jcs.parse_strict_i_json.
That helper already provides the size limit, the duplicate-member rejection
at every depth, and a lone-surrogate sweep this module also needs, but its
call into json.loads does not expose a parse_float hook a caller can supply,
so it has no way to reject a wire number token that carries a fraction or
exponent. Without that hook, a value like "2.0" would reach it as an
ordinary Python float rather than being refused at the token level the way
the TypeScript SDK's parser refuses it. So this module reimplements the same
duplicate member, size and lone-surrogate checks directly against json.loads,
adding the fraction/exponent rule as a parse_float/parse_constant hook.

Provisional: rejecting a fraction or exponent even when the number denotes
an integer (for example depth.remaining written as "2.0" or "2e0") is kept
identical to the TypeScript SDK. The draft does not say whether such a
spelling should be admitted; the TypeScript SDK rejects it because a
JavaScript number carries no separate integer/float tag, so the token
itself is the only place it can draw that line. In Python the strict
type(v) is int checks in schema.py would already reject this value on
their own once it is decoded as a float, so this rule mainly matters for
producing the rejection at the parse step rather than the schema step.
"""

from __future__ import annotations

import json

from .schema import validate_authority_delegation_shape
from .types import AuthorityDelegationError, AuthorityFailure

_MAX_WIRE_BYTES = 1_048_576


class _StrictJsonError(Exception):
    """Internal marker for a wire-syntax violation, caught before schema validation."""


def _reject_duplicate_pairs(pairs):
    seen = set()
    obj = {}
    for key, value in pairs:
        if key in seen:
            raise _StrictJsonError(f"duplicate object member {key!r}")
        seen.add(key)
        obj[key] = value
    return obj


def _reject_non_integer_number(token):
    raise _StrictJsonError(f"non-integer JSON number literal {token!r} is not permitted")


def _reject_constant(token):
    raise _StrictJsonError(f"JSON constant {token!r} is not permitted")


def _assert_no_lone_surrogate(value) -> None:
    """Recursively reject an unpaired UTF-16 surrogate in any decoded string.

    Mirrors the sweep in agent_passport.receipt_core.jcs.parse_strict_i_json.
    In this closed schema every string field is either matched against an
    ASCII-only regular expression (which a surrogate could never pass) or is
    one of the three identifiers schema.py already runs through its own
    well-formed-Unicode check, so this sweep is a defensive, belt-and-suspenders
    pass over the whole decoded document rather than one that changes an
    outcome the schema check would not already reach on its own.
    """
    if type(value) is str:
        for ch in value:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise _StrictJsonError("string contains an unpaired UTF-16 surrogate")
    elif type(value) is list:
        for item in value:
            _assert_no_lone_surrogate(item)
    elif type(value) is dict:
        for key, item in value.items():
            _assert_no_lone_surrogate(key)
            _assert_no_lone_surrogate(item)


def parse_authority_delegation_json(source: str) -> dict:
    """Parse and validate a wire authority-delegation record.

    ``source`` must be a string of at most 1,048,576 UTF-8 bytes containing
    strict JSON (duplicate member names rejected at every depth, and any
    number token with a fraction or exponent rejected even when it denotes an
    integer), free of unpaired UTF-16 surrogates, and matching the closed v1
    schema. Any failure raises AuthorityDelegationError.
    """
    if type(source) is not str or len(source.encode("utf-8", "surrogatepass")) > _MAX_WIRE_BYTES:
        failure = AuthorityFailure(
            code="SCHEMA_INVALID", message="authority delegation JSON must be a string no larger than 1 MiB",
        )
        raise AuthorityDelegationError("SCHEMA_INVALID", (failure,))

    try:
        decoded = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_non_integer_number,
            parse_constant=_reject_constant,
        )
        _assert_no_lone_surrogate(decoded)
    except _StrictJsonError as exc:
        failure = AuthorityFailure(
            code="SCHEMA_INVALID", message=f"authority delegation JSON is not strict wire JSON: {exc}",
        )
        raise AuthorityDelegationError("SCHEMA_INVALID", (failure,)) from exc
    except (ValueError, TypeError, RecursionError) as exc:
        failure = AuthorityFailure(
            code="SCHEMA_INVALID", message=f"authority delegation JSON is not valid JSON: {exc}",
        )
        raise AuthorityDelegationError("SCHEMA_INVALID", (failure,)) from exc

    failures = validate_authority_delegation_shape(decoded)
    if failures:
        raise AuthorityDelegationError(failures[0].code, tuple(failures))
    return decoded
