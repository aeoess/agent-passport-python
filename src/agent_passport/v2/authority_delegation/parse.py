# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Strict untrusted-wire entry point.

Python port of the TypeScript SDK's src/v2/authority-delegation/parse.ts.

This does not reuse agent_passport.receipt_core.jcs.parse_strict_i_json.
That helper already provides the size limit and the duplicate-member
rejection at every depth this module also needs, but its call into
json.loads does not expose a parse_float hook a caller can supply, so it has
no way to recognize a wire number token that carries a fraction or exponent
but denotes an integer value (for example "3.0" or "3e0") as the same int
that "3" itself decodes to. Without that hook, such a token would reach it
as an ordinary Python float, and the schema's exact type(v) is int checks
(depth.remaining, reputation.ceiling) would then refuse it as SCHEMA_INVALID
even though an integral-valued I-JSON number is admissible however it is
written and RFC 8785 canonicalizes the spelling to the same bytes as "3". So
this module reimplements the duplicate-member and size checks directly
against json.loads, adding a parse_float hook that converts an
integral-valued token to int and leaves any other value as float for the
schema to judge.

This module does not itself sweep the decoded document for a surrogate or a
noncharacter: validate_authority_delegation_shape (called at the end of
parse_authority_delegation_json below) walks the whole record for one, so a
separate sweep here would only duplicate that walk.

No spelling rule applies to a wire number token: an integral-valued I-JSON
number is admissible however it is written, and RFC 8785 canonicalizes the
spelling, so "2.0" and "2e0" decode to the same int as "2" (this parser
previously rejected any fraction or exponent token outright, matching the
TypeScript SDK's own now-removed spelling rule). A value that is not an
integer where the schema requires one is still refused, by the schema's
exact type(v) is int checks, not at the parse step.
"""

from __future__ import annotations

import json
import math

from .schema import validate_authority_delegation_shape
from .types import AuthorityDelegationError, AuthorityFailure

# The draft states no maximum wire size. This 1 MiB (1,048,576-byte) limit is this
# implementation's own ceiling, not a protocol rule: crossing it means this parser
# declines to read the document, which is why it raises here rather than reporting a
# conformance failure. The chain verifier reports its equivalent ceiling as
# RESOURCE_LIMIT and indeterminate.
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


def _parse_number_token(token: str):
    """Admit any spelling of an I-JSON number: an integral value becomes a Python
    int, matching what "3" itself decodes to, so the schema's exact type(v) is int
    checks see the same value regardless of whether the wire wrote "3", "3.0" or
    "3e0". A non-integral or non-finite value is left as a float for the schema (via
    _has_non_i_json_value) to judge; a token like "1e400" becomes the float
    infinity, exactly as json.loads's default parse_float would decode it, and is
    rejected there for not being finite.
    """
    value = float(token)
    if math.isfinite(value) and value.is_integer():
        return int(value)
    return value


def _reject_constant(token):
    raise _StrictJsonError(f"JSON constant {token!r} is not permitted")


def parse_authority_delegation_json(source: str) -> dict:
    """Parse and validate a wire authority-delegation record.

    ``source`` must be a string of at most 1,048,576 UTF-8 bytes containing
    strict JSON (duplicate member names rejected at every depth) and matching
    the closed v1 schema, which itself rejects a surrogate or noncharacter
    code point anywhere in the decoded record. An integral-valued number
    token is admitted however it is spelled ("3", "3.0" and "3e0" all decode
    to the same int); a value that is not an integer where the schema
    requires one is refused there. Any failure raises
    AuthorityDelegationError.
    """
    if type(source) is not str or len(source.encode("utf-8", "surrogatepass")) > _MAX_WIRE_BYTES:
        failure = AuthorityFailure(
            code="SCHEMA_INVALID",
            message="authority delegation JSON must be a string within this implementation's 1 MiB ceiling",
        )
        raise AuthorityDelegationError("SCHEMA_INVALID", (failure,))

    try:
        decoded = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_parse_number_token,
            parse_constant=_reject_constant,
        )
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
