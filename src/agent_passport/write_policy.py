# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS write policy: admissibility rules applied at signing and new-write boundaries.

This is a layer ABOVE canonicalization, not a part of it. RFC 8785 canonicalization
must remain able to canonicalize any valid binary64 number, so nothing here belongs
inside ``canonicalize`` or ``canonicalize_jcs``.

The rule implemented here refuses an integer-valued JSON number whose absolute value
exceeds 9007199254740991, which is 2**53 minus 1. RFC 7493 (I-JSON) section 2.2 states
that a sender cannot expect a receiver to treat integers outside that range exactly, and
RECOMMENDS representing such values as JSON strings where exact interchange is required.
It recommends; it does not mandate. APS adopts the recommendation as a write rule: an
exact large quantity is carried as a decimal string, which is what
draft-pidlisnyi-aps-03 already does with ``"per_action":"5000"``.

Applied at write time only. A verifier reading an artifact signed before this rule
existed MUST NOT be given this check, or it would refuse bytes it accepted before.

Deliberately narrower than ``receipt_core.jcs.assert_i_json``. That validator also
rejects any value whose type is outside a fixed JSON set, including ``datetime``, which
legacy signing payloads carry. This one inspects numbers and recurses through
containers, and leaves every other type alone, so adding it to an existing signing path
cannot refuse a write that succeeds today for a reason unrelated to the number rule.
"""

from __future__ import annotations

import math

#: Largest integer magnitude that survives a binary64 round trip exactly.
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class UnsafeIntegerError(ValueError):
    """A new-write value carries an integer outside the interoperable IEEE 754 range.

    Subclasses ValueError so callers that already fail closed around signing keep
    working. Carries a stable machine-readable ``category`` and ``reason`` so a caller
    can branch without parsing the message, and the message names the JSON path of the
    offending member, matching the Go SDK's ``ErrInvalidIJSON`` wording.
    """

    #: Stable machine-readable category for this write-policy refusal.
    category = "invalid_number"

    def __init__(self, message: str, reason: str = "integer_exceeds_interoperable_range") -> None:
        super().__init__(message)
        #: Specific failure within the category.
        self.reason = reason


def assert_write_safe_numbers(value, path: str = "$", _ancestors: set[int] | None = None) -> None:
    """Raise :class:`UnsafeIntegerError` if ``value`` carries an unsafe integer anywhere.

    Recurses through lists and dicts so the rule applies to the whole artifact rather
    than only its top-level members. Non-numeric values of any type are left untouched.

    Args:
        value: The in-memory value about to be canonicalized and signed.
        path: JSON path of ``value``, used to locate the offending member.

    Raises:
        UnsafeIntegerError: An integer-valued number exceeds the interoperable range.
    """
    if _ancestors is None:
        _ancestors = set()

    # bool is a subclass of int in Python and is never a number for this purpose.
    if value is None or isinstance(value, bool) or isinstance(value, str):
        return

    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(
                f"{path}: integer exceeds the interoperable IEEE 754 range"
            )
        return

    if isinstance(value, float):
        # Only integer-valued floats are bounded. A fractional value carries no claim
        # to exactness beyond the double itself, which is the same rule the Go SDK
        # applies with math.Trunc(x) == x.
        if math.isfinite(value) and value.is_integer() and abs(value) > MAX_SAFE_INTEGER:
            raise UnsafeIntegerError(
                f"{path}: integer exceeds the interoperable IEEE 754 range"
            )
        return

    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in _ancestors:
            return
        _ancestors.add(identity)
        for index, item in enumerate(value):
            assert_write_safe_numbers(item, f"{path}[{index}]", _ancestors)
        _ancestors.discard(identity)
        return

    if isinstance(value, dict):
        identity = id(value)
        if identity in _ancestors:
            return
        _ancestors.add(identity)
        for key, item in value.items():
            assert_write_safe_numbers(item, f"{path}.{key}", _ancestors)
        _ancestors.discard(identity)
        return

    # Any other type is outside this rule's remit and is left to the canonicalizer.
    return
