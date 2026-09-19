# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS native action reference, draft-pidlisnyi-aps-03 section 4.1 (profile ``aps-action-ref-v2``).

This is the draft-03 native ``action_ref``: a content-addressed identity for one
authorized action, bound to the acting agent, the exact target, the granted scope,
the payload actually dispatched, an issuance timestamp, and a nonce. It is
DISTINCT from :func:`agent_passport.action_ref.compute_action_ref`, which is a
pre-draft-03 compatibility digest over a different preimage and must never be
presented as an ``action_ref`` or as ``action-ref-v1-jcs-sha256``. It is also
distinct from the section 4.2 legacy external correlation form.

Mirrors ``src/v2/action-reference/v2.ts`` in the TypeScript SDK: the same
profile string, the same two domain-separation tags, the same validation
order and the same rejection of a non-string ``payload_ref``/``issued_at``/
``nonce`` before the format check runs (no ``String()`` coercion). Canonicalization
goes through the strict new-write I-JSON JCS in
:mod:`agent_passport.receipt_core.jcs`, not the legacy canonicalizer.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import cast

from ...receipt_core.jcs import (
    IJsonValidationError,
    assert_i_json,
    parse_strict_i_json,
    strict_jcs,
)

# Profile identifier the input object's "profile" member must equal.
ACTION_REF_V2_PROFILE = "aps-action-ref-v2"

# Domain-separation tags, byte-identical to the TypeScript reference's
# 'APS-ACTION-REF-V2\0' and 'APS-ACTION-PAYLOAD-V1\0' (a JS string with an
# embedded NUL, UTF-8 encoded, is exactly these bytes).
ACTION_REF_V2_DOMAIN = b"APS-ACTION-REF-V2\x00"
PAYLOAD_REF_V1_DOMAIN = b"APS-ACTION-PAYLOAD-V1\x00"

# Required members, in the order they are checked. Also the exact and only
# members an input object may carry (assertExactKeys in the TS reference).
_REQUIRED_MEMBERS = (
    "profile",
    "agent_id",
    "action_type",
    "target",
    "payload_ref",
    "scope_required",
    "issued_at",
    "nonce",
)
_ALLOWED_MEMBERS = frozenset(_REQUIRED_MEMBERS)

# issued_at: RFC 3339 UTC, exactly three fractional digits, literal Z. Anchored
# by re.fullmatch, so no leading/trailing anchors are needed in the pattern.
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z"
)
_PAYLOAD_REF_RE = re.compile(r"[0-9a-f]{64}")
_NONCE_RE = re.compile(r"[0-9a-f]{32}")

# Days per month in the proleptic Gregorian calendar, non-leap year, 1-indexed
# by (month - 1). February is corrected for leap years in _is_valid_calendar_day.
_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


class ActionReferenceError(ValueError):
    """A candidate ``aps-action-ref-v2`` input or payload failed validation.

    Carries a stable machine-readable ``code``, exactly one of: ``not_object``,
    ``missing_member``, ``unknown_member``, ``duplicate_member``,
    ``wrong_profile``, ``not_string``, ``empty_string``, ``bad_hex``,
    ``bad_timestamp``, ``scope_not_array``, ``scope_not_canonical``,
    ``lone_surrogate``, ``non_i_json``, ``empty_scope_required``, so a caller
    can branch on the failure without parsing the message.

    Subclasses ``ValueError`` so an existing fail-closed handler that catches
    ``ValueError`` around validation or canonicalization keeps working.
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        #: Stable machine-readable failure code. See the class docstring.
        self.code = code


def _is_leap_year(year: int) -> bool:
    """Proleptic Gregorian leap-year rule. Year 0000 is a leap year (0 % 400 == 0)."""
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _is_valid_calendar_day(year: int, month: int, day: int) -> bool:
    """True when `day` exists in `month` of `year` under the proleptic Gregorian
    calendar. Pure arithmetic: `datetime` cannot represent year 0000 (MINYEAR=1),
    and this function must accept it.
    """
    max_day = _DAYS_IN_MONTH[month - 1]
    if month == 2 and _is_leap_year(year):
        max_day = 29
    return day <= max_day


def validate_action_reference_input_v2(candidate: object) -> None:
    """Validate a candidate ``aps-action-ref-v2`` input object in place.

    Raises :class:`ActionReferenceError` on the first violation found, in this
    order, mirroring ``validateActionReferenceInputV2`` in the TS reference:

    1. ``candidate`` is a plain ``dict`` (``type(candidate) is dict``), else
       ``not_object``.
    2. Every required member is present, checked in the order ``profile``,
       ``agent_id``, ``action_type``, ``target``, ``payload_ref``,
       ``scope_required``, ``issued_at``, ``nonce`` (else ``missing_member``),
       then no member outside that set (else ``unknown_member``).
    3. The whole value is I-JSON (else ``non_i_json``, or ``lone_surrogate``
       for an unpaired UTF-16 surrogate specifically).
    4. ``profile`` equals :data:`ACTION_REF_V2_PROFILE` (else ``wrong_profile``).
    5. ``agent_id``, ``action_type``, ``target`` are non-empty strings (else
       ``not_string`` / ``empty_string``).
    6. ``payload_ref`` is a string matching 64 lowercase hex characters (else
       ``not_string`` / ``bad_hex``).
    7. ``scope_required`` is an array (else ``scope_not_array``). This function
       takes no profile and therefore never admits an empty array: the draft
       lets only a profile decide that, so ``[]`` is always
       ``empty_scope_required`` here. Each element must be a non-empty string
       (else ``not_string`` / ``empty_string``), already in NFC, and the array
       strictly increasing by the lexicographic order of UTF-8 encodings, with
       no duplicate (else ``scope_not_canonical``). Nothing is normalized here.
    8. ``issued_at`` is a string matching the canonical RFC 3339 UTC
       millisecond form, naming a day that exists in that month under the
       proleptic Gregorian calendar (else ``not_string`` / ``bad_timestamp``).
    9. ``nonce`` is a string matching 32 lowercase hex characters (else
       ``not_string`` / ``bad_hex``).
    """
    if type(candidate) is not dict:
        raise ActionReferenceError("action reference input: expected an object", "not_object")
    obj = cast(dict, candidate)

    for key in _REQUIRED_MEMBERS:
        if key not in obj:
            raise ActionReferenceError(
                f"action reference input: missing member {key!r}", "missing_member"
            )
    for key in obj:
        if key not in _ALLOWED_MEMBERS:
            raise ActionReferenceError(
                f"action reference input: unknown member {key!r}", "unknown_member"
            )

    try:
        assert_i_json(obj)
    except IJsonValidationError as exc:
        code = "lone_surrogate" if "surrogate" in str(exc) else "non_i_json"
        raise ActionReferenceError(str(exc), code) from exc

    if obj["profile"] != ACTION_REF_V2_PROFILE:
        raise ActionReferenceError(
            f"action reference input: profile must equal {ACTION_REF_V2_PROFILE!r}",
            "wrong_profile",
        )

    for key in ("agent_id", "action_type", "target"):
        value = obj[key]
        if type(value) is not str:
            raise ActionReferenceError(f"{key}: expected a string", "not_string")
        if len(value) == 0:
            raise ActionReferenceError(f"{key}: must not be empty", "empty_string")

    payload_ref = obj["payload_ref"]
    if type(payload_ref) is not str:
        raise ActionReferenceError("payload_ref: expected a string", "not_string")
    if _PAYLOAD_REF_RE.fullmatch(payload_ref) is None:
        raise ActionReferenceError(
            "payload_ref: expected 64 lowercase hexadecimal characters", "bad_hex"
        )

    scope_required = obj["scope_required"]
    if type(scope_required) is not list:
        raise ActionReferenceError("scope_required: expected an array", "scope_not_array")
    scopes = cast(list, scope_required)
    if len(scopes) == 0:
        raise ActionReferenceError(
            "scope_required: empty array; only a profile may permit an empty "
            "scope_required and this function takes no profile, so [] is "
            "always rejected here",
            "empty_scope_required",
        )
    for scope in scopes:
        if type(scope) is not str:
            raise ActionReferenceError("scope_required: element is not a string", "not_string")
        if len(scope) == 0:
            raise ActionReferenceError("scope_required: element must not be empty", "empty_string")
    for scope in scopes:
        if scope != unicodedata.normalize("NFC", scope):
            raise ActionReferenceError(
                f"scope_required: {scope!r} is not in Unicode NFC", "scope_not_canonical"
            )
    for previous, current in zip(scopes, scopes[1:]):
        if previous.encode("utf-8") >= current.encode("utf-8"):
            raise ActionReferenceError(
                "scope_required: must be strictly increasing by UTF-8 byte "
                "order, with no duplicate",
                "scope_not_canonical",
            )

    issued_at = obj["issued_at"]
    if type(issued_at) is not str:
        raise ActionReferenceError("issued_at: expected a string", "not_string")
    if _TIMESTAMP_RE.fullmatch(issued_at) is None:
        raise ActionReferenceError(
            "issued_at: expected YYYY-MM-DDTHH:MM:SS.sssZ", "bad_timestamp"
        )
    year, month, day = int(issued_at[0:4]), int(issued_at[5:7]), int(issued_at[8:10])
    if not _is_valid_calendar_day(year, month, day):
        raise ActionReferenceError(
            f"issued_at: {issued_at!r} names a day that does not exist in that "
            "month under the proleptic Gregorian calendar",
            "bad_timestamp",
        )

    nonce = obj["nonce"]
    if type(nonce) is not str:
        raise ActionReferenceError("nonce: expected a string", "not_string")
    if _NONCE_RE.fullmatch(nonce) is None:
        raise ActionReferenceError(
            "nonce: expected 32 lowercase hexadecimal characters", "bad_hex"
        )


def compute_action_ref_v2(input_object: dict) -> str:
    """Compute the draft-03 section 4.1 ``action_ref`` (lowercase hex SHA-256).

    Validates first, then hashes the domain-separation tag concatenated with
    the strict RFC 8785 JCS bytes of `input_object`, matching
    ``computeActionRefV2`` in the TS reference exactly.
    """
    validate_action_reference_input_v2(input_object)
    canonical = strict_jcs(input_object)
    return hashlib.sha256(ACTION_REF_V2_DOMAIN + canonical.encode("utf-8")).hexdigest()


def compute_payload_ref_v1(payload: object) -> str:
    """Compute ``payload_ref``: lowercase hex SHA-256 of the payload domain tag
    concatenated with the strict RFC 8785 JCS bytes of `payload`.

    `payload` is the exact JSON value presented for authorization and
    dispatch, not the action reference input object. Raises
    :class:`ActionReferenceError` with code ``lone_surrogate`` for an
    unpaired UTF-16 surrogate, or ``non_i_json`` for any other I-JSON
    violation (an unsafe integer, a non-finite number, and so on).
    """
    try:
        canonical = strict_jcs(payload)
    except IJsonValidationError as exc:
        code = "lone_surrogate" if "surrogate" in str(exc) else "non_i_json"
        raise ActionReferenceError(str(exc), code) from exc
    return hashlib.sha256(PAYLOAD_REF_V1_DOMAIN + canonical.encode("utf-8")).hexdigest()


def create_action_reference_input_v2(
    *,
    agent_id: str,
    action_type: str,
    target: str,
    payload_ref: str,
    scope_required,
    issued_at: str,
    nonce: str,
) -> dict:
    """Build and validate an ``aps-action-ref-v2`` input object.

    Each element of `scope_required` must be a string (else
    :class:`ActionReferenceError` with code ``not_string``). Every element is
    NFC-normalized, the result is sorted by the lexicographic order of its
    UTF-8 encoding, and a duplicate surviving normalization is rejected with
    ``scope_not_canonical`` rather than silently deduplicated: two distinct
    inputs must never collapse onto one identity without an error.

    The eight members are assembled in the wire order ``profile``,
    ``agent_id``, ``action_type``, ``target``, ``payload_ref``,
    ``scope_required``, ``issued_at``, ``nonce``, then validated with
    :func:`validate_action_reference_input_v2` before being returned.
    """
    # A str is iterable in Python, so without this check "ab" would be read as
    # the two scopes ["a", "b"]. Only a list or tuple of strings is a scope array.
    if type(scope_required) not in (list, tuple):
        raise ActionReferenceError("scope_required: expected an array", "scope_not_array")
    normalized_scopes = []
    for scope in scope_required:
        if type(scope) is not str:
            raise ActionReferenceError(
                "scope_required: element is not a string", "not_string"
            )
        # Checked before sorting: the sort key encodes to UTF-8, which has no
        # encoding for an unpaired surrogate and would raise a bare
        # UnicodeEncodeError instead of this module's error.
        if any(0xD800 <= ord(char) <= 0xDFFF for char in scope):
            raise ActionReferenceError(
                "scope_required: unpaired UTF-16 surrogate", "lone_surrogate"
            )
        normalized_scopes.append(unicodedata.normalize("NFC", scope))
    normalized_scopes.sort(key=lambda s: s.encode("utf-8"))
    for previous, current in zip(normalized_scopes, normalized_scopes[1:]):
        if previous == current:
            raise ActionReferenceError(
                f"scope_required: {current!r} is a duplicate after NFC "
                "normalization",
                "scope_not_canonical",
            )

    value = {
        "profile": ACTION_REF_V2_PROFILE,
        "agent_id": agent_id,
        "action_type": action_type,
        "target": target,
        "payload_ref": payload_ref,
        "scope_required": normalized_scopes,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    validate_action_reference_input_v2(value)
    return value


def parse_action_reference_input_v2(raw: str) -> dict:
    """Parse a serialized ``aps-action-ref-v2`` input document and validate it.

    Rejecting a duplicate object member is a property of PARSING, not of
    validation: by the time raw JSON has become a Python dict, the second
    occurrence of a member name has already overwritten the first and the
    evidence is gone. This entry point therefore parses `raw` with the
    existing strict I-JSON parser in :mod:`agent_passport.receipt_core.jcs`,
    which rejects a duplicate member name (compared AFTER escape decoding, so
    ``"a"`` and ``"\\u0061"`` collide as the same name) before it can be lost,
    then hands the result to :func:`validate_action_reference_input_v2`
    unchanged: nothing here weakens or bypasses that validator.
    """
    try:
        parsed = parse_strict_i_json(raw)
    except IJsonValidationError as exc:
        message = str(exc)
        if "duplicate object member" in message:
            code = "duplicate_member"
        elif "surrogate" in message:
            code = "lone_surrogate"
        else:
            code = "non_i_json"
        raise ActionReferenceError(message, code) from exc
    validate_action_reference_input_v2(parsed)
    return cast(dict, parsed)


def compute_action_ref_v2_from_json(raw: str) -> str:
    """Compose :func:`parse_action_reference_input_v2` and
    :func:`compute_action_ref_v2`, for a caller holding wire bytes rather than
    an already-parsed input object. Identical digest to the parsed path for
    any document that parses, because it IS the parsed path once the bytes
    have been read.
    """
    return compute_action_ref_v2(parse_action_reference_input_v2(raw))
