# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS native action reference, draft-pidlisnyi-aps-03 section 4.1 (profile ``aps-action-ref-v2``).

This is the draft-03 native ``action_ref``: the content-addressed identity of
one intended action; it commits to the acting agent, the operation, the exact
target, the payload presented for authorization and dispatch (through
``payload_ref``), the scopes required, the issuance time and a nonce;
computing it establishes no authorization, grant or dispatch. It is DISTINCT
from :func:`agent_passport.action_ref.compute_action_ref`, which is a
pre-draft-03 compatibility digest over a different preimage and must never be
presented as an ``action_ref`` or as ``action-ref-v1-jcs-sha256``. It is also
distinct from the section 4.2 legacy external correlation form.

Mirrors the TypeScript SDK's ``src/v2/action-reference/v2.ts`` with the same
profile string and domain-separation tags, giving the same digest for every
input both accept. Draft-pidlisnyi-aps-03 section 4.1 line 799 lets a
profile permit an empty ``scope_required`` array; ``validate_action_reference_input_v2``,
``compute_action_ref_v2``, ``parse_action_reference_input_v2`` and
``compute_action_ref_v2_from_json`` all refuse one by default
(``empty_scope_required``) and admit it only when the keyword-only
``empty_scope_required_permitted=True`` is passed, for a caller holding the
applicable profile; before this was ruled, an empty array was refused here
unconditionally, calling that choice provisional. The context changes only
what is admitted, never what is hashed: no marker enters the preimage, so
the digest of a permitted empty array is the digest of that input. Known
differences from the TypeScript SDK: the order of checks is similar but not
identical, so an input with several faults can be reported under a
different code. Canonicalization goes through the strict new-write I-JSON
JCS in :mod:`agent_passport.receipt_core.jcs`, not the legacy canonicalizer;
that module's validator and canonicalizer are iterative, not recursive, so
a deeply nested value is processed rather than rejected. The ``nesting_limit``
code below is kept for a future engine limit this port does not defend
against today, not for ordinary deep nesting.

Also rejects Unicode noncharacters (U+FDD0 through U+FDEF, and every code
point whose low 16 bits are 0xFFFE or 0xFFFF) in any object key or string
value, at any depth, on the section 4.1 input object and on the payload
passed to :func:`compute_payload_ref_v1` (draft-pidlisnyi-aps-03 section
4.1, lines 813-815; RFC 7493 section 2.1). That check is local to this
module (see ``_check_no_noncharacters`` below, run after the shared strict
I-JSON check) because the shared helper, :func:`agent_passport.receipt_core.jcs.assert_i_json`,
does not reject noncharacters and is not changed here: it is also used by
receipt-core, and this port must not alter its behaviour.
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

# issued_at: RFC 3339 UTC, exactly three fractional digits, literal Z. A
# second of 60 is valid only at 23:59 on the last day of its month (RFC 3339
# section 5.7; Appendix D's "YYYY-MM-DDT23:59:60Z"); that restriction is
# checked separately below with integer arithmetic, since a fixed-width
# regex cannot express "only the last day of this particular month".
# Anchored by re.fullmatch, so no leading/trailing anchors are needed in the
# pattern.
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)\.[0-9]{3}Z"
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
    ``lone_surrogate``, ``non_i_json``, ``empty_scope_required``,
    ``nesting_limit``, so a caller can branch on the failure without parsing
    the message. ``nesting_limit`` is not a rule of the draft; it names a
    resource ceiling this port might one day need, not one it has today,
    since :mod:`agent_passport.receipt_core.jcs` validates and canonicalizes
    iteratively rather than recursively.

    Subclasses ``ValueError`` so an existing fail-closed handler that catches
    ``ValueError`` around validation or canonicalization keeps working.
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        #: Stable machine-readable failure code. See the class docstring.
        self.code = code


def _classify_i_json_error(message: str) -> str:
    """Classify a jcs error message into a stable ActionReferenceError code.

    An unpaired UTF-16 surrogate message always ENDS WITH the exact suffix
    ": unpaired UTF-16 surrogate" (see ``_assert_scalar_string`` in
    :mod:`agent_passport.receipt_core.jcs`); the strict parser's duplicate-
    member message is EXACTLY "$: duplicate object member". Matching on
    these exact forms, and not on a substring the message merely contains,
    matters because both messages can embed a caller-controlled JSON path or
    member name: a payload key named "surrogate" holding a non-finite number,
    or an extra member named "duplicate object member", must not be
    misclassified just because that text appears somewhere in the message.
    """
    if message.endswith(": unpaired UTF-16 surrogate"):
        return "lone_surrogate"
    if message == "$: duplicate object member":
        return "duplicate_member"
    return "non_i_json"


# The 66 Unicode noncharacters: U+FDD0 through U+FDEF, and U+xFFFE/U+xFFFF for
# each of the 17 planes. RFC 7493 section 2.1 refers to Noncharacters as
# defined by Unicode; this module enforces that under the section 4.1
# I-JSON requirement (draft-pidlisnyi-aps-03 lines 813-815; RFC 7493
# section 2.1) even though the shared strict I-JSON helper in
# receipt_core/jcs.py does not, per this module's docstring above.
_NONCHARACTER_LOW_16 = frozenset({0xFFFE, 0xFFFF})


def _is_noncharacter(code_point: int) -> bool:
    """True for one of the 66 Unicode noncharacter code points."""
    if 0xFDD0 <= code_point <= 0xFDEF:
        return True
    return (code_point & 0xFFFF) in _NONCHARACTER_LOW_16


class _NoncharacterWalkExit:
    """Sentinel pushed onto :func:`_check_no_noncharacters`'s stack to mark
    leaving a list or dict.

    Carries the container's ``id()`` so the walk can drop it from
    ``ancestors`` on the way out, the same enter/leave bracketing
    :func:`agent_passport.receipt_core.jcs.assert_i_json` does recursively
    with its own ``ancestors`` set. An instance of this class can never be
    confused with a real value from the input: by the time this walk runs,
    the strict I-JSON check has already limited every value in the tree to
    ``None``, ``bool``, ``str``, ``int``, ``float``, ``list`` or ``dict``.
    """

    __slots__ = ("identity",)

    def __init__(self, identity: int) -> None:
        self.identity = identity


def _check_no_noncharacters(root: object) -> None:
    """Iteratively walk `root`, raising :class:`ActionReferenceError` with
    code ``non_i_json`` if any dict key or str value, at any depth, contains
    a noncharacter code point (see :func:`_is_noncharacter`).

    Non-recursive: an explicit list is used as a stack instead of function
    recursion, so this cannot exhaust the interpreter stack on deep input.
    Cycle-safe: entering a list or dict records its ``id()`` in `ancestors`
    and pushes a :class:`_NoncharacterWalkExit` sentinel that removes it
    again once every child has been pushed, so a value that refers back to
    one of its own containers is recognized and not walked a second time,
    rather than looping forever. This assumes `root` already passed the
    shared strict I-JSON check (called before this in every caller below),
    so the only container types it needs to handle are `list` and `dict`.
    Every dict key is already known to be a `str` instance: assert_i_json
    (:mod:`agent_passport.receipt_core.jcs`) admits a key with `isinstance`,
    not an exact type check, so it accepts a `str` subclass; this walk
    checks keys and string values the same way, with `isinstance`, so it
    does not silently skip a subclass instance the shared check let through.
    """
    ancestors: set[int] = set()
    stack: list[object] = [root]
    while stack:
        item = stack.pop()
        if type(item) is _NoncharacterWalkExit:
            ancestors.discard(item.identity)
            continue
        if isinstance(item, str):
            for char in item:
                if _is_noncharacter(ord(char)):
                    raise ActionReferenceError(
                        f"value contains noncharacter U+{ord(char):04X}",
                        "non_i_json",
                    )
            continue
        if type(item) is list:
            identity = id(item)
            if identity in ancestors:
                continue
            ancestors.add(identity)
            stack.append(_NoncharacterWalkExit(identity))
            stack.extend(cast(list, item))
            continue
        if type(item) is dict:
            identity = id(item)
            if identity in ancestors:
                continue
            ancestors.add(identity)
            stack.append(_NoncharacterWalkExit(identity))
            for key, value in cast(dict, item).items():
                if isinstance(key, str):
                    for char in key:
                        if _is_noncharacter(ord(char)):
                            raise ActionReferenceError(
                                f"object key contains noncharacter U+{ord(char):04X}",
                                "non_i_json",
                            )
                stack.append(value)
            continue
        # None, bool, int, float: no characters to check.


def _is_leap_year(year: int) -> bool:
    """Proleptic Gregorian leap-year rule. Year 0000 is a leap year (0 % 400 == 0)."""
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _days_in_month(year: int, month: int) -> int:
    """Last day-of-month number for `month` of `year`, proleptic Gregorian
    calendar. Pure arithmetic: `datetime` cannot represent year 0000
    (MINYEAR=1), and this function must accept it.
    """
    if month == 2 and _is_leap_year(year):
        return 29
    return _DAYS_IN_MONTH[month - 1]


def _is_valid_calendar_day(year: int, month: int, day: int) -> bool:
    """True when `day` exists in `month` of `year` under the proleptic Gregorian
    calendar.
    """
    return day <= _days_in_month(year, month)


def validate_action_reference_input_v2(
    candidate: object, *, empty_scope_required_permitted: bool = False
) -> None:
    """Validate a candidate ``aps-action-ref-v2`` input object in place.

    `empty_scope_required_permitted` is the flattened form of the TypeScript
    reference's ``ActionReferenceProfileContextV2.emptyScopeRequiredPermitted``:
    pass ``True`` only when the applicable profile explicitly permits an
    empty ``scope_required`` array (draft-pidlisnyi-aps-03 section 4.1 line
    799). It changes only step 8 below; it is not hashed and does not
    otherwise change what this function accepts.

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
    4. No object key or string value, at any depth, contains a Unicode
       noncharacter (else ``non_i_json``; see the module docstring).
    5. ``profile`` equals :data:`ACTION_REF_V2_PROFILE` (else ``wrong_profile``).
    6. ``agent_id``, ``action_type``, ``target`` are non-empty strings (else
       ``not_string`` / ``empty_string``).
    7. ``payload_ref`` is a string matching 64 lowercase hex characters (else
       ``not_string`` / ``bad_hex``).
    8. ``scope_required`` is an array (else ``scope_not_array``). An empty
       array is rejected with ``empty_scope_required`` unless
       `empty_scope_required_permitted` is ``True``. Each element must be a
       non-empty string (else ``not_string`` / ``empty_string``), already in
       NFC, and the array strictly increasing by the lexicographic order of
       UTF-8 encodings, with no duplicate (else ``scope_not_canonical``).
       Nothing is normalized here.
    9. ``issued_at`` is a string matching the canonical RFC 3339 UTC
       millisecond form, naming a day that exists in that month under the
       proleptic Gregorian calendar (else ``not_string`` / ``bad_timestamp``).
       A second of 60 is valid only at 23:59 on the last day of its month
       (RFC 3339 section 5.7; Appendix D's ``YYYY-MM-DDT23:59:60Z``); every
       other second-60 timestamp is ``bad_timestamp``.
    10. ``nonce`` is a string matching 32 lowercase hex characters (else
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
    except RecursionError as exc:
        raise ActionReferenceError(
            "action reference input: value nested too deeply for this implementation",
            "nesting_limit",
        ) from exc
    except IJsonValidationError as exc:
        message = str(exc)
        raise ActionReferenceError(message, _classify_i_json_error(message)) from exc

    _check_no_noncharacters(obj)

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
    if len(scopes) == 0 and not empty_scope_required_permitted:
        raise ActionReferenceError(
            "scope_required: empty array; only a profile that explicitly permits "
            "an empty scope_required does so, by passing "
            "empty_scope_required_permitted=True",
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
    if issued_at[17:19] == "60" and (
        day != _days_in_month(year, month)
        or issued_at[11:13] != "23"
        or issued_at[14:16] != "59"
    ):
        raise ActionReferenceError(
            f"issued_at: {issued_at!r} has second 60 outside 23:59 on the "
            "last day of its month (RFC 3339 section 5.7; Appendix D)",
            "bad_timestamp",
        )

    nonce = obj["nonce"]
    if type(nonce) is not str:
        raise ActionReferenceError("nonce: expected a string", "not_string")
    if _NONCE_RE.fullmatch(nonce) is None:
        raise ActionReferenceError(
            "nonce: expected 32 lowercase hexadecimal characters", "bad_hex"
        )


def compute_action_ref_v2(
    input_object: dict, *, empty_scope_required_permitted: bool = False
) -> str:
    """Compute the draft-03 section 4.1 ``action_ref`` (lowercase hex SHA-256).

    Validates first, then hashes the domain-separation tag concatenated with
    the strict RFC 8785 JCS bytes of `input_object`, giving the same digest
    as ``computeActionRefV2`` in the TypeScript SDK for any input both
    accept. `empty_scope_required_permitted` is forwarded to
    :func:`validate_action_reference_input_v2` unchanged: it changes what is
    admitted, never what is hashed, so the digest of a permitted empty
    ``scope_required`` is the digest of that input.
    """
    validate_action_reference_input_v2(
        input_object, empty_scope_required_permitted=empty_scope_required_permitted
    )
    try:
        canonical = strict_jcs(input_object)
    except RecursionError as exc:
        raise ActionReferenceError(
            "action reference input: value nested too deeply for this implementation",
            "nesting_limit",
        ) from exc
    return hashlib.sha256(ACTION_REF_V2_DOMAIN + canonical.encode("utf-8")).hexdigest()


def compute_payload_ref_v1(payload: object) -> str:
    """Compute ``payload_ref``: lowercase hex SHA-256 of the payload domain tag
    concatenated with the strict RFC 8785 JCS bytes of `payload`.

    `payload` is the exact JSON value presented for authorization and
    dispatch, not the action reference input object. Raises
    :class:`ActionReferenceError` with code ``lone_surrogate`` for an
    unpaired UTF-16 surrogate, ``non_i_json`` for any other I-JSON violation
    (an unsafe integer, a non-finite number, a Unicode noncharacter in a key
    or string value at any depth, and so on).
    """
    try:
        canonical = strict_jcs(payload)
    except RecursionError as exc:
        raise ActionReferenceError(
            "payload: value nested too deeply for this implementation",
            "nesting_limit",
        ) from exc
    except IJsonValidationError as exc:
        message = str(exc)
        raise ActionReferenceError(message, _classify_i_json_error(message)) from exc
    _check_no_noncharacters(payload)
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
        if len(scope) == 0:
            raise ActionReferenceError(
                "scope_required: element must not be empty", "empty_string"
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


def parse_action_reference_input_v2(
    raw: str, *, empty_scope_required_permitted: bool = False
) -> dict:
    """Parse a serialized ``aps-action-ref-v2`` input document and validate it.

    Rejecting a duplicate object member is a property of PARSING, not of
    validation: by the time raw JSON has become a Python dict, the second
    occurrence of a member name has already overwritten the first and the
    evidence is gone. This entry point therefore parses `raw` with the
    existing strict I-JSON parser in :mod:`agent_passport.receipt_core.jcs`,
    which rejects a duplicate member name (compared AFTER escape decoding, so
    ``"a"`` and ``"\\u0061"`` collide as the same name) before it can be lost,
    then hands the result, and `empty_scope_required_permitted` unchanged, to
    :func:`validate_action_reference_input_v2`: nothing here weakens or
    bypasses that validator.
    """
    try:
        parsed = parse_strict_i_json(raw)
    except RecursionError as exc:
        raise ActionReferenceError(
            "action reference input: value nested too deeply for this implementation",
            "nesting_limit",
        ) from exc
    except IJsonValidationError as exc:
        message = str(exc)
        raise ActionReferenceError(message, _classify_i_json_error(message)) from exc
    validate_action_reference_input_v2(
        parsed, empty_scope_required_permitted=empty_scope_required_permitted
    )
    return cast(dict, parsed)


def compute_action_ref_v2_from_json(
    raw: str, *, empty_scope_required_permitted: bool = False
) -> str:
    """Compose :func:`parse_action_reference_input_v2` and
    :func:`compute_action_ref_v2`, for a caller holding wire bytes rather than
    an already-parsed input object. Identical digest to the parsed path for
    any document that parses, because it IS the parsed path once the bytes
    have been read. `empty_scope_required_permitted` is forwarded to both.
    """
    return compute_action_ref_v2(
        parse_action_reference_input_v2(
            raw, empty_scope_required_permitted=empty_scope_required_permitted
        ),
        empty_scope_required_permitted=empty_scope_required_permitted,
    )
