# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Section 4.2 external correlation form (label ``action-ref-v1-jcs-sha256``).

This is the legacy cross-ecosystem correlation key defined by
draft-pidlisnyi-aps-03 section 4.2, published text lines 845-892. It is a
correlation key only: a matching value shows only that two records carry the
same action_type, agent_id, scope and timestamp strings; the form omits the
target, payload digest and nonce, so two different actions can share one
value. Per section 9 (published text lines
1616-1620), a match is not evidence of the authenticity, authority, or
integrity of either record, and MUST NOT be treated as an authority claim.
This value must not be presented, logged, or relied upon as identifying an
APS policy decision, approval, dispatch, spend reservation, or receipt.

This form predates ``aps-action-ref-v2`` (section 4.1) and is kept only for
correlation with records that already use it. It MUST NOT be presented as an
``action_ref`` under section 4.1: that is a distinct primitive with a
distinct preimage, computed by
:func:`agent_passport.v2.action_reference.compute_action_ref_v2`. The two
forms differ in field naming, field forms, scope arity, and timestamp
precision, and produce unrelated digest values for the same underlying
action (draft lines 889-892). This module is also distinct from the
pre-draft-03 compatibility digest in :mod:`agent_passport.action_ref`
(``compute_action_ref``), a third, unrelated preimage.

The label ``action-ref-v1-jcs-sha256`` (``EXTERNAL_ACTION_REF_V1_LABEL``)
identifies this construction. The value returned by
:func:`compute_external_action_ref_v1` is the bare hex digest: it carries no
embedded label of its own. The label travels in this function's name and in
this documentation, not in the returned string. A caller that serializes,
stores, or transmits an external action reference anywhere the construction
is not already implied by context (a field name, a schema, a nearby
constant) must carry ``EXTERNAL_ACTION_REF_V1_LABEL`` alongside it, or a
reader has no way to tell this digest apart from any other SHA-256 hex
string, let alone from a section 4.1 ``action_ref``.

Byte parity with the TypeScript reference (``computeExternalActionRefV1``,
agent-passport-system ``src/core/external-action-ref.ts``) on every valid
input in the vector set is checked by
tests/cross_impl/external-action-ref-v1-vectors.json.

Known divergences: the TypeScript computeExternalActionRefV1 rejects
non-string fields and array-wrapped and calendar-invalid timestamps, as this
helper does, and both currently accept a timestamp second of 60 only at
23:59 on the last day of its month (RFC 3339 section 5.7; Appendix D's
``YYYY-MM-DDT23:59:60Z``); this helper rejects every other second-60 value
with ``bad_timestamp``. The remaining difference is that the TypeScript
helper also accepts a ``Date`` object, which this helper does not.
"""

from __future__ import annotations

import hashlib
import re

from .receipt_core.jcs import IJsonValidationError, strict_jcs

# The label identifying this construction (section 4.2, published text lines
# 847-850). Not embedded in the returned digest; see the module docstring.
EXTERNAL_ACTION_REF_V1_LABEL = "action-ref-v1-jcs-sha256"

# Exactly RFC 3339 UTC at millisecond precision: four-digit year, calendar
# month 01-12, calendar day 01-31, hour 00-23, minute 00-59, second 00-60,
# exactly three fractional-second digits, literal uppercase Z. A second of
# 60 is valid only at 23:59 on the last day of its month (RFC 3339 section
# 5.7; Appendix D's "YYYY-MM-DDT23:59:60Z"); that restriction, like the
# calendar-day bound below, is checked separately with integer arithmetic,
# because a fixed-width regex alone cannot encode "day <= 28, 29, 30, or 31
# depending on month and leap year" or "only the last day of this
# particular month". Anchored by re.fullmatch, so no leading/trailing
# anchors are needed in the pattern itself.
_TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    r"T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)\.[0-9]{3}Z"
)

# Days per month in the proleptic Gregorian calendar, non-leap year,
# 1-indexed by (month - 1). February is corrected for leap years below.
_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


class ExternalActionRefError(ValueError):
    """A candidate section 4.2 external correlation input failed validation.

    Carries a stable machine-readable ``code``, exactly one of:
    ``not_string`` (a field is not a string), ``bad_timestamp`` (the
    timestamp is not exactly ``YYYY-MM-DDTHH:MM:SS.sssZ``, names a day that
    does not exist in that month under the proleptic Gregorian calendar, or
    has a second of 60 outside 23:59 on the last day of its month),
    ``lone_surrogate`` (a field contains an unpaired UTF-16 surrogate, which
    has no UTF-8 encoding). A caller can branch on the failure without
    parsing the message.

    Subclasses ``ValueError`` so an existing fail-closed handler that
    catches ``ValueError`` around this construction keeps working.
    """

    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        #: Stable machine-readable failure code. See the class docstring.
        self.code = code


def _is_leap_year(year: int) -> bool:
    """Proleptic Gregorian leap-year rule. Year 0000 is a leap year (0 % 400 == 0)."""
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _days_in_month(year: int, month: int) -> int:
    """Last day-of-month number for `month` of `year`, proleptic Gregorian
    calendar. Pure arithmetic, not `datetime`: `datetime` cannot represent
    year 0000 (MINYEAR=1), and this function must accept it.
    """
    if month == 2 and _is_leap_year(year):
        return 29
    return _DAYS_IN_MONTH[month - 1]


def _is_valid_calendar_day(year: int, month: int, day: int) -> bool:
    """True when `day` exists in `month` of `year` under the proleptic
    Gregorian calendar.
    """
    return day <= _days_in_month(year, month)


def compute_external_action_ref_v1(
    *, action_type: str, agent_id: str, scope: str, timestamp: str
) -> str:
    """Compute the section 4.2 external correlation key (bare hex digest).

    This is the cross-ecosystem correlation key labelled
    ``action-ref-v1-jcs-sha256`` (``EXTERNAL_ACTION_REF_V1_LABEL``). It is a
    correlation key only: it does not identify an APS policy decision,
    approval, dispatch, spend reservation, or receipt, and a matching value
    is evidence of correlation between records, not of the authenticity,
    authority, or integrity of either one (section 9). It must never be
    presented as an ``action_ref`` under section 4.1: that is
    :func:`agent_passport.v2.action_reference.compute_action_ref_v2`, a
    distinct primitive over a distinct preimage. See the module docstring
    for the full set of distinctions.

    ``external_action_ref = lowercase-hex(SHA-256(canonicalize(input_object)))``
    where ``canonicalize`` is RFC 8785 (JCS, via
    :func:`agent_passport.receipt_core.jcs.strict_jcs`), the hash is
    computed over the UTF-8 encoding of the canonicalized JSON, and
    ``input_object`` is exactly ``{action_type, agent_id, scope,
    timestamp}`` (draft lines 852-857). No domain-separation tag is
    prepended; the formula hashes the canonicalized bytes directly.

    Every argument is keyword-only and must be a ``str``, else this raises
    :class:`ExternalActionRefError` with code ``not_string``. ``timestamp``
    must additionally match ``YYYY-MM-DDTHH:MM:SS.sssZ`` (exactly three
    fractional-second digits, literal uppercase ``Z``) and name a day that
    exists in that month under the proleptic Gregorian calendar, else code
    ``bad_timestamp`` (draft lines 866-871: an implementation MUST reject a
    non-conforming timestamp and MUST NOT coerce, truncate, extend, or
    renormalize it). A second of 60 is valid only at 23:59 on the last day
    of its month (RFC 3339 section 5.7; Appendix D's
    ``YYYY-MM-DDT23:59:60Z``); every other second-60 timestamp is also
    ``bad_timestamp``. Any field containing an unpaired UTF-16 surrogate
    raises code ``lone_surrogate``: a lone surrogate has no UTF-8 encoding,
    so the canonicalized JSON cannot be hashed.

    Field values are hashed exactly as supplied: no Unicode normalization,
    no coercion, and no non-empty-string requirement (the section 4.2 text
    states none). The returned value is the bare digest: it carries no
    embedded label, so a caller that serializes it anywhere must carry
    ``EXTERNAL_ACTION_REF_V1_LABEL`` alongside it. See the module docstring.

    The TypeScript reference additionally accepts a ``Date`` object as
    ``timestamp``; this Python port has no such input path and takes
    strings only.
    """
    fields = {
        "action_type": action_type,
        "agent_id": agent_id,
        "scope": scope,
        "timestamp": timestamp,
    }
    for name, value in fields.items():
        if type(value) is not str:
            raise ExternalActionRefError(
                f"compute_external_action_ref_v1: {name} must be a string, "
                f"got {type(value).__name__}",
                "not_string",
            )

    if _TIMESTAMP_RE.fullmatch(timestamp) is None:
        raise ExternalActionRefError(
            f"compute_external_action_ref_v1: timestamp {timestamp!r} must "
            "match YYYY-MM-DDTHH:MM:SS.sssZ (RFC 3339 UTC, exactly three "
            "fractional-second digits, literal uppercase Z)",
            "bad_timestamp",
        )
    year, month, day = int(timestamp[0:4]), int(timestamp[5:7]), int(timestamp[8:10])
    if not _is_valid_calendar_day(year, month, day):
        raise ExternalActionRefError(
            f"compute_external_action_ref_v1: timestamp {timestamp!r} names "
            "a day that does not exist in that month under the proleptic "
            "Gregorian calendar",
            "bad_timestamp",
        )
    if timestamp[17:19] == "60" and (
        day != _days_in_month(year, month)
        or timestamp[11:13] != "23"
        or timestamp[14:16] != "59"
    ):
        raise ExternalActionRefError(
            f"compute_external_action_ref_v1: timestamp {timestamp!r} has "
            "second 60 outside 23:59 on the last day of its month (RFC 3339 "
            "section 5.7; Appendix D)",
            "bad_timestamp",
        )

    preimage = {
        "action_type": action_type,
        "agent_id": agent_id,
        "scope": scope,
        "timestamp": timestamp,
    }
    try:
        canonical = strict_jcs(preimage)
    except IJsonValidationError as exc:
        # Every field is already confirmed to be a plain str above, so the
        # only I-JSON violation strict_jcs can still raise here is an
        # unpaired UTF-16 surrogate inside one of those strings.
        raise ExternalActionRefError(str(exc), "lone_surrogate") from exc

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
