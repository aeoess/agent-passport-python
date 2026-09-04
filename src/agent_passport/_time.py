# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""UTC timestamp parsing that is correct on Python 3.9+ (matches the TS SDK).

``datetime.fromisoformat`` did not accept a trailing ``Z`` until Python 3.11.
The SDK writes ``Z``-suffixed timestamps and the TS reference issues them, so a
bare ``fromisoformat(ts)`` silently raised ``ValueError`` on the standard form
under the declared minimum interpreter (3.10). Where that error was swallowed,
expiry checks became no-ops (fail open). This helper normalizes ``Z`` to
``+00:00`` first, so a valid timestamp parses on every supported version, and
raises on genuinely malformed input so the caller can fail closed.
"""

import re
from datetime import datetime, timezone
from typing import NamedTuple, Optional


def parse_iso_utc(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp to a timezone-aware UTC datetime.

    Accepts a trailing ``Z`` (UTC designator) on Python 3.9+. A naive
    (offsetless) timestamp is read as UTC, matching how the SDK writes them.
    Raises ``ValueError``/``TypeError`` on malformed input; callers treating an
    unparseable expiry as expired keep the check fail-closed.
    """
    if not isinstance(ts, str):
        raise TypeError(f"timestamp must be str, got {type(ts).__name__}")
    normalized = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ══════════════════════════════════════════════════════════════════
# parse_rfc3339 - the strict timestamp parse for security boundaries
# ══════════════════════════════════════════════════════════════════
# parse_iso_utc above is a compatibility shim for the two callers that
# already fail closed on a raise. It is NOT this. It delegates to
# ``datetime.fromisoformat``, which is a convenience parser, not RFC 3339:
# it accepts a zone-less local time, a bare date, and a space separator,
# it rolls hour 24 into the next day, and it refuses the lowercase 't'/'z'
# that RFC 3339 section 5.6 permits and the TypeScript SDK accepts. An
# accept-set at a boundary has to be stated, not inherited.
#
# Two properties of that stdlib parser matter at a boundary specifically:
#   - ``fromisoformat('2026-01-01T24:00:00Z')`` returns a real instant one
#     day later. RFC 3339 bounds time-hour at 23; 24:00:00 is an ISO 8601
#     end-of-day form denoting the same instant as the next day's 00:00:00,
#     so one instant has two spellings and a window check can be moved by
#     choosing the other one.
#   - ``fromisoformat('2026-01-01T00:00:00')`` returns a naive datetime that
#     callers here promote to UTC, while the TypeScript reference reads the
#     same string as LOCAL time. The two SDKs then disagree about which
#     instant an artifact names, by however many hours the host is offset.
# This function range-checks every field and computes the instant
# arithmetically, so neither string parses.
#
# GRAMMAR ACCEPTED (RFC 3339 5.6 full-date "T" full-time, narrowed):
#   YYYY-MM-DDTHH:MM:SS[.fff...](Z|+-HH:MM)
#   - The date-time separator may be 'T' or 't' and the zero offset 'Z' or
#     'z'. Refusing the lowercase forms would reject conformant third-party
#     artifacts on a verification path, and a lowercase spelling names
#     exactly the same instant. Emission has one spelling: format_rfc3339.
#   - The offset is REQUIRED. A local time with no zone does not denote an
#     instant, so it can never be compared against one.
#
# FRACTIONAL SECONDS: 1 to 9 digits; zero digits after a '.' or more than 9
# is malformed. The instant is truncated (not rounded) to milliseconds, the
# resolution every other time value in this SDK carries. Digits below the
# third are validated for syntax and then discarded, so two strings
# differing only below a millisecond parse to one instant.
#
# LEAP SECONDS: a time-second of 60 is REFUSED with its own reason. RFC 3339
# admits it, but the instant it denotes has no representation on the
# millisecond timeline this SDK compares against, and folding it to :59 or
# to the following :00 would move a boundary. A caller that must carry a
# leap second has to decide what it means before a verifier can.
#
# RANGE: years 0000-9999, the four-digit grammar.
#
# Byte-for-byte the contract of parseRfc3339 in the TypeScript SDK
# (agent-passport-system src/core/rfc3339.ts), including the reason
# vocabulary, so the two implementations refuse the same strings for the
# same stated cause.
# ══════════════════════════════════════════════════════════════════

# ASCII digits only, spelled out rather than \d. Python's \d matches every
# Unicode decimal digit and int() accepts them, so \d would parse
# '\u0662\u0660\u0662\u0666-01-01T00:00:00Z' as the year 2026 while the
# TypeScript \d, which is ASCII-only, refuses it. Two SDKs would disagree on
# whether a timestamp is a timestamp.
_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?"
    r"(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))"
)

#: Why a string was refused. Same vocabulary as the TypeScript SDK.
#:   not_a_string      - input was not a str
#:   malformed         - did not match the accepted grammar
#:   field_out_of_range- grammar matched, a field was outside its RFC 3339
#:                       range, including a day absent from its month and
#:                       hour 24
#:   leap_second       - time-second was 60
#:   not_representable - the instant is not a safe integer of milliseconds
RFC3339_FAILURE_REASONS = (
    "not_a_string",
    "malformed",
    "field_out_of_range",
    "leap_second",
    "not_representable",
)


class Rfc3339ParseResult(NamedTuple):
    """Outcome of :func:`parse_rfc3339`.

    A failed parse carries ``ms=None`` and never an instant, so a caller that
    forgets to test ``ok`` raises a TypeError on the comparison rather than
    silently reading a time out of a failure. That is the whole point: the
    defect this replaces was a comparison against a value that answered
    "not expired" for a string that was not a date.
    """

    ok: bool
    ms: Optional[int]
    reason: Optional[str]


def _days_in_month(year: int, month: int) -> int:
    """Days in ``month`` (1-12) of ``year``, proleptic Gregorian."""
    if month == 2:
        leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days from 1970-01-01 to the given civil date, proleptic Gregorian.

    Integer arithmetic only, mirroring the TypeScript implementation, so that
    year 0001 is placed where the grammar says rather than wherever a
    two-digit-year convenience mapping would put it.
    """
    y = year - (1 if month <= 2 else 0)
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse_rfc3339(value: object) -> Rfc3339ParseResult:
    """Parse an RFC 3339 instant strictly, for use at a security boundary.

    Returns milliseconds since the Unix epoch, or a reason. It never raises
    and never returns a sentinel that compares false in both directions.

    Invariants:
      - Only the grammar documented above is accepted; an absent offset, a
        date-only value, surrounding whitespace, a trailing newline, or an
        empty string is ``malformed``.
      - Every field is range-checked, so 2026-02-30 and 24:00:00 are
        ``field_out_of_range`` rather than instants.
      - Equal instants written with different offsets return the same ``ms``.
      - Sub-millisecond digits are validated and then truncated away.
    """
    if not isinstance(value, str):
        return Rfc3339ParseResult(False, None, "not_a_string")

    # fullmatch, not a '$'-anchored search: Python's '$' also matches before a
    # final newline, so '...Z\n' and '...Z' would be one instant read from two
    # strings.
    m = _RFC3339.fullmatch(value)
    if m is None:
        return Rfc3339ParseResult(False, None, "malformed")

    year, month, day = int(m[1]), int(m[2]), int(m[3])
    hour, minute, second = int(m[4]), int(m[5]), int(m[6])
    frac, zulu, offset_sign, offset_hour, offset_minute = m[7], m[8], m[9], m[10], m[11]

    if second == 60:
        return Rfc3339ParseResult(False, None, "leap_second")
    if month < 1 or month > 12:
        return Rfc3339ParseResult(False, None, "field_out_of_range")
    if day < 1 or day > _days_in_month(year, month):
        return Rfc3339ParseResult(False, None, "field_out_of_range")
    if hour > 23 or minute > 59 or second > 59:
        return Rfc3339ParseResult(False, None, "field_out_of_range")

    offset_seconds = 0
    if zulu is None:
        oh, om = int(offset_hour), int(offset_minute)
        if oh > 23 or om > 59:
            return Rfc3339ParseResult(False, None, "field_out_of_range")
        offset_seconds = (oh * 3600 + om * 60) * (-1 if offset_sign == "-" else 1)

    # Truncate to millisecond granularity; pad so '.1' is 100ms, not 1ms.
    millis = 0 if frac is None else int(frac.ljust(3, "0")[:3])

    days = _days_from_civil(year, month, day)
    ms = (days * 86400 + hour * 3600 + minute * 60 + second - offset_seconds) * 1000 + millis

    # Unreachable for the four-digit-year grammar, because Python integers do
    # not overflow and the widest accepted instant is well inside the range.
    # Kept so both SDKs carry the same reason vocabulary, and so that widening
    # the grammar later fails closed here instead of silently returning an
    # instant the TypeScript side would refuse.
    if abs(ms) > 2**53 - 1:
        return Rfc3339ParseResult(False, None, "not_representable")
    return Rfc3339ParseResult(True, ms, None)


def _civil_from_days(z: int) -> tuple[int, int, int]:
    """Inverse of :func:`_days_from_civil`."""
    zz = z + 719468
    era = zz // 146097
    doe = zz - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + (3 if mp < 10 else -9)
    year = yoe + era * 400 + (1 if month <= 2 else 0)
    return year, month, day


def format_rfc3339(ms: int) -> str:
    """Render an instant as the one spelling this SDK emits.

    ``YYYY-MM-DDTHH:MM:SS.sssZ``, always three fractional digits, always the
    uppercase designators. The counterpart to :func:`parse_rfc3339`.

    This exists because ``datetime.isoformat()`` emits ``+00:00`` and six
    fractional digits, while the TypeScript SDK's ``toISOString()`` emits
    ``.mmmZ``. Where such a value goes into a signed preimage the two spellings
    are different bytes for the same instant, so the signature made by one SDK
    does not verify in the other.
    """
    if isinstance(ms, bool) or not isinstance(ms, int):
        raise TypeError(f"format_rfc3339: ms must be int, got {type(ms).__name__}")
    days, rem = divmod(ms, 86400000)
    year, month, day = _civil_from_days(days)
    if not 0 <= year <= 9999:
        raise ValueError(f"format_rfc3339: year {year} outside the four-digit grammar")
    seconds, millis = divmod(rem, 1000)
    hour, seconds = divmod(seconds, 3600)
    minute, second = divmod(seconds, 60)
    return (
        f"{year:04d}-{month:02d}-{day:02d}"
        f"T{hour:02d}:{minute:02d}:{second:02d}.{millis:03d}Z"
    )


def now_rfc3339() -> str:
    """The current instant in the SDK's one emission spelling."""
    return format_rfc3339(int(datetime.now(timezone.utc).timestamp() * 1000))
