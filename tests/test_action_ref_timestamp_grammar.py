# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The legacy action_ref timestamp accepts only what TypeScript can recompute.

`datetime.fromisoformat` is a convenience parser, not RFC 3339. It took a space
in place of the date-time separator, and it rolled hour 24 into the next day.
The TypeScript normalizer was tightened at 2f9aeeb and refuses both, so a
Python producer could mint an action_ref that no TypeScript verifier could
reproduce. On a content address that is a correctness gap, not a style
difference.

Only those two spellings are refused. The literals below were captured from the
implementation before the change, and every one of them is unchanged after, so
no already-computed action_ref becomes unreproducible.

The uppercase T and Z stay required. This surface has always refused the
lowercase forms while TypeScript accepts them; that divergence is a decided
outcome recorded in the session 1d report, and tightening this function is not
the moment to reopen it.
"""

import pytest

from agent_passport.action_ref import _normalize_timestamp, compute_action_ref


class TestTheTwoSpellingsThatLeftTypeScriptBehind:
    def test_a_space_separator_is_refused(self):
        with pytest.raises(ValueError, match="invalid timestamp"):
            _normalize_timestamp("2026-04-05 03:39:31Z")

    def test_hour_24_is_refused(self):
        # It used to normalize to 2026-04-06T00:00:00Z, giving one instant two
        # spellings and therefore two action_refs.
        with pytest.raises(ValueError, match="hour 24"):
            _normalize_timestamp("2026-04-05T24:00:00Z")

    def test_hour_23_is_still_the_last_accepted_hour(self):
        assert _normalize_timestamp("2026-04-05T23:59:59Z") == "2026-04-05T23:59:59Z"


# Captured from the implementation before this change.
IDENTITY = [
    ("2026-04-05T03:39:31Z", "2026-04-05T03:39:31Z"),
    ("2026-04-05T03:39:31.987Z", "2026-04-05T03:39:31Z"),
    ("2026-04-05T03:39:31.987654Z", "2026-04-05T03:39:31Z"),
    ("2026-04-05T03:39:31+00:00", "2026-04-05T03:39:31Z"),
    ("2026-04-05T12:39:31+09:00", "2026-04-05T03:39:31Z"),
    ("2026-04-04T22:39:31-05:00", "2026-04-05T03:39:31Z"),
    ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
    ("2024-02-29T12:00:00Z", "2024-02-29T12:00:00Z"),
]


class TestEveryRetainedInputKeepsItsExactValue:
    @pytest.mark.parametrize("value,expected", IDENTITY)
    def test_normalizes_to_the_same_string_as_before(self, value, expected):
        assert _normalize_timestamp(value) == expected

    def test_the_action_ref_itself_is_unchanged(self):
        # One instant written six ways, one address, and that address is the
        # value the implementation produced before the grammar was tightened.
        PINNED = "f00d48a5c11c16a535d93c4b2daeed15fefbb5943ac3b4ca58698d2c8bf918f5"
        for value, _ in IDENTITY[:6]:
            assert compute_action_ref("ag_1", "read", "data:read", value) == PINNED
        assert compute_action_ref("ag_1", "read", "data:read", "1970-01-01T00:00:00Z") == \
            "05841c4e4d583afdc5bd3b14b2998574e08d008baa205a324d7397772000e995"
        assert compute_action_ref("ag_1", "read", "data:read", "2024-02-29T12:00:00Z") == \
            "a667db8eaf5a1bb97a3ac24bf33f21dce04eed3d1b34c32a2c61eab064460f97"


class TestWhatWasAlreadyRefusedStaysRefused:
    @pytest.mark.parametrize("value", [
        "2026-04-05T03:39:31",       # zone-less
        "2026-04-05",                # date only
        "2026-02-30T00:00:00Z",      # impossible day
        "2026-04-05t03:39:31z",      # lowercase, the decided divergence
        "  2026-04-05T03:39:31Z  ",  # padded
        "",
        "not-a-date",
    ])
    def test_still_refused(self, value):
        with pytest.raises(ValueError):
            _normalize_timestamp(value)


class TestReAttack:
    """Attacks this item's brief does not list."""

    def test_non_ascii_digits_are_not_digits(self):
        # Python's \\d matches every Unicode decimal digit and int() accepts
        # them. A grammar written with \\d would read this as the year 2026 and
        # mint an action_ref for a timestamp TypeScript cannot even parse.
        with pytest.raises(ValueError):
            _normalize_timestamp("٢٠٢٦-04-05T03:39:31Z")

    def test_a_trailing_newline_is_not_absorbed(self):
        # Python's `$` matches before a final newline; fullmatch does not.
        with pytest.raises(ValueError):
            _normalize_timestamp("2026-04-05T03:39:31Z\n")

    @pytest.mark.parametrize("value", [
        "2026-04-05\t03:39:31Z",     # tab separator
        "2026-04-05T03:39:31+0000",  # offset without a colon
        "2026-04-05T03:39:31+05",    # offset without minutes
        "2026-04-05T3:39:31Z",       # single-digit hour
        "2026-04-05T03:39:31.Z",     # a dot with no digits
    ])
    def test_other_near_miss_spellings_are_refused(self, value):
        with pytest.raises(ValueError):
            _normalize_timestamp(value)

    def test_a_non_string_is_refused_without_reaching_the_parser(self):
        for bad in (None, 12345, 1.5, b"2026-04-05T03:39:31Z", ["2026-04-05T03:39:31Z"]):
            with pytest.raises(ValueError):
                _normalize_timestamp(bad)
