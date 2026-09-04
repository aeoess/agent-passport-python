# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The accept-set of the boundary timestamp parser, stated rather than inherited.

``datetime.fromisoformat`` is a convenience parser, not RFC 3339. It takes a
zone-less local time, a bare date and a space separator; it rolls hour 24 into
the next day; and it refuses the lowercase ``t``/``z`` that RFC 3339 section 5.6
permits and the TypeScript SDK accepts. Every one of those is a difference
between what this SDK thinks a timestamp on an artifact means and what the
other SDK thinks it means, and the artifact's author chooses which to exploit.

So the grammar is written out and every field range-checked, and the last class
here pins the result against vectors generated from the TypeScript
implementation itself.
"""

import json
from pathlib import Path

import pytest


class TestStrictParseContract:
    """The accept-set of the boundary parser, mirroring the frozen TypeScript
    tables in agent-passport-system tests/rfc3339.test.ts."""

    def _parse(self, value):
        from agent_passport._time import parse_rfc3339
        return parse_rfc3339(value)

    @pytest.mark.parametrize("value,ms", [
        ("1970-01-01T00:00:00Z", 0),
        ("2026-01-01T00:00:00Z", 1767225600000),
        ("2026-01-01T00:00:00.123Z", 1767225600123),
        # RFC 3339 5.6 permits lowercase; the same instant, spelled two ways.
        ("2026-01-01t00:00:00z", 1767225600000),
        # Equal instants written with different offsets are one instant.
        ("2026-01-01T05:30:00+05:30", 1767225600000),
        ("2025-12-31T18:30:00-05:30", 1767225600000),
        # Sub-millisecond digits are validated, then truncated, not rounded.
        ("2026-01-01T00:00:00.123999Z", 1767225600123),
        ("2026-01-01T00:00:00.1Z", 1767225600100),
        ("2026-01-01T00:00:00.123456789Z", 1767225600123),
        # Leap day in a leap year is a real day.
        ("2024-02-29T00:00:00Z", 1709164800000),
    ])
    def test_accepts(self, value, ms):
        result = self._parse(value)
        assert result.ok is True
        assert result.ms == ms

    @pytest.mark.parametrize("value,reason", [
        # No offset does not denote an instant.
        ("2026-01-01T00:00:00", "malformed"),
        ("2026-01-01", "malformed"),
        ("2026-01-01 00:00:00Z", "malformed"),
        ("", "malformed"),
        ("not-a-date", "malformed"),
        ("  2026-01-01T00:00:00Z  ", "malformed"),
        ("2026-01-01T00:00:00.Z", "malformed"),
        ("2026-01-01T00:00:00.1234567890Z", "malformed"),
        ("2026-01-01T00:00:00ZZ", "malformed"),
        ("+002026-01-01T00:00:00Z", "malformed"),
        # A day that does not exist in its month must not roll forward.
        ("2026-02-30T00:00:00Z", "field_out_of_range"),
        ("2026-04-31T00:00:00Z", "field_out_of_range"),
        ("2025-02-29T00:00:00Z", "field_out_of_range"),
        ("2026-13-01T00:00:00Z", "field_out_of_range"),
        ("2026-00-01T00:00:00Z", "field_out_of_range"),
        ("2026-01-00T00:00:00Z", "field_out_of_range"),
        # RFC 3339 bounds time-hour at 23.
        ("2026-01-01T24:00:00Z", "field_out_of_range"),
        ("2026-01-01T00:60:00Z", "field_out_of_range"),
        ("2026-01-01T00:00:00+24:00", "field_out_of_range"),
        ("2026-01-01T00:00:00+00:60", "field_out_of_range"),
        # A leap second has no representation on the millisecond timeline.
        ("2026-12-31T23:59:60Z", "leap_second"),
    ])
    def test_refuses(self, value, reason):
        result = self._parse(value)
        assert result.ok is False
        assert result.reason == reason
        assert result.ms is None, "a failed parse must not carry an instant"

    @pytest.mark.parametrize("value", [None, 12345, 1.5, True, b"2026-01-01T00:00:00Z", ["2026-01-01T00:00:00Z"]])
    def test_refuses_non_strings(self, value):
        result = self._parse(value)
        assert result.ok is False
        assert result.reason == "not_a_string"

    def test_a_trailing_newline_is_not_absorbed(self):
        """Python's `$` matches before a final newline; `fullmatch` does not.
        A verifier that accepted this would read one instant from two strings."""
        assert self._parse("2026-01-01T00:00:00Z\n").ok is False

    @pytest.mark.parametrize("value", [
        "٢٠٢٦-01-01T00:00:00Z",   # Arabic-Indic year
        "2026-०१-01T00:00:00Z",             # Devanagari month
    ])
    def test_non_ascii_digits_are_not_digits(self, value):
        """Python's `\\d` matches Unicode decimal digits and `int()` accepts
        them; the frozen TypeScript `\\d` is ASCII-only. Accepting these would
        make two SDKs disagree on whether a timestamp is even a timestamp."""
        assert self._parse(value).ok is False

    def test_the_grammar_is_anchored_at_both_ends(self):
        for prefix in ("x", " ", "\t"):
            assert self._parse(prefix + "2026-01-01T00:00:00Z").ok is False
            assert self._parse("2026-01-01T00:00:00Z" + prefix).ok is False


class TestCrossImplementationParity:
    """The two SDKs must refuse the same strings for the same stated cause.

    A timestamp is carried on an artifact that crosses between them. If one
    reads an instant where the other reads nothing, or reads a different
    instant, then an expiry window has two different ends depending on who is
    checking, and the artifact's author picks which.
    """

    VECTORS = json.loads(
        (Path(__file__).parent / "cross_impl" / "rfc3339-vectors.json").read_text(encoding="utf-8")
    )["vectors"]

    @pytest.mark.parametrize("vector", VECTORS, ids=lambda v: repr(v["input"]))
    def test_matches_the_typescript_reference(self, vector):
        from agent_passport._time import format_rfc3339, parse_rfc3339
        result = parse_rfc3339(vector["input"])
        assert result.ok is vector["ok"]
        if vector["ok"]:
            assert result.ms == vector["ms"]
            assert format_rfc3339(result.ms) == vector["formatted"]
        else:
            assert result.reason == vector["reason"]
