# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The repaired sites must not drift back to the convenience parser.

Each site below was moved off ``datetime.fromisoformat`` because that parser
accepts a zone-less local time, a bare date and a space separator, rolls hour
24 into the next day, and refuses the lowercase t and z that RFC 3339 permits.
Every one of those is a difference between what this SDK thinks a timestamp on
an artifact means and what the TypeScript SDK thinks it means.

A grep test rather than a behavioral one, because the failure it guards
against is a future edit adding a second parse next to the strict one, which
no fixture would notice until an artifact crossed between the SDKs.

action_ref and receipt_core are deliberately absent from this list. They are
content-address surfaces with their own stricter rules, pinned by
cross-language vectors, and they do not use this parser.
"""

from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "agent_passport"

# Modules whose expiry checks are security boundaries and were repaired.
BOUNDARY_MODULES = [
    "policy.py",
    "values.py",
    "vc_wrapper.py",
    "credential_request.py",
]


@pytest.mark.parametrize("module", BOUNDARY_MODULES)
def test_no_convenience_parse_at_a_boundary(module):
    source = (SRC / module).read_text(encoding="utf-8")
    assert "fromisoformat" not in source, (
        f"{module} parses a timestamp with datetime.fromisoformat again. "
        "Use agent_passport._time.parse_rfc3339: it states its accept-set, "
        "range-checks every field, and refuses rather than raising."
    )


@pytest.mark.parametrize("module", BOUNDARY_MODULES)
def test_each_boundary_module_uses_the_strict_parser(module):
    """The complement of the check above: absence of the old parser is only
    meaningful if the new one is actually there."""
    source = (SRC / module).read_text(encoding="utf-8")
    assert "parse_rfc3339" in source


def test_the_strict_parser_does_not_delegate_to_the_convenience_one():
    """parse_rfc3339 computes the instant arithmetically. If it ever routes
    through fromisoformat or strptime, it inherits their accept-set and this
    whole file stops meaning anything."""
    source = (SRC / "_time.py").read_text(encoding="utf-8")
    body = source.split("def parse_rfc3339", 1)[1]
    body = body.split("\ndef _civil_from_days", 1)[0]
    for banned in ("fromisoformat", "strptime", "dateutil"):
        assert banned not in body, f"parse_rfc3339 delegates to {banned}"
