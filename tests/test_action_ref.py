# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Native action_ref: cross-language parity + canonicalization semantics."""

import json
from pathlib import Path

import pytest

from agent_passport.action_ref import (
    DuplicateScopeRequiredError,
    compute_action_ref,
)

VECTORS = json.loads(
    (Path(__file__).parent / "cross_impl" / "actionref-canonical-vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]


def test_parity_vectors_byte_identical():
    """All 4 shared vectors produce byte-identical hex (TS-generated, Go-verified)."""
    assert len(VECTORS) == 4
    for v in VECTORS:
        inp = v["input"]
        got = compute_action_ref(
            inp["agentId"], inp["actionType"], inp["scopeRequired"], inp["timestamp"]
        )
        assert got == v["action_ref"], f"vector {v['name']}: {got} != {v['action_ref']}"


def test_canonical_scope_order_matches_vectors():
    import unicodedata

    for v in VECTORS:
        scopes = v["input"]["scopeRequired"]
        expected = v["canonical_scope_order"]
        got = sorted(unicodedata.normalize("NFC", s) for s in scopes)
        assert got == expected, f"vector {v['name']}"


def test_unsorted_equals_sorted_and_input_not_mutated():
    scopes = ["repo:write", "admin:keys", "commerce:read"]
    a = compute_action_ref("a", "t", scopes, "2026-07-10T00:00:00Z")
    b = compute_action_ref("a", "t", sorted(scopes), "2026-07-10T00:00:00Z")
    assert a == b
    assert scopes == ["repo:write", "admin:keys", "commerce:read"]


def test_nfd_and_nfc_forms_equal():
    nfd = "cafe\u0301:read"  # e + combining acute (NFD)
    nfc = "caf\u00e9:read"   # precomposed e-acute (NFC)
    assert nfd != nfc
    assert compute_action_ref("a", "t", [nfd], "2026-07-10T00:00:00Z") == compute_action_ref(
        "a", "t", [nfc], "2026-07-10T00:00:00Z"
    )


def test_none_scope_preserved_as_null():
    """Matches the TS null-preservation pin (strict JCS keeps null keys)."""
    ref = compute_action_ref("a", "t", None, "2026-05-21T00:00:00Z")
    assert ref == "0c7573a9f120b37bda5648bea097181bf3261c0739c2f465fb878879c21c4c47"


def test_subsecond_timestamps_truncate_to_same_ref():
    a = compute_action_ref("a", "t", ["s:r"], "2026-07-10T00:00:00.001Z")
    b = compute_action_ref("a", "t", ["s:r"], "2026-07-10T00:00:00.999Z")
    assert a == b


# --- spec 4.1 duplicate-free scope_required -------------------------------
# A duplicated array has no canonical form, so it is rejected rather than
# deduplicated: a silent dedupe would map ["a","a"] and ["a"] onto one
# identity with no error, and would change the identity previously computed
# for the duplicated input.

AT = "2026-07-10T00:00:00Z"


def test_raw_duplicate_scope_rejects_with_named_error():
    with pytest.raises(DuplicateScopeRequiredError) as exc:
        compute_action_ref("a", "t", ["a", "a"], AT)
    assert exc.value.category == "invalid_scope_required"
    assert exc.value.reason == "duplicate_scope_required"
    # rejection, not dedupe: the single-element form still computes
    assert len(compute_action_ref("a", "t", ["a"], AT)) == 64


def test_nfc_colliding_duplicate_scope_rejects():
    import unicodedata

    precomposed = "\u00e9"  # U+00E9
    decomposed = "e\u0301"  # e followed by U+0301 combining acute
    assert precomposed != decomposed  # distinct before normalization
    assert unicodedata.normalize("NFC", precomposed) == unicodedata.normalize(
        "NFC", decomposed
    )
    with pytest.raises(DuplicateScopeRequiredError) as exc:
        compute_action_ref("a", "t", [precomposed, decomposed], AT)
    assert exc.value.reason == "duplicate_scope_required"


def test_valid_vectors_byte_unchanged_after_duplicate_rejection():
    """The 4 pinned cross-language vectors are unaffected by the new rejection.

    Asserted against the recorded action_ref values, not recomputed ones.
    """
    for v in VECTORS:
        inp = v["input"]
        got = compute_action_ref(
            inp["agentId"], inp["actionType"], inp["scopeRequired"], inp["timestamp"]
        )
        assert got == v["action_ref"], f"vector {v['name']}: {got} != {v['action_ref']}"
