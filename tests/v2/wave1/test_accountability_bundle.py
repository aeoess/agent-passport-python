# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APSBundle — Merkle root + construct + verify + byte-parity."""

import json
from hashlib import sha256
from pathlib import Path

from agent_passport.v2.accountability import (
    APSBundle,
    BundledReceiptRef,
    ScopeOfClaim,
    compute_merkle_root,
    create_aps_bundle,
    verify_aps_bundle,
)

BUNDLER_PRIV = "66" * 32
FIXED_TS = "2026-04-30T00:00:00.000Z"
FIXTURE = (
    Path(__file__).parent.parent
    / "fixtures"
    / "wave1"
    / "accountability"
    / "bundle.fixture.json"
)


def _scope():
    return ScopeOfClaim(
        asserts="Bundler asserts the listed receipt_ids were observed in the declared period.",
        does_not_assert=["That the underlying receipts are themselves valid."],
        capture_mode="gateway_observed",
        completeness="complete",
        self_attested=False,
    )


def test_merkle_empty_is_sha256_of_empty_string():
    assert compute_merkle_root([]) == sha256(b"").hexdigest()


def test_merkle_single_leaf_is_sha256_of_id():
    rid = "abc123"
    assert compute_merkle_root([rid]) == sha256(rid.encode()).hexdigest()


def test_merkle_is_sorted():
    a = compute_merkle_root(["a", "b", "c"])
    b = compute_merkle_root(["c", "b", "a"])
    assert a == b


def test_merkle_odd_duplicates_trailing():
    # Manually compute: sorted=[a,b,c]. Layer1: H(a), H(b), H(c).
    # Layer2: H(H(a)+H(b)), H(H(c)+H(c)).
    # Layer3: H(layer2[0]+layer2[1]).
    ha = sha256(b"a").hexdigest()
    hb = sha256(b"b").hexdigest()
    hc = sha256(b"c").hexdigest()
    n01 = sha256((ha + hb).encode()).hexdigest()
    n22 = sha256((hc + hc).encode()).hexdigest()
    expected = sha256((n01 + n22).encode()).hexdigest()
    assert compute_merkle_root(["a", "b", "c"]) == expected


def test_round_trip_with_two_receipts():
    bundle = create_aps_bundle(
        timestamp=FIXED_TS,
        bundler_did="did:aps:test-bundler",
        period_start=FIXED_TS,
        period_end="2026-05-01T00:00:00.000Z",
        receipts=[
            BundledReceiptRef(receipt_id="x" * 64, claim_type="aps:action:v1"),
            BundledReceiptRef(receipt_id="y" * 64, claim_type="aps:authority_boundary:v1"),
        ],
        profile_conformance=["aps:profile/mva-v1"],
        scope_of_claim=_scope(),
        bundler_private_key=BUNDLER_PRIV,
    )
    v = verify_aps_bundle(bundle)
    assert v["valid"] is True
    assert bundle.receipt_count == 2
    assert len(bundle.merkle_root) == 64


def test_round_trip_with_subject_scope():
    bundle = create_aps_bundle(
        timestamp=FIXED_TS,
        bundler_did="did:aps:test-bundler",
        period_start=FIXED_TS,
        period_end="2026-05-01T00:00:00.000Z",
        receipts=[BundledReceiptRef(receipt_id="z" * 64, claim_type="aps:action:v1")],
        profile_conformance=["aps:profile/mva-v1"],
        scope_of_claim=_scope(),
        bundler_private_key=BUNDLER_PRIV,
        subject_scope=["did:aps:subject-1", "did:aps:subject-2"],
    )
    v = verify_aps_bundle(bundle)
    assert v["valid"] is True
    assert bundle.subject_scope == ["did:aps:subject-1", "did:aps:subject-2"]


def test_empty_bundle_uses_sentinel_merkle():
    bundle = create_aps_bundle(
        timestamp=FIXED_TS,
        bundler_did="did:aps:test-bundler",
        period_start=FIXED_TS,
        period_end="2026-05-01T00:00:00.000Z",
        receipts=[],
        profile_conformance=["aps:profile/mva-v1"],
        scope_of_claim=_scope(),
        bundler_private_key=BUNDLER_PRIV,
    )
    v = verify_aps_bundle(bundle)
    assert v["valid"] is True
    assert bundle.merkle_root == sha256(b"").hexdigest()
    assert bundle.receipt_count == 0


def test_tampered_merkle_root_yields_receipt_id_mismatch():
    bundle = create_aps_bundle(
        timestamp=FIXED_TS,
        bundler_did="did:aps:test-bundler",
        period_start=FIXED_TS,
        period_end="2026-05-01T00:00:00.000Z",
        receipts=[BundledReceiptRef(receipt_id="x" * 64, claim_type="aps:action:v1")],
        profile_conformance=["aps:profile/mva-v1"],
        scope_of_claim=_scope(),
        bundler_private_key=BUNDLER_PRIV,
    )
    bundle.merkle_root = "0" * 64
    v = verify_aps_bundle(bundle)
    assert v["valid"] is False
    assert v["reason"] == "RECEIPT_ID_MISMATCH"


def test_invalid_merkle_root_length_rejected():
    bundle = create_aps_bundle(
        timestamp=FIXED_TS,
        bundler_did="did:aps:test-bundler",
        period_start=FIXED_TS,
        period_end="2026-05-01T00:00:00.000Z",
        receipts=[BundledReceiptRef(receipt_id="x" * 64, claim_type="aps:action:v1")],
        profile_conformance=["aps:profile/mva-v1"],
        scope_of_claim=_scope(),
        bundler_private_key=BUNDLER_PRIV,
    )
    bundle.merkle_root = "0" * 32  # too short
    v = verify_aps_bundle(bundle)
    assert v["valid"] is False
    assert v["reason"] == "INVALID_MERKLE_ROOT"


def test_ts_fixture_byte_parity():
    f = json.loads(FIXTURE.read_text())
    s = f["scope_of_claim"]
    bundle = APSBundle(
        claim_type=f["claim_type"],
        receipt_id=f["receipt_id"],
        timestamp=f["timestamp"],
        signer_did=f["signer_did"],
        scope_of_claim=ScopeOfClaim(
            asserts=s["asserts"],
            does_not_assert=s["does_not_assert"],
            capture_mode=s["capture_mode"],
            completeness=s["completeness"],
            self_attested=s["self_attested"],
        ),
        bundler_did=f["bundler_did"],
        period_start=f["period_start"],
        period_end=f["period_end"],
        merkle_root=f["merkle_root"],
        receipt_count=f["receipt_count"],
        profile_conformance=f["profile_conformance"],
        signature=f["signature"],
        subject_scope=f.get("subject_scope"),
    )
    v = verify_aps_bundle(bundle)
    assert v["valid"] is True, f"byte-parity drift: {v}"
