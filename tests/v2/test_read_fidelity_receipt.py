# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""read_fidelity_receipt (v2): tests.

Mirrors src/v2/read_fidelity_receipt/__tests__/read_fidelity_receipt.test.ts.
The shared parity vectors file (byte-identical copy of the TS-generated
read-fidelity-receipt-v0.1-vectors.json) is loaded and every value in
it is reproduced by this implementation: jcs kats (canonical bytes and
sha256), seed kats, exact sampler spans, and the signed record case
(canonical_no_sig sha256, signature verification, deterministic
re-sign parity).

Deterministic throughout: every digest, nonce, seed, and source text
is a fixed string or derived from sha256 over a fixed label. No wall
clock, no randomness.
"""

import hashlib
import json
import re
from pathlib import Path

import pytest

from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import public_key_from_private, sign, verify as ed_verify
from agent_passport.v2.read_fidelity_receipt import (
    canonical_no_sig,
    commit_spans,
    create_read_fidelity_receipt,
    derive_seed,
    sample_spans,
    score_responses,
    verify_against_source,
    verify_read_fidelity_receipt,
    verify_responses,
)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "read-fidelity-receipt"
    / "read-fidelity-receipt-v0.1-vectors.json"
)
VECTORS = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_record(presentation_digest=None, responses=None, k=None):
    """Build a fresh, internally consistent signed record for mutation
    tests. Mirrors the TS test helper."""
    private_key = sha256_hex("rf-test key v1")
    source = (
        "A deterministic test source with enough characters to sample "
        "several spans from, none of them overlapping the ends badly."
    )
    content_digest = f"sha256:{sha256_hex('rf-test content v1')}"
    nonce = "rf-test-nonce-1"
    version = "1"
    seed = derive_seed(content_digest, presentation_digest, nonce, version)
    n = 4
    span_len = 10
    spans = sample_spans(source, seed, n, span_len)
    span_texts = [s["text"] for s in spans]
    if responses is None:
        responses = span_texts
    if k is None:
        k = score_responses(span_texts, responses)["k"]
    record = create_read_fidelity_receipt(
        {
            "content_digest": content_digest,
            "presentation_digest": presentation_digest,
            "challenge": {
                "nonce": nonce,
                "seed": seed,
                "algorithm": "span_sample_v1",
                "version": version,
                "span_len": span_len,
                "span_commitments": commit_spans(span_texts),
            },
            "response_digest": f"sha256:{sha256_hex(canonicalize_jcs(responses))}",
            "k": k,
            "n": n,
            "scoring_method": "exact_match_v1",
            "model_claim": "test-model-v1",
            "runtime_claim": "test-runtime-v1",
            "verification_method": "asserted",
            "challenge_issued_at": "2026-07-04T00:00:00Z",
            "response_observed_at": "2026-07-04T00:00:01Z",
            "receipt_issued_at": "2026-07-04T00:00:02Z",
        },
        private_key,
    )
    return {
        "record": record,
        "source": source,
        "span_texts": span_texts,
        "private_key": private_key,
    }


def resign(record: dict, private_key: str) -> dict:
    """Re-sign a mutated record body with the given key (sig excluded
    from the preimage)."""
    return {**record, "sig": sign(canonical_no_sig(record), private_key)}


class TestSeedDerivation:
    def test_matches_independent_recompute_with_presentation_digest(self):
        content = f"sha256:{sha256_hex('rf-seed-check:content')}"
        presentation = f"sha256:{sha256_hex('rf-seed-check:presentation')}"
        nonce = "rf-seed-check-nonce"
        expected = sha256_hex(content + presentation + nonce + "1")
        assert derive_seed(content, presentation, nonce, "1") == expected

    def test_substitutes_empty_string_for_null_presentation_digest(self):
        content = f"sha256:{sha256_hex('rf-seed-check:content-null')}"
        nonce = "rf-seed-check-nonce-null"
        expected = sha256_hex(content + "" + nonce + "1")
        assert derive_seed(content, None, nonce, "1") == expected
        assert derive_seed(content, None, nonce, "1") != derive_seed(
            content, f"sha256:{'0' * 64}", nonce, "1"
        )

    def test_reproduces_both_seed_kats_from_shared_vectors(self):
        kats = VECTORS["seed_kats"]
        assert len(kats) == 2
        assert any(kat["presentation_digest"] is not None for kat in kats)
        assert any(kat["presentation_digest"] is None for kat in kats)
        for kat in kats:
            assert (
                derive_seed(
                    kat["content_digest"],
                    kat["presentation_digest"],
                    kat["nonce"],
                    kat["version"],
                )
                == kat["seed"]
            ), f"seed KAT {kat['name']}"


class TestSampler:
    def test_deterministic_for_identical_inputs(self):
        seed = sha256_hex("rf-sampler-det:seed")
        source = "determinism check source text, long enough to sample from"
        assert sample_spans(source, seed, 5, 8) == sample_spans(source, seed, 5, 8)

    def test_reproduces_every_sampler_case_in_shared_vectors(self):
        cases = VECTORS["sampler_cases"]
        assert len(cases) == 3
        for c in cases:
            spans = sample_spans(c["source"], c["seed"], c["n"], c["span_len"])
            assert spans == c["spans"], f"sampler case {c['name']}"

    def test_distinct_positions_exhausting_range_when_n_equals_it(self):
        seed = sha256_hex("rf-sampler-distinct:seed")
        source = "abcdefghijklmnop"  # 16 code points
        span_len = 5
        position_range = len(source) - span_len + 1  # 12
        spans = sample_spans(source, seed, position_range, span_len)
        positions = [s["pos"] for s in spans]
        assert len(set(positions)) == position_range
        assert all(0 <= pos < position_range for pos in positions)

    def test_raises_when_n_exceeds_position_range(self):
        seed = sha256_hex("rf-sampler-range:seed")
        with pytest.raises(ValueError, match="n 7 exceeds the position range 6"):
            sample_spans("abcdefghij", seed, 7, 5)
        with pytest.raises(ValueError, match="need at least span_len 5"):
            sample_spans("abc", seed, 1, 5)
        with pytest.raises(ValueError, match="positive integer"):
            sample_spans("abcdef", seed, 0, 2)
        with pytest.raises(ValueError, match="positive integer"):
            sample_spans("abcdef", seed, 1, 0)

    def test_slices_by_code_points_never_splitting_astral_chars(self):
        seed = sha256_hex("rf-sampler-unicode:seed")
        source = "аб🔐вг🙂дежз🌍ийкл"  # cyrillic plus astral emoji
        cps = list(source)
        span_len = 3
        position_range = len(cps) - span_len + 1
        spans = sample_spans(source, seed, position_range, span_len)
        for span in spans:
            assert len(list(span["text"])) == span_len
            assert span["text"] == "".join(cps[span["pos"] : span["pos"] + span_len])
        # The emoji-bearing vector case double-checks against the fixture.
        c = VECTORS["sampler_cases"][1]
        assert c["name"] == "case2_emoji_cyrillic"
        for s in c["spans"]:
            assert len(list(s["text"])) == s["len"]

    def test_scores_responses_by_exact_string_equality_only(self):
        span_texts = ["alpha", "beta", "gamma"]
        scored = score_responses(span_texts, ["alpha", "Beta", "gamma"])
        assert scored["k"] == 2
        assert scored["results"] == [True, False, True]
        with pytest.raises(ValueError, match="does not match span count"):
            score_responses(span_texts, ["alpha"])


class TestCreateAndVerify:
    def test_creates_record_that_verifies_attester_from_key(self):
        built = build_record()
        record = built["record"]
        assert record["type"] == "read_fidelity_receipt"
        assert record["attester"] == public_key_from_private(built["private_key"])
        assert re.fullmatch(r"[0-9a-f]{128}", record["sig"]) is not None
        assert verify_read_fidelity_receipt(record) == {"valid": True}

    def test_fails_signature_when_content_digest_tampered_after_signing(self):
        built = build_record()
        tampered = {
            **built["record"],
            "content_digest": f"sha256:{sha256_hex('rf-tampered content')}",
        }
        res = verify_read_fidelity_receipt(tampered)
        assert res["valid"] is False
        assert res["reason"] == "SIGNATURE_INVALID"

    def test_replayed_nonce_fails_on_seed_derivation_even_resigned(self):
        built = build_record()
        record = built["record"]
        # Replay: same commitments and responses under a NEW nonce. The
        # attacker re-signs, so the signature is valid; the seed no
        # longer matches the derivation and the reason names the seed.
        replayed = resign(
            {
                **record,
                "challenge": {**record["challenge"], "nonce": "rf-replayed-nonce-2"},
            },
            built["private_key"],
        )
        assert ed_verify(
            canonical_no_sig(replayed), replayed["sig"], replayed["attester"]
        )
        res = verify_read_fidelity_receipt(replayed)
        assert res["valid"] is False
        assert res["reason"] == "SEED_MISMATCH"

    def test_swapped_presentation_digest_fails_on_seed_even_resigned(self):
        built = build_record(
            presentation_digest=f"sha256:{sha256_hex('rf-presentation v1')}"
        )
        assert verify_read_fidelity_receipt(built["record"]) == {"valid": True}
        swapped = resign(
            {
                **built["record"],
                "presentation_digest": f"sha256:{sha256_hex('rf-presentation v2')}",
            },
            built["private_key"],
        )
        assert ed_verify(canonical_no_sig(swapped), swapped["sig"], swapped["attester"])
        res = verify_read_fidelity_receipt(swapped)
        assert res["valid"] is False
        assert res["reason"] == "SEED_MISMATCH"

    def test_rejects_n_mismatch_with_span_commitments_at_create(self):
        built = build_record()
        fields = {
            key: value
            for key, value in built["record"].items()
            if key not in ("type", "attester", "sig")
        }
        with pytest.raises(
            ValueError,
            match=r"n \(5\) must equal challenge\.span_commitments\.length \(4\)",
        ):
            create_read_fidelity_receipt(
                {**fields, "n": fields["n"] + 1}, sha256_hex("rf-test key v1")
            )

    def test_rejects_n_mismatch_with_span_commitments_at_verify(self):
        built = build_record()
        mismatched = resign(
            {**built["record"], "n": built["record"]["n"] + 1}, built["private_key"]
        )
        res = verify_read_fidelity_receipt(mismatched)
        assert res["valid"] is False
        assert res["reason"] == "N_MISMATCH"

    def test_rejects_seed_that_does_not_match_derivation_at_create(self):
        built = build_record()
        fields = {
            key: value
            for key, value in built["record"].items()
            if key not in ("type", "attester", "sig")
        }
        with pytest.raises(ValueError, match="seed"):
            create_read_fidelity_receipt(
                {
                    **fields,
                    "challenge": {
                        **fields["challenge"],
                        "seed": sha256_hex("rf-wrong-seed"),
                    },
                },
                sha256_hex("rf-test key v1"),
            )


class TestVerifyAgainstSource:
    def test_fully_passes_on_fixture_record_over_fixture_source(self):
        record = VECTORS["record_case"]["record"]
        source = VECTORS["sampler_cases"][0]["source"]
        res = verify_against_source(record, source)
        assert res["valid"] is True
        assert "reason" not in res
        assert res["signature_valid"] is True
        assert res["seed_valid"] is True
        assert res["commitment_matches"] == [True] * record["n"]

    def test_reports_commitment_mismatches_against_different_source(self):
        record = VECTORS["record_case"]["record"]
        wrong_source = (
            "An entirely different source text that still has enough length "
            "for the sampler to draw all of its spans from without throwing."
        )
        res = verify_against_source(record, wrong_source)
        assert res["valid"] is False
        assert res["reason"] == "COMMITMENT_MISMATCH"
        assert res["signature_valid"] is True
        assert res["seed_valid"] is True
        assert any(m is False for m in res["commitment_matches"])

    def test_reports_span_recompute_failed_when_source_too_short(self):
        record = VECTORS["record_case"]["record"]
        res = verify_against_source(record, "too short")
        assert res["valid"] is False
        assert res["reason"] == "SPAN_RECOMPUTE_FAILED"
        assert res["commitment_matches"] == []


class TestVerifyResponses:
    def test_recomputes_k_equals_n_for_fixture_with_faithful_responses(self):
        record = VECTORS["record_case"]["record"]
        source = VECTORS["sampler_cases"][0]["source"]
        responses = [s["text"] for s in VECTORS["sampler_cases"][0]["spans"]]
        res = verify_responses(record, source, responses)
        assert res["k_recomputed"] == record["n"]
        assert res["matches_claimed_k"] is True
        assert res["response_digest_ok"] is True

    def test_recomputes_honest_k_below_n_for_one_missed_span(self):
        base = build_record()
        degraded = list(base["span_texts"])
        degraded[2] = f"{degraded[2]}!"
        built = build_record(responses=degraded)
        record = built["record"]
        assert record["k"] == len(base["span_texts"]) - 1
        assert verify_read_fidelity_receipt(record) == {"valid": True}
        res = verify_responses(record, built["source"], degraded)
        assert res["k_recomputed"] == record["n"] - 1
        assert res["matches_claimed_k"] is True
        assert res["response_digest_ok"] is True

    def test_flags_claimed_k_the_responses_do_not_support(self):
        base = build_record()
        degraded = list(base["span_texts"])
        degraded[0] = f"{degraded[0]} "
        res = verify_responses(base["record"], base["source"], degraded)
        assert res["k_recomputed"] == base["record"]["n"] - 1
        assert res["matches_claimed_k"] is False
        assert res["response_digest_ok"] is False


class TestRecordCaseFixtureParity:
    def test_reproduces_canonical_no_sig_sha256_and_signature_verifies(self):
        case = VECTORS["record_case"]
        record = case["record"]
        canonical = canonical_no_sig(record)
        assert sha256_hex(canonical) == case["canonical_no_sig_sha256"]
        assert case["signature_valid"] is True
        assert ed_verify(canonical, record["sig"], record["attester"])
        assert record["attester"] == public_key_from_private(case["private_key_hex"])
        assert verify_read_fidelity_receipt(record) == {"valid": True}

    def test_resigning_record_body_with_fixture_key_yields_identical_sig(self):
        case = VECTORS["record_case"]
        record = case["record"]
        # Ed25519 is deterministic: re-signing the identical canonical
        # body with the fixture key must reproduce the recorded sig.
        assert sign(canonical_no_sig(record), case["private_key_hex"]) == record["sig"]

    def test_recreating_the_record_via_create_yields_identical_sig(self):
        case = VECTORS["record_case"]
        record = case["record"]
        fields = {
            key: value
            for key, value in record.items()
            if key not in ("type", "attester", "sig")
        }
        recreated = create_read_fidelity_receipt(fields, case["private_key_hex"])
        assert recreated == record

    def test_binds_record_to_fixture_constants_from_build_contract(self):
        case = VECTORS["record_case"]
        record = case["record"]
        assert case["private_key_hex"] == sha256_hex("read-fidelity fixture key v1")
        assert (
            record["content_digest"]
            == f"sha256:{sha256_hex('read-fidelity fixture content v1')}"
        )
        assert record["presentation_digest"] is None
        assert record["challenge"]["nonce"] == "fixture-nonce-1"
        assert record["challenge"]["version"] == "1"
        assert record["k"] == record["n"]
        assert record["n"] == len(record["challenge"]["span_commitments"])
        # The fixture commitments are the commitments of sampler case 1 texts.
        assert record["challenge"]["span_commitments"] == commit_spans(
            [s["text"] for s in VECTORS["sampler_cases"][0]["spans"]]
        )


class TestSharedVectorsFileIntegrity:
    def test_replays_every_jcs_kat_including_unicode(self):
        kats = VECTORS["jcs_kats"]
        assert len(kats) >= 4
        assert any(k["name"] == "unicode_emoji_cyrillic" for k in kats)
        for kat in kats:
            assert canonicalize_jcs(kat["value"]) == kat["canonical"], (
                f"jcs KAT {kat['name']}"
            )
            assert sha256_hex(kat["canonical"]) == kat["sha256"], f"jcs KAT {kat['name']}"
