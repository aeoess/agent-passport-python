# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance and cross-language parity for the PROPOSED multi-source status decision.

Every expectation comes from conformance/status-coverage/v0/vectors.json, which is the
SHARED fixture: the TypeScript SDK authors it and this repository vendors a byte-identical
copy, so the same cases run through both ports. Expectations are hand specified in the
vectors, never computed by the code under test, so the test is not circular. The file's
SHA-256 is pinned in both repositories, so the two copies can be shown identical without
either repository importing the other.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os

import pytest

from agent_passport import (
    DETERMINATE_STATUS_ANSWERS,
    STATUS_ANSWERS,
    STATUS_COVERAGE_REASON_CODES,
    STATUS_USE_BASES,
    DeclaredStatusSource,
    RequiredSourceSet,
    SnapshotSource,
    StaleAnswerPolicy,
    StatusAnswerInput,
    StatusCoverageError,
    StatusTrustPolicy,
    decide_multi_source_status,
    verify_authority_delegation_chain,
)

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "conformance", "status-coverage", "v0", "vectors.json"
)
with open(_VECTORS_PATH, "rb") as _handle:
    _VECTORS_BYTES = _handle.read()
_VECTORS = json.loads(_VECTORS_BYTES.decode("utf-8"))

# Pinned so the TypeScript SDK's authoring copy can be shown byte identical. If this
# moves, the TypeScript repo's copy and its own pin move with it, in the same change.
_VECTORS_SHA256 = "dc3c0165d9e90488a772c14ffe2ba64fefe90c504b7d48d8aa3cd916bd6649e5"


def _trust_policy(raw: dict) -> StatusTrustPolicy:
    """Build the typed trust policy from the fixture's wire form.

    Only shapes the fixture states well are typed. A vector that deliberately omits
    `silence_is` or names an unknown mode is handed through as the raw mapping, so the
    module's own refusal is what the test observes rather than a dataclass TypeError.
    """
    sources = raw.get("sources")
    if not isinstance(sources, dict) or "silence_is" not in sources or not isinstance(
        sources.get("required"), list
    ):
        return raw  # type: ignore[return-value]
    required = []
    for declared in sources["required"]:
        if set(declared) != {"source_id", "freshness_bound_s"}:
            return raw  # type: ignore[return-value]
        required.append(
            DeclaredStatusSource(
                source_id=declared["source_id"],
                freshness_bound_s=declared["freshness_bound_s"],
            )
        )
    snapshot = raw.get("snapshot_source")
    return StatusTrustPolicy(
        mode=raw["mode"],
        sources=RequiredSourceSet(
            required=tuple(required), silence_is=sources["silence_is"]
        ),
        snapshot_source=(
            None
            if snapshot is None
            else SnapshotSource(
                source_id=snapshot["source_id"],
                declared_bound_s=snapshot["declared_bound_s"],
            )
        ),
    )


def _stale_policy(raw: object) -> object:
    if isinstance(raw, dict) and set(raw) == {
        "stale_revoked_still_counts",
        "stale_active_still_counts",
    }:
        return StaleAnswerPolicy(**raw)
    return raw


def _answers(raw: object) -> object:
    if not isinstance(raw, list):
        return raw
    out = []
    for item in raw:
        if set(item) <= {"source_id", "answer", "as_of"} and "source_id" in item:
            out.append(
                StatusAnswerInput(
                    source_id=item["source_id"],
                    answer=item.get("answer"),
                    as_of=item.get("as_of"),
                )
            )
        else:
            out.append(item)
    return out


def _call(raw: dict):
    """Run one vector through the port.

    The vectors use the wire names. This port takes keyword arguments in snake_case,
    exactly as the TypeScript port takes camelCase for the three parameters that are not
    part of the record. Nothing else is translated.
    """
    return decide_multi_source_status(
        authority_ref=raw["authority_ref"],
        trust_policy=_trust_policy(raw["trust_policy"]),
        answers=_answers(raw["answers"]),
        conflict_policy=raw["conflict_policy"],
        stale_policy=_stale_policy(raw["stale_policy"]),
        now=raw["now"],
    )


def _as_json(value) -> object:
    """A JSON-shaped view of a dataclass tree, so the comparison against the shared
    vectors is the same comparison the TypeScript port makes."""
    return json.loads(json.dumps(dataclasses.asdict(value)))


def _lifecycle_as_plain(result) -> dict:
    out: dict = {"verdict": result.verdict, "reason_code": result.reason_code}
    if result.missing is not None:
        out["missing"] = list(result.missing)
    if result.applied_default is not None:
        out["applied_default"] = result.applied_default
    if result.outstanding is not None:
        out["outstanding"] = [dataclasses.asdict(c) for c in result.outstanding]
    return out


class TestSharedFixture:
    def test_the_vectors_file_is_the_pinned_bytes(self) -> None:
        assert hashlib.sha256(_VECTORS_BYTES).hexdigest() == _VECTORS_SHA256

    def test_the_fixture_declares_the_profile_this_module_implements(self) -> None:
        assert _VECTORS["profile"] == "aps-status-coverage-v0"

    def test_the_vocabulary_in_the_fixture_is_the_vocabulary_in_the_code(self) -> None:
        vocab = _VECTORS["vocabulary"]
        assert list(STATUS_ANSWERS) == vocab["status_answers"]
        assert list(DETERMINATE_STATUS_ANSWERS) == vocab["determinate_status_answers"]
        assert list(STATUS_USE_BASES) == vocab["status_use_bases"]
        assert list(STATUS_COVERAGE_REASON_CODES) == vocab["reason_codes"]

    def test_every_case_id_is_unique(self) -> None:
        ids = [c["id"] for c in _VECTORS["decision_cases"]] + [
            c["id"] for c in _VECTORS["error_cases"]
        ]
        assert len(set(ids)) == len(ids)


@pytest.mark.parametrize(
    "vector", _VECTORS["decision_cases"], ids=[c["id"] for c in _VECTORS["decision_cases"]]
)
def test_decision_vector(vector: dict) -> None:
    decision = _call(vector["input"])
    expected = vector["expected"]
    assert decision.outcome == expected["outcome"]
    assert decision.reason_code == expected["reason_code"]
    assert _lifecycle_as_plain(decision.lifecycle) == expected["lifecycle"]
    assert _as_json(decision.basis) == expected["basis"]


@pytest.mark.parametrize(
    "vector", _VECTORS["error_cases"], ids=[c["id"] for c in _VECTORS["error_cases"]]
)
def test_refusal_vector(vector: dict) -> None:
    with pytest.raises(StatusCoverageError) as caught:
        _call(vector["input"])
    assert caught.value.code == vector["expected"]["error_code"]


_BASE_INPUT = {
    "authority_ref": "delegation:alpha",
    "trust_policy": {
        "mode": "online",
        "sources": {
            "required": [{"source_id": "registry-a", "freshness_bound_s": 300}],
            "silence_is": "coverage_gap",
        },
    },
    "answers": [
        {"source_id": "registry-a", "answer": "active", "as_of": "2026-09-20T11:59:00Z"}
    ],
    "conflict_policy": "deny_with_conflict",
    "stale_policy": {
        "stale_revoked_still_counts": True,
        "stale_active_still_counts": False,
    },
    "now": "2026-09-20T12:00:00Z",
}


def _vector(case_id: str) -> dict:
    for case in _VECTORS["decision_cases"]:
        if case["id"] == case_id:
            return case
    raise AssertionError(f"no such vector: {case_id}")


class TestPropertiesTheVectorsCannotState:
    def test_a_later_boundary_never_rewrites_an_earlier_decision(self) -> None:
        # SC-02 then SC-18. The earlier record is held across the later decision and
        # compared afterwards. Later findings never rewrite earlier receipts: the second
        # boundary is a new decision that says nothing about the first.
        earlier = _call(_vector("SC-02-two-sources-agree-active-admits")["input"])
        earlier_snapshot = _as_json(earlier.basis)
        later = _call(_vector("SC-18-later-boundary-conflicts")["input"])
        assert later.outcome == "denied"
        assert _as_json(earlier.basis) == earlier_snapshot
        assert earlier.outcome == "authorized"

    def test_the_decision_is_immutable(self) -> None:
        decision = _call(_BASE_INPUT)
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.outcome = "denied"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.basis.coverage.complete = False  # type: ignore[misc]
        assert isinstance(decision.basis.sources_consulted, tuple)

    def test_the_caller_input_is_not_mutated(self) -> None:
        before = json.dumps(_BASE_INPUT, sort_keys=True)
        _call(_BASE_INPUT)
        assert json.dumps(_BASE_INPUT, sort_keys=True) == before

    def test_the_module_reads_no_clock(self) -> None:
        first = _call(_BASE_INPUT)
        second = _call(_BASE_INPUT)
        assert _as_json(first.basis) == _as_json(second.basis)
        assert first.reason_code == second.reason_code

    def test_a_null_as_of_on_an_unavailable_answer_is_the_same_as_an_absent_one(
        self,
    ) -> None:
        # Python has one absent value where TypeScript has two. A vector that writes
        # "as_of": null must not decide differently from one that omits the key.
        omitted = _call(
            {**_BASE_INPUT, "answers": [{"source_id": "registry-a", "answer": "unavailable"}]}
        )
        explicit_null = _call(
            {
                **_BASE_INPUT,
                "answers": [
                    {"source_id": "registry-a", "answer": "unavailable", "as_of": None}
                ],
            }
        )
        assert _as_json(omitted.basis) == _as_json(explicit_null.basis)
        assert explicit_null.reason_code == "STATUS_NO_USABLE_OBSERVATION"

    def test_a_not_established_decision_always_names_at_least_one_limb(self) -> None:
        for case in _VECTORS["decision_cases"]:
            decision = _call(case["input"])
            if decision.lifecycle.verdict == "not_established":
                assert decision.lifecycle.missing, f"{case['id']} named no limb"

    def test_a_conflict_never_makes_the_artifact_invalid_and_never_admits(self) -> None:
        for case in _VECTORS["decision_cases"]:
            decision = _call(case["input"])
            if decision.basis.conflict is not None:
                assert decision.lifecycle.verdict == "not_established"
                assert decision.outcome != "authorized"

    def test_an_offline_admission_records_the_snapshot_and_the_age(self) -> None:
        # The `offline-admit-without-recording` control: an admission whose record cannot
        # be recomputed from itself is the defect this field exists to catch.
        for case in _VECTORS["decision_cases"]:
            decision = _call(case["input"])
            if decision.reason_code == "ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND":
                assert decision.outcome == "authorized"
                snapshot = decision.basis.snapshot
                assert snapshot is not None
                assert isinstance(snapshot.as_of, str)
                assert isinstance(snapshot.age_s, int)
                assert snapshot.age_s <= snapshot.declared_bound_s
            else:
                assert decision.basis.snapshot is None

    def test_the_basis_echoes_both_policies_and_the_silence_reading_back(self) -> None:
        # A record that does not say which reading produced it cannot be compared against
        # a record produced under the other reading.
        decision = _call(_BASE_INPUT)
        assert decision.basis.conflict_policy == "deny_with_conflict"
        assert decision.basis.stale_policy.stale_revoked_still_counts is True
        assert decision.basis.stale_policy.stale_active_still_counts is False
        assert decision.basis.silence_is == "coverage_gap"
        assert sorted(dataclasses.asdict(decision.basis.stale_policy)) == [
            "stale_active_still_counts",
            "stale_revoked_still_counts",
        ]


class TestNothingExistingChanged:
    def test_chain_verification_still_returns_its_own_vocabulary(self) -> None:
        # The module is reported ALONGSIDE a chain result and never merged into it.
        result = verify_authority_delegation_chain(
            [],
            now="2026-09-20T12:00:00Z",
            resolve_verification_key=lambda _issuer, _method: None,
            trust_root=lambda _candidate: False,
            resolve_revocation=lambda _delegation: "active",
        )
        assert result.state in ("valid", "invalid", "indeterminate", "unsupported")
        assert not hasattr(result, "lifecycle")
        assert not hasattr(result, "basis")
