# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance and cross-language parity for the PROPOSED non-time bounds module.

Every expectation comes from conformance/authority-bounds/v0/vectors.json, which is the
SHARED fixture: the TypeScript SDK authors it and this repository vendors a byte-identical
copy, so the same cases run through both ports. The file's SHA-256 is pinned in both
repositories, so the two copies can be shown identical without either repository importing
the other, and a one-sided edit fails the test on the side that was edited.

On circularity. Every verdict, reason code, missing-limb set, expected boolean and refusal
code in the file is hand specified. The ``signature`` and ``exhaustion_id`` byte values were
minted once by the TypeScript implementation, and their purpose is exactly this check: this
port signs and content-addresses the same bodies with the same private keys and has to
produce the same characters.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from agent_passport import (
    ATTESTOR_ROLE_ANSWERS,
    AUTHORITY_BOUND_FULFILMENT_TYPE,
    AUTHORITY_BOUND_TYPE,
    AUTHORITY_EXHAUSTION_TYPE,
    BOUND_KINDS,
    BOUND_REASON_CODES,
    BOUND_STATES,
    FULFILMENT_REASON_CODES,
    AuthorityBoundError,
    InMemoryAuthorityBudgetLedger,
    assess_fulfilment,
    compute_authority_exhaustion_id,
    evaluate_bound,
    is_purpose_permitted,
    issue_authority_bound_fulfilment,
    issue_authority_exhaustion,
    purpose_category,
    sign_authority_bound_fulfilment,
    sign_authority_exhaustion,
    verify_authority_delegation_chain,
    verify_authority_exhaustion,
)

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "conformance", "authority-bounds", "v0", "vectors.json"
)

#: Pinned so the TypeScript SDK's authored copy can be shown byte identical. If this moves,
#: the TypeScript repository's copy and its own pin move with it, in the same change.
VECTORS_SHA256 = "7d8818f4d28661876bfc73a8ae7f2dce27e132ee942706d10a6ae8c460dac7f2"

with open(_VECTORS_PATH, "rb") as _handle:
    _VECTORS_BYTES = _handle.read()

VECTORS = json.loads(_VECTORS_BYTES.decode("utf-8"))


def _resolve_attestor_role(attestor, _roles, _at_instant):
    return VECTORS["resolvers"]["roles"].get(attestor, "unknown")


def _resolve_verification_key(_attestor, method, _at_instant):
    return VECTORS["resolvers"]["keys"].get(method)


# ── the shared fixture ──────────────────────────────────────────────────────────────────


def test_the_vectors_file_is_the_pinned_bytes():
    assert hashlib.sha256(_VECTORS_BYTES).hexdigest() == VECTORS_SHA256


def test_the_module_vocabulary_matches_the_fixture_vocabulary_exactly():
    vocab = VECTORS["vocabulary"]
    assert list(BOUND_KINDS) == vocab["bound_kinds"]
    assert list(BOUND_STATES) == vocab["bound_states"]
    assert list(BOUND_REASON_CODES) == vocab["bound_reason_codes"]
    assert list(FULFILMENT_REASON_CODES) == vocab["fulfilment_reason_codes"]
    assert list(ATTESTOR_ROLE_ANSWERS) == vocab["attestor_role_answers"]


def test_the_record_types_are_the_proposed_ones_not_aps_ones():
    assert AUTHORITY_BOUND_TYPE == VECTORS["record_types"]["bound"]
    assert AUTHORITY_BOUND_FULFILMENT_TYPE == VECTORS["record_types"]["fulfilment"]
    assert AUTHORITY_EXHAUSTION_TYPE == VECTORS["record_types"]["exhaustion"]
    for value in VECTORS["record_types"].values():
        assert value.startswith("proposed:"), f"{value} must be marked proposed on the wire"


# ── assessing one fulfilment record ─────────────────────────────────────────────────────


@pytest.mark.parametrize("vec", VECTORS["assessment_cases"], ids=lambda v: v["id"])
def test_assessment_cases(vec):
    got = assess_fulfilment(
        vec["bound"],
        vec["record"],
        vec["at_instant"],
        _resolve_attestor_role,
        _resolve_verification_key,
    )
    assert got.accepted == vec["expected"]["accepted"]
    assert got.reason_code == vec["expected"]["reason_code"]
    assert got.role_answer == vec["expected"].get("role_answer")
    expected_missing = vec["expected"].get("missing")
    if expected_missing is None:
        assert got.missing is None
    else:
        assert list(got.missing or ()) == expected_missing


# ── evaluating a bound ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("vec", VECTORS["evaluation_cases"], ids=lambda v: v["id"])
def test_evaluation_cases(vec):
    got = evaluate_bound(
        vec["bound"],
        vec["at_instant"],
        fulfilments=vec["fulfilments"],
        resolve_attestor_role=_resolve_attestor_role,
        resolve_verification_key=_resolve_verification_key,
        consumed=vec.get("consumed"),
        budget_counter=vec.get("budget_counter"),
    )
    expected = vec["expected"]
    assert got.bound_state == expected["bound_state"]
    assert got.reason_code == expected["reason_code"]
    assert got.ending == expected["ending"]
    assert got.lifecycle.verdict == expected["lifecycle"]["verdict"]
    assert got.lifecycle.reason_code == expected["lifecycle"]["reason_code"]
    expected_missing = expected["lifecycle"].get("missing")
    if expected_missing is None:
        assert got.lifecycle.missing is None
    else:
        assert list(got.lifecycle.missing or ()) == expected_missing
    assert got.remaining == expected.get("remaining")
    assert [f.reason_code for f in got.fulfilments] == expected["fulfilment_reason_codes"]
    # `ending` is exhaustion exactly when the state is exhausted, and never anything else.
    assert got.ending == ("exhaustion" if got.bound_state == "exhausted" else None)


def test_the_purpose_verdict_does_not_depend_on_record_order():
    """CAND-02 made executable: an established exhaustion is not downgraded by a later
    claim nobody could authenticate, whichever order the records arrive in."""
    mixed = [
        v
        for v in VECTORS["evaluation_cases"]
        if v["bound"]["kind"] == "purpose" and len(v["fulfilments"]) > 1
    ]
    assert mixed, "the fixture must carry a purpose case with more than one record"
    for vec in mixed:
        forward = evaluate_bound(
            vec["bound"],
            vec["at_instant"],
            fulfilments=vec["fulfilments"],
            resolve_attestor_role=_resolve_attestor_role,
            resolve_verification_key=_resolve_verification_key,
        )
        reverse = evaluate_bound(
            vec["bound"],
            vec["at_instant"],
            fulfilments=list(reversed(vec["fulfilments"])),
            resolve_attestor_role=_resolve_attestor_role,
            resolve_verification_key=_resolve_verification_key,
        )
        assert forward.bound_state == reverse.bound_state
        assert forward.reason_code == reverse.reason_code
        assert forward.ending == reverse.ending


# ── purpose membership, which is not exhaustion ─────────────────────────────────────────


@pytest.mark.parametrize("vec", VECTORS["purpose_membership_cases"], ids=lambda v: v["id"])
def test_purpose_membership_cases(vec):
    assert is_purpose_permitted(vec["requested"], vec["allowed"]) == vec["expected"]


@pytest.mark.parametrize("vec", VECTORS["purpose_category_cases"], ids=lambda v: v["id"])
def test_purpose_category_cases(vec):
    assert purpose_category(vec["purpose"]) == vec["expected"]


def test_membership_answers_the_same_for_a_second_exercise_of_the_same_grant():
    """The defective implementation the purpose-bound corpus exists to catch: membership
    says yes to the second compressor exactly as it did to the first, so it can never
    decide exhaustion. evaluate_bound is the exhaustion question."""
    assert is_purpose_permitted("maintenance:compressor-replacement", ["maintenance:*"])
    assert is_purpose_permitted("maintenance:compressor-replacement", ["maintenance:*"])


# ── the optional exhaustion record ──────────────────────────────────────────────────────


@pytest.mark.parametrize("vec", VECTORS["exhaustion_record_cases"], ids=lambda v: v["id"])
def test_exhaustion_record_cases(vec):
    if vec.get("unresolvable_key") is True:

        def resolve(_boundary, _method, _found_at):
            return None

    else:

        def resolve(_boundary, _method, _found_at):
            return VECTORS["keys"]["boundary"]["public_key"]

    got = verify_authority_exhaustion(vec["record"], resolve)
    assert got.status == vec["expected"]["status"]
    assert list(got.failures) == vec["expected"]["failures"]
    if vec["expected"].get("evidence_length") is not None:
        assert len(vec["record"]["evidence"]) == vec["expected"]["evidence_length"]


# ── refusals ────────────────────────────────────────────────────────────────────────────

_REFUSAL_ID_EXHAUSTION = (
    "AB-R-01-an-exhaustion-record-cannot-be-minted-for-a-state-that-is-not-exhausted"
)


def test_an_exhaustion_record_cannot_be_minted_for_a_state_that_is_not_exhausted():
    not_established_case = next(
        v
        for v in VECTORS["evaluation_cases"]
        if v["expected"]["bound_state"] == "not_established"
    )
    evaluation = evaluate_bound(
        not_established_case["bound"],
        not_established_case["at_instant"],
        fulfilments=not_established_case["fulfilments"],
        resolve_attestor_role=_resolve_attestor_role,
        resolve_verification_key=_resolve_verification_key,
    )
    assert evaluation.bound_state == "not_established"
    with pytest.raises(AuthorityBoundError) as excinfo:
        issue_authority_exhaustion(
            evaluation,
            VECTORS["evaluation_cases"][0]["bound"]["delegation_id"],
            boundary="did:example:boundary",
            verification_method="did:example:boundary#k1",
            found_at="2026-09-23T10:00:00.000Z",
            private_key=VECTORS["keys"]["boundary"]["private_key"],
        )
    assert excinfo.value.code == "EXHAUSTION_STATE_NOT_EXHAUSTED"


@pytest.mark.parametrize(
    "vec",
    [v for v in VECTORS["refusal_cases"] if v["id"] != _REFUSAL_ID_EXHAUSTION],
    ids=lambda v: v["id"],
)
def test_refusal_cases(vec):
    source = next(v for v in VECTORS["evaluation_cases"] if v["fulfilments"])
    omit = vec.get("omit_resolver")
    with pytest.raises(AuthorityBoundError) as excinfo:
        evaluate_bound(
            vec["bound"],
            "2026-09-23T10:00:00.000Z",
            fulfilments=source["fulfilments"] if vec.get("with_records") is True else [],
            resolve_attestor_role=None if omit == "role" else _resolve_attestor_role,
            resolve_verification_key=None if omit == "key" else _resolve_verification_key,
            consumed=vec.get("consumed"),
        )
    assert excinfo.value.code == vec["expected_error_code"]


# ── byte determinism across languages ───────────────────────────────────────────────────


@pytest.mark.parametrize("vec", VECTORS["signature_cases"], ids=lambda v: v["id"])
def test_signature_cases(vec):
    if vec.get("body") is not None:
        body = vec["body"]
        assert (
            sign_authority_bound_fulfilment(body, vec["private_key"])
            == vec["expected_signature"]
        )
        reissued = issue_authority_bound_fulfilment(
            bound_id=body["bound_id"],
            delegation_id=body["delegation_id"],
            attestor=body["attestor"],
            verification_method=body["verification_method"],
            attested_at=body["attested_at"],
            outcome=body["outcome"],
            reason_code=body["reason_code"],
            detail=body.get("detail"),
            private_key=vec["private_key"],
        )
        assert reissued["signature"] == vec["expected_signature"]
        assert reissued == {**body, "signature": vec["expected_signature"]}
    if vec.get("exhaustion_body") is not None:
        body = vec["exhaustion_body"]
        exhaustion_id = compute_authority_exhaustion_id(body)
        assert exhaustion_id == vec["expected_exhaustion_id"]
        assert (
            sign_authority_exhaustion(
                {**body, "exhaustion_id": exhaustion_id}, vec["private_key"]
            )
            == vec["expected_signature"]
        )


def test_an_exhaustion_record_minted_here_verifies_here():
    """End to end, and with the evidence limb the fixture's own accepted records carry."""
    exhausted_case = next(
        v
        for v in VECTORS["evaluation_cases"]
        if v["bound"]["kind"] == "purpose" and v["expected"]["bound_state"] == "exhausted"
    )
    evaluation = evaluate_bound(
        exhausted_case["bound"],
        exhausted_case["at_instant"],
        fulfilments=exhausted_case["fulfilments"],
        resolve_attestor_role=_resolve_attestor_role,
        resolve_verification_key=_resolve_verification_key,
    )
    record = issue_authority_exhaustion(
        evaluation,
        exhausted_case["bound"]["delegation_id"],
        boundary="did:example:boundary",
        verification_method="did:example:boundary#k1",
        found_at="2026-09-23T10:00:00.000Z",
        private_key=VECTORS["keys"]["boundary"]["private_key"],
    )
    got = verify_authority_exhaustion(
        record, lambda *_: VECTORS["keys"]["boundary"]["public_key"]
    )
    assert got.status == "valid"
    assert got.failures == ()
    assert len(record["evidence"]) >= 1
    # The record attests the boundary's own finding, so it carries the reason code the
    # evaluation reached and never a state of the world.
    assert record["reason_code"] == "PURPOSE_EXHAUSTED"


# ── nothing existing changed ────────────────────────────────────────────────────────────


def test_a_bound_evaluation_is_never_merged_into_a_chain_result():
    chain = verify_authority_delegation_chain(
        [],
        now="2026-09-23T10:00:00.000Z",
        resolve_verification_key=lambda *_: None,
        trust_root=lambda *_: False,
        resolve_revocation=lambda *_: {"status": "active"},
    )
    assert chain.state in ("valid", "invalid", "indeterminate", "unsupported")
    assert not hasattr(chain, "bound_state")
    assert not hasattr(chain, "ending")


def test_the_budget_kind_reads_the_ledger_counter_shape_rather_than_one_of_its_own():
    """The budget kind delegates to the ledger that already answers it and never
    reimplements it. draft-03 section 3.4 states the rule, verbatim: "Signatures establish
    static limits; they do not establish the current cumulative total."
    """
    ledger = InMemoryAuthorityBudgetLedger()
    counter = ledger.counter("sha256:" + "a" * 64)
    budget_case = next(v for v in VECTORS["evaluation_cases"] if v["bound"]["kind"] == "budget")
    # The empty ledger's counter is a valid input to evaluate_bound without translation.
    got = evaluate_bound(
        budget_case["bound"], "2026-09-22T14:00:00.000Z", budget_counter=counter
    )
    assert got.bound_state == "not_reached"
    assert got.ending is None


def test_a_purpose_bound_with_no_records_and_no_resolvers_does_not_raise():
    purpose_case = VECTORS["evaluation_cases"][0]
    got = evaluate_bound(purpose_case["bound"], purpose_case["at_instant"])
    assert got.bound_state == "not_reached"
