# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance and cross-language parity for the PROPOSED activation-condition module.

Every expectation comes from ``conformance/activation/v0/vectors.json``, which is vendored
byte for byte from the TypeScript SDK, where it is authored. Expectations are hand specified
in the generator that emits the file, never computed by the code under test, so the test is
not circular. The file's SHA-256 is pinned below and in the TypeScript SDK's own test, so the
two copies can be shown identical without either repository importing the other, and a
one-sided edit fails on the side that was edited.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agent_passport.crypto import verify as verify_ed25519
from agent_passport.v2.activation import (
    ACTIVATION_ASSERTIONS,
    ACTIVATION_ATTESTATION_ID_DOMAIN,
    ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN,
    ACTIVATION_ATTESTATION_TYPE,
    ACTIVATION_CONDITION_KINDS,
    ACTIVATION_CONDITION_SIGNATURE_DOMAIN,
    ACTIVATION_CONDITION_TYPE,
    ACTIVATION_FINDINGS,
    ACTIVATION_INSTANT_BASES,
    ACTIVATION_REASON_CODES,
    ATTESTOR_ROLE_STANDINGS,
    ActivationError,
    activation_attestation_body,
    activation_attestation_signature_input,
    activation_condition_signature_input,
    compose_activation,
    compute_activation_attestation_id,
    validate_activation_condition,
    verify_activation,
)
from agent_passport.v2.authority_delegation.types import (
    AuthorityFailure,
    AuthorityValidationResult,
)

#: Pinned so the TypeScript SDK's authored copy can be shown byte identical. If this moves,
#: the TypeScript repo's copy and its own pin move with it, in the same change.
VECTORS_SHA256 = "9340152cc3ddd4c0ac02d07b8cb8ccb85f7174ab72e4ffab6ad279d6027ee48e"

_VECTORS_PATH = (
    Path(__file__).resolve().parents[1] / "conformance" / "activation" / "v0" / "vectors.json"
)
_VECTORS_BYTES = _VECTORS_PATH.read_bytes()
VECTORS = json.loads(_VECTORS_BYTES.decode("utf-8"))


def resolve_attestor_role(attestor: str, role: str, at_instant: str) -> str:
    """Role standing resolved OUTSIDE the record, from the vectors' own registry.

    An attestor the registry has never heard of is ``unknown`` for every role: ignorance,
    never a denial.
    """
    held = VECTORS["attestor_role_registry"].get(attestor)
    if held is None:
        return "unknown"
    return "holds" if role in held else "does_not_hold"


def resolve_verification_key(attestor: str, method: str, at_instant: str):
    """Keyed on the verification method alone, so a record naming one attestor while
    presenting another's method still resolves a key and the attestor-binding check is what
    catches it."""
    return VECTORS["verification_keys"].get(method)


def condition_of(label: str) -> dict:
    return VECTORS["conditions"][label]


def run_verify_case(case_id: str):
    vector = next(c for c in VECTORS["verify_cases"] if c["id"] == case_id)
    return verify_activation(
        condition=condition_of(vector["condition"]),
        delegation_id=VECTORS["delegation_id"],
        action_instant=VECTORS["clock"][vector["action_at"]],
        attestations=[VECTORS["attestations"][label] for label in vector["presented"]],
        resolve_attestor_role=resolve_attestor_role,
        resolve_verification_key=resolve_verification_key,
    )


# ── integrity and vocabulary ───────────────────────────────────────────────────────────


def test_the_shared_vectors_file_is_the_pinned_one():
    assert hashlib.sha256(_VECTORS_BYTES).hexdigest() == VECTORS_SHA256


def test_the_file_states_it_is_proposed():
    assert VECTORS["profile"] == "aps-activation-v0"
    assert VECTORS["status"] == "proposed"


def test_the_vocabulary_in_the_file_is_the_vocabulary_the_module_exports():
    vocabulary = VECTORS["vocabulary"]
    assert tuple(vocabulary["condition_kinds"]) == ACTIVATION_CONDITION_KINDS
    assert tuple(vocabulary["instant_bases"]) == ACTIVATION_INSTANT_BASES
    assert tuple(vocabulary["assertions"]) == ACTIVATION_ASSERTIONS
    assert tuple(vocabulary["attestor_role_standings"]) == ATTESTOR_ROLE_STANDINGS
    assert tuple(vocabulary["findings"]) == ACTIVATION_FINDINGS
    assert tuple(vocabulary["reason_codes"]) == ACTIVATION_REASON_CODES
    assert VECTORS["record_types"]["condition"] == ACTIVATION_CONDITION_TYPE
    assert VECTORS["record_types"]["attestation"] == ACTIVATION_ATTESTATION_TYPE


def test_the_record_types_carry_a_proposed_namespace():
    # Nothing here reads as minted APS vocabulary.
    assert ACTIVATION_CONDITION_TYPE.startswith("proposed:")
    assert ACTIVATION_ATTESTATION_TYPE.startswith("proposed:")


@pytest.mark.parametrize(
    "domain",
    [
        ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN,
        ACTIVATION_ATTESTATION_ID_DOMAIN,
        ACTIVATION_CONDITION_SIGNATURE_DOMAIN,
    ],
)
def test_every_domain_tag_says_proposed_and_ends_in_one_zero_byte(domain):
    assert "PROPOSED" in domain
    assert domain.endswith("\x00")
    assert domain.index("\x00") == len(domain) - 1


def test_the_three_domain_tags_are_distinct():
    # Bytes minted for one construction are never read as bytes minted for another.
    assert (
        len(
            {
                ACTIVATION_ATTESTATION_SIGNATURE_DOMAIN,
                ACTIVATION_ATTESTATION_ID_DOMAIN,
                ACTIVATION_CONDITION_SIGNATURE_DOMAIN,
            }
        )
        == 3
    )


# ── canonical bytes, and cross-language byte parity ────────────────────────────────────


def test_the_signed_body_excludes_exactly_the_two_members_derived_from_it():
    attestation = VECTORS["attestations"]["ATT_OCCURRED_ON_TIME"]
    body = activation_attestation_body(attestation)
    assert "attestation_id" not in body
    assert "signature" not in body
    assert len(body) == len(attestation) - 2


def test_every_other_member_is_inside_the_preimage():
    attestation = dict(VECTORS["attestations"]["ATT_OCCURRED_ON_TIME"])
    attestation["operator_note"] = "rides along"
    # Members this module never interprets are still authenticated.
    assert "operator_note" in activation_attestation_signature_input(attestation)


def test_the_identifier_is_recomputable_from_the_body():
    attestation = VECTORS["attestations"]["ATT_OCCURRED_ON_TIME"]
    assert compute_activation_attestation_id(attestation) == attestation["attestation_id"]


def test_the_identifier_changes_when_any_signed_member_changes():
    attestation = dict(VECTORS["attestations"]["ATT_OCCURRED_ON_TIME"])
    attestation["occurred_at"] = "2026-09-20T09:00:01.000Z"
    assert (
        compute_activation_attestation_id(attestation)
        != VECTORS["attestations"]["ATT_OCCURRED_ON_TIME"]["attestation_id"]
    )


def test_a_condition_preimage_is_available_for_a_deployment_that_signs_conditions():
    assert activation_condition_signature_input(condition_of("COND_EVENT")).startswith(
        ACTIVATION_CONDITION_SIGNATURE_DOMAIN
    )


@pytest.mark.parametrize(
    "label",
    [
        label
        for label in VECTORS["attestations"]
        # The forged record is the one whose signature is deliberately not the signed bytes.
        if label != "ATT_MONITOR_FORGED"
    ],
)
def test_signatures_minted_by_the_typescript_sdk_verify_under_the_python_preimage(label):
    # THE BYTE-PARITY CLAIM. Every record in the shared vectors was signed by the TypeScript
    # module over its own domain-tagged RFC 8785 preimage. Each one verifying here shows the
    # two ports build identical bytes, which is what makes the shared vectors meaningful.
    attestation = VECTORS["attestations"][label]
    key = VECTORS["verification_keys"].get(attestation["verification_method"])
    if key is None:
        # ATT_UNRESOLVABLE_KEY names a method no resolver answers for, which is the point
        # of that record rather than a parity gap.
        pytest.skip("no key is published for this verification method")
    assert verify_ed25519(
        activation_attestation_signature_input(attestation), attestation["signature"], key
    )


@pytest.mark.parametrize("label", list(VECTORS["attestations"]))
def test_every_attestation_id_in_the_shared_vectors_recomputes_in_python(label):
    attestation = VECTORS["attestations"][label]
    assert compute_activation_attestation_id(attestation) == attestation["attestation_id"]


# ── condition shape rules ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "vector", VECTORS["condition_validation_cases"], ids=lambda v: v["id"]
)
def test_validate_activation_condition(vector):
    if vector["expected"]["ok"]:
        assert validate_activation_condition(vector["condition"]) == vector["condition"]
        return
    with pytest.raises(ActivationError) as caught:
        validate_activation_condition(vector["condition"])
    assert caught.value.code == vector["expected"]["error_code"]


# ── the shared verify vectors ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("vector", VECTORS["verify_cases"], ids=lambda v: v["id"])
def test_verify_activation_vectors(vector):
    result = run_verify_case(vector["id"])
    expected = vector["expected"]
    assert result.state.verdict == expected["verdict"]
    assert result.state.reason_code == expected["reason_code"]
    assert (
        None if result.state.missing is None else list(result.state.missing)
    ) == expected.get("missing")
    assert [
        {"attestation": f.attestation_id, "finding": f.finding} for f in result.findings
    ] == [
        {
            "attestation": VECTORS["attestations"][f["attestation"]]["attestation_id"],
            "finding": f["finding"],
        }
        for f in expected["findings"]
    ]
    assert [
        {"attestation": r.attestation_id, "reason_code": r.reason_code}
        for r in result.rejections
    ] == [
        {
            "attestation": VECTORS["attestations"][r["attestation"]]["attestation_id"],
            "reason_code": r["reason_code"],
        }
        for r in expected["rejections"]
    ]
    assert result.condition_id == condition_of(vector["condition"])["condition_id"]


def test_invalid_is_never_a_verdict_this_module_reaches():
    for vector in VECTORS["verify_cases"]:
        assert run_verify_case(vector["id"]).state.verdict != "invalid", vector["id"]


def test_only_three_of_the_six_lifecycle_verdicts_are_reachable_here():
    reached = {run_verify_case(v["id"]).state.verdict for v in VECTORS["verify_cases"]}
    assert sorted(reached) == ["not_established", "not_yet_effective", "valid"]


def test_every_not_established_verdict_names_at_least_one_establishment_limb():
    for vector in VECTORS["verify_cases"]:
        state = run_verify_case(vector["id"]).state
        if state.verdict != "not_established":
            continue
        assert state.missing, vector["id"]


def test_freshness_is_never_claimed():
    # This module is given no bound to measure against, so it never claims that limb.
    for vector in VECTORS["verify_cases"]:
        state = run_verify_case(vector["id"]).state
        assert "freshness" not in (state.missing or ()), vector["id"]


def test_one_entry_per_presented_attestation():
    for vector in VECTORS["verify_cases"]:
        if condition_of(vector["condition"])["condition_type"] == "date":
            continue
        if vector["expected"]["reason_code"] == "CONDITION_DELEGATION_MISMATCH":
            continue
        result = run_verify_case(vector["id"])
        assert len(result.findings) + len(result.rejections) == len(
            vector["presented"]
        ), vector["id"]


def test_the_result_is_immutable_so_a_caller_cannot_edit_a_verdict_after_the_fact():
    result = run_verify_case("AC-01-occurrence-before-action-valid")
    with pytest.raises(Exception):
        result.state = None  # type: ignore[misc]
    assert isinstance(result.findings, tuple)
    assert isinstance(result.rejections, tuple)


# ── call-site rules ────────────────────────────────────────────────────────────────────


def _base_call(**overrides):
    call = {
        "condition": condition_of("COND_EVENT"),
        "delegation_id": "acv-grant-1",
        "action_instant": "2026-09-20T10:00:00.000Z",
        "resolve_attestor_role": resolve_attestor_role,
        "resolve_verification_key": resolve_verification_key,
    }
    call.update(overrides)
    return call


def test_a_role_resolver_is_required():
    # Standing is resolved outside the record, always.
    with pytest.raises(ActivationError) as caught:
        verify_activation(**_base_call(resolve_attestor_role=None))
    assert caught.value.code == "ROLE_RESOLVER_REQUIRED"


def test_a_role_resolver_is_required_even_for_a_date_condition():
    # So a caller cannot get a date answer and then discover the event path needs plumbing
    # it does not have.
    with pytest.raises(ActivationError) as caught:
        verify_activation(
            **_base_call(condition=condition_of("COND_DATE"), resolve_attestor_role=None)
        )
    assert caught.value.code == "ROLE_RESOLVER_REQUIRED"


def test_a_key_resolver_is_required():
    with pytest.raises(ActivationError) as caught:
        verify_activation(**_base_call(resolve_verification_key=None))
    assert caught.value.code == "KEY_RESOLVER_REQUIRED"


def test_a_delegation_id_is_required():
    with pytest.raises(ActivationError) as caught:
        verify_activation(**_base_call(delegation_id=""))
    assert caught.value.code == "DELEGATION_ID_REQUIRED"


def test_a_malformed_action_instant_raises_rather_than_producing_a_verdict():
    with pytest.raises(ActivationError) as caught:
        verify_activation(**_base_call(action_instant="2026-09-20"))
    assert caught.value.code == "INSTANT_MALFORMED"


def test_a_caller_supplied_preimage_must_come_with_the_accepted_record_types():
    with pytest.raises(ActivationError) as caught:
        verify_activation(**_base_call(attestation_preimage=lambda a: "x"))
    assert caught.value.code == "ACCEPTED_RECORD_TYPES_REQUIRED"


def test_this_function_reads_no_clock():
    first = run_verify_case("AC-30-date-not-reached-not-yet-effective")
    second = run_verify_case("AC-30-date-not-reached-not-yet-effective")
    assert first.state == second.state


# ── the escape hatch for evidence this module does not own ─────────────────────────────

FOREIGN_TYPE = "fixture:some-other-attestation:v0"


def test_a_declared_foreign_record_type_is_accepted_with_a_caller_preimage():
    # A model can accept condition evidence in a record shape this module never defined.
    # Which bytes a signature covers is a property of a record type, so the caller supplies
    # both the preimage and the types it accepts. This is the path the lab fixture takes.
    result = verify_activation(
        condition=condition_of("COND_EVENT"),
        delegation_id=VECTORS["delegation_id"],
        action_instant=VECTORS["clock"]["T_ACTION"],
        attestations=[VECTORS["attestations"]["ATT_WRONG_RECORD_TYPE"]],
        resolve_attestor_role=resolve_attestor_role,
        resolve_verification_key=resolve_verification_key,
        accepted_attestation_record_types=[FOREIGN_TYPE],
        attestation_preimage=activation_attestation_signature_input,
    )
    assert result.state.verdict == "valid"
    assert result.state.reason_code == "ACTIVATION_ESTABLISHED"


def test_an_undeclared_record_type_is_still_rejected_with_a_preimage_supplied():
    result = verify_activation(
        condition=condition_of("COND_EVENT"),
        delegation_id=VECTORS["delegation_id"],
        action_instant=VECTORS["clock"]["T_ACTION"],
        attestations=[VECTORS["attestations"]["ATT_WRONG_RECORD_TYPE"]],
        resolve_attestor_role=resolve_attestor_role,
        resolve_verification_key=resolve_verification_key,
        accepted_attestation_record_types=["fixture:something-else:v0"],
        attestation_preimage=activation_attestation_signature_input,
    )
    assert result.state.verdict == "not_established"
    assert result.state.reason_code == "ATTESTATION_RECORD_TYPE_NOT_ACCEPTED"


def test_a_preimage_that_does_not_match_the_signed_bytes_rejects_the_record():
    result = verify_activation(
        condition=condition_of("COND_EVENT"),
        delegation_id=VECTORS["delegation_id"],
        action_instant=VECTORS["clock"]["T_ACTION"],
        attestations=[VECTORS["attestations"]["ATT_WRONG_RECORD_TYPE"]],
        resolve_attestor_role=resolve_attestor_role,
        resolve_verification_key=resolve_verification_key,
        accepted_attestation_record_types=[FOREIGN_TYPE],
        attestation_preimage=lambda a: "bytes nobody signed",
    )
    assert result.state.reason_code == "ATTESTATION_SIGNATURE_UNVERIFIED"


# ── composition, reported alongside a chain result and never merged into it ────────────


def _chain_from(spec: dict) -> AuthorityValidationResult:
    """The vectors carry the chain result as plain data in the draft-03 four-value
    vocabulary. ``valid`` is a derived property here rather than a field, so the vectors'
    ``valid`` member is checked against it instead of being passed in."""
    result = AuthorityValidationResult(
        state=spec["state"],
        failures=tuple(
            AuthorityFailure(
                code=f["code"], message=f.get("message", ""), index=f.get("index")
            )
            for f in spec.get("failures", ())
        ),
    )
    assert result.valid == spec["valid"]
    return result


@pytest.mark.parametrize("vector", VECTORS["compose_cases"], ids=lambda v: v["id"])
def test_compose_activation_vectors(vector):
    activation = (
        None
        if vector["activation_from_case"] is None
        else run_verify_case(vector["activation_from_case"])
    )
    composite = compose_activation(
        _chain_from(vector["chain_result"]), activation, mapping=vector.get("mapping")
    )
    expected = vector["expected"]
    assert composite.chain.state == expected["chain_state"]
    assert composite.lifecycle.verdict == expected["lifecycle_verdict"]
    assert composite.lifecycle.reason_code == expected["lifecycle_reason_code"]
    assert (
        None if composite.lifecycle.missing is None else list(composite.lifecycle.missing)
    ) == expected.get("lifecycle_missing")


def test_the_chain_result_is_returned_untouched_never_rewritten():
    chain = _chain_from({"state": "valid", "valid": True, "failures": []})
    composite = compose_activation(
        chain, run_verify_case("AC-15-accepted-negative-not-yet-effective")
    )
    assert composite.chain is chain


@pytest.mark.parametrize("state", ["invalid", "indeterminate", "unsupported"])
def test_nothing_here_turns_an_invalid_chain_into_a_valid_lifecycle_verdict(state):
    composite = compose_activation(
        _chain_from(
            {
                "state": state,
                "valid": False,
                "failures": [{"code": "REVOKED", "message": "revoked", "index": 0}],
            }
        ),
        run_verify_case("AC-01-occurrence-before-action-valid"),
    )
    assert composite.lifecycle.verdict != "valid"


def test_invariant_l1_a_revoked_instrument_is_not_rescued_by_activation_evidence():
    # CAND-13's pre-committed replacement grant is an ordinary grant with an ordinary
    # condition. The ordering in compose_activation is what keeps L1 intact.
    composite = compose_activation(
        _chain_from(
            {
                "state": "invalid",
                "valid": False,
                "failures": [
                    {"code": "REVOKED", "message": "ancestor revoked", "index": 0}
                ],
            }
        ),
        run_verify_case("AC-01-occurrence-before-action-valid"),
    )
    assert composite.lifecycle.verdict == "invalid"
    assert composite.lifecycle.reason_code == "REVOKED"
