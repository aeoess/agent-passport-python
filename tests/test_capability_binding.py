# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Conformance and cross-language parity for the PROPOSED capability-binding module.

Every expectation comes from conformance/capability-binding/v0/vectors.json, which is the
SHARED fixture: the TypeScript SDK authors it and this repository vendors a byte-identical
copy, so the same cases run through both ports. Expectations are hand specified in the
vectors, never computed by the code under test, so the test is not circular. The file's
SHA-256 is pinned in both repositories, so the two copies can be shown identical without
either repository importing the other.

The identifier records are stored UNSIGNED and are signed here, by this SDK's own ``sign``
over this SDK's own ``identifier_record_signed_bytes``. That is deliberate: a canonical-byte
divergence between the two SDKs shows up as a failed signature check in one of them rather
than as two runners agreeing on a stored blob neither of them produced.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from agent_passport import (
    BOUNDARY_OUTCOMES,
    CAPABILITY_BINDING_REASON_CODES,
    CAPABILITY_METADATA_DOMAIN_CBD_V0,
    ESTABLISHMENT_GAPS,
    IDENTIFIER_BINDING_UNSIGNED_FIELDS,
    IDENTIFIER_CONTINUITY_REASON_CODES,
    IDENTIFIER_RETENTION_UNSIGNED_FIELDS,
    CapabilityBindingError,
    CapabilityPin,
    ToolAttestationObservation,
    capability_implementation_digest,
    capability_metadata_digest,
    capability_pin_is_empty,
    capability_pin_scope_grants,
    create_tool_registry_entry,
    evaluate_capability_binding,
    evaluate_identifier_continuity,
    identifier_controller_pin_scope_grant,
    identifier_dependency_scope_grant,
    identifier_record_signed_bytes,
    observe_tool_attestation,
    parse_capability_pin_from_scope_grants,
    parse_identifier_controller_pins,
    project_boundary_outcome_to_candidate_v0,
    referent_binding_result,
    tool_scope_grant,
    verify_tool_integrity,
)
from agent_passport.crypto import generate_key_pair, sign

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "conformance", "capability-binding", "v0", "vectors.json"
)
with open(_VECTORS_PATH, "rb") as _handle:
    _VECTORS_BYTES = _handle.read()
_VECTORS = json.loads(_VECTORS_BYTES.decode("utf-8"))
_IC = _VECTORS["identifier_continuity"]

# Pinned so the TypeScript SDK's authoring copy can be shown byte identical. If this
# moves, the TypeScript repo's copy and its own pin move with it, in the same change.
_VECTORS_SHA256 = "d25efe67c9b065caa72045613430bb238b52aaafe8c0c0aa354bb31696cf3829"


def _assert_binding(actual, expected, case_id: str) -> None:
    assert actual.outcome == expected["outcome"], f"{case_id}: outcome"
    assert actual.continuity == expected["continuity"], f"{case_id}: continuity"
    assert actual.reason_code == expected["reason_code"], f"{case_id}: reason_code"
    if "missing" in expected:
        assert list(actual.missing or ()) == expected["missing"], f"{case_id}: missing"
    else:
        assert actual.missing is None, f"{case_id}: missing must be absent"
    if "controller_at_instant" in expected:
        assert (
            actual.controller_at_instant == expected["controller_at_instant"]
        ), f"{case_id}: controller"


# ── the shared fixture ────────────────────────────────────────────────────────


def test_vectors_file_is_the_pinned_bytes() -> None:
    assert hashlib.sha256(_VECTORS_BYTES).hexdigest() == _VECTORS_SHA256


def test_fixture_states_its_own_specification_position() -> None:
    assert _VECTORS["profile"] == "aps-capability-binding-v0"
    assert _VECTORS["status"] == "candidate_against_proposed"


def test_every_expected_reason_code_is_in_the_module_enumeration() -> None:
    for case in _VECTORS["capability_binding_cases"]:
        assert case["expected"]["reason_code"] in CAPABILITY_BINDING_REASON_CODES, case["id"]
    for case in _IC["cases"]:
        assert case["expected"]["reason_code"] in IDENTIFIER_CONTINUITY_REASON_CODES, case["id"]


def test_every_module_reason_code_is_exercised_by_the_fixture() -> None:
    used = {c["expected"]["reason_code"] for c in _VECTORS["capability_binding_cases"]}
    for code in CAPABILITY_BINDING_REASON_CODES:
        assert code in used, f"unexercised capability reason code: {code}"
    used_id = {c["expected"]["reason_code"] for c in _IC["cases"]}
    for code in IDENTIFIER_CONTINUITY_REASON_CODES:
        assert code in used_id, f"unexercised identifier reason code: {code}"


def test_every_expected_outcome_is_a_boundary_outcome_never_an_artifact_verdict() -> None:
    for case in _VECTORS["capability_binding_cases"] + _IC["cases"]:
        assert case["expected"]["outcome"] in BOUNDARY_OUTCOMES, case["id"]
        for gap in case["expected"].get("missing", []):
            assert gap in ESTABLISHMENT_GAPS, case["id"]


# ── digests ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", _VECTORS["implementation_digest_cases"], ids=lambda c: c["label"])
def test_implementation_digest(case) -> None:
    assert capability_implementation_digest(case["implementation"]) == case["expected"]


@pytest.mark.parametrize("case", _VECTORS["metadata_digest_cases"], ids=lambda c: c["label"][:40])
def test_metadata_digest(case) -> None:
    assert (
        capability_metadata_digest(case["metadata"], _VECTORS["metadata_digest_domain"])
        == case["expected"]
    )


def test_offered_domain_label_is_the_one_the_fixture_declares() -> None:
    assert CAPABILITY_METADATA_DOMAIN_CBD_V0 == _VECTORS["metadata_digest_domain"]


def test_absent_metadata_domain_is_a_call_error_not_a_verdict() -> None:
    with pytest.raises(CapabilityBindingError) as excinfo:
        capability_metadata_digest({}, "")
    assert excinfo.value.code == _VECTORS["metadata_digest_domain_required"]["error_code"]


def test_implementation_digest_equals_what_the_registry_entry_computes() -> None:
    attestor = generate_key_pair()
    implementation = _VECTORS["implementation_digest_cases"][0]["implementation"]
    entry = create_tool_registry_entry(
        tool_name=_VECTORS["tool_name"],
        implementation=implementation,
        attestor_id="did:aps:example:cb-attestor",
        attestor_private_key=attestor["privateKey"],
        verified_at="2026-09-23T00:00:00.000Z",
    )
    assert entry.implementationHash == capability_implementation_digest(implementation)


# ── the scope_grant_v0 pin encoding ───────────────────────────────────────────


@pytest.mark.parametrize("case", _VECTORS["scope_grant_parse_cases"], ids=lambda c: c["label"][:40])
def test_scope_grant_parse(case) -> None:
    pin = parse_capability_pin_from_scope_grants(case["grants"], case["tool_name"])
    if case["expected"] is None:
        assert pin is None
        return
    assert pin is not None
    assert pin.tool_name == case["expected"]["tool_name"]
    assert list(pin.implementation_digests) == case["expected"]["implementation_digests"]
    assert list(pin.metadata_digests) == case["expected"]["metadata_digests"]
    assert pin.encoding == case["expected"]["encoding"]


def _pin_from_fixture(raw) -> CapabilityPin:
    return CapabilityPin(
        tool_name=raw["tool_name"],
        implementation_digests=tuple(raw["implementation_digests"]),
        metadata_digests=tuple(raw["metadata_digests"]),
        encoding=raw["encoding"],
    )


@pytest.mark.parametrize("case", _VECTORS["scope_grant_write_cases"], ids=lambda c: c["label"][:40])
def test_scope_grant_write(case) -> None:
    pin = _pin_from_fixture(case["pin"])
    if "expected_error_code" in case:
        with pytest.raises(CapabilityBindingError) as excinfo:
            capability_pin_scope_grants(pin)
        assert excinfo.value.code == case["expected_error_code"]
        return
    assert list(capability_pin_scope_grants(pin)) == case["expected"]


def test_write_then_parse_round_trips() -> None:
    for case in _VECTORS["scope_grant_write_cases"]:
        if "expected_error_code" in case:
            continue
        pin = _pin_from_fixture(case["pin"])
        grants = capability_pin_scope_grants(pin)
        parsed = parse_capability_pin_from_scope_grants(grants, pin.tool_name)
        assert parsed is not None
        assert parsed.implementation_digests == pin.implementation_digests
        assert parsed.metadata_digests == pin.metadata_digests


def test_named_and_unpinned_is_not_the_same_answer_as_not_named() -> None:
    named = parse_capability_pin_from_scope_grants(["tool:t"], "t")
    assert named is not None
    assert capability_pin_is_empty(named) is True
    assert parse_capability_pin_from_scope_grants(["other:grant"], "t") is None
    assert tool_scope_grant("ledger.export") == "tool:ledger.export"


# ── evaluate_capability_binding ───────────────────────────────────────────────


def _binding_kwargs(raw) -> dict:
    pin = None if raw["pin"] is None else _pin_from_fixture(raw["pin"])
    attestation = (
        None
        if raw["attestation"] is None
        else ToolAttestationObservation(
            attested_tool_name=raw["attestation"]["attested_tool_name"],
            attested_implementation_digest=raw["attestation"]["attested_implementation_digest"],
            attestor_key_resolved=raw["attestation"]["attestor_key_resolved"],
            attestor_signature_valid=raw["attestation"]["attestor_signature_valid"],
        )
    )
    return {
        "requested_tool_name": raw["requestedToolName"],
        "granted_scopes": raw["grantedScopes"],
        "required_scopes": tuple(raw.get("requiredScopes", ())),
        "pin": pin,
        "attestation": attestation,
        "observed_implementation_digest": raw["observedImplementationDigest"],
        "observed_metadata_digest": raw["observedMetadataDigest"],
    }


@pytest.mark.parametrize(
    "case", _VECTORS["capability_binding_cases"], ids=lambda c: c["id"]
)
def test_evaluate_capability_binding(case) -> None:
    result = evaluate_capability_binding(**_binding_kwargs(case["input"]))
    _assert_binding(result, case["expected"], case["id"])


def test_no_case_returns_an_artifact_verdict_or_a_truthiness_shortcut() -> None:
    for case in _VECTORS["capability_binding_cases"]:
        result = evaluate_capability_binding(**_binding_kwargs(case["input"]))
        assert result.outcome in BOUNDARY_OUTCOMES, case["id"]
        assert not hasattr(result, "verdict"), case["id"]
        assert not hasattr(result, "valid"), case["id"]


def test_a_pin_for_a_different_tool_is_a_call_error_not_a_verdict() -> None:
    with pytest.raises(CapabilityBindingError) as excinfo:
        evaluate_capability_binding(
            requested_tool_name="a",
            granted_scopes=["tool:b"],
            pin=CapabilityPin(
                tool_name="b",
                implementation_digests=(),
                metadata_digests=(),
                encoding="scope_grant_v0",
            ),
            attestation=None,
            observed_implementation_digest=None,
            observed_metadata_digest=None,
        )
    assert excinfo.value.code == "PIN_TOOL_MISMATCH"


# ── observe_tool_attestation over the ported tool-integrity layer ─────────────


_ATTESTOR = generate_key_pair()
_OTHER = generate_key_pair()
_IMPL = _VECTORS["implementation_digest_cases"][0]["implementation"]
_DRIFTED = _VECTORS["implementation_digest_cases"][1]["implementation"]
_ENTRY = create_tool_registry_entry(
    tool_name=_VECTORS["tool_name"],
    implementation=_IMPL,
    attestor_id="did:aps:example:cb-attestor",
    attestor_private_key=_ATTESTOR["privateKey"],
    verified_at="2026-09-23T00:00:00.000Z",
)


def test_a_resolved_key_over_an_unchanged_implementation_is_accepted() -> None:
    observed = observe_tool_attestation(
        registry_entry=_ENTRY,
        requested_tool_name=_VECTORS["tool_name"],
        observed_implementation=_IMPL,
        resolve_trusted_attestor_key=lambda _tool: _ATTESTOR["publicKey"],
    )
    assert observed == ToolAttestationObservation(
        attested_tool_name=_VECTORS["tool_name"],
        attested_implementation_digest=capability_implementation_digest(_IMPL),
        attestor_key_resolved=True,
        attestor_signature_valid=True,
    )


def test_standing_is_resolved_by_tool_never_from_the_asserted_attestor_id() -> None:
    observed = observe_tool_attestation(
        registry_entry=_ENTRY,
        requested_tool_name=_VECTORS["tool_name"],
        observed_implementation=_IMPL,
        resolve_trusted_attestor_key=lambda _tool: _OTHER["publicKey"],
    )
    assert observed.attestor_key_resolved is True
    assert observed.attestor_signature_valid is False


def test_no_resolvable_key_means_no_accepted_attestation_and_no_signature_claim() -> None:
    observed = observe_tool_attestation(
        registry_entry=_ENTRY,
        requested_tool_name=_VECTORS["tool_name"],
        observed_implementation=_IMPL,
        resolve_trusted_attestor_key=lambda _tool: None,
    )
    assert observed.attestor_key_resolved is False
    assert observed.attestor_signature_valid is False


def test_end_to_end_a_signed_entry_that_no_longer_describes_the_tool_is_stale() -> None:
    observed = observe_tool_attestation(
        registry_entry=_ENTRY,
        requested_tool_name=_VECTORS["tool_name"],
        observed_implementation=_DRIFTED,
        resolve_trusted_attestor_key=lambda _tool: _ATTESTOR["publicKey"],
    )
    assert observed.attestor_signature_valid is True
    grants = [tool_scope_grant(_VECTORS["tool_name"])]
    result = evaluate_capability_binding(
        requested_tool_name=_VECTORS["tool_name"],
        granted_scopes=grants,
        pin=parse_capability_pin_from_scope_grants(grants, _VECTORS["tool_name"]),
        attestation=observed,
        observed_implementation_digest=capability_implementation_digest(_DRIFTED),
        observed_metadata_digest=None,
    )
    assert result.outcome == "not_established"
    assert result.reason_code == "REGISTRY_ENTRY_IMPLEMENTATION_MISMATCH"
    assert list(result.missing or ()) == ["freshness"]


def test_end_to_end_a_pinned_digest_established_to_have_changed_is_a_denial() -> None:
    observed = observe_tool_attestation(
        registry_entry=create_tool_registry_entry(
            tool_name=_VECTORS["tool_name"],
            implementation=_DRIFTED,
            attestor_id="did:aps:example:cb-attestor",
            attestor_private_key=_ATTESTOR["privateKey"],
            verified_at="2026-09-23T00:00:00.000Z",
        ),
        requested_tool_name=_VECTORS["tool_name"],
        observed_implementation=_DRIFTED,
        resolve_trusted_attestor_key=lambda _tool: _ATTESTOR["publicKey"],
    )
    grant = tool_scope_grant(_VECTORS["tool_name"])
    grants = [grant, f"{grant}:impl:{capability_implementation_digest(_IMPL)}"]
    result = evaluate_capability_binding(
        requested_tool_name=_VECTORS["tool_name"],
        granted_scopes=grants,
        pin=parse_capability_pin_from_scope_grants(grants, _VECTORS["tool_name"]),
        attestation=observed,
        observed_implementation_digest=capability_implementation_digest(_DRIFTED),
        observed_metadata_digest=None,
    )
    assert result.outcome == "denied"
    assert result.continuity == "mismatch"
    assert result.reason_code == "PINNED_IMPLEMENTATION_DIGEST_MISMATCH"
    assert result.missing is None


# ── the verified_at override is additive ──────────────────────────────────────


def test_supplying_verified_at_makes_the_entry_reproducible() -> None:
    attestor = generate_key_pair()
    kwargs = dict(
        tool_name="t",
        implementation="x",
        attestor_id="did:aps:example:cb-attestor",
        attestor_private_key=attestor["privateKey"],
        verified_at="2026-09-23T00:00:00.000Z",
    )
    assert create_tool_registry_entry(**kwargs) == create_tool_registry_entry(**kwargs)


def test_omitting_verified_at_stamps_a_real_timestamp_and_still_verifies() -> None:
    attestor = generate_key_pair()
    entry = create_tool_registry_entry(
        tool_name="t",
        implementation="x",
        attestor_id="did:aps:example:cb-attestor",
        attestor_private_key=attestor["privateKey"],
    )
    assert entry.verifiedAt.endswith("Z")
    integrity = verify_tool_integrity(
        registry_entry=entry,
        current_implementation="x",
        attestor_public_key=attestor["publicKey"],
    )
    assert integrity.attestor_signature_valid is True
    assert integrity.implementation_verified is True


# ── identifier records ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "case", _VECTORS["record_signed_bytes_cases"], ids=lambda c: c["label"][:40]
)
def test_identifier_record_signed_bytes(case) -> None:
    assert identifier_record_signed_bytes(case["record"], case["unsigned_fields"]) == case[
        "expected"
    ]


def test_unsigned_field_lists_are_what_the_fixture_uses() -> None:
    assert list(IDENTIFIER_BINDING_UNSIGNED_FIELDS) == ["binding_id", "signature"]
    assert list(IDENTIFIER_RETENTION_UNSIGNED_FIELDS) == ["retention_id", "signature"]


def test_identifier_scope_grants_are_the_two_the_fixture_grants_use() -> None:
    assert (
        identifier_dependency_scope_grant("mail-domain", "acme-legal.example")
        == "extid:mail-domain:acme-legal.example"
    )
    assert (
        identifier_controller_pin_scope_grant(
            "mail-domain", "acme-legal.example", "did:aps:example:cb-org"
        )
        == "extid:mail-domain:acme-legal.example:controller:did:aps:example:cb-org"
    )


def test_controller_pins_are_read_only_for_the_identifier_asked_about() -> None:
    grants = [
        "extid:mail-domain:a.example:controller:did:one",
        "extid:mail-domain:b.example:controller:did:two",
    ]
    assert list(parse_identifier_controller_pins(grants, "mail-domain", "a.example")) == ["did:one"]


# ── evaluate_identifier_continuity ────────────────────────────────────────────


def _sign_records(entries, unsigned_fields) -> list[dict]:
    out: list[dict] = []
    for entry in entries:
        if "signature_literal" in entry:
            signature = entry["signature_literal"]
        elif entry["sign_as"] is None:
            signature = _IC["invalid_signature_literal"]
        else:
            signature = sign(
                identifier_record_signed_bytes(entry["record"], unsigned_fields),
                _IC["custodian_private_keys"][entry["sign_as"]],
            )
        out.append({**entry["record"], "signature": signature})
    return out


@pytest.mark.parametrize("case", _IC["cases"], ids=lambda c: c["id"])
def test_evaluate_identifier_continuity(case) -> None:
    raw = case["input"]
    standing = raw.get("custodian_standing_override", _IC["custodian_standing"])
    result = evaluate_identifier_continuity(
        identifier_kind=raw["identifierKind"],
        identifier=raw["identifier"],
        granted_scopes=raw["grantedScopes"],
        grant_issued_at=raw["grantIssuedAt"],
        at=raw["at"],
        bindings=_sign_records(raw["bindings"], IDENTIFIER_BINDING_UNSIGNED_FIELDS),
        retentions=_sign_records(raw["retentions"], IDENTIFIER_RETENTION_UNSIGNED_FIELDS),
        resolve_custodian_standing=lambda kind: standing.get(kind),
        resolve_custodian_key=lambda custodian: _IC["custodian_public_keys"].get(custodian),
    )
    _assert_binding(result, case["expected"], case["id"])


def test_a_denial_on_a_changed_controller_names_who_holds_the_identifier_now() -> None:
    for case in _IC["cases"]:
        if case["expected"]["reason_code"] != "IDENTIFIER_CONTROLLER_CHANGED":
            continue
        assert isinstance(case["expected"]["controller_at_instant"], str), case["id"]


# ── the constructor and the known divergence ──────────────────────────────────


def test_a_not_established_outcome_must_name_at_least_one_limb() -> None:
    with pytest.raises(CapabilityBindingError) as excinfo:
        referent_binding_result(
            outcome="not_established", continuity="not_established", reason_code="X"
        )
    assert excinfo.value.code == "MISSING_REQUIRED"


def test_a_reached_outcome_must_not_carry_a_limb() -> None:
    with pytest.raises(CapabilityBindingError) as excinfo:
        referent_binding_result(
            outcome="denied",
            continuity="mismatch",
            reason_code="X",
            missing=("coverage",),
        )
    assert excinfo.value.code == "MISSING_NOT_ALLOWED"


def test_the_v0_projection_collapses_denied_into_not_established_and_only_that_way() -> None:
    assert project_boundary_outcome_to_candidate_v0("authorized", "admitted") == "admitted"
    assert project_boundary_outcome_to_candidate_v0("authorized", "valid") == "valid"
    assert project_boundary_outcome_to_candidate_v0("denied", "admitted") == "not_established"
    assert (
        project_boundary_outcome_to_candidate_v0("not_established", "valid") == "not_established"
    )


def test_the_module_never_reports_an_established_mismatch_as_not_established() -> None:
    for case in _VECTORS["capability_binding_cases"] + _IC["cases"]:
        if case["expected"]["continuity"] != "mismatch":
            continue
        assert case["expected"]["outcome"] == "denied", case["id"]
        assert "missing" not in case["expected"], case["id"]
