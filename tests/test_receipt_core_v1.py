import copy

import pytest

from agent_passport.crypto import public_key_from_private
from agent_passport.receipt_core import (
    build_decision_ref_v1,
    build_evidence_bundle_body_v2,
    build_evidence_bundle_proof_v2,
    classify_supporting_record_format,
    compute_receipt_id_v1,
    create_receipt_v1,
    create_supporting_record_v1,
    normalize_core_decision_output_v1,
    verify_evidence_bundle_body_v2,
    verify_evidence_bundle_proof_v2,
    verify_receipt_v1,
    verify_supporting_record_v1,
)
from agent_passport.receipt_core.jcs import IJsonValidationError, parse_strict_i_json, strict_jcs

PRIVATE_KEY = "00" * 32
PUBLIC_KEY = public_key_from_private(PRIVATE_KEY)
KAT = {
    "decision_ref": "2157809a9a722314ae19dce7a242ea3b54a8948230fab2fab5d5dc15bd663dc2",
    "receipt_id": "89b0b77807e99845aab403f01bcdaa2f02949f6c9db84e1aca6c0a8449e4d023",
    "receipt_sig": "83deb713568bbdf0c85e1a6d46345530e84dbe86cdefe1cb608b0f14372c176a9e69e0033db11c4c44ff84be3de3bee5e212707eb84206f6c34455206d37f90b",
    "merkle_root": "03700eeba1b453086063612d3df73f711827735c3fe30cf8a8a2a6379a6f6d5f",
    "record_id": "7d73684a65444088e841f2b30f0ecf139fbadbeab277d57d20d1a2ef5fe2a7b2",
    "record_sig": "56a2116eb4e259a336c36a646e69322cf2e7850b7202f2093c5957e4e6a100cf4cae8048cb4647bbc557447bea531dd7e69c117e9298515cc767110cf0f7d809",
    "proof_root": "dab9f2f5f3571345327f0144f2eafbb6e835ac5cbb48e9d789224e135ce16247",
    "proof_left": "f3bdfcf031dea9da3129ae67bdf7f69caefc41660541d0acb015e1b49ae95470",
}


def hx(char):
    return char * 64


def test_decision_ref_is_content_derived_and_normalizes_constraints():
    first = build_decision_ref_v1(
        action_ref=hx("a"), authority_state={"scope": ["read"], "revoked": False},
        policy_input={"id": "p1", "version": "1"}, decision_context={"tenant": "t1"},
        decision_output={"verdict": "permit", "constraints": []},
    )
    assert first["decision_ref"] == KAT["decision_ref"]
    reordered = build_decision_ref_v1(
        action_ref=hx("a"), authority_state={"revoked": False, "scope": ["read"]},
        policy_input={"version": "1", "id": "p1"}, decision_context={"tenant": "t1"},
        decision_output={"constraints": [], "verdict": "permit"},
    )
    assert first["decision_ref"] == reordered["decision_ref"]
    output = normalize_core_decision_output_v1({"profile": "aps-core-decision-output-v1", "verdict": "narrow", "effective_authority_ref": hx("b"), "constraints": ["é", "read", "e\u0301", "read"]})
    assert output["constraints"] == ["read", "é"]


def test_receipt_binds_id_signer_descriptor_and_content():
    receipt = create_receipt_v1({
        "profile": "aps-receipt-v1", "receipt_type": "aps:action:v1", "issuer": "did:example:issuer",
        "subject_agent": "did:example:agent", "action_ref": hx("a"), "delegation_ref": hx("b"),
        "decision_ref": hx("c"), "issued_at": "2026-07-18T12:00:00.000Z",
        "evidence_refs": [{"artifact_type": "z", "sha256": hx("e")}, {"artifact_type": "a", "sha256": hx("d")}],
        "result": {"status": "success", "detail": None},
    }, [{"signer": "did:example:issuer", "key_id": "key-1", "private_key": PRIVATE_KEY}])
    assert receipt["receipt_id"] == compute_receipt_id_v1(receipt)
    assert receipt["receipt_id"] == KAT["receipt_id"]
    assert receipt["signatures"][0]["value"] == KAT["receipt_sig"]
    assert verify_receipt_v1(receipt, lambda *_: PUBLIC_KEY)["valid"]
    relabeled = copy.deepcopy(receipt)
    relabeled["signatures"][0]["key_id"] = "key-2"
    assert not verify_receipt_v1(relabeled, lambda *_: PUBLIC_KEY)["valid"]
    tampered = copy.deepcopy(receipt)
    tampered["result"]["status"] = "failure"
    assert not verify_receipt_v1(tampered, lambda *_: PUBLIC_KEY)["valid"]


def test_supporting_record_and_bundle_bind_every_member_axis():
    payloads = {"m1": {"value": None}, "m2": {"value": 2}}
    bundle = build_evidence_bundle_body_v2([
        {"member_id": "m2", "member_type": "two", "payload": payloads["m2"]},
        {"member_id": "m1", "member_type": "one", "payload": payloads["m1"]},
    ])
    assert bundle["merkle_root"] == KAT["merkle_root"]
    assert verify_evidence_bundle_body_v2(bundle, payloads)
    record = create_supporting_record_v1({
        "profile": "aps-supporting-record-v1", "record_type": "aps:evidence-bundle:v2",
        "issuer": "did:example:issuer", "issuer_key_id": "key-1", "issued_at": "2026-07-18T12:00:00.000Z",
        "body": bundle, "sig_alg": "Ed25519",
    }, PRIVATE_KEY)
    assert record["record_id"] == KAT["record_id"]
    assert record["sig"] == KAT["record_sig"]
    assert verify_supporting_record_v1(record, PUBLIC_KEY)["valid"]
    changed = copy.deepcopy(bundle)
    changed["members"][0]["member_type"] = "changed"
    assert not verify_evidence_bundle_body_v2(changed, payloads)
    three = build_evidence_bundle_body_v2([
        {"member_id": "m3", "member_type": "three", "payload": {"value": 3}},
        {"member_id": "m1", "member_type": "one", "payload": {"value": 1}},
        {"member_id": "m2", "member_type": "two", "payload": {"value": 2}},
    ])
    proof = build_evidence_bundle_proof_v2(three["members"], "m3")
    assert three["merkle_root"] == KAT["proof_root"]
    assert proof["path"] == [{"position": "promote"}, {"position": "left", "sha256": KAT["proof_left"]}]
    assert any(step["position"] == "promote" for step in proof["path"])
    assert verify_evidence_bundle_proof_v2(proof, three["merkle_root"], {"value": 3})
    malformed = copy.deepcopy(proof)
    malformed["leaf_count"] = 4
    assert not verify_evidence_bundle_proof_v2(malformed, three["merkle_root"], {"value": 3})


def test_strict_new_write_and_explicit_legacy_dispatch():
    with pytest.raises(IJsonValidationError):
        strict_jcs({"x": object()})
    with pytest.raises(IJsonValidationError):
        strict_jcs({"x": "\ud800"})
    with pytest.raises(IJsonValidationError, match="IEEE 754"):
        strict_jcs({"integer": 9_007_199_254_740_992})
    with pytest.raises(IJsonValidationError, match="duplicate object member"):
        parse_strict_i_json('{"a":1,"\\u0061":2}')
    assert classify_supporting_record_format({"manifest": {"profile": "aps:evidence-bundle:v1"}})["format"] == "evidence-bundle-v1"
    assert classify_supporting_record_format({"profile": "future"})["format"] == "unknown"
