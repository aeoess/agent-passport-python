"""Stable APS ReceiptV1 identifiers, signatures, and verification."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import re

from ..crypto import sign, verify
from .jcs import assert_exact_keys, strict_jcs

RECEIPT_ID_TAG = "APS-RECEIPT-ID-V1"
RECEIPT_SIG_TAG = "APS-RECEIPT-SIG-V1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
UTC_MS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_exact_utc_milliseconds(value: str) -> bool:
    if not UTC_MS.fullmatch(value):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" == value


def _without(receipt: dict, *keys: str) -> dict:
    return {key: copy.deepcopy(value) for key, value in receipt.items() if key not in keys}


def receipt_id_payload_v1(receipt: dict) -> str:
    return f"{RECEIPT_ID_TAG}\0{strict_jcs(_without(receipt, 'receipt_id', 'signatures'))}"


def compute_receipt_id_v1(receipt: dict) -> str:
    return _sha256_hex(receipt_id_payload_v1(receipt))


def receipt_signature_payload_v1(receipt: dict, descriptor: dict) -> str:
    form = {"receipt": _without(receipt, "signatures"), "signer": copy.deepcopy(descriptor)}
    return f"{RECEIPT_SIG_TAG}\0{strict_jcs(form)}"


def validate_receipt_v1(receipt: dict, require_values: bool = True) -> None:
    allowed = {"profile", "receipt_id", "receipt_type", "issuer", "subject_agent", "action_ref", "delegation_ref", "decision_ref", "issued_at", "evidence_refs", "result", "prev", "signatures"}
    required = allowed - {"decision_ref", "prev"}
    assert_exact_keys(receipt, allowed, required, "ReceiptV1")
    strict_jcs(receipt)
    if receipt["profile"] != "aps-receipt-v1":
        raise ValueError("ReceiptV1: profile")
    for key in ("receipt_type", "issuer", "subject_agent", "delegation_ref"):
        if not isinstance(receipt[key], str) or not receipt[key]:
            raise ValueError("ReceiptV1: empty identifier")
    if require_values and (not isinstance(receipt["receipt_id"], str) or not HEX64.fullmatch(receipt["receipt_id"])):
        raise ValueError("ReceiptV1: receipt_id")
    if not isinstance(receipt["action_ref"], str) or not HEX64.fullmatch(receipt["action_ref"]):
        raise ValueError("ReceiptV1: action_ref")
    for key in ("decision_ref", "prev"):
        if key in receipt and (not isinstance(receipt[key], str) or not HEX64.fullmatch(receipt[key])):
            raise ValueError(f"ReceiptV1: {key}")
    if not isinstance(receipt["issued_at"], str) or not _is_exact_utc_milliseconds(receipt["issued_at"]):
        raise ValueError("ReceiptV1: issued_at")
    if not isinstance(receipt["result"], dict):
        raise ValueError("ReceiptV1: result")
    if not isinstance(receipt["evidence_refs"], list) or not isinstance(receipt["signatures"], list):
        raise ValueError("ReceiptV1: arrays")
    seen = set()
    previous = None
    for ref in receipt["evidence_refs"]:
        assert_exact_keys(ref, {"artifact_type", "sha256"}, {"artifact_type", "sha256"}, "EvidenceRefV1")
        if not isinstance(ref["artifact_type"], str) or not ref["artifact_type"] or not isinstance(ref["sha256"], str) or not HEX64.fullmatch(ref["sha256"]):
            raise ValueError("EvidenceRefV1: value")
        order = (ref["artifact_type"].encode("utf-8"), ref["sha256"].encode("utf-8"))
        if order in seen:
            raise ValueError("ReceiptV1: duplicate evidence_ref")
        if previous is not None and previous >= order:
            raise ValueError("ReceiptV1: evidence_refs not sorted")
        seen.add(order)
        previous = order
    seen = set()
    previous = None
    for proof in receipt["signatures"]:
        keys = {"signer", "key_id", "alg", "value"}
        assert_exact_keys(proof, keys, keys, "ReceiptSignatureV1")
        if not isinstance(proof["signer"], str) or not proof["signer"] or not isinstance(proof["key_id"], str) or not proof["key_id"] or proof["alg"] != "Ed25519":
            raise ValueError("ReceiptSignatureV1: value")
        if require_values and (not isinstance(proof["value"], str) or not HEX128.fullmatch(proof["value"])):
            raise ValueError("ReceiptSignatureV1: value")
        order = (proof["signer"].encode("utf-8"), proof["key_id"].encode("utf-8"))
        if order in seen:
            raise ValueError("ReceiptV1: duplicate signature")
        if previous is not None and previous >= order:
            raise ValueError("ReceiptV1: signatures not sorted")
        seen.add(order)
        previous = order
    if require_values and not any(proof["signer"] == receipt["issuer"] for proof in receipt["signatures"]):
        raise ValueError("ReceiptV1: issuer signature missing")


def create_receipt_v1(fields: dict, signers: list[dict]) -> dict:
    if not signers:
        raise ValueError("ReceiptV1: at least one signer")
    receipt = copy.deepcopy(fields)
    receipt["evidence_refs"] = sorted(receipt["evidence_refs"], key=lambda ref: (ref["artifact_type"].encode("utf-8"), ref["sha256"].encode("utf-8")))
    descriptors = sorted(signers, key=lambda item: (item["signer"].encode("utf-8"), item["key_id"].encode("utf-8")))
    receipt["receipt_id"] = "0" * 64
    receipt["signatures"] = []
    validate_receipt_v1(receipt, False)
    receipt["receipt_id"] = compute_receipt_id_v1(receipt)
    receipt["signatures"] = []
    for item in descriptors:
        descriptor = {"signer": item["signer"], "key_id": item["key_id"], "alg": "Ed25519"}
        receipt["signatures"].append({**descriptor, "value": sign(receipt_signature_payload_v1(receipt, descriptor), item["private_key"])})
    validate_receipt_v1(receipt)
    return receipt


def verify_receipt_v1(receipt: dict, resolve_key) -> dict:
    try:
        validate_receipt_v1(receipt)
    except (TypeError, ValueError) as exc:
        return {"valid": False, "receipt_id_valid": False, "signature_results": [], "errors": [str(exc)]}
    id_valid = compute_receipt_id_v1(receipt) == receipt["receipt_id"]
    errors = [] if id_valid else ["receipt_id_mismatch"]
    results = []
    for proof in receipt["signatures"]:
        try:
            public_key = resolve_key(proof["signer"], proof["key_id"], receipt["issued_at"])
        except Exception:
            results.append({"signer": proof["signer"], "key_id": proof["key_id"], "valid": False, "reason": "key_resolution_error"})
            continue
        if public_key is None:
            results.append({"signer": proof["signer"], "key_id": proof["key_id"], "valid": False, "reason": "key_unresolved"})
            continue
        descriptor = {"signer": proof["signer"], "key_id": proof["key_id"], "alg": proof["alg"]}
        results.append({"signer": proof["signer"], "key_id": proof["key_id"], "valid": verify(receipt_signature_payload_v1(receipt, descriptor), proof["value"], public_key)})
    if any(not item["valid"] for item in results):
        errors.append("signature_invalid")
    return {"valid": not errors, "receipt_id_valid": id_valid, "signature_results": results, "errors": errors}
