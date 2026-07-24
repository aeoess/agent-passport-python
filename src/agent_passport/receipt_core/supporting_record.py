"""Typed supporting records and EvidenceBundle v2 content binding."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import re

from ..crypto import sign, verify
from .jcs import assert_exact_keys, strict_jcs

SUPPORTING_RECORD_ID_TAG = "APS-SUPPORTING-RECORD-ID-V1"
SUPPORTING_RECORD_SIG_TAG = "APS-SUPPORTING-RECORD-SIG-V1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
UTC_MS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _is_exact_utc_milliseconds(value: str) -> bool:
    if not UTC_MS.fullmatch(value):
        return False
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" == value


def _without(record: dict, *keys: str) -> dict:
    return {key: copy.deepcopy(value) for key, value in record.items() if key not in keys}


def supporting_record_id_payload_v1(record: dict) -> str:
    return f"{SUPPORTING_RECORD_ID_TAG}\0{record['record_type']}\0{strict_jcs(_without(record, 'record_id', 'sig'))}"


def compute_supporting_record_id_v1(record: dict) -> str:
    return _sha256(supporting_record_id_payload_v1(record).encode()).hex()


def supporting_record_signature_payload_v1(record: dict) -> str:
    return f"{SUPPORTING_RECORD_SIG_TAG}\0{record['record_type']}\0{strict_jcs(_without(record, 'sig'))}"


def validate_supporting_record_v1(record: dict, require_crypto: bool = True) -> None:
    allowed = {"profile", "record_id", "record_type", "issuer", "issuer_key_id", "issued_at", "action_ref", "body", "sig_alg", "sig"}
    required = allowed - {"action_ref"}
    assert_exact_keys(record, allowed, required, "SupportingRecordV1")
    strict_jcs(record)
    if record["profile"] != "aps-supporting-record-v1":
        raise ValueError("SupportingRecordV1: profile")
    for key in ("record_type", "issuer", "issuer_key_id"):
        if not isinstance(record[key], str) or not record[key]:
            raise ValueError("SupportingRecordV1: identifier")
    if not isinstance(record["issued_at"], str) or not _is_exact_utc_milliseconds(record["issued_at"]):
        raise ValueError("SupportingRecordV1: issued_at")
    if "action_ref" in record and (not isinstance(record["action_ref"], str) or not HEX64.fullmatch(record["action_ref"])):
        raise ValueError("SupportingRecordV1: action_ref")
    if not isinstance(record["body"], dict):
        raise ValueError("SupportingRecordV1: body")
    if record["sig_alg"] != "Ed25519":
        raise ValueError("SupportingRecordV1: sig_alg")
    if require_crypto and (not isinstance(record["record_id"], str) or not HEX64.fullmatch(record["record_id"]) or not isinstance(record["sig"], str) or not HEX128.fullmatch(record["sig"])):
        raise ValueError("SupportingRecordV1: crypto encoding")


def create_supporting_record_v1(fields: dict, private_key: str) -> dict:
    record = copy.deepcopy(fields)
    record.update({"record_id": "0" * 64, "sig": ""})
    validate_supporting_record_v1(record, False)
    record["record_id"] = compute_supporting_record_id_v1(record)
    record["sig"] = sign(supporting_record_signature_payload_v1(record), private_key)
    validate_supporting_record_v1(record)
    return record


def verify_supporting_record_v1(record: dict, public_key: str) -> dict:
    try:
        validate_supporting_record_v1(record)
    except (TypeError, ValueError):
        return {"valid": False, "id_valid": False, "signature_valid": False}
    id_valid = compute_supporting_record_id_v1(record) == record["record_id"]
    signature_valid = verify(supporting_record_signature_payload_v1(record), record["sig"], public_key)
    return {"valid": id_valid and signature_valid, "id_valid": id_valid, "signature_valid": signature_valid}


def _entry_bytes(entry: dict) -> bytes:
    return strict_jcs(entry).encode("utf-8")


def evidence_bundle_merkle_root_v2(entries: list[dict]) -> str:
    if not entries:
        raise ValueError("EvidenceBundleV2: at least one member")
    seen = set()
    canonical_entries = []
    previous = None
    for entry in entries:
        keys = {"member_id", "member_type", "sha256"}
        assert_exact_keys(entry, keys, keys, "EvidenceBundleMemberV2")
        if not isinstance(entry["member_id"], str) or not entry["member_id"] or not isinstance(entry["member_type"], str) or not entry["member_type"] or not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"]):
            raise ValueError("EvidenceBundleMemberV2: value")
        if entry["member_id"] in seen:
            raise ValueError("EvidenceBundleV2: duplicate member_id")
        seen.add(entry["member_id"])
        canonical = _entry_bytes(entry)
        if previous is not None and previous >= canonical:
            raise ValueError("EvidenceBundleV2: members not sorted")
        previous = canonical
        canonical_entries.append(canonical)
    level = [_sha256(b"\x00" + canonical) for canonical in canonical_entries]
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(_sha256(b"\x01" + level[index] + level[index + 1]))
        level = next_level
    return level[0].hex()


def build_evidence_bundle_body_v2(members: list[dict]) -> dict:
    if not members:
        raise ValueError("EvidenceBundleV2: at least one member")
    seen = set()
    entries = []
    for member in members:
        assert_exact_keys(member, {"member_id", "member_type", "payload"}, {"member_id", "member_type", "payload"}, "EvidenceBundleMemberInputV2")
        if not isinstance(member["member_id"], str) or not member["member_id"] or not isinstance(member["member_type"], str) or not member["member_type"]:
            raise ValueError("EvidenceBundleV2: member identifier")
        if member["member_id"] in seen:
            raise ValueError("EvidenceBundleV2: duplicate member_id")
        seen.add(member["member_id"])
        entries.append({"member_id": member["member_id"], "member_type": member["member_type"], "sha256": _sha256(strict_jcs(member["payload"]).encode()).hex()})
    entries.sort(key=_entry_bytes)
    return {"members": entries, "merkle_root": evidence_bundle_merkle_root_v2(entries)}


def verify_evidence_bundle_body_v2(body: dict, payloads: dict | None = None) -> bool:
    try:
        assert_exact_keys(body, {"members", "merkle_root"}, {"members", "merkle_root"}, "EvidenceBundleBodyV2")
        if not isinstance(body["members"], list) or not body["members"] or not isinstance(body["merkle_root"], str) or not HEX64.fullmatch(body["merkle_root"]):
            return False
        seen = set()
        previous = None
        for entry in body["members"]:
            keys = {"member_id", "member_type", "sha256"}
            assert_exact_keys(entry, keys, keys, "EvidenceBundleMemberV2")
            if not isinstance(entry["member_id"], str) or not entry["member_id"] or not isinstance(entry["member_type"], str) or not entry["member_type"] or not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"]):
                return False
            if entry["member_id"] in seen:
                return False
            seen.add(entry["member_id"])
            canonical = _entry_bytes(entry)
            if previous is not None and previous >= canonical:
                return False
            previous = canonical
            if payloads is not None and (entry["member_id"] not in payloads or _sha256(strict_jcs(payloads[entry["member_id"]]).encode()).hex() != entry["sha256"]):
                return False
        return evidence_bundle_merkle_root_v2(body["members"]) == body["merkle_root"]
    except (TypeError, ValueError, KeyError):
        return False


def _evidence_leaf(entry: dict) -> bytes:
    return _sha256(b"\x00" + _entry_bytes(entry))


def build_evidence_bundle_proof_v2(entries: list[dict], member_id: str) -> dict:
    """Build a shape-checked inclusion proof; odd nodes are promoted, not copied."""
    evidence_bundle_merkle_root_v2(entries)
    try:
        leaf_index = next(index for index, entry in enumerate(entries) if entry["member_id"] == member_id)
    except StopIteration as exc:
        raise ValueError("EvidenceBundleV2: member not found") from exc
    index = leaf_index
    level = [_evidence_leaf(entry) for entry in entries]
    path = []
    while len(level) > 1:
        if index % 2 == 1:
            path.append({"position": "left", "sha256": level[index - 1].hex()})
        elif index + 1 < len(level):
            path.append({"position": "right", "sha256": level[index + 1].hex()})
        else:
            path.append({"position": "promote"})
        next_level = []
        for offset in range(0, len(level), 2):
            if offset + 1 == len(level):
                next_level.append(level[offset])
            else:
                next_level.append(_sha256(b"\x01" + level[offset] + level[offset + 1]))
        index //= 2
        level = next_level
    return {
        "profile": "aps-evidence-proof-v2",
        "member": copy.deepcopy(entries[leaf_index]),
        "leaf_index": leaf_index,
        "leaf_count": len(entries),
        "path": path,
    }


_PAYLOAD_ABSENT = object()


def verify_evidence_bundle_proof_v2(proof: dict, trusted_root: str, payload=_PAYLOAD_ABSENT) -> bool:
    try:
        keys = {"profile", "member", "leaf_index", "leaf_count", "path"}
        assert_exact_keys(proof, keys, keys, "EvidenceBundleProofV2")
        if proof["profile"] != "aps-evidence-proof-v2" or not isinstance(trusted_root, str) or not HEX64.fullmatch(trusted_root):
            return False
        member = proof["member"]
        member_keys = {"member_id", "member_type", "sha256"}
        assert_exact_keys(member, member_keys, member_keys, "EvidenceBundleMemberV2")
        if not isinstance(member["member_id"], str) or not member["member_id"] or not isinstance(member["member_type"], str) or not member["member_type"] or not isinstance(member["sha256"], str) or not HEX64.fullmatch(member["sha256"]):
            return False
        leaf_index = proof["leaf_index"]
        leaf_count = proof["leaf_count"]
        if isinstance(leaf_index, bool) or isinstance(leaf_count, bool) or not isinstance(leaf_index, int) or not isinstance(leaf_count, int) or leaf_count < 1 or leaf_index < 0 or leaf_index >= leaf_count or not isinstance(proof["path"], list):
            return False
        if payload is not _PAYLOAD_ABSENT and _sha256(strict_jcs(payload).encode()).hex() != member["sha256"]:
            return False
        index, width = leaf_index, leaf_count
        digest = _evidence_leaf(member)
        path_index = 0
        while width > 1:
            if path_index >= len(proof["path"]):
                return False
            step = proof["path"][path_index]
            path_index += 1
            expected = "left" if index % 2 == 1 else "right" if index + 1 < width else "promote"
            if not isinstance(step, dict) or step.get("position") != expected:
                return False
            if expected == "promote":
                assert_exact_keys(step, {"position"}, {"position"}, "EvidenceBundleProofStepV2")
            else:
                assert_exact_keys(step, {"position", "sha256"}, {"position", "sha256"}, "EvidenceBundleProofStepV2")
                if not isinstance(step["sha256"], str) or not HEX64.fullmatch(step["sha256"]):
                    return False
                sibling = bytes.fromhex(step["sha256"])
                digest = _sha256(b"\x01" + sibling + digest) if expected == "left" else _sha256(b"\x01" + digest + sibling)
            index //= 2
            width = (width + 1) // 2
        return path_index == len(proof["path"]) and digest.hex() == trusted_root
    except (TypeError, ValueError, KeyError):
        return False


def classify_supporting_record_format(value) -> dict:
    if not isinstance(value, dict):
        return {"format": "unknown", "canonicalization": "unknown", "legacy": False}
    if value.get("profile") == "aps-supporting-record-v1":
        return {"format": "supporting-record-v1", "canonicalization": "rfc8785", "legacy": False}
    if value.get("profile") == "aps-composition-check-v0":
        return {"format": "composition-check-v0", "canonicalization": "rfc8785-tagged-v0", "legacy": True}
    if value.get("spec_version") == "0.1.0" and value.get("record_type") == "accountability_record":
        return {"format": "accountability-record-0.1.0", "canonicalization": "rfc8785-untagged", "legacy": True}
    if value.get("type") == "read_fidelity_receipt":
        return {"format": "read-fidelity-unwrapped", "canonicalization": "rfc8785-untagged", "legacy": True}
    if isinstance(value.get("manifest"), dict) and value["manifest"].get("profile") == "aps:evidence-bundle:v1":
        return {"format": "evidence-bundle-v1", "canonicalization": "aps-legacy-null-dropping", "legacy": True}
    if "authority_ref" in value and "observer_key" in value and "profile" not in value:
        return {"format": "revocation-observation-unversioned", "canonicalization": "aps-legacy-null-dropping", "legacy": True}
    return {"format": "unknown", "canonicalization": "unknown", "legacy": False}
