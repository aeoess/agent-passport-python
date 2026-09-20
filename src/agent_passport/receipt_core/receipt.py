"""Stable APS ReceiptV1 identifiers, signatures, and verification."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from ..crypto import sign, verify
from .jcs import assert_exact_keys, parse_strict_i_json, snapshot_i_json_shape, strict_jcs

RECEIPT_ID_TAG = "APS-RECEIPT-ID-V1"
RECEIPT_SIG_TAG = "APS-RECEIPT-SIG-V1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
# Case-insensitive and deliberately separate from HEX64: a resolver's answer, unlike a
# receipt member, is not itself subject to the envelope's lowercase-only hex rule (draft
# section 2.5 lines 360-364). Anything matching this is usable Ed25519 key material;
# anything else never reaches the signature check (see _key_resolution_reason).
KEY_MATERIAL = re.compile(r"^[0-9a-fA-F]{64}$")
UTC_MS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.\d{3}Z$")
# delegation_ref carries the "sha256:" prefix of a delegation_id, not a bare digest
# (draft-pidlisnyi-aps-03 lines 964, 982, 484: the envelope example writes it as
# "sha256:<64 lowercase hexadecimal characters>", and section 3.1 gives delegation_id
# that exact form). Binding the value to a leaf needs a supplied chain, which is a
# section 5.6 composition point; this is the standalone structural form only.
DELEGATION_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _days_in_month(year: int, month: int) -> int:
    if month == 2 and _is_leap_year(year):
        return 29
    return _DAYS_IN_MONTH[month - 1]


def _is_exact_utc_milliseconds(value: str) -> bool:
    # Regex plus integer calendar arithmetic, no datetime.strptime/strftime: strftime's
    # platform-dependent zero-padding below year 1000 and datetime's refusal of year 0000
    # are not rules the draft states (draft line 986). Second 60 is RFC 3339 section 5.7
    # with Appendix D: valid only at 23:59 on the last day of its month; no leap-second
    # table is consulted or needed.
    match = UTC_MS.fullmatch(value)
    if not match:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    if not 1 <= month <= 12:
        return False
    if not 1 <= day <= _days_in_month(year, month):
        return False
    if not 0 <= hour <= 23:
        return False
    if not 0 <= minute <= 59:
        return False
    if second == 60:
        return hour == 23 and minute == 59 and day == _days_in_month(year, month)
    return 0 <= second <= 59


def _without(receipt: dict, *keys: str) -> dict:
    return {key: snapshot_i_json_shape(value) for key, value in receipt.items() if key not in keys}


def receipt_id_payload_v1(receipt: dict) -> str:
    return f"{RECEIPT_ID_TAG}\0{strict_jcs(_without(receipt, 'receipt_id', 'signatures'))}"


def compute_receipt_id_v1(receipt: dict) -> str:
    return _sha256_hex(receipt_id_payload_v1(receipt))


def receipt_signature_payload_v1(receipt: dict, descriptor: dict) -> str:
    form = {"receipt": _without(receipt, "signatures"), "signer": snapshot_i_json_shape(descriptor)}
    return f"{RECEIPT_SIG_TAG}\0{strict_jcs(form)}"


# The 66 Unicode noncharacters: U+FDD0 through U+FDEF, and U+xFFFE/U+xFFFF for each of the
# 17 planes. Rejected anywhere in a receipt (draft line 1213). strict_jcs already rejects an
# unpaired surrogate but not a noncharacter, and it is shared with other record families, so
# this check is local to receipt.py rather than a change to jcs.py's assert_i_json. Same
# shape as agent_passport.v2.action_reference.v2._check_no_noncharacters and
# agent_passport.v2.authority_delegation.schema._is_surrogate_or_noncharacter.
_NONCHARACTER_LOW_16 = frozenset({0xFFFE, 0xFFFF})


def _is_noncharacter(code_point: int) -> bool:
    if 0xFDD0 <= code_point <= 0xFDEF:
        return True
    return (code_point & 0xFFFF) in _NONCHARACTER_LOW_16


class _NoncharacterWalkExit:
    """Stack marker for leaving a list or dict during `_assert_no_noncharacters_v1`."""

    __slots__ = ("identity",)

    def __init__(self, identity: int) -> None:
        self.identity = identity


def _assert_no_noncharacters_v1(root) -> None:
    """Iteratively walk `root` (already known to be I-JSON, so only list/dict/str/other
    scalars remain), raising ValueError if any string value or object key, at any depth,
    contains a Unicode noncharacter. Non-recursive and cycle-safe for the same reasons as
    the two established implementations cited above.
    """
    ancestors: set[int] = set()
    stack: list = [root]
    while stack:
        item = stack.pop()
        if type(item) is _NoncharacterWalkExit:
            ancestors.discard(item.identity)
            continue
        if isinstance(item, str):
            for char in item:
                if _is_noncharacter(ord(char)):
                    raise ValueError(f"ReceiptV1: noncharacter U+{ord(char):04X}")
            continue
        if type(item) is list:
            identity = id(item)
            if identity in ancestors:
                continue
            ancestors.add(identity)
            stack.append(_NoncharacterWalkExit(identity))
            stack.extend(item)
            continue
        if type(item) is dict:
            identity = id(item)
            if identity in ancestors:
                continue
            ancestors.add(identity)
            stack.append(_NoncharacterWalkExit(identity))
            for key, value in item.items():
                if isinstance(key, str):
                    for char in key:
                        if _is_noncharacter(ord(char)):
                            raise ValueError(f"ReceiptV1: noncharacter U+{ord(char):04X} in object key")
                stack.append(value)
            continue
        # None, bool, int, float: no characters to check.


def validate_receipt_v1(receipt: dict, require_values: bool = True) -> None:
    allowed = {"profile", "receipt_id", "receipt_type", "issuer", "subject_agent", "action_ref", "delegation_ref", "decision_ref", "issued_at", "evidence_refs", "result", "prev", "signatures"}
    required = allowed - {"decision_ref", "prev"}
    assert_exact_keys(receipt, allowed, required, "ReceiptV1")
    strict_jcs(receipt)
    _assert_no_noncharacters_v1(receipt)
    if receipt["profile"] != "aps-receipt-v1":
        raise ValueError("ReceiptV1: profile")
    for key in ("receipt_type", "issuer", "subject_agent"):
        if not isinstance(receipt[key], str) or not receipt[key]:
            raise ValueError("ReceiptV1: empty identifier")
    if not isinstance(receipt["delegation_ref"], str) or not DELEGATION_REF.fullmatch(receipt["delegation_ref"]):
        raise ValueError("ReceiptV1: delegation_ref")
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
    receipt = snapshot_i_json_shape(fields)
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


# Draft section 2.5 lines 360-364 require a resolver to keep six outcomes apart: resolved;
# subject or key not found; ambiguous; structurally malformed key material; transport
# unreachability; and an unsupported identifier scheme. This SDK used to report every
# unresolved case as the same "key_unresolved" answer.
_KEY_OUTCOME_REASONS = {
    "not_found": "key_not_found",
    "ambiguous": "key_ambiguous",
    "malformed": "key_material_malformed",
    "unreachable": "key_unreachable",
    "unsupported_scheme": "key_scheme_unsupported",
}


def _key_resolution_reason(resolved) -> str | None:
    """The reason `resolved` (a receipt key resolver's answer) is not usable key material,
    or None when it is usable and the signature check should run.

    A string that is not 32 bytes of hexadecimal never reaches that check: the check
    returns False on a length mismatch, which used to be reported as "signature_invalid",
    saying the bytes were checked and failed when nothing was checked. A mapping names one
    of the outcomes above; an unrecognised outcome, or any other value including None,
    keeps "key_unresolved".
    """
    if isinstance(resolved, str):
        return None if KEY_MATERIAL.fullmatch(resolved) else "key_material_malformed"
    if isinstance(resolved, dict) and isinstance(resolved.get("outcome"), str):
        return _KEY_OUTCOME_REASONS.get(resolved["outcome"], "key_unresolved")
    return "key_unresolved"


def _declares_foreign_profile(receipt) -> bool:
    """True when `receipt` names an envelope profile other than aps-receipt-v1. Such an
    artifact is unsupported (draft section 5.6 line 1226) rather than invalid, and is not
    judged against the aps-receipt-v1 schema, which is not its schema."""
    if not isinstance(receipt, dict):
        return False
    profile = receipt.get("profile")
    return isinstance(profile, str) and profile != "aps-receipt-v1"


def verify_receipt_v1(
    receipt: dict,
    resolve_key,
    *,
    expected_receipt_type=None,
    boundary_identity=None,
    required_signers: Iterable[str] = (),
) -> dict:
    """Verify a ReceiptV1: envelope, identifier, signatures and the section 5.3 stage
    rules for the record's own receipt_type.

    Only a REQUIRED signature decides the aggregate state (draft line 1041). Draft line
    999 names one required signer, the issuer; `required_signers` names any others the
    applicable profile or this caller also requires. Every carried signature is checked
    and reported in `signature_results`, marked `required` accordingly, but a non-required
    signature that fails or cannot be resolved only moves the separate `other_signatures`
    axis ("none" / "all_verified" / "not_all_verified"): draft lines 1003-1009 keep
    signatures outside receipt_id, so a third party can append a descriptor to a published
    receipt without changing its digest, and letting that flip a conforming receipt to
    invalid would hand the outcome to that third party. A required signer that carries no
    descriptor at all is a missing required signature: `required_signature_missing` is
    added to `errors` and `status` becomes "invalid".

    The stage dispatch is part of this because draft line 1214 has a verifier enforce the
    closed ReceiptV1 schema AND the type-specific schema, and this function reports its
    outcome in the draft's own state words. Without it, an action-intent record issued by
    someone other than the acting agent, carrying prev and decision_ref and a free-form
    result, came back "valid".

    `receipt_id_valid` and `stage` are "not_checked" where the record never reached those
    steps, rather than False, which would say a check ran and failed.
    """
    # Imported here rather than at module scope: stage.py imports this module, and a
    # module-level import in both directions would leave one of them half-initialized.
    from .stage import validate_receipt_stage_v1

    if _declares_foreign_profile(receipt):
        return {
            "valid": False,
            "status": "unsupported",
            "receipt_id_valid": "not_checked",
            "stage": "not_checked",
            "signer_authority": "not_checked",
            "signature_results": [],
            "other_signatures": "none",
            "errors": ["unsupported_profile"],
        }
    try:
        validate_receipt_v1(receipt)
    except (TypeError, ValueError) as exc:
        return {
            "valid": False,
            "status": "invalid",
            "receipt_id_valid": "not_checked",
            "stage": "not_checked",
            "signer_authority": "not_checked",
            "signature_results": [],
            "other_signatures": "none",
            "errors": [str(exc)],
        }
    id_valid = compute_receipt_id_v1(receipt) == receipt["receipt_id"]
    errors = [] if id_valid else ["receipt_id_mismatch"]

    required_set = {receipt["issuer"], *required_signers}
    results = []
    for proof in receipt["signatures"]:
        required = proof["signer"] in required_set
        try:
            resolved = resolve_key(proof["signer"], proof["key_id"], receipt["issued_at"])
        except Exception:
            results.append({"signer": proof["signer"], "key_id": proof["key_id"], "valid": False, "required": required, "reason": "key_resolution_error"})
            continue
        reason = _key_resolution_reason(resolved)
        if reason is not None:
            results.append({"signer": proof["signer"], "key_id": proof["key_id"], "valid": False, "required": required, "reason": reason})
            continue
        descriptor = {"signer": proof["signer"], "key_id": proof["key_id"], "alg": proof["alg"]}
        results.append({
            "signer": proof["signer"],
            "key_id": proof["key_id"],
            "required": required,
            "valid": verify(receipt_signature_payload_v1(receipt, descriptor), proof["value"], resolved),
        })

    for signer in required_set:
        if not any(item["signer"] == signer for item in results):
            errors.append("required_signature_missing")

    required_results = [item for item in results if item["required"]]
    other_results = [item for item in results if not item["required"]]

    # key_scheme_unsupported is kept apart from the other unresolved reasons: it makes the
    # receipt unsupported rather than indeterminate, so it is excluded from `unresolved`
    # and tracked on its own (draft section 5.6 line 1226 makes an unsupported requirement
    # its own state, not a form of indeterminate).
    unsupported_scheme = any(item.get("reason") == "key_scheme_unsupported" for item in required_results)
    unresolved = [item for item in required_results if item.get("reason") is not None and item["reason"] != "key_scheme_unsupported"]
    # An unresolved key and a signature that fails verification are different findings: the
    # former never had its bytes checked, so it must not also raise "signature_invalid"
    # (draft section 2.4 line 322, section 2.5 lines 360-369, section 5.6 line 1226). Only
    # a required signature's own failure counts here; see the docstring above.
    bad_bytes = [item for item in required_results if not item["valid"] and "reason" not in item]
    if bad_bytes:
        errors.append("signature_invalid")
    if unsupported_scheme:
        errors.append("signer_key_scheme_unsupported")
    if unresolved:
        errors.append("signer_authority_indeterminate")
    if bad_bytes:
        signer_authority = "invalid"
    elif unresolved or unsupported_scheme:
        signer_authority = "not_established"
    else:
        signer_authority = "verified"
    other_signatures = (
        "none"
        if not other_results
        else "all_verified"
        if all(item["valid"] for item in other_results)
        else "not_all_verified"
    )
    stage = validate_receipt_stage_v1(
        receipt, expected_receipt_type=expected_receipt_type, boundary_identity=boundary_identity
    )
    if stage["status"] != "valid":
        errors.append(f"stage_{stage['status']}")
        errors.extend(failure["code"] for failure in stage["failures"])
    if bad_bytes or not id_valid or stage["status"] == "invalid" or "required_signature_missing" in errors:
        status = "invalid"
    elif stage["status"] == "unsupported" or unsupported_scheme:
        status = "unsupported"
    elif unresolved or stage["status"] == "indeterminate":
        status = "indeterminate"
    else:
        status = "valid"
    return {
        "valid": status == "valid",
        "status": status,
        "receipt_id_valid": id_valid,
        "stage": stage,
        "signer_authority": signer_authority,
        "signature_results": results,
        "other_signatures": other_signatures,
        "errors": errors,
    }


def verify_receipt_v1_serialized(
    raw: str,
    resolve_key,
    *,
    expected_receipt_type=None,
    boundary_identity=None,
    max_utf8_bytes: int = 1_048_576,
    max_depth: int = 128,
    required_signers: Iterable[str] = (),
) -> dict:
    """Verify a receipt from its serialized bytes.

    Draft line 1213 has a verifier parse bounded I-JSON WHILE PRESERVING DUPLICATE NAMES.
    Rejecting a duplicate member is a property of parsing: once bytes have become a dict
    the later member has already overwritten the earlier one and the evidence is gone, so
    verify_receipt_v1, which receives an object, cannot detect it however carefully it
    validates. Without this entry point the only Python route was json.loads plus
    verify_receipt_v1, which accepts a document TypeScript rejects.

    Parse failure is reported as the error code `parse_error` followed by the parser's own
    message, so it is distinguishable from a structural failure, which surfaces the
    validator's message with no code, and from a signature failure, which surfaces
    `signature_invalid`.

    `required_signers` is forwarded to verify_receipt_v1 unchanged; see its docstring.
    """
    try:
        parsed = parse_strict_i_json(raw, max_utf8_bytes=max_utf8_bytes, max_depth=max_depth)
    except (TypeError, ValueError) as exc:
        return {
            "valid": False,
            "status": "invalid",
            "receipt_id_valid": "not_checked",
            "stage": "not_checked",
            "signer_authority": "not_checked",
            "signature_results": [],
            "other_signatures": "none",
            "errors": ["parse_error", str(exc)],
        }
    return verify_receipt_v1(
        parsed,
        resolve_key,
        expected_receipt_type=expected_receipt_type,
        boundary_identity=boundary_identity,
        required_signers=required_signers,
    )
