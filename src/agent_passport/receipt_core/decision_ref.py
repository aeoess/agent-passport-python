"""Content-derived policy decision references."""

from __future__ import annotations

import hashlib
import re
import unicodedata

from .jcs import assert_exact_keys, strict_jcs
from .receipt import _is_exact_utc_milliseconds

DECISION_REF_TAG = "APS-DECISION-REF-V1"
DECISION_COMPONENT_TAGS = {
    "authority": "APS-DECISION-AUTHORITY-V1",
    "policy": "APS-DECISION-POLICY-V1",
    "context": "APS-DECISION-CONTEXT-V1",
    "output": "APS-DECISION-OUTPUT-V1",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def compute_decision_component_ref_v1(kind: str, value) -> str:
    if kind not in DECISION_COMPONENT_TAGS:
        raise ValueError("unknown decision component")
    return _sha256_hex(f"{DECISION_COMPONENT_TAGS[kind]}\0{strict_jcs(value)}")


def validate_decision_ref_input_v1(value: dict) -> None:
    keys = {"profile", "action_ref", "authority_state_ref", "policy_ref", "context_ref", "decision_output_ref"}
    assert_exact_keys(value, keys, keys, "DecisionRefInputV1")
    strict_jcs(value)
    if value["profile"] != "aps-decision-ref-v1":
        raise ValueError("DecisionRefInputV1: profile")
    for key in keys - {"profile"}:
        if not isinstance(value[key], str) or not HEX64.fullmatch(value[key]):
            raise ValueError(f"DecisionRefInputV1: {key} must be lowercase sha256 hex")


def compute_decision_ref_v1(value: dict) -> str:
    validate_decision_ref_input_v1(value)
    return _sha256_hex(f"{DECISION_REF_TAG}\0{strict_jcs(value)}")


def _assert_core_decision_output_shape_v1(value: dict) -> None:
    """The five-member shape of CoreDecisionOutputV1, draft lines 1074-1091, everything
    except the canonical form of the constraints array. Both entry points below run this."""
    keys = {"profile", "verdict", "effective_authority_ref", "constraints", "valid_until"}
    assert_exact_keys(value, keys, keys, "CoreDecisionOutputV1")
    strict_jcs(value)
    if value["profile"] != "aps-core-decision-output-v1":
        raise ValueError("CoreDecisionOutputV1: profile")
    verdict = value["verdict"]
    if verdict not in {"permit", "deny", "narrow"}:
        raise ValueError("CoreDecisionOutputV1: verdict")
    effective = value["effective_authority_ref"]
    # isinstance checked before the pattern: a non-string must not reach HEX64.fullmatch.
    if effective is not None and (not isinstance(effective, str) or not HEX64.fullmatch(effective)):
        raise ValueError("CoreDecisionOutputV1: effective_authority_ref")
    if verdict == "deny" and effective is not None:
        raise ValueError("CoreDecisionOutputV1: deny requires null effective_authority_ref")
    if verdict != "deny" and effective is None:
        raise ValueError("CoreDecisionOutputV1: permit/narrow require effective_authority_ref")
    constraints = value["constraints"]
    if not isinstance(constraints, list) or not all(isinstance(item, str) for item in constraints):
        raise ValueError("CoreDecisionOutputV1: constraints")
    valid_until = value["valid_until"]
    if verdict == "deny":
        if valid_until is not None:
            raise ValueError("CoreDecisionOutputV1: deny requires null valid_until")
    elif not isinstance(valid_until, str) or not _is_exact_utc_milliseconds(valid_until):
        raise ValueError("CoreDecisionOutputV1: permit/narrow require valid_until as exact UTC milliseconds")


def validate_core_decision_output_v1(value: dict) -> dict:
    """Validate a CoreDecisionOutputV1 exactly as received, repairing nothing.

    Draft line 1086 says constraints is a duplicate-free array of NFC strings sorted by
    UTF-8 bytes; section 5.6 makes a structural failure invalid, so a received array that
    is unsorted, duplicated, or not in NFC is rejected here rather than quietly repaired.
    Lines 822-824 state the same principle for the other canonical array in this protocol.

    normalize_core_decision_output_v1 keeps repairing, for the issuing side, where the
    caller is building the value it is about to sign.
    """
    _assert_core_decision_output_shape_v1(value)
    constraints = value["constraints"]
    previous = None
    for index, item in enumerate(constraints):
        if unicodedata.normalize("NFC", item) != item:
            raise ValueError(f"CoreDecisionOutputV1: constraints[{index}] is not in NFC")
        if previous is not None:
            if previous == item:
                raise ValueError("CoreDecisionOutputV1: duplicate constraint")
            if previous.encode("utf-8") > item.encode("utf-8"):
                raise ValueError("CoreDecisionOutputV1: constraints not sorted by UTF-8 bytes")
        previous = item
    return value


def normalize_core_decision_output_v1(value: dict) -> dict:
    _assert_core_decision_output_shape_v1(value)
    normalized = sorted({unicodedata.normalize("NFC", item) for item in value["constraints"]}, key=lambda s: s.encode("utf-8"))
    return {**value, "constraints": normalized}


def build_decision_ref_v1(*, action_ref: str, authority_state, policy_input, decision_context, decision_output) -> dict:
    if not isinstance(action_ref, str) or not HEX64.fullmatch(action_ref):
        raise ValueError("action_ref must be lowercase sha256 hex")
    if not isinstance(decision_output, dict):
        raise ValueError("decision_output must be a CoreDecisionOutputV1 object")
    # Normalize before hashing: the normalizer validates the closed five-member shape, so an
    # unnormalized or malformed decision output cannot reach the digest through this path.
    normalized_output = normalize_core_decision_output_v1(decision_output)
    ref_input = {
        "profile": "aps-decision-ref-v1",
        "action_ref": action_ref,
        "authority_state_ref": compute_decision_component_ref_v1("authority", authority_state),
        "policy_ref": compute_decision_component_ref_v1("policy", policy_input),
        "context_ref": compute_decision_component_ref_v1("context", decision_context),
        "decision_output_ref": compute_decision_component_ref_v1("output", normalized_output),
    }
    return {"input": ref_input, "decision_ref": compute_decision_ref_v1(ref_input)}
