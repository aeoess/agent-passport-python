# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — envelope construction, JCS, signing, digest.

Mirrors src/v2/cognitive-attestation/envelope.ts.

Wire compatibility with the TypeScript SDK (and the Paper 4 Python
reference at papers/paper-4/poc/src/envelope.py) is preserved via:
  - canonicalize_jcs (RFC 8785, nulls preserved)
  - base64 signatures
  - feature_activations sorted by (feature_id, activation_statistic)
"""

import base64
from dataclasses import replace
from hashlib import sha256
from typing import List, Optional

from ...canonical import canonicalize_jcs
from ...crypto import sign as ed_sign_hex
from .types import (
    AggregationPolicy,
    BuildAttestationInput,
    CognitiveAttestation,
    DictionaryRef,
    ExecutionEnvironment,
    FeatureActivation,
    ModelRef,
    Signature,
    SignerRole,
    TokenRange,
)

SPEC_VERSION = "1.0"


def _hex_to_b64(hex_str: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_str)).decode("ascii")


def sort_feature_activations(acts: List[FeatureActivation]) -> List[FeatureActivation]:
    """Sort feature_activations canonically.

    Primary key: feature_id ascending. Secondary: activation_statistic
    alphabetically. Returns a new list; does not mutate input.
    """
    return sorted(
        acts,
        key=lambda a: (a.feature_id, a.activation_statistic),
    )


def build_attestation(input: BuildAttestationInput) -> CognitiveAttestation:
    """Construct an unsigned CognitiveAttestation.

    `signatures` initialized to []. `feature_activations` canonically
    sorted. Caller signs via sign_attestation.
    """
    timestamp = input.timestamp if input.timestamp is not None else _now_iso()
    return CognitiveAttestation(
        spec_version=SPEC_VERSION,
        model_ref=ModelRef(
            model_id=input.model_id,
            model_version_hash=input.model_version_hash,
            tokenizer_version_hash=input.tokenizer_version_hash,
            inference_provider=input.inference_provider,
            execution_environment=ExecutionEnvironment(
                hardware_family=input.hardware_family,
                precision=input.precision,
                inference_engine=input.inference_engine,
                deterministic_mode=input.deterministic_mode,
            ),
        ),
        dictionary_ref=DictionaryRef(
            dictionary_id=input.dictionary_id,
            dictionary_version_hash=input.dictionary_version_hash,
            training_corpus_hash=input.training_corpus_hash,
            layer_index=input.layer_index,
            attachment_point=input.attachment_point,
            sae_type=input.sae_type,
        ),
        token_range=TokenRange(
            absolute_sequence_hash=input.absolute_sequence_hash,
            prior_state_hash=input.prior_state_hash,
            start_token_index=input.start_token_index,
            end_token_index=input.end_token_index,
            token_count=input.token_count,
        ),
        feature_activations=sort_feature_activations(input.feature_activations),
        aggregation_policy=AggregationPolicy(
            top_k=input.aggregation_policy.top_k,
            threshold=input.aggregation_policy.threshold,
            attestation_epsilon=input.aggregation_policy.attestation_epsilon,
            feature_allowlist_hash=input.aggregation_policy.feature_allowlist_hash,
            completeness_claim=input.aggregation_policy.completeness_claim,
            tiebreaker_rule=input.aggregation_policy.tiebreaker_rule,
            required_signer_roles=list(input.aggregation_policy.required_signer_roles),
        ),
        signatures=[],
        attestation_timestamp=timestamp,
    )


def _now_iso() -> str:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def canonicalize_attestation(att: CognitiveAttestation) -> bytes:
    """JCS-canonicalize the attestation for signing.

    Signatures are elided (signatures: []) so all signers over the same
    payload produce byte-identical input regardless of signing order.
    Feature activations are sorted canonically. Returns UTF-8 bytes.
    """
    sorted_features = sort_feature_activations(att.feature_activations)
    view = replace(att, feature_activations=sorted_features, signatures=[])
    canonical_str = canonicalize_jcs(view.to_canonical_dict())
    return canonical_str.encode("utf-8")


def sign_attestation(
    att: CognitiveAttestation,
    private_key: bytes,
    signer_did: str,
    signer_role: SignerRole,
) -> CognitiveAttestation:
    """Sign an attestation with a 32-byte Ed25519 seed.

    Appends a new entry to `signatures`. Returns a new object; never
    mutates input. The signature covers canonicalize_attestation(att),
    so additional signers produce byte-identical input regardless of
    order.
    """
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
        raise ValueError(
            "sign_attestation: private_key must be a 32-byte bytes object (Ed25519 seed)"
        )
    if not isinstance(signer_did, str) or len(signer_did) == 0:
        raise ValueError("sign_attestation: signer_did must be a non-empty string")

    canonical_bytes = canonicalize_attestation(att)
    canonical_str = canonical_bytes.decode("utf-8")
    private_key_hex = bytes(private_key).hex()
    sig_hex = ed_sign_hex(canonical_str, private_key_hex)
    sig_b64 = _hex_to_b64(sig_hex)

    sorted_features = sort_feature_activations(att.feature_activations)
    new_signatures = list(att.signatures) + [
        Signature(signer_did=signer_did, signer_role=signer_role, signature=sig_b64)
    ]
    return replace(
        att,
        feature_activations=sorted_features,
        signatures=new_signatures,
    )


def cognitive_attestation_digest(att: CognitiveAttestation) -> str:
    """Cross-primitive content anchor.

    Returns lowercase hex sha256 of the full signed envelope (including
    signatures) under JCS. Use when an APS action receipt needs to
    reference a cognitive attestation by content hash. Matches the
    hashing pattern of other v2 primitives (wallet-binding digest,
    attribution-primitive canonical hash).
    """
    sorted_features = sort_feature_activations(att.feature_activations)
    with_sorted = replace(att, feature_activations=sorted_features)
    canonical = canonicalize_jcs(with_sorted.to_canonical_dict())
    return sha256(canonical.encode("utf-8")).hexdigest()


# ── Shape validation (hand-rolled schema check) ────────────────────────

import re

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PRECISIONS = frozenset(["fp32", "fp16", "bf16", "int8"])
_ATTACHMENT_POINTS = frozenset(["residual_stream", "attention_output", "mlp_output"])
_SAE_TYPES = frozenset(["standard", "topk", "jumprelu", "gated", "batchtopk"])
_STATS = frozenset(["max", "mean", "sum", "integral", "last"])
_COMPLETENESS = frozenset(["top_k_only", "all_above_threshold", "dictionary_exhaustive"])
_TIEBREAKERS = frozenset(["lowest_feature_id", "highest_feature_id"])
_ROLES = frozenset(["agent", "operator", "provider", "third_party_attester"])


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_hex64(errors: list, path: str, v) -> None:
    if not isinstance(v, str) or not _HEX64.match(v):
        errors.append(f"{path}: expected 64-char lowercase hex")


def _check_hex64_nullable(errors: list, path: str, v) -> None:
    if v is None:
        return
    _check_hex64(errors, path, v)


def validate_attestation_shape(att) -> dict:
    """Hand-rolled schema check matching the normative JSON schema.

    Returns {"ok": bool, "errors": List[str]}. Mirrors TS
    validateAttestationShape exactly.
    """
    errors: list = []

    def _is_dict(v) -> bool:
        return isinstance(v, dict)

    # CognitiveAttestation dataclass also acceptable; convert to canonical dict.
    if hasattr(att, "to_canonical_dict") and not _is_dict(att):
        att = att.to_canonical_dict()
    if not _is_dict(att):
        return {"ok": False, "errors": ["root: expected object"]}

    if att.get("spec_version") != "1.0":
        errors.append('spec_version: must be "1.0"')

    # model_ref
    m = att.get("model_ref")
    if not _is_dict(m):
        errors.append("model_ref: expected object")
    else:
        if not isinstance(m.get("model_id"), str):
            errors.append("model_ref.model_id: expected string")
        _check_hex64(errors, "model_ref.model_version_hash", m.get("model_version_hash"))
        _check_hex64(errors, "model_ref.tokenizer_version_hash", m.get("tokenizer_version_hash"))
        ip = m.get("inference_provider")
        if ip is not None and not isinstance(ip, str):
            errors.append("model_ref.inference_provider: expected string|null")
        ee = m.get("execution_environment")
        if not _is_dict(ee):
            errors.append("model_ref.execution_environment: expected object")
        else:
            if not isinstance(ee.get("hardware_family"), str):
                errors.append("execution_environment.hardware_family: expected string")
            if ee.get("precision") not in _PRECISIONS:
                errors.append("execution_environment.precision: must be fp32|fp16|bf16|int8")
            if not isinstance(ee.get("inference_engine"), str):
                errors.append("execution_environment.inference_engine: expected string")
            if not isinstance(ee.get("deterministic_mode"), bool):
                errors.append("execution_environment.deterministic_mode: expected boolean")

    # dictionary_ref
    d = att.get("dictionary_ref")
    if not _is_dict(d):
        errors.append("dictionary_ref: expected object")
    else:
        if not isinstance(d.get("dictionary_id"), str):
            errors.append("dictionary_ref.dictionary_id: expected string")
        _check_hex64(errors, "dictionary_ref.dictionary_version_hash", d.get("dictionary_version_hash"))
        _check_hex64_nullable(errors, "dictionary_ref.training_corpus_hash", d.get("training_corpus_hash"))
        li = d.get("layer_index")
        if not _is_int(li) or li < 0:
            errors.append("dictionary_ref.layer_index: expected non-negative integer")
        if d.get("attachment_point") not in _ATTACHMENT_POINTS:
            errors.append("dictionary_ref.attachment_point: must be residual_stream|attention_output|mlp_output")
        if d.get("sae_type") not in _SAE_TYPES:
            errors.append("dictionary_ref.sae_type: must be standard|topk|jumprelu|gated|batchtopk")

    # token_range
    tr = att.get("token_range")
    if not _is_dict(tr):
        errors.append("token_range: expected object")
    else:
        _check_hex64(errors, "token_range.absolute_sequence_hash", tr.get("absolute_sequence_hash"))
        _check_hex64_nullable(errors, "token_range.prior_state_hash", tr.get("prior_state_hash"))
        for fld, expected in (("start_token_index", 0), ("end_token_index", 0), ("token_count", 1)):
            v = tr.get(fld)
            if not _is_int(v) or v < expected:
                op = "non-negative integer" if expected == 0 else f"integer >= {expected}"
                errors.append(f"token_range.{fld}: expected {op}")

    # feature_activations
    fa_list = att.get("feature_activations")
    if not isinstance(fa_list, list):
        errors.append("feature_activations: expected array")
    else:
        for i, fa in enumerate(fa_list):
            if not _is_dict(fa):
                errors.append(f"feature_activations[{i}]: expected object")
                continue
            fid = fa.get("feature_id")
            if not _is_int(fid) or fid < 0:
                errors.append(f"feature_activations[{i}].feature_id: expected non-negative integer")
            fl = fa.get("feature_label")
            if fl is not None and not isinstance(fl, str):
                errors.append(f"feature_activations[{i}].feature_label: expected string|null")
            if fa.get("activation_statistic") not in _STATS:
                errors.append(f"feature_activations[{i}].activation_statistic: must be max|mean|sum|integral|last")
            av = fa.get("activation_value")
            if not isinstance(av, (int, float)) or isinstance(av, bool) or av < 0:
                errors.append(f"feature_activations[{i}].activation_value: expected number >= 0")
            ta = fa.get("tokens_active")
            if not _is_int(ta) or ta < 0:
                errors.append(f"feature_activations[{i}].tokens_active: expected non-negative integer")

    # aggregation_policy
    ap = att.get("aggregation_policy")
    if not _is_dict(ap):
        errors.append("aggregation_policy: expected object")
    else:
        tk = ap.get("top_k")
        if tk is not None and (not _is_int(tk) or tk < 1):
            errors.append("aggregation_policy.top_k: expected integer >= 1 or null")
        th = ap.get("threshold")
        if th is not None and (not isinstance(th, (int, float)) or isinstance(th, bool) or th < 0):
            errors.append("aggregation_policy.threshold: expected number >= 0 or null")
        ae = ap.get("attestation_epsilon")
        if not isinstance(ae, (int, float)) or isinstance(ae, bool) or ae <= 0:
            errors.append("aggregation_policy.attestation_epsilon: required, must be number > 0")
        _check_hex64_nullable(errors, "aggregation_policy.feature_allowlist_hash", ap.get("feature_allowlist_hash"))
        if ap.get("completeness_claim") not in _COMPLETENESS:
            errors.append("aggregation_policy.completeness_claim: must be top_k_only|all_above_threshold|dictionary_exhaustive")
        if ap.get("tiebreaker_rule") not in _TIEBREAKERS:
            errors.append("aggregation_policy.tiebreaker_rule: must be lowest_feature_id|highest_feature_id")
        rsr = ap.get("required_signer_roles")
        if not isinstance(rsr, list) or len(rsr) == 0:
            errors.append("aggregation_policy.required_signer_roles: required, non-empty array")
        else:
            seen = set()
            for i, r in enumerate(rsr):
                if r not in _ROLES:
                    errors.append(f"aggregation_policy.required_signer_roles[{i}]: must be agent|operator|provider|third_party_attester")
                if r in seen:
                    errors.append(f'aggregation_policy.required_signer_roles: duplicate "{r}"')
                seen.add(r)

    # signatures
    sigs = att.get("signatures")
    if not isinstance(sigs, list) or len(sigs) < 1:
        errors.append("signatures: expected non-empty array")
    else:
        for i, s in enumerate(sigs):
            if not _is_dict(s):
                errors.append(f"signatures[{i}]: expected object")
                continue
            sid = s.get("signer_did")
            if not isinstance(sid, str) or len(sid) == 0:
                errors.append(f"signatures[{i}].signer_did: expected non-empty string")
            if s.get("signer_role") not in _ROLES:
                errors.append(f"signatures[{i}].signer_role: must be agent|operator|provider|third_party_attester")
            sg = s.get("signature")
            if not isinstance(sg, str) or len(sg) == 0:
                errors.append(f"signatures[{i}].signature: expected non-empty base64 string")

    # attestation_timestamp
    ats = att.get("attestation_timestamp")
    if not isinstance(ats, str):
        errors.append("attestation_timestamp: expected ISO 8601 date-time string")
    else:
        # Accept any valid ISO-8601-ish string. Python's fromisoformat is
        # stricter than JS Date.parse, so try a fallback that accepts the
        # 'Z' suffix.
        try:
            from datetime import datetime
            datetime.fromisoformat(ats.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            errors.append("attestation_timestamp: expected ISO 8601 date-time string")

    return {"ok": len(errors) == 0, "errors": errors}
