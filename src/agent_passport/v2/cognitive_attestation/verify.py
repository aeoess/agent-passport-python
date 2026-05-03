# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cognitive Attestation — three-stage verification.

Mirrors src/v2/cognitive-attestation/verify.ts.

Stage 1 (cryptographic): verify_signature + verify_required_signer_roles.
Stage 2 (registry):      verify_against_registry — interface + basic impl;
                          concrete resolvers injected by integrators.
Stage 3 (replay):        verify_by_replay — typed shape only; SDK does not
                          bundle a running SAE.

Divergence from TS: the TS RegistryResolver is async (Promise-returning).
Python ports as a sync callable to match the rest of this SDK's lack of
asyncio dependencies. Integrators wrap async resolvers as needed.
"""

import base64
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set

from ...crypto import verify as ed_verify_hex
from .envelope import canonicalize_attestation
from .types import CognitiveAttestation, SignerRole


def _b64_to_hex(b64: str) -> Optional[str]:
    try:
        return base64.b64decode(b64).hex()
    except Exception:
        return None


# ── Stage 1a — cryptographic single-signer check ───────────────────────


def verify_signature(
    att: CognitiveAttestation,
    public_key: bytes,
    signer_did: str,
) -> bool:
    """Verify that at least one signature entry for signer_did validates
    against public_key. Returns False on tamper, wrong DID, malformed
    signature, or key mismatch.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False

    canonical_bytes = canonicalize_attestation(att)
    canonical_str = canonical_bytes.decode("utf-8")
    public_key_hex = bytes(public_key).hex()

    matches = [s for s in att.signatures if s.signer_did == signer_did]
    if not matches:
        return False

    for entry in matches:
        sig_hex = _b64_to_hex(entry.signature)
        if sig_hex is None:
            continue
        if ed_verify_hex(canonical_str, sig_hex, public_key_hex):
            return True
    return False


# ── Stage 1b — required signer role coverage ──────────────────────────


@dataclass
class RequiredRoleCoverage:
    ok: bool
    missing: List[SignerRole]
    present: List[SignerRole]


def verify_required_signer_roles(att: CognitiveAttestation) -> RequiredRoleCoverage:
    """Confirm every role in aggregation_policy.required_signer_roles is
    represented by at least one signature entry with that role.

    Structural check only — does NOT verify cryptographically. Pair with
    verify_signature for full Stage 1 coverage.
    """
    required: Set[SignerRole] = set(att.aggregation_policy.required_signer_roles)
    present_roles: Set[SignerRole] = set(s.signer_role for s in att.signatures)
    missing: List[SignerRole] = [r for r in required if r not in present_roles]
    return RequiredRoleCoverage(
        ok=len(missing) == 0,
        missing=missing,
        present=list(present_roles),
    )


# ── Stage 2 — registry verification ────────────────────────────────────


@dataclass
class RegistryResolver:
    """Sync resolver protocol. Integrators construct one via callables.

    is_known_model(model_id, model_version_hash) -> bool
    is_known_dictionary(dictionary_id, dictionary_version_hash) -> bool
    """

    is_known_model: Callable[[str, str], bool]
    is_known_dictionary: Callable[[str, str], bool]


@dataclass
class RegistryVerificationResult:
    ok: bool
    model_known: bool
    dictionary_known: bool
    errors: List[str] = field(default_factory=list)


def verify_against_registry(
    att: CognitiveAttestation,
    registry_resolver: RegistryResolver,
) -> RegistryVerificationResult:
    """Stage 2 — check that referenced model and dictionary versions exist
    in the resolver's registry view. The SDK ships no registry client.
    """
    errors: List[str] = []
    model_known = False
    dictionary_known = False

    try:
        model_known = bool(
            registry_resolver.is_known_model(
                att.model_ref.model_id,
                att.model_ref.model_version_hash,
            )
        )
        if not model_known:
            errors.append(
                f'unknown model_version_hash for model_id="{att.model_ref.model_id}"'
            )
    except Exception as e:
        errors.append(f"model resolver error: {e}")

    try:
        dictionary_known = bool(
            registry_resolver.is_known_dictionary(
                att.dictionary_ref.dictionary_id,
                att.dictionary_ref.dictionary_version_hash,
            )
        )
        if not dictionary_known:
            errors.append(
                f'unknown dictionary_version_hash for dictionary_id="{att.dictionary_ref.dictionary_id}"'
            )
    except Exception as e:
        errors.append(f"dictionary resolver error: {e}")

    return RegistryVerificationResult(
        ok=len(errors) == 0 and model_known and dictionary_known,
        model_known=model_known,
        dictionary_known=dictionary_known,
        errors=errors,
    )


# ── Stage 3 — computational replay (typed stub) ───────────────────────


@dataclass
class ReplayVerificationResult:
    ok: bool
    per_feature_delta: dict  # feature_id -> delta
    over_epsilon: List[int]
    missing_from_replay: List[int]
    unexpected_in_replay: List[int]


@dataclass
class ReplayBackend:
    """Inject a callable that runs the SAE replay. SDK does not ship one.

    replay(att) -> ReplayVerificationResult
    """

    replay: Callable[[CognitiveAttestation], ReplayVerificationResult]


def verify_by_replay(att: CognitiveAttestation, replayer: ReplayBackend) -> ReplayVerificationResult:
    """Stage 3 — requires an injected ReplayBackend. SDK does not bundle
    a running SAE. Use a private backend or the gateway's replay service.

    TODO: Once a reference replay backend exists (gateway-side, not SDK),
    document its contract here and ship test vectors covering
    threshold-delta, missing-feature, and unexpected-feature cases.
    """
    if replayer is None or not callable(replayer.replay):
        raise NotImplementedError(
            "verify_by_replay: not implemented in SDK. Inject a ReplayBackend "
            "or use a private backend (e.g. gateway replay service)."
        )
    return replayer.replay(att)
