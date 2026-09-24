# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Tool registry integrity: the legacy registry-entry layer, at byte parity with the
TypeScript SDK's ``src/core/tool-integrity.ts``.

An attestor signs that a named tool's implementation bytes are the ones it approved, and a
verifier later checks that the tool reachable now still hashes to the same value. That is
the whole of this module.

WHAT THIS MODULE IS NOT. The TypeScript SDK's file also carries a signed tool MANIFEST
layer (``createToolManifest``, ``verifyToolManifest``, ``reviseToolManifest``,
``reapproveToolManifest``) and a namespace-claim layer (``createNamespaceClaim``,
``verifyNamespaceClaim``), with publisher identity, ``did:web`` trust-root resolution and
metadata-change re-approval. None of that is ported here. Those are a larger job with their
own resolution behaviour, and a partial port would be behavioural drift, which
``AGENTS.md`` calls a bug rather than a feature. The Python SDK therefore has no manifest
layer and a caller needing one should say so rather than assume parity.

SPECIFICATION POSITION. draft-pidlisnyi-aps-03 defines no tool registry entry and no
tool-integrity check. This layer is EXPERIMENTAL in both SDKs. It is ported now because the
proposed capability-binding module needs an attested implementation digest to compare a pin
against, and inventing a second, Python-only attestation shape for that would be the drift
this repository exists to avoid.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from .canonical import canonicalize, canonicalize_for_write
from .crypto import sign, verify

__all__ = [
    "ToolRegistryEntry",
    "ToolRequirements",
    "AgentCapabilities",
    "ToolIntegrityResult",
    "create_tool_registry_entry",
    "verify_tool_integrity",
]


@dataclass(frozen=True)
class ToolRegistryEntry:
    """Registry entry for a verified tool.

    Field names are the TypeScript SDK's camelCase names verbatim, because these names are
    signed: the attestor signature is taken over the canonical JSON of
    ``{toolName, implementationHash, attestorId, verifiedAt}``, and renaming any of them to
    snake_case would produce different bytes and a signature neither SDK could check.
    Python callers construct and read the dataclass with those attribute names.
    """

    #: Tool name. Matches the name in delegation scope.
    toolName: str
    #: ``sha256:`` over the implementation bytes: source, binary or endpoint descriptor.
    implementationHash: str
    #: Who attested this tool's integrity, as a runtime, registry or auditor DID.
    attestorId: str
    #: When the tool hash was last verified, RFC 3339.
    verifiedAt: str
    #: Ed25519 signature over the canonical body, that is the four fields above.
    signature: str

    def signed_body(self) -> dict[str, str]:
        """The four signed members, in the shape the signature is taken over."""
        return {
            "toolName": self.toolName,
            "implementationHash": self.implementationHash,
            "attestorId": self.attestorId,
            "verifiedAt": self.verifiedAt,
        }


@dataclass(frozen=True)
class ToolRequirements:
    """Per-invocation trust requirements a tool declares."""

    min_grade: int | None = None
    required_scopes: tuple[str, ...] | None = None
    min_trust_score: float | None = None
    requires_wallet: bool = False


@dataclass(frozen=True)
class AgentCapabilities:
    """What the agent presenting the invocation currently has."""

    grade: int
    scopes: tuple[str, ...]
    trust_score: float
    has_wallet: bool


@dataclass(frozen=True)
class ToolIntegrityResult:
    """Result of the integrity check and, when asked for, the requirements check."""

    valid: bool
    implementation_verified: bool
    attestor_signature_valid: bool
    requirements_met: bool
    failed_requirements: tuple[str, ...] = ()
    errors: tuple[str, ...] = field(default=())


def _sha256_prefixed(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def create_tool_registry_entry(
    *,
    tool_name: str,
    implementation: str | bytes,
    attestor_id: str,
    attestor_private_key: str,
    verified_at: str | None = None,
) -> ToolRegistryEntry:
    """Register a tool: the attestor signs that this implementation is known and approved.

    ``verified_at`` is an optional override for deterministic conformance fixtures, the
    same override the TypeScript SDK takes. Omit it and the stamp comes from the system
    clock. Supply it and the function is reproducible, so calling it twice with the same
    inputs gives the same bytes and the same signature.
    """
    stamped = (
        verified_at
        if verified_at is not None
        else datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    body = {
        "toolName": tool_name,
        "implementationHash": _sha256_prefixed(implementation),
        "attestorId": attestor_id,
        "verifiedAt": stamped,
    }
    signature = sign(canonicalize_for_write(body), attestor_private_key)
    return ToolRegistryEntry(
        toolName=body["toolName"],
        implementationHash=body["implementationHash"],
        attestorId=body["attestorId"],
        verifiedAt=body["verifiedAt"],
        signature=signature,
    )


def verify_tool_integrity(
    *,
    registry_entry: ToolRegistryEntry,
    current_implementation: str | bytes,
    attestor_public_key: str,
    requirements: ToolRequirements | None = None,
    agent_capabilities: AgentCapabilities | None = None,
) -> ToolIntegrityResult:
    """Is this the same tool that was approved, and does the agent meet what it declares?

    The two questions are answered separately and both are reported. A signature that
    verifies says the attestor made the claim; it does not say the claim is still true of
    the implementation reachable now, which is what ``implementation_verified`` is for.
    """
    errors: list[str] = []
    failed_requirements: list[str] = []

    attestor_signature_valid = verify(
        canonicalize(registry_entry.signed_body()),
        registry_entry.signature,
        attestor_public_key,
    )
    if not attestor_signature_valid:
        errors.append("Tool attestor signature invalid")

    current_hash = _sha256_prefixed(current_implementation)
    implementation_verified = current_hash == registry_entry.implementationHash
    if not implementation_verified:
        errors.append(
            "Tool implementation hash mismatch: expected "
            f"{registry_entry.implementationHash}, got {current_hash}"
        )

    requirements_met = True
    if requirements is not None and agent_capabilities is not None:
        reqs, caps = requirements, agent_capabilities
        if reqs.min_grade is not None and caps.grade < reqs.min_grade:
            failed_requirements.append(f"Grade {caps.grade} < required {reqs.min_grade}")
            requirements_met = False
        if reqs.min_trust_score is not None and caps.trust_score < reqs.min_trust_score:
            failed_requirements.append(
                f"Trust score {caps.trust_score} < required {reqs.min_trust_score}"
            )
            requirements_met = False
        if reqs.required_scopes:
            missing: Sequence[str] = [s for s in reqs.required_scopes if s not in caps.scopes]
            if missing:
                failed_requirements.append(f"Missing scopes: {', '.join(missing)}")
                requirements_met = False
        if reqs.requires_wallet and not caps.has_wallet:
            failed_requirements.append("Tool requires wallet but agent has none")
            requirements_met = False

    if not requirements_met:
        errors.append(
            "Agent does not meet tool requirements: " + "; ".join(failed_requirements)
        )

    return ToolIntegrityResult(
        valid=len(errors) == 0,
        implementation_verified=implementation_verified,
        attestor_signature_valid=attestor_signature_valid,
        requirements_met=requirements_met,
        failed_requirements=tuple(failed_requirements),
        errors=tuple(errors),
    )
