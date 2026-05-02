# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Claim Verifier (Module 2 of the Evidentiary Type Safety set).

Mirrors src/v2/claim-verifier.ts in the TypeScript SDK at
agent-passport-system 2.6.0-alpha.0.

verify_evidence_claim is a pure function. It checks an evidence
bundle against the EvidenceProfile for a stated claim and returns
a tagged-union result. No I/O, no signing, no key resolution, no
clock reads, no network, no mutation.

What this module DOES check:
  - claim.type is a known ClaimType present in the registry
  - the registry entry for claim.type is populated (not a stub)
  - APSBundle records are not silently substituted for leaf
    evidence (a bundle is a Merkle commitment over receipt_ids;
    satisfying a leaf claim from it requires an inclusion proof,
    which is out of scope here)
  - no forbidden substitution is being attempted (e.g. ActionReceipt
    for BINDING_COMMITMENT)
  - every required RecordType is present in the evidence list
  - if open_contestation_resolver is provided, no staged record
    is under a blocking contestation (filed / under_review /
    upheld / remedied)

What this module does NOT check:
  - signatures, receipt_id integrity, JCS canonicality
  - timestamp freshness, expiry, key rotation, revocation
  - delegation/authority chains
  - cross-receipt referential integrity (e.g. that an
    AuthorityBoundaryReceipt.action_id matches an ActionReceipt
    whose receipt_id appears in a sibling record)

Those checks belong to the gateway TypeInterceptor (private repo).

DESIGN NOTE — discriminated union representation:

TypeScript's ClaimVerificationResult is a string-literal-discriminated
union. Python options ranked at port time:
  1. TaggedUnion: a single dataclass with `status: Literal[...]` and
     optional fields per variant. None-valued fields drop out of the
     canonical JSON serialization, matching TS's per-variant shapes.
  2. Per-variant dataclass + Union typing. More Pythonic, more
     boilerplate. Doesn't match TS's collapsed JSON shape without
     custom serialization.
  3. Pydantic models. Strongest validation, adds a dependency the
     rest of this Python SDK does not carry.

Pre-decided in the port spec: option 1. Documented here for future
maintainers. Python attribute names are snake_case per PEP 8; the
to_canonical_dict() method emits camelCase JSON keys for cross-impl
byte-parity with TypeScript. The canonical-hash path goes through
to_canonical_dict, not the dataclass attributes directly.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, List, Literal, Optional, Union

from .claim_evidence_types import (
    ClaimType,
    EvidenceProfiles,
    RecordType,
)
from .downstream_taint import ContestStatus

# APSBundle is referenced in the bundle_requires_inclusion_proof variant.
# Wave 1 accountability defers the full Python port; the verifier passes
# through whatever record the caller put in the evidence entry, no
# introspection. When Wave 1 ports, replace this with a real type import.
APSBundle = Any


# Statuses where the contestation is open or resolved against the record.
# A record under one of these statuses cannot be relied on to satisfy a
# claim. Mirrors TS's BLOCKING_CONTEST_STATUSES.
BLOCKING_CONTEST_STATUSES: tuple[ContestStatus, ...] = (
    "filed",
    "under_review",
    "upheld",
    "remedied",
)


@dataclass
class OpenContestationLookup:
    """Resolver result shape: which contestation, what status."""

    contestation_id: str
    status: ContestStatus


# A resolver maps a record_id to a contestation lookup, or None if no
# contestation exists for that record. Mirrors TS's
# OpenContestationResolver type alias.
OpenContestationResolver = Callable[[str], Optional[OpenContestationLookup]]


@dataclass
class EvidenceEntry:
    """One staged record in the evidence list."""

    record_type: RecordType
    record: Any
    receipt_id: Optional[str] = None


@dataclass
class ClaimVerificationInput:
    """Input to verify_evidence_claim."""

    claim_type: ClaimType
    subject: str
    evidence: List[EvidenceEntry] = field(default_factory=list)
    # Optional Module 4 hook. When provided, every evidence entry that
    # carries a receipt_id is checked against the resolver after the
    # static registry passes but before the verifier returns 'valid'.
    open_contestation_resolver: Optional[OpenContestationResolver] = None


# Status discriminator literal. Keep these strings byte-identical to TS.
ClaimVerificationStatus = Literal[
    "valid",
    "missing_evidence",
    "forbidden_substitution",
    "unsupported_claim_type",
    "profile_not_populated",
    "bundle_requires_inclusion_proof",
    "contested",
]


@dataclass
class ClaimVerificationResult:
    """Tagged-union result of verify_evidence_claim.

    The `status` field is the discriminator. Per-variant fields are
    Optional and only populated when the discriminator selects them.
    Python attribute names are snake_case per PEP 8; the
    to_canonical_dict() method emits camelCase JSON keys for cross-impl
    byte-parity with the TypeScript SDK. None-valued fields drop from
    the canonical-dict output so each variant's JSON shape matches
    TS exactly.
    """

    status: ClaimVerificationStatus
    claim_type: ClaimType
    # 'valid' fields
    satisfied_by: Optional[List[RecordType]] = None
    # 'missing_evidence' fields
    missing: Optional[List[RecordType]] = None
    provided: Optional[List[RecordType]] = None
    # 'forbidden_substitution' fields
    offending_record: Optional[RecordType] = None
    reason: Optional[str] = None
    # 'bundle_requires_inclusion_proof' fields
    bundle_record: Optional[APSBundle] = None
    # 'contested' fields
    contested_record_id: Optional[str] = None
    contestation_id: Optional[str] = None
    contestation_status: Optional[ContestStatus] = None

    def to_canonical_dict(self) -> dict:
        """Emit camelCase JSON dict for cross-impl byte-parity with TS.

        The canonical hash path uses this output, not the dataclass
        attributes. None-valued fields drop. Enums collapse to their
        string values. Lists of enums collapse element-wise.
        """
        out: dict = {
            "status": self.status,
            "claimType": _enum_value(self.claim_type),
        }
        if self.satisfied_by is not None:
            out["satisfiedBy"] = [_enum_value(r) for r in self.satisfied_by]
        if self.missing is not None:
            out["missing"] = [_enum_value(r) for r in self.missing]
        if self.provided is not None:
            out["provided"] = [_enum_value(r) for r in self.provided]
        if self.offending_record is not None:
            out["offendingRecord"] = _enum_value(self.offending_record)
        if self.reason is not None:
            out["reason"] = self.reason
        if self.bundle_record is not None:
            out["bundleRecord"] = self.bundle_record
        if self.contested_record_id is not None:
            out["contestedRecordId"] = self.contested_record_id
        if self.contestation_id is not None:
            out["contestationId"] = self.contestation_id
        if self.contestation_status is not None:
            out["contestationStatus"] = self.contestation_status
        return out


def _enum_value(v: Union[ClaimType, RecordType, str]) -> str:
    """Collapse an enum to its string value; pass through plain strings."""
    if hasattr(v, "value"):
        return v.value
    return v


def verify_evidence_claim(input: ClaimVerificationInput) -> ClaimVerificationResult:
    """Verify a stated claim against staged evidence.

    Pure function. No I/O. Mirrors TS verifyEvidenceClaim exactly:
    same precedence, same string discriminator values, same per-variant
    fields. Cross-impl byte-parity is verified via fixture tests.
    """
    claim_type = input.claim_type
    evidence = input.evidence

    # 1. unsupported_claim_type — claim.type is not a registry key.
    profile = EvidenceProfiles.get(claim_type)
    if profile is None:
        return ClaimVerificationResult(
            status="unsupported_claim_type",
            claim_type=claim_type,
        )

    # 2. profile_not_populated — registry entry is a stub.
    has_required = len(profile.required) > 0
    has_forbidden = len(profile.forbidden_substitutions) > 0
    if not has_required and not has_forbidden:
        return ClaimVerificationResult(
            status="profile_not_populated",
            claim_type=claim_type,
        )

    # 3. bundle_requires_inclusion_proof — APSBundle slipped in for a
    #    non-batch claim.
    if claim_type != ClaimType.BATCH_ATTESTED:
        for entry in evidence:
            if entry.record_type == RecordType.APSBundle:
                return ClaimVerificationResult(
                    status="bundle_requires_inclusion_proof",
                    claim_type=claim_type,
                    bundle_record=entry.record,
                )

    # 4. forbidden_substitution — first match wins, in evidence order.
    for entry in evidence:
        reason = profile.forbidden_substitutions.get(entry.record_type)
        if reason is not None:
            return ClaimVerificationResult(
                status="forbidden_substitution",
                claim_type=claim_type,
                offending_record=entry.record_type,
                reason=reason,
            )

    # 5. missing_evidence — required types not present in evidence.
    provided_types = [e.record_type for e in evidence]
    provided_set = set(provided_types)
    missing = [r for r in profile.required if r not in provided_set]
    if missing:
        return ClaimVerificationResult(
            status="missing_evidence",
            claim_type=claim_type,
            missing=missing,
            provided=provided_types,
        )

    # 6. contested (Module 4) — only when caller wires a resolver and an
    #    evidence entry carries a receipt_id. First blocking match wins.
    if input.open_contestation_resolver is not None:
        for entry in evidence:
            if entry.receipt_id is None:
                continue
            lookup = input.open_contestation_resolver(entry.receipt_id)
            if lookup is not None and lookup.status in BLOCKING_CONTEST_STATUSES:
                return ClaimVerificationResult(
                    status="contested",
                    claim_type=claim_type,
                    contested_record_id=entry.receipt_id,
                    contestation_id=lookup.contestation_id,
                    contestation_status=lookup.status,
                )

    # 7. valid.
    return ClaimVerificationResult(
        status="valid",
        claim_type=claim_type,
        satisfied_by=list(profile.required),
    )
