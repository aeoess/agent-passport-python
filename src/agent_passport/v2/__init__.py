# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS v2 — boundary primitives ported from the TypeScript SDK.

Cross-language signature compatibility: any signed artifact produced by
the TS SDK (canonical JSON + Ed25519) verifies in Python and vice versa.
"""

# Evidentiary Type Safety primitives (Modules 1, 2, 4).
# Mirrors agent-passport-system 2.6.0-alpha.0.
from .claim_evidence_types import (
    ClaimType,
    RecordType,
    EvidenceProfile,
    EvidenceProfiles,
    required_evidence_for,
)
from .claim_verifier import (
    ClaimVerificationInput,
    ClaimVerificationResult,
    ClaimVerificationStatus,
    EvidenceEntry,
    OpenContestationLookup,
    OpenContestationResolver,
    verify_evidence_claim,
)
from .downstream_taint import (
    ContestStatus,
    ContestabilityControllerResponse,
    ContestabilityReceipt,
    GroundsClass,
    TaintCandidate,
    TaintedRecord,
    TaintedSet,
    compute_downstream_taint,
    is_contestation_tainting,
)
