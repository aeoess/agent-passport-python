# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Wave 1 accountability — public surface.

Mirrors src/v2/accountability/index.ts in agent-passport-system 2.6.0-alpha.0.

Five primitives: ActionReceipt, AuthorityBoundaryReceipt, CustodyReceipt,
ContestabilityReceipt, APSBundle. Cross-impl byte-parity with the TS SDK
verified against TS-supplied fixtures in tests/v2/wave1/.

This module replaces the minimal ContestabilityReceipt that shipped in
v2/downstream_taint.py at 2.4.0a0. The downstream-taint cascade now
imports its receipt and response shapes from here directly; the cascade
contract is unchanged.
"""

from .types import (
    # base
    CaptureMode,
    Completeness,
    ScopeOfClaim,
    # action
    ActionPayload,
    ActionReceipt,
    SideEffectClass,
    TransparencyLogInclusion,
    # authority-boundary
    AuthorityBoundaryReceipt,
    BoundaryResult,
    # custody
    CustodyEventType,
    CustodyPurpose,
    CustodyReceipt,
    SubjectReceiptBatch,
    # contestability
    ContestabilityContestant,
    ContestabilityControllerResponse,
    ContestabilityReceipt,
    ContestStatus,
    GroundsClass,
    GroundsClassValue,
    RequestedRemedy,
    StandingBasis,
    # bundle
    APSBundle,
    BundledReceiptRef,
)

from .construct import (
    attach_controller_response,
    create_action_receipt,
    create_authority_boundary_receipt,
    create_contestability_receipt,
    create_custody_receipt,
)

from .bundle import (
    compute_merkle_root,
    create_aps_bundle,
    verify_aps_bundle,
)

from .verify import (
    verify_action_receipt,
    verify_authority_boundary_receipt,
    verify_contestability_receipt,
    verify_custody_receipt,
)

__all__ = [
    # types
    "APSBundle",
    "ActionPayload",
    "ActionReceipt",
    "AuthorityBoundaryReceipt",
    "BoundaryResult",
    "BundledReceiptRef",
    "CaptureMode",
    "Completeness",
    "ContestStatus",
    "ContestabilityContestant",
    "ContestabilityControllerResponse",
    "ContestabilityReceipt",
    "CustodyEventType",
    "CustodyPurpose",
    "CustodyReceipt",
    "GroundsClass",
    "GroundsClassValue",
    "RequestedRemedy",
    "ScopeOfClaim",
    "SideEffectClass",
    "StandingBasis",
    "SubjectReceiptBatch",
    "TransparencyLogInclusion",
    # construct
    "attach_controller_response",
    "create_action_receipt",
    "create_aps_bundle",
    "create_authority_boundary_receipt",
    "create_contestability_receipt",
    "create_custody_receipt",
    # bundle helpers
    "compute_merkle_root",
    # verify
    "verify_action_receipt",
    "verify_aps_bundle",
    "verify_authority_boundary_receipt",
    "verify_contestability_receipt",
    "verify_custody_receipt",
]
