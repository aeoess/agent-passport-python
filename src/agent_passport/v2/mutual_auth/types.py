# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Mutual Authentication v1 — types (TypedDict shapes).

Mirrors src/v2/mutual-auth/types.ts. Field names match the TypeScript
version exactly for wire compatibility.
"""

from typing import TypedDict, List, Optional, Literal


MutualAuthRole = Literal["agent", "information_system"]
MutualAuthIssuerRole = Literal["agent", "information_system", "trust_anchor"]

MutualAuthFailureReason = Literal[
    "expired_certificate",
    "not_yet_valid_certificate",
    "unknown_issuer",
    "revoked_anchor",
    "signature_invalid",
    "binding_mismatch",
    "downgrade_detected",
    "nonce_mismatch",
    "version_unsupported",
    "expired_session",
    "replay_detected",
    "grade_insufficient",
]


class MutualAuthCertificate(TypedDict, total=False):
    spec_version: str  # "1.0"
    role: MutualAuthRole
    subject_id: str
    issuer_id: str
    issuer_role: MutualAuthIssuerRole
    issuer_pubkey_hex: str
    subject_pubkey_hex: str
    not_before: int
    not_after: int
    binding: str
    attestation_grade: Optional[int]
    supported_versions: List[str]
    capabilities: Optional[List[str]]
    signature_b64: str


class TrustAnchor(TypedDict, total=False):
    anchor_id: str
    display_name: str
    role: MutualAuthIssuerRole
    pubkey_hex: str
    not_before: int
    not_after: int
    binding_constraints: Optional[List[str]]


class TrustAnchorBundle(TypedDict, total=False):
    spec_version: str  # "1.0"
    bundle_id: str
    issued_at: int
    anchors: List[TrustAnchor]
    refresh_after: int
    revoked_anchors: Optional[List[str]]
    signature_b64: str
    publisher_pubkey_hex: str


class MutualAuthHello(TypedDict):
    spec_version: str
    role: MutualAuthRole
    supported_versions: List[str]
    nonce_b64: str
    timestamp: int


class MutualAuthAttest(TypedDict):
    spec_version: str
    role: MutualAuthRole
    chosen_version: str
    own_nonce_b64: str
    peer_nonce_b64: str
    certificate: MutualAuthCertificate
    signature_b64: str
    timestamp: int


class MutualAuthSession(TypedDict):
    spec_version: str
    session_id: str
    agent_cert: MutualAuthCertificate
    is_cert: MutualAuthCertificate
    chosen_version: str
    agent_nonce_b64: str
    is_nonce_b64: str
    established_at: int
    expires_at: int


class MutualAuthResult(TypedDict, total=False):
    ok: bool
    session: Optional[MutualAuthSession]
    failure: Optional[dict]  # {"reason": str, "detail": Optional[str]}


class MutualAuthPolicy(TypedDict, total=False):
    accepted_versions: List[str]
    min_agent_grade: Optional[int]
    required_capabilities: Optional[List[str]]
    max_clock_skew_ms: Optional[int]
    max_session_ms: Optional[int]
