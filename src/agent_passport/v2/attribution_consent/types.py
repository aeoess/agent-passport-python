# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Type aliases and TypedDicts mirroring the TS attribution-consent module.

Wire format is plain dict — keys match TS exactly so canonicalize() output
is byte-identical across languages.
"""

from typing import TypedDict, Optional, List

# String aliases (match TS DID/signature aliases).
AgentDID = str
PrincipalDID = str
ContextID = str
Ed25519Signature = str


class HybridTimestamp(TypedDict):
    logicalTime: int
    wallClockEarliest: int
    wallClockLatest: int
    gatewayId: str


class ArtifactCitation(TypedDict):
    receipt_id: str
    cited_principal: PrincipalDID
    citation_content: str


class CitingArtifact(TypedDict, total=False):
    citations: List[ArtifactCitation]


class AttributionReceipt(TypedDict, total=False):
    id: str
    version: str  # always "1.0"
    citer: AgentDID
    citer_public_key: str
    cited_principal: PrincipalDID
    cited_principal_public_key: str
    citation_content: str
    binding_context: ContextID
    created_at: HybridTimestamp
    expires_at: HybridTimestamp
    citer_signature: Ed25519Signature
    cited_principal_signature: Ed25519Signature  # optional


class AttributionConsentResult(TypedDict, total=False):
    valid: bool
    reason: str
