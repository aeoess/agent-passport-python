# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Attribution Consent — citation requires the cited principal's sign-off.

Mirrors src/v2/attribution-consent in the TypeScript SDK. Same canonical
core, same sha256 id, same Ed25519 signature semantics.
"""

from .types import (
    AttributionReceipt,
    AttributionConsentResult,
    ArtifactCitation,
    CitingArtifact,
)
from .create import create_attribution_receipt, receipt_core
from .sign import sign_attribution_consent
from .verify import verify_attribution_consent, check_artifact_citations

__all__ = [
    "AttributionReceipt",
    "AttributionConsentResult",
    "ArtifactCitation",
    "CitingArtifact",
    "create_attribution_receipt",
    "receipt_core",
    "sign_attribution_consent",
    "verify_attribution_consent",
    "check_artifact_citations",
]
