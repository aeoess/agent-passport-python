# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Mutual Authentication v1 — Python port.

Mirrors src/v2/mutual-auth/ in the TypeScript SDK. Closes the asymmetry
where agents authenticate to systems but systems do not authenticate to
agents. Ships as a standalone primitive with no federation dependency.

Cross-language signature interop: Python signatures over these envelopes
verify against TypeScript, and vice versa, because both sides use
canonicalize_jcs() (RFC 8785) over identical field layouts.
"""

from .types import (
    MutualAuthRole,
    MutualAuthCertificate,
    TrustAnchor,
    TrustAnchorBundle,
    MutualAuthHello,
    MutualAuthAttest,
    MutualAuthSession,
    MutualAuthResult,
    MutualAuthPolicy,
    MutualAuthFailureReason,
)

from .certificate import (
    build_certificate,
    sign_certificate,
    certificate_id,
    verify_certificate_signature,
    is_certificate_temporally_valid,
    check_anchor,
)

from .trust_bundle import (
    build_bundle,
    sign_bundle,
    verify_bundle,
)

from .handshake import (
    new_nonce,
    build_hello,
    choose_version,
    build_attest,
    verify_attest,
    derive_session,
    is_session_active,
)

__all__ = [
    # types
    "MutualAuthRole",
    "MutualAuthCertificate",
    "TrustAnchor",
    "TrustAnchorBundle",
    "MutualAuthHello",
    "MutualAuthAttest",
    "MutualAuthSession",
    "MutualAuthResult",
    "MutualAuthPolicy",
    "MutualAuthFailureReason",
    # certificate
    "build_certificate",
    "sign_certificate",
    "certificate_id",
    "verify_certificate_signature",
    "is_certificate_temporally_valid",
    "check_anchor",
    # trust bundle
    "build_bundle",
    "sign_bundle",
    "verify_bundle",
    # handshake
    "new_nonce",
    "build_hello",
    "choose_version",
    "build_attest",
    "verify_attest",
    "derive_session",
    "is_session_active",
]
