# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Content addressing and Ed25519 signing for the two records this
module declares.

Python port of the TypeScript SDK's src/v2/bounds/canonical.ts. Nothing here reimplements
JCS, SHA-256 or Ed25519: each comes from the helper the rest of this package already uses,
``agent_passport.canonical.canonicalize_jcs`` (the verification path, TypeScript's
``canonicalizeJCS``) and ``canonicalize_jcs_for_write`` (the issuing path, TypeScript's
``canonicalizeJCSForWrite``).

Not required by draft-pidlisnyi-aps-03. See ``types.py`` for the specification position.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ...canonical import canonicalize_jcs, canonicalize_jcs_for_write
from ...crypto import sign, verify

# Domain tags. Each is a distinct tag followed by one zero byte, the same discipline
# AuthorityDelegationV1 and AuthorityRevocationV1 follow, so bytes minted for one
# construction can never be read as bytes minted for another. The PROPOSED- prefix is part
# of the tag: if any of this is ever specified, the specified construction will use a
# different tag and records minted under this one will not verify under it. That is the
# intended behaviour, not a migration problem to solve later.
AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN = (
    "PROPOSED-APS-AUTHORITY-BOUND-FULFILMENT-SIGNATURE-V0\x00"
)
AUTHORITY_EXHAUSTION_ID_DOMAIN = "PROPOSED-APS-AUTHORITY-EXHAUSTION-ID-V0\x00"
AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN = "PROPOSED-APS-AUTHORITY-EXHAUSTION-SIGNATURE-V0\x00"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _without(record: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k not in keys}


def authority_bound_fulfilment_signature_input(body: dict[str, Any]) -> str:
    """Exact Ed25519 preimage: the domain tag plus RFC 8785 JCS of the record with
    ``signature`` absent."""
    return AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN + canonicalize_jcs(body)


def authority_bound_fulfilment_signature_input_for_write(body: dict[str, Any]) -> str:
    """Write-boundary twin. Use when ISSUING. The verification path keeps calling the
    unrestricted form, so a record minted before the write rule still verifies."""
    return AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN + canonicalize_jcs_for_write(body)


def sign_authority_bound_fulfilment(body: dict[str, Any], private_key_hex: str) -> str:
    return sign(
        authority_bound_fulfilment_signature_input_for_write(body), private_key_hex
    )


def verify_authority_bound_fulfilment_signature(record: dict[str, Any], public_key_hex: str) -> bool:
    return verify(
        authority_bound_fulfilment_signature_input(_without(record, "signature")),
        record.get("signature", ""),
        public_key_hex,
    )


def authority_exhaustion_id_input(body: dict[str, Any]) -> str:
    """Exact preimage for ``exhaustion_id``: the ID domain tag plus JCS of the body."""
    return AUTHORITY_EXHAUSTION_ID_DOMAIN + canonicalize_jcs(body)


def compute_authority_exhaustion_id(body: dict[str, Any]) -> str:
    return "sha256:" + _sha256_hex(authority_exhaustion_id_input(body))


def compute_authority_exhaustion_id_for_write(body: dict[str, Any]) -> str:
    return "sha256:" + _sha256_hex(
        AUTHORITY_EXHAUSTION_ID_DOMAIN + canonicalize_jcs_for_write(body)
    )


def authority_exhaustion_signature_input(record: dict[str, Any]) -> str:
    """Exact Ed25519 preimage for the exhaustion record: the signature domain tag plus JCS
    of the record with ``signature`` absent. ``exhaustion_id`` IS inside this preimage, so
    the identifier is signed rather than being an unauthenticated label beside the
    signature."""
    return AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN + canonicalize_jcs(record)


def authority_exhaustion_signature_input_for_write(record: dict[str, Any]) -> str:
    return AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN + canonicalize_jcs_for_write(record)


def sign_authority_exhaustion(record: dict[str, Any], private_key_hex: str) -> str:
    return sign(authority_exhaustion_signature_input_for_write(record), private_key_hex)


def verify_authority_exhaustion_signature(record: dict[str, Any], public_key_hex: str) -> bool:
    return verify(
        authority_exhaustion_signature_input(_without(record, "signature")),
        record.get("signature", ""),
        public_key_hex,
    )
