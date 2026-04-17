# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Signing / signature verification — Python port of
src/v2/attribution-settlement/sign.ts.

Ed25519 over canonicalize(record minus signature). Byte-identical
payload to the TS SDK so TS-signed records verify in Python.
"""

import hashlib

from ...canonical import canonicalize
from ...crypto import sign as ed25519_sign, verify as ed25519_verify


def settlement_signing_payload(record: dict) -> str:
    """Canonical byte string signed (or verified). Strips the
    ``signature`` field if present."""
    body = dict(record)
    body.pop("signature", None)
    return canonicalize(body)


def settlement_record_hash(record: dict) -> str:
    return hashlib.sha256(settlement_signing_payload(record).encode("utf-8")).hexdigest()


def sign_settlement_record(record: dict, gateway_private_key_hex: str) -> str:
    if not isinstance(gateway_private_key_hex, str) or not gateway_private_key_hex:
        raise ValueError("attribution-settlement: gateway_private_key_hex required")
    return ed25519_sign(settlement_signing_payload(record), gateway_private_key_hex)


def verify_settlement_signature(record: dict, gateway_public_key_hex: str) -> bool:
    if not gateway_public_key_hex:
        return False
    sig = record.get("signature")
    if not isinstance(sig, str) or not sig:
        return False
    try:
        body = dict(record)
        body.pop("signature", None)
        return ed25519_verify(
            settlement_signing_payload(body),
            sig,
            gateway_public_key_hex,
        )
    except Exception:
        return False
