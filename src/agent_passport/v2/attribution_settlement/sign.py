# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Signing / signature verification — Python port of
src/v2/attribution-settlement/sign.ts.

Ed25519 over canonicalize(record minus signature). Byte-identical
payload to the TS SDK so TS-signed records verify in Python.
"""

import hashlib

from ...canonical import canonicalize, canonicalize_for_write
from ...crypto import sign as ed25519_sign, verify as ed25519_verify


def _settlement_signing_payload_impl(record: dict, _canon) -> str:
    """Shared body so the read and write twins can never drift apart."""
    body = dict(record)
    body.pop("signature", None)
    return _canon(body)


def settlement_signing_payload(record: dict) -> str:
    """Canonical byte string signed (or verified). Strips the
    ``signature`` field if present."""
    return _settlement_signing_payload_impl(record, canonicalize)


def settlement_signing_payload_for_write(record: dict) -> str:
    """Write-boundary twin of :func:`settlement_signing_payload`.

    Emits the same bytes as :func:`settlement_signing_payload` for every value it accepts. The only
    difference is that an integer-valued number outside the interoperable IEEE 754
    range is refused instead of serialized. Use at signing and new-write boundaries
    only: :func:`settlement_signing_payload` stays unrestricted so an artifact signed before this rule
    existed keeps verifying.
    """
    return _settlement_signing_payload_impl(record, canonicalize_for_write)


def settlement_record_hash(record: dict) -> str:
    return hashlib.sha256(settlement_signing_payload(record).encode("utf-8")).hexdigest()


def sign_settlement_record(record: dict, gateway_private_key_hex: str) -> str:
    if not isinstance(gateway_private_key_hex, str) or not gateway_private_key_hex:
        raise ValueError("attribution-settlement: gateway_private_key_hex required")
    return ed25519_sign(settlement_signing_payload_for_write(record), gateway_private_key_hex)


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
