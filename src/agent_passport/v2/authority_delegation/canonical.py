# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Content addressing and Ed25519 signing for the authority-delegation record.

Python port of the TypeScript SDK's src/v2/authority-delegation/canonical.ts.

The id and signature inputs are the domain bytes followed by the UTF-8 bytes
of RFC 8785 JCS, matching ``agent_passport.canonical.canonicalize_jcs`` (the
verification path, used by TypeScript's ``canonicalizeJCS``) and
``canonicalize_jcs_for_write`` (the issuing path, used by TypeScript's
``canonicalizeJCSForWrite``).
"""

from __future__ import annotations

import hashlib
import re

from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

from ...canonical import canonicalize_jcs, canonicalize_jcs_for_write

AUTHORITY_DELEGATION_ID_DOMAIN = b"APS-AUTHORITY-DELEGATION-ID-V1\x00"
AUTHORITY_DELEGATION_SIGNATURE_DOMAIN = b"APS-AUTHORITY-DELEGATION-SIGNATURE-V1\x00"

_HEX_CHARS = re.compile(r"[0-9a-fA-F]+")


def _is_hex_of_length(value, length: int) -> bool:
    """True only for a str of exactly ``length`` hexadecimal characters.

    ``bytes.fromhex`` is deliberately not relied on for this check: it
    tolerates ASCII whitespace between byte pairs (so "ab cd" decodes the
    same as "abcd"), which would let a public key or signature written with
    spaces verify here even though it is not the fixed-width hex string the
    wire format requires.
    """
    return type(value) is str and len(value) == length and bool(_HEX_CHARS.fullmatch(value))


def authority_delegation_id_input(body: dict) -> bytes:
    """Exact RFC 8785 input used to derive delegation_id."""
    return AUTHORITY_DELEGATION_ID_DOMAIN + canonicalize_jcs(body).encode("utf-8")


def authority_delegation_id_input_for_write(body: dict) -> bytes:
    """Write-boundary twin of authority_delegation_id_input().

    Emits the same bytes as authority_delegation_id_input() for every value it
    accepts. The only difference is that an integer-valued number outside the
    interoperable IEEE 754 range is refused instead of serialized. Use at
    signing and new-write boundaries ONLY: authority_delegation_id_input()
    stays unrestricted so an artifact signed before this rule keeps verifying.
    """
    return AUTHORITY_DELEGATION_ID_DOMAIN + canonicalize_jcs_for_write(body).encode("utf-8")


def compute_authority_delegation_id(body: dict) -> str:
    return "sha256:" + hashlib.sha256(authority_delegation_id_input(body)).hexdigest()


def compute_authority_delegation_id_for_write(body: dict) -> str:
    """Write-boundary twin of compute_authority_delegation_id().

    Reaches a canonicalizer only indirectly, through
    authority_delegation_id_input_for_write(). Use when ISSUING a delegation;
    verify.py and the budget ledger keep calling the unrestricted form so a
    delegation issued before this rule still re-derives its id.
    """
    return "sha256:" + hashlib.sha256(authority_delegation_id_input_for_write(body)).hexdigest()


def authority_delegation_signature_input(delegation: dict) -> bytes:
    """Exact Ed25519 input: domain plus JCS(record without signature)."""
    return AUTHORITY_DELEGATION_SIGNATURE_DOMAIN + canonicalize_jcs(delegation).encode("utf-8")


def _authority_delegation_signature_input_for_write(delegation: dict) -> bytes:
    """Write-boundary twin of authority_delegation_signature_input().

    sign_authority_delegation() mints a signature over this string while
    verify_authority_delegation_signature() rebuilds the identical string
    (through the unrestricted twin above) to check an existing one, so the
    write rule only ever applies on the signing side.
    """
    return AUTHORITY_DELEGATION_SIGNATURE_DOMAIN + canonicalize_jcs_for_write(delegation).encode("utf-8")


def sign_authority_delegation(delegation: dict, private_key: str) -> str:
    signing_key = SigningKey(bytes.fromhex(private_key))
    material = _authority_delegation_signature_input_for_write(delegation)
    return signing_key.sign(material).signature.hex()


def verify_authority_delegation_signature(delegation: dict, public_key: str) -> bool:
    """True if ``signature`` verifies over the rest of ``delegation`` under ``public_key``.

    Any problem with ``public_key`` or ``signature`` (wrong type, wrong
    length, not hexadecimal, or a genuinely bad signature) is reported as
    ``False`` rather than raised, matching the TypeScript SDK's ``verify``,
    which never throws. ``public_key`` and ``signature`` are each checked
    against a fixed-width hex pattern before being decoded, rather than
    handed straight to ``bytes.fromhex``, precisely so that a value ``bytes.
    fromhex`` would otherwise tolerate (whitespace between byte pairs, an odd
    number of nibbles padded some other way) cannot verify here.
    """
    if not _is_hex_of_length(public_key, 64):
        return False
    signature = delegation.get("signature")
    if not _is_hex_of_length(signature, 128):
        return False
    unsigned = {key: value for key, value in delegation.items() if key != "signature"}
    material = authority_delegation_signature_input(unsigned)
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key))
        verify_key.verify(material, bytes.fromhex(signature))
        return True
    except (CryptoError, ValueError, TypeError, KeyError):
        return False


def authority_delegation_body(delegation: dict) -> dict:
    return {key: value for key, value in delegation.items() if key not in ("delegation_id", "signature")}
