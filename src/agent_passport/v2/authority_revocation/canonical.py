# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Content addressing and Ed25519 signing for the authority-revocation record.

Python port of the TypeScript SDK's src/v2/authority-revocation/canonical.ts.

The three preimages are the domain bytes followed by the UTF-8 bytes of RFC 8785
JCS, matching ``agent_passport.canonical.canonicalize_jcs`` (the verification
path, TypeScript's ``canonicalizeJCS``) and ``canonicalize_jcs_for_write`` (the
issuing path, TypeScript's ``canonicalizeJCSForWrite``). Nothing here
reimplements JCS, SHA-256 or Ed25519; each comes from the helper the rest of
this package already uses.
"""

from __future__ import annotations

import hashlib
import re

from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

from ...canonical import canonicalize_jcs, canonicalize_jcs_for_write

# Domain tags for the three preimages this record uses. Each is a distinct APS
# tag followed by one zero byte, the same discipline AuthorityDelegationV1
# follows, so bytes minted for one construction can never be read as bytes
# minted for another. The trailing NUL is part of the tag: dropping it, or
# changing one byte of the text, changes every identifier and signature this
# module produces.
AUTHORITY_REVOCATION_ID_DOMAIN = b"APS-AUTHORITY-REVOCATION-ID-V1\x00"
AUTHORITY_REVOCATION_SIGNATURE_DOMAIN = b"APS-AUTHORITY-REVOCATION-SIGNATURE-V1\x00"
AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN = (
    b"APS-AUTHORITY-REVOCATION-CASCADE-TRANSACTION-ID-V1\x00"
)

_HEX_CHARS = re.compile(r"[0-9a-fA-F]+")


def _is_hex_of_length(value, length: int) -> bool:
    """True only for a str of exactly ``length`` hexadecimal characters.

    ``bytes.fromhex`` is deliberately not relied on for this check: it tolerates
    ASCII whitespace between byte pairs (so "ab cd" decodes the same as "abcd"),
    which would let a public key or signature written with spaces verify here
    even though it is not the fixed-width hex string the wire format requires.
    Same rule as authority_delegation.canonical.
    """
    return type(value) is str and len(value) == length and bool(_HEX_CHARS.fullmatch(value))


def authority_revocation_cascade_transaction_input(origin: dict) -> bytes:
    """Exact RFC 8785 input used to derive cascade_transaction_id.

    ``origin`` is the revocation body with ``cascade_transaction_id`` absent,
    which is already a record without ``revocation_id`` and ``signature``.

    Draft section 3.5.1 says a cascade carries a transaction identity shared by
    every record it produces, and says nothing about how it is constructed. A
    content-bound derivation is chosen over a random value so that issuance
    stays byte-deterministic for fixed inputs and so a verifier can recompute
    the field instead of accepting whatever the issuer wrote there. Independent
    cascades do not collide because the origin's 16-byte ``nonce`` is inside
    this preimage.
    """
    return AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN + canonicalize_jcs(origin).encode("utf-8")


def _authority_revocation_cascade_transaction_input_for_write(origin: dict) -> bytes:
    """Write-boundary twin of authority_revocation_cascade_transaction_input()."""
    return AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN + canonicalize_jcs_for_write(origin).encode("utf-8")


def compute_authority_revocation_cascade_transaction_id(origin: dict) -> str:
    return "sha256:" + hashlib.sha256(authority_revocation_cascade_transaction_input(origin)).hexdigest()


def compute_authority_revocation_cascade_transaction_id_for_write(origin: dict) -> str:
    """Write-boundary twin of compute_authority_revocation_cascade_transaction_id()."""
    return "sha256:" + hashlib.sha256(
        _authority_revocation_cascade_transaction_input_for_write(origin)
    ).hexdigest()


def authority_revocation_id_input(body: dict) -> bytes:
    """Exact RFC 8785 input used to derive revocation_id.

    ``body`` is the record with ``revocation_id`` and ``signature`` absent;
    ``cascade_transaction_id`` IS inside it.
    """
    return AUTHORITY_REVOCATION_ID_DOMAIN + canonicalize_jcs(body).encode("utf-8")


def _authority_revocation_id_input_for_write(body: dict) -> bytes:
    """Write-boundary twin of authority_revocation_id_input()."""
    return AUTHORITY_REVOCATION_ID_DOMAIN + canonicalize_jcs_for_write(body).encode("utf-8")


def compute_authority_revocation_id(body: dict) -> str:
    return "sha256:" + hashlib.sha256(authority_revocation_id_input(body)).hexdigest()


def compute_authority_revocation_id_for_write(body: dict) -> str:
    """Write-boundary twin of compute_authority_revocation_id().

    Emits the same bytes as compute_authority_revocation_id() for every value it
    accepts; it only refuses an integer-valued number outside the interoperable
    IEEE 754 range rather than serializing it. Use when ISSUING. verify.py keeps
    calling the unrestricted form, so a record minted before this rule still
    re-derives its identifier.
    """
    return "sha256:" + hashlib.sha256(_authority_revocation_id_input_for_write(body)).hexdigest()


def authority_revocation_signature_input(revocation: dict) -> bytes:
    """Exact Ed25519 input: the signature domain tag plus JCS of the record with
    ``signature`` absent.

    ``revocation_id`` IS inside this preimage, so the identifier is signed
    rather than being an unauthenticated label beside the signature.
    """
    return AUTHORITY_REVOCATION_SIGNATURE_DOMAIN + canonicalize_jcs(revocation).encode("utf-8")


def _authority_revocation_signature_input_for_write(revocation: dict) -> bytes:
    """Write-boundary twin of authority_revocation_signature_input().

    sign_authority_revocation() mints a signature over this string while
    verify_authority_revocation_signature() rebuilds the identical string
    (through the unrestricted twin above) to check an existing one, so the write
    rule only ever applies on the signing side.
    """
    return AUTHORITY_REVOCATION_SIGNATURE_DOMAIN + canonicalize_jcs_for_write(revocation).encode("utf-8")


def sign_authority_revocation(revocation: dict, private_key: str) -> str:
    """Sign the record-without-signature under ``private_key`` (64 hex of seed)."""
    signing_key = SigningKey(bytes.fromhex(private_key))
    material = _authority_revocation_signature_input_for_write(revocation)
    return signing_key.sign(material).signature.hex()


def verify_authority_revocation_signature(revocation: dict, public_key: str) -> bool:
    """True if ``signature`` verifies over the rest of ``revocation`` under ``public_key``.

    Any problem with ``public_key`` or ``signature`` (wrong type, wrong length,
    not hexadecimal, or a genuinely bad signature) is reported as False rather
    than raised, matching the TypeScript SDK's ``verify``, which never throws.
    """
    if not _is_hex_of_length(public_key, 64):
        return False
    signature = revocation.get("signature")
    if not _is_hex_of_length(signature, 128):
        return False
    unsigned = {key: value for key, value in revocation.items() if key != "signature"}
    material = authority_revocation_signature_input(unsigned)
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key))
        verify_key.verify(material, bytes.fromhex(signature))
        return True
    except (CryptoError, ValueError, TypeError, KeyError):
        return False


def authority_revocation_body(revocation: dict) -> dict:
    """The body a revocation_id is computed over: the record with
    ``revocation_id`` and ``signature`` removed."""
    return {key: value for key, value in revocation.items() if key not in ("revocation_id", "signature")}


def authority_revocation_cascade_origin(body: dict) -> dict:
    """The cascade origin a cascade_transaction_id is computed over: the body
    with ``cascade_transaction_id`` removed."""
    return {key: value for key, value in body.items() if key != "cascade_transaction_id"}
