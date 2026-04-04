# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""DID Interop (did:key + did:web).

Translation layer between APS passports and W3C DID methods.
did:key for self-certifying identifiers, did:web for domain-linked.
Cross-language compatible with the TypeScript SDK's did-interop module.
"""

import base58
from urllib.parse import unquote


# Ed25519 multicodec prefix
_ED25519_PREFIX = bytes([0xED, 0x01])


def _hex_to_multibase(hex_key: str) -> str:
    """Convert hex Ed25519 public key to z-prefix base58btc multibase."""
    key_bytes = bytes.fromhex(hex_key)
    return "z" + base58.b58encode(_ED25519_PREFIX + key_bytes).decode("ascii")


def _multibase_to_hex(multibase: str) -> str:
    """Convert z-prefix base58btc multibase back to hex public key."""
    if not multibase.startswith("z"):
        raise ValueError("Only z-prefix (base58btc) multibase supported")
    raw = base58.b58decode(multibase[1:])
    if len(raw) < 2 or raw[0] != 0xED or raw[1] != 0x01:
        raise ValueError("Invalid Ed25519 multicodec prefix")
    return raw[2:].hex()


def to_did_key(ed25519_public_key_hex: str) -> str:
    """Convert an Ed25519 public key (hex) to did:key format.

    Format: did:key:z6Mk... (multicodec 0xed01 + base58btc)

    Args:
        ed25519_public_key_hex: 64-char hex string (32 bytes).

    Returns:
        did:key string.
    """
    if not ed25519_public_key_hex or not _is_valid_hex_key(ed25519_public_key_hex):
        raise ValueError("Invalid Ed25519 public key: expected 64-char hex string")
    multibase = _hex_to_multibase(ed25519_public_key_hex)
    return f"did:key:{multibase}"


def from_did_key(did_key: str) -> str:
    """Parse a did:key back to a raw Ed25519 public key (hex).

    Args:
        did_key: A did:key string (e.g., did:key:z6Mk...).

    Returns:
        64-char hex string (32-byte Ed25519 public key).
    """
    if not isinstance(did_key, str):
        raise ValueError("did:key must be a string")
    parts = did_key.split(":")
    if len(parts) != 3 or parts[0] != "did" or parts[1] != "key":
        raise ValueError(f"Invalid did:key format: {did_key}")
    multibase = parts[2]
    if not multibase.startswith("z"):
        raise ValueError("did:key identifier must use z-prefix (base58btc) multibase")
    return _multibase_to_hex(multibase)


def did_web_to_url(did_web: str) -> str:
    """Construct the HTTPS URL for a did:web DID document.

    did:web:example.com         -> https://example.com/.well-known/did.json
    did:web:example.com:users:1 -> https://example.com/users/1/did.json
    did:web:example.com%3A8443  -> https://example.com:8443/.well-known/did.json

    Args:
        did_web: A did:web string.

    Returns:
        HTTPS URL to the DID document.
    """
    if not isinstance(did_web, str):
        raise ValueError("did:web must be a string")
    parts = did_web.split(":")
    if len(parts) < 3 or parts[0] != "did" or parts[1] != "web":
        raise ValueError(f"Invalid did:web format: {did_web}")
    segments = [unquote(s) for s in parts[2:]]
    domain = segments[0]
    if not domain:
        raise ValueError("did:web must include a domain")
    if len(segments) == 1:
        return f"https://{domain}/.well-known/did.json"
    path = "/".join(segments[1:])
    return f"https://{domain}/{path}/did.json"


def passport_to_did_document(agent_id: str, public_key: str, created_at: str = None) -> dict:
    """Convert an APS passport to a W3C DID Document.

    Produces a document with did:key as the subject identifier
    and a single Ed25519VerificationKey2020 verification method.

    Args:
        agent_id: The agent's unique identifier.
        public_key: 64-char hex Ed25519 public key.
        created_at: Optional ISO 8601 timestamp.

    Returns:
        W3C DID Document dict.
    """
    if not public_key or not _is_valid_hex_key(public_key):
        raise ValueError("Invalid passport: public_key must be 64-char hex")
    if not agent_id:
        raise ValueError("Invalid passport: agent_id is required")

    did = to_did_key(public_key)
    key_id = f"{did}#key-1"
    public_key_multibase = _hex_to_multibase(public_key)

    from datetime import datetime, timezone
    now = created_at or datetime.now(timezone.utc).isoformat()

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "controller": did,
        "alsoKnownAs": [f"did:aps:{public_key_multibase}"],
        "verificationMethod": [{
            "id": key_id,
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": public_key_multibase,
        }],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "capabilityDelegation": [key_id],
        "service": [{
            "id": f"{did}#aps",
            "type": "AgentPassportService",
            "serviceEndpoint": {
                "agentId": agent_id,
                "protocol": "aps",
                "version": "1.0.0",
            },
        }],
        "created": now,
        "updated": now,
    }


def _is_valid_hex_key(key: str) -> bool:
    """Check if a string is a valid 64-char hex key."""
    if len(key) != 64:
        return False
    try:
        int(key, 16)
        return True
    except ValueError:
        return False
