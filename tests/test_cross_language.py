"""Cross-language compatibility tests.

These test vectors ensure Python SDK output is compatible with the TypeScript SDK.
The canonical serialization MUST produce identical strings across languages for
signatures to be verifiable cross-language.
"""

from agent_passport.canonical import canonicalize
from agent_passport.crypto import generate_key_pair, sign, verify, public_key_from_private


# Test vectors from TypeScript SDK canonical.test.ts
CANONICAL_VECTORS = [
    ({"z": 1, "a": "hello", "m": None, "b": [3, 1, 2]}, '{"a":"hello","b":[3,1,2],"z":1}'),
    ({"name": "test", "nested": {"z": True, "a": False}}, '{"name":"test","nested":{"a":false,"z":true}}'),
    ({"empty_array": [], "num": 0, "neg": -1}, '{"empty_array":[],"neg":-1,"num":0}'),
    ([1, None, 3], "[1,null,3]"),
    (None, "null"),
]


def test_canonical_vectors():
    """Canonical serialization matches TypeScript SDK test vectors."""
    for obj, expected in CANONICAL_VECTORS:
        result = canonicalize(obj)
        assert result == expected, f"Mismatch: {result} != {expected}"


def test_sign_verify_roundtrip():
    """Keys generated in Python can sign and verify. The hex format is
    compatible with TS SDK (both use raw 32-byte Ed25519 keys as hex)."""
    kp = generate_key_pair()
    assert len(kp["privateKey"]) == 64
    assert len(kp["publicKey"]) == 64

    msg = canonicalize({"agentId": "test", "version": "1.0.0"})
    sig = sign(msg, kp["privateKey"])
    assert len(sig) == 128  # 64 bytes hex
    assert verify(msg, sig, kp["publicKey"])


def test_public_key_derivation():
    """Public key derived from private key matches the generated pair.
    This is critical for cross-language key import."""
    kp = generate_key_pair()
    derived = public_key_from_private(kp["privateKey"])
    assert derived == kp["publicKey"]


def test_canonical_passport_structure():
    """A passport-like structure produces deterministic canonical JSON.
    This ensures signatures over passports are cross-language compatible."""
    passport = {
        "version": "1.0.0",
        "agentId": "cross-lang-test",
        "agentName": "Test Agent",
        "capabilities": ["code_execution"],
        "publicKey": "abc123",
        "metadata": {},
    }
    canonical = canonicalize(passport)
    # Verify it's deterministic
    assert canonical == canonicalize(passport)
    # Verify key ordering
    assert canonical.startswith('{"agentId":')
    # Sign and verify
    kp = generate_key_pair()
    sig = sign(canonical, kp["privateKey"])
    assert verify(canonical, sig, kp["publicKey"])
