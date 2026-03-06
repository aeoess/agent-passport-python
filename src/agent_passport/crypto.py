"""Ed25519 cryptographic operations for Agent Passport System.

Uses PyNaCl (libsodium) for Ed25519 key generation, signing, and verification.
Keys are stored as hex-encoded 32-byte strings for cross-language compatibility
with the TypeScript SDK.
"""

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
import os


def generate_key_pair() -> dict:
    """Generate an Ed25519 key pair.

    Returns:
        dict with 'privateKey' and 'publicKey' as hex strings (32 bytes each).
        Compatible with TypeScript SDK key format.
    """
    sk = SigningKey(os.urandom(32))
    return {
        "privateKey": sk.encode().hex(),
        "publicKey": sk.verify_key.encode().hex(),
    }


def sign(message: str, private_key_hex: str) -> str:
    """Sign a UTF-8 message with Ed25519.

    Args:
        message: UTF-8 string to sign.
        private_key_hex: Hex-encoded 32-byte private key (seed).

    Returns:
        Hex-encoded 64-byte signature.
    """
    sk = SigningKey(bytes.fromhex(private_key_hex))
    signed = sk.sign(message.encode("utf-8"))
    return signed.signature.hex()


def verify(message: str, signature_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature.

    Args:
        message: UTF-8 string that was signed.
        signature_hex: Hex-encoded 64-byte signature.
        public_key_hex: Hex-encoded 32-byte public key.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        vk.verify(message.encode("utf-8"), bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, Exception):
        return False


def public_key_from_private(private_key_hex: str) -> str:
    """Derive public key from private key.

    Args:
        private_key_hex: Hex-encoded 32-byte private key (seed).

    Returns:
        Hex-encoded 32-byte public key.
    """
    sk = SigningKey(bytes.fromhex(private_key_hex))
    return sk.verify_key.encode().hex()
