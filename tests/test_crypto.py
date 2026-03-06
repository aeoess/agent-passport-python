"""Tests for Ed25519 cryptographic operations."""

from agent_passport.crypto import generate_key_pair, sign, verify, public_key_from_private


def test_generates_valid_keypair():
    kp = generate_key_pair()
    assert len(kp["privateKey"]) == 64  # 32 bytes hex
    assert len(kp["publicKey"]) == 64


def test_signs_and_verifies():
    kp = generate_key_pair()
    sig = sign("hello world", kp["privateKey"])
    assert verify("hello world", sig, kp["publicKey"])


def test_rejects_tampered():
    kp = generate_key_pair()
    sig = sign("hello world", kp["privateKey"])
    assert not verify("hello tampered", sig, kp["publicKey"])


def test_rejects_wrong_key():
    kp1 = generate_key_pair()
    kp2 = generate_key_pair()
    sig = sign("hello world", kp1["privateKey"])
    assert not verify("hello world", sig, kp2["publicKey"])


def test_derives_pubkey():
    kp = generate_key_pair()
    derived = public_key_from_private(kp["privateKey"])
    assert derived == kp["publicKey"]
