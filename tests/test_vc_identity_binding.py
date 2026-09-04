# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""A credential's proof must be the claimed issuer's, and its replay context
must be inside the signed bytes.

Two contracts, one for each half of the finding.

BINDING. ``proof.verificationMethod`` is part of the document the presenter
writes. Deriving the verification key from it and verifying under that key
establishes only that whoever assembled the document held one private key,
which is true of every document anyone can make. The relying party's question
is whether that key belongs to the identity the document CLAIMS to speak for:
``issuer`` on a credential, ``holder`` on a presentation.

REPLAY. ``challenge`` and ``domain`` were attached to the proof after the body
was signed, so a presentation minted for one verifier could be readdressed to
another without invalidating it, and the one function that compared a challenge
compared a field the presenter could rewrite.

``valid`` here means integrity plus binding of the proof key to the claimed
identity plus the required proof context. It does NOT mean the issuer or holder
is trusted; the verifier returns the bound DID so the caller can apply its own
allowlist.
"""

import base64

import pytest

from agent_passport.canonical import canonicalize_for_write
from agent_passport.credential_request import (
    create_credential_request,
    fulfill_credential_request,
    verify_credential_response,
)
from agent_passport.crypto import generate_key_pair, sign
from agent_passport.did_interop import to_did_key
from agent_passport.vc_wrapper import (
    create_verifiable_presentation,
    passport_to_verifiable_credential,
    verify_verifiable_credential,
    verify_verifiable_presentation,
)

ATTACKER = generate_key_pair()
TRUSTED = generate_key_pair()
HOLDER = generate_key_pair()


def _proof_value(body: dict, private_key: str) -> str:
    """The pre-repair signature: over the document body, proof excluded."""
    raw = bytes.fromhex(sign(canonicalize_for_write(body), private_key))
    return base64.b64encode(raw).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")


def _credential(issuer: str, verification_method: str, signing_key: str,
                proof_purpose: str = "assertionMethod",
                proof_type: str = "Ed25519Signature2020") -> dict:
    body = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:aps:credential:binding-fixture",
        "type": ["VerifiableCredential"],
        "issuer": issuer,
        "issuanceDate": "2026-01-01T00:00:00.000Z",
        "credentialSubject": {"id": "did:example:subject", "role": "admin"},
    }
    return {
        **body,
        "proof": {
            "type": proof_type,
            "created": "2026-01-01T00:00:00.000Z",
            "verificationMethod": verification_method,
            "proofPurpose": proof_purpose,
            "proofValue": _proof_value(body, signing_key),
        },
    }


class TestCredentialIssuerBinding:
    def test_refuses_a_credential_naming_an_issuer_it_was_not_signed_by(self):
        """A credential naming a trusted issuer, carrying an attacker's proof."""
        result = verify_verifiable_credential(_credential(
            issuer=to_did_key(TRUSTED["publicKey"]),
            verification_method=f'{to_did_key(ATTACKER["publicKey"])}#key-1',
            signing_key=ATTACKER["privateKey"],
        ))
        assert result["valid"] is False
        assert result["key_authority"] == "rejected"
        # And it must not hand back the issuer the forgery named. Returning a
        # trusted DID from a rejected verification is how a caller allowlists
        # an attacker.
        assert result["issuer_did"] == ""

    def test_refuses_a_non_did_key_identifier_read_as_raw_key_material(self):
        """The fallback took the last colon-separated segment as a public key,
        so a did:aps identifier supplied its own verification key with nothing
        tying it to the claimed did:key issuer."""
        result = verify_verifiable_credential(_credential(
            issuer=to_did_key(TRUSTED["publicKey"]),
            verification_method=f'did:aps:{ATTACKER["publicKey"]}#key-1',
            signing_key=ATTACKER["privateKey"],
        ))
        assert result["valid"] is False
        assert result["key_authority"] == "rejected"

    def test_a_non_self_certifying_method_is_unresolved_not_accepted(self):
        result = verify_verifiable_credential(_credential(
            issuer="did:web:example.com",
            verification_method="did:web:example.com#key-1",
            signing_key=ATTACKER["privateKey"],
        ))
        assert result["valid"] is False
        # Not "rejected": nothing was disproved. This verifier resolves no DID
        # documents, so it cannot establish the binding either way, and an
        # unestablished binding is not an acceptance.
        assert result["key_authority"] == "unresolved"

    def test_refuses_a_proof_made_for_a_different_purpose(self):
        result = verify_verifiable_credential(_credential(
            issuer=to_did_key(TRUSTED["publicKey"]),
            verification_method=f'{to_did_key(TRUSTED["publicKey"])}#key-1',
            signing_key=TRUSTED["privateKey"],
            proof_purpose="authentication",
        ))
        assert result["valid"] is False

    def test_refuses_a_proof_of_a_different_type(self):
        result = verify_verifiable_credential(_credential(
            issuer=to_did_key(TRUSTED["publicKey"]),
            verification_method=f'{to_did_key(TRUSTED["publicKey"])}#key-1',
            signing_key=TRUSTED["privateKey"],
            proof_type="JsonWebSignature2020",
        ))
        assert result["valid"] is False

    def test_a_signature_failure_is_not_an_identity_rejection(self):
        """The binding held; the bytes did not. Two different findings."""
        vc = passport_to_verifiable_credential(
            {"agentId": "agent-binding", "publicKey": HOLDER["publicKey"]},
            TRUSTED["privateKey"],
        )
        tampered = {**vc, "credentialSubject": {**vc["credentialSubject"], "role": "admin"}}
        result = verify_verifiable_credential(tampered)
        assert result["valid"] is False
        assert result["key_authority"] == "verified"
        assert result["proof_of_possession"] is False


class TestPresentationHolderBinding:
    def test_refuses_a_presentation_naming_a_holder_it_was_not_signed_by(self):
        body = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:aps:presentation:binding-fixture",
            "type": ["VerifiablePresentation"],
            "holder": to_did_key(TRUSTED["publicKey"]),
            "verifiableCredential": [],
        }
        vp = {
            **body,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2026-01-01T00:00:00.000Z",
                "verificationMethod": f'{to_did_key(ATTACKER["publicKey"])}#key-1',
                "proofPurpose": "authentication",
                "proofValue": _proof_value(body, ATTACKER["privateKey"]),
                "challenge": "nonce-a",
            },
        }
        result = verify_verifiable_presentation(vp, expected_challenge="nonce-a")
        assert result["valid"] is False
        assert result["key_authority"] == "rejected"


class TestPresentationReplay:
    def test_accepts_the_presentation_it_was_minted_for(self):
        vp = create_verifiable_presentation(
            [], HOLDER["privateKey"], challenge="nonce-a", domain="verifier-a.example"
        )
        result = verify_verifiable_presentation(
            vp, expected_challenge="nonce-a", expected_domain="verifier-a.example"
        )
        assert result["valid"] is True
        # The verified challenge is returned so caller state can consume it.
        # One-time use is relying-party state, not verifier state.
        assert result["challenge"] == "nonce-a"
        assert result["domain"] == "verifier-a.example"

    def test_refuses_a_challenge_rewritten_after_signing(self):
        vp = create_verifiable_presentation(
            [], HOLDER["privateKey"], challenge="nonce-a", domain="verifier-a.example"
        )
        vp["proof"]["challenge"] = "nonce-b"
        result = verify_verifiable_presentation(vp, expected_challenge="nonce-b")
        assert result["valid"] is False

    def test_refuses_a_domain_rewritten_after_signing(self):
        vp = create_verifiable_presentation(
            [], HOLDER["privateKey"], challenge="nonce-a", domain="verifier-a.example"
        )
        vp["proof"]["domain"] = "verifier-b.example"
        result = verify_verifiable_presentation(
            vp, expected_challenge="nonce-a", expected_domain="verifier-b.example"
        )
        assert result["valid"] is False

    def test_refuses_a_created_rewritten_after_signing(self):
        vp = create_verifiable_presentation([], HOLDER["privateKey"], challenge="nonce-a")
        vp["proof"]["created"] = "2020-01-01T00:00:00.000Z"
        result = verify_verifiable_presentation(vp, expected_challenge="nonce-a")
        assert result["valid"] is False

    def test_refuses_a_proof_purpose_rewritten_after_signing(self):
        vp = create_verifiable_presentation([], HOLDER["privateKey"], challenge="nonce-a")
        vp["proof"]["proofPurpose"] = "assertionMethod"
        result = verify_verifiable_presentation(vp, expected_challenge="nonce-a")
        assert result["valid"] is False

    def test_refuses_a_challenge_that_does_not_match(self):
        vp = create_verifiable_presentation([], HOLDER["privateKey"], challenge="nonce-a")
        assert verify_verifiable_presentation(vp, expected_challenge="nonce-b")["valid"] is False

    def test_refuses_a_proof_carrying_no_challenge_when_one_is_expected(self):
        vp = create_verifiable_presentation([], HOLDER["privateKey"], challenge="nonce-a")
        del vp["proof"]["challenge"]
        assert verify_verifiable_presentation(vp, expected_challenge="nonce-a")["valid"] is False

    def test_refuses_a_verifier_that_states_no_challenge(self):
        """A presentation that answers no challenge answers any challenge."""
        vp = create_verifiable_presentation([], HOLDER["privateKey"], challenge="nonce-a")
        assert verify_verifiable_presentation(vp)["valid"] is False


class TestPresentationCreatorGuards:
    @pytest.mark.parametrize("challenge", [None, "", 12345, {"nonce": "a"}])
    def test_creator_refuses_a_challenge_that_is_not_a_non_empty_string(self, challenge):
        with pytest.raises((TypeError, ValueError)):
            create_verifiable_presentation([], HOLDER["privateKey"], challenge=challenge)

    @pytest.mark.parametrize("domain", ["", 443, {"host": "a"}])
    def test_creator_refuses_a_present_but_unusable_domain(self, domain):
        with pytest.raises((TypeError, ValueError)):
            create_verifiable_presentation(
                [], HOLDER["privateKey"], challenge="nonce-a", domain=domain
            )

    def test_creator_still_accepts_a_challenge_alone_and_with_a_domain(self):
        assert create_verifiable_presentation([], HOLDER["privateKey"], challenge="nonce-a")
        assert create_verifiable_presentation(
            [], HOLDER["privateKey"], challenge="nonce-a", domain="verifier-a.example"
        )


class TestCredentialResponseReplay:
    def test_compares_a_challenge_that_is_actually_signed(self):
        agent = generate_key_pair()
        request = create_credential_request(["grade"], "did:key:z6MkVerifier", "real-challenge")
        vp = fulfill_credential_request(
            request,
            {"agentId": "agent-replay", "publicKey": agent["publicKey"], "grade": 1,
             "expiresAt": "2027-01-01T00:00:00.000Z"},
            agent["privateKey"],
        )
        assert verify_credential_response(vp, "real-challenge")["valid"] is True
        assert verify_credential_response(vp, "wrong-challenge")["valid"] is False

        # The rewrite that defeated the check this function advertises.
        vp["proof"]["challenge"] = "wrong-challenge"
        assert verify_credential_response(vp, "wrong-challenge")["valid"] is False

    def test_requires_an_expected_challenge(self):
        agent = generate_key_pair()
        request = create_credential_request(["grade"], "did:key:z6MkVerifier", "some-challenge")
        vp = fulfill_credential_request(
            request,
            {"agentId": "agent-noreplay", "publicKey": agent["publicKey"], "grade": 1,
             "expiresAt": "2027-01-01T00:00:00.000Z"},
            agent["privateKey"],
        )
        # Verified against no challenge is a response to nothing in particular,
        # replayable by anyone who has seen it.
        assert verify_credential_response(vp)["valid"] is False
        assert verify_credential_response(vp, "some-challenge")["valid"] is True
