# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""The old body-only proof preimage is not accepted, and must not become
accepted again.

Before this branch a credential's proof was made over the document body alone
and the proof block was attached afterwards, so ``created``, ``proofPurpose``,
``verificationMethod``, ``challenge`` and ``domain`` were rewritable without
invalidating ``proofValue``. The preimage now covers the proof configuration,
and credentials issued under the old rule do not verify. Reissuance is the
migration; this is a ratified break.

The tempting repair is to accept both preimages for a while. It cannot be done
safely. A verifier that still accepts an old-format proof cannot authenticate
that proof's challenge or domain, because they were never signed, so the
replay hole stays open for anything presented in the old format, and the
presenter chooses the format. Dual verification would keep the finding open
under the appearance of having closed it.

Every credential below is signed by the LEGITIMATE issuer over the exact bytes
the shipped code signed. Nothing here is forged. They are refused for covering
too little, which is the point: if any of these passes again, dual
verification has been reintroduced.
"""

import base64

from agent_passport.canonical import canonicalize_for_write
from agent_passport.credential_request import verify_credential_response
from agent_passport.crypto import generate_key_pair, sign
from agent_passport.did_interop import to_did_key
from agent_passport.vc_wrapper import (
    verify_verifiable_credential,
    verify_verifiable_presentation,
)

ISSUER = generate_key_pair()
DID = to_did_key(ISSUER["publicKey"])


def _body_only_proof_value(body: dict) -> str:
    """The pre-branch signature: over the document body, proof excluded.

    Reproduced here rather than imported, because the code that produced it no
    longer exists.
    """
    raw = bytes.fromhex(sign(canonicalize_for_write(body), ISSUER["privateKey"]))
    return base64.b64encode(raw).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")


def _old_format_credential() -> dict:
    body = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:aps:credential:old-format",
        "type": ["VerifiableCredential"],
        "issuer": DID,
        "issuanceDate": "2026-01-01T00:00:00.000Z",
        "credentialSubject": {"id": DID, "role": "reader"},
    }
    return {
        **body,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2026-01-01T00:00:00.000Z",
            "verificationMethod": f"{DID}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": _body_only_proof_value(body),
        },
    }


def _old_format_presentation(challenge: str) -> dict:
    body = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:aps:presentation:old-format",
        "type": ["VerifiablePresentation"],
        "holder": DID,
        "verifiableCredential": [],
    }
    return {
        **body,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": "2026-01-01T00:00:00.000Z",
            "verificationMethod": f"{DID}#key-1",
            "proofPurpose": "authentication",
            # Signed over the body only, then challenge and domain grafted on.
            # This is exactly the artifact whose replay fields were rewritable.
            "proofValue": _body_only_proof_value(body),
            "challenge": challenge,
            "domain": "verifier-a.example",
        },
    }


class TestTheOldPreimageIsRefused:
    def test_a_credential_the_issuer_really_signed_is_refused(self):
        result = verify_verifiable_credential(_old_format_credential())
        assert result["valid"] is False, (
            "accepting the old preimage reopens the finding: the proof "
            "configuration would be unauthenticated"
        )
        # The issuer binding holds. This is not a forgery, and the failure is
        # about what the signature covers, not about who made it.
        assert result["key_authority"] == "verified"
        assert result["proof_of_possession"] is False

    def test_a_presentation_is_refused_even_when_the_challenge_matches(self):
        vp = _old_format_presentation("nonce-a")
        result = verify_verifiable_presentation(
            vp, expected_challenge="nonce-a", expected_domain="verifier-a.example"
        )
        assert result["valid"] is False, (
            "the challenge on an old-format proof was never signed, so "
            "matching it establishes nothing"
        )
        assert result["proof_of_possession"] is False

    def test_the_credential_response_verifier_refuses_it_too(self):
        vp = _old_format_presentation("nonce-a")
        assert verify_credential_response(vp, "nonce-a")["valid"] is False


class TestWhyTheBreakIsNecessaryRatherThanChosen:
    def test_an_old_format_proof_carries_a_challenge_nothing_signed(self):
        """The presenter, not the issuer, decides what the challenge says. Two
        presentations differing only in their challenge carry the SAME
        proofValue, because the signature never covered it. A verifier that
        accepted this format could compare the field and learn nothing."""
        for_a = _old_format_presentation("nonce-a")
        for_b = _old_format_presentation("nonce-b")
        assert for_a["proof"]["proofValue"] == for_b["proof"]["proofValue"], (
            "one signature, two challenges: this is why the old format cannot "
            "be dual-verified"
        )
        # And neither readdressing succeeds.
        assert verify_verifiable_presentation(for_a, expected_challenge="nonce-a")["valid"] is False
        assert verify_verifiable_presentation(for_b, expected_challenge="nonce-b")["valid"] is False

    def test_the_current_format_binds_the_challenge_to_the_signature(self):
        """The same comparison on the repaired format: two challenges, two
        different signatures. That is what makes comparing one meaningful."""
        from agent_passport.vc_wrapper import create_verifiable_presentation
        holder = generate_key_pair()
        a = create_verifiable_presentation([], holder["privateKey"], challenge="nonce-a")
        b = create_verifiable_presentation([], holder["privateKey"], challenge="nonce-b")
        assert a["proof"]["proofValue"] != b["proof"]["proofValue"]
