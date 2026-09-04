# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""A consent receipt proves consent only if the consenting key is the
principal's key.

The receipt names each party twice: ``citer`` beside ``citer_public_key``, and
``cited_principal`` beside ``cited_principal_public_key``. Nothing bound either
pair, and both signatures were checked against the keys the receipt carries. So
the principal whose consent is being proved supplied the key that proves it: an
attacker could name any victim as the cited principal, put their own key in the
key field, sign the consent themselves, and the receipt verified.

That is the whole point of the primitive inverted. Its purpose is that citing a
position a principal never took is not possible.

The fix uses the F-02 self-certifying binding from session P1 and nothing else.
Each named party's DID must commit to the key sitting next to it. A DID that
does not commit to any key cannot be bound offline, and this package resolves
no DID documents, so it is refused rather than assumed.

Python has no charter or completion gate today. This closes the hole before a
port can inherit it.
"""

import pytest

from agent_passport.crypto import generate_key_pair
from agent_passport.did_interop import to_did_key
from agent_passport.v2.attribution_consent.create import create_attribution_receipt
from agent_passport.v2.attribution_consent.sign import sign_attribution_consent
from agent_passport.v2.attribution_consent.verify import (
    check_artifact_citations,
    verify_attribution_consent,
)

EARLY = {"wallClockEarliest": 1, "wallClockLatest": 2, "logicalTime": 1, "gatewayId": "gw"}
LATE = {"wallClockEarliest": 10 ** 12, "wallClockLatest": 10 ** 12, "logicalTime": 9, "gatewayId": "gw"}


_UNSET = object()


def _receipt(citer_kp, cited_kp, *, citer_did=_UNSET, cited_did=_UNSET,
             citer_key=_UNSET, cited_key=_UNSET, consent_kp=None):
    pick = lambda given, default: default if given is _UNSET else given
    r = create_attribution_receipt(
        citer=pick(citer_did, to_did_key(citer_kp["publicKey"])),
        citer_public_key=pick(citer_key, citer_kp["publicKey"]),
        citer_private_key=citer_kp["privateKey"],
        cited_principal=pick(cited_did, to_did_key(cited_kp["publicKey"])),
        cited_principal_public_key=pick(cited_key, cited_kp["publicKey"]),
        citation_content="The principal endorses this.",
        binding_context="ctx-1",
        created_at=EARLY,
        expires_at=LATE,
    )
    signer = consent_kp or cited_kp
    return sign_attribution_consent(r, signer["privateKey"])


class TestConsentIsBoundToThePrincipal:
    def test_an_honest_receipt_verifies(self):
        citer, cited = generate_key_pair(), generate_key_pair()
        result = verify_attribution_consent(_receipt(citer, cited), EARLY)
        assert result["valid"] is True, result.get("reason")

    def test_a_victim_did_beside_an_attacker_key_is_refused(self):
        """The finding. The attacker names the victim and supplies their own
        key for the victim, then signs the consent themselves."""
        attacker, victim = generate_key_pair(), generate_key_pair()
        receipt = _receipt(
            attacker, victim,
            cited_did=to_did_key(victim["publicKey"]),
            cited_key=attacker["publicKey"],
            consent_kp=attacker,
        )
        result = verify_attribution_consent(receipt, EARLY)
        assert result["valid"] is False
        assert "cited_principal" in (result.get("reason") or "")

    def test_a_victim_did_beside_an_attacker_key_on_the_citer_is_refused(self):
        attacker, victim, cited = generate_key_pair(), generate_key_pair(), generate_key_pair()
        receipt = _receipt(
            attacker, cited,
            citer_did=to_did_key(victim["publicKey"]),
            citer_key=attacker["publicKey"],
        )
        result = verify_attribution_consent(receipt, EARLY)
        assert result["valid"] is False
        assert "citer" in (result.get("reason") or "")

    def test_the_two_parties_keys_swapped_is_refused(self):
        """Refused at creation: sign_attribution_consent already checks the
        consent signature against cited_principal_public_key, so a swap cannot
        even be built. Recorded because the creator guard is load-bearing and a
        later edit that relaxed it would otherwise go unnoticed."""
        a, b = generate_key_pair(), generate_key_pair()
        with pytest.raises(ValueError):
            _receipt(a, b, citer_key=b["publicKey"], cited_key=a["publicKey"])

    def test_a_consent_signature_by_a_key_that_does_not_bind_is_refused(self):
        """The key field is honest, the signature is somebody else's. Also
        refused at creation, for the same reason."""
        citer, cited, stranger = generate_key_pair(), generate_key_pair(), generate_key_pair()
        with pytest.raises(ValueError):
            _receipt(citer, cited, consent_kp=stranger)

    def test_a_swap_assembled_without_the_creator_is_refused_at_verification(self):
        """The creator guard is not the only line: an attacker writes the dict
        directly. Verification must refuse it on the binding alone."""
        a, b = generate_key_pair(), generate_key_pair()
        honest = _receipt(a, b)
        swapped = {**honest,
                   "citer_public_key": honest["cited_principal_public_key"],
                   "cited_principal_public_key": honest["citer_public_key"]}
        assert verify_attribution_consent(swapped, EARLY)["valid"] is False

    @pytest.mark.parametrize("did", [
        "principal:cited", "agent:citer", "did:web:example.com",
        "did:example:1234", "", "not-a-did",
    ])
    def test_a_did_that_commits_to_no_key_is_refused_not_assumed(self, did):
        citer, cited = generate_key_pair(), generate_key_pair()
        receipt = _receipt(citer, cited, cited_did=did)
        result = verify_attribution_consent(receipt, EARLY)
        assert result["valid"] is False
        assert result.get("reason")

    def test_a_non_canonical_did_key_is_refused(self):
        """Re-attack, not in the handoff list. A did:key whose multibase body
        decodes to the right key but is not the canonical spelling of it would
        give one signer two identities. The P1 helper round-trips, so it does
        not."""
        citer, cited = generate_key_pair(), generate_key_pair()
        canonical = to_did_key(cited["publicKey"])
        mangled = canonical + "z"
        receipt = _receipt(citer, cited, cited_did=mangled)
        assert verify_attribution_consent(receipt, EARLY)["valid"] is False


class TestTheCitationCheckInheritsTheBinding:
    def test_an_artifact_citing_a_forged_receipt_is_refused(self):
        attacker, victim = generate_key_pair(), generate_key_pair()
        victim_did = to_did_key(victim["publicKey"])
        receipt = _receipt(
            attacker, victim, cited_did=victim_did,
            cited_key=attacker["publicKey"], consent_kp=attacker,
        )
        artifact = {"citations": [{
            "receipt_id": receipt["id"],
            "citation_content": receipt["citation_content"],
            "cited_principal": victim_did,
        }]}
        result = check_artifact_citations(artifact, [receipt], binding_context="ctx-1", now=EARLY)
        assert result["valid"] is False

    def test_an_artifact_citing_an_honest_receipt_still_passes(self):
        citer, cited = generate_key_pair(), generate_key_pair()
        receipt = _receipt(citer, cited)
        artifact = {"citations": [{
            "receipt_id": receipt["id"],
            "citation_content": receipt["citation_content"],
            "cited_principal": receipt["cited_principal"],
        }]}
        result = check_artifact_citations(artifact, [receipt], binding_context="ctx-1", now=EARLY)
        assert result["valid"] is True, result.get("reason")
