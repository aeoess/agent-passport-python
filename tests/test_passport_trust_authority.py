# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""A signature over a passport says who signed it, not who vouches for it.

``verify_passport`` read the verifying key out of ``passport.publicKey`` and
took no other argument, so a passport minted with any freshly generated key,
claiming any agentId and any owner, returned ``valid: True``. There was no
parameter through which a relying party could name the keys it accepts, so
there was no correct way to call it.

Two library functions gated on that result. ``intent.assign_role`` documents
itself as assigning a role "after verifying their passport" and raises unless
the result is valid; ``commerce.commerce_preflight`` labels the same call
``Gate 1`` and folds it into ``permitted``. Both therefore authorized on a
self-vouching credential.

The contract here: a good signature establishes integrity, never authority.
``valid`` is true only when the caller supplied a trust input that the
passport satisfies, or when the caller explicitly opted into accepting a
self-signed one. Self-signed acceptance is never the default, and it is
reported in its own result field rather than inferred from a warning string.

This is deliberately stricter than the frozen TypeScript, whose
``selfSignedAccepted`` doc keeps ``valid`` true for a self-signed passport for
backward compatibility. The trust SHAPE is mirrored; the default is not.
"""

import pytest

from agent_passport.canonical import canonicalize
from agent_passport.commerce import commerce_preflight
from agent_passport.crypto import generate_key_pair, sign
from agent_passport.intent import assign_role
from agent_passport.passport import create_passport, verify_passport


def _minted(agent_id="ag_attacker_claims_treasury", capabilities=None):
    """A passport nobody vouched for, minted with a key generated right here."""
    return create_passport(
        agent_id=agent_id,
        agent_name="Treasury Bot",
        owner_alias="acme-finance",
        mission="move money",
        capabilities=capabilities or ["commerce:checkout"],
        runtime={"platform": "python", "models": [], "toolsCount": 0, "memoryType": "session"},
    )


def _countersign(signed: dict, issuer_private_key: str, issuer_public_key: str,
                 issuer_id: str = "aeoess") -> dict:
    """The issuer countersignature the other three SDKs already carry.

    Signs canonicalize({passport, signature, signedAt}), which is exactly the
    preimage verify.ts builds at src/verification/verify.ts:102-106 and the
    Rust and Go suites pin.
    """
    payload = canonicalize({
        "passport": signed["passport"],
        "signature": signed["signature"],
        "signedAt": signed.get("signedAt"),
    })
    return {
        **signed,
        "issuerSignature": {
            "issuerId": issuer_id,
            "issuerPublicKey": issuer_public_key,
            "signature": sign(payload, issuer_private_key),
            "signedAt": signed.get("signedAt"),
        },
    }


class TestASignatureIsNotAuthority:
    def test_a_self_minted_passport_is_not_valid_without_a_trust_input(self):
        """The finding. Nobody vouched for this passport and nobody was asked."""
        result = verify_passport(_minted()["signedPassport"])
        assert result["valid"] is False
        assert result["issuer_trust_checked"] is False
        assert result["self_signed_accepted"] is False

    def test_a_self_minted_passport_is_not_valid_under_a_trust_set_it_is_absent_from(self):
        stranger = generate_key_pair()
        result = verify_passport(
            _minted()["signedPassport"], trusted_issuers=[stranger["publicKey"]]
        )
        assert result["valid"] is False
        assert result["issuer_trust_checked"] is True

    def test_a_countersigned_passport_is_valid_under_its_issuer(self):
        issuer = generate_key_pair()
        signed = _countersign(_minted()["signedPassport"], issuer["privateKey"], issuer["publicKey"])
        result = verify_passport(signed, trusted_issuers=[issuer["publicKey"]])
        assert result["valid"] is True, result["errors"]
        assert result["issuer_trust_checked"] is True
        assert result["self_signed_accepted"] is False

    def test_a_countersignature_by_an_untrusted_issuer_is_refused(self):
        issuer, stranger = generate_key_pair(), generate_key_pair()
        signed = _countersign(_minted()["signedPassport"], issuer["privateKey"], issuer["publicKey"])
        result = verify_passport(signed, trusted_issuers=[stranger["publicKey"]])
        assert result["valid"] is False

    def test_a_countersignature_naming_a_trusted_issuer_but_signed_by_another_is_refused(self):
        """The trusted key is named, the bytes are somebody else's."""
        issuer, forger = generate_key_pair(), generate_key_pair()
        signed = _countersign(_minted()["signedPassport"], forger["privateKey"], issuer["publicKey"])
        result = verify_passport(signed, trusted_issuers=[issuer["publicKey"]])
        assert result["valid"] is False
        assert any("countersignature" in e.lower() for e in result["errors"])

    def test_a_countersigned_passport_whose_body_was_altered_is_refused(self):
        """Re-attack, not in the handoff list: the countersignature covers the
        agent signature and signedAt, so altering the passport body breaks the
        agent signature first, and the issuer countersignature second."""
        issuer = generate_key_pair()
        signed = _countersign(_minted()["signedPassport"], issuer["privateKey"], issuer["publicKey"])
        tampered = {**signed, "passport": {**signed["passport"], "agentId": "ag_promoted"}}
        result = verify_passport(tampered, trusted_issuers=[issuer["publicKey"]])
        assert result["valid"] is False

    def test_self_signed_acceptance_is_an_explicit_opt_in(self):
        result = verify_passport(_minted()["signedPassport"], allow_self_signed=True)
        assert result["valid"] is True, result["errors"]
        assert result["self_signed_accepted"] is True
        assert result["issuer_trust_checked"] is False

    def test_opting_in_to_self_signed_still_requires_a_good_signature(self):
        signed = _minted()["signedPassport"]
        tampered = {**signed, "passport": {**signed["passport"], "agentId": "ag_other"}}
        result = verify_passport(tampered, allow_self_signed=True)
        assert result["valid"] is False

    def test_an_expired_passport_under_a_trusted_issuer_is_still_refused(self):
        issuer = generate_key_pair()
        minted = _minted()
        expired = {
            **minted["signedPassport"],
            "passport": {**minted["signedPassport"]["passport"], "expiresAt": "2020-01-01T00:00:00Z"},
        }
        # Re-sign so only expiry is wrong.
        expired["signature"] = sign(canonicalize(expired["passport"]), minted["keyPair"]["privateKey"])
        signed = _countersign(expired, issuer["privateKey"], issuer["publicKey"])
        result = verify_passport(signed, trusted_issuers=[issuer["publicKey"]])
        assert result["valid"] is False
        assert any("expired" in e.lower() for e in result["errors"])

    @pytest.mark.parametrize("bad", ["not-a-list", 12345, [123], [""], [None]])
    def test_a_malformed_trust_input_is_a_caller_error_not_an_acceptance(self, bad):
        """Re-attack: a caller that fumbles its own trust list must not thereby
        get the permissive path."""
        result = verify_passport(_minted()["signedPassport"], trusted_issuers=bad)
        assert result["valid"] is False


class TestTheTwoGatesFailClosedWithoutTrust:
    def test_assign_role_refuses_a_passport_nobody_vouched_for(self):
        assigner = generate_key_pair()
        with pytest.raises(ValueError):
            assign_role(
                signed_passport=_minted()["signedPassport"], role="treasurer",
                autonomy_level="high", scope=["commerce:checkout"],
                assigner_private_key=assigner["privateKey"],
                assigner_public_key=assigner["publicKey"],
            )

    def test_assign_role_accepts_one_countersigned_by_a_trusted_issuer(self):
        assigner, issuer = generate_key_pair(), generate_key_pair()
        signed = _countersign(_minted()["signedPassport"], issuer["privateKey"], issuer["publicKey"])
        assignment = assign_role(
            signed_passport=signed, role="treasurer", autonomy_level="high",
            scope=["commerce:checkout"],
            assigner_private_key=assigner["privateKey"],
            assigner_public_key=assigner["publicKey"],
            trusted_issuers=[issuer["publicKey"]],
        )
        assert assignment["role"] == "treasurer"

    def test_the_commerce_passport_gate_does_not_pass_without_trust(self):
        delegation = {"delegationId": "del_1", "scope": ["commerce:checkout"],
                      "spendLimit": 1000, "spentAmount": 0, "spendLimitUnit": "USD"}
        result = commerce_preflight(
            signed_passport=_minted()["signedPassport"], delegation=delegation,
            merchant_name="acme", estimated_total={"amount": 10, "currency": "USD"},
        )
        gate = next(c for c in result["checks"] if c["check"] == "passport_valid")
        assert gate["passed"] is False
        assert result["permitted"] is False

    def test_the_commerce_passport_gate_passes_under_a_trusted_issuer(self):
        issuer = generate_key_pair()
        signed = _countersign(_minted()["signedPassport"], issuer["privateKey"], issuer["publicKey"])
        delegation = {"delegationId": "del_1", "scope": ["commerce:checkout"],
                      "spendLimit": 1000, "spentAmount": 0, "spendLimitUnit": "USD"}
        result = commerce_preflight(
            signed_passport=signed, delegation=delegation, merchant_name="acme",
            estimated_total={"amount": 10, "currency": "USD"},
            trusted_issuers=[issuer["publicKey"]],
        )
        gate = next(c for c in result["checks"] if c["check"] == "passport_valid")
        assert gate["passed"] is True, result["checks"]
