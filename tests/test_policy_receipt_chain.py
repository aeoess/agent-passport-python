# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""A receipt that attests to a chain must have checked the chain.

A policy receipt carries three signature strings copied out of an intent, a
decision and an action receipt. It does not carry the objects those signatures
were made over, so the preimages cannot be reconstructed from the receipt and
chain verification has to take them from the relying party, which is also
where the three trust anchors belong.

Before this file, ``verify_policy_receipt`` tested the three strings for
presence and returned ``valid: True``. A receipt whose chain block held the
words "not a signature at all" verified. Presence is not verification, and a
verifier's result may claim only what it actually established.

The split is deliberate. ``verify_policy_receipt`` requires the chain and
answers the whole question. ``verify_policy_receipt_envelope`` answers only
"were these bytes signed by this key", and says so in its name, for the caller
that genuinely wants only that.
"""

import pytest

from agent_passport.crypto import generate_key_pair
from agent_passport.delegation import create_action_receipt, create_delegation
from agent_passport.policy import (
    FloorValidatorV1,
    create_policy_receipt,
    request_action,
    verify_policy_receipt,
    verify_policy_receipt_envelope,
)

ACTION = {"type": "code_execution", "scopeRequired": "code_execution", "target": "main.py"}


def _chain():
    """A real three-signature chain, each object signed by its own party."""
    agent, evaluator = generate_key_pair(), generate_key_pair()
    delegation = create_delegation(
        delegated_by=evaluator["publicKey"], delegated_to=agent["publicKey"],
        scope=["code_execution"], private_key=evaluator["privateKey"], spend_limit=100,
    )
    result = request_action(
        agent_id="agent-1", agent_public_key=agent["publicKey"],
        agent_private_key=agent["privateKey"], delegation_id=delegation["delegationId"],
        action=ACTION, validator=FloorValidatorV1(),
        validation_context={
            "agentRegistered": True, "agentAttestationValid": True,
            "floorVersion": "0.1", "delegation": delegation, "floorPrinciples": [],
        },
        evaluator_id="eval-1", evaluator_public_key=evaluator["publicKey"],
        evaluator_private_key=evaluator["privateKey"],
    )
    receipt = create_action_receipt(
        agent_id="agent-1", delegation=delegation, action_type="code_execution",
        target="main.py", scope_used="code_execution", result_status="success",
        result_summary="Executed main.py", private_key=agent["privateKey"],
    )
    pr = create_policy_receipt(
        intent=result["intent"], decision=result["decision"],
        receipt=receipt, verifier_private_key=evaluator["privateKey"],
    )
    inputs = {
        "intent": result["intent"],
        "decision": result["decision"],
        "receipt": receipt,
        "intentSignerPublicKey": agent["publicKey"],
        "decisionSignerPublicKey": evaluator["publicKey"],
        "receiptSignerPublicKey": agent["publicKey"],
    }
    return pr, inputs, evaluator["publicKey"], agent, evaluator


class TestTheChainIsActuallyVerified:
    def test_an_honest_chain_verifies(self):
        pr, chain, verifier_key, _, _ = _chain()
        result = verify_policy_receipt(pr, verifier_key, chain)
        assert result["valid"] is True, result["errors"]
        assert result["envelope_signature_valid"] is True
        assert result["chain_verified"] is True

    def test_omitting_the_chain_is_not_a_verified_receipt(self):
        """The two-argument call used to return valid: True for any receipt
        with three non-empty strings. It now states that nothing was checked,
        and it states it as a result rather than as an exception, because an
        untyped caller is still a caller."""
        pr, _, verifier_key, _, _ = _chain()
        result = verify_policy_receipt(pr, verifier_key)
        assert result["valid"] is False
        assert result["chain_verified"] is False
        # The envelope really was signed; that is the part that did hold.
        assert result["envelope_signature_valid"] is True

    @pytest.mark.parametrize("field", ["intentSignature", "decisionSignature", "receiptSignature"])
    def test_a_copied_signature_that_is_only_text_is_refused(self, field):
        """The finding, exactly: a chain block holding words instead of
        signatures. The envelope is re-signed so the receipt is internally
        consistent and only the copied strings are wrong."""
        pr, chain, verifier_key, _, evaluator = _chain()
        forged = {**pr, "chain": {**pr["chain"], field: "not a signature at all"}}
        from agent_passport.canonical import canonicalize_for_write
        from agent_passport.crypto import sign
        unsigned = {k: v for k, v in forged.items() if k != "signature"}
        forged["signature"] = sign(canonicalize_for_write(unsigned), evaluator["privateKey"])

        result = verify_policy_receipt(forged, verifier_key, chain)
        assert result["valid"] is False
        assert result["chain_verified"] is False
        assert result["envelope_signature_valid"] is True

    def test_a_signature_from_a_different_chain_is_refused(self):
        """Three real signatures, taken from somewhere else. Presence and even
        cryptographic validity are not enough: they must be the signatures on
        the objects presented."""
        pr, chain, verifier_key, _, evaluator = _chain()
        other_pr, _, _, _, _ = _chain()
        from agent_passport.canonical import canonicalize_for_write
        from agent_passport.crypto import sign
        forged = {**pr, "chain": other_pr["chain"]}
        unsigned = {k: v for k, v in forged.items() if k != "signature"}
        forged["signature"] = sign(canonicalize_for_write(unsigned), evaluator["privateKey"])

        result = verify_policy_receipt(forged, verifier_key, chain)
        assert result["valid"] is False
        assert result["chain_verified"] is False

    @pytest.mark.parametrize("anchor", [
        "intentSignerPublicKey", "decisionSignerPublicKey", "receiptSignerPublicKey",
    ])
    def test_a_signature_that_does_not_verify_under_the_caller_anchor_is_refused(self, anchor):
        """The anchors are the relying party's, not the artifacts'. Swapping
        one for an unrelated key must fail even though every object in the
        chain is genuine."""
        pr, chain, verifier_key, _, _ = _chain()
        stranger = generate_key_pair()
        result = verify_policy_receipt(
            pr, verifier_key, {**chain, anchor: stranger["publicKey"]}
        )
        assert result["valid"] is False
        assert result["chain_verified"] is False

    @pytest.mark.parametrize("field", ["intentId", "decisionId", "receiptId"])
    def test_an_id_that_names_something_else_is_refused(self, field):
        pr, chain, verifier_key, _, evaluator = _chain()
        from agent_passport.canonical import canonicalize_for_write
        from agent_passport.crypto import sign
        forged = {**pr, field: "prec_something_else"}
        unsigned = {k: v for k, v in forged.items() if k != "signature"}
        forged["signature"] = sign(canonicalize_for_write(unsigned), evaluator["privateKey"])
        result = verify_policy_receipt(forged, verifier_key, chain)
        assert result["valid"] is False
        assert result["chain_verified"] is False

    def test_a_decision_that_decides_a_different_intent_is_refused(self):
        pr, chain, verifier_key, _, _ = _chain()
        other = _chain()[1]
        result = verify_policy_receipt(pr, verifier_key, {**chain, "intent": other["intent"]})
        assert result["valid"] is False

    def test_a_receipt_attesting_to_a_denied_decision_is_refused(self):
        """create_policy_receipt refuses to build one. A verifier must refuse
        to accept one built another way."""
        pr, chain, verifier_key, _, _ = _chain()
        denied = {**chain["decision"], "verdict": "deny"}
        result = verify_policy_receipt(pr, verifier_key, {**chain, "decision": denied})
        assert result["valid"] is False
        assert any("denied" in e for e in result["errors"])

    def test_an_unreadable_decision_expiry_is_refused(self):
        pr, chain, verifier_key, _, _ = _chain()
        broken = {**chain["decision"], "expiresAt": "not-a-date"}
        result = verify_policy_receipt(pr, verifier_key, {**chain, "decision": broken})
        assert result["valid"] is False
        assert any("expiresAt" in e for e in result["errors"])


class TestTheEnvelopeHelperSaysWhatItChecks:
    def test_it_verifies_the_envelope_and_claims_nothing_more(self):
        pr, _, verifier_key, _, _ = _chain()
        result = verify_policy_receipt_envelope(pr, verifier_key)
        assert result["valid"] is True
        assert result["envelope_signature_valid"] is True
        # No chain_verified key: this function does not answer that question,
        # so it does not report an answer to it.
        assert "chain_verified" not in result

    def test_it_refuses_an_envelope_signed_by_someone_else(self):
        pr, _, _, _, _ = _chain()
        stranger = generate_key_pair()
        result = verify_policy_receipt_envelope(pr, stranger["publicKey"])
        assert result["valid"] is False
        assert result["envelope_signature_valid"] is False

    def test_it_accepts_a_receipt_whose_chain_is_nonsense(self):
        """Deliberate, and the reason the name matters. The envelope check
        does not look at the chain, so a caller reaching for it must be a
        caller that does not need the chain checked."""
        pr, _, verifier_key, _, evaluator = _chain()
        from agent_passport.canonical import canonicalize_for_write
        from agent_passport.crypto import sign
        forged = {**pr, "chain": {"intentSignature": "x", "decisionSignature": "y",
                                  "receiptSignature": "z"}}
        unsigned = {k: v for k, v in forged.items() if k != "signature"}
        forged["signature"] = sign(canonicalize_for_write(unsigned), evaluator["privateKey"])
        assert verify_policy_receipt_envelope(forged, verifier_key)["valid"] is True
        # And the function that does claim the chain refuses it.
        assert verify_policy_receipt(forged, verifier_key)["valid"] is False
