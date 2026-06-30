# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""trace_beneficiary parity tests: verified is real ed25519 (not a lookup), resolved is the
lookup, lineage reporting is deterministic and tied to receipt.delegationId. Mirrors the
TypeScript beneficiary-verified-honesty + determinism cases."""
from agent_passport import (
    create_action_receipt,
    create_delegation,
    generate_key_pair,
    trace_beneficiary,
)

HUMAN = generate_key_pair()
AGENT = generate_key_pair()


def _delegation(by=None, to=None, by_priv=None, scope=None, days=30):
    return create_delegation(
        delegated_by=by or HUMAN["publicKey"],
        delegated_to=to or AGENT["publicKey"],
        scope=scope or ["code_execution"],
        private_key=by_priv or HUMAN["privateKey"],
        spend_limit=1000,
        expires_in_days=days,
    )


def _receipt(delegation, signer_priv, chain, spend=10):
    return create_action_receipt(
        agent_id="agent-a",
        delegation=delegation,
        action_type="execute",
        target="task",
        scope_used="code_execution",
        result_status="success",
        result_summary="done",
        private_key=signer_priv,
        spend_amount=spend,
        delegation_chain=chain,
    )


def test_legit_trace_is_resolved_and_verified():
    d = _delegation()
    rc = _receipt(d, AGENT["privateKey"], [HUMAN["publicKey"], AGENT["publicKey"]])
    t = trace_beneficiary(rc, [d], {HUMAN["publicKey"]: {"principalId": "tymofii"}})
    assert t["beneficiary"] == "tymofii"
    assert t["resolved"] is True
    assert t["verified"] is True
    assert t["totalDepth"] == 1


def test_unknown_beneficiary_drives_resolved_not_verified():
    d = _delegation()
    rc = _receipt(d, AGENT["privateKey"], [HUMAN["publicKey"], AGENT["publicKey"]])
    t = trace_beneficiary(rc, [d], {})
    assert t["resolved"] is False  # no known beneficiary
    assert t["verified"] is True   # crypto holds regardless of the label map


def test_forged_chain_resolves_but_does_not_verify():
    attacker = generate_key_pair()
    # Forged: claims the human delegated to the attacker, but only the attacker signed it.
    forged = _delegation(by=HUMAN["publicKey"], to=attacker["publicKey"], by_priv=attacker["privateKey"])
    # Attacker's own self-delegation so create_action_receipt will sign a receipt.
    selfd = _delegation(by=attacker["publicKey"], to=attacker["publicKey"], by_priv=attacker["privateKey"])
    rc = _receipt(selfd, attacker["privateKey"], [HUMAN["publicKey"], attacker["publicKey"]], spend=1)
    t = trace_beneficiary(rc, [forged], {HUMAN["publicKey"]: {"principalId": "tymofii"}})
    assert t["resolved"] is True
    assert t["verified"] is False  # forged hop fails verify_delegation


def test_tampered_receipt_does_not_verify():
    d = _delegation()
    rc = _receipt(d, AGENT["privateKey"], [HUMAN["publicKey"], AGENT["publicKey"]])
    rc["action"]["spend"]["amount"] = 999999  # mutate after signing
    t = trace_beneficiary(rc, [d], {HUMAN["publicKey"]: {"principalId": "tymofii"}})
    assert t["verified"] is False


def test_cannot_verify_without_delegation_records():
    d = _delegation()
    rc = _receipt(d, AGENT["privateKey"], [HUMAN["publicKey"], AGENT["publicKey"]])
    t = trace_beneficiary(rc, [], {HUMAN["publicKey"]: {"principalId": "tymofii"}})
    assert t["resolved"] is False
    assert t["verified"] is False


def test_expired_delegation_resolves_but_does_not_verify():
    agent_exp = generate_key_pair()
    expired = _delegation(by=HUMAN["publicKey"], to=agent_exp["publicKey"], by_priv=HUMAN["privateKey"], days=-1)
    selfd = _delegation(by=agent_exp["publicKey"], to=agent_exp["publicKey"], by_priv=agent_exp["privateKey"])
    rc = _receipt(selfd, agent_exp["privateKey"], [HUMAN["publicKey"], agent_exp["publicKey"]], spend=1)
    t = trace_beneficiary(rc, [expired], {HUMAN["publicKey"]: {"principalId": "tymofii"}})
    assert t["resolved"] is True
    assert t["verified"] is False


def test_tail_reports_receipt_delegation_id_deterministically():
    # Two valid delegations for the SAME (human -> agent) pair (a re-issue).
    d_old = _delegation()
    d_new = _delegation()
    assert d_old["delegationId"] != d_new["delegationId"]
    rc = _receipt(d_new, AGENT["privateKey"], [HUMAN["publicKey"], AGENT["publicKey"]])  # issued under d_new
    bmap = {HUMAN["publicKey"]: {"principalId": "tymofii"}}
    t1 = trace_beneficiary(rc, [d_old, d_new], bmap)
    t2 = trace_beneficiary(rc, [d_new, d_old], bmap)  # shuffled input order
    assert t1["chain"][-1]["delegationId"] == rc["delegationId"]
    assert t2["chain"][-1]["delegationId"] == rc["delegationId"]
    assert t1["chain"] == t2["chain"]  # deterministic regardless of array order
    assert t1["verified"] is True and t2["verified"] is True


def test_reissued_after_expiry_still_verifies_even_with_expired_duplicate_first():
    agent2 = generate_key_pair()
    expired_old = _delegation(by=HUMAN["publicKey"], to=agent2["publicKey"], by_priv=HUMAN["privateKey"], days=-1)
    fresh_new = _delegation(by=HUMAN["publicKey"], to=agent2["publicKey"], by_priv=HUMAN["privateKey"])
    rc = _receipt(fresh_new, agent2["privateKey"], [HUMAN["publicKey"], agent2["publicKey"]])
    t = trace_beneficiary(rc, [expired_old, fresh_new], {HUMAN["publicKey"]: {"principalId": "tymofii"}})
    assert t["verified"] is True  # a valid delegation exists for the hop -> no false-negative
    assert t["chain"][-1]["delegationId"] == fresh_new["delegationId"]
