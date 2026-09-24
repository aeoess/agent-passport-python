# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""agent_passport.v2.chain_selection: the properties a vector table cannot state.

The recorded cross-language vectors live in
tests/cross_impl/test_chain_selection_v0_vectors.py. This file covers what those
cannot: that no second chain is reachable from a decision, that a refusal leaves
no reservation behind, and that neither entry point raises on hostile input.
"""

from __future__ import annotations

import hashlib

import agent_passport
from agent_passport.crypto import public_key_from_private
from agent_passport.v2.authority_delegation import (
    InMemoryAuthorityBudgetLedger,
    issue_authority_delegation,
)
from agent_passport.v2.chain_selection import (
    HeldChain,
    RequiredSpendV1,
    select_chain_for_action,
    select_with_fallback,
)

SEED = hashlib.sha256(b"agent-passport-system:chain-selection-test:p").hexdigest()
PUBLIC_KEY = public_key_from_private(SEED)
ISSUER = "did:example:chain-selection-test-root"
VM = f"{ISSUER}#key-1"
NOW = "2026-03-15T00:00:00.000Z"
UNIT = "iso4217:USD:minor"


def mint(grants, ceiling, nonce):
    return issue_authority_delegation(
        {
            "record_type": "aps:authority-delegation:v1",
            "version": "1.0",
            "parent_delegation_id": None,
            "issuer": ISSUER,
            "subject": "did:example:chain-selection-test-leaf",
            "verification_method": VM,
            "issued_at": "2026-03-01T00:00:00.000Z",
            "nonce": nonce,
            "authority": {
                "scope": {"profile": "aps-hierarchical-v1", "grants": grants},
                "spend": {"mode": "bounded", "unit": UNIT, "per_action": ceiling, "cumulative": ceiling},
                "depth": {"remaining": 1},
                "time": {"not_before": "2026-03-01T00:00:00.000Z", "not_after": "2026-04-01T00:00:00.000Z"},
                "reputation": {"profile": "aps-score-0-100-v1", "ceiling": 100},
                "values": {"profile": "aps-values-identifiers-v1", "required": []},
                "reversibility": {"profile": "aps-tci-v1", "ceiling": "irreversible"},
            },
        },
        SEED,
    )


def options(resolve_revocation=None):
    return dict(
        now=NOW,
        resolve_verification_key=lambda _issuer, method, _at: PUBLIC_KEY if method == VM else None,
        trust_root=lambda _root: True,
        resolve_revocation=resolve_revocation or (lambda _delegation: "active"),
    )


def test_the_selection_surface_is_importable_from_the_package_root():
    # Release check, not a unit test. A symbol implemented under src but absent
    # from the package root is not reachable the way consumers import it.
    assert callable(agent_passport.select_chain_for_action)
    assert callable(agent_passport.select_with_fallback)
    assert agent_passport.HELD_SET_CEILING == 256


def test_a_refused_selection_reserves_nothing_against_any_chain():
    a = mint(["resource1:read"], "5", "00000000000000000000000000000001")
    b = mint(["resource1:read"], "5", "00000000000000000000000000000002")
    ledger = InMemoryAuthorityBudgetLedger()
    outcome = select_chain_for_action(
        [HeldChain("a", [a]), HeldChain("b", [b])],
        required_grants=["resource1:read"],
        required_spend=RequiredSpendV1(unit=UNIT, amount="8", action_ref="a" * 64),
        reserve_budget=ledger,
        **options(),
    )
    assert outcome.selected is False
    # Neither chain's counter moved: a refusal is not a partial reservation, and
    # the second chain was never reached, so its ceiling could not have been
    # added to the first.
    assert ledger.counter(a["delegation_id"]) == {"reserved": "0", "committed": "0"}
    assert ledger.counter(b["delegation_id"]) == {"reserved": "0", "committed": "0"}


def test_a_selection_reserves_against_exactly_one_chain():
    a = mint(["resource1:read"], "5", "00000000000000000000000000000003")
    b = mint(["resource1:read"], "5", "00000000000000000000000000000004")
    ledger = InMemoryAuthorityBudgetLedger()
    outcome = select_chain_for_action(
        [HeldChain("a", [a]), HeldChain("b", [b])],
        required_grants=["resource1:read"],
        required_spend=RequiredSpendV1(unit=UNIT, amount="4", action_ref="b" * 64),
        reserve_budget=ledger,
        **options(),
    )
    assert outcome.selected is True
    assert outcome.chain_id == "a"
    assert ledger.counter(a["delegation_id"]) == {"reserved": "4", "committed": "0"}
    assert ledger.counter(b["delegation_id"]) == {"reserved": "0", "committed": "0"}


def test_fallback_none_never_hands_a_second_chain_to_any_callback():
    a = mint(["resource1:read"], "5", "00000000000000000000000000000005")
    b = mint(["resource1:read"], "5", "00000000000000000000000000000006")
    seen = []

    def resolve_revocation(delegation):
        seen.append(delegation["delegation_id"])
        return "revoked"

    outcome = select_with_fallback(
        [HeldChain("a", [a]), HeldChain("b", [b])],
        preferred_chain_id="a",
        fallback=None,
        required_grants=["resource1:read"],
        **options(resolve_revocation),
    )
    assert outcome.selected is False
    assert outcome.code == "no_valid_chain"
    assert outcome.fallback_considered is False
    assert seen == [a["delegation_id"]]
    assert len(outcome.evaluations) == 1


def test_an_authorized_fallback_names_what_it_switched_from():
    a = mint(["resource1:read"], "5", "00000000000000000000000000000007")
    b = mint(["resource1:read"], "5", "00000000000000000000000000000008")
    outcome = select_with_fallback(
        [HeldChain("a", [a]), HeldChain("b", [b])],
        preferred_chain_id="a",
        fallback={"authorization_ref": "opaque-ref"},
        required_grants=["resource1:read"],
        **options(lambda delegation: "revoked" if delegation["delegation_id"] == a["delegation_id"] else "active"),
    )
    assert outcome.selected is True
    assert outcome.chain_id == "b"
    assert outcome.switched_from == "a"
    assert outcome.fallback_ref == "opaque-ref"
    # The reason the action left its selected chain stays in the record even
    # though the fallback succeeded. A later finding does not rewrite an earlier one.
    assert outcome.evaluations[0].chain_id == "a"
    assert outcome.evaluations[0].code == "REVOKED"


def test_an_authorization_with_no_usable_reference_does_not_switch():
    a = mint(["resource1:read"], "5", "00000000000000000000000000000009")
    b = mint(["resource1:read"], "5", "0000000000000000000000000000000a")
    outcome = select_with_fallback(
        [HeldChain("a", [a]), HeldChain("b", [b])],
        preferred_chain_id="a",
        fallback={"authorization_ref": ""},
        required_grants=["resource1:read"],
        **options(lambda _delegation: "revoked"),
    )
    assert outcome.selected is False
    assert outcome.code == "invalid_action_requirement"


def test_neither_entry_point_raises_on_hostile_input():
    hostile = [
        None,
        "not-a-list",
        [],
        [{"chain_id": "a"}],
        [{"chain_id": "", "chain": []}],
        [HeldChain("a", [])],
        [HeldChain("a", [{}])],
        [HeldChain("a", [])] * 300,
    ]
    for held in hostile:
        first = select_chain_for_action(held, required_grants=["x:y"], **options())
        assert isinstance(first.selected, bool)
        second = select_with_fallback(
            held, preferred_chain_id="a", fallback=None, required_grants=["x:y"], **options()
        )
        assert isinstance(second.selected, bool)


def test_a_caller_mutating_its_own_chain_after_the_call_changes_nothing():
    a = mint(["resource1:read"], "5", "0000000000000000000000000000000b")
    chain = [dict(a)]
    outcome = select_chain_for_action(
        [HeldChain("a", chain)],
        required_grants=["resource1:read"],
        **options(),
    )
    assert outcome.selected is True
    chain[0]["subject"] = "did:example:someone-else"
    assert outcome.chain_id == "a"
    assert outcome.result.state == "valid"
