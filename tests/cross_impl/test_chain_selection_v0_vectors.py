# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Cross-language parity for agent_passport.v2.chain_selection.

The vector file is the TypeScript SDK's own, vendored byte for byte (see
chain-selection-v0-vectors.PROVENANCE.md). Every case's inputs are rebuilt here
and the outcome is compared member for member against what the TypeScript
implementation recorded. A behaviour difference between the two SDKs fails this
test. No Node runs and nothing calls into the TypeScript SDK.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agent_passport.v2.authority_delegation import InMemoryAuthorityBudgetLedger
from agent_passport.v2.chain_selection import (
    CHAIN_SELECTION_EVALUATION_CODES,
    CHAIN_SELECTION_FAILURE_CODES,
    HeldChain,
    RequiredSpendV1,
    select_chain_for_action,
    select_with_fallback,
)

HERE = Path(__file__).resolve().parent
VECTOR_PATH = HERE / "chain-selection-v0-vectors.json"

# Pinned in chain-selection-v0-vectors.PROVENANCE.md. The vendored copy cannot
# drift from the bytes this port was checked against without this failing.
VECTOR_SHA256 = "ccef7e27b6af314a0c49dc3d957579592565b521b9ecacf3d54c5e9b3f82d753"

RAW = VECTOR_PATH.read_bytes()
VECTORS = json.loads(RAW.decode("utf-8"))
LABEL_BY_DELEGATION_ID = {value: key for key, value in VECTORS["delegation_ids"].items()}


def test_vendored_vector_file_matches_its_recorded_digest() -> None:
    assert hashlib.sha256(RAW).hexdigest() == VECTOR_SHA256


def _held_for(case):
    return [
        HeldChain(chain_id=name, chain=[VECTORS["records"][label] for label in VECTORS["chains"][name]])
        for name in case["held"]
    ]


def _resolver_for(case):
    def by_record_label(delegation):
        label = LABEL_BY_DELEGATION_ID.get(delegation.get("delegation_id"))
        answer = case["revocation"].get(label) if label is not None else None
        if answer is None:
            # Fail loud: a case with no declared answer must not read as active.
            raise RuntimeError(f"no revocation answer for {label!r} in {case['id']}")
        return answer

    return by_record_label


def _spend_for(case):
    spend = case["required_spend"]
    if spend is None:
        return None
    return RequiredSpendV1(unit=spend["unit"], amount=spend["amount"], action_ref=spend["action_ref"])


def _run(case):
    shared = dict(
        required_grants=case["required_grants"],
        required_spend=_spend_for(case),
        now=VECTORS["now"],
        resolve_verification_key=lambda _issuer, method, _at: VECTORS["verification_keys"].get(method),
        trust_root=lambda _root: True,
        resolve_revocation=_resolver_for(case),
        # A fresh ledger per case, so a reservation never leaks between cases.
        reserve_budget=None if case["ledger"] == "none" else InMemoryAuthorityBudgetLedger(),
    )
    if case["api"] == "selectChainForAction":
        return select_chain_for_action(_held_for(case), **shared)
    return select_with_fallback(
        _held_for(case),
        preferred_chain_id=case["preferred_chain_id"],
        fallback=case["fallback"],
        **shared,
    )


def _flatten(outcome):
    flat = {
        "selected": outcome.selected,
        "evaluations": [
            {
                "chain_id": item.chain_id,
                "outcome": item.outcome,
                "code": item.code,
                "chain_state": item.chain_state,
            }
            for item in outcome.evaluations
        ],
    }
    if outcome.selected:
        flat["chain_id"] = outcome.chain_id
        flat["state"] = outcome.result.state
        if outcome.switched_from is not None:
            flat["switched_from"] = outcome.switched_from
        if outcome.fallback_ref is not None:
            flat["fallback_ref"] = outcome.fallback_ref
    else:
        flat["code"] = outcome.code
    if outcome.fallback_considered is not None:
        flat["fallback_considered"] = outcome.fallback_considered
    return flat


def test_every_recorded_case_reproduces() -> None:
    assert len(VECTORS["cases"]) == 19
    for case in VECTORS["cases"]:
        assert _flatten(_run(case)) == case["expected"], case["id"]


def test_every_recorded_code_is_a_declared_code() -> None:
    own = set(CHAIN_SELECTION_EVALUATION_CODES) | set(CHAIN_SELECTION_FAILURE_CODES)
    # Codes the chain verifier and the ledger produce are passed through
    # unchanged, so this list is the set of pass-throughs the vectors exercise,
    # not a second vocabulary.
    passthrough = {"REVOKED", "REVOCATION_UNKNOWN", "PER_ACTION_EXCEEDED", "RESERVED"}
    for case in VECTORS["cases"]:
        expected = case["expected"]
        if "code" in expected:
            assert expected["code"] in own, case["id"]
        for evaluation in expected["evaluations"]:
            assert evaluation["code"] in own or evaluation["code"] in passthrough, case["id"]
