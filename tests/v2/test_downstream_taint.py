# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Downstream taint cascade — Module 4.

Two test sections:
  1. Unit tests covering predicate + cascade BFS + cycles.
  2. Cross-impl byte-parity using TS-generated fixtures.
"""

import hashlib
import json
from pathlib import Path

import pytest

from agent_passport import (
    ContestabilityControllerResponse,
    ContestabilityReceipt,
    GroundsClass,
    RecordType,
    TaintCandidate,
    canonicalize,
    compute_downstream_taint,
    is_contestation_tainting,
)

ACTION_ID = "action_001"

FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "evidentiary-type-safety" / "fixtures.json"
)


def _make_contestation(status, receipt_id="contest_001", action_id=ACTION_ID):
    response = (
        ContestabilityControllerResponse(status=status) if status is not None else None
    )
    return ContestabilityReceipt(
        receipt_id=receipt_id,
        action_id=action_id,
        controller_response=response,
    )


def _load_fixtures():
    with FIXTURE_PATH.open() as f:
        return json.load(f)


# ── is_contestation_tainting ──


def test_is_tainting_filed():
    assert is_contestation_tainting(_make_contestation("filed")) is False


def test_is_tainting_upheld():
    assert is_contestation_tainting(_make_contestation("upheld")) is True


def test_is_tainting_remedied():
    assert is_contestation_tainting(_make_contestation("remedied")) is True


def test_is_tainting_rejected():
    assert is_contestation_tainting(_make_contestation("rejected")) is False


def test_is_tainting_no_controller_response():
    assert is_contestation_tainting(_make_contestation(None)) is False


# ── compute_downstream_taint ──


def test_taint_returns_none_for_non_tainting():
    result = compute_downstream_taint(
        _make_contestation("filed"),
        [
            TaintCandidate(
                receipt_id="decision_001",
                record_type=RecordType.DecisionReceipt,
                references=[ACTION_ID],
            )
        ],
    )
    assert result is None


def test_taint_direct_reference_depth_1():
    result = compute_downstream_taint(
        _make_contestation("upheld"),
        [
            TaintCandidate(
                receipt_id="decision_001",
                record_type=RecordType.DecisionReceipt,
                references=[ACTION_ID],
            )
        ],
    )
    assert result is not None
    assert len(result.tainted) == 1
    assert result.tainted[0].receipt_id == "decision_001"
    assert result.tainted[0].taint_depth == 1


def test_taint_transitive_depth_2():
    result = compute_downstream_taint(
        _make_contestation("upheld"),
        [
            TaintCandidate(
                receipt_id="A",
                record_type=RecordType.DecisionReceipt,
                references=[ACTION_ID],
            ),
            TaintCandidate(
                receipt_id="B",
                record_type=RecordType.DerivationReceipt,
                references=["A"],
            ),
        ],
    )
    assert result is not None
    assert len(result.tainted) == 2
    by_id = {t.receipt_id: t for t in result.tainted}
    assert by_id["A"].taint_depth == 1
    assert by_id["B"].taint_depth == 2


def test_taint_no_false_positives():
    result = compute_downstream_taint(
        _make_contestation("upheld"),
        [
            TaintCandidate(
                receipt_id="tainted",
                record_type=RecordType.DecisionReceipt,
                references=[ACTION_ID],
            ),
            TaintCandidate(
                receipt_id="clean",
                record_type=RecordType.ActionReceipt,
                references=["action_999"],
            ),
        ],
    )
    assert result is not None
    assert len(result.tainted) == 1
    assert result.tainted[0].receipt_id == "tainted"


def test_taint_cycle_neither_references_action():
    result = compute_downstream_taint(
        _make_contestation("upheld"),
        [
            TaintCandidate(
                receipt_id="A", record_type=RecordType.DecisionReceipt, references=["B"]
            ),
            TaintCandidate(
                receipt_id="B",
                record_type=RecordType.DerivationReceipt,
                references=["A"],
            ),
        ],
    )
    assert result is not None
    assert result.tainted == []


def test_taint_cycle_with_action_root_both_tainted():
    result = compute_downstream_taint(
        _make_contestation("upheld"),
        [
            TaintCandidate(
                receipt_id="A",
                record_type=RecordType.DecisionReceipt,
                references=[ACTION_ID, "B"],
            ),
            TaintCandidate(
                receipt_id="B",
                record_type=RecordType.DerivationReceipt,
                references=["A"],
            ),
        ],
    )
    assert result is not None
    assert len(result.tainted) == 2
    by_id = {t.receipt_id: t for t in result.tainted}
    assert by_id["A"].taint_depth == 1
    assert by_id["B"].taint_depth == 2


def test_root_fields_surface_on_tainted_set():
    result = compute_downstream_taint(_make_contestation("upheld"), [])
    assert result is not None
    assert result.root_action_id == ACTION_ID
    assert result.root_contestation_id == "contest_001"
    assert result.tainted == []


# ── grounds_class round-trip on the minimal ContestabilityReceipt ──


def test_grounds_class_round_trips_on_minimal_receipt():
    """Wave 1 accountability defers; the minimal Python ContestabilityReceipt
    still carries grounds_class so callers can route on it.
    """
    c = ContestabilityReceipt(
        receipt_id="contest_001",
        action_id=ACTION_ID,
        controller_response=ContestabilityControllerResponse(status="upheld"),
        grounds_class=GroundsClass.EVIDENCE_INSUFFICIENT,
    )
    assert c.grounds_class == GroundsClass.EVIDENCE_INSUFFICIENT
    assert c.grounds_class.value == "evidence_insufficient"
    # Cascade still fires.
    assert is_contestation_tainting(c) is True


# ── Cross-impl byte-parity ──

CASCADE_FIXTURES = _load_fixtures()["cascade_scenarios"]


def _ts_to_python_taint_candidate(c):
    return TaintCandidate(
        receipt_id=c["receiptId"],
        record_type=RecordType(c["recordType"]),
        references=c.get("references", []),
    )


def _ts_to_python_contestation(c):
    response = c.get("controller_response")
    return ContestabilityReceipt(
        receipt_id=c["receipt_id"],
        action_id=c["action_id"],
        controller_response=(
            ContestabilityControllerResponse(status=response["status"])
            if response is not None
            else None
        ),
    )


def _tainted_set_to_canonical_dict(tset):
    """Map the Python TaintedSet to the dict shape TS produces.

    TS field names are camelCase; Python's are snake_case. Translate
    snake_case → camelCase here so canonical JSON matches.
    """
    if tset is None:
        return None
    return {
        "rootActionId": tset.root_action_id,
        "rootContestationId": tset.root_contestation_id,
        "tainted": [
            {
                "receiptId": t.receipt_id,
                "recordType": t.record_type.value,
                "taintReason": t.taint_reason,
                "taintDepth": t.taint_depth,
            }
            for t in tset.tainted
        ],
    }


@pytest.mark.parametrize(
    "fixture",
    CASCADE_FIXTURES,
    ids=[f["name"] for f in CASCADE_FIXTURES],
)
def test_cascade_byte_parity_with_ts(fixture):
    contestation = _ts_to_python_contestation(fixture["contestation"])
    candidates = [
        _ts_to_python_taint_candidate(c) for c in fixture["candidates"]
    ]

    # is_contestation_tainting agrees with TS.
    assert is_contestation_tainting(contestation) == fixture["isTainting"], (
        f"is_contestation_tainting drift for {fixture['name']}"
    )

    # compute_downstream_taint output canonicalizes byte-identical to TS.
    result = compute_downstream_taint(contestation, candidates)
    canon_input = _tainted_set_to_canonical_dict(result)
    canonical = canonicalize(canon_input)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    assert canonical == fixture["canonicalJson"], (
        f"canonical JSON drift for {fixture['name']}\n"
        f"  python: {canonical}\n"
        f"  ts:     {fixture['canonicalJson']}"
    )
    assert digest == fixture["canonicalSha256"], (
        f"sha256 drift for {fixture['name']}\n"
        f"  python: {digest}\n"
        f"  ts:     {fixture['canonicalSha256']}"
    )
