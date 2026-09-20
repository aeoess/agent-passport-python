# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Check the Python aps-action-ref-v2 port against tests/cross_impl/action-ref-v2-vectors.json.

Every case must produce its expected digest, or be rejected with its expected
failure code. Create-entry cases must also produce the recorded canonical input.
The vector file records where each expected value comes from (expected_provenance);
agreement here shows the Python port matches those values, not more.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_passport import (
    ActionReferenceError,
    compute_action_ref_v2,
    compute_action_ref_v2_from_json,
    compute_payload_ref_v1,
    create_action_reference_input_v2,
)

_VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "action-ref-v2-vectors.json").read_text(encoding="utf-8")
)
_CASES = _VECTORS["cases"]


def _profile_context(case):
    """Profile context a case supplies. Draft line 799 puts the permission to carry an
    empty scope_required in a profile rather than in the generic computation, so a case
    that exercises the permitted side says so here."""
    context = case.get("profile_context") or {}
    return {"empty_scope_required_permitted": bool(context.get("emptyScopeRequiredPermitted"))}


def _run(case):
    entry = case["entry"]
    context = _profile_context(case)
    if entry == "payload":
        return compute_payload_ref_v1(case["input"]), None
    if entry == "object":
        return compute_action_ref_v2(case["input"], **context), None
    if entry == "json":
        return compute_action_ref_v2_from_json(case["input_json"], **context), None
    if entry == "create":
        value = create_action_reference_input_v2(**case["create_input"])
        return compute_action_ref_v2(value), value
    raise AssertionError(f"unknown entry {entry!r}")


def test_vector_file_shape():
    assert len(_CASES) == _VECTORS["counts"]["total"]
    assert {c["expected_provenance"] for c in _CASES} <= {
        "draft-derived",
        "ts-conformant-regression",
        "ruling-derived",
    }
    # A ruling-derived case is one the draft names without fixing its outcome. The count
    # is asserted so that silently relabelling one as draft-derived breaks a test.
    assert _VECTORS["counts"]["by_expected_provenance"]["ruling-derived"] == 2
    codes = {row["code"] for row in _VECTORS["failure_codes"]}
    for case in _CASES:
        if case["expected"]["result"] == "reject":
            assert case["expected"]["failure"] in codes, case["id"]


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_vector(case):
    expected = case["expected"]
    if expected["result"] == "accept":
        digest, created = _run(case)
        assert digest == (expected.get("action_ref") or expected["payload_ref"])
        if case["entry"] == "create":
            assert created == expected["canonical_input"]
    else:
        with pytest.raises(ActionReferenceError) as exc_info:
            _run(case)
        assert exc_info.value.code == expected["failure"]
