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


def _run(case):
    entry = case["entry"]
    if entry == "payload":
        return compute_payload_ref_v1(case["input"]), None
    if entry == "object":
        return compute_action_ref_v2(case["input"]), None
    if entry == "json":
        return compute_action_ref_v2_from_json(case["input_json"]), None
    if entry == "create":
        value = create_action_reference_input_v2(**case["create_input"])
        return compute_action_ref_v2(value), value
    raise AssertionError(f"unknown entry {entry!r}")


def test_vector_file_shape():
    assert len(_CASES) == _VECTORS["counts"]["total"]
    assert {c["expected_provenance"] for c in _CASES} <= {"draft-derived", "ts-conformant-regression"}
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
