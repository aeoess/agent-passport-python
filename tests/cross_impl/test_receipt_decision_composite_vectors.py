"""Replay the composite receipt-and-decision vectors against this implementation.

Every case in the vector file carries the TypeScript reference's own result object for the
inputs it names, recorded verbatim by
tests/cross_impl/gen_receipt_decision_composite_vectors.mts. This module runs the Python
composite verifier over the same inputs and asserts the two results are equal field for
field, key order ignored.

What a passing run establishes: the two implementations return the same object for these
inputs. It is not a draft-conformance claim. The draft-derived surface for receipts lives in
receipt-v1-stage-vectors.json, whose generator fixes every expectation from the draft text
independently of what TypeScript returns.

The opt-in mapping is the thing this file exists to pin. The reference reads own-property
presence on its options object; this port reads a module-private sentinel default. A case
whose `predecessor_supplied` is false omits the argument here and passes no property there.
A case whose `predecessor_id` is "undefined" or "null" passes two different JavaScript values
that both map to Python None, and both must come back `not_established`.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_passport.receipt_core import verify_receipt_with_decision_v1

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "receipt-decision-composite-vectors.json").read_text(encoding="utf-8")
)
CASES = VECTORS["cases"]
RESOLVER_KEYS = VECTORS["resolver_keys"]


def resolve_key(signer, key_id, issued_at):
    """The resolver the vector conventions name: the fixture's published verification key for
    a key_id it carries, and nothing for one it does not."""
    return RESOLVER_KEYS.get(key_id)


def test_vector_file_is_self_describing() -> None:
    counts = VECTORS["counts"]
    assert counts["total"] == len(CASES)
    assert counts["total"] == counts["records"] * counts["evidences"] * counts["predecessor_variants"]
    assert VECTORS["generated_from"]["repository"] == "agent-passport-system"
    assert VECTORS["records_from"]["family"].endswith("chain.json")
    for case in CASES:
        assert case["id"], case
        assert set(case["expected"]) == {
            "valid", "status", "receipt", "stage", "decision_ref_present", "decision_ref_bound",
            "decision_output_bound", "temporal_relation_valid", "predecessor_bound", "errors",
        }, case["id"]


def test_every_predecessor_state_is_represented() -> None:
    # A vector file that lost the not_established or the decided-boolean cases would still
    # pass every case below while establishing nothing about the axis this work adds.
    states = {case["expected"]["predecessor_bound"] for case in CASES}
    assert states == {"not_checked", "not_applicable", "not_established", True, False}
    statuses = {case["expected"]["status"] for case in CASES}
    assert statuses == {"valid", "invalid", "indeterminate"}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_composite_vector(case: dict) -> None:
    kwargs = {"boundary_identity": case["boundary_identity"]}
    if case["predecessor_supplied"]:
        # TypeScript's undefined and null are two distinct values in that language and one
        # value here. Both are an opt-in that supplied no record, so both pass None.
        kwargs["predecessor"] = case["predecessor_value"]

    result = verify_receipt_with_decision_v1(case["record"], case["evidence"], resolve_key, **kwargs)
    assert result == case["expected"], case["id"]
