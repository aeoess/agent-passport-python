# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Downstream Taint (Module 4 of the Evidentiary Type Safety set).

Mirrors src/v2/downstream-taint.ts in the TypeScript SDK at
agent-passport-system 2.6.0-alpha.0.

Public cascade primitive per DECISIONS.md 2026-05-02 Option B.
The closure ships in the public SDK so the gateway, third-party
verifiers, and external auditors all consume the same logic.
This module is pure: no I/O, no aggregation, no signing, no key
resolution. The caller surfaces the candidate reference graph;
the function computes the transitive closure of receipts
downstream of an upheld or remedied contestation.

The reference shape is deliberately abstract. A candidate
declares which other receipt_ids it references — by action_id,
parent_receipt_id, derived_from, or any other field name. The
SDK does not introspect receipt internals here; it walks the
graph the caller provides.

History note: 2.4.0a0 shipped a minimal ContestabilityReceipt stub
inline in this module while Wave 1 accountability was TypeScript-only.
2.4.0a1 ships the full Wave 1 surface in v2.accountability; this
module now imports the full receipt + response shapes from there.
The cascade contract is unchanged.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from .accountability import (
    ContestabilityControllerResponse,
    ContestabilityReceipt,
    ContestStatus,
    GroundsClass,
)
from .claim_evidence_types import RecordType


def is_contestation_tainting(c: ContestabilityReceipt) -> bool:
    """A contestation taints downstream receipts iff the controller
    has upheld or remedied it.

    Filed and under_review contestations record a dispute but do not
    yet justify cascade. Rejected, expired, and abandoned never taint.
    """
    if c.controller_response is None:
        return False
    return c.controller_response.status in ("upheld", "remedied")


@dataclass
class TaintedRecord:
    """One receipt downstream of a tainting contestation.

    Python attribute names are snake_case per PEP 8; to_canonical_dict
    emits camelCase JSON keys for cross-impl byte-parity with TS.
    """

    receipt_id: str
    record_type: RecordType
    taint_reason: str
    # 1 = direct reference to the contested action_id. 2+ = transitive.
    taint_depth: int

    def to_canonical_dict(self) -> dict:
        """Emit camelCase JSON dict for cross-impl byte-parity with TS."""
        return {
            "receiptId": self.receipt_id,
            "recordType": self.record_type.value
            if isinstance(self.record_type, RecordType)
            else self.record_type,
            "taintReason": self.taint_reason,
            "taintDepth": self.taint_depth,
        }


@dataclass
class TaintedSet:
    """Result of computing the cascade closure.

    Python attribute names are snake_case per PEP 8; to_canonical_dict
    emits camelCase JSON keys for cross-impl byte-parity with TS.
    """

    root_action_id: str
    root_contestation_id: str
    tainted: List[TaintedRecord] = field(default_factory=list)

    def to_canonical_dict(self) -> dict:
        """Emit camelCase JSON dict for cross-impl byte-parity with TS."""
        return {
            "rootActionId": self.root_action_id,
            "rootContestationId": self.root_contestation_id,
            "tainted": [t.to_canonical_dict() for t in self.tainted],
        }


@dataclass
class TaintCandidate:
    """One candidate receipt the caller offers to the cascade.

    The caller decides which of its own fields qualify as references.
    """

    receipt_id: str
    record_type: RecordType
    references: List[str] = field(default_factory=list)


def compute_downstream_taint(
    contestation: ContestabilityReceipt,
    candidates: List[TaintCandidate],
) -> Optional[TaintedSet]:
    """Compute the transitive closure of receipts downstream of an
    upheld or remedied contestation.

    Returns None if the contestation does not taint (filed,
    under_review, rejected, expired, abandoned, or absent
    controller_response). Otherwise returns a TaintedSet with
    `tainted` containing every candidate that directly or
    transitively references the contested action_id, with
    `taint_depth` recording BFS distance.

    Cycle handling: dedup via a seen set. A → B → A → action_id
    will mark every node visited at its first observed depth and
    not re-add later.
    """
    if not is_contestation_tainting(contestation):
        return None

    root_action_id = contestation.action_id
    tainted_map: dict[str, TaintedRecord] = {}
    frontier: List[TaintedRecord] = []

    # Depth 1: candidates whose references include the contested action_id.
    for c in candidates:
        if root_action_id in c.references:
            t = TaintedRecord(
                receipt_id=c.receipt_id,
                record_type=c.record_type,
                taint_reason=f"Directly references contested action {root_action_id}",
                taint_depth=1,
            )
            tainted_map[c.receipt_id] = t
            frontier.append(t)

    # Depth 2+: BFS expansion.
    while frontier:
        next_frontier: List[TaintedRecord] = []
        for parent in frontier:
            for c in candidates:
                if c.receipt_id in tainted_map:
                    continue
                if parent.receipt_id in c.references:
                    t = TaintedRecord(
                        receipt_id=c.receipt_id,
                        record_type=c.record_type,
                        taint_reason=(
                            f"Transitively references tainted receipt {parent.receipt_id}"
                        ),
                        taint_depth=parent.taint_depth + 1,
                    )
                    tainted_map[c.receipt_id] = t
                    next_frontier.append(t)
        frontier = next_frontier

    return TaintedSet(
        root_action_id=root_action_id,
        root_contestation_id=contestation.receipt_id,
        tainted=list(tainted_map.values()),
    )
