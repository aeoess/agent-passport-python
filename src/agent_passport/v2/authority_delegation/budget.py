# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""In-memory authority budget ledger.

Python port of the TypeScript SDK's src/v2/authority-delegation/budget.ts.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from .canonical import authority_delegation_body, compute_authority_delegation_id
from .schema import is_canonical_quantity, validate_authority_delegation_shape
from .types import BudgetOperationResult

_ACTION_REF = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class _Counter:
    reserved: int = 0
    committed: int = 0


@dataclass
class _Reservation:
    action_ref: str
    unit: str
    amount: int
    delegation_ids: list = field(default_factory=list)
    state: str = "reserved"


class InMemoryAuthorityBudgetLedger:
    """Reference linearizable ledger for one Python process.

    The TypeScript class relies on JavaScript being single-threaded, so each
    of its methods is already one implicit critical section. Python is not
    single-threaded in the same sense, so this port guards each public method
    with one lock, making each mutation one explicit critical section.
    Distributed deployments must replace this with a store providing the same
    all-ancestors atomicity and idempotency.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, _Counter] = {}
        self._reservations: dict[str, _Reservation] = {}

    def reserve(self, verified_chain, action_ref: str, unit: str, amount_string: str) -> BudgetOperationResult:
        with self._lock:
            if (
                type(action_ref) is not str
                or not _ACTION_REF.fullmatch(action_ref)
                or type(unit) is not str
                or not is_canonical_quantity(amount_string)
            ):
                return BudgetOperationResult(ok=False, code="CONFLICT")
            # Identity tests, never a tuple membership test: see verify.py.
            if type(verified_chain) is not list and type(verified_chain) is not tuple:
                return BudgetOperationResult(ok=False, code="CONFLICT")
            # Provisional: the draft does not state a maximum chain length.
            # This 256-record limit is kept identical to the TypeScript SDK
            # and to verify.py's own chain-length check, pending a protocol
            # ruling.
            length = len(verified_chain)
            if length == 0 or length > 256:
                return BudgetOperationResult(ok=False, code="CONFLICT")

            seen: set[str] = set()
            for i in range(length):
                current = verified_chain[i]
                if (
                    validate_authority_delegation_shape(current)
                    or compute_authority_delegation_id(authority_delegation_body(current)) != current["delegation_id"]
                    or current["delegation_id"] in seen
                ):
                    return BudgetOperationResult(ok=False, code="CONFLICT")
                seen.add(current["delegation_id"])
                if i == 0:
                    if current["parent_delegation_id"] is not None:
                        return BudgetOperationResult(ok=False, code="CONFLICT")
                else:
                    parent = verified_chain[i - 1]
                    if current["parent_delegation_id"] != parent["delegation_id"] or current["issuer"] != parent["subject"]:
                        return BudgetOperationResult(ok=False, code="CONFLICT")

            amount = int(amount_string)
            bounded = [item for item in verified_chain if item["authority"]["spend"]["mode"] == "bounded"]
            ids = [item["delegation_id"] for item in bounded]

            # A cancelled reservation holds nothing: its amount was released from
            # every bounded ancestor's counter. Reporting a retry of it as idempotent
            # would tell a boundary that the amount is reserved when no counter holds
            # it, and two such calls could dispatch twice against one signed
            # cumulative ceiling, which draft-pidlisnyi-aps-03 lines 602-607 require
            # to be reserved "against every bounded ancestor or against none". A call
            # naming a cancelled action_ref is therefore treated as the fresh
            # reservation it is: every limit is checked again and the cancelled record
            # is replaced. Provisional: the draft says only that an identical retry is
            # idempotent and conflicting reuse is rejected (lines 621-622), and does
            # not say which of those a retry after cancellation is, so refusing it
            # outright would be defensible too. This choice keeps a boundary able to
            # retry after releasing, and it can never report a reservation it does not
            # hold. Pending a protocol ruling. The TypeScript SDK makes the same
            # choice.
            prior = self._reservations.get(action_ref)
            if prior is not None and prior.state != "cancelled":
                identical = prior.unit == unit and prior.amount == amount and prior.delegation_ids == ids
                if identical:
                    return BudgetOperationResult(ok=True, code="IDEMPOTENT", state=prior.state)
                return BudgetOperationResult(ok=False, code="CONFLICT", state=prior.state)

            for delegation in bounded:
                spend = delegation["authority"]["spend"]
                if spend["unit"] != unit:
                    return BudgetOperationResult(ok=False, code="UNIT_MISMATCH")
                if amount > int(spend["per_action"]):
                    return BudgetOperationResult(ok=False, code="PER_ACTION_EXCEEDED")
                counter = self._counters.get(delegation["delegation_id"], _Counter())
                if counter.reserved + counter.committed + amount > int(spend["cumulative"]):
                    return BudgetOperationResult(ok=False, code="CUMULATIVE_EXCEEDED")

            # All checks completed before any counter is changed.
            for delegation in bounded:
                delegation_id = delegation["delegation_id"]
                counter = self._counters.get(delegation_id)
                if counter is None:
                    counter = _Counter()
                    self._counters[delegation_id] = counter
                counter.reserved += amount

            self._reservations[action_ref] = _Reservation(
                action_ref=action_ref, unit=unit, amount=amount, delegation_ids=ids, state="reserved",
            )
            return BudgetOperationResult(ok=True, code="RESERVED", state="reserved")

    def mark_dispatched(self, action_ref: str) -> BudgetOperationResult:
        with self._lock:
            if type(action_ref) is not str:
                return BudgetOperationResult(ok=False, code="NOT_FOUND")
            reservation = self._reservations.get(action_ref)
            if reservation is None:
                return BudgetOperationResult(ok=False, code="NOT_FOUND")
            if reservation.state == "dispatched":
                return BudgetOperationResult(ok=True, code="IDEMPOTENT", state="dispatched")
            if reservation.state != "reserved":
                return BudgetOperationResult(ok=False, code="INVALID_STATE", state=reservation.state)
            reservation.state = "dispatched"
            return BudgetOperationResult(ok=True, code="DISPATCHED", state="dispatched")

    def commit(self, action_ref: str) -> BudgetOperationResult:
        with self._lock:
            if type(action_ref) is not str:
                return BudgetOperationResult(ok=False, code="NOT_FOUND")
            reservation = self._reservations.get(action_ref)
            if reservation is None:
                return BudgetOperationResult(ok=False, code="NOT_FOUND")
            if reservation.state == "committed":
                return BudgetOperationResult(ok=True, code="IDEMPOTENT", state="committed")
            if reservation.state not in ("reserved", "dispatched"):
                return BudgetOperationResult(ok=False, code="INVALID_STATE", state=reservation.state)
            for delegation_id in reservation.delegation_ids:
                counter = self._counters.get(delegation_id)
                if counter is None or counter.reserved < reservation.amount:
                    return BudgetOperationResult(ok=False, code="INVALID_STATE", state=reservation.state)
            for delegation_id in reservation.delegation_ids:
                counter = self._counters[delegation_id]
                counter.reserved -= reservation.amount
                counter.committed += reservation.amount
            reservation.state = "committed"
            return BudgetOperationResult(ok=True, code="COMMITTED", state="committed")

    def cancel(self, action_ref: str) -> BudgetOperationResult:
        """Cancellation is allowed only before dispatch."""
        with self._lock:
            if type(action_ref) is not str:
                return BudgetOperationResult(ok=False, code="NOT_FOUND")
            reservation = self._reservations.get(action_ref)
            if reservation is None:
                return BudgetOperationResult(ok=False, code="NOT_FOUND")
            if reservation.state == "cancelled":
                return BudgetOperationResult(ok=True, code="IDEMPOTENT", state="cancelled")
            if reservation.state != "reserved":
                return BudgetOperationResult(ok=False, code="INVALID_STATE", state=reservation.state)
            for delegation_id in reservation.delegation_ids:
                counter = self._counters.get(delegation_id)
                if counter is None or counter.reserved < reservation.amount:
                    return BudgetOperationResult(ok=False, code="INVALID_STATE", state=reservation.state)
            for delegation_id in reservation.delegation_ids:
                self._counters[delegation_id].reserved -= reservation.amount
            reservation.state = "cancelled"
            return BudgetOperationResult(ok=True, code="CANCELLED", state="cancelled")

    def counter(self, delegation_id: str) -> dict:
        with self._lock:
            if type(delegation_id) is not str:
                return {"reserved": "0", "committed": "0"}
            counter = self._counters.get(delegation_id, _Counter())
            return {"reserved": str(counter.reserved), "committed": str(counter.committed)}
