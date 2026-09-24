# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Shared types and code vocabularies for chain selection.

Python port of the TypeScript SDK's src/v2/chain-selection/types.ts. Same names,
adapted to Python conventions: snake_case functions and members, frozen
dataclasses instead of interfaces, keyword-only options instead of an options
object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol

from ..authority_delegation.types import AuthorityValidationResult, BudgetOperationResult


@dataclass(frozen=True)
class HeldChain:
    """One chain an agent holds, under a caller-chosen name.

    ``chain_id`` is the caller's own label for this chain, not a protocol field
    and not derived from the records: nothing in draft-03 names a chain. It
    exists so a selection result can say which chain it decided against, which
    is what makes a selection, and a later switch away from it, visible. Two
    held entries carrying the same ``chain_id`` are refused rather than
    disambiguated, because a result naming an ambiguous label would not
    identify a chain.

    ``chain`` is root-to-leaf and untrusted, the same shape and the same trust
    level ``verify_authority_delegation_chain`` takes.
    """

    chain_id: str
    chain: Any


@dataclass(frozen=True)
class RequiredSpendV1:
    """The spend an action requires, if any.

    ``action_ref`` keys the reservation in the ledger, exactly as
    ``InMemoryAuthorityBudgetLedger.reserve`` requires: 64 lowercase
    hexadecimal characters. One action reserves against one chain, so a single
    ``action_ref`` is reserved at most once here, against the chain that was
    selected.
    """

    unit: str
    #: Canonical unsigned decimal integer, the same grammar the spend facet uses.
    amount: str
    action_ref: str


class AuthorityBudgetReserver(Protocol):
    """The reservation boundary this module calls.

    Satisfied structurally by :class:`InMemoryAuthorityBudgetLedger`. Injected
    rather than constructed here: a selection that minted its own ledger would
    report ``RESERVED`` against counters nobody else can see, and a real
    deployment's ledger is a store, not an object in this process.
    """

    def reserve(
        self, verified_chain: Any, action_ref: str, unit: str, amount_string: str
    ) -> BudgetOperationResult:  # pragma: no cover - structural type
        ...


@dataclass(frozen=True)
class ChainEvaluation:
    """What one held chain said about one action.

    ``outcome`` is one of ``"authorizes"``, ``"refuses"`` or ``"undecided"``.
    ``authorizes`` means this chain alone covers the action. ``refuses`` means
    this chain alone establishes that it does not. ``undecided`` means no
    conclusion was reached about this chain, which is not the negation of one:
    an indeterminate revocation answer, an unsupported facet profile, or a
    missing ledger all land here, and none of them is a statement that the
    chain does not authorize the action. draft-03 section 3.3 forbids
    collapsing indeterminate or unsupported into valid, and this keeps them out
    of ``refuses`` as well, so a caller that reports a denial reason does not
    report one the evidence does not support.

    ``code`` is the check that decided this chain: an ``AuthorityFailure`` code
    from chain verification, a ``BudgetOperationResult`` code from the reserver,
    or one of :data:`CHAIN_SELECTION_EVALUATION_CODES`. Codes from the other two
    sources are passed through unchanged rather than remapped, so a caller
    reading this member sees the name the deciding component used.

    ``chain_state`` is the chain's own four-valued verification state, or
    ``None`` when verification did not run.
    """

    chain_id: str
    outcome: str
    code: str
    chain_state: Optional[str]


#: This module's own evaluation codes, the ones that come from neither chain
#: verification nor the reserver.
#:
#: - ``scope_covered``: the chain covers every needed grant and the action
#:   required no spend.
#: - ``scope_not_covered``: some needed grant is covered by no grant on this
#:   chain's leaf.
#: - ``chain_set_presented_as_one``: this held entry is not one root-to-leaf
#:   chain. A member after the first carries a null ``parent_delegation_id``, so
#:   the entry is two or more chains concatenated. Refused before verification
#:   rather than being reported as the broken parent link chain verification
#:   would otherwise call it, because the fault is the presentation, not the
#:   records: this is the shape a caller would reach for to have two chains
#:   evaluated as one.
#: - ``spend_ledger_unavailable``: the action requires spend and no reserver was
#:   supplied, so the spend half could not be decided. Undecided, never a refusal.
CHAIN_SELECTION_EVALUATION_CODES: tuple[str, ...] = (
    "scope_covered",
    "scope_not_covered",
    "chain_set_presented_as_one",
    "spend_ledger_unavailable",
)

#: Why no chain was selected.
#:
#: - ``held_set_empty``: the held set is not a readable sequence of at least one entry.
#: - ``held_set_over_ceiling``: more held entries than this implementation will
#:   judge. draft-03 states no such ceiling, so this says this implementation
#:   declined, never that the input is bad.
#: - ``held_chain_malformed``: a held entry carries no non-empty string
#:   ``chain_id``, or no ``chain`` member at all.
#: - ``duplicate_chain_id``: two held entries share a ``chain_id``.
#: - ``invalid_action_requirement``: the needed grants are not a readable list of
#:   valid scope grants, or the required spend's shape is not usable. A request
#:   fault, kept apart from ``scope_not_covered``, which is a statement about a chain.
#: - ``preferred_chain_not_held``: :func:`select_with_fallback` was given a
#:   ``preferred_chain_id`` that names no held entry.
#: - ``no_valid_chain``: every candidate refused, and none of them verified ``valid``.
#: - ``no_chain_covers_action``: every candidate refused, and at least one of them
#:   verified ``valid`` and then failed to cover the action.
#: - ``selection_undecided``: at least one candidate was ``undecided``, so nothing
#:   was established about it and nothing is established about the set. Not
#:   established is kept apart from refused deliberately: draft-03 section 3.3
#:   forbids collapsing indeterminate or unsupported into valid, and collapsing
#:   them into a refusal would be the opposite error, a denial reason the evidence
#:   does not support.
CHAIN_SELECTION_FAILURE_CODES: tuple[str, ...] = (
    "held_set_empty",
    "held_set_over_ceiling",
    "held_chain_malformed",
    "duplicate_chain_id",
    "invalid_action_requirement",
    "preferred_chain_not_held",
    "no_valid_chain",
    "no_chain_covers_action",
    "selection_undecided",
)


@dataclass(frozen=True)
class FallbackAuthorizationV0:
    """Explicit authorization for switching away from the chain an action selected.

    PROPOSED, not draft-03. draft-03 says nothing about what an implementation
    does after the chain it selected turns out to be unusable: ``fallback``,
    ``fall back``, ``resurrect`` and ``reselect`` occur zero times in the
    published text. The invariant candidate this shape serves is L11, "No silent
    authority resurrection", in ``AUTHORITY-LIFECYCLE.md`` of the
    aeoess/agent-authority-lifecycle concept document, whose own status there is
    ``proposed``: when the authority path an implementation selected becomes
    invalid, it should not quietly fall back to another stored grant unless that
    fallback was itself explicitly authorized.

    That document does not define what makes a fallback "explicitly authorized",
    and this SDK does not invent a definition. ``authorization_ref`` is an OPAQUE
    reference the caller supplies and this module records and never interprets:
    it is not resolved, not verified, not required to name any record type, and
    its presence is not a claim that the fallback was authorized. What the
    presence of this object does is make the switch a decision the caller had to
    take deliberately and that the result then reports.
    """

    authorization_ref: str


@dataclass(frozen=True)
class SelectionOutcome:
    """The result of a selection.

    ``chain_id`` is one name or ``None``, never a list: there is no
    representable outcome in which two chains were combined.

    When ``selected`` is True, ``chain_id`` and ``result`` are both set and
    ``code`` is ``None``. When it is False, ``code`` is set and ``chain_id`` and
    ``result`` are both ``None``.

    ``switched_from``, ``fallback_ref`` and ``fallback_considered`` are PROPOSED
    (L11) and are set only by :func:`select_with_fallback`.
    """

    selected: bool
    chain_id: Optional[str]
    #: Every candidate this call evaluated, in the order it evaluated them.
    evaluations: tuple[ChainEvaluation, ...] = ()
    #: The selected chain's own verification result, unchanged from the chain verifier.
    result: Optional[AuthorityValidationResult] = None
    code: Optional[str] = None
    #: PROPOSED (L11). The chain the action had selected, when this call switched away.
    switched_from: Optional[str] = None
    #: PROPOSED (L11). The opaque reference given for that switch, recorded, not interpreted.
    fallback_ref: Optional[str] = None
    #: PROPOSED (L11). True when the call was allowed to look past the chain the action
    #: selected. False means no other held chain was read at all, which is the observable
    #: difference between a refusal and a silent switch.
    fallback_considered: Optional[bool] = None


#: This implementation's own ceiling on held entries. draft-03 states none.
HELD_SET_CEILING = 256
