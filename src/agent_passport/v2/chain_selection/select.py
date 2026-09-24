# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Chain selection for one action, over the set of chains an agent holds.

Python port of the TypeScript SDK's src/v2/chain-selection/select.ts. Both SDKs
run the same rule and record the same codes, checked by the shared parity
vectors (tests/cross_impl/chain-selection-v0-vectors.json).

draft-pidlisnyi-aps-03 section 3.3, lines 594-596, verbatim:

    Each action selects one root-to-leaf authority chain.  A verifier
    MUST NOT union scopes or budgets from multiple chains.  Cross-
    principal composition requires a separate profile.

Every other entry point in this SDK takes exactly one chain, so the first
sentence has had no surface: a caller could obey it, and a caller could evaluate
an action against three chains and pool the answers, and nothing in the SDK could
tell the two apart. This module is that surface.

The second sentence is enforced structurally rather than by a check: no function
here ever holds two chains' scope grants or spend ceilings in one comparison.
Each held chain is verified, scope-checked and budget-checked alone, and the
result names one ``chain_id``, never a set.

There is no wall clock anywhere in this module. ``now`` is a required
keyword-only argument supplied by the caller, exactly as the chain verifier
takes it.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from typing import Any, Optional, cast

from ..authority_delegation.scope import is_valid_scope_grant, scope_grant_covers
from ..authority_delegation.types import AuthorityValidationResult
from ..authority_delegation.verify import verify_authority_delegation_chain
from .types import (
    HELD_SET_CEILING,
    AuthorityBudgetReserver,
    ChainEvaluation,
    FallbackAuthorizationV0,
    HeldChain,
    RequiredSpendV1,
    SelectionOutcome,
)

_ACTION_REF = re.compile(r"^[0-9a-f]{64}$")

# A canonical unsigned decimal integer, the grammar the spend facet already uses.
_QUANTITY = re.compile(r"^(0|[1-9][0-9]*)$")

_MISSING = object()

# The resolver callables this module accepts and passes straight through to
# verify_authority_delegation_chain, annotated here so the two stable entry points
# below carry a checked signature. They are the caller's, exactly as the chain
# verifier takes them: nothing in this module constructs one.
_ResolveVerificationKey = Callable[..., Any]
_TrustRoot = Callable[..., Any]
_ResolveRevocation = Callable[..., Any]
_HeldPair = tuple[str, Any]
_Requirement = tuple[list[str], Optional[RequiredSpendV1]]


def _read_held_set(held: Any) -> list[_HeldPair] | str:
    """Read the held set once, into this module's own list.

    Every member of every held entry is read exactly here, so a caller object
    whose member is a property cannot answer one way when the set is checked and
    another way when a chain is verified. A read that raises leaves the entry
    malformed, which is a coded result. Nothing in this module raises.

    Returns a list of (chain_id, chain) pairs, or a failure code string.
    """
    # Identity tests rather than isinstance or a tuple membership test: neither
    # runs caller code, which a hostile metaclass's __eq__ or __instancecheck__ would.
    if type(held) is not list and type(held) is not tuple:
        return "held_set_empty"
    if len(held) > HELD_SET_CEILING:
        return "held_set_over_ceiling"
    if len(held) < 1:
        return "held_set_empty"
    output: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for entry in held:
        try:
            if type(entry) is dict:
                chain_id = entry.get("chain_id", _MISSING)
                chain = entry.get("chain", _MISSING)
            else:
                chain_id = getattr(entry, "chain_id", _MISSING)
                chain = getattr(entry, "chain", _MISSING)
        except Exception:
            return "held_chain_malformed"
        if type(chain_id) is not str or len(chain_id) == 0:
            return "held_chain_malformed"
        if chain is _MISSING:
            return "held_chain_malformed"
        if chain_id in seen:
            return "duplicate_chain_id"
        seen.add(chain_id)
        output.append((chain_id, chain))
    return output


def _read_requirement(required_grants: Any, required_spend: Any) -> Optional[_Requirement]:
    """Read the action's requirement once, the same way and for the same reason.

    Returns (grants, spend) or None.
    """
    if type(required_grants) is not list and type(required_grants) is not tuple:
        return None
    needed: list[str] = []
    for grant in required_grants:
        # An unusable needed grant is a fault in the request, never a statement
        # that some chain failed to cover it: a caller told a chain is refusing
        # an action it was never coherently asked about would report a denial
        # the evidence does not support.
        if type(grant) is not str or not is_valid_scope_grant(grant):
            return None
        needed.append(grant)
    if required_spend is None:
        return needed, None
    try:
        if type(required_spend) is dict:
            unit = required_spend.get("unit", _MISSING)
            amount = required_spend.get("amount", _MISSING)
            action_ref = required_spend.get("action_ref", _MISSING)
        else:
            unit = getattr(required_spend, "unit", _MISSING)
            amount = getattr(required_spend, "amount", _MISSING)
            action_ref = getattr(required_spend, "action_ref", _MISSING)
    except Exception:
        return None
    if type(unit) is not str or len(unit) == 0:
        return None
    if type(amount) is not str or not _QUANTITY.fullmatch(amount):
        return None
    if type(action_ref) is not str or not _ACTION_REF.fullmatch(action_ref):
        return None
    return needed, RequiredSpendV1(unit=unit, amount=amount, action_ref=action_ref)


def _evaluate_held_chain(
    chain_id: str,
    chain: Any,
    needed: list[str],
    spend: Optional[RequiredSpendV1],
    reserve_budget: Optional[AuthorityBudgetReserver],
    *,
    now: str,
    resolve_verification_key: _ResolveVerificationKey,
    trust_root: _TrustRoot,
    resolve_revocation: _ResolveRevocation,
) -> tuple[ChainEvaluation, Optional[AuthorityValidationResult]]:
    """Decide ONE held chain against the action.

    This function never sees another chain, and it is the only place a chain is
    judged, so neither :func:`select_chain_for_action` nor
    :func:`select_with_fallback` has a route by which a second chain's grants or
    ceiling could enter a comparison. That is draft-03 section 3.3's "A verifier
    MUST NOT union scopes or budgets from multiple chains" held by construction
    rather than by a check.

    Order: presentation, then chain verification, then scope, then spend. Scope
    before spend so an action refused on both is refused under the check that
    does not touch the ledger, which keeps a refusal from leaving a reservation
    behind.

    Returns (ChainEvaluation, AuthorityValidationResult or None).
    """

    def refuse(
        code: str, chain_state: Optional[str]
    ) -> tuple[ChainEvaluation, Optional[AuthorityValidationResult]]:
        return ChainEvaluation(chain_id=chain_id, outcome="refuses", code=code, chain_state=chain_state), None

    def undecided(
        code: str, chain_state: Optional[str]
    ) -> tuple[ChainEvaluation, Optional[AuthorityValidationResult]]:
        return ChainEvaluation(chain_id=chain_id, outcome="undecided", code=code, chain_state=chain_state), None

    # Presentation. A member after the first with a null parent_delegation_id is
    # a root, so this entry is two or more chains concatenated rather than one
    # root-to-leaf chain. Refused before verification: the fault is that a set
    # was presented as one chain, which is precisely the shape a caller reaches
    # for to have two chains evaluated together, and naming it as chain
    # verification's broken parent link would hide that. Only exact dicts are
    # read here, and only with .get, so no caller code runs.
    if type(chain) is list or type(chain) is tuple:
        for i in range(1, len(chain)):
            member = chain[i]
            if type(member) is dict and member.get("parent_delegation_id", _MISSING) is None:
                return refuse("chain_set_presented_as_one", None)

    result = verify_authority_delegation_chain(
        chain,
        now=now,
        resolve_verification_key=resolve_verification_key,
        trust_root=trust_root,
        resolve_revocation=resolve_revocation,
    )
    if result.state != "valid":
        code = result.failures[0].code if result.failures else result.state
        return refuse(code, result.state) if result.state == "invalid" else undecided(code, result.state)

    # Every record has now passed the chain verifier, so each one is a plain JSON
    # value of exact types and bounded depth: copying it runs no caller code, and
    # the copy is what the reserver is handed, so a caller writing to its own
    # dicts after this point changes nothing a reservation was made against.
    records = [copy.deepcopy(chain[i]) for i in range(len(chain))]

    # Scope. The leaf's grants are what the chain's own narrowing has already
    # reduced the root's grants to, which verification above established.
    grants = records[-1]["authority"]["scope"]["grants"]
    for want in needed:
        if not any(scope_grant_covers(grant, want) for grant in grants):
            return refuse("scope_not_covered", result.state)

    if spend is None:
        return (
            ChainEvaluation(chain_id=chain_id, outcome="authorizes", code="scope_covered", chain_state=result.state),
            result,
        )
    if reserve_budget is None:
        # Not established, not a refusal: nothing was learned about whether this
        # chain's ceiling covers the amount.
        return undecided("spend_ledger_unavailable", result.state)
    try:
        reservation = reserve_budget.reserve(records, spend.action_ref, spend.unit, spend.amount)
    except Exception:
        return undecided("spend_ledger_unavailable", result.state)
    reservation_code: Any = getattr(reservation, "code", None)
    ok = getattr(reservation, "ok", None)
    if type(reservation_code) is not str:
        return undecided("spend_ledger_unavailable", result.state)
    if ok is not True:
        return refuse(reservation_code, result.state)
    return (
        ChainEvaluation(
            chain_id=chain_id, outcome="authorizes", code=reservation_code, chain_state=result.state
        ),
        result,
    )


def _failure_for(evaluations: list[ChainEvaluation]) -> str:
    """One undecided candidate is enough to make the whole answer not established.

    Nothing was learned about that chain, so "no chain covers the action" is a
    claim the evaluations do not support. Where every candidate did refuse, a
    candidate that verified valid and then failed scope or spend establishes that
    a valid chain did not cover the action. A candidate that never verified valid
    establishes nothing about coverage, only that it was not a usable chain.
    """
    if any(item.outcome == "undecided" for item in evaluations):
        return "selection_undecided"
    if any(item.chain_state == "valid" for item in evaluations):
        return "no_chain_covers_action"
    return "no_valid_chain"


def select_chain_for_action(
    held: Any,
    *,
    required_grants: Any,
    required_spend: Any = None,
    now: str,
    resolve_verification_key: _ResolveVerificationKey,
    trust_root: _TrustRoot,
    resolve_revocation: _ResolveRevocation,
    reserve_budget: Optional[AuthorityBudgetReserver] = None,
) -> SelectionOutcome:
    """Select the one chain an action is decided against, out of the set an agent holds.

    draft-03 section 3.3 (lines 594-596) states the rule this implements: "Each
    action selects one root-to-leaf authority chain.  A verifier MUST NOT union
    scopes or budgets from multiple chains.  Cross-principal composition requires
    a separate profile." Required behaviour, not a proposal. The one part of this
    module that is proposed rather than specified is the fallback surface, and it
    lives in :func:`select_with_fallback`.

    Selection rule, which draft-03 does not state and this implementation
    therefore fixes and documents. Candidates are evaluated in held order. The
    FIRST candidate that both verifies ``valid`` and covers every needed scope
    grant is the selected chain, and the action's spend is then reserved against
    that chain and no other. A spend refusal is that chain's refusal, and no
    further candidate is read. Scope selects, spend admits or refuses. The
    alternative, continuing past a spend refusal to a chain with a larger
    ceiling, is a fallback in everything but name, and this function does not do
    it silently.

    ``held`` never shrinks to the one chain: every candidate this call read
    appears in ``evaluations``, and the chosen ``chain_id`` is one name, so a
    caller and an auditor can both see which chain the action was decided
    against and which chains were passed over.

    A caller that already had a chain selected and is now asking again because
    that chain failed is switching, not selecting, and should use
    :func:`select_with_fallback`. This function does not know that a previous
    selection existed and cannot report a switch.

    Nothing here reads a clock, a random source or the network. This function
    never raises.
    """
    read = _read_held_set(held)
    if type(read) is str:
        return SelectionOutcome(selected=False, chain_id=None, code=read, evaluations=())
    # `type(...) is str` is this module's deliberate identity test: isinstance can run
    # caller code through __instancecheck__. mypy narrows the str branch from it but not
    # the list branch, so the cast states what the check established. No runtime effect.
    entries = cast(list[_HeldPair], read)
    requirement = _read_requirement(required_grants, required_spend)
    if requirement is None:
        return SelectionOutcome(selected=False, chain_id=None, code="invalid_action_requirement", evaluations=())
    needed, spend = requirement

    evaluations: list[ChainEvaluation] = []
    # Two passes over the candidates, because a reservation mutates a ledger and
    # a refused scope check does not: every candidate is scope-checked with no
    # spend requirement first, and only the one that wins is reserved against. A
    # single pass would reserve against a chain that a later candidate replaces.
    chosen: Optional[tuple[str, Any]] = None
    chosen_result: Optional[AuthorityValidationResult] = None
    for chain_id, chain in entries:
        evaluation, result = _evaluate_held_chain(
            chain_id, chain, needed, None, None,
            now=now,
            resolve_verification_key=resolve_verification_key,
            trust_root=trust_root,
            resolve_revocation=resolve_revocation,
        )
        evaluations.append(evaluation)
        if evaluation.outcome == "authorizes":
            chosen = (chain_id, chain)
            chosen_result = result
            break
    if chosen is None or chosen_result is None:
        return SelectionOutcome(
            selected=False, chain_id=None, code=_failure_for(evaluations), evaluations=tuple(evaluations)
        )
    if spend is None:
        return SelectionOutcome(
            selected=True, chain_id=chosen[0], result=chosen_result, evaluations=tuple(evaluations)
        )
    # Re-evaluate the winner with the spend requirement attached. This is the
    # only reservation this call makes.
    evaluation, result = _evaluate_held_chain(
        chosen[0], chosen[1], needed, spend, reserve_budget,
        now=now,
        resolve_verification_key=resolve_verification_key,
        trust_root=trust_root,
        resolve_revocation=resolve_revocation,
    )
    evaluations[-1] = evaluation
    if evaluation.outcome != "authorizes" or result is None:
        return SelectionOutcome(
            selected=False, chain_id=None, code=_failure_for(evaluations), evaluations=tuple(evaluations)
        )
    return SelectionOutcome(selected=True, chain_id=chosen[0], result=result, evaluations=tuple(evaluations))


def select_with_fallback(
    held: Any,
    *,
    preferred_chain_id: str,
    fallback: Any,
    required_grants: Any,
    required_spend: Any = None,
    now: str,
    resolve_verification_key: _ResolveVerificationKey,
    trust_root: _TrustRoot,
    resolve_revocation: _ResolveRevocation,
    reserve_budget: Optional[AuthorityBudgetReserver] = None,
) -> SelectionOutcome:
    """Decide an action against the chain it already selected, and switch to another
    held chain only when the caller has explicitly authorized a switch.

    The preferred-chain half is draft-03 section 3.3: one chain, no union. The
    fallback half is PROPOSED and has no counterpart in draft-03, where
    ``fallback``, ``fall back``, ``resurrect`` and ``reselect`` occur zero times.
    It serves a proposed rule this SDK does not claim is specified anywhere: a
    switch to another stored grant should be a visible decision, not a retry.

    ``fallback=None`` is that proposed rule in one argument. It reads no held chain
    other than ``preferred_chain_id``, so ``evaluations`` has exactly one entry
    and ``fallback_considered`` is False. There is no code path on which this
    function reaches another chain without the caller having passed an
    authorization object.

    With an authorization object, the remaining held chains are evaluated in held
    order and the first that authorizes the action is selected. The result then
    carries ``switched_from``, the chain the action had selected, and
    ``fallback_ref``, the caller's opaque reference, so the switch is in the
    result rather than only in the caller's head. That reference is recorded and
    NEVER interpreted: nothing specified defines what makes a fallback explicitly
    authorized, and this SDK does not invent a definition, so a ``fallback_ref``
    is not evidence that anything authorized anything.

    The preferred chain is always evaluated first and its own outcome is always
    ``evaluations[0]``, including when a fallback then succeeds, so the reason
    the action left its selected chain stays in the record. A later finding never
    rewrites it.

    This function never raises.
    """
    read = _read_held_set(held)
    if type(read) is str:
        return SelectionOutcome(selected=False, chain_id=None, code=read, evaluations=())
    # See the note in select_chain_for_action. No runtime effect.
    entries = cast(list[_HeldPair], read)
    requirement = _read_requirement(required_grants, required_spend)
    if requirement is None:
        return SelectionOutcome(selected=False, chain_id=None, code="invalid_action_requirement", evaluations=())
    needed, spend = requirement

    preferred = None
    if type(preferred_chain_id) is str:
        for entry in entries:
            if entry[0] == preferred_chain_id:
                preferred = entry
                break
    if preferred is None:
        return SelectionOutcome(selected=False, chain_id=None, code="preferred_chain_not_held", evaluations=())

    fallback_ref: Optional[str] = None
    if fallback is not None:
        try:
            if type(fallback) is dict:
                ref = fallback.get("authorization_ref", _MISSING)
            else:
                ref = getattr(fallback, "authorization_ref", _MISSING)
        except Exception:
            ref = _MISSING
        # An authorization object with no usable reference is not an
        # authorization. Refusing to switch is the fail-closed answer: a switch
        # recorded with no reference would be exactly the invisible switch the
        # proposed rule above is about.
        if type(ref) is not str or len(ref) == 0:
            return SelectionOutcome(selected=False, chain_id=None, code="invalid_action_requirement", evaluations=())
        fallback_ref = ref

    evaluations: list[ChainEvaluation] = []

    def decide(chain_id: str, chain: Any) -> Optional[AuthorityValidationResult]:
        evaluation, result = _evaluate_held_chain(
            chain_id, chain, needed, None, None,
            now=now,
            resolve_verification_key=resolve_verification_key,
            trust_root=trust_root,
            resolve_revocation=resolve_revocation,
        )
        if evaluation.outcome != "authorizes":
            evaluations.append(evaluation)
            return None
        if spend is None:
            evaluations.append(evaluation)
            return result
        evaluation, result = _evaluate_held_chain(
            chain_id, chain, needed, spend, reserve_budget,
            now=now,
            resolve_verification_key=resolve_verification_key,
            trust_root=trust_root,
            resolve_revocation=resolve_revocation,
        )
        evaluations.append(evaluation)
        return result if evaluation.outcome == "authorizes" else None

    first = decide(preferred[0], preferred[1])
    if first is not None:
        return SelectionOutcome(
            selected=True,
            chain_id=preferred[0],
            result=first,
            evaluations=tuple(evaluations),
            fallback_considered=fallback_ref is not None,
        )
    if fallback_ref is None:
        return SelectionOutcome(
            selected=False,
            chain_id=None,
            code=_failure_for(evaluations),
            evaluations=tuple(evaluations),
            fallback_considered=False,
        )
    for chain_id, chain in entries:
        if chain_id == preferred[0]:
            continue
        result = decide(chain_id, chain)
        if result is not None:
            return SelectionOutcome(
                selected=True,
                chain_id=chain_id,
                result=result,
                evaluations=tuple(evaluations),
                switched_from=preferred[0],
                fallback_ref=fallback_ref,
                fallback_considered=True,
            )
    return SelectionOutcome(
        selected=False,
        chain_id=None,
        code=_failure_for(evaluations),
        evaluations=tuple(evaluations),
        fallback_considered=True,
    )
