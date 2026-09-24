# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Activation conditions and condition attestation (Python port).

NOT REQUIRED BY draft-pidlisnyi-aps-03. The published text states no activation-condition
rule, no attestor role and no attestation-acceptance rule: a case-insensitive search of
draft-pidlisnyi-aps-03 for ``activation``, ``attestor`` and ``contingen`` returns nothing.
Draft-03 section 3.2 also states, verbatim: "authority contains exactly seven required
facets: scope, spend, depth, time, reputation, values, and reversibility. A missing facet
is invalid rather than an implicit unconstrained value." That closes the authority vector,
so an activation condition can never be a facet. It is a SEPARATE artifact that references
a ``delegation_id``, which is what this module models.

Concept source: the aeoess/agent-authority-lifecycle concept document
(AUTHORITY-LIFECYCLE.md, "Activation condition" under "Authority and dependencies", marked
proposed with no public case testing it) and invariant candidates CAND-04 (activation is
established, not yet effective, or not established), CAND-13 (replacement authority may be
pre-committed) and BROAD-L7 (any current lifecycle state claim is established only from an
accepted source, within a declared freshness bound, over the coverage the claim states).
All three are proposed. Nothing here claims otherwise.

Additive and opt-in. Nothing any existing function returns changes, and a caller that never
imports this module sees exactly today's behaviour.

Python port of the TypeScript SDK's src/v2/activation/types.ts, name for name, with
snake_case adapted to Python convention.

THREE THINGS THE CONCEPT TEXT DOES NOT DECIDE, and how this module refuses to decide them:

  1. WHICH INSTANT an occurrence is measured from. A recorded-event condition carries
     ``instant_basis`` and there is no default.
  2. HOW MANY acceptable attestations establish a condition. ``threshold`` is required and
     there is no default.
  3. WHO decides a condition. Role standing is resolved through a caller-supplied resolver
     and is never read off the attestation asserting it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

#: Record type of the activation condition this module owns. The ``proposed:`` prefix is
#: deliberate: the conformance suite's CONTRIBUTING.md reserves record fields, failure-class
#: names and verifier semantics to the schema owner, so nothing here is minted APS
#: vocabulary and nothing downstream should treat it as stable.
ACTIVATION_CONDITION_TYPE = "proposed:aps:activation-condition:v0"

#: Record type of the activation attestation this module owns. Same caveat as above. A
#: model may accept condition evidence in a shape this module does not own, through
#: ``attestation_preimage``.
ACTIVATION_ATTESTATION_TYPE = "proposed:aps:activation-attestation:v0"

#: The two kinds of activation condition the concept text names in one sentence: "A grant
#: can be validly issued and still wait on a date or a recorded event." They are answered by
#: different deciders, which is why they are separate shapes rather than one shape with
#: optional fields. A date condition needs no evidence at all: the verifier reads the date.
#: A recorded-event condition needs evidence from a source the model accepts for it.
ACTIVATION_CONDITION_KINDS: tuple[str, ...] = ("date", "recorded_event")

#: Which instant a ``condition_occurred`` attestation is measured against.
#:
#: - ``condition_occurrence``  the instant the condition itself is asserted to have
#:                            occurred, from the record's ``occurred_at``. This is CAND-04
#:                            v2's reading: "A condition that first occurred after an action
#:                            does not make that action exercisable", which is a statement
#:                            about the condition's own instant. Under it, a record written
#:                            after an action can establish a condition that obtained before
#:                            it, which is the normal case for any model built around an
#:                            after-the-fact determination.
#: - ``attestation_written``  the instant the record was written, from ``attested_at``. A
#:                            model that keys activation on when someone wrote the
#:                            determination down rather than on when the condition occurred
#:                            can say so here.
#:
#: THERE IS NO DEFAULT. The concept text groups a date and a recorded event in one sentence
#: and says nothing about which instant either is measured from, and a default in an SDK is
#: a ruling made by whoever wrote the SDK. Both readings give opposite verdicts on a
#: deployment-relevant case (an occurrence before an action, attested after it), so the
#: condition has to state which one governs.
#:
#: ``instant_basis`` does not apply to a ``condition_not_occurred_through`` record. That
#: assertion states the interval it covers, and the interval is what the coverage check
#: reads. Concept source: BROAD-L7's coverage limb.
ACTIVATION_INSTANT_BASES: tuple[str, ...] = ("condition_occurrence", "attestation_written")

#: The two assertions an activation attestation can carry.
#:
#: - ``condition_occurred``             the event occurred, at ``occurred_at``.
#: - ``condition_not_occurred_through`` the event had not occurred through
#:                                     ``not_occurred_through``. A NEGATIVE that is
#:                                     evidence, not an absence of evidence, which is the
#:                                     distinction between ``not_yet_effective`` and
#:                                     ``not_established``.
#:
#: An absence-triggered condition, where the trigger is that something did NOT happen
#: within a declared window, is NOT modelled here. CAND-04's own counterexample analysis
#: names it as the shape most likely to be implemented wrongly in the fail-closed direction,
#: and this module has no vocabulary for it. A resolver returning ``unknown`` is what keeps
#: that case reachable for a later surface rather than silently answered here.
ACTIVATION_ASSERTIONS: tuple[str, ...] = (
    "condition_occurred",
    "condition_not_occurred_through",
)

#: What a resolver can say about whether an attestor holds a role at an instant.
#:
#: THREE VALUES, NOT A BOOLEAN. "This registry does not know" is a distinct answer from
#: "this party does not hold that role", and collapsing the first into the second turns
#: ignorance into a denial. That collapse is the failure BROAD-L7 exists to name, and it is
#: the reason an absence-triggered condition needs ``unknown`` to stay reachable.
ATTESTOR_ROLE_STANDINGS: tuple[str, ...] = ("holds", "does_not_hold", "unknown")

#: What one accepted attestation establishes about the condition at the action instant.
#:
#: - ``occurred_by_action``          the condition's instant is at or before the action
#:                                  instant.
#: - ``occurred_after_action``       the condition's instant is after it. The SAME record
#:                                  establishes the condition for any later action, which is
#:                                  what makes this a wait rather than a failure.
#: - ``not_occurred_through_action`` an accepted record states the condition had not
#:                                  occurred through an instant that reaches the action
#:                                  instant.
ACTIVATION_FINDINGS: tuple[str, ...] = (
    "occurred_by_action",
    "occurred_after_action",
    "not_occurred_through_action",
)

#: Every reason code this module emits, verdict-level and rejection-level.
#:
#: Module-local and SCREAMING_SNAKE_CASE, per the lifecycle-state vocabulary's rule that two
#: findings sharing a verdict name must be told apart by their codes. Not minted APS
#: vocabulary.
#:
#: Verdict-level:
#:   ACTIVATION_ESTABLISHED                  valid. An accepted record establishes the
#:                                           condition at or before the action instant, or a
#:                                           date condition's date has been reached.
#:   CONDITION_DATE_NOT_REACHED              not_yet_effective. A date condition's
#:                                           activation date is after the action instant.
#:   CONDITION_ESTABLISHED_NOT_YET_OCCURRED  not_yet_effective. An accepted record states
#:                                           the condition had not occurred through an
#:                                           instant reaching the action instant.
#:   CONDITION_FIRST_OCCURRED_AFTER_ACTION   not_yet_effective. An accepted record puts the
#:                                           condition's first occurrence after the action
#:                                           instant. No retroactive activation: the same
#:                                           record establishes the condition for a later
#:                                           action, and never for this one.
#:   CONDITION_EVIDENCE_CONFLICT             not_established, source. Two accepted records
#:                                           disagree about the action instant. Neither
#:                                           defeats the other and this module has no
#:                                           precedence rule.
#:   ACTIVATION_THRESHOLD_NOT_MET            not_established, source. Accepted records exist
#:                                           but fewer than ``threshold`` support the
#:                                           finding.
#:   NO_ATTESTATION_PRESENTED                not_established, source. Nothing was presented.
#:   CONDITION_DELEGATION_MISMATCH           not_established, coverage. The condition
#:                                           presented gates a different delegation.
#:
#: Rejection-level, in check order, ranked by how far the record got:
#:   ATTESTATION_RECORD_TYPE_NOT_ACCEPTED    source. Not a type the model declared it
#:                                           accepts for this condition.
#:   ATTESTATION_SIGNATURE_UNVERIFIED        source. No key resolved at the record's own
#:                                           ``attested_at``, or the signature does not
#:                                           verify over the record's canonical bytes.
#:   ATTESTATION_ATTESTOR_BINDING_MISMATCH   source. The verification method does not belong
#:                                           to the attestor the body names, so a valid
#:                                           signature says nothing about who attested.
#:   ATTESTATION_ATTESTOR_ROLE_UNKNOWN       source. The resolver does not know. Ignorance,
#:                                           and deliberately not folded into a mismatch.
#:   ATTESTATION_ROLE_CLAIM_CONFLICT         source. The record claims a role the resolver
#:                                           says the attestor does not hold.
#:   ATTESTATION_ATTESTOR_ROLE_MISMATCH      source. The attestor holds no role the
#:                                           condition requires.
#:   ATTESTATION_CONDITION_MISMATCH          source. The record's condition, event type or
#:                                           event id is not the condition's.
#:   ATTESTATION_UNKNOWN_ASSERTION           source. The assertion is not one of the two
#:                                           this module defines, or the member that
#:                                           assertion needs is absent.
#:   ATTESTATION_INSTANT_MALFORMED           source. An instant on the record is not an
#:                                           RFC 3339 instant this module will compare.
#:   ATTESTATION_DOES_NOT_REACH_ACTION       coverage. A negative record stops before the
#:                                           action instant, so it says nothing about the
#:                                           interval between where it stops and the action.
ACTIVATION_REASON_CODES: tuple[str, ...] = (
    "ACTIVATION_ESTABLISHED",
    "CONDITION_DATE_NOT_REACHED",
    "CONDITION_ESTABLISHED_NOT_YET_OCCURRED",
    "CONDITION_FIRST_OCCURRED_AFTER_ACTION",
    "CONDITION_EVIDENCE_CONFLICT",
    "ACTIVATION_THRESHOLD_NOT_MET",
    "NO_ATTESTATION_PRESENTED",
    "CONDITION_DELEGATION_MISMATCH",
    "ATTESTATION_RECORD_TYPE_NOT_ACCEPTED",
    "ATTESTATION_SIGNATURE_UNVERIFIED",
    "ATTESTATION_ATTESTOR_BINDING_MISMATCH",
    "ATTESTATION_ATTESTOR_ROLE_UNKNOWN",
    "ATTESTATION_ROLE_CLAIM_CONFLICT",
    "ATTESTATION_ATTESTOR_ROLE_MISMATCH",
    "ATTESTATION_CONDITION_MISMATCH",
    "ATTESTATION_UNKNOWN_ASSERTION",
    "ATTESTATION_INSTANT_MALFORMED",
    "ATTESTATION_DOES_NOT_REACH_ACTION",
)

#: Which establishment limb is missing when a reason code produces ``not_established``.
#:
#: ``freshness`` never appears. A freshness bound is model declared, this module is given
#: none, and the surface that owns multi-source status observation owns freshness. A mapping
#: that invented a freshness finding would be claiming something the verifier never
#: measured.
ACTIVATION_GAPS_BY_REASON: dict[str, tuple[str, ...]] = {
    "CONDITION_DELEGATION_MISMATCH": ("coverage",),
    "ATTESTATION_DOES_NOT_REACH_ACTION": ("coverage",),
}

#: How far through the checks a rejected attestation got. When no record was accepted, the
#: reported code is the reason of the record that got FURTHEST, so the verdict names the
#: closest thing to usable evidence that was presented. Ties break on ``attestation_id``
#: ascending, which makes the answer independent of presentation order. Verdict-level codes
#: never rank: they are not rejections of a record.
REJECTION_RANK: dict[str, int] = {
    "ATTESTATION_RECORD_TYPE_NOT_ACCEPTED": 1,
    "ATTESTATION_SIGNATURE_UNVERIFIED": 2,
    "ATTESTATION_ATTESTOR_BINDING_MISMATCH": 3,
    "ATTESTATION_ATTESTOR_ROLE_UNKNOWN": 4,
    "ATTESTATION_ROLE_CLAIM_CONFLICT": 5,
    "ATTESTATION_ATTESTOR_ROLE_MISMATCH": 6,
    "ATTESTATION_CONDITION_MISMATCH": 7,
    "ATTESTATION_UNKNOWN_ASSERTION": 8,
    "ATTESTATION_INSTANT_MALFORMED": 9,
    "ATTESTATION_DOES_NOT_REACH_ACTION": 10,
}

#: Resolves whether ``attestor`` held ``role`` at ``at_instant``, returning one of
#: :data:`ATTESTOR_ROLE_STANDINGS`.
#:
#: Role standing is resolved OUTSIDE the record, always. This module never reads standing
#: from the artifact asserting it, which is the single control that separates a real
#: attestor-role check from a self-declared one. ``at_instant`` is passed so a registry with
#: its own history can answer for the right moment. A resolver that ignores it is answering
#: for "now", which is a choice the resolver makes and not one this module makes for it.
#:
#: Where role standing comes from, who publishes it and what a verifier consults are not
#: settled by any published or proposed text. That is why this is a callable and not a
#: registry type.
AttestorRoleResolver = Callable[[str, str, str], str]


@dataclass(frozen=True)
class ActivationFinding:
    """One accepted attestation and what it established."""

    attestation_id: str
    attestor: str
    finding: str


@dataclass(frozen=True)
class ActivationRejection:
    """One rejected attestation and why.

    A rejected attestation is NOT evidence in either direction: it cannot establish the
    condition and it equally cannot establish that the condition was unmet. That is the
    whole of the difference between ``not_established`` and ``not_yet_effective`` for a
    record from a source the model does not accept.
    """

    attestation_id: str
    attestor: str
    reason_code: str


@dataclass(frozen=True)
class ActivationResult:
    """What :func:`verify_activation` concludes.

    ``state`` is a ``LifecycleStateResult`` in the lifecycle-state vocabulary, so activation
    shares one verdict set with every other proposed lifecycle surface instead of spelling a
    seventh local copy of the same missing values. Only three of the six verdicts are
    reachable here: ``valid``, ``not_yet_effective`` and ``not_established``. ``invalid`` is
    NEVER one of them. An unmet activation condition does not make a grant invalid, and
    whether the grant is valid at all is chain verification's answer, not this module's.

    ``findings`` and ``rejections`` are the working, one entry per presented attestation
    across the two, so a caller can report which record did what rather than only the
    verdict.
    """

    state: Any
    condition_id: str
    condition_type: str
    findings: tuple[ActivationFinding, ...] = field(default_factory=tuple)
    rejections: tuple[ActivationRejection, ...] = field(default_factory=tuple)


class ActivationError(ValueError):
    """Raised when a condition or a call is malformed.

    A shape rule broken at the call site is a programming error, not a verdict, which is the
    same split ``lifecycle_state`` makes. Evidence problems are never raised: they are
    verdicts. ``code`` is the single stable code callers branch on.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
