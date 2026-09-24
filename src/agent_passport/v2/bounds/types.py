# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Non-time bounds on a grant: purpose, use count and budget, and the
state "this bound has been reached".

Python port of the TypeScript SDK's src/v2/bounds/types.ts, name for name, with
snake_case adapted to Python convention.

NOT REQUIRED BY draft-pidlisnyi-aps-03. Two sentences of that document constrain
everything here. Section 3.2, verbatim:

    "authority contains exactly seven required facets: scope, spend, depth, time,
    reputation, values, and reversibility.  A missing facet is invalid rather than an
    implicit unconstrained value."

The facet set is closed, so a purpose bound or a use-count bound cannot be carried inside
a signed AuthorityDelegationV1 at all. This module therefore declares a SEPARATE artifact
that references a delegation by its content address, and never touches the delegation
schema. Section 3.3, verbatim:

    "Verification returns one of valid, invalid, indeterminate, or unsupported with a
    stable failure code."

That enumeration is closed too. Nothing here changes it. ``AuthorityValidationResult`` and
everything ``verify_authority_delegation_chain`` returns are byte for byte what they were,
and a caller that never imports this module sees exactly today's behaviour. What a bound
evaluation concludes is reported ALONGSIDE the chain result, in the separately named
vocabulary ``agent_passport.v2.lifecycle_state`` owns.

A search of draft-03 finds zero occurrences of "exhaust" and zero of "use_count". It does
use "single-use", of an APPROVAL in section 4.3 ("a first-class consumable artifact, bound
to the action_ref it approves, single-use, and carrying a bounded lifetime"), never of a
grant. So the word for the state in this module is minted here.

Concept source: the aeoess/agent-authority-lifecycle concept document. Invariant L10
(expiry is not revocation), whose "Expiry or exhaustion" concept entry names a use count, a
budget and a purpose as bounds whose being reached ends authority; and invariant candidate
CAND-01 (an external event is authority-changing only when established), which is why an
unauthenticated fulfilment claim here yields ``not_established`` and never ``exhausted``.
Both are PROPOSED. Nothing published requires any of it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

#: Record type of the bound declaration. The ``proposed:`` prefix is load-bearing: this is
#: not an ``aps:`` record type, because no published specification defines it.
AUTHORITY_BOUND_TYPE = "proposed:aps:authority-bound:v0"

#: Record type of a fulfilment attestation against a bound.
AUTHORITY_BOUND_FULFILMENT_TYPE = "proposed:aps:authority-bound-fulfilment:v0"

#: Record type of the optional exhaustion record. See ``record.py`` for what it does and
#: does not attest.
AUTHORITY_EXHAUSTION_TYPE = "proposed:aps:authority-exhaustion:v0"

#: The three bound kinds the case corpus produces.
#:
#: - ``purpose``   the grant states a reason. It is reached when a fulfilment record from a
#:   party with standing establishes the reason was met. Exercising the grant does NOT by
#:   itself reach it.
#: - ``use_count`` the grant allows a fixed number of admissions. The admission itself
#:   reaches it. No fulfilment record is involved.
#: - ``budget``    a cumulative spend ceiling. Listed for completeness and delegated to,
#:   never reimplemented: ``InMemoryAuthorityBudgetLedger`` already answers it, and
#:   draft-03 section 3.4 already states the rule, verbatim: "Signatures establish static
#:   limits; they do not establish the current cumulative total."
#:
#: Three bases for one state, kept apart on purpose. Proposed.
BOUND_KINDS: tuple[str, ...] = ("purpose", "use_count", "budget")

#: The state of one grant's declared bound, as a verifier can establish it at an instant.
#:
#: - ``not_reached``     established: the bound has not been reached.
#: - ``exhausted``       established: it has. Neither revocation nor expiry. L10.
#: - ``not_established`` the verifier cannot say. A fulfilment claim arrived that could not
#:   be authenticated, or could not be attributed to a party with standing. That
#:   establishes neither that the bound was reached nor that it was not, and it is never
#:   the negation of either. CAND-01.
#:
#: Proposed.
BOUND_STATES: tuple[str, ...] = ("not_reached", "exhausted", "not_established")

#: What a resolver says about one attestor's standing at one instant.
#:
#: Three values, and the third is the point. ``unknown`` is not ``does_not_hold_role``: a
#: resolver that cannot answer has not told the verifier that the attestor lacks the role,
#: and collapsing the two would turn an unanswered question into a finding.
ATTESTOR_ROLE_ANSWERS: tuple[str, ...] = ("holds_role", "does_not_hold_role", "unknown")

#: The reason codes this module emits. Stable, module-local, SCREAMING_SNAKE_CASE.
#:
#: - ``BOUND_NOT_REACHED``            not_reached: nothing accepted reaches the bound.
#: - ``PURPOSE_EXHAUSTED``            exhausted: an accepted fulfilment record.
#: - ``USE_COUNT_EXHAUSTED``          exhausted: admissions reached the limit.
#: - ``BUDGET_EXHAUSTED``             exhausted: committed plus reserved reached the ceiling.
#: - ``BOUND_STATE_NOT_ESTABLISHED``  not_established: at least one claim could not be
#:   established and none was accepted. The per-record code says which limb failed.
BOUND_REASON_CODES: tuple[str, ...] = (
    "BOUND_NOT_REACHED",
    "PURPOSE_EXHAUSTED",
    "USE_COUNT_EXHAUSTED",
    "BUDGET_EXHAUSTED",
    "BOUND_STATE_NOT_ESTABLISHED",
)

#: Per-record codes an assessment carries. A rejected record always says which of the three
#: failure classes it fell into, because "we did not accept it" is not an answer.
#:
#: ``FULFILMENT_ATTESTOR_WITHOUT_STANDING`` and ``FULFILMENT_SIGNATURE_INVALID`` are
#: deliberately separate. A valid signature establishes WHO signed. It does not establish
#: that the signer was allowed to make this statement, and this module will not collapse
#: the two failures. ``FULFILMENT_ATTESTOR_ROLE_UNKNOWN`` is a third thing again: nobody
#: has told the verifier anything.
FULFILMENT_REASON_CODES: tuple[str, ...] = (
    "FULFILMENT_ACCEPTED",
    "FULFILMENT_SCHEMA_INVALID",
    "FULFILMENT_NOT_BOUND_TO_BOUND",
    "FULFILMENT_OUTCOME_NOT_FULFILLED",
    "FULFILMENT_NOT_YET_ATTESTED",
    "FULFILMENT_KEY_UNRESOLVED",
    "FULFILMENT_SIGNATURE_INVALID",
    "FULFILMENT_ATTESTOR_WITHOUT_STANDING",
    "FULFILMENT_ATTESTOR_ROLE_UNKNOWN",
    "FULFILMENT_NOT_APPLICABLE_TO_KIND",
)


@dataclass(frozen=True)
class AuthorityBound:
    """A bound declared on one delegation.

    This module does NOT authenticate the bound declaration itself. A bound is an input
    the caller has already established, by whatever means its authority model provides: a
    principal signature over this body, an entry in a registry the verifier accepts, or a
    term of a contract outside the wire format. Saying so plainly matters, because
    draft-03's closed facet set means there is no way to put the bound inside the signed
    delegation, and a module that silently treated an unauthenticated bound as established
    would be inventing the very thing CAND-01 forbids inventing.

    What this module DOES authenticate is the fulfilment record, which is the external
    event CAND-01 is about.

    ``fulfilment_attestor_roles`` holds ROLES, not principals, for the reason a role
    registry exists at all: the party with standing to say a compressor was installed is
    whoever currently holds the maintenance-attestor role, not whoever held it when the
    grant was signed. An empty tuple means nobody but the delegation's issuer, and a
    resolver is still what decides whether a given attestor holds the role. Ignored for
    kind ``use_count`` and kind ``budget``, where no attestation is involved.
    """

    bound_id: str
    delegation_id: str
    kind: str
    #: kind ``purpose``: a hierarchical colon-separated purpose, the same grammar
    #: ``is_purpose_permitted`` reads for a scope grant.
    #: kind ``use_count``: a canonical unsigned decimal integer, no leading zero unless the
    #: value is exactly "0".
    #: kind ``budget``: a canonical unsigned decimal integer in the unit's minor units.
    value: str
    fulfilment_attestor_roles: tuple[str, ...] = ()
    record_type: str = AUTHORITY_BOUND_TYPE


@dataclass(frozen=True)
class FulfilmentAssessment:
    """What this module concluded about ONE fulfilment record."""

    attestor: str
    attested_at: str
    accepted: bool
    reason_code: str
    #: The resolver's answer, when one was asked for.
    role_answer: str | None = None
    #: Which establishment limb this rejection leaves missing, when the rejection is an
    #: evidential one rather than an established negative. ``None`` on an accepted record
    #: and on ``FULFILMENT_OUTCOME_NOT_FULFILLED``, which is a conclusion, not a gap.
    missing: tuple[str, ...] | None = None


@dataclass(frozen=True)
class BoundEvaluation:
    """What :func:`agent_passport.v2.bounds.evaluate_bound` concludes."""

    bound_id: str
    kind: str
    bound_state: str
    reason_code: str
    #: L10's ending vocabulary. ``"exhaustion"`` exactly when ``bound_state`` is
    #: ``exhausted``, and ``None`` otherwise. Never ``"expiry"`` and never
    #: ``"revocation"``: both of those are chain-verification answers, they arrive as
    #: EXPIRED and REVOKED failure codes on an AuthorityValidationResult, and a bound
    #: evaluation has no standing to restate them. A grant can be expired AND exhausted at
    #: the same instant, which is why the two are reported side by side and neither
    #: overwrites the other.
    ending: str | None
    #: The same conclusion in the ``lifecycle_state`` vocabulary, for reporting alongside a
    #: chain result. ``not_reached`` is ``valid``, ``exhausted`` is ``invalid`` (that
    #: vocabulary has no seventh verdict and exhaustion is one of the findings that lands
    #: there, separated by reason code), ``not_established`` is ``not_established`` with its
    #: limbs. Typed loosely to avoid a circular import, and it is a
    #: ``lifecycle_state.LifecycleStateResult``.
    lifecycle: object
    #: Every fulfilment record that was looked at, in the order supplied, with what
    #: happened to it. Never a count and never a boolean.
    fulfilments: tuple[FulfilmentAssessment, ...] = ()
    #: kind ``use_count`` only: admissions still allowed, as a canonical decimal string.
    #: "0" when exhausted. ``None`` for the other kinds.
    remaining: str | None = None


#: Resolve whether ``attestor`` held any of ``roles`` at ``at_instant``. Roles, not
#: principals. The resolver is the caller's, because who holds a role is not a local fact.
AttestorRoleResolver = Callable[[str, tuple[str, ...], str], str]

#: Resolve the verification key for one attestor's method as of one instant. ``None`` means
#: no key was resolved, which is a ``source`` gap and never a signature failure. The
#: instant-taking shape matches the historical key resolution invariant L9 describes.
BoundVerificationKeyResolver = Callable[[str, str, str], str | None]


class AuthorityBoundError(ValueError):
    """Raised when an input this module cannot read at all is passed.

    A malformed BOUND is a programming error, not a verdict: the module was asked a
    question about nothing. A malformed FULFILMENT RECORD is different and never raises,
    because a record somebody else wrote is data, and the right answer about it is a
    rejection with a reason code. ``code`` is the single stable code callers branch on.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
