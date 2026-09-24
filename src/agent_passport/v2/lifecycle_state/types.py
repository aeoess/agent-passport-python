# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. The lifecycle state vocabulary.

NOT REQUIRED BY draft-pidlisnyi-aps-03. Draft-03 section 3.3 states, verbatim:
"Verification returns one of valid, invalid, indeterminate, or unsupported with a
stable failure code." That enumeration is closed and this module does not touch it.
``AuthorityValidationResult`` and everything ``verify_authority_delegation_chain``
returns are unchanged. A caller that never imports this module sees exactly today's
behaviour.

What this module adds is a SECOND, separately named vocabulary for a different
question. Draft-03 asks whether a chain verifies. The lifecycle work asks what a
verifier can say about an authority artifact's current lifecycle state, and the corpus
behind it produces answers draft-03 has no slot for. Concept source: the
aeoess/agent-authority-lifecycle concept document (AUTHORITY-LIFECYCLE.md, invariant
candidates BROAD-L7, CAND-01, CAND-04, CAND-05, CAND-07, CAND-11, and invariant L8).
Every one of those is proposed, not specified. Nothing here claims otherwise.

Python port of the TypeScript SDK's src/v2/lifecycle-state/types.ts. Same names, same
semantics, snake_case per Python convention.

This module is deliberately small. It is the shared base other proposed lifecycle
modules build their results on, so it owns the vocabulary and nothing else. It has no
clock, no I/O, no crypto and no policy.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The six artifact verdicts. A verdict is always about a named subject, and this is the
#: set for the subject "an authority artifact at a moment".
#:
#: - ``valid``             the verifier establishes the artifact currently confers the
#:                         authority claimed.
#: - ``invalid``           the verifier establishes it does not, or no longer does.
#:                         Revoked, expired, exhausted, void from issuance and dependent
#:                         on an invalid ancestor all land here, separated by reason code.
#: - ``not_established``   the verifier cannot reach a conclusion. Ignorance, never a
#:                         finding about the world, and never the negation of the claim.
#: - ``not_yet_effective`` the verifier establishes the artifact is validly issued and
#:                         that an enabling condition (a date, an event, an activation
#:                         attestation) has not occurred yet. The remedy is to wait, not
#:                         to find a better source.
#: - ``suspended``         use is paused by one or more live causes, each separately
#:                         releasable.
#: - ``restricted``        authority continues in reduced form under a live constraint
#:                         that does not pause it.
#:
#: Concept source: aeoess/agent-authority-lifecycle, invariant candidates v2 section 2.2,
#: and invariant L8 (suspension is not revocation). Proposed.
LIFECYCLE_VERDICTS: tuple[str, ...] = (
    "valid",
    "invalid",
    "not_established",
    "not_yet_effective",
    "suspended",
    "restricted",
)

#: What an enforcement point decides about ONE action at ONE authorization boundary.
#: A different subject from the artifact verdicts, kept apart on purpose: a composition
#: rule that is not satisfied does not make any artifact invalid, it makes the action
#: unauthorized at that boundary, and a restriction imposed from outside the chain denies
#: the action without making the chain invalid.
#:
#: Concept source: aeoess/agent-authority-lifecycle, invariant candidates v2 section 2.1.
#: Proposed.
BOUNDARY_OUTCOMES: tuple[str, ...] = ("authorized", "denied", "not_established")

#: Which limb was missing when a state could not be established. A ``not_established``
#: verdict that does not say which of the three was missing is unreadable, so this module
#: makes at least one member mandatory on that verdict.
#:
#: - ``source``     no source the authority model accepts for this state produced a usable
#:                  answer, or the answer came from a source the model does not accept for
#:                  it, or two accepted sources are in unresolved conflict.
#: - ``freshness``  an answer existed but was older than the bound the model declares for
#:                  its source. Bounds are model declared; this module declares none.
#: - ``coverage``   the claim does not state that it covers what the verdict needed. A
#:                  verifier must not read a state claim as covering more than it states.
#:
#: Concept source: aeoess/agent-authority-lifecycle, invariant candidate BROAD-L7.
#: Proposed.
ESTABLISHMENT_GAPS: tuple[str, ...] = ("source", "freshness", "coverage")

#: THE TWO MEANINGS OF "NOT ESTABLISHED", SPLIT.
#:
#: Use A, the evidential sense, keeps the name. The verifier cannot reach the conclusion.
#: That is the verdict ``not_established``, and this module requires it to carry at least
#: one establishment gap, because saying which limb was missing is the whole content of
#: the answer.
#:
#: Use B, the established negative, is a conclusion the verifier HAS reached, and the
#: conclusion is negative. Three shapes appear and none of them is ``not_established``:
#:
#: ===================================== ==========================================
#: shape                                 correct output
#: ===================================== ==========================================
#: enabling_condition_not_yet_occurred   artifact verdict ``not_yet_effective``
#: composition_not_satisfied             boundary outcome ``denied``, stated reason
#: pinned_referent_mismatch              boundary outcome ``denied``, stated reason
#: ===================================== ==========================================
#:
#: Use :func:`~agent_passport.v2.lifecycle_state.resolve_established_negative` to get the
#: right output for a shape rather than reaching for ``not_established``. A module that
#: reports ignorance for a positively established negative teaches the collapse this
#: split exists to prevent.
#:
#: Concept source: aeoess/agent-authority-lifecycle, invariant candidates v2 section 3.
#: Proposed.
ESTABLISHED_NEGATIVE_SHAPES: tuple[str, ...] = (
    "enabling_condition_not_yet_occurred",
    "composition_not_satisfied",
    "pinned_referent_mismatch",
)

#: The reason codes this module's own mapping emits. Other lifecycle modules mint their
#: own; ``reason_code`` is typed as ``str`` so they can, and this tuple is not a closed
#: universe. Named here so the mapping's codes do not drift silently.
LIFECYCLE_BASE_REASON_CODES: tuple[str, ...] = (
    "CHAIN_VALID",
    "CHAIN_INVALID",
    "CHAIN_UNSUPPORTED",
    "CHAIN_INDETERMINATE",
    "NOT_BEFORE_UNREACHED",
)


@dataclass(frozen=True)
class OutstandingCause:
    """One cause, bound or condition still outstanding against an artifact.

    Never a count and never a boolean. Causes compose: an artifact can be subject to
    more than one concurrent suspension or restriction cause, releasing one does not
    release another, and a verdict has to say which ones remain. ``id`` names the cause,
    ``kind`` says what sort of thing it is (this module does not enumerate kinds; the
    module that owns the cause does), ``reason_code`` is that module's stable code.

    Concept source: aeoess/agent-authority-lifecycle, invariant candidate CAND-05.
    Proposed.
    """

    id: str
    kind: str
    reason_code: str


@dataclass(frozen=True)
class LifecycleStateResult:
    """What a lifecycle module concludes about one artifact at one moment.

    Reported ALONGSIDE a chain result, never merged into it. See
    :class:`CompositeAuthorityResult`.

    There is deliberately NO ``valid`` property on this class.
    ``AuthorityValidationResult`` has one and it is correct there, because that state set
    is genuinely two sided. Here the whole point is that ``not_established`` is not a
    boolean's false branch, and a truthiness shortcut invites exactly the collapse this
    vocabulary exists to prevent.

    Construct with :func:`lifecycle_state` or :func:`not_established`, which enforce the
    shape rules. Proposed.
    """

    verdict: str
    #: Stable, module-local, SCREAMING_SNAKE_CASE. Required on every verdict: two
    #: findings that share a verdict name must carry different reason codes, or a
    #: conformance claim that reports only verdict names is unreadable.
    reason_code: str
    #: Present with at least one member exactly when ``verdict`` is ``not_established``.
    missing: tuple[str, ...] | None = None
    #: Set when the authority model declared a default for absence and the verifier used
    #: it, which is how a verifier reaches a conclusion where it would otherwise have
    #: none. Incompatible with ``not_established`` by construction: if a default applied,
    #: the state was established.
    applied_default: str | None = None
    #: Present with at least one member exactly when ``verdict`` is ``suspended`` or
    #: ``restricted``. Every cause still outstanding, as a set.
    outstanding: tuple[OutstandingCause, ...] | None = None


@dataclass(frozen=True)
class EstablishedNegativeResolution:
    """Resolution of one established-negative shape to its correct subject and output.

    ``subject`` is ``"artifact"`` or ``"boundary"``. An artifact resolution carries
    ``verdict`` and leaves ``outcome`` ``None``; a boundary resolution carries
    ``outcome`` and leaves ``verdict`` ``None``. Neither ever carries
    ``not_established``.
    """

    shape: str
    subject: str
    reason_code: str
    verdict: str | None = None
    outcome: str | None = None


@dataclass(frozen=True)
class CompositeAuthorityResult:
    """What a caller reports when a lifecycle module ran alongside chain verification.

    ``chain`` is the draft-03 four-value result, exactly what
    ``verify_authority_delegation_chain`` returned. ``lifecycle`` is this vocabulary's
    answer, ``None`` when no module ran. The two are never merged and the second never
    rewrites the first: a later finding is a new record that references an earlier one.
    """

    chain: object
    lifecycle: LifecycleStateResult | None = None


class LifecycleStateError(ValueError):
    """Raised when a caller asks for a state the vocabulary does not allow.

    A shape rule broken at construction is a programming error, not a verdict. ``code``
    is the single stable code callers branch on.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
