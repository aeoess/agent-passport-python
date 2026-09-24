# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Multi-source status observation with per-source freshness bounds.

NOT REQUIRED BY draft-pidlisnyi-aps-03. Draft-03 section 3.3 rules exactly one revocation
result per chain member and closes chain verification at, verbatim: "Verification returns
one of valid, invalid, indeterminate, or unsupported with a stable failure code." It says
nothing about two sources answering about the same chain member, nothing about a per-source
freshness bound, nothing about coverage over a declared source set, and nothing about an
offline admission on a snapshot. Proposed draft-04 adds nothing here either.

So everything in this module is EXPERIMENTAL and proposed. Concept source: the
aeoess/agent-authority-lifecycle concept document, invariant candidate BROAD-L7, all three
limbs, whose broadened statement reads: any claim about current lifecycle state is
established only from a source the authority model accepts for that claim, within a
freshness bound the model declares, over the coverage the claim requires. Also invariant L7
(unknown revocation state is not active), which is the published-text half, and invariant
candidate CAND-01's second limb. Every one of those is proposed.

Python port of the TypeScript SDK's ``src/v2/status-coverage/``. Same names, same
semantics, snake_case per Python convention. A shared conformance vector file,
``conformance/status-coverage/v0/vectors.json``, is byte identical in both repositories and
both SDKs run it.

What this module does NOT change. ``AuthorityValidationResult`` and everything
``verify_authority_delegation_chain`` returns are exactly what they were. A caller that
never imports this module sees exactly today's behaviour.

THE COVERAGE LIMB DOES NOT ESTABLISH COMPLETENESS. :class:`StatusCoverage` expresses a
DECLARED required-source set and reports whether every member of it produced a usable
determinate answer. That is all. Invariant L12 (completeness is a separate and stronger
claim) is open, and OPEN-QUESTIONS.md names three unsettled pieces a completeness basis
would need. Nothing here answers any of them, and a caller must not read a
``complete=True`` coverage block as a statement that the declared set was every source that
mattered.

TWO READINGS THE PROPOSED TEXT DOES NOT CHOOSE BETWEEN, so this module refuses to choose
either and takes both as required parameters with no defaults:

1. What a conflict returns. Two accepted sources answering determinately and disagreeing
   can defensibly be a denial carrying a conflict reason, or a not-established state. They
   differ in what a caller may do next, and two implementations choosing differently are
   both consistent with the text as written. ``conflict_policy`` is required.
2. Whether an answer past its own bound still counts. Draft-03 section 3.5 says
   "Revocation is irreversible", which argues a ``revoked`` answer observed once does not
   become unobserved with age. Read the other way, L7's unavailable-or-stale rule drops it.
   The two readings give opposite verdicts on a stale revoked answer against a fresh active
   one. ``stale_policy`` is required.

A default on either would be this module making a specification decision in code.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..lifecycle_state.types import LifecycleStateResult

#: What one status source said about one ``authority_ref``.
#:
#: ``unavailable`` is a source that was consulted and produced no usable answer. It is not
#: a third determinate state and it is never used as one. Silence, a source that produced
#: no observation at all, is a different thing again and is carried by
#: :attr:`RequiredSourceSet.silence_is`.
STATUS_ANSWERS: tuple[str, ...] = ("active", "revoked", "unavailable")

#: The two answers that say something about the authority. Agreement and disagreement are
#: both measured over this set only.
DETERMINATE_STATUS_ANSWERS: tuple[str, ...] = ("active", "revoked")

#: What an accepted source going SILENT means. The proposed text does not say.
#:
#: - ``coverage_gap``       a required source that produced no observation is a hole in
#:                         coverage, and coverage is measured over the declared set.
#: - ``unavailable_answer`` silence is read as that source answering ``unavailable``, and
#:                         coverage is measured over the sources that answered.
#:
#: Required, no default, because the two readings decide whether a silent required source
#: blocks an admission and the text as written supports both.
SILENCE_POLICIES: tuple[str, ...] = ("coverage_gap", "unavailable_answer")

#: What a conflict returns. See the module docstring, reading 1. Required, no default.
CONFLICT_POLICIES: tuple[str, ...] = ("deny_with_conflict", "not_established")

VERIFIER_MODES: tuple[str, ...] = ("online", "offline")

#: Which denominator ``complete`` was measured against, derived from ``silence_is`` so the
#: choice is visible in the record rather than implied by a policy field.
COVERAGE_DENOMINATORS: tuple[str, ...] = ("declared_required_set", "sources_that_answered")

#: Why one answer was or was not used in the decision.
#:
#: - ``within_freshness_bound``                        the answer was inside the bound
#:                                                     declared for its source, so it was
#:                                                     used.
#: - ``revocation_observed_outside_bound_still_used``  a ``revoked`` answer past its bound,
#:                                                     used because
#:                                                     ``stale_revoked_still_counts`` is
#:                                                     set.
#: - ``stale_active_admitted_by_policy``               an ``active`` answer past its bound,
#:                                                     used because
#:                                                     ``stale_active_still_counts`` is
#:                                                     set.
#: - ``stale_beyond_bound``                            past its bound and not used.
#: - ``source_gave_no_answer``                         ``unavailable``, which is never used.
#: - ``answer_dated_after_boundary``                   ``as_of`` is later than the boundary
#:                                                     instant, so no age is measurable
#:                                                     against the bound. Not used. The
#:                                                     proposed text does not rule clock
#:                                                     skew at all, and this module refuses
#:                                                     the answer rather than reading a
#:                                                     negative age as fresh. Recorded
#:                                                     distinctly so a reader can tell skew
#:                                                     from staleness.
#: - ``source_not_accepted``                           an answer from a source that is
#:                                                     neither in the required set nor the
#:                                                     declared snapshot source. Not used.
#:                                                     BROAD-L7's source limb covers this:
#:                                                     an answer from a source the model
#:                                                     does not accept for the claim does
#:                                                     not establish it.
STATUS_USE_BASES: tuple[str, ...] = (
    "within_freshness_bound",
    "revocation_observed_outside_bound_still_used",
    "stale_active_admitted_by_policy",
    "stale_beyond_bound",
    "source_gave_no_answer",
    "answer_dated_after_boundary",
    "source_not_accepted",
)

#: The reason codes this module emits. Module local and stable, SCREAMING_SNAKE_CASE, which
#: is what ``LifecycleStateResult.reason_code`` requires. Not APS vocabulary: these names
#: are placeholders until the concept text is ruled.
#:
#: - ``STATUS_ACTIVE_ALL_SOURCES_AGREE``            authorized.
#: - ``ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND`` authorized, offline, and the basis names
#:                                                  the snapshot and the age.
#: - ``STATUS_REVOKED``                             denied, lifecycle verdict invalid.
#: - ``STATUS_SOURCES_CONFLICT``                    denied or not established per the
#:                                                  conflict policy, lifecycle verdict not
#:                                                  established with the source limb.
#: - ``STATUS_STALE_BEYOND_BOUND``                  not established, freshness limb.
#: - ``STATUS_COVERAGE_INCOMPLETE``                 not established, coverage limb.
#: - ``STATUS_NO_USABLE_OBSERVATION``               not established, source limb.
STATUS_COVERAGE_REASON_CODES: tuple[str, ...] = (
    "STATUS_ACTIVE_ALL_SOURCES_AGREE",
    "ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND",
    "STATUS_REVOKED",
    "STATUS_SOURCES_CONFLICT",
    "STATUS_STALE_BEYOND_BOUND",
    "STATUS_COVERAGE_INCOMPLETE",
    "STATUS_NO_USABLE_OBSERVATION",
)


@dataclass(frozen=True)
class DeclaredStatusSource:
    """One status source the authority model accepts, with the freshness bound the model
    declares FOR THAT SOURCE.

    Per source, not global. Deployed practice already carries a per-answer bound, and two
    sources fetched while writing this module say so. RFC 6960 section 2.4 defines the OCSP
    field, verbatim: "thisUpdate      The most recent time at which the status being
    indicated is known by the responder to have been correct." The W3C Bitstring Status List
    Recommendation of 15 May 2025 states, verbatim: "The ``ttl`` is an OPTIONAL property that
    indicates the "time to live" in milliseconds before a refresh SHOULD be attempted. If not
    present, no default value is assumed."

    Neither is a source for anything this module requires. They are cited only to show that a
    per-answer bound is an existing shape rather than an invention here. BROAD-L7 declares no
    number and neither does this module. The bound is the caller's, and a caller that has no
    declared bound has nothing to pass here, which is the point: BROAD-L7 forbids admitting
    on a stale snapshot with no declared bound.

    ``freshness_bound_s`` is in whole seconds and the comparison is INCLUSIVE: an age equal
    to the bound is within it.
    """

    source_id: str
    freshness_bound_s: int


@dataclass(frozen=True)
class StatusAnswerInput:
    """One answer, as supplied by the caller. This module reads no network and no clock.

    ``as_of`` is the instant the source says the answer was known correct, RFC 3339. ``None``
    exactly when the answer dates nothing, which is what ``unavailable`` means.
    """

    source_id: str
    answer: str
    as_of: str | None = None


@dataclass(frozen=True)
class RequiredSourceSet:
    """The set of sources the RELYING PARTY requires an answer from, declared by the relying
    party and never read from any record. Standing to be a status source for a claim is
    resolved outside the record, always.
    """

    required: tuple[DeclaredStatusSource, ...]
    silence_is: str


@dataclass(frozen=True)
class SnapshotSource:
    """The offline posture: a snapshot source and the maximum snapshot age the verifier
    declared IN ADVANCE that it would admit on.

    BROAD-L7 explicitly does not claim liveness is required. A declared offline posture with
    a snapshot inside its declared bound satisfies the rule, and the verifier records what
    it used. What the rule forbids is the undeclared version, admitting on a stale snapshot
    with no declared bound, which is unreachable here because ``declared_bound_s`` is
    required.
    """

    source_id: str
    declared_bound_s: int


@dataclass(frozen=True)
class StatusTrustPolicy:
    """What the verifier accepts, for one ``authority_ref``, at one authorization boundary.

    ``snapshot_source`` is present exactly when ``mode`` is ``offline``.
    """

    mode: str
    sources: RequiredSourceSet
    snapshot_source: SnapshotSource | None = None


@dataclass(frozen=True)
class StaleAnswerPolicy:
    """Whether an answer past its own source's bound still counts. See the module docstring,
    reading 2. Both members required, no defaults.

    The two are separate because the arguments for them are separate. A stale ``revoked``
    answer still counting rests on revocation being irreversible. A stale ``active`` answer
    still counting has no such argument behind it, and setting it true is the weakest posture
    this module can be put in.
    """

    stale_revoked_still_counts: bool
    stale_active_still_counts: bool


@dataclass(frozen=True)
class StatusSourceLine:
    """One source's answer with everything the decision derived from it. The audit half, and
    it is not optional: a reader of this line alone can recompute whether the answer was
    within its bound and whether it was used.

    ``freshness_bound_s`` is ``None`` when no bound was declared for the source, which is the
    ``source_not_accepted`` case.
    """

    source_id: str
    answer: str
    as_of: str | None
    age_s: int | None
    freshness_bound_s: int | None
    within_bound: bool
    used: bool
    use_basis: str


@dataclass(frozen=True)
class StatusConflict:
    """Two or more accepted sources in unresolved disagreement about one ``authority_ref``.

    ``states`` is the set of determinate answers that were used, sorted. ``sources`` is the
    sources that carried them, sorted. Both are named because a conflict a record does not
    attribute is not actionable.
    """

    states: tuple[str, ...]
    sources: tuple[str, ...]


@dataclass(frozen=True)
class StatusCoverage:
    """Coverage over the DECLARED required-source set. Not a completeness claim. See the
    module docstring.

    - ``required``           size of the declared required set.
    - ``answered``           required sources that produced any observation at all.
    - ``usable_determinate`` required sources whose answer was used and determinate.
    - ``silent``             required sources that produced no observation, sorted.
    """

    required: int
    answered: int
    usable_determinate: int
    silent: tuple[str, ...]
    measured_over: str
    complete: bool


@dataclass(frozen=True)
class AdmittedSnapshot:
    """The snapshot an offline admission actually admitted on, with the age it admitted at.

    Present exactly when the reason code is ``ADMITTED_ON_SNAPSHOT_WITHIN_DECLARED_BOUND``.
    This class exists because the proposed text does not require a verifier that admitted on
    a snapshot to record which snapshot or how old it was, and without the record the
    admission cannot be recomputed afterwards.
    """

    source_id: str
    as_of: str
    age_s: int
    declared_bound_s: int


@dataclass(frozen=True)
class MultiSourceStatusBasis:
    """Everything the decision rested on, in recomputable form. Both policies and the silence
    reading are echoed back, because a record that does not say which reading produced it
    cannot be compared against a record produced under the other.
    """

    authority_ref: str
    evaluated_at: str
    verifier_mode: str
    required_sources: tuple[str, ...]
    sources_consulted: tuple[StatusSourceLine, ...]
    sources_silent: tuple[str, ...]
    coverage: StatusCoverage
    conflict: StatusConflict | None
    snapshot: AdmittedSnapshot | None
    conflict_policy: str
    stale_policy: StaleAnswerPolicy
    silence_is: str


@dataclass(frozen=True)
class MultiSourceStatusDecision:
    """What this module concludes for one ``authority_ref`` at one authorization boundary.

    TWO SUBJECTS, kept apart, following the lifecycle-state vocabulary:

    - ``outcome`` is the BOUNDARY subject, what the enforcement point decides about the
      action here and now: ``authorized``, ``denied`` or ``not_established``.
    - ``lifecycle`` is the ARTIFACT subject, what the verifier can say about the authority's
      current lifecycle state.

    They are not the same answer and a conflict is where that shows. A conflict under
    ``deny_with_conflict`` denies the action while leaving the artifact's state NOT
    ESTABLISHED, not invalid: the verifier reached no conclusion about the authority, it
    refused the action. Under ``not_established`` both are not established. Nothing here ever
    reports a conflict as a finding that the authority is revoked, and nothing here claims an
    answer is false. A stale active answer is an answer the verifier could not use, not a lie.

    Reported ALONGSIDE a chain result, never merged into it. A later boundary that finds a
    conflict is a new decision that references the earlier record, and it never rewrites it.
    """

    outcome: str
    lifecycle: LifecycleStateResult
    reason_code: str
    basis: MultiSourceStatusBasis


class StatusCoverageError(ValueError):
    """Raised when the input is not something the module can decide over.

    A malformed input is a programming error, not a verdict: returning ``not_established``
    for a caller that passed an unparseable instant would report ignorance about the
    authority when the defect is in the call. ``code`` is the single stable code callers
    branch on.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
