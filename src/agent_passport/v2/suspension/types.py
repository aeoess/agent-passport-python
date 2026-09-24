# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Suspension and restriction as a SET OF CAUSES.

NOT REQUIRED BY draft-pidlisnyi-aps-03. The published draft states no suspension rule,
no restriction rule, no release rule and no lifecycle-standing rule: a case-insensitive
search of the published plain text returns zero occurrences of ``suspend`` and
``suspension``, and the only status answer the protocol has is the revocation resolver's
closed set ``active``, ``revoked``, ``unknown``. There is nowhere in that type to put one
cause, let alone three. Section 3.2 closes the authority vector at seven facets and says a
missing facet is invalid, so no cause can ride inside a signed ``AuthorityDelegationV1``
either. Section 3.3 closes chain verification at four values.

Nothing in this module touches any of that. ``AuthorityValidationResult`` and everything
``verify_authority_delegation_chain`` returns are unchanged. A caller who never imports
this module sees exactly today's behaviour.

CONCEPT SOURCE: the aeoess/agent-authority-lifecycle concept document.

- invariant L8, "Suspension is not revocation": suspension stops the use of authority and
  can be lifted, revocation is terminal for the artifact it names, and a restricted state
  is different again and does not have to pause descendants. L8 is marked proposed there
  and says nothing about ARITY, so an implementation holding exactly one suspension at a
  time conforms to every word of it and is still wrong.
- invariant candidate CAND-05, "Suspension and restriction causes compose": an authority
  artifact can be subject to more than one concurrent cause, a verifier must represent
  them as a SET rather than as a single state, releasing one cause does not release
  another, a release is effective against a cause only from a source with lifecycle
  standing over THAT cause (which is not necessarily the source that imposed it), and
  where any cause remains unreleased the verdict remains suspended or restricted and
  records which causes remain.
- ``OPEN-QUESTIONS.md``, "Release from suspension", which says in terms that lifting one
  suspension should not clear another or bypass a revocation that happened while the agent
  was suspended, that causes probably need to compose with each released separately, and
  that none of it is specified yet.

CAND-05 states plainly that composition is FORCED BY THE CORPUS AND EXTERNALLY UNSOURCED.
This module inherits that: it is one reading of a paragraph that says "probably" and "not
yet specified", and every identifier here is a placeholder to argue about rather than
minted vocabulary.

Python port of the TypeScript SDK's src/v2/suspension/types.ts. Same names, same
semantics, snake_case per Python convention.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..lifecycle_state.types import LifecycleStateResult, OutstandingCause

#: Record type of a lifecycle cause. The ``proposed:`` namespace is deliberate: this is not
#: an APS record type, nothing published defines it, and it stays namespaced until the
#: schema owner rules on it.
SUSPENSION_CAUSE_TYPE = "proposed:aps:suspension-cause:v0"

#: Record type of a cause release. Also not an APS record type.
SUSPENSION_RELEASE_TYPE = "proposed:aps:cause-release:v0"

#: The two pause kinds invariant L8 separates.
#:
#: ``suspension`` pauses the use of authority and of everything that depends on it.
#: ``restriction`` is an external block that can stop some effects while the grant itself
#: stays valid, and it does not have to pause descendants. This module does not model
#: descendant propagation for either kind: what it decides is the state of the ONE artifact
#: its causes name.
#:
#: Concept source: aeoess/agent-authority-lifecycle, invariant L8. Proposed.
PAUSE_KINDS: tuple[str, ...] = ("suspension", "restriction")

#: What a standing resolver may answer about one release against one cause.
#:
#: Three values, not two, because "I do not know whether this party holds standing over
#: this cause" is not the same finding as "this party does not hold standing over it".
#: CAND-05's standing clause is what blocks an internal process clearing an externally
#: imposed restriction, and its non-authorship clause blocks the opposite error of refusing
#: a superior source's release. Neither clause says what to do when the answer is absent,
#: so this module reports absence as absence.
#:
#: Proposed.
RELEASE_STANDINGS: tuple[str, ...] = ("has_standing", "no_standing", "unknown")


@dataclass(frozen=True)
class SuspensionCause:
    """One lifecycle cause standing against one authority artifact.

    A cause is a SEPARATE SIGNED ARTIFACT that references ``delegation_id``. It is not a
    facet, not a flag on the delegation and not a field anything existing carries, because
    draft-03 section 3.2 closes the authority vector at seven facets and calls a missing
    facet invalid. Adding an eighth would break every existing record.

    ``release_authority`` is ADVISORY ONLY and NEVER CONSULTED BY THIS MODULE. A cause may
    name who it believes may release it, and :func:`evaluate_pause_state` does not read
    that member and does not let it decide anything, because standing is resolved outside
    the record, always, and a verifier never reads standing from the artifact asserting it.
    A cause that could nominate its own releaser would let the imposer of a cause decide who
    may lift it, which is precisely the superior-authority case CAND-05 says an implementer
    gets wrong by reading "standing over that cause" as "the source that imposed it". It is
    carried so a caller's ``resolve_release_standing`` can read it off the cause it is
    handed, if that caller's authority model gives it weight. ``tests/test_suspension.py``
    contains a negative control that sets it to the releasing party and asserts the release
    is still ineffective when the resolver answers ``no_standing``.

    ``extra`` holds any member the record carried that this class does not name. Every
    member signs, including these, so an extension cannot be added to a record after
    signing. Proposed.
    """

    record_type: str
    cause_id: str
    delegation_id: str
    kind: str
    imposed_by: str
    issued_at: str
    reason_code: str
    verification_method: str
    signature: str
    release_authority: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SuspensionRelease:
    """A record releasing one or more named causes.

    One release MAY clear several causes: CAND-05 says in terms that it does not claim a
    single release record cannot clear several, and that one record from a party with
    standing over each of them can release all of them. What is forbidden is releasing
    cause A having the SIDE EFFECT of clearing cause B. So the record names every cause it
    claims to clear and the evaluator clears exactly those the releaser holds standing over,
    deciding each one independently. A release record is not a list of assertions a verifier
    accepts wholesale. Proposed.
    """

    record_type: str
    release_id: str
    delegation_id: str
    cause_ids: tuple[str, ...]
    issuer: str
    issued_at: str
    verification_method: str
    signature: str
    extra: Mapping[str, Any] = field(default_factory=dict)


#: Every stable code this module emits, on a verdict or on a disposition.
#:
#: Module-local and SCREAMING_SNAKE_CASE, per the lifecycle-state vocabulary's rule that two
#: findings sharing a verdict name must be told apart by their codes. These are a proposal:
#: the conformance suite's CONTRIBUTING.md reserves failure-class names and verifier
#: semantics to the schema owner, and a module is not the vehicle for minting them.
SUSPENSION_REASON_CODES: tuple[str, ...] = (
    # --- verdict codes ---------------------------------------------------------------
    # ``valid``: the input carried no cause at all. Says nothing about the chain.
    "NO_CAUSE_PRESENTED",
    # ``valid``: causes were presented and none is in evidence at this instant. Distinct
    # from the above so a caller can see records were offered and rejected rather than
    # never supplied.
    "NO_CAUSE_IN_EVIDENCE",
    # ``valid``: every cause in evidence was released by a party holding standing over it.
    "ALL_CAUSES_RELEASED",
    # ``suspended`` or ``restricted``: at least one cause in evidence remains unreleased.
    # The result's ``outstanding`` member names every one of them.
    "CAUSES_OUTSTANDING",
    # ``not_established``, missing ``source``: a standing resolver answered ``unknown`` for
    # a cause nothing else released, so whether that cause still holds is not something this
    # verifier established either way.
    "RELEASE_STANDING_NOT_ESTABLISHED",
    # --- cause dispositions ----------------------------------------------------------
    "CAUSE_IN_EVIDENCE",
    "CAUSE_NOT_ON_DELEGATION",
    "CAUSE_RECORD_TYPE_UNRECOGNISED",
    "CAUSE_NOT_YET_IN_EVIDENCE",
    "CAUSE_SIGNATURE_UNVERIFIED",
    "CAUSE_IMPOSER_BINDING_MISMATCH",
    "CAUSE_RELEASED",
    # --- release record dispositions --------------------------------------------------
    "RELEASE_IN_EVIDENCE",
    "RELEASE_NOT_ON_DELEGATION",
    "RELEASE_RECORD_TYPE_UNRECOGNISED",
    "RELEASE_SIGNATURE_UNVERIFIED",
    "RELEASE_ISSUER_BINDING_MISMATCH",
    "RELEASE_AFTER_EVALUATION_INSTANT",
    # --- per-cause dispositions inside a release ---------------------------------------
    "CAUSE_NOT_PRESENTED",
    "RELEASE_PRECEDES_IMPOSITION",
    "RELEASER_WITHOUT_STANDING",
)


@dataclass(frozen=True)
class ReleaseCauseDisposition:
    """How one cause named inside one release record was decided."""

    cause_id: str
    disposition: str


@dataclass(frozen=True)
class ReleaseDisposition:
    """How one release record was decided, and what it did to each cause it named.

    ``causes`` is empty exactly when the record failed a record-level check, because a
    record rejected at record level is never applied to any cause.
    """

    release_id: str
    disposition: str
    causes: tuple[ReleaseCauseDisposition, ...] = ()


@dataclass(frozen=True)
class CauseDisposition:
    """How one cause was decided.

    ``released_by`` names the release record that cleared it, and is present exactly when
    ``disposition`` is ``CAUSE_RELEASED``.
    """

    cause_id: str
    disposition: str
    released_by: str | None = None


@dataclass(frozen=True)
class PauseStateExplanation:
    """The full audit trail behind a pause state, for a caller that has to show its work.

    ``state`` is the same value :func:`evaluate_pause_state` returns. The two disposition
    tuples are why: a verdict that names which causes remain is CAND-05's whole content, and
    a caller writing evidence needs to say why each record did or did not move the answer.

    ``outstanding`` mirrors ``state.outstanding`` exactly, and is empty where the state
    carries none. Exposed separately so a caller does not have to branch on the verdict.
    """

    state: LifecycleStateResult
    causes: tuple[CauseDisposition, ...]
    releases: tuple[ReleaseDisposition, ...]
    outstanding: tuple[OutstandingCause, ...]


#: Resolves standing for one release against one cause.
#:
#: Handed both records so a caller's authority model can look at whatever it needs. What it
#: must NOT be is the identity comparison ``release.issuer == cause.imposed_by``: CAND-05
#: says explicitly that standing is not authorship, and cites a court's power over
#: conditions it did not create. A resolver that implements authorship is a defensible
#: reading of text that does not exist yet, which makes it a finding about the text rather
#: than a defect, but it is not this module's reading and this module will not supply it.
ReleaseStandingResolver = Callable[[SuspensionRelease, SuspensionCause], str]

#: Resolves the public key a record's ``verification_method`` names, as hex.
#:
#: Same shape as the chain verifier's own key resolver: caller supplied, no I/O inside this
#: module, ``None`` when the key cannot be resolved. A record whose key does not resolve
#: fails its signature check and is not in evidence.
SuspensionVerificationKeyResolver = Callable[[str, str], "str | None"]
