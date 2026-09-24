# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Authority state markers, write fencing, and withdrawal of a recorded
revocation.

NOT REQUIRED BY draft-pidlisnyi-aps-03. The published text contains no occurrence of
``epoch``, ``fencing``, ``snapshot``, ``replica`` or ``restore``, and defines no record for
withdrawing a revocation. What it does fix, and what this module is careful not to disturb,
is section 3.3: "Verification returns one of valid, invalid, indeterminate, or unsupported
with a stable failure code", and section 3.5: "Revocation is irreversible."
``AuthorityValidationResult``, the revocation store and everything
``verify_authority_delegation_chain`` returns are unchanged, and a caller that never imports
this module sees exactly today's behaviour.

Concept source: the aeoess/agent-authority-lifecycle concept document
(AUTHORITY-LIFECYCLE.md, the ``Authority epoch`` concept and invariants L3, L7 and L11;
OPEN-QUESTIONS.md, ``Authority rollback``) and its invariant candidates CAND-08 (no silent
restoration from rollback or stale state) and CAND-02 (later evidence does not rewrite
earlier evidence). Every one of those is proposed, not specified. Nothing here claims
otherwise, and ``OPEN-QUESTIONS.md`` keeps open both the mechanism and what a verifier
should return after a restore.

Three deliberate non-decisions are encoded as types rather than as behaviour:

1. The proposed text says an authority epoch is "where a system uses generations" and
   stops. It does not say who advances one, whether it is global or per delegation, whether
   it is signed, or what evidence carries it. :class:`StateMarker` is therefore an opaque
   comparable supplied by the caller, and this module defines only the comparison.
2. A verifier with no prior observation has nothing to compare against. That is
   ``unplaceable``, and it is not a verdict. The caller says what to do with it.
3. Who may withdraw a revocation is not stated anywhere. Standing is resolved through an
   injected callback and never read from the record asserting it.

Python port of the TypeScript SDK's src/v2/authority-state/types.ts. Same names, same
semantics, snake_case per Python convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

#: What a marker is counted within. Comparing two markers from different scopes orders
#: nothing, so the comparison reports ``unplaceable`` rather than inventing an order.
#:
#: The proposed text names none of these. They exist because the fixture that forced this
#: module had to pick one (it picked a global integer on a state view) and recorded that the
#: choice was not read from the text. Carrying the scope makes that choice visible in the
#: record instead of implicit in the deployment. Proposed.
STATE_MARKER_SCOPES: tuple[str, ...] = ("global", "per_delegation", "per_principal", "per_store")

#: The result of placing a presented marker against what a verifier has established.
#:
#: - ``forward``      the presented marker advanced, or held equal. Read the view normally.
#: - ``regressed``    the presented marker went backwards against an established high-water
#:                    mark. CAND-08's refusal case.
#: - ``unplaceable``  there is nothing to compare against, or the two markers are counted in
#:                    different scopes. **Deliberately not a verdict.** A high-water mark has
#:                    to start somewhere and neither the proposed text nor draft-03 says
#:                    whether a first read is trusted or refused. Both are defensible and the
#:                    outcomes differ, so this module reports the fact and the caller decides.
MONOTONICITY_OUTCOMES: tuple[str, ...] = ("forward", "regressed", "unplaceable")

#: What a caller wants done with an ``unplaceable`` presented view. Required, with no
#: default, because the SDK picking one would be the SDK deciding a question its own concept
#: source records as undecided.
UNPLACEABLE_DISPOSITIONS: tuple[str, ...] = ("read_presented", "refuse")

#: Why a fenced write was refused.
#:
#: - ``stale_fencing_token``      the token went backwards against the highest already seen.
#:                                The only one of the three the source states.
#: - ``fencing_scope_mismatch``   the token is counted in a different scope from the log's,
#:                                so it cannot be ordered against what the log holds.
#: - ``fencing_token_unreadable`` the token is absent or not a well-formed marker.
#:
#: A write path that cannot order a token is not fenced, so the second and third refuse
#: rather than guess. Neither is in any source; both are this module's choice.
FENCED_WRITE_REFUSAL_CODES: tuple[str, ...] = (
    "stale_fencing_token",
    "fencing_scope_mismatch",
    "fencing_token_unreadable",
)

#: The record type a withdrawal carries.
#:
#: ``proposed:`` is load-bearing. Record fields, failure-class names and verifier semantics
#: are conformance vocabulary reserved to the maintainer, and neither draft-03 nor the
#: proposed text defines a record for withdrawing a recorded revocation or says what a
#: verifier should do with one. This is a placeholder to argue about, not APS vocabulary.
REVOCATION_WITHDRAWAL_RECORD_TYPE = "proposed:aps:revocation-withdrawal:v0"
REVOCATION_WITHDRAWAL_VERSION = "0"

#: What an injected standing resolver may answer.
#:
#: ``unknown`` is a first-class answer and is not ``no_standing``. A verifier that cannot
#: establish whether the withdrawer had standing has not established that they lacked it,
#: and the refusal reason says which of the two happened.
WITHDRAWAL_STANDINGS: tuple[str, ...] = ("has_standing", "no_standing", "unknown")

#: Why a withdrawal was accepted or refused. Stable, module-local codes.
WITHDRAWAL_OUTCOME_CODES: tuple[str, ...] = (
    # Accepted as a record. Accepted never means the revocation is gone.
    "WITHDRAWAL_ACCEPTED",
    # The record is not a well-formed withdrawal.
    "WITHDRAWAL_SCHEMA_INVALID",
    # No revocation in the held set carries the revocation_id this record names.
    "WITHDRAWAL_NAMES_NO_HELD_REVOCATION",
    # The named revocation exists but is a revocation of a different delegation.
    "WITHDRAWAL_TARGET_MISMATCH",
    # The resolver established that this party may not withdraw this revocation.
    "WITHDRAWAL_SIGNER_WITHOUT_STANDING",
    # The resolver could not establish standing either way. Not the same finding as the one
    # above, and reported as not established rather than as a denial.
    "WITHDRAWAL_STANDING_NOT_ESTABLISHED",
)


class AuthorityStateError(ValueError):
    """Raised when a caller asks for a marker or record the vocabulary does not allow.

    A shape rule broken at construction is a programming error, not a verdict. ``code`` is
    the single stable code callers branch on. Mirrors ``LifecycleStateError`` in
    ``agent_passport.v2.lifecycle_state``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class StateMarker:
    """A monotonic generation marker on authority state.

    ``value`` is a canonical unsigned decimal integer, the same convention the seven-facet
    authority vector already uses for spend quantities: no sign, no leading zero, no
    separators, arbitrary width. It is a string rather than an int so it round-trips through
    JSON unchanged at any width, and it is compared as an integer, never lexically.

    Nothing here is signed and nothing here is a wire field. No delegation, revocation or
    store in this SDK carries a marker, and none is being given one: a marker is state the
    caller has about a state source, handed in at comparison time. Proposed.
    """

    value: str
    scope: str
    #: Which delegation, principal or store this marker is counted within. Required on every
    #: scope except ``global``, where it is ``None``.
    scope_ref: str | None = None


@dataclass(frozen=True)
class RetainedAuthorityState:
    """What a verifier has established about authority state, as TWO separate inputs.

    Splitting them is the whole point of this class. Two verifiers can hold the same
    high-water mark and give different answers about the same restored view: the one that
    retained the revocation records it observed can establish a revocation from records and
    answers ``revoked``, and the one that retained only the number cannot, and answers
    ``unknown``, which draft-03 section 3.3 makes indeterminate. The proposed text does not
    distinguish those two verifiers at all, and the distinction turns out to be the substance
    of the rollback question. An API taking "the epoch" as one value cannot express it.

    ``records`` is not a store and does not behave like one. It can answer ``revoked`` and it
    can answer ``unknown``. It can never answer ``active``: a retained record set says
    nothing about the delegations it does not mention, which is the same reason absence from
    a revocation store is ``unknown`` rather than ``active``.
    """

    #: Revocation records the verifier retained at its high-water mark. Each is re-verified
    #: against the delegation in front of it before it can produce a ``revoked`` answer, so a
    #: record that reached this tuple by some other route still cannot assert one.
    records: tuple[dict[str, Any], ...] = ()
    #: The newest marker this verifier has established, or ``None`` if it has established
    #: none.
    high_water_mark: StateMarker | None = None


@dataclass(frozen=True)
class FencedWriteOutcome:
    """What a fenced log reports about one write.

    An EQUAL token is accepted, and that is not an oversight. The rule the source states is
    about tokens going backwards, and an equal token has not gone backwards: it is the same
    holder retrying, which makes a retry idempotent.

    ``code`` is ``None`` on an accepted write and one of
    :data:`FENCED_WRITE_REFUSAL_CODES` on a refused one. ``published`` is the highest token
    the log holds after this call, which on a refusal is the one it already held.
    """

    accepted: bool
    published: StateMarker | None = None
    code: str | None = None
    payload: Any = None


@dataclass(frozen=True)
class RevocationWithdrawalV0:
    """A record stating that a recorded revocation was published in error.

    It REFERENCES the revocation and never removes it. Inside a revocation store
    irreversibility is already structural: the store exposes ``track``, ``tracks``, ``get``
    and ``insert_verified_revocation``, there is no removal method, and this module does not
    add one. Draft-03 section 3.5 states "Revocation is irreversible", and a removal method
    would be one call away from breaking it.

    NOT AUTHENTICATED BY THIS MODULE. There is no canonical preimage here, no signature
    field, and no verification function, deliberately: minting the signed form of a record
    type is the vocabulary decision this module is not entitled to make. A caller hands in a
    withdrawal it has already authenticated, exactly as ``insert_verified_revocation`` takes
    a revocation ``record_authority_revocation`` has already verified. Whoever reaches
    :func:`evaluate_revocation_withdrawal` is the party asserting the record is genuine.
    """

    #: The revocation this record withdraws: ``sha256:<64 lowercase hex>``.
    revocation_id: str
    #: The delegation that revocation named. Carried so a withdrawal that names a revocation
    #: of a different delegation is refusable without a second lookup.
    delegation_id: str
    #: Who states the withdrawal. Whether this party may is NOT decided here.
    withdrawn_by: str
    #: Canonical UTC-millisecond time, supplied by the caller, never read from a clock.
    withdrawn_at: str
    #: Machine-readable ground. No grammar is fixed for one and none is invented here.
    reason_code: str
    #: OPTIONAL free-text detail. ``None`` means absent.
    detail: str | None = None
    record_type: str = REVOCATION_WITHDRAWAL_RECORD_TYPE
    version: str = REVOCATION_WITHDRAWAL_VERSION


#: Decides whether a withdrawal's author may withdraw this revocation.
#:
#: Injected, never hardcoded, and never read from the withdrawal record itself. Draft-03
#: section 3.5 states "Any delegation MAY be revoked by its issuer" and the SDK enforces
#: ``revoker == issuer`` for a revocation. Nothing anywhere states who may WITHDRAW one.
#: :func:`withdrawal_signer_is_revoker` is supplied as one resolver, is what the forcing
#: fixture chose, and is a choice rather than a rule read from any text.
WithdrawalStandingResolver = Callable[["RevocationWithdrawalV0", dict[str, Any]], str]


@dataclass(frozen=True)
class WithdrawalEvaluation:
    """What :func:`evaluate_revocation_withdrawal` concludes about one withdrawal record."""

    accepted: bool
    reason_code: str
    #: What the resolver answered, or ``None`` when evaluation refused before asking it.
    standing: str | None
    #: The record evaluated, unchanged.
    withdrawal: Any


@dataclass(frozen=True)
class CorrectedRevocationView:
    """The current position of one revocation together with every withdrawal referencing it.

    This is CAND-02 made into a shape. The revocation is present, unchanged, whether or not a
    withdrawal was accepted. A later finding is a new record that references the earlier one
    and states its own effect; it is never an edit of the earlier one and never its removal.
    A verifier that must report "revoked, and the revoker later said this was recorded in
    error" reports exactly this.
    """

    #: The revocation record, byte for byte what it was.
    revocation: dict[str, Any]
    #: Accepted withdrawals, in the order supplied. Non-empty does NOT make the revocation
    #: ineffective and does NOT change any chain verdict.
    accepted: tuple[WithdrawalEvaluation, ...] = ()
    #: Refused withdrawals, each with the code saying why. A withdrawal that changes nothing
    #: in silence is indistinguishable from one that was never submitted.
    refused: tuple[WithdrawalEvaluation, ...] = ()


@dataclass(frozen=True)
class AuthorityStateReport:
    """A chain result, the lifecycle vocabulary's reading of it, how the state view placed,
    and the correction records that reference any revocation behind it.

    Five fields, five separate claims, none merged into another. ``chain`` is exactly what
    ``verify_authority_delegation_chain`` returned and a caller that reads only that field
    sees exactly today's behaviour.
    """

    chain: Any
    lifecycle: Any = None
    #: How the presented state view placed against the verifier's established mark, or
    #: ``None`` when no state comparison ran.
    monotonicity: str | None = None
    #: The mark the verifier holds after this read.
    high_water_mark_after: StateMarker | None = None
    #: Revocations behind this result together with the withdrawals referencing them. Empty
    #: when none was submitted. A non-empty ``accepted`` list NEVER implies the chain result
    #: would have been different.
    corrections: tuple[CorrectedRevocationView, ...] = ()
