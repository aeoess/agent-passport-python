# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""PROPOSED, OPT-IN. Withdrawal, or correction, of a recorded revocation.

See ``types.py`` for the specification position. Concept source:
aeoess/agent-authority-lifecycle, invariant candidate CAND-02 (later evidence does not
rewrite earlier evidence) and invariant L3 (reauthorization creates new authority). Proposed.

THE ONE SENTENCE THIS FILE EXISTS FOR. A corrected false revocation is a separate record, not
a resurrection. Draft-03 section 3.5 states "Revocation is irreversible", and nothing below
relaxes that: an accepted withdrawal leaves the revocation held, leaves it verifying byte for
byte, and leaves every chain verdict exactly where it was. What the withdrawal changes is what
a verifier can REPORT, which had no representation at all.

Continuity after a correction still needs a fresh grant from a principal who currently holds
authority. This module mints no grant and no authority of any kind.

Python port of the TypeScript SDK's src/v2/authority-state/withdrawal.ts.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from .types import (
    REVOCATION_WITHDRAWAL_RECORD_TYPE,
    REVOCATION_WITHDRAWAL_VERSION,
    WITHDRAWAL_STANDINGS,
    AuthorityStateError,
    CorrectedRevocationView,
    RevocationWithdrawalV0,
    WithdrawalEvaluation,
)

_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


def is_withdrawal_standing(value: object) -> bool:
    return isinstance(value, str) and value in WITHDRAWAL_STANDINGS


def revocation_withdrawal(
    *,
    revocation_id: str,
    delegation_id: str,
    withdrawn_by: str,
    withdrawn_at: str,
    reason_code: str,
    detail: str | None = None,
) -> RevocationWithdrawalV0:
    """Build a :class:`RevocationWithdrawalV0`.

    A shape constructor and nothing more. It does not sign, does not canonicalize, and does
    not compute an identifier, because minting the signed form of a record type is a
    conformance-vocabulary decision reserved to the maintainer and this module is not making
    it. ``record_type`` carries the ``proposed:`` namespace for the same reason.
    """
    for name, value in (("revocation_id", revocation_id), ("delegation_id", delegation_id)):
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise AuthorityStateError(
                "WITHDRAWAL_ID_NONCANONICAL", f"{name} must be sha256:<64 lowercase hex>"
            )
    for name, value in (
        ("withdrawn_by", withdrawn_by),
        ("withdrawn_at", withdrawn_at),
        ("reason_code", reason_code),
    ):
        if not isinstance(value, str) or value == "":
            raise AuthorityStateError(
                "WITHDRAWAL_FIELD_REQUIRED", f"{name} must be a non-empty string"
            )
    if detail is not None and (not isinstance(detail, str) or detail == ""):
        raise AuthorityStateError(
            "WITHDRAWAL_DETAIL_INVALID", "detail must be a non-empty string when present"
        )
    return RevocationWithdrawalV0(
        revocation_id=revocation_id,
        delegation_id=delegation_id,
        withdrawn_by=withdrawn_by,
        withdrawn_at=withdrawn_at,
        reason_code=reason_code,
        detail=detail,
    )


def withdrawal_signer_is_revoker(withdrawal: Any, revocation: Mapping[str, Any]) -> str:
    """A standing resolver that accepts a withdrawal only from the party the revocation itself
    names as revoker.

    Supplied because it is the rule the forcing fixture chose and it needs to be runnable.
    IT IS A CHOICE, NOT A RULE READ FROM ANY TEXT. Draft-03 section 3.5 names the issuer as
    the party who may revoke; nothing in draft-03 or in the proposed text says who may
    withdraw a revocation, and the concept document's own ``Lifecycle standing`` entry says
    the party who may change an artifact "is not always the issuer". A deployment whose
    authority model gives a security function, a successor or a quorum standing to correct a
    publication error should pass its own resolver instead of this one.
    """
    return (
        "has_standing"
        if _field(withdrawal, "withdrawn_by") == revocation.get("revoker")
        else "no_standing"
    )


def _field(record: Any, name: str) -> Any:
    """Read one field from either a dataclass record or a plain mapping.

    Both shapes are accepted because a withdrawal arrives either from
    :func:`revocation_withdrawal` or, in a runner, decoded from JSON.
    """
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def _malformed(withdrawal: Any) -> bool:
    if withdrawal is None:
        return True
    if _field(withdrawal, "record_type") != REVOCATION_WITHDRAWAL_RECORD_TYPE:
        return True
    if _field(withdrawal, "version") != REVOCATION_WITHDRAWAL_VERSION:
        return True
    for name in ("revocation_id", "delegation_id"):
        value = _field(withdrawal, name)
        if not isinstance(value, str) or not _ID.fullmatch(value):
            return True
    for name in ("withdrawn_by", "withdrawn_at", "reason_code"):
        value = _field(withdrawal, name)
        if not isinstance(value, str) or value == "":
            return True
    return False


def evaluate_revocation_withdrawal(
    withdrawal: Any,
    held_revocations: Iterable[Mapping[str, Any]],
    resolve_standing: Any,
) -> WithdrawalEvaluation:
    """Decide whether one withdrawal record is accepted against a set of held revocations.

    Four questions, kept separate on purpose, each with its own code:

    1. Is the record a well-formed withdrawal? ``WITHDRAWAL_SCHEMA_INVALID``.
    2. Does it name a revocation the held set actually contains?
       ``WITHDRAWAL_NAMES_NO_HELD_REVOCATION``.
    3. Does that revocation revoke the delegation this record names?
       ``WITHDRAWAL_TARGET_MISMATCH``.
    4. May this party withdraw it? Asked of the injected resolver, never of the record.
       ``WITHDRAWAL_SIGNER_WITHOUT_STANDING`` when the resolver establishes they may not, and
       ``WITHDRAWAL_STANDING_NOT_ESTABLISHED`` when it cannot establish either way.

    The last split is the wording rule, executable: a standing question the verifier could not
    answer is not established, and that is not the same finding as a party established to lack
    standing. Both refuse the withdrawal, and a caller reporting the refusal has to be able to
    say which one happened.

    AUTHENTICATION IS THE CALLER'S. This function never checks a signature, because a
    withdrawal has no signed form in this SDK, on purpose; see
    :class:`~agent_passport.v2.authority_state.types.RevocationWithdrawalV0`. Whoever calls it
    is the party asserting the record is genuine, exactly as whoever calls
    ``insert_verified_revocation`` asserts the revocation was verified.

    NOTHING HERE REMOVES A REVOCATION, on any path. An accepted withdrawal is a record about a
    record. The held set handed in is not mutated and no store is touched.
    """
    if _malformed(withdrawal):
        return WithdrawalEvaluation(
            accepted=False,
            reason_code="WITHDRAWAL_SCHEMA_INVALID",
            standing=None,
            withdrawal=withdrawal,
        )

    revocation_id = _field(withdrawal, "revocation_id")
    target = None
    for record in held_revocations or ():
        if isinstance(record, Mapping) and record.get("revocation_id") == revocation_id:
            target = record
            break

    if target is None:
        return WithdrawalEvaluation(
            accepted=False,
            reason_code="WITHDRAWAL_NAMES_NO_HELD_REVOCATION",
            standing=None,
            withdrawal=withdrawal,
        )
    if target.get("delegation_id") != _field(withdrawal, "delegation_id"):
        return WithdrawalEvaluation(
            accepted=False,
            reason_code="WITHDRAWAL_TARGET_MISMATCH",
            standing=None,
            withdrawal=withdrawal,
        )

    try:
        standing = resolve_standing(withdrawal, target)
    except Exception:  # noqa: BLE001 - a resolver that raises establishes nothing
        standing = "unknown"
    if not is_withdrawal_standing(standing):
        standing = "unknown"

    if standing == "has_standing":
        return WithdrawalEvaluation(
            accepted=True,
            reason_code="WITHDRAWAL_ACCEPTED",
            standing=standing,
            withdrawal=withdrawal,
        )
    return WithdrawalEvaluation(
        accepted=False,
        reason_code=(
            "WITHDRAWAL_SIGNER_WITHOUT_STANDING"
            if standing == "no_standing"
            else "WITHDRAWAL_STANDING_NOT_ESTABLISHED"
        ),
        standing=standing,
        withdrawal=withdrawal,
    )


def corrected_revocation_view(
    revocation: Mapping[str, Any],
    withdrawals: Iterable[Any],
    resolve_standing: Any,
) -> CorrectedRevocationView:
    """The current position of one revocation together with every withdrawal referencing it.

    This is the field that did not exist. A verifier that must report "revoked, and the
    revoker later said this was recorded in error" had nowhere to put the second half, in
    either reference SDK or in the proposed text, so it could only report the first half and
    drop the rest.

    ``revocation`` is present and unchanged whether or not anything was accepted. Accepted
    withdrawals are listed, refused ones are listed with their codes, and neither list makes
    the revocation ineffective: a later finding is a new record that references the earlier one
    and states its own effect, never an edit of it and never its removal.

    Withdrawals naming a different revocation are not silently dropped. They are evaluated,
    refused ``WITHDRAWAL_NAMES_NO_HELD_REVOCATION``, and appear in ``refused``.
    """
    held = (revocation,)
    evaluations = [
        evaluate_revocation_withdrawal(w, held, resolve_standing) for w in (withdrawals or ())
    ]
    return CorrectedRevocationView(
        revocation=dict(revocation),
        accepted=tuple(e for e in evaluations if e.accepted),
        refused=tuple(e for e in evaluations if not e.accepted),
    )


__all__ = [
    "evaluate_revocation_withdrawal",
    "corrected_revocation_view",
    "revocation_withdrawal",
    "withdrawal_signer_is_revoker",
    "is_withdrawal_standing",
]
