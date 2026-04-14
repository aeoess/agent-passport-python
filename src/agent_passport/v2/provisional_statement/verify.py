# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""verify_promotion. Mirrors src/v2/provisional-statement/verify.ts."""

from ...crypto import verify
from .types import ProvisionalStatement, PromotionPolicy, PromotionVerifyResult
from .create import verify_author_signature
from .promote import promotion_signing_payload


def verify_promotion(
    statement: ProvisionalStatement,
    policy: PromotionPolicy,
) -> PromotionVerifyResult:
    """Cryptographic + policy verification of a statement's promotion."""
    errors: list = []

    if statement.get("status") != "promoted":
        errors.append(f'Status is "{statement.get("status")}", expected "promoted"')
    promotion = statement.get("promotion")
    if not promotion:
        errors.append("No promotion event attached")
        return {"valid": False, "errors": errors}

    if not verify_author_signature(statement):
        errors.append("Author signature invalid — statement tampered with")

    if promotion.get("kind") == "dead_man_elapsed":
        errors.append("dead_man_elapsed is not a binding promotion kind")

    if promotion.get("policy_reference") != policy["id"]:
        errors.append(
            f'policy_reference "{promotion.get("policy_reference")}" '
            f'does not match policy "{policy["id"]}"'
        )

    promoter_authorized = promotion.get("promoter") in policy["required_signers"]
    if not promoter_authorized:
        errors.append(
            f'Promoter "{promotion.get("promoter")}" is not in policy.required_signers'
        )

    if policy["threshold"] > 1:
        errors.append(
            f'Threshold {policy["threshold"]} not satisfied — only one signature present'
        )
    if policy["threshold"] < 1:
        errors.append(f'Policy threshold must be >= 1 (got {policy["threshold"]})')

    payload = promotion_signing_payload({
        "statement_id": statement["id"],
        "kind": promotion["kind"],
        "promoted_at": promotion["promoted_at"],
        "promoter": promotion["promoter"],
        "policy_reference": promotion["policy_reference"],
    })
    if not promotion.get("promoter_signature"):
        errors.append("Missing promoter signature")
    else:
        try:
            ok = verify(payload, promotion["promoter_signature"], promotion["promoter"])
        except Exception:
            ok = False
        if not ok:
            errors.append("Promoter signature invalid")

    created_latest = statement["created_at"]["wallClockLatest"]
    promoted_earliest = promotion["promoted_at"]["wallClockEarliest"]
    elapsed = promoted_earliest - created_latest
    if elapsed > policy["max_time_to_promote"]:
        errors.append(
            f'Promotion exceeded max_time_to_promote ({elapsed}ms > {policy["max_time_to_promote"]}ms)'
        )

    deadline = statement.get("dead_man_expires_at")
    if deadline and promoted_earliest > deadline["wallClockLatest"]:
        errors.append("Promotion after dead_man_expires_at — statement already auto-withdrawn")

    return {"valid": len(errors) == 0, "errors": errors}
