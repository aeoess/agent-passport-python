# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""APS Composition Check Receipt v0 - Python port of the carrier + anchor verifier.

Mirrors src/v2/composition-check/ in the TypeScript SDK: the same COMPOSITION_CHECK_TAG,
the same ``f"{TAG}.{JCS(receipt-without-signature)}"`` signing payload (canonicalize_jcs is
RFC 8785, byte-matching the TS canonicalizeJCS), and the same hex Ed25519 sign/verify. A
receipt signed by either SDK therefore verifies under the other (cross-language interop).

This is ONLY the carrier and the stateless ANCHOR verifier. There is NO policy grammar, NO
detection engine, NO aggregation, and NO ``safe`` boolean: detection of composition hazards
is private gateway intelligence and is not in this SDK. policy_profile_ids and checks_run are
opaque identifiers (string identity only). A per-check ``pass`` means only "the named attestor
reported pass for the named profile over the bound context", never global safety. Independence
is corroborated from the trust context (registered_by_operator is False), never the receipt's
self-declaration; gateway_self is always weak. Includes the F1 (independence gated on
anchor_verified) and F2 (non-finite now_ms fails closed) hardening from the TS branch.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from agent_passport.canonical import canonicalize_jcs
from agent_passport.crypto import verify as _ed_verify

COMPOSITION_CHECK_PROFILE = "aps-composition-check-v0"
# Domain-separation tag. The single signature signs f"{TAG}.{JCS(receipt-without-signature)}".
COMPOSITION_CHECK_TAG = "APS-COMPCHECK-V0"

# SMALL FIXED ENUM. No 'safe'/'unsafe' member: a per-check result is the attestor's finding
# for one named check, never a global verdict.
COMPOSITION_CHECK_RESULTS = ("pass", "fail", "indeterminate", "not_checked")
ATTESTOR_INDEPENDENCE_CLASSES = ("gateway_self", "independent_registered")

_VALID_RESULTS = set(COMPOSITION_CHECK_RESULTS)


def composition_check_signing_payload(receipt: dict) -> str:
    """The exact bytes an attestor signs: the tag, then strict RFC 8785 JCS of the receipt
    with its ``signature`` field removed. Byte-identical to the TS
    compositionCheckSigningPayload, so signatures interoperate across SDKs."""
    copy = {k: v for k, v in receipt.items() if k != "signature"}
    return f"{COMPOSITION_CHECK_TAG}.{canonicalize_jcs(copy)}"


def _sig_ok(payload: str, sig: Any, pubkey: Any) -> bool:
    if not sig or not pubkey:
        return False
    try:
        return _ed_verify(payload, sig, pubkey)
    except Exception:
        return False


def _iso_to_ms(value: Any) -> float:
    """Parse an ISO 8601 timestamp to epoch milliseconds, or NaN if unparseable."""
    if not isinstance(value, str):
        return math.nan
    try:
        s = value[:-1] + "+00:00" if value.endswith("Z") else value
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp() * 1000.0
    except (ValueError, TypeError):
        return math.nan


def verify_composition_check(receipt: dict, ctx: dict) -> dict:
    """Verify a CompositionCheckReceipt against a caller-supplied trust context.

    Verifies the ANCHOR only (signature, binding, freshness, well-formedness, attestor trust)
    and SURFACES independence corroborated from the trust context. Returns the per-check
    results verbatim and NEVER a ``safe`` verdict. Mirrors verifyCompositionCheck in the TS
    SDK (including the F1/F2 hardening).
    """
    violations: list[str] = []

    trusted = ctx.get("trusted_attestors") or {}
    attestor = trusted.get(receipt.get("attestor_key_id"))

    # 1. signature valid under attestor_key_id (only a trusted key carries a public key here).
    payload = composition_check_signing_payload(receipt)
    if not _sig_ok(payload, receipt.get("signature"), (attestor or {}).get("publicKey")):
        violations.append("signature")

    # 2. bound to THIS chain_hash / action_ref / context_hash.
    if receipt.get("chain_hash") != ctx.get("expected_chain_hash"):
        violations.append("chain_binding")
    if receipt.get("action_ref") != ctx.get("expected_action_ref"):
        violations.append("action_binding")
    if receipt.get("context_hash") != ctx.get("expected_context_hash"):
        violations.append("context_binding")

    # 3. attestor recognized AND trusted for EVERY named profile (string identity only).
    if not attestor:
        violations.append("attestor_not_trusted")
    else:
        covered = set(attestor.get("profiles") or [])
        uncovered = [p for p in (receipt.get("policy_profile_ids") or []) if p not in covered]
        if uncovered:
            violations.append("attestor_not_trusted_for_profiles")

    # 4. freshness: issued_at <= now <= expires_at. now_ms is caller-supplied; no clock read.
    #    Fail CLOSED on a non-finite now_ms (F2): comparisons against it would be meaningless.
    now_ms = ctx.get("now_ms")
    now_finite = (
        isinstance(now_ms, (int, float)) and not isinstance(now_ms, bool) and math.isfinite(now_ms)
    )
    issued_ms = _iso_to_ms(receipt.get("issued_at"))
    expires_ms = _iso_to_ms(receipt.get("expires_at"))
    ts_finite = math.isfinite(issued_ms) and math.isfinite(expires_ms)
    if not now_finite:
        violations.append("now_malformed")
    if not ts_finite:
        violations.append("timestamp_malformed")
    if now_finite and ts_finite:
        if now_ms < issued_ms:
            violations.append("not_yet_valid")
        elif now_ms > expires_ms:
            violations.append("expired")

    # 5. well-formedness: profile tag, every result a member of the fixed enum, one per check.
    #    The VALUES (pass/fail/...) are never aggregated, only validated as members.
    if receipt.get("profile") != COMPOSITION_CHECK_PROFILE:
        violations.append("profile_mismatch")
    results = receipt.get("result_per_check")
    if results is None:
        results = []
    results_is_list = isinstance(results, list)
    if not results_is_list or not all(r in _VALID_RESULTS for r in results):
        violations.append("result_enum")
    results_len = len(results) if results_is_list else None
    checks_run = receipt.get("checks_run")
    checks_len = len(checks_run) if isinstance(checks_run, list) else 0
    if checks_len != results_len:
        violations.append("result_count_mismatch")

    # 6. independence: SURFACE it, corroborated from the trust context AND gated on the receipt
    #    anchor-verifying (F1). A self-declared 'independent_registered' the context does not
    #    back is downgraded; an independent attestor whose receipt fails the anchor is not a
    #    usable second anchor either. Downgraded, never upgraded. The raw claimed class is
    #    still echoed below.
    anchor_ok = len(violations) == 0
    claimed_independent = receipt.get("attestor_independence_class") == "independent_registered"
    context_independent = bool(attestor) and attestor.get("registered_by_operator") is False
    independence_is_second_anchor = anchor_ok and claimed_independent and context_independent

    return {
        "profile": COMPOSITION_CHECK_PROFILE,
        "anchor_verified": anchor_ok,
        "violations": violations,
        "policy_profile_ids": receipt.get("policy_profile_ids") or [],
        "checks_run": receipt.get("checks_run") or [],
        "result_per_check": results,
        "attestor_key_id": receipt.get("attestor_key_id"),
        "attestor_independence_class": receipt.get("attestor_independence_class"),
        "independence_is_second_anchor": independence_is_second_anchor,
        "issued_at": receipt.get("issued_at"),
        "expires_at": receipt.get("expires_at"),
    }
