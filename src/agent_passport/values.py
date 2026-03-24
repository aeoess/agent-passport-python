# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Human Values Floor — attestation, compliance evaluation, and common ground.

Layer 2 of the Agent Social Contract.
Cross-language compatible with the TypeScript SDK.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize

# Enforcement escalation order (higher = stricter)
ENFORCEMENT_ESCALATION: dict[str, int] = {
    "warn": 1,
    "audit": 2,
    "inline": 3,
}


# ══════════════════════════════════════
# FLOOR LOADING
# ══════════════════════════════════════


def load_floor(content: str) -> dict[str, Any]:
    """Parse a Values Floor from JSON or YAML string."""
    # Try JSON first (canonical format)
    try:
        parsed = json.loads(content)
        if "floor" in parsed and isinstance(parsed["floor"], list):
            return parsed
    except (json.JSONDecodeError, KeyError):
        pass

    # Fall back to minimal YAML parser
    return _parse_yaml_floor(content)


def load_floor_from_file(file_path: str) -> dict[str, Any]:
    """Load a Values Floor from a file path."""
    with open(file_path, "r", encoding="utf-8") as f:
        return load_floor(f.read())


def _extract_val(line: str) -> str:
    """Extract value after first colon."""
    idx = line.find(":")
    if idx == -1:
        return ""
    v = line[idx + 1 :].strip()
    if (v.startswith('"') and v.endswith('"')) or (
        v.startswith("'") and v.endswith("'")
    ):
        v = v[1:-1]
    return v


def _parse_yaml_floor(yaml_content: str) -> dict[str, Any]:
    """Minimal YAML parser matching the TypeScript implementation."""
    floor: dict[str, Any] = {
        "version": "",
        "schema": "",
        "lastUpdated": "",
        "governanceUri": "",
        "floor": [],
    }

    current: Optional[dict[str, Any]] = None
    in_floor = False
    in_enforcement = False
    in_section = False

    for line in yaml_content.split("\n"):
        trimmed = line.strip()
        if trimmed.startswith("#") or trimmed == "":
            continue

        if not in_section:
            if trimmed.startswith("version:"):
                floor["version"] = _extract_val(trimmed); continue
            if trimmed.startswith("schema:"):
                floor["schema"] = _extract_val(trimmed); continue
            if trimmed.startswith("last_updated:"):
                floor["lastUpdated"] = _extract_val(trimmed); continue
            if trimmed.startswith("governance_uri:"):
                floor["governanceUri"] = _extract_val(trimmed); continue

        if trimmed == "floor:":
            in_floor = True; in_section = True; continue
        if in_floor and (trimmed.startswith("extensions:") or trimmed.startswith("integration:")):
            in_floor = False; continue

        if in_floor:
            if trimmed.startswith("- id:"):
                if current and current.get("id"):
                    floor["floor"].append(current)
                current = {
                    "id": _extract_val(trimmed[2:]),
                    "enforcement": {"technical": False, "mechanism": ""},
                    "weight": "mandatory",
                }
                in_enforcement = False
            if current:
                if trimmed.startswith("name:"):
                    current["name"] = _extract_val(trimmed)
                if trimmed.startswith("weight:"):
                    current["weight"] = _extract_val(trimmed)
                if trimmed.startswith("principle:") and not trimmed.endswith(">"):
                    current["principle"] = _extract_val(trimmed)
                if trimmed == "enforcement:":
                    in_enforcement = True; continue
                if in_enforcement:
                    if trimmed.startswith("mode:"):
                        mode = _extract_val(trimmed)
                        if mode in ("inline", "audit", "warn"):
                            current["enforcement"]["mode"] = mode
                    if trimmed.startswith("technical:"):
                        current["enforcement"]["technical"] = "true" in trimmed
                    if trimmed.startswith("mechanism:"):
                        current["enforcement"]["mechanism"] = _extract_val(trimmed)
                    if trimmed.startswith("protocol_ref:"):
                        current["enforcement"]["protocolRef"] = _extract_val(trimmed)

    if current and current.get("id"):
        floor["floor"].append(current)

    # Post-process: resolve enforcement modes for backward compat
    for p in floor["floor"]:
        if not p["enforcement"].get("mode"):
            p["enforcement"]["mode"] = resolve_enforcement_mode(p["enforcement"])

    return floor


# ══════════════════════════════════════
# ENFORCEMENT MODE RESOLUTION
# ══════════════════════════════════════


def resolve_enforcement_mode(enforcement: dict[str, Any]) -> str:
    """Resolve effective enforcement mode from a principle's enforcement config."""
    if enforcement.get("mode"):
        return enforcement["mode"]
    if enforcement.get("technical") is True:
        return "inline"
    if enforcement.get("technical") is False:
        return "audit"
    return "audit"


def effective_enforcement_mode(floor_mode: str, *extension_modes: str) -> str:
    """Compute effective mode across floor + extensions. Strictest wins."""
    all_modes = [floor_mode, *extension_modes]
    return max(all_modes, key=lambda m: ENFORCEMENT_ESCALATION.get(m, 0))


# ══════════════════════════════════════
# FLOOR ATTESTATION
# ══════════════════════════════════════


def attest_floor(
    agent_id: str,
    public_key: str,
    floor_version: str,
    extensions: list[str],
    private_key: str,
    expires_in_days: int = 365,
) -> dict[str, Any]:
    """Create a signed floor attestation."""
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(days=expires_in_days)

    attestation = {
        "attestationId": "att_" + uuid.uuid4().hex[:12],
        "agentId": agent_id,
        "publicKey": public_key,
        "floorVersion": floor_version,
        "extensions": extensions,
        "attestedAt": now.isoformat().replace("+00:00", "Z"),
        "expiresAt": expiry.isoformat().replace("+00:00", "Z"),
        "commitment": f"floor:{floor_version}|ext:{','.join(sorted(extensions)) or 'none'}|ts:{now.isoformat().replace('+00:00', 'Z')}",
    }

    canonical = canonicalize(attestation)
    signature = sign(canonical, private_key)
    return {**attestation, "signature": signature}


def verify_attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    """Verify an attestation's signature and expiry."""
    errors: list[str] = []

    unsigned = {k: v for k, v in attestation.items() if k != "signature"}
    canonical = canonicalize(unsigned)
    if not verify(canonical, attestation.get("signature", ""), attestation.get("publicKey", "")):
        errors.append("Invalid attestation signature")

    expires_at = attestation.get("expiresAt", "")
    if expires_at:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if exp < datetime.now(timezone.utc):
            errors.append("Attestation expired")

    if not attestation.get("floorVersion"):
        errors.append("No floor version specified")

    return {"valid": len(errors) == 0, "errors": errors}


# ══════════════════════════════════════
# COMPLIANCE EVALUATION
# ══════════════════════════════════════


def evaluate_compliance(
    agent_id: str,
    receipts: list[dict[str, Any]],
    floor: dict[str, Any],
    delegations: dict[str, dict[str, Any]],
    verifier_private_key: str,
) -> dict[str, Any]:
    """Evaluate compliance by producing facts about each principle."""
    agent_receipts = [r for r in receipts if r.get("agentId") == agent_id]
    checks = [
        _evaluate_principle(p, agent_receipts, delegations)
        for p in floor["floor"]
    ]

    total = len(checks)
    score = sum(
        1.0 if c["status"] == "enforced"
        else 0.8 if c["status"] == "attested"
        else 0.5 if c["status"] == "unverifiable"
        else 0.0
        for c in checks
    ) / max(total, 1)

    timestamps = sorted(r.get("timestamp", "") for r in agent_receipts)
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report = {
        "reportId": "comp_" + uuid.uuid4().hex[:12],
        "agentId": agent_id,
        "floorVersion": floor.get("version", ""),
        "period": {
            "from": timestamps[0] if timestamps else now_iso,
            "to": timestamps[-1] if timestamps else now_iso,
        },
        "receiptsAnalyzed": len(agent_receipts),
        "checks": checks,
        "overallCompliance": round(score, 3),
        "generatedAt": now_iso,
    }

    canonical = canonicalize(report)
    signature = sign(canonical, verifier_private_key)
    return {**report, "signature": signature}


def _evaluate_principle(
    principle: dict[str, Any],
    receipts: list[dict[str, Any]],
    delegations: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate a single principle against receipts."""
    mode = resolve_enforcement_mode(principle.get("enforcement", {}))
    base = {
        "principleId": principle["id"],
        "principleName": principle.get("name", ""),
        "enforcementMode": mode,
    }
    pid = principle["id"]

    if pid == "F-001":  # Traceability
        if not receipts:
            return {**base, "status": "unverifiable", "detail": "No receipts to analyze"}
        traced = [r for r in receipts if r.get("delegationChain") and len(r["delegationChain"]) > 0]
        if len(traced) == len(receipts):
            return {**base, "status": "enforced", "detail": f"All {len(receipts)} receipts have delegation chains"}
        return {**base, "status": "violation", "detail": f"{len(receipts) - len(traced)} receipts missing delegation chain"}

    if pid == "F-002":  # Honest Identity
        ids = set(r.get("agentId", "") for r in receipts)
        if len(ids) <= 1:
            return {**base, "status": "enforced", "detail": "Consistent agent identity across all receipts"}
        return {**base, "status": "violation", "detail": f"Multiple agent IDs: {', '.join(ids)}"}

    if pid == "F-003":  # Scoped Authority
        bad = [r for r in receipts
               if r.get("delegationId") in delegations
               and r.get("action", {}).get("scopeUsed", "") not in delegations[r["delegationId"]].get("scope", [])]
        if not bad:
            return {**base, "status": "enforced", "detail": "All actions within delegated scope"}
        return {**base, "status": "violation", "detail": f"{len(bad)} out-of-scope actions"}

    if pid == "F-004":  # Revocability
        revoked = [r for r in receipts if delegations.get(r.get("delegationId", ""), {}).get("revoked")]
        if not revoked:
            return {**base, "status": "enforced", "detail": "No actions under revoked delegations"}
        return {**base, "status": "violation", "detail": f"{len(revoked)} actions under revoked delegations"}

    if pid == "F-005":  # Auditability
        if not receipts:
            return {**base, "status": "unverifiable", "detail": "No receipts to audit"}
        signed = [r for r in receipts if r.get("signature")]
        if len(signed) == len(receipts):
            return {**base, "status": "enforced", "detail": f"All {len(receipts)} receipts cryptographically signed"}
        return {**base, "status": "violation", "detail": "Unsigned receipts found"}

    if pid == "F-006":  # Non-Deception
        return {**base, "status": "attested", "detail": "Requires reasoning-level verification"}

    if pid == "F-007":  # Proportionality
        return {**base, "status": "attested", "detail": "Requires reputation context"}

    return {**base, "status": "unverifiable", "detail": f"Unknown principle {pid}"}


# ══════════════════════════════════════
# COMMON GROUND NEGOTIATION
# ══════════════════════════════════════


def negotiate_common_ground(
    passport_a: dict[str, Any],
    attestation_a: dict[str, Any],
    passport_b: dict[str, Any],
    attestation_b: dict[str, Any],
) -> dict[str, Any]:
    """Determine shared ethical ground between two agents."""
    reasons: list[str] = []
    now = datetime.now(timezone.utc)

    for label, att, passport in [("A", attestation_a, passport_a), ("B", attestation_b, passport_b)]:
        exp = att.get("expiresAt", "")
        if exp:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if exp_dt < now:
                reasons.append(f"Agent {passport.get('agentId', label)} attestation expired")

    major_a = attestation_a.get("floorVersion", "").split(".")[0]
    major_b = attestation_b.get("floorVersion", "").split(".")[0]
    compatible = major_a == major_b

    if not compatible:
        reasons.append(
            f"Incompatible floor versions: {attestation_a.get('floorVersion')} vs {attestation_b.get('floorVersion')}"
        )

    ext_a = set(attestation_a.get("extensions", []))
    shared = [e for e in attestation_b.get("extensions", []) if e in ext_a]

    return {
        "floorVersion": attestation_a.get("floorVersion") if compatible else None,
        "sharedExtensions": shared,
        "agentA": passport_a.get("publicKey", ""),
        "agentB": passport_b.get("publicKey", ""),
        "negotiatedAt": now.isoformat().replace("+00:00", "Z"),
        "compatible": len(reasons) == 0 and compatible,
        "incompatibilityReasons": reasons,
    }
