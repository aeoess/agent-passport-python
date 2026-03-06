"""Coordination Primitives — Protocol-native task coordination for multi-agent units.

Layer 6 of the Agent Social Contract.
Every operation is Ed25519 signed. Every handoff is verifiable.
Cross-language compatible with the TypeScript SDK.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize


def _rand_hex(n: int = 4) -> str:
    return os.urandom(n).hex()


def _time_id() -> str:
    return hex(int(time.time() * 1000))[2:]


# ═══════════════════════════════════════
# Task Brief — Operator decomposes work
# ═══════════════════════════════════════


def create_task_brief(
    title: str,
    description: str,
    operator_public_key: str,
    operator_private_key: str,
    roles: list[dict],
    deliverables: list[dict],
    acceptance_criteria: list[str],
    deadline: Optional[str] = None,
) -> dict:
    """Create a signed task brief."""
    task_id = f"task-{_time_id()}-{_rand_hex()}"

    full_roles = [{**r, "assignedTo": None, "delegationId": None} for r in roles]
    full_deliverables = [{**d, "deliverableId": f"{task_id}-del-{i}"} for i, d in enumerate(deliverables)]

    brief = {
        "taskId": task_id,
        "version": "1.0",
        "title": title,
        "description": description,
        "createdBy": operator_public_key,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "deadline": deadline,
        "roles": full_roles,
        "deliverables": full_deliverables,
        "acceptanceCriteria": acceptance_criteria,
        "status": "draft",
    }

    signature = sign(canonicalize(brief), operator_private_key)
    return {**brief, "signature": signature}


def verify_task_brief(brief: dict) -> dict:
    """Verify a task brief's signature and structure."""
    errors: list[str] = []
    unsigned = {k: v for k, v in brief.items() if k != "signature"}
    try:
        if not verify(canonicalize(unsigned), brief.get("signature", ""), brief["createdBy"]):
            errors.append("Invalid operator signature on task brief")
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")

    if not brief.get("roles"):
        errors.append("Task brief must have at least one role")
    if not brief.get("deliverables"):
        errors.append("Task brief must have at least one deliverable")
    if not brief.get("acceptanceCriteria"):
        errors.append("Task brief must have acceptance criteria")

    role_names = [r["role"] for r in brief.get("roles", [])]
    for d in brief.get("deliverables", []):
        if d.get("producedBy") not in role_names:
            errors.append(f'Deliverable "{d.get("name")}" assigned to role "{d.get("producedBy")}" which is not in the task')

    return {"valid": len(errors) == 0, "errors": errors}


# ═══════════════════════════════════════
# Task Assignment
# ═══════════════════════════════════════


def assign_task(
    brief: dict,
    role: str,
    agent_id: str,
    agent_public_key: str,
    delegation_id: str,
    operator_private_key: str,
) -> dict:
    """Assign an agent to a role.

    Returns:
        dict with 'assignment' and 'updatedBrief'.

    Raises:
        ValueError: If role not found or already assigned.
    """
    role_spec = next((r for r in brief["roles"] if r["role"] == role), None)
    if not role_spec:
        raise ValueError(f'Role "{role}" not found in task brief')
    if role_spec.get("assignedTo"):
        raise ValueError(f'Role "{role}" already assigned to {role_spec["assignedTo"]}')

    assignment_content = {
        "assignmentId": f"assign-{_time_id()}-{_rand_hex()}",
        "taskId": brief["taskId"],
        "role": role,
        "agentId": agent_id,
        "agentPublicKey": agent_public_key,
        "delegationId": delegation_id,
        "assignedBy": brief["createdBy"],
        "assignedAt": datetime.now(timezone.utc).isoformat(),
    }

    op_sig = sign(canonicalize(assignment_content), operator_private_key)
    assignment = {**assignment_content, "operatorSignature": op_sig}

    updated_roles = [
        {**r, "assignedTo": agent_public_key, "delegationId": delegation_id} if r["role"] == role else r
        for r in brief["roles"]
    ]
    all_assigned = all(r.get("assignedTo") for r in updated_roles)
    brief_content = {k: v for k, v in brief.items() if k != "signature"}
    brief_content["roles"] = updated_roles
    brief_content["status"] = "assigned" if all_assigned else "draft"
    new_sig = sign(canonicalize(brief_content), operator_private_key)

    return {"assignment": assignment, "updatedBrief": {**brief_content, "signature": new_sig}}


def accept_task(assignment: dict, agent_private_key: str) -> dict:
    """Agent accepts a task assignment."""
    accepted_at = datetime.now(timezone.utc).isoformat()
    to_sign = {"assignmentId": assignment["assignmentId"], "taskId": assignment["taskId"], "acceptedAt": accepted_at}
    agent_sig = sign(canonicalize(to_sign), agent_private_key)
    return {**assignment, "acceptedAt": accepted_at, "agentSignature": agent_sig}


# ═══════════════════════════════════════
# Evidence Submission
# ═══════════════════════════════════════


def submit_evidence(
    task_id: str,
    submitter_public_key: str,
    submitter_private_key: str,
    role: str,
    claims: list[dict],
    methodology: str,
) -> dict:
    """Submit a signed evidence packet."""
    packet_id = f"evid-{_time_id()}-{_rand_hex()}"
    full_claims = [{**c, "claimId": f"{packet_id}-c{i}"} for i, c in enumerate(claims)]

    gap_count = sum(1 for c in full_claims if c.get("confidence") == "not_found")
    source_urls = set(c.get("sourceUrl") for c in full_claims if c.get("sourceUrl") and c.get("confidence") != "not_found")
    cited = sum(1 for c in full_claims if c.get("sourceUrl") and c.get("confidence") != "not_found")

    content = {
        "packetId": packet_id,
        "taskId": task_id,
        "submittedBy": submitter_public_key,
        "role": role,
        "submittedAt": datetime.now(timezone.utc).isoformat(),
        "claims": full_claims,
        "metadata": {
            "sourcesSearched": len(source_urls),
            "totalClaims": len(full_claims),
            "citedClaims": cited,
            "gapCount": gap_count,
            "methodology": methodology,
        },
    }

    signature = sign(canonicalize(content), submitter_private_key)
    return {**content, "signature": signature}


def verify_evidence(packet: dict) -> dict:
    """Verify an evidence packet's signature."""
    errors: list[str] = []
    unsigned = {k: v for k, v in packet.items() if k != "signature"}
    try:
        if not verify(canonicalize(unsigned), packet.get("signature", ""), packet["submittedBy"]):
            errors.append("Invalid signature on evidence packet")
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")

    for claim in packet.get("claims", []):
        if claim.get("confidence") != "not_found" and len(claim.get("quote", "").split()) < 3:
            errors.append(f"Claim {claim.get('claimId')}: quote too short (< 3 words)")

    return {"valid": len(errors) == 0, "errors": errors}


# ═══════════════════════════════════════
# Review Decision
# ═══════════════════════════════════════


def review_evidence(
    task_id: str,
    packet: dict,
    reviewer_public_key: str,
    reviewer_private_key: str,
    verdict: str,
    score: int,
    threshold: int,
    rationale: str,
    issues: Optional[list[dict]] = None,
) -> dict:
    """Create a signed review decision.

    Raises:
        ValueError: If approving below threshold.
    """
    if score < threshold and verdict == "approve":
        raise ValueError(f"Cannot approve: score {score} below threshold {threshold}")

    content = {
        "reviewId": f"review-{_time_id()}-{_rand_hex()}",
        "taskId": task_id,
        "packetId": packet["packetId"],
        "reviewedBy": reviewer_public_key,
        "reviewedAt": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "score": score,
        "threshold": threshold,
        "rationale": rationale,
        "issues": issues,
    }
    signature = sign(canonicalize(content), reviewer_private_key)
    return {**content, "signature": signature}


def verify_review(review: dict) -> dict:
    """Verify a review decision's signature."""
    errors: list[str] = []
    unsigned = {k: v for k, v in review.items() if k != "signature"}
    try:
        if not verify(canonicalize(unsigned), review.get("signature", ""), review["reviewedBy"]):
            errors.append("Invalid signature on review decision")
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")
    if not (0 <= review.get("score", -1) <= 100):
        errors.append("Score must be 0-100")
    return {"valid": len(errors) == 0, "errors": errors}


# ═══════════════════════════════════════
# Evidence Handoff
# ═══════════════════════════════════════


def handoff_evidence(
    task_id: str,
    packet: dict,
    review: dict,
    from_role: str,
    to_role: str,
    to_agent_public_key: str,
    operator_private_key: str,
) -> dict:
    """Hand off approved evidence between roles.

    Raises:
        ValueError: If evidence not approved or review mismatch.
    """
    if review.get("verdict") != "approve":
        raise ValueError(f"Cannot handoff: evidence not approved (verdict: {review.get('verdict')})")
    if review.get("packetId") != packet.get("packetId"):
        raise ValueError("Review does not match evidence packet")

    content = {
        "handoffId": f"handoff-{_time_id()}-{_rand_hex()}",
        "taskId": task_id,
        "packetId": packet["packetId"],
        "reviewId": review["reviewId"],
        "fromRole": from_role,
        "toRole": to_role,
        "fromAgent": packet["submittedBy"],
        "toAgent": to_agent_public_key,
        "handoffAt": datetime.now(timezone.utc).isoformat(),
    }
    op_sig = sign(canonicalize(content), operator_private_key)
    return {**content, "operatorSignature": op_sig}


def verify_handoff(handoff: dict, operator_public_key: str) -> dict:
    """Verify a handoff's operator signature."""
    errors: list[str] = []
    unsigned = {k: v for k, v in handoff.items() if k != "operatorSignature"}
    try:
        if not verify(canonicalize(unsigned), handoff.get("operatorSignature", ""), operator_public_key):
            errors.append("Invalid operator signature on handoff")
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")
    return {"valid": len(errors) == 0, "errors": errors}


# ═══════════════════════════════════════
# Deliverable
# ═══════════════════════════════════════


def submit_deliverable(
    task_id: str,
    spec_id: str,
    submitter_public_key: str,
    submitter_private_key: str,
    role: str,
    content: str,
    evidence_packet_ids: list[str],
    citation_count: int,
    gaps_flagged: int,
) -> dict:
    """Submit a signed deliverable."""
    deliv = {
        "deliverableId": f"deliv-{_time_id()}-{_rand_hex()}",
        "taskId": task_id,
        "specId": spec_id,
        "submittedBy": submitter_public_key,
        "role": role,
        "submittedAt": datetime.now(timezone.utc).isoformat(),
        "content": content,
        "evidencePacketIds": evidence_packet_ids,
        "citationCount": citation_count,
        "gapsFlagged": gaps_flagged,
    }
    signature = sign(canonicalize(deliv), submitter_private_key)
    return {**deliv, "signature": signature}


def verify_deliverable(deliverable: dict) -> dict:
    """Verify a deliverable's signature."""
    errors: list[str] = []
    unsigned = {k: v for k, v in deliverable.items() if k != "signature"}
    try:
        if not verify(canonicalize(unsigned), deliverable.get("signature", ""), deliverable["submittedBy"]):
            errors.append("Invalid signature on deliverable")
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")
    return {"valid": len(errors) == 0, "errors": errors}


# ═══════════════════════════════════════
# Task Completion
# ═══════════════════════════════════════


def complete_task(
    brief: dict,
    unit: dict,
    operator_public_key: str,
    operator_private_key: str,
    status: str,
    retrospective: Optional[str] = None,
) -> dict:
    """Complete a task with metrics and retrospective."""
    deliverable_ids = [d["deliverableId"] for d in unit.get("deliverables", [])]
    brief_time = datetime.fromisoformat(brief["createdAt"].replace("Z", "+00:00")).timestamp()
    now = time.time()
    total_duration = int(now - brief_time)
    overhead_events = len(unit.get("reviews", [])) + len(unit.get("handoffs", []))
    coordination_overhead = overhead_events * 30
    task_work_time = total_duration - coordination_overhead
    overhead_ratio = round(coordination_overhead / max(task_work_time, 1), 2)

    total_claims = sum(p.get("metadata", {}).get("totalClaims", 0) for p in unit.get("evidencePackets", []))
    total_gaps = sum(p.get("metadata", {}).get("gapCount", 0) for p in unit.get("evidencePackets", []))
    gap_rate = round(total_gaps / max(total_claims, 1), 2)
    rework_count = sum(1 for r in unit.get("reviews", []) if r.get("verdict") == "rework")
    errors_caught = sum(len(r.get("issues", []) or []) for r in unit.get("reviews", []))
    agent_keys = set(a["agentPublicKey"] for a in unit.get("assignments", []))

    metrics = {
        "totalDuration": total_duration,
        "coordinationOverhead": coordination_overhead,
        "taskWorkTime": task_work_time,
        "overheadRatio": overhead_ratio,
        "evidenceGapRate": gap_rate,
        "reworkCount": rework_count,
        "errorsCaught": errors_caught,
        "agentCount": len(agent_keys),
    }

    completion = {
        "taskId": brief["taskId"],
        "completedBy": operator_public_key,
        "completedAt": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "deliverableIds": deliverable_ids,
        "metrics": metrics,
        "retrospective": retrospective,
    }
    signature = sign(canonicalize(completion), operator_private_key)
    return {**completion, "signature": signature}


def verify_completion(completion: dict, operator_public_key: str) -> dict:
    """Verify a task completion's operator signature."""
    errors: list[str] = []
    unsigned = {k: v for k, v in completion.items() if k != "signature"}
    try:
        if not verify(canonicalize(unsigned), completion.get("signature", ""), operator_public_key):
            errors.append("Invalid operator signature on task completion")
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")
    return {"valid": len(errors) == 0, "errors": errors}


# ═══════════════════════════════════════
# Task Unit — Full lifecycle container
# ═══════════════════════════════════════


def create_task_unit(brief: dict) -> dict:
    """Create a task unit container from a brief."""
    return {
        "brief": brief,
        "assignments": [],
        "evidencePackets": [],
        "reviews": [],
        "handoffs": [],
        "deliverables": [],
        "completion": None,
    }


def get_task_status(unit: dict) -> str:
    """Determine current task status from the unit state."""
    if unit.get("completion"):
        return "completed" if unit["completion"].get("status") == "completed" else "failed"
    if unit.get("deliverables"):
        return "delivered"
    if any(r.get("verdict") == "approve" for r in unit.get("reviews", [])):
        return "approved"
    if any(r.get("verdict") == "rework" for r in unit.get("reviews", [])):
        return "rework_requested"
    if unit.get("reviews"):
        return "under_review"
    if unit.get("evidencePackets"):
        return "evidence_submitted"
    if unit.get("assignments"):
        return "in_progress" if all(a.get("acceptedAt") for a in unit["assignments"]) else "assigned"
    return "draft"


def validate_task_unit(unit: dict) -> dict:
    """Validate the entire unit's integrity — every signature, every link."""
    errors: list[str] = []
    brief = unit["brief"]

    brief_result = verify_task_brief(brief)
    errors.extend(brief_result["errors"])

    for a in unit.get("assignments", []):
        if a["taskId"] != brief["taskId"]:
            errors.append(f"Assignment {a['assignmentId']}: taskId mismatch")
        if not any(r["role"] == a["role"] for r in brief.get("roles", [])):
            errors.append(f"Assignment {a['assignmentId']}: role \"{a['role']}\" not in brief")

    for p in unit.get("evidencePackets", []):
        if p["taskId"] != brief["taskId"]:
            errors.append(f"Evidence {p['packetId']}: taskId mismatch")
        errors.extend(verify_evidence(p)["errors"])

    for r in unit.get("reviews", []):
        if r["taskId"] != brief["taskId"]:
            errors.append(f"Review {r['reviewId']}: taskId mismatch")
        if not any(p["packetId"] == r["packetId"] for p in unit.get("evidencePackets", [])):
            errors.append(f"Review {r['reviewId']}: references unknown packet {r['packetId']}")
        errors.extend(verify_review(r)["errors"])

    for h in unit.get("handoffs", []):
        rev = next((r for r in unit.get("reviews", []) if r["reviewId"] == h["reviewId"]), None)
        if not rev:
            errors.append(f"Handoff {h['handoffId']}: references unknown review {h['reviewId']}")
        elif rev["verdict"] != "approve":
            errors.append(f"Handoff {h['handoffId']}: review not approved (verdict: {rev['verdict']})")

    for d in unit.get("deliverables", []):
        errors.extend(verify_deliverable(d)["errors"])
        for pid in d.get("evidencePacketIds", []):
            if not any(p["packetId"] == pid for p in unit.get("evidencePackets", [])):
                errors.append(f"Deliverable {d['deliverableId']}: references unknown packet {pid}")

    if unit.get("completion"):
        errors.extend(verify_completion(unit["completion"], brief["createdBy"])["errors"])

    return {"valid": len(errors) == 0, "errors": errors}
