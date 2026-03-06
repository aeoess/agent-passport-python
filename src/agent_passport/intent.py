"""Intent Architecture — Roles, Deliberation, Consensus, Precedents.

Layer 5a of the Agent Social Contract.
Cross-language compatible with the TypeScript SDK.
"""

from __future__ import annotations

import math
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize
from .passport import verify_passport


def _rand_hex(n: int = 4) -> str:
    return os.urandom(n).hex()


def _time_id() -> str:
    return hex(int(time.time() * 1000))[2:]


# ── Agent Roles ──


def assign_role(
    signed_passport: dict,
    role: str,
    autonomy_level: str,
    scope: list[str],
    assigner_private_key: str,
    assigner_public_key: str,
    department: Optional[str] = None,
) -> dict:
    """Assign a role to an agent after verifying their passport.

    Raises:
        ValueError: If passport verification fails.
    """
    verification = verify_passport(signed_passport)
    if not verification["valid"]:
        raise ValueError(
            f"Cannot assign role: passport verification failed — {', '.join(verification['errors'])}"
        )

    assignment = {
        "agentId": signed_passport["passport"]["agentId"],
        "role": role,
        "department": department,
        "autonomyLevel": autonomy_level,
        "assignedBy": assigner_public_key,
        "assignedAt": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
    }

    signature = sign(canonicalize(assignment), assigner_private_key)
    return {**assignment, "signature": signature}


# ── Tradeoff Rules ──


def create_tradeoff_rule(
    when: str,
    prefer: str,
    until: str,
    then_prefer: str,
    context: Optional[str] = None,
) -> dict:
    """Create a tradeoff rule for intent documents."""
    return {
        "ruleId": f"rule-{_rand_hex()}",
        "when": when,
        "prefer": prefer,
        "until": until,
        "thenPrefer": then_prefer,
        "context": context,
    }


def evaluate_tradeoff(rule: dict, threshold_exceeded: bool) -> dict:
    """Evaluate a tradeoff rule given whether the threshold was exceeded."""
    winner = rule["thenPrefer"] if threshold_exceeded else rule["prefer"]
    return {
        "ruleId": rule["ruleId"],
        "winner": winner,
        "thresholdExceeded": threshold_exceeded,
        "reasoning": (
            f'Threshold "{rule["until"]}" exceeded — preferring {rule["thenPrefer"]} over {rule["prefer"]}'
            if threshold_exceeded
            else f'Within threshold "{rule["until"]}" — preferring {rule["prefer"]} over {rule["thenPrefer"]}'
        ),
    }


# ── Intent Documents ──


def create_intent_document(
    author_public_key: str,
    author_private_key: str,
    title: str,
    goals: list[dict],
    tradeoff_hierarchy: list[dict],
    department: Optional[str] = None,
    expires_at: Optional[str] = None,
) -> dict:
    """Create a signed intent document.

    Raises:
        ValueError: If no tradeoff rules provided.
    """
    if not tradeoff_hierarchy:
        raise ValueError(
            "Intent document requires at least one tradeoff rule. "
            "Goals without tradeoff rules are just a wishlist."
        )

    doc = {
        "intentId": f"intent-{_time_id()}-{_rand_hex()}",
        "version": "1.0",
        "department": department,
        "authoredBy": author_public_key,
        "title": title,
        "goals": goals,
        "tradeoffHierarchy": tradeoff_hierarchy,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "expiresAt": expires_at,
    }

    signature = sign(canonicalize(doc), author_private_key)
    return {**doc, "signature": signature}


# ── Deliberative Consensus ──


def create_deliberation(
    subject: str,
    description: str,
    initiated_by: str,
    reversibility_score: float,
    convergence_threshold: float = 8.0,
    max_rounds: int = 5,
) -> dict:
    """Create a new deliberation."""
    return {
        "deliberationId": f"delib-{_time_id()}-{_rand_hex()}",
        "subject": subject,
        "description": description,
        "initiatedBy": initiated_by,
        "initiatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "active",
        "rounds": [],
        "convergenceThreshold": convergence_threshold,
        "maxRounds": max_rounds,
        "reversibilityScore": reversibility_score,
    }


def submit_consensus_round(
    deliberation: dict,
    agent_id: str,
    public_key: str,
    private_key: str,
    role: str,
    assessment: list[dict],
    reasoning: str,
    department: Optional[str] = None,
) -> dict:
    """Submit a consensus round to a deliberation.

    Returns:
        dict with 'deliberation' (updated) and 'round'.

    Raises:
        ValueError: If deliberation is not active.
    """
    if deliberation["status"] != "active":
        raise ValueError(f"Deliberation is {deliberation['status']}, cannot submit round")

    total_weight = sum(a["weight"] for a in assessment)
    overall_score = (
        sum(a["score"] * a["weight"] for a in assessment) / total_weight
        if total_weight > 0
        else 0
    )

    previous = [r for r in deliberation["rounds"] if r["agentId"] == agent_id]
    position_delta = (
        overall_score - previous[-1]["overallScore"] if previous else None
    )

    round_numbers = [r["roundNumber"] for r in deliberation["rounds"]]
    current_round = (max(round_numbers) + 1) if round_numbers else 1

    round_content = {
        "roundId": f"round-{_rand_hex()}",
        "deliberationId": deliberation["deliberationId"],
        "roundNumber": current_round,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agentId": agent_id,
        "publicKey": public_key,
        "role": role,
        "department": department,
        "assessment": assessment,
        "overallScore": overall_score,
        "reasoning": reasoning,
        "positionDelta": position_delta,
    }

    signature = sign(canonicalize(round_content), private_key)
    rnd = {**round_content, "signature": signature}

    updated = {
        **deliberation,
        "rounds": [*deliberation["rounds"], rnd],
    }

    return {"deliberation": updated, "round": rnd}


# ── Consensus Evaluation ──


def evaluate_consensus(deliberation: dict) -> dict:
    """Evaluate whether a deliberation has converged."""
    rounds = deliberation["rounds"]
    if not rounds:
        return {
            "converged": False, "standardDeviation": float("inf"),
            "roundNumber": 0, "agentCount": 0, "recommendation": "continue",
        }

    latest_round = max(r["roundNumber"] for r in rounds)
    latest_scores = [r["overallScore"] for r in rounds if r["roundNumber"] == latest_round]
    agent_count = len(latest_scores)

    if agent_count < 2:
        return {
            "converged": False, "standardDeviation": 0,
            "roundNumber": latest_round, "agentCount": agent_count,
            "recommendation": "continue",
        }

    mean = sum(latest_scores) / agent_count
    variance = sum((s - mean) ** 2 for s in latest_scores) / agent_count
    std_dev = math.sqrt(variance)

    converged = std_dev <= deliberation["convergenceThreshold"]
    at_max = latest_round >= deliberation["maxRounds"]

    if converged:
        recommendation = "converged"
    elif at_max:
        recommendation = "escalate"
    else:
        recommendation = "continue"

    return {
        "converged": converged,
        "standardDeviation": round(std_dev, 2),
        "roundNumber": latest_round,
        "agentCount": agent_count,
        "recommendation": recommendation,
    }


# ── Resolve & Precedent ──


def resolve_deliberation(
    deliberation: dict,
    decision: str,
    votes_for: list[str],
    votes_against: list[str],
    abstained: list[str],
    resolver_private_key: str,
    resolver_agent_id: str,
    escalated_to: Optional[str] = None,
) -> dict:
    """Resolve a deliberation, producing outcome and precedent.

    Returns:
        dict with 'deliberation', 'outcome', 'precedent'.
    """
    evaluation = evaluate_consensus(deliberation)

    outcome_content = {
        "decision": decision,
        "consensusScore": evaluation["standardDeviation"],
        "roundsToConverge": evaluation["roundNumber"],
        "votesFor": votes_for,
        "votesAgainst": votes_against,
        "abstained": abstained,
        "escalatedTo": escalated_to,
        "resolvedAt": datetime.now(timezone.utc).isoformat(),
    }

    outcome_sig = sign(canonicalize(outcome_content), resolver_private_key)
    precedent_id = f"prec-{_rand_hex()}"
    outcome = {**outcome_content, "precedentId": precedent_id, "signature": outcome_sig}

    agent_scores = {
        r["agentId"]: r["overallScore"]
        for r in deliberation["rounds"]
        if r["roundNumber"] == evaluation["roundNumber"]
    }

    precedent = {
        "precedentId": precedent_id,
        "deliberationId": deliberation["deliberationId"],
        "subject": deliberation["subject"],
        "context": deliberation["description"],
        "decision": decision,
        "agentScores": agent_scores,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "citedCount": 0,
    }

    status = (
        "converged" if evaluation["converged"]
        else ("escalated" if escalated_to else "deadlocked")
    )
    resolved = {**deliberation, "status": status, "outcome": outcome}

    return {"deliberation": resolved, "outcome": outcome, "precedent": precedent}


# ── Precedent Lookup ──


def get_precedents_by_topic(precedents: list[dict], topic: str) -> list[dict]:
    """Find precedents matching a topic, sorted by citedCount descending."""
    lower = topic.lower()
    matches = [
        p for p in precedents
        if lower in p["subject"].lower()
        or lower in p["context"].lower()
        or lower in p["decision"].lower()
    ]
    return sorted(matches, key=lambda p: p["citedCount"], reverse=True)


def cite_precedent(precedent: dict) -> dict:
    """Increment a precedent's citation count."""
    return {**precedent, "citedCount": precedent["citedCount"] + 1}


# ── Intent Passport Extension ──


def create_intent_passport_extension(
    role: str,
    autonomy_level: str,
    active_intents: list[str],
    tradeoff_hierarchy_hash: str,
    department: Optional[str] = None,
) -> dict:
    """Create an intent extension for an agent's passport."""
    return {
        "role": role,
        "autonomyLevel": autonomy_level,
        "department": department,
        "activeIntents": active_intents,
        "tradeoffHierarchyHash": tradeoff_hierarchy_hash,
        "deliberationsParticipated": 0,
        "precedentsCited": 0,
    }
