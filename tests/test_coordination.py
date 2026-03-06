"""Tests for Coordination Primitives (Layer 6 — Task lifecycle)."""

import pytest

from agent_passport import (
    generate_key_pair,
    create_task_brief,
    verify_task_brief,
    assign_task,
    accept_task,
    submit_evidence,
    verify_evidence,
    review_evidence,
    verify_review,
    handoff_evidence,
    verify_handoff,
    submit_deliverable,
    verify_deliverable,
    complete_task,
    verify_completion,
    create_task_unit,
    get_task_status,
    validate_task_unit,
)


def _setup():
    op_kp = generate_key_pair()
    researcher_kp = generate_key_pair()
    analyst_kp = generate_key_pair()
    return op_kp, researcher_kp, analyst_kp


def test_create_and_verify_task_brief():
    op_kp, _, _ = _setup()
    brief = create_task_brief(
        title="Research Task",
        description="Research AI agent protocols",
        operator_public_key=op_kp["publicKey"],
        operator_private_key=op_kp["privateKey"],
        roles=[{"role": "researcher", "requiredCapabilities": ["web_search"]}],
        deliverables=[{"name": "Report", "format": "markdown", "producedBy": "researcher"}],
        acceptance_criteria=["Minimum 5 sources"],
    )
    assert brief["taskId"]
    assert brief["status"] == "draft"
    result = verify_task_brief(brief)
    assert result["valid"]


def test_full_task_lifecycle():
    op_kp, researcher_kp, analyst_kp = _setup()

    # Create brief
    brief = create_task_brief(
        title="Full Lifecycle",
        description="End-to-end test",
        operator_public_key=op_kp["publicKey"],
        operator_private_key=op_kp["privateKey"],
        roles=[
            {"role": "researcher", "requiredCapabilities": ["web_search"]},
            {"role": "analyst", "requiredCapabilities": ["analysis"]},
        ],
        deliverables=[{"name": "Analysis", "format": "markdown", "producedBy": "analyst"}],
        acceptance_criteria=["Complete analysis"],
    )
    unit = create_task_unit(brief)
    assert get_task_status(unit) == "draft"

    # Assign roles
    result = assign_task(
        brief=brief, role="researcher",
        agent_id="researcher-1", agent_public_key=researcher_kp["publicKey"],
        delegation_id="del-1", operator_private_key=op_kp["privateKey"],
    )
    brief = result["updatedBrief"]
    unit["assignments"].append(result["assignment"])

    result2 = assign_task(
        brief=brief, role="analyst",
        agent_id="analyst-1", agent_public_key=analyst_kp["publicKey"],
        delegation_id="del-2", operator_private_key=op_kp["privateKey"],
    )
    brief = result2["updatedBrief"]
    unit["brief"] = brief
    unit["assignments"].append(result2["assignment"])
    assert brief["status"] == "assigned"

    # Accept assignments
    unit["assignments"][0] = accept_task(unit["assignments"][0], researcher_kp["privateKey"])
    unit["assignments"][1] = accept_task(unit["assignments"][1], analyst_kp["privateKey"])
    assert get_task_status(unit) == "in_progress"

    # Submit evidence
    packet = submit_evidence(
        task_id=brief["taskId"],
        submitter_public_key=researcher_kp["publicKey"],
        submitter_private_key=researcher_kp["privateKey"],
        role="researcher",
        claims=[
            {"claim": "AI agents need identity", "confidence": "high", "sourceUrl": "https://example.com", "quote": "Agents need verifiable identity"},
            {"claim": "No standard exists", "confidence": "medium", "sourceUrl": "https://example2.com", "quote": "There is no existing standard"},
        ],
        methodology="web search",
    )
    unit["evidencePackets"].append(packet)
    assert get_task_status(unit) == "evidence_submitted"
    assert verify_evidence(packet)["valid"]

    # Review evidence
    review = review_evidence(
        task_id=brief["taskId"], packet=packet,
        reviewer_public_key=op_kp["publicKey"],
        reviewer_private_key=op_kp["privateKey"],
        verdict="approve", score=85, threshold=70,
        rationale="Good research quality",
    )
    unit["reviews"].append(review)
    assert verify_review(review)["valid"]

    # Handoff
    handoff = handoff_evidence(
        task_id=brief["taskId"], packet=packet, review=review,
        from_role="researcher", to_role="analyst",
        to_agent_public_key=analyst_kp["publicKey"],
        operator_private_key=op_kp["privateKey"],
    )
    unit["handoffs"].append(handoff)
    assert verify_handoff(handoff, op_kp["publicKey"])["valid"]

    # Submit deliverable
    deliv = submit_deliverable(
        task_id=brief["taskId"], spec_id=brief["deliverables"][0]["deliverableId"],
        submitter_public_key=analyst_kp["publicKey"],
        submitter_private_key=analyst_kp["privateKey"],
        role="analyst", content="# Analysis Report\nComplete analysis.",
        evidence_packet_ids=[packet["packetId"]],
        citation_count=2, gaps_flagged=0,
    )
    unit["deliverables"].append(deliv)
    assert verify_deliverable(deliv)["valid"]

    # Complete
    completion = complete_task(
        brief=brief, unit=unit,
        operator_public_key=op_kp["publicKey"],
        operator_private_key=op_kp["privateKey"],
        status="completed", retrospective="Smooth run",
    )
    unit["completion"] = completion
    assert get_task_status(unit) == "completed"
    assert verify_completion(completion, op_kp["publicKey"])["valid"]

    # Validate entire unit
    result = validate_task_unit(unit)
    assert result["valid"], f"Validation errors: {result['errors']}"


def test_cannot_approve_below_threshold():
    op_kp, researcher_kp, _ = _setup()
    brief = create_task_brief(
        title="Test", description="Test",
        operator_public_key=op_kp["publicKey"],
        operator_private_key=op_kp["privateKey"],
        roles=[{"role": "researcher", "requiredCapabilities": []}],
        deliverables=[{"name": "Output", "format": "text", "producedBy": "researcher"}],
        acceptance_criteria=["Done"],
    )
    packet = submit_evidence(
        task_id=brief["taskId"],
        submitter_public_key=researcher_kp["publicKey"],
        submitter_private_key=researcher_kp["privateKey"],
        role="researcher",
        claims=[{"claim": "Test", "confidence": "low", "quote": "This is test content"}],
        methodology="test",
    )
    with pytest.raises(ValueError, match="Cannot approve"):
        review_evidence(
            task_id=brief["taskId"], packet=packet,
            reviewer_public_key=op_kp["publicKey"],
            reviewer_private_key=op_kp["privateKey"],
            verdict="approve", score=50, threshold=70,
            rationale="Should fail",
        )


def test_cannot_handoff_unapproved():
    op_kp, researcher_kp, analyst_kp = _setup()
    brief = create_task_brief(
        title="Test", description="Test",
        operator_public_key=op_kp["publicKey"],
        operator_private_key=op_kp["privateKey"],
        roles=[{"role": "researcher", "requiredCapabilities": []}],
        deliverables=[{"name": "Output", "format": "text", "producedBy": "researcher"}],
        acceptance_criteria=["Done"],
    )
    packet = submit_evidence(
        task_id=brief["taskId"],
        submitter_public_key=researcher_kp["publicKey"],
        submitter_private_key=researcher_kp["privateKey"],
        role="researcher",
        claims=[{"claim": "Test", "confidence": "low", "quote": "This is test content"}],
        methodology="test",
    )
    review = review_evidence(
        task_id=brief["taskId"], packet=packet,
        reviewer_public_key=op_kp["publicKey"],
        reviewer_private_key=op_kp["privateKey"],
        verdict="rework", score=40, threshold=70,
        rationale="Needs work",
    )
    with pytest.raises(ValueError, match="not approved"):
        handoff_evidence(
            task_id=brief["taskId"], packet=packet, review=review,
            from_role="researcher", to_role="analyst",
            to_agent_public_key=analyst_kp["publicKey"],
            operator_private_key=op_kp["privateKey"],
        )
