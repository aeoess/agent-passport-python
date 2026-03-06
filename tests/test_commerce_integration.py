"""Tests for Commerce (Layer 8) and Integration Wiring (Layer 7)."""

from agent_passport import (
    generate_key_pair,
    create_passport,
    create_delegation,
    commerce_preflight,
    request_human_approval,
    create_commerce_delegation,
    get_spend_summary,
    sign_commerce_receipt,
    verify_commerce_receipt,
    commerce_with_intent,
    commerce_receipt_to_action_receipt,
    validate_commerce_delegation,
    coordination_to_agora,
    post_task_created,
    create_feed,
    create_registry,
    create_task_brief,
    FloorValidatorV1,
)


def _make_passport():
    result = create_passport(
        agent_id="shopper-001", agent_name="Shopper",
        owner_alias="tima", mission="Buy things",
        capabilities=["web_search"],
        runtime={"platform": "python", "models": [], "toolsCount": 1, "memoryType": "none"},
    )
    return result["signedPassport"], result["keyPair"]


def test_commerce_preflight_permits():
    sp, kp = _make_passport()
    deleg = create_commerce_delegation(
        agent_id="shopper-001", delegation_id="del-1",
        spend_limit=1000, approved_merchants=["TestShop"],
    )
    result = commerce_preflight(
        signed_passport=sp, delegation=deleg,
        merchant_name="TestShop",
        estimated_total={"amount": 50, "currency": "usd"},
    )
    assert result["permitted"]
    assert all(c["passed"] for c in result["checks"])


def test_commerce_preflight_denies_overspend():
    sp, kp = _make_passport()
    deleg = create_commerce_delegation(
        agent_id="shopper-001", delegation_id="del-1",
        spend_limit=100,
    )
    deleg["spentAmount"] = 90
    result = commerce_preflight(
        signed_passport=sp, delegation=deleg,
        merchant_name="AnyShop",
        estimated_total={"amount": 50, "currency": "usd"},
    )
    assert not result["permitted"]


def test_commerce_preflight_denies_unapproved_merchant():
    sp, kp = _make_passport()
    deleg = create_commerce_delegation(
        agent_id="shopper-001", delegation_id="del-1",
        spend_limit=1000, approved_merchants=["GoodShop"],
    )
    result = commerce_preflight(
        signed_passport=sp, delegation=deleg,
        merchant_name="EvilShop",
        estimated_total={"amount": 10, "currency": "usd"},
    )
    assert not result["permitted"]


def test_human_approval_request():
    req = request_human_approval(
        agent_id="shopper-001", delegation_id="del-1",
        merchant_name="LuxuryShop",
        items=[{"skuId": "sku-1", "name": "Widget", "quantity": 1}],
        total_amount={"amount": 5000, "currency": "usd"},
        reason="High-value purchase",
    )
    assert req["status"] == "pending"
    assert req["requestId"]


def test_spend_summary():
    deleg = create_commerce_delegation(
        agent_id="shopper-001", delegation_id="del-1",
        spend_limit=1000,
    )
    deleg["spentAmount"] = 850
    summary = get_spend_summary(deleg)
    assert summary["remaining"] == 150
    assert summary["nearLimit"]
    assert summary["utilizationPercent"] == 85.0


def test_sign_and_verify_commerce_receipt():
    kp = generate_key_pair()
    receipt = sign_commerce_receipt(
        agent_id="shopper-001", delegation_id="del-1",
        action_type="commerce:checkout", target="https://shop.example.com",
        method="POST", merchant_name="TestShop",
        session_id="sess-1", items=[{"skuId": "sku-1", "name": "Widget", "quantity": 1, "unitPrice": 25}],
        total_amount=25, total_currency="usd", status="completed",
        delegation_chain=[kp["publicKey"]], beneficiary="human-1",
        private_key=kp["privateKey"],
    )
    assert receipt["signature"]
    result = verify_commerce_receipt(receipt, kp["publicKey"])
    assert result["valid"]


def test_commerce_receipt_to_action_receipt():
    kp = generate_key_pair()
    receipt = sign_commerce_receipt(
        agent_id="shopper-001", delegation_id="del-1",
        action_type="commerce:checkout", target="https://shop.example.com",
        method="POST", merchant_name="TestShop",
        session_id="sess-1", items=[{"skuId": "sku-1", "name": "Widget", "quantity": 1, "unitPrice": 25}],
        total_amount=25, total_currency="usd", status="completed",
        delegation_chain=[kp["publicKey"]], beneficiary="human-1",
        private_key=kp["privateKey"],
    )
    action_receipt = commerce_receipt_to_action_receipt(receipt)
    assert action_receipt["receiptId"] == receipt["receiptId"]
    assert action_receipt["action"]["scopeUsed"] == "commerce:checkout"
    assert "TestShop" in action_receipt["result"]["summary"]


def test_validate_commerce_delegation():
    kp = generate_key_pair()
    proto_del = create_delegation(
        delegated_by=kp["publicKey"], delegated_to=kp["publicKey"],
        scope=["commerce:checkout", "commerce:browse"],
        private_key=kp["privateKey"], spend_limit=500,
    )
    comm_del = create_commerce_delegation(
        agent_id="agent-1", delegation_id=proto_del["delegationId"],
        spend_limit=200,
    )
    result = validate_commerce_delegation(comm_del, proto_del)
    assert result["valid"]
    assert result["scopeMatch"]
    assert result["withinSpendLimit"]


def test_coordination_to_agora():
    kp = generate_key_pair()
    feed = create_feed()
    registry = create_registry()
    result = coordination_to_agora(
        event="task_created", task_id="task-001",
        agent_id="op-1", agent_name="Operator",
        public_key=kp["publicKey"], private_key=kp["privateKey"],
        feed=feed, registry=registry, detail="New task created",
    )
    assert result["message"]["topic"] == "coordination:task-001"
    assert result["feed"]["messageCount"] == 1


def test_commerce_with_intent():
    sp, agent_kp = _make_passport()
    evaluator_kp = generate_key_pair()
    delegation = create_delegation(
        delegated_by=evaluator_kp["publicKey"],
        delegated_to=agent_kp["publicKey"],
        scope=["commerce:checkout"],
        private_key=evaluator_kp["privateKey"],
        spend_limit=500,
    )
    comm_del = create_commerce_delegation(
        agent_id="shopper-001", delegation_id=delegation["delegationId"],
        spend_limit=500, approved_merchants=["TestShop"],
    )
    ctx = {
        "agentRegistered": True,
        "agentAttestationValid": True,
        "floorVersion": "0.1",
        "delegation": delegation,
        "floorPrinciples": [],
    }
    result = commerce_with_intent(
        signed_passport=sp, agent_private_key=agent_kp["privateKey"],
        delegation=delegation, commerce_delegation=comm_del,
        merchant_name="TestShop",
        estimated_total={"amount": 50, "currency": "usd"},
        action_description="Buy widgets",
        validator=FloorValidatorV1(),
        validation_context=ctx,
        evaluator_id="eval-1",
        evaluator_public_key=evaluator_kp["publicKey"],
        evaluator_private_key=evaluator_kp["privateKey"],
    )
    assert result["permitted"]
    assert result["decision"]["verdict"] == "permit"
