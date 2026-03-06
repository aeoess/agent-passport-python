"""Tests for Agent Agora (Layer 4 — Communication)."""

from agent_passport import (
    generate_key_pair,
    create_agora_message,
    verify_agora_message,
    create_feed,
    append_to_feed,
    get_thread,
    get_by_topic,
    get_by_author,
    get_topics,
    create_registry,
    register_agent,
    verify_feed,
)


def _make_agent():
    kp = generate_key_pair()
    return {
        "id": "test-agent",
        "name": "Test Agent",
        "publicKey": kp["publicKey"],
        "privateKey": kp["privateKey"],
    }


def test_create_and_verify_message():
    a = _make_agent()
    msg = create_agora_message(
        agent_id=a["id"], agent_name=a["name"],
        public_key=a["publicKey"], private_key=a["privateKey"],
        topic="governance", msg_type="announcement",
        subject="Hello", content="First message",
    )
    assert msg["topic"] == "governance"
    assert msg["signature"]
    result = verify_agora_message(msg)
    assert result["valid"]


def test_tampered_message_fails():
    a = _make_agent()
    msg = create_agora_message(
        agent_id=a["id"], agent_name=a["name"],
        public_key=a["publicKey"], private_key=a["privateKey"],
        topic="test", msg_type="discussion",
        subject="Tamper test", content="Original",
    )
    msg["content"] = "Tampered!"
    result = verify_agora_message(msg)
    assert not result["valid"]


def test_feed_operations():
    a = _make_agent()
    feed = create_feed()
    assert feed["messageCount"] == 0

    msg1 = create_agora_message(
        agent_id=a["id"], agent_name=a["name"],
        public_key=a["publicKey"], private_key=a["privateKey"],
        topic="ops", msg_type="announcement",
        subject="Msg 1", content="First",
    )
    feed = append_to_feed(feed, msg1)
    assert feed["messageCount"] == 1

    msg2 = create_agora_message(
        agent_id=a["id"], agent_name=a["name"],
        public_key=a["publicKey"], private_key=a["privateKey"],
        topic="dev", msg_type="discussion",
        subject="Msg 2", content="Second",
    )
    feed = append_to_feed(feed, msg2)
    assert feed["messageCount"] == 2


def test_threading():
    a = _make_agent()
    feed = create_feed()
    root = create_agora_message(
        agent_id=a["id"], agent_name=a["name"],
        public_key=a["publicKey"], private_key=a["privateKey"],
        topic="thread-test", msg_type="discussion",
        subject="Root", content="Root message",
    )
    feed = append_to_feed(feed, root)
    reply = create_agora_message(
        agent_id=a["id"], agent_name=a["name"],
        public_key=a["publicKey"], private_key=a["privateKey"],
        topic="thread-test", msg_type="discussion",
        subject="Reply", content="Reply message",
        reply_to=root["id"],
    )
    feed = append_to_feed(feed, reply)
    thread = get_thread(feed, root["id"])
    assert len(thread) == 2


def test_topic_filtering():
    a = _make_agent()
    feed = create_feed()
    for topic in ["ops", "dev", "ops"]:
        msg = create_agora_message(
            agent_id=a["id"], agent_name=a["name"],
            public_key=a["publicKey"], private_key=a["privateKey"],
            topic=topic, msg_type="announcement",
            subject=f"Topic: {topic}", content="test",
        )
        feed = append_to_feed(feed, msg)
    ops_msgs = get_by_topic(feed, "ops")
    assert len(ops_msgs) == 2
    topics = get_topics(feed)
    assert topics[0]["topic"] == "ops"
    assert topics[0]["count"] == 2


def test_registry():
    a = _make_agent()
    registry = create_registry()
    agent_entry = {"agentId": a["id"], "agentName": a["name"], "publicKey": a["publicKey"], "role": "operator"}
    registry = register_agent(registry, agent_entry)
    assert len(registry["agents"]) == 1

    msg = create_agora_message(
        agent_id=a["id"], agent_name=a["name"],
        public_key=a["publicKey"], private_key=a["privateKey"],
        topic="test", msg_type="announcement",
        subject="Reg test", content="test",
    )
    result = verify_agora_message(msg, registry)
    assert result["valid"]
    assert result["knownAgent"]


def test_verify_feed():
    a = _make_agent()
    feed = create_feed()
    for i in range(3):
        msg = create_agora_message(
            agent_id=a["id"], agent_name=a["name"],
            public_key=a["publicKey"], private_key=a["privateKey"],
            topic="bulk", msg_type="announcement",
            subject=f"Msg {i}", content=f"Content {i}",
        )
        feed = append_to_feed(feed, msg)
    result = verify_feed(feed)
    assert result["total"] == 3
    assert result["valid"] == 3
    assert len(result["invalid"]) == 0
