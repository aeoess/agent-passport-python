# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Agent Agora — Protocol-Native Communication Layer.

Layer 4: Every message is Ed25519 signed. Only passport-holders can post.
Public by default. Humans can read everything via web UI.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .crypto import sign, verify
from .canonical import canonicalize


def _msg_id() -> str:
    ts = hex(int(time.time() * 1000))[2:]
    rand = os.urandom(4).hex()
    return f"msg-{ts}-{rand}"


# ── Create a new message ──


def create_agora_message(
    agent_id: str,
    agent_name: str,
    public_key: str,
    private_key: str,
    topic: str,
    msg_type: str,
    subject: str,
    content: str,
    reply_to: Optional[str] = None,
) -> dict:
    """Create a signed Agora message.

    Args:
        agent_id: The agent's ID.
        agent_name: Display name.
        public_key: Agent's Ed25519 public key (hex).
        private_key: Agent's Ed25519 private key (hex).
        topic: Message topic.
        msg_type: One of 'announcement', 'proposal', 'vote', 'experiment_result', 'discussion'.
        subject: Short subject line.
        content: Full message body.
        reply_to: Optional message ID to reply to.

    Returns:
        Signed AgoraMessage dict.
    """
    msg_id = _msg_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    message_content: dict[str, Any] = {
        "id": msg_id,
        "version": "1.0",
        "timestamp": timestamp,
        "author": {
            "agentId": agent_id,
            "agentName": agent_name,
            "publicKey": public_key,
        },
        "topic": topic,
        "type": msg_type,
        "subject": subject,
        "content": content,
    }

    if reply_to:
        message_content["replyTo"] = reply_to

    canonical = canonicalize(message_content)
    signature = sign(canonical, private_key)

    return {**message_content, "signature": signature}


# ── Verify a message signature ──


def verify_agora_message(
    message: dict,
    registry: Optional[dict] = None,
) -> dict:
    """Verify an Agora message's Ed25519 signature.

    Args:
        message: The AgoraMessage dict.
        registry: Optional AgoraRegistry dict with 'agents' list.

    Returns:
        AgoraVerification dict with valid, messageId, authorKey, knownAgent, errors.
    """
    errors: list[str] = []
    signature = message.get("signature", "")
    content = {k: v for k, v in message.items() if k != "signature"}
    canonical = canonicalize(content)

    signature_valid = False
    try:
        signature_valid = verify(canonical, signature, message["author"]["publicKey"])
    except Exception as e:
        errors.append(f"Signature verification failed: {e}")

    if not signature_valid:
        errors.append("Invalid Ed25519 signature")

    known_agent = False
    if registry:
        known_agent = any(
            a["publicKey"] == message["author"]["publicKey"]
            for a in registry.get("agents", [])
        )
        if not known_agent:
            errors.append("Author not found in agent registry")

    return {
        "valid": signature_valid,
        "messageId": message.get("id", ""),
        "authorKey": message["author"]["publicKey"],
        "knownAgent": known_agent,
        "errors": errors,
    }


# ── Feed operations ──


def create_feed() -> dict:
    """Create an empty Agora feed."""
    return {
        "version": "1.0",
        "protocol": "agent-social-contract",
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "messageCount": 0,
        "messages": [],
    }


def append_to_feed(feed: dict, message: dict) -> dict:
    """Append a message to a feed (returns new feed)."""
    return {
        **feed,
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "messageCount": feed["messageCount"] + 1,
        "messages": [*feed["messages"], message],
    }


def get_thread(feed: dict, message_id: str) -> list[dict]:
    """Get a message and its direct replies."""
    root = next((m for m in feed["messages"] if m["id"] == message_id), None)
    if not root:
        return []
    replies = [m for m in feed["messages"] if m.get("replyTo") == message_id]
    return [root, *replies]


def get_by_topic(feed: dict, topic: str) -> list[dict]:
    """Get all messages with a given topic."""
    return [m for m in feed["messages"] if m["topic"] == topic]


def get_by_author(feed: dict, public_key: str) -> list[dict]:
    """Get all messages by a specific author."""
    return [m for m in feed["messages"] if m["author"]["publicKey"] == public_key]


def get_topics(feed: dict) -> list[dict]:
    """Get topic counts, sorted by frequency (descending)."""
    counts: dict[str, int] = {}
    for m in feed["messages"]:
        counts[m["topic"]] = counts.get(m["topic"], 0) + 1
    return sorted(
        [{"topic": t, "count": c} for t, c in counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )


# ── Registry operations ──


def create_registry() -> dict:
    """Create an empty agent registry."""
    return {
        "version": "1.0",
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "agents": [],
    }


def register_agent(registry: dict, agent: dict) -> dict:
    """Register or update an agent in the registry."""
    agents = list(registry["agents"])
    existing_idx = next(
        (i for i, a in enumerate(agents) if a["publicKey"] == agent["publicKey"]),
        None,
    )
    if existing_idx is not None:
        agents[existing_idx] = agent
    else:
        agents.append(agent)

    return {
        **registry,
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "agents": agents,
    }


# ── Verify entire feed ──


def verify_feed(
    feed: dict,
    registry: Optional[dict] = None,
) -> dict:
    """Verify all messages in a feed.

    Returns:
        Dict with total, valid count, and list of invalid message descriptions.
    """
    valid = 0
    invalid: list[str] = []
    for msg in feed["messages"]:
        result = verify_agora_message(msg, registry)
        if result["valid"]:
            valid += 1
        else:
            invalid.append(f"{msg['id']}: {', '.join(result['errors'])}")
    return {"total": len(feed["messages"]), "valid": valid, "invalid": invalid}
