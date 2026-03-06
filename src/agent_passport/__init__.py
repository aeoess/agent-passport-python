"""Agent Passport System — Python SDK.

Cryptographic identity, delegation, governance, and attribution for AI agents.
Cross-language compatible with the TypeScript SDK (npm: agent-passport-system).

Quick start:
    from agent_passport import create_passport, verify_passport

    result = create_passport(
        agent_id="my-agent-001",
        agent_name="My Agent",
        owner_alias="developer",
        mission="Assist with development tasks",
        capabilities=["code_execution", "web_search"],
        runtime={"platform": "python", "models": ["gpt-4"], "toolsCount": 5, "memoryType": "session"},
    )
    passport = result["signedPassport"]
    key_pair = result["keyPair"]

    # Verify
    check = verify_passport(passport)
    assert check["valid"]

Remote MCP: https://mcp.aeoess.com/sse
Docs: https://aeoess.com/llms-full.txt
"""

__version__ = "0.2.0"

# Crypto
from .crypto import generate_key_pair, sign, verify, public_key_from_private

# Canonical serialization
from .canonical import canonicalize

# Passport (Layer 1 — Identity)
from .passport import (
    create_passport,
    sign_passport,
    verify_passport,
    update_passport,
    is_expired,
)

# Delegation (Layer 1 — Delegation)
from .delegation import (
    create_delegation,
    verify_delegation,
    sub_delegate,
    revoke_delegation,
    create_action_receipt,
)

# Attribution (Layer 3 — Merkle proofs)
from .attribution import (
    build_merkle_root,
    get_merkle_proof,
    verify_merkle_proof,
)

# Values Floor (Layer 2 — Human Values Floor)
from .values import (
    load_floor,
    load_floor_from_file,
    resolve_enforcement_mode,
    effective_enforcement_mode,
    attest_floor,
    verify_attestation,
    evaluate_compliance,
    negotiate_common_ground,
)
