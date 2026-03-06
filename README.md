# Agent Passport System — Python SDK

[![PyPI](https://img.shields.io/pypi/v/agent-passport-system)](https://pypi.org/project/agent-passport-system/)

Cryptographic identity, delegation, governance, and attribution for AI agents. Python implementation of the [Agent Passport Protocol](https://aeoess.com).

**Cross-language compatible** with the [TypeScript SDK](https://www.npmjs.com/package/agent-passport-system). Signatures created in Python verify in TypeScript and vice versa.

## Install

```bash
pip install agent-passport-system
```

## Quick Start

```python
from agent_passport import (
    generate_key_pair, create_passport, sign_passport, verify_passport,
    create_delegation, verify_delegation, create_action_receipt,
    build_merkle_root, get_merkle_proof, verify_merkle_proof,
    load_floor, attest_floor, verify_attestation, evaluate_compliance,
)

# Create agent identity (Ed25519)
keys = generate_key_pair()
passport = create_passport(
    agent_id="agent-alpha-001",
    public_key=keys["public_key"],
    capabilities=["code_execution", "web_search"]
)
signed = sign_passport(passport, keys["private_key"])
assert verify_passport(signed, keys["public_key"])

# Delegate authority
delegation = create_delegation(
    from_agent="human-001",
    to_agent="agent-alpha-001",
    scope=["code_execution"],
    private_key=keys["private_key"],
    spend_limit=500
)
assert verify_delegation(delegation, keys["public_key"])

# Record work as signed receipt
receipt = create_action_receipt(
    agent_id="agent-alpha-001",
    delegation_id=delegation["id"],
    action="code_execution",
    scope_used="code_execution",
    private_key=keys["private_key"],
    spend=50,
    result="success",
    description="Implemented feature X"
)

# Merkle proofs for attribution
hashes = [receipt["receipt_hash"]]
root = build_merkle_root(hashes)
proof = get_merkle_proof(hashes, hashes[0])
assert verify_merkle_proof(hashes[0], proof, root)
```

## What's Included

| Module | What It Does |
|--------|-------------|
| `crypto` | Ed25519 key generation, signing, verification |
| `canonical` | Deterministic JSON serialization (cross-language compatible) |
| `passport` | Agent identity creation, signing, verification, expiry |
| `delegation` | Scoped delegation chains, sub-delegation, revocation |
| `attribution` | Merkle proofs, beneficiary tracing, contribution tracking |
| `values` | Human Values Floor: load YAML/JSON, attestation, compliance, graduated enforcement |

## Cross-Language Compatibility

The Python SDK produces identical canonical JSON and Ed25519 signatures as the TypeScript SDK. This means:

- A passport signed in Python can be verified in TypeScript
- Delegation chains can span Python and TypeScript agents
- Merkle roots computed from the same receipts match across languages

```python
from agent_passport import canonical_json

# Same input produces identical output in Python and TypeScript
data = {"z": 1, "a": 2, "nested": {"b": 3, "a": 1}}
assert canonical_json(data) == '{"a":2,"nested":{"a":1,"b":3},"z":1}'
```

## Protocol Layers

This Python SDK implements 4 of the 8 Agent Passport Protocol layers:

1. **Identity** — Ed25519 passports with capabilities and vote weight
2. **Delegation** — Scoped authority with spend limits and depth controls
3. **Attribution** — Merkle proofs for contribution tracking
4. **Values Floor** — 7 principles (F-001 through F-007), YAML/JSON loading, attestation, compliance evaluation, graduated enforcement (inline/audit/warn)

The remaining layers (Agora, Intent Architecture, Coordination, Commerce) are available in the [TypeScript SDK](https://www.npmjs.com/package/agent-passport-system) and via the [MCP server](https://mcp.aeoess.com/sse).

## Links

- **Website**: https://aeoess.com
- **TypeScript SDK**: https://www.npmjs.com/package/agent-passport-system
- **MCP Server**: https://www.npmjs.com/package/agent-passport-system-mcp
- **Remote MCP**: https://mcp.aeoess.com/sse
- **Paper**: https://doi.org/10.5281/zenodo.18749779
- **LLM docs**: https://aeoess.com/llms-full.txt

## Tests

```bash
pip install pynacl pytest
PYTHONPATH=src pytest tests/ -v
# 50 tests, including cross-language compatibility and Values Floor
```

## License

Apache-2.0
