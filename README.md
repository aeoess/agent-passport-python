# Agent Passport System — Python SDK

[![PyPI](https://img.shields.io/pypi/v/agent-passport-system)](https://pypi.org/project/agent-passport-system/)

**Enforcement and accountability layer for AI agents. Bring your own identity.** Python implementation of the [Agent Passport Protocol](https://aeoess.com), cross-language compatible with the [TypeScript SDK](https://www.npmjs.com/package/agent-passport-system) — signatures created in Python verify in TypeScript and vice versa. The Python port is a strict subset of the TS SDK; see the note under "What's Included" below for the current scope boundary.

## Install

```bash
pip install agent-passport-system
```

> **Current PyPI version**: `2.3.0` (default install). Cross-language parity with `agent-passport-system` npm v2.6.0-alpha.0 covers identity, delegation, governance, data source registration, training attribution, per-period attribution settlement, and mutual authentication. Wave 1 accountability and the evidentiary type safety primitives are TypeScript-only this iteration.


## Quick Start

Lead with the minimum you need to get a signed passport and a verifiable delegation — identity, delegation, policy evaluation. Import the rest from `agent_passport` when you need it. Full protocol surface (all 8 layers: attribution, values, agora, intent, coordination, commerce) is still available on the same package.

```python
from agent_passport import (
    generate_key_pair, create_passport, sign_passport, verify_passport,
    create_delegation, verify_delegation, create_action_receipt,
    # full surface available — import more when you need it:
    # build_merkle_root, load_floor, attest_floor, evaluate_compliance, ...
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

| Module | Layer | What It Does |
|--------|-------|-------------|
| `crypto` | — | Ed25519 key generation, signing, verification |
| `canonical` | — | Deterministic JSON serialization (cross-language compatible) |
| `passport` | 1 | Agent identity creation, signing, verification, expiry |
| `delegation` | 1 | Scoped delegation chains, sub-delegation, revocation |
| `values` | 2 | Human Values Floor: load YAML/JSON, attestation, compliance, graduated enforcement |
| `attribution` | 3 | Merkle proofs, beneficiary tracing, contribution tracking |
| `agora` | 4 | Signed message feeds, topics, threading, agent registry |
| `intent` | 5a | Roles, deliberation, consensus, tradeoff evaluation, precedents |
| `policy` | 5b | 3-signature chain, FloorValidatorV1, action intents |
| `coordination` | 6 | Task lifecycle: briefs, evidence, review, handoff, deliverables |
| `integration` | 7 | Cross-layer bridges (commerce+intent, coord+agora, etc.) |
| `commerce` | 8 | 4-gate checkout, human approval, spend tracking, receipts |

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

This Python SDK implements all 8 Agent Passport Protocol layers:

1. **Identity + Delegation** — Ed25519 passports, scoped delegation chains, cascade revocation
2. **Human Values Floor** — 7 principles (F-001 through F-007), graduated enforcement (inline/audit/warn)
3. **Beneficiary Attribution** — Merkle proofs for contribution tracking
4. **Agent Agora** — Signed message feeds with topics, threading, and agent registry
5. **Intent Architecture + Policy Engine** — Roles, deliberation, consensus, 3-signature policy chain
6. **Coordination** — Full task lifecycle: briefs, evidence, review, handoff, deliverables
7. **Integration Wiring** — Cross-layer bridges (commerce+intent, coordination+agora)
8. **Agentic Commerce** — 4-gate checkout, human approval, spend limits

Strict subset of the [TypeScript SDK](https://www.npmjs.com/package/agent-passport-system) at npm v2.6.0-alpha.0. Wave 1 accountability primitives (ActionReceipt, AuthorityBoundaryReceipt, CustodyReceipt, ContestabilityReceipt, APSBundle) and the evidentiary type safety primitives (claim-evidence registry, claim verifier, downstream-taint cascade) ship in the TypeScript SDK only this iteration; Python port deferred. Cross-language signature verification continues to work for the primitives Python does ship. Also available via the [MCP server](https://mcp.aeoess.com/sse).

## Links

- **Website**: https://aeoess.com
- **TypeScript SDK**: https://www.npmjs.com/package/agent-passport-system
- **MCP Server**: https://www.npmjs.com/package/agent-passport-system-mcp
- **Remote MCP**: https://mcp.aeoess.com/sse
- **Papers**:
  - [The Agent Social Contract](https://doi.org/10.5281/zenodo.18749779)
  - [Monotonic Narrowing](https://doi.org/10.5281/zenodo.18932404)
  - [Faceted Authority Attenuation](https://doi.org/10.5281/zenodo.19260073)
  - [Behavioral Derivation Rights](https://doi.org/10.5281/zenodo.19476002)
  - [Physics-Enforced Delegation](https://doi.org/10.5281/zenodo.19478584)
  - [Governance in the Medium](https://doi.org/10.5281/zenodo.19582550)
  - [Cognitive Attestation](https://doi.org/10.5281/zenodo.19646276)
  - [The Evidence-Safety Gap](https://doi.org/10.5281/zenodo.19914628)
  - IETF Internet-Draft: `draft-pidlisnyi-aps-00`
- **LLM docs**: https://aeoess.com/llms-full.txt

## Tests

```bash
pip install pynacl pytest
PYTHONPATH=src pytest tests/ -v
# 348 passed, 1 skipped, 6 xfailed across 27 test files. Coverage tracks the
# protocol layers the Python port has actually shipped (see "Strict subset" note above).
```

## License

Apache-2.0
