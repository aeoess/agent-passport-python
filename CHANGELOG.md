# Changelog

## Unreleased

### Fixed / Security (audit 2026-07-10; pending review before release)
- **Expiry fail-open on Python < 3.11 (authority).** `verify_delegation`, `is_expired`, and `sub_delegate` parsed `expiresAt` with `datetime.fromisoformat`, which did not accept a trailing `Z` until 3.11, and swallowed the resulting error so the expiry check silently no-opped on the declared minimum interpreter. Added `_time.parse_iso_utc` (correct on 3.9+) and made an unparseable expiry fail closed (treated as expired), not open.
- **Canonical-byte divergence from RFC 8785 / the TS SDK (cross-language signatures).** `canonicalize` and `canonicalize_jcs` serialized floats with Python `repr`/`json.dumps` (e.g. `1e21`, `1e-07`, `1e-06`) and sorted object keys by code point. Both now use `_es_number` (ECMAScript `Number::toString`, validated byte-identical to Node over 20k values) and a UTF-16 code-unit key sort, matching the TS reference on floats and astral-plane keys. The JCS non-container fallback also now sets `ensure_ascii=False`.
- **action_ref naive-timestamp divergence.** `compute_action_ref` assumed UTC for offsetless timestamps while the TS reference parses them as local time; it now rejects naive timestamps (spec 4.1 requires an explicit `Z`/offset) and formats the year with explicit zero-padding.

## 2.8.0 (2026-07-10)

### Added
- **`compute_action_ref(agent_id, action_type, scope_required, timestamp)`** (`action_ref.py`): the native APS action_ref of draft-pidlisnyi-aps-03 section 4.1, SHA-256 over the strict RFC 8785 canonicalization of `{agentId, actionType, scopeRequired, timestamp}` with NFC per scope string and a Unicode code-point sort of the scope list on a copy. **Cross-language byte parity with the TS SDK (npm v3.3.0) and the Go implementation**, pinned by the shared vectors in `tests/cross_impl/actionref-canonical-vectors.json` (4 of 4 byte-identical hex). Distinct from `compute_attribution_action_ref` (attribution preimage with nonce and params); that function is untouched.

## 2.7.0 (2026-07-04)

- Release/version bump only: synced the package version and the description's cross-language parity line to the current TS SDK. No functional or byte-level changes to the protocol primitives (README.md, pyproject.toml).

## 2.6.0 (2026-07-04)

### Added
- **`trace_beneficiary(receipt, delegations, beneficiary_map)`** (`attribution.py`) and **`verify_action_receipt(receipt, agent_public_key)`** (`delegation.py`): parity with the TypeScript beneficiary-verified-honesty change. `verified` is a real cryptographic check (the receipt signature verifies at the chain tail via `verify_action_receipt`, and every delegation in the lineage verifies via `verify_delegation`), not a lookup; a new `resolved` field carries the lookup-only semantics (lineage maps to known records and a known beneficiary, no cryptographic claim). The reported lineage is deterministic (valid-first, then `delegationId`) with the tail hop tied to `receipt.delegationId`. A forged or tampered chain reports `resolved` true but `verified` false. Reuses the existing Ed25519 verifiers; no crypto reimplemented.
- **APS Composition Check Receipt v0** (`v2/composition_check/`): port of the carrier and stateless ANCHOR verifier `verify_composition_check`. Verifies the signature, the `(chain_hash, action_ref, context_hash)` binding, freshness (caller-supplied `now_ms`, fails closed on a non-finite value), well-formedness, and attestor trust for the opaque `policy_profile_ids`; surfaces `independence_is_second_anchor` corroborated from the trust context (`registered_by_operator` is False) and gated on `anchor_verified`. No policy grammar, no detection logic, no aggregate, and no `safe` boolean: detection stays in the private gateway. `result_per_check` is a fixed enum (`pass | fail | indeterminate | not_checked`). **Cross-language signature compatible with the TS SDK**: a receipt signed by either SDK verifies under the other (the canonical signing bytes are `f"APS-COMPCHECK-V0.{canonicalize_jcs(receipt-without-signature)}"`, byte-matching the TS `canonicalizeJCS`). Conformance vectors in `conformance/composition-check/v0/` are the TS-signed vectors, verified here. Additive: new functions and a new module, no existing type changed.

## 2.5.0

### Added
- **`record_spend(commerce_delegation, amount)`** (`commerce.py`): the stateless write primitive for
  commerce spend. It returns a new CommerceDelegation with `spentAmount` incremented, refusing a
  non-finite or negative amount and refusing a spend that would exceed `spendLimit`. It pairs with the
  spend gate: check before a purchase, record after, persist the returned object. The SDK does not
  persist spend between calls; cumulative enforcement across purchases is the caller's or the gateway's
  responsibility. This is the parity primitive for the TypeScript `recordSpend`.

### Fixed / Security
- **Spend-accumulation no-op closed.** `spentAmount` was read by the spend check but never written, so a
  single delegation passed unlimited purchases against its cap. `record_spend` is the write half; the
  signed core delegation's `spentAmount` is documented as an immutable spend-at-issue value (always 0),
  not a running total.
- **`sub_delegate` now verifies the parent and narrows correctly** (`delegation.py`). It verifies the
  parent before minting a child, caps the child's expiry to the parent's, rejects a child whose spend
  exceeds the parent's remaining budget, and computes depth-exceeded rather than hardcoding it false.
- **`commerce_preflight` spend gate denies a currency mismatch** (`commerce.py`). The gate compared
  amounts without checking currency, so a purchase in one currency passed a budget denominated in
  another (the SDK does no conversion). A declared currency mismatch is now denied; an absent currency
  on either side stays unconstrained.

### Behavior changes (operations previously permitted now fail closed)
- A cross-currency commerce spend (purchase currency differs from the budget currency) is now denied
  instead of passing.
- A sub-delegation that widens authority (spend above the parent remaining, expiry beyond the parent,
  or depth past the limit) or that derives from a parent that does not verify is now rejected instead of
  produced.
