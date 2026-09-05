# Changelog

## 3.0.1 (2026-09-04)

Documentation only. The README published with 3.0.0 still described the package as 2.11.0 and omitted the Rust SDK; the package page now states the current family. No code change.

## 3.0.0 (2026-09-04)

Security release. The full cross-SDK account, including the affected version
ranges and the severity assessment, is in the security advisory for this
release. [The verification boundary](https://github.com/aeoess/agent-passport-python/blob/main/docs/verification-boundary.md)
names the verification APIs that establish authority from caller-supplied trust,
and the trust input each takes.

Several exported verification functions returned a successful verification
result (`valid: true` or an equivalent) without establishing all of the trust,
linkage, context and temporal conditions the result implied. In the affected
paths the verification key came from the artifact itself, the claimed identity
was not bound to the key that signed, chained artifacts were not linked to the
artifacts they claimed to derive from, or an unreadable timestamp compared as
neither expired nor stale. A relying party that treated those results as
authorization could accept an artifact an attacker produced with keys the
attacker controls.

This release changes what the affected functions establish. Trust anchors and
the expected challenge are caller-supplied where the result claims authority;
the presentation domain is signed, and a caller that uses domain as a
relying-party boundary compares it through the expected-domain option.
Identities are bound to keys. Chains are linked. Invalid time fails closed.
Creators refuse to mint artifacts their own verifiers reject. The affected
verifiers return a rejection on a malformed timestamp or a missing chain
instead of raising; creators and `assign_role` raise.

### Affected surfaces

One row per exported surface and defect class; a surface with two defect classes
appears twice. Copied from the security advisory for this release.

| exported name | module path | defect class | consumer change |
|---|---|---|---|
| `verify_passport` | src/agent_passport/passport.py | authority false accept | Two keyword-only params with defaults, so positional calls still bind, but the answer changes: a self-signed passport now returns valid False. Callers establishing issuer authority pass trusted_issuers; allow_self_signed=True explicitly accepts a self-signed passport and is appropriate only where issuer authority is not being established.|
| `assign_role` | src/agent_passport/intent.py | authority false accept | Two keyword-only params added. A call that omits both now raises ValueError instead of returning a role assignment |
| `commerce_preflight` | src/agent_passport/commerce.py | authority false accept | Two keyword-only params added; positional calls still bind. Calls that previously reported permitted True on a self-signed passport now report permitted False until trust is supplied |
| `commerce_with_intent` | src/agent_passport/integration.py | authority false accept | Two keyword-only params added after evaluator_private_key; positional calls still bind but a self-signed passport no longer yields a permitted preflight |
| `verify_verifiable_credential` | src/agent_passport/vc_wrapper.py | artifact key used as trust root | Result gains key_authority (verified/rejected/unresolved), issuer_did (empty unless binding succeeded) and proof_of_possession. Non-self-certifying issuers such as did:web now return unresolved and valid False. Credentials issued under the old body-only preimage no longer verify |
| `verify_verifiable_presentation` | src/agent_passport/vc_wrapper.py | identity not bound to key | Signature widens to (vp, expected_challenge=None, expected_domain=None); a one-argument call now returns valid False. Result gains key_authority, holder_did, proof_of_possession, challenge and domain. Presentations made under the old preimage no longer verify |
| `create_verifiable_presentation` | src/agent_passport/vc_wrapper.py | identity not bound to key | Signature gains a required challenge and an optional domain; omitting challenge raises TypeError: omitting it raises TypeError instead of minting an artifact. Presentations it emits do not verify against a before the fixed version verifier and vice versa |
| `passport_to_verifiable_credential` | src/agent_passport/vc_wrapper.py | identity not bound to key | No signature change. The artifact changes: credentials it emits are a new preimage that before the fixed version verifiers reject, and credentials it produced before the fixed version no longer verify. The signed preimage is identical in the TypeScript and Python SDKs. |
| `fulfill_credential_request` | src/agent_passport/credential_request.py | identity not bound to key | No signature change. Responses it emits are a new preimage: before the fixed version verify_credential_response rejects them and responses produced before the fixed version no longer verify |
| `verify_credential_response` | src/agent_passport/credential_request.py | identity not bound to key | Signature unchanged, but a call that omits expected_challenge now returns valid False. Result gains holder_did, empty unless the binding held. Non-self-certifying holders and issuers now fail as unresolved |
| `verify_policy_receipt` | src/agent_passport/policy.py | chain not linked | Third parameter chain added. A two-argument call now returns valid False with chain_verified False, not an exception. Result gains envelope_signature_valid and chain_verified. Callers that only want envelope integrity should move to verify_policy_receipt_envelope |
| `verify_policy_receipt_envelope` | src/agent_passport/policy.py | chain not linked | New export added to src/agent_passport/__init__.py. A caller that does not need the chain checked must now name this function; it cannot get that answer by accident from verify_policy_receipt |
| `verify_policy_decision` | src/agent_passport/policy.py | invalid time fails open | An expiresAt outside strict RFC 3339 (zone-less, space separator, hour 24, leap second, lowercase t/z, sub-millisecond over 9 digits) now yields valid False with a stated reason instead of an exception or a silent pass |
| `verify_attestation` | src/agent_passport/values.py | invalid time fails open | Returns valid False with a reason instead of raising. Attestations carrying a non-RFC-3339 expiresAt no longer verify |
| `negotiate_common_ground` | src/agent_passport/values.py | invalid time fails open | Returns a refusal reason instead of raising. Two agents whose attestations carry non-RFC-3339 expiries no longer reach common ground |
| `FloorValidatorV1.evaluate` | src/agent_passport/policy.py | invalid time fails open | Delegations carrying a non-RFC-3339 expiresAt now fail Auditability under whatever enforcement mode is configured (inline, audit or warn). evaluate_intent and request_action, which call the validator, inherit the new verdict |
| `verify_attribution_consent` | src/agent_passport/v2/attribution_consent/verify.py | artifact key used as trust root | Signature unchanged. Behavioural break: receipts whose parties are named by opaque identifiers (agent:citer, did:web:...) no longer verify. Reissuance under did:key is the migration. The signed preimage did not move: both the did:key and the opaque-identifier fixtures still hash to the same id |
| `check_artifact_citations` | src/agent_passport/v2/attribution_consent/verify.py | artifact key used as trust root | Signature unchanged. Artifacts citing receipts with opaque party identifiers stop passing the gate; same reissuance migration as verify_attribution_consent |
| `compute_action_ref` | src/agent_passport/action_ref.py | invalid time fails open | The two spellings now raise ValueError instead of returning a hash. Every input that produced an address before still produces the same one: one instant written six ways still hashes to f00d48a5c11c16a535d93c4b2daeed15fefbb5943ac3b4ca58698d2c8bf918f5, and the shared cross-language vectors are unaffected. One divergence remains by decision: lowercase t/z, which TypeScript accepts and Python refuses |

### Migration

| package | old call shape | new call shape | unmigrated call | artifacts reissued |
|---|---|---|---|---|
| python | `verify_passport(signed_passport) returned valid True for a self-minted passport` | `verify_passport(signed_passport, trusted_issuers=[...]) or verify_passport(signed_passport, allow_self_signed=True)` | valid false: the additions are keyword-only with defaults so every positional call still binds; result carries issuer_trust_checked and self_signed_accepted | no: no artifact shape changes; issuer_signature_preimage is exported so an issuer can countersign an existing passport |
| python | `assign_role(signed_passport, role, autonomy_level, scope, assigner_private_key, assigner_public_key, department=None)` | `same call plus trusted_issuers=[...] or allow_self_signed=True` | exception: raises ValueError, as it already did for an invalid passport | no: no artifact changes |
| python | `commerce_preflight(signed_passport, delegation, merchant_name, estimated_total)` | `same call plus trusted_issuers=[...] or allow_self_signed=True` | valid false: Gate 1 reports passed False, which makes permitted False | no: no artifact changes |
| python | `commerce_with_intent(..., evaluator_private_key) with no trust input` | `same call plus trusted_issuers=[...] or allow_self_signed=True` | valid false: it threads the trust input to the preflight, so permitted is False without one | no: no artifact changes |
| python | `verify_attribution_consent(receipt) accepted citer and cited_principal as opaque identifiers with any key beside them` | `same call, with each party named by a did:key or a multibase did:aps that commits to the key beside it` | valid false: reason is 'unresolved' or 'rejected'; check_artifact_citations inherits it | yes: receipts naming parties by opaque identifiers must be reissued under did:key; both fixtures still hash to the same id, so the signed preimage did not move |
| python | `compute_action_ref(..., timestamp) accepted the space separator '2026-04-05 03:39:31Z' and rolled '2026-04-05T24:00:00Z' into the next day` | `compute_action_ref(..., timestamp) with the uppercase T separator and an hour of 23 or less` | exception: ValueError naming the rule, raised from _normalize_timestamp | no: every input that produced an address still produces the same one, and one instant written six ways still hashes to f00d48a5c11c16a535d93c4b2daeed15fefbb5943ac3b4ca58698d2c8bf918f5 |
| python | `verify_verifiable_credential(vc) and verify_verifiable_presentation(vp) over a proof signed on the body only, with created written by datetime.isoformat` | `same calls; the proof configuration is inside the signed bytes and created is written by format_rfc3339` | valid false: there is no dual-verification path, so a before the fixed version artifact does not verify | yes: every Python-minted VC and VP issued before the fixed version must be reissued |
| python | `verify_verifiable_presentation(vp) and verify_credential_response(vp) with no expected challenge (the comparison was skipped entirely)` | `verify_verifiable_presentation(vp, expected_challenge) and verify_credential_response(vp, expected_challenge)` | valid false: the parameters still default to None so the call binds, but a presentation verified against no challenge is refused | no reissue for the expected-challenge change itself; credential responses minted under the previous signed preimage must be reissued (see the fulfill_credential_request row) |
| python | `create_verifiable_presentation(credentials, holder_private_key) minted a presentation carrying no challenge` | `create_verifiable_presentation(credentials, holder_private_key, challenge, domain=None)` | exception: TypeError; creators raise where verifiers return | yes: a challenge-less presentation is one this package's own verifier always rejects |
| python | `verify_policy_receipt(policy_receipt, verifier_public_key) returned valid True with three fake inner signature strings` | `verify_policy_receipt(policy_receipt, verifier_public_key, chain: PolicyReceiptChainInputs), or verify_policy_receipt_envelope for the envelope-only check` | valid false: chain is still Optional with a None default so the call binds; the result carries chain_verified False and no exception is raised | no: receipts unchanged; the caller must present the intent, decision and action receipt plus an anchor for each |
| python | `FloorValidatorV1 swallowed an unreadable expiresAt and produced no Auditability finding; verify_policy_decision, verify_attestation, negotiate_common_ground, verify_verifiable_credential and verify_credential_response parsed with no guard at all` | `all six route through _time.parse_rfc3339 and report the refusal in the vocabulary the site already uses` | valid false: a present-but-unreadable expiresAt now produces a finding where it produced none; an absent or empty expiresAt still means no stated end | yes: artifacts whose expiresAt is present but unreadable; every spelling this package emits is inside the grammar, so conforming artifacts are unaffected |

## 2.11.0 (2026-08-20)

### Fixed / Security

- **`canonicalize_jcs` serializes `int` through the RFC 8785 number domain, so canonical bytes agree with the TypeScript and Go SDKs.** RFC 8785 section 3.2.2.3 defines the JCS number domain as IEEE 754 binary64 serialized under ECMAScript `Number::toString`. Python's `int` is arbitrary precision and the previous code emitted it verbatim, keeping a decimal spelling the double does not have: 2^60 emitted as `1152921504606846976` where the binary64 serialization is `1152921504606847000`. Where those two spellings differ, a digest or signature computed over `canonicalize_jcs` output disagreed with the same object canonicalized by the TypeScript or Go SDK, both of which already emitted the binary64 form, so such an artifact verified in this SDK and failed for a peer that recomputed the bytes through the RFC 8785 number domain. The `int` branch now widens to binary64 first and takes the same path a `float` takes. An integer beyond the binary64 range raises `JCSCanonicalizationError` with reason `number_out_of_double_range`, since RFC 8785 defines no representation for it. The generic `canonicalize` is untouched.

### Behavior change

- **Canonical JCS bytes move for integers whose decimal spelling differs from the binary64 serialization of the same value, which is why the minor version moves rather than the patch.** Not every large integer is affected. `9007199254740992` and `9007199254740994` are unchanged, while `9007199254740993` now emits `9007199254740992`, 2^60 emits `1152921504606847000` and 2^68 emits `295147905179352830000`. A signature made by 2.10.0 or earlier over an affected value does not verify against bytes recomputed by 2.11.0. Those artifacts were already unverifiable outside Python for the reason above, so this release makes the failure visible in one place instead of leaving it to the peer. The pinned canonicalization baselines are unchanged and the generic `canonicalize` keeps its previous output.
- **Signing and new-write boundaries refuse integer-valued numbers outside the interoperable IEEE 754 range.** RFC 7493 section 2.2 says an I-JSON sender cannot expect a receiver to treat an integer whose absolute value exceeds 9007199254740991 as an exact value, and recommends encoding such a value as a JSON string. A new-write value carrying such an integer now raises `UnsafeIntegerError`, a `ValueError` subclass carrying the JSON path of the offending member. Only integer-valued numbers are bounded. Verification and recompute paths keep calling the unrestricted canonicalizer, so this rule refuses nothing on the verification side: where a pre-2.11.0 artifact stops verifying, the cause is the canonicalization change above and not this rule. The guard is internal: no write-policy name is exported from `agent_passport`, and `write_policy.py` ships in the wheel for internal use. One limit worth knowing at the call site: a documented set of exported helpers both mint and re-derive a value through the same function and stay unrestricted, so that re-derivation of a value minted before the rule keeps working. Minting an unsafe integer through one of those helpers is not covered. Scope, the call-site inventory and the proofs are in #6.

## 2.10.0 (2026-07-26)

### Added
- **receipt-core v1 module.** The Python port of the receipt-core module lands with the same shapes and the same canonical bytes as the TypeScript SDK.

### Behavior change
- **`scope_required` now rejects duplicate elements after NFC normalization.** Section 4.1 defines `scope_required` as a duplicate-free array. The canonicalizer normalized and sorted but neither deduplicated nor rejected, so `["a","a"]` and `["a"]` produced different action references while the specification admits one form. `canonicalize_scope_required` now raises `DuplicateScopeRequiredError`, a `ValueError` subclass carrying category `invalid_scope_required` and reason `duplicate_scope_required`, before any identity is computed. Detection runs after NFC, so two spellings that collide only under normalization also reject. Input that previously produced an `action_ref` now raises, and only duplicated input is affected.

### Fixed
- **`decision_ref` construction now normalizes before hashing.** The decision reference was computed over unnormalized input on one path, so two byte-different encodings of the same decision could produce different references.
- **`valid_until` is now bound in `CoreDecisionOutputV1`.** The field was carried but not covered by the signed material, so a validity window could be altered without invalidating the signature.

## 2.9.0 (2026-07-13)

### Fixed / Security
- **JCS canonicalization now rejects lone surrogates (RFC 8785).** `canonicalize` and `canonicalize_jcs` previously accepted strings carrying an unpaired UTF-16 surrogate and let it reach the canonical output, so input that is not valid Unicode could be signed and could diverge across implementations. It is now rejected before hashing with a stable error, matching the TS and Go SDKs.

### Behavior change
- Input that was previously accepted is now rejected. A value carrying a lone surrogate on a canonicalization or signing path raises instead of producing a signature. Callers that never emit unpaired surrogates see no change. This is why the minor version moves rather than the patch.

## 2.8.1 (2026-07-10)

### Fixed / Security (audit 2026-07-10)
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
