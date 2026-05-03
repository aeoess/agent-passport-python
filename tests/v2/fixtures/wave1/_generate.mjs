// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generates byte-parity fixtures for cognitive_attestation and
// instruction_provenance against the published TS SDK
// (agent-passport-system 2.6.0-alpha.0). Re-run when the TS surface
// changes; pin the SDK version recorded in fixture metadata.

import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// SDK path resolves from APS_SDK_PATH env var (default: ../agent-passport-system
// relative to this Python repo). Mirrors the convention 5214ff6 introduced
// for the existing TS-import test scripts.
const APS_SDK_PATH = process.env.APS_SDK_PATH ?? '../agent-passport-system'
const SDK_INDEX = await import(`${APS_SDK_PATH}/dist/src/index.js`)
const {
  // cognitive-attestation
  buildAttestation,
  signCognitiveAttestation,
  cognitiveAttestationDigest,
  canonicalizeAttestation,
  // instruction-provenance
  createInstructionProvenanceReceipt,
  // util
  publicKeyFromPrivate,
} = SDK_INDEX

const __dirname = dirname(fileURLToPath(import.meta.url))

// 32-byte Ed25519 seed of 0x11 — same shape the accountability fixtures use,
// so all wave1 fixtures share a deterministic key.
const SEED32 = new Uint8Array(32).fill(0x11)
const PRIV_HEX = '11'.repeat(32)
const PUB_HEX = publicKeyFromPrivate(PRIV_HEX)

function writeFixture(relPath, value) {
  const abs = resolve(__dirname, relPath)
  mkdirSync(dirname(abs), { recursive: true })
  writeFileSync(abs, JSON.stringify(value, null, 2))
  console.log(`wrote ${relPath}`)
}

// ── Cognitive Attestation ────────────────────────────────────────────

const caBase = {
  model_id: 'meta-llama/Llama-3.1-8B-Instruct',
  model_version_hash: 'a'.repeat(64),
  tokenizer_version_hash: 'b'.repeat(64),
  inference_provider: 'openai',
  hardware_family: 'nvidia/hopper/h100-sxm5',
  precision: 'fp16',
  inference_engine: 'vllm@0.6.3',
  deterministic_mode: true,
  dictionary_id: 'aeoess/sae-llama-3.1-8b/v1',
  dictionary_version_hash: 'c'.repeat(64),
  training_corpus_hash: null,
  layer_index: 12,
  attachment_point: 'residual_stream',
  sae_type: 'topk',
  absolute_sequence_hash: 'd'.repeat(64),
  prior_state_hash: null,
  start_token_index: 0,
  end_token_index: 16,
  token_count: 16,
  feature_activations: [
    { feature_id: 7, feature_label: 'syntax-paren', activation_statistic: 'max', activation_value: 0.91, tokens_active: 4 },
    { feature_id: 3, feature_label: null, activation_statistic: 'mean', activation_value: 0.42, tokens_active: 9 },
  ],
  aggregation_policy: {
    top_k: 5, threshold: 0.05, attestation_epsilon: 0.001,
    feature_allowlist_hash: null, completeness_claim: 'top_k_only',
    tiebreaker_rule: 'lowest_feature_id', required_signer_roles: ['agent', 'provider'],
  },
  timestamp: '2026-05-02T12:00:00.000Z',
}

const caUnsigned = buildAttestation(caBase)
const caSigned = signCognitiveAttestation(caUnsigned, SEED32, PUB_HEX, 'agent')
const caBoth = signCognitiveAttestation(caSigned, SEED32, PUB_HEX, 'provider')
const caCanonical = new TextDecoder().decode(canonicalizeAttestation(caSigned))
const caDigest = cognitiveAttestationDigest(caBoth)

writeFixture('cognitive-attestation/single-signed.fixture.json', caSigned)
writeFixture('cognitive-attestation/two-signers.fixture.json', caBoth)
writeFixture('cognitive-attestation/canonical-bytes.fixture.json', {
  description: 'Canonical bytes for sign_attestation input (signatures elided, features sorted)',
  input: caBase,
  canonical_jcs: caCanonical,
})
writeFixture('cognitive-attestation/digest.fixture.json', {
  description: 'cognitive_attestation_digest of the two-signer envelope',
  envelope: caBoth,
  digest: caDigest,
})

// ── Instruction Provenance ───────────────────────────────────────────

const iprBase = {
  delegation_chain_root: 'e'.repeat(64),
  agent_did: 'did:aps:test-agent-001',
  discovery_patterns: ['**/CLAUDE.md', '**/AGENTS.md', '**/rules/*.md'],
  working_root: '/test/root',
  filesystem_mode: 'case-sensitive',
  instruction_files: [
    { path: 'CLAUDE.md', digest: 'f'.repeat(64), bytes: 1024, role: 'agent_md' },
    { path: 'AGENTS.md', digest: '0'.repeat(64), bytes: 256, role: 'agent_md' },
    { path: 'rules/safety.md', digest: '1'.repeat(64), bytes: 512, role: 'rules' },
  ],
  recompute_at_action: false,
  issued_at: '2026-05-02T00:00:00.000Z',
  bound_to: { type: 'session', ref: 'sess_2026_05_02_001' },
  privateKeyHex: PRIV_HEX,
  publicKeyHex: PUB_HEX,
}

const ipr1 = createInstructionProvenanceReceipt(iprBase)
writeFixture('instruction-provenance/basic.fixture.json', ipr1)

const ipr2 = createInstructionProvenanceReceipt({
  ...iprBase,
  recompute_at_action: true,
  expires_at: '2026-06-02T00:00:00.000Z',
  bound_to: { type: 'action', ref: '2'.repeat(64) },
})
writeFixture('instruction-provenance/recompute-and-action-bound.fixture.json', ipr2)

// case-insensitive mode lowercases the canonical path. Patterns must
// already be lowercase or use case-agnostic globs to match.
const ipr3 = createInstructionProvenanceReceipt({
  ...iprBase,
  filesystem_mode: 'case-insensitive',
  discovery_patterns: ['**/*.md'],
  instruction_files: [
    { path: 'Claude.MD', digest: '3'.repeat(64), bytes: 1024, role: 'agent_md' },
  ],
})
writeFixture('instruction-provenance/case-insensitive.fixture.json', ipr3)

// Metadata
writeFixture('META.json', {
  generator: 'tests/v2/fixtures/wave1/_generate.mjs',
  sdk_version: '2.6.0-alpha.0',
  generated_at: new Date().toISOString(),
  ed25519_seed_hex: PRIV_HEX,
  ed25519_pubkey_hex: PUB_HEX,
  note: 'Fixtures pin TS SDK output for cross-impl byte-parity. Regenerate when the TS surface or canonicalization changes.',
})
