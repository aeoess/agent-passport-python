// Build an AttributionPrimitive in TypeScript and print JSON for Python to verify.
// Called from tests/test_attribution_primitive.py::test_cross_language_ts_to_python.

import {
  constructAttributionPrimitive,
  generateKeyPair,
} from '../../agent-passport-system/src/index.js'

const { publicKey, privateKey } = generateKeyPair()

const primitive = constructAttributionPrimitive({
  action: {
    agentId: 'did:aps:cross-lang-agent',
    actionType: 'query.summarize',
    params: { q: 'hello', region: 'us-west' },
    nonce: 'fixed-nonce-for-determinism',
  },
  axes: {
    D: [
      { source_did: 'did:data:kff-2025', contribution_weight: '0.583000', access_receipt_hash: 'a'.repeat(64) },
      { source_did: 'did:data:cms-archive-2025', contribution_weight: '0.417000', access_receipt_hash: 'b'.repeat(64) },
    ],
    P: [
      { module_id: 'redact-pii-v2.3', module_version: '2.3.1', evaluation_outcome: 'approved', evaluation_receipt_hash: 'c'.repeat(64) },
      { module_id: 'cite-verify-v1.7', module_version: '1.7.4', evaluation_outcome: 'approved', evaluation_receipt_hash: 'd'.repeat(64) },
    ],
    G: [
      { delegation_id: 'root', signer_did: 'did:aps:r', scope_hash: 'e'.repeat(64), depth: 0 },
      { delegation_id: 'agent', signer_did: 'did:aps:a', scope_hash: 'f'.repeat(64), depth: 1 },
    ],
    C: [
      { provider_did: 'did:compute:x', compute_share: '0.500000', hardware_attestation_hash: '1'.repeat(64) },
      { provider_did: 'did:compute:y', compute_share: '0.500000', hardware_attestation_hash: '2'.repeat(64) },
    ],
  },
  issuer: 'did:aps:cross-lang-issuer',
  issuerPrivateKey: privateKey,
})

process.stdout.write(JSON.stringify({ primitive, publicKey }))
