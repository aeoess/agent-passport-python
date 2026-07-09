# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""A read fidelity receipt proves sampled readback fidelity at the stated n under the declared sampling
assumptions. It does not prove every byte was read correctly, does not prove perception or comprehension,
does not prove which channel was used, and carries no normative pass threshold: the consumer judges k of n.

read_fidelity_receipt (v2): types. Mirrors
src/v2/read_fidelity_receipt/types.ts in the TypeScript SDK.

A signed record of a sampled readback challenge: a verifier supplies
a nonce, the seed binds that nonce to the exact content digest and
presentation digest, spans are sampled deterministically from the
seed, and the record commits to the span hashes and the scored
readback result (k of n). The raw span texts and responses are NOT
in the record; only their commitments and digests are.

Signature convention: "sig" is EXCLUDED from the signing preimage.
The preimage is canonicalize_jcs(record with the sig key removed
entirely), NOT a record with sig set to an empty string.

Records are plain dicts in this SDK (they arrive from and return to
JSON). The TypedDict classes below document the exact shapes.
"""

from typing import List, Literal, Optional, TypedDict

# Literal tag for record discrimination at the wire level.
ReadFidelityReceiptType = Literal["read_fidelity_receipt"]

# The v1 sampling algorithm identifier.
ReadFidelitySamplingAlgorithm = Literal["span_sample_v1"]

# The v1 scoring method identifier: exact string equality per span.
ReadFidelityScoringMethod = Literal["exact_match_v1"]

# How the executor claims were checked. "asserted" means the attester
# simply asserts model_claim and runtime_claim; "provider_attestation"
# means a provider-level attestation backs them.
ReadFidelityVerificationMethod = Literal["asserted", "provider_attestation"]

# Failure reasons for verify_read_fidelity_receipt and
# verify_against_source. Check order in verify_read_fidelity_receipt:
# shape (INVALID_* and N_MISMATCH), then SIGNATURE_INVALID, then
# SEED_MISMATCH. A record tampered after signing therefore fails on
# the signature; a record re-signed after a nonce or presentation swap
# carries a valid signature and fails on the seed derivation instead.
ReadFidelityVerifyReason = Literal[
    "INVALID_TYPE",
    "INVALID_CONTENT_DIGEST",
    "INVALID_PRESENTATION_DIGEST",
    "INVALID_CHALLENGE",
    "INVALID_N",
    "N_MISMATCH",
    "INVALID_K",
    "INVALID_RESPONSE_DIGEST",
    "INVALID_SCORING_METHOD",
    "INVALID_ATTESTER",
    "INVALID_CLAIMS",
    "INVALID_VERIFICATION_METHOD",
    "INVALID_TIMESTAMP",
    "INVALID_LEXICON_FIELDS",
    "INVALID_SIG_FORMAT",
    "SIGNATURE_INVALID",
    "SEED_MISMATCH",
    "SPAN_RECOMPUTE_FAILED",
    "COMMITMENT_MISMATCH",
]


class ReadFidelityChallenge(TypedDict):
    """The challenge block. The nonce is verifier-supplied and never
    derivable from the document alone. The seed MUST equal
      sha256hex(utf8( canonicalize_jcs({
        content_digest, presentation_digest, nonce, version }) ))
    the RFC 8785 JCS preimage of those four fields (presentation_digest
    null when absent); verifiers recompute and reject on mismatch, which
    is the replay binding: reusing commitments under a different nonce,
    content, or presentation breaks the derivation.

    span_len is the span length in code points; required to recompute
    spans. span_commitments carries the sha256 of the UTF-8 bytes of
    each span text, in sampling order, each as
    "sha256:<64 lowercase hex>". Raw span texts are NOT in the record.
    """

    nonce: str
    seed: str
    algorithm: ReadFidelitySamplingAlgorithm
    version: Literal["1"]
    span_len: int
    span_commitments: List[str]


class _ReadFidelityReceiptRequired(TypedDict):
    type: ReadFidelityReceiptType
    content_digest: str
    presentation_digest: Optional[str]
    challenge: ReadFidelityChallenge
    response_digest: str
    k: int
    n: int
    scoring_method: ReadFidelityScoringMethod
    attester: str
    model_claim: str
    runtime_claim: str
    verification_method: ReadFidelityVerificationMethod
    challenge_issued_at: str
    response_observed_at: str
    receipt_issued_at: str
    sig: str


class ReadFidelityReceipt(_ReadFidelityReceiptRequired, total=False):
    """The signed record. See the module docstring for what it proves
    and what it does not prove.

    Field notes:
      - content_digest: digest of the canonical content bytes,
        "sha256:<64 lowercase hex>".
      - presentation_digest: digest of the rendered presentation as
        served, or None.
      - response_digest: "sha256:" + sha256hex(canonicalize_jcs(
        responses)) where responses is the ordered array of readback
        strings.
      - k: count of responses that exactly matched their span text.
      - n: sample count; MUST equal len(challenge["span_commitments"]).
      - attester: Ed25519 public key hex of the SIGNING identity. May
        differ from the executing model; model_claim and runtime_claim
        are claims about the executor, not proofs.
      - challenge_issued_at / response_observed_at / receipt_issued_at:
        ISO 8601, caller-provided; the library never reads a wall
        clock.
      - lexicon_id, lexicon_profile: optional; present when
        word_digest_handles appear in the flow ("single-list-v1" is
        the lexicon_profile value).
      - sig: 128 hex chars, Ed25519 over canonicalize_jcs(record with
        sig excluded).
    """

    lexicon_id: str
    lexicon_profile: str


class SampledSpan(TypedDict):
    """One sampled span: code-point position, length, and text."""

    pos: int
    len: int
    text: str


class ScoreResponsesResult(TypedDict):
    """Result of score_responses: per-span exact-match flags and their
    count."""

    k: int
    results: List[bool]


class ReadFidelityVerifyResult(TypedDict, total=False):
    """Result of verify_read_fidelity_receipt. "reason" is present only
    when valid is False."""

    valid: bool
    reason: ReadFidelityVerifyReason


class VerifyAgainstSourceResult(TypedDict, total=False):
    """Result of verify_against_source. commitment_matches[i] compares
    the recomputed commitment of span i against
    challenge["span_commitments"][i]; ALL must match for validity.
    signature_valid and seed_valid are reported independently so a
    caller can see which binding broke. "reason" is present only when
    valid is False.
    """

    valid: bool
    reason: ReadFidelityVerifyReason
    commitment_matches: List[bool]
    signature_valid: bool
    seed_valid: bool


class VerifyResponsesResult(TypedDict):
    """Result of verify_responses: the recomputed k over the supplied
    responses, whether it equals the recorded k, and whether the
    responses JCS-hash to the recorded response_digest."""

    k_recomputed: int
    matches_claimed_k: bool
    response_digest_ok: bool
