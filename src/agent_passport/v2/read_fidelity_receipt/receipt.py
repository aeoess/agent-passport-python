# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""read_fidelity_receipt (v2): create and verify.

Mirrors src/v2/read_fidelity_receipt/receipt.ts in the TypeScript SDK.

Signature convention: sig is EXCLUDED from the signing preimage.
The preimage is canonicalize_jcs(record with the sig key removed
entirely). Verification order: shape checks and n consistency,
then the Ed25519 signature against the embedded attester, then the
seed derivation. A record tampered after signing fails on the
signature; a record re-signed after a nonce or presentation swap
carries a valid signature and fails on the seed derivation, which
is the replay binding doing its job.
"""

import hashlib
import re
from typing import Dict, List, Optional, Sequence

from ...canonical import canonicalize_jcs
from ...crypto import public_key_from_private, sign, verify as ed_verify

from .sampler import commit_spans, derive_seed, sample_spans, score_responses
from .types import (
    ReadFidelityReceipt,
    ReadFidelityVerifyReason,
    ReadFidelityVerifyResult,
    VerifyAgainstSourceResult,
    VerifyResponsesResult,
)

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_HEX128_RE = re.compile(r"[0-9a-f]{128}")
_ISO_8601_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})"
)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _matches(pattern: "re.Pattern[str]", value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def canonical_no_sig(record: dict) -> str:
    """Canonical signing preimage: RFC 8785 JCS of the record with the
    "sig" key removed entirely. Accepts a signed record (sig dropped)
    or an unsigned draft (no sig key present)."""
    rest = {k: v for k, v in record.items() if k != "sig"}
    return canonicalize_jcs(rest)


def _challenge_shape_reason(value: object) -> Optional[ReadFidelityVerifyReason]:
    if not isinstance(value, dict):
        return "INVALID_CHALLENGE"
    nonce = value.get("nonce")
    if not isinstance(nonce, str) or len(nonce) == 0:
        return "INVALID_CHALLENGE"
    if not _matches(_HEX64_RE, value.get("seed")):
        return "INVALID_CHALLENGE"
    if value.get("algorithm") != "span_sample_v1":
        return "INVALID_CHALLENGE"
    if value.get("version") != "1":
        return "INVALID_CHALLENGE"
    span_len = value.get("span_len")
    if not _is_int(span_len) or span_len < 1:
        return "INVALID_CHALLENGE"
    commitments = value.get("span_commitments")
    if not isinstance(commitments, list) or len(commitments) == 0:
        return "INVALID_CHALLENGE"
    for s in commitments:
        if not _matches(_DIGEST_RE, s):
            return "INVALID_CHALLENGE"
    return None


def _shape_reason(value: object) -> Optional[ReadFidelityVerifyReason]:
    """Structural checks shared by verify_read_fidelity_receipt and
    verify_against_source. Returns the first failing reason, or None
    when the value is structurally a ReadFidelityReceipt. Does NOT
    check the signature or the seed derivation."""
    if not isinstance(value, dict):
        return "INVALID_TYPE"
    r = value
    if r.get("type") != "read_fidelity_receipt":
        return "INVALID_TYPE"
    if not _matches(_DIGEST_RE, r.get("content_digest")):
        return "INVALID_CONTENT_DIGEST"
    presentation = r.get("presentation_digest")
    if presentation is not None and not _matches(_DIGEST_RE, presentation):
        return "INVALID_PRESENTATION_DIGEST"
    challenge_reason = _challenge_shape_reason(r.get("challenge"))
    if challenge_reason is not None:
        return challenge_reason
    commitments = r["challenge"]["span_commitments"]
    n = r.get("n")
    if not _is_int(n) or n < 1:
        return "INVALID_N"
    if n != len(commitments):
        return "N_MISMATCH"
    k = r.get("k")
    if not _is_int(k) or k < 0 or k > n:
        return "INVALID_K"
    if not _matches(_DIGEST_RE, r.get("response_digest")):
        return "INVALID_RESPONSE_DIGEST"
    if r.get("scoring_method") != "exact_match_v1":
        return "INVALID_SCORING_METHOD"
    if not _matches(_HEX64_RE, r.get("attester")):
        return "INVALID_ATTESTER"
    if not isinstance(r.get("model_claim"), str) or not isinstance(
        r.get("runtime_claim"), str
    ):
        return "INVALID_CLAIMS"
    if r.get("verification_method") not in ("asserted", "provider_attestation"):
        return "INVALID_VERIFICATION_METHOD"
    for field in ("challenge_issued_at", "response_observed_at", "receipt_issued_at"):
        if not _matches(_ISO_8601_RE, r.get(field)):
            return "INVALID_TIMESTAMP"
    if "lexicon_id" in r or "lexicon_profile" in r:
        if not _matches(_DIGEST_RE, r.get("lexicon_id")):
            return "INVALID_LEXICON_FIELDS"
        if "lexicon_profile" in r:
            profile = r.get("lexicon_profile")
            if not isinstance(profile, str) or len(profile) == 0:
                return "INVALID_LEXICON_FIELDS"
    if not _matches(_HEX128_RE, r.get("sig")):
        return "INVALID_SIG_FORMAT"
    return None


def _seed_matches(record: dict) -> bool:
    return record["challenge"]["seed"] == derive_seed(
        record["content_digest"],
        record["presentation_digest"],
        record["challenge"]["nonce"],
        record["challenge"]["version"],
    )


def create_read_fidelity_receipt(fields: dict, private_key_hex: str) -> ReadFidelityReceipt:
    """Build and sign a read fidelity receipt. Validates the input
    (n MUST equal len(challenge["span_commitments"]), challenge["seed"]
    MUST equal the seed derivation, every digest MUST be
    "sha256:<64 lowercase hex>", timestamps MUST be ISO 8601), sets
    "attester" from the private key, and signs the JCS canonical form
    of the record with the sig key excluded. Raises ValueError on any
    validation failure; nothing is signed unless the record is
    internally consistent.

    fields is the record minus the fields the library sets itself
    ("type" is the literal, "attester" is derived from the private
    key, "sig" is computed).
    """
    attester = public_key_from_private(private_key_hex)
    challenge = fields.get("challenge")
    if not isinstance(challenge, dict):
        raise ValueError("invalid read fidelity receipt input: INVALID_CHALLENGE")
    commitments = challenge.get("span_commitments")
    if not isinstance(commitments, list):
        raise ValueError("invalid read fidelity receipt input: INVALID_CHALLENGE")

    draft: Dict[str, object] = {
        "type": "read_fidelity_receipt",
        "content_digest": fields.get("content_digest"),
        "presentation_digest": fields.get("presentation_digest"),
        "challenge": {
            "nonce": challenge.get("nonce"),
            "seed": challenge.get("seed"),
            "algorithm": challenge.get("algorithm"),
            "version": challenge.get("version"),
            "span_len": challenge.get("span_len"),
            "span_commitments": list(commitments),
        },
        "response_digest": fields.get("response_digest"),
        "k": fields.get("k"),
        "n": fields.get("n"),
        "scoring_method": fields.get("scoring_method"),
        "attester": attester,
        "model_claim": fields.get("model_claim"),
        "runtime_claim": fields.get("runtime_claim"),
        "verification_method": fields.get("verification_method"),
        "challenge_issued_at": fields.get("challenge_issued_at"),
        "response_observed_at": fields.get("response_observed_at"),
        "receipt_issued_at": fields.get("receipt_issued_at"),
    }
    if fields.get("lexicon_id") is not None:
        draft["lexicon_id"] = fields["lexicon_id"]
    if fields.get("lexicon_profile") is not None:
        draft["lexicon_profile"] = fields["lexicon_profile"]

    if fields.get("n") != len(commitments):
        raise ValueError(
            f"n ({fields.get('n')}) must equal challenge.span_commitments.length "
            f"({len(commitments)})"
        )
    # Full structural validation on the draft plus a placeholder sig so
    # create and verify enforce the identical shape rules.
    reason = _shape_reason({**draft, "sig": "0" * 128})
    if reason is not None:
        raise ValueError(f"invalid read fidelity receipt input: {reason}")
    expected_seed = derive_seed(
        fields["content_digest"],
        fields["presentation_digest"],
        challenge["nonce"],
        challenge["version"],
    )
    if challenge["seed"] != expected_seed:
        raise ValueError(
            "challenge.seed does not match the seed derivation over "
            "content_digest, presentation_digest, nonce, and version"
        )

    sig = sign(canonical_no_sig(draft), private_key_hex)
    return {**draft, "sig": sig}  # type: ignore[return-value]


def verify_read_fidelity_receipt(record: object) -> ReadFidelityVerifyResult:
    """Verify a read fidelity receipt: shape checks, n consistency
    against challenge["span_commitments"], Ed25519 signature against
    the embedded attester, and the seed derivation recompute. Accepts
    any value and never raises on malformed input; failures carry a
    reason code."""
    reason = _shape_reason(record)
    if reason is not None:
        return {"valid": False, "reason": reason}
    r = record  # structurally a ReadFidelityReceipt dict now
    if not ed_verify(canonical_no_sig(r), r["sig"], r["attester"]):
        return {"valid": False, "reason": "SIGNATURE_INVALID"}
    if not _seed_matches(r):
        return {"valid": False, "reason": "SEED_MISMATCH"}
    return {"valid": True}


def verify_against_source(record: object, source_text: str) -> VerifyAgainstSourceResult:
    """Verify a receipt against the source text it claims to sample:
    everything verify_read_fidelity_receipt checks, plus a recompute of
    the spans from challenge seed / n / span_len over source_text, a
    sha256 commitment of each recomputed span, and a positionwise
    comparison against challenge["span_commitments"]. ALL commitments
    must match. signature_valid and seed_valid are reported
    independently."""
    reason = _shape_reason(record)
    if reason is not None:
        return {
            "valid": False,
            "reason": reason,
            "commitment_matches": [],
            "signature_valid": False,
            "seed_valid": False,
        }
    r = record
    signature_valid = ed_verify(canonical_no_sig(r), r["sig"], r["attester"])
    seed_valid = _seed_matches(r)

    commitment_matches: List[bool] = []
    span_reason: Optional[ReadFidelityVerifyReason] = None
    try:
        spans = sample_spans(
            source_text,
            r["challenge"]["seed"],
            r["n"],
            r["challenge"]["span_len"],
        )
        recomputed = commit_spans([s["text"] for s in spans])
        commitment_matches = [
            c == r["challenge"]["span_commitments"][i] for i, c in enumerate(recomputed)
        ]
    except ValueError:
        span_reason = "SPAN_RECOMPUTE_FAILED"

    all_match = span_reason is None and all(m is True for m in commitment_matches)
    valid = signature_valid and seed_valid and all_match
    if valid:
        return {
            "valid": True,
            "commitment_matches": commitment_matches,
            "signature_valid": signature_valid,
            "seed_valid": seed_valid,
        }
    failure: ReadFidelityVerifyReason
    if not signature_valid:
        failure = "SIGNATURE_INVALID"
    elif not seed_valid:
        failure = "SEED_MISMATCH"
    elif span_reason is not None:
        failure = span_reason
    else:
        failure = "COMMITMENT_MISMATCH"
    return {
        "valid": False,
        "reason": failure,
        "commitment_matches": commitment_matches,
        "signature_valid": signature_valid,
        "seed_valid": seed_valid,
    }


def verify_responses(
    record: dict,
    source_text: str,
    responses: Sequence[str],
) -> VerifyResponsesResult:
    """Recompute k for a set of readback responses against the source
    text: resample the spans the record commits to, score responses
    under exact_match_v1, and compare the recomputed k with the
    recorded k and the responses JCS digest with the recorded
    response_digest. Raises ValueError when the source cannot produce
    the spans (wrong length) or when responses has the wrong length;
    use verify_against_source first to establish that the record
    matches the source at all."""
    spans = sample_spans(
        source_text,
        record["challenge"]["seed"],
        record["n"],
        record["challenge"]["span_len"],
    )
    scored = score_responses([s["text"] for s in spans], responses)
    digest = f"sha256:{_sha256_hex(canonicalize_jcs(list(responses)))}"
    return {
        "k_recomputed": scored["k"],
        "matches_claimed_k": scored["k"] == record["k"],
        "response_digest_ok": digest == record["response_digest"],
    }
