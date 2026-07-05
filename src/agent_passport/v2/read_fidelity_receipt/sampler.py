# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""read_fidelity_receipt (v2): seed derivation, span sampler, scoring.

Mirrors src/v2/read_fidelity_receipt/sampler.ts in the TypeScript SDK.
Deterministic, pure functions: no I/O, no clock, no randomness.
Bit-exact across languages:
  seed = sha256hex(utf8( canonicalize_jcs({
           content_digest, presentation_digest (null when absent),
           nonce, version }) ))           (RFC 8785 JCS preimage)
  position i, attempt j:
    h = sha256(utf8(seed + ":" + i + ":" + j))
    pos = BE-uint64(first 8 bytes of h) mod range
    bump j on repeat until the position is unused
  span text = code points [pos, pos + span_len), list(str) slicing.
"""

import hashlib
from typing import List, Optional, Sequence

from ...canonical import canonicalize_jcs
from .types import SampledSpan, ScoreResponsesResult


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def derive_seed(
    content_digest: str,
    presentation_digest_or_null: Optional[str],
    nonce: str,
    version: str,
) -> str:
    """Derive the challenge seed. The preimage is the RFC 8785 JCS
    canonicalization of an object carrying the four bound fields, so the
    component boundaries are unambiguous: presentation_digest is a
    distinct JSON member (null when absent), never foldable into the
    nonce. An earlier concatenation preimage let a null-presentation
    record with nonce = P || N derive the same seed as a P-presentation
    record with nonce N; the structured preimage closes that.
    """
    return _sha256_hex(
        canonicalize_jcs(
            {
                "content_digest": content_digest,
                "presentation_digest": presentation_digest_or_null,
                "nonce": nonce,
                "version": version,
            }
        )
    )


def sample_spans(
    source_text: str,
    seed: str,
    n: int,
    span_len: int,
) -> List[SampledSpan]:
    """Sample n spans of span_len code points from source_text at
    distinct positions determined by seed (algorithm span_sample_v1).

    The source is split into code points via list(str), so astral
    characters (emoji) count as one position each and spans never
    split a surrogate pair. With L code points the position range is
    L - span_len + 1. Raises ValueError when span_len or n is not a
    positive integer, when the source is shorter than span_len code
    points, or when n exceeds the position range.
    """
    if not _is_positive_int(span_len):
        raise ValueError(f"span_len must be a positive integer, got {span_len}")
    if not _is_positive_int(n):
        raise ValueError(f"n must be a positive integer, got {n}")
    cps = list(source_text)
    length = len(cps)
    if length < span_len:
        raise ValueError(f"source has {length} code points, need at least span_len {span_len}")
    position_range = length - span_len + 1
    if n > position_range:
        raise ValueError(f"n {n} exceeds the position range {position_range}")
    used = set()
    spans: List[SampledSpan] = []
    for i in range(n):
        j = 0
        while True:
            h = hashlib.sha256(f"{seed}:{i}:{j}".encode("utf-8")).digest()
            pos = int.from_bytes(h[:8], "big") % position_range
            if pos in used:
                j += 1
                continue
            used.add(pos)
            spans.append(
                {
                    "pos": pos,
                    "len": span_len,
                    "text": "".join(cps[pos : pos + span_len]),
                }
            )
            break
    return spans


def commit_spans(span_texts: Sequence[str]) -> List[str]:
    """Commit to span texts: "sha256:" + sha256hex(UTF-8 of each span
    text), in the given (sampling) order."""
    return [f"sha256:{_sha256_hex(t)}" for t in span_texts]


def score_responses(
    span_texts: Sequence[str],
    responses: Sequence[str],
) -> ScoreResponsesResult:
    """Score responses against span texts under exact_match_v1: exact
    string equality per index. Raises ValueError when the sequences
    differ in length; a missing response is a protocol error, not a
    miss."""
    if len(span_texts) != len(responses):
        raise ValueError(
            f"responses length {len(responses)} does not match span count {len(span_texts)}"
        )
    results = [responses[i] == t for i, t in enumerate(span_texts)]
    return {"k": sum(1 for r in results if r), "results": results}
