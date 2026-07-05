# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""word_handles (word_digest_handle codec, v2): public surface.

Mirrors src/v2/word_handles/index.ts in the TypeScript SDK. Renders the
leading bits of a digest as words from the versioned aps-handle-en-v1
lexicon (2048 words, 11 bits per word) plus one or two
position-dependent checksum words. Pure functions: no I/O, no clock,
no randomness.

A word_digest_handle MUST be resolved against a full digest or a
collision-checked set and MUST NOT serve as a sole record identifier,
a secret, or wallet material.
"""

from .codec import (
    LEXICON_PROFILE,
    PROFILES,
    decode,
    decode_profile,
    encode,
    encode_profile,
    min_unique_prefix_bits,
)

from .lexicon import (
    LEXICON_ID,
    LEXICON_NAME,
    WORDS,
    canonical_wordlist_text,
)

__all__ = [
    # codec
    "LEXICON_PROFILE",
    "PROFILES",
    "decode",
    "decode_profile",
    "encode",
    "encode_profile",
    "min_unique_prefix_bits",
    # lexicon
    "LEXICON_ID",
    "LEXICON_NAME",
    "WORDS",
    "canonical_wordlist_text",
]
