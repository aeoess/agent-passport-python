# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""word_handles codec (v2): encode, decode, min_unique_prefix_bits,
PROFILES, encode_profile, decode_profile.

Mirrors src/v2/word_handles/codec.ts in the TypeScript SDK, bit-exact.
Deterministic, pure functions: no I/O, no clock, no randomness.

Encoding rules (v2):
  - prefix_bits is a positive multiple of 11. checksum_words is 1 or
    2. Word count = prefix_bits/11 + checksum_words.
  - Bit order is MSB-first from byte 0. Data word i covers bits
    [11*i, 11*i + 11) as an integer index into WORDS.
  - packed_prefix = the first prefix_bits bits packed into
    ceil(prefix_bits/8) bytes, MSB-first, unused low-order bits of
    the final byte set to 0.
  - checksum_digest = sha256( BE16(prefix_bits) || packed_prefix ).
    BE16 is the two-byte big-endian unsigned encoding of prefix_bits.
    Checksum word j (j = 0..checksum_words-1) = bits [11*j, 11*j+11)
    of checksum_digest, appended after the data words in order.
  - The construction is position-dependent: the hash runs over the
    ordered packed bits, so transposing any two differing data words
    changes packed_prefix and fails the checksum with probability
    1 - 2^-11 per event for one checksum word (1 - 2^-22 for two).

Localization caveat: with one checksum word a wrong position is
coincidentally fixable with probability about 0.63, so 44-bit
localization is frequently ambiguous, while detection itself misses
only with probability 2^-11 (2^-22 with two checksum words).
"""

import hashlib
import math
import re
from typing import Dict, List, Optional, Sequence, Union

from .lexicon import WORDS

_WORD_BITS = 11
_HEX_RE = re.compile(r"[0-9a-fA-F]*")
_LOWER_HEX_RE = re.compile(r"[0-9a-f]+")

# Identifier of the lexicon layout profile used by this codec.
LEXICON_PROFILE = "single-list-v1"

# Built-in word handle profiles. Word count = data_words + checksum_words;
# prefix_bits = 11 * data_words.
#
#   compact:        4+1 (44 bits). Set-scoped display ONLY; render-time
#                   uniqueness plus lengthening is mandatory
#                   (min_unique_prefix_bits is the tool).
#   default:        6+1 (66 bits). Minimum for any cross-set reference.
#   high_assurance: 8+2 (88 bits). Archival and adversarial contexts.
PROFILES: Dict[str, Dict[str, object]] = {
    "compact": {
        "name": "compact",
        "data_words": 4,
        "checksum_words": 1,
        "prefix_bits": 44,
    },
    "default": {
        "name": "default",
        "data_words": 6,
        "checksum_words": 1,
        "prefix_bits": 66,
    },
    "high_assurance": {
        "name": "high_assurance",
        "data_words": 8,
        "checksum_words": 2,
        "prefix_bits": 88,
    },
}

# Lexicon word to index, built once. Exact code-point key equality
# (no trim, no unicode normalization).
_WORD_INDEX: Dict[str, int] = {w: i for i, w in enumerate(WORDS)}


def _coerce_int(value: object) -> object:
    """Coerce an integer-valued number to int; leave everything else unchanged.

    JavaScript has no int/float distinction, so the TypeScript codec treats 66
    and 66.0 identically. Python does distinguish, so accept an integer-valued
    float (66.0) as the integer it equals while a fractional value (66.5) falls
    through to the caller's validation and is rejected. bool is left as-is so the
    caller can reject it explicitly.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _validate_prefix_bits(prefix_bits: object) -> int:
    prefix_bits = _coerce_int(prefix_bits)
    if (
        isinstance(prefix_bits, bool)
        or not isinstance(prefix_bits, int)
        or prefix_bits <= 0
        or prefix_bits % _WORD_BITS != 0
    ):
        raise ValueError(
            f"prefix_bits must be a positive multiple of {_WORD_BITS}, got {prefix_bits}"
        )
    if prefix_bits > 0xFFFF:
        raise ValueError(
            f"prefix_bits must fit in 16 bits (BE16 header), got {prefix_bits}"
        )
    return prefix_bits


def _validate_checksum_words(checksum_words: object) -> int:
    checksum_words = _coerce_int(checksum_words)
    if isinstance(checksum_words, bool) or checksum_words not in (1, 2):
        raise ValueError(f"checksum_words must be 1 or 2, got {checksum_words}")
    return checksum_words


def _strip_sha256_prefix(hex_str: str) -> str:
    """Strip an optional leading "sha256:" from a hex string."""
    return hex_str[len("sha256:"):] if hex_str.startswith("sha256:") else hex_str


def _to_bytes(data: Union[bytes, bytearray, str]):
    """Normalize encode input to bytes plus the exact number of bits the
    caller supplied. Hex strings supply 4 bits per character; an
    odd-length hex string is padded with a zero nibble for byte packing
    but the padding does not count toward the supplied bits.
    """
    if isinstance(data, str):
        hex_str = _strip_sha256_prefix(data)
        if _HEX_RE.fullmatch(hex_str) is None:
            raise ValueError("input hex string contains non-hex characters")
        bit_length = len(hex_str) * 4
        padded = hex_str if len(hex_str) % 2 == 0 else hex_str + "0"
        return bytes.fromhex(padded), bit_length
    if isinstance(data, (bytes, bytearray)):
        return bytes(data), len(data) * 8
    raise ValueError("input must be bytes or a hex string")


def _pack_prefix(data: bytes, prefix_bits: int) -> bytes:
    """Pack the first prefix_bits bits of data into ceil(prefix_bits/8)
    bytes, MSB-first, unused low-order bits of the final byte set to 0.
    """
    byte_len = (prefix_bits + 7) // 8
    packed = bytearray(byte_len)
    packed[: min(byte_len, len(data))] = data[:byte_len]
    rem = prefix_bits % 8
    if rem != 0:
        packed[byte_len - 1] &= (0xFF << (8 - rem)) & 0xFF
    return bytes(packed)


def _checksum_indices_for(
    prefix_bits: int, packed_prefix: bytes, checksum_words: int
) -> List[int]:
    """Checksum word indices: bits [11*j, 11*j + 11) of
    sha256( BE16(prefix_bits) || packed_prefix ) for j = 0..checksum_words-1.
    """
    msg = prefix_bits.to_bytes(2, "big") + packed_prefix
    digest = hashlib.sha256(msg).digest()
    digest_int = int.from_bytes(digest, "big")
    digest_bits = len(digest) * 8
    out: List[int] = []
    for j in range(checksum_words):
        shift = digest_bits - _WORD_BITS * (j + 1)
        out.append((digest_int >> shift) & 0x7FF)
    return out


def encode(
    data: Union[bytes, bytearray, str],
    prefix_bits: int = 66,
    checksum_words: int = 1,
) -> List[str]:
    """Encode the first prefix_bits bits of the input as a
    word_digest_handle: prefix_bits/11 data words followed by
    checksum_words checksum words.

    The input is raw bytes or a hex string; a leading "sha256:" prefix
    on hex input is stripped. Raises ValueError when prefix_bits is not
    a positive multiple of 11, when the input supplies fewer than
    prefix_bits bits, or when checksum_words is not 1 or 2.
    """
    prefix_bits = _validate_prefix_bits(prefix_bits)
    checksum_words = _validate_checksum_words(checksum_words)
    raw, bit_length = _to_bytes(data)
    if bit_length < prefix_bits:
        raise ValueError(f"input supplies {bit_length} bits, need at least {prefix_bits}")
    total_bits = len(raw) * 8
    value = int.from_bytes(raw, "big")
    data_word_count = prefix_bits // _WORD_BITS
    words: List[str] = []
    for i in range(data_word_count):
        shift = total_bits - _WORD_BITS * (i + 1)
        idx = (value >> shift) & 0x7FF
        words.append(WORDS[idx])
    packed = _pack_prefix(raw, prefix_bits)
    for idx in _checksum_indices_for(prefix_bits, packed, checksum_words):
        words.append(WORDS[idx])
    return words


def encode_profile(data: Union[bytes, bytearray, str], profile: str) -> List[str]:
    """Encode with a named profile (prefix_bits and checksum_words from
    the PROFILES table)."""
    p = PROFILES.get(profile)
    if p is None:
        raise ValueError(f"unknown word handle profile: {profile}")
    return encode(data, p["prefix_bits"], p["checksum_words"])


def _pack_from_indices(indices: Sequence[int], prefix_bits: int) -> bytes:
    """Rebuild the packed prefix bytes from data word indices."""
    byte_len = (prefix_bits + 7) // 8
    value = 0
    for idx in indices:
        value = (value << _WORD_BITS) | idx
    value <<= byte_len * 8 - prefix_bits
    return value.to_bytes(byte_len, "big")


def decode(words: Sequence[str], checksum_words: int = 1) -> Dict[str, object]:
    """Decode a word_digest_handle. Never raises on unknown words
    (reported via "out_of_lexicon"); raises ValueError when
    checksum_words is not 1 or 2 or when the word count leaves no data
    words.

    Result keys: prefix_hex, prefix_bits, checksum_ok,
    failed_word_index, out_of_lexicon.

    Field semantics:
      - out_of_lexicon: 0-based indices of input words that are not
        exactly equal (code-point equality, no trim, no unicode
        normalization) to a lexicon word. When non-empty, no decoding
        is attempted: prefix_hex and prefix_bits are None, checksum_ok
        is False, and failed_word_index is None.
      - prefix_hex: lowercase hex of the packed prefix, exactly
        2*ceil(prefix_bits/8) characters. Trailing pad bits (bit
        positions >= prefix_bits) are zero. Consumers must compare
        BIT-scoped using prefix_bits, never by raw string beyond
        prefix_bits.
      - prefix_bits: 11 times the data word count (word count minus
        checksum_words). None when out_of_lexicon is non-empty.
      - checksum_ok: whether ALL given checksum words equal the
        recomputed checksum words for the recovered prefix.
      - failed_word_index: best-effort localization of a single bad
        word, populated only when checksum_ok is False and
        out_of_lexicon is empty. A data position is "fixable" if some
        other lexicon word at that position validates ALL checksum
        words. Exactly one fixable position: that index. No fixable
        position: if exactly one given checksum word differs from the
        recomputed one, that absolute index; otherwise None. More than
        one fixable position: None (ambiguous). With one checksum
        word, a wrong position is coincidentally fixable with
        probability about 0.63, so 44-bit localization is frequently
        ambiguous; detection itself misses only with probability 2^-11
        (2^-22 with two checksum words).
    """
    checksum_words = _validate_checksum_words(checksum_words)

    out_of_lexicon: List[int] = []
    for i, w in enumerate(words):
        if w not in _WORD_INDEX:
            out_of_lexicon.append(i)
    if out_of_lexicon:
        return {
            "prefix_hex": None,
            "prefix_bits": None,
            "checksum_ok": False,
            "failed_word_index": None,
            "out_of_lexicon": out_of_lexicon,
        }

    data_word_count = len(words) - checksum_words
    if data_word_count <= 0:
        raise ValueError(
            f"word count {len(words)} with {checksum_words} checksum word(s) "
            "leaves no data words"
        )
    prefix_bits = _WORD_BITS * data_word_count
    prefix_bits = _validate_prefix_bits(prefix_bits)

    indices = [_WORD_INDEX[w] for w in words[:data_word_count]]
    given_checksums = [_WORD_INDEX[w] for w in words[data_word_count:]]
    packed = _pack_from_indices(indices, prefix_bits)
    prefix_hex = packed.hex()

    expected_checksums = _checksum_indices_for(prefix_bits, packed, checksum_words)
    checksum_ok = expected_checksums == given_checksums

    failed_word_index: Optional[int] = None
    if not checksum_ok:
        fixable: List[int] = []
        trial = list(indices)
        for i in range(data_word_count):
            original = trial[i]
            for cand in range(len(WORDS)):
                if cand == original:
                    continue
                trial[i] = cand
                cand_packed = _pack_from_indices(trial, prefix_bits)
                cand_checksums = _checksum_indices_for(
                    prefix_bits, cand_packed, checksum_words
                )
                if cand_checksums == given_checksums:
                    fixable.append(i)
                    break
            trial[i] = original
        if len(fixable) == 1:
            failed_word_index = fixable[0]
        elif len(fixable) == 0:
            differing = [
                data_word_count + j
                for j in range(checksum_words)
                if given_checksums[j] != expected_checksums[j]
            ]
            failed_word_index = differing[0] if len(differing) == 1 else None
        else:
            failed_word_index = None

    return {
        "prefix_hex": prefix_hex,
        "prefix_bits": prefix_bits,
        "checksum_ok": checksum_ok,
        "failed_word_index": failed_word_index,
        "out_of_lexicon": out_of_lexicon,
    }


def decode_profile(words: Sequence[str], profile: str) -> Dict[str, object]:
    """Decode with a named profile. Raises ValueError when the word
    count does not match the profile shape (data_words + checksum_words)."""
    p = PROFILES.get(profile)
    if p is None:
        raise ValueError(f"unknown word handle profile: {profile}")
    expected = p["data_words"] + p["checksum_words"]
    if len(words) != expected:
        raise ValueError(f"profile {p['name']} expects {expected} words, got {len(words)}")
    return decode(words, p["checksum_words"])


def _bit_prefix_key(hex_str: str, bits: int) -> str:
    """First bits bits of a hex string as a canonical comparison key:
    ceil(bits/4) hex chars with unused low-order bits of the final
    nibble masked to zero. Raises ValueError when the hex string
    supplies fewer than bits bits.
    """
    if len(hex_str) * 4 < bits:
        raise ValueError(
            f"digest supplies {len(hex_str) * 4} bits, need at least {bits} "
            "to compare prefixes"
        )
    chars = (bits + 3) // 4
    prefix = hex_str[:chars]
    rem = bits % 4
    if rem == 0:
        return prefix
    masked = int(prefix[chars - 1], 16) & ((0xF << (4 - rem)) & 0xF)
    return prefix[: chars - 1] + format(masked, "x")


def min_unique_prefix_bits(digests_hex: Sequence[str], start_bits: int = 44) -> int:
    """Smallest multiple of 11 that is >= start_bits such that the
    leading prefixes of all digests are pairwise BIT-distinct at that
    length.

    Hex inputs may carry "sha256:" prefixes (stripped) and are compared
    case-insensitively. Raises ValueError on empty input or duplicate
    full digests (no prefix length can separate identical digests).
    """
    if len(digests_hex) == 0:
        raise ValueError("min_unique_prefix_bits requires at least one digest")
    normalized: List[str] = []
    for d in digests_hex:
        hex_str = _strip_sha256_prefix(d).lower()
        if len(hex_str) == 0 or _LOWER_HEX_RE.fullmatch(hex_str) is None:
            raise ValueError(f"digest is not a hex string: {d}")
        normalized.append(hex_str)
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate digests: no prefix length can separate them")
    bits = max(_WORD_BITS, math.ceil(start_bits / _WORD_BITS) * _WORD_BITS)
    while True:
        prefixes = {_bit_prefix_key(d, bits) for d in normalized}
        if len(prefixes) == len(normalized):
            return bits
        bits += _WORD_BITS
