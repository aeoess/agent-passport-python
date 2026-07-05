# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""word_handles codec (v2): tests.

Mirrors src/v2/word_handles/__tests__/word_handles.test.ts at reduced
trial counts, plus a replay of every word handle value in the shared
parity vectors file (byte-identical copy of the TS-generated
read-fidelity-receipt-v0.1-vectors.json).

Deterministic throughout: every derived digest, substituted position,
replacement word, and transposition site comes from sha256 over a
fixed label plus a counter. No wall clock, no randomness.
"""

import hashlib
import json
from pathlib import Path

import pytest

from agent_passport.v2.word_handles import (
    LEXICON_ID,
    LEXICON_NAME,
    LEXICON_PROFILE,
    PROFILES,
    WORDS,
    canonical_wordlist_text,
    decode,
    decode_profile,
    encode,
    encode_profile,
    min_unique_prefix_bits,
)

FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "read-fidelity-receipt"
    / "read-fidelity-receipt-v0.1-vectors.json"
)
VECTORS = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

WORD_TO_INDEX = {w: i for i, w in enumerate(WORDS)}
PROFILE_NAMES = ("compact", "default", "high_assurance")


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def seed_uint32(label: str) -> int:
    """First 4 bytes of sha256(label) as a big-endian uint32 seed."""
    return int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest()[:4], "big")


def expected_prefix_hex(digest_hex: str, prefix_bits: int) -> str:
    """Expected prefix_hex: first ceil(prefix_bits/8) bytes, pad bits zeroed."""
    byte_len = (prefix_bits + 7) // 8
    raw = bytearray(bytes.fromhex(digest_hex[: byte_len * 2]))
    rem = prefix_bits % 8
    if rem != 0:
        raw[byte_len - 1] &= (0xFF << (8 - rem)) & 0xFF
    return bytes(raw).hex()


class TestLexiconIntegrity:
    def test_has_exactly_2048_words(self):
        assert len(WORDS) == 2048

    def test_strictly_sorted_ascending_implies_unique(self):
        for i in range(1, len(WORDS)):
            assert WORDS[i - 1] < WORDS[i], f"not strictly sorted at index {i}"

    def test_unique_4_character_prefixes(self):
        assert len({w[:4] for w in WORDS}) == len(WORDS)

    def test_canonical_wordlist_text_hashes_to_lexicon_id(self):
        assert LEXICON_NAME == "aps-handle-en-v1"
        assert f"sha256:{sha256_hex(canonical_wordlist_text())}" == LEXICON_ID


class TestProfiles:
    def test_profile_table_and_lexicon_profile_id(self):
        assert LEXICON_PROFILE == "single-list-v1"
        assert PROFILES["compact"] == {
            "name": "compact",
            "data_words": 4,
            "checksum_words": 1,
            "prefix_bits": 44,
        }
        assert PROFILES["default"] == {
            "name": "default",
            "data_words": 6,
            "checksum_words": 1,
            "prefix_bits": 66,
        }
        assert PROFILES["high_assurance"] == {
            "name": "high_assurance",
            "data_words": 8,
            "checksum_words": 2,
            "prefix_bits": 88,
        }

    def test_fixture_pins_lexicon_identifiers(self):
        assert (
            VECTORS["lexicon_id"]
            == "sha256:2a9c4de3b5457154e6bde9d40af0da552c2556d8e80a2dec8b82dee4bca74510"
        )
        assert VECTORS["lexicon_id"] == LEXICON_ID
        assert VECTORS["lexicon_profile"] == LEXICON_PROFILE


class TestFixtureWordHandleCases:
    def test_replays_all_round_trips(self):
        round_trips = VECTORS["word_handle_cases"]["round_trips"]
        assert len(round_trips) == 12
        for case in round_trips:
            assert encode_profile(case["digest"], case["profile"]) == case["words"]
            res = decode_profile(case["words"], case["profile"])
            assert res["checksum_ok"] is True
            assert res["prefix_hex"] == case["prefix_hex"]
            assert res["prefix_bits"] == case["prefix_bits"]

    def test_replays_substitution_negative(self):
        case = VECTORS["word_handle_cases"]["substitution_negative"]
        res = decode_profile(case["words"], case["profile"])
        assert res["checksum_ok"] == case["checksum_ok"]
        assert res["checksum_ok"] is False
        base = encode_profile(case["digest"], case["profile"])
        idx = case["substituted_index"]
        assert case["words"][idx] != base[idx]

    def test_replays_transposition_negative(self):
        case = VECTORS["word_handle_cases"]["transposition_negative"]
        res = decode_profile(case["words"], case["profile"])
        assert res["checksum_ok"] == case["checksum_ok"]
        assert res["checksum_ok"] is False
        base = encode_profile(case["digest"], case["profile"])
        i, j = case["swapped_indices"]
        assert case["words"][i] == base[j]
        assert case["words"][j] == base[i]

    def test_replays_out_of_lexicon_negative(self):
        case = VECTORS["word_handle_cases"]["out_of_lexicon_negative"]
        res = decode_profile(case["words"], case["profile"])
        assert res["out_of_lexicon"] == case["out_of_lexicon"]
        assert res["checksum_ok"] is False
        assert res["prefix_hex"] is None
        assert res["prefix_bits"] is None
        assert res["failed_word_index"] is None


class TestRoundTrip:
    def test_round_trips_100_derived_digests_per_profile(self):
        for t in range(100):
            digest = sha256_hex(f"wh-roundtrip:{t}")
            for name in PROFILE_NAMES:
                p = PROFILES[name]
                words = encode_profile(digest, name)
                assert len(words) == p["data_words"] + p["checksum_words"]
                res = decode_profile(words, name)
                assert res["checksum_ok"] is True
                assert res["prefix_bits"] == p["prefix_bits"]
                assert res["prefix_hex"] == expected_prefix_hex(digest, p["prefix_bits"])
                assert res["failed_word_index"] is None
                assert res["out_of_lexicon"] == []

    def test_accepts_sha256_prefix_and_raw_bytes_as_equivalent(self):
        digest = sha256_hex("wh-input-forms:0")
        from_hex = encode(digest)
        assert encode(f"sha256:{digest}") == from_hex
        assert encode(bytes.fromhex(digest)) == from_hex


class TestSubstitutionDetection:
    def test_detects_at_least_297_of_300_single_data_word_substitutions(self):
        data_words = PROFILES["default"]["data_words"]
        detected = 0
        for t in range(300):
            digest = sha256_hex(f"wh-substitute:{t}")
            words = encode(digest)
            pos = seed_uint32(f"wh-substitute-pos:{t}") % data_words
            orig_idx = WORD_TO_INDEX[words[pos]]
            delta = 1 + (seed_uint32(f"wh-substitute-word:{t}") % (len(WORDS) - 1))
            mutated = list(words)
            mutated[pos] = WORDS[(orig_idx + delta) % len(WORDS)]
            res = decode(mutated)
            if not res["checksum_ok"]:
                detected += 1
            if res["failed_word_index"] is not None:
                assert res["failed_word_index"] == pos, (
                    f"trial {t}: localized {res['failed_word_index']}, substituted {pos}"
                )
        assert detected >= 297, f"detected {detected} of 300, expected >= 297"


class TestTranspositionDetection:
    def test_detects_at_least_147_of_150_adjacent_differing_swaps(self):
        data_words = PROFILES["default"]["data_words"]
        detected = 0
        for t in range(150):
            digest = sha256_hex(f"wh-transpose:{t}")
            words = encode(digest)
            start = seed_uint32(f"wh-transpose-pos:{t}") % (data_words - 1)
            pair = -1
            for k in range(data_words - 1):
                i = (start + k) % (data_words - 1)
                if words[i] != words[i + 1]:
                    pair = i
                    break
            assert pair >= 0, f"trial {t}: no adjacent differing data words"
            mutated = list(words)
            mutated[pair], mutated[pair + 1] = mutated[pair + 1], mutated[pair]
            res = decode(mutated)
            if not res["checksum_ok"]:
                detected += 1
        assert detected >= 147, f"detected {detected} of 150, expected >= 147"


class TestHighAssuranceProfile:
    def test_round_trips_with_two_checksum_words(self):
        digest = sha256_hex("wh-high-assurance:0")
        words = encode_profile(digest, "high_assurance")
        assert len(words) == 10
        res = decode(words, 2)
        assert res["checksum_ok"] is True
        assert res["prefix_bits"] == 88
        assert res["prefix_hex"] == expected_prefix_hex(digest, 88)

    def test_detects_and_localizes_substitutions(self):
        data_words = PROFILES["high_assurance"]["data_words"]
        localized = 0
        for t in range(20):
            digest = sha256_hex(f"wh-ha-substitute:{t}")
            words = encode_profile(digest, "high_assurance")
            pos = seed_uint32(f"wh-ha-substitute-pos:{t}") % data_words
            orig_idx = WORD_TO_INDEX[words[pos]]
            delta = 1 + (seed_uint32(f"wh-ha-substitute-word:{t}") % (len(WORDS) - 1))
            mutated = list(words)
            mutated[pos] = WORDS[(orig_idx + delta) % len(WORDS)]
            res = decode_profile(mutated, "high_assurance")
            assert res["checksum_ok"] is False, f"trial {t}: substitution not detected"
            if res["failed_word_index"] is not None:
                assert res["failed_word_index"] == pos
                localized += 1
        # With two checksum words a wrong position is coincidentally
        # fixable with probability about 2047 * 2^-22, so localization
        # is almost always unique.
        assert localized >= 17, f"localized {localized} of 20, expected >= 17"


class TestOutOfLexicon:
    def test_reports_indices_and_suppresses_decoding(self):
        digest = sha256_hex("wh-out-of-lexicon:0")
        words = encode(digest)
        mutated = list(words)
        mutated[2] = "notaword"
        mutated[4] = "Abacus"  # case-sensitive: "abacus" is in the lexicon, this is not
        res = decode(mutated)
        assert res["out_of_lexicon"] == [2, 4]
        assert res["prefix_hex"] is None
        assert res["prefix_bits"] is None
        assert res["checksum_ok"] is False
        assert res["failed_word_index"] is None

    def test_does_not_trim_whitespace_exact_equality(self):
        digest = sha256_hex("wh-out-of-lexicon:1")
        words = encode(digest)
        mutated = list(words)
        mutated[0] = f"{mutated[0]} "
        res = decode(mutated)
        assert res["out_of_lexicon"] == [0]
        assert res["checksum_ok"] is False


class TestPrefixHexPadding:
    def test_66_bit_decode_returns_18_hex_chars_pad_bits_zero(self):
        all_ones = "ff" * 32
        res = decode(encode(all_ones, 66, 1))
        assert res["prefix_bits"] == 66
        assert len(res["prefix_hex"]) == 18
        # 66 data bits into 9 bytes: the final byte keeps its top 2 bits
        # and pads the low 6 with zeros, so an all-ones input ends in c0.
        assert res["prefix_hex"] == "ffffffffffffffffc0"

    def test_44_and_88_bit_cases_pad_to_byte_boundary(self):
        all_ones = "ff" * 32
        compact = decode(encode(all_ones, 44, 1))
        assert compact["prefix_bits"] == 44
        assert compact["prefix_hex"] == "fffffffffff0"
        high = decode(encode(all_ones, 88, 2), 2)
        assert high["prefix_bits"] == 88
        assert high["prefix_hex"] == "ff" * 11


class TestMinUniquePrefixBits:
    def test_returns_44_when_44_bit_prefixes_already_distinct(self):
        digests = [sha256_hex(f"wh-unique:{i}") for i in range(4)]
        assert min_unique_prefix_bits(digests) == 44

    def test_moves_to_next_multiple_of_11_that_separates(self):
        # Shared first 48 bits (12 hex chars), differing at bit 48:
        # 44-bit prefixes collide, 55-bit prefixes differ.
        shared = "0123456789ab"
        digests = [f"{shared}0{'0' * 19}", f"{shared}f{'0' * 19}"]
        assert min_unique_prefix_bits(digests) == 55
        # Shared first 56 bits (14 hex chars), differing at bit 56:
        # 55-bit prefixes collide too, 66-bit prefixes differ.
        shared56 = "0123456789abcd"
        digests56 = [f"{shared56}0{'0' * 17}", f"{shared56}f{'0' * 17}"]
        assert min_unique_prefix_bits(digests56) == 66

    def test_rounds_start_bits_up_to_multiple_of_11(self):
        digests = [sha256_hex(f"wh-startbits:{i}") for i in range(2)]
        assert min_unique_prefix_bits(digests, 50) == 55

    def test_strips_sha256_prefix_and_single_digest_returns_44(self):
        digest = sha256_hex("wh-single:0")
        assert min_unique_prefix_bits([f"sha256:{digest}"]) == 44

    def test_raises_on_duplicates_and_empty_input(self):
        digest = sha256_hex("wh-duplicate:0")
        with pytest.raises(ValueError, match="duplicate digests"):
            min_unique_prefix_bits([f"sha256:{digest}", digest])
        with pytest.raises(ValueError, match="at least one digest"):
            min_unique_prefix_bits([])


class TestValidationErrors:
    DIGEST = sha256_hex("wh-validate:0")

    def test_rejects_prefix_bits_not_positive_multiple_of_11(self):
        with pytest.raises(ValueError, match="positive multiple of 11"):
            encode(self.DIGEST, 12)
        with pytest.raises(ValueError, match="positive multiple of 11"):
            encode(self.DIGEST, 0)
        with pytest.raises(ValueError, match="positive multiple of 11"):
            encode(self.DIGEST, -11)

    def test_rejects_input_shorter_than_prefix_bits(self):
        with pytest.raises(ValueError, match="supplies 16 bits"):
            encode("abcd", 66)
        with pytest.raises(ValueError, match="supplies 64 bits"):
            encode(bytes(8), 88, 2)

    def test_rejects_checksum_words_outside_1_and_2(self):
        with pytest.raises(ValueError, match="checksum_words must be 1 or 2"):
            encode(self.DIGEST, 66, 0)
        with pytest.raises(ValueError, match="checksum_words must be 1 or 2"):
            encode(self.DIGEST, 66, 3)
        with pytest.raises(ValueError, match="checksum_words must be 1 or 2"):
            decode(encode(self.DIGEST), 3)

    def test_rejects_non_hex_string_input(self):
        with pytest.raises(ValueError, match="non-hex characters"):
            encode("xyz")

    def test_rejects_word_counts_that_leave_no_data_words(self):
        with pytest.raises(ValueError, match="leaves no data words"):
            decode([WORDS[0]], 1)
        with pytest.raises(ValueError, match="leaves no data words"):
            decode([WORDS[0], WORDS[1]], 2)

    def test_rejects_profile_word_count_mismatches(self):
        words = encode_profile(self.DIGEST, "default")
        with pytest.raises(ValueError, match="expects 7 words, got 5"):
            decode_profile(words[:5], "default")

    def test_rejects_unknown_profile(self):
        with pytest.raises(ValueError, match="unknown word handle profile"):
            encode_profile(self.DIGEST, "gigantic")
        with pytest.raises(ValueError, match="unknown word handle profile"):
            decode_profile(encode(self.DIGEST), "gigantic")


class TestIntegerValuedFloatArgs:
    """Cross-language input-strictness parity (adversarial finding, 2026-07-04).

    JavaScript has no int/float distinction, so the TS codec treats 66 and 66.0
    identically. Python coerces an integer-valued float to int so the two SDKs
    agree, and rejects a fractional value cleanly (ValueError, not a deep
    TypeError) instead of diverging.
    """

    DIGEST = "aabbccddee11223344556677"

    def test_integer_valued_float_prefix_bits_matches_int(self):
        assert encode(self.DIGEST, 66.0, 1) == encode(self.DIGEST, 66, 1)

    def test_integer_valued_float_checksum_words_matches_int(self):
        assert encode(self.DIGEST, 66, 1.0) == encode(self.DIGEST, 66, 1)

    def test_fractional_prefix_bits_rejected_cleanly(self):
        with pytest.raises(ValueError):
            encode(self.DIGEST, 66.5, 1)

    def test_fractional_checksum_words_rejected_cleanly(self):
        with pytest.raises(ValueError):
            encode(self.DIGEST, 66, 1.5)

    def test_bool_prefix_bits_rejected(self):
        with pytest.raises(ValueError):
            encode(self.DIGEST, True, 1)
