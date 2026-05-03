# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""IPR — path canonicalization + sort + context_root."""

import pytest

from agent_passport.v2.instruction_provenance import (
    InstructionFile,
    IPRPathError,
    canonicalize_path,
    compute_context_root,
    sort_instruction_files,
)


def test_canonical_relative_path_stripped_of_root():
    out = canonicalize_path("/wr/CLAUDE.md", working_root="/wr", filesystem_mode="case-sensitive")
    assert out == "CLAUDE.md"


def test_canonical_handles_relative_input_inferring_root():
    out = canonicalize_path("CLAUDE.md", working_root="/wr", filesystem_mode="case-sensitive")
    assert out == "CLAUDE.md"


def test_strips_leading_dot_slash():
    out = canonicalize_path("./CLAUDE.md", working_root="/wr", filesystem_mode="case-sensitive")
    assert out == "CLAUDE.md"


def test_rejects_empty_path():
    with pytest.raises(IPRPathError) as exc:
        canonicalize_path("", working_root="/wr", filesystem_mode="case-sensitive")
    assert exc.value.code == "EMPTY"


def test_rejects_percent_encoding():
    with pytest.raises(IPRPathError) as exc:
        canonicalize_path("foo%20bar.md", working_root="/wr", filesystem_mode="case-sensitive")
    assert exc.value.code == "PERCENT_ENCODING"


def test_rejects_traversal():
    with pytest.raises(IPRPathError) as exc:
        canonicalize_path("../etc/passwd", working_root="/wr", filesystem_mode="case-sensitive")
    assert exc.value.code == "TRAVERSAL"


def test_rejects_outside_root_when_absolute():
    with pytest.raises(IPRPathError) as exc:
        canonicalize_path("/other/CLAUDE.md", working_root="/wr", filesystem_mode="case-sensitive")
    assert exc.value.code == "OUTSIDE_ROOT"


def test_rejects_trailing_slash():
    with pytest.raises(IPRPathError) as exc:
        canonicalize_path("docs/", working_root="/wr", filesystem_mode="case-sensitive")
    assert exc.value.code == "TRAILING_SLASH"


def test_rejects_non_absolute_working_root():
    with pytest.raises(IPRPathError) as exc:
        canonicalize_path("CLAUDE.md", working_root="relative/wr", filesystem_mode="case-sensitive")
    assert exc.value.code == "WORKING_ROOT_NOT_ABSOLUTE"


def test_case_insensitive_mode_lowercases():
    out = canonicalize_path("CLAUDE.MD", working_root="/wr", filesystem_mode="case-insensitive")
    assert out == "claude.md"


def test_case_sensitive_mode_preserves_case():
    out = canonicalize_path("CLAUDE.MD", working_root="/wr", filesystem_mode="case-sensitive")
    assert out == "CLAUDE.MD"


def test_unicode_nfc_normalization():
    # 'é' as NFD (e + combining acute) should normalize to NFC ('é').
    nfd_path = "café.md"  # already NFC
    out = canonicalize_path(nfd_path, working_root="/wr", filesystem_mode="case-sensitive")
    assert out == "café.md"


def test_sort_instruction_files_lexicographic_by_path():
    files = [
        InstructionFile(path="z.md", digest="0" * 64, bytes=1, role="other"),
        InstructionFile(path="a.md", digest="0" * 64, bytes=1, role="other"),
        InstructionFile(path="m.md", digest="0" * 64, bytes=1, role="other"),
    ]
    sorted_f = sort_instruction_files(files)
    assert [f.path for f in sorted_f] == ["a.md", "m.md", "z.md"]


def test_compute_context_root_is_deterministic():
    files = [
        InstructionFile(path="a.md", digest="0" * 64, bytes=10, role="other"),
        InstructionFile(path="b.md", digest="1" * 64, bytes=20, role="other"),
    ]
    a = compute_context_root(files)
    b = compute_context_root(list(reversed(files)))
    assert a == b
    assert len(a) == 64


def test_context_root_changes_when_file_digest_changes():
    f1 = [InstructionFile(path="a.md", digest="0" * 64, bytes=10, role="other")]
    f2 = [InstructionFile(path="a.md", digest="1" * 64, bytes=10, role="other")]
    assert compute_context_root(f1) != compute_context_root(f2)
