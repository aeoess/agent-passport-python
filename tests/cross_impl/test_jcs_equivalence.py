"""Cross-implementation JCS byte-match harness (Python side).

Mirror of agent-passport-system/tests/cross-impl/jcs-equivalence.test.ts.

For every vector in jcs-test-vectors.json (pinned expected canonical bytes
+ SHA-256), this test asserts:

  1. canonicalize_jcs(input)                — Python SDK strict-JCS path —
     matches the pinned canonical bytes.
  2. SHA-256(canonicalize_jcs(input))       — matches the pinned SHA-256.
  3. rfc8785.dumps(input)                   — Python reference impl —
     matches the pinned canonical bytes.
  4. SHA-256(rfc8785.dumps(input))          — matches the pinned SHA-256.

If any vector fails, either the Python SDK has drifted from strict
RFC 8785, or rfc8785@0.1.4's behaviour has shifted, or the pinned
vectors are stale. To regenerate the pinned vectors after an
intentional change, run tests/cross_impl/gen_vectors.py.

CI runs both this test and the parallel TypeScript test that exercises
canonicalize@3.0.0 against the same vectors. Three-way byte-match
across the npm SDK + canonicalize@3.0.0 + rfc8785@0.1.4 = Python SDK
is the actual conformance signal.

The pinned manifest is shared verbatim with the TypeScript SDK; updating
it in one place requires copying to the other.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from agent_passport.canonical import canonicalize_jcs

try:
    import rfc8785
except ImportError:  # pragma: no cover - CI installs this; local devs may not
    rfc8785 = None  # type: ignore[assignment]


_MANIFEST_PATH = pathlib.Path(__file__).parent / "jcs-test-vectors.json"
_MANIFEST = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
_VECTORS = _MANIFEST["vectors"]


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("v", _VECTORS, ids=lambda v: v["id"])
def test_sdk_canonicalize_jcs_matches_pinned_bytes(v):
    """The Python SDK's strict-JCS path must produce the pinned canonical bytes."""
    sdk_bytes = canonicalize_jcs(v["input"])
    assert sdk_bytes == v["expected_canonical_bytes"], (
        f"{v['id']}: SDK canonicalize_jcs diverged from pinned bytes"
    )


@pytest.mark.parametrize("v", _VECTORS, ids=lambda v: v["id"])
def test_sdk_canonicalize_jcs_matches_pinned_sha256(v):
    """SHA-256(canonicalize_jcs(input)) must match the pinned hash."""
    sdk_hash = _sha256_hex(canonicalize_jcs(v["input"]))
    assert sdk_hash == v["expected_sha256"], (
        f"{v['id']}: SDK canonicalize_jcs SHA-256 diverged from pinned hash"
    )


@pytest.mark.skipif(rfc8785 is None, reason="rfc8785 not installed (CI installs it)")
@pytest.mark.parametrize("v", _VECTORS, ids=lambda v: v["id"])
def test_rfc8785_reference_matches_pinned_bytes(v):
    """rfc8785@0.1.4 — the Python reference impl — must produce pinned bytes."""
    ref = rfc8785.dumps(v["input"])
    ref_str = ref.decode("utf-8") if isinstance(ref, (bytes, bytearray)) else ref
    assert ref_str == v["expected_canonical_bytes"], (
        f"{v['id']}: rfc8785 reference diverged from pinned bytes"
    )


@pytest.mark.skipif(rfc8785 is None, reason="rfc8785 not installed (CI installs it)")
@pytest.mark.parametrize("v", _VECTORS, ids=lambda v: v["id"])
def test_sdk_matches_rfc8785_directly(v):
    """The SDK and rfc8785 must produce identical canonical bytes — no pin needed."""
    sdk_bytes = canonicalize_jcs(v["input"])
    ref = rfc8785.dumps(v["input"])
    ref_str = ref.decode("utf-8") if isinstance(ref, (bytes, bytearray)) else ref
    assert sdk_bytes == ref_str, (
        f"{v['id']}: SDK canonicalize_jcs and rfc8785.dumps disagree"
    )


def test_manifest_metadata_sanity():
    """Quick guard that the pinned manifest header is well-formed."""
    assert "rfc8785" in _MANIFEST["generator"], _MANIFEST["generator"]
    assert "RFC 8785" in _MANIFEST["spec"], _MANIFEST["spec"]
    assert "SHA-256" in _MANIFEST["hash"]
    assert "lowercase hex" in _MANIFEST["hash"]
    assert len(_VECTORS) >= 10, f"expected >=10 vectors, got {len(_VECTORS)}"
    for v in _VECTORS:
        assert len(v["expected_sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in v["expected_sha256"]), v["id"]
