# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Loader parity test for the shared canonical-bytes JCS vectors.

The vectors are generated from the TS SDK canonicalizeJCS reference. This test
proves the Python canonicalize_jcs produces byte-identical canonical output and
SHA-256 for each, i.e. cross-language JCS parity on the byte-contract cases.
"""

import hashlib
import json
from pathlib import Path

from agent_passport.canonical import canonicalize_jcs

VECTORS = json.loads(
    (Path(__file__).parent / "cross_impl" / "canonical-bytes-jcs-vectors.json").read_text(
        encoding="utf-8"
    )
)["vectors"]


def test_canonical_bytes_jcs_parity():
    assert len(VECTORS) == 8
    for v in VECTORS:
        canon = canonicalize_jcs(v["input"])
        assert canon == v["canonical"], f"{v['name']}: {canon!r} != {v['canonical']!r}"
        assert canon.encode("utf-8").hex() == v["canonical_bytes_hex"], v["name"]
        assert hashlib.sha256(canon.encode("utf-8")).hexdigest() == v["canonical_sha256"], v["name"]
