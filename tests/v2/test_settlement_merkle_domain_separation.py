# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Settlement Merkle domain separation (CVE-2012-2459 class) — Day-145
audit, receipt format v1.1 -> v1.2. Python port must stay byte-identical to
src/v2/attribution-settlement/merkle.ts on the TypeScript branch
audit/day145/sdk-merkle-domain-separation."""

import pytest

from agent_passport.v2.attribution_settlement import (
    build_contributor_merkle_path,
    build_merkle_root,
    leaf_hash,
    verify_merkle_path,
)

LEAVES = [leaf_hash({"id": f"aps-settlement-parity-{i}"}) for i in range(5)]


def test_duplicate_leaf_collision_defeated():
    three = build_merkle_root(LEAVES[:3])
    dup = build_merkle_root(LEAVES[:3] + [LEAVES[2]])
    assert three != dup, "CVE-2012-2459: settlement roots must differ"


def test_genuine_contributor_paths_reconstruct_root():
    three = build_merkle_root(LEAVES[:3]).hex()
    # index 2 is the odd/promoted leaf, the worst case for the fold.
    for idx in range(3):
        path = build_contributor_merkle_path(LEAVES[:3], idx)
        assert verify_merkle_path(LEAVES[idx], idx, path, three), f"path for index {idx} failed"

    five = build_merkle_root(LEAVES).hex()
    for idx in range(5):
        path = build_contributor_merkle_path(LEAVES, idx)
        assert verify_merkle_path(LEAVES[idx], idx, path, five), f"path for index {idx} failed"


def test_phantom_duplicate_path_rejected():
    three = build_merkle_root(LEAVES[:3]).hex()
    phantom_path = build_contributor_merkle_path(LEAVES[:3] + [LEAVES[2]], 3)
    assert not verify_merkle_path(LEAVES[2], 3, phantom_path, three), (
        "phantom-duplicate path must not reconstruct the honest root"
    )


def test_empty_input_raises():
    with pytest.raises(ValueError):
        build_merkle_root([])
    with pytest.raises(ValueError):
        build_contributor_merkle_path([], 0)


def test_pinned_cross_language_roots_and_path():
    """Known-answer values computed from the patched TypeScript reference.
    Leaves are settlementLeafHash({id: 'aps-settlement-parity-<i>'})."""
    pinned_roots = {
        1: "cef5568a669d62bda7cab5497c29aad308ff41fb76742dde9170ea50d788bbde",
        2: "6363294169a739168de7c5d2010465572a9fb4f6209f21cb0e6ae7fd47274f99",
        3: "49d406cad18acfbf9a2c477f0adf3da8314ff6e7e42319eff0cb567032ee7839",
        5: "0f04d0d3ec635d5db1c7774c4fc5579ce458d0a4496a7bb1ac52babf907ce7b8",
    }
    for n, want in pinned_roots.items():
        assert build_merkle_root(LEAVES[:n]).hex() == want, f"n={n}: root diverged from TS"

    assert (
        build_merkle_root(LEAVES[:3] + [LEAVES[2]]).hex()
        == "09a0e8f522bfcb2b938a74285cf7a5b229ea17e1a989e9b587cb771cfec40fda"
    )

    # The promoted odd leaf records the sentinel token, not a self-duplicate.
    assert build_contributor_merkle_path(LEAVES[:3], 2) == [
        "promoted",
        "6363294169a739168de7c5d2010465572a9fb4f6209f21cb0e6ae7fd47274f99",
    ]
