# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Chain selection over the set of chains an agent holds.

draft-pidlisnyi-aps-03 section 3.3's "each action selects one root-to-leaf
authority chain" given an interface, plus the PROPOSED L11 fallback surface,
marked as such at every symbol that carries it.

Python port of the TypeScript SDK's src/v2/chain-selection package, following it
file by file. Both SDKs run the shared parity vectors in
tests/cross_impl/chain-selection-v0-vectors.json.
"""

from .select import select_chain_for_action, select_with_fallback
from .types import (
    CHAIN_SELECTION_EVALUATION_CODES,
    CHAIN_SELECTION_FAILURE_CODES,
    HELD_SET_CEILING,
    AuthorityBudgetReserver,
    ChainEvaluation,
    FallbackAuthorizationV0,
    HeldChain,
    RequiredSpendV1,
    SelectionOutcome,
)

__all__ = [
    "CHAIN_SELECTION_EVALUATION_CODES",
    "CHAIN_SELECTION_FAILURE_CODES",
    "HELD_SET_CEILING",
    "AuthorityBudgetReserver",
    "ChainEvaluation",
    "FallbackAuthorizationV0",
    "HeldChain",
    "RequiredSpendV1",
    "SelectionOutcome",
    "select_chain_for_action",
    "select_with_fallback",
]
