# Contributing to agent-passport-python

Thanks for showing up here. This is the Python SDK for the Agent Passport System — Ed25519 identity, delegation, governance, and commerce primitives for AI agents. The TypeScript SDK at [`agent-passport-system`](https://github.com/aeoess/agent-passport-system) is the reference implementation; this library tracks its API surface in Python-idiomatic form.

## Quick start

**For a bug fix**, submit:

1. A failing test that reproduces the bug (in the existing test module where it logically belongs)
2. The minimal fix that makes the test pass without breaking other tests
3. No scope expansion — fix the bug, don't refactor adjacent code in the same PR

**For a feature addition**, open an issue first. Features should track the TypeScript SDK's capability surface unless there's a Python-specific reason for divergence. Once the direction is clear, a PR can follow.

**For documentation**, straight PR is fine. No issue needed first.

**Submission mechanics:** fork the repo, create a feature branch from `main`, open a PR against `main`. Keep PRs focused — one concern per PR.

---

## What makes a PR mergeable

1. **Tests pass.** Run `pytest` at repo root. 125+ tests currently, PR should not drop the count or decrease coverage of touched code.
2. **Type checks pass.** `mypy` clean on modified files.
3. **Format is consistent.** `ruff format` and `ruff check` clean. Module layout matches existing patterns — one concept per module, shared types in `types.py`.
4. **API tracks TypeScript SDK** where feasible. If you're porting a TS module, keep the public surface close. Diverge only where Python idioms demand it (async/await, dataclasses, type hints) and note the divergence in the PR.
5. **Changes to the public API include a CHANGELOG entry** and a version bump rationale in the PR description.

## Stability expectations

The Python SDK follows semantic versioning. API changes that would break downstream consumers require a major version bump with migration notes. Internal refactors can land in patch releases.

## Out of scope

- **New signature algorithms beyond Ed25519 in core identity primitives.** Ed25519 is load-bearing across the protocol. Alternative algorithms can ride alongside via extension modules, not replace.
- **Vendored dependencies or binary wheels without justification.** The library ships as pure Python where possible. If a native dependency is necessary, document why in the PR.
- **Non-reproducible tests.** Tests that rely on external network calls, current time, or other non-deterministic inputs should be refactored or marked with `pytest.mark.integration`.

---

## How review works

Every PR is evaluated against five questions, applied to every contributor equally:

1. **Identity.** Is the contributor identifiable, with a real GitHub presence?
2. **Format.** Does the change match existing patterns (module layout, type hints, error handling, test density)?
3. **Substance.** Do tests actually exercise the claimed behavior?
4. **Scope.** Does the PR stay scoped to its stated purpose?
5. **Reversibility.** Can the change be reverted cleanly if a downstream issue surfaces?

Substantive declines include the reason.

---

## Practical details

- **Maintainer:** [@aeoess](https://github.com/aeoess) (Tymofii Pidlisnyi)
- **Review timing:** maintainer-bandwidth dependent. If a PR has had no response after 5 business days, ping it.
- **CLA / DCO:** no CLA is required. Contributions accepted on the understanding that the submitter has the right to contribute under the Apache 2.0 license.
- **Security issues:** open a private security advisory via GitHub rather than a public issue.
- **Code of Conduct:** Contributor Covenant 2.1 — see [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

---

## Licensing

Apache License 2.0 (see [`LICENSE`](./LICENSE)). By contributing, you agree that your contributions will be licensed under the same license.
