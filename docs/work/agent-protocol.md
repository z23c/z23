<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Parallel worker protocol

This document is the compatibility entry point for parallel workers. Authority
lives in [`../../AGENTS.md`](../../AGENTS.md); the normal loop lives in
[`../DEVELOPING.md`](../DEVELOPING.md); dispatch and return adapters live in
[`../agent/LANE_LAUNCH.md`](../agent/LANE_LAUNCH.md) and
[`../agent/LANE_REPORT.md`](../agent/LANE_REPORT.md).

## Startup ritual

One command establishes your situation:

```sh
[ "$(git rev-parse --git-dir)" = "$(git rev-parse --git-common-dir)" ] \
  && echo STANDALONE || echo SHARED_CHECKOUT_LANE
```

Then run:

```sh
build/bin/z23-dev dev agent start --input='{"files":["<files you will touch>"]}'
```

This prints your situation, the rules for it, the base head, dirty and untracked
counts, whether hooks are armed, and the next commands. The rule text comes from
`engine/composition/agent_rules.def`: one declaration, twelve rows, six topics
(`push_target`, `commit_scope`, `gate_command`, `gate_skip`, `force_push`,
`history`).

Preserve every unrelated edit. Never stash, rebase, reset, force, or reuse
another worker's index or build directory. Source work does not inherit
live-node authority; only work operating the maintainer's hosted node reads
handoff material.

## Claim your files

```sh
build/bin/z23-dev dev agent claim --input='{"story":"<slug>","files":[...]}'
```

This refuses with `CLAIM_OVERLAP` when another worktree on the same checkout
holds one of the files. Release files when done by adding `"release":true` to
the same command.

## Work

- Ask the native code navigator whether the capability already exists.
- Keep one primary writer per component and use the canonical capability,
  command, impact, task, candidate, action, receipt, and publication catalogs.
- Use a private explicit datadir for tests and diagnostics.
- Build and test only the affected surface while editing. Quote exact verdicts;
  cached, skipped, incomplete, unavailable, and unrun evidence are not green.
- Commit a coherent owned slice so its immutable identity can be reviewed even
  if the worktree moves later.
- Re-derive every count you touch from the tree itself and say which command
  produced it.

## Completion ritual

```sh
build/bin/z23-dev dev agent done
```

This reports `ready true` only when the tree is clean, at least one commit is
ahead of `origin/main`, every commit is signed, and the branch is not `main`.
Hand off the head SHA it prints.

Return the exact baseline, head, diff, evidence, and unresolved work. The
manager reviews the complete commit, fetches current `origin/main`, integrates
normally, reruns affected acceptance, pushes without force, and verifies local,
tracking, and remote identities agree.

The installed pre-push hook is receipt-only. Current post-commit notification is
best-effort and the resident proof queue remains filesystem-backed. A canonical
signed-commit promoter backed by the existing task/candidate/action/receipt
fabric is still unfinished; do not create another queue or describe handoff as
automatic publication.

## Forbidden moves

- Never stash, rebase, reset, force-push, or reuse another worker's index or
  build directory.
- Never record anything in version control and never publish to any remote as an
  agent; a person reads the work before either happens.
- Never weaken an assertion, threshold, baseline, or fail-closed refusal to get
  a green result. An honest red is the correct answer.
