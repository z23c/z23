<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Parallel worker protocol

This document is the compatibility entry point for parallel workers. Authority
lives in [`../../AGENTS.md`](../../AGENTS.md); the normal loop lives in
[`../dev/DEVELOPING.md`](../dev/DEVELOPING.md); dispatch and return adapters live in
[`../agent/LANE_LAUNCH.md`](LANE_LAUNCH.md) and
[`../agent/LANE_REPORT.md`](LANE_REPORT.md).

## Startup ritual

On a managed host, read its policy and inspect the assigned lane. Inspect dirty work and
`git worktree list --porcelain`, then fetch and record exact `origin/main`.
Resume owned work in place. Worktree layout alone grants no ownership or
publication authority. Use native lane preparation when isolation is required.

Then run:

```sh
build/bin/z23-dev dev agent start --input='{"files":["<files you will touch>"]}'
```

This prints your situation, the rules for it, the base head, dirty and untracked
counts, whether hooks are armed, and the next commands. The rule text comes from
`engine/composition/agent_rules.def`; derive its current topics from the binary
rather than treating copied counts or standalone rule text as ownership.

Preserve every unrelated edit. Never stash shared work, force-push, or
rebase/reset another worker's checkout; never reuse their index or build
directory. Source work does not inherit
live-node authority; only work operating the maintainer's hosted node reads
handoff material.

## Claim your files

```sh
build/bin/z23-dev dev agent claim --input='{"story":"<slug>","files":[...]}'
```

This refuses with `CLAIM_OVERLAP` when another worktree on the same checkout
holds one of the files. A successful claim reports `expires_unix` and lasts 15
minutes. Repeat the same claim before that time to renew it; stop writing if
the lease expires, then claim again before resuming. A later claimant may take
expired files, and the ledger removes expired rows on a successful claim. Rows
written before leases have no expiry; do not expire or delete them by age.
Use only qualified native release or retirement with its exact evidence and
refusals. A missing directory alone is not retirement authority.
Release files when done by adding `"release":true` to the same command. A
file claim coordinates writers; it never grants proof or publication authority.

## Work

- Ask the native code navigator whether the capability already exists.
- Keep one primary writer per component and use the canonical capability,
  command, impact, task, candidate, action, receipt, and publication catalogs.
- Use a private explicit datadir for tests and diagnostics.
- Run heavy builds, proofs, benchmarks, and test matrices through
  `devbuild --wait`, retaining repository presets and native locks. Keep
  services, timers, watchers, and development nodes disabled unless the
  operator explicitly requests activation.
- Build and test only the affected surface while editing. Quote exact verdicts;
  unqualified cached summaries, skipped, incomplete, unavailable, and unrun
  evidence are not green. Report receiver-qualified exact reuse separately
  from newly executed work.
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

Return the exact baseline, head, diff, evidence, and unresolved work. A
non-author reviews the complete commit. Any authorized worker may then use the
native receipt-gated landing route in DEVELOPING.md, preserving other queue
items and leases. Fetch current `origin/main`, rerun affected gates, and
independently verify the exact remote commit. No permanent lead is required.

The installed pre-push hook is receipt-only. Current post-commit notification is
best-effort and the resident proof queue remains filesystem-backed. A canonical
signed-commit promoter backed by the existing task/candidate/action/receipt
fabric is still unfinished; do not create another queue or describe handoff as
automatic publication.

## Forbidden moves

- Never stash shared work, force-push, or rebase/reset another worker's
  checkout, index, or build directory. Integrate an owned sanctioned lane
  safely through the canonical procedure, preserving unrelated edits.
- Commit only an owned coherent slice, signed normally, for non-author review.
  Publication requires the authorized native receipt-gated route; a queued
  request or clean checkpoint alone does not permit it.
- Never weaken an assertion, threshold, baseline, or fail-closed refusal to get
  a green result. An honest red is the correct answer.
