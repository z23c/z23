<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Parallel worker contract

This compatibility document is intentionally small. The authoritative
engineering, safety, Git, and continuation rules are
[`../../AGENTS.md`](../../AGENTS.md); detailed commands are in
[`../DEVELOPING.md`](../DEVELOPING.md). If either changes, this adapter gains no
independent exception.

A parallel worker must:

- work only in the assigned worktree and owned file set;
- derive its baseline and head with Git rather than copying a typed SHA;
- preserve unrelated dirty work and the shared stash, refs, and object store;
- use C23 for compiled code and never add Python;
- keep consensus, custody, canonical datadirs, deployment, and node restarts
  outside its authority unless the mission explicitly grants the required
  owner action;
- use the native code navigator and tracked-tree searches before broad reads;
- run the smallest focused acceptance that observes the changed invariant;
- quote literal verdicts and report skipped, cached, incomplete, or unrun work
  honestly;
- commit only its owned coherent slice and return the exact commit identity;
- identify every contract statement that contradicted the tree.

Never use `git stash`, rebase, reset, force, `--no-verify`, or a recursive
delete to coordinate parallel work. Never weaken an assertion or convert an
unavailable proof into a pass.

The current installed native pre-push hook reads ancestry and exact fixed-width
receipts; it does not build, lint, test, fetch, or run `make pre-push-ci`.
Receipt production is still asynchronous and filesystem-backed. A worker must
not invent a second queue or translate canonical task/candidate/action/receipt
facts into a parallel landing verdict.

Use [`LANE_LAUNCH.md`](LANE_LAUNCH.md) to dispatch and
[`LANE_REPORT.md`](LANE_REPORT.md) to return work.
