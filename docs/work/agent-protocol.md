<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Parallel worker protocol

This is a compatibility entry point, not a second development process.
Authoritative priority and authority live in [`../../AGENTS.md`](../../AGENTS.md);
the normal loop lives in [`../DEVELOPING.md`](../DEVELOPING.md); dispatch and
return adapters live in [`../agent/LANE_LAUNCH.md`](../agent/LANE_LAUNCH.md) and
[`../agent/LANE_REPORT.md`](../agent/LANE_REPORT.md).

## Start

1. Record `pwd`, `git status --short --branch`, the full `HEAD`, and the full
   advertised `origin/main` observed by the manager.
2. Preserve every unrelated edit. Never stash, rebase, reset, force, or reuse
   another worker's index/build directory.
3. Confirm the owned paths, invariant, focused acceptance, and escalation
   boundary from the mission capsule.
4. Read `docs/HANDOFF.md` only when the task operates the maintainer's hosted
   node; source work does not inherit live-node authority.

## Work

- Ask the native code navigator whether the capability already exists.
- Keep one primary writer per component and use the canonical capability,
  command, impact, task, candidate, action, receipt, and publication catalogs.
- Use a private explicit datadir for tests and diagnostics.
- Build and test only the affected surface while editing. Quote exact verdicts;
  cached, skipped, incomplete, unavailable, and unrun evidence are not green.
- Commit a coherent owned slice so its immutable identity can be reviewed even
  if the worktree moves later.

## Return and integration

Return the exact baseline, head, diff, evidence, and unresolved work. The
manager reviews the complete commit, fetches current `origin/main`, integrates
normally, reruns affected acceptance, pushes without force, and verifies local,
tracking, and remote identities agree.

The installed pre-push hook is receipt-only. Current post-commit notification
is best-effort and the resident proof queue remains filesystem-backed. The
tracked `tools/land` prototype is a separate legacy batching path and does not
publish. A canonical signed-commit promoter backed by the existing
task/candidate/action/receipt fabric is still unfinished; do not create another
queue or describe handoff as automatic publication.
