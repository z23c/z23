<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Parallel assignment adapter

This page adds only the mechanics needed when several workers share one Git
object store. The project contract remains [`../../AGENTS.md`](../../AGENTS.md)
and the development procedure remains
[`../DEVELOPING.md`](../DEVELOPING.md). Do not copy either into a lane prompt.

## Dispatch

1. Fetch `origin/main` once in a clean manager checkout and record its full
   commit ID. A worker baseline is the recorded commit, not a path or branch
   name.
2. Give each worker a disjoint owned-path set and a concrete acceptance. Only
   one worker may own a high-contention catalog such as `Makefile`, the command
   definitions, impact rules, or generated capability inventory.
3. Use a separate worktree when workers need independent indexes or builds.
   Create it detached at the recorded `origin/main`; the resulting commit ID is
   the handoff. A branch is optional metadata, not evidence.
4. Prime a fresh worktree with `tools/scripts/worktree_init.sh` before its first
   build. Never copy a build directory from another worktree.
5. Pass a compact mission capsule:

   ```text
   NORTH STAR
   USER OUTCOME
   CURRENT BASELINE
   OWNED SURFACE
   INVARIANTS
   ACCEPTANCE
   CONTINUATION QUEUE
   ESCALATE ONLY IF
   ```

## Shared-store safety

- Never use `git stash`; all worktrees share `refs/stash`.
- Never reset, rebase, force-push, or remove another worker's worktree.
- Never infer liveness from a directory name. Inspect
  `git worktree list --porcelain` and preserve dirty or locked worktrees.
- Use an explicit isolated datadir for every datadir-taking command.
- Keep one primary writer per component and report required out-of-scope edits
  instead of making them.

## Handoff

A worker reports its baseline, exact head commit, owned diff, literal focused
verdicts, and unresolved items in the shape of
[`LANE_REPORT.md`](LANE_REPORT.md). The manager reviews every byte, fetches the
current `origin/main`, integrates normally, reruns affected acceptance, and
pushes only an exact admitted commit.

The repository currently has a native exact-receipt hook and a resident
filesystem proof queue. It does **not** yet have a durable signed-commit
promoter that fetches, integrates, proves, and publishes automatically. The
separate `tools/land` batching prototype is not that authority: it runs the
legacy gate and stops at a local `land/ready` ref. Until the canonical
task/candidate/action/receipt fabric owns publication, do not tell workers that
enqueue means published.

Reclaim worktrees only through the repository's worktree-GC procedure after
their commits are reachable from verified `origin/main` and their ownership is
known. A directory count is telemetry, never permission to delete.
