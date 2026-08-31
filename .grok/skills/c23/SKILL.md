---
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
name: c23
description: >
  Write, fix, and extend Z23 in C23. Use on every source change in this
  repository: implement, fix, patch, add a command, controller, service,
  model, job, condition, net, wallet, consensus, zcode, or test. Use when
  the user says C, C23, z23, zclassic23, "write code", "add a feature",
  "make it work", or runs /c23. Never reach for Python.
when-to-use: >
  Any edit under app/, lib/, core/, domain/, ports/, adapters/, config/,
  tools/, or a new native command. Any request to build, test, or debug
  the node. Any temptation to parse JSON/SQL with Python.
---

# C23 work in this repository

Canonical contract is [`AGENTS.md`](../../../AGENTS.md). This skill is the
Grok working loop so that contract is followed on every edit, not only on
the first turn.

## Language

- Compiled code is C23, built through this tree's `make` / `zcc`.
- Never Python: no `.py`, no `python3`, no Python heredocs, no "just this
  once" parser.
- JSON: `grep`/`sed`/`awk` for flat fields; `build/bin/jsonq` for nested
  documents. SQLite: `build/bin/sqlq`.
- New operator surface is a typed native command, not a one-off script,
  unless the work is truly a single local shell step.

## Loop

1. Inspect existing work and verify the manager-pinned baseline. Parallel
   workers do not fetch or integrate independently; the single publication
   authority fetches `origin/main` and reconciles upstream normally. Never
   rebase, reset, force, or discard another worktree's changes.
2. Orient with the built binary, not a repo-root recursive search:

   ```bash
   build/bin/z23 code map
   build/bin/z23 discover help
   build/bin/z23 discover search <query>
   build/bin/z23 discover schema <leaf>
   ```

   Raw search, when needed, is `git grep` / `git ls-files` on the tracked
   tree.
3. Reuse an existing C23 function, command, CAS/task/action/receipt path,
   or model before adding a file. One primary writer per component.
4. Edit the smallest owned surface. `app/` shape is
   controller → service → model. Defensive rails:
   [`docs/DEFENSIVE_CODING.md`](../../../docs/DEFENSIVE_CODING.md)
   (AR save lifecycle, logged errors, checked allocations, command
   response bodies, custody before/after-save hooks).
5. Prove with the focused group, not a direct test binary:

   ```bash
   make -j"$(getconf _NPROCESSORS_ONLN)" t-fast ONLY=<group>
   make lint-fast
   ```

   Green means exactly one suite verdict, zero failures, skips, and
   unobserved groups, and complete ran/reused accounting. Never
   `ZCL_TEST_CACHE=1` for a merge claim.
6. Commit only owned files and hand the exact commit to the integrator. The
   publication authority fetches `origin/main` immediately before integration
   and push. The installed native pre-push hook admits an exact receipt; it
   does not run `make pre-push-ci`. Map new paths in
   `app/controllers/include/controllers/agent_impact_rules.def`.

## Do not

- Change consensus predicates or the byte-sealed core without the unseal
  ritual in [`docs/CONSENSUS_PARITY_DOCTRINE.md`](../../../docs/CONSENSUS_PARITY_DOCTRINE.md).
- Touch production/canonical datadirs, spend keys, or deploy.
- Weaken an assertion to get a green result.
- Add a parallel source of truth next to CAS, task, candidate, action,
  receipt, or queue.
- Expand HOT_FORK / reflex / fleet tooling unless a P0/P1 acceptance is
  blocked.

Mission order: [`docs/work/FORWARD_PLAN.md`](../../../docs/work/FORWARD_PLAN.md).
Traps: [`docs/AGENT_TRAPS.md`](../../../docs/AGENT_TRAPS.md).
