<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Agent document index

New to a z23 fleet? Read [START_HERE.md](START_HERE.md) first. Then [AGENTS.md](../../AGENTS.md), then select work under its fleet priorities, using
[FORWARD_PLAN.md](../work/FORWARD_PLAN.md) for scoped context. The development procedure is
[DEVELOPING.md](../DEVELOPING.md). These adapters do not reorder that work.

Before editing, inspect dirty work and `git worktree list --porcelain`, and
fetch the exact `origin/main` identity. On a managed host, also read its host
policy and run `devworker where z23`; those tools are not part of the repository.
A standalone checkout is not exclusive
ownership or permission to publish; directory layout grants no authority.

## Choose the adapter

| Need | Document |
|---|---|
| Establish ownership and resume a lane | [Parallel worker protocol](../work/agent-protocol.md) |
| Assign disjoint work to another worker | [Lane launch](LANE_LAUNCH.md) |
| Start a bounded source slice | [Lane quickstart](LANE_QUICKSTART.md) |
| Report an exact checkpoint and evidence | [Lane report](LANE_REPORT.md) |
| Integrate through native receipt gates | [Train protocol](TRAIN_PROTOCOL.md) |
| Distinguish evidence from acceptance | [Evidence ladder](EVIDENCE_LADDER.md) |
| Inspect historical observations | [Lessons](LESSONS.md) |
| Inspect fleet transport boundaries | [Native channel](NATIVE_CHANNEL.md), [Fleet join](FLEET_JOIN.md) |
| Install the Claude Code plugin | [Z23 plugin for Claude Code](../../.claude/plugin/README.md), opt-in fleet gateway: [fleet plugin](../../.claude/plugin-fleet/README.md) |
| Inspect experimental unit contracts | [Flash unit](FLASH_UNIT.md), [Executor heuristics](EXECUTOR_HEURISTICS.md) |

Use the built binary's `discover` catalog and code navigator to establish
available commands and exact input keys. Source declarations and plans are not
proof that a command is available in an older binary.

## Working rules

- Preserve unrelated dirty work, protected refs, and existing leases.
- Use native lane and file-claim tools; keep one writer per component. Renew
  each claim before its reported expiry and release it after the checkpoint.
- Run heavy builds, proofs, benchmarks, and test matrices through
  `devbuild --wait`, retaining repository job presets and native locks.
- Keep services, timers, watchers, and development nodes disabled unless the
  operator explicitly requests activation.
- Commit an owned coherent slice normally and retain its exact signed identity
  for non-author review. A handoff or queued request is not publication.
- Publish only through the authorized native receipt-gated route described in
  DEVELOPING.md, then independently verify the exact remote commit.
- Never stash shared work, force-push, bypass hooks, or weaken a refusal.
- Use existing task, candidate, action, receipt, and signature authorities.
  A coordination message is not an independent proof or a new authority.
