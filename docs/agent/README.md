<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Agent document index

New to a z23 fleet? Read [START_HERE.md](START_HERE.md) first. Then [AGENTS.md](../../AGENTS.md), then select work under its fleet priorities, using
[FORWARD_PLAN.md](../work/FORWARD_PLAN.md) for scoped context. The development procedure is
[DEVELOPING.md](../dev/DEVELOPING.md). These adapters do not reorder that work.

Before editing, inspect dirty work and `git worktree list --porcelain`, and
fetch the exact `origin/main` identity. On a managed host, also read its host
policy and inspect the assigned lane; host policy is not part of the repository.
A standalone checkout is not exclusive
ownership or permission to publish; directory layout grants no authority.

## Choose the adapter

| Need | Document |
|---|---|
| Establish ownership and resume a lane | [Parallel worker protocol](agent-protocol.md) |
| Assign disjoint work to another worker | [Lane launch](LANE_LAUNCH.md) |
| Start a bounded source slice | [Lane quickstart](LANE_QUICKSTART.md) |
| Report an exact checkpoint and evidence | [Lane report](LANE_REPORT.md) |
| Integrate through native receipt gates | [Train protocol](TRAIN_PROTOCOL.md) |
| Distinguish evidence from acceptance | [Evidence ladder](EVIDENCE_LADDER.md) |
| Inspect historical observations | [Lessons](LESSONS.md) |
| Inspect fleet transport boundaries | [Native channel](NATIVE_CHANNEL.md), [Fleet join](FLEET_JOIN.md) |
| Design and prove a regression fixture | [Representative fixtures](REPRESENTATIVE_FIXTURES.md) |
| Admit validation jobs on a small disk | [Small-disk qualification](SMALL_DISK_QUALIFICATION.md) |
| Install the Claude Code plugin | [Z23 plugin for Claude Code](../../.claude/plugin/README.md), opt-in fleet gateway: [fleet plugin](../../.claude/plugin-fleet/README.md) |
| Inspect experimental unit contracts | [Flash unit](FLASH_UNIT.md), [Executor heuristics](EXECUTOR_HEURISTICS.md) |
| See where the development system is going | [Development system vision](VISION.md) |
| Operate the fleet: machines, joining, tunnel, roles | [Fleet guide](FLEET.md) |
| Post to or read the fleet board | [Fleet board](FLEET_BOARD.md) |
| Read the fleet ledger and its refusals | [Fleet ledger](FLEET_LEDGER.md) |
| Check the closed trigger registry | [Fleet triggers](FLEET_TRIGGERS.md) |
| Search or write fleet wiki pages | [Wiki](WIKI.md) |
| Read or claim owner-signed work cards | [Work cards](WORK_CARDS.md) |
| Add a feature slice | [Agent architecture](AGENT_ARCHITECTURE.md) |
| Check intentional behavior before repairing it | [Agent traps](AGENT_TRAPS.md) |
| Separate claims from evidence | [AI safety gates](AI_SAFETY_GATES.md) |
| Measure the development system | [Development MVP](DEVELOPMENT_MVP.md) |

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

## Also in this directory

- [`AGENT_API.md`](./AGENT_API.md): AGENT_API.md — native API for AI coding operators
- [`COMMUTING_TICKETS.md`](./COMMUTING_TICKETS.md): Commuting tickets
- [`HANDOFF.md`](./HANDOFF.md): HANDOFF — current state
