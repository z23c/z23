# Train protocol

This document defines how fleet nodes land lanes on main one train at a time without a human, and specifies that process as a state machine.

## Purpose

Main moves one train at a time. A node orders finished lanes into a train of at most 4 lanes. It rebases the train onto the exact current origin/main tip. lint-fast is green before the train goes further. The push-hook proof runs once. Then the node pushes.

Every push to main moves the base and invalidates every in-flight proof on every box. Because of this, trains stay small and results are posted the moment a push succeeds.

See also: `AGENTS.md`, `docs/DEVELOPING.md`, `docs/work/agent-protocol.md`.

## Definitions

| Term | Meaning |
| --- | --- |
| lane | One unit of finished work queued for main. For lane launch and reporting, see `docs/agent/LANE_LAUNCH.md` and `docs/agent/LANE_REPORT.md`. |
| train | An ordered batch of at most 4 lanes. |
| base | The exact current origin/main tip a train is rebased onto. One train per base, fleet-wide. |
| proof | The push-hook proof. It runs once per train, before the push. |
| box | One machine in the fleet. One proof per box at a time; this is the box lock. |
| board | Where claim and result rows are posted. |

## The state machine

```text
IDLE ─────claim────▶ PROVING ─────push ok────▶ LANDED ─────result────▶ IDLE

PROVING ─────base moved────▶ REBASE ─▶ PROVING
                                REBASE rebases the train onto the exact current
                                origin/main tip; the train then proves again.

PROVING ──gate red or too large──▶ WITHDRAWN ─────result────▶ IDLE
```

A node in IDLE posts a claim and enters PROVING. PROVING ends in exactly one of three ways: the push succeeds (LANDED), the base moves (REBASE, then PROVING again), or a gate is red or the train is too large (WITHDRAWN). LANDED and WITHDRAWN each end with a result row and a return to IDLE. The box lock is held from the claim until the result.

## Board rows

| Event | Row posted |
| --- | --- |
| The node starts proving | `claim train <name> base=<tip> commits=<n> lanes: <names>` |
| The push succeeded | `result train <name> <new tip>` |
| The node gave up | `result train <name> WITHDRAWN <reason>` |

| Field | Meaning |
| --- | --- |
| `<name>` | Train name. |
| `<tip>` | The base: the origin/main tip the train is proven against. |
| `<n>` | Commit count of the train. |
| `<names>` | Lane names, in train order. |
| `<new tip>` | The origin/main tip after the push. |
| `<reason>` | Why the train was withdrawn. |

No node starts a proof against a base another node has claimed and not resolved. A claim is resolved by either form of result row.

## Rules

- A train carries at most 4 lanes, in a fixed order, rebased onto the exact current origin/main tip.
- lint-fast is green before the proof runs.
- One proof per box at a time. One train per base, fleet-wide.
- Never push while another node's claim is live.
- Post the result the moment the push succeeds.
- A withdrawn train posts why.
- Land generated files (capability inventory, API reference) by regenerating them once on the train. Do not cherry-pick each lane's copy.
- Every commit is signed.
- Never `git stash`.
- Never force-push. Fast-forward only.

The table below is the measured record behind the size cap and the timeout override. The values are fleet observations dated 2026-09-04, not properties of this checkout.

| Observation (2026-09-04) | Value |
| --- | --- |
| Withdrawn train | 135 commits, 1,036 files |
| Why withdrawn | Impact planning alone took about an hour, and every push to main invalidated it. |
| Change since | The same lanes land as trains of at most 4 lanes. |
| Proof duration | 15 to 45 minutes per box. |
| Release build inside a proof | About 20 minutes. |
| Loaded box | Load 450, disk-bound. Every proof child exited 124 until the timeout became an environment override. |

## What replaces the shell loop

The shell loop that drives these transitions today is interim. The C23 leaf `zcode land` (node2's lane) replaces it. `zcode land` posts the claim and result rows itself and drives the same state machine. Until it lands, the loop remains the operator, and every rule in this document binds it unchanged.

Related tooling in the tree: `tools/scripts/worktree_init.sh`, `tools/scripts/worktree_gc.sh`.
