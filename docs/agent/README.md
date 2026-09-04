# Agent document index

This page is the one-page index of agent-facing documents in this repository, written for a coding agent that has 60 seconds before its first command.

## Decide your situation

Which rules apply to you is decided by a test, not by assumption. Run this first:

```sh
[ "$(git rev-parse --git-dir)" = "$(git rev-parse --git-common-dir)" ] && echo STANDALONE || echo SHARED_CHECKOUT_LANE
```

| Output | Meaning | Your rules |
|---|---|---|
| `STANDALONE` | You own the checkout. | Gate once, then push `origin/main` yourself. |
| `SHARED_CHECKOUT_LANE` | You share the checkout with other agents. | Commit on your lane branch. Never push. The orchestrator merges. |

The native leaf `build/bin/z23-dev dev agent start` is landing now. It prints situation, rules, base, dirty counts, and next commands. Until it lands, read docs/work/agent-protocol.md.

## Read in this order

| # | Document | What it gives you |
|---|---|---|
| 1 | AGENTS.md | Durable product direction and authority boundaries. Read first. |
| 2 | docs/DEVELOPING.md | Workflow, tests, push procedure. |
| 3 | docs/work/agent-protocol.md | Startup and completion ritual for a shared checkout lane. |
| 4 | docs/agent/LANE_LAUNCH.md | How an orchestrator launches a lane. |
| 5 | docs/agent/LANE_QUICKSTART.md | The short lane start. |
| 6 | docs/agent/LANE_REPORT.md | The required report shape. |
| 7 | docs/agent/LESSONS.md | Measured lessons. |

Five more documents are being written in parallel. Cite them even before they land. docs/work/AGENT_SYNC_PLAN.md is the plan that ties them together.

| Document | What it gives you |
|---|---|
| docs/agent/FLASH_UNIT.md | Contract for one-file flash units. |
| docs/agent/EXECUTOR_HEURISTICS.md | Which model gets which unit, measured. |
| docs/agent/NATIVE_CHANNEL.md | How agents on different nodes find each other. |
| docs/agent/TRAIN_PROTOCOL.md | Landing on main as a state machine. |
| docs/agent/UNIT_DISPATCH.md | Run a unit through the C23 harness. |
| docs/work/AGENT_SYNC_PLAN.md | The plan that ties them together. |

## Ask the checkout

These five commands answer questions in milliseconds and need no running node.

| Question | Command |
|---|---|
| What subcommands does `discover` list? | `build/bin/z23-dev discover help` |
| Which tests are registered for a file? | `build/bin/z23-dev code tests --input='{"path":"<file>"}'` |
| Which room owns a file? | `build/bin/z23-dev code room --input='{"path":"<file>"}'` |
| What is the impact of a set of files? | `build/bin/z23-dev agentimpact <files...>` |
| Is this checkout ready for an agent? | `build/bin/z23-dev dev agent ready` |

## Rules that stand

| Rule |
|---|
| Never `git stash`. A stash is shared across worktrees. |
| Never push any ref but `main`. |
| Never force-push. |
| Never skip the push gate. |
| No Python, no jq, no external dependencies. |
| Write scratch under `build/scratch/` only. |
| Sign every commit. |
| Count results, not activity. |
