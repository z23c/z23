# Agent sync plan — every agent on one board, one target, one typed protocol

This document is the handoff plan for the next developer.

Goal: every agent, human or model, on any fleet box, sees the same small typed state, uses the same few verbs, and gets green work onto `main` in minutes. Nothing in the protocol blocks. Every step is a state transition recorded as an event. Every verdict comes from a gate, never from a report.

Measured on 2026-09-04 from node1. Recheck each number before acting; these are dated observations, not invariants.

## 1. Where it stands

| Fact | Value |
|---|---|
| Linked worktrees on node1's checkout | 214 |
| Local branches other than `main` | 190 |
| Documents an agent reads before its first commit | 4 |
| Push-hook proof cost | 15 to 45 min per train, one proof per box |
| Trains | one per box per round, alternating by board claim/result |
| Fleet board | JSONL per host, ssh sync every 2 min (interim); native `zcode fleet say/read` is node2's lane |
| Native agent channel | `msg_send` / `msg_inbox` over the onion mesh, verified node1 to node2 2026-09-04 |
| GLM flash through opencode on node1 | 0 of 40 logs contain an edit; exit code is 1 on every run, success or not |
| GLM flash through the C23 harness | HTTPS probe 200 in 1.4 s through the tree's own TLS client |

## 2. Architecture

Three planes. All typed. None blocking.

**Facts plane.** A leaf answers a question from the tree or the checkout in milliseconds and writes nothing: situation, rules, base, dirty state, owning tests. This is `dev agent *` (node1) and `zcode fleet status` (node2).

**Event plane.** Every claim, result, problem, and train transition is one signed append-only row. Agents subscribe and wake; nobody polls. Today: the JSONL board. Target: `zcode fleet say/read` over the peer wire (node2), and `msg_send` for point-to-point.

**Verdict plane.** Gates decide. A unit's outcome is the receipt written by `zclassic23-engine-unit` after it ran the owning test group cold; a train's outcome is the proof receipt. A model's own report is never evidence.

### The train state machine (fleet-wide, one instance per base)

```
IDLE --claim train <base>--> PROVING --push ok--> LANDED --result train <tip>--> IDLE
                                 |--base moved--> REBASE --> PROVING
                                 |--gate red---> WITHDRAWN --result train withdrawn--> IDLE
```

Exactly one node holds PROVING for a given base. A node that sees a live claim does not start a proof. Every transition is a board row. This is what "push main together" means in practice: node2 lands, posts result, node1 claims the new tip, lands, posts result, and so on. A train carries at most 4 lanes. A 1000-file train was withdrawn on 2026-09-04: impact planning alone cost an hour, and every push invalidated it.

### The unit state machine (per one-file unit, fully async)

```
COMPOSED --dispatch (systemd unit)--> RUNNING --receipt--> PASS | FAIL | TIMEOUT
FAIL --attempt+1 with gate log in the task, max 3--> COMPOSED
PASS --> VERIFIED (diff touches one file, ceiling ok, signed) --> TRAIN
```

The orchestrator never waits on a model. It dispatches, returns, and is woken by the receipt file. A unit gets three attempts, then a finisher (Sonnet) or a drop.

## 3. The verbs, as C23 leaves under the existing `dev.agent` branch

| Leaf | Answers | Writes |
|---|---|---|
| `dev agent situation` | standalone or shared checkout lane, by the decidable git test | nothing |
| `dev agent rules` | the rule rows for that situation from `engine/composition/agent_rules.def` | nothing |
| `dev agent start` | situation + rules + base head + dirty counts + hooks + next commands | nothing |
| `dev agent claim` | refuses file overlap with a live claim from another worktree | `<git-common-dir>/z23-agent-claims.jsonl` |
| `dev agent done` | ready to hand off: clean, ahead, signed, not on main | nothing |
| `dev agent triage` | every local branch binned land / rebase / delete | nothing |
| `dev agent ceiling` | refuses unrequested files, rewrites, and over-ceiling diffs | nothing |
| `dev agent pace` | tool calls before first edit, edits, commits, verdict for a unit log | nothing |

The rules table is one X-macro file. Documents cite it; they do not restate it. Fleet-wide claims and posts stay on node2's `zcode fleet say/read`. These leaves are checkout-local facts and refusals.

## 4. How a flash unit is run

1. Scaffold first, by a strong model: declaration, prototype, stub with the full contract in its header, pinned test group. The stub compiles and returns NOT_IMPLEMENTED. The test is red.
2. The unit's task file is composed mechanically: the stub, the test, the reply pattern from a neighbouring handler, the spawn API (`platform/modules/util/include/util/spawn.h`), and on retry the previous gate log. Around 20 KB. The model sees nothing else.
3. Dispatch through `zclassic23-engine-unit --engine glm --model glm-5.3-flash --group devagent_<leaf>` in its own transient systemd unit with a CPU quota. The harness applies the whole-file envelope to an isolated worktree and runs `make t-fast-exact ONLY=<group>` cold.
4. The verdict is the receipt. Then `dev agent ceiling` checks the diff: exactly one file, no rewrite of a foreign file, no unrequested file.
5. Outcome rows feed the executor heuristics. Flash is routed only to one-file units with a pinned test.

Why not opencode: 40 headless runs on node1 produced no edit marker in any log, and exit code 1 on every run regardless of outcome. The exit code and the transcript carry no verdict. The harness does.

## 5. Steps and bars

1. Land the eight leaves (this lane) and `ZCL_PROOF_TIMEOUT_MS`. Bar: every `devagent_*` group green on `main`.
2. Retire the prose: `docs/work/agent-protocol.md`, `docs/agent/LANE_LAUNCH.md`, and `docs/agent/LANE_REPORT.md` shrink to "run `dev agent start`" plus the why. Bar: a fresh Haiku unit given only that output commits a green one-file change, five of five.
3. Train protocol in code: `zcode land` (node2's lane) posts the state transitions above itself. Bar: a lane that is lint-fast green at claim time reaches `main` in under 5 minutes, ten times running.
4. Worktree hygiene: `dev agent done` marks a worktree reclaimable; an hourly timer applies `tools/scripts/worktree_gc.sh`. Bar: under 30 worktrees for a week untouched.
5. `fleet bottlenecks` names the constraint hourly on the front page.

## 6. Do not relearn

- Origin has one branch, `main`. No GitHub issues, no board on a branch.
- Never `git stash`, `add -A` mid-rebase, `cherry-pick -q`, `--no-verify`, `ZCL_SKIP_PREPUSH=1`.
- Hooks are per worktree; submodules are not inherited; prime before build.
- Ask the checkout: `z23-dev code tests`, `code room`, `dev agent start`.
- No Python, no Rust, no jq, no external deps, no `/tmp`.
- Never IPs, keys, tunnels, or private onions on the board.
- Count results, not activity: a unit that changed nothing is a failure.

## Companion documents

Written in parallel with this plan:

| Document | Content |
|---|---|
| `docs/agent/FLASH_UNIT.md` | The contract for one-file flash units. |
| `docs/agent/EXECUTOR_HEURISTICS.md` | The measured executor routing table. |
| `docs/agent/NATIVE_CHANNEL.md` | How agents on different nodes find each other. |
| `docs/agent/TRAIN_PROTOCOL.md` | The landing state machine. |
| `docs/agent/UNIT_DISPATCH.md` | The operator runbook for the harness. |
