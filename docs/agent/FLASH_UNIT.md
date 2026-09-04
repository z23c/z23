# Flash unit contract

This document is the contract for a one-file unit given to GLM 5.3 flash and judged by the tree's own harness.

## Purpose

A flash unit is one mechanical file edit with a pinned test. The worker model is GLM 5.3 flash. Dispatch and judgement go through the tree's own unit harness, `tools/engine_unit.c`, built as `build/bin/zclassic23-engine-unit`. The verdict is the receipt, `receipt.json` in the `--state-dir`. The model's own report is not evidence. This document states what flash finishes and does not finish, how a unit is composed, how it is dispatched and judged, the retry policy, the acceptance checks after a PASS receipt, and the rules the model must follow.

## What flash is good at and not

Every count below is a runtime record of runs on node1, 2026-09-03/04. These counts come from those runs; no command in this tree re-derives them.

| Subject | Count | Reading |
| --- | --- | --- |
| Multi-file tasks | 0 of 10 finished | Flash does not finish multi-file work. |
| Single-file mechanical tasks with a pinned test | 2 of 2 finished; each commit verified by the gate | This is the only task shape flash is known to finish here. |
| Headless `opencode` runs on node1 | 40 runs; no run's log contains an edit; exit code 1 on every run, pass or fail | A chat-session dispatch produces no edits. Exit code and transcript carry no verdict. |
| Prompt: add one table row | Row added correctly; whole file rewritten: +35/-173 lines; the header doctrine comment removed | Flash rewrites whole files. A per-file change ceiling is required before an envelope is applied. |
| Read-heavy task | About 2,000 lines of tool output read; the vendor then dropped the connection before any edit | Read-heavy tasks never reach an edit. Do not dispatch them to flash. |
| Units dispatched with no registered test group | 15 of 24 units ran zero groups | A unit with no group that runs can never leave UNVERIFIED. Confirm the group is registered in `tools/dev/test_group_catalog.def` before dispatch. |
| Retry after a REFUSED with the gate log tail re-attached | 5 of 5 returned REFUSED again | Retrying a refused unit with a gate log tail produces another refusal, not a repair. |

## Measured outcomes

Unit receipts, newest last, 2026-09-04. Verdicts come from `receipt.json` in each unit's `--state-dir`; no command in this tree re-derives them.

| Verdict | Model | Units |
| --- | --- | --- |
| PASS | glm-5.3-flash | 3 (situation/a1, nothink/a1, claim/a2) |
| UNVERIFIED | glm-5.3-flash | 8 (agentreadme/a1, channel/a1, flashunit/a1, heuristics/a1, syncplan/a1, protocol/a1, tuner/a1, lessons/a1) |
| UNVERIFIED | glm-5.3 | 3 (ladder/a1, train/a1, tickets/a1) |
| REFUSED | glm-5.3-flash | 6 (pace/a1 why: rate_limited; rules/a2; pace/a2; triage/a2; done/a2; ceiling/a2) |
| NO_RECEIPT | (none recorded) | 8 (dispatch/a1, done/a1, ceiling/a1, rules/a1, claim/a1, start/a1, triage/a1, start/a2) |

Of the 28 units, 20 produced receipts; 8 produced no receipt at all. Of the 28 records, 6 carry `rate_limited` or an empty refusal in `why` (pace/a1, done/a1, ceiling/a1, rules/a1, claim/a1, start/a1). Every PASS unit changed exactly 1 file and ran exactly 1 group with 0 failures. Every other unit ran a groups_ran of zero. A unit dispatched with no test group cannot be verified; its receipt stays UNVERIFIED regardless of what the reply looks like. Every unit needs a registered test group that actually runs.

Recurring refusal pattern: after a retry with the previous attempt's gate log tail, five units (rules/a2, pace/a2, triage/a2, done/a2, ceiling/a2) returned REFUSED instead of an edit. Retrying a refused unit with a gate log tail produces another refusal, not a repair.

Recurring gate failures in this batch: `check-doc-counts` failed on doc-count drift (tuner/a1), and `check-doc-inline-paths` failed on backticked Markdown paths that do not exist (protocol/a1). A document edit must re-derive any count it changes, and must cite only paths present in the tree.

## How a unit is composed

The prompt is one task file, at most 128 KB, about 20 KB in practice. It contains:

| Component | Content and role |
| --- | --- |
| Stub file | The full contract for the task sits in its header comment. |
| Pinned test file | Read-only. It defines done. |
| Reply-pattern excerpt | A neighbouring handler shows the whole-file envelope reply pattern. |
| Spawn API | `platform/modules/util/include/util/spawn.h`. `zcl_spawn_capture` is the only allowed way to run a process. |
| Gate log tail | Present on retry only: the tail of the previous attempt's gate log. |

## How it is dispatched and judged

| Step | Fact |
| --- | --- |
| Harness | `tools/engine_unit.c`, binary `build/bin/zclassic23-engine-unit`. |
| Prompt | One prompt per attempt. The task file is the prompt. Maximum 128 KB. |
| Reply format | Whole-file envelopes: `Z23-BEGIN-FILE path`, the complete file contents, `Z23-END-FILE`. |
| Apply | The harness applies the envelopes to an isolated git worktree. |
| Test | `make t-fast-exact ONLY=<group>`, run cold. |
| Consent | `--yes-dispatch` is required on every run. |
| Repair turns | `--turns` are repair turns for replies that do not apply. |
| Verdict | The receipt, `receipt.json` in the `--state-dir`. Never the model's report. |

## Retry policy

| Item | Policy |
| --- | --- |
| Attempts | At most 3. |
| Each retry | The prompt includes the previous attempt's gate log tail. |
| After 3 attempts | The unit goes to a stronger model, or is dropped. |
| After a REFUSED | Do not re-dispatch the same unit to flash with the same gate log tail. Escalate or drop. |

## Acceptance after PASS

A PASS receipt is accepted only when every check below holds.

| Check | Requirement |
| --- | --- |
| Diff scope | The diff touches exactly the one named file. |
| Unrelated files | No rewrite of an unrelated file. |
| Unrequested files | No unrequested file. |
| Commit | Signed by the orchestrator. |

## Rules for the model

The prompt states these rules. The model must:

1. Edit exactly one named file.
2. Treat the test file as read-only.
3. Never relax an assertion.
4. Use C23. No VLAs. No external dependencies. No Python. No jq.
5. Run processes, including git, only through `zcl_spawn_capture` from `platform/modules/util/include/util/spawn.h`.
6. Make the first edit early.
7. Finish fewer files completely rather than truncate a reply.
8. Re-derive every count you change in a document; do not restate a stale number.
9. Cite only file paths that exist in the tree; never invent a path in backticks.
10. Stop at the first REFUSED verdict and do not produce a second reply for the same prompt.
   (predicted: reduces the repeat-refusal class, 5 of 5 retry-after-REFUSED units returned REFUSED again; regresses rules, pace, triage, done, ceiling retry units)

## How to approach it

Re-derive every count you touch from the tree itself and say which command produced it.

## Dispatch through `dev agent queue`

Dispatch goes through the typed leaf `dev agent queue`, never through
shell scripts.

### Verbs

| Verb | Effect |
| --- | --- |
| `dev agent queue post --kind=<leaf\|doc\|file\|fix-gate> --name=<n>` | Appends one durable row and returns its sequence number at once. |
| `dev agent queue next` | Takes the oldest queued row, finds a free warm worktree in the pool, and launches the harness detached. Returns the run or `no_free_worktree` or `empty`. Never waits for the run. |
| `dev agent queue reap` | Records every new receipt as an outcome and requeues a rate-limit refusal with the next attempt number. Returns what it recorded. |
| `dev agent queue status [--json]` | One screen: queued rows, running rows with worktree and age, recent outcomes, pool occupancy. |

Kinds: `leaf` fixes one dev-agent leaf judged by its own group;
`fix-gate` is the same shape for a free-form fix; `doc` writes one document
from a brief with no group; `file` writes one file judged by `--group`.
Doc and file units need `--path` (a repo-relative path) and `--brief` (an
existing file inside the repo or the state dir).

### State

Rows live at `<state>/queue/queue.jsonl`, outcomes at
`<state>/queue/outcomes.jsonl`, the pool list at
`<state>/queue/pool.txt` (one warm worktree directory per line; warm means
the directory carries `.eu-warm`). Runs live at
`<state>/engine/<name>/a<attempt>/` with the verdict in `receipt.json`.
`<state>` is the owner-private platform state root.

### Loop

No verb blocks on a model, a build, or another process. A long-lived loop
is the caller's business: a timer or watcher calling `next` plus `reap`.
Attempts stop after the third; a unit still failing then goes to a stronger
model or is dropped. The harness is `tools/engine_unit.c`; the leaf
implementation is `tools/command/native_devagent_queue.c`, declared in
`engine/composition/commands/dev.def` and proved by
`tests/harness/src/test_devagent_queue.c`.
