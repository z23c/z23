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
