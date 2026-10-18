<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Agentic development baselines

Date: 2026-10-18 (UTC). Revision: `d0a7aa0af` unless noted. Environment:
GCC 14.2.0, AMD Ryzen 9 7950X3D, Linux. Method: read-only measurements by
small-model agents. Each section names its source so the result can be
repeated.

## Question

Where does an AI coding agent spend time and tokens in this repository?
Working hypothesis: cost = orientation reading + search noise + large files +
late feedback. Each term was measured once before any change.

## E1 — late landing failures

Source: the landing worktree's proof cache (`.cache/zcl-dev-proof/*.failed`,
309 markers over the queue's history) and queue rows 699–708.

| First line of the failure marker | Count |
| --- | ---: |
| `head_changed_during_proof` | 101 |
| `child_proof_failed_exit_2` | 68 |
| `child_proof_failed_exit_1` | 47 |
| `proof_generated_docs_stale:docs/agent/EXECUTOR_HEURISTICS.md` | 20 |
| `test_accounting_incomplete` | 9 |
| `changed_set_empty` | 7 |
| `remote_base_not_ancestor` | 6 |

On 2026-10-18 two of seven submitted rows failed in the proof on checks the
submit step did not run: an exact doc-text assertion
(`lint_gate_deploy_contracts.c`, row 704) and a duplicated registry root
count (`test_zcode_node_command.c`, row 707). Each failure costs one proof
(about 15 minutes) plus a resubmit.

Finding: the submit step ran lint but no test groups, and `code tests`
already maps a changed path to the groups the proof will run (for example
`.github/CONTRIBUTING.md` → `make_lint_gates`).

## E2 — search noise

Twenty ripgrep queries over a snapshot, honouring the root `.ignore`.

- Median share of hits in generated, vendored or corpus files: **2.6%**
  (range 0–11.5%, outliers `TODO` and `test_group` at 62%).
- Files most often in a query's top five: `test_impact_composition.c`
  (607 KB), `test_zcode_dev_objects.c` (567 KB), `test_fleet_board.c`
  (388 KB), `dev_proof.c` (529 KB), `Makefile` (931 KB), `test_dev_land.c`
  (637 KB).

Finding: generated-file noise is already controlled; the hypothesis is
rejected. Hits concentrate in very large hand-written files.

## E3 — size × churn

Churn = commits touching a file in the last 60 days; score = churn × lines.

| File | Churn | Lines | Score |
| --- | ---: | ---: | ---: |
| `tests/harness/src/test_fleet_board.c` | 20 | 8524 | 170480 |
| `cognition/controllers/include/controllers/agent_impact_rules.def` | 21 | 3424 | 71904 |
| `tools/command/native_fleet_steer.c` | 10 | 6955 | 69550 |
| `tools/command/native_command.h` | 20 | 3289 | 65780 |
| `tests/harness/src/test_command_registry_catalog.c` | 9 | 5943 | 53487 |
| `tools/dev/dev_proof.c` | 4 | 12381 | 49524 |

216 C files exceed the 1500-line ceiling stated in the project doctrine
(vendored headers included).

## E4 — command search

`z23 discover search "<intent>"` on the installed binary, 20 plain-language
intents with a known target leaf: **hit@1 8/20, hit@5 10/20**. Ten intents
returned no result, among them "search the wiki", "open a shell on another
machine", "check fleet health" and "show help for a command".

## E5 — brittle pins

- About 1900 `ASSERT(strstr(...))` lines in six `lint_gate_*_contracts.c`
  files read exact text from about fifteen Markdown documents (upper bound:
  the count includes non-document buffers).
- 160 `claim:` markers in 25 documents assert facts instead of wording.
- The registry root count was pinned in two tests.

Finding: those documents cannot be edited without running the doc-contract
groups, which the submit step did not do.

## Changes made from these results

| Finding | Change | Measure to repeat |
| --- | --- | --- |
| E1 | The maintainer submit step runs every group `code tests` routes from the changed paths before submitting. | late failures per landed row |
| E5 | The duplicated root-count pin is removed. | duplicate pins |
| E4 | Command search ranking is under revision with a 25-intent regression test and 10 held-out intents. | hit@1, hit@5 |
| orientation | `code guide` takes `paths`/`topic` and returns a brief of about 0.9 KB for `tools/command/native_command.c`, against 8 KB of contract documents (120 KB with `docs/DEVELOPING.md`). | E6 |

## Next experiment

E6 replays small landed commits as tasks (task = commit message, base =
parent, acceptance = the commit's focused test groups plus a reviewer's
equivalence verdict) with a small and a mid-size model, with and without the
`code guide` brief. Measures: tokens, wall time, files read, success rate.
