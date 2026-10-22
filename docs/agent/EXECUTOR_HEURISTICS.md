# Executor heuristics

This document is the measured routing table for executors: which model gets which unit kind, with the failure modes recorded during one orchestration day on node1, 2026-09-03.

## Purpose

Executors fail in different ways. This table records what each model was given on the recorded day, what failed, and the countermeasure applied. The sample is one day, so n is small: read every row as a prior, not as a steady-state measurement. The structural rules are verified on this checkout. The routing rule turns the table into a default decision.

## The table

n is units dispatched on the recorded day. A row can record incidents and still show every unit finishing clean: Sonnet verification stalled 3 times waiting for a background notification, and 14 of 14 finished clean.

| Model | Task kind | n | Finished clean | Failure mode | Countermeasure |
| --- | --- | --- | --- | --- | --- |
| Muse (high) | implement, 2 h wall | 9 | 3 | timeout at 7200 s with all work uncommitted; builds machinery around a key that does not exist | always follow with a finisher (finish-or-remove, commit signed); specify interfaces — file, flags, error names, test fixtures — not goals |
| Opus | hard implementation | 5 | 4 | API overload stalls; 1 correctly refused a brief that duplicated a landed subsystem; 1 used git stash and unpacked another lane's stash (recovered) | resume after a stall; read the refusal, it was right; every brief must say NEVER git stash |
| Sonnet | verifier (LAND/HOLD) | 14 | 14 | 3 stalled waiting for a background notification | prompt: foreground Bash only |
| Sonnet | finisher / rebase / conflict | 8 | 8 | 1 used git stash | forbid stash explicitly |
| Sonnet | gate fixer (lint) | 8 | 8 | — | give the exact gate name; never raise a baseline |
| Haiku | mechanical (rows, doc counts) | 3 | 3 | trailers sometimes missing | state the trailer literally |
| GLM 5.3 | implement | 3 | 1 | vendor server errors (2) | retry once; else escalate |
| GLM 5.3 | audit-only (is this stale?) | 1 | 1 | — | good at honest negative results |
| GLM 5.3 flash | multi-file | 10 | 0 | jq use; writes outside the worktree auto-rejected; merged a foreign branch into its lane; server errors; read-heavy then connection drop | route flash ONLY to one-file units with a pinned test |
| GLM 5.3 flash | single-file mechanical with pinned test | 2 | 2 | rewrote a whole file when asked for one row | per-file change ceiling before apply; first edit early |

In the recorded 2026-09-03 experiment, a Muse unit required a separate finisher
before it was counted complete. That historical arrangement does not require
a permanent central role; current completion uses exact checkpoints,
non-author review, and qualified native acceptance.

## Historical structural observations

These observations describe the recorded 2026-09-03 workflow. Current
ownership, resource limits, exact proof reuse, and landing eligibility come
from AGENTS.md, DEVELOPING.md, host policy, and qualified native receiver
state; they do not depend on the model or a permanent lead.

- Stack pick loops conflict on the two tracked generated docs (the CODEBASE_MAP counts, the routing table above). Take either side, then run `make fix-doc-counts` and `make docs-executor-routing` once on the stack; the inventory and API reference are build output and cannot conflict.
- Revalidate a lane against the exact current base through the native landing
  route; commit distance alone does not determine safety or required work.
- Native proof/build locks and `devbuild --wait` bound work. Do not infer a
  fleet-wide proof monopoly or publication authority from a historical box rule.
- Report gates red on main with their exact inputs and evidence. Never hide
  them in a per-box baseline or raise a pin to turn a gate green.

## Routing rule

Route by the story's next beat, not by author. This table is GENERATED from
`engine/composition/fleet_facts.def`, which is where a routing fact is written
and the only place `z23 dev know` and `z23 dev fleet mind ask executor_for`
read routing facts. Do not edit it here; change the row and run
`make docs-executor-routing`. Ask it directly instead of reading it:

```
z23 dev know --subject=sonnet
z23 dev know --subject=glm-5.3-flash --relation=handles_poorly
z23 dev fleet mind ask executor_for sonnet
z23 dev fleet mind ask trap_of test_boot_phase
```

<!-- FLEET-FACTS-ROUTING-BEGIN -->

| Executor | Relation | Object | Why |
| --- | --- | --- | --- |
| glm-5.3 | handles_well | audit-only | answers is-this-stale honestly, including an honest negative result |
| glm-5.3 | handles_well | scoped-implementation | takes a brief that invites planning, which the flash tier cannot |
| glm-5.3-flash | handles_poorly | multi-file-implementation | writes outside the worktree, merges a foreign branch into its lane, rewrites a whole file when asked for one row |
| glm-5.3-flash | handles_well | single-file-pinned-test | one file, one registered group that actually runs, and a per-file change ceiling |
| glm-5.3-flash | requires | pinned-test | a registered group in tools/dev/test_group_catalog.def that runs, not a test file that merely exists |
| grok | handles_poorly | seam-finding | a brief that says find where X is registered burns every round; name the seam yourself (file, function, table row) before queueing |
| grok | handles_well | gate-port-pair | two small self-contained lint gates in one job land in one round at the cost of one; pair gates that source no helper script and pin both output strings |
| grok | handles_well | single-file-pinned-test | one function, one table row, one test: the lint-gate ports and the bip page cache each landed in one round; brief it with file:line, the literal output strings, and the mutation check |
| grok | requires | finisher | a rounds-exhausted verdict is judged, not trusted: rerun the judged group in the unit worktree first; two of two such verdicts were stale judge logs over a fix already committed |
| haiku | handles_well | mechanical-rows | row edits, doc counts, log triage; state the commit trailer literally or it goes missing |
| muse | handles_well | long-wall-implementation | the only tier given a two-hour wall; specify interfaces (file, flags, error names, fixtures), never goals |
| muse | requires | finisher | Historical 2026-09-03 experiment: a separate finisher completed timed-out units; current completion requires exact checkpoints and non-author acceptance, not a permanent central role |
| opus | handles_well | hard-implementation | deep debugging and design judgement; read its refusal, a brief that duplicates a landed subsystem is correctly declined |
| sonnet | handles_poorly | fixture-line-reading | a verifier reading a gate's selftest transcript reports the fixture's FAIL lines as a red gate although the exit is zero; the brief says only the exit and the final summary line count, and names the fixture lines in advance |
| sonnet | handles_well | finishing-rebase | finishes an unfinished unit and resolves a rebase conflict; the brief must forbid git stash explicitly |
| sonnet | handles_well | gate-fixing | give it the exact gate name; a gate is never turned green by raising a baseline |
| sonnet | handles_well | scoped-implementation | one well-scoped change with a named test group and a stated acceptance bar |
| sonnet | handles_well | verification | reads a diff, runs the named gates, answers LAND or HOLD; keep it in the foreground, it stalls waiting on a background notification |

<!-- FLEET-FACTS-ROUTING-END -->

Notes:

- Flash gets one-file units with a pinned test and nothing else.
- A pinned test is a registered test group that actually runs; group catalogue: tools/dev/test_group_catalog.def.
- Every brief carries NEVER git stash; briefs: docs/agent/agent-protocol.md.

## Observed routing

This table is GENERATED from `engine/composition/fleet_observations.def`,
which `tools/dev/fleet_observe.c` generates from the experiment ledger — a
MEASURED table, distinct from the DOCTRINE one above. Do not edit it here;
regenerate the .def and run `make docs-executor-routing`. Ask it directly:

```
z23 dev know --subject=grok --relation=routable_for
z23 dev know --subject=glm --relation=probe_for
```

### Ledger columns

`tools/dev/fleet_observe.c` reads the experiment ledger
(`$XDG_STATE_HOME/zclassic23/experiments/rows.tsv`, or
`~/.local/state/zclassic23/experiments/rows.tsv`), a tab-separated file, 22
columns per row, one row per predict/result. This is the closed vocabulary a
row is checked against; a value outside it, or a row missing a column, is a
malformed ledger, refused by line number:

| # | Column | Closed vocabulary / format |
| --- | --- | --- |
| 0 | ts | ISO-8601 UTC, e.g. `2026-09-05T11:40:56Z` |
| 1 | kind | `predict`, `result` |
| 2 | box | free text (hostname/box id) |
| 3 | task_id | free text |
| 4 | task_class | `read`, `verify`, `unit_docs`, `unit_c23_one_file`, `lane_multi_file`, `rebase_land`, `diagnose`, `land_train`, `unknown` |
| 5 | story | free text |
| 6 | executor | `claude-fable`, `claude-opus`, `claude-sonnet`, `claude-haiku`, `grok`, `glm`, `codex`, `muse`, `mac` |
| 7 | harness | free text (e.g. `agent-tool`) |
| 8 | model | free text (e.g. `sonnet`) |
| 9 | effort | free text (e.g. `medium`) |
| 10-16 | token/turn/wall ints | seven integers |
| 17 | outcome | `LAND`, `FIX_LAND`, `FIX`, `HOLD`, `READY`, `blocked`, `timeout`, `wrong`, `landed`, `failed`, `unknown` |
| 18-20 | lines_added / lines_removed / defects | integers |
| 21 | note | free text |

The vocabulary lives in code as `k_task_classes`, `k_executors`, `k_kinds`
and `k_outcomes` in `tools/dev/fleet_observe.c`; this table is the prose
mirror an operator reads.

<!-- FLEET-OBSERVATIONS-BEGIN -->

| Executor | Relation | Task class | n | window (days) |
| --- | --- | --- | --- | --- |
| claude-haiku | probe_for | diagnose | 0/1 | 7 |
| claude-opus | routable_for | lane_multi_file | 3/3 | 7 |
| claude-sonnet | observed_for | rebase_land | 3/4 | 7 |
| claude-sonnet | routable_for | verify | 10/10 | 7 |
| glm | probe_for | unit_c23_one_file | 0/1 | 7 |
| glm | observed_for | verify | 2/3 | 7 |
| grok | handles_with_finisher | unit_c23_one_file | 2/3 | 7 |
| grok | routable_for | unit_c23_one_file | 3/3 | 7 |
| grok | probe_for | unit_docs | 2/2 | 7 |
| mac | refused_for | land_train | 0/2 | 7 |
| muse | observed_for | lane_multi_file | 1/6 | 7 |

<!-- FLEET-OBSERVATIONS-END -->

## How to update this table

- Append a row with the count and the date.
- Never delete a measured row.
- State the source of a new count: the command that produced it, or the recorded run.
- If a note and a count in a row disagree, keep the row as measured, record both readings, and re-derive before merging them. As received, the Muse row carried the note "both clean runs had fully specified interfaces" against 3 finished clean; this copy withholds the count word until that number is re-derived. The interface rule itself stands: specify interfaces (file, flags, error names, test fixtures), not goals.

## Receipt causes and harness behavior

A receipt verdict is classified from `gate.log` and `task.txt`, not from the
verdict string. Causes: HARNESS (a REFUSED unit whose gate log holds only make
"Entering/Leaving directory" lines and no compiler output), ENV (a build-epoch
race, or a unit dispatched with no test group, which `engine_verdict_of()`
returns UNVERIFIED for by design), UNKNOWN (a FAIL(NO-CHANGE) unit whose raw
reply is not archived), and PASS (the gate log ends in `ALL TESTS PASSED` with
0 groups_failed).

The harness behaves as follows:

1. `engine_patch.c` strips one bare opening and one bare closing Markdown fence
   line when they are the first and last line of a whole-file envelope body.
2. `engine_gate_read()` sets `env_epoch_race` on a "compiler/toolchain changed
   during build" log line, and `tools/engine_unit.c` retries the gate once on
   the same diff before computing a verdict.
3. `engine_patch_is_drastic_shrink()` refuses, before anything is written, a
   whole-file body under half the on-disk file's line count.
4. `engine_state_next_is_operator()` surfaces a `next: Operator: ...` line as
   `needs_operator=true` at the top of `receipt.json`.
5. `build_task_with_file_contents()` scans the task text for tokens that pass
   `engine_patch_looks_like_a_path()` and exist under the prepared worktree, and
   appends each one's current content before the first turn. Open: repeating
   that scan on later turns so a unit can read back its own prior edits.
