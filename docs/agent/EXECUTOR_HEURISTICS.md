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

A Muse unit is not done until a finisher has run (finish-or-remove, commit signed).

## Structural rules

Verified on this checkout:

- Stack pick loops fail on regenerated files (inventory, API reference). Regenerate once on the stack.
- A lane whose base is more than 10 commits behind main needs a rebase before stacking. Pointers: lane launch docs/agent/LANE_LAUNCH.md; worktree init tools/scripts/worktree_init.sh; worktree GC tools/scripts/worktree_gc.sh.
- One proof per box means finished stacks are batched.
- Lint gates red on main go into the per-box baseline before relint. Never raise a baseline to turn a gate green.

## Routing rule

Route by the story's next beat, not by author. This table is GENERATED from
`engine/composition/fleet_facts.def`, which is where a routing fact is written
and the only place `z23 dev know` reads. Do not edit it here; change the row
and run `make docs-executor-routing`. Ask it directly instead of reading it:

```
z23 dev know --subject=sonnet
z23 dev know --subject=glm-5.3-flash --relation=handles_poorly
```

<!-- FLEET-FACTS-ROUTING-BEGIN -->

| Executor | Relation | Object | Why |
| --- | --- | --- | --- |
| glm-5.3 | handles_well | audit-only | answers is-this-stale honestly, including an honest negative result |
| glm-5.3 | handles_well | scoped-implementation | takes a brief that invites planning, which the flash tier cannot |
| glm-5.3-flash | handles_poorly | multi-file-implementation | writes outside the worktree, merges a foreign branch into its lane, rewrites a whole file when asked for one row |
| glm-5.3-flash | handles_well | single-file-pinned-test | one file, one registered group that actually runs, and a per-file change ceiling |
| glm-5.3-flash | requires | pinned-test | a registered group in tools/dev/test_group_catalog.def that runs, not a test file that merely exists |
| haiku | handles_well | mechanical-rows | row edits, doc counts, log triage; state the commit trailer literally or it goes missing |
| muse | handles_well | long-wall-implementation | the only tier given a two-hour wall; specify interfaces (file, flags, error names, fixtures), never goals |
| muse | requires | finisher | a unit is not done until a finisher has run, because the wall expires with the work uncommitted |
| opus | handles_well | hard-implementation | deep debugging and design judgement; read its refusal, a brief that duplicates a landed subsystem is correctly declined |
| sonnet | handles_well | finishing-rebase | finishes an unfinished unit and resolves a rebase conflict; the brief must forbid git stash explicitly |
| sonnet | handles_well | gate-fixing | give it the exact gate name; a gate is never turned green by raising a baseline |
| sonnet | handles_well | scoped-implementation | one well-scoped change with a named test group and a stated acceptance bar |
| sonnet | handles_well | verification | reads a diff, runs the named gates, answers LAND or HOLD; keep it in the foreground, it stalls waiting on a background notification |

<!-- FLEET-FACTS-ROUTING-END -->

Notes:

- Flash gets one-file units with a pinned test and nothing else.
- A pinned test is a registered test group that actually runs; group catalogue: tools/dev/test_group_catalog.def.
- Every brief carries NEVER git stash; briefs: docs/work/agent-protocol.md.

## Observed routing

This table is GENERATED from `engine/composition/fleet_observations.def`,
which `tools/dev/fleet_observe.c` generates from the experiment ledger — a
MEASURED table, distinct from the DOCTRINE one above. Do not edit it here;
regenerate the .def and run `make docs-executor-routing`. Ask it directly:

```
z23 dev know --subject=grok --relation=routable_for
z23 dev know --subject=glm --relation=probe_for
```

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

## 2026-09-04 receipt audit

Source: every receipt.json (and its gate.log/task.txt) under
`~/.local/state/zclassic23/engine/*/a*/`, dispatched through
`build/bin/zclassic23-engine-unit`, 01:50Z-06:17Z. 33 receipts total, all
engine "glm" (30 model=glm-5.3-flash, 3 model=glm-5.3).

Verdict counts: PASS 3, REFUSED 12, UNVERIFIED 11, FAIL(NO-CHANGE) 7.

Cause classification (read from gate.log/task.txt, not guessed from the
verdict string):

| Cause | n | Basis |
| --- | --- | --- |
| HARNESS | 10 | REFUSED units whose gate.log holds only "Entering directory" / "build-epoch-session: acquired ..." / "Leaving directory" — no compiler output, no verdict line. All 10 ran 02:51Z-04:07Z, before the gate-stderr-capture fix (this branch's 6a675e44a, landed 04:35Z). Units: ceiling/a1, ceiling/a2, claim/a1, done/a1, done/a2, pace/a1, pace/a2, rules/a2, start/a1, triage/a2. |
| ENV (build-epoch race) | 2 | REFUSED units whose gate.log shows `build-epoch-session: compiler/toolchain changed during build expected=... actual=...` followed by `make: *** Error 2`. Both ran 05:52Z-06:17Z, after the stderr-capture fix but before the epoch-race fix (lane/epoch's 39ec3f5c3, landed 06:33Z, not yet on this branch). Units: mailfix/a2, queuefix/a2. |
| ENV (no group, by design) | 11 | UNVERIFIED units, all `kind: doc-claim` or otherwise dispatched with no test group (task.txt has no GATE COMMAND / files_changed=1, group=""). engine_verdict_of() returns UNVERIFIED for exactly this case; it is not a defect. Units: agentreadme/a1, channel/a1, flashunit/a1, heuristics/a1, ladder/a1, lessons/a1, protocol/a1, syncplan/a1, tickets/a1, train/a1, tuner/a1. |
| UNKNOWN | 7 | FAIL(NO-CHANGE) units (wf-arm_symbol_single/a1, wf-byte_order_codec_single/a1, wf-capability_closure/a1, wf-clang_portability/a1, wl-doc-inline-paths/a1, wl-hex-codec-single/a1, wl-no-raw-clock-outside-platform/a1). files_changed=0, completion_tokens 605-919 (short). No reply.txt exists for any of them — the raw-reply archive (dd83bdf91) landed 06:56Z, after every one of these runs (05:22Z-05:33Z) — so the model's actual text cannot be read back to tell a legitimate "the assertion is right, I change nothing" refusal (which the prompt explicitly allows) from a lost edit. |
| PASS (no defect) | 3 | claim/a2, nothink/a1, situation/a1 — gate.log ends in the literal `ALL TESTS PASSED` token with 0 groups_failed. |

Full row-by-row table: build/scratch/receipt_audit.tsv (not checked in;
regenerate from the same state directory).

Two harness defects were confirmed and fixed against this table:

1. A model wraps a whole-file envelope body in a Markdown code fence even
   though the protocol text says not to; `engine_patch_parse()` wrote the
   fence lines into the file verbatim. Fixed: `engine_patch.c` now strips
   one bare opening and one bare closing fence line when they are the
   first/last line of the body (commit dd4033f78).
2. A build-epoch race ("compiler/toolchain changed during build") reached
   the model as an unqualified REFUSED. Fixed: `engine_gate_read()` now sets
   `env_epoch_race` on that exact log line, and `tools/engine_unit.c` retries
   the gate once, on the same diff, before computing a verdict.

The 10-unit log-capture gap and the 11-unit no-group UNVERIFIED path were
each already fixed or already correct by design before this audit; no
further harness change was needed for them. The 7-unit UNKNOWN group could
not be resolved from these receipts because they predate the reply.txt
archive; a future run of the same task kinds, on a binary carrying
dd83bdf91, will have the raw text to classify.

Two more harness defects were confirmed live (post-dd83bdf91 receipts, with
reply.txt/applied.txt/state.txt) and fixed the same day, from state dirs
`~/.local/state/zclassic23/engine/glm53-ramlease/a1` and
`~/.local/state/zclassic23/engine/cmp-capability_closure-glm53/a1`:

3. `glm53-ramlease/a1` (model glm-5.3): turn 1 overwrote
   `tests/harness/src/test_impact_composition.c` (1,850 lines) with a
   partial whole-file body and changed `platform_ram_scratch_root`'s
   signature elsewhere. Turn 2 had no way to read the damaged file back and
   correctly refused: "leftovers from an earlier whole-file overwrite of
   the test I cannot read back ... I refuse to fabricate the full
   ~1850-line file", ending `next: Operator: restore or paste ...`. Fixed
   two ways: `engine_patch_is_drastic_shrink()` now refuses, before
   anything is written, a whole-file body under half the on-disk file's
   line count (commit 5f62b643f); and `engine_state_next_is_operator()` now
   surfaces a `next: Operator: ...` line as `needs_operator=true` at the
   top of receipt.json instead of leaving it buried in state.txt (commit
   9a0928280). Cause: HARNESS.
4. `cmp-capability_closure-glm53/a1` (model glm-5.3): the task brief named
   two ~1,090-line registries and quoted 5 lines of them combined, asking
   for one-line edits as whole-file envelopes; the unit has no shell and no
   read access. All 3 turns were FAIL(NO-CHANGE), ending "next: dispatcher
   must paste the full current contents of
   engine/composition/capability_symbols.def and
   engine/composition/module_capabilities.def (or grant read)". Fixed:
   `build_task_with_file_contents()` now scans the task text for tokens
   that pass `engine_patch_looks_like_a_path()` and exist under the
   prepared worktree, and appends each one's current content before the
   first turn is dispatched (commit d9dfe0751). Cause: HARNESS. Not done in
   this pass: re-running that scan on turns after the first, so a unit can
   read back its own prior turn's edits — the other half of the
   glm53-ramlease/a1 failure. The one-time scan at dispatch covers a task
   that never gave file contents at all; per-turn read-back is the next
   increment.
