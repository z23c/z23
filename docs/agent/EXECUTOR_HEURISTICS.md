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

Route by the story's next beat, not by author:

| Story's next beat | Route |
| --- | --- |
| pinned-test single file | GLM 5.3 flash |
| scoped implementation with a test group | Sonnet or GLM 5.3 |
| hard concurrency/consensus | Opus |
| verification (LAND/HOLD) | Sonnet |
| anything with a 2 h wall | Muse plus a finisher |

Notes:

- Flash gets one-file units with a pinned test and nothing else.
- A pinned test is a registered test group that actually runs; group catalogue: tools/dev/test_group_catalog.def.
- Every brief carries NEVER git stash; briefs: docs/work/agent-protocol.md.

## How to update this table

- Append a row with the count and the date.
- Never delete a measured row.
- State the source of a new count: the command that produced it, or the recorded run.
- If a note and a count in a row disagree, keep the row as measured, record both readings, and re-derive before merging them. As received, the Muse row carried the note "both clean runs had fully specified interfaces" against 3 finished clean; this copy withholds the count word until that number is re-derived. The interface rule itself stands: specify interfaces (file, flags, error names, test fixtures), not goals.
