<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Objectives

What z23 optimizes lives in two places today: prose
(`docs/ARCHITECTURE_NORTH_STAR.md`, the owner's standing directives) and an
agent's own memory of them. Neither is a number the binary can check itself
against. `z23-dev fleet objectives` is the first slice that closes that gap:
a closed catalog of named objectives, each with a producer and a target, and
one command that prints where every one of them stands right now.

```
z23-dev fleet objectives
z23-dev fleet objectives --format=json
```

## The catalog

The catalog is the ONE declaration, in
[`engine/composition/objectives.def`](../engine/composition/objectives.def).
An id not written there is not an objective — the command answers only the
rows below, never an ad hoc number.

| id | source | direction | target | unit |
| --- | --- | --- | --- | --- |
| `landing_latency_s` | outcomes.jsonl | min | 1200 | s |
| `landing_attempts_per_train` | outcomes.jsonl | min | 1 | count |
| `proof_lint_wall_s` | phases.txt | min | 300 | s |
| `proof_test_wall_s` | phases.txt | min | 600 | s |
| `commits_landed_today` | git_log | max | 20 | count |
| `lint_families_over_ceiling` | lintc_line_counts | min | 0 | count |
| `functions_over_complexity_cap` | cyclomatic_baseline | min | 0 | count |
| `fresh_node_sync_eta_s` | unmeasured | min | 3600 | s |
| `tokens_per_landed_commit` | unmeasured | min | 200000 | tokens |

`direction` says which way is better: `min` for a cost, `max` for an
outcome. `unmeasured` in the source column means no producer exists in this
tree yet — the row is declared so the gap is visible, not hidden.

## What each producer reads

- **`landing_latency_s`** and **`landing_attempts_per_train`** read the
  landing outcomes ledger (`outcomes.jsonl`) scoped to one TRAIN, identified
  by its `note` (e.g. `traintrain43`, constant across every attempt of one
  train — falling back to `worktree` when `note` is empty, since `tip` and
  `base` both change on every rebase and cannot identify a train). The
  newest row with `state: "landed"` names that train; every row in the file
  with the same identity (any state) is its own history. The latency is
  the landed row's `ts` minus the EARLIEST such row's `started` field (or
  its `ts`, when `started` is absent). The attempts figure is the count of
  that train's DISTINCT (attempt, started) pairs whose state is `landed` or
  `failed` — a `conflict`/rebase row is not itself a proof attempt, and a
  literal duplicate row for one already-counted attempt is not double
  counted.
- **`proof_lint_wall_s`** and **`proof_test_wall_s`** read the most recently
  modified proof attempt's `phases.txt` and take the `elapsed_ms` value on
  its `step=lint` and `step=test` lines, rounded to the nearest second.
- **`commits_landed_today`** runs `git log --since=midnight --pretty=oneline
  HEAD` through the tree's no-shell spawn seam (`zcl_spawn_capture`) and
  counts the lines.
- **`lint_families_over_ceiling`** counts the `.c` files under
  `tools/lint/lintc` whose line count exceeds 1500.
- **`functions_over_complexity_cap`** counts the rows of
  `tools/lint/cyclomatic_complexity_baseline.txt` when that file exists.
- **`fresh_node_sync_eta_s`** and **`tokens_per_landed_commit`** have no
  producer yet: the first needs a fresh-sync timing leaf, the second needs
  the experiment ledger's cost side wired to a landed-commit count. Both
  print `unmeasured` with that reason, never a fabricated number.

## Status

Each row's `status` is `met`, `unmet`, or `unmeasured(<reason>)`. A value
this tree cannot measure today is never reported as zero — zero is a
different fact from "the tree cannot say," and this command distinguishes
them by name.

## What it does not do

This is a report, not a gate. No build or push decision reads this command's
output; it is a plain measurement, for a person or an agent deciding what to
work on next.
