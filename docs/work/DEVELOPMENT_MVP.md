<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23 development MVP

**Development MVP = "a fleet of interchangeable coding agents lands correct C23
changes quickly, on any number of hosts, at a known and falling cost per landed
change."** Eight milestones, each with one measurement and one threshold. The
Development Readiness Score (DRS) is the count of milestones met; the
development MVP is achieved at 8/8.

This file defines acceptance for the current mission in
[`FORWARD_PLAN.md`](./FORWARD_PLAN.md), *fast C23 development with fleet
Insight + Control*. Public-node acceptance (C1–C8) stays in
[`../MVP.md`](../MVP.md) and remains mandatory; nothing here replaces or
weakens it. Durable priorities and authority live in
[`../../AGENTS.md`](../../AGENTS.md).

## Unit of account

One **landed change**: a unique, useful C23 change that passed its own test,
its mutation check, two independent reviews and the landing proof, and is on
`main`. Every unsuccessful attempt, review, repair and shared validation run is
charged to the change it served. A duplicate of a landed change counts as zero.

Cost is reported as a vector, never one number: provider requests, input
tokens, cached input tokens, output tokens, test-host minutes and landing-host
minutes. A missing counter is reported as unknown, never as zero.

## Milestones

| # | Milestone | Measurement | Threshold | Status |
|---|---|---|---|---|
| D1 | **Every run is accounted** | Share of finished worker runs with provider-reported requests, input, cached input and output recorded | 100% on every host, with unknowns listed | ◐ |
| D2 | **Few requests per change** | Provider requests per accepted change, writer plus both reviews, on closed-contract changes of at most 120 lines | median at most 18 | ☐ |
| D3 | **Reviews agree with the truth** | Known-answer review set: share of sound changes rejected, and share of seeded code defects accepted | at most 10% and at most 5%, on at least 59 distinct seeded defects | ☐ |
| D4 | **Changes are accepted first time** | Share of delivered changes that both reviews accept without a repair round | at least 60% over 100 consecutive deliveries | ☐ |
| D5 | **Cost per landed change is known and halved** | Uncached input plus output tokens per landed change, all attempts charged | at most half the D5 baseline below, with first-test pass rate not lower | ☐ |
| D6 | **Fast feedback** | Time from delivery to the focused test and mutation verdict on a warm test lane | p95 within 180 seconds; a build-rule edit does not rebuild unaffected objects | ☐ |
| D7 | **Landing keeps pace** | Landing groups that fail without a named cause; spacing between consecutive landed groups under backlog | zero unnamed failures in 20 consecutive groups; median spacing at most 20 minutes | ☐ |
| D8 | **Any fleet shape** | Host roles, counts and paths come only from configuration; coordination tools are C23 | adding or removing a host needs one configuration line and no source edit; no shell script on the coordination path | ◐ |

**Legend:** ☐ unmet · ◐ partly met, with the remaining condition stated below ·
✅ met by the stated measurement on the stated sample. A ✅ records a measured
run; it is re-measured whenever the brief templates, the worker tools or the
model configuration change.

## Baseline

Measured from the maintainers' development fleet records on 2026-10-07. Six
hosts, thirty worker seats, two Linux test hosts with two lanes each, one
landing host. Not randomized: tasks were not assigned to configurations at
random, so differences between hosts may reflect the tasks.

| Milestone | Baseline |
|---|---|
| D1 | 1,451 finished runs recorded on four Linux hosts; one host has no record yet |
| D2 | 102 requests per worker run; 96.9% of input tokens served from cache; no closed-contract cohort measured yet |
| D3 | 38 distinct changes, 19 with a seeded defect, 110 reviews: sound changes rejected in 20 of 57 reviews, 12 of them for function complexity alone; seeded defects accepted in 6 of 57, 5 of them defects of the change message only |
| D4 | 19% to 40% by host, observational |
| D5 | 300,000 to 1,200,000 logged tokens per change accepted by both reviews, by host, observational |
| D6 | 1 to 3 minutes per change on a warm lane; 13 to 45 minutes after any build-rule edit |
| D7 | 2 of the last 6 groups failed with no cause named; group spacing about 29 minutes |
| D8 | Host roles and paths are configured; staging, package tests and dispatch still run as shell scripts |

## Remaining condition per milestone

- **D1:** record the remaining host and the per-run template and tool versions.
- **D2:** deterministic steps (context preparation, validation, review packaging)
  run as single tool operations; the model is asked only for decisions.
- **D3:** mechanically measured rules reach the reviewer as facts; reviewers
  return findings and the control side derives the verdict, separately for the
  change and for the claims made about it. Zero misses on 59 independent seeded
  defects bounds the miss rate below 5% at one-sided 95% confidence; fewer
  cases cannot show this threshold.
- **D4:** follows D3 and explicit scope in every task; measured on live
  deliveries, not on the known-answer set.
- **D5:** follows D2 and D4; reported with the full cost vector.
- **D6:** compile reuse keyed on each action's real inputs instead of the whole
  build file.
- **D7:** a failed landing proof names the change that caused it; a change
  whose tested base is older than a file it touches is tested again before it
  is grouped.
- **D8:** replace the remaining shell scripts with C23 and qualify the same
  tools on arm64 macOS.

## Rules for changing a status

1. Run the measurement on the stated sample and keep its output.
2. Record date, sample size, measured value and where the output is kept in the
   *Baseline* table or a row beneath it.
3. Change the status only when the threshold is met as written. A threshold is
   changed only by an owner decision recorded in this file with its date.
4. No gate is relaxed to move a number: tests, the mutation check, both
   reviews and the landing proof stay as they are.
