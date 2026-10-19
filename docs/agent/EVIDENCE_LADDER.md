<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Evidence ladder

The development and publication procedure lives in
[DEVELOPING.md](../dev/DEVELOPING.md). This page explains what observations can
support, without defining another promotion ledger or requiring activation.

## Use the cheapest meaningful refutation first

| Stage | Observation | Limit of the claim |
|---|---|---|
| Local behavior | Focused acceptance observing the changed invariant. | A unit pass alone does not establish consensus, custody, or public-node acceptance. |
| Registered tests | Canonical runner verdict with exact selected groups and executed/reused/failed/skipped counts. | Zero matches, stale catalogs, unrun groups, and cached summaries alone are not green. |
| Lint and generated artifacts | Required gates at the affected scope; owning generators reproduce tracked outputs. | Empty scans and weakened pins are not passes. Lower a shrink-only complexity pin when the function becomes simpler. |
| Exact proof | Native receiver admits a complete receipt for the exact candidate/base and its declared dimensions. | Evidence establishes only its bound claim; signatures and hashes alone do not establish correctness. |
| Publication | Native receipt-gated landing outcome, followed by independent remote identity verification. | A clean checkout, board row, handoff, or queued request is not publication. |

Run heavy builds, proofs, benchmarks, and test matrices through
`devbuild --wait`, preserving repository job presets and native locks. Freeze
inputs during the observation. Use current receiver-qualified exact reuse only
where implemented; report it separately from freshly executed work. Do not
assume every proof is full-suite cold, or that a prior pass covers a new base.

Public hot-swap and activation paths remain contained or unavailable; this
ladder does not authorize them. Separate qualified activation APIs retain their
own operator and platform boundaries. Resident save loops are optional only
when explicitly authorized, never mandatory rungs. Keep services, timers,
watchers, and nodes disabled unless explicitly requested. Refusal or unavailable capability is an observation,
never permission to substitute pathname execution or a weaker gate.

A failed or incomplete stage names its exact input, dimension, refusal, and
log or receipt. Retry only through existing authorities after addressing the
cause. Do not create a parallel job ledger, wait on a human as a scheduler, or
require a permanent lead. Non-author review and receiving-node policy remain
necessary wherever the operating contract requires them.

## Historical measurements: node1, 2026-08/09

These are recorded observations from earlier implementations. Derive current
counts and costs from the qualified binary and the actual run.

| Observation | Historical measurement |
|---|---|
| Owning-group lookup | About 10 ms. |
| Hot-swap comparison | 31x faster than a rebuild; under 2 s was a target, not a measured universal bound. |
| Focused cold test | Seconds to a minute. |
| Fast lint | 32 gates, about 10 s warm. |
| Full lint | 211 gates, 25 minutes cold, 2 minutes warm. |
| Exact proof | 15 to 45 minutes per box; release build about 20 minutes. |
| Engine territory query | 24 files routed to 6 groups, none unrouted; 74 public functions: 67 reached, 7 unreached, 0 unknown. Complete data returned at 2490 ms against a 900 ms budget. |

Routing identifies registered groups. Reach identifies functions called by test
entry points. Those are different observations and must not be added together.

## Designs that are not acceptance requirements

The earlier six-rung design proposed an on-chain anchor for a receipt-ledger
root and resource classes `build:<host>`, `proof:<host>`, and `vendor:<name>`.
Those proposals are not evidence of implementation, a reason to require an
on-chain write, or permission to spend funds. Existing receipt/CAS/task
objects remain the authorities; consult current code and receiver policy
before claiming any proposed feature is complete.
