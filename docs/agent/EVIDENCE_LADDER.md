# Evidence ladder

This document defines the six rungs of evidence a change passes through, from hot-loaded rough test to receipt frozen on chain, with the measured cost, signal, and receipt of each rung and the promotion and async rules that govern them.

## Purpose

The ladder orders the checks a change must pass before it counts as landed and frozen. It covers streaming C23 development on this checkout. Every rung is an asynchronous event, never a wait. A rung finishes, emits a typed receipt, and the next rung is claimed from that receipt.

## The principle (information per second)

Rungs are ordered by expected information per second. The cheapest check that can most often refute the change runs first. A change spends the next rung's cost only after the cheaper rung is green. A skipped or unobserved rung is not a pass. A rung that cannot refute the change does not belong on the ladder.

## The rungs

Costs below were measured on node1 (2026-08/09). They are recorded measurements, not estimates.

| Rung | Command | Measured cost | Signal | Receipt |
|---|---|---|---|---|
| 1 hot-load | Save the file, hot-swap the changed function into the running dev binary, run the owning test group. Owning group from `build/bin/z23-dev code tests --input='{"path":"<file>"}'`; hot-swap via `dev.hotswap.apply` / `dev.hotswap.probe`. | Owning-group lookup about 10 ms; hot-swap measured 31x faster than a rebuild; target under 2 s save-to-verdict. | The function still satisfies its own group. | Hot-swap verdict row naming the file and the owning group. |
| 2 tested | `make t-fast ONLY=<group>`, cold | Seconds to a minute. | The registered group ran and passed. Read the SUITE VERDICT line, never the exit code: a selector that matches nothing prints groups_ran=0 and exits 0. | Suite verdict row carrying SUITE VERDICT and groups_ran. |
| 3 linted | `make lint-fast` on every slice; `make lint` at a train boundary | `make lint-fast`: 23 gates, about 25 s. `make lint`: 182 gates, 25 min cold, 2 min warm. | The change class's gates ran on the whole scope; a gate that scanned nothing refuses (partial-scan floors). | Gate receipt naming each gate and the scope it scanned. |
| 4 proven | `dev proof ensure`, then `dev proof wait` (push-hook proof) | 15 to 45 min per box; includes the release build, about 20 min; one proof per box. Every push to main moves the base and restarts in-flight proofs; hence trains. | The exact main tip plus this change builds and passes the full suite cold. | Proof receipt naming the exact tip and the verdict. |
| 5 landed | Push to origin/main, fast-forward only, signed commits | Not measured; the rung is the push itself. | The commit is on origin/main; the train posts `result train <tip>` on the board. | Train board post `result train <tip>`. |
| 6 frozen | Append the landing receipt to the fleet's append-only receipt ledger; anchor the ledger root on chain through the node's identity anchor | Not measured; the on-chain anchor is designed, not landed (see below). | Finality of the on-chain anchor; any node verifies a receipt without trusting the box that produced it. | Signed ticket — commit, proof verdict, groups ran, gates — appended to the ledger; the ledger root is an MMR of tickets. |

## Promotion rules

1. Rungs run in the order 1 through 6. A change claims rung n+1 only from rung n's receipt.
2. The cheaper rung must be green before the next rung's cost is spent.
3. A skipped or unobserved rung is not a pass. No rung is promoted on absence of evidence.
4. Rung 2: read the SUITE VERDICT line, never the exit code. groups_ran=0 is not a pass.
5. Rung 3: `make lint-fast` on every slice; full `make lint` at a train boundary. A gate that scanned nothing refuses.
6. Rung 4: one proof per box. A push to main moves the base and restarts in-flight proofs, so proofs batch into trains. A proof names the exact tip it covers.
7. Rung 5: fast-forward only, signed commits.
8. Never weaken an assertion, a threshold, or a gate to force a promotion. An honest red at the rung that produced it is the correct result.

## Async rules

- Each rung is a job with a resource class and a cap. Resource classes: build:<host>, proof:<host>, vendor:<name>. Not yet implemented; see below.
- A rung's completion is a receipt row.
- Orchestrators subscribe to receipts. They never poll a model or a human.
- A failed rung produces a typed result — FAIL, TIMEOUT, UNOBSERVED, NOSHA — that names the exact gate or group.
- A retry is a new job that references the failed receipt.
- No rung waits inside another rung. The next rung starts from a receipt, not from a block.

## What exists and what is missing

Exists today:

- tools/engine_unit.c — units judged by the gate.
- engine/modules/engine/src/engine_receipt.c — chained receipt ledger: append-only, refuses a torn last line.
- engine/composition/commands/dev.def — `dev.hotswap.apply`, `dev.hotswap.probe`, `dev.loop.*`, `dev.proof.ensure`, `dev.proof.status`, `dev.proof.wait`, `dev.publication.*`, `dev.agent.*`.
- Related protocols: docs/agent/UNIT_DISPATCH.md, docs/agent/TRAIN_PROTOCOL.md, docs/work/AGENT_SYNC_PLAN.md.

Routing and reach facts are re-derived per checkout, not copied. On this run the `code.territory` command on the engine/modules/engine territory reported: 24 files routed to 6 groups, 0 files routed to none; 74 public functions = 67 reached + 7 unreached + 0 unknown. The command overran its 900 ms budget at 2490 ms elapsed and returned complete, untruncated data. Routed (which registered group runs when a file changes) and reached (whether a registered test entry point calls the function) are different facts and are never added together; `unknown` is the call graph refusing to answer.

Missing, plainly:

- Rung 1 is not yet wired as one command from save to verdict. The pieces exist; the single command does not.
- Rung 6's on-chain anchor of the receipt root is designed, not landed. The chained ledger exists; the anchor does not.
- The job ledger has no resource classes yet. build:<host>, proof:<host>, and vendor:<name> are design, not implementation.

## How to add a rung

1. Declare the cost. Measure it on a named host and period, and write the number into the table above.
2. Declare the signal. State exactly what the rung refutes and how often it refutes it.
3. Declare the receipt kind. State the typed row the rung emits on completion and on each failure type.
4. Place the rung by expected information per second: after every cheaper rung that refutes more often per second, before every dearer one.
5. Never insert a rung that cannot refute the change. A rung that cannot fail is not evidence.
6. A new rung must be observable. If it emits no receipt, nothing can be promoted past it.
