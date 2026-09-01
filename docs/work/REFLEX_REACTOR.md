# Local zero-wait reflex reactor

North star: edit C23, receive the first exact result that can change the next
action almost immediately, and keep working while stronger proof proceeds.
One warm local service owns the loop. `drive` is the compact human form:

```text
begin -> edit -> drive
```

The machine form is attach once and never block the agent's edit loop:

```text
begin -> dev loop events --after=<cursor> --format=jsonl
      -> edit -> continue thinking
      <- IMPACT_READY / COMPILE_GREEN / STORY_GREEN
      <- STORY_RED + zcl.dev_diagnostic_capsule.v1
```

Git, Make, a database, network I/O, publication, full links, full scans and
full-suite proof are behind the latency firewall. They may consume an immutable
candidate, but cannot be prerequisites for reflex feedback.

## Stage and authority contract

```text
EDIT_SEEN -> IMPACT_READY -> COMPILE_GREEN / COMPILE_RED
                              |
                              v
                       STORY_GREEN / STORY_RED       REFLEX
                              |
                              v
                       FOCUSED_GREEN / FOCUSED_RED   ASYNC PROOF
                              |
                              v
                         PROOF_PENDING               ACCEPTANCE
                              |
                        human approval
                              |
                              v
                        ZVCS evidence -> P2P publication
```

`SUPERSEDED` terminates obsolete work when a newer save arrives. Every event is
an observation about one immutable edit epoch, never approval or publication
authority. `dev loop wait` exposes every event. A normal `dev drive` consumes
the mechanical acknowledgements and returns the first action-changing
diagnostic/story for the new edit. `FOCUSED_GREEN` still keeps
`proof_complete=false`; only the conservative source-wide proof can create
reusable acceptance, and only a later human-approved ZVCS boundary may publish.
Verify mode never publishes a runtime.

## Why this owner

The frozen recent-history replay selected
`contexts/wallet/controllers/src/vault_intent_controller.c` as the highest-frequency
ordinary production owner (6 weighted edits), rather than choosing a toy file.
That controller mixed custody authority with a deterministic planning decision.
The refactor leaves parsing, wallet snapshots, coin reservation, persistence,
signing and broadcast in the static controller. Only the proposal moves to
`contexts/wallet/services/src/vault_intent_decision_service.c`:

```text
STATIC AUTHORITY SHELL                 PURE DECISION CORE
wallet/database/value authority  ---> immutable copied snapshot
                                      proposal-only decision
                               <---   no effect capabilities
```

Its five-case KAT is the smallest executable user story: current funds permit
an exact reservation, while stale money, bad fees, insufficient funds and the
development cap refuse. The candidate runs as `HOT_SHADOW` in a forked child
against frozen fixtures. It cannot acquire wallet, database, network, reducer,
custody, supervisor, deployment or publication authority.

## Before extraction: exact trace

The original ordinary-edit path took 12.677 s to its first green receipt. Tests
consumed 9.906 s, aggregate compilation 1.066 s and aggregate overlay linking
2.028 s. After the first stage split—but before this reactor—the same owner
reached candidate feedback in 2.463 s and five-group proof in 10.603 s:

| Work | Monotonic time | Processes |
|---|---:|---:|
| `EDIT_SEEN` | missed by latest-value polling | 0 |
| observable `IMPACT_READY` | 164.468 ms | 0 |
| path impact | 0.113 ms | 0 |
| closure snapshot | 20.263 ms | 0 |
| exact test selection | 207.636 ms | 0 |
| three incremental source guards | 98.428 ms | 0 |
| candidate + proof compiler startup/body | 12.232 / 1,009.205 ms | 4 |
| candidate + proof linker startup/body | 6.541 / 3,353.458 ms | 2 |
| test startup/body | 2.742 / 4,741.473 ms | 1 |
| bounded runtime probe | receipt-bound | 1 |

The exact selected groups were `test_db_migration_idempotent`,
`test_transaction_intent`, `test_wallet_funds_safety`,
`test_command_registry_catalog` and `test_command_input_bounds`; 71 broader
groups remained named. This trace identified polling, broad proof and process
setup as latency, not the 0.113 ms path rule itself.

## Implemented reactor

The resident watcher now keeps the last reconciled Merkle snapshot in memory.
One save hashes only known changed paths and creates an immutable epoch carrying
changed paths, previous/new SHA3 blob roots and sizes, owner/component,
dependency generation, sequence and parent epoch. No Git status or repository
inventory scan occurs on this path. A newer save constructs and publishes its
impact inside the old proof's cancellation observation, so process reaping
cannot delay the new epoch.

The progressive stream is a 64-slot bounded local ring ahead of an append-only,
SHA3-sealed journal. Ring publication has no fsync or storage acknowledgement.
After the action-changing event is visible, `flush-through` seals every epoch
in order; the journal remains evidence authority and restart recovery rejects
gaps or bad seals. `dev drive` waits with inotify, closing the check/sleep race;
there is no polling sleep.

The candidate builder keeps its frozen action/dependency plan and artifact
cache warm, invokes the compiler and module linker directly, then forks the
preloaded parent for the story. No command shell, Make parser, test runner or
full-program linker enters the reflex. Exact affected proof starts only after
the story. Scheduling remembers the prior failed exact group for the task,
then runs the goal story, cheap likely regression, direct owner invariant and
the complete affected batch; priority changes, required proof does not.

## Dependency map and latency firewall

```text
REFLEX
  inotify -> resident path/blob epoch -> direct module compile/link
          -> forked HOT_SHADOW story -> volatile event

ASYNC PROOF
  exact path floor + code-index closure -> failure-first focused groups

ACCEPTANCE
  conservative source-wide compile + tests + lint-fast

PUBLICATION
  reusable proof -> human approval -> ZVCS receipt -> DHT/P2P workers
```

The audited reflex events carry explicit zero counters for Make, shells, Git,
publication, remote/network operations, storage-ack waits, SQLite, full-tree
scans and full-program links. Local candidate artifacts are content-addressed
inputs, not acceptance. The foreground has no call edge into ZVCS, DHT, P2P,
wallet or runtime activation.

## General development substrate

Recent-edit coverage is measured, not inferred, by `make
reflex-coverage-audit`. It freezes the most recent 100 production-C commits,
weights repeated edits as repeated occurrences, applies two distinct safe edits
to every registered fast owner, and records the first result-bound event plus
every fallback reason. `engine/composition/hotswap_shadow_owners.def` is the coverage map:
a static authority shell is compile-checked exactly, while only its declared
pure service core runs as `HOT_SHADOW`. `HOTSHADOW_SERVICE_MEMBERS` admits a
helper TU into executable candidate bytes only after the same no-state,
no-effects lint as the service itself.

Every `STORY_GREEN` contains a `zcl.dev_proof_handoff.v1` object with exactly:

```text
candidate_epoch + source_epoch
affected_component + affected_file_count
action + proof_inputs_sha3
compile_green + story_obtained + focused_evidence_sha3
```

That immutable value is the entire handoff to later server-side proof. It
carries no path capability, command handle, database handle, network handle,
or publication authority. Remote proof may append receipts later; it cannot
reach backward into the reflex lane or change an already emitted verdict.

## Reproducible measurement

Run `make reflex-reactor-bench`. It applies 20 randomized, distinct atomic
source edits plus one compile-valid behavior regression, uses one verify-only
watcher and one `drive` per edit, reads the exact sealed event range, restores
the source bytes and writes the ignored receipt
`build/dev-loop/reflex-reactor-benchmark.json`.

The final 21-edit run measured:

| Result | p50 | p95 | max | Gate |
|---|---:|---:|---:|---:|
| `EDIT_SEEN` | 13 us | 14 us | 16 us | <10 ms p95 |
| `IMPACT_READY` | 238 us | 302 us | 1.340 ms | <50 ms p95 |
| compile diagnostic | 61.631 ms | 67.090 ms | 68.838 ms | <250 ms p95 |
| green `HOT_SHADOW` story | 65.076 ms | 70.763 ms | 73.506 ms | <1 s p95 |
| edit to compact `drive` reply | 260.685 ms | 294.323 ms | 294.707 ms | measured |
| useful `STORY_RED` | 67.935 ms feedback | 286.265 ms wall | n/a | <1 s |

The run observed 21 each of `EDIT_SEEN`, `IMPACT_READY`, `COMPILE_GREEN` and
shadow forks, 20 `STORY_GREEN`, one `STORY_RED`, and 20 `SUPERSEDED`. Every
candidate was distinct: 21 compiler children, 21 module-linker children and
zero foreground test processes. Every firewall counter was zero.

The `<2% active-development time blocked` target requires longitudinal editor
telemetry and is not claimed from a synthetic 21-edit latency run. The reactor
now makes the necessary behavior true—proof is asynchronous and obsolete work
is cancelled—but that ratio remains a product/workload measurement, not a
fabricated benchmark result.

## Self-hosting safety

The pre-change binary remains trusted stage 0. A changed watcher, scheduler,
event system, loader, identity layer or proof router is only a stage-1 shadow
candidate until that saved stage-0 binary proves the final source. Candidate
KATs and focused tests cannot certify or replace the machinery that ran them.
