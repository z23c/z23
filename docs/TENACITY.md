# TENACITY — Standing Engineering Doctrine for a Tenacious Binary

*This is the **doctrine** (timeless rules), distilled from an
information-theory diagnosis of the project's failure modes. The dated status
board this doctrine was distilled from — the divergence-surface audit, the
failure-rate budget (F1–F11), the verification gates (G1–G5), and the merged
rock-solid recovery-program L1/L2 items — is
[`docs/work/tenacity-roadmap.md`](work/tenacity-roadmap.md), superseded as a
roadmap by [`docs/work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) but retained on
disk because reindex/replay-canary/seal_kv code still cites its numbered items
by name.
Near-term hardening sequencing (including the hold-class doctrine and the
stability-hardening backlog) is in that same file's "Hold-class doctrine" and
"Stability hardening backlog" sections.*

Companion docs: `docs/work/canonical-frontier-derived-state-plan.md` (the what),
`docs/CONSENSUS_PARITY_DOCTRINE.md` (the parity bar),
`docs/work/fast-path.md` (diagnose on a COPY, never live).

Live bootstrap/cure status: [`docs/HANDOFF.md`](HANDOFF.md); design:
`docs/work/self-verified-tip-plan.md`. Verify live state from
`z23 status` / `z23 dumpstate reducer_frontier`, never from this
doctrine document. The six principles below are timeless, independent of that
status.

---

## The z23 way

Six principles, stated natively. Everything else here is an instance of one of
them. The plain model first: **blocks are the input rows; everything else is a
formula.** Every table, cursor, mirror, and commitment in the datadir is a
formula over the chain. Bugs happen when someone types a number into a formula
cell — the cell now disagrees with its own formula, and no amount of comparing
cells tells you which one is right. You never fix it by editing the cell.

1. **The chain is the only truth — everything else is derived.** The block
   chain is the one immutable input; cursors, coins, verdicts, and commitments
   are recomputable views of it. A tip *installed* above what the validated
   evidence supports — a typed-in number, not a derived one — is the standing
   defect class behind every boot crash-loop this doctrine guards against:
   state installed instead of derived.

2. **One writer per fact; everything else is a formula.** Each fact has exactly
   one authoritative writer inside one transaction; every other encoding is
   read-only derivation. The coin tear was representable only because node.db
   `utxos` had 4 independent writers. The cure is to make the tear check a
   formula over utxo_apply's OWN co-committed log and demote every copy to a
   labeled cache.

3. **The sealed domain and the working window.** Derived state splits at a
   finality boundary: at or below it, state pinned by checkpointed SHA3 UTXO
   commitments, recomputable from genesis and continuously re-proven; above it,
   a working window of cursors, stage logs, and coin deltas that is explicitly
   disposable. The compiled checkpoint h=3,056,758 (sha3 `5817f0ec…`) is the
   degenerate seal today; the rolling seal ring above it is roadmap work.

4. **One recovery verb: rebuild the window, never repair it.** Any window
   anomaly — coin tear, height splice, stale verdict, integrity mismatch — gets
   one remedy: discard the window, reset to the last seal, replay forward (a
   ≤~2,100-block span, seconds at measured replay throughput), recompute the
   commitment, resume. Every recovery that works is a recompute (crash-only
   auto-reindex, cold-import); every one that fails is a repair — an
   anti-rewind floor refusing a consistent rollback target compounds into a
   crash-loop, and depth-3 poison-rewinds oscillate instead of converging.
   `window_rebuild` is the verb that makes each ladder deletion safe;
   auto-reindex-from-anchor is its landed degenerate form.

5. **Recompute fixes bugs — fix the code, re-derive the state.** When a wrong
   formula has written wrong cells, the fix is the formula plus a recompute of
   the column, never hand-editing cells. The height-splice fix derives heights
   from parent links and hash-binds verdicts, so spliced rows are re-derived
   rather than patched.

6. **Verify against the chain, not against text or mirrors.** Ground truth is
   the canonical chain's own bytes; reference source text and sibling copies are
   lossy proxies. Text said 102,000 bytes was the tx maximum; the chain holds a
   125,811-byte tx at h=478544, and trusting the text FATALs genesis replay
   (see I4). Trusting a lagging mirror can manufacture a false coin-tear —
   both classes cure by checking the derivation, not the copy.

---

## The information-theoretic invariants (I1–I6)

These are the laws. Every wedge, crash-loop, and silent hole in project history
traces to violating one of them.

**I1 — Single source of truth.** Each fact has exactly one authoritative
encoding. For chain progress that is the stage cursor + logs + coins inside
consensus.db (the kernel store; `progress.kv` on a pre-flip datadir),
committed as one `BEGIN IMMEDIATE`
(`engine/modules/storage/include/storage/coins_kv.h:6-13` states the theorem: two WAL
databases have no atomic cross-commit; a crash drifts copies apart and no
forward path realigns them).

**I2 — Derive views, never install state.** Everything that is not the source is
a projection, recomputed from the source, never written independently. H* is the
model: pure-derived, read-only (`engine/reducer/jobs/include/jobs/reducer_frontier.h:73-76`).
Invariant B applied this to the coin-tear — derived from utxo_apply's OWN
co-committed log, not the lagging frontier (`c8018a388`).

**I3 — Divergence unrepresentable.** When copies CAN diverge, repair code that
guesses between them becomes the bug (an anti-rewind floor that refuses a
consistent rollback target compounds into a systemd-FAILED crash-loop). The
cure is a write-time
invariant at a chokepoint, never a new repair module. **Standing rule: new wedge
= new write-time invariant, never a new repair rung.** A PR adding
`*repair*|*recover*|*heal*|*reconcile*` code must cite the invariant that makes
the divergence unwritable, or be declined.

**I4 — Verify against the chain, not text.** The canonical chain is the only
ground truth for consensus; reference source code is a lossy proxy. Precedence:
**chain > deployed zclassicd behavior > zclassicd source text**. The proof — the
125,811-byte tx at h=478544 that the text-copied 102,000 cap false-rejects — and
the grandfather fix are documented in `docs/CONSENSUS_PARITY_DOCTRINE.md`.

**I5 — Crash-only.** Every derived state is rebuildable from the source; every
recovery is bounded, automatic, and terminates in SERVING. The process may die
at any instruction; the boot path must converge without an operator. Anchors:
crash-only auto-reindex instead of FATAL crash-loop (`706a7c00a`); never-give-up
unit (`StartLimitIntervalSec=0`, stepped backoff, `0b45e93a5`).

**I6 — Measure the real distribution.** test_parallel green is a regression
floor, not a liveness proof: a fully green hermetic suite can coexist with the
node down for hours in production, because no gate as configured samples that
failure class. Gates must sample real crash/import/repair histories and real
chain content — see the G1–G5 gate program in [`tenacity-roadmap.md`](work/tenacity-roadmap.md).

---

## The divergence surface (summary)

~3 facts, ~16 named encodings across 6+ separate stores (4 SQLite WAL databases
— consensus.db, node.db, utxo_projection.db, block_index_projection.db — plus
LevelDB and the block_index.bin flat file), no atomic cross-commit between
stores. Per-encoding authority verdicts (which is CANONICAL, which is a demote /
delete target) live in the audit table in
`docs/work/canonical-frontier-derived-state-plan.md` Phase 1/2 and
[`tenacity-roadmap.md`](work/tenacity-roadmap.md).

The single canonical writer per fact:

| Fact | Canonical encoding |
|---|---|
| UTXO set | `coins` table in consensus.db (coins_kv), written by the reducer inside the stage txn |
| Applied frontier / best block | utxo_apply stage cursor in consensus.db, written by the reducer txn |
| Block index | event_log `EV_BLOCK_HEADER` (log-of-record); block_index.bin + SHA3 sidecar load-bearing today |

Every other encoding is a duplicate to demote to a read-only derived view or
delete. **Ordering constraint: deletions run only AFTER the canonical-frontier
plan steps make each duplicate zero-callers — never out of order.**

---

## The sync-speed floor

Trusted bootstrap's information floor is *headers + UTXO snapshot*. We measure
at the floor today; remaining work is recipe-safety, not throughput. The proven
two-step cold-sync recipe, its measured timings, and the port table are in
`docs/SYNC.md` — the canonical source. The recipe's `--importblockindex`-FIRST
order is load-bearing: skipping it leaves a 3.1M header hole (headers=960) and
pins forever, so the footgun must be removed or auto-composed in code, not
documented around.

**Targets:** (a) one-command recipe, hole unrepresentable; (b) post-import
completeness invariant (gate G4) so a fast sync can never be a silently
incomplete one — precedent: a UTXO import once silently dropped the txid keyspace
tail (1,561 records) with plausible row counts and shipped green its whole life.

---

## The failure-rate budget (doctrine)

Defense in depth: each failure mode is absorbed by the innermost layer that can;
outer layers are backstops; the residue pages the operator via
EV_OPERATOR_NEEDED / Conditions / supervisor — **never a silent halt, never a
FATAL loop.** The live F1–F11 status board (absorbing layer + landed/open per
mode) is in [`tenacity-roadmap.md`](work/tenacity-roadmap.md).

**Page-the-operator residue** (everything the layers do NOT absorb): consensus
divergence vs zclassicd at identical height (parity break — never auto-heal),
exhausted auto-reindex (reindex loop count threshold), disk-full / IO error, and
any supervisor child in stall_fires escalation. These must surface as
EV_OPERATOR_NEEDED + Condition, with the node held SERVING-degraded where safe.

---

## Standing verification institutions (doctrine)

The gates ARE the product, and they are the only honest verification of the
refactor — **they land FIRST.** Budget: ~1–1.5 h/night + ~30 min/week on the
existing 32-core box. Each must emit a verdict sentinel (never exit-0 alone —
`a91770f88` passed build+lint+tests with its new seed path never executing; only
repro-on-copy proved it fires). The five-gate program (G1 full-history replay
canary, G2 chain-derived golden extremals, G3 crash-boot soak, G4 recipe smokes,
G5 push-time execution) and its land status are in
[`tenacity-roadmap.md`](work/tenacity-roadmap.md).

**What exists today (honest):** the `make lint` gates (source-text greps —
count derived from `LINT_GATES` in the Makefile, not restated here), the
hermetic test_parallel groups (synthetic regtest 48,5 fixtures — count derived
by `make test-parallel`, likewise not restated), `make ci`
(policy-forbidden from starting a node), test-crash (guaranteed-SKIP —
`ZCL_CRASH_DATADIR` unset). All valuable as a regression floor; none sample the
live failure distribution. That is the gap G1–G5 close.
