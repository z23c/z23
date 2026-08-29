> Verify the live H* via `z23 status` / `z23 dumpstate
> reducer_frontier` before trusting this note. This derive-state/
> delete-heal-ladder design remains historical input, not an open plan;
> current gates are in `SOVEREIGN-NETWORK-ROADMAP.md`.

# Canonical frontier-derived state — two gates, delete the heal ladder

Net-subtractive design: two small gates, nine repair modules deleted. Both
live wedge classes are one defect — **state INSTALLED instead of DERIVED from
the log** — surfacing at two chokepoints (the wedge narratives live in
[`tenacity-roadmap.md`](./tenacity-roadmap.md); this doc is the
design-of-record for the gates and the deletion order).

## Canonical invariants (enforced by construction at one chokepoint each)

- **INVARIANT A (frontier-bounded tip).** A tip is committable at height `h` only if
  `validate_headers_log` has a contiguous ok=1 prefix reaching `h`, OR the commit carries
  a typed `rollback_auth` (SNAPSHOT/RESTORE/VALIDATION/REINDEX/BOOT_REPAIR), OR it is the
  existing `forward_from_active_tip` carve-out. `pindex_best_header` is a **projection** of
  that prefix, never slammed forward. Chokepoint: `csr_validate_locked`.
- **INVARIANT B (coins bounded by finality).** `utxo_apply` may not advance
  `coins_applied_height` past `tip_finalize`'s finalized frontier by more than a
  one-block pipeline depth (the tear check compares coins_applied against
  utxo_apply_log's own contiguous ok=1 prefix + 1; no named constant).
  Chokepoint: `utxo_apply` `step_apply`
  precondition. The tear test compares `coins_applied` against `utxo_apply_log`'s **own**
  contiguous prefix + depth, not the `tip_finalize`-pinned global MIN H*.
- **Derived-state corollary.** One shared frontier reader
  (`reducer_frontier_log_frontier`, wrapping the existing static
  `log_contiguous_prefix`); `coins_best_block` derived from `coins_applied_height`; the
  node.db `utxos` table loses all read authority (SHA3 commitment + fast-sync serve
  re-pointed to `coins_kv` via the **same** encoder → byte-identical commitment).
- **Consensus parity (unchanged).** Neither gate touches Equihash params, activation
  heights, or block/tx validity. They constrain only the **sequencing** of when derived
  state may be installed. Accept/reject set identical to zclassicd.

## Ordered steps (each independently buildable + gated build+lint+test_parallel green)

Steps 1–4 (frontier reader, Invariant B, Invariant A, restore tip-selection) are
**landed**. Step 6 (derive `coins_best_block` from `coins_applied_height`,
killing the two-name drift) is **landed**
(`reducer_frontier_derive_coins_best` + `coins_kv_is_proven_authority`).

5. **Re-point SHA3 / fast-sync serve readers to coins_kv** (IN PROGRESS;
   parity-gated, `utxos` still present). The first authority primitive landed on
   2026-08-29: an independent read-only connection pins one proven `coins_kv`
   WAL generation, exposes its applied frontier and authority generation, and
   strictly validates the canonical `(txid,vout)` traversal. A concurrent
   writer fixture proves the scan cannot mix generations. Network chunk serving
   now refuses a live `node.db` fallback after an immutable snapshot cache miss.
   A sequential adapter now emits deterministic 500-entry wire chunks from that
   reader while deriving the full-set SHA3 and each chunk hash; boundary tests
   cover 499/500/501 rows and refuse oversize scripts without truncation.
   Remaining: persist and publish the immutable chunk artifact from this adapter,
   bind it to the exact `coins_applied_height - 1` active hash, and route receipt
   through the verified staging installer before enabling publication.
7. **Delete the dead heal ladder** (grep-proven zero callers): chain_restore_integrity,
   chain_restore rebuild ladder, stage_repair_reducer_frontier_{tipfin,refill,purge} +
   tear branch, reducer_frontier_reconcile_light, utxo_recovery_torn_anchor (M2),
   coins_view_sqlite rewind/reconcile/case-b gate.
8. **Simulator tests + real-data copy-prove + parity gate.**

## Redundancy ladder (reuses existing primitives — no new heal code)

1. **reducer / every tick** — Invariant B backpressure: a body-starved tip_finalize holds
   the whole pipeline at one height; `body_fetch` refills; resumes. No tear, no L2.
2. **boot / process start** — Invariant A + frontier-clamped restore: always commits the
   highest validated tip; no post-restore FATAL to crash-loop on.
3. **service-restart / supervisor** — `chain_tip_watchdog` (300/600/1200s, bounded 3) —
   now fires only on genuine peer/network stalls.
4. **external / systemd + native command** — after the bounded budget, emit
   `EV_OPERATOR_NEEDED`, leave node up degraded; `z23 ops state
   --subsystem=chain_tip_watchdog` surfaces it. No silent halt.

## Real-data proof (copies only, never live)

Fixture: `~/.zclassic-c23-postrestore-wedge-20260611` (frozen failing datadir: tip 3143175
ahead of header frontier 3141533, 1267 holes, 631 mismatches). zclassicd oracle at RPC
8232, tip 3,143,314. (1) Repro the crash-loop on a COPY with the current binary. (2) Patched
binary boots the COPY degraded-but-live at 3141533 (no FATAL) and the reducer advances
forward. (3) `coins_kv_serve_utxo_root` over `coins` == prior commitment over `utxos`
byte-for-byte, and == zclassicd `gettxoutsetinfo` at the same finalized height. Deploy is a
separate owner-gated action only after the copy reaches tip with byte-identical parity.

## Open questions to close during implementation

- Enumerate all `update_header_tip=true` tip-commit callers; assert each supplies a
  `header_frontier_hint` or a `rollback_auth` (no above-frontier tip slips the gate).
- Prove `block_index_loader` warm-boot tip == frontier on a clean datadir (no over-reject).
- `data_integrity_compute` shadow-seed: confirm non-consensus or repoint. The
  `utxo_projection` half of this question is CLOSED, not open — Program H1
  (commit 9b5add018) deleted the event-log-fed projection and its view, and
  `check-no-utxo-projection` now enforces that the copy stays dead.
  <!-- claim: file-absent lib/storage/src/utxo_projection.c # deleted by Program H1, 9b5add018 -->
  <!-- claim: gate-passes check-no-utxo-projection # the copy must stay dead -->
  <!-- claim: symbol-absent coins_view_projection lib/storage # the view is gone -->

  The `data_integrity_compute` half is still OPEN: the symbol is live in
  `lib/coins/src/utxo_commitment.c` and read by
  `app/controllers/src/blockchain_controller_chain.c`.
  <!-- claim: symbol-present data_integrity_compute lib/coins/src/utxo_commitment.c # open while this still exists -->

- `reconcile_light`: shrink-vs-delete after the step-7 grep shows registration sites.
  Still OPEN — the only production registration site is
  `app/jobs/src/reducer_frontier_replay.c` (the rest are tests), so this is a
  one-caller decision, not a survey.
  <!-- claim: symbol-present reconcile_light app/jobs/src/reducer_frontier_replay.c # open until it shrinks or goes -->
