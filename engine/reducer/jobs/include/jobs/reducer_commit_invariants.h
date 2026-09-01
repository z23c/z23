/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_commit_invariants — cheap O(batch) conservation checks asserted at
 * EVERY reducer batch commit, so state corruption surfaces at the commit that
 * introduces it instead of at the next hour-long install verify.
 *
 * The three invariants (advance-or-named-blocker doctrine — a violation
 * REFUSES the commit and raises the PERMANENT typed blocker
 * `utxo_apply.commit_invariant_violation` naming the exact height + which
 * invariant failed):
 *
 *   (a) coins_kv row-count delta == outputs created − inputs spent across the
 *       batch. `expected` is Σ(added − spent) accumulated in memory from each
 *       authored block's own delta stats (no table scan); `actual` is the
 *       exact physical coins_kv row delta metered at each add/spend from
 *       SQLite's affected-row result, so replacements and absent deletes
 *       retain their real zero delta without a read-before-write query or
 *       either batch-boundary COUNT(*) scan.
 *       Under the bulk-fold overlay the meter is skipped and (a) rides the
 *       fold's own from-genesis self-verify + crash-proof accounting; (b)/(c)
 *       still fire. See verify() for the gate.
 *
 *   (b) the anchor set is append-only / monotonic within the batch: every
 *       Sprout/Sapling frontier appended by the fold lands at a height strictly
 *       ABOVE the pool's pre-batch max and above every earlier append in the
 *       batch (O(1) per append; the baseline is one indexed MAX per pool).
 *
 *   (c) nullifier inserts are UNIQUE — a duplicate insert within the batch
 *       (same nf+pool) is never silently ignored (nullifier_kv_add is INSERT OR
 *       REPLACE, which would swallow it): an in-memory set catches it.
 *
 * Threading / lock order: every entry point below runs on the single reducer
 * drive thread while it holds progress_store_tx_lock (the drain wraps
 * begin..note..verify inside that lock). It NEVER takes csr->lock (LOCK-ORDER
 * LAW). All state is plain module-static (single-writer); no atomics needed.
 * All note and verify calls are no-ops unless a batch is active, so unbatched
 * drains, repair paths, and single-step tests are untouched. */
#ifndef ZCL_JOBS_REDUCER_COMMIT_INVARIANTS_H
#define ZCL_JOBS_REDUCER_COMMIT_INVARIANTS_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* Blocker id (literal so the check_blocker_remedy lint gate resolves it). */
#define UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID "utxo_apply.commit_invariant_violation"

/* Open a fresh conservation window: reset accumulators, arm the exact physical
 * coins delta meter (unless the overlay is active), and read per-pool anchor max. Call once,
 * right after stage_batch_begin opens the outer batch txn. */
void reducer_commit_invariants_batch_begin(struct sqlite3 *db);

/* Disable invariant (a) (the coins-count cross-check) for THIS batch. The
 * caller (utxo_apply drain) invokes this after batch_begin when the production
 * coins_kv-backed lookup is NOT installed — a synthetic test lookup resolves
 * prevouts that are not coins_kv rows, so a spend deletes nothing and (a)'s
 * premise (physical delta == created−spent) does not hold. (b)/(c) still run. */
void reducer_commit_invariants_disable_coins_check(void);

/* Note one authored block's coins delta (from its validated delta summary). */
void reducer_commit_invariants_note_coins(int height,
                                          uint64_t added, uint64_t spent);

/* Note one anchor frontier appended at `height` in `pool` (ANCHOR_POOL_*). */
void reducer_commit_invariants_note_anchor(int height, int pool);

/* Note one nullifier revealed at `height` in `pool` (NULLIFIER_POOL_*). */
void reducer_commit_invariants_note_nullifier(int height,
                                              const uint8_t nf[32], int pool);

/* A reorg unwind mutated coins/anchors/nullifiers inside this batch. The
 * unwind's inverse-delta math (re-adds + deletes across a rewound range) makes
 * the pure-forward conservation baseline invalid, so the batch is rebaselined:
 * verify() rebases and passes (loudly, INFO) rather than false-refusing. Reorg
 * batches are covered by the crash-replay/reorg test groups. */
void reducer_commit_invariants_note_reorg(void);

/* Verify at the commit boundary (BEFORE stage_batch_end's COMMIT). Returns:
 *   true  — invariants hold (or batch rebaselined / no batch): the caller may
 *           COMMIT.
 *   false — a violation was found: the caller MUST refuse (ROLLBACK) the batch.
 *           The typed blocker is already raised and the numbers LOG_ERR'd.
 * Always resets the window (a fresh begin is required for the next batch). */
bool reducer_commit_invariants_verify(struct sqlite3 *db);

/* Discard the window without verifying (the drain's no-commit / ROLLBACK path,
 * or a defensive reset). Idempotent. */
void reducer_commit_invariants_reset(void);

/* Wall-microseconds the last verify() spent reading the O(1) coins delta meter
 * (0 when the meter was gated/skipped). Overhead-measurement surface. */
int64_t reducer_commit_invariants_last_count_us(void);

#endif /* ZCL_JOBS_REDUCER_COMMIT_INVARIANTS_H */
