/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_kv — the reducer's canonical UTXO set as a `coins` table IN progress.kv.
 *
 * WHY (docs/work/tip-durability-collapse.md): the live coins set once lived in
 * a SEPARATE WAL database, folded from an out-of-txn event_log, while the stage
 * cursor + inverse-delta + utxo_apply_log row commit in progress.kv. Two WAL
 * databases have NO atomic cross-commit (WAL has no master journal) — a crash
 * drifted the coins from the cursor and no forward path could realign them (the
 * entire tip-wedge class). Storing the coins HERE, on the progress.kv handle,
 * makes every mutation commit inside the SAME stage_run_once BEGIN IMMEDIATE as
 * the cursor: every effect of a block lands or rolls back as one atomic unit.
 * That separate event-log-fed projection was deleted (Program H1) — coins_kv is
 * the one live UTXO ledger. Mirrors the proven created_outputs_index.
 *
 * Every function operates on the passed progress.kv handle and therefore
 * participates in whatever transaction the caller already holds open. Schema +
 * serialisation match the legacy `utxos` table column-for-column so the SHA3
 * UTXO commitment matches the legacy coins.db commitment.
 *
 * Callers may invoke from any thread: every function prepares and finalizes
 * its statement within the call (no shared statement state). See coins_kv.c
 * for why a cached statement is forbidden on this cross-thread shared handle.
 */
#ifndef STORAGE_COINS_KV_H
#define STORAGE_COINS_KV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;
struct sqlite3_stmt;
struct coins;

/* CREATE TABLE IF NOT EXISTS coins(...). Idempotent. */
bool coins_kv_ensure_schema(struct sqlite3 *db);

/* Insert or update one output. `script` may be NULL iff `script_len`==0. */
bool coins_kv_add(struct sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                  int64_t value, int32_t height, bool is_coinbase,
                  const uint8_t *script, size_t script_len);

/* DELETE one output (spend). A missing row is not an error. */
bool coins_kv_spend(struct sqlite3 *db, const uint8_t txid[32], uint32_t vout);

/* ── Batched per-block apply (utxo_apply_stage.c apply_coins_kv hot loop) ──
 *
 * coins_kv_add / coins_kv_spend each prepare+step+finalize their own statement
 * per row. A block with thousands of outputs/inputs pays that prepare/finalize
 * cost thousands of times. These _many variants prepare ONE statement (a
 * STACK-LOCAL stmt — NOT a module-static cached statement; the coins_kv.c
 * statement-lifetime prohibition is specifically about cached statics shared
 * across threads, which these are not) and reset+bind+step it for every row in
 * the SAME (txid,vout) order the per-row helpers would have used. The emitted
 * SQL is byte-identical to coins_kv_add / coins_kv_spend, so the resulting
 * coins set — and therefore coins_kv_commitment — is bit-identical. The
 * stack-local statement is finalized before the call returns; nothing escapes.
 *
 * Caller MUST preserve the intra-block invariant (adds BEFORE spends) by
 * invoking coins_kv_add_many for the whole added[] array first, then
 * coins_kv_spend_many for the whole spent[] array — exactly as the per-row
 * loop did. `txids`/`scripts` buffers must outlive the call (SQLITE_STATIC
 * binds); they do (the caller owns the parsed block until after this returns).
 *
 * Returns false on the first row whose step fails (the partial writes roll back
 * with the caller's enclosing transaction); the index of any failing row is
 * logged. count==0 is a clean true no-op. */
struct coins_kv_add_row {
    const uint8_t *txid;        /* 32 bytes */
    uint32_t       vout;
    int64_t        value;
    int32_t        height;
    bool           is_coinbase;
    const uint8_t *script;      /* may be NULL iff script_len==0 */
    size_t         script_len;
};
struct coins_kv_spend_row {
    const uint8_t *txid;        /* 32 bytes */
    uint32_t       vout;
};
bool coins_kv_add_many(struct sqlite3 *db, const struct coins_kv_add_row *rows,
                       size_t count);
bool coins_kv_spend_many(struct sqlite3 *db,
                         const struct coins_kv_spend_row *rows, size_t count);

/* True iff (txid,vout) is currently live (unspent). */
bool coins_kv_exists(struct sqlite3 *db, const uint8_t txid[32], uint32_t vout);

/* Point-read one live output (txid,vout). Returns true iff the output is
 * currently live (unspent), filling value/script via the non-NULL out-pointers.
 * If `script_cap` is smaller than the stored script length the script is
 * truncated to `script_cap` bytes, but `*script_len_out` always reports the
 * true length. This is script_validate's prevout resolver read source. A spent
 * or absent output returns false. */
bool coins_kv_get(struct sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                  int64_t *value_out, uint8_t *script_out, size_t script_cap,
                  size_t *script_len_out);

/* Point-read one live output plus the per-coin metadata needed by prevout
 * resolvers. Same live/absent/script truncation contract as coins_kv_get(),
 * with height/is_coinbase filled when requested. This avoids reconstructing a
 * sparse `struct coins` when a caller only needs one vout. */
bool coins_kv_get_prevout(struct sqlite3 *db, const uint8_t txid[32],
                          uint32_t vout, int64_t *value_out,
                          uint8_t *script_out, size_t script_cap,
                          size_t *script_len_out, int32_t *height_out,
                          bool *is_coinbase_out);

/* Overlay-aware cached prevout read: identical result/dispatch to
 * coins_kv_get_prevout, but on the durable-SQLite path it reuses the caller's
 * single-owner prepared statement (*cache) instead of preparing per call. The
 * overlay path never touches *cache. Single-owner rules from
 * coins_kv_get_prevout_sqlite_cached apply: one thread owns *cache and MUST
 * finalize it before `db` closes/rebinds. */
bool coins_kv_get_prevout_cached(struct sqlite3 *db, struct sqlite3_stmt **cache,
                                 const uint8_t txid[32], uint32_t vout,
                                 int64_t *value_out, uint8_t *script_out,
                                 size_t script_cap, size_t *script_len_out,
                                 int32_t *height_out, bool *is_coinbase_out);

/* Per-thread monotonic count of actual sqlite3_prepare_v2 calls made by point
 * lookups, including RAM-overlay read-through misses. Diagnostic sampling may
 * take a before/after delta without changing lookup behavior. */
uint64_t coins_kv_prepare_count_thread(void);

/* Count of live outputs. Returns -1 on error. */
int64_t coins_kv_count(struct sqlite3 *db);

/* Exact O(batch) physical-row delta meter for the reducer commit invariant.
 * begin/finish/cancel are thread-local and must bracket one outer SQLite
 * transaction. While armed, every coins_kv add/spend records SQLite's
 * affected-row result: replacing an existing (txid,vout) is 0, inserting a
 * new row is +1, deleting a live row is -1, and deleting an absent row is 0.
 * This preserves the old exact COUNT(*)-delta proof without a read-before-
 * write query or scanning the full chain state twice per batch.
 * finish returns false if no matching meter is active. */
void coins_kv_delta_begin(void);
void coins_kv_delta_cancel(void);
bool coins_kv_delta_finish(int64_t *delta_out);

/* ── RAW (overlay-bypassing) accessors ──────────────────────────────────
 *
 * The in-RAM bulk-fold overlay (storage/coins_ram.h) fronts coins_kv_get /
 * coins_kv_exists / coins_kv_get_coins / coins_kv_count when active. Those
 * shims must read THROUGH to the durable SQLite set on a cold miss WITHOUT
 * re-entering the overlay (infinite recursion). These _sqlite variants are the
 * raw SQLite implementations, called by the overlay's read-through path and by
 * the public shims when the overlay is inactive. App code should keep calling
 * the public coins_kv_* functions. */
bool    coins_kv_get_sqlite(struct sqlite3 *db, const uint8_t txid[32],
                            uint32_t vout, int64_t *value_out,
                            uint8_t *script_out, size_t script_cap,
                            size_t *script_len_out);
bool    coins_kv_get_prevout_sqlite(struct sqlite3 *db,
                                    const uint8_t txid[32], uint32_t vout,
                                    int64_t *value_out, uint8_t *script_out,
                                    size_t script_cap,
                                    size_t *script_len_out,
                                    int32_t *height_out,
                                    bool *is_coinbase_out);
bool    coins_kv_exists_sqlite(struct sqlite3 *db, const uint8_t txid[32],
                               uint32_t vout);
bool    coins_kv_get_coins_sqlite(struct sqlite3 *db, const uint8_t txid[32],
                                  struct coins *out);

/* ── CACHED point-read variants (single-owner prepared-statement reuse) ──────
 *
 * Byte-identical query + column extraction to the _sqlite variants above, but
 * the caller owns a persistent prepared statement (*cache) that is prepared
 * lazily on the first call and REUSED (reset + rebind + step) on every
 * subsequent call — hoisting the per-call sqlite3_prepare_v2 SQL compilation
 * (measured ~2 us, ≈half of a ~4 us point query) out of the fold hot loop.
 * Results are bit-for-bit the same as the fresh-prepare path, so terminal
 * state is unchanged (a pure HOW-not-WHAT change).
 *
 * NOT thread-safe on *cache: a prepared statement is single-owner. Use ONLY
 * where one thread owns *cache — the coins_ram single-writer bulk-fold read-
 * through (storage/coins_ram.h: reads gate on coins_ram_writer_thread() ||
 * coins_ram_mint_drive_thread(), both entered on the one fold/drive thread).
 * The owner MUST finalize *cache (sqlite3_finalize) before `db` is closed or
 * rebound — coins_ram_shutdown / the coins_ram_init rebind path do this. A
 * prepare failure leaves *cache NULL and returns false. */
bool    coins_kv_get_sqlite_cached(struct sqlite3 *db,
                                   struct sqlite3_stmt **cache,
                                   const uint8_t txid[32], uint32_t vout,
                                   int64_t *value_out, uint8_t *script_out,
                                   size_t script_cap, size_t *script_len_out);
bool    coins_kv_get_prevout_sqlite_cached(struct sqlite3 *db,
                                           struct sqlite3_stmt **cache,
                                           const uint8_t txid[32], uint32_t vout,
                                           int64_t *value_out,
                                           uint8_t *script_out,
                                           size_t script_cap,
                                           size_t *script_len_out,
                                           int32_t *height_out,
                                           bool *is_coinbase_out);
bool    coins_kv_exists_sqlite_cached(struct sqlite3 *db,
                                      struct sqlite3_stmt **cache,
                                      const uint8_t txid[32], uint32_t vout);
int64_t coins_kv_count_sqlite(struct sqlite3 *db);
bool    coins_kv_setinfo_sqlite(struct sqlite3 *db, int64_t *num_txs,
                                int64_t *num_txouts, int64_t *total_amount);
/* RAW batched write variants — the overlay's flush drains into the durable
 * SQLite set THROUGH these (the public _many shims would re-enter the overlay). */
bool    coins_kv_add_many_sqlite(struct sqlite3 *db,
                                 const struct coins_kv_add_row *rows,
                                 size_t count);
bool    coins_kv_spend_many_sqlite(struct sqlite3 *db,
                                   const struct coins_kv_spend_row *rows,
                                   size_t count);

/* Reconstruct a `struct coins` for `txid` from live rows (`out` is coins_init'd
 * by this call). Returns false (num_vout==0) if the txid has no live outputs.
 * Same two-pass shape as coins_view_sqlite. */
bool coins_kv_get_coins(struct sqlite3 *db, const uint8_t txid[32],
                        struct coins *out);

/* gettxoutsetinfo aggregate: distinct txids, total outputs, summed value.
 * Returns false on error. */
bool coins_kv_setinfo(struct sqlite3 *db, int64_t *num_txs,
                      int64_t *num_txouts, int64_t *total_amount);

/* SHA3-256 UTXO commitment over the coins set in canonical (txid,vout) order.
 * The serialisation matches the legacy coins.db gettxoutsetinfo commitment (the
 * read-flip relies on this matching the oracle). Returns 0 on
 * success, -1 on error. */
int coins_kv_commitment(struct sqlite3 *db, uint8_t out[32]);

/* Forward-declared (chain/checkpoints.h) so a caller that only needs to verify
 * against the compiled checkpoint does not have to pull the chain headers in. */
struct sha3_utxo_checkpoint;

/* THE single re-check of a compiled SHA3 UTXO checkpoint against the live
 * coins_kv content. Re-derives the canonical commitment via the SAME ONE fold
 * coins_kv_commitment() implements (the fold the -ratify-mint-anchor verb and
 * the -refold-from-anchor hard-assert already use — there is exactly one digest
 * implementation) and compares BOTH it and coins_kv_count() against `cp`.
 * Returns true iff the SHA3-256 commitment == cp->sha3_hash AND coins_kv_count
 * == cp->utxo_count.
 *
 * WHY: the frontier fold consumes only the checkpoint HEIGHT as a numeric floor
 * (app/jobs/src/reducer_frontier.c), so a transparent set that is wrong BELOW
 * the checkpoint is otherwise invisible. Wire this at the moments state is
 * written wholesale AT the checkpoint height (the -refold-from-anchor reseed
 * hard-assert) and expose it on demand (the -verify-rom operator verb). It does
 * NOT belong on the height-agnostic tip seeds — coins_kv_seed_from_node_db is
 * also called by the reindex epilogue and the recovery restore, which seed the
 * TIP set, where the checkpoint's cp->height commitment legitimately does not
 * apply (see the note on coins_kv_seed_from_node_db).
 *
 * out_got_root (32 bytes) and *out_got_count receive the derived values when
 * non-NULL (for the caller's banner / FATAL message). On mismatch a short typed
 * cause is written to `reason` (when non-NULL, reason_cap > 0): it always names
 * the diverging component with the substring "sha3" and/or "count" and includes
 * both hex digests. SELECT-only: NO markers are stamped, NO mutation. Returns
 * false (reason set) on a NULL/read error too. */
bool coins_kv_verify_against_checkpoint(struct sqlite3 *db,
                                        const struct sha3_utxo_checkpoint *cp,
                                        uint8_t out_got_root[32],
                                        int64_t *out_got_count,
                                        char *reason, size_t reason_cap);

/* ── Per-boundary UTXO root table (the keystone's reproducibility anchor) ──
 *
 * The MMB leaf carries a per-height utxo_root, but ONLY at boundary heights
 * (height % MMR_COMMITMENT_INTERVAL == 0). Three independent paths build the
 * same leaf — the live connect path (tip_finalize_post_step), the catch-up
 * path (rpc_blockchain_mmb_catchup), and the leaf-store rebuild
 * (mmb_leaf_store_rebuild) — and all three MUST stamp the IDENTICAL boundary
 * utxo_root or their leaf hashes diverge and every prior FlyClient proof
 * breaks. The leaf store persists only 32-byte leaf HASHES, so the boundary
 * root is not recoverable from it. The live connect path computes
 * coins_kv_commitment ONCE at each boundary and records it here; catch-up and
 * rebuild READ it back, so no path has to re-fold the historical UTXO set.
 *
 * Keyed per height under "mmb_utxo_root:<height>" in progress_meta (opaque
 * 32-byte blob). _set opens its OWN txn (own-BEGIN) — use ONLY when no
 * transaction is already open on `db`. _set_in_tx runs the statement inside
 * the caller's ALREADY-OPEN transaction (no inner BEGIN/COMMIT): this is the
 * variant the tip_finalize reducer step MUST use, because it runs inside the
 * stage's batch BEGIN IMMEDIATE + per-step SAVEPOINT — calling the own-BEGIN
 * _set there fails 100% ("cannot start a transaction within a transaction")
 * and never persists the root. _get returns false in *found when the boundary
 * root has not been recorded yet, in which case the caller uses the zero
 * sentinel (the leaf hash is then the pre-keystone value for that height). A
 * boundary skipped under the IBD / live-catch-up defer gates
 * (tip_finalize_post_step.c) is never re-folded — no path can observe the
 * historical coins set at that height once the tip has moved past it — so
 * its binding stays absent, never forged.
 */
bool coins_kv_boundary_root_set(struct sqlite3 *db, int32_t height,
                                const uint8_t utxo_root[32]);
bool coins_kv_boundary_root_set_in_tx(struct sqlite3 *db, int32_t height,
                                      const uint8_t utxo_root[32]);
bool coins_kv_boundary_root_get(struct sqlite3 *db, int32_t height,
                                uint8_t out_utxo_root[32], bool *found);

/* One-shot idempotent boot migration marker: stamps migration-complete when
 * coins_kv already holds the live set (forward-built / snapshot-seeded), so the
 * read path is recognised as canonical. No-op on an empty coins_kv, which
 * re-derives from block bodies via the normal fold (the event-log-fed UTXO
 * projection this once copied from was deleted in Program H1). Safe to call
 * before progress_store is open (returns true, no-op). */
bool coins_kv_boot_rebuild_if_needed(struct sqlite3 *progress_db);

/* Seed coins_kv from node.db's `utxos` table right after a cold
 * LevelDB import (the projection-based boot rebuild sees an empty
 * projection on that boot and copies nothing). Idempotent via the
 * same migration stamp; no-op when coins_kv already has rows. */
bool coins_kv_seed_from_node_db(struct sqlite3 *progress_db,
                                const char *node_db_path);

/* ── Bootstrap-seed checkpoint-content gate ──────────────────────────────────
 *
 * Turns the documented cure copy-proof into a resident boot invariant: a
 * bootstrap seed that reaches the compiled SHA3 UTXO checkpoint height MUST
 * reproduce its committed UTXO commitment (get_sha3_utxo_checkpoint()->
 * sha3_hash + utxo_count), else it is a height-correct/state-wrong set that
 * must never seed the fold.
 *
 * The verdict is height-triggered so it is INVISIBLE on the ordinary full-tip
 * seed (whose newest coin is far above the checkpoint): only a set whose
 * MAX(coins.height) equals cp->height CLAIMS to be the checkpoint-anchored
 * state and is compared. SELECT-only — safe to call mid-transaction on the
 * seed's own connection (it reads the connection's uncommitted rows).
 *   NOT_CHECKED — no compiled checkpoint (testnet/regtest), the set does not
 *                 reach cp->height, or the applicability read failed (fail-open
 *                 on the gate's ability to RUN, never a false FATAL).
 *   MATCH       — set at cp->height reproduces cp->sha3_hash and cp->utxo_count.
 *   MISMATCH    — set at cp->height, wrong commitment/count (or the commitment
 *                 could not be computed for a confirmed checkpoint set): the
 *                 seed functions roll this back and _exit rather than fold from
 *                 an unproven base. */
enum coins_kv_checkpoint_verdict {
    COINS_KV_CHECKPOINT_NOT_CHECKED = 0,
    COINS_KV_CHECKPOINT_MATCH       = 1,
    COINS_KV_CHECKPOINT_MISMATCH    = 2,
};
enum coins_kv_checkpoint_verdict
coins_kv_seed_checkpoint_verdict(struct sqlite3 *db);

/* ── coins_applied_height — the canonical contiguous applied-frontier ──
 *
 * A single progress_meta key recording the contiguous applied frontier of the
 * coins_kv UTXO set: it ALWAYS equals the utxo_apply stage cursor by
 * construction (see docs/work/sync-organism-map.md). The frontier is
 * co-committed inside the SAME transaction as every WRITE that moves the
 * utxo_apply cursor — never lagging it — unlike MAX(coins.height), which is only
 * the most-recent surviving coin's creation height and cannot see an interior
 * hole. The complete set of utxo_apply cursor writers, each co-writing this
 * frontier in its own transaction:
 *   (a) forward apply (utxo_apply_stage.c step_apply): successful applies only
 *       write frontier = cursor+1. Failed verdicts return JOB_BLOCKED with the
 *       cursor/frontier unchanged, so a later height cannot apply over a hole;
 *   (b) reorg unwind (utxo_apply_delta_reorg.c): pulls the frontier BACK to
 *       fork+1 (a PLAIN set — the decrease must not be blocked);
 *   (c) the poison_rewind cursor-mover (stage_repair_rewind.c
 *       stage_repair_header_solution_poison_rewind): forces the utxo_apply cursor
 *       DOWN to the frontier height and co-writes frontier = height. Its ok=1
 *       guard (success_checked_logs includes utxo_apply_log) proves no coins were
 *       mutated at/above that height, so frontier == coins is exact.
 * The ONE non-co-writing cursor-touching path is the snapshot bulk seed
 * (coins_kv_seed_from_node_db): it bulk-copies the source UTXOs but does
 * NOT write this frontier directly — it relies on the snapshot anchor stamping
 * the utxo_apply cursor + the next-boot if-absent backfill below to seed the
 * frontier from that cursor, with a transient ABSENT="unknown" window in between
 * (a clean unknown, never 0-as-applied). This gives the self-heal a single
 * non-divergent coins-frontier input with a stage-name-independent name. The
 * value is stored as a stable little-endian int64 blob under this key. */
#define COINS_APPLIED_HEIGHT_KEY "coins_applied_height"

/* Canonical state-frontier writer, implemented by the utxo_apply stage. This
 * storage declaration lets tests and callback consumers name the capability;
 * production callers request it through utxo_apply_frontier_set_in_tx. */
bool coins_kv_set_applied_height_in_tx(struct sqlite3 *db, int32_t height);

/* Read the applied frontier. *found is false (a clean "unknown") when the row
 * is absent — a fresh / un-synced datadir reports ABSENT, never 0-as-applied.
 * Returns false only on a hard read error (db NULL / malformed blob).
 *
 * THE coins-best derivation lives at
 * app/jobs/include/jobs/reducer_frontier.h reducer_frontier_derive_coins_best
 * (coins-best height = this value - 1; hash from the durable stage logs).
 * The node_state 'coins_best_block' key is a CACHE of that derivation. */
bool coins_kv_get_applied_height(struct sqlite3 *db, int32_t *out, bool *found);

/* One-shot migration stamp: set when coins_kv provably holds the live coin
 * set (fresh-sync forward population, projection bulk-copy, or
 * coins_kv_seed_from_node_db). Written by coins_kv_boot_rebuild.c / the
 * seed path; read by the proven-authority predicate below. */
#define COINS_KV_MIGRATION_COMPLETE_KEY "coins_kv_migration_complete"

/* Stamp the migration-complete marker (own-txn; a pure provenance bit with NO
 * coin mutation — the same standalone-txn justification as
 * coins_kv_mark_self_folded). Set it once a path has provably populated coins_kv
 * with the live set: a full-validation mint whose fold reproduces the compiled
 * checkpoint, a fresh-sync forward population, or a projection bulk-copy.
 * Idempotent. Returns false on a DB error (logs context). */
bool coins_kv_mark_migration_complete(struct sqlite3 *db);

/* THE proven-authority predicate — true iff coins_kv is the CANONICAL coin
 * store on this datadir (the wave-2 "canonical datadir" signal; the same
 * three rungs the L1 torn-anchor heal requires):
 *   (1) coins_applied_height present (durable applied frontier);
 *   (2) COINS_KV_MIGRATION_COMPLETE_KEY == 1 (the store provably holds the
 *       live set — a cursor-backfilled frontier alone is NOT proof);
 *   (3) coins_kv_count > 0.
 * On true, *out_applied (nullable) receives the applied frontier. Read
 * errors return false — degrading to the STRICTER legacy gates, never the
 * permissive derived path. SELECT-only. */
bool coins_kv_is_proven_authority(struct sqlite3 *db, int32_t *out_applied);

/* ── Self-folded provenance marker (the sovereign-cure G-SOV part 3) ──────────
 *
 * THE bit that distinguishes a CHECKPOINT-ROOT-VERIFIED anchor seed from a
 * BORROWED-and-stamped one. coins_kv_is_proven_authority() is true in BOTH
 * cases — the borrowed
 * zclassicd-chainstate copy (coins_kv_seed_from_node_db) also stamps
 * COINS_KV_MIGRATION_COMPLETE_KEY — so the migration stamp ALONE cannot prove
 * the UTXO trust root is checkpoint-bound. This durable progress.kv key is SET
 * only by a self-derived/checkpoint-verified path: a from-anchor reseed from a
 * SHA3-checkpoint-bound minted snapshot, or a from-genesis bodies-only refold.
 * It proves the loaded set equals the compiled checkpoint root; it does not, by
 * itself, prove which machine produced the snapshot file.
 *
 * LIFECYCLE — the explicit -refold-from-anchor path SETs this marker only after
 * a verified minted snapshot reproduces the compiled checkpoint and the anchor
 * cursor arm commits. Borrowed/node.db reseeds CLEAR it (coins_kv_clear_self_
 * folded, also folded into coins_kv_reset_for_reseed) so a later borrow cannot
 * inherit a stale claim. The default live borrowed-snapshot path still does not
 * set it, so coins_kv_tip_is_self_derived correctly reports that shape as
 * NOT-yet-sovereign (borrowed-and-stamped). */
#define COINS_KV_SELF_FOLDED_KEY "coins_kv_self_folded"

/* Stamp the self-folded marker (own-txn, the same standalone-txn justification
 * as coins_kv_backfill_applied_height_if_absent: a pure provenance bit, NO coin
 * mutation). Idempotent. Returns false on a DB error (logs context). */
bool coins_kv_mark_self_folded(struct sqlite3 *db);

/* Clear the self-folded marker (own-txn). Idempotent — an absent key is a clean
 * no-op true. Returns false on a DB error (logs context). */
bool coins_kv_clear_self_folded(struct sqlite3 *db);

/* SELECT-only reader: true iff COINS_KV_SELF_FOLDED_KEY is set — the coins_kv
 * set was produced by a self-derived path, never the borrowed node.db copy. A
 * read error degrades to false (conservatively "not proven self-folded"). */
bool coins_kv_contains_refold_marker(struct sqlite3 *db);

/* ── The composite sovereignty gate (G-SOV parts 2 & 3) ──────────────────────
 *
 * A boot's (tip, utxo) is SELF-VERIFIED-SOVEREIGN at H* iff ALL THREE hold
 * (docs/work/self-verified-tip-plan.md, G-SOV):
 *   (1) H* climbed past the target wedge height   [RUNTIME, TWO-SAMPLE — the
 *       copy-prove harness owns it; NOT checkable from one DB snapshot here];
 *   (2) coins_applied_height == hstar + 1          [checked here — continuous
 *       log coverage, no NULL/stamped span];
 *   (3) coins_kv_is_proven_authority() == false, OR (== true AND
 *       coins_kv_contains_refold_marker())          [checked here — separates
 *       self-derived from borrowed-and-stamped].
 *
 * This predicate checks the two STATICALLY-DERIVABLE parts (2 and 3) from ONE
 * consistent progress.kv snapshot; the caller passes the H* it computed (via
 * reducer_frontier_compute_hstar) and remains responsible for part 1 (the
 * climb). Returns true iff parts 2 and 3 hold. On false, *reason (when
 * non-NULL, cap > 0) receives a short machine-readable cause. SELECT-only. */
bool coins_kv_tip_is_self_derived(struct sqlite3 *db, int32_t hstar,
                                  char *reason, size_t reason_cap);

/* One-time idempotent boot backfill for existing datadirs that predate this
 * key: if coins_applied_height is ABSENT, seed it (in its OWN BEGIN IMMEDIATE —
 * the one allowed standalone txn, since it backfills a derived value that
 * already equals the durable cursor with NO coin mutation) from the trusted
 * utxo_apply stage cursor. NEVER seeds from MAX(coins.height). No-op once the
 * key exists. Returns false on error (next boot retries). */
typedef bool (*coins_kv_frontier_writer_fn)(struct sqlite3 *, int32_t);
bool coins_kv_backfill_applied_height_if_absent(
    struct sqlite3 *db, coins_kv_frontier_writer_fn writer);

/* Seed coins_applied_height for a PRISTINE from-genesis regtest store so the
 * on-demand-mining sovereignty gate (coins_kv_tip_is_self_derived part 2:
 * coins_applied_height == hstar+1) recognises a genuinely self-derived
 * from-genesis node as mint-eligible. A fresh regtest datadir has NO utxo_apply
 * cursor and never folds a block ABOVE genesis until `generate` runs — but
 * generate's guard fires FIRST (at hstar==0, where the required frontier is 1),
 * so without this the gate refuses forever: a chicken-and-egg the cursor
 * backfill above cannot break (there is no cursor row yet to derive from).
 * Genesis is applied state by construction — its coinbase is consensus-
 * unspendable, so the coin delta is empty — hence coins_applied_height = 1 is
 * EXACTLY the value the forward fold co-commits the instant it applies genesis
 * (cursor_in 0 -> next_cursor 1). See app/controllers/src/sovereignty_controller.c
 * and docs/MVP.md C7. Called ONLY from utxo_apply_stage_init (this frontier's
 * single writer — check-frontier-single-writer); the paired genesis anchor that
 * unblocks the follower's proof_validate is seeded separately at boot
 * (config/src/boot_services.c).
 *
 * Fail-closed + idempotent; NEVER touches a borrowed seed:
 *   - no-op if coins_applied_height is already present (never re-seed — a later
 *     legitimate rewind must be free to move it);
 *   - no-op if the store is a proven-authority (borrowed / snapshot) seed —
 *     those are refused by the gate's part 3 (borrowed_seed_no_refold_marker),
 *     never minted on, and already carry coins_applied_height anyway;
 *   - no-op if any coins exist or a utxo_apply cursor row is already stamped
 *     (the store is not a pristine genesis store — a fold/seed has begun).
 * The CALLER MUST gate on chain_params fMineBlocksOnDemand (true ONLY for
 * regtest) so main/testnet boot is unchanged. Returns false only on a store
 * write error (the next boot retries). */
bool coins_kv_seed_genesis_applied_height(
    struct sqlite3 *db, coins_kv_frontier_writer_fn writer);

/* Truncate coins_kv + clear the migration stamp + drop coins_applied_height so
 * a subsequent coins_kv_seed_from_node_db performs a FRESH copy. The reindex
 * epilogue (app/services/src/reindex_epilogue.c) calls this right after a full
 * from-genesis replay: the replayed node.db `utxos` mirror is the authority and
 * coins_kv is being rebuilt from it in the SAME boot, so the pre-reindex set
 * (which may carry rows the replay legitimately deleted) must be discarded
 * first — coins_kv_seed_from_node_db short-circuits when the migration stamp is
 * already set, so without clearing it the reseed would no-op over a stale set.
 *
 * ONE BEGIN IMMEDIATE: DELETE FROM coins; clear COINS_KV_MIGRATION_COMPLETE_KEY
 * + COINS_APPLIED_HEIGHT_KEY. The single legal standalone txn for a reindex
 * epilogue (boot single-writer, no stage threads running yet — same
 * justification as boot_index_clear_coins_state). Idempotent (a fresh store is
 * a no-op delete + absent-key clears). Returns false on error so the caller
 * aborts the epilogue and leaves the reindex sentinel pending for a retry. */
bool coins_kv_reset_for_reseed(struct sqlite3 *db);

/* Durable generation of the entire coins authority.  Every destructive
 * reset increments it atomically; forward reducer folds do not. */
#define COINS_KV_AUTHORITY_GENERATION_KEY "coins_kv_authority_generation.v1"
bool coins_kv_get_authority_generation(struct sqlite3 *db, uint64_t *out);
bool coins_kv_bump_authority_generation_in_tx(struct sqlite3 *db);

/* ── ANCHOR-SET MINT writer (lib/storage/src/coins_kv_snapshot_write.c) ──
 *
 * Stream the LIVE coins_kv set to a UTXO snapshot sidecar in the exact
 * on-disk format the loader (lib/chain/src/utxo_snapshot_loader.c) reads and
 * the `--gen-utxo-snapshot` tool writes:
 *
 *   Header (104 bytes, little-endian): magic="ZCLUTXO\0", version u32=1,
 *     reserved u32, height u32, reserved u32, count u64, total_supply i64,
 *     anchor_block_hash[32], sha3_hash[32] (SHA3-256 over the body).
 *   Body: `count` records in canonical (txid,vout) order, each
 *     txid[32], vout u32, value i64, script_len u32, script[*], height u32,
 *     is_coinbase u8.
 *
 * The per-record encoding is the SAME single encoder as coins_kv_commitment
 * (utxo_commitment_sha3_write_record), so the body SHA3 written here equals
 * coins_kv_commitment(db) — and therefore comparable to the
 * compiled checkpoint root. The caller (the `-mint-anchor` driver) HARD-ASSERTS
 * the written header's sha3_hash + count against checkpoints.c before trusting
 * the artifact.
 *
 * Writes to `out_path` atomically (out_path.tmp then rename). `height` and
 * `anchor_block_hash` are stamped into the header for the loader's bind check.
 * On success fills *out_sha3 (32 bytes) and *out_count with what was written.
 * Returns true on success, false (and removes the temp file) on any error.
 *
 * ONE canonical writer, versioned by DATA (the header version byte is derived
 * from the shielded argument's content, NEVER encoded in the function name):
 *
 *   - `shielded_or_null == NULL`            → format version 1 (coins only).
 *   - `shielded` carries ONLY a Sapling     → format version 2: append a single
 *     frontier (sprout_len == 0 &&            Sapling commitment-tree frontier
 *     nf_count == 0, sapling_len > 0)         section ([u32 sapling_len LE][blob])
 *                                             after the UTXO records, still inside
 *                                             the body SHA3. The frontier must be
 *                                             incremental_tree_serialize output for
 *                                             the tree AT `height`; a fresh node
 *                                             root-verifies it against the PoW-proven
 *                                             hashFinalSaplingRoot, skipping replay.
 *   - `shielded` carries a Sprout frontier  → format version 3: append the full
 *     and/or a nullifier set                  SHIELDED section (Sapling + Sprout
 *     (sprout_len > 0 || nf_count > 0)        frontiers + the complete nullifier
 *                                             set — see storage/snapshot_shielded.h),
 *                                             still inside the body SHA3. This lets a
 *                                             fresh node install the shielded state
 *                                             (anchor_kv frontier rows + the nullifier
 *                                             set) that gates the first post-seed
 *                                             shielded transaction WITHOUT borrowing a
 *                                             zclassicd chainstate. Only the Sapling
 *                                             frontier is header-verifiable; the Sprout
 *                                             frontier and nullifier set inherit the
 *                                             snapshot's overall body-SHA3 trust.
 *
 * NOTE: `out_sha3` is the FULL body SHA3 (coins + any shielded section), i.e. the
 * value stamped into the header and re-checked by uss_open. For the coins-only
 * commitment (the compiled-checkpoint comparison) call coins_kv_commitment(). */
struct snapshot_shielded;
bool coins_kv_snapshot_write(struct sqlite3 *db, const char *out_path,
                             int32_t height, const uint8_t anchor_block_hash[32],
                             const struct snapshot_shielded *shielded_or_null,
                             uint8_t out_sha3[32], uint64_t *out_count,
                             int64_t *out_total_supply);

#endif /* STORAGE_COINS_KV_H */
