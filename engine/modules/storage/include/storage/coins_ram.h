/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_ram — a flag-gated in-RAM open-addressed (robin-hood / linear-probe)
 * hash map keyed (txid[32],vout) -> coin, the HOT STORE for the BULK-FOLD MODE
 * (the from-genesis mint + the -refold-from-anchor catch-up).
 *
 * WHY (measured this session): the durable coins set is a SQLite WITHOUT ROWID
 * B-tree keyed on a random 32-byte txid blob (coins_kv.c). The bulk fold is
 * single-threaded CPU-bound doing O(log 1.3M) B-tree descents per add/spend/get
 * through a 234 MB WAL-index — ~461 ms/block and RISING as N grows. Disk/locks
 * are NOT the bottleneck (tmpfs, 0 iowait). An O(1)-amortised in-RAM hash map
 * removes the B-tree descent from the hot path. SQLite coins_kv stays the
 * steady-state store (1 block / 2.5 min — SQLite is fine there), so this is
 * STRICTLY OPT-IN: with the flag off the program is byte-for-byte unchanged.
 *
 * Contract this store must preserve (so the from-genesis fold stays SELF-
 * VERIFYING against the compiled checkpoint):
 *
 *   1. Read-through. A point/coins read missing the RAM map (a cold miss for a
 *      coin that lives only in the durable coins_kv — the seeded set or an
 *      earlier flush) reads through to coins_kv. A live RAM entry shadows the
 *      durable row; a RAM tombstone (spent) shadows it as ABSENT.
 *   2. Commitment identity. coins_ram_commitment iterates the EFFECTIVE live
 *      set (RAM overlay + durable rows it does not shadow) in canonical
 *      (txid,vout) order and feeds the SAME single encoder
 *      (utxo_commitment_sha3_write_record) — byte-for-byte equal to
 *      coins_kv_commitment over the same set. The checkpoint self-verify holds.
 *   3. Atomic per-flush durability. Mutations accumulate in RAM; every K blocks
 *      (and on clean stop) coins_ram_flush drains the overlay into the durable
 *      coins_kv inside ONE BEGIN IMMEDIATE that ALSO co-writes the utxo_apply
 *      stage cursor + coins_applied_height DOWN to the flushed height. The
 *      un-flushed tail is replayable: at boot coins_ram_reconcile_boot rewinds
 *      the cursor to the durable flush watermark so the fold re-applies the
 *      tail (a crash never serves a value above the watermark).
 *
 * Threading: the bulk fold is single-threaded on the reducer drive (it holds
 * progress_store_tx_lock for the whole step). This store is NOT internally
 * locked — it relies on that same single-writer discipline coins_kv already
 * documents. The flag must only be enabled for the bulk fold.
 */
#ifndef STORAGE_COINS_RAM_H
#define STORAGE_COINS_RAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;
struct coins;

/* Durable progress_meta watermark: the last height whose coins were FLUSHED
 * into coins_kv. The crash-replay anchor — see coins_ram_reconcile_boot. */
#define COINS_RAM_FLUSHED_HEIGHT_KEY "coins_ram_flushed_height"

/* True iff the in-RAM bulk-fold store is enabled for this process. Decided
 * ONCE at first call from the ZCL_FOLD_INRAM env var (or the -fold-inram boot
 * flag, which sets that env). Cheap to call on the hot path (cached). With it
 * false EVERY coins_ram_* entry below is a no-op / "not active" and coins_kv.c
 * runs its original SQLite path unchanged. */
bool coins_ram_enabled(void);

/* Lazily allocate the map (sized for ~4M entries) and bind it to the durable
 * coins_kv handle used for read-through + flush. Idempotent. Returns false on
 * OOM. No-op (returns true) when the flag is off. `flush_every_blocks` is the
 * block cadence (0 → ZCL_FOLD_INRAM_FLUSH_EVERY or the compiled default). A
 * second trigger, the live-slot HIGH WATER (ZCL_FOLD_INRAM_MAX_SLOTS, default
 * ~3M; 0 disables), flushes a dense window before it can grow the overlay
 * without bound and OOM. Both drain through coins_ram_note_applied. */
typedef bool (*coins_ram_frontier_writer_fn)(struct sqlite3 *, int32_t);
bool coins_ram_init(struct sqlite3 *db, uint32_t flush_every_blocks,
                    coins_ram_frontier_writer_fn frontier_writer);

/* True once coins_ram_init has bound a live map (and the flag is on). The
 * coins_kv.c shims test THIS, not coins_ram_enabled(), so a flagged build that
 * never called init (e.g. steady-state at-tip) still runs the SQLite path. */
bool coins_ram_active(void);

/* ── single-writer guard (the phashBlock-into-bucket UAF class) ──
 *
 * coins_ram is NOT internally locked — it relies on the reducer's single-writer
 * discipline (utxo_apply_stage_step_once holds progress_store_tx_lock for the
 * fold step). But the coins_kv_* READ shims route to coins_ram_* whenever
 * coins_ram_active(), and those shims are called from OTHER threads (bg-
 * validation worker pthreads, the RPC thread pool's gettxoutsetinfo, the
 * seal_service background thread). A reader loading s->script or holding a slot
 * pointer races the writer's free()+repoint / the grow() free(old_slots).
 *
 * The guard: a _Thread_local "am-the-writer" counter. coins_ram_writer_enter/
 * exit bracket the reducer's fold step (utxo_apply_stage_step_once).
 * coins_ram_writer_thread() reports whether the CALLING thread is inside that
 * bracket. The coins_kv.c READ shims gate overlay use on
 * (coins_ram_active() && coins_ram_writer_thread()); a non-writer thread
 * transparently takes the SQLite path (no UAF — SQLite is the FULLMUTEX shared
 * store). Counter form so nested/recursive entry is safe. NO-OP on the hot
 * path when the overlay is inactive (one relaxed load). */
void coins_ram_writer_enter(void);
void coins_ram_writer_exit(void);
bool coins_ram_writer_thread(void);

/* ── mint serial-pipeline READ marker (distinct from the writer bracket) ──
 *
 * The offline FULL mint (-mint-anchor, config/boot_mint_anchor.c
 * boot_mint_anchor_run) drives all eight reducer stages serially on ONE thread,
 * so script_validate's prevout resolver and utxo_apply's writer bracket run on
 * the SAME thread in different steps. The writer bracket (write visibility) only
 * spans utxo_apply; this marker (read visibility) spans the WHOLE drive so
 * coins_kv_overlay_safe() lets every stage — script_validate included — read the
 * un-flushed overlay (a writer-only gate would take the durable path and miss a
 * recent coin, wedging the fold: prevout_unresolved). Counter form so nested
 * entry is balanced.
 *
 * CONTRACT: valid ONLY for the single-threaded offline mint pipeline; NEVER
 * enter it on a live, multi-threaded node. Inert where not entered (default
 * false on every thread). A debug build asserts, in coins_ram_writer_enter, that
 * the writer bracket runs on this drive thread while the marker is active. */
void coins_ram_mint_drive_enter(void);
void coins_ram_mint_drive_exit(void);
bool coins_ram_mint_drive_thread(void);

/* ── overlay mutations (mirror coins_kv_add_many / coins_kv_spend_many) ── */

/* Insert/replace one output into the RAM overlay. Mirrors coins_kv_add. */
bool coins_ram_add(const uint8_t txid[32], uint32_t vout, int64_t value,
                   int32_t height, bool is_coinbase,
                   const uint8_t *script, size_t script_len);

/* Mark one output spent: shadow it as a tombstone so reads see it ABSENT even
 * if a durable coins_kv row still exists (it is removed at flush). A spend of
 * an output created earlier IN the same un-flushed window deletes the live RAM
 * entry outright (mirrors coins_kv_spend's DELETE-of-absent-is-noop). */
bool coins_ram_spend(const uint8_t txid[32], uint32_t vout);

/* ── reads (read-through to coins_kv on a cold miss) ── */

/* Mirror coins_kv_get. Returns true iff (txid,vout) is currently live in the
 * EFFECTIVE set (RAM overlay shadowing coins_kv). */
bool coins_ram_get(const uint8_t txid[32], uint32_t vout,
                   int64_t *value_out, uint8_t *script_out, size_t script_cap,
                   size_t *script_len_out);

/* O(1) single-prevout resolver: like coins_ram_get but ALSO returns the per-
 * coin metadata (height, is_coinbase) the fold's prevout resolver needs. This
 * is the point-lookup fast path that AVOIDS coins_ram_get_coins' two O(cap)
 * linear scans — the bulk fold's per-input hot path (utxo_apply_stage.c
 * projection_live_lookup) routes here. Returns true iff (txid,vout) is live in
 * the EFFECTIVE set: a LIVE overlay slot supplies all four fields; a TOMB
 * returns false (shadowed absent); a cold miss reads through to durable
 * coins_kv (one indexed point SELECT, no reconstruction). Any of the out-
 * pointers may be NULL. */
bool coins_ram_get_prevout(const uint8_t txid[32], uint32_t vout,
                           int64_t *value_out, uint8_t *script_out,
                           size_t script_cap, size_t *script_len_out,
                           int32_t *height_out, bool *is_coinbase_out);

/* Mirror coins_kv_exists over the effective set. */
bool coins_ram_exists(const uint8_t txid[32], uint32_t vout);

/* Mirror coins_kv_get_coins: reconstruct a `struct coins` for `txid` from the
 * effective live set (RAM overlay merged over the durable rows). Returns false
 * (num_vout==0) when the txid has no live output anywhere. */
bool coins_ram_get_coins(const uint8_t txid[32], struct coins *out);

/* ── aggregates / commitment over the EFFECTIVE set ── */

/* Live output count over the effective set. -1 on error. */
int64_t coins_ram_count(void);

/* Mirror coins_kv_setinfo over the effective set. */
bool coins_ram_setinfo(int64_t *num_txs, int64_t *num_txouts,
                       int64_t *total_amount);

/* SHA3-256 commitment over the effective set in canonical (txid,vout) order,
 * BYTE-IDENTICAL to coins_kv_commitment. Returns 0 on success, -1 on error.
 * O(n log n) (one sort). Used by the self-verify at the checkpoint height. */
int coins_ram_commitment(uint8_t out[32]);

/* Stream the EFFECTIVE set (RAM overlay merged over coins_kv) to a ZCLUTXO
 * snapshot at `out_path`, byte-identical to coins_kv_snapshot_write's format
 * and body encoder. Used by the anchor self-mint when the overlay is active so
 * the artifact reflects the COMPLETE applied set (including the un-flushed
 * tail) and its body SHA3 still matches the compiled checkpoint. Fills
 * *out_sha3 / *out_count / *out_total_supply on success.
 *
 * ONE canonical writer, versioned by DATA exactly like coins_kv_snapshot_write:
 * `shielded_or_null == NULL` → v1 (coins only); Sapling-only frontier
 * (sprout_len == 0 && nf_count == 0, sapling_len > 0) → v2; a Sprout frontier
 * and/or nullifier set → v3 (full storage/snapshot_shielded.h section). This is
 * the coins_ram overlay-active twin of coins_kv_snapshot_write and emits the
 * byte-identical stream for the same inputs. */
struct snapshot_shielded;
bool coins_ram_snapshot_write(const char *out_path, int32_t height,
                              const uint8_t anchor_block_hash[32],
                              const struct snapshot_shielded *shielded_or_null,
                              uint8_t out_sha3[32], uint64_t *out_count,
                              int64_t *out_total_supply);

/* ── durability ── */

/* Drain the RAM overlay into coins_kv and advance the durable flush watermark
 * to `flushed_height`, ALSO co-writing the utxo_apply stage cursor +
 * coins_applied_height to flushed_height+1, all in ONE BEGIN IMMEDIATE. After a
 * successful flush the overlay is empty and every live coin lives in coins_kv.
 * Returns false (and rolls back) on any error. */
bool coins_ram_flush(int32_t flushed_height);

/* Flush only when the note_applied cadence is due. Used by the utxo_apply
 * drain after its outer stage batch COMMITs, so the overlay can preserve its
 * own BEGIN/COMMIT/clear contract instead of nesting inside a stage batch. */
bool coins_ram_flush_due(void);

/* Clean-stop flush: drain the overlay through the highest height noted via
 * coins_ram_note_applied. No-op (true) when inactive or the overlay is empty
 * (nothing applied since the last flush). Call from shutdown BEFORE
 * coins_ram_shutdown so a graceful stop persists the un-flushed tail. */
bool coins_ram_flush_final(void);

/* Called per applied height by the fold AFTER coins for that height landed in
 * the overlay: bumps the in-RAM height counter and triggers coins_ram_flush
 * every K blocks. Returns false only if a triggered flush failed. A no-op
 * (true) when the store is inactive. */
bool coins_ram_note_applied(int32_t height);

/* Boot crash-replay reconcile: if the store is enabled and the durable flush
 * watermark is BELOW the persisted utxo_apply cursor, rewind the cursor +
 * coins_applied_height to the watermark so the fold re-applies the un-flushed
 * tail. For an in-progress mint/refold, an absent watermark means no RAM flush
 * has landed yet, so the safe replay point is genesis (cursor 0). One BEGIN
 * IMMEDIATE. No-op (true) when the flag is off, the watermark is absent on a
 * non-mint/refold datadir, or the cursor is already <= it. */
bool coins_ram_reconcile_boot(struct sqlite3 *db,
                              coins_ram_frontier_writer_fn frontier_writer);

/* Free the map. Does NOT flush (caller flushes first on a clean stop). */
void coins_ram_shutdown(void);

#endif /* STORAGE_COINS_RAM_H */
