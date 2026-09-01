/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Incremental UTXO set commitment using XOR-hash accumulator.
 * Each UTXO is hashed to 32 bytes via SHA256(txid || vout || value || height).
 * The accumulator is the XOR of all UTXO hashes.
 * Add and remove are the same operation (XOR is self-inverse). */

#ifndef ZCL_UTXO_COMMITMENT_H
#define ZCL_UTXO_COMMITMENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct utxo_commitment {
    uint8_t accumulator[32]; /* XOR of SHA256(utxo) for all UTXOs */
    uint64_t count;          /* number of UTXOs in the set */
};

/* Initialize to empty set */
void utxo_commitment_init(struct utxo_commitment *uc);

/* Add a UTXO: XOR SHA256(txid || vout_le(4) || value_le(8) || height_le(4))
 * into the accumulator and increment count. The 48-byte preimage is in that
 * EXACT order and width (txid first, then little-endian vout/value/height) —
 * this is the commitment's must-never-fork hash input; any caller computing
 * the same set MUST feed identical bytes (see coins_view_cache_recompute_
 * commitment and utxo_commitment_compute_db, which use these same fields).
 * No-op when g_utxo_commitment_skip is set. */
void utxo_commitment_add(struct utxo_commitment *uc,
                          const uint8_t txid[32], uint32_t vout,
                          int64_t value, int32_t height);

/* Remove a UTXO: byte-for-byte the SAME operation as add (XOR is
 * self-inverse), but decrements count (saturating at 0). Pass the identical
 * (txid, vout, value, height) the UTXO was added with, or the accumulator
 * will not cancel. No-op when g_utxo_commitment_skip is set. */
void utxo_commitment_remove(struct utxo_commitment *uc,
                             const uint8_t txid[32], uint32_t vout,
                             int64_t value, int32_t height);

/* Combine two set commitments: XOR the accumulators and ADD the counts.
 * Used to fold a child cache's incremental delta into its parent on flush.
 * Unlike add/remove this is unconditional — it ignores g_utxo_commitment_skip. */
void utxo_commitment_merge(struct utxo_commitment *dst,
                            const struct utxo_commitment *src);

/* Serialize: 32-byte accumulator (raw) + 8-byte count (little-endian) = 40
 * bytes. */
#define UTXO_COMMITMENT_SERIALIZED_SIZE 40

void utxo_commitment_serialize(const struct utxo_commitment *uc,
                                uint8_t buf[UTXO_COMMITMENT_SERIALIZED_SIZE]);

/* Inverse of serialize. Returns false (uc untouched) if len <
 * UTXO_COMMITMENT_SERIALIZED_SIZE; otherwise reads the 32-byte accumulator
 * and the 8-byte little-endian count. Trailing bytes beyond 40 are ignored. */
bool utxo_commitment_deserialize(struct utxo_commitment *uc,
                                  const uint8_t *buf, size_t len);

/* Equal iff BOTH count and the 32-byte accumulator match. The count is part
 * of the identity, so two different sets that happen to XOR-collide still
 * compare unequal unless they also hold the same number of UTXOs. */
bool utxo_commitment_equal(const struct utxo_commitment *a,
                            const struct utxo_commitment *b);

/* Process-wide kill switch for incremental tracking. While true,
 * utxo_commitment_add/remove are no-ops (count and accumulator frozen) so a
 * bulk reindex/import does not pay per-UTXO hashing. After such a bulk
 * operation the live commitment is STALE and must be rebuilt from the set via
 * utxo_commitment_compute_db (or _sha3_compute). Atomic: read with relaxed
 * ordering from the hot path. utxo_commitment_merge ignores this flag. */
extern _Atomic bool g_utxo_commitment_skip;

/* ── Checkpoint verification ──────────────────────────────── */

struct sqlite3;

/* Recompute the XOR commitment over the WHOLE `utxos` table (txid,vout
 * ordered) and compare to *expected via utxo_commitment_equal. Returns false
 * (and logs a count line) on mismatch or NULL args. O(n); startup/periodic
 * use only. Uses the SAME per-UTXO hash inputs as utxo_commitment_add. */
bool utxo_commitment_verify_db(struct sqlite3 *db,
                                const struct utxo_commitment *expected);

/* Recompute the XOR commitment from the full SQLite `utxos` table into *out
 * (path-independent — derived from the live set, not any incremental field).
 * Rows ordered by (txid,vout); each contributes
 * SHA256(txid||vout_le||value_le||height_le), identical to
 * utxo_commitment_add. On a prepare error *out is left initialized to empty.
 * O(n). */
void utxo_commitment_compute_db(struct sqlite3 *db,
                                 struct utxo_commitment *out);

/* Persist *uc (40-byte serialization) into node_state under key
 * 'utxo_commitment' (INSERT OR REPLACE). Returns false on NULL args or any
 * SQLite prepare/step failure (logged). */
bool utxo_commitment_save_checkpoint(struct sqlite3 *db,
                                      const struct utxo_commitment *uc);

/* Load the 'utxo_commitment' checkpoint from node_state into *uc. Returns
 * false if no row is stored, the blob is shorter than
 * UTXO_COMMITMENT_SERIALIZED_SIZE, or on NULL args / prepare failure. */
bool utxo_commitment_load_checkpoint(struct sqlite3 *db,
                                      struct utxo_commitment *uc);

/* node_state key holding the height through which the 'utxo_commitment'
 * checkpoint above is ASSERTED accurate (every coin change up to and
 * including this height has been folded in). Only utxo_commitment_save_
 * checkpoint_at_height() sets it; the plain utxo_commitment_save_checkpoint()
 * (used whenever the caller does NOT know an exact covering height) deletes
 * it, so a stale/absent height key can never be paired with a blob it
 * doesn't actually describe. A reader that needs to trust this height for
 * incremental maintenance MUST go through
 * utxo_commitment_load_checkpoint_at_height(), never read the key alone. */
#define UTXO_COMMITMENT_HEIGHT_KEY "utxo_commitment_height"

/* Save *uc and stamp UTXO_COMMITMENT_HEIGHT_KEY = height in node_state
 * (two INSERT-OR-REPLACE statements, no implicit BEGIN/COMMIT — atomic only
 * if the caller's own transaction wraps this call, matching the "same commit
 * boundary that mutates coins" contract an incremental maintainer relies on).
 * Use ONLY when `height` is an exact covering height: a full recompute over
 * state known consistent through `height`, or an incremental fold that
 * started from a trusted _at_height baseline and only advanced it to
 * `height`. Returns false (nothing persisted) on NULL args; a mid-way SQLite
 * failure is logged and non-fatal (matches utxo_commitment_save_checkpoint's
 * existing best-effort contract — this is a derived diagnostic aid, never a
 * consensus input). */
bool utxo_commitment_save_checkpoint_at_height(struct sqlite3 *db,
                                               const struct utxo_commitment *uc,
                                               int32_t height);

/* Load *uc AND *out_height together. Returns true only when BOTH the blob and
 * a valid height stamp are present — a checkpoint saved via the plain
 * utxo_commitment_save_checkpoint() (no height claim) reports false here even
 * though the blob itself loads fine, because there is no trustworthy covering
 * height to incrementally build on top of. *uc / *out_height are left
 * untouched on false. */
bool utxo_commitment_load_checkpoint_at_height(struct sqlite3 *db,
                                               struct utxo_commitment *uc,
                                               int32_t *out_height);

/* Boot-time / recovery integrity check for the checkpoint against the live
 * `utxos` mirror table, height-tracking aware. `mirror_height` is the height
 * the caller's `utxos` table (on `db`) is currently persisted through
 * (typically UTXO_MIRROR_SYNC_CURSOR_KEY read from the SAME db); pass a
 * negative value if unknown.
 *
 * FAST PATH: if the stored checkpoint carries a covering-height stamp
 * (utxo_commitment_load_checkpoint_at_height) equal to `mirror_height`, it is
 * trusted BY CONSTRUCTION — utxo_mirror_delta_apply (and a wholesale mirror
 * rebuild) maintain that stamp at the SAME commit boundary that mutates the
 * mirror, so a matching stamp means every coin change through that height is
 * already folded in. Returns true immediately, *out_computed (if non-NULL)
 * gets the trusted checkpoint, *out_refreshed stays false — NO O(n) `utxos`
 * scan runs. This is the common case on a cleanly-shut-down node.
 *
 * SLOW PATH (stamp missing or mismatched — never tracked, or a torn shutdown
 * left it behind): the genuinely-stale safety net. Recomputes over `utxos`
 * (utxo_commitment_compute_db, O(n)) and compares; a mismatch refreshes the
 * stored checkpoint (height-stamped when `mirror_height` is known, else the
 * plain unstamped form) and sets *out_refreshed. *out_computed gets the
 * recomputed digest either way.
 *
 * Returns false only for a NULL `db`; a match, a refresh, and "nothing
 * stored yet" are all reported true (nothing for the caller to escalate —
 * corruption classification, if any, is the caller's job). */
bool utxo_commitment_boot_check_and_refresh(struct sqlite3 *db,
                                            int32_t mirror_height,
                                            struct utxo_commitment *out_computed,
                                            bool *out_refreshed);

/* Re-derive the XOR checkpoint from the live `utxos` table (utxo_commitment_compute_db)
 * and OVERWRITE the stored node_state('utxo_commitment') checkpoint with it.
 * Since the covering height is unknown to this call, it saves via the PLAIN
 * (unstamped) form — which clears any UTXO_COMMITMENT_HEIGHT_KEY stamp a
 * prior _at_height save left behind, so a later incremental-maintenance
 * reader never trusts a height that doesn't describe this fresh blob. Prefer
 * utxo_commitment_boot_check_and_refresh() at a known mirror height so the
 * checkpoint stays live-trackable; this is for callers (reindex, corruption-
 * audit resync) with no cheap height to assert. Logs the count on success /
 * a warning on save failure. Copies the recomputed digest to *out_optional
 * when non-NULL. Returns the save result. */
bool utxo_commitment_resync_from_db(struct sqlite3 *db,
                                    struct utxo_commitment *out_optional);

/* ── Bounded keyspace-window commitment (state_auditor) ────── */

/* Compute the XOR-hash accumulator (the SAME hash-and-fold used by
 * utxo_commitment_add / utxo_commitment_compute_db) over a BOUNDED slice of
 * `table`'s (txid,vout) primary-key keyspace: rows with txid >= txid_lo,
 * ordered (txid,vout), capped at max_rows.
 *
 * WHY a keyspace window and not a height range: `table` is queried through
 * its (txid,vout) PRIMARY KEY, so "txid >= ? ORDER BY txid,vout LIMIT ?" is
 * an index range scan (O(log n + max_rows)) on BOTH the `coins` table
 * (progress.kv authority — no secondary index, and this deliberately never
 * adds one to that hot reducer-write table) and the `utxos` table (node.db
 * projection). A `height` predicate would need a height index that `coins`
 * does not have and should not pay for, making every sampled tick an O(n)
 * table scan — the opposite of "bounded work per tick". Both call sites
 * that compare two tables MUST pass the identical `txid_lo`/`max_rows` pair
 * so the two scans cover the exact same keyspace slice.
 *
 * `table` must be exactly "coins" or "utxos" (SQL-injection / wrong-table
 * guard, same idiom as utxo_commitment_sha3_compute_table) — any other value
 * is refused: returns false, *out left empty, *out_rows 0.
 *
 * On success (true): *out holds the accumulator+count over the matched
 * rows (0 rows is a valid, non-error outcome — check *out_rows), *out_rows
 * the row count actually scanned, *out_min_height and *out_max_height the
 * observed min/max of the `height` column among those rows (left at
 * INT32_MAX / INT32_MIN when *out_rows==0), and out_last_txid (may be NULL)
 * the txid of the LAST row scanned (a caller walking the whole keyspace in
 * windows can feed this back in as the next window's txid_lo). */
bool utxo_commitment_compute_range(struct sqlite3 *db, const char *table,
                                   const uint8_t txid_lo[32], int max_rows,
                                   struct utxo_commitment *out,
                                   size_t *out_rows,
                                   int32_t *out_min_height,
                                   int32_t *out_max_height,
                                   uint8_t out_last_txid[32]);

/* ── SHA3-256 full-set commitment ────────────────────────── */

/* Single-source per-record serializer for the SHA3 UTXO commitment.
 *
 * Emits ONE record in the must-never-fork consensus byte layout:
 *   txid(32) || vout_le(4) || value_le(8) || script_len_le(4) ||
 *   script(var) || height_le(4) || is_coinbase(1)
 * into `buf`, writing the total length to *out_len. `script_len` is
 * the count actually emitted (0 if script==NULL). is_coinbase is
 * normalized to 0/1.
 *
 * This is the authoritative encoder behind utxo_commitment_sha3_compute_table
 * and coins_kv_commitment — feeding *buf into a
 * SHA3-256 sponge in (txid,vout) row order is byte-for-byte equivalent to the
 * separate per-field writes those callers historically did (a sponge does not
 * distinguish write boundaries). A single endianness/field-order divergence
 * here silently FORKS the chain, so this MUST stay the only copy.
 *
 * The caller's `buf` must hold at least UTXO_SHA3_RECORD_MAX(script_len)
 * bytes. Returns false (and leaves *out_len 0) if buf_cap is too small or
 * any pointer arg is NULL — callers fall back to streaming the fields
 * directly when they cannot size a buffer for a pathological script. */
#define UTXO_SHA3_RECORD_HDR  (32 + 4 + 8 + 4)   /* txid+vout+value+slen */
#define UTXO_SHA3_RECORD_TRL  (4 + 1)            /* height+is_coinbase   */
#define UTXO_SHA3_RECORD_MAX(script_len) \
    ((size_t)UTXO_SHA3_RECORD_HDR + (size_t)(script_len) + UTXO_SHA3_RECORD_TRL)

bool utxo_sha3_serialize_record(uint8_t *buf, size_t buf_cap, size_t *out_len,
                                const uint8_t txid[32], uint32_t vout,
                                int64_t value,
                                const uint8_t *script, uint32_t script_len,
                                uint32_t height, uint8_t is_coinbase);

/* Absorb one canonical UTXO record into an in-progress SHA3-256 context.
 * This is the streaming front-end every full-set commitment loop should use:
 * it serializes the record (utxo_sha3_serialize_record) into a stack buffer
 * and does ONE sha3_256_write, falling back to field-by-field writes through
 * the identical layout only for the rare script too large for the buffer.
 * `ctx` is a `struct sha3_256_ctx *` (opaque here to keep this header free of
 * the crypto include); pass NULL script for an empty script. */
struct sha3_256_ctx;
void utxo_commitment_sha3_write_record(struct sha3_256_ctx *ctx,
                                       const uint8_t txid[32], uint32_t vout,
                                       int64_t value,
                                       const uint8_t *script,
                                       uint32_t script_len,
                                       uint32_t height, uint8_t is_coinbase);

/* Deterministic SHA3-256 hash over the canonically ordered UTXO set.
 * ORDER-DEPENDENT (unlike the XOR accumulator): rows are streamed in
 * (txid, vout) order into ONE SHA3 context, so the result is sensitive to
 * set membership AND ordering. Per-UTXO record (must-never-fork layout):
 *   txid(32) || vout_le(4) || value_le(8) || script_len_le(4) ||
 *   script(var) || height_le(4) || is_coinbase(1)
 * (the byte stream is identical whether produced inline or via the oversized-
 * script fallback). out gets the 32-byte digest; *utxo_count (if non-NULL)
 * gets the row count. More secure than the XOR accumulator but O(n). */
void utxo_commitment_sha3_compute(struct sqlite3 *db, uint8_t out[32],
                                   uint64_t *utxo_count);

/* As above but over a named table. ONLY "utxos" and "snapshot_staging_utxos"
 * are accepted (SQL-injection / wrong-table guard); any other name is refused
 * with a logged warning and out is left all-zero, *utxo_count 0. */
void utxo_commitment_sha3_compute_table(struct sqlite3 *db,
                                        const char *table,
                                        uint8_t out[32],
                                        uint64_t *utxo_count);

/* Persist the SHA3 commitment into node_state key 'utxo_sha3' as a 44-byte
 * blob: hash(32) || height_le(4) || count_le(8) (INSERT OR REPLACE). Returns
 * false on NULL db or any prepare/step failure (logged). This is the
 * fast-sync anchor record (see _sha3_load). */
bool utxo_commitment_sha3_save(struct sqlite3 *db, const uint8_t hash[32],
                                int32_t height, uint64_t count);

/* Load the 'utxo_sha3' record. Fills hash[32] and, when non-NULL, *height /
 * *count from the little-endian trailer. Returns false if no row exists, the
 * blob is shorter than 44 bytes, or on NULL db / prepare failure. */
bool utxo_commitment_sha3_load(struct sqlite3 *db, uint8_t hash[32],
                                int32_t *height, uint64_t *count);

/* ── Full data integrity hash ────────────────────────────── */

/* SHA3-256 over ALL consensus-critical data in canonical order:
 * blocks, transactions, tx_inputs, tx_outputs, utxos,
 * sapling_nullifiers, sapling_outputs, sapling_spends,
 * sprout_nullifiers, joinsplits, zslp_tokens, zslp_transfers.
 * Each table hashed separately, then combined into a master hash.
 * Returns per-table hashes in the detail struct for diagnostics. */
struct data_integrity_detail {
    uint8_t blocks[32];
    uint8_t transactions[32];
    uint8_t tx_inputs[32];
    uint8_t tx_outputs[32];
    uint8_t utxos[32];
    uint8_t sapling_nullifiers[32];
    uint8_t sapling_outputs[32];
    uint8_t sapling_spends[32];
    uint8_t sprout_nullifiers[32];
    uint8_t joinsplits[32];
    uint8_t zslp_tokens[32];
    uint8_t zslp_transfers[32];
    uint8_t master[32];         /* SHA3-256 of all above concatenated */
};

/* Compute every per-table hash in `out` and the combined `out->master`.
 * Each table is SHA3-256'd over all rows in a fixed ORDER BY (primary key,
 * or rowid where noted) for determinism; within a row, columns are streamed
 * by type: integers as 8-byte LE, blob/text as a 4-byte LE length prefix +
 * bytes, float as 8 raw bytes, NULL as 4 zero bytes. `out->master` is
 * SHA3-256 over the 12 per-table digests concatenated in the struct's
 * declaration order (blocks..zslp_transfers) — it does NOT include the
 * master field itself. On NULL db, out is zeroed and returned. */
void data_integrity_compute(struct sqlite3 *db,
                            struct data_integrity_detail *out);

#endif
