#ifndef ZCL_JOBS_CREATED_OUTPUTS_INDEX_H
#define ZCL_JOBS_CREATED_OUTPUTS_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward creation index: (txid, vout, height) -> {value, scriptPubKey}.
 *
 * Populated by body_persist (pipeline stage 4) as each verified block body
 * lands on disk. Because body_persist runs strictly UPSTREAM of script_validate
 * (stage 5) — body_persist.cursor > script_validate.cursor at all times — every
 * output created at or below the script_validate frontier is already indexed
 * BEFORE script_validate needs it, independent of the trailing utxo_apply cursor
 * (stage 7). This is the production prevout source for transparent script
 * verification when the node runs without -txindex.
 *
 * It is a CREATION index, not a UTXO set: rows are never deleted on spend, so a
 * coin spent earlier in the same lookahead window is still resolvable. Pre-anchor
 * (snapshot-seeded) coins are NOT here — the resolver falls back to the seeded
 * kernel coins store (coins_kv) for those. */

struct block;
typedef struct sqlite3 sqlite3;

/* Create the created_outputs table + height index if absent. Idempotent.
 * Returns false on a real SQLite error. Call from body_persist_stage_init. */
bool created_outputs_index_ensure_schema(sqlite3 *db);

/* Insert every output of every tx in `blk`, created at `height`. Idempotent
 * (INSERT OR REPLACE keyed on (txid,vout,height)) so a post-rewind re-persist
 * rewrites identical rows without letting a future duplicate historical txid
 * erase an earlier creator. Returns false on a real SQLite error. */
bool created_outputs_index_put_block(sqlite3 *db, const struct block *blk,
                                     int height);

/* Finalize this thread's batch-owned prepared statements. Idempotent; called
 * on stage shutdown, while generation/DB changes self-invalidate on use. */
void created_outputs_index_batch_reset(void);

/* Per-thread monotonic count of actual sqlite3_prepare_v2 calls made by this
 * index. Intended for bounded before/after diagnostic sampling. */
uint64_t created_outputs_index_prepare_count_thread(void);

/* Resolve one outpoint at its newest indexed creator height. Callers needing a
 * historical view must use the bounded form below. Returns true and fills
 * *value_out + script (up to script_cap bytes, with the true length in
 * *script_len_out) when found; false when absent or on error. */
bool created_outputs_index_get(sqlite3 *db, const uint8_t txid[32],
                               uint32_t vout, int64_t *value_out,
                               uint8_t *script_out, size_t script_cap,
                               size_t *script_len_out);

/* Resolve the newest version of one outpoint whose creator height is inside
 * [min_height, max_height]. This is used by repair replay and script validation
 * to build a bounded historical view without authorizing a later duplicate
 * txid or an unrelated sparse-log island. */
bool created_outputs_index_get_bounded(sqlite3 *db, const uint8_t txid[32],
                                       uint32_t vout, int min_height,
                                       int max_height, int64_t *value_out,
                                       uint8_t *script_out, size_t script_cap,
                                       size_t *script_len_out,
                                       int *height_out);

/* Prune all rows with height < floor (finality/retention pruning). Returns
 * false on a real SQLite error. */
bool created_outputs_index_prune_below(sqlite3 *db, int floor);

/* Bounded form for production cleanup: delete all rows for at most
 * max_heights distinct old heights below floor. This keeps one reducer tick
 * from turning a historically large table into one giant DELETE, while still
 * reclaiming stale creation-index rows over time. rows_deleted_out may be
 * NULL. */
bool created_outputs_index_prune_below_limited(sqlite3 *db, int floor,
                                               int max_heights,
                                               int *rows_deleted_out);

#endif /* ZCL_JOBS_CREATED_OUTPUTS_INDEX_H */
