/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_readers - public SELECT-only helper readers for the L0
 * reducer frontier. The H* authority stays in reducer_frontier.c; this file
 * holds reusable derived-state queries that other subsystems consume.
 */

#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"

#include "platform/time_compat.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int32_t reducer_frontier_external_tip_height(void)
{
    if (reducer_frontier_provable_tip_is_published())
        return reducer_frontier_provable_tip_cached();

    sqlite3 *pdb = progress_store_db();
    int durable_height = -1;
    uint8_t durable_hash[32];
    if (pdb && tip_finalize_stage_resolve_durable_tip(
            pdb, &durable_height, durable_hash) && durable_height >= 0)
        return durable_height;

    return reducer_frontier_provable_tip_cached();
}

bool reducer_frontier_derive_coins_best(sqlite3 *progress_db,
                                        int32_t *out_height,
                                        uint8_t out_hash[32],
                                        bool *hash_found,
                                        bool *found)
{
    if (!progress_db || !out_height || !out_hash || !hash_found || !found)
        LOG_FAIL("reducer", "derive_coins_best: NULL arg");
    *found = false;
    *hash_found = false;
    *out_height = -1;
    memset(out_hash, 0, 32);

    /* Recursive lock: one consistent durable snapshot across all reads. */
    progress_store_tx_lock();

    /* THE proven-authority predicate (coins_kv.h): applied frontier present
     * AND migration stamp set AND non-empty. A cursor-backfilled frontier on
     * a pre-migration datadir is NOT canonical - *found stays false and the
     * caller keeps its (stricter) legacy gates. Authority-proof read errors
     * also degrade to !found, never to the permissive derived path. */
    int32_t applied = -1;
    bool ok = true;
    if (coins_kv_is_proven_authority(progress_db, &applied)) {
        int32_t h = applied - 1;
        *out_height = h;
        *found = true;
        /* Hash witness 1: tip_finalize_log, read CONVENTION-AWARE via
         * tip_finalize_stage_block_hash_at - the finalized ok=1 row at h-1
         * carries hash(h) (step_finalize binds the LOOKAHEAD successor into
         * the row), and an anchor seed row at h carries the block's own
         * hash(h). Reading the raw row AT h would return hash(h+1) for
         * finalized rows: an inconsistent (height, hash) authority-pair shape
         * (see tip_finalize_stage.c step_finalize publish comment). */
        uint8_t tf[32];
        bool tf_found = tip_finalize_stage_block_hash_at(progress_db, h, tf);
        /* Hash witness 2: validate_headers_log.hash at h (own-hash by
         * construction) - the Invariant A trust root; covers the <=1-block
         * pipeline window where utxo_apply leads tip_finalize (Invariant B
         * bound) and anchor-seeded datadirs whose tip_finalize window is
         * empty at the frontier. */
        uint8_t vh[32];
        bool vh_found = false;
        if (!reducer_frontier_log_hash_at(progress_db, "validate_headers_log",
                                          "hash", h, vh, &vh_found)) {
            ok = false;  /* real DB read error; height outputs stand */
        } else if (tf_found && vh_found && memcmp(tf, vh, 32) != 0) {
            /* Hash-identity guard: two durable logs disagreeing about the
             * SAME height is the don't-guess shape - withhold the hash
             * LOUDLY rather than install either candidate. The height stays
             * authoritative; the caller resolves height->hash via its own
             * index, never the reverse. */
            static struct log_throttle mismatch_throttle = LOG_THROTTLE_INIT;
            uint64_t reps = 0;
            if (log_throttle_should_emit(&mismatch_throttle,
                                         (uint64_t)(uint32_t)h,
                                         platform_time_wall_unix(), 300,
                                         &reps))
                LOG_WARN("reducer",
                         "derive_coins_best: cross-log hash mismatch at h=%d "
                         "(tip_finalize witness %02x%02x%02x%02x.. vs "
                         "validate_headers %02x%02x%02x%02x..) - hash "
                         "withheld, height stands repeated=%llu",
                         h, tf[0], tf[1], tf[2], tf[3],
                         vh[0], vh[1], vh[2], vh[3],
                         (unsigned long long)reps);
        } else if (tf_found) {
            memcpy(out_hash, tf, 32);
            *hash_found = true;
        } else if (vh_found) {
            memcpy(out_hash, vh, 32);
            *hash_found = true;
        }
        /* Neither witness resolving is SUCCESS with *hash_found=false:
         * the height stays authoritative; the caller resolves
         * height->hash via its own index, never the reverse. */
    }

    progress_store_tx_unlock();
    return ok;
}

bool reducer_frontier_derive_coins_best_now(int32_t *out_height,
                                            uint8_t out_hash[32],
                                            bool *out_hash_found)
{
    if (!out_height)
        LOG_FAIL("reducer", "derive_coins_best_now: NULL out_height");
    *out_height = -1;
    if (out_hash) memset(out_hash, 0, 32);
    if (out_hash_found) *out_hash_found = false;

    sqlite3 *pdb = progress_store_db();
    if (!pdb)
        return false;  /* store closed => legacy fallback; not an error */
    uint8_t hash[32];
    bool hf = false, found = false;
    bool ok = reducer_frontier_derive_coins_best(pdb, out_height, hash,
                                                 &hf, &found);
    if (!ok)
        return false;  /* hard read error already logged */
    if (!found)
        return false;
    if (out_hash && hf) memcpy(out_hash, hash, 32);
    if (out_hash_found) *out_hash_found = hf;
    return true;
}

bool reducer_frontier_log_coverage_floor(sqlite3 *progress_db,
                                         const char *log_table,
                                         int32_t *out_lo, bool *found)
{
    if (!progress_db || !log_table || !out_lo || !found)
        LOG_FAIL("reducer", "log_coverage_floor: NULL arg");
    *found = false;
    *out_lo = 0;

    /* log_table is a fixed caller constant (never network/user input), same
     * concat discipline as reducer_frontier_log_hash_at. */
    char sql[128];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT MIN(height) FROM %s", log_table);
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("reducer", "log_coverage_floor sql overflow for %s",
                 log_table);

    /* Recursive lock: safe whether or not the caller already holds it. */
    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    bool rc_ok = true;
    if (sqlite3_prepare_v2(progress_db, sql, -1, &st, NULL) != SQLITE_OK) {
        progress_store_tx_unlock();
        LOG_FAIL("reducer", "prepare coverage floor %s failed: %s",
                 log_table, sqlite3_errmsg(progress_db));
    }
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
            *out_lo = (int32_t)sqlite3_column_int64(st, 0);
            *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "step coverage floor %s failed: %s",
                 log_table, sqlite3_errmsg(progress_db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();
    return rc_ok;
}
