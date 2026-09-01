/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ar-validate-skip:pure-comparison-not-a-row
 *   This file only READS this node's own coins_kv boundary-root store and
 *   an mmb_leaf_store, then compares the bytes to the compiled ladder
 *   table. Nothing here is an AR row record and nothing is written, so
 *   the validates_* family / AR_BEGIN_SAVE lifecycle does not apply — the same
 *   reasoning as engine/models/src/mmb_leaf_store.c's read-side helpers.
 *
 * See models/utxo_root_ladder_verify.h for the contract. */

#include "models/utxo_root_ladder_verify.h"
#include "models/mmb_leaf_store.h"

#include "chain/mmb.h"
#include "chain/utxo_root_ladder.h"
#include "storage/coins_kv.h"
#include "util/log_macros.h"

#include <string.h>

bool utxo_root_ladder_verify_against_store(
        struct sqlite3 *db,
        struct utxo_root_ladder_verify_result *out_results, size_t out_cap,
        size_t *out_count)
{
    if (!db)
        LOG_FAIL("utxo_root_ladder", "verify_against_store: NULL db");

    bool any_divergence = false;
    size_t written = 0;
    size_t compared = 0;   /* COVERAGE: rungs actually FOUND + byte-compared
                            * this call — independent of any_divergence
                            * (AGREEMENT). See the header: never let one
                            * dimension stand in for the other. */

    for (size_t i = 0; i < g_utxo_root_ladder_count; i++) {
        const struct utxo_root_ladder_entry *rung = &g_utxo_root_ladder[i];

        enum utxo_root_ladder_verify_status status =
            UTXO_ROOT_LADDER_VERIFY_NOT_YET_REACHED;

        uint8_t local_root[32] = {0};
        bool found = false;
        if (coins_kv_boundary_root_get(db, rung->height, local_root, &found) &&
            found) {
            compared++;
            if (memcmp(local_root, rung->utxo_root, 32) == 0) {
                status = UTXO_ROOT_LADDER_VERIFY_MATCH;
            } else {
                status = UTXO_ROOT_LADDER_VERIFY_DIVERGENT;
                any_divergence = true;
                LOG_WARN("utxo_root_ladder",
                        "DIVERGENT boundary root at h=%d: this node's own "
                        "coins_kv_boundary_root differs from the locked "
                        "golden-height ladder rung (state-wrong-coin class)",
                        rung->height);
            }
        }

        if (out_results && written < out_cap) {
            out_results[written].height = rung->height;
            out_results[written].status = status;
            written++;
        }
    }

    /* Broadcast the coverage pair onto every WRITTEN entry (computed over
     * the FULL g_utxo_root_ladder_count loop above, not clamped by
     * out_cap/written — coverage must stay accurate even when the caller's
     * buffer is smaller than the ladder, same as any_divergence already
     * is). Any consumer inspecting one entry or the whole array sees the
     * same compared/total pair. */
    for (size_t j = 0; j < written; j++) {
        out_results[j].compared = compared;
        out_results[j].total = g_utxo_root_ladder_count;
    }

    if (out_count) *out_count = written;
    return !any_divergence;
}

bool utxo_root_ladder_verify_dense_anchor(struct mmb_leaf_store *store,
                                          uint8_t out_mismatch_root[32])
{
    if (out_mismatch_root) memset(out_mismatch_root, 0, 32);

    if (g_utxo_root_ladder_dense_height < 0)
        return true;  /* dense anchor absent — nothing to check */

    if (!store)
        LOG_FAIL("utxo_root_ladder", "verify_dense_anchor: NULL store");

    uint64_t need = (uint64_t)g_utxo_root_ladder_dense_height + 1;
    if (store->num_leaves < need) {
        /* Not yet reached — same "not a failure" doctrine as the per-rung
         * boundary-root check. */
        return true;
    }

    struct mmb m;
    mmb_init(&m);
    for (uint64_t i = 0; i < need; i++) {
        const uint8_t *leaf_hash = mmb_leaf_store_get(store, i);
        if (!leaf_hash)
            LOG_FAIL("utxo_root_ladder",
                    "verify_dense_anchor: leaf %llu missing from store "
                    "despite num_leaves=%llu",
                    (unsigned long long)i,
                    (unsigned long long)store->num_leaves);
        if (mmb_append_hash(&m, leaf_hash) < 0)
            LOG_FAIL("utxo_root_ladder",
                    "verify_dense_anchor: mmb_append_hash failed at leaf %llu",
                    (unsigned long long)i);
    }

    uint8_t recomputed[32];
    mmb_root(&m, recomputed);

    if (memcmp(recomputed, g_utxo_root_ladder_dense_mmb_root, 32) == 0)
        return true;

    if (out_mismatch_root) memcpy(out_mismatch_root, recomputed, 32);
    LOG_WARN("utxo_root_ladder",
            "DIVERGENT dense mmb_root at h=%d: this node's own leaf-store "
            "pipeline no longer reproduces the locked dense anchor",
            g_utxo_root_ladder_dense_height);
    return false;
}
