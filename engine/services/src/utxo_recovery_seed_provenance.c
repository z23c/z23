/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:best-effort-provenance-tokens
//
// Both functions are BEST-EFFORT by contract (moved verbatim from
// utxo_recovery_restore.c): the consumer's live coin-count cross-check in
// block_index_loader_seed_stages_from_cold_import is the backstop, so a
// failed key write must not fail the import/wipe that invoked it. No
// fallible service surface to carry a zcl_result.

/* Cold-import seed provenance — the durable anchor keys that let
 * block_index_loader_seed_stages_from_cold_import trust a cold-imported
 * coin set across reboots. Split from utxo_recovery_restore.c (wave 2).
 *
 * Keys written:
 *   cold_import_seed_anchor_height      int64 H
 *   cold_import_seed_anchor_hash        32B coins-best hash
 *   cold_import_seed_anchor_utxo_count  int64 live node.db mirror rows
 *   cold_import_seed_coins_kv_count     int64 canonical coins_kv rows
 *                                       (wave 2: attests the CANONICAL
 *                                       store; consumer checks it FIRST)
 */

#include "services/utxo_recovery_service.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdint.h>

#include "utxo_recovery_internal.h"

/* DURABLE cold-import seed anchor. Writes the keys the consumer
 * (block_index_loader_seed_stages_from_cold_import) reads every boot to heal
 * the staged-sync wedge. The count is the PROVENANCE TOKEN: H* is
 * cursor/log-derived (coins are C4 diagnostic-only in
 * reducer_frontier_compute_hstar) so the post-seed H*==H self-check cannot
 * detect a coin tear — the consumer instead requires the live coin count ==
 * the recorded count. Cleared by every wipe / reimport-prepare so the key
 * never outlives the coins it attests to. */
void utxo_recovery_write_cold_import_seed(struct node_db *ndb,
                                          int height,
                                          const struct uint256 *hash,
                                          int64_t utxo_count)
{
    if (!ndb || height <= 0 || !hash || utxo_count <= 0)
        return;
    (void)node_db_state_set_int(ndb, "cold_import_seed_anchor_height",
                                (int64_t)height);
    (void)node_db_state_set(ndb, "cold_import_seed_anchor_hash",
                            hash->data, 32);
    (void)node_db_state_set_int(ndb, "cold_import_seed_anchor_utxo_count",
                                utxo_count);
    /* ALSO attest the CANONICAL store. Written only when coins_kv
     * is already seeded (post coins_kv_seed_from_node_db) — the consumer
     * checks this token FIRST and falls back to the mirror-count token when
     * absent. Additive + idempotent (INSERT OR REPLACE semantics of
     * node_db_state_set_int). */
    {
        int64_t ck = coins_kv_count(progress_store_db());
        if (ck > 0)
            (void)node_db_state_set_int(ndb,
                "cold_import_seed_coins_kv_count", ck);
    }
}

/* Read the durable cold-import seed anchor identity. See the contract in
 * utxo_recovery_internal.h. Strict: both keys present, height in range, hash
 * exactly 32 bytes — otherwise a clean false (caller behaves as "no seed"). */
bool utxo_recovery_read_cold_import_seed(struct node_db *ndb,
                                         int *out_height,
                                         struct uint256 *out_hash)
{
    if (!ndb || !out_height || !out_hash)
        return false;
    int64_t h = 0;
    if (!node_db_state_get_int(ndb, "cold_import_seed_anchor_height", &h))
        return false;
    if (h <= 0 || h > INT32_MAX)
        return false;
    size_t hn = 0;
    if (!node_db_state_get(ndb, "cold_import_seed_anchor_hash",
                           out_hash->data, sizeof(out_hash->data), &hn) ||
        hn != sizeof(out_hash->data))
        return false;
    *out_height = (int)h;
    return true;
}

/* Clear all durable cold-import seed keys. Called from every UTXO wipe /
 * reimport-prepare so a stale key cannot outlive the coins it attests to.
 * Best-effort; the consumer's live coin-count cross-check is the backstop. */
bool utxo_recovery_clear_cold_import_seed_checked(struct node_db *ndb)
{
    if (!ndb)
        return false;
    bool ok = node_db_exec(ndb,
        "DELETE FROM node_state WHERE key IN ("
        "'cold_import_seed_anchor_height',"
        "'cold_import_seed_anchor_hash',"
        "'cold_import_seed_anchor_utxo_count',"
        "'cold_import_seed_coins_kv_count')");
    /* import-gate-spec.md PART A: the bless-time forward-evidence gate raises
     * a PERMANENT "seed.torn_import" blocker on a torn import. PERMANENT
     * blockers only clear by operator action; a wipe / reimport-prepare IS
     * that action (the operator-prescribed remedy), so clear it here too —
     * otherwise a clean re-import would stay permanently blocked by a stale
     * blocker from the torn datadir it replaced. */
    if (ok)
        blocker_clear("seed.torn_import");
    return ok;
}

void utxo_recovery_clear_cold_import_seed(struct node_db *ndb)
{
    if (ndb && !utxo_recovery_clear_cold_import_seed_checked(ndb))
        LOG_WARN("utxo_recovery", "cold-import seed clear failed");
}
