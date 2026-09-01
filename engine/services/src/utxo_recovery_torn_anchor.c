/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:boolean-did-recover-verdict — the public surface returns
// a bool "did the recovery fire" verdict so it composes with the bool-returning
// coins_view_sqlite_open() at the boot gate (mirrors the sibling
// utxo_recovery_repair_stale_cursor_from_sync_projection). Every refusal/failure
// reason travels via structured LOG_INFO/LOG_WARN/LOG_FAIL, not a result struct.
/*
 * L1 torn-legacy-coins boot recovery (the §3 dual-store tear).
 *
 * Z23 keeps TWO coins stores:
 *   (A) node.db `utxos` — the DEPRECATED, lazily-batched legacy mirror. Still
 *       load-bearing for the SHA3 UTXO commitment + the fast-sync snapshot
 *       SERVED to peers (core/modules/net/src/fast_sync.c streams `FROM utxos`).
 *   (B) progress.kv `coins` (coins_kv) — the tear-PROOF reducer authority. The
 *       reducer writes coins_kv atomically with the stage cursor in ONE
 *       BEGIN IMMEDIATE (docs/work/tip-durability-collapse.md), so every block's
 *       effect lands or rolls back as one unit.
 *
 * A SIGKILL between the legacy mirror's lazy batch flush and its tip-anchor
 * update leaves node.db with `utxos` rows but `coins_best_block` UNSET, while
 * coins_kv committed every block. The boot coins-integrity gate
 * (coins_view_sqlite.c check_tip_consistency, the have_utxos && !tip_set case)
 * then returns false and the boot FATALs — even though the tear-proof authority
 * (B) is perfectly healthy, merely a couple of blocks ahead of the stale
 * mirror (A).
 *
 * This file heals exactly that shape, and ONLY that shape, from the boot gate
 * AFTER coins_view_sqlite_open() has already failed. It is gated on coins_kv
 * being the PROVEN-healthy authority and writes ONLY the legacy anchor (no log
 * deletes, no coins_kv mutation, no tip reset — reset-safe). Every unproven
 * case returns false so the caller's strict FATAL is preserved unchanged.
 *
 * Kept as a dedicated seam file so utxo_recovery_service.c stays under the
 * app/ file-size ceiling (E1).
 */

#include "services/utxo_recovery_service.h"

#include "models/database.h"
#include "models/block.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "event/event.h"

#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utxo_recovery_internal.h"

/* Predicate: is coins_kv the PROVEN-healthy authority on this datadir?
 * All three must hold (see header). Any failure → caller's FATAL stands. */
static bool urs_coins_kv_is_proven_authority(struct sqlite3 *progress_db)
{
    if (!progress_db)
        return false;

    /* (1) migration-complete flag: the read-flip is done; coins_kv is sole. */
    uint8_t mig = 0;
    size_t mig_len = 0;
    bool mig_found = false;
    if (!progress_meta_get(progress_db, "coins_kv_migration_complete",
                           &mig, sizeof(mig), &mig_len, &mig_found))
        return false;
    if (!mig_found || mig_len != 1 || mig != 1) {
        LOG_INFO("utxo_recovery",
                 "torn-anchor heal refused: coins_kv migration not complete "
                 "(found=%d len=%zu val=%d) — coins_kv is not the proven "
                 "authority; preserving FATAL",
                 mig_found ? 1 : 0, mig_len, (int)mig);
        return false;
    }

    /* (2) coins_kv actually holds the live set. */
    int64_t n = coins_kv_count(progress_db);
    if (n <= 0) {
        LOG_INFO("utxo_recovery",
                 "torn-anchor heal refused: coins_kv_count=%lld — empty/error; "
                 "preserving FATAL", (long long)n);
        return false;
    }

    /* (3) it has a durable applied frontier (a clean "unknown" is NOT proof). */
    int32_t applied = 0;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(progress_db, &applied, &applied_found) ||
        !applied_found) {
        LOG_INFO("utxo_recovery",
                 "torn-anchor heal refused: coins_applied_height absent — "
                 "frontier unknown; preserving FATAL");
        return false;
    }

    LOG_INFO("utxo_recovery",
             "coins_kv proven-authority: migration_complete=1 count=%lld "
             "applied_height=%d", (long long)n, applied);
    return true;
}

/* wave-3 delete (whole module): the boot call site is gated on !derived
 * (boot.c) AND the derived gate in coins_view_sqlite_check_tip_consistency
 * passes canonical datadirs without consulting the legacy anchor — this
 * heal can only fire on legacy datadirs until canonical-plan step 5. */
bool utxo_recovery_heal_torn_legacy_coins_anchor(
    struct node_db *ndb,
    struct sqlite3 *progress_db,
    const char *datadir)
{
    if (!ndb || !ndb->open || !ndb->db) {
        LOG_WARN("utxo_recovery",
                 "torn-anchor heal: node.db not open; cannot recover");
        return false;
    }
    if (!datadir || !datadir[0]) {
        LOG_WARN("utxo_recovery",
                 "torn-anchor heal: datadir missing; cannot recover");
        return false;
    }

    /* Shape gate: this recovery is ONLY for the torn-legacy shape —
     * node.db `utxos` has rows but `coins_best_block` is UNSET. Any other
     * coins_view_sqlite_open failure (UTXOs-ahead-of-tip, etc.) is left to
     * the strict FATAL: re-seeding the anchor would be the wrong remedy. */
    int64_t utxo_count = node_db_utxo_count(ndb);
    if (utxo_count <= 0) {
        LOG_INFO("utxo_recovery",
                 "torn-anchor heal: utxos table empty — not the torn-legacy "
                 "shape; preserving FATAL");
        return false;
    }
    {
        uint8_t cur_anchor[32];
        size_t anchor_len = 0;
        bool have_anchor = node_db_state_get(ndb, "coins_best_block",
                                             cur_anchor, sizeof(cur_anchor),
                                             &anchor_len);
        if (have_anchor && anchor_len == 32) {
            LOG_INFO("utxo_recovery",
                     "torn-anchor heal: coins_best_block already set — not "
                     "the torn-legacy shape; preserving FATAL");
            return false;
        }
    }

    /* Authority gate: only heal when coins_kv proves the live UTXO set is the
     * tear-proof reducer authority. Otherwise the legacy mirror is the only
     * coins source and re-seeding its anchor would be unproven — FATAL stands. */
    if (!urs_coins_kv_is_proven_authority(progress_db))
        return false;

    /* Anchor strategy: seed coins_best_block to the height the LEGACY mirror
     * (node.db utxos) actually reaches — MAX(height) FROM utxos — NEVER the
     * (further-ahead) coins_kv applied frontier. This keeps the SHA3 snapshot
     * SERVED to peers self-consistent with its committed anchor: a peer
     * fast-syncing gets exactly the set the anchor names. (R3: serve_snapshot
     * streams `FROM utxos`; the peer recomputes the SHA3 and rejects a short
     * set — so a too-high anchor would silently break served sync.) */
    int64_t max_h = -1;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT MAX(height) FROM utxos", -1, &st, NULL) == SQLITE_OK) {
            if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW &&
                sqlite3_column_type(st, 0) == SQLITE_INTEGER)
                max_h = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
        }
    }
    if (max_h < 0) {
        LOG_WARN("utxo_recovery",
                 "torn-anchor heal: could not read MAX(height) from utxos; "
                 "preserving FATAL");
        return false;
    }

    /* The chosen anchor height must be consensus-backed on disk: a node.db
     * `blocks` row at that height with status>=3 (connected). This is the
     * pre-block-index-load equivalent of the consensus-backed check (the
     * block index map is not loaded yet at the boot gate). Refuse otherwise. */
    struct db_block anchor_blk;
    if (!db_block_find_by_height(ndb, (int)max_h, &anchor_blk)) {
        LOG_WARN("utxo_recovery",
                 "torn-anchor heal: no blocks row at utxos MAX(height)=%lld; "
                 "preserving FATAL", (long long)max_h);
        return false;
    }
    if (anchor_blk.status < 3) {
        LOG_WARN("utxo_recovery",
                 "torn-anchor heal: blocks row at h=%lld is not connected "
                 "(status=%d < 3); preserving FATAL",
                 (long long)max_h, anchor_blk.status);
        return false;
    }

    /* Durably seed coins_best_block to the anchor block hash. This is the ONLY
     * write: no *_log deletes, no coins_kv mutation, no tip reset (reset-safe). */
    if (!node_db_state_set(ndb, "coins_best_block", anchor_blk.hash, 32)) {
        LOG_FAIL("utxo_recovery",
                 "torn-anchor heal: failed to write coins_best_block anchor "
                 "at h=%lld", (long long)max_h);
        return false;
    }

    char hex[65] = {0};
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", anchor_blk.hash[i]);
    LOG_WARN("utxo_recovery",
             "torn-anchor heal: re-seeded coins_best_block to utxos "
             "MAX(height)=%lld hash=%s (coins_kv proven authority) — retrying "
             "coins view open", (long long)max_h, hex);
    event_emitf(EV_BOOT_UTXO_IMPORT, 0,
                "phase=torn-anchor-heal anchor_height=%lld utxos=%lld",
                (long long)max_h, (long long)utxo_count);
    return true;
}

/* The cold-import seed-key writer/clearer pair lives in
 * utxo_recovery_seed_provenance.c (wave 2 — also attests the canonical
 * coins_kv store via cold_import_seed_coins_kv_count). */
