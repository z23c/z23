/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the POST-INSTALL derived-state reconciliation of the sovereign
 * consensus-state install — the coin-tip check, the bundle Sapling-tree cache,
 * the provable-tip cache reset, and the derived `utxos` mirror reset that must
 * follow a durably activated bundle.
 *
 * Split out of engine/composition/src/consensus_state_install_runtime.c when that file
 * passed its shape ceiling. Pure move: the bodies below are byte-identical to
 * the ones that file carried; only the linkage of the two entry points changed
 * (static -> external) so the install engine can still reach them across the TU
 * boundary. Contract:
 * engine/composition/src/consensus_state_install_derived_state_internal.h.
 */

#include "config/consensus_state_install_runtime.h"

#if defined(_WIN32)

/* Nothing to reconcile: consensus_state_install_from_bundle refuses on Windows
 * before any bundle is admitted, so no install ever reaches this stage. */

#else

#include "consensus_state_install_derived_state_internal.h"
#include "controllers/sync_controller.h"              /* sapling_tree_persist_pair */
#include "core/serialize.h"                           /* byte_stream */
#include "jobs/reducer_frontier.h"                    /* reducer_frontier_provable_tip_reset */
#include "models/database.h"                          /* node_db state helpers */
#include "sapling/incremental_merkle_tree.h"
#include "services/utxo_mirror_sync_service.h"        /* UTXO_MIRROR_SYNC_CURSOR_KEY */
#include "storage/anchor_kv.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* Same log-subsystem name the other installer TUs report under
 * (boot_install_consensus_bundle.c, boot_auto_install_bundle.c,
 * consensus_state_install_header_frontier.c, consensus_state_install_runtime.c). */
#define ICB_SUBSYS "install_consensus_bundle"

/* MAX(coins.height) on the installed progress store. found=false on an empty
 * coins table (MAX over 0 rows is SQL NULL). */
static bool icb_coins_max_height(sqlite3 *progress_db, int64_t *out, bool *found)
{
    *out = -1;
    *found = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(progress_db, "SELECT MAX(height) FROM coins", -1,
                           &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    if (sqlite3_step(st) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        if (sqlite3_column_type(st, 0) != SQLITE_NULL) {
            *out = sqlite3_column_int64(st, 0);
            *found = true;
        }
    } else {
        ok = false;
    }
    sqlite3_finalize(st);
    return ok;
}

/* The activated bundle already installed every Sapling anchor row, including
 * the verified current frontier tree. Persist that frontier into node.db's
 * boot cache as the bundle-height state instead of deleting the cache and
 * forcing an O(chain) block replay. The latest stored anchor may have been
 * created below bundle_height when intervening blocks carried no Sapling
 * outputs; its unchanged root still represents the Sapling state at the
 * bundle height, which admission/activation bound to the selected header.
 *
 * The bundle ships the complete sapling tree, so a successful install must
 * leave boot able to load it and skip the Sapling rebuild. The pair writer is
 * atomic: a stale pre-install blob can never survive beside the new height. */
static bool icb_install_bundle_sapling_tree(struct node_db *ndb,
                                            sqlite3 *progress_db,
                                            int32_t bundle_height)
{
    if (!ndb || !progress_db || bundle_height < 0)
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: invalid ndb/progress_db/height");

    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    int64_t frontier_height = -1;
    enum anchor_kv_lookup_result found = anchor_kv_latest_tree(
        progress_db, ANCHOR_POOL_SAPLING, &tree, NULL, &frontier_height);
    if (found != ANCHOR_KV_FOUND || frontier_height < 0 ||
        frontier_height > bundle_height)
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: installed frontier unavailable "
                 "or out of range (result=%d frontier_h=%lld bundle_h=%d)",
                 (int)found, (long long)frontier_height, bundle_height);

    struct byte_stream encoded;
    stream_init(&encoded, 4096);
    bool serialized = incremental_tree_serialize(&tree, &encoded) &&
                      !encoded.error && encoded.size > 0;
    if (!serialized) {
        stream_free(&encoded);
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: frontier serialization failed "
                 "at bundle height=%d", bundle_height);
    }

    bool persisted = sapling_tree_persist_pair(
        ndb, encoded.data, encoded.size, (int64_t)bundle_height);
    stream_free(&encoded);
    if (!persisted)
        LOG_FAIL(ICB_SUBSYS,
                 "post-install Sapling cache: atomic tree/height persist failed "
                 "at bundle height=%d", bundle_height);

    LOG_INFO(ICB_SUBSYS,
             "post-install Sapling cache installed from bundle frontier_h=%lld "
             "at bundle_h=%d (boot skips Sapling rebuild)",
             (long long)frontier_height, bundle_height);
    return true;
}

/* Post-install derived-state reconciliation. The atomic activate step resets the
 * kernel store's (consensus.db) reducer/tip_finalize authority to the installed
 * anchor, but two derived surfaces live OUTSIDE that store and would fight the new
 * kernel on the next boot. Returns true iff every derived
 * store is now consistent with the freshly installed bundle at bundle_height. */
bool icb_invalidate_derived_state(struct node_db *ndb,
                                  sqlite3 *progress_db,
                                  int32_t bundle_height)
{
    if (!ndb || !progress_db)
        LOG_FAIL(ICB_SUBSYS, "post-install invalidation: null ndb/progress_db");

    /* (1) tip_finalize provable-tip cache. Its DURABLE source (tip_finalize_log
     * + the 8 stage cursors) was already reset to the installed anchor AND
     * post-install-verified inside consensus_state_snapshot_install_activate.
     * This path pre-warmed the process-local reducer_frontier provable-tip cache
     * from the PRE-install store, so drop that stale in-memory value: nothing may
     * republish the old tip if this path returns rather than _exit()ing. */
    reducer_frontier_provable_tip_reset();

    /* (2) The installed coin set must sit exactly at the bundle height. */
    int64_t coins_max = -1;
    bool have_coins = false;
    if (!icb_coins_max_height(progress_db, &coins_max, &have_coins))
        LOG_FAIL(ICB_SUBSYS,
                 "post-install invalidation: reading MAX(coins.height) failed");
    if (!have_coins || coins_max != (int64_t)bundle_height) {
        LOG_ERROR(ICB_SUBSYS,
                  "post-install invalidation: MAX(coins.height)=%lld != bundle "
                  "height=%d (installed coin tip is not at the bundle tip)",
                  (long long)coins_max, bundle_height);
        return false;
    }

    /* (3) Replace any stale node.db Sapling tree pair with the complete,
     * destination-verified frontier that activation just installed. */
    if (!icb_install_bundle_sapling_tree(ndb, progress_db, bundle_height))
        return false;

    LOG_INFO(ICB_SUBSYS,
             "post-install derived-state reconciliation OK: bundle Sapling "
             "tree cached, provable-tip cache reset, coins tip=%lld == bundle "
             "height=%d", (long long)coins_max, bundle_height);
    return true;
}

/* node.db `utxos` is a DERIVED, rebuildable read-model projection —
 * utxo_mirror_sync_service.h's own design doc: consensus reads never depend on
 * it, its sole writer is this background service, and every drift shape it
 * detects (cursor lag OR a row-count mismatch) is healed by a wholesale rebuild
 * straight from coins_kv. A bundle install SWAPS coins/anchors/nullifiers to a
 * possibly different-provenance dataset — not a continuation of whatever the
 * mirror was tracking before — so rows the mirror already held (at ANY height,
 * not just above the bundle height) are not guaranteed to match the freshly
 * installed coins_kv content byte-for-byte.
 *
 * Left alone, a stale mirror bites on the very next boot: utxo_recovery_
 * clean_above_tip's bounded guard (utxo_recovery_service.c,
 * UTXO_BOOT_REWIND_MAX_ROWS=32) only auto-heals a single-block, <=32-row
 * overshoot, so a larger stale-mirror overshoot raises the PERMANENT
 * utxo_recovery.rewind_overshoot blocker — a wedge on a table that carries no
 * consensus weight at all.
 *
 * Reset wholesale (not a height-bounded delete) plus the sync cursor, so
 * utxo_mirror_sync_service's own drift detector fires on its first pass after
 * boot and rebuilds the mirror straight from the just-installed coins_kv —
 * reusing the service's existing contract rather than a bespoke partial patch
 * here. Best-effort: the activation itself already durably succeeded, so a reset
 * failure is loud but must not turn a successful install into a refusal. */
bool icb_reset_utxo_mirror(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL(ICB_SUBSYS, "post-install mirror reset: node.db not open");

    bool ok = node_db_exec(ndb, "DELETE FROM utxos");
    if (!ok)
        LOG_WARN(ICB_SUBSYS, "post-install mirror reset: DELETE FROM utxos failed");
    bool commitment_ok = node_db_exec(ndb,
        "DELETE FROM node_state WHERE key='utxo_commitment'");
    if (!commitment_ok)
        LOG_WARN(ICB_SUBSYS,
                 "post-install mirror reset: utxo_commitment cache clear failed");
    /* -1 is never a valid mirror height — guarantees the next sync pass sees
     * cursor != the newly installed coins_kv applied frontier and rebuilds, even
     * in the edge case where DELETE FROM utxos above already left the table empty
     * (row-count-divergence drift would also catch that, but don't rely on two
     * guards firing when one explicit reset is simpler). */
    bool cursor_ok = node_db_state_set_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, -1);
    if (!cursor_ok)
        LOG_WARN(ICB_SUBSYS, "post-install mirror reset: sync cursor reset failed");
    return ok && commitment_ok && cursor_ok;
}

#endif /* !_WIN32 */
