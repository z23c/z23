/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The pending wallet-cutover boot after a legacy install at a baked rung: the
 * projection-only index lacks the coins tip, no island exists, and the 28 full
 * headers rung-27..rung were staged in header_solution_repair before the
 * install armed. The boot proves them, registers the island in memory only and
 * the unchanged pending restore decides. Included once by
 * test_recovery_no_worse.c after its pending-restore fixture. */

#ifndef BOOT_PENDING_ISLAND_TEST_H
#define BOOT_PENDING_ISLAND_TEST_H

#include "../../../engine/composition/src/boot_cutover_startup_internal.h"
#include "config/boot_projection_hole_scan.h"
#include "config/boot_wallet_cutover_replay.h"
#include "config/db_service.h"
#include "config/flysync_island.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_helpers.h"
#include "jobs/stage_repair.h"
#include "storage/event_log.h"
#include "test/test_flysync_island_common.h"
#include "wallet/wallet.h"

#define NW_ISLAND_H FSI_RUNG_H

bool boot_test_pending_replay_prepare(struct boot_cutover_env *, struct app_context *,
    struct boot_cutover_replay *, struct wallet_rpc_context *, void **);
void boot_test_pending_replay_close(void *);

/* The flysync_island group's hash-linked window; the rung header (nothing links
 * to it) commits to the fixture's durable Sapling tree. */
static void nw_island_build(struct fsi_island *is, const struct uint256 *sapling_root)
{
    fsi_build_island(is);
    is->w[0].hashFinalSaplingRoot = *sapling_root;
    block_header_get_hash(&is->w[0], &is->hash[0]);
    memcpy(is->rung.cp.block_hash, is->hash[0].data, 32);
}

static struct uint256 g_fsi_nw_bad;
static bool nw_island_reject_one(const struct uint256 *hash, const struct block_header *hdr)
{
    (void)hdr;
    return !uint256_eq(hash, &g_fsi_nw_bad);
}

static void nw_island_overrides(struct fsi_island *is)
{
    if (is) checkpoints_set_rom_state_rungs_override_for_test(&is->rung, 1);
    else checkpoints_reset_rom_state_rungs_override_for_test();
    flysync_island_test_set_rung(is ? &is->rung : NULL);
    flysync_island_test_set_frozen_verifier(is ? fsi_accept_all : NULL);
}

static bool nw_island_stage(sqlite3 *db, const struct fsi_island *is, int skip)
{
    bool ok = true;
    for (int i = 0; ok && i < FSI_W; i++)
        if (i != skip) ok = stage_repair_header_solution_save(db, NW_ISLAND_H - i, &is->hash[i], &is->w[i]);
    return ok;
}

/* No island row reached the event log or the projection. */
static bool nw_island_unprojected(struct nw_pending_restore_fixture *f, const struct fsi_island *is,
                                  uint64_t log_size)
{
    if (!event_log_flush(f->log) || block_index_projection_catch_up(f->projection) == UINT64_MAX ||
        event_log_size(f->log) != log_size) return false;
    for (int i = 0; i < FSI_W; i++) {
        struct disk_block_index disk;
        if (block_index_projection_lookup_strict(f->projection, is->hash[i].data, &disk) != BIP_LOOKUP_ABSENT)
            return false;
    }
    return true;
}

static bool nw_island_untouched(struct nw_pending_restore_fixture *f, size_t map_before,
                                const struct wallet_cutover_binding *b, const struct uint256 *coins)
{
    return !island_anchor_registered() && !boot_pending_island_active() &&
        f->replay.ms.map_block_index.size == map_before &&
        boot_wallet_pending_restore(&f->replay.ms, &f->csr, NW_ISLAND_H, coins, b->target_height,
            coins) == BOOT_PENDING_RESTORE_ANCESTRY_INVALID;
}

/* Every other route decides as before: nothing attempted, nothing registered. */
static int nw_pending_island_skips(struct nw_pending_restore_fixture *f, struct fsi_island *is,
    const struct wallet_cutover_binding *b, const struct uint256 *coins, size_t map_before)
{
    int failures = 0;
    struct wallet_cutover_binding bound = *b;
    bound.history_identity_present = true;
    NW_CHECK("pending island: a bound-route binding is not this route",
        boot_pending_island_prepare(&f->replay.ms, &bound, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_SKIPPED &&
        nw_island_untouched(f, map_before, b, coins));
    struct wallet_cutover_binding moved = *b;
    moved.old_height = 5;
    NW_CHECK("pending island: a cutover from a non-fresh coins state (old_height 5) is not this route",
        boot_pending_island_prepare(&f->replay.ms, &moved, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_SKIPPED &&
        nw_island_untouched(f, map_before, b, coins));
    flysync_island_set_requested(true);
    NW_CHECK("pending island: -flysync keeps its own route",
        boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_SKIPPED &&
        nw_island_untouched(f, map_before, b, coins));
    flysync_island_set_requested(false);
    struct uint256 other = *coins;
    other.data[0] ^= 1;
    NW_CHECK("pending island: a coins tip other than the target is not this route",
        boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, &other) == BOOT_PENDING_ISLAND_SKIPPED &&
        nw_island_untouched(f, map_before, b, coins));
    nw_island_overrides(NULL);
    NW_CHECK("pending island: a target that is no baked rung is not this route",
        boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_SKIPPED &&
        nw_island_untouched(f, map_before, b, coins));
    nw_island_overrides(is);
    struct island_anchor fake = {0};
    fake.root_height = 100; fake.rung_height = 127;
    fake.root_hash.data[0] = 1; fake.rung_hash.data[0] = 2; fake.root_work.pn[0] = 1;
    bool reg = island_anchor_register(&fake).ok;
    NW_CHECK("pending island: an already registered island is not this route",
        reg && boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_SKIPPED &&
        f->replay.ms.map_block_index.size == map_before);
    island_anchor_unregister();
    sqlite3 *db = progress_store_db();
    uint8_t fell = ISLAND_ANCHOR_STATE_FELL_BACK;
    bool stored = progress_meta_set(db, "flysync.island_state", &fell, 1);
    NW_CHECK("pending island: a stored island state (FELL_BACK, none registered) is not this route",
        stored && island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_FELL_BACK &&
        boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_SKIPPED &&
        nw_island_untouched(f, map_before, b, coins));
    NW_CHECK("pending island: stored state fixture removed",
        progress_meta_delete(db, "flysync.island_state") &&
        island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_NONE);
    return failures;
}

/* A missing or forged row, or one failing PoW/Equihash, registers nothing. */
static int nw_pending_island_refusals(struct nw_pending_restore_fixture *f, struct fsi_island *is,
    const struct wallet_cutover_binding *b, const struct uint256 *coins, size_t map_before)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    NW_CHECK("pending island: a missing window row refuses (T6: no fetch, refuses as before)",
        nw_island_stage(db, is, 9) &&
        boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_REFUSED &&
        nw_island_untouched(f, map_before, b, coins));
    struct fsi_island forged = *is;
    forged.w[9].nNonce.data[5] ^= 0x40;
    struct uint256 forged_hash;
    block_header_get_hash(&forged.w[9], &forged_hash);
    NW_CHECK("pending island: a row that does not hash-link refuses",
        stage_repair_header_solution_save(db, NW_ISLAND_H - 9, &forged_hash, &forged.w[9]) &&
        boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_REFUSED &&
        nw_island_untouched(f, map_before, b, coins));
    NW_CHECK("pending island: the real row restaged",
        stage_repair_header_solution_save(db, NW_ISLAND_H - 9, &is->hash[9], &is->w[9]));
    g_fsi_nw_bad = is->hash[4];
    flysync_island_test_set_frozen_verifier(nw_island_reject_one);
    NW_CHECK("pending island: one row failing PoW/Equihash refuses",
        boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins) == BOOT_PENDING_ISLAND_REFUSED &&
        nw_island_untouched(f, map_before, b, coins));
    flysync_island_test_set_frozen_verifier(fsi_accept_all);
    return failures;
}

/* The one durable write the pending boot makes from its index: the node.db
 * sync cursor, rewound from above to the coins tip (the rung) and its hash. */
static bool nw_island_cursor_at_rung(struct nw_pending_restore_fixture *f, const struct uint256 *coins)
{
    struct uint256 above = *coins;
    above.data[1] ^= 1;
    int cursor = -1;
    uint8_t stored[32] = {0};
    return node_db_sync_set_tip(&f->replay.ndb, above.data, NW_ISLAND_H + 100) &&
        boot_projection_finalize_cursor(&f->replay.ndb, &f->replay.ms.chain_active, &cursor) &&
        cursor == NW_ISLAND_H && node_db_sync_get_tip_height(&f->replay.ndb) == NW_ISLAND_H &&
        node_db_sync_get_tip_hash(&f->replay.ndb, stored) && memcmp(stored, coins->data, 32) == 0;
}

/* A legacy PENDING record whose scan floor is `from`. */
static bool nw_island_record(struct wallet_sqlite *ws, const struct wallet_cutover_binding *b,
                             struct wallet *w, int from)
{
    wallet_init(w);
    if (!wallet_readiness_initialize(w, WALLET_READINESS_PENDING, true, 1)) return false;
    w->best_block_height = NW_ISLAND_H;
    w->scan_retry.pending = true;
    w->scan_retry.from = from;
    struct wallet_cutover_binding record = *b;
    record.artifact_digest[0] = 1;
    int floor = -1;
    return wallet_sqlite_cutover_prepare(ws, w, &record) &&
        wallet_sqlite_cutover_scan_floor(ws, &floor) == WALLET_CUTOVER_FLOOR_FOUND && floor == from;
}

static bool nw_island_record_retire(struct wallet_sqlite *ws)
{
    struct wallet_cutover_binding gone;
    return sqlite3_exec(ws->db, "DELETE FROM node_state WHERE key IN ('wallet_cutover_binding',"
                        "'wallet_scan_incomplete','wallet_scan_height')", NULL, NULL, NULL) == SQLITE_OK &&
        wallet_sqlite_cutover_read(ws, &gone) == WALLET_CUTOVER_ABSENT;
}

/* Run the unchanged pending replay over the in-memory island chain with no
 * wallet-history archive (the datadir is a file). Returns true when the
 * outcome matches `expect_prepared`, no step returns COMPLETE and wallet
 * readiness stays PENDING (no balance, nothing spendable). */
static bool nw_island_replay_holds(struct nw_pending_restore_fixture *f, struct boot_cutover_env *base,
    struct wallet *w, struct db_service *svc, bool expect_prepared)
{
    char file[700];
    snprintf(file, sizeof(file), "%s/node.db", f->replay.root);
    struct boot_cutover_env env = *base;
    env.state = &f->replay.ms; env.node = &f->replay.ndb; env.wallet = w;
    env.coins_tip = &f->replay.cache; env.db_service = svc; env.sapling_load_ok = true;
    struct app_context ctx = {.datadir = file};
    struct boot_cutover_replay replay = {0};
    struct wallet_rpc_context rpc;
    void *history = NULL;
    bool prepared = boot_test_pending_replay_prepare(&env, &ctx, &replay, &rpc, &history);
    enum boot_cutover_replay_status st = BOOT_CUTOVER_PROGRESS;
    for (int i = 0; prepared && i < 32 && (st == BOOT_CUTOVER_PROGRESS || st == BOOT_CUTOVER_BUSY); i++)
        st = boot_cutover_replay_step(&replay);
    printf("pending island replay: prepared=%d last_step=%d\n", (int)prepared, (int)st);
    bool held = prepared == expect_prepared && st != BOOT_CUTOVER_COMPLETE &&
        wallet_readiness_get(w).state == WALLET_READINESS_PENDING;
    boot_cutover_replay_clear(&replay);
    boot_test_pending_replay_close(history);
    return held;
}

/* I5 on the island chain (rung-27..rung): one wallet with history per floor. */
static bool nw_island_replay_case(struct nw_pending_restore_fixture *f, struct boot_cutover_env *base,
    const struct wallet_cutover_binding *b, int from, bool expect_prepared)
{
    struct wallet *w = zcl_calloc(1, sizeof(*w), "pending island replay wallet");
    if (!w) return false;
    struct db_service svc;
    db_service_init(&svc);
    bool recorded = nw_island_record(base->wallet_db, b, w, from);
    bool started = recorded && db_service_attach(&svc, &f->replay.ndb) && db_service_start_test_worker(&svc);
    bool pending_blocks_handoff = recorded && !boot_pending_island_handoff_ready(base, b);
    w->map_wallet[0].used = true; /* history the empty-wallet proof must not ignore */
    bool held = started && pending_blocks_handoff && nw_island_replay_holds(f, base, w, &svc, expect_prepared);
    w->map_wallet[0].used = false;
    if (started) db_service_stop(&svc);
    wallet_free(w);
    free(w);
    return nw_island_record_retire(base->wallet_db) && held;
}

static int nw_island_replay_cases(struct nw_pending_restore_fixture *f, struct boot_cutover_env *env,
                                  const struct wallet_cutover_binding *b)
{
    int failures = 0;
    /* The restore moves the active window to the island tip; the walk stops at
     * the parentless root and keeps the lower window it had (here genesis at
     * slot 0, chainstate.c active_chain_fill_window), so slots between are
     * empty. */
    const struct active_chain *chain = &f->replay.ms.chain_active;
    NW_CHECK("pending island: the island chain links only down to rung-27; genesis stays in the lower window",
        active_chain_at(chain, NW_ISLAND_H - (FSI_W - 1)) && !active_chain_at(chain, NW_ISLAND_H - FSI_W) &&
        !active_chain_at(chain, 1) && active_chain_at(chain, 0));
    NW_CHECK("I5: history with a floor below the window on an empty slot and no archive refuses "
             "(pending replay history unavailable); the PENDING record blocks the restart; readiness PENDING",
        nw_island_replay_case(f, env, b, 1, false));
    NW_CHECK("I5: history with a floor on the kept lower window cannot complete over rows without "
             "bodies; the PENDING record blocks the restart; readiness PENDING",
        nw_island_replay_case(f, env, b, 0, true));
    NW_CHECK("I5: history with a floor inside the window cannot complete over rows without bodies; "
             "readiness PENDING",
        nw_island_replay_case(f, env, b, NW_ISLAND_H - 3, true));
    return failures;
}

/* After the restore: the restart and its handoff, the sync cursor and I5. */
static int nw_pending_island_after_restore(struct nw_pending_restore_fixture *f,
    struct boot_cutover_env *env, const struct wallet_cutover_binding *b, const struct uint256 *coins)
{
    int failures = 0;
    NW_CHECK("pending island: no handoff before this boot saw the replay complete",
        !boot_pending_island_handoff_ready(env, b));
    NW_CHECK("pending island: after completion the boot restarts instead of serving (T3)",
        boot_pending_island_restart_due(b));
    NW_CHECK("pending island: the restart hands off once the PENDING record is retired",
        boot_pending_island_handoff_ready(env, b));
    struct wallet_cutover_binding other = *b;
    other.target_hash[0] ^= 1;
    NW_CHECK("pending island: a binding other than the completed one never hands off",
        !boot_pending_island_handoff_ready(env, &other));
    NW_CHECK("pending island: the sync cursor is written at the rung tip and hash, nothing else projected",
        nw_island_cursor_at_rung(f, coins));
    failures += nw_island_replay_cases(f, env, b);
    return failures;
}

/* The staged, verified window registers in memory only and the unchanged
 * pending restore then proves the coins tip; nothing durable is written. */
static int nw_pending_island_registers(struct nw_pending_restore_fixture *f, struct fsi_island *is,
    const struct wallet_cutover_binding *b, const struct uint256 *coins)
{
    int failures = 0;
    sqlite3 *db = progress_store_db();
    struct wallet_sqlite ws = {0};
    bool wallet = wallet_sqlite_open_r(&ws, f->replay.ndb.db).ok;
    struct boot_cutover_env env = {.wallet_db = &ws};
    NW_CHECK("pending island: no island, no restart, no handoff before a window registers",
        wallet && !boot_pending_island_restart_due(b) && !boot_pending_island_handoff_ready(&env, b));
    NW_CHECK("pending island: the full window is staged", nw_island_stage(db, is, -1));
    uint64_t log_size = event_log_flush(f->log) ? event_log_size(f->log) : 0;
    int changes = sqlite3_total_changes(db);
    enum boot_pending_island_result prepared = boot_pending_island_prepare(&f->replay.ms, b, NW_ISLAND_H, coins);
    NW_CHECK("pending island: the staged verified window registers for this boot",
        prepared == BOOT_PENDING_ISLAND_REGISTERED && boot_pending_island_active() && island_anchor_registered());
    NW_CHECK("pending island: nothing durable (island state NONE, progress store and event log unchanged)",
        island_anchor_state_load(db) == ISLAND_ANCHOR_STATE_NONE && sqlite3_total_changes(db) == changes &&
        nw_island_unprojected(f, is, log_size));
    enum boot_pending_restore_result restored =
        boot_wallet_pending_restore(&f->replay.ms, &f->csr, NW_ISLAND_H, coins, NW_ISLAND_H, coins);
    printf("pending island restore result=%d\n", (int)restored);
    NW_CHECK("pending island: the unchanged pending restore proves the rung tip",
        restored == BOOT_PENDING_RESTORE_OK && sqlite3_total_changes(db) == changes);
    if (wallet && restored == BOOT_PENDING_RESTORE_OK)
        failures += nw_pending_island_after_restore(f, &env, b, coins);
    NW_CHECK("pending island: the island rows still reached neither the event log nor the projection",
        nw_island_unprojected(f, is, log_size));
    boot_pending_island_test_reset();
    NW_CHECK("pending island: a process without the in-memory island never restarts on it",
        !boot_pending_island_restart_due(b) && !boot_pending_island_handoff_ready(&env, b) &&
        !island_anchor_registered());
    if (wallet) wallet_sqlite_close(&ws);
    return failures;
}

/* The measured fresh-node state: a legacy pending cutover to a baked rung whose
 * coins tip the projection-only index lacks. */
static int nw_pending_island_case(void)
{
    int failures = 0;
    struct nw_pending_restore_fixture f = {0};
    bool ready = nw_pending_restore_open(&f);
    NW_CHECK("pending island fixture opens", ready);
    if (!ready) { nw_pending_restore_close(&f); return failures; }
    struct uint256 root;
    incremental_tree_root(&f.tree, &root);
    static struct fsi_island is;
    nw_island_build(&is, &root);
    flysync_island_test_reset();
    boot_pending_island_test_reset();
    nw_island_overrides(&is);
    struct wallet_cutover_binding b = {0};
    b.target_height = NW_ISLAND_H;
    memcpy(b.target_hash, is.hash[0].data, 32);
    struct uint256 coins = is.hash[0];
    size_t map_before = f.replay.ms.map_block_index.size;
    NW_CHECK("measured state: the rung coins tip absent from the index refuses with 3",
        boot_wallet_pending_restore(&f.replay.ms, &f.csr, NW_ISLAND_H, &coins, NW_ISLAND_H, &coins) == 3);
    failures += nw_pending_island_skips(&f, &is, &b, &coins, map_before);
    failures += nw_pending_island_refusals(&f, &is, &b, &coins, map_before);
    failures += nw_pending_island_registers(&f, &is, &b, &coins);
    nw_island_overrides(NULL);
    flysync_island_test_reset();
    nw_pending_restore_close(&f);
    return failures;
}

#endif /* BOOT_PENDING_ISLAND_TEST_H */
