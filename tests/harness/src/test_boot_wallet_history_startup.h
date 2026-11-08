/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef Z23_TEST_BOOT_WALLET_HISTORY_STARTUP_H
#define Z23_TEST_BOOT_WALLET_HISTORY_STARTUP_H
#include "../../../engine/composition/src/boot_cutover_startup_internal.h"
#include "config/boot.h"
#include "coins/coins_view.h"
#include "config/boot_wallet_cutover_replay.h"
#include "config/db_service.h"
#include "controllers/wallet_helpers.h"
#include "models/database.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet.h"

static struct uint256 bil_startup_genesis;
static struct zcl_result bil_startup_archive_open(struct main_state *state,
    const char *path, size_t cap, int32_t height, const uint8_t hash[32],
    struct block_header *window)
{
    return block_index_history_archive_test_open(state, path, cap, height, hash,
                                                  &bil_startup_genesis, window);
}
void boot_test_pending_history_set_open(struct zcl_result (*fn)(struct main_state *,
    const char *, size_t, int32_t, const uint8_t[32], struct block_header *));
bool boot_test_pending_replay_prepare(struct boot_cutover_env *, struct app_context *,
    struct boot_cutover_replay *, struct wallet_rpc_context *, void **);
void boot_test_pending_replay_close(void *);

static bool bil_startup_chain(struct main_state *canonical, struct block_index slots[2],
                              const struct uint256 hashes[29])
{
    main_state_init(canonical);
    for (int i = 0; i < 2; i++) {
        block_index_init(&slots[i]);
        slots[i].nHeight = 26 + i;
        slots[i].hashBlock = hashes[26 + i];
        slots[i].phashBlock = &slots[i].hashBlock;
        slots[i].pprev = i ? &slots[0] : NULL;
        if (!active_chain_install_tip_slot(&canonical->chain_active, &slots[i])) return false;
    }
    return true;
}

static bool bil_startup_wallet_prepare(struct wallet *wallet, struct wallet_sqlite *ws,
                                       const struct uint256 hashes[29])
{
    wallet_init(wallet);
    if (!wallet_readiness_initialize(wallet, WALLET_READINESS_PENDING, true, 1)) return false;
    struct wallet_cutover_binding binding = {.old_height = 0, .target_height = 26};
    memcpy(binding.target_hash, hashes[26].data, 32);
    binding.artifact_digest[0] = 1;
    wallet->scan_retry.pending = true;
    wallet->scan_retry.from = 0;
    return wallet_sqlite_cutover_prepare(ws, wallet, &binding);
}

static bool bil_startup_bound(const struct boot_cutover_replay *replay,
    const struct wallet_rpc_context *rpc, const struct boot_cutover_env *env,
    const struct app_context *ctx)
{
    return replay->canonical_state == env->state && rpc->main_state != env->state &&
        rpc->wallet == env->wallet && rpc->wallet_db == env->wallet_db &&
        rpc->node_db == env->node && rpc->coins_tip == env->coins_tip &&
        rpc->datadir == ctx->datadir && replay->service == env->db_service &&
        replay->floor == 0 && replay->ctx == rpc;
}

struct bil_startup_fixture {
    char dir[PATH_MAX], archive[PATH_MAX + 32], dbpath[PATH_MAX + 32];
    struct uint256 hashes[29];
    struct main_state canonical;
    struct block_index slots[2];
    struct node_db node;
    struct wallet_sqlite ws;
    struct wallet *wallet;
    struct db_service service;
    struct coins_view_cache coins;
    bool made, chain, db_open, ws_open, wallet_initialized, started;
};

static bool bil_startup_fixture_open(struct bil_startup_fixture *f)
{
    if (!test_mkdtemp(f->dir, sizeof(f->dir), "bil_boot_history")) return false;
    snprintf(f->archive, sizeof(f->archive), "%s/wallet-history", f->dir);
    snprintf(f->dbpath, sizeof(f->dbpath), "%s/node.db", f->dir);
    f->made = mkdir(f->archive, 0700) == 0 && bil_history_make(f->archive, f->hashes, 0);
    bil_startup_genesis = f->hashes[0];
    f->chain = f->made && bil_startup_chain(&f->canonical, f->slots, f->hashes);
    f->db_open = f->chain && node_db_open(&f->node, f->dbpath);
    f->ws_open = f->db_open && wallet_sqlite_open_r(&f->ws, f->node.db).ok;
    f->wallet = zcl_calloc(1, sizeof(*f->wallet), "startup fixture wallet");
    f->wallet_initialized = f->ws_open && f->wallet;
    bool prepared = f->wallet_initialized && bil_startup_wallet_prepare(f->wallet, &f->ws, f->hashes);
    db_service_init(&f->service);
    f->started = prepared && db_service_attach(&f->service, &f->node) &&
        db_service_start_test_worker(&f->service);
    return f->started;
}

static void bil_startup_fixture_close(struct bil_startup_fixture *f)
{
    boot_test_pending_history_set_open(NULL);
    if (f->started) db_service_stop(&f->service);
    if (f->wallet_initialized) wallet_free(f->wallet);
    free(f->wallet);
    if (f->ws_open) wallet_sqlite_close(&f->ws);
    if (f->db_open) node_db_close(&f->node);
    if (f->made) main_state_free(&f->canonical);
    if (f->dir[0]) (void)test_rm_rf_recursive(f->dir);
}

static bool bil_startup_empty_prepare(struct bil_startup_fixture *f)
{
    struct boot_cutover_env env = {.state = &f->canonical, .node = &f->node,
        .wallet = f->wallet, .wallet_db = &f->ws, .coins_tip = &f->coins,
        .db_service = &f->service, .sapling_load_ok = true};
    struct app_context ctx = {.datadir = f->dbpath}; /* A file, so no history directory exists. */
    struct boot_cutover_replay replay = {0}; struct wallet_rpc_context rpc;
    void *history = NULL;
    bool ok = boot_test_pending_replay_prepare(&env, &ctx, &replay, &rpc, &history);
    bool complete = ok && replay.full_empty && replay.shielded_empty && replay.floor == 0 &&
        replay.phase == BOOT_CUTOVER_DONE && !replay.canonical_state &&
        rpc.main_state == &f->canonical && boot_cutover_replay_step(&replay) == BOOT_CUTOVER_COMPLETE &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
    boot_cutover_replay_clear(&replay);
    boot_test_pending_replay_close(history);
    return complete;
}

static int bil_empty_deny_scripts(void *ctx, int action, const char *a, const char *b,
                                  const char *c, const char *d)
{
    (void)ctx; (void)b; (void)c; (void)d;
    return action == SQLITE_READ && a && !strcmp(a, "wallet_scripts") ? SQLITE_DENY : SQLITE_OK;
}

static int bil_startup_empty_cases(struct bil_startup_fixture *f)
{
    int failures = 0;
    bool canary = sqlite3_exec(f->node.db,
        "INSERT OR REPLACE INTO wallet_canary(id,probe,ts) VALUES(1,zeroblob(1),1)",
        NULL, NULL, NULL) == SQLITE_OK;
    BIL_CHECK("empty wallet without history accepts normal canary", canary && bil_startup_empty_prepare(f));
    f->wallet->sapling_keys.keys[0].used = true;
    BIL_CHECK("hidden Sapling key refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->sapling_keys.keys[0].used = false;
    f->wallet->sapling_keys.locked = true;
    BIL_CHECK("locked Sapling wallet refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->sapling_keys.locked = false;
    f->wallet->sapling_keys.num_damaged = 1;
    BIL_CHECK("damaged Sapling wallet refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->sapling_keys.num_damaged = 0;
    f->wallet->keystore.keys[0].used = true;
    BIL_CHECK("hidden transparent key refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->keystore.keys[0].used = false;
    f->wallet->keystore.watching[0].used = true;
    BIL_CHECK("hidden watch entry refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->keystore.watching[0].used = false;
    f->wallet->keystore.scripts[0].used = true;
    BIL_CHECK("hidden script refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->keystore.scripts[0].used = false;
    f->wallet->key_pool[0].persisted = true;
    BIL_CHECK("hidden keypool entry refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->key_pool[0].persisted = false;
    f->wallet->map_wallet[0].used = true;
    BIL_CHECK("hidden transaction refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->map_wallet[0].used = false;
    f->wallet->spent_set[0].occupied = true;
    BIL_CHECK("hidden spent outpoint refuses empty shortcut", !bil_startup_empty_prepare(f));
    f->wallet->spent_set[0].occupied = false;
    bool seed = sqlite3_exec(f->node.db,
        "INSERT INTO wallet_seed(id,seed,next_child) VALUES(1,zeroblob(32),0)",
        NULL, NULL, NULL) == SQLITE_OK;
    BIL_CHECK("durable seed refuses empty shortcut", seed && !bil_startup_empty_prepare(f));
    BIL_CHECK("seed fixture cleanup", sqlite3_exec(f->node.db, "DELETE FROM wallet_seed", NULL, NULL, NULL) == SQLITE_OK);
    bool denied = sqlite3_set_authorizer(f->node.db, bil_empty_deny_scripts, NULL) == SQLITE_OK;
    BIL_CHECK("SQL read error refuses empty shortcut", denied && !bil_startup_empty_prepare(f));
    BIL_CHECK("restore SQL reads", sqlite3_set_authorizer(f->node.db, NULL, NULL) == SQLITE_OK);
    BIL_CHECK("empty proof succeeds after fixture cleanup", bil_startup_empty_prepare(f));
    return failures;
}


static int bil_startup_fixture_exercise(struct bil_startup_fixture *f)
{
    int failures = 0;
    struct boot_cutover_env env = {.state = &f->canonical, .node = &f->node,
        .wallet = f->wallet, .wallet_db = &f->ws, .coins_tip = &f->coins,
        .db_service = &f->service};
    struct app_context ctx = {.datadir = f->dir};
    struct boot_cutover_replay replay; struct wallet_rpc_context rpc;
    void *history = NULL;
    boot_test_pending_history_set_open(bil_startup_archive_open);
    bool ok = f->started && boot_test_pending_replay_prepare(&env, &ctx, &replay, &rpc, &history) &&
        bil_startup_bound(&replay, &rpc, &env, &ctx) &&
        strcmp(replay.archive_datadir, f->archive) == 0 && replay.endpoint.height == 27 &&
        memcmp(replay.endpoint.hash.data, f->hashes[27].data, 32) == 0;
    BIL_CHECK("pending startup binds real wallet and canonical state to archive view", ok);
    bool skip = ok && boot_cutover_replay_step(&replay) == BOOT_CUTOVER_PROGRESS &&
        replay.phase == BOOT_CUTOVER_DISCOVER &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
    BIL_CHECK("empty transparent phase advances without publishing readiness", skip);
    bool retry = skip && boot_cutover_replay_step(&replay) == BOOT_CUTOVER_RETRY &&
        wallet_readiness_get(f->wallet).state == WALLET_READINESS_PENDING;
    BIL_CHECK("header-only history cannot publish wallet readiness", retry);
    boot_test_pending_replay_close(history);
    history = NULL;
    if (f->chain) f->slots[1].hashBlock.data[0] ^= 1;
    bool refused = f->started && !boot_test_pending_replay_prepare(&env, &ctx, &replay, &rpc, &history);
    BIL_CHECK("pending startup refuses archive with wrong canonical endpoint", refused && !history);
    boot_test_pending_replay_close(history);
    return failures;
}

static int bil_startup_archive_case(void)
{
    struct bil_startup_fixture f = {0};
    chain_params_select(CHAIN_REGTEST);
    bool opened = bil_startup_fixture_open(&f);
    int failures = opened ? bil_startup_empty_cases(&f) : 0;
    failures += bil_startup_fixture_exercise(&f);
    if (!opened && !failures) failures++;
    bil_startup_fixture_close(&f);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

#endif
