/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef Z23_TEST_BOOT_WALLET_HISTORY_STARTUP_H
#define Z23_TEST_BOOT_WALLET_HISTORY_STARTUP_H
#include "../../../engine/composition/src/boot_cutover_startup_internal.h"
#include "config/boot.h"
#include "config/consensus_state_install_runtime.h"
#include "services/wallet_history_manifest.h"
#include "services/wallet_history_capability.h"
#include "base/hex.h"
#include "util/thread_registry.h"
#if defined(__linux__)
#include "platform/os_proc.h"
#include <signal.h>
#endif
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

#if defined(__linux__)
enum boot_pending_replay_result boot_test_bound_history_status(const struct app_context *, const struct wallet_cutover_binding *);
static bool boot_test_bound_history_open(const struct app_context *ctx, const struct wallet_cutover_binding *binding)
{ return boot_test_bound_history_status(ctx, binding) == BOOT_PENDING_COMPLETE; }
static bool bil_bound_stopped(const struct app_context *ctx, const struct wallet_cutover_binding *binding,
                              enum boot_pending_replay_result expected)
{
    pid_t child = fork();
    if (!child) {
        thread_registry_request_shutdown();
        _exit(boot_test_bound_history_status(ctx, binding) == expected ? 0 : 1);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool bil_bound_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t n = strlen(content);
    bool ok = write(fd, content, n) == (ssize_t)n;
    return close(fd) == 0 && ok;
}
struct bil_fresh_race { bool changed; };
static void bil_fresh_rewrite(const char *datadir, void *opaque)
{
    struct bil_fresh_race *race = opaque;
    race->changed = boot_install_bound_bundle_test_rewrite(datadir, 1);
}
static bool bil_fresh_mismatches(const char *dir, const struct boot_bound_bundle_observation *obs)
{
    for (unsigned i = 0; i < 7; ++i) {
        struct boot_bound_bundle_observation stale = *obs;
        if (i == 0) stale.attempts++;
        if (i == 1) stale.endpoint_height++;
        if (i == 2) stale.endpoint_hash[0] ^= 1;
        if (i == 3) stale.snapshot_sha3[0] ^= 1;
        if (i == 4) stale.history_manifest_root[0] ^= 1;
        if (i == 5) stale.bundle_path[1] ^= 1;
        if (i == 6) stale.private_history_path[1] ^= 1;
        struct wallet_history_capability cap; wallet_history_capability_init(&cap);
        bool refused = boot_bound_history_acquire_observed(dir, &stale, false, &cap) == BOOT_PENDING_FAILED && !cap.verified;
        wallet_history_capability_release(&cap);
        if (!refused) return false;
    }
    return true;
}
static bool bil_fresh_cancel(const char *dir, const struct boot_bound_bundle_observation *obs,
                             enum boot_pending_replay_result expected)
{
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(1);
        thread_registry_request_shutdown();
        struct wallet_history_capability cap; wallet_history_capability_init(&cap);
        enum boot_pending_replay_result result = boot_bound_history_acquire_observed(dir, obs, false, &cap);
        wallet_history_capability_release(&cap); _exit(result == expected ? 0 : 1);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int bil_fresh_history_case(const char *dir, const char *lock_leaf, bool setup)
{
    int failures = 0; struct boot_bound_bundle_observation obs = {0}, after = {0};
    bool ready = setup && boot_install_bound_bundle_read(dir, &obs) == BOOT_BOUND_READ_READY;
    struct wallet_history_capability cap; wallet_history_capability_init(&cap);
    bool acquired = ready && boot_bound_history_acquire_observed(dir, &obs, false, &cap) == BOOT_PENDING_COMPLETE &&
        wallet_history_capability_matches(&cap, obs.history_manifest_root).ok &&
        wallet_history_capability_matches_path(&cap, obs.private_history_path).ok;
    struct platform_directory_transaction parent; struct platform_directory_lock lease;
    platform_directory_transaction_init(&parent); platform_directory_lock_init(&lease);
    bool parent_open = platform_directory_transaction_open(&parent, dir);
    bool blocked = parent_open && platform_directory_lock_acquire(&parent, lock_leaf, false,
        PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) == PLATFORM_DIRECTORY_REFUSED;
    BIL_CHECK("fresh observation holds verified capability and lease", acquired && blocked);
    BIL_CHECK("fresh acquisition refuses occupied output without releasing lease", acquired &&
        boot_bound_history_acquire_observed(dir, &obs, false, &cap) == BOOT_PENDING_FAILED && cap.verified);
    wallet_history_capability_release(&cap);
    bool unlocked = parent_open && platform_directory_lock_acquire(&parent, lock_leaf, false,
        PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) == PLATFORM_DIRECTORY_OK;
    BIL_CHECK("fresh capability release releases lease", acquired && unlocked);
    platform_directory_lock_release(&lease); platform_directory_transaction_close(&parent);
    BIL_CHECK("fresh observation rejects every stale request field", ready && bil_fresh_mismatches(dir, &obs));
    struct boot_bound_bundle_observation unterminated = obs;
    memset(unterminated.bundle_path, 'x', sizeof(unterminated.bundle_path));
    wallet_history_capability_init(&cap);
    BIL_CHECK("fresh refuses unterminated observation", ready &&
        boot_bound_history_acquire_observed(dir, &unterminated, false, &cap) == BOOT_PENDING_FAILED && !cap.verified);
    wallet_history_capability_release(&cap);
    BIL_CHECK("fresh observed cancellation returns Stop", ready && bil_fresh_cancel(dir, &obs, BOOT_PENDING_STOPPED));
    struct bil_fresh_race race = {0}; wallet_history_capability_init(&cap);
    boot_bound_history_test_after_acquire(bil_fresh_rewrite, &race);
    enum boot_pending_replay_result changed = ready ? boot_bound_history_acquire_observed(dir, &obs, false, &cap) : BOOT_PENDING_COMPLETE;
    boot_bound_history_test_after_acquire(NULL, NULL);
    bool read_changed = boot_install_bound_bundle_read(dir, &after) == BOOT_BOUND_READ_READY && after.attempts == 1;
    BIL_CHECK("fresh post-acquire request change refuses and releases", ready && race.changed &&
        changed == BOOT_PENDING_FAILED && !cap.verified && read_changed);
    wallet_history_capability_release(&cap);
    bool restored = boot_install_bound_bundle_test_rewrite(dir, BOOT_INSTALL_BUNDLE_TERMINAL) &&
        boot_install_bound_bundle_read(dir, &after) == BOOT_BOUND_READ_TERMINAL;
    wallet_history_capability_init(&cap);
    bool terminal_refused = restored && boot_bound_history_acquire_observed(dir, &after, false, &cap) == BOOT_PENDING_FAILED;
    bool terminal_allowed = restored && boot_bound_history_acquire_observed(dir, &after, true, &cap) == BOOT_PENDING_COMPLETE;
    BIL_CHECK("fresh refuses terminal while pending recovery accepts it", terminal_refused && terminal_allowed);
    wallet_history_capability_release(&cap);
    bool reset = boot_install_bound_bundle_test_rewrite(dir, 0);
    BIL_CHECK("fresh test restores original request", reset && boot_install_bound_bundle_read(dir, &after) == BOOT_BOUND_READ_READY && after.attempts == 0);
    return failures;
}
static int bil_bound_history_case(void)
{
    int failures = 0;
    static const char expected_root[] =
        "history-0100000000000000000000000000000000000000000000000000000000000000-"
        "0200000000000000000000000000000000000000000000000000000000000000";
    static const char expected_stage[] =
        ".history-0100000000000000000000000000000000000000000000000000000000000000-"
        "0200000000000000000000000000000000000000000000000000000000000000-stage";
    static const char expected_lock[] =
        ".history-0100000000000000000000000000000000000000000000000000000000000000-"
        "0200000000000000000000000000000000000000000000000000000000000000-lock";
    uint8_t vector_snapshot[32] = {1}, vector_root[32] = {2};
    struct wallet_history_names vector_names;
    BIL_CHECK("receiver naming refuses missing snapshot", !wallet_history_capability_names(NULL, vector_root, &vector_names).ok);
    BIL_CHECK("receiver naming refuses missing root", !wallet_history_capability_names(vector_snapshot, NULL, &vector_names).ok);
    BIL_CHECK("receiver naming refuses missing output", !wallet_history_capability_names(vector_snapshot, vector_root, NULL).ok);
    BIL_CHECK("receiver naming vector", wallet_history_capability_names(vector_snapshot, vector_root, &vector_names).ok &&
        !strcmp(vector_names.root, expected_root) && strlen(vector_names.stage) == 144 &&
        !strcmp(vector_names.stage, expected_stage) &&
        !strcmp(vector_names.lock, expected_lock));
    char dir[PATH_MAX] = {0}, stage[PATH_MAX], blocks[PATH_MAX], file[PATH_MAX];
    char archive[PATH_MAX], lock[PATH_MAX], identity[130], leaf[140];
    bool made = test_mkdtemp(dir, sizeof(dir), "bound_restart");
    struct wallet_cutover_binding binding = {.target_height = 26, .history_identity_present = true};
    binding.snapshot_whole_sha3[0] = 1; binding.target_hash[0] = 2;
    bool ok = made && snprintf(stage, sizeof(stage), "%s/stage", dir) < (int)sizeof(stage) &&
        snprintf(blocks, sizeof(blocks), "%s/blocks", stage) < (int)sizeof(blocks) &&
        mkdir(stage, 0700) == 0 && mkdir(blocks, 0700) == 0 &&
        snprintf(file, sizeof(file), "%s/block_index.bin", stage) < (int)sizeof(file) &&
        bil_bound_file(file, "index") &&
        snprintf(file, sizeof(file), "%s/blk00000.dat", blocks) < (int)sizeof(file) &&
        bil_bound_file(file, "block");
    struct file_manifest *manifest = calloc(1, sizeof(*manifest));
    ok = ok && manifest && wallet_history_manifest_build(manifest, stage, 1).ok;
    if (ok) memcpy(binding.history_manifest_root, manifest->root_hash, 32);
    free(manifest);
    zcl_hex_encode(binding.snapshot_whole_sha3, 32, identity); identity[64] = '-';
    zcl_hex_encode(binding.history_manifest_root, 32, identity + 65);
    ok = ok && snprintf(leaf, sizeof(leaf), "history-%s", identity) < (int)sizeof(leaf) &&
        snprintf(archive, sizeof(archive), "%s/%s", dir, leaf) < (int)sizeof(archive) &&
        snprintf(lock, sizeof(lock), "%s/.history-%s-lock", dir, identity) < (int)sizeof(lock) &&
        rename(stage, archive) == 0 && bil_bound_file(lock, "lease");
    struct boot_bound_bundle_request request = {.bundle_path = "/fixture", .private_history_path = archive,
        .endpoint_height = binding.target_height};
    memcpy(request.snapshot_sha3, binding.snapshot_whole_sha3, 32);
    memcpy(request.endpoint_hash, binding.target_hash, 32);
    memcpy(request.history_manifest_root, binding.history_manifest_root, 32);
    struct app_context ctx = {.datadir = dir};
    ok = ok && boot_install_bound_bundle_request(dir, &request, NULL) == BOOT_BUNDLE_ARM_CREATED;
    char fresh_lock_leaf[144];
    int fresh_lock_len = snprintf(fresh_lock_leaf, sizeof(fresh_lock_leaf), ".history-%s-lock", identity);
    failures += bil_fresh_history_case(dir, fresh_lock_leaf, ok && fresh_lock_len >= 0 &&
                                       (size_t)fresh_lock_len < sizeof(fresh_lock_leaf));
    BIL_CHECK("bound restart reacquires exact retained history", ok && boot_test_bound_history_open(&ctx, &binding));
    BIL_CHECK("bound restart maps observed cancellation to Stop", ok && bil_bound_stopped(&ctx, &binding, BOOT_PENDING_STOPPED));
    BIL_CHECK("bound restart rejects null context", !boot_test_bound_history_open(NULL, &binding));
    BIL_CHECK("bound restart rejects null binding", !boot_test_bound_history_open(&ctx, NULL));
    struct platform_directory_transaction parent;
    struct platform_directory_lock held;
    platform_directory_transaction_init(&parent); platform_directory_lock_init(&held);
    char lock_leaf[144];
    bool locked = ok && snprintf(lock_leaf, sizeof(lock_leaf), ".history-%s-lock", identity) < (int)sizeof(lock_leaf) &&
        platform_directory_transaction_open(&parent, dir) &&
        platform_directory_lock_acquire(&parent, lock_leaf, false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &held) == PLATFORM_DIRECTORY_OK;
    BIL_CHECK("bound restart refuses held lease", locked && !boot_test_bound_history_open(&ctx, &binding));
    platform_directory_lock_release(&held); platform_directory_transaction_close(&parent);
    char extra[PATH_MAX];
    ok = ok && snprintf(file, sizeof(file), "%s/blocks/blk00000.dat", archive) < (int)sizeof(file) &&
        snprintf(extra, sizeof(extra), "%s/blocks/blk00001.dat", archive) < (int)sizeof(extra) &&
        bil_bound_file(extra, "extra");
    BIL_CHECK("bound restart refuses extra block", ok && !boot_test_bound_history_open(&ctx, &binding));
    ok = ok && unlink(extra) == 0 && rename(file, extra) == 0;
    BIL_CHECK("bound restart refuses block gap", ok && !boot_test_bound_history_open(&ctx, &binding));
    ok = ok && rename(extra, file) == 0;
    struct wallet_cutover_binding bad = binding; bad.history_manifest_root[0] ^= 1;
    BIL_CHECK("bound restart refuses mismatched root", ok && !boot_test_bound_history_open(&ctx, &bad));
    bad = binding; bad.target_hash[0] ^= 1;
    BIL_CHECK("bound restart refuses mismatched endpoint", ok && !boot_test_bound_history_open(&ctx, &bad));
    bad = binding; bad.snapshot_whole_sha3[0] ^= 1;
    BIL_CHECK("bound restart refuses mismatched snapshot", ok && !boot_test_bound_history_open(&ctx, &bad));
    ok = ok && snprintf(file, sizeof(file), "%s/blocks/blk00000.dat", archive) < (int)sizeof(file) &&
        bil_bound_file(file, "altered");
    BIL_CHECK("bound restart refuses changed history", ok && !boot_test_bound_history_open(&ctx, &binding));
    ok = ok && bil_bound_file(file, "block") && unlink(lock) == 0;
    BIL_CHECK("bound restart refuses missing lease", ok && !boot_test_bound_history_open(&ctx, &binding));
    struct boot_bound_bundle_observation fresh_missing = {0};
    bool fresh_ready = boot_install_bound_bundle_read(dir, &fresh_missing) == BOOT_BOUND_READ_READY;
    BIL_CHECK("fresh lease error takes precedence over Stop", ok && fresh_ready &&
        bil_fresh_cancel(dir, &fresh_missing, BOOT_PENDING_FAILED));
    BIL_CHECK("bound restart preserves lease error over Stop", ok && bil_bound_stopped(&ctx, &binding, BOOT_PENDING_FAILED));
    if (made) test_rm_rf_recursive(dir);
    return failures;
}
#endif

static int bil_startup_archive_case(void)
{
    struct bil_startup_fixture f = {0};
    chain_params_select(CHAIN_REGTEST);
    bool opened = bil_startup_fixture_open(&f);
    int failures = opened ? bil_startup_empty_cases(&f) : 0;
#if defined(__linux__)
    failures += bil_bound_history_case();
#endif
    failures += bil_startup_fixture_exercise(&f);
    if (!opened && !failures) failures++;
    bil_startup_fixture_close(&f);
    chain_params_select(CHAIN_MAIN);
    return failures;
}

#endif
