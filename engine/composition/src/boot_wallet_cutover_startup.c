/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pending wallet cutover startup. */
#include "platform/socket_compat.h"
#include "services/wallet_history_capability.h"
#include "platform/wallet_startup_auth.h"
#include "platform/wallet_startup_auth_protocol.h"
#include "base/cleanse.h"
#include "wallet/wallet_lock.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "config/boot_blkidx_ladder.h"
#include "config/boot_blocktree_cleanup.h"
#include "config/boot_flight_recorder.h"
#include "config/flysync_island.h"
#include "config/bundle_exporter.h"
#include "config/boot_cursor_state.h"
#include "config/boot_datadir_lock.h"
#include "config/boot_internal.h"
#include "config/boot_wallet_pending_restore.h"
#include "config/boot_wallet_cutover_replay.h"
#include "boot_wallet_cutover_checkpoint_internal.h"
#include "services/block_index_loader.h"
#include "jobs/stage_repair.h"
#include "config/boot_wallet_cutover_publish.h"
#include "controllers/wallet_private_broadcast.h"
#include "services/wallet_private_relay.h"
#include "models/wallet_tx.h"
#include "models/wallet_send_once.h"
#include "util/ar_step_readonly.h"
#include "storage/wallet_projection.h"
#include "storage/event_log_singleton.h"
#include "controllers/wallet_helpers.h"
#include "config/boot_projection_hole_scan.h"
#include "config/boot_legacy_blocks.h"
#include "config/boot_memory_guard.h"
#include "config/boot_postmortem.h"
#include "config/boot_error.h"
#include "config/boot_refusal_reports.h"
#include "config/boot_block_files_fingerprint.h"
#include "config/boot_shutdown_marker.h"
#include "util/shutdown_stagewatch.h"
#include "config/boot_fast_restart.h"
#include "config/boot_snapshot_failure_memory.h"
#include "config/boot_snapshot_import.h"
#include "config/boot_snapshot_install.h"
#include "config/boot_stale_locks.h"
#include "config/boot_first_run_banner.h"
#include "config/boot_wallet_phrase.h"
#include "boot_timing_marks_internal.h"
#include "boot_block_index_scan_internal.h"
#include "support/cleanse.h"
#include "net/snapshot_sync_contract.h"
#include "services/chain_activation_service.h"
#include "services/chain_restore_boot_snapshot.h"
#include "services/chain_restore_executor.h"
#include "services/chain_restore_integrity.h"
#include "services/chain_restore_repair.h"
#include "services/chain_state_service.h"
#include "services/nullifier_backfill_service.h"
#include "util/service_state.h"
#include "services/service_state_driver.h"
#include "services/chain_tip.h"
#include "services/sync_benchmark_service.h"
#include "services/recovery_policy.h"
#include "services/utxo_recovery_service.h"
#include "supervisors/staged_sync_supervisor.h"
#include "storage/progress_store.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/anchor_kv.h"  /* seed the verified Sapling anchor frontier at boot */
#include "storage/nullifier_kv.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"  /* refold_progress_mark_started_from_anchor (B2) */
#include "jobs/stage_repair.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/utxo_reimport_flag.h"
#include "storage/boot_auto_reindex.h"   /* #6 B1: terminal mark on dead-end */
#include "storage/boot_auto_refold.h"    /* A1: consume the escalator's armed refold */
#include "config/consensus_state_install_runtime.h" /* 1b/1c: sovereign complete-state install */
#include "config/boot_crashonly.h"
#include "services/header_probe.h"
#include "services/block_index_integrity.h"
#include "services/sovereign_promotion_service.h"
#include "services/wallet_backup_service.h"
#include "services/disk_monitor.h"
#include "services/binary_staleness_service.h"
#include "services/storage_housekeeping.h"
#include "services/binary_ab_fallback.h"
#include "services/ibd_throttle.h"
#include "services/db_maintenance.h"
#include "config/boot_network_monitor.h"
#include "controllers/wallet_scan.h"
#include "util/blocker.h"
#include "util/boot_status.h"
#include "util/ar_step_readonly.h"
#include "util/signal_handler.h"
#include "util/self_backtrace.h"
#include "util/thread_registry.h"
#include "util/sync.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/boot_phase.h"
#include "util/boot_scan.h"
#include "util/sysinit.h"
#include "platform/os_sandbox.h"
#include "platform/private_directory.h"
#include "util/util.h"
#include "net/msgprocessor.h"
#include "chain/chainparams.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "coins/coins_view.h"
#include "coins/utxo_commitment.h"
#include "chain/checkpoints.h"
#include "storage/coins_view_sqlite.h"
#include "storage/coins_view_kv.h"
#include "base/serialize_le.h"
#include "storage/coins_kv.h"
#include "storage/consensus_db.h"
#include "storage/coins_db.h"
#include "storage/ldb_snapshot.h"
#include "consensus/validation.h"
#include "controllers/blockchain_controller.h"
#include "controllers/repair_controller.h"
#include "controllers/chain_inspect_controller.h"
#include "controllers/misc_controller.h"
#include "controllers/network_controller.h"
#include "rpc/httpserver.h"
#include "controllers/mining_controller.h"
#include "controllers/transaction_controller.h"
#include "rpc/server.h"
#include "storage/block_index_db.h"
#include "storage/block_index_projection.h"
#include "storage/disk_block_io.h"
#include "services/block_index_loader.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "validation/contextual_check_tx.h"
#include "net/connman.h"
#include "net/netbase.h"
#include "keys/key_io.h"
#include "mining/gen.h"
#include "script/standard.h"
#include "controllers/api_controller.h"
#include "controllers/explorer_controller.h"
#include "controllers/wallet_controller.h"
#include "controllers/zslp_controller.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_canary.h"
#include "wallet/wallet_db.h"
#include "sapling/params_init.h"
#include "config/boot_params_gate.h"
#include "metrics/metrics.h"
#include "chain/pow.h"
#include "controllers/sync_controller.h"
#include "controllers/legacy_import.h"
#include "controllers/snapshot_controller.h"
#include "validation/update_coins.h"
#include "validation/connect_block.h"
/* LevelDB dbwrapper only used for legacy import paths */
#include "net/tor_integration.h"
#include "net/https_server.h"
#include "net/fast_sync.h"
#include "net/peer_strategy.h"
#include "event/event.h"
#include "controllers/event_controller.h"
#include "models/block.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#if defined(__GLIBC__)
#include <malloc.h>
#endif
#include <limits.h>
#include <sqlite3.h>
#include "boot_steps_internal.h"
#include "boot_cutover_startup_internal.h"

#if !defined(_WIN32)
static bool boot_cutover_recover_committed(struct boot_cutover_env *e, const char *datadir, int fd,
    const struct wallet_cutover_binding *before, bool present, uint64_t generation)
{
    struct zcl_result recovered = consensus_state_install_recover_committed(e->node, datadir, NULL);
    bool next_present = false; uint64_t next_generation = 0;
    enum wallet_install_reconcile state = consensus_state_wallet_install_classify(
        e->wallet_db, e->node, fd, &next_present, &next_generation);
    struct wallet_cutover_binding after;
    return recovered.ok && state == WALLET_INSTALL_COMMITTED &&
        present == next_present && generation == next_generation &&
        wallet_sqlite_cutover_read(e->wallet_db, &after) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(before, &after) &&
        wallet_readiness_initialize(e->wallet, WALLET_READINESS_PENDING, present, generation);
}

static bool boot_cutover_pending_preflight(struct boot_cutover_env *e, const char *datadir,
    const struct wallet_cutover_binding *before, enum boot_cutover_preflight_kind *kind)
{
    int fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || !consensus_state_wallet_preflight_identity(e->wallet_db, e->node, fd) ||
        !progress_store_open_existing(datadir)) {
        if (fd >= 0) close(fd);
        LOG_ERROR("wallet", "wallet cutover existing authority cannot be opened safely");
        return false;
    }
    bool present = false; uint64_t generation = 0;
    enum wallet_install_reconcile state = consensus_state_wallet_install_classify(
        e->wallet_db, e->node, fd, &present, &generation);
    bool ok = false;
    if (state == WALLET_INSTALL_COMMITTED) {
        ok = boot_cutover_recover_committed(e, datadir, fd, before, present, generation);
        if (ok) *kind = BOOT_CUTOVER_COMMITTED;
    } else if (state == WALLET_INSTALL_OLD) {
        struct wallet_cutover_binding after;
        ok = wallet_sqlite_cutover_read(e->wallet_db, &after) == WALLET_CUTOVER_PENDING &&
            wallet_cutover_binding_equal(before, &after);
        if (ok) *kind = BOOT_CUTOVER_OLD_RETRY;
    }
    close(fd);
    if (!ok) {
        const char *reason = state == WALLET_INSTALL_OLD ? "old authority" :
            state == WALLET_INSTALL_COMMITTED ? "committed recovery unverified" : "unknown authority";
        LOG_ERROR("wallet", "wallet cutover requires recovery: %s", reason);
    }
    return ok;
}
#endif

/* No authority-changing bootstrap may run before this pending preflight. */
bool boot_cutover_preflight_classify(struct boot_cutover_env *e, const char *datadir,
    enum boot_cutover_preflight_kind *kind, struct wallet_cutover_binding *binding)
{
    if (!e || !kind || !binding) return false;
    *kind = BOOT_CUTOVER_NONE;
    enum wallet_cutover_status status = wallet_sqlite_cutover_read(e->wallet_db, binding);
    if (status == WALLET_CUTOVER_ABSENT) return true;
    if (status != WALLET_CUTOVER_PENDING) {
        LOG_ERROR("wallet", "wallet cutover binding unavailable or malformed (status=%d)", status);
        return false;
    }
#if defined(_WIN32)
    (void)datadir;
    LOG_ERROR("wallet", "wallet cutover recovery unavailable on this platform");
    return false;
#else
    return boot_cutover_pending_preflight(e, datadir, binding, kind);
#endif
}

bool boot_cutover_preflight(struct boot_cutover_env *e, const char *datadir, bool *pending)
{
    if (!pending) return false;
    *pending = false;
    struct wallet_cutover_binding binding;
    enum boot_cutover_preflight_kind kind;
    if (!boot_cutover_preflight_classify(e, datadir, &kind, &binding) ||
        kind == BOOT_CUTOVER_OLD_RETRY) return false;
    *pending = kind == BOOT_CUTOVER_COMMITTED;
    return true;
}



static bool boot_cutover_verify_committed_mode(struct boot_cutover_env *e, const char *datadir,
    const struct wallet_cutover_binding *expected, bool stop)
{
#if defined(_WIN32)
    (void)e; (void)datadir; (void)expected; (void)stop; return false;
#else
    if (!e || !datadir || !expected) return false;
    int fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool present = false; uint64_t generation = 0;
    enum wallet_install_reconcile state = stop ? consensus_state_wallet_install_classify_stop(
        e->wallet_db, e->node, fd, &present, &generation) : consensus_state_wallet_install_classify(
        e->wallet_db, e->node, fd, &present, &generation);
    struct wallet_cutover_binding actual;
    bool ok = state == WALLET_INSTALL_COMMITTED &&
        wallet_sqlite_cutover_read(e->wallet_db, &actual) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(expected, &actual);
    close(fd);
    return ok;
#endif
}

bool boot_cutover_verify_committed(struct boot_cutover_env *e, const char *dir,
    const struct wallet_cutover_binding *expected)
{ return boot_cutover_verify_committed_mode(e, dir, expected, false); }
bool boot_cutover_verify_committed_stop(struct boot_cutover_env *e, const char *dir,
    const struct wallet_cutover_binding *expected)
{ return boot_cutover_verify_committed_mode(e, dir, expected, true); }

/* Open the runtime handles without entering legacy repair or cleanup paths. */
static bool boot_pending_runtime_stores_open(const char *datadir, struct node_db *ndb,
    struct coins_view_sqlite *coins, struct block_tree_db *tree)
{
    if (!datadir || !datadir[0] || !ndb || !ndb->open || !ndb->db || !coins || !tree ||
        coins->db || tree->db.db)
        return false;
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/blocks/index", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    if (!coins_view_sqlite_open(coins, ndb->db))
        return false;
    if (!block_tree_db_open(tree, path, 256 << 20, false, false)) {
        coins_view_sqlite_close(coins);
        return false;
    }
    return true;
}

#ifdef ZCL_TESTING
bool boot_test_pending_runtime_stores_open(const char *datadir, struct node_db *ndb,
    struct coins_view_sqlite *coins, struct block_tree_db *tree)
{
    return boot_pending_runtime_stores_open(datadir, ndb, coins, tree);
}
#endif

/* Pending wallets retain the installed authority; ordinary repair/import paths
 * must not replace it while wallet history is being reconciled. */
bool boot_bound_memory_bind(struct boot_cutover_env *e)
{
    if (!e || !e->coins_view || !e->coins_tip || !e->state || !e->node ||
        !progress_store_db() || !coins_view_kv_init(e->coins_view)) return false;
    coins_view_cache_init(e->coins_tip, &e->coins_view->view);
    csr_init(csr_instance(), &e->state->map_block_index, &e->state->chain_active,
             &e->state->pindex_best_header, e->coins_tip, e->node, NULL);
    csr_set_db_service(csr_instance(), e->db_service);
    return true;
}

static bool boot_pending_bind_storage(struct boot_cutover_env *e, struct app_context *ctx)
{
    if (!progress_store_db() || !flysync_island_boot_register(ctx->datadir) ||
        !boot_ensure_event_log(ctx->datadir) ||
        !boot_bind_wallet_replay_event_log() || !boot_bound_memory_bind(e))
        return false;
    if (!boot_ensure_block_index_projection(ctx->datadir) ||
        !flysync_island_boot_rehydrate(e->state) ||
        !boot_pending_runtime_stores_open(ctx->datadir, e->node,
                                          e->coins_sqlite, e->block_tree))
        return false;
    *e->block_tree_open = true;
    g_active_block_tree = e->block_tree;
    return true;
}

static bool boot_cutover_load_chain_binding(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip,
    const struct wallet_cutover_binding *expected)
{
    if (!boot_pending_bind_storage(e, ctx)) return false;
    struct zcl_result loaded = boot_try_rebuild_block_index_from_projection(
        e->state, params, 0, false);
    if (!loaded.ok || !flysync_island_boot_materialize(e->state)) return false;
    struct boot_derived_coins_best coins;
    if (!boot_derive_coins_best(&coins) || !coins.hash_found || coins.height < 0)
        return false;
    struct wallet_cutover_binding pending;
    if (!expected) {
        if (wallet_sqlite_cutover_read(e->wallet_db, &pending) != WALLET_CUTOVER_PENDING) return false;
        expected = &pending;
    }
    struct uint256 installed_hash;
    memcpy(installed_hash.data, expected->target_hash, sizeof(installed_hash.data));
    struct uint256 hash;
    memcpy(hash.data, coins.hash, sizeof(hash.data));
    enum boot_pending_restore_result restored = boot_wallet_pending_restore(
        e->state, csr_instance(), coins.height, &hash,
        expected->target_height, &installed_hash);
    if (restored != BOOT_PENDING_RESTORE_OK) {
        LOG_ERROR("wallet", "pending wallet chain restore refused: %d", (int)restored);
        return false;
    }
    *tip = active_chain_tip(&e->state->chain_active);
    if (!e->gate_index(ctx, true)) return false;
    set_sapling_checkpoint_datadir(ctx->datadir);
    if (!sapling_checkpoint_path()) return false;
    set_sapling_tree_for_flush(&e->state->sapling_tree);
    return sysinit_run_stage(BOOT_STAGE_BLOCK_INDEX_LOADED, ctx).ok;
}

bool boot_cutover_load_chain(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip)
{ return boot_cutover_load_chain_binding(e, ctx, params, tip, NULL); }

bool boot_cutover_load_completed_chain(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip, const struct wallet_cutover_binding *binding)
{ return binding && boot_cutover_load_chain_binding(e, ctx, params, tip, binding); }

static bool boot_old_restore_view(struct boot_cutover_env *e,
                                  const struct wallet_cutover_binding *binding)
{
    enum boot_pending_restore_result restored;
    if (binding->old_height == 0) {
        restored = boot_wallet_old_genesis_restore(e->state, csr_instance(), binding);
    } else {
        struct boot_derived_coins_best coins;
        if (!boot_derive_coins_best(&coins) || !coins.hash_found ||
            coins.height != binding->old_height || memcmp(coins.hash, binding->old_hash, 32) != 0)
            return false;
        restored = boot_wallet_old_partial_restore(e->state, csr_instance(), binding);
    }
    if (restored == BOOT_PENDING_RESTORE_OK) return true;
    LOG_ERROR("wallet", "old wallet chain restore refused: %d", (int)restored);
    return false;
}

#ifdef ZCL_TESTING
bool boot_test_old_restore_view(struct main_state *state,
    const struct wallet_cutover_binding *binding)
{
    struct boot_cutover_env env = {.state = state};
    return boot_old_restore_view(&env, binding);
}
#endif

bool boot_cutover_load_old_chain(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding,
    struct block_index **tip)
{
    if (!e || !ctx || !params || !binding || !tip || !boot_pending_bind_storage(e, ctx))
        return false;
    struct zcl_result loaded = boot_try_rebuild_block_index_from_projection(
        e->state, params, 0, false);
    if (!loaded.ok || !flysync_island_boot_materialize(e->state)) return false;
    if (!boot_old_restore_view(e, binding)) return false;
    *tip = active_chain_tip(&e->state->chain_active);
    if (!*tip || (binding->old_height > 0 &&
        !stage_reducer_frontier_restore_script(progress_store_db(), e->state, *tip)))
        return false;
    return e->gate_index(ctx, true) && sysinit_run_stage(BOOT_STAGE_BLOCK_INDEX_LOADED, ctx).ok;
}

/* The archive is app-owned and its files must remain immutable while replay runs. */
#define BOOT_WALLET_HISTORY_MAX_ROWS 3500000u
struct boot_pending_history {
    struct boot_bound_bundle_observation observation;
    bool observation_valid;
    struct wallet_history_capability capability;
    struct main_state *state;
    uintptr_t directory;
    bool directory_open;
    char path[4096];
};

static void boot_pending_history_close(struct boot_pending_history *history)
{
    if (history->state) {
        main_state_free(history->state);
        free(history->state);
    }
    if (history->directory_open) platform_private_directory_close(history->directory);
    wallet_history_capability_release(&history->capability);
}

static bool boot_bound_history_names(struct platform_directory_transaction *root, unsigned *count)
{
    struct platform_directory_transaction blocks;
    struct platform_directory_names names = {0};
    platform_directory_transaction_init(&blocks);
    bool ok = platform_directory_transaction_open_child(root, "blocks", false, &blocks) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_list_regular(&blocks, &names) && names.count > 0 && names.count <= 253;
    for (size_t i = 0; ok && i < names.count; ++i) {
        char expected[16];
        int n = snprintf(expected, sizeof(expected), "blk%05zu.dat", i);
        if (n != 12 || strcmp(expected, names.items[i])) ok = false;
    }
    if (ok) *count = (unsigned)names.count;
    platform_directory_names_free(&names);
    platform_directory_transaction_close(&blocks);
    return ok;
}

static bool boot_bound_history_cancelled(void *context)
{
    (void)context;
    return thread_registry_shutdown_requested();
}

bool boot_bound_observation_equal(const struct boot_bound_bundle_observation *a,
    const struct boot_bound_bundle_observation *b)
{
    return a && b && memchr(a->bundle_path, 0, sizeof(a->bundle_path)) &&
        memchr(a->private_history_path, 0, sizeof(a->private_history_path)) &&
        memchr(b->bundle_path, 0, sizeof(b->bundle_path)) &&
        memchr(b->private_history_path, 0, sizeof(b->private_history_path)) &&
        a->attempts == b->attempts && a->endpoint_height == b->endpoint_height &&
        !strcmp(a->bundle_path, b->bundle_path) && !strcmp(a->private_history_path, b->private_history_path) &&
        !memcmp(a->snapshot_sha3, b->snapshot_sha3, 32) && !memcmp(a->endpoint_hash, b->endpoint_hash, 32) &&
        !memcmp(a->history_manifest_root, b->history_manifest_root, 32);
}
static bool boot_bound_history_location(const struct boot_bound_bundle_observation *obs,
    struct wallet_history_names *names, char parent[BOOT_BOUND_PATH_CAP])
{
    int n = snprintf(parent, BOOT_BOUND_PATH_CAP, "%s", obs->private_history_path);
    if (n < 0 || (size_t)n >= BOOT_BOUND_PATH_CAP ||
        !wallet_history_capability_names(obs->snapshot_sha3, obs->history_manifest_root, names).ok) return false;
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent || strcmp(slash + 1, names->root)) return false;
    *slash = 0;
    return true;
}
static bool boot_bound_history_request(const struct app_context *ctx,
    const struct wallet_cutover_binding *binding, struct boot_bound_bundle_observation *obs,
    struct wallet_history_names *names, char parent[BOOT_BOUND_PATH_CAP])
{
    enum boot_bound_read_result read = boot_install_bound_bundle_read(ctx->datadir, obs);
    if ((read != BOOT_BOUND_READ_READY && read != BOOT_BOUND_READ_TERMINAL) ||
        obs->endpoint_height != binding->target_height ||
        memcmp(obs->endpoint_hash, binding->target_hash, 32) ||
        memcmp(obs->snapshot_sha3, binding->snapshot_whole_sha3, 32) ||
        memcmp(obs->history_manifest_root, binding->history_manifest_root, 32)) return false;
    return boot_bound_history_location(obs, names, parent);
}

static enum boot_pending_replay_result boot_bound_history_acquire(struct wallet_history_capability *cap,
    const struct boot_bound_bundle_observation *obs,
    const struct wallet_history_names *names, const char *parent)
{
    struct platform_directory_transaction p, root;
    struct platform_directory_lock lease;
    platform_directory_transaction_init(&p); platform_directory_transaction_init(&root);
    platform_directory_lock_init(&lease);
    unsigned count = 0;
    bool opened = platform_directory_transaction_open(&p, parent) &&
        platform_directory_lock_acquire(&p, names->lock, false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_open_child(&p, names->root, false, &root) == PLATFORM_DIRECTORY_OK &&
        boot_bound_history_names(&root, &count);
    enum boot_pending_replay_result result = BOOT_PENDING_FAILED;
    if (opened) {
        struct zcl_result acquired = wallet_history_capability_acquire_cancelable(cap,
            &p, &root, &lease, names->root, names->lock, count, obs->history_manifest_root,
            boot_bound_history_cancelled, NULL);
        if (acquired.code == WALLET_HISTORY_CAPABILITY_CANCELLED) result = BOOT_PENDING_STOPPED;
        else if (acquired.ok && wallet_history_capability_matches_path(cap,
                                                                       obs->private_history_path).ok)
            result = BOOT_PENDING_COMPLETE;
    }
    platform_directory_transaction_close(&root); platform_directory_lock_release(&lease);
    platform_directory_transaction_close(&p);
    if (result != BOOT_PENDING_COMPLETE) wallet_history_capability_release(cap);
    return result;
}

#ifdef ZCL_TESTING
static void (*boot_bound_history_after_acquire)(const char *, void *);
static void *boot_bound_history_after_acquire_context;
void boot_bound_history_test_after_acquire(void (*hook)(const char *, void *), void *context)
{
    boot_bound_history_after_acquire = hook;
    boot_bound_history_after_acquire_context = context;
}
#endif
static bool boot_bound_history_capability_empty(const struct wallet_history_capability *cap)
{
    return cap && !cap->verified && cap->parent.native == UINTPTR_MAX && cap->root.native == UINTPTR_MAX &&
        cap->blocks.native == UINTPTR_MAX && cap->lease.native == UINTPTR_MAX;
}
static bool boot_bound_history_read_expected(const char *datadir,
    const struct boot_bound_bundle_observation *expected, bool allow_terminal,
    struct boot_bound_bundle_observation *observed)
{
    enum boot_bound_read_result status = boot_install_bound_bundle_read(datadir, observed);
    return (status == BOOT_BOUND_READ_READY || (allow_terminal && status == BOOT_BOUND_READ_TERMINAL)) &&
        boot_bound_observation_equal(expected, observed);
}
enum boot_pending_replay_result boot_bound_history_acquire_observed(const char *datadir,
    const struct boot_bound_bundle_observation *expected, bool allow_terminal,
    struct wallet_history_capability *cap)
{
    if (!datadir || !datadir[0] || !expected || !boot_bound_history_capability_empty(cap))
        return BOOT_PENDING_FAILED;
    struct boot_bound_bundle_observation wanted = *expected, observed = {0};
    struct wallet_history_names names; char parent[BOOT_BOUND_PATH_CAP];
    if (!boot_bound_history_read_expected(datadir, &wanted, allow_terminal, &observed) ||
        !boot_bound_history_location(&observed, &names, parent)) return BOOT_PENDING_FAILED;
    enum boot_pending_replay_result result = boot_bound_history_acquire(cap, &observed, &names, parent);
    if (result != BOOT_PENDING_COMPLETE) return result;
#ifdef ZCL_TESTING
    if (boot_bound_history_after_acquire) boot_bound_history_after_acquire(datadir, boot_bound_history_after_acquire_context);
#endif
    if (!boot_bound_history_read_expected(datadir, &wanted, allow_terminal, &observed)) {
        wallet_history_capability_release(cap);
        return BOOT_PENDING_FAILED;
    }
    return BOOT_PENDING_COMPLETE;
}
static enum boot_pending_replay_result boot_bound_history_open(struct boot_pending_history *history,
    const struct app_context *ctx, const struct wallet_cutover_binding *binding)
{
    if (!history || !ctx || !ctx->datadir || !binding) return BOOT_PENDING_FAILED;
    struct boot_bound_bundle_observation obs = {0};
    struct wallet_history_names names;
    char parent[BOOT_BOUND_PATH_CAP];
    if (!boot_bound_history_request(ctx, binding, &obs, &names, parent)) return BOOT_PENDING_FAILED;
    enum boot_pending_replay_result result = boot_bound_history_acquire_observed(
        ctx->datadir, &obs, true, &history->capability);
    if (result == BOOT_PENDING_COMPLETE) { history->observation = obs; history->observation_valid = true; }
    return result;
}
#ifdef ZCL_TESTING
enum boot_pending_replay_result boot_test_bound_history_status(const struct app_context *ctx,
    const struct wallet_cutover_binding *binding)
{
    struct boot_pending_history history = {0};
    wallet_history_capability_init(&history.capability);
    enum boot_pending_replay_result status = boot_bound_history_open(&history, ctx, binding);
    boot_pending_history_close(&history);
    return status;
}
#endif

#ifdef ZCL_TESTING
typedef struct zcl_result (*boot_test_history_open_fn)(struct main_state *, const char *,
    size_t, int32_t, const uint8_t[32], struct block_header *);
static boot_test_history_open_fn g_boot_test_history_open;
void boot_test_pending_history_set_open(boot_test_history_open_fn fn)
{
    g_boot_test_history_open = fn;
}
#endif

static struct zcl_result boot_pending_history_load(struct main_state *state, const char *path,
    const struct wallet_witness_endpoint *endpoint)
{
#ifdef ZCL_TESTING
    if (g_boot_test_history_open)
        return g_boot_test_history_open(state, path, BOOT_WALLET_HISTORY_MAX_ROWS,
                                       endpoint->height, endpoint->hash.data, NULL);
#endif
    return block_index_history_archive_open(state, path, BOOT_WALLET_HISTORY_MAX_ROWS,
                                             endpoint->height, endpoint->hash.data, NULL);
}

static bool boot_pending_history_open(struct boot_pending_history *history,
    const struct app_context *ctx, const struct wallet_witness_endpoint *endpoint,
    const struct wallet_cutover_binding *binding)
{
    if (!ctx || !ctx->datadir || !ctx->datadir[0] || !endpoint) return false;
    int n = snprintf(history->path, sizeof(history->path), "%s/wallet-history", ctx->datadir);
    if (binding && binding->history_identity_present) {
        const char *path = wallet_history_capability_path(&history->capability);
        n = path ? snprintf(history->path, sizeof(history->path), "%s", path) : -1;
        if (n <= 0 || (size_t)n >= sizeof(history->path) - sizeof("/blocks/blk00000.dat")) return false;
    } else {
        if (n <= 0 || (size_t)n >= sizeof(history->path) - sizeof("/blocks/blk00000.dat") ||
            !platform_private_directory_open_validated_traverse(history->path, &history->directory)) return false;
        history->directory_open = true;
    }
    history->state = zcl_calloc(1, sizeof(*history->state), "wallet history archive state");
    if (!history->state) return false;
    main_state_init(history->state);
    struct zcl_result loaded = boot_pending_history_load(history->state, history->path, endpoint);
    if (!loaded.ok) LOG_WARN("wallet", "wallet history archive refused: %s", loaded.message);
    return loaded.ok;
}

#ifdef ZCL_TESTING
bool boot_test_pending_history_open(const struct app_context *ctx,
    const struct wallet_witness_endpoint *endpoint)
{
    struct boot_pending_history history = {0};
    wallet_history_capability_init(&history.capability);
    bool ok = boot_pending_history_open(&history, ctx, endpoint, NULL);
    boot_pending_history_close(&history);
    return ok;
}
#endif

/* Runs before network, reducer and wallet services can mutate the reference. */
static enum boot_pending_replay_result boot_pending_replay_prepare(struct boot_cutover_env *e, struct app_context *ctx,
    struct boot_cutover_replay *replay, struct wallet_rpc_context *rpc,
    struct boot_pending_history *history)
{
    struct block_index *tip = active_chain_tip(&e->state->chain_active);
    struct wallet_cutover_binding binding;
    uint8_t identity[32];
    int floor = -1;
    if (!tip || !tip->phashBlock ||
        wallet_sqlite_cutover_read(e->wallet_db, &binding) != WALLET_CUTOVER_PENDING ||
        wallet_sqlite_cutover_scan_floor(e->wallet_db, &floor) != WALLET_CUTOVER_FLOOR_FOUND ||
        !wallet_scan_identity(e->wallet, identity)) return BOOT_PENDING_FAILED;
    if (binding.history_identity_present) {
        enum boot_pending_replay_result status = boot_bound_history_open(history, ctx, &binding);
        if (status != BOOT_PENDING_COMPLETE) return status;
    }
    *rpc = (struct wallet_rpc_context){.wallet = e->wallet, .wallet_db = e->wallet_db,
        .node_db = e->node, .main_state = e->state, .datadir = ctx->datadir,
        .coins_tip = e->coins_tip};
    struct wallet_witness_endpoint endpoint = {
        .height = tip->nHeight, .hash = *tip->phashBlock, .root = tip->hashFinalSaplingRoot};
    bool ready;
    if (active_chain_at(&e->state->chain_active, floor))
        ready = boot_cutover_replay_init(replay, rpc, e->db_service, &binding, floor, &endpoint, identity);
    else {
        ready = boot_cutover_replay_init(replay, rpc, e->db_service, &binding, floor, &endpoint, identity);
        if (ready) {
            replay->sapling_load_ok = e->sapling_load_ok;
            ready = boot_cutover_replay_complete_full_empty(replay);
            if (!ready) boot_cutover_replay_clear(replay);
        }
        if (!ready) {
            if (!boot_pending_history_open(history, ctx, &endpoint, &binding)) return BOOT_PENDING_FAILED;
            rpc->main_state = history->state;
            ready = boot_cutover_replay_init_archive(replay, rpc, e->db_service, &binding,
                floor, &endpoint, identity, e->state, history->path);
        }
    }
    if (ready) replay->sapling_load_ok = e->sapling_load_ok;
    return ready ? BOOT_PENDING_COMPLETE : BOOT_PENDING_FAILED;
}

#ifdef ZCL_TESTING
bool boot_test_pending_replay_prepare(struct boot_cutover_env *env, struct app_context *ctx,
    struct boot_cutover_replay *replay, struct wallet_rpc_context *rpc, void **owned_history)
{
    struct boot_pending_history *history = zcl_calloc(1, sizeof(*history), "pending history test");
    if (!history) return false;
    wallet_history_capability_init(&history->capability);
    bool ok = boot_pending_replay_prepare(env, ctx, replay, rpc, history) == BOOT_PENDING_COMPLETE;
    if (!ok) { boot_pending_history_close(history); free(history); return false; }
    *owned_history = history;
    return true;
}
void boot_test_pending_replay_close(void *owned_history)
{
    struct boot_pending_history *history = owned_history;
    if (history) { boot_pending_history_close(history); free(history); }
}
#endif

static bool boot_pending_publish(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, struct boot_cutover_replay *replay)
{
    struct wpr *relay = wpr_global();
    if (!ctx->datadir || !ctx->datadir[0] ||
        strlen(ctx->datadir) >= sizeof(relay->datadir) ||
        wallet_readiness_get(e->wallet).state != WALLET_READINESS_PENDING)
        return false;
    struct boot_svc_ctx svc;
    e->build_svc(ctx, &svc);
    svc.runtime.db_service = e->db_service;
    if (!e->node || boot_node_db(&svc) != e->node) return false;
    if (!boot_start_wallet_broadcast(&svc, ctx, params)) return false;
    struct db_wallet_utxo_cutover_delivery delivery = {0};
    bool published = boot_wallet_cutover_publish_guarded(replay, relay, &delivery);
    bool delivered = published && (!delivery.armed || db_wallet_utxo_cutover_delivery_flush(&delivery));
    db_wallet_utxo_cutover_delivery_clear(&delivery);
    if (!published) LOG_ERROR("wallet", "wallet publication refused; recovery remains pending");
    else if (!delivered) LOG_ERROR("wallet", "wallet committed; public view delivery failed, restart to recover");
    return published && delivered;
}

#ifdef ZCL_TESTING
bool boot_test_pending_publish(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, struct boot_cutover_replay *replay)
{
    return boot_pending_publish(e, ctx, params, replay);
}
#endif

/* The descriptor is a one-shot capability, never wallet authority itself. */
static bool boot_pending_authenticate(struct boot_cutover_env *e, struct app_context *ctx,
                                      bool *unlocked, int64_t *deadline)
{
    *unlocked = false;
    *deadline = 0;
    bool needed = wallet_lock_encrypted_at_rest() && wallet_lock_is_locked();
    if (!needed) {
        if (ctx->wallet_startup_auth_present) {
            platform_wallet_startup_auth_close(ctx->wallet_startup_auth_fd);
            ctx->wallet_startup_auth_present = false;
        }
        return e->sapling_load_ok && wallet_sqlite_verify_startup_sapling_r(e->wallet_db, e->wallet).ok;
    }
    if (!ctx->wallet_startup_auth_present || thread_registry_shutdown_requested()) return false;
    int fd = ctx->wallet_startup_auth_fd;
    ctx->wallet_startup_auth_present = false;
    char secret[Z23_WALLET_AUTH_SECRET_MAX + 1] = {0};
    bool received = platform_wallet_startup_auth_receive(fd, 120000, secret, sizeof(secret));
    struct zcl_result result = received ? wallet_lock_unlock(e->wallet, e->wallet_db, secret)
                                        : ZCL_ERR(-1, "startup authentication unavailable");
    memory_cleanse(secret, sizeof(secret));
    if (!result.ok) return false;
    *unlocked = true;
    if (!e->sapling_load_ok) return false;
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || now > INT64_MAX - 3600000 || thread_registry_shutdown_requested()) return false;
    result = wallet_lock_arm_timeout(e->wallet, 3600);
    if (!result.ok) return false;
    *deadline = now + 3600000;
    if (!wallet_lock_startup_publication_begin(*deadline)) return false;
    result = wallet_sqlite_verify_startup_sapling_r(e->wallet_db, e->wallet);
    wallet_lock_startup_publication_end();
    return result.ok;
}


#ifdef ZCL_TESTING
bool boot_test_pending_authenticate(struct wallet *wallet, struct wallet_sqlite *ws, int fd,
                                    bool *unlocked, int64_t *deadline)
{
    struct boot_cutover_env env = {.wallet = wallet, .wallet_db = ws, .sapling_load_ok = true};
    struct app_context ctx = {.wallet_startup_auth_present = true, .wallet_startup_auth_fd = fd};
    return boot_pending_authenticate(&env, &ctx, unlocked, deadline);
}
#endif

/* Only repeated contention is retried; shutdown, lock and elapsed bounds win. */
static enum boot_busy_result boot_pending_busy_at(int64_t *since, int64_t deadline,
    int limit_ms, int64_t now, bool locked, bool shutdown)
{
    if (now <= 0 || (deadline && (now >= deadline || locked)))
        return BOOT_BUSY_FAILED;
    if (!*since) *since = now;
    if (now < *since || now - *since >= limit_ms) return BOOT_BUSY_FAILED;
    if (shutdown) return BOOT_BUSY_STOPPED;
    return BOOT_BUSY_RETRY;
}

static enum boot_busy_result boot_pending_busy_result(int64_t *since, int64_t deadline, int limit_ms)
{
    enum boot_busy_result result = boot_pending_busy_at(since, deadline, limit_ms,
        platform_time_monotonic_ms(), deadline && wallet_lock_is_locked(),
        thread_registry_shutdown_requested());
    if (result == BOOT_BUSY_RETRY) platform_sleep_ms(50);
    return result;
}

#ifdef ZCL_TESTING
static bool boot_pending_busy_backoff(int64_t *since, int64_t deadline, int limit_ms)
{
    return boot_pending_busy_result(since, deadline, limit_ms) == BOOT_BUSY_RETRY;
}
int boot_test_pending_busy_at(int64_t *since, int64_t deadline, int limit_ms,
    int64_t now, bool locked, bool shutdown)
{ return (int)boot_pending_busy_at(since, deadline, limit_ms, now, locked, shutdown); }
bool boot_test_pending_busy_backoff(int64_t *since, int64_t deadline, int limit_ms)
{
    return boot_pending_busy_backoff(since, deadline, limit_ms);
}
#endif

static bool boot_replay_progress_format(const struct boot_cutover_replay *r,
                                        char *out, size_t cap)
{
    static const char *const names[] = {"transparent", "discover", "witness", "spends"};
    if (!r || !out || !cap || (unsigned)r->phase > BOOT_CUTOVER_SPENDS || r->floor < 0 ||
        r->endpoint.height < r->floor || r->next < r->floor ||
        (int64_t)r->next > (int64_t)r->endpoint.height + 1) return false;
    int n = snprintf(out, cap, "[wallet-replay] phase=%s floor=%d next=%d reference=%d",
                     names[r->phase], r->floor, r->next, r->endpoint.height);
    return n > 0 && (size_t)n < cap;
}
#ifdef ZCL_TESTING
bool boot_test_replay_progress_format(const struct boot_cutover_replay *r, char *out, size_t cap)
{ return boot_replay_progress_format(r, out, cap); }
#endif

static void boot_replay_progress_emit(const struct boot_cutover_replay *r,
                                      int *last_phase, int64_t *last_ms)
{
    int64_t now = platform_time_monotonic_ms();
    if (*last_phase == (int)r->phase && (now <= 0 || now < *last_ms || now - *last_ms < 1000)) return;
    char line[160];
    if (!boot_replay_progress_format(r, line, sizeof(line))) return;
    fprintf(stderr, "%s\n", line);
    fflush(stderr);
    *last_phase = (int)r->phase;
    *last_ms = now;
}

static bool boot_replay_stopped(enum boot_cutover_replay_status status,
                                const struct boot_cutover_replay *replay,
                                int *last_phase, int64_t *last_ms)
{
    if (status == BOOT_CUTOVER_PROGRESS) {
        boot_replay_progress_emit(replay, last_phase, last_ms);
        return false;
    }
    LOG_WARN("wallet", "pending replay stopped: status=%d phase=%d next=%d reference=%d",
             (int)status, (int)replay->phase, replay->next, replay->endpoint.height);
    return true;
}

static bool boot_pending_checkpoint_due(int64_t last, int64_t now)
{
    return now > 0 && (last == 0 || (now >= last && now - last >= 30000));
}
#ifdef ZCL_TESTING
bool boot_test_pending_checkpoint_due(int64_t last, int64_t now)
{ return boot_pending_checkpoint_due(last, now); }
#endif
static enum boot_pending_replay_result boot_pending_checkpoint_resume(struct boot_cutover_replay *r)
{
    int64_t since = 0;
    for (;;) {
        enum boot_discover_resume result = boot_wallet_discover_checkpoint_resume(r);
        if (result == BOOT_DISCOVER_FLOOR || result == BOOT_DISCOVER_RESUMED) return BOOT_PENDING_COMPLETE;
        if (result == BOOT_DISCOVER_STOPPED) return BOOT_PENDING_STOPPED;
        if (result != BOOT_DISCOVER_BUSY) return BOOT_PENDING_FAILED;
        enum boot_busy_result busy = boot_pending_busy_result(&since, r->auth_deadline_ms, 30000);
        if (busy == BOOT_BUSY_STOPPED) return BOOT_PENDING_STOPPED;
        if (busy != BOOT_BUSY_RETRY) return BOOT_PENDING_FAILED;
    }
}
static enum boot_pending_replay_result boot_pending_checkpoint_save(struct boot_cutover_replay *r)
{
    struct wallet_discover_checkpoint checkpoint;
    enum boot_discover_prepare prepared = boot_wallet_discover_checkpoint_prepare_result(r, &checkpoint);
    if (prepared == BOOT_DISCOVER_PREPARE_STOPPED) return BOOT_PENDING_STOPPED;
    if (prepared != BOOT_DISCOVER_PREPARED) return BOOT_PENDING_FAILED;
    int64_t since = 0;
    for (;;) {
        enum boot_discover_save result = boot_wallet_discover_checkpoint_save(r, &checkpoint);
        if (result == BOOT_DISCOVER_SAVED) return BOOT_PENDING_COMPLETE;
        if (result == BOOT_DISCOVER_SAVE_STOPPED) return BOOT_PENDING_STOPPED;
        if (result != BOOT_DISCOVER_SAVE_BUSY) return BOOT_PENDING_FAILED;
        enum boot_busy_result busy = boot_pending_busy_result(&since, r->auth_deadline_ms, 30000);
        if (busy == BOOT_BUSY_STOPPED) return BOOT_PENDING_STOPPED;
        if (busy != BOOT_BUSY_RETRY) return BOOT_PENDING_FAILED;
    }
}

static enum boot_pending_replay_result boot_pending_checkpoint_progress(struct boot_cutover_replay *replay,
    enum boot_cutover_replay_status status, enum boot_cutover_replay_phase before_phase,
    int before, int64_t *last_checkpoint_ms)
{
    if (status == BOOT_CUTOVER_PROGRESS && before_phase == BOOT_CUTOVER_TRANSPARENT &&
        replay->phase == BOOT_CUTOVER_DISCOVER)
        return boot_pending_checkpoint_resume(replay);
    if (status != BOOT_CUTOVER_PROGRESS || before_phase != BOOT_CUTOVER_DISCOVER ||
        replay->phase != BOOT_CUTOVER_DISCOVER || replay->next <= before) return BOOT_PENDING_COMPLETE;
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || (*last_checkpoint_ms && now < *last_checkpoint_ms)) return BOOT_PENDING_FAILED;
    if (!boot_pending_checkpoint_due(*last_checkpoint_ms, now)) return BOOT_PENDING_COMPLETE;
    enum boot_pending_replay_result result = boot_pending_checkpoint_save(replay);
    if (result != BOOT_PENDING_COMPLETE) return result;
    *last_checkpoint_ms = platform_time_monotonic_ms();
    return *last_checkpoint_ms > 0 ? BOOT_PENDING_COMPLETE : BOOT_PENDING_FAILED;
}

static enum boot_busy_result boot_replay_busy(struct boot_cutover_replay *replay, int before,
                             int64_t *since, int64_t deadline)
{
    if (replay->next != before) *since = 0;
    return boot_pending_busy_result(since, deadline, 30000);
}

static bool boot_replay_busy_retry(struct boot_cutover_replay *replay, int before,
    int64_t *since, int64_t deadline, enum boot_pending_replay_result *result)
{
    enum boot_busy_result busy = boot_replay_busy(replay, before, since, deadline);
    if (busy == BOOT_BUSY_STOPPED) *result = BOOT_PENDING_STOPPED;
    return busy == BOOT_BUSY_RETRY;
}

#ifdef ZCL_TESTING
static void (*boot_test_pending_after_step)(void);
void boot_test_pending_step_hook(void (*hook)(void)) { boot_test_pending_after_step = hook; }
static void (*boot_test_pending_detail)(enum boot_cutover_replay_phase, enum boot_cutover_replay_status);
void boot_test_pending_detail_hook(void (*hook)(enum boot_cutover_replay_phase, enum boot_cutover_replay_status))
{ boot_test_pending_detail = hook; }
#endif

static bool boot_pending_deadline_valid(int64_t deadline)
{
    if (!deadline) return true;
    int64_t now = platform_time_monotonic_ms();
    return now > 0 && now < deadline && !wallet_lock_is_locked();
}

static enum boot_pending_replay_result boot_pending_replay_loop(struct boot_cutover_env *e,
    struct app_context *ctx, const struct chain_params *params, struct boot_cutover_replay *replay,
    int64_t deadline)
{
    enum boot_pending_replay_result result = BOOT_PENDING_FAILED;
    int64_t busy_since = 0, last_progress_ms = 0, last_checkpoint_ms = 0;
    int last_progress_phase = -1;
    for (;;) {
        if (!boot_pending_deadline_valid(deadline)) break;
        if (thread_registry_shutdown_requested()) {
            result = BOOT_PENDING_STOPPED;
            break;
        }
        int before = replay->next;
        enum boot_cutover_replay_phase before_phase = replay->phase;
        enum boot_cutover_replay_status status = boot_cutover_replay_step(replay);
#ifdef ZCL_TESTING
        if (boot_test_pending_after_step) boot_test_pending_after_step();
        if (boot_test_pending_detail) boot_test_pending_detail(before_phase, status);
#endif
        if (status == BOOT_CUTOVER_BUSY) {
            if (!boot_replay_busy_retry(replay, before, &busy_since, deadline, &result)) break;
            continue;
        }
        if (status == BOOT_CUTOVER_STOPPED) {
            if (boot_pending_deadline_valid(deadline))
                result = BOOT_PENDING_STOPPED;
            break;
        }
        busy_since = 0;
        if (status == BOOT_CUTOVER_COMPLETE) {
            if (boot_pending_publish(e, ctx, params, replay)) result = BOOT_PENDING_COMPLETE;
            break;
        }
        enum boot_pending_replay_result checkpoint =
            boot_pending_checkpoint_progress(replay, status, before_phase, before, &last_checkpoint_ms);
        if (checkpoint != BOOT_PENDING_COMPLETE) { result = checkpoint; break; }
        if (boot_replay_stopped(status, replay, &last_progress_phase, &last_progress_ms)) break;
    }
    return result;
}
#ifdef ZCL_TESTING
enum boot_pending_replay_result boot_test_pending_loop(struct boot_cutover_replay *replay)
{ return boot_pending_replay_loop(NULL, NULL, NULL, replay, 0); }
#endif

static enum boot_pending_replay_result boot_cutover_replay_observed(struct boot_cutover_env *e, struct app_context *ctx, const struct chain_params *params, struct boot_bound_bundle_observation *observation)
{
    struct boot_cutover_replay replay = {0};
    struct wallet_rpc_context rpc;
    struct boot_pending_history history = {0};
    wallet_history_capability_init(&history.capability);
    enum boot_pending_replay_result result = BOOT_PENDING_FAILED;
    bool unlocked = false;
    int64_t deadline = 0;
    if (!boot_pending_authenticate(e, ctx, &unlocked, &deadline)) goto done;
    result = boot_pending_replay_prepare(e, ctx, &replay, &rpc, &history);
    if (result != BOOT_PENDING_COMPLETE) {
        if (result == BOOT_PENDING_FAILED) LOG_ERROR("wallet", "pending replay reference or scan floor unavailable");
        goto done;
    }
    replay.auth_deadline_ms = deadline;
    result = boot_pending_replay_loop(e, ctx, params, &replay, deadline);
    if (result == BOOT_PENDING_COMPLETE && observation && history.observation_valid)
        *observation = history.observation;
done:
    if (unlocked) wallet_lock_lock(e->wallet);
    boot_cutover_replay_clear(&replay);
    boot_pending_history_close(&history);
    return result;
}

enum boot_pending_replay_result boot_cutover_replay(struct boot_cutover_env *e, struct app_context *ctx, const struct chain_params *params)
{ return boot_cutover_replay_observed(e, ctx, params, NULL); }

enum boot_pending_replay_result boot_cutover_replay_and_retire(struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params, const struct wallet_cutover_binding *binding)
{
    if (!env || !ctx || !binding) return BOOT_PENDING_FAILED;
    struct boot_bound_bundle_observation observation = {0};
    enum boot_pending_replay_result result = boot_cutover_replay_observed(env, ctx, params, &observation);
    if (result != BOOT_PENDING_COMPLETE || !binding->history_identity_present) return result;
#if defined(_WIN32)
    return BOOT_PENDING_FAILED;
#else
    uintptr_t directory = 0;
    if (!platform_private_directory_open_validated_traverse(ctx->datadir, &directory)) {
        LOG_ERROR("wallet", "bound completion datadir unavailable");
        return BOOT_PENDING_FAILED;
    }
    enum boot_bound_completion_result retired = boot_bound_completed_retire(env->wallet_db,
        env->node, env->wallet, env->state, ctx->datadir, (int)directory, binding, &observation);
    platform_private_directory_close(directory);
    if (retired != BOOT_BOUND_COMPLETION_RETIRED) {
        LOG_ERROR("wallet", "bound completion request retirement refused: %d", (int)retired);
        return BOOT_PENDING_FAILED;
    }
    return BOOT_PENDING_COMPLETE;
#endif
}

static bool boot_cutover_retry_bound(struct boot_cutover_env *env, struct app_context *ctx,
                                     const struct wallet_cutover_binding *binding)
{
    struct boot_pending_history history = {0};
    wallet_history_capability_init(&history.capability);
    enum boot_pending_replay_result opened = boot_bound_history_open(&history, ctx, binding);
    struct boot_bound_bundle_observation obs = {0};
    struct wallet_history_names names;
    char parent[BOOT_BOUND_PATH_CAP];
    bool valid = opened == BOOT_PENDING_COMPLETE &&
        boot_bound_history_request(ctx, binding, &obs, &names, parent);
    struct consensus_state_install_runtime_result result = {0};
    struct zcl_result installed = valid ? consensus_state_install_from_bound_bundle_terminal_old_retry(
        env->node, env->state, ctx->datadir, env->wallet_db, env->wallet, &obs,
        &history.capability, binding, &result) : ZCL_ERR(-1, "bound old cutover history unavailable");
    boot_pending_history_close(&history);
    if (!installed.ok || !result.state_installed) {
        LOG_ERROR("wallet", "bound old wallet cutover retry refused: %s", installed.message);
        return false;
    }
    if (!boot_cutover_verify_committed(env, ctx->datadir, binding)) {
        LOG_ERROR("wallet", "bound old wallet cutover committed but recovery verification failed");
        return false;
    }
    return true;
}

bool boot_cutover_retry_old(struct boot_cutover_env *env, struct app_context *ctx,
                            const struct chain_params *params,
                            const struct wallet_cutover_binding *binding)
{
    struct block_index *tip = NULL;
    if (!boot_cutover_mode_supported(ctx) ||
        !wallet_readiness_initialize(env->wallet, WALLET_READINESS_PENDING,
                                     binding->old_generation_present, binding->old_generation))
        return false;
    if (binding->history_identity_present && binding->old_height > 0)
        return boot_bound_old_cold_retry(env, ctx, params, binding);
    if (!boot_cutover_load_old_chain(env, ctx, params, binding, &tip)) return false;
    if (binding->history_identity_present) return boot_cutover_retry_bound(env, ctx, binding);
    char *bundle = consensus_state_find_old_retry_bundle(ctx->datadir, binding);
    if (!bundle) {
        LOG_ERROR("wallet", "old wallet cutover artifact unavailable");
        return false;
    }
    struct consensus_state_install_runtime_result result;
    struct zcl_result installed = binding->old_height == 0 ?
        consensus_state_install_from_bundle_old_retry(
            env->node, env->state, bundle, ctx->datadir, env->wallet_db, env->wallet, binding, &result) :
        consensus_state_install_from_bundle_terminal_old_retry(
            env->node, env->state, bundle, ctx->datadir, env->wallet_db, env->wallet, binding, &result);
    free(bundle);
    if (!installed.ok || !result.state_installed) {
        LOG_ERROR("wallet", "old wallet cutover retry refused: %s", installed.message);
        return false;
    }
    if (!boot_cutover_verify_committed(env, ctx->datadir, binding)) {
        LOG_ERROR("wallet", "old wallet cutover committed but recovery verification failed");
        return false;
    }
    return true;
}

static bool boot_pending_maintenance_requested(const struct app_context *ctx)
{
    return ctx->refold_staged || ctx->refold_from_anchor || ctx->verify_rom ||
        ctx->export_consensus_bundle || ctx->verify_consensus_bundle ||
        ctx->promote_shielded_history || ctx->reimport_utxos;
}

bool boot_cutover_mode_supported(const struct app_context *ctx)
{
    return !ctx->mint_anchor && !ctx->full_fold && !ctx->reindex_chainstate &&
        !ctx->snapshot_dir && !ctx->ratify_mint_anchor && !ctx->reindex_explorer &&
        !ctx->backfill_zslp && !ctx->backfill_nullifiers && !boot_pending_maintenance_requested(ctx);
}

#ifdef ZCL_TESTING
bool boot_pending_mode_supported_test(const struct app_context *ctx)
{
    return ctx && boot_cutover_mode_supported(ctx);
}
#endif


bool boot_cutover_publish_readiness(struct boot_cutover_env *e, struct app_context *ctx)
{
    if (ctx->wallet_startup_auth_present) {
        platform_wallet_startup_auth_close(ctx->wallet_startup_auth_fd);
        ctx->wallet_startup_auth_present = false;
    }
    struct wallet_cutover_binding completed;
    enum wallet_cutover_observation_status observed = wallet_sqlite_cutover_observe_completed(e->wallet_db, &completed);
    if (observed == WALLET_CUTOVER_OBS_FOUND) return true;
    if (observed != WALLET_CUTOVER_OBS_ABSENT) {
        LOG_ERROR("wallet", "wallet completion authority unavailable");
        return false;
    }
    struct wallet_cutover_binding boot_binding;
    if (wallet_sqlite_cutover_read(e->wallet_db, &boot_binding) != WALLET_CUTOVER_ABSENT) {
        LOG_ERROR("wallet", "wallet cutover needs reconciliation before services");
        return false;
    }
#if !defined(_WIN32)
    int wallet_dir_fd = open(ctx->datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool generation_present = false;
    uint64_t generation = 0;
    enum wallet_install_reconcile wallet_install =
        consensus_state_wallet_install_classify(e->wallet_db, e->node,
            wallet_dir_fd, &generation_present, &generation);
    if (wallet_dir_fd >= 0) close(wallet_dir_fd);
    if (wallet_install == WALLET_INSTALL_ABSENT) {
        if (!wallet_readiness_initialize(e->wallet, WALLET_READINESS_READY,
                                         generation_present, generation)) return false;
    } else {
        LOG_WARN("wallet", "wallet readiness unknown; amounts and spending remain unavailable");
    }
#else
    sqlite3 *wallet_progress = progress_store_db();
    uint8_t generation_bytes[8] = {0}; size_t generation_len = 0;
    bool generation_present = false;
    progress_store_tx_lock();
    bool generation_ok = wallet_progress && progress_meta_get_blob_exact(
        wallet_progress, COINS_KV_AUTHORITY_GENERATION_KEY, generation_bytes,
        sizeof(generation_bytes), &generation_len, &generation_present) &&
        (!generation_present || generation_len == sizeof(generation_bytes));
    progress_store_tx_unlock();
    if (generation_ok) {
        if (!wallet_readiness_initialize(e->wallet, WALLET_READINESS_READY,
              generation_present, generation_present ? zcl_read_u64_le(generation_bytes) : 0))
            return false;
    } else {
        LOG_WARN("wallet", "wallet readiness unknown; amounts and spending remain unavailable");
    }
#endif
    return true;
}

bool boot_cutover_publish_completed(struct boot_cutover_env *e, struct app_context *ctx, bool required)
{
    if (ctx->wallet_startup_auth_present) {
        platform_wallet_startup_auth_close(ctx->wallet_startup_auth_fd);
        ctx->wallet_startup_auth_present = false;
    }
    struct wallet_cutover_binding completed;
    enum wallet_cutover_observation_status observed = wallet_sqlite_cutover_observe_completed(e->wallet_db, &completed);
    if (observed == WALLET_CUTOVER_OBS_ABSENT && !required) return true;
    if (observed != WALLET_CUTOVER_OBS_FOUND) {
        LOG_ERROR("wallet", "completed wallet observation refused: %d", (int)observed);
        return false;
    }
#if defined(_WIN32)
    (void)ctx;
    return false;
#else
    struct boot_bound_bundle_observation request = {0};
    enum boot_bound_read_result request_status = boot_install_bound_bundle_read(ctx->datadir, &request);
    if (request_status != BOOT_BOUND_READ_ABSENT) {
        LOG_ERROR("wallet", "completed wallet request state refused: %d", (int)request_status);
        return false;
    }
#ifdef ZCL_TESTING
    boot_test_run_completed_before_proof(e, ctx);
#endif
    int fd = open(ctx->datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool present = false; uint64_t generation = 0;
    enum boot_bound_completion_result proof = fd < 0 ? BOOT_BOUND_COMPLETION_ERROR :
        boot_bound_completed_prove(e->wallet_db, e->node, e->wallet, e->state,
                                   ctx->datadir, fd, &present, &generation);
    if (fd >= 0 && close(fd) != 0) return false;
    if (proof != BOOT_BOUND_COMPLETION_PROVEN) {
        LOG_ERROR("wallet", "completed wallet proof refused: %d", (int)proof);
        return false;
    }
    return wallet_readiness_initialize(e->wallet, WALLET_READINESS_READY, present, generation);
#endif
}

bool consensus_state_wallet_preflight_identity(struct wallet_sqlite *wallet,
    struct node_db *node, int dir_fd)
{
#if defined(_WIN32)
    (void)wallet; (void)node; (void)dir_fd; return false;
#else
    return wallet && wallet->open && wallet->db && node && node->open &&
        wallet->db == node->db && boot_wallet_cutover_recovery_context_matches(node, wallet) &&
        boot_datadir_lock_matches_fd(dir_fd) && consensus_state_wallet_node_file_matches(wallet->db, dir_fd);
#endif
}

#if !defined(_WIN32)
struct boot_old_height_entry { struct uint256 hash; int height; };
/* Only journal modes with a persistent rollback log can make a FULL commit
 * a durable fence. OFF, MEMORY and unknown modes fail closed. */
bool boot_cutover_journal_durable(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    if (!db || sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    bool ok = false;
    enum zcl_step step = ar_step_checked(s, "wallet journal mode", NULL);
    if (step == ZCL_STEP_ROW && sqlite3_column_type(s, 0) == SQLITE_TEXT) {
        const char *mode = (const char *)sqlite3_column_text(s, 0);
        ok = mode && (!strcmp(mode, "wal") || !strcmp(mode, "delete") ||
                      !strcmp(mode, "truncate") || !strcmp(mode, "persist"));
        step = ar_step_checked(s, "wallet journal mode completion", NULL);
        if (step != ZCL_STEP_DONE) ok = false;
    }
    if (sqlite3_finalize(s) != SQLITE_OK) return false;
    return ok;
}
bool boot_cutover_set_sync(struct node_db *node, int level)
{
    char sql[32];
    if (!node || !node->db || level < 0 || level > 3) return false;
    int n = snprintf(sql, sizeof(sql), "PRAGMA synchronous=%d", level);
    return n > 0 && (size_t)n < sizeof(sql) &&
           sqlite3_exec(node->db, sql, NULL, NULL, NULL) == SQLITE_OK &&
           db_wallet_send_once_sync_level(node) == level;
}
bool boot_cutover_raise_sync(struct node_db *node, int previous)
{
    if (previous >= 0 && boot_cutover_set_sync(node, previous >= 2 ? previous : 2)) return true;
    if (previous >= 0 && !boot_cutover_set_sync(node, previous))
        LOG_ERROR("install_consensus_bundle", "wallet sync-mode restoration failed");
    return false;
}
static int boot_old_height_compare(const void *a, const void *b)
{
    return memcmp(((const struct boot_old_height_entry *)a)->hash.data,
                  ((const struct boot_old_height_entry *)b)->hash.data, 32);
}
static size_t boot_old_height_mark(struct boot_old_height_map *map, const struct block_index *p)
{
    struct boot_old_height_entry key = {.hash = *p->phashBlock};
    struct boot_old_height_entry *found = bsearch(&key, map->entries, map->count,
                                                  sizeof(*map->entries), boot_old_height_compare);
    if (!found) return 0;
    size_t i = (size_t)(found - map->entries), marked = 0;
    while (i && !boot_old_height_compare(&map->entries[i - 1], &key)) --i;
    while (i < map->count && !boot_old_height_compare(&map->entries[i], &key)) {
        if (map->entries[i].height < 0) { map->entries[i].height = p->nHeight; ++marked; }
        ++i;
    }
    return marked;
}
static bool boot_old_height_block_valid(struct boot_old_height_map *map, struct block_index *p)
{
    return p->phashBlock && p->nHeight >= 0 && block_index_is_valid(p, BLOCK_VALID_TREE) &&
        !block_is_revalidation_pending(p) &&
        !memcmp(p->phashBlock->data, p->hashBlock.data, 32) &&
        active_chain_at(&map->main->chain_active, p->nHeight) == p;
}

static bool boot_old_height_walk(struct boot_old_height_map *map, struct block_index *p)
{
    size_t remaining = map->count;
    bool reference = false;
    while (p && (remaining || !reference)) {
        if (!boot_old_height_block_valid(map, p)) return false;
        if (p->nHeight == map->reference_height) {
            memcpy(map->reference_hash, p->phashBlock->data, 32); reference = true;
        }
        remaining -= boot_old_height_mark(map, p);
        if (p->nHeight > 0 && (!p->pprev || p->pprev->nHeight != p->nHeight - 1 ||
            active_chain_at(&map->main->chain_active, p->nHeight - 1) != p->pprev)) return false;
        p = p->pprev;
    }
    return !remaining && reference;
}
bool boot_old_height_allocate(struct boot_old_height_map *map)
{
    if (!map || map->entries) return false;
    map->entries = zcl_calloc(MAX_WALLET_TX, sizeof(*map->entries), "old wallet height map");
    return map->entries != NULL;
}
static void boot_old_height_collect(struct boot_old_height_map *map, const struct wallet *wallet)
{
    const uint8_t zero[32] = {0};
    for (size_t i = 0; i < MAX_WALLET_TX; ++i) {
        if (wallet->map_wallet[i].used && memcmp(wallet->map_wallet[i].hash_block.data, zero, 32)) {
            map->entries[map->count].hash = wallet->map_wallet[i].hash_block;
            map->entries[map->count++].height = -1;
        }
    }
}

bool boot_old_height_prepare_locked(struct boot_old_height_map *map,
    struct main_state *main, const struct wallet *wallet, const struct wallet_cutover_binding *binding)
{
    if (!map) return false;
    map->ready = false;
    if (!map->entries || !main || !wallet || !binding || wallet->best_block_height < 0) return false;
    map->count = 0; map->main = main;
    map->reference_height = wallet->best_block_height;
    boot_old_height_collect(map, wallet);
    qsort(map->entries, map->count, sizeof(*map->entries), boot_old_height_compare);
    if (!zcl_mutex_trylock(&main->chain_active.write_lock)) return false;
    map->tip = active_chain_cached_tip(&main->chain_active);
    bool ok = map->tip && binding->old_height >= map->reference_height &&
        binding->old_height <= map->tip->nHeight;
    if (ok) map->frontier = active_chain_at(&main->chain_active, binding->old_height);
    ok = ok && map->frontier && map->frontier->phashBlock &&
        !memcmp(map->frontier->phashBlock->data, binding->old_hash, 32) &&
        boot_old_height_walk(map, map->frontier);
    zcl_mutex_unlock(&main->chain_active.write_lock);
    map->ready = ok;
    return ok;
}
bool boot_old_height_resolve(void *opaque, const unsigned char hash[32], int *height)
{
    struct boot_old_height_map *map = opaque;
    if (!map || !map->ready || !hash || !height) return false;
    if (!memcmp(hash, map->reference_hash, 32)) { *height = map->reference_height; return true; }
    struct boot_old_height_entry key = {0}; memcpy(key.hash.data, hash, 32);
    const struct boot_old_height_entry *found = bsearch(&key, map->entries, map->count,
                                                         sizeof(*map->entries), boot_old_height_compare);
    if (!found || found->height < 0) return false;
    *height = found->height; return true;
}
bool boot_old_height_reference(void *opaque, int height, const unsigned char hash[32])
{
    struct boot_old_height_map *map = opaque;
    return map && map->ready && hash &&
        height == map->reference_height && !memcmp(hash, map->reference_hash, 32);
}
void boot_old_height_free(struct boot_old_height_map *map)
{
    if (!map) return;
    free(map->entries); memset(map, 0, sizeof(*map));
}
static bool boot_bound_wallet_commit_locked(struct node_db *node, struct main_state *main,
    struct wallet_sqlite *ws, struct wallet *wallet,
    const struct consensus_state_publication_decision_record *decision,
    const struct consensus_state_bundle_manifest *manifest,
    const unsigned char whole[32], const unsigned char history_root[32],
    struct wallet_cutover_binding *binding, struct boot_old_height_map *heights)
{
    sqlite3 *progress = progress_store_db();
    if (!progress || !sqlite3_get_autocommit(node->db) || !boot_cutover_journal_durable(node->db)) return false;
    memset(binding, 0, sizeof(*binding));
    if (!icb_wallet_old_authority_locked(progress, decision, binding)) return false;
    binding->target_height = manifest->height;
    memcpy(binding->target_hash, manifest->block_hash, 32);
    memcpy(binding->artifact_digest, manifest->artifact_digest, 32);
    binding->history_identity_present = true;
    memcpy(binding->snapshot_whole_sha3, whole, 32);
    memcpy(binding->history_manifest_root, history_root, 32);
    if (!boot_old_height_prepare_locked(heights, main, wallet, binding)) return false;
    int previous_sync = db_wallet_send_once_sync_level(node);
    bool raised = boot_cutover_raise_sync(node, previous_sync);
    bool ok = raised && wallet_readiness_get_locked(wallet).state == WALLET_READINESS_UNKNOWN &&
        wallet_sqlite_cutover_prepare_bound_preserving_cursor(ws, wallet, binding,
            heights->reference_height, heights->reference_hash, boot_old_height_resolve,
            boot_old_height_reference, heights);
    bool restored = !raised || boot_cutover_set_sync(node, previous_sync);
    if (!restored) LOG_ERROR("install_consensus_bundle", "wallet sync-mode restoration failed");
    if (!ok || !restored || !sqlite3_get_autocommit(ws->db)) return false;
    struct wallet_cutover_binding reread;
    return wallet_sqlite_cutover_read(ws, &reread) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(&reread, binding);
}
static bool boot_bound_wallet_arguments_valid(struct node_db *node, struct main_state *main,
    struct wallet_sqlite *ws, struct wallet *wallet,
    const struct consensus_state_publication_decision_record *decision,
    const struct consensus_state_bundle_manifest *manifest,
    const unsigned char *whole, const unsigned char *history_root,
    struct wallet_cutover_binding *binding)
{
    return node && node->db && main && ws && ws->db == node->db && wallet &&
        decision && manifest && whole && history_root && binding;
}

bool boot_bound_wallet_fence(struct node_db *node, struct main_state *main,
    struct wallet_sqlite *ws, struct wallet *wallet,
    const struct consensus_state_publication_decision_record *decision,
    const struct consensus_state_bundle_manifest *manifest,
    const unsigned char whole[32], const unsigned char history_root[32],
    struct wallet_cutover_binding *binding)
{
    if (!boot_bound_wallet_arguments_valid(node, main, ws, wallet, decision, manifest,
                                           whole, history_root, binding)) return false;
    struct boot_old_height_map heights = {0};
    if (!boot_old_height_allocate(&heights)) return false;
    if (!zcl_mutex_trylock(&main->cs_main)) { boot_old_height_free(&heights); return false; }
    bool progress_held = progress_store_tx_trylock();
    sqlite3_mutex *connection = sqlite3_db_mutex(node->db);
    bool connection_held = progress_held && connection && sqlite3_mutex_try(connection) == SQLITE_OK;
    bool wallet_held = connection_held && zcl_mutex_trylock(&wallet->cs);
    bool ok = wallet_held && boot_bound_wallet_commit_locked(node, main, ws, wallet,
                                                             decision, manifest, whole, history_root, binding, &heights);
    if (wallet_held) zcl_mutex_unlock(&wallet->cs);
    if (connection_held) sqlite3_mutex_leave(connection);
    if (progress_held) progress_store_tx_unlock();
    zcl_mutex_unlock(&main->cs_main);
    boot_old_height_free(&heights);
    return ok;
}

bool boot_wallet_cutover_stop_identity(struct wallet_sqlite *wallet,
    struct node_db *node, int dir_fd)
{
    return wallet && wallet->open && wallet->db && node && node->open &&
        wallet->db == node->db && boot_wallet_cutover_stop_context_matches(node, wallet) &&
        boot_datadir_lock_matches_fd(dir_fd) && consensus_state_wallet_node_file_matches(wallet->db, dir_fd) &&
        progress_store_directory_matches_fd(progress_store_db(), dir_fd);
}

#endif
