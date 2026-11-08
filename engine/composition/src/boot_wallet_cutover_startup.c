/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pending wallet cutover startup. */
#include "platform/socket_compat.h"
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



bool boot_cutover_verify_committed(struct boot_cutover_env *e, const char *datadir,
    const struct wallet_cutover_binding *expected)
{
#if defined(_WIN32)
    (void)e; (void)datadir; (void)expected; return false;
#else
    if (!e || !datadir || !expected) return false;
    int fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool present = false; uint64_t generation = 0;
    enum wallet_install_reconcile state = consensus_state_wallet_install_classify(
        e->wallet_db, e->node, fd, &present, &generation);
    struct wallet_cutover_binding actual;
    bool ok = state == WALLET_INSTALL_COMMITTED &&
        wallet_sqlite_cutover_read(e->wallet_db, &actual) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(expected, &actual);
    close(fd);
    return ok;
#endif
}

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
static bool boot_pending_bind_storage(struct boot_cutover_env *e, struct app_context *ctx)
{
    if (!progress_store_db() || !flysync_island_boot_register(ctx->datadir) ||
        !boot_ensure_event_log(ctx->datadir) ||
        !boot_bind_wallet_replay_event_log() ||
        !coins_view_kv_init(e->coins_view))
        return false;
    coins_view_cache_init(e->coins_tip, &e->coins_view->view);
    csr_init(csr_instance(), &e->state->map_block_index, &e->state->chain_active,
             &e->state->pindex_best_header, e->coins_tip, e->node, NULL);
    csr_set_db_service(csr_instance(), e->db_service);
    if (!boot_ensure_block_index_projection(ctx->datadir) ||
        !flysync_island_boot_rehydrate(e->state) ||
        !boot_pending_runtime_stores_open(ctx->datadir, e->node,
                                          e->coins_sqlite, e->block_tree))
        return false;
    *e->block_tree_open = true;
    g_active_block_tree = e->block_tree;
    return true;
}

bool boot_cutover_load_chain(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip)
{
    if (!boot_pending_bind_storage(e, ctx)) return false;
    struct zcl_result loaded = boot_try_rebuild_block_index_from_projection(
        e->state, params, 0, false);
    if (!loaded.ok || !flysync_island_boot_materialize(e->state)) return false;
    struct boot_derived_coins_best coins;
    if (!boot_derive_coins_best(&coins) || !coins.hash_found || coins.height < 0)
        return false;
    struct wallet_cutover_binding binding;
    if (wallet_sqlite_cutover_read(e->wallet_db, &binding) != WALLET_CUTOVER_PENDING)
        return false;
    struct uint256 installed_hash;
    memcpy(installed_hash.data, binding.target_hash, sizeof(installed_hash.data));
    struct uint256 hash;
    memcpy(hash.data, coins.hash, sizeof(hash.data));
    enum boot_pending_restore_result restored = boot_wallet_pending_restore(
        e->state, csr_instance(), coins.height, &hash,
        binding.target_height, &installed_hash);
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
}

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
    const struct app_context *ctx, const struct wallet_witness_endpoint *endpoint)
{
    if (!ctx || !ctx->datadir || !ctx->datadir[0] || !endpoint) return false;
    int n = snprintf(history->path, sizeof(history->path), "%s/wallet-history", ctx->datadir);
    if (n <= 0 || (size_t)n >= sizeof(history->path) - sizeof("/blocks/blk00000.dat") ||
        !platform_private_directory_open_validated_traverse(history->path, &history->directory))
        return false;
    history->directory_open = true;
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
    bool ok = boot_pending_history_open(&history, ctx, endpoint);
    boot_pending_history_close(&history);
    return ok;
}
#endif

/* Runs before network, reducer and wallet services can mutate the reference. */
static bool boot_pending_replay_prepare(struct boot_cutover_env *e, struct app_context *ctx,
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
        !wallet_scan_identity(e->wallet, identity)) return false;
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
            if (!boot_pending_history_open(history, ctx, &endpoint)) return false;
            rpc->main_state = history->state;
            ready = boot_cutover_replay_init_archive(replay, rpc, e->db_service, &binding,
                floor, &endpoint, identity, e->state, history->path);
        }
    }
    if (ready) replay->sapling_load_ok = e->sapling_load_ok;
    return ready;
}

#ifdef ZCL_TESTING
bool boot_test_pending_replay_prepare(struct boot_cutover_env *env, struct app_context *ctx,
    struct boot_cutover_replay *replay, struct wallet_rpc_context *rpc, void **owned_history)
{
    struct boot_pending_history *history = zcl_calloc(1, sizeof(*history), "pending history test");
    if (!history) return false;
    bool ok = boot_pending_replay_prepare(env, ctx, replay, rpc, history);
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
static bool boot_pending_busy_backoff(int64_t *since, int64_t deadline, int limit_ms)
{
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || thread_registry_shutdown_requested() ||
        (deadline && (now >= deadline || wallet_lock_is_locked()))) return false;
    if (!*since) *since = now;
    if (now < *since || now - *since >= limit_ms) return false;
    platform_sleep_ms(50);
    return true;
}
#ifdef ZCL_TESTING
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
static bool boot_pending_checkpoint_resume(struct boot_cutover_replay *r)
{
    int64_t since = 0;
    for (;;) {
        enum boot_discover_resume result = boot_wallet_discover_checkpoint_resume(r);
        if (result == BOOT_DISCOVER_FLOOR || result == BOOT_DISCOVER_RESUMED) return true;
        if (result != BOOT_DISCOVER_BUSY ||
            !boot_pending_busy_backoff(&since, r->auth_deadline_ms, 30000)) return false;
    }
}
static bool boot_pending_checkpoint_save(struct boot_cutover_replay *r)
{
    struct wallet_discover_checkpoint checkpoint;
    if (!boot_wallet_discover_checkpoint_prepare(r, &checkpoint)) return false;
    int64_t since = 0;
    for (;;) {
        enum boot_discover_save result = boot_wallet_discover_checkpoint_save(r, &checkpoint);
        if (result == BOOT_DISCOVER_SAVED) return true;
        if (result != BOOT_DISCOVER_SAVE_BUSY ||
            !boot_pending_busy_backoff(&since, r->auth_deadline_ms, 30000)) return false;
    }
}

static bool boot_pending_checkpoint_progress(struct boot_cutover_replay *replay,
    enum boot_cutover_replay_status status, enum boot_cutover_replay_phase before_phase,
    int before, int64_t *last_checkpoint_ms)
{
    if (status == BOOT_CUTOVER_PROGRESS && before_phase == BOOT_CUTOVER_TRANSPARENT &&
        replay->phase == BOOT_CUTOVER_DISCOVER)
        return boot_pending_checkpoint_resume(replay);
    if (status != BOOT_CUTOVER_PROGRESS || before_phase != BOOT_CUTOVER_DISCOVER ||
        replay->phase != BOOT_CUTOVER_DISCOVER || replay->next <= before) return true;
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || (*last_checkpoint_ms && now < *last_checkpoint_ms)) return false;
    if (!boot_pending_checkpoint_due(*last_checkpoint_ms, now)) return true;
    if (!boot_pending_checkpoint_save(replay)) return false;
    *last_checkpoint_ms = platform_time_monotonic_ms();
    return *last_checkpoint_ms > 0;
}

static bool boot_replay_busy(struct boot_cutover_replay *replay, int before,
                             int64_t *since, int64_t deadline)
{
    if (replay->next != before) *since = 0;
    return boot_pending_busy_backoff(since, deadline, 30000);
}

bool boot_cutover_replay(struct boot_cutover_env *e, struct app_context *ctx, const struct chain_params *params)
{
    struct boot_cutover_replay replay = {0};
    struct wallet_rpc_context rpc;
    struct boot_pending_history history = {0};
    bool ok = false, unlocked = false;
    int64_t deadline = 0, busy_since = 0, last_progress_ms = 0, last_checkpoint_ms = 0;
    int last_progress_phase = -1;
    if (!boot_pending_authenticate(e, ctx, &unlocked, &deadline)) goto done;
    if (!boot_pending_replay_prepare(e, ctx, &replay, &rpc, &history)) {
        LOG_ERROR("wallet", "pending replay reference or scan floor unavailable");
        goto done;
    }
    replay.auth_deadline_ms = deadline;
    while (!thread_registry_shutdown_requested()) {
        int64_t now = deadline ? platform_time_monotonic_ms() : 0;
        if (deadline && (now <= 0 || now >= deadline || wallet_lock_is_locked())) break;
        int before = replay.next;
        enum boot_cutover_replay_phase before_phase = replay.phase;
        enum boot_cutover_replay_status status = boot_cutover_replay_step(&replay);
        if (status == BOOT_CUTOVER_BUSY) {
            if (!boot_replay_busy(&replay, before, &busy_since, deadline)) break;
            continue;
        }
        busy_since = 0;
        if (status == BOOT_CUTOVER_COMPLETE) {
            ok = boot_pending_publish(e, ctx, params, &replay);
            break;
        }
        if (!boot_pending_checkpoint_progress(&replay, status, before_phase, before, &last_checkpoint_ms)) break;
        if (boot_replay_stopped(status, &replay, &last_progress_phase, &last_progress_ms)) break;
    }
done:
    if (unlocked) wallet_lock_lock(e->wallet);
    boot_cutover_replay_clear(&replay);
    boot_pending_history_close(&history);
    return ok;
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
