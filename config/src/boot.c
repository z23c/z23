/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "platform/time_compat.h"
#include "config/boot_blkidx_ladder.h"
#include "config/boot_blocktree_cleanup.h"
#include "config/boot_flight_recorder.h"
#include "config/bundle_exporter.h"
#include "config/boot_cursor_state.h"
#include "config/boot_datadir_lock.h"
#include "config/boot_internal.h"
#include "config/boot_legacy_blocks.h"
#include "config/boot_memory_guard.h"
#include "config/boot_postmortem.h"
#include "config/boot_refusal_reports.h"
#include "config/boot_shutdown_marker.h"
#include "util/shutdown_stagewatch.h"
#include "config/boot_fast_restart.h"
#include "config/boot_snapshot_failure_memory.h"
#include "config/boot_snapshot_import.h"
#include "config/boot_snapshot_install.h"
#include "config/boot_stale_locks.h"
#include "config/boot_wallet_phrase.h"
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
#include "services/recovery_policy.h"
#include "services/utxo_recovery_service.h"
#include "supervisors/staged_sync_supervisor.h"
#include "storage/progress_store.h"
#include "storage/anchor_kv.h"  /* seed the verified Sapling anchor frontier at boot */
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
#include "util/boot_phase.h"
#include "util/boot_scan.h"
#include "util/sysinit.h"
#include "platform/os_sandbox.h"
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
#include "keys/key_io.h"
#include "mining/gen.h"
#include "script/standard.h"
#include "controllers/api_controller.h"
#include "controllers/explorer_internal.h"
#include "controllers/explorer_controller.h"
#include "controllers/wallet_controller.h"
#include "controllers/zslp_controller.h"
#include "wallet/wallet.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet_keystore.h"
#include "wallet/wallet_canary.h"
#include "wallet/wallet_db.h"
#include "sapling/params_init.h"
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
#include <netdb.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <malloc.h>
#include <limits.h>
#include <sqlite3.h>

static struct main_state g_state;
static struct coins_view_sqlite g_coins_sqlite;
/* Read authority for the coins_tip cache backing: a read-only coins_view over
 * coins_kv (canonical UTXO set in progress.kv, authored in-txn by the reducer —
 * atomically consistent with the stage cursor on every crash). The legacy
 * g_coins_sqlite is still opened for legacy damage-recovery best-block reads
 * below; retiring that fallback is remaining one-write-path debt. */
static struct coins_view_kv g_coins_read_view;
static struct coins_view_cache g_coins_tip;
static struct chain_activation_controller g_activation_ctl;

struct chain_activation_controller *boot_activation_controller(void)
{
    return &g_activation_ctl;
}
static struct block_tree_db g_block_tree;
/* g_active_block_tree is defined in lib/validation (declared in
 * <validation/process_block.h>); boot publishes g_block_tree into it once
 * the tree is open. */
static bool g_block_tree_open = false;
static struct tx_mempool g_mempool;
static struct rpc_table g_rpc_table;
static struct msg_processor g_msg_processor;
static struct connman g_connman;
static struct wallet g_wallet;
static struct gen_context g_gen;
static struct wallet_sqlite g_wallet_sqlite;
static struct node_db g_node_db;
static struct db_service g_db_service;
static struct app_runtime_context g_boot_runtime;
static const char *g_datadir = NULL;
const char *g_blog_datadir = NULL;
static _Atomic bool g_running = false;
static struct wallet_backup_config g_wallet_backup_cfg;
static struct disk_monitor_config g_disk_monitor_cfg;
static struct binary_staleness_config g_binary_staleness_cfg;
static struct ibd_throttle_config g_ibd_throttle_cfg;
static struct zcl_service_kernel g_guard_kernel;
static struct zcl_service_kernel g_maintenance_kernel;
static struct zcl_service_kernel g_boot_db_kernel;

static struct db_service *boot_runtime_db_service(void)
{
    return db_service_is_started(&g_db_service) ? &g_db_service : NULL;
}

/* Policy-gated UTXO wipe moved to utxo_recovery_service.c.
 * boot_policy_wipe_utxos → utxo_recovery_wipe(&g_node_db, reason) */

static bool boot_db_enter_turbo_mode(void)
{
    struct db_service *dbsvc = boot_runtime_db_service();

    if (dbsvc)
        return db_service_ibd_turbo_mode(dbsvc);
    return g_node_db.open && node_db_ibd_turbo_mode(&g_node_db);
}

static bool boot_db_restore_normal_mode(void)
{
    struct db_service *dbsvc = boot_runtime_db_service();

    if (dbsvc)
        return db_service_normal_mode(dbsvc);
    return g_node_db.open && node_db_normal_mode(&g_node_db);
}

static bool boot_db_set_sync_batch_size(int batch_size)
{
    struct db_service *dbsvc = boot_runtime_db_service();

    if (dbsvc)
        return db_service_set_sync_batch_size(dbsvc, batch_size);
    if (!g_node_db.open)
        return false;
    node_db_set_sync_batch_size(&g_node_db, batch_size);
    return true;
}

/* Shielded backfill moved to utxo_recovery_service.c —
 * utxo_recovery_backfill_shielded(). */
static struct metrics_context g_metrics;

/* Comparator for sorting block_index pointers by height (for qsort). */
static int cmp_block_index_height(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index **)a;
    const struct block_index *pb = *(const struct block_index **)b;
    return (pa->nHeight > pb->nHeight) - (pa->nHeight < pb->nHeight);
}

/* Callback for block_tree_db_load_block_index_guts — inserts a block
 * into the block map, reusing existing entry if hash already present. */
static struct block_index *boot_insert_block_index_cb(void *ctx_ptr,
                                                       const struct uint256 *hash)
{
    struct main_state *ms = (struct main_state *)ctx_ptr;
    return chainstate_insert_block_index((struct chainstate *)ms, hash);
}

/* SQLite tuning and file operations now live in the model layer:
 *   node_db_ibd_turbo_mode()  — database.h
 *   node_db_normal_mode()     — database.h
 *   file_copy(), dir_copy()   — file_ops.h
 */

/* Background ZK param loading */
static char g_params_dir_buf[1024];
static pthread_t g_params_thread;
static bool g_params_thread_started = false;
static _Atomic bool g_params_loaded = false;
static struct boot_svc_ctx g_svc;

/* Single source of truth for the live boot service context — the &g_svc handed
 * to app_init_services; boot_services.c's main.c-facing entry points read it. */
struct boot_svc_ctx *boot_active_svc(void) { return &g_svc; }

/* boot_park_until_shutdown prototype is in config/boot_internal.h (included
 * above); defined below (line ~1175), non-static so boot_node_db_gate.c can
 * share the same park path. */

static bool boot_params_thread_failure_is_fatal(const struct app_context *ctx,
                                                const char *network_id)
{
    return ctx && ctx->params_dir && network_id &&
           strcmp(network_id, "main") == 0 && !ctx->mint_anchor_fast;
}

#ifdef ZCL_TESTING
bool boot_test_params_thread_failure_is_fatal(bool has_params_dir,
                                              bool is_mainnet,
                                              bool mint_anchor_fast)
{
    struct app_context ctx = {0};
    ctx.params_dir = has_params_dir ? "/tmp/zcash-params" : NULL;
    ctx.mint_anchor_fast = mint_anchor_fast;
    return boot_params_thread_failure_is_fatal(&ctx,
                                               is_mainnet ? "main" : "test");
}
#endif

void *load_params_thread(void *arg)
{
    (void)arg;
    printf("Loading verification keys (background)...\n");
    if (sapling_init_params(g_params_dir_buf)) {
        atomic_store(&g_params_loaded, true);
        printf("Verification keys loaded.\n");
        return NULL;
    }

    /* A failed background param load must NOT silently downgrade to a
     * one-line warning while proof_validate idles forever. The synchronous
     * pre-check in boot_step_init_crypto_and_state already confirmed the files
     * EXIST before CRYPTO_READY advanced, so reaching here on mainnet means the
     * files are present-but-corrupt (SHA-512/parse failure). Name a PERMANENT
     * blocker and page the operator ONCE; the running node then surfaces this
     * named blocker via proof_validate's params gate (JOB_BLOCKED) instead of a
     * silent JOB_IDLE — a stall that is always named, never a quiet stop. */
    const struct chain_params *cp = chain_params_get();
    if (cp && strcmp(cp->strNetworkID, "main") == 0) {
        struct blocker_record rec;
        if (blocker_init(&rec, "params_missing", "crypto.params",
                         BLOCKER_PERMANENT,
                         "mainnet zk verification keys present but failed to load "
                         "(SHA-512/parse) — proof validation cannot proceed") &&
            blocker_set(&rec) == 0)
            event_emitf(EV_OPERATOR_NEEDED, 0,
                        "check=params_missing dir=%s", g_params_dir_buf);
        LOG_WARN("crypto.params",
                 "[crypto.params] zk params failed to load from %s — proof "
                 "validation BLOCKED (params_missing); operator paged once",
                 g_params_dir_buf);
    } else {
        fprintf(stderr, "Warning: Failed to load ZK params (non-mainnet)\n");
    }
    return NULL;
}

/* Block index, chainstate rebuild, and address backfill are in
 * boot_index.c. Service startup (P2P, RPC, Tor) and shutdown
 * are in boot_services.c. */

/* Boot timing helper */
static int64_t boot_clock_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Emit an indented [boot] sub-phase marker + feed boot_flight_recorder;
 * return a fresh clock reading so the caller can chain: t = boot_submark("x", t). */
static int64_t boot_submark(const char *name, int64_t since)
{
    int64_t ms = boot_clock_ms() - since;
    printf("[boot]   %-28s %lldms\n", name, (long long)ms);
    boot_flight_recorder_mark(name, ms);
    return boot_clock_ms();
}

/* Top-level [boot] phase marker + boot_flight_recorder feed (boot_submark, one indent level up). */
static void boot_topmark(const char *name, int64_t since)
{
    int64_t ms = boot_clock_ms() - since;
    printf("[boot] %-30s %lldms\n", name, (long long)ms);
    boot_flight_recorder_mark(name, ms);
}

/* ── boot.c decomposition ──────────────────────────────────────────
 * app_init is split into named, single-responsibility `boot_step_*`
 * static functions returning bool — true to continue, false to bail.
 * Contract: either the precondition holds and the step succeeds, or
 * the process exits non-zero before any other subsystem can observe
 * partial state. */

static bool boot_step_init_observability(void)
{
    /* Install fatal-signal handler BEFORE any thread is spawned so the
     * handler is inherited process-wide. Any SIGABRT/SIGSEGV/SIGBUS/SIGFPE
     * gets a logged backtrace before systemd sees the exit. */
    if (signal_handler_install() != 0) {
        /* Fatal: booting without a crash handler means the next SEGV/ABRT is
         * silent and undiagnosable — a silent crash can scramble block
         * storage. Refuse to start blind. */
        fprintf(stderr, "FATAL: signal_handler_install failed; refusing to "
                        "boot without a crash handler\n");
        return false;
    }

    /* Arm the live self-backtrace handler (SIGRTMIN+2) before threads spawn so
     * every worker inherits it. Non-fatal: a diagnostic surface, not a
     * correctness gate. Enables `ops.debug.backtrace` to dump all threads on a
     * running node without perf/gdb. */
    if (!self_backtrace_install())
        fprintf(stderr, "WARNING: self_backtrace_install failed; "
                        "ops.debug.backtrace will be unavailable\n");

    db_service_init(&g_db_service);

    /* Initialize event log first — everything after this is observable */
    event_log_init();
    event_install_crash_handler();

    /* Start async observer thread + register error accumulator.
     * Captures DB errors, block rejections, flush failures for
     * instant health queries via /api/health and healthcheck RPC. */
    if (!event_async_start())
        fprintf(stderr, "WARNING: failed to start async event dispatcher\n");
    struct error_ring *er = error_ring_global();
    event_observe_async(EV_DB_ERROR, error_ring_observer, er);
    event_observe_async(EV_COINS_FLUSH_FAILED, error_ring_observer, er);
    event_observe_async(EV_BLOCK_REJECTED, error_ring_observer, er);
    event_observe_async(EV_UTXO_CHECKPOINT_FAIL, error_ring_observer, er);

    /* Observe validation failures as errors too */
    event_observe_async(EV_MODEL_VALIDATION_FAILED, error_ring_observer, er);

    /* Typed blocker registry: init BEFORE the restore/import producers.
     * blocker_module_init memsets the registry; if it first ran AFTER
     * restore it would silently wipe any band/producer blockers recorded
     * during restore. Idempotent — the boot_services call remains as a
     * backstop. */
    blocker_module_init();

    /* If the launcher (deploy/zclassic23-launch.sh) fell back to the
     * last-known-good binary after a boot-failure streak, surface the
     * degraded-but-alive state as a typed blocker as early as the registry
     * is live — so `z23 status` shows it throughout this boot, not
     * only once we reach ready. Sibling of the stale-binary blocker above.
     * No-op when launched directly (env unset). */
    binary_ab_raise_fallback_blocker_env();

    event_emitf(EV_NODE_STARTING, 0, "zclassic23 1.0.0");
    return true;
}

static bool boot_step_select_chain_and_datadir(struct app_context *ctx)
{
    if (ctx->regtest)
        chain_params_select(CHAIN_REGTEST);
    else if (ctx->testnet)
        chain_params_select(CHAIN_TESTNET);
    else
        chain_params_select(CHAIN_MAIN);
    boot_apply_regtest_shielded(ctx->regtest_shielded, ctx->regtest);
    g_datadir = ctx->datadir;
    g_blog_datadir = ctx->datadir;
    SetDataDir(ctx->datadir);

    /* Auto-create datadir if it doesn't exist.
     *
     * The mkdir return value used to be discarded and "Created data
     * directory: X" printed unconditionally — so a create that FAILED (a
     * missing parent, a read-only mount, a denied path) still claimed
     * success, and the operator's first real signal was the datadir lock a
     * few lines below reporting a bare errno on a directory the log had just
     * said was created. Name the create failure where it happens. EEXIST is
     * not a failure: another process (or the stat race) won. */
    struct stat st;
    if (stat(ctx->datadir, &st) != 0) {
        if (mkdir(ctx->datadir, 0700) == 0) {
            printf("Created data directory: %s\n", ctx->datadir);
        } else if (errno != EEXIST) {
            int e = errno;
            boot_report_datadir_create_failed(ctx->datadir, e);
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "datadir_create_failed errno=%d", e);
            return false;
        }
    }

    /* Now that the datadir is known, point the crash handler at a durable,
     * fsync'd crash log there. Until this call a crash still lands on stderr;
     * after it, the backtrace also survives in $datadir/crash_log.txt
     * independent of systemd's stderr routing. */
    {
        char crash_path[600];
        snprintf(crash_path, sizeof(crash_path), "%s/crash_log.txt",
                 ctx->datadir);
        signal_handler_set_crash_log(crash_path);
    }

    /* Arm the pre-RPC boot-progress beacon (util/boot_status.h). */
    boot_status_init(ctx->datadir);

    /* Acquire data directory lock — prevents two instances from
     * corrupting SQLite / LevelDB by writing concurrently. */
    if (!boot_datadir_lock_acquire(ctx->datadir))
        return false;

    boot_stage_advance_to(BOOT_STAGE_DATADIR_LOCKED);
    return true;
}

static void boot_step_backfill_shielded_if_needed(struct app_context *ctx,
                                                   struct block_index *tip)
{
    /* Populate blocks.{sprout,sapling}_value through the tip when an LDB import
     * left them empty. The service is cursor-gated (`shielded_backfill_height`),
     * so a fresh 2-step datadir skips the O(chain) disk walk and RPC binds
     * fast. Skipped in no_services mode (speedrun / benchmarking). */
    if (!(g_node_db.open && tip && tip->nHeight > 1000 && !ctx->no_services))
        return;
    utxo_recovery_backfill_shielded_if_needed(&g_node_db,
        boot_runtime_db_service(), &g_state, g_datadir, (int)tip->nHeight);
}

static void boot_step_build_svc_ctx(struct app_context *ctx,
                                     struct boot_svc_ctx *svc)
{
    *svc = (struct boot_svc_ctx){
        .state = &g_state,
        .coins_sqlite = &g_coins_sqlite,
        .coins_tip = &g_coins_tip,
        .mempool = &g_mempool,
        .rpc_table = &g_rpc_table,
        .msg_processor = &g_msg_processor,
        .connman = &g_connman,
        .wallet = &g_wallet,
        .gen = &g_gen,
        .wallet_sqlite = &g_wallet_sqlite,
        .node_db = &g_node_db,
        .db_service = &g_db_service,
        .metrics = &g_metrics,
        .running = &g_running,
        .datadir = g_datadir,
        .params_thread = g_params_thread,
        .params_thread_started = g_params_thread_started,
        .params_loaded = &g_params_loaded,
        .block_tree_open = g_block_tree_open,
        .block_tree = &g_block_tree,
        .want_address_backfill = false,
        .want_snapshot_tx_index = ctx->tx_index || ctx->snapshot_dir != NULL,
        .defer_payment_service = false,
        .defer_offer_service = false,
    };
    if (g_node_db.open) {
        int64_t addr_done = 0;
        node_db_state_get_int(&g_node_db, "addresses_backfilled", &addr_done);
        svc->want_address_backfill = (addr_done == 0);
    }
}

static void boot_step_finalize_chain_state(void)
{
    /* Restore normal SQLite settings after any IBD replay */
    if (g_node_db.open) {
        if (!boot_db_restore_normal_mode())
            fprintf(stderr, "boot: failed to restore normal mode\n");
        if (!boot_db_set_sync_batch_size(1))
            fprintf(stderr, "boot: failed to reset sync batch size\n");
    }
    /* Flush every 500 blocks during normal sync so crash/kill never
     * loses more than ~500 blocks of connected coins state. */
    set_flush_policy(3600, 500000, 500);

    struct block_index *tip = active_chain_tip(&g_state.chain_active);
    if (tip && tip->phashBlock) {
        if (g_node_db.open &&
            !node_db_sync_set_tip(&g_node_db, tip->phashBlock->data,
                                  tip->nHeight))
            fprintf(stderr, "boot: failed to persist final chain tip\n");
        char hex[65];
        uint256_get_hex(tip->phashBlock, hex);
        printf("Chain tip: height=%d hash=%s\n", tip->nHeight, hex);
        boot_status_set_height(tip->nHeight);
        event_emitf(EV_BOOT_ACTIVATE, 0, "done tip=%d", tip->nHeight);

        /* Do not auto-extend deferred proof validation at startup: chainstate
         * came from a trusted source (import / prior run / hash-checked coins
         * DB); only blocks received via P2P AFTER startup need new validation. */
    } else {
        printf("Chain tip: genesis\n");
    }
}

static bool boot_promote_tip_via_csr_internal(struct block_index *tip,
                                              const char *reason,
                                              bool persist_coins_best,
                                              bool update_header_tip)
{
    if (!tip || !tip->phashBlock)
        return false;

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_BOOT_REPAIR,
        .decision = POLICY_ALLOW,
        .from_height = active_chain_height(&g_state.chain_active),
        .to_height = tip->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "boot_repair_verified",
        .reason = reason ? reason : "boot_repair",
    };
    struct chain_state_commit commit = {
        .new_tip = tip,
        .new_coins_best = *tip->phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = update_header_tip,
        .persist_coins_best = persist_coins_best,
        .rollback_auth = &rollback_auth,
        .wallet_scan_height = -1,
        .reason = reason ? reason : "boot_repair",
    };

    enum csr_result rc = csr_commit_tip(csr_instance(), &commit);
    if (rc != CSR_OK) {
        fprintf(stderr, // obs-ok:pre-existing-diagnostic
                "[boot] csr rejected boot repair promotion (%s) "
                "reason=%s h=%d\n",
                csr_result_name(rc), reason ? reason : "", tip->nHeight);
        return false;
    }

    return true;
}

bool boot_promote_tip_via_csr(struct block_index *tip,
                              const char *reason,
                              bool persist_coins_best)
{
    return boot_promote_tip_via_csr_internal(
        tip, reason, persist_coins_best, true);
}

bool boot_promote_tip_preserving_header_via_csr(
    struct block_index *tip,
    const char *reason,
    bool persist_coins_best)
{
    return boot_promote_tip_via_csr_internal(
        tip, reason, persist_coins_best, false);
}

static bool boot_promote_header_via_csr(struct block_index *header,
                                        const char *reason)
{
    if (!header || !header->phashBlock)
        return false;

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_BOOT_REPAIR,
        .decision = POLICY_ALLOW,
        .from_height = g_state.pindex_best_header
            ? g_state.pindex_best_header->nHeight : -1,
        .to_height = header->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "boot_header_verified",
        .reason = reason ? reason : "boot_header",
    };
    struct chain_state_header_commit commit = {
        .new_header_tip = header,
        .rollback_auth = &rollback_auth,
        .reason = reason ? reason : "boot_header",
    };
    enum csr_result rc = csr_commit_header_tip(csr_instance(), &commit);
    if (rc != CSR_OK) {
        fprintf(stderr, // obs-ok:pre-existing-diagnostic
                "[boot] csr rejected header promotion (%s) "
                "reason=%s h=%d\n",
                csr_result_name(rc), reason ? reason : "", header->nHeight);
        return false;
    }
    return true;
}

/* DERIVED coins-best (wave 2): one cheap point-read of progress.kv's own
 * co-committed state via reducer_frontier_derive_coins_best. Recomputed at
 * every decision point (derive, don't cache). Returns true iff
 * coins_applied_height is present — the canonical-datadir signal that the
 * legacy node_state/mirror anchors are mere caches and every legacy
 * anchor-repair rung below must be skipped. */
struct boot_derived_coins_best {
    int32_t height;      /* coins_applied_height - 1 */
    uint8_t hash[32];    /* valid iff hash_found */
    bool hash_found;
};

static bool boot_derive_coins_best(struct boot_derived_coins_best *out)
{
    memset(out, 0, sizeof(*out));
    out->height = -1;
    return reducer_frontier_derive_coins_best_now(&out->height, out->hash,
                                                  &out->hash_found);
}

static bool boot_step_init_crypto_and_state(struct app_context *ctx,
                                             const struct chain_params *params)
{
    /* Assumevalid is set after block index loads (see below — first the
     * default-from-checkpoint case fires here, the user-provided-hash
     * case is deferred). The implementation in contextual_check_tx.c
     * handles both script verification (connect_block.c) and Sapling
     * proof verification (contextual_check_tx.c) via
     * g_deferred_proof_validation_below_height. */

    ecc_start();
    ecc_verify_init();

    /* SHA-256 hardware self-test */
    if (!sha256_selftest())
        printf("WARNING: SHA-256 SHA-NI self-test FAILED — using portable fallback\n");
    printf("SHA-256: %s\n", sha256_implementation());

    /* Report field arithmetic acceleration */
    extern const char *fr_accel_implementation(void);
    printf("Field arithmetic: %s\n", fr_accel_implementation());

    main_state_init(&g_state);
    g_state.fTxIndex = ctx->tx_index;
    g_state.fCheckpointsEnabled = ctx->checkpoints_enabled;

    /* Initialize chain activation controller — single authority for when the
     * reducer activation path can run. Must be before any chain work. */
    activation_controller_init(&g_activation_ctl, &g_state, &g_coins_tip,
                               params, ctx->datadir);
    activation_set_state(&g_activation_ctl, ACTIVATION_BOOT_PENDING,
                         "boot_start");

    /* -deferproofvalidationbelow: skip Groth16/Sapling proof verification for blocks
     * at or below the specified hash's height. Default: latest checkpoint.
     * Pass -deferproofvalidationbelow=0 to disable (verify everything). */
    if (ctx->defer_proof_validation_below && strcmp(ctx->defer_proof_validation_below, "0") == 0) {
        g_deferred_proof_validation_below_height = -1;
        printf("Deferred proof validation: disabled (verifying all proofs)\n");
    } else if (ctx->defer_proof_validation_below) {
        /* Resolve user-provided hash after block index loads (deferred) */
    } else {
        /* Default: latest checkpoint height */
        if (params->checkpointData.nEntries > 0) {
            g_deferred_proof_validation_below_height =
                params->checkpointData.entries[params->checkpointData.nEntries - 1].height;
            printf("Deferred proof validation: height %d (latest checkpoint)\n",
                   g_deferred_proof_validation_below_height);
        }
    }

    /* Defer ZK key loading to background thread — not needed for RPC startup.
     * Keys load in parallel while block index + wallet initialize. */
    g_params_thread_started = false;
    if (ctx->params_dir)
        snprintf(g_params_dir_buf, sizeof(g_params_dir_buf), "%s", ctx->params_dir);

    /* On mainnet, the zk verification keys are consensus-critical — a
     * node with no ~/.zcash-params cannot validate shielded proofs, and the
     * deferred background loader would just fail while proof_validate idles
     * forever (the old silent-halt). Synchronously confirm the required files
     * EXIST + are readable BEFORE advancing CRYPTO_READY. If any is missing:
     * name a PERMANENT blocker, page the operator ONCE, do NOT advance
     * CRYPTO_READY (params genuinely failed to load), and PARK alive-degraded
     * so a missing-params install is a NAMED blocker — never a silent idle and
     * never a systemd Restart=always crash-loop.
     *
     * EXEMPTION: -mint-anchor-fast passes the crypto stages through without
     * running (jobs/mint_skip_crypto.h), so that offline self-mint legitimately
     * needs no zk params — do not park it for missing params. */
    if (params && strcmp(params->strNetworkID, "main") == 0 &&
        !ctx->mint_anchor_fast) {
        static const char *const req[] = {
            "sapling-spend.params", "sapling-output.params",
            "sprout-groth16.params", "sprout-verifying.key",
        };
        const char *missing = NULL;
        char missing_path[1100] = {0};
        if (!ctx->params_dir) {
            missing = "(no -paramsdir configured)";
        } else {
            for (size_t i = 0; i < sizeof(req) / sizeof(req[0]); i++) {
                char p[1100];
                snprintf(p, sizeof(p), "%s/%s", g_params_dir_buf, req[i]);
                if (access(p, R_OK) != 0) {
                    missing = req[i];
                    snprintf(missing_path, sizeof(missing_path), "%s", p);
                    break;
                }
            }
        }
        if (missing) {
            struct blocker_record rec;
            if (blocker_init(&rec, "params_missing", "crypto.params",
                             BLOCKER_PERMANENT,
                             "mainnet zk verification keys are missing/unreadable "
                             "— proof validation cannot run; install ~/.zcash-params") &&
                blocker_set(&rec) == 0)
                event_emitf(EV_OPERATOR_NEEDED, 0,
                            "check=params_missing file=%s path=%s", missing,
                            missing_path[0] ? missing_path : "");
            LOG_WARN("crypto.params",
                     "[crypto.params] mainnet requires zk params but '%s' is "
                     "missing/unreadable (dir=%s) — NOT advancing CRYPTO_READY; "
                     "parking alive-degraded after paging the operator",
                     missing, ctx->params_dir ? ctx->params_dir : "(unset)");
            /* Do NOT advance CRYPTO_READY: the params actually failed to load. */
            return boot_park_until_shutdown("crypto_params_missing");
        }
    }

    if (ctx->params_dir) {
        /* One-shot ZK params loader; joined at shutdown via
         * app_shutdown's params_thread field. raw-pthread-ok */
        if (pthread_create(&g_params_thread, NULL, load_params_thread, NULL) == 0)
            g_params_thread_started = true;
        else if (boot_params_thread_failure_is_fatal(
                     ctx, params ? params->strNetworkID : NULL)) {
            struct blocker_record rec;
            if (blocker_init(&rec, "params_missing", "crypto.params",
                             BLOCKER_PERMANENT,
                             "mainnet zk params loader thread failed to start "
                             "— proof validation cannot run") &&
                blocker_set(&rec) == 0)
                event_emitf(EV_OPERATOR_NEEDED, 0,
                            "check=params_missing reason=params_loader_thread_start_failed dir=%s",
                            g_params_dir_buf);
            LOG_WARN("crypto.params",
                     "[crypto.params] failed to start zk params loader thread "
                     "for mainnet dir=%s — NOT advancing CRYPTO_READY; parking "
                     "alive-degraded after paging the operator",
                     g_params_dir_buf);
            return boot_park_until_shutdown("crypto_params_loader_thread");
        } else {
            fprintf(stderr,
                    "WARNING: failed to start ZK params loader thread\n");
        }
    }

    boot_stage_advance_to(BOOT_STAGE_CRYPTO_READY);
    return true;
}

static bool boot_disk_monitor_service_start(void *ctx)
{
    const char *datadir = ctx;
    if (!datadir)
        return false;
    disk_monitor_config_defaults(&g_disk_monitor_cfg);
    g_disk_monitor_cfg.datadir = datadir;
    struct zcl_result dr = disk_monitor_start(&g_disk_monitor_cfg);
    if (dr.ok) {
        printf("Disk monitor started (warn=%lldGB refuse=%lldGB)\n",
               (long long)(g_disk_monitor_cfg.warn_free_bytes >> 30),
               (long long)(g_disk_monitor_cfg.refuse_free_bytes >> 30));
        return true;
    }
    fprintf(stderr, "[boot] %s:%d disk_monitor_start failed: code=%d %s\n",
            dr.source_file, dr.source_line, dr.code, dr.message);
    return false;
}

static void boot_disk_monitor_service_stop(void *ctx)
{
    (void)ctx;
    disk_monitor_stop();
}

static bool boot_ibd_throttle_service_start(void *ctx)
{
    (void)ctx;
    ibd_throttle_config_defaults(&g_ibd_throttle_cfg);
    ibd_throttle_config_from_env(&g_ibd_throttle_cfg);
    struct zcl_result ir = ibd_throttle_start(&g_ibd_throttle_cfg);
    if (ir.ok) {
        printf("IBD throttle started (rate=%lld/s burst=%lld)\n",
               (long long)g_ibd_throttle_cfg.blocks_per_sec,
               (long long)g_ibd_throttle_cfg.burst);
        return true;
    }
    fprintf(stderr, "[boot] %s:%d ibd_throttle_start failed: code=%d %s\n",
            ir.source_file, ir.source_line, ir.code, ir.message);
    return false;
}

static void boot_ibd_throttle_service_stop(void *ctx)
{
    (void)ctx;
    ibd_throttle_stop();
}

static bool boot_wallet_backup_service_start(void *ctx)
{
    struct node_db *db = ctx;
    static char backup_dir[1024];

    if (!db || !db->open || !db->db) {
        printf("Wallet backup deferred until node DB is open\n");
        return true;
    }

    /* Defaults apply the WALLET_BACKUP_PASSWORD encryption policy. */
    wallet_backup_config_defaults(&g_wallet_backup_cfg);

    if (!g_wallet_backup_cfg.backup_dir) {
        const char *home = getenv("HOME");
        snprintf(backup_dir, sizeof(backup_dir), "%s/wallet_backups",
                 home && home[0] ? home : ".");
        g_wallet_backup_cfg.backup_dir = backup_dir;
    }
    struct zcl_result br = wallet_backup_start(&g_wallet_backup_cfg, db);
    if (br.ok) {
        printf("Wallet backup started (interval=%ds max=%d encrypt=%s)\n",
               g_wallet_backup_cfg.interval_seconds, g_wallet_backup_cfg.max_versions,
               g_wallet_backup_cfg.encrypt ? "on" : "off");
        return true;
    }
    fprintf(stderr, "[boot] %s:%d wallet_backup_start failed: code=%d %s\n",
            br.source_file, br.source_line, br.code, br.message);
    return false;
}

static void boot_wallet_backup_service_stop(void *ctx)
{
    (void)ctx;
    wallet_backup_stop();
}

static bool boot_db_maintenance_service_start(void *ctx)
{
    struct node_db *db = ctx;
    if (!db || !db->open)
        return true;

    const char *enabled = getenv("ZCL_ENABLE_BOOT_DB_MAINT");
    if (!enabled || strcmp(enabled, "1") != 0) {
        printf("DB maintenance deferred (set ZCL_ENABLE_BOOT_DB_MAINT=1 to enable boot scheduler)\n");
        return true;
    }

    struct db_maintenance_schedule dbm_sched;
    db_maintenance_schedule_defaults(&dbm_sched);
    dbm_sched.wal_checkpoint_minutes = 5;
    struct zcl_result _dbm_r = db_maintenance_start(db, &dbm_sched);
    if (_dbm_r.ok) {
        printf("DB maintenance started (wal=%dmin analyze=%dh)\n",
               dbm_sched.wal_checkpoint_minutes,
               dbm_sched.analyze_hours);
        return true;
    }
    fprintf(stderr, "db_maintenance_start failed: %s\n", _dbm_r.message);
    return false;
}

static void boot_db_maintenance_service_stop(void *ctx)
{
    (void)ctx;
    db_maintenance_stop();
}

static bool boot_binary_staleness_service_start(void *ctx)
{
    (void)ctx;
    binary_staleness_config_defaults(&g_binary_staleness_cfg);
    struct zcl_result bsr = binary_staleness_start(&g_binary_staleness_cfg);
    if (bsr.ok) {
        printf("Binary staleness monitor started (poll=%ds)\n",
               g_binary_staleness_cfg.poll_seconds);
        return true;
    }
    fprintf(stderr,
            "[boot] %s:%d binary_staleness_start failed: code=%d %s\n",
            bsr.source_file, bsr.source_line, bsr.code, bsr.message);
    /* Registered ZCL_SERVICE_OPTIONAL below — the kernel marks this
     * service FAILED and continues booting rather than aborting: stale-
     * binary detection is an observability signal, not a consensus or
     * data-safety dependency. */
    return false;
}

static void boot_binary_staleness_service_stop(void *ctx)
{
    (void)ctx;
    binary_staleness_stop();
}

static bool boot_register_guard_services(const char *datadir)
{
    const struct zcl_service_spec disk_spec = {
        .name = "disk_monitor",
        .start = boot_disk_monitor_service_start,
        .stop = boot_disk_monitor_service_stop,
        .ctx = (void *)datadir,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    const struct zcl_service_spec ibd_spec = {
        .name = "ibd_throttle",
        .start = boot_ibd_throttle_service_start,
        .stop = boot_ibd_throttle_service_stop,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(&g_guard_kernel, &disk_spec) &&
           zcl_service_kernel_register(&g_guard_kernel, &ibd_spec);
}

static bool boot_register_maintenance_services(void)
{
    const struct zcl_service_spec wallet_backup_spec = {
        .name = "wallet_backup",
        .start = boot_wallet_backup_service_start,
        .stop = boot_wallet_backup_service_stop,
        .ctx = &g_node_db,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    const struct zcl_service_spec db_maintenance_spec = {
        .name = "db_maintenance",
        .start = boot_db_maintenance_service_start,
        .stop = boot_db_maintenance_service_stop,
        .ctx = &g_node_db,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    const struct zcl_service_spec binary_staleness_spec = {
        .name = "binary_staleness",
        .start = boot_binary_staleness_service_start,
        .stop = boot_binary_staleness_service_stop,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    sovereign_promotion_service_register();
    return zcl_service_kernel_register(&g_maintenance_kernel, &wallet_backup_spec) &&
           zcl_service_kernel_register(&g_maintenance_kernel, &db_maintenance_spec) &&
           zcl_service_kernel_register(&g_maintenance_kernel, &binary_staleness_spec) &&
           bundle_exporter_register_service(&g_maintenance_kernel, g_datadir) &&
           boot_register_network_monitor_service(&g_maintenance_kernel, &g_node_db) &&
           boot_register_network_crawler_service(&g_maintenance_kernel);
}

static void boot_step_start_disk_and_ibd_guards(const char *datadir)
{
    zcl_service_kernel_init(&g_guard_kernel);
    if (!boot_register_guard_services(datadir) ||
        !zcl_service_kernel_start_all(&g_guard_kernel)) {
        fprintf(stderr, "WARNING: failed to start boot guard services\n");
    }
}

static void boot_step_start_maintenance_services(void)
{
    zcl_service_kernel_init(&g_maintenance_kernel);
    if (!boot_register_maintenance_services() ||
        !zcl_service_kernel_start_all(&g_maintenance_kernel)) {
        fprintf(stderr, "WARNING: failed to start maintenance services\n");
    }
}

/* ── SYSINIT records: the boot-stage boundaries between DB_OPEN and READY ──
 *
 * These convert boot.c's literal call order into declarative records the
 * boot-stage machine advances through (util/sysinit.h). Each record's init
 * runs at its true boundary and either establishes/verifies the stage's
 * guarantee or is fail-closed. app_init calls sysinit_run_stage() at the point
 * the guarantee becomes true; run_stage advances the stage only if the records
 * succeed. Registered order does not matter — the deterministic (stage, order,
 * name) sort (pinned by tools/lint/check_sysinit_ordering.sh) does.
 *
 * ctx: WALLET_LOADED / BLOCK_INDEX_LOADED / CHAIN_TIP_RESOLVED /
 * SERVICES_RUNNING receive the `struct app_context *`; NETWORK_READY (run from
 * boot_services.c app_init_services) receives the `struct boot_svc_ctx *`. */

static struct zcl_result sr_wallet_loaded(void *ctx)
{
    (void)ctx;
    /* STATE C/D/E/F handling above has already aborted on a wallet that
     * could not be opened/verified; reaching here means wallet_init +
     * (load or create) completed and the keystore is the authority. */
    if (!g_node_db.open)
        return ZCL_OK;  /* STATE A: no node.db — keypool generated in RAM */
    return ZCL_OK;
}

static struct zcl_result sr_block_index_loaded(void *ctx)
{
    (void)ctx;
    /* The flat/SQLite/LevelDB loaders, projection topup, and height/pprev
     * repair have run and the sidecar integrity gate accepted the map. A
     * genesis-only map (size <= 1) is legitimate on a fresh datadir. */
    return ZCL_OK;
}

static struct zcl_result sr_chain_tip_resolved(void *ctx)
{
    (void)ctx;
    /* Restore normal SQLite mode, persist the resolved tip, and stamp
     * boot_status — the coins/block-index reconciliation is complete by the
     * time app_init calls this. */
    boot_step_finalize_chain_state();
    return ZCL_OK;
}

static struct zcl_result sr_network_ready(void *ctx)
{
    const struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->connman)
        return ZCL_ERR(-1, "network boundary reached without a connman");
    return ZCL_OK;
}

static struct zcl_result sr_services_running(void *ctx)
{
    (void)ctx;
    boot_step_start_maintenance_services();
    return ZCL_OK;
}

/* Late confinement: enter the os_sandbox node steady-state profile once every
 * thread is spawned and every late fd is open (SERVICES_RUNNING, highest
 * `order` — last record before READY). No-op unless -sandbox=steady.
 * fs grants: the datadir tree (rw, covers <datadir>/ssl + SQLite WAL/shm/tmp),
 * the agent-test status dir when present, and a read-only OS_SANDBOX_PROC_
 * SELF_STATUS_PATH grant (metrics RSS — see os_sandbox_landlock_apply_to_self
 * in platform/os_sandbox.h for the full Landlock-retrofit design/scope note).
 * Fail-closed: an applicable-but-failed confinement request FATALs boot
 * rather than run unconfined. Thread coverage (`dumpstate sandbox`): seccomp
 * installs via TSYNC (every thread, atomically); Landlock has no TSYNC
 * equivalent, so os_sandbox_landlock_apply_to_self() is the retrofit join an
 * already-running thread calls from its own loop — wired into the
 * health-sweep and metrics loops today. Deliberately NOT wired into the
 * supervisor dispatch thread (lib/util/src/supervisor.c): that one thread
 * runs EVERY registered supervisor child's on_tick synchronously, so
 * confining it would confine every dispatched callback across every domain,
 * not just an audited loop — it stays the documented Landlock-unconfined
 * (still seccomp-confined) residual alongside file_service/
 * wallet_backup_service/disk_monitor/event_async. */
/* Build the shared Landlock fs-grant set for the node confinement profiles: rw
 * under the datadir (covers <datadir>/ssl + SQLite WAL/shm/tmp), rw under the
 * agent-test status dir when present, and a read-only self-status grant. Returns
 * the count written into `rules` (capacity >= 3). `extra_ro` toggles the
 * extra read-only paths the confined node opens post-boot (Sapling params dir,
 * /etc/resolv.conf) — enabled for -confine, which uses a strict seccomp
 * allow-list and therefore benefits from the fuller path set. */
static size_t sandbox_build_fs_rules(const char *datadir,
                                     struct os_sandbox_path_rule *rules,
                                     size_t cap, bool extra_ro,
                                     char scratch[][PATH_MAX], size_t scratch_cap)
{
    size_t n = 0;
    size_t s = 0;
    if (cap == 0) return 0;
    rules[n++] = (struct os_sandbox_path_rule){
        .path = datadir, .allow_read = true, .allow_write = true };

    const char *home = getenv("HOME");
    if (home && home[0] && n < cap && s < scratch_cap) {
        snprintf(scratch[s], PATH_MAX, "%s/.zclassic-c23-agent-test-status", home);
        struct stat st;
        if (stat(scratch[s], &st) == 0 && S_ISDIR(st.st_mode)) {
            rules[n++] = (struct os_sandbox_path_rule){
                .path = scratch[s], .allow_read = true, .allow_write = true };
            s++;
        }
    }

    if (extra_ro) {
        /* Sapling params dir (read-only proving/verifying keys). */
        if (home && home[0] && n < cap && s < scratch_cap) {
            snprintf(scratch[s], PATH_MAX, "%s/.zcash-params", home);
            struct stat st;
            if (stat(scratch[s], &st) == 0 && S_ISDIR(st.st_mode)) {
                rules[n++] = (struct os_sandbox_path_rule){
                    .path = scratch[s], .allow_read = true };
                s++;
            }
        }
        /* DNS resolver config (peer hostname resolution). Grant the /etc/
         * directory read-only only if it exists (it always does on Linux). */
        struct stat est;
        if (n < cap && stat("/etc/resolv.conf", &est) == 0)
            rules[n++] = (struct os_sandbox_path_rule){
                .path = "/etc/resolv.conf", .allow_read = true };
    }

    /* Self-introspection only (getrusage/sysinfo already cover this ground). */
    if (n < cap)
        rules[n++] = (struct os_sandbox_path_rule){
            .path = OS_SANDBOX_PROC_SELF_STATUS_PATH, .allow_read = true };
    return n;
}

/* -confine / -confine=serving (strict seccomp ALLOW-list + Landlock): apply
 * once every listen socket/file/thread is up. An unexpected syscall KILLs the
 * process; actx->confine_serving picks the wider allow-set (adds the socket
 * family) so a node doing real P2P/HTTPS/onion I/O is not SIGSYS-killed at its
 * first accept()/recv()/connect(); plain -confine keeps the strict set.
 * Refuse to HALF-apply: on a partway os_sandbox_enter() failure run the node
 * UNCONFINED and raise 'confine.apply_failed' (remedy OWNER — only an operator
 * can widen the allow-list / enable Landlock and restart) rather than leave a
 * partial sandbox; Landlock degrades gracefully on an older kernel (logged,
 * skipped). Every degrade path returns ZCL_OK, so the REQUEST is noted FIRST —
 * that is the only way the `confinement` witness tells "nobody asked" apart
 * from "asked, and running wide open anyway". */
static struct zcl_result sr_confine_enter(const struct app_context *actx)
{
    os_sandbox_note_requested(actx->confine_serving ? "node_confine_serving" : "node_confine");
    const char *datadir = actx->datadir ? actx->datadir : g_datadir;
    if (!datadir || !datadir[0]) {
        /* No datadir to scope: cannot confine safely. Run unconfined + name it. */
        struct blocker_record r;
        if (blocker_init(&r, "confine.apply_failed", "sandbox",
                         BLOCKER_PERMANENT,
                         "-confine requested but no datadir to grant; running "
                         "UNCONFINED (operator must fix the datadir + restart)"))
            (void)blocker_set(&r);
        LOG_WARN("sandbox", "-confine: no datadir to grant; running unconfined "
                 "(blocker confine.apply_failed raised)");
        return ZCL_OK;  /* NOT fatal: unconfined-but-loud, per the -confine contract */
    }

    int abi = os_sandbox_landlock_abi();
    bool seccomp_ok = os_sandbox_seccomp_supported();
    if (abi < 1 && !seccomp_ok) {
        /* Neither mechanism available on this kernel/build: degrade (log+skip),
         * do NOT raise a blocker — this is graceful degradation, not a failure
         * of an applicable request. */
        LOG_WARN("sandbox",
                 "-confine: neither Landlock (abi=%d) nor seccomp available on "
                 "this kernel/build; running unconfined (graceful degrade)", abi);
        return ZCL_OK;
    }

    char scratch[4][PATH_MAX];
    struct os_sandbox_path_rule rules[6];
    size_t n = sandbox_build_fs_rules(datadir, rules, 6, /*extra_ro=*/true,
                                      scratch, 4);

    struct os_sandbox_profile prof = actx->confine_serving
        ? os_sandbox_node_confine_serving_profile(rules, n)
        : os_sandbox_node_confine_profile(rules, n);
    struct zcl_result r = os_sandbox_enter(&prof);
    if (!r.ok) {
        /* Refuse to half-apply: run unconfined + raise the named blocker. Note:
         * a seccomp allow-list that KILLs mid-install would have taken the
         * process down already, so reaching here means an earlier builder
         * (no_new_privs/Landlock) failed cleanly and nothing partial is live. */
        struct blocker_record br;
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "os_sandbox_enter(%s) failed code=%d %s; running "
                 "UNCONFINED (operator must widen the allow-list / enable "
                 "Landlock and restart)",
                 actx->confine_serving ? "node_confine_serving" : "node_confine",
                 r.code, r.message[0] ? r.message : "?");
        if (blocker_init(&br, "confine.apply_failed", "sandbox",
                         BLOCKER_PERMANENT, reason))
            (void)blocker_set(&br);
        LOG_WARN("sandbox", "-confine apply failed (code=%d %s) — running "
                 "unconfined, blocker confine.apply_failed raised",
                 r.code, r.message);
        return ZCL_OK;  /* NOT fatal: the -confine contract is unconfined-but-loud */
    }
    printf("[boot] confine: entered '%s' profile (landlock_abi=%d, %zu fs "
           "grants, seccomp allow-list via %s)\n",
           os_sandbox_active_profile_name() ? os_sandbox_active_profile_name() : "?",
           abi, n, os_sandbox_seccomp_install_method());
    return ZCL_OK;
}

static struct zcl_result sr_sandbox_enter(void *ctx)
{
    const struct app_context *actx = ctx;
    if (!actx)
        return ZCL_OK;

    /* -confine: strict allow-list confinement (distinct from -sandbox=steady;
     * main.c refuses both at once). Unconfined-but-loud on apply failure. */
    if (actx->confine)
        return sr_confine_enter(actx);

    if (!actx->sandbox_steady)
        return ZCL_OK;  /* -sandbox=off (default): no confinement requested */

    os_sandbox_note_requested("node_steady_state");
    const char *datadir = actx->datadir ? actx->datadir : g_datadir;
    if (!datadir || !datadir[0])
        return ZCL_ERR(-1, "-sandbox=steady: no datadir to grant");

    char scratch[4][PATH_MAX];
    struct os_sandbox_path_rule rules[3];
    size_t n = sandbox_build_fs_rules(datadir, rules, 3, /*extra_ro=*/false,
                                      scratch, 4);

    struct os_sandbox_profile prof =
        os_sandbox_node_steady_state_profile(rules, n);
    struct zcl_result r = os_sandbox_enter(&prof);
    if (!r.ok) {
        fprintf(stderr,  // obs-ok:sandbox-enter-fatal-precedes-boot-fail
            "FATAL: -sandbox=steady requested but os_sandbox_enter failed: "
            "code=%d %s\n", r.code, r.message);
        return r;
    }
    printf("[boot] sandbox: entered '%s' profile (landlock_abi=%d, %zu fs grants)\n",
           os_sandbox_active_profile_name() ? os_sandbox_active_profile_name() : "?",
           os_sandbox_landlock_abi(), n);
    return ZCL_OK;
}

/* The boot boundary table. One record per line so the golden lint gate can
 * parse (stage, order, name) without a C compile. `order` reserves headroom
 * for future per-subsystem records at each boundary; the single record per
 * stage today keeps the sort trivial. */
static const struct sysinit_record k_boot_sysinit_records[] = {
    { .subsystem = "wallet",      .stage = BOOT_STAGE_WALLET_LOADED,      .order = 10, .init = sr_wallet_loaded,      .fini = NULL, .name = "wallet_loaded" },
    { .subsystem = "block_index", .stage = BOOT_STAGE_BLOCK_INDEX_LOADED, .order = 10, .init = sr_block_index_loaded, .fini = NULL, .name = "block_index_loaded" },
    { .subsystem = "chain",       .stage = BOOT_STAGE_CHAIN_TIP_RESOLVED, .order = 10, .init = sr_chain_tip_resolved, .fini = NULL, .name = "chain_tip_resolved" },
    { .subsystem = "net",         .stage = BOOT_STAGE_NETWORK_READY,      .order = 10, .init = sr_network_ready,      .fini = NULL, .name = "network_ready" },
    { .subsystem = "services",    .stage = BOOT_STAGE_SERVICES_RUNNING,   .order = 10, .init = sr_services_running,   .fini = NULL, .name = "services_running" },
    { .subsystem = "sandbox",     .stage = BOOT_STAGE_SERVICES_RUNNING,   .order = 90, .init = sr_sandbox_enter,      .fini = NULL, .name = "sandbox" },
};

static void boot_sysinit_register_all(void)
{
    for (size_t i = 0; i < sizeof(k_boot_sysinit_records) /
                           sizeof(k_boot_sysinit_records[0]); i++)
        (void)sysinit_register(&k_boot_sysinit_records[i]);
}

static void boot_stop_platform_services(void)
{
    zcl_service_kernel_stop_all(&g_maintenance_kernel);
    zcl_service_kernel_stop_all(&g_guard_kernel);
    zcl_service_kernel_reset(&g_maintenance_kernel);
    zcl_service_kernel_reset(&g_guard_kernel);
}

static bool boot_db_worker_service_init(struct zcl_service_kernel *kernel,
                                        void *ctx)
{
    (void)kernel;
    (void)ctx;
    return db_service_attach(&g_db_service, &g_node_db);
}

static bool boot_db_worker_service_start(void *ctx)
{
    (void)ctx;
    if (db_service_start(&g_db_service)) {
        memset(&g_boot_runtime, 0, sizeof(g_boot_runtime));
        g_boot_runtime.db_service = &g_db_service;
        app_runtime_set_current(&g_boot_runtime);
        return true;
    }
    return false;
}

static void boot_db_worker_service_stop(void *ctx)
{
    (void)ctx;
    db_service_stop(&g_db_service);
}

static bool boot_step_start_db_service(void)
{
    const struct zcl_service_spec db_spec = {
        .name = "db_service",
        .init = boot_db_worker_service_init,
        .start = boot_db_worker_service_start,
        .stop = boot_db_worker_service_stop,
    };

    zcl_service_kernel_init(&g_boot_db_kernel);
    return zcl_service_kernel_register(&g_boot_db_kernel, &db_spec) &&
           zcl_service_kernel_start_all(&g_boot_db_kernel);
}

void boot_stop_db_service_kernel(void)
{
    zcl_service_kernel_stop_all(&g_boot_db_kernel);
    zcl_service_kernel_reset(&g_boot_db_kernel);
}

/* Park the process alive-but-degraded after a boot-storage gate exhausted its
 * bounded re-derive budget. This is the TERMINATING end-state for a genuinely
 * unrecoverable local-storage corruption: the operator was paged ONCE (the
 * gate emitted EV_OPERATOR_NEEDED), and instead of _exit()ing into a
 * Restart=always crash-loop the process stays alive so the halt is observable
 * (the PID lock is held, the page stands) and never a silent power-cycle.
 * Blocks until a shutdown is requested (SIGTERM/SIGINT → the signal handler
 * calls thread_registry_request_shutdown), then returns false so the caller
 * exits cleanly. This converts "crash-loop" into "named blocker, parked", honouring
 * the stickiness law that a stall is never a silent stop. Never returns true.
 *
 * The wait condition is thread_registry_shutdown_requested() — the single
 * source of truth set by the SIGINT/SIGTERM handler installed in main() before
 * app_init (and re-installed inside it). It is NOT g_running (which is not yet
 * set true at the pre-services boot-storage gates). Polls on a short sleep so a
 * service-manager stop is honoured promptly. */
bool boot_park_until_shutdown(const char *gate_name)
{
    fprintf(stderr,
        "[boot] PARKED alive-degraded at gate '%s' — bounded re-derive budget "
        "exhausted; the operator was paged. NOT crash-looping; waiting for a "
        "shutdown signal.\n", gate_name ? gate_name : "boot_storage_gate");
    while (!thread_registry_shutdown_requested())
        sleep(2);
    return false;
}

/* lane/sapling-tree-persist: decide whether a persisted Sapling tree that
 * mismatches the CURRENT tip may still be trusted as an older-but-consistent
 * frontier, rather than treated as corrupt.
 *
 * A node_state["sapling_tree"] / flat-checkpoint blob mismatching the
 * current tip's hashFinalSaplingRoot is EXPECTED whenever any block was
 * applied after the tree was last persisted — that alone does not mean the
 * tree is wrong. Reuses the same pure verify-then-trust predicate the
 * flat-file checkpoint load path already trusts (sapling_ckpt_verify_binding,
 * lib/sapling/src/incremental_merkle_tree.c) against the tree's OWN claimed
 * height instead of the tip: if the tree's root matches hashFinalSaplingRoot
 * at `saved_height`, the caller may fold forward from saved_height+1 to tip
 * via sapling_tree_rebuild()'s existing checkpoint-resume path (bounded work
 * proportional to tip - saved_height) instead of a full from-activation
 * replay.
 *
 * Returns 1 when verified (safe to fold forward), 0 when there is no
 * `saved_height` to check (legacy datadir predating this key, or the tree
 * is already at/above tip — not an error, caller's existing fallback runs
 * unchanged), or -1 (via LOG_ERR, every relevant number logged) when
 * `saved_height` itself fails to verify — the "genuine corruption" case the
 * full-rebuild fallback must still catch. */
static int sapling_tree_verify_at_saved_height(
    const struct active_chain *chain,
    const struct uint256 *tree_root, size_t tree_size,
    int64_t saved_height, int tip_height)
{
    if (saved_height <= 476969 || saved_height >= tip_height)
        return 0;

    const struct block_index *saved_bi =
        active_chain_at(chain, (int)saved_height);
    static const uint8_t zeros32[32] = {0};
    bool hash_known = saved_bi && saved_bi->phashBlock;
    bool root_known = saved_bi && memcmp(saved_bi->hashFinalSaplingRoot.data,
                                         zeros32, 32) != 0;

    enum sapling_ckpt_verdict v = sapling_ckpt_verify_binding(
        saved_height, tree_root, NULL, tip_height,
        hash_known ? saved_bi->phashBlock->data : NULL, hash_known,
        root_known ? &saved_bi->hashFinalSaplingRoot : NULL, root_known);
    if (v == SAPLING_CKPT_OK)
        return 1;

    char expected_hex[65] = "unknown";
    char got_hex[65];
    uint256_get_hex(tree_root, got_hex);
    if (root_known)
        uint256_get_hex(&saved_bi->hashFinalSaplingRoot, expected_hex);
    LOG_ERR("sapling_tree",
            "verify_at_saved_height: verdict=%s expected_root=%s "
            "got_root=%s tree_size=%zu saved_h=%lld tip_h=%d",
            sapling_ckpt_verdict_str(v), expected_hex, got_hex, tree_size,
            (long long)saved_height, tip_height);
}

/* lane/sapling-tree-persist: given a verified older-but-consistent tree
 * (sapling_tree_verify_at_saved_height already returned 1 for this
 * saved_height), fold forward to tip via sapling_tree_rebuild()'s existing
 * checkpoint-resume path instead of a full from-activation rebuild. Reloads
 * g_state.sapling_tree from the rebuilt node_state on success. Returns true
 * only when the fold-forward fully completed and reloaded; false leaves
 * g_state.sapling_tree untouched so the caller's existing full-rebuild
 * fallback still runs. */
static bool sapling_tree_attempt_fold_forward(struct app_context *ctx,
                                              int tip_height, size_t old_size,
                                              int64_t saved_height)
{
    printf("Sapling tree verified at saved_h=%lld (size=%zu) — folding "
          "forward to tip_h=%d\n", (long long)saved_height, old_size,
          tip_height);
    fflush(stdout);
    atomic_store(&g_sapling_tree_rebuilding, true);

    bool folded = false;
    int fn = sapling_tree_rebuild(&g_node_db, &g_state.chain_active,
                                  g_datadir);
    if (fn >= 0) {
        uint8_t fbuf[8192];
        size_t flen = 0;
        if (node_db_state_get(&g_node_db, "sapling_tree", fbuf, sizeof(fbuf),
                              &flen) && flen > 0) {
            struct byte_stream fts;
            stream_init_from_data(&fts, fbuf, flen);
            sapling_tree_init(&g_state.sapling_tree);
            incremental_tree_deserialize(&g_state.sapling_tree, &fts);
            set_sapling_tree_for_flush(&g_state.sapling_tree);
            printf("Sapling tree folded forward: %d commitments (was %zu, "
                  "resumed from saved_h=%lld)\n", fn, old_size,
                  (long long)saved_height);
            folded = true;
        }
    }
    atomic_store(&g_sapling_tree_rebuilding, false);
    node_db_wal_checkpoint(&g_node_db);
    save_block_index_flat(ctx->datadir, &g_state);
    return folded;
}

bool app_init(struct app_context *ctx)
{
    int64_t t_boot_start = boot_clock_ms();
    int64_t t_phase;

    /* ── Move 5 boot checklist: prologue steps ───────────────────
     * Each step is a named static above. Failing steps return false
     * and the process exits non-zero — never partial-init state. */
    if (!boot_step_init_observability())
        return false;
    /* Register the declarative boot-stage boundary records before any
     * sysinit_run_stage() call below advances the stage machine. */
    boot_sysinit_register_all();
    if (!boot_step_select_chain_and_datadir(ctx))
        return false;
    if (!ctx->mint_anchor && !ctx->ratify_mint_anchor &&
        !ctx->export_consensus_bundle && !ctx->verify_consensus_bundle &&
        !ctx->verify_rom && !boot_mint_anchor_normal_boot_preflight(ctx->datadir))
        return false;
    if (!boot_refold_staged_preflight(ctx->refold_staged)) return false;
    const struct chain_params *params = chain_params_get();

    boot_postmortem_start(ctx->datadir);
    boot_shutdown_marker_detect_unclean(ctx->datadir);
    /* Tier-2 fast restart: arm node_db_open's quick_check-skip probe BEFORE
     * node.db opens (consumes the binding detect_unclean just cached). */
    boot_fast_restart_arm_quick_check_skip_probe();
    boot_step_start_disk_and_ibd_guards(ctx->datadir);

    if (!boot_step_init_crypto_and_state(ctx, params))
        return false;

    /* Timing only: the boot prologue (observability, chain/datadir select,
     * postmortem, unclean-shutdown detect, disk/IBD guards, crypto+state
     * init) as a named phase. */
    boot_topmark("prologue", t_boot_start);

    boot_stale_locks_preflight(ctx->datadir);

    /* Open SQLite node database */
    t_phase = boot_clock_ms();
    if (node_db_sync_init(&g_node_db, ctx->datadir)) {
        int migrate_rc = node_db_migrate(&g_node_db, ctx->datadir);
        if (migrate_rc == -2) {
            /* Schema downgrade refused — node_db_migrate has already
             * printed the operator-actionable explanation to stderr.
             * Bail before any wallet / chain logic runs so we don't
             * write through a schema we don't understand. */
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "node_db_schema_downgrade_refused rc=%d", migrate_rc);
            exit(1);
        }
        process_block_set_node_db(&g_node_db);
        if (!db_service_is_started(&g_db_service)) {
            if (!boot_step_start_db_service()) {
                fprintf(stderr,
                    "Warning: DB service unavailable during boot; "
                    "activation metadata writes will use direct SQLite\n");
            }
        }
        boot_stage_advance_to(BOOT_STAGE_DB_OPEN);
        int db_tip = node_db_sync_get_tip_height(&g_node_db);
        if (db_tip >= 0) {
            printf("SQLite tip: height=%d\n", db_tip);
            event_emitf(EV_BOOT_DB_OPEN, 0, "schema=%d tip=%d",
                        node_db_schema_version(&g_node_db), db_tip);
        }
        /* Bake the current schema version into the next clean-shutdown marker
         * (advisory field in the quick_check-skip binding). */
        boot_shutdown_marker_set_schema_version(
            node_db_schema_version(&g_node_db));
    } else {
        /* #7: every other boot-storage gate names a typed blocker and parks
         * alive-degraded on open failure; this one used to log a warning and
         * CONTINUE booting RAM-only. See boot_node_db_gate.c. */
        return boot_node_db_open_failed_gate(ctx->datadir);
    }
    boot_topmark("sqlite_open_migrate", t_phase);

    if (!boot_wallet_identity_ensure(&g_node_db, params->consensus.hashGenesisBlock.data, app_operator_lane_name(ctx->operator_lane))) return false;
    /* Initialize wallet AFTER node.db is open (g_node_db.open=true) and
     * BEFORE the block index load below — the latter is the only
     * ordering -importlegacy actually needs. Persisted wallet state
     * (keys, sapling keys, scripts, txs, scan height) lives in the
     * shared node.db tables wallet_keys / wallet_sapling_keys /
     * wallet_scripts / wallet_seed / wallet_watch_only /
     * wallet_transactions — there is intentionally no separate
     * wallet*.db. If this block ran before node.db was open (the prior
     * ordering bug), g_node_db.open was false, wallet_sqlite_open_r was
     * never called, every load/flush below silently no-op'd, and an
     * imported key or trial-decrypted note vanished on restart while the
     * STATE D/E/F abort guards (all conditioned on g_node_db.open) sat
     * dead. Opening node.db first makes the persistence layer and its
     * guards live.
     *
     * Wallet persistence boot state machine (per WALLET_PERSISTENCE_PLAN.md §7).
     *
     *   STATE A — node.db absent:          generate keypool, flush.
     *   STATE B — wallet_keys missing:     CREATE (done at DB open), flush.
     *   STATE C — wallet_keys non-empty, open OK:  load, canary, verify count.
     *   STATE D — wallet_keys non-empty, open FAILS: ABORT.
     *   STATE E — canary self-test fails on existing wallet:       ABORT.
     *   STATE F — loaded keystore count != on-disk row count:      ABORT.
     *
     * D/E/F are the paths the pre-fix code took silently, overwriting
     * the user's wallet with a fresh keypool. Refuse to do that here. */
    t_phase = boot_clock_ms();
    wallet_init(&g_wallet);
    boot_wallet_credential_register_or_die();
    /* OS-S2: bind the boot cursors to the tip_finalize reorg-rewind chokepoint
     * so a live reorg clamps them down (next boot re-derives above the fork). */
    if (g_node_db.open)
        boot_cursor_install_reorg_clamp(&g_node_db);

    /* Determine the on-disk wallet_keys row count BEFORE attempting to
     * open the wallet_sqlite subsystem. Used below for the abort
     * decisions — we only refuse to proceed when there's something to
     * lose. */
    int64_t pre_open_key_rows = 0;          /* 0 = empty; -1 = cannot determine */
    if (g_node_db.open) {
        sqlite3_stmt *wk_count = NULL;
        if (sqlite3_prepare_v2(g_node_db.db,
                "SELECT count(*) FROM wallet_keys",
                -1, &wk_count, NULL) == SQLITE_OK && wk_count) {
            if (AR_STEP_ROW_READONLY(wk_count) == SQLITE_ROW)
                pre_open_key_rows = sqlite3_column_int64(wk_count, 0);
            sqlite3_finalize(wk_count);
        } else {
            /* wallet_keys table absent — fell through to STATE B. */
            pre_open_key_rows = -1;
        }
    }

    /* Attempt to open — use the rich-error *_r API (Agent 2) so any
     * prepare failure carries a WSQL_* code + message + source
     * location we can surface in the abort diagnostic. */
    struct zcl_result wsql_open_r = {0};
    bool sqlite_open = false;
    if (g_node_db.open) {
        wsql_open_r = wallet_sqlite_open_r(&g_wallet_sqlite, g_node_db.db);
        sqlite_open = wsql_open_r.ok;
    }

    if (!sqlite_open && pre_open_key_rows > 0) {
        /* STATE D: wallet has user keys on disk but we cannot open the
         * persistence layer. The ONLY safe action is to refuse the
         * boot and preserve the datadir for the operator to
         * investigate. Silently generating a fresh keypool here is
         * what caused 0.4 ZCL to become unspendable. */
        boot_report_wallet_persistence_open_failed(
            ctx->datadir, &wsql_open_r, (long long)pre_open_key_rows);
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "wallet_persistence_open_failed code=%d rows=%lld",
                    wsql_open_r.code, (long long)pre_open_key_rows);
        exit(1);
    }
    if (sqlite_open) { /* STATE C: load everything. */
        {
            struct zcl_result _r = wallet_sqlite_read_keys_r(
                &g_wallet_sqlite, &g_wallet);
            if (!_r.ok) {
                fprintf(stderr,
                    "wallet_sqlite_read_keys failed: code=%d %s (%s:%d)\n",
                    _r.code, _r.message,
                    _r.source_file ? _r.source_file : "?", _r.source_line);
            }
        }
        boot_wallet_read_keypool_or_exit(&g_wallet_sqlite, &g_wallet);
        wallet_sqlite_read_txs(&g_wallet_sqlite, &g_wallet);
        wallet_rebuild_spent_set(&g_wallet);
        wallet_sqlite_read_sapling_keys(&g_wallet_sqlite, &g_wallet);
        boot_wallet_adopt_seed_if_it_governs(&g_wallet);
        wallet_sqlite_read_scripts(&g_wallet_sqlite, &g_wallet);
        wallet_sqlite_read_watch_only(&g_wallet_sqlite, &g_wallet);
        int saved_height = 0;
        if (wallet_sqlite_read_scan_height(&g_wallet_sqlite, &saved_height))
            g_wallet.best_block_height = saved_height;
        printf("Wallet loaded: %zu keys, %zu sapling keys, %zu scripts, "
               "%zu watch-only, %zu txs, scan height %d.\n",
               g_wallet.keystore.num_keys,
               g_wallet.sapling_keys.num_keys,
               g_wallet.keystore.num_scripts,
               g_wallet.keystore.num_watching,
               g_wallet.num_wallet_tx,
               g_wallet.best_block_height);
        /* Backward compat: an existing wallet opens regardless of the
         * at-rest policy, but without a passphrase its keys are plaintext
         * on disk — warn every boot rather than imply it is encrypted. */
        if (pre_open_key_rows > 0 &&
            wallet_at_rest_creation_policy() != WALLET_AT_REST_ENCRYPTED)
            fprintf(stderr, "WARNING: wallet private keys are stored "
                "UNENCRYPTED at rest in node.db (no ZCL_WALLET_PASSPHRASE); "
                "anyone with datadir read access can drain every coin.\n");
        /* STATE E: canary self-test. Writes then reads a fresh random
         * probe through the same sqlite handle the node will use for
         * user RPCs. A failure here is STATE E — if keys exist on
         * disk, abort rather than risk a silent overwrite. */
        struct wallet_canary_status cs;
        int crc = wallet_canary_run(g_node_db.db, &cs);
        if (crc != WALLET_CANARY_OK) {
            if (pre_open_key_rows > 0) {
                boot_report_wallet_canary_failed(
                    ctx->datadir, crc, cs.error,
                    (long long)pre_open_key_rows);
                event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                            "wallet_canary_failed code=%d rows=%lld",
                            crc, (long long)pre_open_key_rows);
                exit(1);
            }
            fprintf(stderr,
                "WARNING: wallet canary failed (code=%d): %s —"
                " continuing on empty wallet.\n", crc, cs.error);
        }

        /* STATE F: invariant — the keystore count loaded from disk
         * must equal the row count we observed before opening. A
         * mismatch means read_keys dropped rows or the table changed
         * under us. Either is a bug that would become silent data
         * loss on the next flush. */
        if (pre_open_key_rows > 0 &&
            (int64_t)g_wallet.keystore.num_keys != pre_open_key_rows) {
            boot_report_wallet_keystore_count_mismatch(
                ctx->datadir, (long long)pre_open_key_rows,
                g_wallet.keystore.num_keys);
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "wallet_keystore_count_mismatch rows=%lld loaded=%zu",
                        (long long)pre_open_key_rows,
                        g_wallet.keystore.num_keys);
            exit(1);
        }
        boot_wallet_migrate_envelopes_or_exit(ctx->datadir, &g_wallet_sqlite, &g_wallet);
        boot_wallet_top_up_legacy_keypool_or_exit(
            pre_open_key_rows, &g_wallet_sqlite, &g_wallet);
    } else {
        /* STATE A/B: new datadir, no user keys at risk. */
        printf("New wallet created.\n");
    }

    /* One-time wallet migration: if SQLite wallet is empty but LevelDB
     * wallet/ directory exists, import keys/txs from LevelDB. Only
     * runs when pre_open_key_rows <= 0 (no existing user keys), so no
     * conflict with the state machine. */
    if (g_wallet.keystore.num_keys == 0) {
        char wallet_path[1024];
        snprintf(wallet_path, sizeof(wallet_path), "%s/wallet", ctx->datadir);
        struct stat wst;
        if (stat(wallet_path, &wst) == 0) {
            struct wallet_db legacy_wdb;
            if (wallet_db_open(&legacy_wdb, wallet_path)) {
                printf("Migrating wallet from LevelDB...\n");
                wallet_db_read_keys(&legacy_wdb, &g_wallet);
                wallet_db_read_txs(&legacy_wdb, &g_wallet);
                wallet_rebuild_spent_set(&g_wallet);
                wallet_db_read_sapling_keys(&legacy_wdb, &g_wallet);
                wallet_db_read_scripts(&legacy_wdb, &g_wallet);
                int saved_height = 0;
                if (wallet_db_read_scan_height(&legacy_wdb, &saved_height))
                    g_wallet.best_block_height = saved_height;
                wallet_db_close(&legacy_wdb);

                /* Persist to SQLite and check the result — a silent
                 * failure here is exactly what the boot state machine's
                 * never-silent invariant forbids. */
                if (g_wallet_sqlite.open) {
                    struct zcl_result _r = wallet_sqlite_flush_r(
                        &g_wallet_sqlite, &g_wallet);
                    if (!_r.ok) {
                        fprintf(stderr,
                            "\nFATAL: LevelDB wallet migration flush failed.\n"
                            "       code=%d message=%s\n"
                            "       source=%s:%d\n"
                            "       REFUSING to proceed — keys would be RAM-only.\n\n",
                            _r.code, _r.message,
                            _r.source_file ? _r.source_file : "?",
                            _r.source_line);
                        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                                    "wallet_migration_flush_failed code=%d",
                                    _r.code);
                        exit(1);
                    }
                }

                printf("Wallet migrated: %zu keys, %zu sapling keys\n",
                       g_wallet.keystore.num_keys,
                       g_wallet.sapling_keys.num_keys);
            }
        }
    }

    if (g_wallet.keystore.num_keys == 0) {
        /* Genuinely empty wallet — first-run. A wallet decision must NOT be a
         * precondition for syncing, and plaintext keys must NEVER be minted
         * silently. So REFUSE (no passphrase, no -allow-plaintext-wallet opt-in
         * on a canonical/unknown node) means "boot KEYLESS (no-spend) and sync"
         * — mint nothing; only an explicit passphrase (encrypt) or opt-in
         * (plaintext) mints a keypool. */
        enum wallet_boot_wallet_action act =
            wallet_at_rest_boot_decision(wallet_at_rest_creation_policy(),
                                         ctx->mint_anchor, ctx->operator_lane);
        wallet_at_rest_boot_report(act, ctx->operator_lane);
        if (act == WALLET_BOOT_REFUSE) {
            /* No-spend: sync now (NAMED via EV_BOOT_PHASE), never a required flag. */
            event_emitf(EV_BOOT_PHASE, 0, "wallet_no_spend keyless_sync");
            printf("Wallet: NO-SPEND mode (0 keys) — syncing.\n");
        } else if (!boot_wallet_create_new(&g_wallet, &g_wallet_sqlite,
                                           &g_node_db, act,
                                           ctx->operator_lane)) {
            exit(1);   /* refusal already NAMED its blocker in the beacon */
        }
    }
    printf("Wallet has %zu keys.\n", g_wallet.keystore.num_keys);
    boot_topmark("wallet_load", t_phase);

    /* WALLET_LOADED: keys read + canary passed, or a keypool was generated. */
    {
        struct zcl_result wr = sysinit_run_stage(BOOT_STAGE_WALLET_LOADED, ctx);
        if (!wr.ok) return false;
    }

    /* Upload the onion descriptor in parallel with block-index hydration. */
    if (!ctx->no_services) (void)boot_onion_tor_start_early(ctx);

    /* Keep staged-sync cursors in progress.kv, independent of node.db. */
    bool progress_open = progress_store_open(ctx->datadir);
    boot_snapshot_install_gate_boot(progress_open, ctx->load_snapshot_at_own_height);
    if (progress_open) {
        /* Wave A3 flip, second half: progress_store_open() already migrated a
         * legacy progress.kv kernel into consensus.db and opened it. Prune the
         * migrated tables from progress.kv + stamp the flip marker. Idempotent,
         * crash-safe, NON-fatal — consensus.db is the sole authority regardless;
         * the next boot retries. */
        char flip_err[256] = "";
        if (!consensus_db_finalize_flip(ctx->datadir, progress_store_db(),
                                        flip_err, sizeof(flip_err)))
            fprintf(stderr,  // obs-ok:helper-context-logged
                    "[boot] consensus.db flip finalize deferred: %s\n",
                    flip_err[0] ? flip_err : "(no message)");
        if (!ctx->mint_anchor && !ctx->ratify_mint_anchor &&
            !ctx->export_consensus_bundle && !ctx->verify_consensus_bundle &&
            !ctx->verify_rom && !boot_mint_anchor_normal_boot_gate(progress_store_db()))
            return false;
        /* Restore the prior operational mode (non-fatal; boot overwrites below). */
        (void)service_state_restore_from_progress_store();
        /* Refresh BOTH refold caches (refold_in_progress + refold_from_anchor,
         * B2) from the durable progress.kv keys — a mid-fold restart resumes the
         * correct floor without re-running the reset. mark_started here is the
         * from-GENESIS arm only (refold_staged); the from-ANCHOR mark is set
         * inside boot_refold_from_anchor_reset below. */
        boot_refold_staged_init(ctx->refold_staged);  /* cache refold_in_progress + refold_from_anchor */
    }

    /* Snapshot-first: if a downloaded consensus_snapshot.db
     * is present in the datadir, import its UTXOs into node.db *before*
     * any chain-tip restoration runs. This makes coins_best_block
     * resolve to the snapshot height when the coins view first reads
     * it, so utxo_recovery_restore_chain_tip / chain_restore_finalize
     * observe the snapshot anchor as ground truth instead of racing
     * past it with the older block_index.bin tip and leaving utxos=0.
     *
     * Idempotent: the helper refuses to import if main.utxos already
     * holds the snapshot's contents (handled by checking the source
     * file's integrity + size; a re-run with utxos>1000 is a no-op via
     * the export guard in consensus_snapshot_export_service_run_bound). */
    /* Timing only: the stretch to the block_index_load marker (~1.3–13s warm)
     * had no markers — attribute its heaviest steps via boot_submark(). */
    int64_t t_sub = boot_clock_ms();

    if (g_node_db.open) {
        char snap_path[PATH_MAX];
        int sp_n = snprintf(snap_path, sizeof(snap_path),
                            "%s/consensus_snapshot.db", ctx->datadir);
        if (sp_n > 0 && (size_t)sp_n < sizeof(snap_path)) {
            struct stat sp_st;
            if (stat(snap_path, &sp_st) == 0 &&
                sp_st.st_size > (off_t)(10 * 1024 * 1024)) {
                /* Wave 2: the canonical coin count lives in coins_kv;
                 * the node.db mirror count is the legacy fallback. */
                int64_t existing = coins_kv_count(progress_store_db());
                if (existing <= 0)
                    existing = node_db_utxo_count(&g_node_db);
                if (existing > 1000) {
                    printf("[boot] consensus_snapshot.db present "
                           "(%.0f MB) — node.db already has %lld UTXOs, "
                           "skipping pre-restore import\n",
                           (double)sp_st.st_size / (1024.0 * 1024.0),
                           (long long)existing);
                    chain_restore_record_snapshot_import(
                        true, existing, -1);
                } else {
                    int64_t imp_utxos = 0, imp_height = 0;
                    uint8_t imp_best[32] = {0};
                    bool ok = boot_import_snapshot_db(&g_node_db,
                                                     snap_path,
                                                     &imp_utxos,
                                                     &imp_height,
                                                     imp_best);
                    chain_restore_record_snapshot_import(
                        ok, imp_utxos, imp_height);
                    event_emitf(EV_BOOT_UTXO_IMPORT, 0,
                                "phase=pre-restore ok=%d utxos=%lld "
                                "height=%lld",
                                ok ? 1 : 0,
                                (long long)imp_utxos,
                                (long long)imp_height);
                    if (ok)
                        printf("[boot] snapshot-first import OK: "
                               "%lld UTXOs at h=%lld — chain restore "
                               "will observe snapshot anchor\n",
                               (long long)imp_utxos,
                               (long long)imp_height);
                    else
                        fprintf(stderr,  // obs-ok:helper-context-logged
                                "[boot] snapshot-first import failed "
                                "for %s — falling through to block-by-block "
                                "IBD path\n", snap_path);
                }
            }
        }
    }

    t_sub = boot_submark("coins.snapshot_first", t_sub);

    /* -snapshot: Create snapshot of legacy data dir, import in parallel,
     * then start normally with P2P sync to catch up any delta. */
    if (ctx->snapshot_dir) {
        if (!g_node_db.open) {
            fprintf(stderr, "Error: SQLite database required for snapshot\n");
            return false;
        }

        /* Step 1: Create snapshot (hardlink block files, copy LevelDB) */
        const char *snap = snapshot_create(ctx->snapshot_dir,
                                           ctx->datadir, 2);
        if (!snap) {
            fprintf(stderr, "Error: Failed to create snapshot\n");
            return false;
        }

        /* Step 2: Parallel import (block index + UTXOs + wallet) */
        if (snapshot_import(snap, ctx->datadir,
                            &g_node_db, &g_wallet) < 0) {
            fprintf(stderr, "Warning: Snapshot import had errors\n");
        }

        /* Step 3: Build transaction index after runtime services take
         * ownership of background jobs, so shutdown can join it cleanly. */
    }

    /* Open block index database after removing stale filesystem artifacts left
     * behind by interrupted legacy import/copy paths. */
    char blocktree_path[1024];
    struct boot_blocktree_cleanup_result blocktree_cleanup =
        boot_blocktree_cleanup_prepare(ctx->datadir, blocktree_path,
                                       sizeof(blocktree_path));
    if (!blocktree_cleanup.blocktree_path_ready)
        fprintf(stderr, "Warning: block tree path unavailable for datadir %s\n",
                ctx->datadir ? ctx->datadir : "(null)");
    if (block_tree_db_open(&g_block_tree, blocktree_path,
                           256 << 20, false, false)) {
        g_block_tree_open = true;
        g_active_block_tree = &g_block_tree;
    } else {
        fprintf(stderr, "Warning: Could not open block tree DB at %s\n",
                blocktree_path);
    }

    /* Open coins view on the SHARED sqlite3 handle.
     * Both node_db and coins_view_sqlite use the same connection.
     * Transaction coordination is handled by flush_coins_if_needed
     * which commits node_db's batch before the coins flush runs
     * its own BEGIN/COMMIT. One connection = no WAL lock contention. */
    if (g_node_db.open) {
        /* Sticky boot (#6 — B1 fix): CONSUME a prior boot's crash-only reindex
         * request HERE, before the coins-clear and the coins-view integrity
         * gate. boot_crashonly_storage_gate() (the coins_view / progress_kv /
         * block_index gates below) records a -reindex-chainstate request and
         * exits; the NEXT boot must turn that request into an ACTUAL reindex.
         * MUST run before the coins-view gate: consuming up front sets
         * ctx->reindex_chainstate so (1) boot_index_clear_coins_state wipes the
         * stale/torn coins state, (2) coins_view_sqlite_open then opens cleanly
         * (the gate does not re-fire), and (3) reindex_chainstate(...) actually
         * re-derives the UTXO set from blocks/ at the post-block-index site.
         * The request file is a top-level sentinel (no DB needed), so it is safe
         * to read before the coins view opens. */
        if (!ctx->reindex_chainstate) {
            struct boot_derived_coins_best pre_reindex_dcb;
            if (boot_derive_coins_best(&pre_reindex_dcb)) {
                (void)boot_crashonly_clear_reindex_request_if_covered(
                    ctx->datadir, pre_reindex_dcb.height,
                    pre_reindex_dcb.hash_found);
            }
            if (boot_crashonly_consume_reindex_request(ctx->datadir))
                ctx->reindex_chainstate = true;
        }

        /* -reindex-chainstate explicitly rebuilds the UTXO set from on-disk
         * block data, discarding the stored coins state. Clear that state
         * BEFORE the coins-integrity gate runs — otherwise a torn coins anchor
         * FATAL-halts boot before reindex_chainstate (which
         * performs the same wipe idempotently, ~line 2539) can run the rebuild
         * the operator asked for. Guarded strictly on the explicit request: a
         * normal boot never wipes a recoverable coins set here. */
        /* Verb check BEFORE the wipe (never wipe state we cannot rebuild from
         * local inputs): a from-genesis replay needs genesis-side block data.
         * On a cold-import / bodyless datadir the wipe would delete the coins
         * mirror + anchors and then reindex_chainstate's own verb check would
         * refuse — leaving nothing to fold forward from. Skip the early clear
         * there; the mirror is preserved and the reducer reconciles forward. */
        if (ctx->reindex_chainstate) {
            if (!boot_index_reindex_replay_executable(&g_state, &g_block_tree,
                    g_block_tree_open, ctx->datadir))
                fprintf(stderr,
                    "[boot] -reindex-chainstate: genesis-side block data "
                    "unreadable (cold-import window) — NOT clearing coins state "
                    "before the verb check; preserving the seed to fold "
                    "forward\n");
            else if (boot_index_clear_coins_state(&g_node_db))
                fprintf(stderr,
                    "[boot] -reindex-chainstate: cleared coins state before the "
                    "integrity gate; UTXO set will be rebuilt from block data\n");
        }
        /* Wave 2: on canonical datadirs (coins_applied_height present) the
         * coins-best fact is DERIVED from coins_kv's own co-committed state —
         * the legacy anchor caches cannot wedge boot, so the legacy repair
         * rungs (stale-cursor repair W4, torn-anchor heal W5 — both
         * node_state-key writers) are skipped entirely. Legacy datadirs keep
         * both rungs unchanged. */
        struct boot_derived_coins_best boot_dcb;
        bool boot_dcb_found = boot_derive_coins_best(&boot_dcb);
        if (boot_dcb_found)
            printf("[boot] derived coins-best h=%d hash_found=%d (coins_kv "
                   "authority) — skipping legacy anchor-repair rungs\n",
                   boot_dcb.height, boot_dcb.hash_found ? 1 : 0);
        else
            (void)utxo_recovery_repair_stale_cursor_from_sync_projection(
                &g_node_db);
        /* On open failure, try L1 torn-legacy-coins recovery (§3 dual-store
         * tear, utxo_recovery_torn_anchor.c — reset-safe, refuses unless
         * coins_kv is the proven authority, so the FATAL never weakens), then
         * retry. If neither path recovers, refuse to start with a crash event. */
        if (!coins_view_sqlite_open(&g_coins_sqlite, g_node_db.db) &&
            !(!boot_dcb_found &&
              utxo_recovery_heal_torn_legacy_coins_anchor(
                  &g_node_db, progress_store_db(), ctx->datadir) &&
              coins_view_sqlite_open(&g_coins_sqlite, g_node_db.db))) {
            fprintf(stderr,
                "WARNING: coins view integrity check failed — the "
                "UTXO set is inconsistent with the stored tip anchor and the "
                "auto-rewind guard did not recover it. Entering bounded "
                "crash-only re-derive instead of FATAL-crash-looping.\n");
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "coins_view tip mismatch exceeds auto-rewind guard");
            /* Sticky boot (#6 — B1): if a reindex is ALREADY in flight (this is
             * the consuming boot), do NOT re-arm the gate — the coins clear ran
             * just above and the reindex_chainstate execution below re-derives
             * the UTXO set from blocks/. Re-requesting here would exit before
             * the reindex runs and dead-end the bounded ladder. Just continue. */
            if (!ctx->reindex_chainstate) {
                /* A derived coins-view incoherence is the reindex-recoverable
                 * class — re-derive the UTXO set from blocks/ via a bounded
                 * -reindex-chainstate request rather than _exit()ing into a
                 * Restart=always crash-loop. While the budget allows, exit
                 * cleanly so the restart consumes the request and rebuilds; once
                 * exhausted, park alive-degraded (paged once), never power-cycle. */
                if (boot_crashonly_storage_gate(ctx->datadir,
                        "coins_view_integrity",
                        boot_index_reindex_replay_executable(&g_state,
                            &g_block_tree, g_block_tree_open, ctx->datadir))
                        == BOOT_GATE_PARK_DEGRADED)
                    return boot_park_until_shutdown("coins_view_integrity");
                return false;
            }
            /* Reindex pending but the coins view STILL won't open even after the
             * clear — without g_coins_sqlite.db the reindex below cannot run.
             * Park (paged) rather than continue into a NULL-coins reindex. */
            fprintf(stderr, "[boot] coins_view_integrity: open failed even with "
                    "reindex pending — parking alive-degraded.\n");
            (void)boot_auto_reindex_mark_terminal(ctx->datadir, 0);
            event_emitf(EV_OPERATOR_NEEDED, 0,
                "condition=coins_view_open_failed_under_reindex");
            return boot_park_until_shutdown("coins_view_integrity");
        }
    }

    t_sub = boot_submark("coins.view_open_gate", t_sub);

    /* One-time migration: import UTXOs from LevelDB chainstate into SQLite.
     * The old LevelDB had the authoritative UTXO set; SQLite's utxos table
     * may be incomplete. Check for migration flag in node_state. */
    if (g_node_db.open && g_coins_sqlite.db) {
        /* Do not seed coins_best_block from the sync projection cursor.
         * Only do this if UTXOs exist AND no LDB chainstate is available.
         * If chainstate/ exists, the LDB import will set coins_best_block
         * correctly — seeding from a projection cursor would create a mismatch
         * (UTXO data from LDB height ~3M labeled as chain tip ~2M). */
        struct boot_derived_coins_best seed_dcb;
        if (boot_derive_coins_best(&seed_dcb)) {
            /* Canonical datadir: the unset/stale cache key is irrelevant —
             * the coins-best fact is derived. Nothing to seed or refuse. */
            printf("[boot] coins_best_block cache check skipped — derived "
                   "coins-best h=%d (coins_kv authority)\n", seed_dcb.height);
        } else {
            struct uint256 coins_check;
            memset(&coins_check, 0, sizeof(coins_check));
            if (!coins_view_sqlite_get_best_block(&g_coins_sqlite,
                                                  &coins_check)
                || uint256_is_null(&coins_check)) {
                /* Check if LDB chainstate exists — if so, skip the seed
                 * and let LDB import set coins_best_block properly. */
                char cs_path[576];
                snprintf(cs_path, sizeof(cs_path), "%s/chainstate",
                         ctx->datadir);
                struct stat cs_st;
                bool has_chainstate = (stat(cs_path, &cs_st) == 0 &&
                                        S_ISDIR(cs_st.st_mode));
                int64_t utxo_count = node_db_utxo_count(&g_node_db);
                if (has_chainstate)
                    printf("[boot] chainstate/ exists — skipping "
                           "coins_best_block seed (LDB import will set it)\n");
                else if (utxo_count > 0)
                    printf("[boot] coins_best_block is unset with %lld "
                           "UTXOs; refusing to seed it from sync "
                           "projection\n", (long long)utxo_count);
            }
        }

        /* Auto-recovery: check for needs_reimport flag */
        if (utxo_reimport_flag_check_and_clear(ctx->datadir))
            ctx->reimport_utxos = true;

        /* (Crash-only reindex request is consumed EARLIER, above the coins
         * clear + the coins-view integrity gate — see boot_index.c reorder
         * note near the block-index open. Consuming it here would be too late:
         * the coins-view gate already ran and would re-fire before the reindex,
         * dead-ending the bounded re-derive ladder.) */

        /* -reimport-utxos: force re-import from LevelDB chainstate */
        if (ctx->reimport_utxos) {
            if (!utxo_recovery_prepare_reimport(&g_node_db).ok)
                ctx->reimport_utxos = false;
        }

        /* LDB UTXO import deferred to post-block-index (see below). */
    }

    /* coins_kv-backed read authority: the coins_tip RAM cache resolves
     * misses against coins_kv (canonical UTXO set in progress.kv), authored
     * in-txn by the reducer so it is atomically consistent with the stage
     * cursor on every crash — durability a separate-WAL projection lacks,
     * which is what guards against the tip-wedge tear class.
     * We open + publish the event_log here (no-op reuse of the later
     * boot_start_projection_storage open) so the singleton is available before
     * the coins read view + the other projections bind. FATAL only if
     * progress.kv (the coins_kv home) is not open — coins_view_kv binds
     * progress_store_db() lazily at read time. */
    (void)boot_ensure_event_log(ctx->datadir);
    if (!progress_store_db() ||
        !coins_view_kv_init(&g_coins_read_view)) {
        fprintf(stderr,
                "WARNING: progress.kv (coins_kv) not open; cannot serve coins "
                "reads. Entering bounded crash-only re-derive instead of "
                "FATAL-crash-looping.\n");
        event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                    "coins_kv unavailable for coins read view");
        /* Sticky boot (#6): progress.kv (the coins_kv home) failing to open is
         * NOT in-process reindex-recoverable — reindex_epilogue_derive REQUIRES
         * progress_store_db() to be open to reseed coins_kv, and continuing here
         * would also use an uninitialized read view. So drive the bounded ladder
         * directly: request -reindex-chainstate and exit while the budget allows
         * (the next boot retries the open after the restart re-opens progress.kv),
         * and once the shared boot-storage budget is exhausted PARK alive-degraded
         * (paged once). This does NOT dead-end: even on the consuming boot the
         * gate re-fires and counts a strike against the SAME episode anchor (0),
         * so it climbs 1→2→3 and parks rather than _exit()ing into a crash-loop.
         * The reindex sentinel is harmless if progress.kv later opens — it is
         * consumed up front and the reindex_chainstate execution rebuilds. */
        if (boot_crashonly_storage_gate(ctx->datadir, "progress_kv_open",
                boot_index_reindex_replay_executable(&g_state, &g_block_tree,
                    g_block_tree_open, ctx->datadir))
                == BOOT_GATE_PARK_DEGRADED)
            return boot_park_until_shutdown("progress_kv_open");
        return false;
    }
    coins_view_cache_init(&g_coins_tip, &g_coins_read_view.view);

    /* Hoist the block_index_projection open next to the event-log open
     * so load_block_index_from_projection (under -rebuildfromlog) has the
     * caught-up projection available BEFORE the block-index load below.
     * The phase-4 fan-out re-call in
     * boot_start_projection_storage is a no-op reuse (first opener wins).
     * Non-fatal if it cannot open: -rebuildfromlog simply falls through to
     * the legacy loaders. */
    (void)boot_ensure_block_index_projection(ctx->datadir);

    /* Wire the process-lifetime chain_state_repository singleton now
     * that g_coins_tip is alive. From this point on, call-site
     * migrations can go through csr_commit_tip() and get all six
     * sources of truth updated atomically under one mutex. Wallet
     * scan height is unwired (NULL) — the wallet manages its own
     * scan state and must not be driven through the repository. */
    csr_init(csr_instance(),
             &g_state.map_block_index,
             &g_state.chain_active,
             &g_state.pindex_best_header,
             &g_coins_tip,
             &g_node_db,
             NULL);
    csr_set_db_service(csr_instance(), &g_db_service);

    /* Wire UTXO commitment: load from SQLite and set pointer for
     * persistence on flush. */
    set_coins_sqlite_for_commitment(&g_coins_sqlite);
    if (coins_view_sqlite_read_commitment(&g_coins_sqlite, &g_coins_tip.commitment)) {
        printf("Loaded UTXO commitment from SQLite (count=%llu)\n",
               (unsigned long long)g_coins_tip.commitment.count);
    }

    /* skip_activate removed — activation controller is the authority */
    bool fast_restart = false;
    /* Set true if the block index + tip were rebuilt purely from the
     * log-derived projection (-rebuildfromlog). Function-scoped so the
     * legacy UTXO importer block below can also be skipped. */
    bool rebuilt_from_log = false;
    bool boot_restored_authority_tip = false;
    int boot_restored_authority_height = -1;
    struct uint256 boot_restored_authority_hash;
    memset(&boot_restored_authority_hash, 0, sizeof(boot_restored_authority_hash));

    /* Block index is now cached in SQLite (load_block_index_sqlite).
     * The full index is saved on shutdown/save, enabling instant restart
     * without the 10-15s LevelDB scan. */

    t_sub = boot_submark("coins.readview_csr", t_sub);

    /* OOM protection: estimate block index memory before loading.
     * Warn if it would exceed 50% of system RAM. */
    {
        int64_t est_count = g_node_db.open
            ? db_block_max_height(&g_node_db)
            : 0;
        boot_block_index_memory_warn(est_count);
    }

    (void)boot_submark("blkidx.mem_estimate", t_sub);

    /* Block index load: flat file first (mmap, <2s), then SQLite, then LevelDB.
     * Jeff Dean rule: use the fastest data structure available. */
    t_phase = boot_clock_ms();
    {
        struct boot_blkidx_load_ctx blkidx = {
            .ctx = ctx, .st = &g_state, .ndb = &g_node_db, .params = params,
            .block_tree = &g_block_tree, .block_tree_open = g_block_tree_open,
        };
        /* Ordered block-index load ladder (projection rebuild -> flat ->
         * sqlite -> kill-9 projection rebuild -> flat-union taint check ->
         * blocks-table hydrate -> LevelDB). The rung table + the
         * flat_union_tainted guard live in config/src/boot_blkidx_ladder.c
         * (E1 seam); the loader functions are unchanged. Per-rung fire
         * counters: `ops state --subsystem=block_index_load_rungs`. */
        boot_blkidx_run_ladder(&blkidx);
        rebuilt_from_log = blkidx.rebuilt_from_log;

        /* If block index is much smaller than the chain, try loading
         * from zclassicd's LevelDB. This gives us 3M+ entries with
         * correct heights and pprev chains in seconds. Triggers when
         * we have <10% of expected entries (e.g., 3K vs 3M chain).
         * Skipped on the log-rebuild path: the log/projection is the sole
         * authority there, so no legacy LevelDB read is performed. */
        if (!rebuilt_from_log && !ctx->no_legacy_auto_import) {
            int chain_h = active_chain_height(&g_state.chain_active);
            if (chain_h < 1000) {
                /* Estimate expected height from SQLite or coins */
                int64_t db_h = g_node_db.open ? db_block_max_height(&g_node_db) : 0;
                if (db_h > chain_h) chain_h = (int)db_h;
            }
            /* Legacy source probe, hoisted: feeds need_zcd + the LevelDB open. */
            const char *home = getenv("HOME");
            char zcd_idx_path[1024];
            if (home)
                snprintf(zcd_idx_path, sizeof(zcd_idx_path),
                         "%s/.zclassic/blocks/index", home);
            else
                snprintf(zcd_idx_path, sizeof(zcd_idx_path),
                         ".zclassic/blocks/index");
            struct stat zcd_st;
            bool legacy_source_present = (stat(zcd_idx_path, &zcd_st) == 0);
            /* Ratio or empty-datadir trigger — see boot_need_legacy_header_pull. */
            bool need_zcd = boot_need_legacy_header_pull(
                (int64_t)g_state.map_block_index.size, (int64_t)chain_h, legacy_source_present);
        if (need_zcd) {
            /* Derive our OWN coins frontier up front. The zclassicd LevelDB
             * index tops out at zclassicd's own tip; if our derived frontier
             * is STRICTLY above it, promoting/saving zclassicd's best would
             * commit the public tip BACKWARD below our frontier — a downshift
             * that detaches our coins-best block, forces a window re-chase,
             * and latches contradiction_frozen. We STILL import the index for
             * the 0..zcd-tip ANCESTRY (so the detached block gets a real pprev
             * root), but suppress the backward tip COMMIT. (We still save the
             * resulting flat — it is now ENRICHED with that ancestry and
             * carries no tip field, so persisting it is desirable.) Key
             * strictly on '>' so a legitimate fresh fast-cold-sync (at/below
             * zclassicd) and a legacy datadir (no derived frontier) promote
             * normally. */
            struct boot_derived_coins_best ndcb;
            bool have_ndcb = boot_derive_coins_best(&ndcb);

            if (legacy_source_present) {
                printf("Loading block index from zclassicd LevelDB: %s\n",
                       zcd_idx_path);
                fflush(stdout);

                /* Build a snapshot dir so we can open the LevelDB even
                 * while a live zclassicd holds the source LOCK.
                 * Hardlinks the immutable .ldb SST files + copies the
                 * small MANIFEST/CURRENT/LOG metadata + gives the
                 * snapshot a fresh empty LOCK (distinct fcntl context).
                 * See lib/storage/src/ldb_snapshot.c for the rationale. */
                char snap_path[1200];
                snprintf(snap_path, sizeof(snap_path),
                         "%s/.legacy_ldb_snap", ctx->datadir);
                char snap_err[256] = {0};
                bool snap_ok = false;
                for (int snap_try = 0; snap_try < 3 && !snap_ok; snap_try++) {
                    snap_ok = ldb_snapshot_make(zcd_idx_path, snap_path,
                                                snap_err, sizeof(snap_err));
                    if (!snap_ok &&
                        strcmp(snap_err, "manifest_changed") != 0)
                        break;
                }
                const char *open_path = snap_ok ? snap_path : zcd_idx_path;
                if (!snap_ok) {
                    fprintf(stderr,
                            "[boot] ldb_snapshot_make(%s) failed: %s; "
                            "falling back to direct open (may unlink "
                            "stale LOCK)\n", zcd_idx_path, snap_err);
                    /* Fallback path for a crashed zclassicd whose LOCK
                     * is stale: unlink it and open directly. Only used
                     * when the snapshot path itself fails. */
                    char lock_path[1300];
                    snprintf(lock_path, sizeof(lock_path),
                             "%s/LOCK", zcd_idx_path);
                    unlink(lock_path);
                }

                struct block_tree_db zcd_btdb;
                int64_t t0 = (int64_t)platform_time_wall_time_t();
                if (block_tree_db_open(&zcd_btdb, open_path,
                                       450 << 20, false, false)) {
                    if (block_tree_db_load_block_index_guts(
                            &zcd_btdb, boot_insert_block_index_cb, &g_state)) {
                        int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
                        printf("Loaded %zu block index entries from zclassicd "
                               "in %llds\n",
                               g_state.map_block_index.size,
                               (long long)elapsed);

                        /* Option A: re-seed per-node hash storage and point
                         * phashBlock at it (boot_insert_block_index_cb ->
                         * chainstate_insert_block_index already does this at
                         * insert; idempotent re-assert here). Never points
                         * into the reallocatable bucket array. */
                        size_t iter2 = 0;
                        struct block_index *pi2;
                        const struct uint256 *hash2;
                        while (block_map_next(&g_state.map_block_index,
                                              &iter2, &hash2, &pi2))
                            if (pi2 && hash2) {
                                pi2->hashBlock = *hash2;
                                pi2->phashBlock = &pi2->hashBlock;
                            }

                        /* Compute chain work + set chain tip directly.
                         * This avoids the O(n^2) find_most_work_chain scan
                         * which is catastrophically slow with 3M entries. */
                        {
                            size_t n = g_state.map_block_index.size;
                            struct block_index **sorted = zcl_malloc(
                                n * sizeof(struct block_index *), "boot.chainwork_sorted");
                            if (sorted) {
                                size_t si = 0, idx2 = 0;
                                struct block_index *sp;
                                while (block_map_next(&g_state.map_block_index,
                                                      &si, NULL, &sp))
                                    if (sp && idx2 < n) sorted[idx2++] = sp;
                                n = idx2;
                                qsort(sorted, n, sizeof(*sorted),
                                      cmp_block_index_height);

                                /* Forward pass: compute nChainWork + nChainTx */
                                struct block_index *best = NULL;
                                for (size_t i = 0; i < n; i++) {
                                    struct block_index *b = sorted[i];
                                    struct arith_uint256 proof = GetBlockProof(b);
                                    if (b->pprev)
                                        arith_uint256_add(&b->nChainWork,
                                            &b->pprev->nChainWork, &proof);
                                    else
                                        b->nChainWork = proof;

                                    if (b->nTx > 0) {
                                        if (b->pprev && b->pprev->nChainTx > 0)
                                            b->nChainTx = b->pprev->nChainTx + b->nTx;
                                        else if (!b->pprev)
                                            b->nChainTx = b->nTx;
                                    }

                                    /* Track best valid chain tip */
                                    if (b->nChainTx > 0 &&
                                        (b->nStatus & BLOCK_HAVE_DATA) &&
                                        !(b->nStatus & BLOCK_FAILED_MASK)) {
                                        if (!best || arith_uint256_compare(
                                                &b->nChainWork,
                                                &best->nChainWork) > 0)
                                            best = b;
                                    }
                                }
                                free(sorted);

                                if (best && best->nHeight > 0) {
                                    int32_t zcd_best_h = best->nHeight;
                                    if (have_ndcb &&
                                        ndcb.height > zcd_best_h) {
                                        /* Our derived frontier is ahead of
                                         * zclassicd's index — do NOT commit the
                                         * tip backward. Ancestry is already
                                         * imported; the downstream restore
                                         * utxo_recovery_restore_chain_tip
                                         * (reason coins_best_restore, later in
                                         * this boot) promotes our real derived
                                         * tip from the same coins authority. */
                                        fprintf(stderr,
                                            "[boot] suppressing "
                                            "zclassicd_import_best tip commit: "
                                            "derived coins-best h=%d > zclassicd "
                                            "index-best h=%d (would commit tip "
                                            "backward below our frontier)\n",
                                            ndcb.height, zcd_best_h);
                                        event_emitf(EV_RECOVERY_ACTION, 0,
                                            "action=zcd_import_tip_suppressed "
                                            "derived=%d zcd_best=%d",
                                            ndcb.height, zcd_best_h);
                                    } else if (boot_promote_tip_via_csr(
                                                   best, "zclassicd_import_best",
                                                   false)) {
                                        printf("Chain tip from zclassicd: "
                                               "height=%d nChainTx=%u\n",
                                               best->nHeight, best->nChainTx);
                                    }
                                }
                            }
                        }

                        /* Save flat file for instant future boots. The map is
                         * now ENRICHED with zclassicd's 0..zcd-tip ancestry; the
                         * flat persists the entry SET only (no tip), so saving it
                         * is desirable even when the backward tip promotion above
                         * was suppressed — OPTION 1's durable effect is the
                         * skipped CSR promotion, not flat avoidance. */
                        save_block_index_flat(ctx->datadir, &g_state);
                    }
                    block_tree_db_close(&zcd_btdb);
                } else {
                    fprintf(stderr, "Could not open zclassicd block index "
                            "at %s\n", open_path);
                }
                /* Tear down the snapshot (hardlinks free cheaply). */
                if (snap_ok)
                    ldb_snapshot_destroy(snap_path);

                /* Copy block files from zclassicd if we don't have them */
                if (g_state.map_block_index.size > 1000) {
                    char zcd_blk_dir[1024];
                    if (home)
                        snprintf(zcd_blk_dir, sizeof(zcd_blk_dir),
                                 "%s/.zclassic/blocks", home);
                    else
                        snprintf(zcd_blk_dir, sizeof(zcd_blk_dir),
                                 ".zclassic/blocks");
                    struct boot_legacy_block_file_import_result import_files =
                        boot_legacy_import_block_files(zcd_blk_dir,
                                                       ctx->datadir, 256);
                    if (import_files.failures > 0)
                        printf("Block files linked/copied from zclassicd "
                               "with %d failure(s); see node.log\n",
                               import_files.failures);
                    else
                        printf("Block files linked/copied from zclassicd\n");
                    fflush(stdout);
                }
            }
        } /* need_zcd */
        } /* chain height check scope */

        /* Save recent blocks to SQLite (skip for large indexes —
         * the flat file handles 3M+ entries in 1-3s and the SQLite
         * cache path uses 10GB+ RAM causing OOM kills) */
        if (g_node_db.open && g_state.map_block_index.size > 1000
            && g_state.map_block_index.size < 500000)
            save_block_index_recent(&g_node_db, &g_state);

        /* Ensure block files from zclassicd are available.
         * Hard-link (instant, same FS) or skip (cross-FS handled above).
         * This runs every boot to catch the case where block_index.bin
         * was loaded from a previous session but blocks/ was wiped. */
        if (!ctx->no_legacy_auto_import &&
            g_state.map_block_index.size > 1000) {
            const char *home = getenv("HOME");
            char zcd_blk[1024];
            if (home)
                snprintf(zcd_blk, sizeof(zcd_blk), "%s/.zclassic/blocks", home);
            else
                snprintf(zcd_blk, sizeof(zcd_blk), ".zclassic/blocks");
            struct boot_legacy_block_file_link_result link_files =
                boot_legacy_link_missing_block_files(zcd_blk,
                                                     ctx->datadir, 256);
            if (link_files.linked > 0)
                printf("Linked %d block files from zclassicd\n",
                       link_files.linked);
        }

        /* Projection top-up: fold the event-log block_index_projection over
         * the loaded map raise-only so a restart keeps the connected extent
         * instead of dropping to the stale flat floor. Runs BEFORE the
         * nChainTx propagation below; skipped on -rebuildfromlog. Non-fatal
         * (re-synced from peers), but a silent false drops to the flat floor.
         * Full contract: block_index_loader_topup.c. */
        if (!rebuilt_from_log &&
            !block_index_projection_topup(&g_state, ctx->datadir))
            LOG_WARN("boot",
                     "[boot] block_index projection top-up FAILED — the "
                     "connected extent may regress to the last flat-file "
                     "save; expect a window re-chase (see node.log above)");

        /* node.db forward-extent top-up (cold-import restart fragility): folds
         * the body-backed window above a cold-import seed anchor into the map
         * so the anchor stops being a DETACHED orphan tip and the tip does not
         * drop to genesis. Contract + STRICT no-op: block_index_loader_topup.c. */
        if (!rebuilt_from_log &&
            !block_index_node_db_topup(&g_state, &g_node_db, ctx->datadir))
            LOG_WARN("boot", "[boot] block_index node.db forward-extent top-up "
                     "FAILED — a cold-import restart may regress (node.log above)");

        /* Propagate nChainTx for all blocks in the index (OS-S2 #2).
         * Without it, find_most_work_chain() skips blocks with nChainTx=0,
         * causing "tip=X most_work=Y" with Y << X. Cursor-gated
         * (BOOT_CUR_NCHAINTX): a warm boot only re-checks entries above the
         * persisted high-water and skips the O(n log n) rebuild entirely when
         * they are contiguous-complete. Full body: boot_cursor_state.c. */
        boot_cursor_propagate_nchaintx(&g_state, &g_node_db);
    }

    boot_topmark("block_index_load", t_phase);

    /* Log block index memory usage */
    boot_block_index_memory_log_loaded(g_state.map_block_index.size,
                                       g_state.map_block_index.capacity);

    /* Bulk height repair: fix scrambled nHeight values from LDB import.
     * This must run AFTER block index is loaded but BEFORE header sync.
     * Without this, header processing fixes heights 160-at-a-time which
     * is far too slow for 3M+ entries with wrong heights. */
    int index_repaired = 0;
    if (g_state.map_block_index.size > 100)
        index_repaired += boot_cursor_repair_heights(&g_state, &g_node_db);

    /* pprev chain repair: fix corrupted pprev pointers from LDB import (reads
     * hashPrevBlock from disk; must run after height repair). Cursor-gated on
     * `pprev_repaired_height`: only rescan blocks above the verified cursor and
     * re-stamp it, so a consistent index (e.g. right after --importblockindex)
     * skips the O(chain) disk walk. A fresh datadir has no cursor (-1) and does
     * the full walk once. */
    if (g_state.map_block_index.size > 100) {
        int64_t pprev_done = -1;
        if (g_node_db.open)
            node_db_state_get_int(&g_node_db, "pprev_repaired_height",
                                  &pprev_done);
        int pprev_max = -1;
        int pprev_fixed = block_index_repair_pprev(&g_state, ctx->datadir,
                                                   (int)pprev_done, &pprev_max);
        if (pprev_fixed > 0) {
            index_repaired += pprev_fixed;
            index_repaired += block_index_repair_heights(&g_state);
        }
        if (g_node_db.open && pprev_max > (int)pprev_done)
            node_db_state_set_int(&g_node_db, "pprev_repaired_height",
                                  pprev_max);
    }

    if (index_repaired > 0 && g_state.map_block_index.size > 1000) {
        printf("Block index repaired: saving canonical flat file "
               "(%d repairs)\n", index_repaired);
        save_block_index_flat(ctx->datadir, &g_state);
    }

    /* Block index integrity — verify sidecar SHA3 after all loads.
     *
     * File integrity failures are still quarantined before boot can
     * continue. SQLite cross-check mismatches are different: the loaded
     * block index may be ahead of the SQL metadata during legacy/body-pull
     * recovery, and refusing boot there forces operators into the unsafe
     * ZCL_ALLOW_CORRUPT_INDEX path. Record the mismatch as degraded
     * reconciliation state and let the guarded boot pipeline repair or
     * fill SQL without publishing evidence by fiat. */
    {
        struct block_index *tip = active_chain_tip(&g_state.chain_active);
        char err[256] = "";
        enum bii_verdict v = bii_verify(ctx->datadir, &g_node_db,
                                         tip, err, sizeof(err));
        if (v == BII_OK) {
            bii_record_recovery_status(v, BII_RECOVERY_ACCEPTED,
                                       tip ? "block index sidecar and SQL tip match"
                                           : "block index sidecar valid; no active tip yet",
                                       false, false);
        } else if (v == BII_SIDECAR_MISSING || v == BII_BODY_MISSING) {
            bii_record_recovery_status(v, BII_RECOVERY_ACCEPTED,
                                       err[0] ? err : "first run or index will be rebuilt",
                                       false, false);
        } else if (tip &&
                   (v == BII_TIP_MISSING_IN_SQL ||
                    v == BII_TIP_HEIGHT_MISMATCH)) {
            bii_record_recovery_status(v, BII_RECOVERY_RECONCILE_REQUIRED,
                                       err[0] ? err : bii_verdict_name(v),
                                       true, false);
            fprintf(stderr,
                    "WARNING: block index integrity: %s "
                    "(continuing in degraded reconcile mode)\n",
                    err[0] ? err : bii_verdict_name(v));
        } else {
            const char *allow = getenv("ZCL_ALLOW_CORRUPT_INDEX");
            if (allow && allow[0] == '1') {
                bii_record_recovery_status(v, BII_RECOVERY_OVERRIDE,
                                           err[0] ? err : bii_verdict_name(v),
                                           true, true);
                fprintf(stderr, "WARNING: block index integrity: %s "
                        "(continuing — ZCL_ALLOW_CORRUPT_INDEX=1)\n", err);
            } else {
                bii_record_recovery_status(v, BII_RECOVERY_QUARANTINED,
                                           err[0] ? err : bii_verdict_name(v),
                                           true, false);
                fprintf(stderr, "WARNING: block index integrity: %s\n"
                        "Entering bounded crash-only re-derive (or set "
                        "ZCL_ALLOW_CORRUPT_INDEX=1 to override).\n", err);
                bii_quarantine_corrupt(ctx->datadir, v);
                /* Sticky boot (#6): the quarantined-index class returned false
                 * here, which under Restart=always is a crash-loop with no
                 * in-binary remedy. Drive the SAME bounded re-derive ladder:
                 * request -reindex-chainstate so the restart rebuilds the index
                 * from blocks/; once the budget is exhausted, park
                 * alive-degraded (paged once) instead of looping. */
                if (boot_crashonly_storage_gate(ctx->datadir,
                        "block_index_integrity",
                        boot_index_reindex_replay_executable(&g_state,
                            &g_block_tree, g_block_tree_open, ctx->datadir))
                        == BOOT_GATE_PARK_DEGRADED)
                    return boot_park_until_shutdown("block_index_integrity");
                return false;
            }
        }
    }

    /* BLOCK_INDEX_LOADED boundary: the block index is loaded, repaired, and
     * the sidecar integrity gate accepted the map. The tip is not yet
     * resolved (UTXO import + chain-tip restore run below). */
    {
        struct zcl_result br =
            sysinit_run_stage(BOOT_STAGE_BLOCK_INDEX_LOADED, ctx);
        if (!br.ok) return false;
    }

    /* ── LDB UTXO import (runs AFTER block index load) ──
     * Skipped on the log-rebuild path: the UTXO projection (bound as the
     * coins read view above) is the sole money authority there; reading the
     * legacy ~/.zclassic chainstate LevelDB into coins.db would re-introduce
     * the legacy seed this path exists to eliminate. */
    t_phase = boot_clock_ms();
    if (!rebuilt_from_log && !ctx->no_legacy_auto_import &&
        !ctx->no_legacy_utxo_import) {
        struct utxo_recovery_ctx uctx = {
            .state = &g_state,
            .coins_sqlite = &g_coins_sqlite,
            .coins_tip = &g_coins_tip,
            .ndb = &g_node_db,
            .datadir = ctx->datadir,
            .params = params,
            .activation_ctl = &g_activation_ctl,
            .db_service = boot_runtime_db_service(),
        };
        struct utxo_import_result ir = utxo_recovery_import_ldb(&uctx);
        if (!ir.status.ok)
            fprintf(stderr, "[boot] UTXO import failed: %s\n",
                    ir.status.message);
        if (ir.skip_activate) {
            if (ir.anchor_reason[0])
                activation_set_anchor_active(&g_activation_ctl,
                                              ir.anchor_reason);
        }
    }

    boot_topmark("utxo_import", t_phase);

    /* Timing only (no behavior change): mark the start of the
     * block-index reconcile span — single-pass block-index scan,
     * utxo_recovery_restore_chain_tip, block-index repair/relink,
     * utxo_recovery_execute, and the on-disk block-file scan. This stretch
     * sat between the utxo_import and sapling_tree_load markers and was
     * part of the warm-start unattributed gap. */
    int64_t t_reconcile_blockindex = boot_clock_ms();
    int64_t t_reconcile_sub = t_reconcile_blockindex;

    /* Resolve -deferproofvalidationbelow=<hash> now that block index is loaded */
    if (ctx->defer_proof_validation_below && strcmp(ctx->defer_proof_validation_below, "0") != 0) {
        struct uint256 av_hash;
        if (strlen(ctx->defer_proof_validation_below) == 64) {
            /* Parse hex hash (reversed byte order like block explorer) */
            for (int bi = 0; bi < 32; bi++) {
                unsigned int byte;
                sscanf(ctx->defer_proof_validation_below + bi * 2, "%02x", &byte);
                av_hash.data[31 - bi] = (uint8_t)byte;
            }
            struct block_index *pav = block_map_find(&g_state.map_block_index,
                                                      &av_hash);
            if (pav) {
                g_deferred_proof_validation_below_height = pav->nHeight;
                printf("Deferred proof validation: height %d (from hash)\n",
                       g_deferred_proof_validation_below_height);
            } else {
                printf("Deferred proof validation: hash not found in block index, "
                       "using checkpoint default\n");
            }
        } else {
            fprintf(stderr, "Warning: -deferproofvalidationbelow hash must be 64 hex chars\n");
        }
    }

    /* ── Single-pass block index scan ────────────────────────────
     * Previously 6+ separate O(n) scans of 3M entries (15-20s).
     * Now ONE pass that: clears BLOCK_FAILED, finds best header,
     * finds fallback (most chain work with HAVE_DATA+nChainTx),
     * finds reindex target, tracks max HAVE_DATA height. */
    struct block_index *scan_best_header = NULL;  /* most chain work */
    struct block_index *scan_fallback = NULL;      /* most work w/ data */
    struct block_index *scan_reindex_best = NULL;  /* highest w/ pprev+nChainTx */
    int scan_cleared_failed = 0;
    int scan_max_have_data_h = 0;
    int scan_have_data_count = 0;
    int scan_missing_header_data = 0;

    {
        size_t si = 0;
        struct block_index *sp;
        while (block_map_next(&g_state.map_block_index, &si, NULL, &sp)) {
            if (!sp) continue;
            /* Clear BLOCK_FAILED */
            if (sp->nStatus & BLOCK_FAILED_MASK) {
                sp->nStatus &= ~BLOCK_FAILED_MASK;
                scan_cleared_failed++;
            }
            /* Best header: most chain work; height tiebreak/fallback when either side's work is zero (a rebuild-from-blocks data gap must not silently cap best_header — same rule as promote_best_header_after_load). */
            if (!scan_best_header || (arith_uint256_is_zero(&sp->nChainWork) || arith_uint256_is_zero(&scan_best_header->nChainWork)
                 ? sp->nHeight > scan_best_header->nHeight
                 : arith_uint256_compare(&sp->nChainWork, &scan_best_header->nChainWork) > 0))
                scan_best_header = sp;
            /* Fallback: most work with HAVE_DATA + nChainTx */
            if ((sp->nStatus & BLOCK_HAVE_DATA) && sp->nChainTx > 0) {
                if (!scan_fallback ||
                    arith_uint256_compare(&sp->nChainWork,
                                          &scan_fallback->nChainWork) > 0)
                    scan_fallback = sp;
            }
            /* Reindex target: highest with pprev + nChainTx */
            if (sp->pprev && sp->nHeight > 0 && sp->nChainTx > 0) {
                if (!scan_reindex_best ||
                    sp->nHeight > scan_reindex_best->nHeight)
                    scan_reindex_best = sp;
            }
            /* Max HAVE_DATA height + aggregate body-coverage count (gates the
             * reindex-target decision below; no extra O(chain) pass). */
            if (sp->nStatus & BLOCK_HAVE_DATA) {
                scan_have_data_count++;
                if (sp->nHeight > scan_max_have_data_h)
                    scan_max_have_data_h = sp->nHeight;
            }
            if ((sp->nStatus & BLOCK_HAVE_DATA) && sp->nDataPos > 0 &&
                sp->nHeight > 0 &&
                (sp->nVersion == 0 || sp->nTime == 0 || sp->nBits == 0))
                scan_missing_header_data++;
        }
    }
    if (scan_cleared_failed > 0)
        printf("Cleared BLOCK_FAILED from %d block index entries\n",
               scan_cleared_failed);
    if (scan_missing_header_data > 0)
        printf("Block index has %d HAVE_DATA entries with missing headers; "
               "will hydrate from block files\n",
               scan_missing_header_data);

    t_reconcile_sub = boot_submark("blkidx.scan", t_reconcile_sub);

    /* Tier-2 P2 fast-restart decision (helper does verify + in-memory install;
     * any mismatch ⇒ full dirty-boot path). Never on reindex/log-rebuild/mint/
     * refold/snapshot — those intentionally rebuild. */
    if (!ctx->reindex_chainstate && !rebuilt_from_log &&
        !ctx->mint_anchor && !ctx->refold_from_anchor && !ctx->refold_staged &&
        ctx->load_snapshot_at_own_height == NULL) {
        struct block_index *fr_tip = NULL;
        if (boot_fast_restart_try(&g_state, &fr_tip) && fr_tip) {
            fast_restart = true;
            boot_restored_authority_tip = true;
            boot_restored_authority_height = fr_tip->nHeight;
            if (fr_tip->phashBlock)
                boot_restored_authority_hash = *fr_tip->phashBlock;
            if (scan_best_header)
                (void)boot_promote_header_via_csr(scan_best_header,
                                                  "fast_restart");
        }
    }

    /* Coverage gate: a -reindex-chainstate (explicit or sentinel-consumed)
     * replays from genesis and cannot skip a missing body. When coins are
     * already seeded but local bodies materially fail to cover [0..target] (a
     * cold-import seed), the replay would wipe the seed and then stall on the
     * first missing body. Prefer fold-forward-from-seed: refuse the reindex,
     * clear the sentinel so it does not re-arm, and fall through to the restore
     * path (the else-if chain below). Uses only facts the single-pass scan
     * already computed — no new O(chain) pass. */
    if (ctx->reindex_chainstate && scan_reindex_best) {
        struct boot_derived_coins_best cov_dcb;
        bool seeded = boot_derive_coins_best(&cov_dcb) ||
                      node_db_utxo_count(&g_node_db) > 0;
        if (!boot_crashonly_reindex_coverage_ok(ctx->datadir,
                scan_reindex_best->nHeight, scan_max_have_data_h,
                scan_have_data_count, seeded))
            ctx->reindex_chainstate = false;
    }

    /* Restore chain tip from coins DB best block hash */
    if (ctx->reindex_chainstate) {
        if (scan_reindex_best) {
            if (boot_promote_tip_via_csr(scan_reindex_best,
                                         "scan_reindex_best", false)) {
                printf("Reindex target: height=%d\n",
                       scan_reindex_best->nHeight);
            }
        } else {
            printf("Reindex: no best found (total=%zu)\n",
                   g_state.map_block_index.size);
        }
        if (!reindex_chainstate(&g_state, &g_coins_sqlite, &g_coins_tip,
                                 &g_node_db, ctx->datadir)) {
            /* Replay-from-blocks/ failed. Warn-and-continue: the post-restore
             * integrity gate + boot_crashonly_handle_unrecoverable own the
             * BOUNDED reindex budget (a genuinely-corrupt datadir climbs to
             * BOOT_AUTO_REINDEX_MAX there and persists the terminal marker ->
             * stays-up-degraded). The errors==0 epilogue-derivation-failure case
             * (boot_index.c) is deliberately retry-forever-with-paging on a
             * FIXABLE failure, so we must NOT advance the budget here. */
            fprintf(stderr, "Warning: Chainstate reindex had errors\n");
        }
        /* Raise pindex_best_header to the real header frontier after a reindex.
         * The reindex restores the coins/active tip (scan_reindex_best) but
         * leaves pindex_best_header pinned at that height; the branch that
         * promotes the most-work header (scan_best_header) lives only in the
         * non-reindex path below and is never reached here. Without this, a node
         * that reindexed while behind the network stays pinned at the replayed
         * coins tip: gap_fill (gap_fill_service.c best_h<=tip_h) requests no
         * bodies and tip_finalize's is_canonical_header_successor rejects the
         * next height (new_tip->nHeight > best_header->nHeight), so the node
         * stalls below the network tip and never catches up (observed live:
         * stuck at 3162166 with headers known to 3162641). Mirror the
         * non-reindex promotion; csr's boot rollback-auth carve-out installs it,
         * and the guard makes it a no-op when there is no gap. */
        if (scan_best_header)
            (void)boot_promote_header_via_csr(scan_best_header,
                                              "scan_best_header_reindex");
    } else if (fast_restart) {
    } else if (g_state.map_block_index.size > 1) {
        struct utxo_recovery_ctx uctx = {
            .state = &g_state,
            .coins_sqlite = &g_coins_sqlite,
            .coins_tip = &g_coins_tip,
            .ndb = &g_node_db,
            .datadir = ctx->datadir,
            .params = params,
            .activation_ctl = &g_activation_ctl,
            .db_service = boot_runtime_db_service(),
        };
        /* O(delta) unclean-restart recovery (docs/AGENT_TRAPS.md). This branch
         * runs on every UNCLEAN restart (crash / kill -9 / OOM). When the just-
         * run block-index repair proved the in-memory index consistent, engage
         * the trust fastpath so the restore's internal chain_restore_finalize
         * takes the O(tip) pprev walk instead of the ~74s O(chain) disk header
         * re-read + block-file rescan. Scoped + cleared; the post-restore
         * integrity check stays the fail-safe. The full disk walk is the last-
         * resort rung — reached only when index_repaired > 0 (behind the named
         * block-index-repair blocker), never the default. */
        bool restore_trust =
            chain_restore_index_verified_consistent(
                index_repaired, g_state.map_block_index.size) &&
            !chain_restore_trust_index_fastpath();
        if (restore_trust) {
            printf("[boot] index verified consistent (0 repairs, %zu entries) "
                   "— unclean-restart recovery trusting in-memory pprev walk "
                   "(O(delta)); skipping disk header re-read + block-file "
                   "rescan\n", g_state.map_block_index.size);
            fflush(stdout);
            chain_restore_set_trust_index_fastpath(true);
        }
        struct chain_restore_result cr =
            utxo_recovery_restore_chain_tip(&uctx, scan_fallback);
        if (restore_trust)
            chain_restore_set_trust_index_fastpath(false);
        if (!cr.status.ok)
            fprintf(stderr, "[boot] UTXO chain restore failed: %s\n",
                    cr.status.message);
        if (cr.restored && cr.restored_height > 0) {
            boot_restored_authority_tip = true;
            boot_restored_authority_height = cr.restored_height;
            boot_restored_authority_hash = cr.restored_hash;

            if (!active_chain_tip(&g_state.chain_active) &&
                !uint256_is_null(&boot_restored_authority_hash)) {
                struct block_index *restored = block_map_find(
                    &g_state.map_block_index, &boot_restored_authority_hash);
                /* HEIGHT-AGREEMENT BELT (Invariant A consumer side): the
                 * restore result's hash must map to an index block AT the
                 * recorded height before it may become the live tip. Without
                 * this, a floor row whose recorded height disagrees with the
                 * index would raw-install fabricated state and end in
                 * crash-only reindex. */
                if (restored && restored->nHeight == cr.restored_height) {
                    int populated = chain_restore_rebuild_active_chain(
                        &g_state, restored, NULL);
                    fprintf(stderr,
                        "[boot] restored authority tip h=%d had no active "
                        "chain slot after restore; reinstalled populated=%d\n",
                        restored->nHeight, populated);
                } else if (restored) {
                    fprintf(stderr,
                        "[boot] restored authority hash maps to h=%d but the "
                        "recorded restore height is %d — refusing raw tip "
                        "install (hash/height disagreement; waiting for "
                        "P2P)\n",
                        restored->nHeight, cr.restored_height);
                    event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=restore_reinstall_refused mapped_h=%d "
                        "recorded_h=%d", restored->nHeight,
                        cr.restored_height);
                }
            }
        }
        if (cr.skip_activate) {
            if (cr.anchor_reason[0])
                activation_set_anchor_active(&g_activation_ctl,
                                              cr.anchor_reason);
        }
        if (scan_best_header)
            (void)boot_promote_header_via_csr(scan_best_header,
                                              "scan_best_header");
    }

    /* Ensure genesis block is always properly initialized.
     * On a fresh start, load_block_index creates genesis. On restart,
     * LevelDB may have entries but genesis might lack BLOCK_HAVE_DATA
     * or chain_active might not have a tip set. Fix both. */
    {
        struct block_index *genesis = block_map_find(
            &g_state.map_block_index, &params->consensus.hashGenesisBlock);
        if (!genesis) {
            genesis = chainstate_insert_block_index(
                (struct chainstate *)&g_state,
                &params->consensus.hashGenesisBlock);
        }
        if (genesis) {
            if (genesis->nHeight != 0)
                genesis->nHeight = 0;
            if (!(genesis->nStatus & BLOCK_HAVE_DATA)) {
                genesis->nStatus |= BLOCK_HAVE_DATA;
                genesis->nStatus = (genesis->nStatus & ~BLOCK_VALID_MASK) |
                                    BLOCK_VALID_SCRIPTS;
                genesis->nTx = 1;
                genesis->nChainTx = 1;
                printf("Genesis block: marked BLOCK_HAVE_DATA\n");
            }
            if (arith_uint256_is_zero(&genesis->nChainWork))
                genesis->nChainWork = GetBlockProof(genesis);
            /* Set chain tip to genesis on true fresh boots only. If the
             * coins/UTXO authority restored a non-genesis tip, never turn a
             * cache-rebuild failure into a rollback to height 0: that makes
             * valid historical UTXOs look stale and triggers destructive
             * recovery paths. */
            if (!active_chain_tip(&g_state.chain_active)) {
                int durable_h = -1; uint8_t durable_hash[32];
                if (boot_restored_authority_tip) {
                    fprintf(stderr,
                        "[boot] skipped genesis_init: restored authority "
                        "tip h=%d remains authoritative while active_chain "
                        "is being rebuilt\n",
                        boot_restored_authority_height);
                    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                                "skip_genesis_init restored_authority_tip=%d",
                                boot_restored_authority_height);
                } else if (tip_finalize_stage_resolve_durable_tip(
                               progress_store_db(), &durable_h, durable_hash) &&
                           durable_h > 0) {
                    /* Defensive belt (kill-9-at-genesis): durable finalized
                     * tip > 0 but coins never installed an active tip. Skip
                     * genesis_init (transient tip + misleading rollback_auth);
                     * the genesis-root forward-seed installs the real tip. */
                    fprintf(stderr, "[boot] skipped genesis_init: durable "
                        "finalized tip h=%d pending forward-seed\n", durable_h);
                } else if (boot_promote_tip_via_csr(genesis, "genesis_init",
                                                    false)) {
                    printf("Chain tip: initialized to genesis (height 0)\n");
                }
            }
        }
    }

    t_reconcile_sub = boot_submark("blkidx.restore_tip", t_reconcile_sub);
    if (!boot_seed_oneshot_headers_preflight(ctx, &g_state)) return false; /* D3: seed one-shot headers-prereq fast-fail, boot_seed_gate.c */
    /* Repair block index from SQLite.
     * After legacy import, blocks in the LevelDB index may lack BLOCK_VALID_SCRIPTS
     * (they were validated by zclassicd but our index doesn't know that).
     * Without this, reducer activation won't extend the chain past
     * previously-connected blocks because it only follows fully-validated
     * entries. Also fix any stale file positions. */
    if (g_node_db.open && g_state.map_block_index.size > 1000) {
        /* Only repair blocks near the tip (within 1000 of chain height).
         * The flat file load already has correct data for most blocks.
         * Full 3M-row scan was taking 8+ minutes — this takes <100ms. */
        int repair_from = active_chain_height(&g_state.chain_active) - 1000;
        if (repair_from < 0) repair_from = 0;
        sqlite3_stmt *sel = NULL;
        char repair_sql[256];
        snprintf(repair_sql, sizeof(repair_sql),
            "SELECT hash, file_num, data_pos, status FROM blocks "
            "WHERE file_num >= 0 AND data_pos >= 0 AND height >= %d",
            repair_from);
        int rc = sqlite3_prepare_v2(g_node_db.db, repair_sql, -1, &sel, NULL);
        if (rc == SQLITE_OK && sel) {
            int repaired = 0, checked = 0;
            while (AR_STEP_ROW_READONLY(sel) == SQLITE_ROW) {
                const void *hash_blob = sqlite3_column_blob(sel, 0);
                int hash_len = sqlite3_column_bytes(sel, 0);
                int file_num = sqlite3_column_int(sel, 1);
                int data_pos = sqlite3_column_int(sel, 2);
                int status = sqlite3_column_int(sel, 3);

                if (!hash_blob || hash_len != 32) continue;

                struct uint256 hash;
                memcpy(hash.data, hash_blob, 32);

                struct block_index *bi = block_map_find(
                    &g_state.map_block_index, &hash);
                if (!bi) continue;
                checked++;

                bool changed = false;

                /* Fix file positions */
                if (bi->nFile != file_num || bi->nDataPos != (unsigned)data_pos) {
                    if (file_num >= 0 && data_pos > 0) {
                        bi->nFile = file_num;
                        bi->nDataPos = (unsigned)data_pos;
                        changed = true;
                    }
                }

                /* Promote validation status from SQLite. A prior import
                 * (e.g. -cold-import) may have persisted BLOCK_HAVE_DATA,
                 * BLOCK_HAVE_UNDO, and BLOCK_VALID_SCRIPTS into the
                 * SQLite block_index ahead of this in-memory load. */
                if (status > 0 && (bi->nStatus & BLOCK_VALID_MASK) <
                    (unsigned)(status & BLOCK_VALID_MASK)) {
                    bi->nStatus = (bi->nStatus & ~(unsigned)BLOCK_VALID_MASK) |
                                  ((unsigned)status & (BLOCK_VALID_MASK |
                                   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO));
                    changed = true;
                }

                if (changed) repaired++;
            }
            sqlite3_finalize(sel);
            if (repaired > 0) {
                printf("Block index repair: updated %d/%d entries from SQLite\n",
                       repaired, checked);
                fflush(stdout);
            }
        }
    }

    /* Option A: phashBlock now references per-node block_index.hashBlock
     * (stable, never freed by bucket realloc), seeded at every insert.
     * The old bucket-identity relink pass is intentionally removed: under
     * Option A 'phashBlock != &bucket.hash' is ALWAYS true, so it would
     * re-point every node BACK into the reallocatable bucket array and
     * re-introduce the UAF. No relink is needed. */

    /* Validate coins/chain agreement and execute recovery */
    t_reconcile_sub = boot_submark("blkidx.repair_relink", t_reconcile_sub);
    {
        struct boot_validation_result vr =
            validate_coins_chain_agreement(&g_state, &g_coins_tip,
                                           ctx->datadir);
        struct utxo_recovery_ctx uctx = {
            .state = &g_state,
            .coins_sqlite = &g_coins_sqlite,
            .coins_tip = &g_coins_tip,
            .ndb = &g_node_db,
            .datadir = ctx->datadir,
            .params = params,
            .activation_ctl = &g_activation_ctl,
            .db_service = boot_runtime_db_service(),
        };
        struct recovery_exec_result rr = utxo_recovery_execute(&uctx, &vr);
        if (!rr.status.ok)
            fprintf(stderr, "[boot] UTXO recovery execution failed: %s\n",
                    rr.status.message);
        (void)rr.skip_activate; /* activation controller handles state */

        /* Enter turbo mode if genesis reset happened */
        if (rr.recovered &&
            (vr.action == BOOT_RECOVER_REIMPORT ||
             vr.action == BOOT_RECOVER_WIPE_WAIT) &&
            g_node_db.open) {
            if (!boot_db_enter_turbo_mode())
                fprintf(stderr, "boot: failed to enter turbo mode\n");
            if (!boot_db_set_sync_batch_size(1000))
                fprintf(stderr, "boot: failed to set sync batch size\n");
        }
    }

    /* Clear stale HAVE_DATA above tip — targeted, not full scan.
     * Only needed if max HAVE_DATA height > chain tip (from the
     * single-pass scan above). Skip when block index has 1M+ entries
     * — that means it was loaded from zclassicd's LDB with correct
     * nFile/nDataPos, and clearing HAVE_DATA would force re-download
     * of 3M blocks that are already on disk. */
    {
        int tip_h = active_chain_height(&g_state.chain_active);
        if (scan_max_have_data_h > tip_h && tip_h > 0 &&
            g_state.map_block_index.size < 1000000) {
            int cleared = 0;
            size_t ci = 0;
            struct block_index *cp;
            while (block_map_next(&g_state.map_block_index, &ci, NULL, &cp)) {
                if (cp && cp->nHeight > tip_h &&
                    (cp->nStatus & BLOCK_HAVE_DATA)) {
                    cp->nStatus &= ~BLOCK_HAVE_DATA;
                    cleared++;
                }
            }
            if (cleared > 0)
                printf("Cleared stale HAVE_DATA from %d blocks above tip %d\n",
                       cleared, tip_h);
        }
    }

    /* Scan block files on disk if HAVE_DATA is missing or if entries claim
     * HAVE_DATA but still have placeholder header fields. The latter blocks
     * activation because the validator must reject nBits=0 placeholders.
     * Uses scan_max_have_data_h from the single-pass scan above
     * instead of another partial iteration. */
    {
        /* FIXME(option-ii, follow-up): scan_max_have_data_h is the MAX HAVE_DATA
         * height, NOT span COVERAGE. A header-only import whose projection rung
         * marked an UPPER sub-span (e.g. h>=3,155,843) leaves this gate reading a
         * high max while the LOWER fold span has no bodies — need_scan stays
         * false and this broad scan is skipped. The from-anchor fold-span rebind
         * (boot_refold_body_span_contiguous → scan_block_files_mark_data) now
         * covers that case on a real gap; this gate could ADDITIONALLY fire on a
         * coins-tip-ancestry body gap here rather than trusting the max. */
        bool need_scan = (scan_max_have_data_h < 100 &&
                          g_state.map_block_index.size > 1000) ||
                         g_state.map_block_index.size < 100 ||
                         scan_missing_header_data > 0;
        if (need_scan) {
            bool have_block_files = false;
            for (int ci = 0; ci < 3 && !have_block_files; ci++) {
                char check_path[576];
                snprintf(check_path, sizeof(check_path),
                         "%s/blocks/blk%05d.dat", ctx->datadir, ci);
                struct stat check_st;
                if (stat(check_path, &check_st) == 0 && check_st.st_size > 0)
                    have_block_files = true;
            }
            if (have_block_files) {
                scan_block_files_mark_data(&g_state, ctx->datadir, params);
                fflush(stdout);
                if (g_state.map_block_index.size > 1000)
                    save_block_index_flat(ctx->datadir, &g_state);

                /* Wave 2: on canonical datadirs the post-scan anchor ladder
                 * below is GUESSWORK over caches (node_state anchor, mirror
                 * MAX(height), "most work scanned") that manufactured wedges;
                 * the coins-best fact is derived from coins_kv and the
                 * regular restore path (now derivation-gated) installs the
                 * tip. Skip the whole ladder. Legacy datadirs keep it.
                 * (ladder body = wave-3 delete) */
                struct boot_derived_coins_best scan_dcb;
                if (boot_derive_coins_best(&scan_dcb)) {
                    printf("[boot] post-scan anchor ladder skipped — derived "
                           "coins-best h=%d (coins_kv authority)\n",
                           scan_dcb.height);
                } else {
                /* After block file scan, try to resolve coins_best_block.
                 * The scan may have assigned wrong heights (blocks in random
                 * file order) or picked a wrong "most work" chain due to
                 * incomplete nChainTx propagation.  Use SQLite blocks table
                 * to find the correct height, then set the active chain tip
                 * to the coins-tip block.  This fires when:
                 *   (a) active_chain is empty (no HAVE_DATA blocks), OR
                 *   (b) active_chain tip is far below the coins tip
                 *       (scan picked a wrong short fork). */
                struct uint256 post_scan_best;
                /* This LDB/damage-recovery branch needs the LEGACY coins.db
                 * best-block, not the projection (the projection read view
                 * tracks a consume offset, not a best-block hash). Read it
                 * straight from g_coins_sqlite, which still exists for
                 * legacy damage-recovery reads. */
                uint256_set_null(&post_scan_best);
                if (g_coins_sqlite.db)
                    coins_view_sqlite_get_best_block(&g_coins_sqlite,
                                                     &post_scan_best);
                /* Restore chain tip to match UTXO snapshot height when
                 * the active chain is far below the coins tip. This happens
                 * after LDB import: the UTXO set is at 3M+ but block files
                 * only cover up to ~2M, so reducer activation sets a low
                 * tip. Without this fix, the node tries to re-connect
                 * blocks that are already reflected in the UTXO set, causing
                 * bad-txns-inputs-missingorspent failures. */
                if (!uint256_is_null(&post_scan_best)) {
                    /* Look up correct height from SQLite */
                    int target_h = -1;
                    if (g_node_db.open && g_node_db.db) {
                        /* Look up import height from SQLite blocks table.
                         * blocks.hash stores display-order (big-endian),
                         * coins_best_block is internal-order (little-endian). */
                        uint8_t hash_rev[32];
                        for (int bi = 0; bi < 32; bi++)
                            hash_rev[bi] = post_scan_best.data[31 - bi];

                        struct db_block sqlite_blk;
                        if (db_block_find_by_hash(&g_node_db, hash_rev,
                                                   &sqlite_blk) &&
                            sqlite_blk.height > 0) {
                            target_h = sqlite_blk.height;
                        }

                        /* Fallback: try finding by height range near chain tip */
                        if (target_h <= 0) {
                            sqlite3_stmt *qs = NULL;
                            sqlite3_prepare_v2(g_node_db.db,
                                "SELECT height FROM blocks "
                                "ORDER BY height DESC LIMIT 1",
                                -1, &qs, NULL);
                            if (qs) {
                                if (AR_STEP_ROW_READONLY(qs) == SQLITE_ROW)
                                    target_h = sqlite3_column_int(qs, 0);
                                sqlite3_finalize(qs);
                            }
                            if (target_h > 0)
                                printf("Post-scan: using max block height "
                                       "%d as import target\n", target_h);
                        }

                        if (target_h > 0)
                            printf("Post-scan: import height=%d\n", target_h);
                    }

                    struct block_index *post_found = block_map_find(
                        &g_state.map_block_index, &post_scan_best);
                    if (post_found && target_h > 0) {
                        struct block_index *best_scanned = NULL;
                        size_t scan_iter = 0;
                        struct block_index *scan_bi;
                        while (block_map_next(&g_state.map_block_index,
                                              &scan_iter, NULL, &scan_bi)) {
                            if (!scan_bi) continue;
                            if (!(scan_bi->nStatus & BLOCK_HAVE_DATA)) continue;
                            if (scan_bi->nChainTx == 0) continue;
                            if (!best_scanned ||
                                arith_uint256_compare(&scan_bi->nChainWork,
                                                      &best_scanned->nChainWork) > 0)
                                best_scanned = scan_bi;
                        }
                        if (best_scanned &&
                            best_scanned->nHeight > post_found->nHeight + 1000) {
                            printf("Post-scan: promoting best scanned chain "
                                   "h=%d over stale coins anchor h=%d\n",
                                   best_scanned->nHeight, post_found->nHeight);
                            post_found = best_scanned;
                            target_h = best_scanned->nHeight;
                        }
                        /* SQLite block metadata is a cache and can lag or
                         * carry stale labels after recovery.  The pprev chain
                         * is the authority for block heights here; never
                         * mutate a block_index height from SQLite metadata.
                         * A one-block downlabel is enough to make the active
                         * tip silently disagree with peers and can prune live
                         * UTXOs above the false tip. */
                        if (post_found->nHeight != target_h) {
                            printf("Post-scan: ignoring SQLite height %d for "
                                   "pprev-derived h=%d\n",
                                   target_h, post_found->nHeight);
                            target_h = post_found->nHeight;
                        }
                        if (boot_promote_tip_via_csr(
                                post_found, "post_found_promote", true)) {
                            printf("Post-scan: setting chain tip to h=%d\n",
                                   target_h);
                        }
                    } else if (!post_found) {
                        /* coins_best_block hash not found in block index.
                         * Instead of wiping UTXOs, find the highest UTXO
                         * height and set chain tip there.  The UTXO data
                         * is valid — only the metadata label is wrong. */
                        char hex[65];
                        uint256_get_hex(&post_scan_best, hex);
                        printf("[boot] coins_best_block %s not in "
                               "block index — resolving from UTXO "
                               "heights\n", hex);

                        int utxo_max_h = 0;
                        {
                            sqlite3_stmt *hst = NULL;
                            if (sqlite3_prepare_v2(g_node_db.db,
                                "SELECT MAX(height) FROM utxos",
                                -1, &hst, NULL) == SQLITE_OK && hst) {
                                if (AR_STEP_ROW_READONLY(hst) == SQLITE_ROW)
                                    utxo_max_h = sqlite3_column_int(hst, 0);
                                sqlite3_finalize(hst);
                            }
                        }

                        if (utxo_max_h > 0) {
                            /* Find highest HAVE_DATA block at or below
                             * the UTXO height — conservative but safe. */
                            struct block_index *best_have = NULL;
                            size_t bi = 0;
                            struct block_index *bp;
                            while (block_map_next(
                                &g_state.map_block_index,
                                &bi, NULL, &bp)) {
                                if (!bp) continue;
                                if (bp->nHeight <= utxo_max_h &&
                                    (bp->nStatus & BLOCK_HAVE_DATA) &&
                                    chain_restore_block_is_consensus_backed_on_disk(
                                        bp, g_datadir) &&
                                    (!best_have ||
                                     bp->nHeight > best_have->nHeight))
                                    best_have = bp;
                            }

                            if (best_have && best_have->nHeight > 0 &&
                                boot_promote_tip_via_csr(
                                    best_have, "coins_hash_orphan_promote",
                                    true)) {
                                printf("[boot] coins_best_block hash not "
                                       "in index — setting tip to highest "
                                       "HAVE_DATA block at h=%d\n",
                                       best_have->nHeight);
                            } else {
                                /* No verified disk-backed blocks — record
                                 * metadata only at the UTXO height. */
                                struct block_index *anchor =
                                    chain_restore_create_anchor(
                                        &g_state, &post_scan_best,
                                        utxo_max_h);
                                if (anchor) {
                                    snapsync_set_anchor(anchor);

                                    printf("[boot] coins_best_block hash "
                                           "not in index — metadata anchor "
                                           "at h=%d\n", utxo_max_h);
                                }
                            }
                        } else {
                            /* No UTXOs at all — safe to reset to genesis */
                            printf("[boot] No UTXOs found — resetting to "
                                   "genesis\n");
                            struct block_index *genesis = block_map_find(
                                &g_state.map_block_index,
                                &params->consensus.hashGenesisBlock);
                            if (genesis) {
                                (void)boot_promote_tip_preserving_header_via_csr(
                                    genesis, "no_utxos_reset_genesis", true);
                            }
                        }
                    }
                }
                }  /* end legacy post-scan ladder (!derived) */
            }
        }
    }

    (void)boot_submark("blkidx.validate_recover", t_reconcile_sub);
    boot_topmark("block_index_reconcile", t_reconcile_blockindex);

    t_phase = boot_clock_ms();
    /* Wire the flat-file sapling checkpoint. Tells
     * process_block.c where to flush every 10K blocks; separate from
     * the node_state-backed path because the flat file is immune to
     * the P14 savepoint contention class. */
    set_sapling_checkpoint_datadir(g_datadir);

    /* Load Sapling commitment tree from persistent storage.
     *
     * Three-tier fall-back, most-authoritative first:
     *   (1) Flat-file checkpoint at <datadir>/sapling_tree_ckpt.dat
     * SHA3-verified, atomic, ≤10K blocks stale.
     *   (2) node_state["sapling_tree"] — SQLite-backed, legacy path,
     *       kept as a secondary belt.
     *   (3) Fresh empty tree + replay during the mismatch-check pass.
     *
     * This tree is maintained by connect_block and verified against
     * hashFinalSaplingRoot in each block header. */
    /* The height this tree was verified/persisted at — -1 = unknown (a
     * legacy datadir predating "sapling_tree_rebuild_height", or no tree
     * loaded yet). Threaded into the mismatch-check pass below so a stale
     * (but internally-consistent) tree can fold forward instead of being
     * treated as corrupt. See sapling_tree_verify_at_saved_height(). */
    int64_t sapling_tree_saved_height = -1;
    if (g_node_db.open && !g_state.sapling_tree_loaded && g_datadir) {
        char ckpt_path[512];
        snprintf(ckpt_path, sizeof(ckpt_path),
                 "%s/sapling_tree_ckpt.dat", g_datadir);
        sapling_tree_init(&g_state.sapling_tree);
        int64_t ckpt_height = 0;
        uint8_t ckpt_block_hash[32] = {0};
        if (sapling_tree_load_checkpoint(&g_state.sapling_tree,
                                          &ckpt_height, ckpt_block_hash,
                                          ckpt_path)) {
            /* Verify-then-trust: bind the cached frontier to the
             * authoritative header chain at ckpt_height (height <= tip,
             * same block hash, root == hashFinalSaplingRoot). A stale
             * (above-tip / reorged / mismatched) checkpoint is DELETED and
             * we fall through to the node_state path + full replay — the
             * cache is never trusted unverified. */
            struct uint256 ckpt_root;
            incremental_tree_root(&g_state.sapling_tree, &ckpt_root);
            const struct block_index *ctip =
                active_chain_tip(&g_state.chain_active);
            const struct block_index *cbi =
                active_chain_at(&g_state.chain_active, (int)ckpt_height);
            static const uint8_t zeros32[32] = {0};
            bool exp_hash_known = cbi && cbi->phashBlock;
            bool exp_root_known = cbi && memcmp(cbi->hashFinalSaplingRoot.data,
                                                zeros32, 32) != 0;
            enum sapling_ckpt_verdict v = sapling_ckpt_verify_binding(
                ckpt_height, &ckpt_root, ckpt_block_hash,
                ctip ? ctip->nHeight : -1,
                exp_hash_known ? cbi->phashBlock->data : NULL, exp_hash_known,
                exp_root_known ? &cbi->hashFinalSaplingRoot : NULL,
                exp_root_known);
            if (v == SAPLING_CKPT_OK) {
                g_state.sapling_tree_loaded = true;
                set_sapling_tree_for_flush(&g_state.sapling_tree);
                sapling_tree_saved_height = ckpt_height;
                sapling_ckpt_record_load(SAPLING_CKPT_LOAD_VERIFIED,
                                         ckpt_height, "ok");
                printf("Sapling tree loaded from checkpoint: "
                       "%zu commitments, height=%lld (verified)\n",
                       incremental_tree_size(&g_state.sapling_tree),
                       (long long)ckpt_height);
            } else {
                fprintf(stderr,
                        "WARNING: Sapling checkpoint h=%lld REJECTED (%s) — "
                        "deleting %s and rebuilding\n",
                        (long long)ckpt_height, sapling_ckpt_verdict_str(v),
                        ckpt_path);
                unlink(ckpt_path);
                sapling_tree_init(&g_state.sapling_tree);
                sapling_ckpt_record_load(SAPLING_CKPT_LOAD_DISCARDED,
                                         ckpt_height,
                                         sapling_ckpt_verdict_str(v));
            }
        } else {
            sapling_ckpt_record_load(SAPLING_CKPT_LOAD_ABSENT, -1,
                                     "missing_or_corrupt");
        }
    }

    if (g_node_db.open && !g_state.sapling_tree_loaded) {
        uint8_t tree_buf[8192];
        size_t tree_len = 0;
        if (node_db_state_get(&g_node_db, "sapling_tree",
                               tree_buf, sizeof(tree_buf), &tree_len)
            && tree_len > 0) {
            struct byte_stream ts;
            stream_init_from_data(&ts, tree_buf, tree_len);
            sapling_tree_init(&g_state.sapling_tree);
            if (incremental_tree_deserialize(&g_state.sapling_tree, &ts)) {
                g_state.sapling_tree_loaded = true;
                set_sapling_tree_for_flush(&g_state.sapling_tree);
                /* The height this blob was persisted at — co-written
                 * alongside "sapling_tree" by every production writer
                 * (sync_controller_sapling_tree.c, boot_refold_staged.c,
                 * sync_controller_blocks.c). Absent (-1) only on a legacy
                 * datadir written before this key existed. */
                if (!node_db_state_get_int(&g_node_db,
                        "sapling_tree_rebuild_height",
                        &sapling_tree_saved_height))
                    sapling_tree_saved_height = -1;
                if (sapling_tree_saved_height >= 0) {
                    printf("Sapling tree loaded: %zu commitments "
                           "(saved_h=%lld)\n",
                           incremental_tree_size(&g_state.sapling_tree),
                           (long long)sapling_tree_saved_height);
                } else {
                    printf("Sapling tree loaded: %zu commitments\n",
                           incremental_tree_size(&g_state.sapling_tree));
                }
            } else {
                fprintf(stderr, "WARNING: Sapling tree deserialization "
                        "failed — tree will rebuild during sync\n");
                sapling_tree_init(&g_state.sapling_tree);
            }
        } else {
            printf("No saved Sapling tree — will build during sync\n");
            g_state.sapling_tree_loaded = true; /* empty tree is valid pre-Sapling */
            set_sapling_tree_for_flush(&g_state.sapling_tree);
        }
    }

    /* Verify Sapling tree root matches chain tip. If mismatched,
     * rebuild from block files before P2P starts (no concurrency risk).
     * Skip if hashFinalSaplingRoot is all-zeros (block_index.bin doesn't
     * store this field yet, so it will be zero after flat file load). */
    if (g_state.sapling_tree_loaded && g_datadir) {
        /* Resolve the comparison endpoint from coins-applied state, NOT the
         * pre-fold header tip. On a wedged node (active/header tip >> the
         * durable coins frontier) the loaded sapling tree corresponds to the
         * APPLIED frontier, so comparing it against the HEADER tip's
         * hashFinalSaplingRoot would (a) spuriously mismatch even when the
         * tree is correct for the applied state, and (b) feed the rebuild a
         * header-tip endpoint whose root may be absent and FATAL on
         * `tip_missing_sapling_root` before the forward fold runs. Cap to
         * coins_applied_height - 1 (coins-best) when present and lower; the
         * rebuild itself independently re-derives the same coins-applied
         * endpoint if a mismatch here triggers it. */
        const struct block_index *tip = active_chain_tip(&g_state.chain_active);
        struct boot_derived_coins_best sap_dcb;
        if (boot_derive_coins_best(&sap_dcb) && sap_dcb.height >= 0
            && (!tip || sap_dcb.height < tip->nHeight)) {
            const struct block_index *coins_tip =
                active_chain_at(&g_state.chain_active, sap_dcb.height);
            if (coins_tip) {
                printf("Sapling tree check: using coins-applied height %d "
                       "(header tip %d)\n", sap_dcb.height,
                       tip ? tip->nHeight : -1);
                tip = coins_tip;
            }
        }
        static const uint8_t zeros[32] = {0};
        bool tip_has_sapling_root = tip && tip->nHeight > 476969 &&
            memcmp(tip->hashFinalSaplingRoot.data, zeros, 32) != 0;
        if (tip_has_sapling_root) {
            struct uint256 tree_root;
            incremental_tree_root(&g_state.sapling_tree, &tree_root);
            if (memcmp(tree_root.data,
                       tip->hashFinalSaplingRoot.data, 32) != 0) {
                size_t old_size = incremental_tree_size(&g_state.sapling_tree);

                /* lane/sapling-tree-persist: a mismatch against the CURRENT
                 * tip does not by itself mean the tree is corrupt — it is
                 * the expected state whenever blocks were applied after the
                 * tree was last persisted. If the tree carries the height it
                 * was saved/verified at, check it against THAT height's own
                 * expected root first; a match proves an older-but-consistent
                 * frontier, so fold forward via sapling_tree_rebuild()'s
                 * existing checkpoint-resume path (bounded work proportional
                 * to tip - saved_height) instead of a full from-activation
                 * rebuild. Only a saved_height that itself fails to verify
                 * (or is absent) falls through to the unchanged full-rebuild
                 * fallback below — that path remains for genuine corruption. */
                bool folded_forward = false;
                if (sapling_tree_verify_at_saved_height(
                        &g_state.chain_active, &tree_root, old_size,
                        sapling_tree_saved_height, tip->nHeight) == 1) {
                    folded_forward = sapling_tree_attempt_fold_forward(ctx,
                        tip->nHeight, old_size, sapling_tree_saved_height);
                }

                if (!folded_forward) {
                if (tip->nHeight > 1000000) {
                    printf("Sapling tree root MISMATCH (size=%zu) - "
                           "deferring live rebuild until after boot "
                           "(tip_h=%d)\n", old_size, tip->nHeight);
                    sapling_tree_rebuild_start_deferred(&g_node_db, &g_state.chain_active, g_datadir, &g_state);
                    goto sapling_tree_boot_check_done;
                }
                printf("Sapling tree root MISMATCH (size=%zu) — "
                       "rebuilding from block files...\n", old_size);
                fflush(stdout);
                atomic_store(&g_sapling_tree_rebuilding, true);
                int n = sapling_tree_rebuild(&g_node_db,
                    &g_state.chain_active, g_datadir);
                if (n >= 0) {
                    /* Reload the rebuilt tree from node_state */
                    uint8_t tbuf[8192];
                    size_t tlen = 0;
                    if (node_db_state_get(&g_node_db, "sapling_tree",
                            tbuf, sizeof(tbuf), &tlen) && tlen > 0) {
                        struct byte_stream ts2;
                        stream_init_from_data(&ts2, tbuf, tlen);
                        sapling_tree_init(&g_state.sapling_tree);
                        incremental_tree_deserialize(
                            &g_state.sapling_tree, &ts2);
                        set_sapling_tree_for_flush(&g_state.sapling_tree);
                        printf("Sapling tree rebuilt: %d commitments "
                               "(was %zu)\n", n, old_size);
                    }
                }
                atomic_store(&g_sapling_tree_rebuilding, false);
                /* Checkpoint WAL after bulk tree writes */
                node_db_wal_checkpoint(&g_node_db);
                /* Save block_index.bin after rebuild — the entries
                 * now have correct hashFinalSaplingRoot fields from
                 * the rebuild. This prevents needless 5-min rebuilds
                 * on future boots AND ensures coins_best_block will
                 * be resolvable after a crash. */
                save_block_index_flat(ctx->datadir, &g_state);
                }
            }
        }
sapling_tree_boot_check_done:
        ;
    }

    boot_topmark("sapling_tree_load", t_phase);

    /* Timing only (no behavior change): mark the start of the
     * UTXO/chain reconcile span — clear-failed-above-tip, the
     * coins-vs-chain height mismatch repair, clean-above-tip, and the
     * activation anchor cleanup. This stretch sat between the
     * sapling_tree_load marker and the reducer activation boot phase and was
     * part of the warm-start unattributed gap. */
    int64_t t_reconcile_utxochain = boot_clock_ms();

    /* Clear BLOCK_FAILED flags above the chain tip on boot.
     * After a UTXO repair or crash recovery, blocks may be marked
     * BLOCK_FAILED_VALID/BLOCK_FAILED_CHILD from a prior session where
     * the UTXO set was incomplete. With the UTXO set now repaired,
     * these blocks should be re-validated. Without this, reducer activation
     * skips them and the node is permanently stuck. */
    chain_restore_clear_failed_above_tip(&g_state);

    /* Safety: verify chain tip matches UTXO set height (coins anchor
     * promotion + coins_best/tip reconcile, every real-block promotion
     * gated by the Invariant A trust-root check). Body lives in
     * boot_index.c. */
    boot_index_verify_coins_tip_consistency(&g_state, &g_coins_sqlite,
                                            &g_node_db);

    /* Clean up UTXOs above chain tip only after the mismatch repair above
     * has had a chance to promote a durable snapshot/coins anchor. Running
     * this earlier can delete the high-water UTXO rows that prove where an
     * immutable historical snapshot actually lands. */
    utxo_recovery_clean_above_tip(&g_node_db, &g_state);

    /* Activate best chain via controller (single authority).
     * The controller checks: anchor state, shutdown, UTXO availability.
     * Replaces the old skip_activate boolean with state machine. */
    if (activation_get_state(&g_activation_ctl) == ACTIVATION_BOOT_PENDING)
        activation_boot_complete(&g_activation_ctl, "boot_done");

    /* If anchor exists but chain tip is already past it (previous boot
     * synced successfully), clear the anchor so blocks can connect. */
    if (activation_get_state(&g_activation_ctl) == ACTIVATION_ANCHOR_ACTIVE) {
        struct block_index *tip = active_chain_tip(&g_state.chain_active);
        struct block_index *anc = snapsync_get_anchor();
        if (!anc) {
            printf("Restore anchor cleared during boot finalize — enabling activation\n");
            activation_clear_anchor(&g_activation_ctl, "restore_anchor_cleared");
        } else if (tip && anc && tip->nHeight > anc->nHeight) {
            printf("Anchor at h=%d below chain tip h=%d — clearing\n",
                   anc->nHeight, tip->nHeight);
            snapsync_set_anchor(NULL);
            activation_clear_anchor(&g_activation_ctl, "tip_past_anchor");
        }
    }
    boot_topmark("utxo_chain_reconcile", t_reconcile_utxochain);

    /* Reducer cursor/coins desync reconcile — runs AFTER coins_best is durable
     * (utxo_chain_reconcile above) and BEFORE the staged reducer Jobs init in
     * app_init_services, so the stages load a corrected cursor. If an unclean
     * restart left the tip_finalize cursor AHEAD of the applied coins tip,
     * tip_finalize idles and the connect gate rejects every block as
     * "block-not-finalized-by-reducer", wedging the chain. Clamp tip_finalize
     * down to the served-tip floor (coins_best == the applied tip's OWN height,
     * NOT coins_best+1 — the served-tip cursor convention) so it re-finalizes
     * forward. Reset-safe: deletes no log rows,
     * so the public tip can never drop below coins_best (proven in
     * test_stage_reducer_unwedge). No-op unless the cursor is ahead. */

    if (ctx->full_fold)
        /* GENESIS-FOLD-TO-TIP: same offline driver as -mint-anchor, but the fold
         * ceiling/target is the local header TIP and the terminal checkpoint
         * ceremony is skipped. ctx->full_fold implies ctx->mint_anchor, so this
         * pre-empts the mint reset below. */
        boot_full_fold_reset(&g_node_db, &g_state);
    else if (ctx->mint_anchor) boot_mint_anchor_reset(&g_node_db, ctx->mint_anchor_fast); /* ANCHOR-SET MINT: genesis reset + fold-cap at the anchor; fast => crypto pass-through */
    /* Zero-flag starter-pack bootstrap. Auto-selects a bundled seed only when
     * the current coins authority is absent or below that seed; the loader still
     * self-SHA3-verifies + anchor-binds before any trust. */
    bool snap_from_autodetect = false;
    char snapshot_fail_marker[BOOT_SNAPSHOT_FAILURE_MARKER_MAX] = {0};
    int32_t starter_coins_applied = -1;
    bool starter_coins_proven =
        coins_kv_is_proven_authority(progress_store_db(),
                                     &starter_coins_applied);
    (void)boot_snapshot_failure_memory_prepare(
        ctx,
        starter_coins_proven,
        starter_coins_applied,
        &snap_from_autodetect,
        snapshot_fail_marker,
        sizeof(snapshot_fail_marker));
    /* Offline TERMINAL verbs, placed here so the header chain is loaded for the
     * chain-binding evidence; each validates then _exit()s (never returns). */
    if (ctx->verify_consensus_bundle)
        boot_verify_consensus_bundle(ctx->verify_consensus_bundle, ctx->datadir);
    if (ctx->install_consensus_bundle)
        boot_install_consensus_bundle(&g_node_db, &g_state,
                                      ctx->install_consensus_bundle,
                                      ctx->datadir);
    if (ctx->ratify_mint_anchor)
        boot_ratify_mint_anchor(ctx->datadir);
    if (ctx->verify_rom)
        boot_verify_rom(ctx->datadir);
    if (ctx->export_consensus_bundle)
        boot_export_consensus_bundle(&g_node_db, &g_state, ctx->datadir);
    if (ctx->promote_shielded_history)  /* -> wedged COPY, header-bound Sapling */
        boot_promote_shielded_history(&g_state, ctx->datadir,
                                      ctx->promote_shielded_history);
    /* Explicit recovery: load digest-verified assisted state at its own header
     * height and fold forward. File integrity is not state provenance; posture
     * remains assisted until full-history promotion. */
    if (ctx->load_snapshot_at_own_height) {
        boot_load_snapshot_at_own_height_reset(&g_node_db,
                                               ctx->load_snapshot_at_own_height,
                                               ctx->datadir,
                                               &g_state,
                                               !ctx->no_legacy_auto_import);
        /* No early return may continue with a journaled partial generation. */
        boot_snapshot_install_require_complete();
    }
    /* The reset above ran anchor_kv_reset_mark_empty_below_in_tx(seed_h) with no
     * initial frontier; pre-seed the verified Sapling frontier at the seed cursor when
     * the in-RAM frontier aligns (else the runtime condition seeds it). */
    if (ctx->load_snapshot_at_own_height)
        boot_seed_sapling_anchor_frontier_after_reset(&g_state);
    /* The snapshot seed returned cleanly (the loader _exit()s on failure, so
     * reaching here means success) — drop the failure-memory marker (autodetect
     * OR explicit) so a later deliberate re-seed of the same bundle is allowed. */
    boot_snapshot_failure_memory_clear(snapshot_fail_marker);
    /* The from-anchor reset (LOAD+VERIFY the SHA3 anchor set into coins_kv, then
     * fold ONLY the anchor->tip delta) runs when EITHER:
     *   (a) the explicit -refold-from-anchor override is set, OR
     *   (b) -load-verify-boot is set AND a baked snapshot is present whose
     *       recomputed SHA3 == the compiled checkpoint AND coins_kv is not yet the
     *       proven authority (boot_load_verify_snapshot_eligible — pure probe).
     * (b) is ADDITIVE + SAFE-FALLBACK: with no verified snapshot the predicate is
     * false, so a normal boot runs its current path exactly and the cold-import
     * seed runs. The reset itself binds expected_sha3 = the compiled checkpoint inside
     * the loader AND hard-asserts the re-seeded set, so a mismatched/forged
     * snapshot can NEVER seed coins_kv and a from-genesis re-fold is never reached
     * as a silent fallback. */
    /* 1b/1c + A1 + from-anchor selection — boot_select_state_source (in
     * config/src/boot_auto_install_bundle.c): install a complete-state bundle
     * (a durable request OR <datadir>/bundles/<name>.sqlite) via the atomic installer,
     * which SUPERSEDES the transparent-only from-anchor reset; then consume any
     * armed refold request and compute do_from_anchor. Fail-closed + marker-guarded. */
    /* Arm the fold-span LOCAL body rebind: on a from-anchor / post-install
     * body-span gap (a header-only import carries hashes/heights but not body
     * positions), boot_refold_body_span_contiguous scans <datadir>/blocks so it
     * marks HAVE_DATA from the on-disk bodies before naming refold.body_gap.
     * Set here (before the install + do_from_anchor gates that consult it) so
     * the self-heal covers those callers without threading datadir through the
     * install-runtime seam. */
    boot_refold_body_rebind_set_datadir(ctx->datadir);

    struct boot_state_source_selection ssel;
    boot_select_state_source(&g_node_db, &g_state, ctx, &ssel);
    bool consumed_auto_refold = ssel.consumed_auto_refold;
    bool do_from_anchor = ssel.do_from_anchor;
    if (do_from_anchor) {
        /* B2 — reset the staged reducer to the SHA3 anchor (FULL coins_kv reset +
         * re-seed + HARD-ASSERT; FATALs inside on a mismatch), then mark the
         * from-anchor signal so the L0 floor holds at the anchor and the
         * self-repair is suspended until utxo_apply reaches the resume target
         * (the active tip we are about to fold up to). */
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        int32_t resume_target =
            (int32_t)active_chain_height(&g_state.chain_active);
        if (cp) {
            int32_t first_missing = -1;
            if (!boot_refold_body_span_contiguous(
                    &g_state, cp->height, resume_target, &first_missing,
                    /*raise_blocker=*/true)) {
                fprintf(stderr,
                        "WARNING: refold-from-anchor: fold span (%d..%d] "
                        "has a missing block body at h=%d — refusing the "
                        "explicit cutover before resetting coins_kv. Fill the "
                        "body span and retry.\n",
                        cp->height, resume_target, first_missing);
                event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                            "refold_from_anchor body_gap anchor=%d "
                            "resume_target=%d first_missing=%d",
                            cp->height, resume_target, first_missing);
                return false;
            }
        }
        boot_refold_from_anchor_reset(&g_node_db);
        /* The reset committed the verified anchor set (it _exit()s on mismatch,
         * so reaching here = success) — clear the consumed refold request so a
         * future healthy boot does not re-run it. */
        if (consumed_auto_refold)
            boot_auto_refold_clear(ctx->datadir);
        /* The from-anchor reset cleared node_state["sapling_tree"] to NULL.
         * Carry the fail-closed guard from the snapshot-loader path: re-derive
         * + VERIFY the Sapling commitment tree against the chain BEFORE the
         * forward fold runs, so a corrupt/incoherent seed tree FATALs here
         * rather than silently rebuilding wrong downstream. sapling_tree_rebuild
         * resolves its own endpoint from coins-applied state and returns < 0
         * (fail-closed) on any per-height root mismatch; it is a no-op below
         * Sapling activation. g_datadir is the active datadir. */
        if (g_datadir) {
            atomic_store(&g_sapling_tree_rebuilding, true);
            int sret = sapling_tree_rebuild(&g_node_db, &g_state.chain_active,
                                            g_datadir);
            atomic_store(&g_sapling_tree_rebuilding, false);
            if (sret < 0) {
                fprintf(stderr,
                        "WARNING: refold-from-anchor: sapling_tree_rebuild "
                        "failed (returned %d) — refusing to fold on an "
                        "unverified Sapling commitment tree. Entering bounded "
                        "crash-only re-derive instead of FATAL-crash-looping.\n",
                        sret);
                event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                            "refold_from_anchor sapling_tree_rebuild_failed "
                            "rc=%d", sret);
                /* Sticky boot (#6): a failed post-anchor sapling rebuild is a
                 * derived-state incoherence (the re-seeded anchor's commitment
                 * tree did not reproduce a per-height root). -reindex-chainstate
                 * re-derives the chainstate (and the from-anchor reset re-runs)
                 * on the restart; bounded so a genuinely corrupt base parks
                 * alive-degraded rather than _exit()ing into a crash-loop. */
                if (boot_crashonly_storage_gate(ctx->datadir,
                        "refold_sapling_rebuild",
                        boot_index_reindex_replay_executable(&g_state,
                            &g_block_tree, g_block_tree_open, ctx->datadir))
                        == BOOT_GATE_PARK_DEGRADED)
                    return boot_park_until_shutdown("refold_sapling_rebuild");
                return false;
            }
            /* Reload the verified tree into the live in-memory state. */
            uint8_t tbuf[8192];
            size_t tlen = 0;
            if (node_db_state_get(&g_node_db, "sapling_tree",
                                  tbuf, sizeof(tbuf), &tlen) && tlen > 0) {
                struct byte_stream ts2;
                stream_init_from_data(&ts2, tbuf, tlen);
                sapling_tree_init(&g_state.sapling_tree);
                if (incremental_tree_deserialize(&g_state.sapling_tree, &ts2))
                    set_sapling_tree_for_flush(&g_state.sapling_tree);
            }
        }
        /* The from-anchor reset ran anchor_kv_reset_mark_empty_below_in_tx(anchor)
         * with no initial frontier; sapling_tree_rebuild just re-derived + verified the
         * Sapling frontier to the anchor (== activation cursor), so seed it now
         * and the first shielded block above the anchor folds without stalling
         * (else the runtime condition is the backstop). */
        boot_seed_sapling_anchor_frontier_after_reset(&g_state);
        (void)refold_progress_mark_started_from_anchor(progress_store_db(),
                                                       resume_target);
    }

    {
        /* SINGLE SOURCE OF TRUTH (docs/work/tip-durability-collapse.md):
         * floor on the GENUINE coins frontier. Wave 2: that frontier is
         * DERIVED — coins_applied_height-1 straight from progress.kv's own
         * co-committed state (no hash->block_map->height roundtrip through
         * the node_state cache). Legacy fallback: height(coins_best_block
         * HASH). Under-rewind is SAFE (more forward re-finalize, never
         * ahead); no rows deleted. */
        int64_t coins_best = -1;
        struct boot_derived_coins_best clamp_dcb;
        if (boot_derive_coins_best(&clamp_dcb)) {
            coins_best = clamp_dcb.height;
        } else {
            struct uint256 cbh; uint256_set_null(&cbh);
            if (g_coins_sqlite.db) coins_view_sqlite_get_best_block(&g_coins_sqlite, &cbh);
            struct block_index *cb = uint256_is_null(&cbh) ? NULL : block_map_find(&g_state.map_block_index, &cbh);
            coins_best = cb ? (int64_t)cb->nHeight : -1;
        }
        if (coins_best >= 0) {
            struct sqlite3 *pdb = progress_store_db();
            struct stage_reconcile_result rr;
            if (pdb &&
                stage_reconcile_clamp_tip_finalize_to_floor(
                    pdb, (int)coins_best, &rr) && rr.clamped) {
                printf("[boot] reducer reconcile: clamped tip_finalize cursor "
                       "to served-tip floor=%d (own height of the applied "
                       "coins frontier / deepest finalized row) — "
                       "re-finalizing forward\n",
                       rr.floor);
                service_state_transition_and_persist(SERVICE_STATE_RECONCILE,
                                      "reducer cursor/coins desync reconcile");
            }
        }
    }

    {
        int restored_h = active_chain_height(&g_state.chain_active);
        if (boot_restored_authority_tip && restored_h > 1000) {
            printf("[boot] skipping initial reducer activation after "
                   "authority restore h=%d; coordinator will advance after "
                   "RPC/P2P start\n",
                   restored_h);
            event_emitf(EV_BOOT_ACTIVATE, 0,
                        "skip_initial_activate restored_authority_tip=%d",
                        restored_h);
        } else {
            struct boot_phase bp_act;
            boot_phase_begin(&bp_act, "reducer_activation");
            struct activation_exec_outcome outcome;
            activation_request_connect(&g_activation_ctl, ACTIVATION_SRC_BOOT,
                                       NULL, &outcome);
            if (outcome.result == ACTIVATION_EXEC_FAILED)
                fprintf(stderr, "Warning: Failed to activate best chain: %s\n",
                        outcome.reason);
            boot_phase_end(&bp_act);
        }
    }

    /* final sweep. Post-activation is the last point at
     * which block_map and active_chain could still carry the anchor-
     * restore limp (nBits==0 entries, chain_active holes below tip); the
     * finalize also covers the block-file-scan + `Post-activation: fixed
     * N pprev heights from anchor` path in msg_headers that runs before
     * reducer activation completes. No-op when the integrity check
     * passes; logs a loud stderr line + fills what it can when it does
     * not. Safe on every boot — O(block_map) + one disk read per nBits
     * gap; the real live-node shape is ≤200 reads.
     *
     * Part L: honor the return value. A failed post-restore check at
     * a non-trivial tip height means the on-disk state is corrupted
     * past automatic repair (e.g. 3M holes in active_chain). The user
     * framing — "be brutal, fail fast" — means we refuse to proceed
     * into a half-loaded state. Operators who want the legacy "log
     * loud, continue" behavior must opt in with -allow-degraded. */
    /* Rewind a placeholder tip.
     *
     * If a placeholder (nBits==0) ever became our active tip — e.g.,
     * because a chain_restore anchor at h=N was promoted into the
     * active chain before its real block data arrived — every
     * subsequent header will be rejected with bad-diffbits since
     * GetNextWorkRequired sees prev_bits=0. Walk pprev until we hit
     * a real block, set THAT as the active tip, and let gap-fill
     * resync from there. */
    {
        struct block_index *tip = active_chain_tip(&g_state.chain_active);
        if (tip && tip->nBits == 0 && tip->nHeight > 0) {
            struct block_index *walk = tip->pprev;
            int last_h = tip->nHeight + 1;
            int steps = 0;
            while (walk && walk->nBits == 0 &&
                   walk->pprev && walk->pprev->nHeight < walk->nHeight &&
                   walk->nHeight < last_h && steps++ < 10000) {
                last_h = walk->nHeight;
                walk = walk->pprev;
            }
            if (walk && walk->nBits != 0) {
                fprintf(stderr,
                    "[boot] placeholder tip at h=%d (nBits=0); rewinding "
                    "to last real block h=%d\n",
                    tip->nHeight, walk->nHeight);
                if (boot_promote_tip_via_csr(
                        walk, "rewind_placeholder_tip", true) &&
                    walk->phashBlock) {
                    if (g_node_db.open)
                        (void)coins_rewind_above_tip(
                            g_node_db.db, walk->nHeight, -1);
                }
            } else {
                fprintf(stderr,
                    "[boot] placeholder tip at h=%d but no valid "
                    "ancestor found within 10000 steps; chain stuck\n",
                    tip->nHeight);
            }
        }
    }

    {
        struct boot_phase bp_fin;
        boot_phase_begin(&bp_fin, "chain_restore_finalize");
        service_state_advance(SERVICE_STATE_RECONCILE,
                              "post-restore finalize gate");
        struct zcl_result finalize_r = chain_restore_finalize_verified(
            &g_state, ctx->datadir, index_repaired, g_state.map_block_index.size);
        bool finalize_ok = finalize_r.ok;
        if (!finalize_ok)
            fprintf(stderr,
                    "[boot] chain_restore_finalize failed: code=%d msg=%s\n",
                    finalize_r.code, finalize_r.message);
        boot_phase_end(&bp_fin);
        int  tip_h = active_chain_height(&g_state.chain_active);

        /* Mint/refold flags reset the staged reducer to genesis (or the SHA3
         * anchor) and re-fold over on-disk bodies — boot_*_reset above ALREADY
         * discarded the upper active chain these flags exist to rebuild. So the
         * post-restore integrity of that upper chain is moot: failing it here
         * would abort init (crash-only -reindex-chainstate request) BEFORE the
         * fold ever runs, on damage the fold replaces. Downgrade the failure to
         * a logged warning and skip the abort/degraded gate so boot proceeds to
         * the reset+fold. A normal boot (no flag) is unchanged: the gate below
         * stays fatal on UNRECOVERABLE integrity. */
        bool mint_or_refold =
            ctx->mint_anchor || ctx->refold_from_anchor || ctx->refold_staged ||
            ctx->load_snapshot_at_own_height != NULL;
        if (mint_or_refold && !finalize_ok) {
            fprintf(stderr,
                "[boot] mint/refold flag set: skipping the chain_restore_finalize "
                "integrity abort at tip_h=%d — the reset above already discarded "
                "the upper chain; the genesis->anchor fold rebuilds it.\n",
                tip_h);
            event_emitf(EV_BOOT_ACTIVATE, 0,
                "finalize_integrity_skipped_for_refold tip=%d", tip_h);
            finalize_ok = true;  /* take the clean-integrity branch below */
        }

        /* Classify the post-restore integrity result on its structured
         * breakdown — the finalize bool discards it. A RECONCILABLE
         * divergence (active_chain window holes, with no zero-nbits and
         * no height/pprev mismatch) is normal coins-application lag:
         * headers/bodies are ahead of the applied tip, NOT corruption.
         * It is NEVER fatal — the node enters DEGRADED_SERVING and the
         * condition engine reconciles it forward, so the process always
         * boots into an observable state instead of crash-looping. Only
         * true structural corruption (zero nbits in the tip window, or
         * active_chain height/pprev mismatches) stays fatal, and then
         * LOUD + observable, never a silent loop.
         *
         * This does NOT weaken any consensus gate: the integrity check
         * only counts NULL active_chain[] slots. The consensus gates
         * (connect_block prevhash, CSR rejection, find_most_work_chain
         * validity/HAVE_DATA filters, PoW/sig/proof verification) are
         * untouched and still reject bad blocks. */
        struct chain_integrity_result integ;
        chain_integrity_check_post_restore(&integ, &g_state);
        enum chain_integrity_class cls = chain_integrity_classify(&integ);

        if (!finalize_ok && tip_h > 1000) {
            if (cls == CHAIN_INTEGRITY_UNRECOVERABLE && !ctx->allow_degraded) {
                /* Crash-only: the reindex-recoverable shape (zero_nbits==0, a
                 * derived tip above the validated index extent) auto-requests a
                 * self-rebuild; structural corruption / exhausted budget pages.
                 * Verb check first: replay-from-blocks/ needs genesis-side
                 * block data, which a cold-import datadir does not have —
                 * probe h=1 readability so the classifier never exits into an
                 * impossible rebuild. */
                bool reindex_ok = false;
                {
                    struct block_index *probe =
                        active_chain_at(&g_state.chain_active, 1);
                    struct block pblk;
                    if (probe && read_block_from_disk_index(&pblk, probe,
                                                            ctx->datadir)) {
                        block_free(&pblk);
                        reindex_ok = true;
                    }
                }
                if (boot_crashonly_handle_unrecoverable(ctx->datadir, tip_h,
                        integ.zero_nbits_count, integ.active_chain_mismatches,
                        integ.first_mismatch_height, reindex_ok))
                    return false;
                /* handle_unrecoverable returned false => stay-up-degraded, not
                 * exit. Either the reindex was unexecutable (cold-import window)
                 * or the bounded reindex budget is EXHAUSTED at a stable anchor
                 * (terminal marker persisted; operator paged once). In BOTH
                 * cases the page already fired and operator_needed is latched;
                 * serve DEGRADED so the reducer reconciles forward instead of
                 * crash-looping. The DEGRADED_SERVING state gates the advance to
                 * SYNCING (only the clean-integrity else-branch below transitions
                 * to SYNCING), so the node never serves a bad tip while
                 * degraded. */
                service_state_transition_and_persist(
                    SERVICE_STATE_DEGRADED_SERVING,
                    "reindex unexecutable or budget exhausted; operator needed");
            } else if (cls == CHAIN_INTEGRITY_UNRECOVERABLE) {
                fprintf(stderr,
                    "[boot] WARNING: post-restore structural corruption at "
                    "tip_h=%d; serving DEGRADED because -allow-degraded was "
                    "set.\n", tip_h);
                event_emitf(EV_BOOT_ACTIVATE, 0,
                    "degraded_serving allow_degraded_corruption tip=%d",
                    tip_h);
                service_state_transition_and_persist(SERVICE_STATE_DEGRADED_SERVING,
                    "allow-degraded over structural corruption");
            } else {
                /* RECONCILABLE: coins-application lag. Self-heal; never
                 * exit. The node serves at the contiguous applied tip
                 * while the condition engine reconciles forward. */
                fprintf(stderr,
                    "[boot] post-restore integrity: reconcilable divergence "
                    "at tip_h=%d (tip_window_holes=%d first_hole_h=%d) — "
                    "entering DEGRADED_SERVING; condition engine reconciles "
                    "forward. Not fatal.\n",
                    tip_h, integ.tip_window_holes,
                    integ.first_tip_window_hole);
                event_emitf(EV_BOOT_ACTIVATE, 0,
                    "degraded_serving reconcilable_integrity tip=%d holes=%d",
                    tip_h, integ.tip_window_holes);
                service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                    "reconcilable post-restore divergence");
            }
            (void)service_state_persist_to_progress_store();
        } else {
            /* Clean integrity — the rebuild (if any) converged; clear the budget. */
            boot_crashonly_clear(ctx->datadir);
            service_state_transition_and_persist(SERVICE_STATE_SYNCING,
                                  "post-restore integrity clean");
        }
    }

    /* Auto-scan wallet for transactions in connected blocks.
     * This ensures balance shows immediately after LDB import or
     * snapshot sync — no manual replaywalletfromchain needed.
     * A power node should just work. */
    {
        int tip_h = active_chain_height(&g_state.chain_active);
        if (tip_h > 0 && g_node_db.open) {
            struct boot_phase bp_ws;
            boot_phase_begin(&bp_ws, "wallet_scan_blocks");
            /* O(delta) boot: cursor-gated so each boot scans only [cursor+1,
             * tip] (full scan only on a missing cursor or a changed keyset). */
            int found = boot_cursor_scan_wallet(&g_node_db,
                &g_state.chain_active, &g_wallet, ctx->datadir, tip_h);
            boot_phase_end(&bp_ws);
            if (found > 0)
                printf("Wallet: auto-discovered %d transactions "
                       "(blocks 0-%d)\n", found, tip_h);
        }
    }

    /* Timing only (no behavior change): mark the start of the
     * finalize-and-build span — finalize_chain_state, shielded backfill,
     * and svc-ctx build — which sat uninstrumented between the
     * wallet_scan_blocks boot_phase and the p2p_services_start marker. */
    int64_t t_finalize_build = boot_clock_ms();

    /* CHAIN_TIP_RESOLVED boundary: finalize (restore normal SQLite mode,
     * persist the resolved tip, stamp boot_status) runs as this stage's
     * record. */
    {
        struct zcl_result cr =
            sysinit_run_stage(BOOT_STAGE_CHAIN_TIP_RESOLVED, ctx);
        if (!cr.ok) return false;
    }
    struct block_index *tip = active_chain_tip(&g_state.chain_active);

    /* -reindex-explorer: truncate + rewind AFTER finalize re-stamped the tip
     * so the backfill re-walks genesis..tip (node.db only, boot_index.c). */
    if (ctx->reindex_explorer && g_node_db.open)
        boot_reindex_explorer(&g_node_db);

    /* -backfill-nullifiers / ZCL_NULLIFIER_BACKFILL=1: one-shot
     * populate-only remediation for the nullifier activation gap. Runs
     * before P2P/RPC/runtime services and exits through main.c. */
    if (ctx->backfill_nullifiers) {
        struct nullifier_backfill_config nbc = {
            .main = &g_state, .ndb = &g_node_db,
            .progress_db = progress_store_db(),
            .datadir = ctx->datadir,
        };
        struct nullifier_backfill_report nbr;
        struct zcl_result r =
            nullifier_backfill_service_run(&nbc, &nbr);
        if (!r.ok) {
            fprintf(stderr, // obs-ok:nullifier-backfill-terminal-fatal
                    "FATAL: nullifier backfill failed: code=%d %s\n",
                    r.code, r.message);
            return false;
        }
        printf("Nullifier backfill: complete=%s already_complete=%s "
               "range=[%lld,%lld) scanned=%lld\n",
               nbr.completed ? "true" : "false",
               nbr.already_complete ? "true" : "false",
               (long long)nbr.start_height,
               (long long)nbr.target_exclusive,
               (long long)nbr.blocks_scanned);
        return true;
    }

    /* -backfill-zslp: one-shot re-derive of zslp_* from op_returns (no full
     * block re-walk), then exit before services. The helper guards db-open. */
    if (ctx->backfill_zslp) {
        boot_backfill_zslp(&g_node_db);
        return true;
    }

    boot_step_backfill_shielded_if_needed(ctx, tip);

    /* -mint-anchor is a one-shot offline reducer driver. app_init has already
     * opened storage, restored chain/index state, applied the genesis reset and
     * anchor cap, and initialized the activation controller. Stop here: the
     * fast-mint variant arms a crypto pass-through for script/proof stages, so
     * starting P2P/RPC/runtime services before the driver runs violates the
     * offline-only boundary. Initialize the eight stages without supervisor
     * children and let main.c call boot_mint_anchor_run(). */
    if (ctx->mint_anchor) {
        if (!staged_sync_supervisor_init_stages_offline(&g_state)) {
            fprintf(stderr,
                    "FATAL: -mint-anchor: offline reducer stage init failed\n");
            return false;
        }
        printf("[boot] -mint-anchor: offline reducer stages initialized; "
               "skipping frontend/P2P/runtime services\n");
        boot_topmark("total", t_boot_start);
        boot_flight_recorder_finish(&g_node_db);
        boot_stage_advance_to(BOOT_STAGE_READY);
        return true;
    }

    /* Skip services if no_services flag is set (speedrun / benchmarking) */
    if (ctx->no_services) {
        printf("Boot complete (no_services mode). "
               "Chain tip: height=%d\n",
               active_chain_height(&g_state.chain_active));
        return true;
    }

    /* Runtime services: mempool, P2P, RPC, Tor, wallet sync (boot_services.c) */
    struct boot_svc_ctx svc;
    boot_step_build_svc_ctx(ctx, &svc);
    /* g_svc is stored so app_shutdown can access it */
    g_svc = svc;

    /* Emit crash recovery complete if boot succeeded */
    {
        int chain_h = active_chain_height(&g_state.chain_active);
        event_emitf(EV_CRASH_RECOVERY_COMPLETE, 0,
            "chain_height=%d", chain_h);
    }

    boot_topmark("finalize_and_build", t_finalize_build);

    t_phase = boot_clock_ms();
    bool svc_ok = app_init_services(ctx, params, &g_svc);
    boot_topmark("p2p_services_start", t_phase);
    boot_topmark("total", t_boot_start);
    boot_flight_recorder_finish(&g_node_db);
    /* Per-scanner O(delta) row counts, next to the timing (see util/boot_scan.h). */
    boot_scan_log_summary("boot-complete");
    if (svc_ok) {
        /* SERVICES_RUNNING boundary: background maintenance services
         * (disk_monitor/ibd_throttle already up; db_maintenance/wallet_backup/
         * sync_watchdog started here) come up BEFORE the node advertises READY.
         * NETWORK_READY was advanced inside app_init_services. */
        struct zcl_result sr =
            sysinit_run_stage(BOOT_STAGE_SERVICES_RUNNING, ctx);
        if (!sr.ok) return false;
        boot_stage_advance_to(BOOT_STAGE_READY);
        /* Tier-2 fast restart: if this boot SKIPPED quick_check, run one in the
         * background now (failure raises OPERATOR_NEEDED — never silent). */
        boot_fast_restart_start_bg_quick_check(g_datadir);
    }
    return svc_ok;
}

/* AS-safe SIGALRM backstop. app_shutdown_svc drives a per-stage stagewatch
 * (util/shutdown_stagewatch.h); a fired per-stage deadline lands here and the
 * stagewatch decides truthfully: re-arm a bounded grace for a durability-
 * critical stall, or force a truthful exit (code 0 once durability is secured,
 * code 1 only if it was never reached) after writing a terminal receipt. If
 * the stagewatch was never begun (a shutdown path that armed a raw alarm), it
 * falls back to the legacy loud forced exit. Async-signal-safe throughout. */
static void shutdown_alarm_abort(int sig)
{
    (void)sig;
    shutdown_stagewatch_on_alarm();
}

/* app_shutdown delegates to boot_services.c */
void app_shutdown(void)
{
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_REQUESTED);
    /* Backstop must be live BEFORE app_shutdown_svc arms alarm(90). */
    signal(SIGALRM, shutdown_alarm_abort);
    boot_stop_platform_services();
    app_shutdown_svc(&g_svc);
    boot_postmortem_stop();
    /* app_shutdown_svc completed the marker + receipt durability barrier. */
    boot_datadir_lock_release();
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_COMPLETE);
}

void app_shutdown_offline(void)
{
    bool durability_ok = true;
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_REQUESTED);
    signal(SIGALRM, shutdown_alarm_abort);
    shutdown_stagewatch_begin(g_datadir);
    shutdown_stagewatch_enter("offline-worker-drain", 15, false, true);
    thread_registry_request_shutdown();
    event_async_stop();
    boot_stop_platform_services();
    boot_stop_db_service_kernel();
    staged_sync_supervisor_shutdown_stages();
    boot_offline_join_workers_or_exit(g_datadir);
    coins_view_cache_free(&g_coins_tip);
    coins_view_sqlite_close(&g_coins_sqlite);
    if (g_wallet_sqlite.open) {
        struct zcl_result r = wallet_sqlite_flush_r(&g_wallet_sqlite, &g_wallet);
        if (!r.ok) {
            durability_ok = false;
            fprintf(stderr,
                    "[shutdown] offline wallet flush failed: code=%d "
                    "message=%s source=%s:%d\n",
                    r.code,
                    r.message[0] ? r.message : "wallet_sqlite_flush_r failed",
                    r.source_file ? r.source_file : "?", r.source_line);
        }
        wallet_sqlite_close(&g_wallet_sqlite);
    }
    wallet_free(&g_wallet);
    main_state_free(&g_state);
    sapling_free_params();
    if (!boot_offline_persist_runtime(&g_node_db))
        durability_ok = false;
    ecc_verify_destroy();
    ecc_stop();
    boot_postmortem_stop();
    boot_offline_complete_durability_or_exit(g_datadir, durability_ok);
    boot_datadir_lock_release();
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_COMPLETE);
}

bool app_is_running(void) { return atomic_load(&g_running); }

/* app_add_node, app_start_metrics, app_stop_metrics: boot_services.c */
