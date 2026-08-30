#define _GNU_SOURCE  /* pthread_timedjoin_np */
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Runtime service initialization: mempool, P2P, RPC, Tor, HTTPS,
 * mining, wallet sync, shutdown, and utility functions. */
#include "platform/time_compat.h"
#include "config/boot_internal.h"
#include "config/boot_refusal_reports.h"
#include "util/sysinit.h"
#include "config/boot_shutdown_marker.h"
#include "util/shutdown_stagewatch.h"
#include "config/boot_background_workers.h"
#include "config/bundle_fetch_seeds.h"  /* ZCL_BUNDLE_FETCH_CLEARNET_SEEDS */
#include "config/boot_flyclient.h"
#include "config/boot_snapshot_offer.h"
#include "config/boot_msg_callbacks.h"
#include "config/boot_zcode_dht.h"
#include "config/boot_mesh_pairing.h"
#include "config/boot_mesh_status.h"
#include "config/boot_mesh_terminal.h"
#include "config/boot_mesh_machines.h"
#include "services/binary_ab_fallback.h"
#include "services/chain_activation_service.h"
#include "services/block_index_integrity.h"
#include "services/block_source_policy.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_state_service.h"
#include "services/chain_tip.h"
#include "services/catchup_lifecycle_service.h"
#include "services/hodl_history_service.h"
#include "services/quorum_oracle_service.h"
/* The eight staged-sync stage Job headers are no longer included here: stage
 * teardown relocated to the staged-sync supervisor unit, which owns the
 * stages' init + registration too. boot_services.c reaches the pipeline only
 * through supervisors/staged_sync_supervisor.h now. */
#include "jobs/refold_progress.h"      /* refold_from_anchor_active (-load-verify-boot skip) */
#include "config/boot_fast_restart.h"  /* boot_fast_restart_capture_shutdown_facts (P2) */
#include "services/chain_tip_watchdog.h"
#include "services/address_index_service.h"
#include "services/txindex_projection_service.h"
#include "services/sticky_escalator.h"
#include "services/recovery_coordinator.h"
#include "services/invariant_sentinel.h"
#include "conditions/condition_registry.h"
#include "supervisors/domains.h"
#include "supervisors/self_heal.h"
#include "supervisors/net_supervisor.h"
#include "supervisors/chain_supervisor.h"
#include "supervisors/staged_sync_supervisor.h"
#include "services/node_health_service.h"
#include "services/blocker_history.h"
#include "services/build_fabric_runtime.h"
#include "health/heartbeat.h"
#include "util/sd_notify.h"
#include "util/alerts.h"
#include "config/boot_flight_recorder.h"  /* boot_mark_step: marker + next step name */
#include "util/boot_phase.h"              /* boot_step_enter / boot_step_fail */
#include "util/boot_progress.h"
#include "util/log_macros.h"
#include "util/ar_step_readonly.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/blocker.h"
#include "util/util.h"
#include "net/connman.h"
#include "config/boot_snapshot_import.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/mempool_projection.h"
#include "storage/peers_projection.h"
#include "storage/event_log_singleton.h"
#include "storage/block_index_projection.h"
#include "storage/znam_projection.h"
#include "storage/wallet_projection.h"
#include "storage/small_projections.h"
#include "storage/progress_store.h"
#include "services/block_index_loader.h"
#include "services/reducer_ingest_service.h" /* reducer_ingest_try_seed_anchor (regtest genesis boot seed) */
#include "jobs/tip_finalize_stage.h"         /* tip_finalize_stage_cursor + active_chain_tip */
#include "models/block.h"
#include "models/file_offer.h"
#include "models/file_service.h"
#include "models/utxo.h"
#include "models/zmsg.h"
#include "chain/chainparams.h"
#include "chain/mmr.h"
#include "chain/subsidy.h"
#include "core/uint256.h"
#include "coins/coins_view.h"
#include "controllers/blockchain_controller.h"
#include "controllers/chain_segment_controller.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/hodl_controller.h"
#include "controllers/repair_controller.h"
#include "controllers/chain_inspect_controller.h"
#include "controllers/misc_controller.h"
#include "controllers/network_controller.h"
#include "controllers/mining_controller.h"
#include "controllers/file_controller.h"
#include "net/file_service.h"
#include "controllers/transaction_controller.h"
#include "controllers/api_controller.h"
#include "controllers/explorer_internal.h"
#include "controllers/explorer_controller.h"
#include "controllers/wallet_controller.h"
#include "controllers/zslp_controller.h"
#include "controllers/sync_controller.h"
#include "controllers/event_controller.h"
#include "controllers/snapshot_controller.h"
#include "controllers/game_controller.h"
#include "controllers/health_controller.h"
#include "controllers/file_market_controller.h"
#include "controllers/name_controller.h"
#include "controllers/anchor_controller.h"
#include "controllers/identity_controller.h"
#include "controllers/mesh_pairing_controller.h"
#include "controllers/zdir_controller.h"
#include "controllers/op_return_index_controller.h"
#include "services/op_return_backfill_service.h"
#include "services/zslp_ledger_backfill_service.h"
#include "services/state_auditor.h"
#include "services/telemetry_watch_service.h"
#include "controllers/rpc_client.h"
#include "controllers/messaging_controller.h"
#include "controllers/swap_controller.h"
#include "controllers/blog_controller.h"
#include "controllers/blog_post_controller.h"
#include "rpc/httpserver.h"
#include "rpc/legacy_chain_oracle.h"
#include "rpc/server.h"
#include "command/native_dev_hotswap.h"
#include "json/json.h"
#include "net/https_server.h"
#include "net/fast_sync.h"
#include "net/peer_lifecycle.h"
#include <limits.h>
#include "config/boot_onion_discovery.h"
#include "config/boot_zcode_async_proof.h"
#include "net/peer_strategy_worker.h"
#include "net/tor_integration.h"
#include "net/version.h"
#include "util/thread_registry.h"
#include "validation/mirror_consensus.h"
#include "validation/process_block.h"
#include "event/event.h"
#include "util/service_state.h"
#include "sync/sync_state.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "sapling/params_init.h"
#include "platform/socket_compat.h"
#include <errno.h>
#include <stdatomic.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include "config/boot_mempool_limits.h"
#include "services/wallet_backup_service.h"
#include "services/disk_monitor.h"
#include "services/ibd_throttle.h"
#include "services/sync_monitor.h"
#include "net/download.h"
#include "net/msgprocessor.h"
#include "services/db_maintenance.h"
#include "metrics/prometheus_metrics.h"
extern _Atomic int g_deferred_proof_validation_below_height;
/* Boot context accessors. The handle is threaded explicitly by every caller;
 * the boot svc is owned by boot.c's g_svc, reached via boot_active_svc(). */
static struct app_runtime_context *boot_runtime(struct boot_svc_ctx *svc)
{
    if (!svc)
        return NULL;
    return &svc->runtime;
}
struct node_db *boot_node_db(struct boot_svc_ctx *svc)
{
    struct app_runtime_context *runtime = boot_runtime(svc);
    if (!runtime || !runtime->db_service)
        return NULL;
    return db_service_node_db(runtime->db_service);
}
struct db_service *boot_db_service(struct boot_svc_ctx *svc)
{
    struct app_runtime_context *runtime = boot_runtime(svc);
    if (!runtime)
        return NULL;
    return runtime->db_service;
}
/* Runtime-profile gate accessors. Non-static (prototypes in boot_internal.h)
 * because app_init call sites AND boot_frontend_services.c read them across
 * the TU boundary; they stay beside boot_profile_has_file_service. */
bool boot_profile_has_explorer(const struct app_context *ctx)
{
    if (!ctx)
        return true;
    return app_runtime_profile_has_explorer(ctx->runtime_profile);
}

bool boot_profile_has_store(const struct app_context *ctx)
{
    if (!ctx)
        return true;
    return app_runtime_profile_has_store(ctx->runtime_profile);
}

bool boot_profile_has_onion(const struct app_context *ctx)
{
    return ctx && app_runtime_profile_has_onion(ctx->runtime_profile,
                                                ctx->tor);
}

/* FIX 1 seam (see boot_internal.h). PURE: no side effects. */
bool boot_loader_owns_seed(const struct app_context *ctx)
{
    return ctx && ctx->load_snapshot_at_own_height != NULL;
}

bool boot_profile_has_file_service(const struct app_context *ctx)
{
    if (!ctx)
        return true;
    return app_runtime_profile_has_file_service(ctx->runtime_profile);
}

/* Boot timing helper — mirrors boot.c:boot_clock_ms() so sub-stage markers
 * share the top-level [boot] <phase> Nms monotonic-ms basis. Timing only. */
static int64_t svc_clock_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool boot_connman_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    return svc && svc->connman && connman_start(svc->connman);
}

static void boot_connman_stop(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (svc && svc->connman)
        connman_signal_stop(svc->connman);
}

static int boot_known_zcl23_peers(void *ctx,
                                  struct connman_known_peer *out,
                                  size_t max)
{
    struct boot_svc_ctx *svc = ctx;
    struct db_peer peers[8];
    size_t want = max < 8 ? max : 8;

    if (!svc || !svc->node_db || !svc->node_db->open || !out || want == 0)
        return 0;

    int n = db_peer_fast_zcl23(svc->node_db, peers, want);
    if (n <= 0)
        return n;
    for (int i = 0; i < n; i++) {
        memcpy(out[i].ip, peers[i].ip, 16);
        out[i].port = peers[i].port;
        out[i].services = peers[i].services;
    }
    return n;
}

static bool boot_register_network_services(struct boot_svc_ctx *svc)
{
    const struct zcl_service_spec connman_spec = {
        .name = "connman",
        .start = boot_connman_start,
        .stop = boot_connman_stop,
        .ctx = svc,
    };
    return zcl_service_kernel_register(&svc->network_kernel, &connman_spec);
}

static bool boot_register_runtime_services(struct boot_svc_ctx *svc)
{
    const struct zcl_service_spec specs[] = {
        {
            .name = "bg_validation",
            .start = boot_bg_validation_start,
            .stop = boot_bg_validation_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "bg_hash_verify",
            .start = boot_bg_hash_verify_start,
            .stop = boot_bg_hash_verify_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "header_probe",
            .start = boot_header_probe_start,
            .stop = boot_header_probe_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "gap_fill",
            .start = boot_gap_fill_start,
            .stop = boot_gap_fill_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "legacy_mirror",
            .start = boot_legacy_mirror_start,
            .stop = boot_legacy_mirror_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "zclassicd_oracle",
            .start = boot_zclassicd_oracle_start,
            .stop = boot_zclassicd_oracle_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "rolling_anchor",
            .start = boot_rolling_anchor_start,
            .stop = boot_rolling_anchor_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
        {
            .name = "sd_watchdog",
            .start = boot_sd_watchdog_start,
            .stop = boot_sd_watchdog_stop,
            .ctx = svc,
            .flags = ZCL_SERVICE_OPTIONAL,
        },
    };

    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); i++) {
        if (!zcl_service_kernel_register(&svc->runtime_kernel, &specs[i]))
            return false;
    }
    if (!boot_utxo_parity_register(svc) ||
        !boot_soak_attestation_register(svc) ||
        !boot_canary_watch_register(svc) ||
        !boot_mem_pressure_register(svc) ||
        !boot_utxo_mirror_sync_register(svc) ||
        !boot_supervisor_backstop_register(svc) ||
        !boot_segment_sealer_register(svc))
        return false;

    /* Register the node.db-writing payment worker last so reverse-order
     * runtime shutdown signals and joins it before any other runtime stop.
     * The entire runtime kernel drains before DB/WAL/state release. */
    return boot_register_store_payment_runtime(svc);
}

bool boot_running(const struct boot_svc_ctx *svc)
{
    return svc && svc->running && atomic_load(svc->running);
}

/* Catchup-job lifecycle policy moved to catchup_lifecycle_start/_join/_reap
 * (app/services/src/catchup_lifecycle_service.c); these three stay as thin
 * boot_svc_ctx-to-job plumbing (same job, same timeouts). */
bool boot_start_catchup_service(struct boot_svc_ctx *svc,
                                const char *datadir)
{
    if (!svc)
        return false;

    return catchup_lifecycle_start(&svc->catchup_job, boot_node_db(svc),
                                   &svc->state->chain_active,
                                   svc->wallet, datadir);
}

void boot_join_catchup_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    catchup_lifecycle_join(&svc->catchup_job, 5);
}

bool boot_reap_catchup_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return true;
    return catchup_lifecycle_reap(&svc->catchup_job);
}

static void boot_register_core_liveness_and_reducer(
    struct boot_svc_ctx *svc, const struct chain_params *params)
{
    if (!svc)
        return;

    /* Start the supervisor thread before any core liveness contracts register.
     * Keep this before optional frontend/Tor startup: RPC can come up before
     * Tor finishes, but reducer stages must never wait behind onion/bootstrap
     * work. */
    if (!supervisor_start()) {
        fprintf(stderr,  // obs-ok:supervisor-start-fallback-warn
            "WARNING: supervisor_start failed; lib/health sweeper alone\n");
    }
    supervisor_domains_init();

    /* Initialize the typed blocker primitive. Must come before any subsystem
     * calls blocker_set / mirror_consensus_record_blocker. Idempotent. */
    blocker_module_init();

    /* Outbound peer-floor liveness contract.
     *
     * Failure mode being addressed: the node can sit with 0 outbound
     * peers + a stuck inbound indefinitely. thread_open_connections keeps
     * running but addrman is exhausted, so `connman_pick_next_outbound_target`
     * returns false on every tick — silently, with no log, no event.
     *
     * Contract semantics:
     *   on_tick (every 15 s): snapshot outbound_healthy via
     *     `connman_outbound_healthy_count`; write to progress_marker.
     *     If the count is below the floor (2), do NOT call
     *     supervisor_tick — let the progress-quiet timer advance.
     *   on_stall (after 60 s under floor):
     *     - emit EV_PEER_FLOOR_BREACH for operator visibility
     *     - call connman_kick_seed_discovery to widen addrman
     *
     * The existing thread_open_connections still runs its 1-second
     * adaptive loop; the supervisor only kicks the seed re-walk so the
     * thread has fresh targets to try. */
    net_supervisor_register(svc->connman);
    chain_supervisor_register(svc->state);
    /* Tip-stuck watchdog: watches active_chain_height advance, emits a
     * named stall event, and lets the condition loop handle recovery. */
    chain_tip_watchdog_register(svc->state);
    /* Always-terminating remedy escalator (sticky-node #1): register AFTER the watchdog, BEFORE self_heal. */
    sticky_escalator_set_datadir(svc->datadir);
    sticky_escalator_register(svc->state);
    /* Unified recovery organ (chain domain): cheapest-sufficient-rung selector. */
    recovery_coordinator_set_datadir(svc->datadir);
    recovery_coordinator_register(svc->state);
    condition_registry_register_all();
    invariant_sentinel_register(); /* fail-loud validation pack sweeps (also arms the authority/projection audit) */
    op_return_backfill_set_datadir(svc->datadir);
    op_return_backfill_register(); zslp_ledger_backfill_register(); address_index_service_register(); txindex_projection_service_register(); /* projection backfills to H*: op_return + zslp_ledger (always) + -addressindex/-txindex (opt-in, no-op when off) */
    struct zcl_result build_runtime = build_fabric_runtime_register(svc->app_ctx->build_worker, svc->datadir);
    if (!build_runtime.ok) LOG_WARN("build_fabric", "%s", build_runtime.message);
    state_auditor_set_datadir(svc->datadir); state_auditor_register(); telemetry_watch_service_register(); /* two supervised samplers: the continuous integrity scrubber (complements the hourly full-set audits above) and the ops.telemetry.watch change feed, which diffs one typed snapshot per sampled domain and publishes ONLY on change — unregistered, the feed exists but nothing fills it and every poll samples itself */
    /* Close the alert loop: install the event->sink routing (incl. the
     * EV_OPERATOR_NEEDED rule) BEFORE the condition engine can fire, so a
     * halt that exhausts remedies reaches an operator and the health
     * surface instead of dead-ending. */
    alerts_init();
    /* Durable blocker-firing-history bridge: mirrors every EV_OPERATOR_NEEDED
     * page into the durable event log (EV_OPERATOR_ALERT) so `zclassic23
     * dumpstate blocker_history` survives restart. Registered right after
     * alerts_init() for the same reason — BEFORE the condition engine can
     * fire. */
    blocker_history_bridge_register();
    self_heal_register(svc->state);
    /* Spawn the dedicated condition-runner thread. The engine's detect/remedy
     * passes can run for seconds and MUST NOT run on the root supervisor sweep
     * thread (a heavy pass there freezes supervisor_sweep_heartbeat past the 30 s
     * backstop otherwise). The sweep only supervises the runner's
     * heartbeat; a hung remedy becomes a named blocker, never a frozen root. */
    self_heal_start();
    staged_sync_supervisor_register(svc->state);

    /* Recover the durable finalized frontier a reboot dropped.
     * staged_sync_supervisor_register (above) ran tip_finalize_stage_init,
     * registering the chain-height authority seeded from the coins-restore
     * tip. Adopt the durable frontier forward-only HERE —
     * after the authority is live (active_chain_height reads the real coins tip)
     * but BEFORE runtime services / reducer ingest start — so there is no race.
     * Both calls are no-ops unless their precondition holds; neither rewinds,
     * forks, or deletes log rows. See block_index_loader.h for each contract. */
    int seeded = block_index_loader_seed_tip_from_finalized(
        svc->state, params, progress_store_db());
    (void)seeded;  /* logs its own success line; benign no-op otherwise */
    /* Torn-import recovery is detect-gated and may stamp only the full-SHA3
     * verified compiled anchor set; mismatch is fatal. Explicit refold and
     * verified-load routes remain authoritative and skip cold-import seeding.
     * A healthy synced node never resets or re-folds. */
    /* A verified snapshot loaded at its own height owns the seed. Skip every
     * fallback seeder so none can lower its trusted base or stage cursors. */
    bool loader_owns_seed = boot_loader_owns_seed(svc->app_ctx);
    bool armed_from_anchor =
        loader_owns_seed ||                      /* loader at boot.c re-seeded + armed the stages */
        refold_from_anchor_active() ||           /* already armed: flag / load-verify / mid-fold */
        boot_refold_from_anchor_arm_if_torn(     /* DEFAULT: detect-gated torn-import self-heal */
            svc->state, boot_node_db(svc), progress_store_db()) ||
        block_index_loader_arm_cold_start_from_index( /* W1-L1: --importblockindex + empty coins_kv */
            svc->state, boot_node_db(svc), progress_store_db());
    if (!armed_from_anchor)
        (void)block_index_loader_seed_stages_from_cold_import(
            svc->state, boot_node_db(svc), progress_store_db());

    /* Fresh-genesis bootstrap, EVERY network — boot-time mirror of the
     * on-demand ingest seed in reducer_ingest_service.c. Without it the fold
     * wedges at height 0 forever on ANY network: nothing ever writes the
     * genesis BODY, and body_persist cannot advance past a body it cannot read
     * and the network cannot re-serve. Seeding is the CORRECT verdict, not a
     * skip — zclassicd's ConnectBlock special-cases genesis by HASH and returns
     * before UpdateCoins (its coinbase is consensus-unspendable), so the
     * genesis delta is EMPTY (the exemption utxo_apply_delta.c and
     * psc_extract.c already mirror). The identity asserted is the compiled
     * `consensus.hashGenesisBlock` from the byte-sealed core/ — the binary's
     * own constant, never a peer's word — and the anchor row carries no UTXOs,
     * anchors or nullifiers, so nothing borrowed is admitted. Stamps every
     * upstream cursor to 1, never the coins frontier; inert on a node with real
     * state. Seam analysis: docs/work/fresh-start-seam.md. */
    if (!armed_from_anchor && params) {
        struct block_index *gtip = active_chain_tip(&svc->state->chain_active);
        if (gtip && gtip->phashBlock && gtip->nHeight == 0 &&
            uint256_eq(gtip->phashBlock, &params->consensus.hashGenesisBlock) &&
            tip_finalize_stage_cursor() == 0)
            reducer_ingest_try_seed_anchor(0, gtip->phashBlock->data,
                                           "fresh-genesis-boot");
    }
}

/* ── Runtime service startup (called from app_init) ────────── */
/* Decide whether the ground-truth wallet join is useful without touching the
 * global UTXO corpus. A probe failure withholds the optional rebuild. */
bool boot_wallet_rebuild_probe(sqlite3 *db, bool *has_utxos, bool *has_keys)
{
    sqlite3_stmt *stmt = NULL;
    if (!db || !has_utxos || !has_keys) {
        fprintf(stderr, "wallet_utxos: ownership probe received invalid input\n");
        return false;
    }
    *has_utxos = false;
    *has_keys = false;
    const char *sql = "SELECT EXISTS(SELECT 1 FROM wallet_utxos "
        "WHERE spent_txid IS NULL), EXISTS(SELECT 1 FROM wallet_keys)";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK && stmt && AR_STEP_ROW_READONLY(stmt) == SQLITE_ROW) {
        *has_utxos = sqlite3_column_int(stmt, 0) != 0;
        *has_keys = sqlite3_column_int(stmt, 1) != 0;
        sqlite3_finalize(stmt);
        return true;
    }
    fprintf(stderr, "wallet_utxos: ownership probe failed: %s\n",
            sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return false;
}
#if defined(_WIN32) && defined(__clang__)
    __attribute__((optnone)) /* Bound the Windows startup coordinator frame. */
#elif defined(_WIN32) && defined(__GNUC__)
    __attribute__((optimize("no-inline", "no-inline-functions",
                            "no-inline-small-functions")))
#endif
bool app_init_services(struct app_context *ctx,
                        const struct chain_params *params,
                        struct boot_svc_ctx *svc)
{
    /* Report synchronous service sub-stage timing on the monotonic clock. */
    int64_t t_svc = svc_clock_ms();

    /* Every step below names itself on the way IN (boot_mark_step), so one
     * that never returns still reports; a node once wedged here four hours
     * and the log named only the step BEFORE it. */
    boot_step_enter("svc.init_wallet");

    node_db_sync_catchup_job_init(&svc->catchup_job);
    snapshot_tx_index_job_init(&svc->tx_index_job);
    snapsync_init(&svc->snapshot_sync, svc->node_db);
    svc->app_ctx = ctx;
    svc->params = params;
    /* Bind resident diagnostics to this node before callbacks can run. */
    node_rpc_client_init(ctx->datadir, ctx->rpc_port);
    tx_mempool_init(svc->mempool, WALLET_DEFAULT_FEE_ZAT);
    zcl_service_kernel_init(&svc->service_kernel);
    zcl_service_kernel_init(&svc->network_kernel);
    zcl_service_kernel_init(&svc->runtime_kernel);
    zcl_service_kernel_init(&svc->frontend_kernel);
    if (!boot_start_mempool_limits_service(svc))
        return boot_step_fail("mempool_limits_service");
    svc->runtime.db_service = svc->db_service;
    svc->runtime.snapshot_sync = &svc->snapshot_sync;
    svc->runtime.mempool = svc->mempool;
    svc->runtime.wallet = svc->wallet;
    svc->runtime.main_state = svc->state;
    svc->runtime.coins_tip = svc->coins_tip;
    app_runtime_set_current(&svc->runtime);
    boot_register_process_block_hooks(svc);

    /* Projection storage fan-out. Opens the append-only event log and the
     * reducer read-model projections used by runtime services. */
    boot_start_projection_storage(ctx->datadir);

    /* ── Register sync state observer ──────────────────────────── *
     * Logs every sync state transition via the event system.
     * Registered as async observer so it never blocks P2P threads. */
    extern void boot_sync_state_logger(enum event_type, uint32_t,
                                        const void *, uint32_t, void *);
    event_observe_async(EV_SYNC_STATE_CHANGE, boot_sync_state_logger, NULL);
    event_observe_async(EV_TIP_UPDATED, boot_sync_state_logger, NULL);
    event_observe_async(EV_BLOCK_CONNECTED, boot_sync_state_logger, NULL);
    event_observe_async(EV_REORG_START, boot_sync_state_logger, NULL);

    if (boot_node_db(svc))
        node_db_sync_mempool_load(boot_node_db(svc), svc->mempool,
                                  svc->coins_tip, svc->state, svc->params);

    /* Rescan blockchain for wallet transactions if wallet is behind chain tip */
    {
        struct block_index *chain_tip = active_chain_tip(&svc->state->chain_active);
        int tip_height = active_chain_height(&svc->state->chain_active);
        if (chain_tip && svc->wallet->best_block_height < tip_height) {
            int scan_from = svc->wallet->best_block_height > 0
                ? svc->wallet->best_block_height + 1 : 0;
            if (svc->wallet->time_first_key > 0 && scan_from == 0) {
                int64_t scan_time = svc->wallet->time_first_key - 7200;
                for (int h = tip_height; h >= 0; h--) {
                    struct block_index *bi = active_chain_at(
                        &svc->state->chain_active, h);
                    if (bi && (int64_t)bi->nTime < scan_time) {
                        scan_from = h + 1;
                        break;
                    }
                }
            }
            if (scan_from == 0 && svc->wallet->best_block_height == 0 &&
                tip_height > 1000) {
                printf("Wallet scan height is 0 with %d blocks. "
                       "Use rescanblockchain RPC for targeted rescan.\n",
                       tip_height);
            } else if (tip_height - scan_from < 50000) {
                wallet_rescan(svc->wallet, &svc->state->chain_active,
                              scan_from, tip_height, ctx->datadir);
            } else {
                printf("Wallet needs rescan from %d to %d (%d blocks). "
                       "Deferring — use rescanblockchain RPC.\n",
                       scan_from, tip_height, tip_height - scan_from);
            }
        }
    }

    wallet_verify_utxos(svc->wallet, svc->coins_tip);

    /* Rebuild wallet_utxos from ground truth ONLY if empty */
    {
        struct node_db *ndb = boot_node_db(svc);
        if (ndb && ndb->open) {
            int64_t t0 = (int64_t)platform_time_wall_time_t();
            bool has_utxos = false;
            bool has_keys = false;
            bool ownership_known = boot_wallet_rebuild_probe(
                ndb->db, &has_utxos, &has_keys);
            if (!ownership_known) {
                fprintf(stderr, "wallet_utxos: rebuild withheld because "
                        "wallet ownership is unknown\n");
            } else if (has_utxos) {
                printf("wallet_utxos: keeping existing UTXOs "
                       "(synced from zclassicd)\n");
            } else if (!has_keys) {
                printf("wallet_utxos: no wallet keys; ground-truth rebuild skipped\n");
            } else {
                int rc = sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL);
                if (rc != SQLITE_OK) {
                    fprintf(stderr, "wallet_utxos: BEGIN failed: %s\n",
                            sqlite3_errmsg(ndb->db));
                } else {
                    rc = ar_exec_write_sql(ndb->db,
                    "INSERT OR IGNORE INTO wallet_utxos "
                    "(txid, vout, value, address_hash, script, height, is_coinbase) "
                    "SELECT u.txid, u.vout, u.value, u.address_hash, u.script, "
                    "u.height, u.is_coinbase "
                    "FROM utxos u INNER JOIN wallet_keys wk "
                    "ON u.address_hash = wk.pubkey_hash");
                }
                if (rc != SQLITE_OK) {
                    fprintf(stderr, "wallet_utxos INSERT failed: %s\n",
                            sqlite3_errmsg(ndb->db));
                    if (sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
                        fprintf(stderr, "wallet_utxos: ROLLBACK failed: %s\n",
                                sqlite3_errmsg(ndb->db));
                    }
                } else if (sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
                    fprintf(stderr, "wallet_utxos: COMMIT failed: %s\n",
                            sqlite3_errmsg(ndb->db));
                    if (sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
                        fprintf(stderr, "wallet_utxos: ROLLBACK after COMMIT failure failed: %s\n",
                                sqlite3_errmsg(ndb->db));
                    }
                }
            }
            int64_t bal = 0;
            sqlite3_stmt *s = NULL;
            sqlite3_prepare_v2(ndb->db,
                "SELECT COALESCE(sum(value),0) FROM wallet_utxos "
                "WHERE spent_txid IS NULL", -1, &s, NULL);
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
                bal = sqlite3_column_int64(s, 0);
            sqlite3_finalize(s);
            int cnt = 0;
            sqlite3_prepare_v2(ndb->db,
                "SELECT count(*) FROM wallet_utxos WHERE spent_txid IS NULL",
                -1, &s, NULL);
            if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
                cnt = sqlite3_column_int(s, 0);
            sqlite3_finalize(s);
            printf("Wallet: %.8f ZCL (%d UTXOs, %lldms)\n",
                   (double)bal / 1e8, cnt,
                   (long long)((int64_t)platform_time_wall_time_t() - t0) * 1000);
        }
    }

    /* STATE G: wrap legacy plaintext rows into WKS1 envelopes; fail loud. */
    if (svc->wallet_sqlite->open) {
        struct zcl_result scrub_r =
            wallet_sqlite_scrub_plaintext_r(svc->wallet_sqlite);
        if (!scrub_r.ok) {
            boot_report_wallet_scrub_failed(ctx->datadir, &scrub_r);
            event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                        "wallet_plaintext_scrub_failed code=%d", scrub_r.code);
            exit(1);
        }
    }
    /* Pass base datadir; msg_processor_init re-resolves NET-SPECIFIC. */
    msg_processor_init(svc->msg_processor, svc->state, svc->mempool,
                       svc->coins_tip, params, ctx->datadir,
                       &svc->connman->manager, &svc->runtime);
    rpc_net_set_msg_processor(svc->msg_processor);
    msg_processor_set_block_submit(svc->msg_processor,
                                   boot_submit_p2p_block, svc);
    msg_processor_set_catchup_drain(svc->msg_processor,
                                    boot_drain_catchup_reducer, svc);
    msg_processor_set_catchup_batch_scope(
        svc->msg_processor, boot_begin_catchup_batch,
        boot_end_catchup_batch, svc);
    msg_processor_set_compact_block_submit(svc->msg_processor,
                                           boot_submit_compact_block, svc);
    msg_processor_set_peer_save(svc->msg_processor, boot_save_peer_advisory,
                                svc);
    msg_processor_set_zmsg_save(svc->msg_processor, boot_save_zmsg, svc);
    boot_wire_file_market(svc->msg_processor, svc);
    boot_wire_zswap_yardsale(svc->msg_processor, svc);
    msg_processor_set_file_service_save(svc->msg_processor,
                                        boot_save_file_service, svc);
    msg_processor_set_snapshot_active(svc->msg_processor,
                                      boot_snapshot_active, svc);
    msg_processor_set_snapshot_anchor_accessors(
        svc->msg_processor, boot_snapshot_anchor_get, svc,
        boot_snapshot_anchor_set, svc);
    msg_processor_set_activation_hooks(
        svc->msg_processor, boot_request_header_activation, svc,
        boot_clear_header_activation_anchor, svc,
        boot_repair_header_post_activation_anchor, svc);
    msg_processor_set_header_index_hooks(
        svc->msg_processor, boot_scan_header_block_files, svc,
        boot_header_block_index_heights_repaired, svc);
    msg_processor_set_header_chainstate_hooks(
        svc->msg_processor, boot_commit_header_tip, svc,
        boot_recommit_snapshot_anchor, svc);
    msg_processor_set_wallet_tx_accepted(svc->msg_processor,
                                         boot_wallet_tx_accepted, svc);
    msg_processor_set_block_connected(svc->msg_processor,
                                      boot_block_connected_observer, svc);
    msg_processor_set_peer_header_vote(svc->msg_processor,
                                       boot_record_peer_header_vote, svc);
    msg_processor_set_flyclient_proof_builder(
        svc->msg_processor, boot_build_flyclient_proof, svc);
    msg_processor_set_block_hashes_range(
        svc->msg_processor, boot_load_block_hashes_range, svc);
    msg_processor_set_utxo_sha3_compute(
        svc->msg_processor, boot_compute_utxo_sha3, svc);

    /* Initialize P2P connection manager */
    struct node_signals signals = {
        .get_height = msg_get_height,
        .process_messages = msg_process_messages,
        .send_messages = msg_send_messages,
        .initialize_node = NULL,
        .finalize_node = NULL,
        .ctx = svc->msg_processor,
    };
    connman_init(svc->connman, params, &signals);
    svc->connman->datadir = ctx->datadir;
    connman_set_onion_peer_discovery(svc->connman, ctx->datadir,
                                     blog_discover_onion_peers);
    connman_set_known_zcl23_peer_source(svc->connman,
                                        boot_known_zcl23_peers, svc);
    boot_onion_discovery_register(blog_serve, blog_discover_onion_peers, ctx->datadir);

    /* Load persisted peer addresses from previous session */
    connman_load_addrman(svc->connman);
    app_log_bootstrap_sources(params, svc->connman);

    /* NETWORK_READY boundary: connman initialized + addrman loaded (peer
     * manager ready); listeners are bound just below. Advances the boot-stage
     * machine via the net record registered in boot.c. */
    {
        struct zcl_result nr =
            sysinit_run_stage(BOOT_STAGE_NETWORK_READY, svc);
        if (!nr.ok) {
            fprintf(stderr, "[boot] NETWORK_READY boundary failed: %s\n",
                    nr.message);
            return boot_step_fail("network_ready_boundary");
        }
    }

    if (ctx->listen) {
        struct net_service bind4;
        net_service_init(&bind4);
        unsigned char any4[4] = {0, 0, 0, 0};
        net_addr_set_ipv4(&bind4.addr, any4);
        bind4.port = (uint16_t)ctx->p2p_port;
        if (bind_listen_port(&svc->connman->manager, &bind4, false))
            printf("P2P listening on 0.0.0.0:%d\n", ctx->p2p_port);
        struct net_service bind6;
        net_service_init(&bind6);
        bind6.port = (uint16_t)ctx->p2p_port;
        if (bind_listen_port(&svc->connman->manager, &bind6, false))
            printf("P2P listening on [::]:%d\n", ctx->p2p_port);
    }

    /* Wait for ZK params before P2P (needed for block verification) */
    if (ctx->params_dir) {
        if (svc->params_thread_started) {
            pthread_join(svc->params_thread, NULL);
            svc->params_thread_started = false;
        }
        if (!atomic_load(svc->params_loaded))
            fprintf(stderr, "Warning: ZK params not loaded\n");
    }

    t_svc = boot_mark_step(t_svc, "svc.init_wallet", "svc.file_sync");

    /* File sync BEFORE P2P — download block files first, then start P2P.
     * This prevents concurrent writes to block files (file sync + P2P
     * both writing to blk*.dat caused crashes). */
    {
        int chain_height = active_chain_height(&svc->state->chain_active);
        if (chain_height <= 0 && ctx->no_file_sync) {
            printf("=== Fresh node — file sync disabled (-nofilesync), "
                   "using P2P snapshot sync ===\n");
            goto skip_file_sync;
        }
        if (chain_height <= 0) {
            printf("=== Fresh node — probing optional fast file sync "
                   "(P2P sync is the fallback) ===\n");
            uint8_t utxo_root[32];
            memset(utxo_root, 0, 32);
            bool file_sync_ok = false;

            /* Try -fileservice= peer first (e.g., localhost speedrun) */
            if (ctx->file_service_peer && !file_sync_ok) {
                printf("Trying file service at %s:%d "
                       "(from -fileservice=)...\n",
                       ctx->file_service_peer, FS_PORT);
                int64_t t0 = (int64_t)platform_time_wall_time_t();
                if (fs_client_sync(ctx->file_service_peer, FS_PORT,
                                    ctx->datadir, utxo_root)) {
                    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
                    printf("=== File sync complete from %s: %llds ===\n",
                           ctx->file_service_peer, (long long)elapsed);
                    file_sync_ok = true;
                }
            }

            /* Fall back to hardcoded clearnet seeds ONLY if the operator
             * explicitly opted in with -allow-clearnet-snapshot-fetch.
             *
             * SECURITY: these seeds are unauthenticated (clearnet, no TLS, no
             * ZClassic state commitment). The file_service per-chunk SHA3 only
             * proves the bytes match the SERVING PEER's own manifest, NOT that
             * the chainstate is the real consensus set — and boot_import_snapshot_db
             * only independently checks state AT the single locally compiled
             * checkpoint, trusting anything above it on the peer's word. So a
             * MITM or a malicious seed could otherwise seed a FORGED UTXO set
             * into a default cold start (forged-money / consensus divergence).
             * Default OFF: a fresh node falls back to safe P2P IBD or the
             * operator bundle (its height/hash check remains assisted state).
             * An explicit -fileservice=PEER
             * above is always honored (the operator chose that peer).
             *
             * Also skipped in connect-only mode, where all bootstrap data must
             * come from the explicit peer set. */
            const char *const *file_seeds = ZCL_BUNDLE_FETCH_CLEARNET_SEEDS;
            if (!ctx->allow_clearnet_snapshot_fetch && !file_sync_ok)
                printf("=== Auto-fetch of chainstate from hardcoded clearnet "
                       "seeds is DISABLED (unauthenticated; pass "
                       "-allow-clearnet-snapshot-fetch to opt in) — using P2P "
                       "snapshot sync / operator bundle ===\n");
            for (int round = 0;
                 ctx->allow_clearnet_snapshot_fetch &&
                 !ctx->connect_only && round < 3 && !file_sync_ok;
                 round++) {
                if (round > 0) {
                    printf("File sync: no seed reachable, retrying in 10s "
                           "(optional, round %d/3)...\n", round + 1);
                    sleep(10);
                }
                for (int i = 0; file_seeds[i] && !file_sync_ok; i++) {
                    printf("Probing optional file-sync seed %s:%d...\n",
                           file_seeds[i], FS_PORT);
                    int64_t t0 = (int64_t)platform_time_wall_time_t();
                    if (fs_client_sync(file_seeds[i], FS_PORT,
                                        ctx->datadir, utxo_root)) {
                        int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
                        printf("=== File sync complete from %s: %llds ===\n",
                               file_seeds[i], (long long)elapsed);
                        file_sync_ok = true;
                    }
                }
            }
            if (!ctx->connect_only && !file_sync_ok)
                printf("=== Optional file sync unavailable — continuing "
                       "with P2P snapshot sync (this is normal) ===\n");
            /* After file download: scan block files to populate block
             * index with BLOCK_HAVE_DATA + nChainTx. Without this,
             * 6 GB of blocks sit unused on disk.
             *
             * NOTE: blocks cannot be connected without a UTXO set. The file
             * service only downloads block files, not chainstate. Blocks are
             * indexed so they don't need to be re-downloaded via P2P — once
             * headers arrive and a UTXO snapshot is received, the blocks on
             * disk will be used automatically. */
            /* Run scan even on partial downloads — 94% of blocks is
             * still useful. Blocks on disk can serve headers + delta sync. */
            {
                /* Check if we have any block files at all */
                char blk0[576];
                snprintf(blk0, sizeof(blk0), "%s/blocks/blk00000.dat",
                         ctx->datadir);
                struct stat blk0_st;
                bool have_blocks = (stat(blk0, &blk0_st) == 0 &&
                                    blk0_st.st_size > 100000);
                if (!have_blocks && !file_sync_ok) goto skip_block_scan;
            }
            {
                /* Load block index from flat file if downloaded */
                char dl_flat[576];
                snprintf(dl_flat, sizeof(dl_flat), "%s/block_index.bin",
                         ctx->datadir);
                struct stat flat_st;
                if (stat(dl_flat, &flat_st) == 0 &&
                    flat_st.st_size > 1000000) {
                    printf("Loading downloaded block_index.bin...\n");
                    fflush(stdout);
                    (void)load_block_index_flat(ctx->datadir, svc->state);
                }

                /* Validate block file references — clear HAVE_DATA for
                 * entries pointing to empty/missing block files. The flat
                 * file from the server may reference blk00000.dat which
                 * is empty (genesis has no on-disk data). */
                if (svc->state->map_block_index.size > 1000) {
                    int cleared = 0;
                    /* Build a quick lookup: which block files exist+nonempty */
                    bool file_ok[256] = {false};
                    for (int fi = 0; fi < 256; fi++) {
                        char bp[576];
                        snprintf(bp, sizeof(bp), "%s/blocks/blk%05d.dat",
                                 ctx->datadir, fi);
                        struct stat bst;
                        if (stat(bp, &bst) == 0 && bst.st_size > 0)
                            file_ok[fi] = true;
                    }
                    size_t vi = 0;
                    struct block_index *vp;
                    while (block_map_next(&svc->state->map_block_index,
                                           &vi, NULL, &vp)) {
                        if (!vp) continue;
                        if (!(vp->nStatus & BLOCK_HAVE_DATA)) continue;
                        if (vp->nFile >= 0 && vp->nFile < 256 &&
                            !file_ok[vp->nFile]) {
                            vp->nStatus &= ~BLOCK_HAVE_DATA;
                            cleared++;
                        }
                    }
                    if (cleared > 0)
                        printf("Cleared HAVE_DATA from %d entries "
                               "referencing empty block files\n", cleared);
                }

                /* If no flat file, scan block files from disk */
                if (svc->state->map_block_index.size < 1000) {
                    printf("Scanning downloaded block files...\n");
                    fflush(stdout);
                    int marked = scan_block_files_mark_data(svc->state,
                        ctx->datadir, params);
                    if (marked > 0) {
                        printf("Block file scan: %d blocks indexed\n",
                               marked);
                        save_block_index_flat(ctx->datadir, svc->state);
                    } else {
                        fprintf(stderr, "Block file scan: 0 blocks\n");
                    }
                }

                /* Check if we received consensus_snapshot.db (file_index=254).
                 * If so, import its UTXOs into node.db so the chain tip can
                 * be promoted to the snapshot height. Without this step the
                 * snapshot bytes sit on disk unused and the node falls back
                 * to block-by-block IBD from genesis. */
                bool has_utxo_snapshot = false;
                if (svc->state->map_block_index.size > 1000 &&
                    svc->node_db && svc->node_db->open && svc->node_db->db) {
                    char db_check[576];
                    snprintf(db_check, sizeof(db_check),
                             "%s/consensus_snapshot.db", ctx->datadir);
                    struct stat db_st;
                    if (stat(db_check, &db_st) == 0 &&
                        db_st.st_size > 10000000) {
                        /* Re-boot case: utxos already imported on a prior
                         * boot. node.db is authoritative; do not re-import. */
                        int64_t existing_utxos =
                            node_db_utxo_count(svc->node_db);
                        if (existing_utxos > 1000) {
                            printf("=== UTXO snapshot already imported "
                                   "(%lld UTXOs, %.0f MB on disk) ===\n",
                                   (long long)existing_utxos,
                                   (double)db_st.st_size /
                                       (1024.0 * 1024.0));
                            has_utxo_snapshot = true;
                        } else {
                            int64_t imported = 0, snap_h = 0;
                            uint8_t snap_hash[32];
                            if (boot_import_snapshot_db(svc->node_db,
                                                        db_check,
                                                        &imported,
                                                        &snap_h,
                                                        snap_hash)) {
                                printf("=== UTXO snapshot imported: "
                                       "%lld UTXOs at h=%lld "
                                       "(%.0f MB) ===\n",
                                       (long long)imported,
                                       (long long)snap_h,
                                       (double)db_st.st_size /
                                           (1024.0 * 1024.0));
                                has_utxo_snapshot = true;
                            } else {
                                printf("=== consensus_snapshot.db "
                                       "(%.0f MB) import failed — "
                                       "falling back to IBD ===\n",
                                       (double)db_st.st_size /
                                           (1024.0 * 1024.0));
                            }
                        }
                    }
                }

                if (svc->state->map_block_index.size > 1000) {
                    /* Block-file count on disk — NOT a coin-set verification. */
                    printf("=== Data synced: %zu blocks on disk ===\n",
                           svc->state->map_block_index.size);

                    if (has_utxo_snapshot) {
                        /* UTXO set already on disk from power node.
                         * Only need delta replay from snapshot height
                         * to current tip. This is fast — typically
                         * just the last few hundred blocks. */
                        printf("=== UTXO snapshot imported — "
                               "delta replay only ===\n");
                        /* Fresh receivers should not also start the store
                         * payment scanner. It opens a second node.db handle
                         * and can race the secure snapshot receive path. */
                        svc->defer_payment_service = true;
                        /* Fresh receivers should not also start the local
                         * snapshot/export builder on the shared DB during
                         * bootstrap. That work contends with secure
                         * snapshot receive and can lock the node DB right
                         * when FlyClient verification hands off to receive. */
                        svc->defer_offer_service = true;
                        /* Address aggregation is advisory and can be
                         * rebuilt later; snapshot receive is on the critical
                         * path. Keep bootstrap receivers single-writer until
                         * secure snapshot handoff completes. */
                        svc->want_address_backfill = false;
                    } else {
                        /* Skip full replay — ZCL23 peers will provide
                         * a UTXO snapshot in ~6 seconds. Replaying 3M
                         * blocks would take ~10 min and starve the P2P
                         * socket, preventing snapshot receipt. */
                        printf("=== No UTXO snapshot — waiting for P2P "
                               "snapshot from ZCL23 peers ===\n");
                    }
                    fflush(stdout);

                    /* Only replay if we have a UTXO snapshot from file
                     * service (delta replay). Otherwise, wait for P2P
                     * snapshot which is much faster than full replay. */
                    if (has_utxo_snapshot) {
                        if (!boot_start_replay_service(svc)) {
                            fprintf(stderr,
                                    "WARNING: failed to start tracked UTXO replay thread\n");
                        }
                    }
                } else if (active_chain_height(&svc->state->chain_active) <= 1) {
                    /* Fresh bootstrap receivers with no usable local chain
                     * data should consume secure sync, not waste startup time
                     * building local export/serve state they cannot use yet. */
                    svc->defer_payment_service = true;
                    svc->defer_offer_service = true;
                    svc->want_address_backfill = false;
                    printf("Fresh bootstrap receiver mode: deferring local serve/build work\n");
                }
            }
        skip_block_scan: ;
        }
    }
    skip_file_sync: ;

    t_svc = boot_mark_step(t_svc, "svc.file_sync", "svc.network_start");

    if (!boot_register_network_services(svc) ||
        !zcl_service_kernel_start_all(&svc->network_kernel)) {
        fprintf(stderr, "FATAL: failed to start P2P threads\n");
        return boot_step_fail("p2p_threads");
    }
    sync_set_state(SYNC_FINDING_PEERS, "P2P started");

    t_svc = boot_mark_step(t_svc, "svc.network_start", "svc.mmr_mmb_catchup");

    /* Advertise our external IP in version messages so peers relay us */
    if (ctx->external_ip)
        msg_version_set_external_ip(ctx->external_ip,
                                    (uint16_t)ctx->p2p_port);
    char body_datadir[4096];
    GetDataDir(true, body_datadir, sizeof(body_datadir));
    /* Initialize RPC */
    rpc_table_init(svc->rpc_table);
    rpc_blockchain_set_state(svc->state, svc->mempool, body_datadir);
    rpc_blockchain_set_coins_db(NULL, svc->coins_tip);
    rpc_blockchain_set_node_db(boot_node_db(svc));
    rpc_blockchain_mmr_init_from_state(boot_node_db(svc));
    rpc_blockchain_mmr_catchup(svc->state);
    rpc_blockchain_mmb_init_from_state(boot_node_db(svc));
    rpc_blockchain_mmb_catchup(svc->state);
    boot_prepare_mmb_leaf_store(svc, ctx->datadir, legacy_chain_rpc_get_mmb_leaf);
    rpc_blockchain_commitment_mmr_init_from_state(boot_node_db(svc));
    /* Bootstrap commitment MMR if empty but chain is at height.
     * After legacy import, we have the UTXO set at tip but no
     * commitment history. Compute one commitment at current height
     * as the starting evidence anchor. Full history gets built during
     * reindexchainstate (full block replay). */
    {
        uint64_t commitment_leaves = 0;
        rpc_blockchain_commitment_mmr_snapshot(NULL, &commitment_leaves, NULL);
        int chain_h = active_chain_height(&svc->state->chain_active);
        if (commitment_leaves == 0 && chain_h > 1000 &&
            boot_node_db(svc) && boot_node_db(svc)->open) {
            printf("Commitment MMR empty at height %d — computing "
                   "bootstrap commitment...\n", chain_h);

            /* Round down to nearest commitment interval */
            int commit_h = (chain_h / MMR_COMMITMENT_INTERVAL) *
                            MMR_COMMITMENT_INTERVAL;

            /* Get block hash at commit height */
            const struct block_index *tip =
                active_chain_tip(&svc->state->chain_active);
            const struct block_index *bi = tip;
            /* Monotonicity + step-cap guard. */
            int bi_steps = 0;
            while (bi && bi->nHeight > commit_h) {
                const struct block_index *prev = bi->pprev;
                if (!prev || prev->nHeight >= bi->nHeight ||
                    bi_steps++ > 5000000) {
                    bi = NULL; /* corrupt chain — bail */
                    break;
                }
                bi = prev;
            }

            if (bi && bi->phashBlock && bi->nHeight == commit_h) {
                rpc_blockchain_maybe_commit(
                    commit_h, bi->phashBlock->data,
                    svc->coins_tip->commitment.accumulator,
                    svc->coins_tip->commitment.count);
                rpc_blockchain_commitment_mmr_save(boot_node_db(svc));
                printf("Bootstrap commitment at height %d saved\n",
                       commit_h);
            }
        }
    }
    t_svc = boot_mark_step(t_svc, "svc.mmr_mmb_catchup",
                           "svc.register_rpc_cmds");

    register_blockchain_rpc_commands(svc->rpc_table);

    rpc_hodl_set_state(svc->state, svc->coins_tip, boot_node_db(svc),
                        ctx->datadir);
    register_hodl_rpc_commands(svc->rpc_table);
    rpc_repair_set_state(svc->state, svc->coins_tip, boot_node_db(svc),
                         ctx->datadir, params);
    register_repair_rpc_commands(svc->rpc_table);
    register_rebuild_recent_rpc_commands(svc->rpc_table);
    register_backfill_header_solutions_rpc_commands(svc->rpc_table);
    register_chain_segment_rpc_commands(svc->rpc_table);

    rpc_chain_inspect_set_state(svc->state, body_datadir, NULL,
                                svc->coins_tip, boot_node_db(svc));
    register_chain_inspect_rpc_commands(svc->rpc_table);

    if (boot_profile_has_explorer(ctx)) {
        explorer_set_state(svc->state, svc->mempool, svc->coins_tip,
                            boot_node_db(svc), ctx->datadir);
    }

    api_set_state(svc->state, svc->mempool, svc->coins_tip,
                   boot_node_db(svc), ctx->datadir);

    rpc_rawtx_set_state(svc->state, svc->mempool, svc->coins_tip, body_datadir);
    rpc_rawtx_set_keystore(&svc->wallet->keystore);
    rpc_rawtx_set_connman(svc->connman);
    register_rawtransaction_rpc_commands(svc->rpc_table);

    rpc_mining_set_state(svc->state, svc->mempool, svc->coins_tip);
    register_mining_rpc_commands(svc->rpc_table);

    rpc_misc_set_state(svc->state);
    rpc_misc_set_wallet(svc->wallet);
    register_misc_rpc_commands(svc->rpc_table);
    rpc_net_set_connman(svc->connman);
    rpc_net_set_boot_context(ctx->datadir, ctx->load_snapshot_at_own_height);
    block_source_policy_init(svc->connman, svc->state, boot_node_db(svc));
    register_net_rpc_commands(svc->rpc_table);

    /* Game platform RPC — latency measurement, game types */
    rpc_game_set_connman(svc->connman);
    register_game_rpc_commands(svc->rpc_table);

    sync_monitor_init();
    sync_monitor_set_context(svc->connman, msg_get_download_mgr(), svc->state);
    sync_monitor_set_msg_processor(svc->msg_processor);
    /* Service health and sync detail RPCs */
    rpc_health_set_state(svc->state, &svc->bg_validation, &svc->bg_hash_verify, svc->connman);
    register_health_rpc_commands(svc->rpc_table);
    /* Diagnostics RPCs — dumpstate, getnodelog, dbquery */
    diagnostics_controller_set_state(svc->state, ctx->datadir);
    register_diagnostics_rpc_commands(svc->rpc_table);
    register_mesh_pairing_rpc_commands(svc->rpc_table, boot_node_db(svc));
    boot_zcode_dht_register_rpc(svc->rpc_table);
    boot_mesh_status_register_rpc(svc->rpc_table, boot_node_db(svc),
                                  boot_db_service(svc));
    boot_mesh_terminal_register_rpc(svc->rpc_table);
    boot_mesh_pairing_register_rpc(svc->rpc_table);
    boot_mesh_machines_register_rpc(svc->rpc_table);
    boot_zcode_async_proof_register_rpc(svc->rpc_table);
    /* File transfer service — SHA3-verified chunk serving */
    if (boot_profile_has_file_service(ctx)) {
        file_controller_init(ctx->datadir);
        register_file_rpc_commands(svc->rpc_table);
    }
    /* ZCL Market — crypto-incentivized file sharing */
    if (boot_profile_has_store(ctx)) {
        rpc_market_set_state(boot_node_db(svc));
        register_market_rpc_commands(svc->rpc_table);
    }

    /* On-chain overlays — ZCL Names, ZCL Anchors, identities (ZID), node
     * directory (ZDIR). Wiring only; every write is an operator command. */
    rpc_name_set_state(boot_node_db(svc));
    rpc_name_set_wallet(svc->wallet, svc->mempool, svc->state, svc->coins_tip);
    register_name_rpc_commands(svc->rpc_table);
    rpc_anchor_set_state(boot_node_db(svc));
    rpc_anchor_set_wallet(svc->wallet, svc->mempool, svc->state, svc->coins_tip);
    register_anchor_rpc_commands(svc->rpc_table);
    register_blog_post_rpc_commands(svc->rpc_table);
    rpc_identity_set_state(boot_node_db(svc));
    rpc_identity_set_wallet(svc->wallet, svc->mempool, svc->state, svc->coins_tip);
    register_identity_rpc_commands(svc->rpc_table);
    register_zdir_rpc_commands(svc->rpc_table, boot_node_db(svc), svc->wallet, svc->mempool, svc->state, svc->coins_tip);
    /* OP_RETURN catalog — every OP_RETURN output ever seen, by lokad tag */
    rpc_op_return_index_set_state(boot_node_db(svc));
    register_op_return_index_rpc_commands(svc->rpc_table);

    /* ZCL Messaging — P2P messages (plaintext on the wire) */
    rpc_msg_set_state(boot_node_db(svc), svc->connman);
    register_msg_rpc_commands(svc->rpc_table);

    /* Atomic Swaps — HTLC contracts (settlement is ZCL-leg only) */
    rpc_swap_set_context(boot_node_db(svc), svc->wallet, svc->mempool,
                         svc->state, svc->coins_tip, svc->connman);
    register_swap_rpc_commands(svc->rpc_table);

    /* blk_sync.dat from file service is on disk. P2P will re-request
     * blocks it needs — the OS disk cache serves them fast since the
     * data is already in memory from the recent file sync download.
     * The deferred scanner was causing crashes (SIGABRT from concurrent
     * block_index access) and isn't worth the complexity. */

    rpc_wallet_set_state(svc->wallet, svc->state, body_datadir,
                         svc->wallet_sqlite, svc->mempool, svc->connman);
    rpc_wallet_set_coins_tip(svc->coins_tip);
    rpc_wallet_set_node_db(boot_node_db(svc));
    register_wallet_rpc_commands(svc->rpc_table);
    register_event_rpc_commands(svc->rpc_table);

    zslp_rpc_set_datadir(ctx->datadir);
    register_zslp_rpc_commands(svc->rpc_table);
    boot_register_store_buyer_rpc(svc);
    if (!register_dev_native_hotswap_rpc(svc->rpc_table, ctx->datadir, ctx->rpc_port)) return boot_step_fail("dev_native_hotswap_rpc");

    /* Pre-compute fast sync snapshot offer in background */
    {
        int chain_tip_h = active_chain_height(&svc->state->chain_active);
        int best_header = svc->state->pindex_best_header ?
            svc->state->pindex_best_header->nHeight : chain_tip_h;
        bool behind_ibd = (best_header - chain_tip_h) > 1000;

        if (svc->defer_offer_service) {
            printf("Fast sync offer build deferred during bootstrap receiver mode\n");
        } else if (behind_ibd) {
            printf("Fast sync offer build deferred during IBD "
                   "(chain=%d, headers=%d, behind=%d)\n",
                   chain_tip_h, best_header, best_header - chain_tip_h);
        } else if (!boot_start_offer_service(svc)) {
            fprintf(stderr,
                    "WARNING: failed to start tracked snapshot-offer thread\n");
        }
    }

    /* Initialize metrics observers for Prometheus /metrics */
    metrics_prometheus_init();

    /* svc.core_liveness_reducer was THE UNNAMED GAP: supervisor_start, the
     * condition registry, the self-heal runner and the staged-sync stage
     * inits ran between two markers with no name, so a hang here left the
     * log sitting on `svc.register_rpc_cmds` forever. */
    t_svc = boot_mark_step(t_svc, "svc.register_rpc_cmds",
                           "svc.core_liveness_reducer");

    boot_register_core_liveness_and_reducer(svc, params);
    boot_step_enter("svc.frontend_tor_start");
    boot_configure_frontend_rpc(svc);

    /* frontend kernel start includes onion_tor bootstrap (Tor) — the
     * span the profile flagged as the likely bulk of the ~11s. */
    /* De-fatal: a frontend-service start failure (rpc_http/explorer/Tor) is NOT
     * data-unrecoverable — the node can still serve P2P + advance the chain. Per
     * the mandate ("never silently dies unless the data is truly unrecoverable")
     * we enter DEGRADED_SERVING and continue instead of crash-looping. It is
     * LOUD: stderr + a structured event. (When rpc_http itself is down, dumpstate
     * is unreachable whether we crash or degrade — so degrading strictly gains a
     * live node + no crash-loop. rpc_http start only fails on a NULL-ctx
     * programming invariant, so this path is effectively unreachable in prod.) */
    if (!boot_register_frontend_services(svc) ||
        !zcl_service_kernel_start_all(&svc->frontend_kernel)) {
        fprintf(stderr,
            "WARNING: frontend services failed to start; serving DEGRADED "
            "(RPC/explorer/Tor may be unavailable)\n");
        event_emitf(EV_BOOT_ACTIVATE, 0,
                    "degraded_serving frontend_services_unavailable");
        service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                              "frontend_services_unavailable");
    }

    t_svc = boot_mark_step(t_svc, "svc.frontend_tor_start",
                           "svc.peer_discover_self");

    /* Discover peer reachability — ASYNC. The NAT-PMP/UPnP probe blocks
     * for tens of seconds on a host whose gateway ignores it, and running
     * it here wedged boot ahead of the reducer stage-pipeline init (the
     * node answered RPC because the frontend had already started, masking
     * the stall). The tracked worker (lib/net/src/peer_strategy_worker.c)
     * owns the probe now, publishes the profile and the onion-directory
     * self row when it completes (structured `nat_probe_complete` log),
     * and re-arms the 7200 s mapping lease at half-life so it no longer
     * silently expires. Boot reports the honest intermediate state. */
    peer_strategy_worker_init(&svc->nat_probe_worker,
                              (uint16_t)ctx->p2p_port);
    if (peer_strategy_worker_start(&svc->nat_probe_worker)) {
        printf("Reachability: probing in background (NAT-PMP/UPnP + Tor)\n");
    } else {
        fprintf(stderr,
                "WARNING: failed to start tracked NAT probe thread\n");
    }

    t_svc = boot_mark_step(t_svc, "svc.peer_discover_self",
                           "svc.runtime_and_catchup");

    if (svc->want_address_backfill) {
        /* Re-enabled: SIGSEGV was caused by SQLite memory pressure from
         * a single massive GROUP BY over 1.3M UTXOs with 256MB mmap.
         * Fixed by batching per-address with bounded memory. */
        if (boot_start_address_backfill_service(svc)) {
            printf("Address backfill: started in tracked background thread\n");
            fflush(stdout);
        } else {
            fprintf(stderr,
                    "WARNING: failed to start tracked address backfill thread\n");
        }
    }

    /* HODL history filler — populates per-day "% held > 1y" snapshots
     * for the /explorer/hodl time-series chart. Idempotent; safe to
     * start on every boot even though the table mostly stays current
     * after first fill. */
    if (boot_profile_has_explorer(svc->app_ctx)) {
        if (boot_start_hodl_history_service(svc)) {
            printf("HODL history: filler started in tracked background thread\n");
            fflush(stdout);
        } else {
            fprintf(stderr,
                    "WARNING: failed to start HODL history filler thread\n");
        }
    }

    if (svc->want_snapshot_tx_index) {
        if (!boot_start_tx_index_service(svc)) {
            fprintf(stderr,
                    "WARNING: failed to start tracked tx-index build thread\n");
        }
    }

    atomic_store(svc->running, true);

    /* De-fatal: all runtime specs (bg_validation, gap_fill, legacy_mirror,
     * oracle, rolling_anchor, ...) are ZCL_SERVICE_OPTIONAL and the
     * reducer/coordinator drives chain-advance independently, so a runtime-start
     * failure does not stall consensus. Serve DEGRADED + continue (LOUD via
     * stderr + event); the sync-monitor self-heal re-raises to SYNCING/HEALTHY.
     * Refresh-only if already DEGRADED (don't clobber a frontend reason). */
    if (!boot_register_runtime_services(svc) ||
        !zcl_service_kernel_start_all(&svc->runtime_kernel)) {
        fprintf(stderr,
            "WARNING: runtime services failed to start; serving DEGRADED "
            "(bg-validation/gap-fill/legacy-mirror may be unavailable)\n");
        event_emitf(EV_BOOT_ACTIVATE, 0,
                    "degraded_serving runtime_services_unavailable");
        if (service_state_current() != SERVICE_STATE_DEGRADED_SERVING)
            service_state_advance(SERVICE_STATE_DEGRADED_SERVING,
                                  "runtime_services_unavailable");
    }

    boot_block_prefetch_start(ctx, svc->state); /* no-op sans -prefetch-blocks */
    boot_pv_lookahead_start(ctx, svc->state);   /* no-op sans -pv-lookahead */
    {
        struct block_index *tip = active_chain_tip(&svc->state->chain_active);
        int h = tip ? tip->nHeight : 0;
        event_emitf(EV_NODE_READY, 0, "height=%d peers=%zu",
                    h, svc->connman->manager.num_nodes);
    }
    printf("ZClassic C23 node initialized.\n");

    /* SQLite catchup — skip when no UTXO set (P2P snapshot incoming).
     * Running catchup during snapshot receive causes DB lock contention
     * that stalls the snapshot data flow. */
    if (boot_node_db(svc)) {
        int64_t utxo_count = db_utxo_count(boot_node_db(svc));
        if (utxo_count == 0) {
            printf("SQLite catchup: skipped (no UTXOs, waiting for P2P snapshot)\n");
        } else {
            if (!boot_start_catchup_service(svc, ctx->datadir)) {
                fprintf(stderr,
                        "WARNING: failed to start tracked SQLite catchup thread\n");
            }
        }
        if (!boot_start_projection_backfill_service(svc)) {
            fprintf(stderr,
                    "WARNING: failed to start projection backfill watcher\n");
        }
    }

    (void)boot_mark_step(t_svc, "svc.runtime_and_catchup", NULL);

    /* Booted successfully — every runtime service started (or degraded
     * loudly), EV_NODE_READY emitted, catchup/backfill spun up. Only NOW
     * tell the binary-A/B launcher: reset the boot-failure streak and,
     * unless we are the fallback slot, promote current -> last-good. Any
     * earlier and a binary that crashes later in boot would promote itself
     * before dying, disarming the fallback. No-op when launched directly
     * (launcher env unset). */
    binary_ab_promote_on_ready_env();

    return true;
}

/* ── Shutdown ──────────────────────────────────────────────── */
