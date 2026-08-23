/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Graceful-shutdown pipeline for the runtime services boot_services.c
 * starts: staged, deadline-watched teardown (emergency coins flush ->
 * frontend -> network quiesce -> runtime persist -> durability marker ->
 * best-effort release). Split from boot_services.c along the
 * app_shutdown_svc seam. */
#include "config/boot_internal.h"
#include "config/boot_background_workers.h"
#include "config/boot_snapshot_offer.h"
#include "config/boot_shutdown_marker.h"
#include "config/boot_fast_restart.h"
#include "config/boot_loop_guard.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "util/shutdown_stagewatch.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "util/log_macros.h"
#include "health/heartbeat.h"
#include "supervisors/self_heal.h"
#include "supervisors/staged_sync_supervisor.h"
#include "services/block_index_loader.h"
#include "services/block_index_flat_anchor.h"
#include "controllers/blockchain_controller.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/network_controller.h"
#include "event/event.h"
#include "net/msgprocessor.h"
#include "validation/process_block.h"
#include "validation/process_block_invalidate.h"
#include "validation/txmempool.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "sapling/params_init.h"
#include "keys/pubkey.h"
#include "storage/txdb.h"
#include "storage/coins_view_sqlite.h"
#include "storage/progress_store.h"
#include "coins/utxo_commitment.h"
#include "coins/coins_view.h"
#include "kernel/service_kernel.h"
#include "models/database.h"
#include <signal.h>
#include <stdio.h>
#include <stdatomic.h>
#include <unistd.h>

static void shutdown_stop_frontend_services(struct boot_svc_ctx *svc)
{
    printf("[shutdown] stopping frontend services\n");
    zcl_service_kernel_stop_all(&svc->frontend_kernel);
    printf("[shutdown] frontend services stopped\n");
}

static void shutdown_persist_fast_restart_state(struct boot_svc_ctx *svc)
{
    printf("[shutdown] persisting fast restart state\n");
    /* >1 not >1000: persist small reducer chains (regtest generate) too, else the map restores empty and the finalized-tip seed no-op's (getblockcount=0). */
    if (svc->state->map_block_index.size > 1) {
        printf("Saving block index flat file (%zu entries)...\n",
               svc->state->map_block_index.size);
        save_block_index_flat(svc->datadir, svc->state);
    }
    printf("[shutdown] fast restart state persisted\n");
}

static bool shutdown_flush_coins_to_sqlite(struct boot_svc_ctx *svc,
                                           const char *label)
{
    const char *flush_label = label ? label : "shutdown";
    if (!svc || !svc->coins_sqlite || !svc->coins_tip) {
        LOG_WARN("shutdown",
                 "%s coins flush skipped: svc=%p coins_sqlite=%p "
                 "coins_tip=%p",
                 flush_label, (void *)svc,
                 svc ? (void *)svc->coins_sqlite : NULL,
                 svc ? (void *)svc->coins_tip : NULL);
        return false;
    }

    bool ok = coins_view_sqlite_batch_write( // one-write-path-ok:shutdown-single-writer
        svc->coins_sqlite, &svc->coins_tip->cache_coins,
        &svc->coins_tip->hash_block, &svc->coins_tip->commitment);
    if (!ok) {
        LOG_WARN("shutdown",
                 "%s coins flush failed; retaining %zu dirty entries",
                 flush_label, svc->coins_tip->cache_coins.size);
        return false;
    }

    coins_map_free(&svc->coins_tip->cache_coins);
    coins_map_init(&svc->coins_tip->cache_coins);
    utxo_commitment_init(&svc->coins_tip->commitment);
    return true;
}

static bool shutdown_quiesce_network_and_flush_coins(struct boot_svc_ctx *svc,
                                                     bool diagnostics_drained)
{
    /* Stop P2P entrypoints before flush; any in-flight reducer sees
     * g_shutdown_requested and returns before mutating coins further. */
    printf("[shutdown] stopping network services\n");
    zcl_service_kernel_stop_all(&svc->network_kernel);
    printf("[shutdown] joining replay service\n");
    boot_join_replay_service(svc);
    msg_processor_stop_block_intake(svc->msg_processor);

    /* The message thread is finishing its current iteration; reducer
     * activation already handles shutdown persistence. */
    printf("Flushing coins cache to SQLite...\n");
    if (shutdown_flush_coins_to_sqlite(svc, "network-quiesce")) {
        printf("Coins cache flushed.\n");
    } else {
        fprintf(stderr, "WARNING: Coins cache flush FAILED during shutdown!\n");
    }
    /* Now join threads — safe, coins already persisted */
    printf("[shutdown] joining connman threads\n");
    connman_join(svc->connman);
    /* Revoke the globally published diagnostics/RPC handle before destroying
     * connman.  The diagnostics worker is already joined, but this makes any
     * late read fail closed instead of retaining a stale process-lifetime
     * pointer. */
    rpc_net_set_connman(NULL);
    /* A diagnostics capture that did not drain is still an owned READER of
     * connman. Retaining the allocation costs a process that is about to
     * _exit() nothing; freeing it under a live reader is a use-after-free. */
    if (diagnostics_drained) {
        connman_free(svc->connman);
        printf("[shutdown] connman stopped\n");
    } else {
        printf("[shutdown] connman retained: an undrained diagnostics "
               "capture still owns it\n");
    }

    /* Final flush in case message thread connected blocks before exit. */
    bool final_flush_ok = shutdown_flush_coins_to_sqlite(svc, "final");
    /* The FLUSH above is unconditional -- durability never waits on a
     * diagnostics capture. The CLOSE below is not: an undrained capture is
     * still an owned reader of these views, exactly as it is of connman.
     * Closing under a live reader is the use-after-free this whole branch
     * exists to avoid. */
    if (diagnostics_drained) {
        coins_view_cache_free(svc->coins_tip);
        coins_view_sqlite_close(svc->coins_sqlite);
    } else {
        printf("[shutdown] coins views retained: an undrained diagnostics "
               "capture still owns them\n");
    }

    /* Close cached block file handles */
    disk_block_io_close_cache();
    printf("[shutdown] network quiesced and coins closed\n");
    return final_flush_ok;
}

static void shutdown_stop_runtime_and_drain_workers(struct boot_svc_ctx *svc)
{
    printf("[shutdown] stopping runtime services\n");
    /* The heartbeat sweeper owns periodic callbacks into runtime services,
     * including node-health collection. It does not poll the registry's
     * global shutdown flag because health_stop() is its explicit lifecycle
     * boundary. Stop and join it while the supervisor and node DB are still
     * live; otherwise a periodic health callback can race the DB close below
     * and dereference closed runtime state. */
    health_stop();
    /* Stop + join the self-heal condition runner FIRST, while main_state and
     * the progress store are still live: the runner dereferences both inside a
     * condition tick, so it must never outlive them (they are freed in
     * shutdown_release_owned_resources). The global shutdown flag is already
     * set, so this joins at most one in-flight tick. */
    self_heal_stop();
    zcl_service_kernel_stop_all(&svc->runtime_kernel);
    /* The base service kernel currently owns mempool_limits. Its stop hook is
     * the only authority that sets zcl_mempool_lim's stop token, so it must run
     * before the generic registry join below. More generally, service kernels
     * stop their consumers while DB/progress dependencies are still live; the
     * registry then verifies ownership instead of trying to invent a stop
     * protocol for an otherwise-running service. */
    zcl_service_kernel_stop_all(&svc->service_kernel);
    /* Stop the supervisor AFTER runtime services so any stall-detection
     * callbacks they emit at teardown are still delivered. */
    supervisor_stop();
    /* The supervisor is now joined, so no stage callback can be in flight.
     * Quiesce the staged-sync pipeline while progress storage, node.db, and
     * main_state are still valid. In particular validate_headers owns the
     * vh.worker pool: deferring this call until after thread_registry_join_all
     * makes shutdown wait on workers that have not yet been told to stop. */
    staged_sync_supervisor_shutdown_stages();
    printf("[shutdown] joining runtime workers\n");
    boot_join_address_backfill_service(svc);
    boot_join_hodl_history_service(svc);
    boot_join_tx_index_service(svc);
    boot_join_offer_service(svc);
    boot_join_projection_backfill_service(svc);
    boot_join_catchup_service(svc);

    /* Diagnostic timeout first, then retain ownership until every remaining
     * CONSUMER exits. The DB worker/checkpointer are dependency providers for
     * the persistence stage below, so joining them here creates a lifecycle
     * cycle: the registry waits for zcl_db_worker, but db_service_stop() cannot
     * signal that worker until after the final queued flush/checkpoint. Exclude
     * those exact pthread identities (not names), drain every consumer with
     * dependencies live, then let shutdown_persist_runtime_state() stop the DB
     * provider and run a final all-thread ownership audit. */
    pthread_t db_threads[2];
    size_t db_thread_count = 0;
    if (svc->db_service) {
        if (svc->db_service->worker_started)
            db_threads[db_thread_count++] = svc->db_service->worker_thread;
        if (svc->db_service->ckpt_started)
            db_threads[db_thread_count++] = svc->db_service->ckpt_thread;
    }
    int stragglers = thread_registry_join_all_except(
        2, db_threads, db_thread_count);
    if (stragglers > 0) {
        fprintf(stderr,
                "[shutdown] %d worker(s) exceeded their join budget; "
                "waiting with dependencies retained\n",
                stragglers);
        thread_registry_join_all_owned_except(db_threads, db_thread_count);
    }
    printf("[shutdown] runtime consumers drained; DB provider retained\n");
}

static bool shutdown_persist_runtime_state(struct boot_svc_ctx *svc,
                                          bool diagnostics_drained)
{
    bool ok = true;

    rpc_blockchain_mmr_save(boot_node_db(svc));
    rpc_blockchain_mmb_save(boot_node_db(svc));
    rpc_blockchain_commitment_mmr_save(boot_node_db(svc));

    /* block_index.bin is intentionally published only after the clean marker,
     * when node.db has already closed. Retain its one complete, hash-bound
     * checkpoint header now so that durability ordering does not strip the
     * Equihash solution from the swarm bootstrap artifact. */
    struct zcl_result anchor = block_index_flat_anchor_prepare(svc->state);
    if (!anchor.ok)
        LOG_WARN("shutdown", "flat anchor prepare failed: %s", anchor.message);

    if (svc->block_tree_open) {
        block_tree_db_close(svc->block_tree);
        svc->block_tree_open = false;
    }

    if (svc->wallet_sqlite->open) {
        struct zcl_result wallet_flush =
            wallet_sqlite_flush_r(svc->wallet_sqlite, svc->wallet);
        if (!wallet_flush.ok) {
            LOG_WARN("shutdown", "wallet flush failed: code=%d message=%s",
                     wallet_flush.code,
                     wallet_flush.message[0] ? wallet_flush.message
                                             : "unspecified");
            ok = false;
        }
        wallet_sqlite_close(svc->wallet_sqlite);
    }

    /* progress.kv may have run synchronous=OFF during IBD. Restore its safe
     * mode and prove its WAL checkpoint before closing the handle. */
    if (progress_store_db()) {
        if (!progress_store_set_sync_mode(false))
            ok = false;
        if (!progress_store_checkpoint())
            ok = false;
        progress_store_close();
    }

    if (svc->node_db->open) {
        if (!db_service_flush_write(svc->db_service))
            ok = false;
        node_db_sync_mempool_save(svc->node_db, svc->mempool);
        /* IBD paths may have selected synchronous=OFF. The last authoritative
         * commit and checkpoint must run behind SQLite's strongest barrier. */
        if (!db_service_exec_write(svc->db_service,
                                   "PRAGMA synchronous=FULL"))
            ok = false;
        if (db_service_wal_checkpoint(svc->db_service))
            printf("[shutdown] WAL checkpoint complete\n");
        else {
            fprintf(stderr, "[shutdown] WAL checkpoint failed\n");
            ok = false;
        }
        /* Flush, PRAGMA and checkpoint above are unconditional: they ARE
         * durability. Only the close is gated -- app_runtime_node_db()
         * hands this same handle to diagnostics dumpers, and an undrained
         * capture can still be inside one (the omniscience dumper reaches
         * node_db via db_parity_sample_recent). node_db_close() flips
         * ndb->open and calls sqlite3_close() with no lock, so closing here
         * races that reader. Before this stage was allowed to continue past
         * a failed drain, _exit(1) made the window unreachable; now it is
         * reachable, so it must be guarded. */
        if (diagnostics_drained) {
            if (!db_service_close_write(svc->db_service))
                ok = false;
        } else {
            printf("[shutdown] node.db handle retained: an undrained "
                   "diagnostics capture may still be reading it\n");
        }
    }
    printf("[shutdown] stopping DB provider kernel\n");
    boot_stop_db_service_kernel();

    /* db_service_stop() has now signalled and joined the only intentionally
     * excluded provider threads. No registered thread may survive the final
     * durability barrier or observe the resource-release phase. */
    int stragglers = thread_registry_join_all(2);
    if (stragglers > 0) {
        fprintf(stderr,
                "[shutdown] %d final worker(s) exceeded their join budget; "
                "retaining ownership before durability\n",
                stragglers);
        thread_registry_join_all_owned();
    }
    int live_threads = thread_registry_live_count();
    int unreaped_threads = thread_registry_unreaped_count();
    if (live_threads != 0 || unreaped_threads != 0) {
        fprintf(stderr,
                "[shutdown] final worker ownership audit failed: "
                "live=%d unreaped=%d\n",
                live_threads, unreaped_threads);
        ok = false;
    }
    printf("[shutdown] runtime state persisted\n");
    return ok;
}

static void shutdown_release_owned_resources(struct boot_svc_ctx *svc,
                                             bool diagnostics_drained)
{
    printf("[shutdown] releasing owned resources\n");
    /* Revoking the published runtime handle is fail-CLOSED, so it happens
     * either way; everything below it is destructive. The one reader that may
     * still be live is an undrained diagnostics capture (debug_bundle_shutdown
     * returned false), and every reset/free below is state its dumpers read —
     * so retain it all instead. Durability is already secured by now, so
     * retaining costs nothing but address space in a process that _exit()s
     * within milliseconds. */
    app_runtime_set_current(NULL);
    if (!diagnostics_drained) {
        printf("[shutdown] owned resources RETAINED: a diagnostics capture "
               "did not drain\n");
        return;
    }
    zcl_service_kernel_reset(&svc->frontend_kernel);
    zcl_service_kernel_reset(&svc->runtime_kernel);
    zcl_service_kernel_reset(&svc->network_kernel);
    zcl_service_kernel_reset(&svc->service_kernel);
    /* Stages were quiesced before persistence and the final registry join;
     * the state they read can now go. proof_validate uses the Sapling params. */
    wallet_free(svc->wallet);
    tx_mempool_free(svc->mempool);
    main_state_free(svc->state);
    sapling_free_params();
    boot_stop_projection_storage();

    ecc_verify_destroy();
    ecc_stop();
    printf("[shutdown] owned resources released\n");
}

void app_shutdown_svc(struct boot_svc_ctx *svc)
{
    extern volatile sig_atomic_t g_shutdown_requested;

    /* Per-stage deadlines (shutdown_stagewatch_enter below) replace the old
     * single alarm(90) cliff: each stage is timed + budgeted, a fired deadline
     * names its stage and escalates truthfully, and a datadir receipt records
     * the verdict so a forced-but-durable stop is never mis-reported as
     * failure. See util/shutdown_stagewatch.h. */
    shutdown_stagewatch_begin(svc->datadir);
    boot_loop_guard_note_shutdown_intent();   /* E2: exit-reason breadcrumb */

    atomic_store(svc->running, false);
    process_block_set_gap_fill_kick(NULL, NULL);
    process_block_set_mempool_restore_hook(NULL, NULL);
    process_block_set_tip_publication_hooks(NULL, NULL, NULL);
    g_shutdown_requested = 1;
    thread_registry_request_shutdown();
    /* K3: stop the block-body read-ahead worker before main_state teardown (it
     * reads active_chain_at + preads blk*.dat). Idempotent + safe if never
     * started. */
    boot_block_prefetch_stop();
    event_emitf(EV_NODE_SHUTDOWN, 0, "graceful");
    event_async_stop();

    printf("Shutting down...\n");

    /* Emergency coins flush FIRST — minimize UTXO loss window.
     * SIGKILL from OOM killer / systemd timeout can arrive at any time
     * during shutdown. Flushing coins before anything else ensures the
     * UTXO state is safe even if the rest of shutdown is interrupted.
     * Durability-critical: a fired deadline grants a grace, never a skip. */
    shutdown_stagewatch_enter("emergency-coins-flush", 30, true, true);
    if (svc->coins_tip) {
        printf("Emergency coins flush...\n");
        (void)shutdown_flush_coins_to_sqlite(svc, "emergency");
        printf("Emergency flush done.\n");
    }

    /* Debug capture is an owned reader of connman, node.db and main_state.
     * Revoke new automatic AND RPC captures, then wait — inside a BOUNDED
     * budget — for every active capture before the first dumper dependency is
     * quiesced.
     *
     * Ownership is still never abandoned: a capture that does not drain is
     * never detached, and nothing it reads is freed (see the
     * diagnostics_drained guards in shutdown_quiesce_network_and_flush_coins
     * and shutdown_release_owned_resources). What changed is the CONSEQUENCE.
     * This used to _exit(1) here, which threw away the coins flush, the WAL
     * checkpoint and the clean marker — the whole durability barrier — over a
     * best-effort postmortem capture, and the next boot then paid a ~180 s
     * sqlite.quick_check. A blocked dumper must never cost the node its
     * durability, so shutdown now says so loudly and keeps going. */
    shutdown_stagewatch_enter("diagnostics-drain", 60, false, true);
    bool diagnostics_drained = diagnostics_controller_shutdown();
    if (!diagnostics_drained)
        fprintf(stderr,
                "[shutdown] diagnostics capture did not drain inside its "
                "budget; retaining every dependency it reads and continuing "
                "to durability\n");

    /* I-7b phase-1: detach hot path observers from the feeder while
     * the network is still draining. New block_msg arrivals between
     * here and quiesce will short-circuit at the global hook. */

    shutdown_stagewatch_enter("frontend-stop", 15, false, true);
    shutdown_stop_frontend_services(svc);
    /* Production evidence (2026-08-15) showed that 30s + two 15s graces
     * killed an otherwise healthy node before durability when an optional
     * discovery worker was still owned. Discovery waits are now promptly
     * interruptible; retain a 120s diagnostic budget as defense in depth for
     * legitimate socket/message cleanup and final coins I/O, still below the
     * service manager's 300s hard stop. */
    shutdown_stagewatch_enter("network-quiesce", 120, true, true);
    bool durability_ok =
        shutdown_quiesce_network_and_flush_coins(svc, diagnostics_drained);
    /* Consumer ownership is part of the durability barrier: dependencies may
     * not be closed while a consumer is live. A legitimate slow callback gets
     * bounded graces; a true wedge still exits loudly and unclean. */
    shutdown_stagewatch_enter("worker-drain", 60, true, true);
    shutdown_stop_runtime_and_drain_workers(svc);
    /* Capture while state and progress.kv are still live, after every writer
     * that could move their frontier has been joined. */
    boot_fast_restart_capture_shutdown_facts(svc->state);
    /* runtime-persist holds the final WAL checkpoint + wallet flush + mempool
     * save — the slow-after-a-long-fold stage that used to breach the 90s
     * cliff. Durability-critical: never skipped, only graced. */
    shutdown_stagewatch_enter("runtime-persist", 45, true, true);
    if (!shutdown_persist_runtime_state(svc, diagnostics_drained))
        durability_ok = false;

    if (!durability_ok) {
        fprintf(stderr,
                "[shutdown] durability barrier failed; refusing clean marker\n");
        (void)boot_shutdown_marker_remove_clean(svc->datadir);
        (void)shutdown_stagewatch_complete_unclean();
        fflush(stdout);
        fflush(stderr);
        _exit(1);
    }

    /* Write the verified-clean marker only after every authoritative writer is
     * joined and node.db is WAL-checkpointed and closed. */
    if (!boot_shutdown_marker_write_clean(svc->datadir)) {
        fprintf(stderr,
                "[shutdown] clean marker durability failed; exiting unclean\n");
        (void)boot_shutdown_marker_remove_clean(svc->datadir);
        (void)shutdown_stagewatch_complete_unclean();
        fflush(stdout);
        fflush(stderr);
        _exit(1);
    }

    /* THE durability point: coins flushed, node.db WAL-checkpointed + closed,
     * clean marker written. Everything past here is resumable at next boot, so
     * a fired deadline now forces a TRUTHFUL clean exit (0), not a false fail. */
    shutdown_stagewatch_mark_durable();

    /* Durability secured; only best-effort teardown follows. The block-index flat cache is written AFTER the marker (it previously preceded the checkpoint and lost the marker on a mid-teardown kill). */
    shutdown_stagewatch_enter("fast-restart-persist", 20, false, true);
    shutdown_persist_fast_restart_state(svc);
    /* Every worker was joined before persistence; destructive release is now
     * ownership-safe and cannot race a timed-out background callback. */
    shutdown_stagewatch_enter("release-resources", 15, false, true);
    shutdown_release_owned_resources(svc, diagnostics_drained);

    printf("Shutdown complete.\n");
    /* Closes the last stage, cancels the alarm, writes the CLEAN receipt. */
    if (!shutdown_stagewatch_complete_clean()) {
        fprintf(stderr,
                "[shutdown] receipt durability failed; revoking clean marker\n");
        if (!boot_shutdown_marker_remove_clean(svc->datadir))
            fprintf(stderr,
                    "[shutdown] CRITICAL: failed to revoke clean marker\n");
        fflush(stdout);
        fflush(stderr);
        _exit(1);
    }
}

/* The OFFLINE teardown must obey the same ownership rule. The registry's
 * shutdown request only SETS a flag;
 * some background workers spawned during boot — notably the deferred Sapling-
 * tree rebuild (sapling_tree_rebuild_start_deferred), which the seed one-shot
 * arms on a root-mismatch and which replays h≈activation..tip reading g_state /
 * g_node_db WITHOUT polling that flag — are still live here. Running the
 * destructive frees while such a worker reads that state is a use-after-free.
 * Diagnose bounded-join overruns, then retain dependencies and ownership until
 * every worker actually exits. */
void boot_offline_join_workers_or_exit(const char *datadir)
{
    (void)datadir;
    int stragglers = thread_registry_join_all(2);
    if (stragglers > 0) {
        fprintf(stderr,
                "[shutdown] %d offline worker(s) exceeded join budget; "
                "waiting with dependencies retained\n",
                stragglers);
        thread_registry_join_all_owned();
    }
}

bool boot_offline_persist_runtime(struct node_db *ndb)
{
    bool ok = true;
    shutdown_stagewatch_enter("offline-persist", 45, true, true);
    if (progress_store_db()) {
        if (!progress_store_set_sync_mode(false) ||
            !progress_store_checkpoint()) {
            LOG_WARN("shutdown", "offline progress-store checkpoint failed");
            ok = false;
        }
        progress_store_close();
    }
    boot_stop_projection_storage();
    if (ndb && ndb->open) {
        if (!node_db_sync_flush(ndb) ||
            !node_db_exec(ndb, "PRAGMA synchronous=FULL") ||
            !node_db_wal_checkpoint(ndb)) {
            LOG_WARN("shutdown", "offline node.db durability barrier failed");
            ok = false;
        }
        node_db_close(ndb);
    }
    return ok;
}

void boot_offline_complete_durability_or_exit(const char *datadir,
                                               bool durability_ok)
{
    if (!durability_ok || !boot_shutdown_marker_write_clean(datadir)) {
        fprintf(stderr,
                "[shutdown] offline durability barrier failed; exiting unclean\n");
        (void)boot_shutdown_marker_remove_clean(datadir);
        (void)shutdown_stagewatch_complete_unclean();
        fflush(stdout);
        fflush(stderr);
        _exit(1);
    }
    shutdown_stagewatch_mark_durable();
    if (shutdown_stagewatch_complete_clean())
        return;
    fprintf(stderr,
            "[shutdown] offline receipt durability failed; revoking marker\n");
    (void)boot_shutdown_marker_remove_clean(datadir);
    fflush(stdout);
    fflush(stderr);
    _exit(1);
}
