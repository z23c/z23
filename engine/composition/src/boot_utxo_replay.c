/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot UTXO-replay worker — the post-snapshot-import background chain
 * validation worker, lifted out of boot_background_workers.c to keep that
 * file under the E1 line ceiling. PURE relocation: the worker body is
 * byte-identical to its prior home; only its surrounding TU changed.
 *
 * After a snapshot import (file or P2P), coins_best_block in SQLite points
 * to the snapshot height, but the in-memory g_coins_tip and active chain are
 * still at genesis. This worker restores chain state to the snapshot
 * height, then activation-replays blocks in the background so the node
 * serves data immediately while the UTXO set builds. It is a supervised
 * background worker (Shape 5 — MONITOR): it shares the worker_on_stall
 * handler and boot_register_worker_supervisor helper exposed by
 * boot_background_workers.h and implemented in boot_worker_supervisor.c
 * (single source, not duplicated here), and reaches the boot context
 * through the boot_services.c accessors declared in boot_internal.h.
 *
 * The start/join pair is called from its existing sites in
 * app_init_services / app_shutdown_svc (boot_services.c), boot order
 * preserved. boot_start_replay_service / boot_join_replay_service are
 * declared in boot_background_workers.h (no dedicated header — same
 * pattern as boot_worker_supervisor.c), so boot_services.c needs no new
 * include for this split.
 */

#include "platform/time_compat.h"
#include "config/boot_internal.h"
#include "config/boot_background_workers.h"
#include "services/chain_activation_service.h"
#include "services/chain_state_service.h"
#include "jobs/reducer_frontier.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "validation/process_block.h"
#include "models/block.h"
#include "event/event.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UTXO_REPLAY_SUPERVISOR_DEADLINE_SEC         3600

static struct liveness_contract g_utxo_replay_contract;
static _Atomic supervisor_child_id g_utxo_replay_sup_id = SUPERVISOR_INVALID_ID;

static void *background_utxo_replay(void *arg);

bool boot_start_replay_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    boot_register_worker_supervisor(&g_utxo_replay_sup_id,
                                    &g_utxo_replay_contract, &g_chain_sup,
                                    "chain.background_utxo_replay",
                                    UTXO_REPLAY_SUPERVISOR_DEADLINE_SEC, 0);
    return boot_start_thread_service(&svc->replay_thread,
                                     &svc->replay_thread_started,
                                     background_utxo_replay, svc);
}

void boot_join_replay_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    boot_join_thread_service_named(&svc->replay_thread,
                                   &svc->replay_thread_started,
                                   "utxo_replay", 5);
}

/* ── Background UTXO replay ───────────────────────────────── */
/* After file sync, replay blocks to build UTXO set in background.
 * Node serves data immediately; UTXO set builds while running. */

_Atomic bool g_utxo_replay_active = false;
_Atomic int g_utxo_replay_height = 0;

/* boot_import_snapshot_db lives in engine/composition/src/boot_snapshot_import.c so
 * both boot.c (the pre-restore probe — the authoritative call site) and
 * this file (the late-receive path) share one implementation. */

static void *background_utxo_replay(void *arg)
{
    struct boot_svc_ctx *svc = arg;
    const struct chain_params *params = chain_params_get();
    supervisor_child_id sup_id = atomic_load(&g_utxo_replay_sup_id);

    if (!svc || !svc->state || !svc->coins_tip || !params || !svc->datadir)
        goto done;

    /* Single blocking activation call: heartbeat at entry and exit only.
     * Deep replay is slow sequential I/O, so the deadline is generous
     * (3600 s) and progress_max_quiet_us == 0 keeps the long silent run
     * from false-firing NO_PROGRESS. */
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_tick(sup_id);

    atomic_store(&g_utxo_replay_active, true);
    int64_t t0 = (int64_t)platform_time_wall_time_t();

    printf("UTXO replay: starting background chain validation...\n");
    fflush(stdout);

    /* ── Restore chain state from coins_best_block ──────────────
     * After snapshot import (file or P2P), coins_best_block in SQLite
     * points to the snapshot height, but the in-memory g_coins_tip and
     * active chain are still at genesis. We must advance both so the reducer
     * activation path starts from the snapshot height, not genesis.
     * Without this, connect_block fails at height 1 with BIP30 because
     * the snapshot's UTXOs include block 1's unspent coinbase. */
    struct node_db *ndb_restore = boot_node_db(svc);
    if (ndb_restore && ndb_restore->open) {
        /* Wave 2: locate the snapshot block from the DERIVED coins-best
         * (coins_kv's own co-committed state) first; the node_state
         * 'coins_best_block' key is only the legacy (!found) fallback. */
        struct uint256 cb_hash;
        uint256_set_null(&cb_hash);
        const char *cb_evidence = "snapshot_coins_best_block";
        {
            int32_t d_h = -1;
            uint8_t d_hash[32];
            bool d_hf = false;
            if (reducer_frontier_derive_coins_best_now(&d_h, d_hash,
                                                       &d_hf) && d_hf) {
                memcpy(cb_hash.data, d_hash, 32);
                cb_evidence = "derived_coins_best";
            }
        }
        if (uint256_is_null(&cb_hash)) {
            uint8_t cb_buf[32] = {0};
            size_t cb_len = 0;
            if (node_db_state_get(ndb_restore, "coins_best_block",
                                  cb_buf, sizeof(cb_buf), &cb_len) &&
                cb_len == 32)
                memcpy(cb_hash.data, cb_buf, 32);
        }
        {
            if (!uint256_is_null(&cb_hash)) {
                struct block_index *snap_block = block_map_find(
                    &svc->state->map_block_index, &cb_hash);
                if (snap_block && snap_block->nHeight > 0) {
                    struct chain_state_rollback_authorization rollback_auth = {
                        .source = CSR_ROLLBACK_SOURCE_SNAPSHOT,
                        .decision = POLICY_ALLOW,
                        .from_height = active_chain_height(
                            &svc->state->chain_active),
                        .to_height = snap_block->nHeight,
                        .max_depth = INT64_MAX,
                        .evidence_class = cb_evidence,
                        .reason = "utxo_replay_snapshot_restore",
                    };
                    struct chain_state_commit commit = {
                        .new_tip = snap_block,
                        .new_coins_best = cb_hash,
                        .expected_utxo_count = 0,
                        .update_header_tip = false,
                        .rollback_auth = &rollback_auth,
                        .wallet_scan_height = -1,
                        .reason = "utxo_replay_snapshot_restore",
                    };
                    enum csr_result rc = csr_commit_tip(csr_instance(),
                                                        &commit);
                    if (rc == CSR_OK) {
                        printf("UTXO replay: restored chain state from snapshot "
                               "at h=%d\n", snap_block->nHeight);
                    } else {
                        fprintf(stderr, // obs-ok:pre-existing-diagnostic
                                "UTXO replay: csr rejected snapshot restore "
                                "(%s) h=%d\n", csr_result_name(rc),
                                snap_block->nHeight);
                    }
                } else if (!snap_block) {
                    printf("UTXO replay: coins_best_block not in index "
                           "(waiting for P2P headers)\n");
                }
            }
        }
    }

    /* IBD turbo: skip non-essential work during replay */
    struct db_service *dbsvc = boot_db_service(svc);
    struct node_db *ndb = boot_node_db(svc);
    if (dbsvc) {
        db_service_ibd_turbo_mode(dbsvc);
        db_service_set_sync_batch_size(dbsvc, 1000);
    } else if (ndb && ndb->open) {
        node_db_ibd_turbo_mode(ndb);
        node_db_set_sync_batch_size(ndb, 1000);
    }
    /* Flush every 500 blocks even during IBD to limit UTXO loss on
     * SIGKILL. Previous value of 100000 meant a SIGKILL during boot
     * could lose 100K blocks of UTXO state, requiring full re-sync. */
    set_flush_policy(3600, 1000000, 500);

    {
        struct activation_exec_outcome outcome;
        activation_request_connect(boot_activation_controller(),
                                   ACTIVATION_SRC_UTXO_REPLAY,
                                   NULL, &outcome);
    }

    /* Restore normal flush policy */
    set_flush_policy(3600, 500000, 500);
    if (dbsvc) {
        if (!db_service_flush_write(dbsvc))
            fprintf(stderr, "UTXO replay: flush before normal mode failed\n");
        db_service_normal_mode(dbsvc);
        db_service_set_sync_batch_size(dbsvc, 100);
    } else if (ndb && ndb->open) {
        if (!node_db_sync_flush(ndb))
            fprintf(stderr, "UTXO replay: flush before normal mode failed\n");
        node_db_normal_mode(ndb);
        node_db_set_sync_batch_size(ndb, 100);
    }

    int tip = active_chain_height(&svc->state->chain_active);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    atomic_store(&g_utxo_replay_height, tip);
    atomic_store(&g_utxo_replay_active, false);

    printf("=== UTXO replay complete: tip=%d in %llds "
           "(%.0f blocks/sec) ===\n",
           tip, (long long)elapsed,
           elapsed > 0 ? (double)tip / (double)elapsed : 0);
    fflush(stdout);

    event_emitf(EV_NODE_READY, 0, "utxo_replay_done height=%d secs=%lld",
                tip, (long long)elapsed);

done:
    if (sup_id != SUPERVISOR_INVALID_ID)
        supervisor_tick(sup_id);
    boot_complete_worker_supervisor(&g_utxo_replay_sup_id);
    return NULL;
}
