/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

// one-result-type-ok:health-no-fallible-surface
/* E2 (one-result-type) override. This service owns no fallible public
 * surface: node_health_collect() returns void (it best-effort fills a
 * caller-owned snapshot, defaulting fields it cannot read rather than
 * failing), and node_health_chain_advance_synced() is a pure predicate
 * (a yes/no question over a bsp_decision, not an operation that can
 * fail for a reason). There is no error to carry, so zcl_result would
 * add a code/message that is always ZCL_OK. Marker, not a baseline
 * entry, per check_one_result_type.sh's override path. */

#include "base/text_fit.h"
#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "util/mem_pressure.h"
#include "services/node_health_service.h"
#include "jobs/stage_helpers.h"
#include "jobs/tip_finalize_stage.h"
#include "services/block_source_policy.h"
#include "services/chain_evidence_authority_service.h"
#include "services/chain_state_service.h"
#include "services/invariant_sentinel.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/sync_monitor.h"
#include "services/network_monitor.h"
#include "config/runtime.h"
#include "controllers/sync_controller.h"
#include "controllers/network_controller.h"
#include "models/block.h"
#include "models/database.h"
#include "net/onion_service.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "net/connman.h"
#include "net/download.h"
#include "net/peer_identity.h"
#include "net/tor_integration.h"
#include "net/version.h"
#include "storage/body_history.h"
#include "adapters/outbound/persistence/node_health_store_sqlite.h"
#include "ports/node_health_store_port.h"
#include <stdio.h>
#include <limits.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#include "util/log_macros.h"
#include "util/alerts.h"

static const int64_t HEALTH_JOB_STALL_SECONDS = 120;
static const int64_t HEALTH_RECENT_ERROR_SECONDS = 300;
static const int64_t HEALTH_RSS_WARNING_MB = 4096;
/* Plausibility band above our header tip for one peer's claim (10,000 blocks
 * ~17 days; see node_health_resolve_network_tip in the header). */
#define NODE_HEALTH_PLAUSIBLE_TIP_BAND 10000

int64_t node_health_resolve_network_tip(int64_t raw_max, int peers_above_band,
                                        int64_t header_tip, bool modal_ready,
                                        int64_t modal_height, int modal_count)
{
    int64_t plausible_ceiling =
        header_tip >= 0 ? header_tip + NODE_HEALTH_PLAUSIBLE_TIP_BAND
                        : INT64_MAX;
    int64_t clamped_max = raw_max;
    if (raw_max > plausible_ceiling && peers_above_band < 2)
        clamped_max = plausible_ceiling; /* lone uncorroborated outlier */
    if (modal_ready && modal_count >= 3 && modal_height >= 0)
        return modal_height;             /* >=3-peer modal beats clamped MAX */
    return clamped_max;
}

static int health_tip_finalize_log_head(void)
{
    uint64_t live = tip_finalize_stage_cursor();
    if (live > 0 && live <= INT_MAX)
        return (int)live;

    sqlite3 *db = progress_store_db();
    if (!db)
        return -1; // raw-return-ok:progress-store-not-open

    uint64_t persisted = 0;
    if (!stage_cursor_read_or_zero(db, "tip_finalize", "health", &persisted))
        return -1; // raw-return-ok:stage-helper-logged
    if (persisted == 0 || persisted > INT_MAX)
        return -1; // raw-return-ok:no-durable-tip
    return (int)persisted;
}

#ifdef ZCL_TESTING
static _Atomic int g_test_log_head_override = -2;
static _Atomic int64_t g_test_memory_rss_mb_override = -1;
static bool g_test_chain_advance_decision_override_enabled;
static struct bsp_decision g_test_chain_advance_decision_override;

void node_health_test_set_log_head_override(int log_head)
{
    atomic_store(&g_test_log_head_override, log_head);
}

void node_health_test_set_chain_advance_decision_override(
    const struct bsp_decision *decision)
{
    if (decision) {
        g_test_chain_advance_decision_override = *decision;
        g_test_chain_advance_decision_override_enabled = true;
        return;
    }
    memset(&g_test_chain_advance_decision_override, 0,
           sizeof(g_test_chain_advance_decision_override));
    g_test_chain_advance_decision_override_enabled = false;
}

void node_health_test_set_memory_rss_mb_override(int64_t memory_rss_mb)
{
    atomic_store(&g_test_memory_rss_mb_override, memory_rss_mb);
}
#endif

bool node_health_chain_advance_synced(const struct bsp_decision *decision)
{
    if (!decision)
        return false;
    if (decision->result != BSP_DECISION_USE_SOURCE)
        return false;
    if (decision->selected_source <= BSP_SOURCE_NONE ||
        decision->selected_source >= BSP_SOURCE_NUM)
        return false;
    if (decision->blocker[0] != '\0')
        return false;
    if (decision->local_height < 0 || decision->target_height < 0)
        return false;
    if (decision->local_height + 1 < decision->target_height)
        return false;
    const struct bsp_source_status *source =
        &decision->sources[decision->selected_source];
    return source->available && source->healthy && source->selectable &&
           !source->blocked && source->selection_reason[0] == '\0';
}

static bool node_health_chain_advance_blocks_at_tip(
    const struct bsp_decision *decision)
{
    if (!decision)
        return false;
    if (node_health_chain_advance_synced(decision))
        return false;
    if (decision->blocker[0] != '\0')
        return true;
    if (decision->result == BSP_DECISION_BLOCKED)
        return true;
    if (decision->local_height >= 0 && decision->target_height >= 0 &&
        decision->local_height + 1 < decision->target_height)
        return true;
    return false;
}

static void node_health_chain_advance_reason(
    const struct bsp_decision *decision,
    char *out,
    size_t out_len)
{
    if (!out || out_len == 0)
        return;
    out[0] = '\0';
    if (!decision) {
        snprintf(out, out_len, "chain_advance_unknown");
        return;
    }
    if (decision->blocker[0] != '\0') {
        snprintf(out, out_len, "chain_advance_%.100s", decision->blocker);
        return;
    }
    if (decision->local_height >= 0 && decision->target_height >= 0 &&
        decision->local_height + 1 < decision->target_height) {
        snprintf(out, out_len, "chain_advance_gap_%d",
                 decision->target_height - decision->local_height);
        return;
    }
    if (decision->reason[0] != '\0') {
        snprintf(out, out_len, "chain_advance_%.100s", decision->reason);
        return;
    }
    snprintf(out, out_len, "chain_advance_%s",
             bsp_decision_result_name(decision->result));
}

static void health_add_warning(struct node_health_snapshot *snapshot,
                               const char *reason)
{
    if (!snapshot || !reason || !reason[0])
        return;
    if (strstr(snapshot->warning_reasons, reason))
        return;

    /* warning_count is every warning OBSERVED, warning_reasons is as many as
     * fit; the two disagreeing is intended. Disagreeing SILENTLY was not — the
     * list used to end in half a warning name that read like a whole one. */
    (void)zcl_text_fit_append(snapshot->warning_reasons,
                              sizeof(snapshot->warning_reasons), ",", reason,
                              "health", "node_health.warning_reasons");
    snapshot->warning_count++;
}

static void health_finalize_serving_status(struct node_health_snapshot *snapshot)
{
    if (!snapshot)
        return;

    snapshot->serving = snapshot->healthy;
    if (!snapshot->healthy) {
        snprintf(snapshot->blocking_reason, sizeof(snapshot->blocking_reason),
                 "%s", snapshot->degraded_reason[0]
                          ? snapshot->degraded_reason
                          : "unhealthy");
    }

    if (snapshot->tip_stale)
        health_add_warning(snapshot, "tip_stale");
    if (snapshot->last_error_recent)
        health_add_warning(snapshot, "recent_error");
    if (snapshot->memory_rss_mb > HEALTH_RSS_WARNING_MB)
        health_add_warning(snapshot, "high_memory_usage");
    if (strcmp(snapshot->mirror_lag_breach_severity, "warn") == 0)
        health_add_warning(snapshot, "mirror_lag_warn");
    else if (strcmp(snapshot->mirror_lag_breach_severity, "critical") == 0)
        health_add_warning(snapshot, "mirror_lag_critical");
    if (!snapshot->validation_pack_ok)
        health_add_warning(snapshot,
                           snapshot->validation_pack_detail[0]
                               ? snapshot->validation_pack_detail
                               : "validation_pack");

    if (snapshot->healthy && snapshot->degraded_reason[0])
        health_add_warning(snapshot, snapshot->degraded_reason);

    snapshot->warning = snapshot->warning_count > 0;
    node_health_verdict_publish(snapshot); /* diagnostic publication time */
}

void node_health_collect(struct node_health_snapshot *snapshot,
                         struct node_db *ndb,
                         const struct main_state *ms)
{
    struct node_health_snapshot empty = {0};    char chain_advance_degraded_reason[128] = {0};
    if (!snapshot) return;
    *snapshot = empty;

    if (!ndb)
        ndb = app_runtime_node_db();
    if (!ms)
        ms = sync_monitor_main_state();

    snapshot->sync_state = sync_get_state();
    snapshot->synced = (snapshot->sync_state == SYNC_AT_TIP);
    snapshot->tip_height = -1;
    snapshot->header_height = -1;
    snapshot->peer_best_height = -1;
    snapshot->log_head = -1;
    snapshot->log_head_gap = -1;
    snapshot->last_error_age_seconds = -1;
    snapshot->tor_enabled = tor_integration_is_enabled();
    snapshot->tor_ready = tor_integration_is_ready();
    snapshot->onion_service_ready = false;

    {
        const char *onion = onion_service_get_address();
        if (onion && onion[0]) {
            snprintf(snapshot->onion_address, sizeof(snapshot->onion_address),
                     "%s", onion);
            snapshot->onion_service_ready = true;
        }
    }

    struct connman *cm = rpc_net_get_connman();
    snapshot->peer_count = cm ? connman_get_node_count(cm) : 0;
    snapshot->has_peers = snapshot->peer_count > 0;

    /* Classify handshaked peers by subver so /api/health.network can
     * report magicbean vs zclassic-c23 counts. Uses the same
     * msg_version_classify_peer() helper as getnetworkinfo so the two
     * surfaces never drift. */
    if (cm) {
        struct zcl_peer_host_set zcl23_hosts;
        zcl_peer_host_set_init(&zcl23_hosts);
        zcl_mutex_lock(&cm->manager.cs_nodes);
        for (size_t i = 0; i < cm->manager.num_nodes; i++) {
            struct p2p_node *node = cm->manager.nodes[i];
            if (!node || node->disconnect) continue;
            if (node->state < PEER_HANDSHAKE_COMPLETE) continue;
            bool is_mb = false, is_z23 = false;
            msg_version_classify_peer(node->sub_ver, node->services,
                                      &is_mb, &is_z23);
            if (is_mb) snapshot->magicbean_peer_count++;
            if (is_z23 && !msg_version_peer_uses_external_host(node) &&
                zcl_peer_host_set_add_peer(&zcl23_hosts, node))
                snapshot->zclassic_c23_peer_count++;
        }
        zcl_mutex_unlock(&cm->manager.cs_nodes);
    }

    if (ms) {
        struct block_index *tip = active_chain_tip(&ms->chain_active);
        if (tip) {
            snapshot->tip_height = tip->nHeight;
            if (tip->nTime > 0) {
                int64_t now = (int64_t)platform_time_wall_time_t();
                if (now > (int64_t)tip->nTime) {
                    snapshot->tip_stale_seconds = now - (int64_t)tip->nTime;
                    snapshot->tip_stale = snapshot->tip_stale_seconds > 600;
                }
            }
        }
    }

    if (ndb && ndb->open) {
        struct node_db_status dbs = {0};
        struct db_service *dbsvc = app_runtime_db_service();
        struct db_service_status svc_status = {0};
        /* The three persistent reads node_health does go through the
         * node_health_store port so the service never names sqlite. The
         * two SELECTs read the shared query connection; the WAL stat
         * resolves the primary node-DB filename. Falls back to an
         * in-memory estimate when a persistent read fails. */
        struct node_health_store_sqlite_ctx store_ctx;
        struct node_health_store_port store = {0};
        node_health_store_sqlite_bind(&store_ctx, app_runtime_query_db(),
                                      ndb->db, &store);
        node_db_get_status(ndb, &dbs);
        db_service_get_status(dbsvc, &svc_status);
        snapshot->db_open = dbs.open;
        snapshot->db_tx_open = dbs.tx_open;
        snapshot->db_turbo_mode = dbs.turbo_mode;
        snapshot->db_last_sqlite_rc = dbs.last_sqlite_rc;
        snapshot->db_service_started = svc_status.started;
        snapshot->db_service_worker_started = svc_status.worker_started;
        snapshot->db_service_stop_requested = svc_status.stop_requested;
        snapshot->db_service_queue_depth = svc_status.queue_depth;
        if (svc_status.started_at > 0) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            if (now >= svc_status.started_at)
                snapshot->db_service_uptime_seconds =
                    now - svc_status.started_at;
        }
        snprintf(snapshot->db_last_op, sizeof(snapshot->db_last_op),
                 "%s", dbs.last_op);
        if (dbs.last_activity_time > 0) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            if (now >= dbs.last_activity_time)
                snapshot->db_last_activity_age_seconds =
                    now - dbs.last_activity_time;
        }
        if (snapshot->tip_height < 0) {
            if (!store.tip_height_from_blocks(store.self,
                                              &snapshot->tip_height)) {
                snapshot->tip_height = db_block_max_height(ndb);
            }
        }
        if (!store.utxo_count(store.self, &snapshot->utxo_count)) {
            snapshot->utxo_count = node_db_utxo_count(ndb);
        }

        int64_t wal_bytes = 0;
        if (store.wal_size_bytes(store.self, &wal_bytes))
            snapshot->wal_size_bytes = wal_bytes;
    }

    if (ms && ms->pindex_best_header)
        snapshot->header_height = ms->pindex_best_header->nHeight;
    if (snapshot->header_height < 0)
        snapshot->header_height = snapshot->tip_height;

    if (cm) {
        int64_t newest_peer_block_time = 0;
        /* Gather raw MAX + count of peers past the plausibility band, then
         * resolve (clamp lone outliers; prefer a >=3-peer modal). Health READ
         * only — chain selection is untouched. */
        int64_t raw_max = -1;
        int64_t header_tip = snapshot->header_height;
        int64_t plausible_ceiling =
            header_tip >= 0 ? header_tip + NODE_HEALTH_PLAUSIBLE_TIP_BAND
                            : INT64_MAX;
        int peers_above_band = 0;
        zcl_mutex_lock(&cm->manager.cs_nodes);
        for (size_t i = 0; i < cm->manager.num_nodes; i++) {
            const struct p2p_node *node = cm->manager.nodes[i];
            if (!node || node->disconnect ||
                node->state < PEER_HANDSHAKE_COMPLETE ||
                (node->services & NODE_NETWORK) == 0)
                continue;
            int64_t claim = node->starting_height;
            if (claim > raw_max)
                raw_max = claim;
            if (claim > plausible_ceiling)
                peers_above_band++;
            if (node->last_block_time > newest_peer_block_time)
                newest_peer_block_time = node->last_block_time;
        }
        zcl_mutex_unlock(&cm->manager.cs_nodes);

        struct network_consensus_view nmv;
        bool modal_ready = network_monitor_get_view(&nmv);
        int64_t network_tip = node_health_resolve_network_tip(
            raw_max, peers_above_band, header_tip, modal_ready,
            modal_ready ? nmv.modal_height : -1,
            modal_ready ? nmv.modal_height_count : 0);

        if (network_tip >= 0 && network_tip <= INT_MAX)
            snapshot->peer_best_height = (int)network_tip;

        (void)newest_peer_block_time;
    }

    if (snapshot->peer_best_height >= 0 && snapshot->tip_height >= 0 &&
        snapshot->peer_best_height > snapshot->tip_height) {
        snapshot->tip_lag = snapshot->peer_best_height - snapshot->tip_height;
    }

    /* Prime Directive health = network_tip - log_head. log_head is the
     * tip_finalize cursor, which under the served-tip convention IS the
     * reducer's finalized served height directly — cursor C means "served
     * tip at C". A zero cursor means "nothing served yet" -> -1. */
    {
#ifdef ZCL_TESTING
        int override = atomic_load(&g_test_log_head_override);
        if (override >= -1) {
            snapshot->log_head = override;
        } else
#endif
        {
            snapshot->log_head = health_tip_finalize_log_head();
        }
        if (snapshot->peer_best_height >= 0 && snapshot->log_head >= 0)
            snapshot->log_head_gap =
                snapshot->peer_best_height - snapshot->log_head;
    }

    {
        struct bsp_decision decision;
#ifdef ZCL_TESTING
        if (g_test_chain_advance_decision_override_enabled) {
            decision = g_test_chain_advance_decision_override;
        } else
#endif
        {
            block_source_policy_get_status(&decision);
        }
        if (node_health_chain_advance_synced(&decision) && /* heights only; */
            body_history_is_proven()) { /* UPGRADE needs the archive. Header. */
            snapshot->synced = true;
            snapshot->sync_state = SYNC_AT_TIP;
        } else if (snapshot->sync_state == SYNC_AT_TIP &&
                 node_health_chain_advance_blocks_at_tip(&decision)) {
            snapshot->synced = false;
            node_health_chain_advance_reason(
                &decision, chain_advance_degraded_reason,
                sizeof(chain_advance_degraded_reason));
        }
    }

    dl_get_stats(msg_get_download_mgr(),
                 &snapshot->blocks_requested,
                 &snapshot->blocks_received,
                 &snapshot->blocks_timed_out,
                 &snapshot->in_flight,
                 &snapshot->queued);
    dl_get_throughput(msg_get_download_mgr(),
                      &snapshot->download_bytes_received,
                      &snapshot->download_mbps_avg);
    snapshot->queue_backed_up =
        (snapshot->queued > 256 || snapshot->in_flight > 128);

    {
        struct node_db_sync_job_status jobs = {0};
        node_db_sync_get_job_status(&jobs);
        snapshot->catchup_active = jobs.catchup_active;
        snapshot->catchup_height = jobs.catchup_height;
        snapshot->catchup_target_height = jobs.catchup_target_height;
        snapshot->import_active = jobs.import_active;
        snapshot->import_rows_written = jobs.import_rows_written;
        if (jobs.catchup_started_at > 0) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            if (now >= jobs.catchup_started_at)
                snapshot->catchup_uptime_seconds = now - jobs.catchup_started_at;
        }
        if (jobs.catchup_last_progress_at > 0) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            if (now >= jobs.catchup_last_progress_at)
                snapshot->catchup_progress_age_seconds =
                    now - jobs.catchup_last_progress_at;
        }
        if (jobs.import_started_at > 0) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            if (now >= jobs.import_started_at)
                snapshot->import_uptime_seconds = now - jobs.import_started_at;
        }
        if (jobs.import_last_progress_at > 0) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            if (now >= jobs.import_last_progress_at)
                snapshot->import_progress_age_seconds =
                    now - jobs.import_last_progress_at;
        }

        struct error_ring *er = error_ring_global();
        const struct error_entry *last_err = error_ring_last(er);
        snapshot->error_total = error_ring_total(er);
        if (last_err && last_err->message[0]) {
            int64_t now_us = (int64_t)platform_time_wall_time_t() * 1000000;
            if (last_err->timestamp_us > 0) {
                if (now_us >= last_err->timestamp_us) {
                    snapshot->last_error_age_seconds =
                        (now_us - last_err->timestamp_us) / 1000000;
                } else if (last_err->timestamp_us - now_us < 1000000) {
                    snapshot->last_error_age_seconds = 0;
                }
            }
            snapshot->last_error_recent =
                snapshot->last_error_age_seconds >= 0 &&
                snapshot->last_error_age_seconds <= HEALTH_RECENT_ERROR_SECONDS;
            snprintf(snapshot->last_error, sizeof(snapshot->last_error),
                     "%s", last_err->message);
            snprintf(snapshot->last_error_type, sizeof(snapshot->last_error_type),
                     "%s", event_type_name(last_err->type));
        }
    }

    {
        int64_t age = os_proc_uptime_seconds();
        snapshot->uptime_seconds = age >= 0 ? age : 0;
    }

    {
        struct os_proc_mem mem;
        snapshot->memory_rss_mb = (os_proc_mem_read(&mem) && mem.rss_bytes >= 0)
            ? mem.rss_bytes / (1024 * 1024) : -1;
#ifdef ZCL_TESTING
        int64_t rss_override =
            atomic_load(&g_test_memory_rss_mb_override);
        if (rss_override >= 0)
            snapshot->memory_rss_mb = rss_override;
#endif
    }

    if (!snapshot->has_peers) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "no_peers");
    } else if (snapshot->catchup_active &&
               snapshot->catchup_progress_age_seconds > HEALTH_JOB_STALL_SECONDS) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "catchup_stalled_%llds",
                 (long long)snapshot->catchup_progress_age_seconds);
    } else if (snapshot->import_active &&
               snapshot->import_progress_age_seconds > HEALTH_JOB_STALL_SECONDS) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "import_stalled_%llds",
                 (long long)snapshot->import_progress_age_seconds);
    } else if (chain_advance_degraded_reason[0]) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "%s", chain_advance_degraded_reason);
    } else if (!snapshot->synced) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "sync_state_%s", sync_state_name(snapshot->sync_state));
    } else if (snapshot->header_height >
               snapshot->tip_height + ZCL_NODE_HEALTH_LAG_WARN_BLOCKS) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "headers_ahead_%d", snapshot->header_height - snapshot->tip_height);
    } else if (snapshot->tip_lag > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "tip_lag_%d", snapshot->tip_lag);
    } else if (snapshot->log_head_gap > 1) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "log_head_gap_%d", snapshot->log_head_gap);
    } else if (snapshot->queue_backed_up) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "download_queue_backed_up");
    } else if (snapshot->db_service_started &&
               !snapshot->db_service_worker_started) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "db_service_worker_down");
    } else if (snapshot->db_service_queue_depth > 32) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "db_service_queue_%zu", snapshot->db_service_queue_depth);
    } else if (snapshot->db_tx_open &&
               snapshot->db_last_activity_age_seconds > 60) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "db_tx_open_%llds",
                 (long long)snapshot->db_last_activity_age_seconds);
    } else if (snapshot->tip_height < 0) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "active_tip_unknown");
    } else if (snapshot->header_height < 0) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "best_header_unknown");
    } else if (snapshot->peer_best_height < 0) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "peer_height_unknown");
    } else if (snapshot->log_head < 0) {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "log_head_unknown");
    }

    snapshot->healthy = snapshot->synced &&
                        snapshot->has_peers &&
                        snapshot->tip_height >= 0 &&
                        snapshot->header_height >= 0 &&
                        snapshot->peer_best_height >= 0 &&
                        snapshot->header_height <= snapshot->tip_height +
                            ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
                        snapshot->tip_lag >= 0 &&
                        snapshot->tip_lag <= ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
                        snapshot->log_head >= 0 &&
                        snapshot->log_head_gap <= 1;

    /* mem_pressure's cgroup-aware level, distinct from the raw RSS
     * threshold above. CRITICAL flips healthy=false for serving, conditions,
     * and remedies; systemd's watchdog remains a process-hang detector.
     * HIGH is a warning, giving memory_pressure_high's remedy sinks a chance
     * to work. */
    {
        enum mem_pressure_level mp_level = mem_pressure_current();
        if (mp_level >= MEM_HIGH)
            health_add_warning(snapshot, "mem_pressure_high");
        if (mp_level >= MEM_CRITICAL) {
            if (snapshot->degraded_reason[0] == '\0')
                snprintf(snapshot->degraded_reason,
                         sizeof(snapshot->degraded_reason),
                         "memory_pressure_critical");
            snapshot->healthy = false;
        }
    }

    /* Surface tip-advance age + flip healthy when the watchdog deadman
     * threshold is crossed in any non-tip state with peers. Threshold
     * matches sync_watchdog_service.c state_stuck_timeout for
     * HEADERS_DOWNLOAD / BLOCKS_DOWNLOAD (600s). */
    snapshot->tip_advance_age_seconds = sync_monitor_tip_advance_age();
    if (snapshot->tip_advance_age_seconds > 600 &&
        snapshot->has_peers &&
        snapshot->sync_state != SYNC_AT_TIP &&
        snapshot->degraded_reason[0] == '\0') {
        snprintf(snapshot->degraded_reason, sizeof(snapshot->degraded_reason),
                 "tip_advance_age_%llds_in_%s",
                 (long long)snapshot->tip_advance_age_seconds,
                 sync_state_name(snapshot->sync_state));
        snapshot->healthy = false;
    }

    /* Watchdog stats */
    {
        struct watchdog_stats wd;
        sync_monitor_get_stats(&wd);
        snapshot->wd_checks_run = wd.checks_run;
        snapshot->wd_recoveries = wd.recoveries_total;
        snapshot->wd_blocks_per_sec = wd.blocks_per_sec;
        snapshot->wd_escalation_level = wd.escalation_level;
        snapshot->wd_last_recovery_time = wd.last_recovery_time;
        snapshot->wd_last_recovery_type = (int)wd.last_recovery;
        snapshot->wd_last_recovery_target_height =
            wd.last_recovery_target_height;
        snapshot->wd_last_recovery_manifest_height =
            wd.last_recovery_manifest_height;
        snprintf(snapshot->wd_last_recovery_name,
                 sizeof(snapshot->wd_last_recovery_name),
                 "%s", watchdog_recovery_type_name(wd.last_recovery));
        snprintf(snapshot->wd_last_recovery_reason,
                 sizeof(snapshot->wd_last_recovery_reason),
                 "%s", wd.last_recovery_reason);
        snprintf(snapshot->wd_last_recovery_trigger,
                 sizeof(snapshot->wd_last_recovery_trigger),
                 "%s", wd.last_recovery_trigger);
    }

    /* Mirror lag SLO breach → loud health degradation. Fatal severity flips
     * healthy=false for serving, conditions, remedies, and operator paging.
     * It does not claim that the process is hung or ask systemd to restart. */
    {
        struct chain_evidence_controller cec;
        struct chain_evidence_controller_view view;
        chain_evidence_controller_init(&cec, ndb, csr_instance());
        /* Drain the reducer's pending published tip BEFORE snapshotting:
         * the durable evidence follow runs here — the health path owns the
         * established csr->coins_kv lock order — never on the drive (ABBA
         * deadlock). Doing it first means the snapshot below compares
         * against evidence that already names the served tip, so a green
         * node reads healthy. */
        (void)chain_evidence_drain_pending_tip(&cec);
        chain_evidence_controller_snapshot(&cec, &view);
        if (view.state == CEC_CONTRADICTION_FROZEN) {
            if (snapshot->degraded_reason[0] == '\0') {
                snprintf(snapshot->degraded_reason,
                         sizeof(snapshot->degraded_reason),
                         "%s", view.health_reason[0] ? view.health_reason
                                                       : "chain_evidence_contradiction");
            }
            snapshot->healthy = false;
        } else if (view.health_reason[0]) {
            if (snapshot->degraded_reason[0] == '\0') {
                snprintf(snapshot->degraded_reason,
                         sizeof(snapshot->degraded_reason),
                         "%s", view.health_reason);
            }
            snapshot->healthy = false;
        }
    }

    {
        struct legacy_mirror_sync_stats ms = {0};
        legacy_mirror_sync_stats_snapshot(&ms);
        snapshot->mirror_lag_blocks = ms.lag_known ? ms.lag : -1;
        snapshot->mirror_lag_breach_seconds = ms.lag_breach_seconds;
        snapshot->mirror_lag_critical_seconds = ms.lag_critical_seconds;
        snprintf(snapshot->mirror_lag_breach_severity,
                 sizeof(snapshot->mirror_lag_breach_severity), "%s",
                 ms.lag_breach_severity);
        bool same_height_hash_gap =
            ms.enabled && ms.reachable && ms.lag_known &&
            ms.local_height >= 0 && ms.legacy_height >= 0 &&
            ms.local_height == ms.legacy_height &&
            !ms.tip_hashes_agree;
        if (same_height_hash_gap) {
            if (snapshot->degraded_reason[0] == '\0') {
                snprintf(snapshot->degraded_reason,
                         sizeof(snapshot->degraded_reason),
                         "mirror_same_height_hash_unavailable_or_mismatch");
            }
            snapshot->healthy = false;
        }
        if (ms.unsafe_overrides_total > 0) {
            if (snapshot->degraded_reason[0] == '\0') {
                snprintf(snapshot->degraded_reason,
                         sizeof(snapshot->degraded_reason),
                         "mirror_unsafe_overrides_%lld",
                         (long long)ms.unsafe_overrides_total);
            }
            snapshot->healthy = false;
        }
        if (strcmp(ms.lag_breach_severity, "fatal") == 0) {
            if (snapshot->degraded_reason[0] == '\0') {
                snprintf(snapshot->degraded_reason,
                         sizeof(snapshot->degraded_reason),
                         "mirror_lag_fatal_%lld_blocks_%llds",
                         (long long)ms.lag,
                         (long long)ms.lag_critical_seconds);
            }
            snapshot->healthy = false;
        }
    }

    /* Operator-needed latch — the loudest signal in the system. When the
     * auto-healing condition engine exhausts its remedies it emits
     * EV_OPERATOR_NEEDED, which platform/modules/util/alerts.c latches. Reflect it here
     * so a halt that no remedy could clear shows up as DEGRADED in
     * `z23 status` and stops the sd_notify heartbeat. Overrides any softer
     * degraded_reason because it means automation has given up. */
    {
        char detail[sizeof(snapshot->operator_needed_detail)] = {0};
        snapshot->operator_latch_recovered =
            alerts_operator_needed_clear_if_chain_advance_recovered(
                snapshot->healthy, detail, sizeof(detail), NULL);
        if (snapshot->operator_latch_recovered)
            health_add_warning(snapshot, "operator_latch_recovered");
        snapshot->operator_needed =
            alerts_operator_needed(detail, sizeof(detail), NULL);
        if (snapshot->operator_needed) {
            snprintf(snapshot->operator_needed_detail,
                     sizeof(snapshot->operator_needed_detail), "%s", detail);
            snprintf(snapshot->degraded_reason,
                     sizeof(snapshot->degraded_reason),
                     "operator_needed:%s", detail[0] ? detail : "unspecified");
            snapshot->healthy = false;
        }
    }

    /* Fail-loud validation pack rollup: false while ANY pack blocker
     * (linkage/coinbase-label/pair/window/commitment/mirror-divergence/
     * seed-gate) or the HOLD latch is active. Informational on the
     * health surface — the HOLD already refuses forward progress and the
     * pack pages via EV_OPERATOR_NEEDED; we deliberately do NOT flip
     * snapshot->healthy here (a held node must KEEP serving + keep its
     * sd_notify heartbeat, not get restart-cycled by systemd). */
    {
        char detail[sizeof(snapshot->validation_pack_detail)] = {0};
        snapshot->validation_pack_ok =
            invariant_sentinel_healthy(detail, (int)sizeof(detail));
        snprintf(snapshot->validation_pack_detail,
                 sizeof(snapshot->validation_pack_detail), "%s", detail);
        if (!snapshot->validation_pack_ok &&
            !snapshot->degraded_reason[0])
            snprintf(snapshot->degraded_reason,
                     sizeof(snapshot->degraded_reason),
                     "validation_pack:%s",
                     detail[0] ? detail : "hold_active");
    }

    health_finalize_serving_status(snapshot);
}
