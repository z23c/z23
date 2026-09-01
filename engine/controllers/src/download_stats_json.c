/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "controllers/download_stats_json.h"

#include "controllers/network_controller.h"
#include "json/json.h"
#include "net/download.h"
#include "services/node_health_service.h"

#include <stdio.h>
#include <string.h>

void download_stats_snapshot_collect(struct download_stats_snapshot *out,
                                     bool full)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));

    struct download_manager *dm = msg_get_download_mgr();
    dl_get_stats(dm, &out->requested, &out->received, &out->timed_out,
                &out->in_flight, &out->queued);
    dl_get_throughput(dm, &out->bytes_downloaded, &out->mbps_avg);

    if (!full)
        return;

    dl_get_diagnostics(dm, &out->diag);
    gap_fill_get_stats(&out->gf_stats);
    connman_get_message_cycle_stats(rpc_net_get_connman(), &out->msg_stats);
}

void download_stats_snapshot_from_health(
    struct download_stats_snapshot *out,
    const struct node_health_snapshot *health)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!health)
        return;

    out->requested = health->blocks_requested;
    out->received = health->blocks_received;
    out->timed_out = health->blocks_timed_out;
    out->in_flight = health->in_flight;
    out->queued = health->queued;
    out->bytes_downloaded = health->download_bytes_received;
    out->mbps_avg = health->download_mbps_avg;
}

void download_stats_push_json(struct json_value *obj,
                              const struct download_stats_snapshot *s,
                              bool full)
{
    if (!obj || !s)
        return;

    json_push_kv_int(obj, "requested", (int64_t)s->requested);
    json_push_kv_int(obj, "received", (int64_t)s->received);
    json_push_kv_int(obj, "timed_out", (int64_t)s->timed_out);
    json_push_kv_int(obj, "in_flight", (int64_t)s->in_flight);
    json_push_kv_int(obj, "queued", (int64_t)s->queued);

    if (full) {
        const struct dl_diagnostics *diag = &s->diag;

        json_push_kv_int(obj, "orphaned", (int64_t)diag->total_orphaned);
        json_push_kv_int(obj, "accounting_drift", diag->accounting_drift);
        json_push_kv_int(obj, "request_timeout_seconds",
                         (int64_t)diag->request_timeout_seconds);
        json_push_kv_int(obj, "oldest_in_flight_age_seconds",
                         diag->oldest_in_flight_age_seconds);
        json_push_kv_int(obj, "oldest_in_flight_height",
                         diag->oldest_in_flight_height);
        json_push_kv_int(obj, "oldest_in_flight_peer_id",
                         (int64_t)diag->oldest_in_flight_peer_id);
        json_push_kv_int(obj, "overdue_in_flight",
                         (int64_t)diag->overdue_in_flight);
        json_push_kv_int(obj, "in_flight_peer_count",
                         (int64_t)diag->in_flight_peer_count);
        json_push_kv_int(obj, "queue_peer_avoid_count",
                         (int64_t)diag->queue_peer_avoid_count);
        json_push_kv_int(obj, "queue_peer_avoid_max_seconds",
                         diag->queue_peer_avoid_max_seconds);
        json_push_kv_int(obj, "queued_forward",
                         (int64_t)diag->queued_forward);
        json_push_kv_int(obj, "queued_history",
                         (int64_t)diag->queued_history);
        json_push_kv_int(obj, "in_flight_forward",
                         (int64_t)diag->in_flight_forward);
        json_push_kv_int(obj, "in_flight_history",
                         (int64_t)diag->in_flight_history);
        json_push_kv_int(obj, "assign_attempts",
                         (int64_t)diag->assign_attempts);
        json_push_kv_int(obj, "assign_successes",
                         (int64_t)diag->assign_successes);
        json_push_kv_int(obj, "assign_zero_results",
                         (int64_t)diag->assign_zero_results);
        json_push_kv_int(obj, "dispatch_wakes",
                         (int64_t)s->gf_stats.dispatch_wakes);
        json_push_kv_int(obj, "message_cycles",
                         (int64_t)s->msg_stats.cycles);
        json_push_kv_int(obj, "message_nodes_snapshotted",
                         (int64_t)s->msg_stats.nodes_snapshotted);
        json_push_kv_int(obj, "message_send_calls",
                         (int64_t)s->msg_stats.send_calls);
        json_push_kv_int(obj, "message_process_calls",
                         (int64_t)s->msg_stats.process_calls);
        json_push_kv_int(obj, "message_recv_ready",
                         (int64_t)s->msg_stats.recv_ready);
        json_push_kv_int(obj, "message_idle_waits",
                         (int64_t)s->msg_stats.idle_waits);
        json_push_kv_int(obj, "message_wakes",
                         (int64_t)s->msg_stats.wakes);
        json_push_kv_int(obj, "last_assign_peer_id",
                         (int64_t)diag->last_assign_peer_id);
        json_push_kv_int(obj, "last_assign_max_requested",
                         (int64_t)diag->last_assign_max_requested);
        json_push_kv_int(obj, "last_assign_available",
                         (int64_t)diag->last_assign_available);
        json_push_kv_int(obj, "last_assign_assigned",
                         (int64_t)diag->last_assign_assigned);
        json_push_kv_int(obj, "last_assign_queue_len",
                         (int64_t)diag->last_assign_queue_len);
        json_push_kv_int(obj, "last_assign_active",
                         (int64_t)diag->last_assign_active);
        json_push_kv_int(obj, "last_assign_peer_in_flight",
                         (int64_t)diag->last_assign_peer_in_flight);
        json_push_kv_int(obj, "last_assign_peer_limit",
                         (int64_t)diag->last_assign_peer_limit);
        json_push_kv_int(obj, "last_assign_global_limit",
                         (int64_t)diag->last_assign_global_limit);
        json_push_kv_str(obj, "last_assign_result",
                         dl_assign_result_name(diag->last_assign_result));
    }

    json_push_kv_int(obj, "bytes_downloaded", (int64_t)s->bytes_downloaded);
    char mbps_str[32];
    snprintf(mbps_str, sizeof(mbps_str), "%.1f", s->mbps_avg);
    json_push_kv_str(obj, "mbps_avg", mbps_str);
    char gb_str[32];
    snprintf(gb_str, sizeof(gb_str), "%.2f",
             (double)s->bytes_downloaded / (1024.0 * 1024.0 * 1024.0));
    json_push_kv_str(obj, "gb_downloaded", gb_str);
}
