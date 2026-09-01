/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "event_agent_summary_internal.h"

#include "controllers/agent_resources.h"
#include "controllers/agent_restart_watchdog.h"
#include "json/json.h"
#include "net/download.h"

static void agent_summary_push_indexer_json(
    struct json_value *result,
    const struct agent_fast_snapshot *h)
{
    struct json_value indexer = {0};
    json_set_object(&indexer);
    json_push_kv_bool(&indexer, "block_source_status_cached",
                      h->block_source_status_cached);
    json_push_kv_int(&indexer, "height", h->indexed_height);
    json_push_kv_int(&indexer, "lag", h->projection_lag);
    json_push_kv_int(&indexer, "projection_height", h->projection_height);
    json_push_kv_int(&indexer, "projection_lag", h->projection_lag);
    json_push_kv_bool(&indexer, "projection_deferred",
                      h->projection_deferred);
    json_push_kv_str(&indexer, "projection_state", h->projection_state);
    json_push_kv_int(&indexer, "projection_deferred_total",
                     h->projection_deferred_total);
    json_push_kv_int(&indexer, "last_projection_deferred_height",
                     h->last_projection_deferred_height);
    json_push_kv_int(&indexer, "last_projection_deferred_time",
                     h->last_projection_deferred_time);
    json_push_kv_str(&indexer, "last_projection_deferred_reason",
                     h->last_projection_deferred_reason);
    json_push_kv_bool(&indexer, "catchup_active",
                      h->projection_catchup_active);
    json_push_kv_int(&indexer, "catchup_height",
                     h->projection_catchup_height);
    json_push_kv_int(&indexer, "catchup_target_height",
                     h->projection_catchup_target_height);
    json_push_kv_int(&indexer, "catchup_progress_age_seconds",
                     h->projection_catchup_progress_age_seconds);
    json_push_kv_int(&indexer, "catchup_uptime_seconds",
                     h->projection_catchup_uptime_seconds);
    json_push_kv(result, "indexer", &indexer);
    json_free(&indexer);
}

static void agent_summary_push_reducer_json(
    struct json_value *result,
    const struct agent_fast_snapshot *h)
{
    struct json_value reducer = {0};
    json_set_object(&reducer);
    json_push_kv_int(&reducer, "log_head", h->log_head);
    json_push_kv_int(&reducer, "log_head_gap", h->log_head_gap);
    json_push_kv_bool(&reducer, "provable_tip_published",
                      h->provable_tip_published);
    json_push_kv_int(&reducer, "tip_advance_age_seconds",
                     h->tip_advance_age_seconds);
    json_push_kv_bool(&reducer, "validation_pack_ok",
                      h->validation_pack_ok);
    json_push_kv_str(&reducer, "validation_pack_detail",
                     h->validation_pack_detail);
    json_push_kv(result, "reducer", &reducer);
    json_free(&reducer);
}

static void agent_summary_push_health_json(
    struct json_value *result,
    const struct agent_fast_snapshot *h)
{
    struct json_value health_obj = {0};
    json_set_object(&health_obj);
    json_push_kv_int(&health_obj, "warning_count",
                     (int64_t)h->warning_count);
    json_push_kv_str(&health_obj, "warning_reasons", h->warning_reasons);
    json_push_kv_int(&health_obj, "last_error_age_seconds",
                     h->last_error_age_seconds);
    json_push_kv_str(&health_obj, "last_error_type", h->last_error_type);
    json_push_kv_str(&health_obj, "blocking_reason", h->blocking_reason);
    json_push_kv_bool(&health_obj, "operator_latch_recovered",
                      h->operator_latch_recovered);
    json_push_kv_bool(&health_obj, "operator_latch_active",
                      h->operator_needed);
    json_push_kv_bool(&health_obj, "operator_action_required",
                      h->operator_action_required);
    json_push_kv_bool(&health_obj, "operator_latch_suppressed_by_mirror",
                      h->operator_latch_suppressed_by_mirror);
    json_push_kv_bool(&health_obj, "hard_typed_blocker",
                      h->hard_typed_blocker);
    json_push_kv_str(&health_obj, "dominant_typed_blocker",
                     h->dominant_blocker_id);
    json_push_kv_str(&health_obj, "operator_latch_detail",
                     h->operator_needed_detail);
    json_push_kv_int(&health_obj, "operator_latch_since_unix",
                     h->operator_needed_since_unix);
    json_push_kv_int(&health_obj, "active_condition_count",
                     h->active_condition_count);
    json_push_kv_int(&health_obj, "unresolved_condition_count",
                     h->unresolved_condition_count);
    json_push_kv_int(&health_obj, "unresolved_critical_condition_count",
                     h->unresolved_critical_condition_count);
    json_push_kv(result, "health", &health_obj);
    json_free(&health_obj);
}

static void agent_summary_push_peers_json(
    struct json_value *result,
    const struct agent_fast_snapshot *h)
{
    struct json_value peers = {0};
    json_set_object(&peers);
    json_push_kv_int(&peers, "total", (int64_t)h->peer_count);
    json_push_kv_bool(&peers, "direction_known", h->peer_direction_known);
    json_push_kv_bool(&peers, "ready_known", h->peer_ready_known);
    json_push_kv_int(&peers, "inbound", (int64_t)h->peer_inbound_count);
    json_push_kv_int(&peers, "outbound", (int64_t)h->peer_outbound_count);
    json_push_kv_int(&peers, "ready", (int64_t)h->peer_ready_count);
    json_push_kv_bool(&peers, "max_height_known",
                      h->peer_best_height_known);
    json_push_kv_int(&peers, "max_height", h->peer_best_height);
    json_push_kv_str(&peers, "max_height_trust",
                     "untrusted_peer_advertisement");
    json_push_kv_bool(&peers, "has_peers", h->has_peers);
    json_push_kv_bool(&peers, "snapshot_available",
                      h->peer_snapshot_available);
    json_push_kv_bool(&peers, "snapshot_stale", h->peer_snapshot_stale);
    json_push_kv_int(&peers, "snapshot_age_seconds",
                     h->peer_snapshot_age_seconds);
    json_push_kv_int(&peers, "magicbean",
                     (int64_t)h->magicbean_peer_count);
    json_push_kv_int(&peers, "zclassic23",
                     (int64_t)h->zclassic_c23_peer_count);
    json_push_kv(result, "peers", &peers);
    json_free(&peers);
}

static void agent_summary_push_download_intake_json(
    struct json_value *download,
    const struct agent_fast_snapshot *h)
{
    struct json_value intake = {0};
    json_set_object(&intake);
    json_push_kv_bool(&intake, "running", h->block_intake_running);
    json_push_kv_bool(&intake, "stopping", h->block_intake_stopping);
    json_push_kv_int(&intake, "current_depth",
                     (int64_t)h->block_intake_current_depth);
    json_push_kv_int(&intake, "capacity",
                     (int64_t)h->block_intake_capacity);
    json_push_kv_bool(&intake, "saturated",
                      h->block_intake_running && !h->block_intake_stopping &&
                      h->block_intake_capacity > 0 &&
                      h->block_intake_current_depth >=
                          h->block_intake_capacity);
    json_push_kv_int(&intake, "max_depth",
                     (int64_t)h->block_intake_max_depth);
    json_push_kv_int(&intake, "enqueued",
                     (int64_t)h->block_intake_enqueued);
    json_push_kv_int(&intake, "processed",
                     (int64_t)h->block_intake_processed);
    json_push_kv_int(&intake, "accepted",
                     (int64_t)h->block_intake_accepted);
    json_push_kv_int(&intake, "retryable",
                     (int64_t)h->block_intake_retryable);
    json_push_kv_int(&intake, "rejected",
                     (int64_t)h->block_intake_rejected);
    json_push_kv_int(&intake, "dropped",
                     (int64_t)h->block_intake_dropped);
    json_push_kv_int(&intake, "clone_failed",
                     (int64_t)h->block_intake_clone_failed);
    json_push_kv_int(&intake, "spawn_failed",
                     (int64_t)h->block_intake_spawn_failed);
    json_push_kv(download, "block_intake", &intake);
    json_free(&intake);
}

static void agent_summary_push_download_json(
    struct json_value *result,
    const struct agent_fast_snapshot *h)
{
    struct json_value download = {0};
    json_set_object(&download);
    json_push_kv_int(&download, "requested", (int64_t)h->blocks_requested);
    json_push_kv_int(&download, "received", (int64_t)h->blocks_received);
    json_push_kv_int(&download, "timed_out", (int64_t)h->blocks_timed_out);
    json_push_kv_int(&download, "in_flight", (int64_t)h->in_flight);
    json_push_kv_int(&download, "queued", (int64_t)h->queued);
    json_push_kv_bool(&download, "active", h->catchup_active);
    json_push_kv_bool(&download, "catchup_stalled", h->catchup_stalled);
    json_push_kv_int(&download, "catchup_stall_seconds",
                     h->catchup_stall_seconds);
    json_push_kv_bool(&download, "dispatch_idle",
                      h->download_dispatch_idle);
    json_push_kv_bool(&download, "dispatch_stalled",
                      h->download_dispatch_stalled);
    json_push_kv_int(&download, "dispatch_idle_seconds",
                     h->download_dispatch_idle_seconds);
    json_push_kv_int(&download, "request_timeout_seconds",
                     (int64_t)h->request_timeout_seconds);
    json_push_kv_int(&download, "oldest_in_flight_age_seconds",
                     h->oldest_in_flight_age_seconds);
    json_push_kv_int(&download, "oldest_in_flight_height",
                     h->oldest_in_flight_height);
    json_push_kv_int(&download, "oldest_in_flight_peer_id",
                     (int64_t)h->oldest_in_flight_peer_id);
    json_push_kv_int(&download, "overdue_in_flight",
                     (int64_t)h->overdue_in_flight);
    json_push_kv_int(&download, "in_flight_peer_count",
                     (int64_t)h->in_flight_peer_count);
    json_push_kv_int(&download, "queue_peer_avoid_count",
                     (int64_t)h->queue_peer_avoid_count);
    json_push_kv_int(&download, "queue_peer_avoid_max_seconds",
                     h->queue_peer_avoid_max_seconds);
    json_push_kv_int(&download, "assign_attempts",
                     (int64_t)h->assign_attempts);
    json_push_kv_int(&download, "assign_successes",
                     (int64_t)h->assign_successes);
    json_push_kv_int(&download, "assign_zero_results",
                     (int64_t)h->assign_zero_results);
    json_push_kv_int(&download, "dispatch_wakes",
                     (int64_t)h->dispatch_wakes);
    json_push_kv_int(&download, "message_cycles",
                     (int64_t)h->message_cycles);
    json_push_kv_int(&download, "message_nodes_snapshotted",
                     (int64_t)h->message_nodes_snapshotted);
    json_push_kv_int(&download, "message_send_calls",
                     (int64_t)h->message_send_calls);
    json_push_kv_int(&download, "message_process_calls",
                     (int64_t)h->message_process_calls);
    json_push_kv_int(&download, "message_recv_ready",
                     (int64_t)h->message_recv_ready);
    json_push_kv_int(&download, "message_idle_waits",
                     (int64_t)h->message_idle_waits);
    json_push_kv_int(&download, "message_wakes",
                     (int64_t)h->message_wakes);
    agent_summary_push_download_intake_json(&download, h);
    json_push_kv_int(&download, "last_assign_peer_id",
                     (int64_t)h->last_assign_peer_id);
    json_push_kv_int(&download, "last_assign_max_requested",
                     (int64_t)h->last_assign_max_requested);
    json_push_kv_int(&download, "last_assign_available",
                     (int64_t)h->last_assign_available);
    json_push_kv_int(&download, "last_assign_assigned",
                     (int64_t)h->last_assign_assigned);
    json_push_kv_int(&download, "last_assign_queue_len",
                     (int64_t)h->last_assign_queue_len);
    json_push_kv_int(&download, "last_assign_active",
                     (int64_t)h->last_assign_active);
    json_push_kv_int(&download, "last_assign_peer_in_flight",
                     (int64_t)h->last_assign_peer_in_flight);
    json_push_kv_int(&download, "last_assign_peer_limit",
                     (int64_t)h->last_assign_peer_limit);
    json_push_kv_int(&download, "last_assign_global_limit",
                     (int64_t)h->last_assign_global_limit);
    json_push_kv_str(&download, "last_assign_result",
                     dl_assign_result_name(h->last_assign_result));
    json_push_kv_int(&download, "bytes_received",
                     (int64_t)h->download_bytes_received);
    json_push_kv_real(&download, "mbps_avg", h->download_mbps_avg);
    json_push_kv(result, "download", &download);
    json_free(&download);
}

static void agent_summary_push_services_json(
    struct json_value *result,
    const struct agent_fast_snapshot *h)
{
    struct json_value services = {0};
    json_set_object(&services);
    json_push_kv_bool(&services, "tor_enabled", h->tor_enabled);
    json_push_kv_bool(&services, "tor_ready", h->tor_ready);
    json_push_kv_bool(&services, "onion_service_ready",
                      h->onion_service_ready);
    json_push_kv(result, "services", &services);
    json_free(&services);
}

void agent_summary_push_detail_json(struct json_value *result,
                                    const struct agent_fast_snapshot *health,
                                    bool partial_result)
{
    if (!result || !health)
        return;

    json_push_kv_str(result, "sync_state", sync_state_name(health->sync_state));
    if (!partial_result)
        agent_push_restart_watchdog_json(result, "restart_watchdog", NULL);
    agent_summary_push_indexer_json(result, health);
    agent_summary_push_reducer_json(result, health);
    agent_summary_push_health_json(result, health);
    if (health->resources_collected)
        agent_push_resources_json(result, "resources", &health->resources);
    agent_summary_push_peers_json(result, health);
    agent_summary_push_download_json(result, health);
    agent_summary_push_services_json(result, health);
}
