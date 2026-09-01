/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Compact AI/operator first-call telemetry. This path must stay cheap even
 * while the full healthcheck path is doing repair-era evidence work. */
#include "event_agent_summary.h"
#include "event_agent_summary_internal.h"
#include "api_controller_internal.h"
#include "base/text_fit.h"
#include "controllers/agent_height_contract.h"
#include "controllers/agent_controller.h"
#include "controllers/agent_first_call.h"
#include "controllers/agent_operator_contracts.h"
#include "controllers/agent_restart_watchdog.h"
#include "controllers/agent_resources.h"
#include "controllers/agent_security_posture.h"
#include "controllers/network_controller.h"
#include "controllers/operator_needed_policy.h"
#include "controllers/strong_params.h"
#include "controllers/sync_controller.h"
#include "services/operator_peer_snapshot_service.h"
#include "event_agent_readiness.h"
#include "event/event.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "json/json.h"
#include "models/database.h"
#include "net/connman.h"
#include "net/download.h"
#include "net/msgprocessor.h"
#include "net/onion_service.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/block_source_policy.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/node_health_service.h"
#include "services/invariant_sentinel.h"
#include "services/gap_fill_service.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "util/alerts.h"
#include "util/clientversion.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AGENT_CATCHUP_STALL_SECS 120
#define AGENT_DISPATCH_IDLE_SECS 30
#define AGENT_OPTIONAL_DETAIL_BUDGET_MS 175

struct agent_fast_budget {
    int64_t started_us;
    bool partial_result;
    char partial_reason[96];
};

static int agent_fast_served_height(bool *published_out, bool *known_out)
{
    bool published = reducer_frontier_provable_tip_is_published();
    int32_t served = reducer_frontier_provable_tip_cached();
    if (published_out)
        *published_out = published;
    if (known_out)
        *known_out = published && served >= 0 && served <= INT_MAX;
    if (served < 0 || served > INT_MAX)
        return 0;
    return (int)served;
}

#ifdef ZCL_TESTING
static int64_t agent_fast_test_elapsed_offset_ms(void)
{
    const char *env = getenv("ZCL_AGENT_TEST_ELAPSED_OFFSET_MS");
    if (!env || !env[0])
        return 0;
    char *end = NULL;
    long long value = strtoll(env, &end, 10);
    if (end == env || value <= 0)
        return 0;
    if (value > 60000)
        return 60000;
    return (int64_t)value;
}
#else
static int64_t agent_fast_test_elapsed_offset_ms(void)
{
    return 0;
}
#endif

static int64_t agent_fast_effective_elapsed_ms(int64_t started_us)
{
    int64_t elapsed = agent_first_call_elapsed_ms(started_us);
    int64_t test_offset = agent_fast_test_elapsed_offset_ms();
    if (test_offset > INT64_MAX - elapsed)
        return INT64_MAX;
    return elapsed + test_offset;
}

static bool agent_fast_optional_detail_allowed(
    struct agent_fast_budget *budget,
    const char *component)
{
    if (!budget || budget->started_us <= 0)
        return true;
    if (agent_fast_effective_elapsed_ms(budget->started_us) <
        AGENT_OPTIONAL_DETAIL_BUDGET_MS)
        return true;

    if (!budget->partial_result) {
        budget->partial_result = true;
        snprintf(budget->partial_reason, sizeof(budget->partial_reason),
                 "optional_detail_budget_guard:%s",
                 component && component[0] ? component : "unknown");
    }
    return false;
}

static void agent_fast_add_warning(struct agent_fast_snapshot *s,
                                   const char *reason)
{
    if (!s || !reason || !reason[0])
        return;
    if (strstr(s->warning_reasons, reason))
        return;
    /* Same contract as health_add_warning in node_health_service.c: the count
     * is every warning observed, the list is as many as fit, and a cut list
     * says so in-band instead of ending in half a warning name. */
    (void)zcl_text_fit_append(s->warning_reasons, sizeof(s->warning_reasons),
                              ",", reason, "agent",
                              "agent_fast_snapshot.warning_reasons");
    s->warning_count++;
}

/* POINT 3.4: a TRANSIENT/DEPENDENCY blocker never becomes the hard headline
 * (api_blocker_hard_gates_public_serving is PERMANENT/RESOURCE-only, by
 * design — that boundary is untouched here) — but that also means a
 * stuck/overdue transient can sit for hours while the headline reads
 * "healthy". This is a read-only classifier over the existing blocker
 * snapshot fields (class, age_us, escape_deadline_us/deadline_remaining_us,
 * escalated); it does not touch platform/modules/util/src/blocker.c or its lifecycle
 * sweep. A blocker counts as overdue when any of:
 *   - the supervisor sweep already flagged it `escalated` (deadline re-arm
 *     budget exhausted, see blocker_supervisor_sweep);
 *   - it has an explicit escape_deadline_us that has elapsed
 *     (deadline_remaining_us < 0);
 *   - it has no deadline but has lived past the default TRANSIENT TTL
 *     (BLOCKER_DEFAULT_TRANSIENT_TTL_SECS) — DEPENDENCY blockers are never
 *     TTL-swept by design, so age is the only overdue signal for those. */
static bool agent_blocker_is_overdue_transient(
    const struct blocker_snapshot *b)
{
    if (!b)
        return false;
    if (b->class != BLOCKER_TRANSIENT && b->class != BLOCKER_DEPENDENCY)
        return false;
    if (b->escalated)
        return true;
    if (b->escape_deadline_us > 0 && b->deadline_remaining_us < 0)
        return true;
    return b->age_us >
           (int64_t)BLOCKER_DEFAULT_TRANSIENT_TTL_SECS * 1000000;
}

static bool agent_mirror_same_height_hash_gap(
    const struct legacy_mirror_sync_stats *mirror)
{
    return mirror && mirror->enabled && mirror->reachable &&
           mirror->lag_known && mirror->local_height >= 0 &&
           mirror->legacy_height >= 0 &&
           mirror->local_height == mirror->legacy_height &&
           !mirror->tip_hashes_agree;
}

static int agent_fast_tip_finalize_log_head(void)
{
    uint64_t live = tip_finalize_stage_cursor();
    if (live > 0 && live <= INT_MAX)
        return (int)live;
    return -1; // raw-return-ok:sentinel
}

static void agent_fast_collect_errors(struct agent_fast_snapshot *s)
{
    if (!s)
        return;
    s->last_error_age_seconds = -1;
    struct error_ring *er = error_ring_global();
    const struct error_entry *last_err = error_ring_last(er);
    if (!last_err || !last_err->message[0])
        return;

    int64_t now_us = (int64_t)platform_time_wall_time_t() * 1000000;
    if (last_err->timestamp_us > 0 && now_us >= last_err->timestamp_us)
        s->last_error_age_seconds =
            (now_us - last_err->timestamp_us) / 1000000;
    snprintf(s->last_error_type, sizeof(s->last_error_type),
             "%s", event_type_name(last_err->type));
    if (s->last_error_age_seconds >= 0 &&
        s->last_error_age_seconds <= 300)
        agent_fast_add_warning(s, "recent_error");
}

static void agent_fast_collect_indexer(struct agent_fast_snapshot *s)
{
    if (!s)
        return;

    struct bsp_decision decision;
    memset(&decision, 0, sizeof(decision));
    if (block_source_policy_get_cached_status(&decision)) {
        int projection_basis = s->target_height;
        if (s->served_height > projection_basis)
            projection_basis = s->served_height;
        if (s->tip_height > projection_basis)
            projection_basis = s->tip_height;
        if (decision.local_height > projection_basis)
            projection_basis = decision.local_height;
        if (decision.target_height > projection_basis)
            projection_basis = decision.target_height;

        bool cache_consistent = true;
        if (projection_basis > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
            decision.projection_height >= 0 &&
            decision.projection_lag <= 0 &&
            decision.projection_height + ZCL_NODE_HEALTH_LAG_WARN_BLOCKS <
                projection_basis) {
            cache_consistent = false;
        }
        if (projection_basis > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
            decision.projection_height == 0 &&
            decision.projection_lag == 0 &&
            !decision.projection_state[0]) {
            cache_consistent = false;
        }

        if (!cache_consistent) {
            snprintf(s->projection_state, sizeof(s->projection_state),
                     "cached_status_inconsistent");
            agent_fast_add_warning(s, "block_source_status_stale");
        } else {
            s->block_source_status_cached = true;
            if (decision.projection_height >= 0) {
                s->projection_height = decision.projection_height;
                s->indexed_height = decision.projection_height;
                s->indexed_height_known = true;
            }
            s->projection_lag = decision.projection_lag;
            s->projection_deferred = decision.projection_deferred;
            s->projection_deferred_total =
                decision.projection_deferred_total;
            s->last_projection_deferred_height =
                decision.last_projection_deferred_height;
            s->last_projection_deferred_time =
                decision.last_projection_deferred_time;
            snprintf(s->projection_state, sizeof(s->projection_state),
                     "%s", decision.projection_state);
            snprintf(s->last_projection_deferred_reason,
                     sizeof(s->last_projection_deferred_reason),
                     "%s", decision.last_projection_deferred_reason);
            if (s->projection_lag > 1)
                agent_fast_add_warning(s, "projection_lag");
        }
    } else {
        snprintf(s->projection_state, sizeof(s->projection_state),
                 "cached_status_unavailable");
        agent_fast_add_warning(s, "block_source_status_busy");
    }

    struct node_db_sync_job_status jobs = {0};
    node_db_sync_get_job_status(&jobs);
    s->projection_catchup_active = jobs.catchup_active;
    s->projection_catchup_height = jobs.catchup_height;
    s->projection_catchup_target_height = jobs.catchup_target_height;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (jobs.catchup_started_at > 0 && now >= jobs.catchup_started_at)
        s->projection_catchup_uptime_seconds =
            now - jobs.catchup_started_at;
    if (jobs.catchup_last_progress_at > 0 &&
        now >= jobs.catchup_last_progress_at)
        s->projection_catchup_progress_age_seconds =
            now - jobs.catchup_last_progress_at;
}

static void agent_fast_collect(struct agent_fast_snapshot *s,
                               struct agent_fast_budget *budget)
{
    struct agent_fast_snapshot empty = {0};
    if (!s)
        return;
    *s = empty;
    s->tip_height = -1;
    s->indexed_height = -1;
    s->header_height = -1;
    s->peer_best_height = -1;
    s->projection_height = -1;
    s->projection_lag = -1;
    s->projection_catchup_height = -1;
    s->projection_catchup_target_height = -1;
    s->last_projection_deferred_height = -1;
    s->projection_catchup_progress_age_seconds = -1;
    s->projection_catchup_uptime_seconds = -1;
    s->log_head = -1;
    s->log_head_gap = -1;
    s->last_error_age_seconds = -1;
    s->oldest_in_flight_age_seconds = -1;
    s->oldest_in_flight_height = -1;
    s->peer_snapshot_age_seconds = -1;
    s->validation_pack_ok = true;
    s->operator_needed_since_unix = 0;
    legacy_mirror_sync_stats_cached_snapshot(&s->mirror);
    {
        struct blocker_snapshot blockers[BLOCKER_CAP];
        int blocker_count = blocker_snapshot_all(blockers, BLOCKER_CAP);
        const struct blocker_snapshot *dominant =
            blocker_select_dominant(blockers, blocker_count);
        s->active_blocker_count = blocker_count;
        if (dominant) {
            snprintf(s->dominant_blocker_id,
                     sizeof(s->dominant_blocker_id), "%s", dominant->id);
            snprintf(s->dominant_blocker_class,
                     sizeof(s->dominant_blocker_class), "%s",
                     blocker_class_name((enum blocker_class)dominant->class));
            s->hard_typed_blocker =
                api_blocker_hard_gates_public_serving(dominant);
            if (!s->hard_typed_blocker)
                agent_fast_add_warning(s, dominant->id);
        }
        const struct blocker_snapshot *overdue_dominant = NULL;
        for (int i = 0; i < blocker_count; i++) {
            if (!agent_blocker_is_overdue_transient(&blockers[i]))
                continue;
            s->overdue_transient_count++;
            if (!overdue_dominant ||
                blockers[i].age_us > overdue_dominant->age_us)
                overdue_dominant = &blockers[i];
        }
        if (overdue_dominant)
            snprintf(s->overdue_transient_dominant_id,
                     sizeof(s->overdue_transient_dominant_id), "%s",
                     overdue_dominant->id);
    }
    struct condition_engine_summary condition_summary;
    condition_engine_get_summary(&condition_summary);
    s->active_condition_count = condition_summary.active_count;
    s->unresolved_condition_count = condition_summary.unresolved_count;
    s->unresolved_critical_condition_count =
        condition_summary.unresolved_critical_count;
    if (agent_fast_optional_detail_allowed(budget, "resources")) {
        agent_resource_snapshot_collect(&s->resources);
        s->resources_collected = true;
        if (s->resources.rss_warning)
            agent_fast_add_warning(s, "high_memory_usage");
    }

    s->sync_state = sync_get_state();
    s->served_height = agent_fast_served_height(
        &s->provable_tip_published, &s->served_height_known);
    if (!s->provable_tip_published)
        agent_fast_add_warning(s, "provable_tip_unpublished");

    struct main_state *ms = sync_monitor_main_state();
    if (ms) {
        /* This legacy summary is already called beneath cs_main in some
         * paths. Read the lock-protected cache directly so observation can
         * never recurse through the authority resolver and ABBA deadlock. */
        struct block_index *tip = active_chain_cached_tip(&ms->chain_active);
        if (tip) {
            s->tip_height = tip->nHeight;
            s->tip_height_known = true;
        }
        if (ms->pindex_best_header) {
            s->header_height = ms->pindex_best_header->nHeight;
            s->header_height_known = true;
        }
    }
    if (!s->tip_height_known && s->served_height_known) {
        s->tip_height = s->served_height;
        s->tip_height_known = true;
    }
    s->indexed_height = s->tip_height;
    s->indexed_height_known = s->tip_height_known;
    if (!s->header_height_known && s->tip_height_known) {
        s->header_height = s->tip_height;
        s->header_height_known = true;
    }
    s->chain_evidence_consistent =
        s->served_height_known && s->tip_height_known &&
        s->header_height_known &&
        s->served_height <= s->tip_height &&
        s->tip_height <= s->header_height;
    snprintf(s->projection_state, sizeof(s->projection_state), "unknown");

    {
        struct agent_peer_snapshot peers;
        agent_peer_snapshot_collect(&peers, rpc_net_get_connman());
        s->peer_count = peers.peer_count;
        s->peer_inbound_count = peers.inbound_count;
        s->peer_outbound_count = peers.outbound_count;
        s->peer_ready_count = peers.ready_count;
        s->has_peers = peers.available && !peers.stale &&
            peers.direction_known && peers.ready_known &&
            peers.ready_count > 0;
        s->peer_best_height = peers.peer_best_height;
        s->peer_best_height_known = peers.peer_best_height_known;
        s->peer_direction_known = peers.direction_known;
        s->peer_ready_known = peers.ready_known;
        s->magicbean_peer_count = peers.magicbean_peer_count;
        s->zclassic_c23_peer_count = peers.zclassic_c23_peer_count;
        s->peer_snapshot_available = peers.available;
        s->peer_snapshot_stale = peers.stale;
        s->peer_snapshot_age_seconds = peers.age_seconds;
        if (peers.warning_reason)
            agent_fast_add_warning(s, peers.warning_reason);
    }

    s->log_head = agent_fast_tip_finalize_log_head();
    if (s->peer_best_height >= 0 && s->log_head >= 0)
        s->log_head_gap = s->peer_best_height - s->log_head;

    struct download_manager *dm = msg_get_download_mgr();
    if (dm) {
        struct dl_diagnostics diag;
        dl_get_stats(dm, &s->blocks_requested, &s->blocks_received,
                     &s->blocks_timed_out, &s->in_flight, &s->queued);
        dl_get_diagnostics(dm, &diag);
        s->request_timeout_seconds = diag.request_timeout_seconds;
        s->oldest_in_flight_age_seconds = diag.oldest_in_flight_age_seconds;
        s->oldest_in_flight_height = diag.oldest_in_flight_height;
        s->oldest_in_flight_peer_id = diag.oldest_in_flight_peer_id;
        s->overdue_in_flight = diag.overdue_in_flight;
        s->in_flight_peer_count = diag.in_flight_peer_count;
        s->queue_peer_avoid_count = diag.queue_peer_avoid_count;
        s->queue_peer_avoid_max_seconds = diag.queue_peer_avoid_max_seconds;
        s->assign_attempts = diag.assign_attempts;
        s->assign_successes = diag.assign_successes;
        s->assign_zero_results = diag.assign_zero_results;
        s->last_assign_peer_id = diag.last_assign_peer_id;
        s->last_assign_max_requested = diag.last_assign_max_requested;
        s->last_assign_available = diag.last_assign_available;
        s->last_assign_assigned = diag.last_assign_assigned;
        s->last_assign_queue_len = diag.last_assign_queue_len;
        s->last_assign_active = diag.last_assign_active;
        s->last_assign_peer_in_flight = diag.last_assign_peer_in_flight;
        s->last_assign_peer_limit = diag.last_assign_peer_limit;
        s->last_assign_global_limit = diag.last_assign_global_limit;
        s->last_assign_result = diag.last_assign_result;
        dl_get_throughput(dm, &s->download_bytes_received,
                          &s->download_mbps_avg);
    }
    {
        struct gap_fill_stats gf_stats;
        gap_fill_get_stats(&gf_stats);
        s->dispatch_wakes = gf_stats.dispatch_wakes;
    }
    {
        struct connman_message_cycle_stats msg_stats;
        connman_get_message_cycle_stats(rpc_net_get_connman(), &msg_stats);
        s->message_cycles = msg_stats.cycles;
        s->message_nodes_snapshotted = msg_stats.nodes_snapshotted;
        s->message_send_calls = msg_stats.send_calls;
        s->message_process_calls = msg_stats.process_calls;
        s->message_recv_ready = msg_stats.recv_ready;
        s->message_idle_waits = msg_stats.idle_waits;
        s->message_wakes = msg_stats.wakes;
    }
    {
        struct msg_block_intake_stats intake;
        msg_processor_get_block_intake_stats(rpc_net_get_msg_processor(),
                                             &intake);
        s->block_intake_running = intake.running;
        s->block_intake_stopping = intake.stopping;
        s->block_intake_current_depth = intake.current_depth;
        s->block_intake_capacity = intake.capacity;
        s->block_intake_max_depth = intake.max_depth;
        s->block_intake_enqueued = intake.enqueued;
        s->block_intake_processed = intake.processed;
        s->block_intake_accepted = intake.accepted;
        s->block_intake_retryable = intake.retryable;
        s->block_intake_rejected = intake.rejected;
        s->block_intake_dropped = intake.dropped;
        s->block_intake_clone_failed = intake.clone_failed;
        s->block_intake_spawn_failed = intake.spawn_failed;
        if (intake.running && !intake.stopping && intake.capacity > 0 &&
            intake.current_depth >= intake.capacity)
            agent_fast_add_warning(s, "block_intake_saturated");
        if (intake.clone_failed > 0 || intake.spawn_failed > 0)
            agent_fast_add_warning(s, "block_intake_fault");
    }

    s->tip_advance_age_seconds = sync_monitor_tip_advance_age();
    agent_fast_collect_errors(s);
    s->validation_pack_ok =
        invariant_sentinel_healthy(s->validation_pack_detail,
                                   (int)sizeof(s->validation_pack_detail));
    if (!s->validation_pack_ok)
        agent_fast_add_warning(s, s->validation_pack_detail[0]
                                  ? s->validation_pack_detail
                                  : "validation_pack");
    /* Only local frontiers are authoritative. Peer starting heights remain
     * an explicitly advisory availability hint. */
    s->target_height = s->tip_height > s->served_height
        ? s->tip_height : s->served_height;
    if (s->header_height > s->target_height)
        s->target_height = s->header_height;
    s->target_height_known = s->served_height_known ||
        s->tip_height_known || s->header_height_known;
    agent_fast_collect_indexer(s);
    s->gap = s->chain_evidence_consistent &&
        s->target_height > s->served_height
        ? s->target_height - s->served_height : 0;
    if (!s->chain_evidence_consistent) {
        s->index_gap = 0;
        agent_fast_add_warning(s, "chain_evidence_inconsistent");
    } else if (s->target_height > s->indexed_height) {
        s->index_gap = s->target_height - s->indexed_height;
    } else {
        s->index_gap = 0;
    }
    s->serving = s->served_height_known && s->served_height > 0;
    if (s->tip_advance_age_seconds > 600 &&
        s->sync_state != SYNC_AT_TIP)
        agent_fast_add_warning(s, "tip_advance_stale");

    /* Observation is pure. Latch recovery belongs to supervised health
     * transition work; an RPC read must never clear operator evidence. */
    s->operator_latch_recovered = false;
    s->operator_needed =
        alerts_operator_needed(s->operator_needed_detail,
                               sizeof(s->operator_needed_detail),
                               &s->operator_needed_since_unix);
    s->operator_latch_suppressed_by_mirror =
        agent_operator_latch_suppressed_by_mirror(
            s->operator_needed, s->operator_needed_detail, &s->mirror);
    if (s->operator_latch_suppressed_by_mirror)
        agent_fast_add_warning(s, "operator_latch_suppressed_by_mirror");
    s->operator_action_required =
        s->hard_typed_blocker ||
        (s->operator_needed && !s->operator_latch_suppressed_by_mirror) ||
        s->unresolved_critical_condition_count > 0;

    s->catchup_active = s->in_flight > 0 || s->queued > 0;
    s->catchup_stalled =
        s->gap > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS && s->catchup_active &&
        s->tip_advance_age_seconds >= AGENT_CATCHUP_STALL_SECS;
    s->download_dispatch_idle =
        s->gap > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS && s->queued > 0 && s->in_flight == 0;
    s->download_dispatch_stalled =
        s->download_dispatch_idle &&
        s->tip_advance_age_seconds >= AGENT_DISPATCH_IDLE_SECS;
    if (s->catchup_stalled) {
        s->catchup_stall_seconds = s->tip_advance_age_seconds;
        agent_fast_add_warning(s, "catchup_stalled");
    }
    if (s->download_dispatch_idle) {
        s->download_dispatch_idle_seconds =
            s->tip_advance_age_seconds >= 0 ? s->tip_advance_age_seconds : 0;
        agent_fast_add_warning(s, "download_dispatch_idle");
    }
    if (s->overdue_in_flight > 0)
        agent_fast_add_warning(s, "download_timeouts_overdue");

    bool mirror_same_height_hash_gap =
        agent_mirror_same_height_hash_gap(&s->mirror);
    if (mirror_same_height_hash_gap)
        agent_fast_add_warning(
            s, "mirror_same_height_hash_unavailable_or_mismatch");

    s->healthy = s->serving && s->has_peers &&
                 s->chain_evidence_consistent &&
                 !mirror_same_height_hash_gap &&
                 !s->operator_action_required &&
                 s->gap <= ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
                 s->index_gap <= ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
                 (s->log_head_gap < 0 || s->log_head_gap <= 1);

    if (s->hard_typed_blocker) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason), "%s",
                 s->dominant_blocker_id[0]
                     ? s->dominant_blocker_id : "typed_blocker_operator_needed");
    } else if (s->operator_action_required) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason),
                 "operator_needed:%s",
                 s->operator_needed_detail[0]
                     ? s->operator_needed_detail : "unspecified");
    } else if (mirror_same_height_hash_gap) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason),
                 "mirror_same_height_hash_unavailable_or_mismatch");
    } else if (!s->has_peers) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason),
                 "no_peers");
    } else if (s->catchup_stalled) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason),
                 "catchup_stalled");
    } else if (s->download_dispatch_stalled) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason),
                 "download_dispatch_idle");
    } else if (s->gap > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS &&
               s->in_flight == 0 && s->queued == 0) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason),
                 "download_queue_idle");
    } else if (s->log_head < 0) {
        snprintf(s->blocking_reason, sizeof(s->blocking_reason),
                 "log_head_unknown");
    }

    s->tor_enabled = tor_integration_is_enabled();
    s->tor_ready = tor_integration_is_ready();
    s->onion_service_ready = onion_service_get_address() != NULL;
}

bool rpc_agent_summary(const struct json_value *params, bool help,
                       struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "agent\n"
        "\nReturn the compact first-check node summary used by REST "
        "/api/v1/agent and the native agent command.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.public_status.v3\", \"status\":\"healthy\", "
        "\"build_commit\":\"...\", \"height\":N, \"gap\":0, "
        "\"primary_blocker\":\"none\" }\n");
    int64_t first_call_started_us = agent_first_call_start_us();
    struct agent_fast_budget first_call_budget = {
        .started_us = first_call_started_us, .partial_result = false,
        .partial_reason = {0},
    };
    struct agent_fast_snapshot health;
    agent_fast_collect(&health, &first_call_budget);
    /* posture is the ONLY DB-touching input to this otherwise in-memory summary;
     * the bounded front below (agent_summary_posture_cache.c) routes around a
     * busy/contended connection and reports whether it served from cache. */
    struct agent_security_posture posture;
    agent_summary_posture_collect_bounded(&posture);
    const char *db_maint_op = NULL;
    int64_t db_maint_elapsed_ms = 0;
    bool db_busy = node_db_long_op_active(&db_maint_op, &db_maint_elapsed_ms);
    bool material_gap = health.gap > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS;
    bool material_index_gap = health.index_gap > ZCL_NODE_HEALTH_LAG_WARN_BLOCKS;

    const char *primary = "none", *next = "none";
    /* This chain only picks WHICH reason applies, from what the bounded
     * agent_fast_snapshot can observe (four signals more than the public REST
     * status endpoint sees). status/summary/operator_needed all come back from
     * the one policy table (controllers/operator_needed_policy.def) so the two
     * surfaces cannot answer "does an operator need to act" differently. */
    enum node_status_reason reason = ZCL_STATUS_REASON_NONE;

    if (health.hard_typed_blocker) {
        reason = ZCL_STATUS_REASON_TYPED_BLOCKER;
        primary = health.dominant_blocker_id[0]
            ? health.dominant_blocker_id : "typed_blocker_operator_needed";
        next = "z23 dumpstate blocker";
    } else if (posture.review_required) {
        reason = ZCL_STATUS_REASON_POSTURE_REVIEW;
        primary = posture.status;
        next = posture.next_action;
    } else if (health.operator_action_required) {
        reason = ZCL_STATUS_REASON_HEALTH_BLOCKER;
        primary = health.blocking_reason[0] ? health.blocking_reason
                                            : "operator_needed";
        next = "z23 healthcheck";
    } else if (!health.peer_snapshot_available) {
        reason = ZCL_STATUS_REASON_PEER_SNAPSHOT_BUSY;
        primary = "peer_snapshot_unavailable";
        next = "z23 getpeerinfo";
    } else if (!health.has_peers) {
        reason = ZCL_STATUS_REASON_NO_PEERS;
        primary = "no_peers";
        next = "z23 getpeerinfo";
    } else if (material_gap && health.catchup_stalled) {
        reason = ZCL_STATUS_REASON_CATCHUP_STALLED;
        primary = "catchup_stalled";
        next = "z23 getsyncdiag";
    } else if (material_gap && health.download_dispatch_stalled) {
        reason = ZCL_STATUS_REASON_DOWNLOAD_DISPATCH_IDLE;
        primary = "download_dispatch_idle";
        next = "z23 getsyncdiag";
    } else if (material_gap &&
               (health.in_flight > 0 || health.queued > 0)) {
        reason = ZCL_STATUS_REASON_CHAIN_GAP_DOWNLOADING;
        primary = "chain_gap";
        next = "z23 downloadstats";
    } else if (material_gap) {
        reason = ZCL_STATUS_REASON_DOWNLOAD_QUEUE_IDLE;
        primary = "download_queue_idle";
        next = "z23 getsyncdiag";
    } else if (material_index_gap) {
        reason = ZCL_STATUS_REASON_PROJECTION_LAG;
        primary = "projection_lag";
        next = "z23 dumpstate chain_advance_coordinator";
    } else if (!health.healthy) {
        reason = ZCL_STATUS_REASON_HEALTHCHECK_UNHEALTHY;
        primary = health.blocking_reason[0] ? health.blocking_reason
                                            : "healthcheck_unhealthy";
        next = "z23 healthcheck";
    }
    const char *status = node_status_reason_status(reason);
    const char *summary = node_status_reason_summary(reason);
    bool operator_needed = node_status_reason_operator_needed(
        reason, (int64_t)health.warning_count);
    bool public_serving = health.serving && !operator_needed &&
        agent_security_posture_allows_public_serving(&posture);

    json_set_object(result);
    json_push_kv_str(result, "schema", ZCL_PUBLIC_STATUS_SCHEMA);
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "result_completeness", "bounded");
    /* Never serve stale posture silently: when the DB was busy and the
     * DB-derived slice came from the in-memory snapshot, say so and carry its
     * age. A live collection is source="live". */
    if (posture.served_from_cache) {
        json_push_kv_str(result, "source", "snapshot");
        json_push_kv_int(result, "age_ms", posture.cache_age_ms);
    } else {
        json_push_kv_str(result, "source", "live");
    }
    /* A long-running node.db maintenance op is a named status fact, not a
     * silent hang, sourced from the db_long_op progress registry. */
    if (db_busy) {
        struct json_value maint;
        json_init(&maint);
        json_set_object(&maint);
        json_push_kv_str(&maint, "op", db_maint_op ? db_maint_op : "long_op");
        json_push_kv_int(&maint, "elapsed_ms", db_maint_elapsed_ms);
        json_push_kv(result, "db_maintenance", &maint);
        json_free(&maint);
    }
    json_push_kv_bool(result, "partial_result",
                      first_call_budget.partial_result);
    if (first_call_budget.partial_result) {
        json_push_kv_str(result, "partial_reason",
                         first_call_budget.partial_reason);
        json_push_kv_str(result, "deferred_components",
                         "resources,restart_watchdog");
    }
    agent_push_first_call_simple_json(
        result, "first_call", "agent", "cached_fast_fields",
        ZCL_AGENT_FIRST_CALL_BUDGET_AGENT_MS, first_call_started_us,
        first_call_budget.partial_result, first_call_budget.partial_reason,
        first_call_budget.partial_result ? "z23 healthcheck" : "");
    json_push_kv_str(result, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    agent_push_runtime_build_json(result, "runtime_build");
    json_push_kv_str(result, "status", status);
    json_push_kv_bool(result, "healthy", strcmp(status, "healthy") == 0);
    json_push_kv_bool(result, "serving", public_serving);
    json_push_kv_bool(result, "operator_needed", operator_needed);
    json_push_kv_str(result, "summary", summary);
    json_push_kv_str(result, "primary_blocker", primary);
    json_push_kv_str(result, "next", next);
    agent_push_operator_lane_fields_json(result);
    agent_push_operator_lane_json(result, "operator_lane");
    struct agent_operator_latch_contract_view latch_view = {
        .active = health.operator_needed,
        .operator_action_required = health.operator_action_required,
        .recovered_this_call = health.operator_latch_recovered,
        .suppressed_by_mirror_contract =
            health.operator_latch_suppressed_by_mirror,
        .since_unix = health.operator_needed_since_unix,
        .detail = health.operator_needed_detail,
    };
    agent_push_operator_latch_contract_json(result, &latch_view);
    struct agent_condition_summary_contract_view condition_view = {
        .active_count = health.active_condition_count,
        .unresolved_count = health.unresolved_condition_count,
        .unresolved_critical_count =
            health.unresolved_critical_condition_count,
    };
    agent_push_condition_summary_contract_json(result, &condition_view);
    /* Typed-blocker-registry summary derived from the SAME authority as
     * `z23 dumpstate blocker` (blocker_snapshot_all +
     * blocker_select_dominant). Exposing the registry head and count here lets
     * the compact status brief present it beside the condition-engine count so
     * the two operator surfaces can never name disjoint truths. `dominant_id`
     * is the registry head; the brief's `primary_blocker` may still be a
     * higher-priority posture gate, but the registry head is always visible. */
    {
        struct json_value breg = {0};
        json_set_object(&breg);
        json_push_kv_str(&breg, "schema", "zcl.blocker_registry_summary.v1");
        json_push_kv_int(&breg, "active_count", health.active_blocker_count);
        json_push_kv_str(&breg, "dominant_id",
                         health.dominant_blocker_id[0]
                             ? health.dominant_blocker_id : "none");
        json_push_kv_str(&breg, "dominant_class",
                         health.dominant_blocker_class[0]
                             ? health.dominant_blocker_class : "none");
        /* POINT 3.4: count of active TRANSIENT/DEPENDENCY blockers that are
         * overdue (escalated, past their escape deadline, or past the
         * default TTL — see agent_blocker_is_overdue_transient). These never
         * drive `primary_blocker` (that headline stays PERMANENT/RESOURCE-
         * only by design), so without this an overdue transient could sit
         * for hours behind a "healthy" headline. */
        json_push_kv_int(&breg, "overdue_transient_count",
                         health.overdue_transient_count);
        json_push_kv_str(&breg, "overdue_transient_dominant_id",
                         health.overdue_transient_dominant_id[0]
                             ? health.overdue_transient_dominant_id : "none");
        json_push_kv_str(&breg, "native_state_command",
                         "z23 dumpstate blocker");
        json_push_kv(result, "blocker_registry", &breg);
        json_free(&breg);
    }
    legacy_mirror_sync_push_status_contract_json(result, &health.mirror);
    agent_push_readiness_contract_json(
        result, "readiness", public_serving, health.has_peers, operator_needed,
        health.validation_pack_ok, health.gap, health.index_gap,
        health.log_head_gap, &posture);
    json_push_kv_int(result, "height", health.served_height);
    json_push_kv_int(result, "served_height", health.served_height);
    json_push_kv_bool(result, "served_height_known",
                      health.served_height_known);
    json_push_kv_int(result, "indexed_height", health.indexed_height);
    json_push_kv_bool(result, "indexed_height_known",
                      health.indexed_height_known);
    json_push_kv_int(result, "header_height", health.header_height);
    json_push_kv_bool(result, "header_height_known",
                      health.header_height_known);
    json_push_kv_int(result, "peer_best_height", health.peer_best_height);
    json_push_kv_bool(result, "peer_best_height_known",
                      health.peer_best_height_known);
    json_push_kv_int(result, "target_height", health.target_height);
    json_push_kv_bool(result, "target_height_known",
                      health.target_height_known);
    json_push_kv_str(result, "target_height_source",
                     health.target_height_known
                         ? "local_validated_header"
                         : "unavailable");
    json_push_kv_bool(result, "chain_evidence_consistent",
                      health.chain_evidence_consistent);
    json_push_kv_int(result, "gap", health.gap);
    json_push_kv_int(result, "index_gap", health.index_gap);
    json_push_kv_bool(result, "provable_tip_published",
                      health.provable_tip_published);
    agent_push_height_contract_fields_json(result, "height_contract",
        health.served_height, health.tip_height, health.header_height,
        health.peer_best_height, health.target_height, health.gap,
        health.log_head, health.log_head_gap);
    agent_push_security_posture_snapshot_json(result, "security_posture",
                                               &posture);
    agent_push_trust_tier_json(result, "trust_tier"); /* OPTIONAL, see .h */
    agent_summary_push_detail_json(
        result, &health, first_call_budget.partial_result);
    return true;
}
