/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Typed collection/classification for the target-owned operator snapshot.
 * Every subsystem is copied under its own leaf lock and all locks are released
 * before classification or JSON rendering. */

// one-result-type-ok:snapshot-encodes-component-availability — collection is
// total; unavailable evidence is preserved in typed known/stale fields.

#include "services/operator_snapshot_service.h"

#include "controllers/agent_security_posture.h"
#include "net/download.h"
#include "net/msgprocessor.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"

#include <stdio.h>
#include <stdatomic.h>
#include <string.h>

#define OPERATOR_CAPTURE_MAX_ATTEMPTS 2

static _Atomic uint64_t g_operator_snapshot_sequence;

static void operator_collect_components(struct operator_capture *capture)
{
    struct agent_security_posture posture;

    agent_peer_snapshot_collect(&capture->peers, sync_monitor_connman());

    struct download_manager *download = msg_get_download_mgr();
    capture->download_known = download != NULL;
    if (download) {
        dl_get_stats(download, &capture->download_requested,
                     &capture->download_received,
                     &capture->download_timed_out,
                     &capture->download_in_flight,
                     &capture->download_queued);
    }

    capture->sync_state = sync_get_state();
    capture->sync_state_known =
        capture->sync_state >= SYNC_IDLE &&
        capture->sync_state < SYNC_NUM_STATES;

    capture->blocker_count = blocker_snapshot_all_with_meta(
        capture->blockers, BLOCKER_CAP, &capture->blocker_generation,
        &capture->blocker_escape_dispatched,
        &capture->blocker_rate_limit_ms);
    memset(capture->blocker_class_count, 0,
           sizeof(capture->blocker_class_count));
    for (int i = 0; i < capture->blocker_count; i++) {
        int blocker_class = capture->blockers[i].class;
        if (blocker_class >= 0 && blocker_class < 4)
            capture->blocker_class_count[blocker_class]++;
    }

    condition_engine_get_summary(&capture->conditions);
    capture->operator_latch_active = alerts_operator_needed(
        capture->operator_latch_detail,
        sizeof(capture->operator_latch_detail),
        &capture->operator_latch_since_unix);
    agent_security_posture_collect(&posture, NULL);
    capture->security_review_required = posture.review_required;
    snprintf(capture->security_posture_status,
             sizeof(capture->security_posture_status), "%s", posture.status);
    snprintf(capture->security_posture_next_action,
             sizeof(capture->security_posture_next_action), "%s",
             posture.next_action);
    legacy_mirror_sync_stats_cached_snapshot(&capture->mirror);
}

void operator_snapshot_collect(struct operator_capture *capture)
{
    if (!capture)
        return;
    memset(capture, 0, sizeof(*capture));
    runtime_identity_get(&capture->identity);
    capture->sequence = atomic_fetch_add(&g_operator_snapshot_sequence, 1) + 1;
    capture->started_wall_us = platform_time_realtime_us();
    capture->started_mono_us = platform_time_monotonic_us();

    for (int attempt = 1; attempt <= OPERATOR_CAPTURE_MAX_ATTEMPTS; attempt++) {
        struct chain_frontier_snapshot before = {0};
        struct chain_frontier_snapshot after = {0};
        chain_frontier_snapshot_collect(&before, sync_monitor_main_state());
        operator_collect_components(capture);
        chain_frontier_snapshot_collect(&after, sync_monitor_main_state());
        capture->attempts = attempt;
        capture->chain = after;
        capture->critical_frontier_stable =
            chain_frontier_snapshot_equal(&before, &after);
        if (capture->critical_frontier_stable)
            break;
    }

    int64_t completed_mono_us = platform_time_monotonic_us();
    capture->duration_us = completed_mono_us >= capture->started_mono_us
        ? completed_mono_us - capture->started_mono_us : 0;
    /* Realtime can step backwards during NTP/manual correction.  Anchor the
     * externally comparable window once, then derive its end from monotonic
     * elapsed time so the producer never emits completed<started. */
    capture->completed_wall_us = capture->started_wall_us +
                                 capture->duration_us;
}

static bool operator_chain_values_known(const struct operator_capture *capture)
{
    return chain_frontier_snapshot_values_known(&capture->chain);
}

bool operator_snapshot_chain_bindings_known(
    const struct operator_capture *capture)
{
    return chain_frontier_snapshot_bindings_known(&capture->chain);
}

static bool operator_frontier_order_ok(const struct operator_capture *capture)
{
    return operator_chain_values_known(capture) &&
        capture->chain.served.height <= capture->chain.indexed.height &&
        capture->chain.indexed.height <= capture->chain.header.height;
}

static bool operator_mirror_same_height_hash_gap(
    const struct operator_capture *capture)
{
    const struct legacy_mirror_sync_stats *mirror =
        capture ? &capture->mirror : NULL;
    return mirror && mirror->enabled && mirror->reachable &&
           mirror->lag_known && mirror->local_height >= 0 &&
           mirror->legacy_height >= 0 &&
           mirror->local_height == mirror->legacy_height &&
           !mirror->tip_hashes_agree;
}

const struct blocker_snapshot *operator_snapshot_dominant_blocker(
    const struct operator_capture *capture)
{
    if (!capture)
        return NULL;
    return blocker_select_dominant(capture->blockers,
                                   capture->blocker_count);
}

struct operator_verdict operator_snapshot_classify(
    const struct operator_capture *capture)
{
    struct operator_verdict verdict = {
        .status = "unknown",
        .primary = "unknown",
        .next_action = "inspect operator snapshot components",
        .next_command = "z23 ops snapshot",
        .chain_values_known = operator_chain_values_known(capture),
        .frontier_order_ok = operator_frontier_order_ok(capture),
        .chain_consistent = chain_frontier_snapshot_consistent(&capture->chain),
    };
    verdict.serving = capture->chain.served.height_known &&
                      capture->chain.served.height > 0 &&
                      !capture->security_review_required;
    verdict.gap_known = capture->critical_frontier_stable &&
                        verdict.chain_consistent;
    if (verdict.gap_known) {
        verdict.gap = capture->chain.header.height -
                      capture->chain.served.height;
        verdict.index_gap = capture->chain.header.height -
                            capture->chain.indexed.height;
    }
    bool peer_complete = capture->peers.available && !capture->peers.stale &&
                         capture->peers.direction_known &&
                         capture->peers.ready_known;
    verdict.complete = capture->critical_frontier_stable &&
                       operator_snapshot_chain_bindings_known(capture) &&
                       verdict.chain_consistent && peer_complete &&
                       capture->download_known && capture->sync_state_known &&
                       !operator_mirror_same_height_hash_gap(capture) &&
                       !capture->security_review_required;
    bool hard_typed_blocker =
        capture->blocker_class_count[BLOCKER_PERMANENT] > 0 ||
        capture->blocker_class_count[BLOCKER_RESOURCE] > 0;
    verdict.operator_needed = capture->operator_latch_active ||
                              hard_typed_blocker ||
                              capture->conditions.unresolved_critical_count > 0 ||
                              capture->security_review_required;
    const struct blocker_snapshot *dominant =
        operator_snapshot_dominant_blocker(capture);

    if (hard_typed_blocker) {
        verdict.status = "operator_needed";
        verdict.primary = dominant ? dominant->id
                                   : "typed_blocker_operator_needed";
        verdict.next_action = "inspect authoritative typed blockers";
        verdict.next_command = "z23 core sync blockers";
        verdict.next_command2 = "z23 dumpstate blocker";
    } else if (capture->operator_latch_active) {
        verdict.status = "operator_needed";
        verdict.primary = capture->operator_latch_detail[0]
            ? capture->operator_latch_detail : "operator_needed";
        verdict.next_action = "inspect active conditions and operator latch";
        verdict.next_command = "z23 dumpstate condition_engine";
        verdict.next_command2 = "z23 getnodelog";
    } else if (capture->conditions.unresolved_critical_count > 0) {
        verdict.status = "operator_needed";
        verdict.primary = "critical_condition_unresolved";
        verdict.next_action = "inspect exhausted critical self-heal conditions";
        verdict.next_command = "z23 dumpstate condition_engine";
        verdict.next_command2 = "z23 getnodelog";
    } else if (capture->security_review_required) {
        verdict.status = "operator_needed";
        verdict.primary = capture->security_posture_status[0]
            ? capture->security_posture_status
            : "security_posture_review_required";
        verdict.next_action = capture->security_posture_next_action[0]
            ? capture->security_posture_next_action
            : "inspect security posture before serving";
        verdict.next_command = "z23 ops snapshot";
        verdict.next_command2 = "z23 dumpstate health";
    } else if (!verdict.serving) {
        verdict.status = "blocked";
        verdict.primary = "not_serving";
        verdict.next_action = "restore a published provable frontier";
        verdict.next_command = "z23 status";
    } else if (operator_mirror_same_height_hash_gap(capture)) {
        verdict.status = "degraded";
        verdict.primary =
            "mirror_same_height_hash_unavailable_or_mismatch";
        verdict.next_action =
            "obtain exact same-height hashes and resolve the disagreement";
        verdict.next_command = "z23 core sync diagnose";
        verdict.next_command2 = "z23 dumpstate reducer_frontier";
    } else if (capture->blocker_count > 0) {
        verdict.status = "degraded";
        verdict.primary = dominant ? dominant->id : "typed_blocker_active";
        verdict.next_action = "inspect authoritative typed blockers";
        verdict.next_command = "z23 core sync blockers";
    } else if (capture->conditions.active_count > 0 ||
               capture->conditions.unresolved_count > 0) {
        verdict.status = "degraded";
        verdict.primary = "condition_active";
        verdict.next_action = "inspect active self-heal conditions";
        verdict.next_command = "z23 dumpstate condition_engine";
    } else if (capture->peers.available && capture->peers.peer_count == 0) {
        verdict.status = "blocked";
        verdict.primary = "no_peers";
        verdict.next_action = "connect or inspect peers";
        verdict.next_command = "z23 core network peers list";
    } else if (capture->peers.available && capture->peers.ready_known &&
               capture->peers.ready_count == 0) {
        verdict.status = "degraded";
        verdict.primary = "no_ready_peers";
        verdict.next_action = "restore at least one handshake-ready peer";
        verdict.next_command = "z23 core network peers list";
    } else if (!verdict.chain_values_known) {
        verdict.status = "degraded";
        verdict.primary = "chain_evidence_unavailable";
        verdict.next_action = "restore served and validated-header evidence";
        verdict.next_command = "z23 status";
    } else if (!capture->critical_frontier_stable) {
        verdict.status = "degraded";
        verdict.primary = "chain_evidence_churn";
        verdict.next_action = "retry after the frontier capture stabilizes";
    } else if (!operator_snapshot_chain_bindings_known(capture)) {
        verdict.status = "degraded";
        verdict.primary = "chain_binding_unavailable";
        verdict.next_action = "restore height/hash/work bindings";
        verdict.next_command = "z23 status";
    } else if (!verdict.frontier_order_ok) {
        verdict.status = "degraded";
        verdict.primary = "chain_evidence_inconsistent";
        verdict.next_action = "inspect served/indexed/header ordering";
        verdict.next_command = "z23 core sync diagnose";
    } else if (!verdict.chain_consistent) {
        verdict.status = "degraded";
        verdict.primary = "chain_lineage_unproven";
        verdict.next_action = "inspect durable binding, ancestry, and chainwork";
        verdict.next_command = "z23 ops snapshot";
    } else if (!capture->peers.available || capture->peers.stale ||
               !capture->peers.direction_known ||
               !capture->peers.ready_known) {
        verdict.status = "degraded";
        verdict.primary = "peer_state_unavailable";
        verdict.next_action = "restore a coherent peer snapshot";
        verdict.next_command = "z23 core network peers list";
    } else if (!capture->download_known) {
        verdict.status = "degraded";
        verdict.primary = "download_state_unavailable";
        verdict.next_action = "restore download-manager telemetry";
        verdict.next_command = "z23 core sync diagnose";
    } else if (verdict.gap > 0) {
        bool active = capture->download_in_flight > 0 ||
                      capture->download_queued > 0;
        verdict.status = active ? "catching_up" : "degraded";
        verdict.primary = active ? "chain_gap" : "download_queue_idle";
        verdict.next_action = active
            ? "wait for validated progress and recheck"
            : "inspect sync/download progress";
        verdict.next_command = "z23 core sync diagnose";
        verdict.next_command2 = "z23 getnodelog";
    } else if (!capture->sync_state_known ||
               capture->sync_state != SYNC_AT_TIP) {
        verdict.status = "degraded";
        verdict.primary = "sync_not_at_tip";
        verdict.next_action = "inspect the raw sync state";
        verdict.next_command = "z23 core sync diagnose";
    } else if (!verdict.complete) {
        verdict.status = "degraded";
        verdict.primary = "snapshot_incomplete";
    } else {
        verdict.status = "healthy";
        verdict.primary = "none";
        verdict.next_action = "none";
        verdict.next_command = "";
        verdict.healthy = true;
    }
    return verdict;
}
