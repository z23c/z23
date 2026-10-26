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

static bool operator_peer_snapshot_complete(
    const struct operator_capture *capture)
{
    return capture->peers.available && !capture->peers.stale &&
           capture->peers.direction_known && capture->peers.ready_known;
}

const struct blocker_snapshot *operator_snapshot_dominant_blocker(
    const struct operator_capture *capture)
{
    if (!capture)
        return NULL;
    return blocker_select_dominant(capture->blockers,
                                   capture->blocker_count);
}

enum operator_verdict_class {
    OPERATOR_VERDICT_NONE = 0,
    OPERATOR_VERDICT_HARD_BLOCKER,
    OPERATOR_VERDICT_LATCH,
    OPERATOR_VERDICT_CRITICAL,
    OPERATOR_VERDICT_SECURITY,
    OPERATOR_VERDICT_NOT_SERVING,
    OPERATOR_VERDICT_MIRROR_GAP,
    OPERATOR_VERDICT_TYPED_BLOCKER,
    OPERATOR_VERDICT_CONDITION,
    OPERATOR_VERDICT_NO_PEERS,
    OPERATOR_VERDICT_NO_READY,
    OPERATOR_VERDICT_CHAIN_VALUES,
    OPERATOR_VERDICT_CHAIN_CHURN,
    OPERATOR_VERDICT_CHAIN_BINDING,
    OPERATOR_VERDICT_FRONTIER_ORDER,
    OPERATOR_VERDICT_CHAIN_LINEAGE,
    OPERATOR_VERDICT_PEER_STATE,
    OPERATOR_VERDICT_DOWNLOAD,
    OPERATOR_VERDICT_GAP_ACTIVE,
    OPERATOR_VERDICT_GAP_IDLE,
    OPERATOR_VERDICT_SYNC,
    OPERATOR_VERDICT_INCOMPLETE,
    OPERATOR_VERDICT_HEALTHY
};

/* Text for each class, in the original branch order. A null string leaves
 * that verdict field unchanged. */
struct operator_verdict_row {
    enum operator_verdict_class kind;
    const char *status;
    const char *primary;
    const char *next_action;
    const char *next_command;
    const char *next_command2;
    bool healthy;
};

static const struct operator_verdict_row operator_verdict_rows[] = {
    {
        .kind = OPERATOR_VERDICT_HARD_BLOCKER,
        .status = "operator_needed",
        .primary = "typed_blocker_operator_needed",
        .next_action = "inspect authoritative typed blockers",
        .next_command = "z23 core sync blockers",
        .next_command2 = "z23 dumpstate blocker",
    },
    {
        .kind = OPERATOR_VERDICT_LATCH,
        .status = "operator_needed",
        .primary = "operator_needed",
        .next_action = "inspect active conditions and operator latch",
        .next_command = "z23 dumpstate condition_engine",
        .next_command2 = "z23 getnodelog",
    },
    {
        .kind = OPERATOR_VERDICT_CRITICAL,
        .status = "operator_needed",
        .primary = "critical_condition_unresolved",
        .next_action = "inspect exhausted critical self-heal conditions",
        .next_command = "z23 dumpstate condition_engine",
        .next_command2 = "z23 getnodelog",
    },
    {
        .kind = OPERATOR_VERDICT_SECURITY,
        .status = "operator_needed",
        .primary = "security_posture_review_required",
        .next_action = "inspect security posture before serving",
        .next_command = "z23 ops snapshot",
        .next_command2 = "z23 dumpstate health",
    },
    {
        .kind = OPERATOR_VERDICT_NOT_SERVING,
        .status = "blocked",
        .primary = "not_serving",
        .next_action = "restore a published provable frontier",
        .next_command = "z23 status",
    },
    {
        .kind = OPERATOR_VERDICT_MIRROR_GAP,
        .status = "degraded",
        .primary = "mirror_same_height_hash_unavailable_or_mismatch",
        .next_action =
            "obtain exact same-height hashes and resolve the disagreement",
        .next_command = "z23 core sync diagnose",
        .next_command2 = "z23 dumpstate reducer_frontier",
    },
    {
        .kind = OPERATOR_VERDICT_TYPED_BLOCKER,
        .status = "degraded",
        .primary = "typed_blocker_active",
        .next_action = "inspect authoritative typed blockers",
        .next_command = "z23 core sync blockers",
    },
    {
        .kind = OPERATOR_VERDICT_CONDITION,
        .status = "degraded",
        .primary = "condition_active",
        .next_action = "inspect active self-heal conditions",
        .next_command = "z23 dumpstate condition_engine",
    },
    {
        .kind = OPERATOR_VERDICT_NO_PEERS,
        .status = "blocked",
        .primary = "no_peers",
        .next_action = "connect or inspect peers",
        .next_command = "z23 core network peers list",
    },
    {
        .kind = OPERATOR_VERDICT_NO_READY,
        .status = "degraded",
        .primary = "no_ready_peers",
        .next_action = "restore at least one handshake-ready peer",
        .next_command = "z23 core network peers list",
    },
    {
        .kind = OPERATOR_VERDICT_CHAIN_VALUES,
        .status = "degraded",
        .primary = "chain_evidence_unavailable",
        .next_action = "restore served and validated-header evidence",
        .next_command = "z23 status",
    },
    {
        .kind = OPERATOR_VERDICT_CHAIN_CHURN,
        .status = "degraded",
        .primary = "chain_evidence_churn",
        .next_action = "retry after the frontier capture stabilizes",
    },
    {
        .kind = OPERATOR_VERDICT_CHAIN_BINDING,
        .status = "degraded",
        .primary = "chain_binding_unavailable",
        .next_action = "restore height/hash/work bindings",
        .next_command = "z23 status",
    },
    {
        .kind = OPERATOR_VERDICT_FRONTIER_ORDER,
        .status = "degraded",
        .primary = "chain_evidence_inconsistent",
        .next_action = "inspect served/indexed/header ordering",
        .next_command = "z23 core sync diagnose",
    },
    {
        .kind = OPERATOR_VERDICT_CHAIN_LINEAGE,
        .status = "degraded",
        .primary = "chain_lineage_unproven",
        .next_action = "inspect durable binding, ancestry, and chainwork",
        .next_command = "z23 ops snapshot",
    },
    {
        .kind = OPERATOR_VERDICT_PEER_STATE,
        .status = "degraded",
        .primary = "peer_state_unavailable",
        .next_action = "restore a coherent peer snapshot",
        .next_command = "z23 core network peers list",
    },
    {
        .kind = OPERATOR_VERDICT_DOWNLOAD,
        .status = "degraded",
        .primary = "download_state_unavailable",
        .next_action = "restore download-manager telemetry",
        .next_command = "z23 core sync diagnose",
    },
    {
        .kind = OPERATOR_VERDICT_GAP_ACTIVE,
        .status = "catching_up",
        .primary = "chain_gap",
        .next_action = "wait for validated progress and recheck",
        .next_command = "z23 core sync diagnose",
        .next_command2 = "z23 getnodelog",
    },
    {
        .kind = OPERATOR_VERDICT_GAP_IDLE,
        .status = "degraded",
        .primary = "download_queue_idle",
        .next_action = "inspect sync/download progress",
        .next_command = "z23 core sync diagnose",
        .next_command2 = "z23 getnodelog",
    },
    {
        .kind = OPERATOR_VERDICT_SYNC,
        .status = "degraded",
        .primary = "sync_not_at_tip",
        .next_action = "inspect the raw sync state",
        .next_command = "z23 core sync diagnose",
    },
    {
        .kind = OPERATOR_VERDICT_INCOMPLETE,
        .status = "degraded",
        .primary = "snapshot_incomplete",
    },
    {
        .kind = OPERATOR_VERDICT_HEALTHY,
        .status = "healthy",
        .primary = "none",
        .next_action = "none",
        .next_command = "",
        .healthy = true,
    },
};

static bool operator_snapshot_is_serving(const struct operator_capture *capture)
{
    return capture->chain.served.height_known &&
           capture->chain.served.height > 0 &&
           !capture->security_review_required;
}

static bool operator_snapshot_is_complete(
    const struct operator_capture *capture,
    bool chain_consistent,
    bool peer_complete)
{
    return capture->critical_frontier_stable &&
           operator_snapshot_chain_bindings_known(capture) &&
           chain_consistent && peer_complete &&
           capture->download_known && capture->sync_state_known &&
           !operator_mirror_same_height_hash_gap(capture) &&
           !capture->security_review_required;
}

static bool operator_snapshot_hard_blocker(
    const struct operator_capture *capture)
{
    return capture->blocker_class_count[BLOCKER_PERMANENT] > 0 ||
           capture->blocker_class_count[BLOCKER_RESOURCE] > 0;
}

static bool operator_snapshot_needs_operator(
    const struct operator_capture *capture,
    bool hard_typed_blocker)
{
    return capture->operator_latch_active || hard_typed_blocker ||
           capture->conditions.unresolved_critical_count > 0 ||
           capture->security_review_required;
}

static enum operator_verdict_class operator_snapshot_progress_class(
    const struct operator_capture *capture,
    const struct operator_verdict *verdict)
{
    if (verdict->gap > 0) {
        if (capture->download_in_flight > 0 ||
            capture->download_queued > 0)
            return OPERATOR_VERDICT_GAP_ACTIVE;
        return OPERATOR_VERDICT_GAP_IDLE;
    }
    if (!capture->sync_state_known || capture->sync_state != SYNC_AT_TIP)
        return OPERATOR_VERDICT_SYNC;
    if (!verdict->complete)
        return OPERATOR_VERDICT_INCOMPLETE;
    return OPERATOR_VERDICT_HEALTHY;
}

static enum operator_verdict_class operator_snapshot_evidence_class(
    const struct operator_capture *capture,
    const struct operator_verdict *verdict)
{
    if (!verdict->chain_values_known)
        return OPERATOR_VERDICT_CHAIN_VALUES;
    if (!capture->critical_frontier_stable)
        return OPERATOR_VERDICT_CHAIN_CHURN;
    if (!operator_snapshot_chain_bindings_known(capture))
        return OPERATOR_VERDICT_CHAIN_BINDING;
    if (!verdict->frontier_order_ok)
        return OPERATOR_VERDICT_FRONTIER_ORDER;
    if (!verdict->chain_consistent)
        return OPERATOR_VERDICT_CHAIN_LINEAGE;
    if (!capture->peers.available || capture->peers.stale ||
        !capture->peers.direction_known || !capture->peers.ready_known)
        return OPERATOR_VERDICT_PEER_STATE;
    if (!capture->download_known)
        return OPERATOR_VERDICT_DOWNLOAD;
    return operator_snapshot_progress_class(capture, verdict);
}

static enum operator_verdict_class operator_snapshot_service_class(
    const struct operator_capture *capture,
    const struct operator_verdict *verdict)
{
    if (!verdict->serving)
        return OPERATOR_VERDICT_NOT_SERVING;
    if (operator_mirror_same_height_hash_gap(capture))
        return OPERATOR_VERDICT_MIRROR_GAP;
    if (capture->blocker_count > 0)
        return OPERATOR_VERDICT_TYPED_BLOCKER;
    if (capture->conditions.active_count > 0 ||
        capture->conditions.unresolved_count > 0)
        return OPERATOR_VERDICT_CONDITION;
    if (capture->peers.available && capture->peers.peer_count == 0)
        return OPERATOR_VERDICT_NO_PEERS;
    if (capture->peers.available && capture->peers.ready_known &&
        capture->peers.ready_count == 0)
        return OPERATOR_VERDICT_NO_READY;
    return operator_snapshot_evidence_class(capture, verdict);
}

static enum operator_verdict_class operator_snapshot_needed_class(
    const struct operator_capture *capture,
    const struct operator_verdict *verdict,
    bool hard_typed_blocker)
{
    if (hard_typed_blocker)
        return OPERATOR_VERDICT_HARD_BLOCKER;
    if (capture->operator_latch_active)
        return OPERATOR_VERDICT_LATCH;
    if (capture->conditions.unresolved_critical_count > 0)
        return OPERATOR_VERDICT_CRITICAL;
    if (capture->security_review_required)
        return OPERATOR_VERDICT_SECURITY;
    return operator_snapshot_service_class(capture, verdict);
}

static const char *operator_snapshot_primary_override(
    enum operator_verdict_class kind,
    const struct operator_capture *capture,
    const struct blocker_snapshot *dominant)
{
    if (kind == OPERATOR_VERDICT_HARD_BLOCKER && dominant)
        return dominant->id;
    if (kind == OPERATOR_VERDICT_LATCH &&
        capture->operator_latch_detail[0])
        return capture->operator_latch_detail;
    if (kind == OPERATOR_VERDICT_SECURITY &&
        capture->security_posture_status[0])
        return capture->security_posture_status;
    if (kind == OPERATOR_VERDICT_TYPED_BLOCKER && dominant)
        return dominant->id;
    return NULL;
}

static void operator_snapshot_apply_class(
    struct operator_verdict *verdict,
    enum operator_verdict_class kind,
    const struct operator_capture *capture,
    const struct blocker_snapshot *dominant)
{
    const char *primary = operator_snapshot_primary_override(
        kind, capture, dominant);
    int row_count = (int)(sizeof operator_verdict_rows /
                          sizeof operator_verdict_rows[0]);
    for (int i = 0; i < row_count; i++) {
        const struct operator_verdict_row *row = &operator_verdict_rows[i];
        if (row->kind != kind)
            continue;
        verdict->status = row->status;
        verdict->primary = primary ? primary : row->primary;
        if (kind == OPERATOR_VERDICT_SECURITY &&
            capture->security_posture_next_action[0])
            verdict->next_action = capture->security_posture_next_action;
        else if (row->next_action)
            verdict->next_action = row->next_action;
        if (row->next_command)
            verdict->next_command = row->next_command;
        if (row->next_command2)
            verdict->next_command2 = row->next_command2;
        verdict->healthy = row->healthy;
        return;
    }
}

struct operator_verdict operator_snapshot_classify(
    const struct operator_capture *capture)
{
    struct operator_verdict verdict = {
        .status = "unknown",
        .primary = "unknown",
        .next_action = "inspect operator snapshot components",
        .next_command = "z23 ops snapshot",
    };
    if (!capture)
        return verdict;
    verdict.chain_values_known = operator_chain_values_known(capture);
    verdict.frontier_order_ok = operator_frontier_order_ok(capture);
    verdict.chain_consistent =
        chain_frontier_snapshot_consistent(&capture->chain);
    verdict.serving = operator_snapshot_is_serving(capture);
    verdict.gap_known = capture->critical_frontier_stable &&
                        verdict.chain_consistent;
    if (verdict.gap_known) {
        verdict.gap = capture->chain.header.height -
                      capture->chain.served.height;
        verdict.index_gap = capture->chain.header.height -
                            capture->chain.indexed.height;
    }
    bool peer_complete = operator_peer_snapshot_complete(capture);
    verdict.complete = operator_snapshot_is_complete(
        capture, verdict.chain_consistent, peer_complete);
    bool hard_typed_blocker = operator_snapshot_hard_blocker(capture);
    verdict.operator_needed = operator_snapshot_needs_operator(
        capture, hard_typed_blocker);
    const struct blocker_snapshot *dominant =
        operator_snapshot_dominant_blocker(capture);
    enum operator_verdict_class kind = operator_snapshot_needed_class(
        capture, &verdict, hard_typed_blocker);
    operator_snapshot_apply_class(&verdict, kind, capture, dominant);
    return verdict;
}
