/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:pure-policy-decision-predicates — the three public
// exports (block_source_policy_peer_floor_recovery_needed / _snapshot_offer_
// allowed / _local_header_refill_needed) are pure decision predicates: their
// bool return IS the policy answer (recover / allowed / proceed), a genuine
// yes/no, never a success/failure. Callers consume them as `if (recover)` /
// `bool proceed = ...` / test ASSERTs. The one fallible surface here —
// persisting the decision to node.db — already returns struct zcl_result
// (bsp_record_decision / bsp_persist_decision). Matches the sibling
// block_source_policy.c "pure-policy" marker.

/* Decision seam for the block-source policy stateful runtime. The three
 * public decision predicates (peer-floor recovery, snapshot-offer,
 * local-header refill), plus the shared decision recorder and decision-event
 * emitter they drive. Runtime mutation, persistence, and status
 * serialization stay in sibling files. */

#include "block_source_policy_internal.h"

#include "platform/time_compat.h"
#include "event/event.h"
#include "util/log_macros.h"
#include "util/sync.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct zcl_result bsp_record_decision(const char *op,
                                      const struct bsp_decision *d)
{
    if (!d)
        return ZCL_ERR(-1, "bsp_record_decision: null decision op=%s",
                       op ? op : "unknown");
    struct node_db *ndb = NULL;
    int64_t when = (int64_t)platform_time_wall_time_t();
    int64_t total = 0;
    char op_copy[32];
    bsp_copy_text(op_copy, sizeof(op_copy), op ? op : "unknown");

    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    g_bsp.last = *d;
    g_bsp.has_last = true;
    g_bsp.last_decision_time = when;
    bsp_copy_text(g_bsp.last_op, sizeof(g_bsp.last_op), op_copy);
    g_bsp.decisions_total++;
    total = g_bsp.decisions_total;
    ndb = g_bsp.node_db;
    zcl_mutex_unlock(&g_bsp.lock);

    /* The decision is now authoritative in memory; the node.db mirror is
     * best-effort. Propagate (don't swallow) a disk-write failure. */
    return bsp_persist_decision(ndb, op_copy, d, when, total);
}

static void emit_decision_event(const char *op,
                                const char *action_key,
                                bool action_value,
                                const struct bsp_decision *d,
                                const char *extra_fmt,
                                ...)
{
    if (!d) return;
    (void)action_key;

    char extra[256] = {0};
    if (extra_fmt && *extra_fmt) {
        va_list ap;
        va_start(ap, extra_fmt);
        vsnprintf(extra, sizeof(extra), extra_fmt, ap);
        va_end(ap);
    }

    const struct bsp_source_status *s = NULL;
    if (d->selected_source > BSP_SOURCE_NONE &&
        d->selected_source < BSP_SOURCE_NUM)
        s = &d->sources[d->selected_source];
    const char *selection_blocker =
        s && s->selection_reason[0] ? s->selection_reason : "-";

    const char *source_name = bsp_source_name(d->selected_source);
    const char *trust_name = bsp_source_trust_name(d->selected_source);
    const char *decision_name = bsp_decision_result_name(d->result);

    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "op=%s ok=%s authority=local_consensus_validation "
                "source=%s trust=%s decision=%s score=%d "
                "reason=%s lh=%d th=%d sh=%d sel=%s sb=%s%s%s",
                op ? op : "unknown",
                action_value ? "true" : "false",
                source_name,
                trust_name,
                decision_name,
                d->selected_score,
                d->reason,
                d->local_height,
                d->target_height,
                s ? s->height : 0,
                s && s->selectable ? "true" : "false",
                selection_blocker,
                extra[0] ? " " : "",
                extra);
}

bool block_source_policy_peer_floor_recovery_needed(
    int healthy_outbound,
    int min_healthy,
    int local_height,
    int peer_height,
    struct bsp_decision *out)
{
    struct bsp_plan_input in;
    struct bsp_decision local_out;
    struct bsp_decision *decision = out ? out : &local_out;
    int target_height = peer_height > local_height ? peer_height
                                                   : local_height;

    memset(&in, 0, sizeof(in));
    in.local_height = local_height;
    in.best_header_height = local_height;
    in.target_height = target_height;

    struct bsp_source_status *p2p = &in.sources[BSP_SOURCE_P2P];
    p2p->source = BSP_SOURCE_P2P;
    p2p->available = healthy_outbound > 0;
    p2p->healthy = min_healthy > 0 && healthy_outbound >= min_healthy;
    p2p->height = peer_height;
    p2p->healthy_peers = healthy_outbound;
    p2p->progress_current = healthy_outbound;
    p2p->progress_total = min_healthy;
    bsp_copy_text(p2p->state, sizeof(p2p->state),
                  p2p->healthy ? "healthy" : "peer_floor");
    snprintf(p2p->reason, sizeof(p2p->reason),
             "healthy_outbound=%d min_healthy=%d",
             healthy_outbound, min_healthy);
    if (healthy_outbound < min_healthy) {
        snprintf(p2p->blocker, sizeof(p2p->blocker), "peer_floor");
    }

    block_source_policy_plan(&in, decision);
    struct zcl_result rec = bsp_record_decision("peer_floor", decision);
    if (!rec.ok)
        LOG_WARN("bsp", "record peer_floor decision: %s", rec.message);

    bool recover = healthy_outbound < min_healthy &&
                   decision->selected_source != BSP_SOURCE_P2P;
    const char *p2p_blocker =
        decision->sources[BSP_SOURCE_P2P].selection_reason[0] ?
        decision->sources[BSP_SOURCE_P2P].selection_reason : "-";
    emit_decision_event(
        "peer_floor", "recover", recover, decision,
        "healthy=%d min=%d local=%d peer=%d p2psb=%s",
        healthy_outbound, min_healthy, local_height, peer_height,
        p2p_blocker);
    return recover;
}

bool block_source_policy_snapshot_offer_allowed(
    int local_height,
    int snapshot_height,
    int peer_tip_height,
    bool offer_valid,
    const char *reason,
    struct bsp_decision *out)
{
    struct bsp_plan_input in;
    struct bsp_decision local_out;
    struct bsp_decision *decision = out ? out : &local_out;
    int target_height = peer_tip_height > snapshot_height ? peer_tip_height
                                                          : snapshot_height;

    memset(&in, 0, sizeof(in));
    in.local_height = local_height;
    in.best_header_height = local_height;
    in.target_height = target_height > local_height ? target_height
                                                    : local_height;

    struct bsp_source_status *snap = &in.sources[BSP_SOURCE_SNAPSHOT];
    snap->source = BSP_SOURCE_SNAPSHOT;
    snap->available = true;
    snap->healthy = offer_valid;
    snap->authorized = offer_valid;
    snap->blocked = !offer_valid;
    snap->height = snapshot_height;
    snap->progress_current = snapshot_height;
    snap->progress_total = peer_tip_height;
    bsp_copy_text(snap->state, sizeof(snap->state),
                  offer_valid ? "offer_valid" : "offer_rejected");
    snprintf(snap->reason, sizeof(snap->reason), "%s",
             reason && *reason ? reason : "snapshot_offer");
    if (!offer_valid) {
        snprintf(snap->blocker, sizeof(snap->blocker), "%s",
                 reason && *reason ? reason : "snapshot_offer_rejected");
    }

    block_source_policy_plan(&in, decision);
    struct zcl_result rec = bsp_record_decision("snapshot_offer", decision);
    if (!rec.ok)
        LOG_WARN("bsp", "record snapshot_offer decision: %s", rec.message);

    bool allowed = offer_valid &&
                   decision->selected_source == BSP_SOURCE_SNAPSHOT;
    emit_decision_event(
        "snapshot_offer", "allowed", allowed, decision,
        "local=%d snapshot=%d peer_tip=%d",
        local_height, snapshot_height, peer_tip_height);
    return allowed;
}

bool block_source_policy_local_header_refill_needed(
    int local_height,
    int missing_height,
    int peer_height,
    int eligible_peers,
    int retry_count,
    bool retries_exhausted,
    struct bsp_decision *out)
{
    struct bsp_plan_input in;
    struct bsp_decision local_out;
    struct bsp_decision *decision = out ? out : &local_out;
    int target_height = peer_height > missing_height ? peer_height
                                                     : missing_height;

    memset(&in, 0, sizeof(in));
    in.local_height = local_height;
    in.best_header_height = local_height;
    in.target_height = target_height > local_height ? target_height
                                                    : local_height;
    in.local_recovery_active = true;
    in.local_retries_exhausted = retries_exhausted;

    struct bsp_source_status *li = &in.sources[BSP_SOURCE_LOCAL_IMPORT];
    li->source = BSP_SOURCE_LOCAL_IMPORT;
    li->available = missing_height == local_height + 1;
    li->healthy = eligible_peers > 0;
    li->height = peer_height;
    li->progress_current = local_height;
    li->progress_total = missing_height;
    li->retry_count = retry_count;
    li->distinct_peer_count = eligible_peers;
    bsp_copy_text(li->state, sizeof(li->state),
                  li->healthy ? "refill_ready" : "waiting_for_peer");
    snprintf(li->reason, sizeof(li->reason),
             "missing_height=%d eligible_peers=%d retry=%d",
             missing_height, eligible_peers, retry_count);
    if (!li->available || !li->healthy) {
        snprintf(li->blocker, sizeof(li->blocker),
                 "local_header_refill_no_peer");
    }

    block_source_policy_plan(&in, decision);
    struct zcl_result rec =
        bsp_record_decision("local_header_refill", decision);
    if (!rec.ok)
        LOG_WARN("bsp", "record local_header_refill decision: %s",
                 rec.message);

    bool proceed = decision->result == BSP_DECISION_USE_SOURCE ||
                   decision->result == BSP_DECISION_RECOVER;
    emit_decision_event(
        "local_header_refill", "proceed", proceed, decision,
        "local=%d missing=%d peer=%d eligible=%d retry=%d",
        local_height, missing_height, peer_height, eligible_peers,
        retry_count);
    return proceed;
}
