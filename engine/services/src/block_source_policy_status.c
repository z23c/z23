/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
// one-result-type-ok:bsp-status-pure-serializers
/* This seam owns no fallible service surface: pure JSON serializers
 * (bsp_source_to_json / bsp_decision_to_json), a name lookup
 * (bsp_source_class_name), a void status read (block_source_policy_get_status),
 * a nonblocking cached status read, and block_source_policy_dump_state_json —
 * whose bool return is the g_dumpers[] dispatch-table convention (a
 * serialize-into-out getter, not an error channel; see CLAUDE.md "Adding state
 * introspection"). No node.db writes, no failure path to carry. The fallible
 * persist/restore/record seam lives in the sibling files and returns struct
 * zcl_result. */

/* Status / introspection seam for the block-source policy stateful runtime.
 * The status read (block_source_policy_get_status), the per-source and
 * per-decision JSON serializers, and the native dump-state function
 * (block_source_policy_dump_state_json). Runtime mutation, persistence, and
 * decision recording stay in sibling files. */

#include "block_source_policy_internal.h"

#include "json/json.h"
#include "util/blocker.h"
#include "util/sync.h"

#include <string.h>

const char *bsp_source_class_name(enum bsp_source source)
{
    switch (source) {
        case BSP_SOURCE_NONE:             return "none";
        case BSP_SOURCE_P2P:              return "native_p2p";
        case BSP_SOURCE_SNAPSHOT:         return "snapshot";
        case BSP_SOURCE_LOCAL_IMPORT:     return "local_import";
        case BSP_SOURCE_ZCLASSICD_MIRROR: return "legacy_advisory";
        case BSP_SOURCE_NUM:              break;
    }
    return "unknown";
}

static bool bsp_source_lag_known(const struct bsp_source_status *s)
{
    if (!s)
        return false;
    if (s->source == BSP_SOURCE_ZCLASSICD_MIRROR)
        return s->lag_known;
    return true;
}

static bool bsp_source_lag_valid(const struct bsp_source_status *s)
{
    if (!s)
        return false;
    if (s->source == BSP_SOURCE_ZCLASSICD_MIRROR)
        return s->lag_valid;
    return true;
}

static void bsp_push_source_observed_lag(const struct bsp_source_status *s,
                                         struct json_value *out,
                                         const char *key)
{
    if (bsp_source_lag_known(s)) {
        json_push_kv_int(out, key, s ? s->lag : -1);
        return;
    }
    struct json_value nullv = {0};
    json_set_null(&nullv);
    json_push_kv(out, key, &nullv);
    json_free(&nullv);
}

void bsp_source_to_json(const struct bsp_source_status *s,
                        struct json_value *out)
{
    json_set_object(out);
    json_push_kv_str(out, "source", bsp_source_name(s->source));
    json_push_kv_str(out, "source_class", bsp_source_class_name(s->source));
    json_push_kv_str(out, "candidate_source", bsp_source_class_name(s->source));
    json_push_kv_str(out, "trust", bsp_source_trust_name(s->source));
    json_push_kv_str(out, "candidate_trust", bsp_source_trust_name(s->source));
    json_push_kv_bool(out, "available", s->available);
    json_push_kv_bool(out, "healthy", s->healthy);
    json_push_kv_bool(out, "blocked", s->blocked);
    json_push_kv_str(out, "blocked_class",
                     blocker_class_name(s->blocked_class));
    json_push_kv_bool(out, "authorized", s->authorized);
    json_push_kv_bool(out, "selectable", s->selectable);
    json_push_kv_str(out, "selection_blocker", s->selection_reason);
    json_push_kv_int(out, "height", (int64_t)s->height);
    json_push_kv_int(out, "score", (int64_t)s->score);
    json_push_kv_int(out, "score_base", s->score_base);
    json_push_kv_int(out, "score_health", s->score_health);
    json_push_kv_int(out, "score_height", s->score_height);
    json_push_kv_int(out, "score_authorized", s->score_authorized);
    json_push_kv_int(out, "score_redundancy_bonus",
                     s->score_redundancy_bonus);
    json_push_kv_int(out, "score_target_lag_penalty",
                     s->score_target_lag_penalty);
    json_push_kv_int(out, "score_failure_penalty",
                     s->score_failure_penalty);
    json_push_kv_int(out, "score_mirror_gate_penalty",
                     s->score_mirror_gate_penalty);
    json_push_kv_int(out, "failures", s->failures);
    json_push_kv_int(out, "timeouts", s->timeouts);
    json_push_kv_int(out, "outbound_total", s->outbound_total);
    json_push_kv_int(out, "inbound_total", s->inbound_total);
    json_push_kv_int(out, "healthy_peers", s->healthy_peers);
    json_push_kv_int(out, "inbound_healthy_peers",
                     s->inbound_healthy_peers);
    json_push_kv_int(out, "total_healthy_peers", s->total_healthy_peers);
    json_push_kv_int(out, "connecting_peers", s->connecting_peers);
    json_push_kv_int(out, "handshake_incomplete",
                     s->handshake_incomplete);
    json_push_kv_int(out, "inbound_handshake_incomplete",
                     s->inbound_handshake_incomplete);
    json_push_kv_int(out, "peer_groups", s->peer_groups);
    json_push_kv_int(out, "max_peer_group_size", s->max_peer_group_size);
    json_push_kv_int(out, "healthy_peer_groups", s->healthy_peer_groups);
    json_push_kv_int(out, "healthy_max_peer_group_size",
                     s->healthy_max_peer_group_size);
    json_push_kv_int(out, "addnode_count", s->addnode_count);
    json_push_kv_int(out, "addnode_backoff_active",
                     s->addnode_backoff_active);
    json_push_kv_int(out, "addnode_backoff_max_sec",
                     s->addnode_backoff_max_sec);
    json_push_kv_int(out, "addnode_tcp_failures",
                     s->addnode_tcp_failures);
    json_push_kv_int(out, "addnode_protocol_failures",
                     s->addnode_protocol_failures);
    json_push_kv_int(out, "progress_current", s->progress_current);
    json_push_kv_int(out, "progress_total", s->progress_total);
    bool lag_known = bsp_source_lag_known(s);
    bool lag_valid = bsp_source_lag_valid(s);
    json_push_kv_bool(out, "lag_known", lag_known);
    json_push_kv_bool(out, "lag_valid", lag_valid);
    json_push_kv_int(out, "lag", s->lag);
    bsp_push_source_observed_lag(s, out, "lag_observed");
    json_push_kv_bool(out, "candidate_lag_known", lag_known);
    json_push_kv_bool(out, "candidate_lag_valid", lag_valid);
    json_push_kv_int(out, "candidate_lag", s->lag);
    bsp_push_source_observed_lag(s, out, "candidate_lag_observed");
    json_push_kv_int(out, "retry_count", s->retry_count);
    json_push_kv_int(out, "distinct_peer_count", s->distinct_peer_count);
    json_push_kv_int(out, "serving_peer_id", s->serving_peer_id);
    json_push_kv_str(out, "state", s->state);
    json_push_kv_str(out, "reason", s->reason);
    json_push_kv_str(out, "blocker", s->blocker);
    json_push_kv_str(out, "candidate_blocker",
                     s->blocker[0] ? s->blocker : s->selection_reason);
}

void bsp_decision_to_json(const struct bsp_decision *d,
                          struct json_value *out)
{
    json_set_object(out);
    if (!d) return;
    json_push_kv_str(out, "decision",
                     bsp_decision_result_name(d->result));
    json_push_kv_str(out, "selected_source",
                     bsp_source_name(d->selected_source));
    json_push_kv_str(out, "candidate_source",
                     bsp_source_class_name(d->selected_source));
    json_push_kv_str(out, "selected_source_trust",
                     bsp_source_trust_name(d->selected_source));
    json_push_kv_str(out, "candidate_trust",
                     bsp_source_trust_name(d->selected_source));
    json_push_kv_str(out, "authority", "local_consensus_validation");
    json_push_kv_bool(out, "activation_allowed", d->activation_allowed);
    json_push_kv_bool(out, "mirror_fallback_allowed",
                      d->mirror_fallback_allowed);
    json_push_kv_int(out, "local_height", (int64_t)d->local_height);
    json_push_kv_int(out, "best_header_height",
                     (int64_t)d->best_header_height);
    json_push_kv_int(out, "target_height", (int64_t)d->target_height);
    json_push_kv_int(out, "projection_height",
                     (int64_t)d->projection_height);
    json_push_kv_int(out, "projection_lag", d->projection_lag);
    json_push_kv_bool(out, "projection_deferred",
                      d->projection_deferred);
    json_push_kv_str(out, "projection_state", d->projection_state);
    json_push_kv_int(out, "projection_deferred_total",
                     d->projection_deferred_total);
    json_push_kv_int(out, "last_projection_deferred_height",
                     d->last_projection_deferred_height);
    json_push_kv_int(out, "last_projection_deferred_time",
                     d->last_projection_deferred_time);
    json_push_kv_str(out, "last_projection_deferred_reason",
                     d->last_projection_deferred_reason);
    json_push_kv_int(out, "selected_score", (int64_t)d->selected_score);
    json_push_kv_str(out, "reason", d->reason);
    json_push_kv_str(out, "blocker", d->blocker);
    if (d->selected_source > BSP_SOURCE_NONE &&
        d->selected_source < BSP_SOURCE_NUM) {
        const struct bsp_source_status *s = &d->sources[d->selected_source];
        json_push_kv_str(out, "selected_source_state", s->state);
        json_push_kv_str(out, "selected_source_reason", s->reason);
        json_push_kv_str(out, "selected_source_blocker", s->blocker);
        json_push_kv_bool(out, "selected_source_selectable",
                          s->selectable);
        json_push_kv_str(out, "selected_source_selection_blocker",
                         s->selection_reason);
        json_push_kv_int(out, "selected_source_height", s->height);
        json_push_kv_int(out, "selected_source_score_base", s->score_base);
        json_push_kv_int(out, "selected_source_score_health",
                         s->score_health);
        json_push_kv_int(out, "selected_source_score_height",
                         s->score_height);
        json_push_kv_int(out, "selected_source_score_authorized",
                         s->score_authorized);
        json_push_kv_int(out, "selected_source_score_redundancy_bonus",
                         s->score_redundancy_bonus);
        json_push_kv_int(out, "selected_source_score_target_lag_penalty",
                         s->score_target_lag_penalty);
        json_push_kv_int(out, "selected_source_score_failure_penalty",
                         s->score_failure_penalty);
        json_push_kv_int(out, "selected_source_score_mirror_gate_penalty",
                         s->score_mirror_gate_penalty);
        json_push_kv_bool(out, "selected_source_healthy", s->healthy);
        json_push_kv_bool(out, "selected_source_available", s->available);
        json_push_kv_bool(out, "selected_source_blocked", s->blocked);
    }

    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 1; i < BSP_SOURCE_NUM; i++) {
        struct bsp_source_status source = d->sources[i];
        struct json_value child = {0};
        if (source.source == BSP_SOURCE_NONE)
            source.source = (enum bsp_source)i;
        bsp_source_to_json(&source, &child);
        json_push_back(&arr, &child);
        json_free(&child);
    }
    json_push_kv(out, "sources", &arr);
    json_free(&arr);
}

void block_source_policy_get_status(struct bsp_decision *out)
{
    if (!out) return;
    struct bsp_plan_input in;
    bsp_build_runtime_input(&in);
    block_source_policy_plan(&in, out);
    bsp_enrich_projection_deferral(out);
}

bool block_source_policy_get_cached_status(struct bsp_decision *out)
{
    if (!out)
        return false; // raw-return-ok:null-optional-cache-read
    memset(out, 0, sizeof(*out));

    bsp_lock_init_once();
    if (!zcl_mutex_trylock(&g_bsp.lock))
        return false; // raw-return-ok:busy-optional-cache-read

    bool ok = g_bsp.has_last;
    if (ok) {
        *out = g_bsp.last;
        out->projection_deferred_total = g_bsp.projection_deferred_total;
        out->last_projection_deferred_height =
            g_bsp.last_projection_deferred_height;
        out->last_projection_deferred_time =
            g_bsp.last_projection_deferred_time;
        bsp_copy_text(out->last_projection_deferred_reason,
                      sizeof(out->last_projection_deferred_reason),
                      g_bsp.last_projection_deferred_reason);
    }

    zcl_mutex_unlock(&g_bsp.lock);
    return ok;
}

bool block_source_policy_dump_state_json(struct json_value *out,
                                         const char *key)
{
    (void)key;
    if (!out) return false;
    struct bsp_decision d;
    block_source_policy_get_status(&d);

    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    int64_t decisions_total = g_bsp.decisions_total;
    bool has_last = g_bsp.has_last;
    int64_t last_decision_time = g_bsp.last_decision_time;
    char last_op[32];
    struct bsp_decision last = g_bsp.last;
    bool has_connman = g_bsp.connman != NULL;
    bool has_main_state = g_bsp.main_state != NULL;
    bool has_node_db = g_bsp.node_db != NULL;
    bsp_copy_text(last_op, sizeof(last_op), g_bsp.last_op);
    zcl_mutex_unlock(&g_bsp.lock);

    json_set_object(out);
    json_push_kv_bool(out, "initialized",
                      has_connman && has_main_state && has_node_db);
    json_push_kv_bool(out, "has_connman", has_connman);
    json_push_kv_bool(out, "has_main_state", has_main_state);
    json_push_kv_bool(out, "has_node_db", has_node_db);
    json_push_kv_str(out, "authority", "local_consensus_validation");
    json_push_kv_str(out, "decision",
                     bsp_decision_result_name(d.result));
    json_push_kv_str(out, "selected_source",
                     bsp_source_name(d.selected_source));
    json_push_kv_str(out, "candidate_source",
                     bsp_source_class_name(d.selected_source));
    json_push_kv_str(out, "selected_source_trust",
                     bsp_source_trust_name(d.selected_source));
    json_push_kv_str(out, "candidate_trust",
                     bsp_source_trust_name(d.selected_source));
    json_push_kv_bool(out, "activation_allowed", d.activation_allowed);
    json_push_kv_bool(out, "mirror_fallback_allowed",
                      d.mirror_fallback_allowed);
    json_push_kv_int(out, "local_height", (int64_t)d.local_height);
    json_push_kv_int(out, "best_header_height",
                     (int64_t)d.best_header_height);
    json_push_kv_int(out, "target_height", (int64_t)d.target_height);
    json_push_kv_int(out, "projection_height",
                     (int64_t)d.projection_height);
    json_push_kv_int(out, "projection_lag", d.projection_lag);
    json_push_kv_bool(out, "projection_deferred",
                      d.projection_deferred);
    json_push_kv_str(out, "projection_state", d.projection_state);
    json_push_kv_int(out, "projection_deferred_total",
                     d.projection_deferred_total);
    json_push_kv_int(out, "last_projection_deferred_height",
                     d.last_projection_deferred_height);
    json_push_kv_int(out, "last_projection_deferred_time",
                     d.last_projection_deferred_time);
    json_push_kv_str(out, "last_projection_deferred_reason",
                     d.last_projection_deferred_reason);
    json_push_kv_int(out, "selected_score", (int64_t)d.selected_score);
    json_push_kv_str(out, "reason", d.reason);
    json_push_kv_str(out, "blocker", d.blocker);
    json_push_kv_int(out, "decisions_total", decisions_total);
    json_push_kv_bool(out, "has_last_decision", has_last);
    if (has_last) {
        struct json_value last_json = {0};
        last.projection_deferred_total = d.projection_deferred_total;
        last.last_projection_deferred_height =
            d.last_projection_deferred_height;
        last.last_projection_deferred_time =
            d.last_projection_deferred_time;
        bsp_copy_text(last.last_projection_deferred_reason,
                      sizeof(last.last_projection_deferred_reason),
                      d.last_projection_deferred_reason);
        bsp_decision_to_json(&last, &last_json);
        json_push_kv_str(&last_json, "op", last_op);
        json_push_kv_int(&last_json, "time", last_decision_time);
        json_push_kv(out, "last_decision", &last_json);
        json_free(&last_json);
    }

    struct json_value arr = {0};
    json_set_array(&arr);
    for (int i = 1; i < BSP_SOURCE_NUM; i++) {
        struct json_value child = {0};
        bsp_source_to_json(&d.sources[i], &child);
        json_push_back(&arr, &child);
        json_free(&child);
    }
    json_push_kv(out, "sources", &arr);
    json_free(&arr);

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * engine/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed decision result above — BSP_DECISION_BLOCKED
     * means no advance source is currently usable; no new health logic. */
    {
        bool blocked = (d.result == BSP_DECISION_BLOCKED);
        diag_push_health(out, !blocked, blocked ? d.blocker : "");
    }
    return true;
}
