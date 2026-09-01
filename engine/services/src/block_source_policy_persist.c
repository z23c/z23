/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Persistence seam for the block-source policy stateful runtime.
 * node.db persist/restore of the last decision, per-source snapshots, and
 * the projection-deferral counter. Runtime mutation, decision recording, and
 * status serialization stay in sibling files. */

#include "block_source_policy_internal.h"

#include "models/database.h"
#include "util/sync.h"

#include <stdio.h>
#include <string.h>

#define BSP_STATE_PREFIX "chain_advance_coordinator."
#define BSP_KEY_LAST_OP BSP_STATE_PREFIX "last_op"
#define BSP_KEY_LAST_TIME BSP_STATE_PREFIX "last_time"
#define BSP_KEY_DECISIONS_TOTAL BSP_STATE_PREFIX "decisions_total"
#define BSP_KEY_RESULT BSP_STATE_PREFIX "last_result"
#define BSP_KEY_SOURCE BSP_STATE_PREFIX "last_source"
#define BSP_KEY_ACTIVATION_ALLOWED BSP_STATE_PREFIX "last_activation_allowed"
#define BSP_KEY_MIRROR_FALLBACK_ALLOWED BSP_STATE_PREFIX "last_mirror_fallback_allowed"
#define BSP_KEY_SELECTED_SCORE BSP_STATE_PREFIX "last_selected_score"
#define BSP_KEY_REASON BSP_STATE_PREFIX "last_reason"
#define BSP_KEY_BLOCKER BSP_STATE_PREFIX "last_blocker"
#define BSP_KEY_LOCAL_HEIGHT BSP_STATE_PREFIX "last_local_height"
#define BSP_KEY_BEST_HEADER_HEIGHT BSP_STATE_PREFIX "last_best_header_height"
#define BSP_KEY_TARGET_HEIGHT BSP_STATE_PREFIX "last_target_height"
#define BSP_KEY_PROJECTION_DEFERRED_TOTAL \
    BSP_STATE_PREFIX "projection_deferred_total"
#define BSP_KEY_LAST_PROJECTION_DEFERRED_HEIGHT \
    BSP_STATE_PREFIX "last_projection_deferred_height"
#define BSP_KEY_LAST_PROJECTION_DEFERRED_TIME \
    BSP_STATE_PREFIX "last_projection_deferred_time"
#define BSP_KEY_LAST_PROJECTION_DEFERRED_REASON \
    BSP_STATE_PREFIX "last_projection_deferred_reason"
#define BSP_KEY_SOURCE_STATE BSP_STATE_PREFIX "last_source_state"
#define BSP_KEY_SOURCE_REASON BSP_STATE_PREFIX "last_source_reason"
#define BSP_KEY_SOURCE_BLOCKER BSP_STATE_PREFIX "last_source_blocker"
#define BSP_KEY_SOURCE_HEIGHT BSP_STATE_PREFIX "last_source_height"
#define BSP_KEY_SOURCE_HEALTHY BSP_STATE_PREFIX "last_source_healthy"
#define BSP_KEY_SOURCE_AVAILABLE BSP_STATE_PREFIX "last_source_available"
#define BSP_KEY_SOURCE_BLOCKED BSP_STATE_PREFIX "last_source_blocked"
#define BSP_KEY_SOURCE_PREFIX BSP_STATE_PREFIX "last_source."

static struct zcl_result persist_text(struct node_db *ndb, const char *key,
                                      const char *val)
{
    if (!ndb || !key || !val)
        return ZCL_ERR(-1, "persist_text: null arg key=%s",
                       key ? key : "(null)");
    if (!node_db_state_set(ndb, key, val, strlen(val) + 1))
        return ZCL_ERR(-2, "persist_text: node_db_state_set failed key=%s",
                       key);
    return ZCL_OK;
}

static bool source_field_key(char *buf, size_t buflen,
                             enum bsp_source source,
                             const char *field)
{
    if (!buf || buflen == 0 || !field)
        return false;
    int n = snprintf(buf, buflen, "%s%d.%s", BSP_KEY_SOURCE_PREFIX,
                     (int)source, field);
    return n > 0 && (size_t)n < buflen;
}

static void persist_source_int(struct node_db *ndb,
                               enum bsp_source source,
                               const char *field,
                               int64_t value)
{
    char key[96];
    if (source_field_key(key, sizeof(key), source, field))
        (void)node_db_state_set_int(ndb, key, value);
}

static void restore_source_int(struct node_db *ndb,
                               enum bsp_source source,
                               const char *field,
                               int64_t *out)
{
    char key[96];
    int64_t v = 0;
    if (!out)
        return;
    *out = 0;
    if (source_field_key(key, sizeof(key), source, field) &&
        node_db_state_get_int(ndb, key, &v))
        *out = v;
}

static void persist_source_snapshot(struct node_db *ndb,
                                    enum bsp_source source,
                                    const struct bsp_source_status *s)
{
    if (!ndb || !s || source <= BSP_SOURCE_NONE || source >= BSP_SOURCE_NUM)
        return;
    char key[96];
    if (source_field_key(key, sizeof(key), source, "state"))
        (void)persist_text(ndb, key, s->state);
    if (source_field_key(key, sizeof(key), source, "selection_blocker"))
        (void)persist_text(ndb, key, s->selection_reason);
    if (source_field_key(key, sizeof(key), source, "reason"))
        (void)persist_text(ndb, key, s->reason);
    if (source_field_key(key, sizeof(key), source, "blocker"))
        (void)persist_text(ndb, key, s->blocker);
    persist_source_int(ndb, source, "height", (int64_t)s->height);
    persist_source_int(ndb, source, "score", (int64_t)s->score);
    persist_source_int(ndb, source, "score_base", s->score_base);
    persist_source_int(ndb, source, "score_health", s->score_health);
    persist_source_int(ndb, source, "score_height", s->score_height);
    persist_source_int(ndb, source, "score_authorized",
                       s->score_authorized);
    persist_source_int(ndb, source, "score_target_lag_penalty",
                       s->score_target_lag_penalty);
    persist_source_int(ndb, source, "score_failure_penalty",
                       s->score_failure_penalty);
    persist_source_int(ndb, source, "score_mirror_gate_penalty",
                       s->score_mirror_gate_penalty);
    persist_source_int(ndb, source, "healthy", s->healthy ? 1 : 0);
    persist_source_int(ndb, source, "available", s->available ? 1 : 0);
    persist_source_int(ndb, source, "blocked", s->blocked ? 1 : 0);
    persist_source_int(ndb, source, "blocked_class",
                       (int64_t)s->blocked_class);
    persist_source_int(ndb, source, "authorized", s->authorized ? 1 : 0);
    persist_source_int(ndb, source, "selectable", s->selectable ? 1 : 0);
    persist_source_int(ndb, source, "failures", s->failures);
    persist_source_int(ndb, source, "timeouts", s->timeouts);
    persist_source_int(ndb, source, "outbound_total", s->outbound_total);
    persist_source_int(ndb, source, "inbound_total", s->inbound_total);
    persist_source_int(ndb, source, "healthy_peers", s->healthy_peers);
    persist_source_int(ndb, source, "inbound_healthy_peers",
                       s->inbound_healthy_peers);
    persist_source_int(ndb, source, "total_healthy_peers",
                       s->total_healthy_peers);
    persist_source_int(ndb, source, "connecting_peers", s->connecting_peers);
    persist_source_int(ndb, source, "handshake_incomplete",
                       s->handshake_incomplete);
    persist_source_int(ndb, source, "inbound_handshake_incomplete",
                       s->inbound_handshake_incomplete);
    persist_source_int(ndb, source, "peer_groups", s->peer_groups);
    persist_source_int(ndb, source, "max_peer_group_size",
                       s->max_peer_group_size);
    persist_source_int(ndb, source, "healthy_peer_groups",
                       s->healthy_peer_groups);
    persist_source_int(ndb, source, "healthy_max_peer_group_size",
                       s->healthy_max_peer_group_size);
    persist_source_int(ndb, source, "addnode_count", s->addnode_count);
    persist_source_int(ndb, source, "addnode_backoff_active",
                       s->addnode_backoff_active);
    persist_source_int(ndb, source, "addnode_backoff_max_sec",
                       s->addnode_backoff_max_sec);
    persist_source_int(ndb, source, "addnode_tcp_failures",
                       s->addnode_tcp_failures);
    persist_source_int(ndb, source, "addnode_protocol_failures",
                       s->addnode_protocol_failures);
    persist_source_int(ndb, source, "progress_current",
                       s->progress_current);
    persist_source_int(ndb, source, "progress_total", s->progress_total);
    persist_source_int(ndb, source, "lag", s->lag);
    persist_source_int(ndb, source, "lag_known", s->lag_known ? 1 : 0);
    persist_source_int(ndb, source, "lag_valid", s->lag_valid ? 1 : 0);
    persist_source_int(ndb, source, "retry_count", s->retry_count);
    persist_source_int(ndb, source, "distinct_peer_count",
                       s->distinct_peer_count);
    persist_source_int(ndb, source, "serving_peer_id", s->serving_peer_id);
}

static void restore_source_snapshot(struct node_db *ndb,
                                    enum bsp_source source,
                                    struct bsp_source_status *s)
{
    if (!ndb || !s || source <= BSP_SOURCE_NONE || source >= BSP_SOURCE_NUM)
        return;
    char key[96];
    char text[384] = {0};
    size_t len = 0;
    int64_t v = 0;

    s->source = source;
    if (source_field_key(key, sizeof(key), source, "state") &&
        node_db_state_get(ndb, key, text, sizeof(text) - 1, &len))
        bsp_copy_text(s->state, sizeof(s->state), text);
    text[0] = '\0';
    if (source_field_key(key, sizeof(key), source, "selection_blocker") &&
        node_db_state_get(ndb, key, text, sizeof(text) - 1, &len))
        bsp_copy_text(s->selection_reason, sizeof(s->selection_reason), text);
    text[0] = '\0';
    if (source_field_key(key, sizeof(key), source, "reason") &&
        node_db_state_get(ndb, key, text, sizeof(text) - 1, &len))
        bsp_copy_text(s->reason, sizeof(s->reason), text);
    text[0] = '\0';
    if (source_field_key(key, sizeof(key), source, "blocker") &&
        node_db_state_get(ndb, key, text, sizeof(text) - 1, &len))
        bsp_copy_text(s->blocker, sizeof(s->blocker), text);
    restore_source_int(ndb, source, "height", &v); s->height = (int)v;
    restore_source_int(ndb, source, "score", &v); s->score = (int)v;
    restore_source_int(ndb, source, "score_base", &v);
    s->score_base = (int)v;
    restore_source_int(ndb, source, "score_health", &v);
    s->score_health = (int)v;
    restore_source_int(ndb, source, "score_height", &v);
    s->score_height = (int)v;
    restore_source_int(ndb, source, "score_authorized", &v);
    s->score_authorized = (int)v;
    restore_source_int(ndb, source, "score_target_lag_penalty", &v);
    s->score_target_lag_penalty = (int)v;
    restore_source_int(ndb, source, "score_failure_penalty", &v);
    s->score_failure_penalty = (int)v;
    restore_source_int(ndb, source, "score_mirror_gate_penalty", &v);
    s->score_mirror_gate_penalty = (int)v;
    restore_source_int(ndb, source, "healthy", &v); s->healthy = v != 0;
    restore_source_int(ndb, source, "available", &v); s->available = v != 0;
    restore_source_int(ndb, source, "blocked", &v); s->blocked = v != 0;
    restore_source_int(ndb, source, "blocked_class", &v);
    s->blocked_class = (v >= 0 && v <= BLOCKER_RESOURCE)
                            ? (enum blocker_class)v
                            : BLOCKER_TRANSIENT;
    restore_source_int(ndb, source, "authorized", &v);
    s->authorized = v != 0;
    restore_source_int(ndb, source, "selectable", &v);
    s->selectable = v != 0;
    restore_source_int(ndb, source, "failures", &s->failures);
    restore_source_int(ndb, source, "timeouts", &s->timeouts);
    restore_source_int(ndb, source, "outbound_total", &s->outbound_total);
    restore_source_int(ndb, source, "inbound_total", &s->inbound_total);
    restore_source_int(ndb, source, "healthy_peers", &s->healthy_peers);
    restore_source_int(ndb, source, "inbound_healthy_peers",
                       &s->inbound_healthy_peers);
    restore_source_int(ndb, source, "total_healthy_peers",
                       &s->total_healthy_peers);
    restore_source_int(ndb, source, "connecting_peers", &s->connecting_peers);
    restore_source_int(ndb, source, "handshake_incomplete",
                       &s->handshake_incomplete);
    restore_source_int(ndb, source, "inbound_handshake_incomplete",
                       &s->inbound_handshake_incomplete);
    restore_source_int(ndb, source, "peer_groups", &s->peer_groups);
    restore_source_int(ndb, source, "max_peer_group_size",
                       &s->max_peer_group_size);
    restore_source_int(ndb, source, "healthy_peer_groups",
                       &s->healthy_peer_groups);
    restore_source_int(ndb, source, "healthy_max_peer_group_size",
                       &s->healthy_max_peer_group_size);
    restore_source_int(ndb, source, "addnode_count", &s->addnode_count);
    restore_source_int(ndb, source, "addnode_backoff_active",
                       &s->addnode_backoff_active);
    restore_source_int(ndb, source, "addnode_backoff_max_sec",
                       &s->addnode_backoff_max_sec);
    restore_source_int(ndb, source, "addnode_tcp_failures",
                       &s->addnode_tcp_failures);
    restore_source_int(ndb, source, "addnode_protocol_failures",
                       &s->addnode_protocol_failures);
    restore_source_int(ndb, source, "progress_current",
                       &s->progress_current);
    restore_source_int(ndb, source, "progress_total", &s->progress_total);
    restore_source_int(ndb, source, "lag", &s->lag);
    restore_source_int(ndb, source, "lag_known", &v);
    s->lag_known = v != 0;
    restore_source_int(ndb, source, "lag_valid", &v);
    s->lag_valid = v != 0;
    restore_source_int(ndb, source, "retry_count", &s->retry_count);
    restore_source_int(ndb, source, "distinct_peer_count",
                       &s->distinct_peer_count);
    restore_source_int(ndb, source, "serving_peer_id", &s->serving_peer_id);
}

struct zcl_result bsp_persist_decision(struct node_db *ndb,
                                       const char *op,
                                       const struct bsp_decision *d,
                                       int64_t when,
                                       int64_t total)
{
    if (!ndb || !d)
        return ZCL_ERR(-1, "bsp_persist_decision: null %s",
                       !ndb ? "ndb" : "decision");

    /* Best-effort mirror of the in-memory decision to node.db. We attempt
     * every field; the first write failure becomes the returned result so
     * the caller can log it (the in-memory decision is authoritative and is
     * not rolled back on a disk-write miss). */
    bool ok = true;
    ok = persist_text(ndb, BSP_KEY_LAST_OP, op ? op : "unknown").ok && ok;
    ok = node_db_state_set_int(ndb, BSP_KEY_LAST_TIME, when) && ok;
    (void)node_db_state_set_int(ndb, BSP_KEY_DECISIONS_TOTAL, total);
    (void)node_db_state_set_int(ndb, BSP_KEY_RESULT, (int64_t)d->result);
    (void)node_db_state_set_int(ndb, BSP_KEY_SOURCE,
                                (int64_t)d->selected_source);
    (void)node_db_state_set_int(ndb, BSP_KEY_ACTIVATION_ALLOWED,
                                d->activation_allowed ? 1 : 0);
    (void)node_db_state_set_int(ndb, BSP_KEY_MIRROR_FALLBACK_ALLOWED,
                                d->mirror_fallback_allowed ? 1 : 0);
    (void)node_db_state_set_int(ndb, BSP_KEY_SELECTED_SCORE,
                                (int64_t)d->selected_score);
    (void)persist_text(ndb, BSP_KEY_REASON, d->reason);
    (void)persist_text(ndb, BSP_KEY_BLOCKER, d->blocker);
    (void)node_db_state_set_int(ndb, BSP_KEY_LOCAL_HEIGHT,
                                (int64_t)d->local_height);
    (void)node_db_state_set_int(ndb, BSP_KEY_BEST_HEADER_HEIGHT,
                                (int64_t)d->best_header_height);
    (void)node_db_state_set_int(ndb, BSP_KEY_TARGET_HEIGHT,
                                (int64_t)d->target_height);

    for (int i = 1; i < BSP_SOURCE_NUM; i++)
        persist_source_snapshot(ndb, (enum bsp_source)i, &d->sources[i]);

    if (d->selected_source > BSP_SOURCE_NONE &&
        d->selected_source < BSP_SOURCE_NUM) {
        const struct bsp_source_status *s = &d->sources[d->selected_source];
        (void)persist_text(ndb, BSP_KEY_SOURCE_STATE, s->state);
        (void)persist_text(ndb, BSP_KEY_SOURCE_REASON, s->reason);
        (void)persist_text(ndb, BSP_KEY_SOURCE_BLOCKER, s->blocker);
        (void)node_db_state_set_int(ndb, BSP_KEY_SOURCE_HEIGHT,
                                    (int64_t)s->height);
        (void)node_db_state_set_int(ndb, BSP_KEY_SOURCE_HEALTHY,
                                    s->healthy ? 1 : 0);
        (void)node_db_state_set_int(ndb, BSP_KEY_SOURCE_AVAILABLE,
                                    s->available ? 1 : 0);
        (void)node_db_state_set_int(ndb, BSP_KEY_SOURCE_BLOCKED,
                                    s->blocked ? 1 : 0);
    }

    if (!ok)
        return ZCL_ERR(-3,
                       "bsp_persist_decision: node.db mirror write failed "
                       "op=%s (decision kept in memory)",
                       op ? op : "unknown");
    return ZCL_OK;
}

struct zcl_result bsp_restore_decision(struct node_db *ndb)
{
    if (!ndb)
        return ZCL_ERR(-1, "bsp_restore_decision: null ndb");

    struct bsp_decision d;
    memset(&d, 0, sizeof(d));
    char op[32] = {0};
    char reason[sizeof(d.reason)] = {0};
    char blocker[sizeof(d.blocker)] = {0};
    char source_state[sizeof(d.sources[0].state)] = {0};
    char source_reason[sizeof(d.sources[0].reason)] = {0};
    char source_block_text[sizeof(d.sources[0].blocker)] = {0};
    size_t len = 0;
    int64_t v = 0;
    int64_t total = 0;
    int64_t when = 0;

    /* No persisted decision yet (cold start) is a successful no-op, not a
     * failure — there is simply nothing to restore. */
    if (!node_db_state_get(ndb, BSP_KEY_LAST_OP, op, sizeof(op) - 1, &len))
        return ZCL_OK;
    if (!node_db_state_get_int(ndb, BSP_KEY_RESULT, &v))
        return ZCL_OK;
    d.result = (enum bsp_decision_result)v;
    if (!node_db_state_get_int(ndb, BSP_KEY_SOURCE, &v))
        return ZCL_OK;
    d.selected_source = (enum bsp_source)v;
    if (node_db_state_get_int(ndb, BSP_KEY_ACTIVATION_ALLOWED, &v))
        d.activation_allowed = v != 0;
    if (node_db_state_get_int(ndb, BSP_KEY_MIRROR_FALLBACK_ALLOWED, &v))
        d.mirror_fallback_allowed = v != 0;
    if (node_db_state_get_int(ndb, BSP_KEY_SELECTED_SCORE, &v))
        d.selected_score = (int)v;
    if (node_db_state_get(ndb, BSP_KEY_REASON, reason,
                          sizeof(reason) - 1, &len))
        bsp_copy_text(d.reason, sizeof(d.reason), reason);
    if (node_db_state_get(ndb, BSP_KEY_BLOCKER, blocker,
                          sizeof(blocker) - 1, &len))
        bsp_copy_text(d.blocker, sizeof(d.blocker), blocker);
    if (node_db_state_get_int(ndb, BSP_KEY_LOCAL_HEIGHT, &v))
        d.local_height = (int)v;
    if (node_db_state_get_int(ndb, BSP_KEY_BEST_HEADER_HEIGHT, &v))
        d.best_header_height = (int)v;
    if (node_db_state_get_int(ndb, BSP_KEY_TARGET_HEIGHT, &v))
        d.target_height = (int)v;
    for (int i = 1; i < BSP_SOURCE_NUM; i++)
        restore_source_snapshot(ndb, (enum bsp_source)i, &d.sources[i]);
    if (d.selected_source > BSP_SOURCE_NONE &&
        d.selected_source < BSP_SOURCE_NUM) {
        struct bsp_source_status *s = &d.sources[d.selected_source];
        s->source = d.selected_source;
        s->score = d.selected_score;
        if (node_db_state_get(ndb, BSP_KEY_SOURCE_STATE, source_state,
                              sizeof(source_state) - 1, &len))
            bsp_copy_text(s->state, sizeof(s->state), source_state);
        if (node_db_state_get(ndb, BSP_KEY_SOURCE_REASON, source_reason,
                              sizeof(source_reason) - 1, &len))
            bsp_copy_text(s->reason, sizeof(s->reason), source_reason);
        if (node_db_state_get(ndb, BSP_KEY_SOURCE_BLOCKER, source_block_text,
                              sizeof(source_block_text) - 1, &len))
            bsp_copy_text(s->blocker, sizeof(s->blocker), source_block_text);
        if (node_db_state_get_int(ndb, BSP_KEY_SOURCE_HEIGHT, &v))
            s->height = (int)v;
        if (node_db_state_get_int(ndb, BSP_KEY_SOURCE_HEALTHY, &v))
            s->healthy = v != 0;
        if (node_db_state_get_int(ndb, BSP_KEY_SOURCE_AVAILABLE, &v))
            s->available = v != 0;
        if (node_db_state_get_int(ndb, BSP_KEY_SOURCE_BLOCKED, &v))
            s->blocked = v != 0;
    }
    (void)node_db_state_get_int(ndb, BSP_KEY_LAST_TIME, &when);
    (void)node_db_state_get_int(ndb, BSP_KEY_DECISIONS_TOTAL, &total);

    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    g_bsp.last = d;
    g_bsp.has_last = true;
    g_bsp.last_decision_time = when;
    g_bsp.decisions_total = total > 0 ? total : 1;
    bsp_copy_text(g_bsp.last_op, sizeof(g_bsp.last_op), op);
    zcl_mutex_unlock(&g_bsp.lock);
    return ZCL_OK;
}

struct zcl_result bsp_restore_projection_deferral(struct node_db *ndb)
{
    if (!ndb)
        return ZCL_ERR(-1, "bsp_restore_projection_deferral: null ndb");

    int64_t total = 0;
    int64_t height = 0;
    int64_t when = 0;
    char reason[64] = {0};
    size_t len = 0;

    (void)node_db_state_get_int(ndb, BSP_KEY_PROJECTION_DEFERRED_TOTAL,
                                &total);
    (void)node_db_state_get_int(ndb,
                                BSP_KEY_LAST_PROJECTION_DEFERRED_HEIGHT,
                                &height);
    (void)node_db_state_get_int(ndb, BSP_KEY_LAST_PROJECTION_DEFERRED_TIME,
                                &when);
    (void)node_db_state_get(ndb, BSP_KEY_LAST_PROJECTION_DEFERRED_REASON,
                            reason, sizeof(reason) - 1, &len);

    bsp_lock_init_once();
    zcl_mutex_lock(&g_bsp.lock);
    g_bsp.projection_deferred_total = total;
    g_bsp.last_projection_deferred_height = (int)height;
    g_bsp.last_projection_deferred_time = when;
    bsp_copy_text(g_bsp.last_projection_deferred_reason,
                  sizeof(g_bsp.last_projection_deferred_reason),
                  reason);
    zcl_mutex_unlock(&g_bsp.lock);
    return ZCL_OK;
}
