/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the pure JSON serializers in
 * engine/services/src/block_source_policy_status.c: bsp_source_to_json,
 * bsp_decision_to_json, and the bsp_source_class_name name lookup. The
 * file's own header comment self-labels these "pure JSON serializers" with
 * "no fallible service surface" — plain struct -> struct json_value
 * encoders, fully decoupled from node.db/locks/network. No test in
 * tests/harness/src previously referenced any of them.
 *
 * bsp_source_lag_known/valid and bsp_push_source_observed_lag are `static`
 * in block_source_policy_status.c, so they cannot be called directly; their
 * behavior is pinned indirectly through the "lag_known" / "lag_valid" /
 * "lag_observed" (and "candidate_*" mirrors) keys that bsp_source_to_json
 * emits — exactly the surface an operator/UI actually reads.
 *
 * Every test builds a `struct bsp_source_status` / `struct bsp_decision` on
 * the stack (never touching the stateful g_bsp runtime, which lives in the
 * sibling _runtime.c file and is out of scope here), serializes it, and
 * inspects the resulting struct json_value directly via json_get/json_at —
 * no string-parse round trip needed since bsp_*_to_json writes straight
 * into an in-memory json_value.
 */

#include "test/test_core.h"

/* Internal seam: bsp_source_to_json / bsp_decision_to_json /
 * bsp_source_class_name are declared in this sibling-file-only header, not
 * the public services/block_source_policy.h. Reaching into a shape's own
 * _internal.h from a focused test has established precedent — see
 * test_explorer_rpc_call.c (explorer_controller_internal.h) and
 * test_health_rollup.c (controllers/diagnostics_internal.h). */
#include "../../../engine/services/src/block_source_policy_internal.h"

#define BSPJ_RUN(name, expr) do { \
    printf("%s... ", (name));     \
    bool _ok = (expr);            \
    if (_ok) printf("OK\n");      \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Populate every field of a bsp_source_status with distinct, seed-derived
 * sentinel values so a round-trip test can check each JSON key
 * individually instead of merely "doesn't crash". */
static void bspj_fill_source(struct bsp_source_status *s, enum bsp_source source,
                              int seed)
{
    memset(s, 0, sizeof(*s));
    s->source                       = source;
    s->available                    = (seed % 2) == 0;
    s->healthy                      = (seed % 3) == 0;
    s->blocked                      = (seed % 5) == 0;
    s->blocked_class                = (enum blocker_class)(seed % 4);
    s->authorized                   = (seed % 7) != 0;
    s->selectable                   = (seed % 2) != 0;
    s->height                       = 1000 + seed;
    s->score                        = 50 + seed;
    s->score_base                   = 1 + seed;
    s->score_health                 = 2 + seed;
    s->score_height                 = 3 + seed;
    s->score_authorized             = 4 + seed;
    s->score_redundancy_bonus       = 5 + seed;
    s->score_target_lag_penalty     = 6 + seed;
    s->score_failure_penalty        = 7 + seed;
    s->score_mirror_gate_penalty    = 8 + seed;
    s->failures                     = 9 + seed;
    s->timeouts                     = 10 + seed;
    s->outbound_total               = 11 + seed;
    s->inbound_total                = 12 + seed;
    s->healthy_peers                = 13 + seed;
    s->inbound_healthy_peers        = 14 + seed;
    s->total_healthy_peers          = 15 + seed;
    s->connecting_peers             = 16 + seed;
    s->handshake_incomplete         = 17 + seed;
    s->inbound_handshake_incomplete = 18 + seed;
    s->peer_groups                  = 19 + seed;
    s->max_peer_group_size          = 20 + seed;
    s->healthy_peer_groups          = 21 + seed;
    s->healthy_max_peer_group_size  = 22 + seed;
    s->addnode_count                = 23 + seed;
    s->addnode_backoff_active       = 24 + seed;
    s->addnode_backoff_max_sec      = 25 + seed;
    s->addnode_tcp_failures         = 26 + seed;
    s->addnode_protocol_failures    = 27 + seed;
    s->progress_current             = 28 + seed;
    s->progress_total               = 29 + seed;
    s->lag                          = 30 + seed;
    s->lag_known                    = (seed % 2) == 0;
    s->lag_valid                    = (seed % 2) != 0;
    s->retry_count                  = 31 + seed;
    s->distinct_peer_count          = 32 + seed;
    s->serving_peer_id              = 33 + seed;
    snprintf(s->state, sizeof(s->state), "state_%d", seed);
    snprintf(s->selection_reason, sizeof(s->selection_reason), "selreason_%d", seed);
    snprintf(s->reason, sizeof(s->reason), "reason_%d", seed);
    snprintf(s->blocker, sizeof(s->blocker), "blocker_%d", seed);
}

/* ── 1. bsp_source_class_name: every named enum value ──────────── */

static int t_source_class_name_named(void)
{
    int failures = 0;
    bool ok =
        strcmp(bsp_source_class_name(BSP_SOURCE_NONE), "none") == 0 &&
        strcmp(bsp_source_class_name(BSP_SOURCE_P2P), "native_p2p") == 0 &&
        strcmp(bsp_source_class_name(BSP_SOURCE_SNAPSHOT), "snapshot") == 0 &&
        strcmp(bsp_source_class_name(BSP_SOURCE_LOCAL_IMPORT), "local_import") == 0 &&
        strcmp(bsp_source_class_name(BSP_SOURCE_ZCLASSICD_MIRROR), "legacy_advisory") == 0;
    BSPJ_RUN("bsp_source_class_name: every named source maps correctly", ok);
    return failures;
}

/* ── 2. bsp_source_class_name: NUM + out-of-range -> "unknown" ─── */

static int t_source_class_name_unknown_default(void)
{
    int failures = 0;
    bool ok =
        strcmp(bsp_source_class_name(BSP_SOURCE_NUM), "unknown") == 0 &&
        strcmp(bsp_source_class_name((enum bsp_source)(BSP_SOURCE_NUM + 1)), "unknown") == 0 &&
        strcmp(bsp_source_class_name((enum bsp_source)-1), "unknown") == 0 &&
        strcmp(bsp_source_class_name((enum bsp_source)999), "unknown") == 0;
    BSPJ_RUN("bsp_source_class_name: BSP_SOURCE_NUM + out-of-range fall to default \"unknown\"", ok);
    return failures;
}

/* ── 3. lag_known/lag_valid: mirror source passes struct fields verbatim ── */

static int t_mirror_lag_passthrough(void)
{
    int failures = 0;
    bool ok = true;

    /* known=true, valid=true */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_ZCLASSICD_MIRROR, 1);
        s.lag_known = true; s.lag_valid = true;
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        ok = ok && json_get_bool(json_get(&out, "lag_known")) == true &&
                   json_get_bool(json_get(&out, "lag_valid")) == true;
        json_free(&out);
    }
    /* known=false, valid=false -> mirror must report exactly what the
     * struct says, i.e. false/false (NOT force-true). */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_ZCLASSICD_MIRROR, 2);
        s.lag_known = false; s.lag_valid = false;
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        ok = ok && json_get_bool(json_get(&out, "lag_known")) == false &&
                   json_get_bool(json_get(&out, "lag_valid")) == false;
        json_free(&out);
    }
    /* Mixed: known=true, valid=false -> the two fields are independent. */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_ZCLASSICD_MIRROR, 3);
        s.lag_known = true; s.lag_valid = false;
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        ok = ok && json_get_bool(json_get(&out, "lag_known")) == true &&
                   json_get_bool(json_get(&out, "lag_valid")) == false;
        json_free(&out);
    }
    /* candidate_lag_known / candidate_lag_valid mirror the same values. */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_ZCLASSICD_MIRROR, 4);
        s.lag_known = false; s.lag_valid = true;
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        ok = ok && json_get_bool(json_get(&out, "candidate_lag_known")) == false &&
                   json_get_bool(json_get(&out, "candidate_lag_valid")) == true;
        json_free(&out);
    }
    BSPJ_RUN("bsp_source_to_json: BSP_SOURCE_ZCLASSICD_MIRROR passes lag_known/lag_valid through verbatim", ok);
    return failures;
}

/* ── 4. lag_known/lag_valid: every OTHER source unconditionally reports
 *      true, even when the struct's actual fields are false ─────────── */

static int t_non_mirror_lag_forced_true(void)
{
    int failures = 0;
    bool ok = true;
    enum bsp_source non_mirror[] = {
        BSP_SOURCE_NONE, BSP_SOURCE_P2P, BSP_SOURCE_SNAPSHOT, BSP_SOURCE_LOCAL_IMPORT
    };
    for (size_t i = 0; i < sizeof(non_mirror) / sizeof(non_mirror[0]); i++) {
        struct bsp_source_status s;
        bspj_fill_source(&s, non_mirror[i], 5);
        /* Deliberately false, to catch a flipped branch that would report
         * "lag unknown" for a source class that should always be reported
         * known/valid (the exact regression class named in the review). */
        s.lag_known = false;
        s.lag_valid = false;
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        bool this_ok =
            json_get_bool(json_get(&out, "lag_known")) == true &&
            json_get_bool(json_get(&out, "lag_valid")) == true &&
            json_get_bool(json_get(&out, "candidate_lag_known")) == true &&
            json_get_bool(json_get(&out, "candidate_lag_valid")) == true;
        json_free(&out);
        ok = ok && this_ok;
    }
    BSPJ_RUN("bsp_source_to_json: non-mirror sources report lag_known/lag_valid=true regardless of the struct", ok);
    return failures;
}

/* ── 5. lag_observed: null when NOT known, actual lag when known ─────── */

static int t_lag_observed_null_vs_int(void)
{
    int failures = 0;
    bool ok = true;

    /* Mirror source, lag_known=false -> "lag_observed" must be a JSON
     * null, not an omitted key and not the sentinel -1 int. */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_ZCLASSICD_MIRROR, 6);
        s.lag_known = false;
        s.lag = 777; /* must be ignored when not known */
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        const struct json_value *lo = json_get(&out, "lag_observed");
        const struct json_value *clo = json_get(&out, "candidate_lag_observed");
        ok = ok && lo != NULL && lo->type == JSON_NULL && json_is_null(lo);
        ok = ok && clo != NULL && clo->type == JSON_NULL && json_is_null(clo);
        json_free(&out);
    }
    /* Mirror source, lag_known=true -> "lag_observed" is the actual int
     * lag value, not omitted, not null. */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_ZCLASSICD_MIRROR, 7);
        s.lag_known = true;
        s.lag = 4242;
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        const struct json_value *lo = json_get(&out, "lag_observed");
        const struct json_value *clo = json_get(&out, "candidate_lag_observed");
        ok = ok && lo != NULL && lo->type == JSON_INT && json_get_int(lo) == 4242;
        ok = ok && clo != NULL && clo->type == JSON_INT && json_get_int(clo) == 4242;
        json_free(&out);
    }
    /* Non-mirror source with lag_known=false in the struct: since
     * non-mirror is always treated as known, lag_observed must still be
     * the actual int lag (not null) -- the exact false-"lag unknown" UI
     * regression this test class exists to pin. */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_P2P, 8);
        s.lag_known = false;
        s.lag = 99;
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        const struct json_value *lo = json_get(&out, "lag_observed");
        ok = ok && lo != NULL && lo->type == JSON_INT && json_get_int(lo) == 99;
        json_free(&out);
    }
    BSPJ_RUN("bsp_source_to_json: lag_observed is JSON null iff lag unknown, else the actual int lag", ok);
    return failures;
}

/* ── 6. bsp_source_to_json: full field round trip ─────────────────────── */

static int t_source_to_json_full_roundtrip(void)
{
    int failures = 0;
    struct bsp_source_status s;
    bspj_fill_source(&s, BSP_SOURCE_LOCAL_IMPORT, 13);
    struct json_value out = {0};
    bsp_source_to_json(&s, &out);

    bool ok = out.type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(&out, "source")), bsp_source_name(s.source)) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "source_class")), "local_import") == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "candidate_source")), "local_import") == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "trust")), bsp_source_trust_name(s.source)) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "candidate_trust")), bsp_source_trust_name(s.source)) == 0;
    ok = ok && json_get_bool(json_get(&out, "available")) == s.available;
    ok = ok && json_get_bool(json_get(&out, "healthy")) == s.healthy;
    ok = ok && json_get_bool(json_get(&out, "blocked")) == s.blocked;
    ok = ok && strcmp(json_get_str(json_get(&out, "blocked_class")),
                       blocker_class_name(s.blocked_class)) == 0;
    ok = ok && json_get_bool(json_get(&out, "authorized")) == s.authorized;
    ok = ok && json_get_bool(json_get(&out, "selectable")) == s.selectable;
    ok = ok && strcmp(json_get_str(json_get(&out, "selection_blocker")), s.selection_reason) == 0;
    ok = ok && json_get_int(json_get(&out, "height")) == s.height;
    ok = ok && json_get_int(json_get(&out, "score")) == s.score;
    ok = ok && json_get_int(json_get(&out, "score_base")) == s.score_base;
    ok = ok && json_get_int(json_get(&out, "score_health")) == s.score_health;
    ok = ok && json_get_int(json_get(&out, "score_height")) == s.score_height;
    ok = ok && json_get_int(json_get(&out, "score_authorized")) == s.score_authorized;
    ok = ok && json_get_int(json_get(&out, "score_redundancy_bonus")) == s.score_redundancy_bonus;
    ok = ok && json_get_int(json_get(&out, "score_target_lag_penalty")) == s.score_target_lag_penalty;
    ok = ok && json_get_int(json_get(&out, "score_failure_penalty")) == s.score_failure_penalty;
    ok = ok && json_get_int(json_get(&out, "score_mirror_gate_penalty")) == s.score_mirror_gate_penalty;
    ok = ok && json_get_int(json_get(&out, "failures")) == s.failures;
    ok = ok && json_get_int(json_get(&out, "timeouts")) == s.timeouts;
    ok = ok && json_get_int(json_get(&out, "outbound_total")) == s.outbound_total;
    ok = ok && json_get_int(json_get(&out, "inbound_total")) == s.inbound_total;
    ok = ok && json_get_int(json_get(&out, "healthy_peers")) == s.healthy_peers;
    ok = ok && json_get_int(json_get(&out, "inbound_healthy_peers")) == s.inbound_healthy_peers;
    ok = ok && json_get_int(json_get(&out, "total_healthy_peers")) == s.total_healthy_peers;
    ok = ok && json_get_int(json_get(&out, "connecting_peers")) == s.connecting_peers;
    ok = ok && json_get_int(json_get(&out, "handshake_incomplete")) == s.handshake_incomplete;
    ok = ok && json_get_int(json_get(&out, "inbound_handshake_incomplete")) == s.inbound_handshake_incomplete;
    ok = ok && json_get_int(json_get(&out, "peer_groups")) == s.peer_groups;
    ok = ok && json_get_int(json_get(&out, "max_peer_group_size")) == s.max_peer_group_size;
    ok = ok && json_get_int(json_get(&out, "healthy_peer_groups")) == s.healthy_peer_groups;
    ok = ok && json_get_int(json_get(&out, "healthy_max_peer_group_size")) == s.healthy_max_peer_group_size;
    ok = ok && json_get_int(json_get(&out, "addnode_count")) == s.addnode_count;
    ok = ok && json_get_int(json_get(&out, "addnode_backoff_active")) == s.addnode_backoff_active;
    ok = ok && json_get_int(json_get(&out, "addnode_backoff_max_sec")) == s.addnode_backoff_max_sec;
    ok = ok && json_get_int(json_get(&out, "addnode_tcp_failures")) == s.addnode_tcp_failures;
    ok = ok && json_get_int(json_get(&out, "addnode_protocol_failures")) == s.addnode_protocol_failures;
    ok = ok && json_get_int(json_get(&out, "progress_current")) == s.progress_current;
    ok = ok && json_get_int(json_get(&out, "progress_total")) == s.progress_total;
    ok = ok && json_get_int(json_get(&out, "lag")) == s.lag;
    ok = ok && json_get_int(json_get(&out, "candidate_lag")) == s.lag;
    ok = ok && json_get_int(json_get(&out, "retry_count")) == s.retry_count;
    ok = ok && json_get_int(json_get(&out, "distinct_peer_count")) == s.distinct_peer_count;
    ok = ok && json_get_int(json_get(&out, "serving_peer_id")) == s.serving_peer_id;
    ok = ok && strcmp(json_get_str(json_get(&out, "state")), s.state) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "reason")), s.reason) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "blocker")), s.blocker) == 0;

    json_free(&out);
    BSPJ_RUN("bsp_source_to_json: every field round-trips for a fully populated source", ok);
    return failures;
}

/* ── 7. candidate_blocker fallback: blocker set vs blocker empty ──────── */

static int t_candidate_blocker_fallback(void)
{
    int failures = 0;
    bool ok = true;

    /* blocker non-empty -> candidate_blocker == blocker (selection_reason
     * ignored even though it is also populated). */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_P2P, 9);
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        ok = ok && strcmp(json_get_str(json_get(&out, "candidate_blocker")), s.blocker) == 0;
        json_free(&out);
    }
    /* blocker empty ("") -> candidate_blocker falls back to selection_reason. */
    {
        struct bsp_source_status s;
        bspj_fill_source(&s, BSP_SOURCE_P2P, 10);
        s.blocker[0] = '\0';
        struct json_value out = {0};
        bsp_source_to_json(&s, &out);
        ok = ok && strcmp(json_get_str(json_get(&out, "candidate_blocker")), s.selection_reason) == 0;
        json_free(&out);
    }
    BSPJ_RUN("bsp_source_to_json: candidate_blocker falls back to selection_reason iff blocker[0]=='\\0'", ok);
    return failures;
}

/* ── Helper: build a fully populated bsp_decision on the stack ────────── */

static void bspj_fill_decision(struct bsp_decision *d, enum bsp_source selected)
{
    memset(d, 0, sizeof(*d));
    d->result = BSP_DECISION_USE_SOURCE;
    d->selected_source = selected;
    d->activation_allowed = true;
    d->mirror_fallback_allowed = false;
    d->local_height = 100;
    d->best_header_height = 200;
    d->target_height = 190;
    d->projection_height = 150;
    d->projection_lag = 40;
    d->projection_deferred = true;
    d->projection_deferred_total = 3;
    d->last_projection_deferred_height = 149;
    d->last_projection_deferred_time = 1700000000;
    d->selected_score = 88;
    snprintf(d->projection_state, sizeof(d->projection_state), "deferred");
    snprintf(d->last_projection_deferred_reason,
             sizeof(d->last_projection_deferred_reason), "wait_for_peer");
    snprintf(d->reason, sizeof(d->reason), "decision_reason");
    snprintf(d->blocker, sizeof(d->blocker), "decision_blocker");
    for (int i = 1; i < BSP_SOURCE_NUM; i++)
        bspj_fill_source(&d->sources[i], (enum bsp_source)i, 40 + i);
}

/* ── 8. bsp_decision_to_json: NULL decision -> empty object, no crash ──── */

static int t_decision_null_is_empty_object(void)
{
    int failures = 0;
    struct json_value out = {0};
    bsp_decision_to_json(NULL, &out);
    bool ok = out.type == JSON_OBJ && json_size(&out) == 0 && json_empty(&out);
    json_free(&out);
    BSPJ_RUN("bsp_decision_to_json: d==NULL yields an empty JSON object (json_set_object runs before the NULL check)", ok);
    return failures;
}

/* ── 9. selected_source_* block: absent at both exclusive bounds ──────── */

static int t_selected_source_block_bounds(void)
{
    int failures = 0;
    bool ok = true;

    /* selected_source == BSP_SOURCE_NONE -> block must be absent. */
    {
        struct bsp_decision d;
        bspj_fill_decision(&d, BSP_SOURCE_NONE);
        struct json_value out = {0};
        bsp_decision_to_json(&d, &out);
        ok = ok && json_get(&out, "selected_source_state") == NULL &&
                   json_get(&out, "selected_source_reason") == NULL &&
                   json_get(&out, "selected_source_selectable") == NULL;
        json_free(&out);
    }
    /* selected_source == BSP_SOURCE_NUM (past the last real source) -> also absent. */
    {
        struct bsp_decision d;
        bspj_fill_decision(&d, BSP_SOURCE_NUM);
        struct json_value out = {0};
        bsp_decision_to_json(&d, &out);
        ok = ok && json_get(&out, "selected_source_state") == NULL &&
                   json_get(&out, "selected_source_blocked") == NULL;
        json_free(&out);
    }
    BSPJ_RUN("bsp_decision_to_json: selected_source_* block absent for BSP_SOURCE_NONE and BSP_SOURCE_NUM", ok);
    return failures;
}

/* ── 10. selected_source_* block: present + correct for a real source ─── */

static int t_selected_source_block_present(void)
{
    int failures = 0;
    struct bsp_decision d;
    bspj_fill_decision(&d, BSP_SOURCE_SNAPSHOT);
    const struct bsp_source_status *sel = &d.sources[BSP_SOURCE_SNAPSHOT];

    struct json_value out = {0};
    bsp_decision_to_json(&d, &out);

    bool ok =
        strcmp(json_get_str(json_get(&out, "selected_source_state")), sel->state) == 0 &&
        strcmp(json_get_str(json_get(&out, "selected_source_reason")), sel->reason) == 0 &&
        strcmp(json_get_str(json_get(&out, "selected_source_blocker")), sel->blocker) == 0 &&
        json_get_bool(json_get(&out, "selected_source_selectable")) == sel->selectable &&
        strcmp(json_get_str(json_get(&out, "selected_source_selection_blocker")), sel->selection_reason) == 0 &&
        json_get_int(json_get(&out, "selected_source_height")) == sel->height &&
        json_get_int(json_get(&out, "selected_source_score_base")) == sel->score_base &&
        json_get_int(json_get(&out, "selected_source_score_health")) == sel->score_health &&
        json_get_int(json_get(&out, "selected_source_score_height")) == sel->score_height &&
        json_get_int(json_get(&out, "selected_source_score_authorized")) == sel->score_authorized &&
        json_get_int(json_get(&out, "selected_source_score_redundancy_bonus")) == sel->score_redundancy_bonus &&
        json_get_int(json_get(&out, "selected_source_score_target_lag_penalty")) == sel->score_target_lag_penalty &&
        json_get_int(json_get(&out, "selected_source_score_failure_penalty")) == sel->score_failure_penalty &&
        json_get_int(json_get(&out, "selected_source_score_mirror_gate_penalty")) == sel->score_mirror_gate_penalty &&
        json_get_bool(json_get(&out, "selected_source_healthy")) == sel->healthy &&
        json_get_bool(json_get(&out, "selected_source_available")) == sel->available &&
        json_get_bool(json_get(&out, "selected_source_blocked")) == sel->blocked;

    json_free(&out);
    BSPJ_RUN("bsp_decision_to_json: selected_source_* block matches d->sources[selected_source] for a real source", ok);
    return failures;
}

/* ── 11. sources array: exactly BSP_SOURCE_NUM-1 entries, indices 1..NUM-1 ── */

static int t_sources_array_size_and_order(void)
{
    int failures = 0;
    struct bsp_decision d;
    bspj_fill_decision(&d, BSP_SOURCE_P2P);

    struct json_value out = {0};
    bsp_decision_to_json(&d, &out);
    const struct json_value *arr = json_get(&out, "sources");

    bool ok = arr != NULL && arr->type == JSON_ARR &&
              json_size(arr) == (size_t)(BSP_SOURCE_NUM - 1);

    /* Position k (0-based) corresponds to loop index i = k+1, so
     * arr[0].source == bsp_source_name(BSP_SOURCE_P2P), etc. — BSP_SOURCE_NONE
     * (index 0) must never appear in the array. */
    for (int i = 1; ok && i < BSP_SOURCE_NUM; i++) {
        const struct json_value *child = json_at(arr, (size_t)(i - 1));
        ok = ok && child != NULL &&
             strcmp(json_get_str(json_get(child, "source")),
                    bsp_source_name((enum bsp_source)i)) == 0;
    }

    json_free(&out);
    BSPJ_RUN("bsp_decision_to_json: sources array has exactly BSP_SOURCE_NUM-1 entries in index 1..NUM-1 order", ok);
    return failures;
}

/* ── 12. sources array: self-heals a zeroed source.source field ───────── */

static int t_sources_array_self_heals_zeroed_source_field(void)
{
    int failures = 0;
    struct bsp_decision d;
    memset(&d, 0, sizeof(d));
    d.result = BSP_DECISION_WAIT;
    d.selected_source = BSP_SOURCE_NONE;
    /* Every element of d.sources[] is fully zeroed, including .source
     * (== BSP_SOURCE_NONE for every slot, even though its true index is
     * 1..NUM-1). bsp_decision_to_json must self-heal each entry's .source
     * to the loop index i before serializing, rather than emitting "none"
     * for every slot. */

    struct json_value out = {0};
    bsp_decision_to_json(&d, &out);
    const struct json_value *arr = json_get(&out, "sources");

    bool ok = arr != NULL && json_size(arr) == (size_t)(BSP_SOURCE_NUM - 1);
    for (int i = 1; ok && i < BSP_SOURCE_NUM; i++) {
        const struct json_value *child = json_at(arr, (size_t)(i - 1));
        ok = ok && child != NULL &&
             strcmp(json_get_str(json_get(child, "source")),
                    bsp_source_name((enum bsp_source)i)) == 0 &&
             strcmp(json_get_str(json_get(child, "source")), "none") != 0;
    }
    /* The self-heal must operate on a local copy, never mutate the input
     * decision -- every raw d.sources[i].source stays BSP_SOURCE_NONE (0)
     * after the call. */
    for (int i = 1; ok && i < BSP_SOURCE_NUM; i++)
        ok = ok && d.sources[i].source == BSP_SOURCE_NONE;

    json_free(&out);
    BSPJ_RUN("bsp_decision_to_json: a zeroed source.source field self-heals to the loop index i without mutating the input", ok);
    return failures;
}

/* ── 13. bsp_decision_to_json: full top-level field round trip ────────── */

static int t_decision_to_json_full_roundtrip(void)
{
    int failures = 0;
    struct bsp_decision d;
    bspj_fill_decision(&d, BSP_SOURCE_LOCAL_IMPORT);

    struct json_value out = {0};
    bsp_decision_to_json(&d, &out);

    bool ok = out.type == JSON_OBJ;
    ok = ok && strcmp(json_get_str(json_get(&out, "decision")), bsp_decision_result_name(d.result)) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "selected_source")), bsp_source_name(d.selected_source)) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "candidate_source")), "local_import") == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "selected_source_trust")), bsp_source_trust_name(d.selected_source)) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "candidate_trust")), bsp_source_trust_name(d.selected_source)) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "authority")), "local_consensus_validation") == 0;
    ok = ok && json_get_bool(json_get(&out, "activation_allowed")) == d.activation_allowed;
    ok = ok && json_get_bool(json_get(&out, "mirror_fallback_allowed")) == d.mirror_fallback_allowed;
    ok = ok && json_get_int(json_get(&out, "local_height")) == d.local_height;
    ok = ok && json_get_int(json_get(&out, "best_header_height")) == d.best_header_height;
    ok = ok && json_get_int(json_get(&out, "target_height")) == d.target_height;
    ok = ok && json_get_int(json_get(&out, "projection_height")) == d.projection_height;
    ok = ok && json_get_int(json_get(&out, "projection_lag")) == d.projection_lag;
    ok = ok && json_get_bool(json_get(&out, "projection_deferred")) == d.projection_deferred;
    ok = ok && strcmp(json_get_str(json_get(&out, "projection_state")), d.projection_state) == 0;
    ok = ok && json_get_int(json_get(&out, "projection_deferred_total")) == d.projection_deferred_total;
    ok = ok && json_get_int(json_get(&out, "last_projection_deferred_height")) == d.last_projection_deferred_height;
    ok = ok && json_get_int(json_get(&out, "last_projection_deferred_time")) == d.last_projection_deferred_time;
    ok = ok && strcmp(json_get_str(json_get(&out, "last_projection_deferred_reason")), d.last_projection_deferred_reason) == 0;
    ok = ok && json_get_int(json_get(&out, "selected_score")) == d.selected_score;
    ok = ok && strcmp(json_get_str(json_get(&out, "reason")), d.reason) == 0;
    ok = ok && strcmp(json_get_str(json_get(&out, "blocker")), d.blocker) == 0;

    json_free(&out);
    BSPJ_RUN("bsp_decision_to_json: every top-level field round-trips for a fully populated decision", ok);
    return failures;
}

/* ── 14. bsp_source_class_name is total: no crash across the full enum
 *       range plus adversarial negative/huge values (adversarial input) ── */

static int t_source_class_name_total_adversarial(void)
{
    int failures = 0;
    bool ok = true;
    for (int v = -5; v <= (int)BSP_SOURCE_NUM + 5; v++) {
        const char *n = bsp_source_class_name((enum bsp_source)v);
        ok = ok && n != NULL && n[0] != '\0';
    }
    int extreme[] = { INT32_MIN, INT32_MAX };
    for (size_t i = 0; i < sizeof(extreme) / sizeof(extreme[0]); i++) {
        const char *n = bsp_source_class_name((enum bsp_source)extreme[i]);
        ok = ok && n != NULL && strcmp(n, "unknown") == 0;
    }
    BSPJ_RUN("bsp_source_class_name: total function across full range + INT32_MIN/MAX adversarial input", ok);
    return failures;
}

/* ── Aggregator ─────────────────────────────────────────────────────── */

int test_block_source_policy_status_json(void)
{
    printf("\n=== block_source_policy_status.c JSON serializer tests ===\n");
    int failures = 0;
    failures += t_source_class_name_named();
    failures += t_source_class_name_unknown_default();
    failures += t_mirror_lag_passthrough();
    failures += t_non_mirror_lag_forced_true();
    failures += t_lag_observed_null_vs_int();
    failures += t_source_to_json_full_roundtrip();
    failures += t_candidate_blocker_fallback();
    failures += t_decision_null_is_empty_object();
    failures += t_selected_source_block_bounds();
    failures += t_selected_source_block_present();
    failures += t_sources_array_size_and_order();
    failures += t_sources_array_self_heals_zeroed_source_field();
    failures += t_decision_to_json_full_roundtrip();
    failures += t_source_class_name_total_adversarial();
    return failures;
}
