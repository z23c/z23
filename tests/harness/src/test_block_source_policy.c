/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "coins/undo.h"

#include "conditions/local_header_refill_needed.h"
#include "services/block_source_policy.h"
#include "services/legacy_mirror_sync_service.h"
#include "net/snapshot_sync_contract.h"
#include "services/sync_monitor.h"
#include "config/runtime.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "framework/condition.h"
#include "models/block.h"
#include "models/database.h"
#include "net/connman.h"
#include "net/download.h"
#include "validation/main_state.h"
#include "validation/mirror_consensus.h"

static void init_source(struct bsp_plan_input *in,
                        enum bsp_source source,
                        bool available,
                        bool healthy,
                        int height)
{
    struct bsp_source_status *s = &in->sources[source];
    memset(s, 0, sizeof(*s));
    s->source = source;
    s->available = available;
    s->healthy = healthy;
    s->height = height;
}

static struct bsp_plan_input base_input(void)
{
    struct bsp_plan_input in;
    memset(&in, 0, sizeof(in));
    in.local_height = 100;
    in.best_header_height = 120;
    in.target_height = 120;
    return in;
}

static const struct json_value *find_source_json(const struct json_value *arr,
                                                 const char *source)
{
    if (!arr || arr->type != JSON_ARR || !source)
        return NULL;
    for (size_t i = 0; i < json_size(arr); i++) {
        const struct json_value *child = json_at(arr, i);
        const struct json_value *name = json_get(child, "source");
        if (name && strcmp(json_get_str(name), source) == 0)
            return child;
    }
    return NULL;
}

static int test_bsp_names(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: name tables are stable")
    {
        ASSERT_STR_EQ(bsp_source_name(BSP_SOURCE_P2P), "p2p");
        ASSERT_STR_EQ(bsp_source_name(BSP_SOURCE_ZCLASSICD_MIRROR),
                      "zclassicd_mirror");
        ASSERT_STR_EQ(bsp_source_trust_name(BSP_SOURCE_P2P),
                      "native_peer_validated");
        ASSERT_STR_EQ(bsp_source_trust_name(BSP_SOURCE_ZCLASSICD_MIRROR),
                      "bounded_advisory_fallback");
        ASSERT_STR_EQ(bsp_decision_result_name(BSP_DECISION_USE_SOURCE),
                      "use_source");
        ASSERT_STR_EQ(bsp_source_name((enum bsp_source)BSP_SOURCE_NUM),
                      "unknown");
    } TEST_END
    return failures;
}

static int test_bsp_prefers_native_p2p(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: native P2P beats mirror when healthy")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        init_source(&in, BSP_SOURCE_P2P, true, true, 125);
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 130);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_P2P);
        ASSERT(out.activation_allowed);
        ASSERT(out.local_height == 100);
        ASSERT(out.target_height == 120);
        ASSERT(out.mirror_fallback_allowed);
    } TEST_END
    return failures;
}

static int test_bsp_keeps_caught_up_p2p_when_legacy_is_ahead(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: caught-up P2P remains selected over legacy advisory lag")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.local_height = 120;
        in.best_header_height = 120;
        in.target_height = 122;
        init_source(&in, BSP_SOURCE_P2P, true, true, 120);
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 122);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;
        snprintf(in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].blocker,
                 sizeof(in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].blocker),
                 "activation-no-progress");
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].blocked = true;

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_P2P);
        ASSERT(out.sources[BSP_SOURCE_P2P].selectable);
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_P2P].selection_reason, "");
    } TEST_END
    return failures;
}

static int test_bsp_gates_mirror_during_local_retries(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: mirror waits behind local retries")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.local_recovery_active = true;
        in.local_retries_exhausted = false;
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 130);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_WAIT);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT(!out.mirror_fallback_allowed);
        ASSERT_STR_EQ(out.reason, "local_retries_pending");
        ASSERT(!out.sources[BSP_SOURCE_ZCLASSICD_MIRROR].selectable);
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_ZCLASSICD_MIRROR].
                      selection_reason, "local_recovery_gate");
    } TEST_END
    return failures;
}

static int test_bsp_allows_bounded_mirror_after_retries(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: mirror fallback after local retries exhaust")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.local_recovery_active = true;
        in.local_retries_exhausted = true;
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 130);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_ZCLASSICD_MIRROR);
        ASSERT(out.mirror_fallback_allowed);
        ASSERT(out.sources[BSP_SOURCE_ZCLASSICD_MIRROR].selectable);
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_ZCLASSICD_MIRROR].
                      selection_reason, "");
    } TEST_END
    return failures;
}

/* Concurrent redundancy override: when mirror lag breaches the SLO and
 * the mirror is reachable, mirror_fallback_allowed must be true REGARDLESS
 * of local recovery state. Today's bug: zclassic23 sat 2,178 blocks behind
 * zclassicd because the mirror was gated on local_retries_exhausted, but
 * that flag never tripped (only 1 eligible peer). The test below replays
 * exactly that state and asserts the mirror takes over. */
static int test_bsp_lag_slo_overrides_local_gate(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: lag SLO override allows concurrent mirror")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        /* Local recovery active, not exhausted — old gate would block. */
        in.local_recovery_active = true;
        in.local_retries_exhausted = false;
        in.mirror_lag_sla_breach_blocks = 10;
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 2300);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].lag = 200; /* over breach */
        in.target_height = 2300;

        block_source_policy_plan(&in, &out);
        ASSERT(out.mirror_fallback_allowed);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_ZCLASSICD_MIRROR);
    } TEST_END
    return failures;
}

static int test_bsp_lag_slo_mirror_outranks_near_target_p2p(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: lag SLO mirror outranks near-target P2P")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.local_height = 3170742;
        in.best_header_height = 3170879;
        in.target_height = 3170900;
        in.mirror_lag_sla_breach_blocks = 10;
        init_source(&in, BSP_SOURCE_P2P, true, true, 3170898);
        in.sources[BSP_SOURCE_P2P].timeouts = 4;
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR,
                    true, true, 3170900);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].lag = 158;

        block_source_policy_plan(&in, &out);
        ASSERT(out.mirror_fallback_allowed);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_ZCLASSICD_MIRROR);
        ASSERT(out.sources[BSP_SOURCE_P2P].selectable);
        ASSERT(out.sources[BSP_SOURCE_ZCLASSICD_MIRROR].selectable);
        ASSERT(out.sources[BSP_SOURCE_P2P].score == 81);
        ASSERT(out.sources[BSP_SOURCE_ZCLASSICD_MIRROR].
               score_redundancy_bonus == 30);
        ASSERT(out.sources[BSP_SOURCE_ZCLASSICD_MIRROR].score >
               out.sources[BSP_SOURCE_P2P].score);
    } TEST_END
    return failures;
}

/* Negative case: when lag is BELOW the breach threshold and local
 * recovery is in progress, the original gate still applies — the mirror
 * stays advisory until either retries exhaust or lag crosses breach. */
static int test_bsp_below_breach_still_gates_mirror(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: lag under SLO keeps mirror gated")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.local_recovery_active = true;
        in.local_retries_exhausted = false;
        in.mirror_lag_sla_breach_blocks = 10;
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 105);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].lag = 5; /* below breach */
        in.target_height = 120;

        block_source_policy_plan(&in, &out);
        ASSERT(!out.mirror_fallback_allowed);
        ASSERT(out.result == BSP_DECISION_WAIT);
    } TEST_END
    return failures;
}

static int test_bsp_peer_floor_helper_classifies_recovery(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: peer floor helper records recovery")
    {
        struct bsp_decision out;
        ASSERT(block_source_policy_peer_floor_recovery_needed(
            1, 3, 100, 130, &out));
        ASSERT(out.result == BSP_DECISION_RECOVER);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT_STR_EQ(out.reason, "no_healthy_source");
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_P2P].reason,
                      "healthy_outbound=1 min_healthy=3");
    } TEST_END
    return failures;
}

static int test_bsp_peer_floor_helper_accepts_healthy_p2p(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: peer floor helper accepts healthy P2P")
    {
        struct bsp_decision out;
        ASSERT(!block_source_policy_peer_floor_recovery_needed(
            3, 3, 100, 130, &out));
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_P2P);
        ASSERT_STR_EQ(out.reason, "selected_p2p");
    } TEST_END
    return failures;
}

static int test_bsp_blocks_unsafe_mirror(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: mirror blocker is surfaced")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 130);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].blocked = true;
        snprintf(in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].blocker,
                 sizeof(in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].blocker),
                 "body_hash_mismatch");

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_BLOCKED);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT_STR_EQ(out.blocker, "body_hash_mismatch");
    } TEST_END
    return failures;
}

static int test_bsp_avoids_stale_dead_p2p(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: stale or unhealthy P2P is not selected")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        init_source(&in, BSP_SOURCE_P2P, true, false, 90);
        in.sources[BSP_SOURCE_P2P].timeouts = 5;

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_RECOVER);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT_STR_EQ(out.reason, "no_healthy_source");
        ASSERT(!out.sources[BSP_SOURCE_P2P].selectable);
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_P2P].selection_reason,
                      "unhealthy");
    } TEST_END
    return failures;
}

static int test_bsp_snapshot_can_outrank_mirror(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: snapshot outranks mirror fallback")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        init_source(&in, BSP_SOURCE_SNAPSHOT, true, true, 130);
        init_source(&in, BSP_SOURCE_ZCLASSICD_MIRROR, true, true, 140);
        in.sources[BSP_SOURCE_ZCLASSICD_MIRROR].authorized = true;

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_SNAPSHOT);
    } TEST_END
    return failures;
}

static int test_bsp_fresh_snapshot_outranks_stale_p2p(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: target-reaching snapshot outranks stale P2P")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.target_height = 150;
        in.best_header_height = 150;
        init_source(&in, BSP_SOURCE_P2P, true, true, 110);
        in.sources[BSP_SOURCE_P2P].lag = 40;
        init_source(&in, BSP_SOURCE_SNAPSHOT, true, true, 150);

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_SNAPSHOT);
        ASSERT(out.selected_score >
               out.sources[BSP_SOURCE_P2P].score);
        ASSERT(out.sources[BSP_SOURCE_P2P].score_target_lag_penalty == 25);
        ASSERT(out.sources[BSP_SOURCE_SNAPSHOT].score_target_lag_penalty == 0);
    } TEST_END
    return failures;
}

static int test_bsp_stale_p2p_can_still_advance_when_alone(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: stale P2P can still advance when alone")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.target_height = 150;
        in.best_header_height = 150;
        init_source(&in, BSP_SOURCE_P2P, true, true, 110);
        in.sources[BSP_SOURCE_P2P].lag = 40;

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_P2P);
        ASSERT(out.activation_allowed);
        ASSERT(out.sources[BSP_SOURCE_P2P].score > 0);
        ASSERT(out.sources[BSP_SOURCE_P2P].score_target_lag_penalty == 25);
    } TEST_END
    return failures;
}

static int test_bsp_unknown_height_source_is_not_selectable(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: unknown-height source is not selected")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        in.local_height = 120;
        in.best_header_height = 120;
        in.target_height = 120;
        init_source(&in, BSP_SOURCE_P2P, true, true, -1);

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_RECOVER);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT(!out.sources[BSP_SOURCE_P2P].selectable);
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_P2P].selection_reason,
                      "unknown_height");
    } TEST_END
    return failures;
}

static int test_bsp_projection_status_propagates(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: projection status propagates")
    {
        struct bsp_plan_input in = base_input();
        struct bsp_decision out;
        init_source(&in, BSP_SOURCE_P2P, true, true, 125);
        in.projection_height = 99;
        in.projection_lag = 21;
        in.projection_deferred = true;
        snprintf(in.projection_state, sizeof(in.projection_state),
                 "deferred");

        block_source_policy_plan(&in, &out);
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.projection_height == 99);
        ASSERT(out.projection_lag == 21);
        ASSERT(out.projection_deferred);
        ASSERT_STR_EQ(out.projection_state, "deferred");
    } TEST_END
    return failures;
}

static int test_bsp_snapshot_offer_helper_allows_valid_offer(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: snapshot offer helper allows valid offer")
    {
        struct bsp_decision out;
        ASSERT(block_source_policy_snapshot_offer_allowed(
            100, 10000, 10100, true, "manifest_ok", &out));
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_SNAPSHOT);
        ASSERT(out.activation_allowed);
        ASSERT_STR_EQ(out.reason, "selected_snapshot");
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_SNAPSHOT].reason,
                      "manifest_ok");
    } TEST_END
    return failures;
}

static int test_bsp_snapshot_offer_helper_blocks_invalid_offer(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: snapshot offer helper blocks invalid offer")
    {
        struct bsp_decision out;
        ASSERT(!block_source_policy_snapshot_offer_allowed(
            100, 10000, 10100, false, "weak_work", &out));
        ASSERT(out.result == BSP_DECISION_BLOCKED);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT_STR_EQ(out.reason, "source_blocked");
        ASSERT_STR_EQ(out.blocker, "weak_work");
    } TEST_END
    return failures;
}

static int test_bsp_local_header_refill_helper_records_retry(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: local header refill helper records retry")
    {
        struct bsp_decision out;
        ASSERT(block_source_policy_local_header_refill_needed(
            100, 101, 130, 2, 1, false, &out));
        ASSERT(out.result == BSP_DECISION_USE_SOURCE);
        ASSERT(out.selected_source == BSP_SOURCE_LOCAL_IMPORT);
        ASSERT_STR_EQ(out.reason, "selected_local_import");
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_LOCAL_IMPORT].reason,
                      "missing_height=101 eligible_peers=2 retry=1");
    } TEST_END
    return failures;
}

static int test_bsp_local_header_refill_helper_waits_for_peers(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: local header refill helper waits for eligible peers")
    {
        struct bsp_decision out;
        ASSERT(!block_source_policy_local_header_refill_needed(
            100, 101, 130, 0, 1, false, &out));
        ASSERT(out.result == BSP_DECISION_WAIT);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT_STR_EQ(out.reason, "local_retries_pending");
        ASSERT_STR_EQ(out.blocker, "local_recovery_gate");
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_LOCAL_IMPORT].selection_reason,
                      "unhealthy");
        ASSERT_STR_EQ(out.sources[BSP_SOURCE_LOCAL_IMPORT].reason,
                      "missing_height=101 eligible_peers=0 retry=1");
    } TEST_END
    return failures;
}

static int test_bsp_local_header_refill_helper_recovers_without_peers(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: local header refill helper recovers without peers")
    {
        struct bsp_decision out;
        ASSERT(block_source_policy_local_header_refill_needed(
            100, 101, 130, 0, 3, true, &out));
        ASSERT(out.result == BSP_DECISION_RECOVER);
        ASSERT(out.selected_source == BSP_SOURCE_NONE);
        ASSERT_STR_EQ(out.reason, "no_healthy_source");
    } TEST_END
    return failures;
}

static int test_bsp_dump_json_contract(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate JSON exposes authority and sources")
    {
        struct json_value root;
        const struct json_value *authority;
        const struct json_value *selected_trust;
        const struct json_value *sources;
        const struct json_value *initialized;
        const struct json_value *has_connman;
        const struct json_value *has_main_state;
        const struct json_value *has_node_db;
        const struct json_value *projection_height;
        const struct json_value *projection_lag;
        const struct json_value *projection_deferred;
        const struct json_value *projection_state;
        const struct json_value *projection_deferred_total;
        const struct json_value *last_projection_deferred_height;
        const struct json_value *last_projection_deferred_time;
        const struct json_value *last_projection_deferred_reason;
        const struct json_value *p2p;
        block_source_policy_reset_for_test();
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        initialized = json_get(&root, "initialized");
        has_connman = json_get(&root, "has_connman");
        has_main_state = json_get(&root, "has_main_state");
        has_node_db = json_get(&root, "has_node_db");
        projection_height = json_get(&root, "projection_height");
        projection_lag = json_get(&root, "projection_lag");
        projection_deferred = json_get(&root, "projection_deferred");
        projection_state = json_get(&root, "projection_state");
        projection_deferred_total =
            json_get(&root, "projection_deferred_total");
        last_projection_deferred_height =
            json_get(&root, "last_projection_deferred_height");
        last_projection_deferred_time =
            json_get(&root, "last_projection_deferred_time");
        last_projection_deferred_reason =
            json_get(&root, "last_projection_deferred_reason");
        authority = json_get(&root, "authority");
        selected_trust = json_get(&root, "selected_source_trust");
        sources = json_get(&root, "sources");
        ASSERT(initialized != NULL);
        ASSERT(has_connman != NULL);
        ASSERT(has_main_state != NULL);
        ASSERT(has_node_db != NULL);
        ASSERT(projection_height != NULL);
        ASSERT(projection_lag != NULL);
        ASSERT(projection_deferred != NULL);
        ASSERT(projection_state != NULL);
        ASSERT(projection_deferred_total != NULL);
        ASSERT(last_projection_deferred_height != NULL);
        ASSERT(last_projection_deferred_time != NULL);
        ASSERT(last_projection_deferred_reason != NULL);
        ASSERT(!json_get_bool(initialized));
        ASSERT(!json_get_bool(has_connman));
        ASSERT(!json_get_bool(has_main_state));
        ASSERT(!json_get_bool(has_node_db));
        ASSERT(json_get_int(projection_height) == -1);
        ASSERT(json_get_int(projection_lag) == -1);
        ASSERT(!json_get_bool(projection_deferred));
        ASSERT_STR_EQ(json_get_str(projection_state), "unknown");
        ASSERT(json_get_int(projection_deferred_total) == 0);
        ASSERT(json_get_int(last_projection_deferred_height) == 0);
        ASSERT(json_get_int(last_projection_deferred_time) == 0);
        ASSERT_STR_EQ(json_get_str(last_projection_deferred_reason), "");
        ASSERT(authority != NULL);
        ASSERT_STR_EQ(json_get_str(authority), "local_consensus_validation");
        ASSERT(selected_trust != NULL);
        ASSERT_STR_EQ(json_get_str(selected_trust), "none");
        ASSERT(sources != NULL);
        ASSERT(json_size(sources) == 4);
        p2p = find_source_json(sources, "p2p");
        ASSERT(p2p != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(p2p, "trust")),
                      "native_peer_validated");
        ASSERT(json_get(p2p, "selectable") != NULL);
        ASSERT(json_get(p2p, "selection_blocker") != NULL);
        ASSERT(json_get(p2p, "score_base") != NULL);
        ASSERT(json_get(p2p, "score_health") != NULL);
        ASSERT(json_get(p2p, "score_height") != NULL);
        ASSERT(json_get(p2p, "score_authorized") != NULL);
        ASSERT(json_get(p2p, "score_redundancy_bonus") != NULL);
        ASSERT(json_get(p2p, "score_target_lag_penalty") != NULL);
        ASSERT(json_get(p2p, "score_failure_penalty") != NULL);
        ASSERT(json_get(p2p, "score_mirror_gate_penalty") != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(find_source_json(sources,
                                                             "snapshot"),
                                            "trust")),
                      "native_snapshot_proof_validated");
        ASSERT_STR_EQ(json_get_str(json_get(find_source_json(sources,
                                                             "local_import"),
                                            "trust")),
                      "local_consensus_import");
        ASSERT_STR_EQ(json_get_str(json_get(find_source_json(
                                               sources,
                                               "zclassicd_mirror"),
                                            "trust")),
                      "bounded_advisory_fallback");
        json_free(&root);
    } TEST_END
    return failures;
}

static int test_bsp_dump_reports_projection_lag(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate reports projection lag")
    {
        struct node_db ndb;
        struct main_state ms;
        struct block_index tip;
        struct json_value root;
        struct db_block blk;
        uint8_t solution[] = {0x01, 0x02, 0x03};
        const struct json_value *projection_height;
        const struct json_value *projection_lag;
        const struct json_value *projection_deferred;
        const struct json_value *projection_state;

        ASSERT(node_db_open(&ndb, ":memory:"));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        main_state_init(&ms);
        tip.nHeight = 10;
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &tip));

        memset(&blk, 0, sizeof(blk));
        memset(blk.hash, 0xA5, sizeof(blk.hash));
        memset(blk.prev_hash, 0x5A, sizeof(blk.prev_hash));
        memset(blk.merkle_root, 0xC3, sizeof(blk.merkle_root));
        memset(blk.nonce, 0x3C, sizeof(blk.nonce));
        blk.height = 5;
        blk.version = 4;
        blk.time = 1700000000;
        blk.bits = 0x1d00ffff;
        blk.solution = solution;
        blk.solution_len = sizeof(solution);
        blk.status = 5;
        blk.file_num = 1;
        blk.data_pos = 8192;
        blk.num_tx = 1;
        ASSERT(db_block_save(&ndb, &blk));

        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, &ms, &ndb);
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        projection_height = json_get(&root, "projection_height");
        projection_lag = json_get(&root, "projection_lag");
        projection_deferred = json_get(&root, "projection_deferred");
        projection_state = json_get(&root, "projection_state");
        ASSERT(projection_height != NULL);
        ASSERT(projection_lag != NULL);
        ASSERT(projection_deferred != NULL);
        ASSERT(projection_state != NULL);
        ASSERT(json_get_int(projection_height) == 5);
        ASSERT(json_get_int(projection_lag) == 5);
        ASSERT(json_get_bool(projection_deferred));
        ASSERT_STR_EQ(json_get_str(projection_state), "deferred");
        json_free(&root);

        block_source_policy_reset_for_test();
        main_state_free(&ms);
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int test_bsp_projection_deferral_accounting(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: projection deferral accounting is stable")
    {
        struct json_value root;
        struct bsp_decision status;
        struct bsp_decision cached;
        const struct json_value *total;
        const struct json_value *height;
        const struct json_value *when;
        const struct json_value *reason;

        block_source_policy_reset_for_test();
        block_source_policy_note_projection_deferred(
            42, "consensus_path");

        memset(&status, 0, sizeof(status));
        block_source_policy_get_status(&status);
        ASSERT(status.projection_deferred_total == 1);
        ASSERT(status.last_projection_deferred_height == 42);
        ASSERT(status.last_projection_deferred_time > 0);
        ASSERT_STR_EQ(status.last_projection_deferred_reason,
                      "consensus_path");
        ASSERT(!block_source_policy_get_cached_status(&cached));

        memset(&status, 0, sizeof(status));
        ASSERT(!block_source_policy_peer_floor_recovery_needed(
            3, 2, 100, 100, &status));
        ASSERT(block_source_policy_get_cached_status(&cached));
        ASSERT(cached.result == status.result);
        ASSERT(cached.target_height == status.target_height);
        ASSERT(cached.projection_deferred_total == 1);
        ASSERT(cached.last_projection_deferred_height == 42);
        ASSERT_STR_EQ(cached.last_projection_deferred_reason,
                      "consensus_path");

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        total = json_get(&root, "projection_deferred_total");
        height = json_get(&root, "last_projection_deferred_height");
        when = json_get(&root, "last_projection_deferred_time");
        reason = json_get(&root, "last_projection_deferred_reason");
        ASSERT(total != NULL);
        ASSERT(height != NULL);
        ASSERT(when != NULL);
        ASSERT(reason != NULL);
        ASSERT(json_get_int(total) == 1);
        ASSERT(json_get_int(height) == 42);
        ASSERT(json_get_int(when) > 0);
        ASSERT_STR_EQ(json_get_str(reason), "consensus_path");
        json_free(&root);

        block_source_policy_reset_for_test();
    } TEST_END
    return failures;
}

static struct p2p_node *test_bsp_add_peer(struct connman *cm,
                                          unsigned char a,
                                          unsigned char b,
                                          unsigned char c,
                                          unsigned char d,
                                          enum peer_state state)
{
    struct net_address addr;
    net_address_init(&addr);
    unsigned char ip4[4] = {a, b, c, d};
    net_addr_set_ipv4(&addr.svc.addr, ip4);
    addr.svc.port = 8233;
    struct p2p_node *node = p2p_node_create(
        &cm->manager, ZCL_INVALID_SOCKET, &addr, "cac-peer", false);
    if (!node)
        return NULL;
    node->state = state;
    if (state >= PEER_HANDSHAKE_COMPLETE)
        node->services = NODE_NETWORK;
    node->starting_height = 130;
    cm->manager.nodes[cm->manager.num_nodes++] = node;
    return node;
}

static int test_bsp_dump_populates_p2p_diversity(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate populates P2P diversity")
    {
        struct connman cm;
        struct json_value root;
        struct p2p_node *inbound_peer;
        const struct json_value *sources;
        const struct json_value *p2p;
        const struct json_value *reason;
        const struct json_value *healthy;
        const struct json_value *inbound;
        const struct json_value *inbound_healthy;
        const struct json_value *total_healthy;
        const struct json_value *connecting;
        const struct json_value *groups;
        const struct json_value *healthy_groups;
        const struct json_value *backoff;
        const struct json_value *tcp_failures;
        const struct json_value *protocol_failures;

        memset(&cm, 0, sizeof(cm));
        net_manager_init(&cm.manager);
        cm.manager.nodes = zcl_calloc(4, sizeof(*cm.manager.nodes),
                                      "bsp_test_nodes");
        cm.manager.nodes_cap = 4;
        cm.num_addnodes = 2;
        cm.addnode_backoff_sec[0] = 120;
        cm.addnode_backoff_sec[1] = 300;
        cm.addnode_tcp_failures[0] = 2;
        cm.addnode_protocol_failures[1] = 1;

        ASSERT(test_bsp_add_peer(&cm, 10, 1, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);
        ASSERT(test_bsp_add_peer(&cm, 10, 1, 0, 2,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);
        ASSERT(test_bsp_add_peer(&cm, 172, 16, 0, 1,
                                 PEER_CONNECTING) != NULL);
        inbound_peer = test_bsp_add_peer(&cm, 203, 0, 113, 1,
                                         PEER_HANDSHAKE_COMPLETE);
        ASSERT(inbound_peer != NULL);
        inbound_peer->inbound = true;

        block_source_policy_reset_for_test();
        block_source_policy_init(&cm, NULL, NULL);
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        p2p = json_at(sources, 0);
        ASSERT(p2p != NULL);
        reason = json_get(p2p, "reason");
        ASSERT(reason != NULL);
        healthy = json_get(p2p, "healthy_peers");
        inbound = json_get(p2p, "inbound_total");
        inbound_healthy = json_get(p2p, "inbound_healthy_peers");
        total_healthy = json_get(p2p, "total_healthy_peers");
        connecting = json_get(p2p, "connecting_peers");
        groups = json_get(p2p, "peer_groups");
        healthy_groups = json_get(p2p, "healthy_peer_groups");
        backoff = json_get(p2p, "addnode_backoff_active");
        tcp_failures = json_get(p2p, "addnode_tcp_failures");
        protocol_failures = json_get(p2p, "addnode_protocol_failures");
        ASSERT(healthy != NULL);
        ASSERT(inbound != NULL);
        ASSERT(inbound_healthy != NULL);
        ASSERT(total_healthy != NULL);
        ASSERT(connecting != NULL);
        ASSERT(groups != NULL);
        ASSERT(healthy_groups != NULL);
        ASSERT(backoff != NULL);
        ASSERT(tcp_failures != NULL);
        ASSERT(protocol_failures != NULL);
        ASSERT(json_get_int(healthy) == 2);
        ASSERT(json_get_int(inbound) == 1);
        ASSERT(json_get_int(inbound_healthy) == 1);
        ASSERT(json_get_int(total_healthy) == 3);
        ASSERT(json_get_int(connecting) == 1);
        ASSERT(json_get_int(groups) == 2);
        ASSERT(json_get_int(healthy_groups) == 1);
        ASSERT(json_get_int(backoff) == 2);
        ASSERT(json_get_int(tcp_failures) == 2);
        ASSERT(json_get_int(protocol_failures) == 1);
        ASSERT(strstr(json_get_str(reason), "healthy=2") != NULL);
        ASSERT(strstr(json_get_str(reason), "inbound_healthy=1") != NULL);
        ASSERT(strstr(json_get_str(reason), "total_healthy=3") != NULL);
        ASSERT(strstr(json_get_str(reason), "connecting=1") != NULL);
        ASSERT(strstr(json_get_str(reason), "groups=2") != NULL);
        ASSERT(strstr(json_get_str(reason), "healthy_groups=1") != NULL);
        ASSERT(strstr(json_get_str(reason), "backoff=2/2") != NULL);
        ASSERT(strstr(json_get_str(reason), "tcp_fail=2") != NULL);
        ASSERT(strstr(json_get_str(reason), "proto_fail=1") != NULL);
        json_free(&root);

        block_source_policy_reset_for_test();
        net_manager_free(&cm.manager);
    } TEST_END
    return failures;
}

static int test_bsp_selects_viable_caught_up_p2p(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: caught-up diverse P2P beats mirror with two peers")
    {
        struct connman cm;
        struct main_state ms;
        struct block_index tip;
        struct block_index best_header;
        struct legacy_mirror_sync_stats stats;
        struct json_value root;
        const struct json_value *sources;
        const struct json_value *p2p;
        const struct json_value *selected;
        const struct json_value *healthy;
        const struct json_value *healthy_groups;
        const struct json_value *selection_blocker;
        const struct json_value *reason;

        memset(&cm, 0, sizeof(cm));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(&stats, 0, sizeof(stats));
        net_manager_init(&cm.manager);
        main_state_init(&ms);
        cm.manager.nodes = zcl_calloc(4, sizeof(*cm.manager.nodes),
                                      "bsp_test_viable_p2p_nodes");
        cm.manager.nodes_cap = 4;
        tip.nHeight = 130;
        best_header.nHeight = 130;
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &tip));
        ms.pindex_best_header = &best_header;

        ASSERT(test_bsp_add_peer(&cm, 10, 1, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);
        ASSERT(test_bsp_add_peer(&cm, 172, 16, 0, 2,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);

        legacy_mirror_sync_reset_for_test();
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.legacy_height = 130;
        stats.target_height = 130;
        legacy_mirror_sync_test_set_stats(&stats, &ms);

        block_source_policy_reset_for_test();
        block_source_policy_init(&cm, &ms, NULL);
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        selected = json_get(&root, "selected_source");
        sources = json_get(&root, "sources");
        ASSERT(selected != NULL);
        ASSERT(sources != NULL);
        ASSERT_STR_EQ(json_get_str(selected), "p2p");
        p2p = find_source_json(sources, "p2p");
        ASSERT(p2p != NULL);
        healthy = json_get(p2p, "healthy");
        healthy_groups = json_get(p2p, "healthy_peer_groups");
        selection_blocker = json_get(p2p, "selection_blocker");
        reason = json_get(p2p, "reason");
        ASSERT(healthy != NULL);
        ASSERT(healthy_groups != NULL);
        ASSERT(selection_blocker != NULL);
        ASSERT(reason != NULL);
        ASSERT(json_get_bool(healthy));
        ASSERT(json_get_int(healthy_groups) == 2);
        ASSERT_STR_EQ(json_get_str(selection_blocker), "");
        ASSERT(strstr(json_get_str(reason), "ideal_floor=3") != NULL);
        json_free(&root);

        block_source_policy_reset_for_test();
        legacy_mirror_sync_reset_for_test();
        main_state_free(&ms);
        net_manager_free(&cm.manager);
    } TEST_END
    return failures;
}

static int test_bsp_inbound_assists_near_tip_p2p(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: inbound handshakes assist near-tip P2P")
    {
        struct connman cm;
        struct main_state ms;
        struct block_index tip;
        struct block_index best_header;
        struct json_value root;
        struct p2p_node *inbound_peer;
        const struct json_value *sources;
        const struct json_value *p2p;
        const struct json_value *selected;
        const struct json_value *healthy;
        const struct json_value *inbound_healthy;
        const struct json_value *lag;
        const struct json_value *selection_blocker;
        const struct json_value *reason;

        memset(&cm, 0, sizeof(cm));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        net_manager_init(&cm.manager);
        main_state_init(&ms);
        cm.manager.nodes = zcl_calloc(3, sizeof(*cm.manager.nodes),
                                      "bsp_test_inbound_assist_nodes");
        cm.manager.nodes_cap = 3;
        tip.nHeight = 131;
        best_header.nHeight = 131;
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &tip));
        ms.pindex_best_header = &best_header;

        ASSERT(test_bsp_add_peer(&cm, 10, 1, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);
        ASSERT(test_bsp_add_peer(&cm, 172, 16, 0, 2,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);
        inbound_peer = test_bsp_add_peer(&cm, 203, 0, 113, 3,
                                         PEER_HANDSHAKE_COMPLETE);
        ASSERT(inbound_peer != NULL);
        inbound_peer->inbound = true;

        block_source_policy_reset_for_test();
        block_source_policy_init(&cm, &ms, NULL);
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        selected = json_get(&root, "selected_source");
        sources = json_get(&root, "sources");
        ASSERT(selected != NULL);
        ASSERT(sources != NULL);
        ASSERT_STR_EQ(json_get_str(selected), "p2p");
        p2p = find_source_json(sources, "p2p");
        ASSERT(p2p != NULL);
        healthy = json_get(p2p, "healthy");
        inbound_healthy = json_get(p2p, "inbound_healthy_peers");
        lag = json_get(p2p, "lag");
        selection_blocker = json_get(p2p, "selection_blocker");
        reason = json_get(p2p, "reason");
        ASSERT(healthy != NULL);
        ASSERT(inbound_healthy != NULL);
        ASSERT(lag != NULL);
        ASSERT(selection_blocker != NULL);
        ASSERT(reason != NULL);
        ASSERT(json_get_bool(healthy));
        ASSERT(json_get_int(inbound_healthy) == 1);
        ASSERT(json_get_int(lag) == 1);
        ASSERT_STR_EQ(json_get_str(selection_blocker), "");
        ASSERT(strstr(json_get_str(reason), "inbound_healthy=1") != NULL);
        json_free(&root);

        block_source_policy_reset_for_test();
        main_state_free(&ms);
        net_manager_free(&cm.manager);
    } TEST_END
    return failures;
}

static int test_bsp_dump_explains_stale_p2p_height(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate explains stale P2P height")
    {
        struct connman cm;
        struct main_state ms;
        struct block_index tip;
        struct block_index best_header;
        struct json_value root;
        const struct json_value *sources;
        const struct json_value *p2p;
        const struct json_value *lag;
        const struct json_value *reason;

        memset(&cm, 0, sizeof(cm));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        net_manager_init(&cm.manager);
        main_state_init(&ms);
        cm.manager.nodes = zcl_calloc(4, sizeof(*cm.manager.nodes),
                                      "bsp_test_stale_nodes");
        cm.manager.nodes_cap = 4;
        tip.nHeight = 100;
        best_header.nHeight = 150;
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &tip));
        ms.pindex_best_header = &best_header;

        ASSERT(test_bsp_add_peer(&cm, 10, 1, 0, 1,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);
        ASSERT(test_bsp_add_peer(&cm, 172, 16, 0, 2,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);
        ASSERT(test_bsp_add_peer(&cm, 198, 51, 100, 3,
                                 PEER_HANDSHAKE_COMPLETE) != NULL);

        block_source_policy_reset_for_test();
        block_source_policy_init(&cm, &ms, NULL);
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        p2p = find_source_json(sources, "p2p");
        ASSERT(p2p != NULL);
        lag = json_get(p2p, "lag");
        reason = json_get(p2p, "reason");
        ASSERT(lag != NULL);
        ASSERT(reason != NULL);
        ASSERT(json_get_int(lag) == 20);
        ASSERT(strstr(json_get_str(reason), "peer_height=130") != NULL);
        ASSERT(strstr(json_get_str(reason), "header_height=150") != NULL);
        ASSERT(strstr(json_get_str(reason), "stale_lag=20") != NULL);
        json_free(&root);

        block_source_policy_reset_for_test();
        main_state_free(&ms);
        net_manager_free(&cm.manager);
    } TEST_END
    return failures;
}

static int test_bsp_dump_populates_live_snapshot_source(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate populates live snapshot source")
    {
        struct snapshot_sync_service svc;
        struct app_runtime_context runtime;
        struct json_value root;
        const struct json_value *sources;
        const struct json_value *snapshot;
        const struct json_value *source_name;
        const struct json_value *available;
        const struct json_value *reason;
        const struct json_value *state;
        const struct json_value *serving_peer_id;
        const struct json_value *progress_total;
        uint8_t root_hash[32] = {1};
        uint8_t block_hash[32] = {2};

        memset(&runtime, 0, sizeof(runtime));
        snapsync_init(&svc, NULL);
        ASSERT(snapsync_accept_offer(&svc, 10000, 1234, root_hash,
                                     root_hash, block_hash, 77).ok);
        runtime.snapshot_sync = &svc;
        app_runtime_set_current(&runtime);

        block_source_policy_reset_for_test();
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        snapshot = json_at(sources, 1);
        ASSERT(snapshot != NULL);
        source_name = json_get(snapshot, "source");
        available = json_get(snapshot, "available");
        reason = json_get(snapshot, "reason");
        state = json_get(snapshot, "state");
        serving_peer_id = json_get(snapshot, "serving_peer_id");
        progress_total = json_get(snapshot, "progress_total");
        ASSERT(source_name != NULL);
        ASSERT(available != NULL);
        ASSERT(reason != NULL);
        ASSERT(state != NULL);
        ASSERT(serving_peer_id != NULL);
        ASSERT(progress_total != NULL);
        ASSERT_STR_EQ(json_get_str(source_name), "snapshot");
        ASSERT(json_get_bool(available));
        ASSERT_STR_EQ(json_get_str(state), "negotiating");
        ASSERT(json_get_int(serving_peer_id) == 77);
        ASSERT(json_get_int(progress_total) == 1234);
        ASSERT(strstr(json_get_str(reason), "state=negotiating") != NULL);
        json_free(&root);

        app_runtime_set_current(NULL);
        snapsync_reset(&svc);
    } TEST_END
    return failures;
}

static int test_bsp_dump_populates_local_import_recovery(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate populates local import recovery")
    {
        struct connman cm;
        struct download_manager dm;
        struct main_state ms;
        struct block_index tip;
        struct p2p_node p1;
        struct p2p_node *peers[1];
        struct json_value root;
        const struct json_value *sources;
        const struct json_value *local_import;
        const struct json_value *state;
        const struct json_value *retry_count;
        const struct json_value *distinct_peer_count;
        const struct json_value *progress_current;
        const struct json_value *progress_total;

        memset(&cm, 0, sizeof(cm));
        memset(&dm, 0, sizeof(dm));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&p1, 0, sizeof(p1));
        zcl_mutex_init(&cm.manager.cs_nodes);
        zcl_mutex_init(&dm.cs);
        zcl_mutex_init(&ms.cs_main);

        sync_monitor_init();
        condition_engine_reset_for_testing();
        local_header_refill_needed_test_reset();
        sync_set_state(SYNC_IDLE, "cac local import reset");
        sync_set_state(SYNC_HEADERS_DOWNLOAD, "cac local import setup");
        sync_set_state(SYNC_BLOCKS_DOWNLOAD, "cac next child missing");

        tip.nHeight = 100;
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &tip));

        p1.id = 1;
        p1.starting_height = 130;
        p1.state = PEER_ACTIVE;
        p1.services = NODE_NETWORK;
        peers[0] = &p1;
        cm.manager.nodes = peers;
        cm.manager.num_nodes = 1;

        block_source_policy_reset_for_test();
        block_source_policy_init(&cm, &ms, NULL);
        sync_monitor_set_context(&cm, &dm, &ms);
        condition_engine_set_main_state(&ms);
        register_local_header_refill_needed();
        condition_engine_tick();
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        local_import = json_at(sources, 2);
        ASSERT(local_import != NULL);
        state = json_get(local_import, "state");
        retry_count = json_get(local_import, "retry_count");
        distinct_peer_count = json_get(local_import, "distinct_peer_count");
        progress_current = json_get(local_import, "progress_current");
        progress_total = json_get(local_import, "progress_total");
        ASSERT(state != NULL);
        ASSERT(retry_count != NULL);
        ASSERT(distinct_peer_count != NULL);
        ASSERT(progress_current != NULL);
        ASSERT(progress_total != NULL);
        ASSERT_STR_EQ(json_get_str(state), "next-child-missing");
        ASSERT(json_get_int(retry_count) == 1);
        ASSERT(json_get_int(distinct_peer_count) == 1);
        ASSERT(json_get_int(progress_current) == 100);
        ASSERT(json_get_int(progress_total) == 101);
        json_free(&root);

        sync_monitor_set_context(NULL, NULL, NULL);
        cm.manager.nodes = NULL;
        cm.manager.num_nodes = 0;
        block_source_policy_reset_for_test();
        zcl_mutex_destroy(&dm.cs);
        zcl_mutex_destroy(&cm.manager.cs_nodes);
        zcl_mutex_destroy(&ms.cs_main);
    } TEST_END
    return failures;
}

static int test_bsp_dump_populates_live_mirror_source(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate populates live mirror source")
    {
        struct main_state ms;
        struct block_index tip;
        struct legacy_mirror_sync_stats stats;
        struct json_value root;
        const struct json_value *sources;
        const struct json_value *mirror;
        const struct json_value *state;
        const struct json_value *lag;
        const struct json_value *lag_known;
        const struct json_value *lag_valid;
        const struct json_value *lag_observed;
        const struct json_value *candidate_lag_known;
        const struct json_value *candidate_lag_valid;
        const struct json_value *candidate_lag_observed;
        const struct json_value *progress_current;
        const struct json_value *progress_total;
        const struct json_value *blocked;
        const struct json_value *blocker;
        const struct json_value *blocked_class;
        const struct json_value *healthy;
        const struct json_value *available;
        const struct json_value *authorized;
        const struct json_value *height;
        const struct json_value *reason;
        const struct json_value *selection_blocker;

        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&stats, 0, sizeof(stats));
        zcl_mutex_init(&ms.cs_main);
        tip.nHeight = 500;
        ASSERT(active_chain_move_window_tip(&ms.chain_active, &tip));

        sync_monitor_init();
        legacy_mirror_sync_reset_for_test();
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.legacy_height = 501;
        stats.target_height = 501;
        stats.blocks_applied = 42;
        legacy_mirror_sync_test_set_stats(&stats, &ms);

        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, &ms, NULL);
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        mirror = json_at(sources, 3);
        ASSERT(mirror != NULL);
        state = json_get(mirror, "state");
        lag = json_get(mirror, "lag");
        lag_known = json_get(mirror, "lag_known");
        lag_valid = json_get(mirror, "lag_valid");
        lag_observed = json_get(mirror, "lag_observed");
        candidate_lag_known = json_get(mirror, "candidate_lag_known");
        candidate_lag_valid = json_get(mirror, "candidate_lag_valid");
        candidate_lag_observed =
            json_get(mirror, "candidate_lag_observed");
        progress_current = json_get(mirror, "progress_current");
        progress_total = json_get(mirror, "progress_total");
        ASSERT(state != NULL);
        ASSERT(lag != NULL);
        ASSERT(lag_known != NULL);
        ASSERT(lag_valid != NULL);
        ASSERT(lag_observed != NULL);
        ASSERT(candidate_lag_known != NULL);
        ASSERT(candidate_lag_valid != NULL);
        ASSERT(candidate_lag_observed != NULL);
        ASSERT(progress_current != NULL);
        ASSERT(progress_total != NULL);
        ASSERT_STR_EQ(json_get_str(state), "healthy");
        ASSERT(json_get_int(lag) == 1);
        ASSERT(json_get_bool(lag_known));
        ASSERT(json_get_bool(lag_valid));
        ASSERT(json_get_int(lag_observed) == 1);
        ASSERT(json_get_bool(candidate_lag_known));
        ASSERT(json_get_bool(candidate_lag_valid));
        ASSERT(json_get_int(candidate_lag_observed) == 1);
        ASSERT(json_get_int(progress_current) == 42);
        ASSERT(json_get_int(progress_total) == 501);
        json_free(&root);

        mirror_consensus_set_enabled(true);
        mirror_consensus_record_blocker("body-hash-mismatch");
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "body-hash-mismatch");
        legacy_mirror_sync_test_set_stats(&stats, &ms);

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        mirror = json_at(sources, 3);
        ASSERT(mirror != NULL);
        blocked = json_get(mirror, "blocked");
        blocker = json_get(mirror, "blocker");
        blocked_class = json_get(mirror, "blocked_class");
        healthy = json_get(mirror, "healthy");
        ASSERT(blocked != NULL);
        ASSERT(blocker != NULL);
        ASSERT(blocked_class != NULL);
        ASSERT(healthy != NULL);
        ASSERT(json_get_bool(blocked));
        ASSERT(!json_get_bool(healthy));
        ASSERT_STR_EQ(json_get_str(blocker), "body-hash-mismatch");
        ASSERT_STR_EQ(json_get_str(blocked_class), "permanent");
        json_free(&root);

        mirror_consensus_reset_for_test();
        mirror_consensus_set_enabled(true);
        mirror_consensus_record_blocker("hash-disagreement");
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "hash-disagreement");
        legacy_mirror_sync_test_set_stats(&stats, &ms);

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        mirror = json_at(sources, 3);
        ASSERT(mirror != NULL);
        blocked = json_get(mirror, "blocked");
        blocker = json_get(mirror, "blocker");
        blocked_class = json_get(mirror, "blocked_class");
        ASSERT(blocked != NULL);
        ASSERT(blocker != NULL);
        ASSERT(blocked_class != NULL);
        ASSERT(json_get_bool(blocked));
        ASSERT_STR_EQ(json_get_str(blocker), "hash-disagreement");
        ASSERT_STR_EQ(json_get_str(blocked_class), "transient");
        json_free(&root);

        mirror_consensus_reset_for_test();
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = false;
        stats.legacy_height = 0;
        stats.target_height = 0;
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "rpc-unreachable");
        legacy_mirror_sync_test_set_stats(&stats, &ms);

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        sources = json_get(&root, "sources");
        ASSERT(sources != NULL);
        mirror = json_at(sources, 3);
        ASSERT(mirror != NULL);
        available = json_get(mirror, "available");
        healthy = json_get(mirror, "healthy");
        authorized = json_get(mirror, "authorized");
        height = json_get(mirror, "height");
        lag = json_get(mirror, "lag");
        lag_known = json_get(mirror, "lag_known");
        lag_valid = json_get(mirror, "lag_valid");
        lag_observed = json_get(mirror, "lag_observed");
        candidate_lag_known = json_get(mirror, "candidate_lag_known");
        candidate_lag_valid = json_get(mirror, "candidate_lag_valid");
        candidate_lag_observed =
            json_get(mirror, "candidate_lag_observed");
        reason = json_get(mirror, "reason");
        selection_blocker = json_get(mirror, "selection_blocker");
        ASSERT(available != NULL);
        ASSERT(healthy != NULL);
        ASSERT(authorized != NULL);
        ASSERT(height != NULL);
        ASSERT(lag != NULL);
        ASSERT(lag_known != NULL);
        ASSERT(lag_valid != NULL);
        ASSERT(lag_observed != NULL);
        ASSERT(candidate_lag_known != NULL);
        ASSERT(candidate_lag_valid != NULL);
        ASSERT(candidate_lag_observed != NULL);
        ASSERT(reason != NULL);
        ASSERT(selection_blocker != NULL);
        ASSERT(!json_get_bool(available));
        ASSERT(!json_get_bool(healthy));
        ASSERT(!json_get_bool(authorized));
        ASSERT(json_get_int(height) == -1);
        ASSERT(json_get_int(lag) == -1);
        ASSERT(!json_get_bool(lag_known));
        ASSERT(!json_get_bool(lag_valid));
        ASSERT(json_is_null(lag_observed));
        ASSERT(!json_get_bool(candidate_lag_known));
        ASSERT(!json_get_bool(candidate_lag_valid));
        ASSERT(json_is_null(candidate_lag_observed));
        ASSERT_STR_EQ(json_get_str(selection_blocker), "unavailable");
        ASSERT(strstr(json_get_str(reason), "lag=unknown") != NULL);
        json_free(&root);

        block_source_policy_reset_for_test();
        mirror_consensus_reset_for_test();
        legacy_mirror_sync_reset_for_test();
    } TEST_END
    return failures;
}

static int test_bsp_dump_records_live_decision(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate retains last live decision")
    {
        struct json_value root;
        const struct json_value *total;
        const struct json_value *has_last;
        const struct json_value *last;
        const struct json_value *op;
        const struct json_value *decision;
        const struct json_value *reason;

        block_source_policy_reset_for_test();
        ASSERT(block_source_policy_peer_floor_recovery_needed(
            0, 2, 100, 120, NULL));

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        total = json_get(&root, "decisions_total");
        has_last = json_get(&root, "has_last_decision");
        last = json_get(&root, "last_decision");
        ASSERT(total != NULL);
        ASSERT(json_get_int(total) == 1);
        ASSERT(has_last != NULL);
        ASSERT(json_get_bool(has_last));
        ASSERT(last != NULL);
        op = json_get(last, "op");
        decision = json_get(last, "decision");
        reason = json_get(last, "reason");
        ASSERT(op != NULL);
        ASSERT(decision != NULL);
        ASSERT(reason != NULL);
        ASSERT_STR_EQ(json_get_str(op), "peer_floor");
        ASSERT_STR_EQ(json_get_str(decision), "recover");
        ASSERT_STR_EQ(json_get_str(reason), "no_healthy_source");
        json_free(&root);
    } TEST_END
    return failures;
}

static int test_bsp_dump_records_peer_floor_decision(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate retains peer floor decision")
    {
        struct json_value root;
        const struct json_value *total;
        const struct json_value *last;
        const struct json_value *op;
        const struct json_value *decision;
        const struct json_value *sources;
        const struct json_value *p2p;
        const struct json_value *reason;
        const struct json_value *blocker;
        const struct json_value *selectable;
        const struct json_value *selection_blocker;
        const struct json_value *score_base;
        const struct json_value *score_failure_penalty;

        block_source_policy_reset_for_test();
        ASSERT(block_source_policy_peer_floor_recovery_needed(
            0, 3, 100, 130, NULL));

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        total = json_get(&root, "decisions_total");
        last = json_get(&root, "last_decision");
        ASSERT(total != NULL);
        ASSERT(json_get_int(total) == 1);
        ASSERT(last != NULL);
        op = json_get(last, "op");
        decision = json_get(last, "decision");
        sources = json_get(last, "sources");
        ASSERT(op != NULL);
        ASSERT(decision != NULL);
        ASSERT(sources != NULL);
        ASSERT_STR_EQ(json_get_str(op), "peer_floor");
        ASSERT_STR_EQ(json_get_str(decision), "recover");
        p2p = find_source_json(sources, "p2p");
        ASSERT(p2p != NULL);
        reason = json_get(p2p, "reason");
        blocker = json_get(p2p, "blocker");
        selectable = json_get(p2p, "selectable");
        selection_blocker = json_get(p2p, "selection_blocker");
        score_base = json_get(p2p, "score_base");
        score_failure_penalty = json_get(p2p, "score_failure_penalty");
        ASSERT(reason != NULL);
        ASSERT(blocker != NULL);
        ASSERT(selectable != NULL);
        ASSERT(selection_blocker != NULL);
        ASSERT(score_base != NULL);
        ASSERT(score_failure_penalty != NULL);
        ASSERT_STR_EQ(json_get_str(reason),
                      "healthy_outbound=0 min_healthy=3");
        ASSERT_STR_EQ(json_get_str(blocker), "peer_floor");
        ASSERT(!json_get_bool(selectable));
        ASSERT_STR_EQ(json_get_str(selection_blocker), "unavailable");
        json_free(&root);
    } TEST_END
    return failures;
}

static int test_bsp_dump_records_snapshot_offer_decision(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate retains snapshot offer decision")
    {
        struct json_value root;
        const struct json_value *last;
        const struct json_value *op;
        const struct json_value *source;

        block_source_policy_reset_for_test();
        ASSERT(block_source_policy_snapshot_offer_allowed(
            100, 10000, 10100, true, "manifest_ok", NULL));

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        last = json_get(&root, "last_decision");
        ASSERT(last != NULL);
        op = json_get(last, "op");
        source = json_get(last, "selected_source");
        ASSERT(op != NULL);
        ASSERT(source != NULL);
        ASSERT_STR_EQ(json_get_str(op), "snapshot_offer");
        ASSERT_STR_EQ(json_get_str(source), "snapshot");
        json_free(&root);
    } TEST_END
    return failures;
}

static int test_bsp_decision_event_contract(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: decision events expose authority and trust")
    {
        char buf[4096];
        size_t len;

        event_log_init();
        block_source_policy_reset_for_test();
        ASSERT(block_source_policy_snapshot_offer_allowed(
            100, 10000, 10100, true, "manifest_ok", NULL));

        len = event_dump_json(buf, sizeof(buf), 8);
        ASSERT(len > 0);
        ASSERT(len < sizeof(buf));
        buf[len] = '\0';

        ASSERT(strstr(buf, "chain.advance_decision") != NULL);
        ASSERT(strstr(buf, "op=snapshot_offer") != NULL);
        ASSERT(strstr(buf, "authority=local_consensus_validation") != NULL);
        ASSERT(strstr(buf, "source=snapshot") != NULL);
        ASSERT(strstr(buf, "trust=native_snapshot_proof_validated") != NULL);
        ASSERT(strstr(buf, "decision=use_source") != NULL);
        ASSERT(strstr(buf, "score=") != NULL);
        ASSERT(strstr(buf, "reason=selected_snapshot") != NULL);
        ASSERT(strstr(buf, "lh=100") != NULL);
        ASSERT(strstr(buf, "th=10100") != NULL);
        ASSERT(strstr(buf, "sh=10000") != NULL);
        ASSERT(strstr(buf, "sel=true") != NULL);
        ASSERT(strstr(buf, "sb=-") != NULL);
    } TEST_END
    return failures;
}

static int test_bsp_peer_floor_event_explains_no_source(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: peer floor event explains no selected source")
    {
        char buf[4096];
        size_t len;

        event_log_init();
        block_source_policy_reset_for_test();
        ASSERT(block_source_policy_peer_floor_recovery_needed(
            0, 3, 100, 130, NULL));

        len = event_dump_json(buf, sizeof(buf), 8);
        ASSERT(len > 0);
        ASSERT(len < sizeof(buf));
        buf[len] = '\0';

        ASSERT(strstr(buf, "chain.advance_decision") != NULL);
        ASSERT(strstr(buf, "op=peer_floor") != NULL);
        ASSERT(strstr(buf, "ok=true") != NULL);
        ASSERT(strstr(buf, "authority=local_consensus_validation") != NULL);
        ASSERT(strstr(buf, "source=none") != NULL);
        ASSERT(strstr(buf, "trust=none") != NULL);
        ASSERT(strstr(buf, "decision=recover") != NULL);
        ASSERT(strstr(buf, "score=-1000") != NULL);
        ASSERT(strstr(buf, "reason=no_healthy_source") != NULL);
        ASSERT(strstr(buf, "lh=100") != NULL);
        ASSERT(strstr(buf, "th=130") != NULL);
        ASSERT(strstr(buf, "sel=false") != NULL);
        ASSERT(strstr(buf, "sb=-") != NULL);
        ASSERT(strstr(buf, "healthy=0") != NULL);
        ASSERT(strstr(buf, "min=3") != NULL);
        ASSERT(strstr(buf, "peer=130") != NULL);
        ASSERT(strstr(buf, "p2psb=unavailable") != NULL);
    } TEST_END
    return failures;
}

static int test_bsp_dump_records_local_header_refill_decision(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: dumpstate retains local header refill decision")
    {
        struct json_value root;
        const struct json_value *last;
        const struct json_value *op;
        const struct json_value *source;

        block_source_policy_reset_for_test();
        ASSERT(block_source_policy_local_header_refill_needed(
            100, 101, 130, 1, 1, false, NULL));

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        last = json_get(&root, "last_decision");
        ASSERT(last != NULL);
        op = json_get(last, "op");
        source = json_get(last, "selected_source");
        ASSERT(op != NULL);
        ASSERT(source != NULL);
        ASSERT_STR_EQ(json_get_str(op), "local_header_refill");
        ASSERT_STR_EQ(json_get_str(source), "local_import");
        json_free(&root);
    } TEST_END
    return failures;
}

static int test_bsp_restores_last_decision_from_node_state(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: restores last decision from node_state")
    {
        struct node_db ndb;
        struct json_value root;
        const struct json_value *last;
        const struct json_value *total;
        const struct json_value *op;
        const struct json_value *time_v;
        const struct json_value *source;
        const struct json_value *trust;
        const struct json_value *authority;
        const struct json_value *activation;
        const struct json_value *mirror;
        const struct json_value *score;
        const struct json_value *source_state;
        const struct json_value *source_reason;
        const struct json_value *source_height;
        const struct json_value *source_selectable;
        const struct json_value *source_selection_blocker;
        const struct json_value *source_score_base;
        const struct json_value *source_score_redundancy_bonus;
        const struct json_value *source_score_target_lag_penalty;
        const struct json_value *source_score_failure_penalty;
        const struct json_value *source_healthy;
        const struct json_value *source_available;

        ASSERT(node_db_open(&ndb, ":memory:"));
        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, NULL, &ndb);
        ASSERT(block_source_policy_snapshot_offer_allowed(
            100, 10000, 10100, true, "manifest_ok", NULL));

        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, NULL, &ndb);

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        total = json_get(&root, "decisions_total");
        last = json_get(&root, "last_decision");
        ASSERT(total != NULL);
        ASSERT(json_get_int(total) == 1);
        ASSERT(last != NULL);
        op = json_get(last, "op");
        time_v = json_get(last, "time");
        source = json_get(last, "selected_source");
        trust = json_get(last, "selected_source_trust");
        authority = json_get(last, "authority");
        activation = json_get(last, "activation_allowed");
        mirror = json_get(last, "mirror_fallback_allowed");
        score = json_get(last, "selected_score");
        source_state = json_get(last, "selected_source_state");
        source_reason = json_get(last, "selected_source_reason");
        source_height = json_get(last, "selected_source_height");
        source_selectable = json_get(last, "selected_source_selectable");
        source_selection_blocker =
            json_get(last, "selected_source_selection_blocker");
        source_score_base = json_get(last, "selected_source_score_base");
        source_score_redundancy_bonus =
            json_get(last, "selected_source_score_redundancy_bonus");
        source_score_target_lag_penalty =
            json_get(last, "selected_source_score_target_lag_penalty");
        source_score_failure_penalty =
            json_get(last, "selected_source_score_failure_penalty");
        source_healthy = json_get(last, "selected_source_healthy");
        source_available = json_get(last, "selected_source_available");
        ASSERT(op != NULL);
        ASSERT(source != NULL);
        ASSERT(trust != NULL);
        ASSERT(authority != NULL);
        ASSERT(activation != NULL);
        ASSERT(mirror != NULL);
        ASSERT(score != NULL);
        ASSERT(source_state != NULL);
        ASSERT(source_reason != NULL);
        ASSERT(source_height != NULL);
        ASSERT(source_selectable != NULL);
        ASSERT(source_selection_blocker != NULL);
        ASSERT(source_score_base != NULL);
        ASSERT(source_score_redundancy_bonus != NULL);
        ASSERT(source_score_target_lag_penalty != NULL);
        ASSERT(source_score_failure_penalty != NULL);
        ASSERT(source_healthy != NULL);
        ASSERT(source_available != NULL);
        ASSERT_STR_EQ(json_get_str(op), "snapshot_offer");
        ASSERT(time_v != NULL);
        ASSERT(json_get_int(time_v) > 0);
        ASSERT_STR_EQ(json_get_str(source), "snapshot");
        ASSERT_STR_EQ(json_get_str(trust),
                      "native_snapshot_proof_validated");
        ASSERT_STR_EQ(json_get_str(authority),
                      "local_consensus_validation");
        ASSERT(json_get_bool(activation));
        ASSERT(json_get_bool(mirror));
        ASSERT(json_get_int(score) > 0);
        ASSERT_STR_EQ(json_get_str(source_state), "offer_valid");
        ASSERT_STR_EQ(json_get_str(source_reason), "manifest_ok");
        ASSERT(json_get_int(source_height) == 10000);
        ASSERT(json_get_bool(source_selectable));
        ASSERT_STR_EQ(json_get_str(source_selection_blocker), "");
        ASSERT(json_get_int(source_score_base) == 85);
        ASSERT(json_get_int(source_score_redundancy_bonus) == 0);
        ASSERT(json_get_int(source_score_target_lag_penalty) == 25);
        ASSERT(json_get_int(source_score_failure_penalty) == 0);
        ASSERT(json_get_bool(source_healthy));
        ASSERT(json_get_bool(source_available));
        json_free(&root);

        ASSERT(block_source_policy_peer_floor_recovery_needed(
            0, 3, 100, 130, NULL));
        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        total = json_get(&root, "decisions_total");
        last = json_get(&root, "last_decision");
        ASSERT(total != NULL);
        ASSERT(json_get_int(total) == 2);
        ASSERT(last != NULL);
        op = json_get(last, "op");
        ASSERT(op != NULL);
        ASSERT_STR_EQ(json_get_str(op), "peer_floor");
        json_free(&root);

        block_source_policy_reset_for_test();
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int test_bsp_restores_peer_floor_sources_from_node_state(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: restores peer floor source evidence")
    {
        struct node_db ndb;
        struct json_value root;
        const struct json_value *last;
        const struct json_value *sources;
        const struct json_value *p2p;
        const struct json_value *reason;
        const struct json_value *blocker;
        const struct json_value *score_base;
        const struct json_value *score_failure_penalty;

        ASSERT(node_db_open(&ndb, ":memory:"));
        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, NULL, &ndb);
        ASSERT(block_source_policy_peer_floor_recovery_needed(
            0, 3, 100, 130, NULL));

        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, NULL, &ndb);

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        last = json_get(&root, "last_decision");
        ASSERT(last != NULL);
        sources = json_get(last, "sources");
        ASSERT(sources != NULL);
        p2p = find_source_json(sources, "p2p");
        ASSERT(p2p != NULL);
        reason = json_get(p2p, "reason");
        blocker = json_get(p2p, "blocker");
        score_base = json_get(p2p, "score_base");
        score_failure_penalty = json_get(p2p, "score_failure_penalty");
        ASSERT(reason != NULL);
        ASSERT(blocker != NULL);
        ASSERT(score_base != NULL);
        ASSERT(score_failure_penalty != NULL);
        ASSERT_STR_EQ(json_get_str(reason),
                      "healthy_outbound=0 min_healthy=3");
        ASSERT_STR_EQ(json_get_str(blocker), "peer_floor");
        json_free(&root);

        block_source_policy_reset_for_test();
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

static int test_bsp_restores_local_header_refill_progress(void)
{
    int failures = 0;
    TEST_CASE("block_source_policy: restores local refill progress evidence")
    {
        struct node_db ndb;
        struct json_value root;
        const struct json_value *last;
        const struct json_value *sources;
        const struct json_value *local_import;
        const struct json_value *retry;
        const struct json_value *peers;
        const struct json_value *progress_current;
        const struct json_value *progress_total;

        ASSERT(node_db_open(&ndb, ":memory:"));
        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, NULL, &ndb);
        ASSERT(block_source_policy_local_header_refill_needed(
            100, 101, 130, 2, 3, false, NULL));

        block_source_policy_reset_for_test();
        block_source_policy_init(NULL, NULL, &ndb);

        json_init(&root);
        ASSERT(block_source_policy_dump_state_json(&root, NULL));
        last = json_get(&root, "last_decision");
        ASSERT(last != NULL);
        sources = json_get(last, "sources");
        ASSERT(sources != NULL);
        local_import = find_source_json(sources, "local_import");
        ASSERT(local_import != NULL);
        retry = json_get(local_import, "retry_count");
        peers = json_get(local_import, "distinct_peer_count");
        progress_current = json_get(local_import, "progress_current");
        progress_total = json_get(local_import, "progress_total");
        ASSERT(retry != NULL);
        ASSERT(peers != NULL);
        ASSERT(progress_current != NULL);
        ASSERT(progress_total != NULL);
        ASSERT(json_get_int(retry) == 3);
        ASSERT(json_get_int(peers) == 2);
        ASSERT(json_get_int(progress_current) == 100);
        ASSERT(json_get_int(progress_total) == 101);
        json_free(&root);

        block_source_policy_reset_for_test();
        node_db_close(&ndb);
    } TEST_END
    return failures;
}

int test_block_source_policy(void)
{
    int failures = 0;
    failures += test_bsp_names();
    failures += test_bsp_prefers_native_p2p();
    failures += test_bsp_keeps_caught_up_p2p_when_legacy_is_ahead();
    failures += test_bsp_gates_mirror_during_local_retries();
    failures += test_bsp_allows_bounded_mirror_after_retries();
    failures += test_bsp_lag_slo_overrides_local_gate();
    failures += test_bsp_lag_slo_mirror_outranks_near_target_p2p();
    failures += test_bsp_below_breach_still_gates_mirror();
    failures += test_bsp_peer_floor_helper_classifies_recovery();
    failures += test_bsp_peer_floor_helper_accepts_healthy_p2p();
    failures += test_bsp_blocks_unsafe_mirror();
    failures += test_bsp_avoids_stale_dead_p2p();
    failures += test_bsp_snapshot_can_outrank_mirror();
    failures += test_bsp_fresh_snapshot_outranks_stale_p2p();
    failures += test_bsp_stale_p2p_can_still_advance_when_alone();
    failures += test_bsp_unknown_height_source_is_not_selectable();
    failures += test_bsp_projection_status_propagates();
    failures += test_bsp_snapshot_offer_helper_allows_valid_offer();
    failures += test_bsp_snapshot_offer_helper_blocks_invalid_offer();
    failures += test_bsp_local_header_refill_helper_records_retry();
    failures += test_bsp_local_header_refill_helper_waits_for_peers();
    failures += test_bsp_local_header_refill_helper_recovers_without_peers();
    failures += test_bsp_dump_json_contract();
    failures += test_bsp_dump_reports_projection_lag();
    failures += test_bsp_projection_deferral_accounting();
    failures += test_bsp_dump_populates_p2p_diversity();
    failures += test_bsp_selects_viable_caught_up_p2p();
    failures += test_bsp_inbound_assists_near_tip_p2p();
    failures += test_bsp_dump_explains_stale_p2p_height();
    failures += test_bsp_dump_populates_live_snapshot_source();
    failures += test_bsp_dump_populates_local_import_recovery();
    failures += test_bsp_dump_populates_live_mirror_source();
    failures += test_bsp_dump_records_live_decision();
    failures += test_bsp_dump_records_peer_floor_decision();
    failures += test_bsp_dump_records_snapshot_offer_decision();
    failures += test_bsp_decision_event_contract();
    failures += test_bsp_peer_floor_event_explains_no_source();
    failures += test_bsp_dump_records_local_header_refill_decision();
    failures += test_bsp_restores_last_decision_from_node_state();
    failures += test_bsp_restores_peer_floor_sources_from_node_state();
    failures += test_bsp_restores_local_header_refill_progress();
    return failures;
}
