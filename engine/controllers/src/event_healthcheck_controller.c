/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Event healthcheck RPC. The default path is bounded for first-call
 * operator/AI use; full mode keeps the deeper evidence surface. */
// blocker-ok:rpc_healthcheck_reporter
/* This controller serializes blocker strings created by typed blocker owners
 * such as chain-advance policy and legacy mirror state; it does not create a
 * new blocker source. */

#include "controllers/event_healthcheck_controller.h"
#include "api_controller_internal.h"
#include "config/runtime.h"
#include "controllers/agent_first_call.h"
#include "controllers/agent_security_posture.h"
#include "controllers/strong_params.h"
#include "event_agent_summary.h"
#include "framework/condition.h"
#include "json/json.h"
#include "rpc/server.h"
#include "services/binary_staleness_service.h"
#include "services/block_index_integrity.h"
#include "services/block_source_policy.h"
#include "services/chain_evidence_authority_service.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/node_health_service.h"
#include "sync/sync_state.h"
#include "util/blocker.h"
#include "util/clientversion.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void push_chain_evidence_health_json(struct json_value *checks)
{
    struct chain_evidence_controller cec;
    struct chain_evidence_controller_view view;
    struct json_value ce = {0};

    chain_evidence_controller_init(&cec, app_runtime_node_db(),
                                   csr_instance());
    (void)chain_evidence_drain_pending_tip(&cec);
    chain_evidence_controller_snapshot(&cec, &view);

    json_set_object(&ce);
    json_push_kv_str(&ce, "state",
                     chain_evidence_controller_state_name(view.state));
    json_push_kv_str(&ce, "publish_state",
                     chain_evidence_publish_state_name(view.publish_state));
    json_push_kv_str(&ce, "active_tip_source_class",
                     chain_evidence_source_class_name(
                         view.active_tip_source_class));
    json_push_kv_int(&ce, "active_tip",
                     (int64_t)view.active_tip_height);
    json_push_kv_int(&ce, "header_tip",
                     (int64_t)view.header_tip_height);
    json_push_kv_int(&ce, "persisted_active_tip",
                     (int64_t)view.persisted_active_tip_height);
    json_push_kv_int(&ce, "utxo_max_height",
                     (int64_t)view.utxo_max_height);
    json_push_kv_int(&ce, "coins_best_block_height",
                     (int64_t)view.coins_best_block_height);
    json_push_kv_int(&ce, "csr_sqlite_max_height",
                     (int64_t)view.sqlite_max_height);
    json_push_kv_bool(&ce, "missing_active_tip_evidence",
                      view.missing_active_tip_evidence);
    json_push_kv_bool(&ce, "publish_state_not_local",
                      view.publish_state_not_local);
    json_push_kv_bool(&ce, "active_tip_hash_mismatch",
                      view.active_tip_hash_mismatch);
    json_push_kv_bool(&ce, "csr_cursor_mismatch",
                      view.csr_cursor_mismatch);
    json_push_kv_bool(&ce, "repaired_active_tip_evidence",
                      view.repaired_active_tip_evidence);
    if (view.health_reason[0])
        json_push_kv_str(&ce, "health_reason", view.health_reason);
    if (view.contradiction_reason[0])
        json_push_kv_str(&ce, "contradiction_reason",
                         view.contradiction_reason);
    json_push_kv(checks, "chain_evidence", &ce);
    json_free(&ce);
}

static bool healthcheck_params_request_full(const struct json_value *params)
{
    if (!params)
        return false;

    if (params->type == JSON_OBJ) {
        const struct json_value *full = json_get(params, "full");
        const struct json_value *mode = json_get(params, "mode");
        if (json_get_bool(full))
            return true;
        if (mode && mode->type == JSON_STR &&
            strcmp(json_get_str(mode), "full") == 0)
            return true;
        return false;
    }

    if (params->type != JSON_ARR)
        return false;

    for (size_t i = 0; i < params->num_children; i++) {
        const struct json_value *v = &params->children[i];
        if (v->type == JSON_STR &&
            (strcmp(json_get_str(v), "full") == 0 ||
             strcmp(json_get_str(v), "detailed") == 0))
            return true;
        if (v->type == JSON_OBJ && healthcheck_params_request_full(v))
            return true;
    }
    return false;
}

static void healthcheck_copy_key(struct json_value *dst,
                                 const struct json_value *src,
                                 const char *key)
{
    const struct json_value *v = json_get(src, key);
    if (v)
        json_push_kv(dst, key, v);
}

static void healthcheck_copy_from_object(struct json_value *dst,
                                         const char *dst_key,
                                         const struct json_value *src,
                                         const char *src_key)
{
    const struct json_value *v = src ? json_get(src, src_key) : NULL;
    if (v)
        json_push_kv(dst, dst_key, v);
}

static bool rpc_healthcheck_bounded(const struct json_value *params,
                                    struct json_value *result)
{
    int64_t first_call_started_us = agent_first_call_start_us();
    struct json_value agent = {0};
    if (!rpc_agent_summary(params, false, &agent) || agent.type != JSON_OBJ) {
        json_set_object(result);
        json_push_kv_str(result, "schema", "zcl.healthcheck.v1");
        json_push_kv_str(result, "api_version", "v1");
        json_push_kv_str(result, "status", "error");
        json_push_kv_str(result, "result_completeness", "bounded");
        json_push_kv_bool(result, "partial_result", true);
        json_push_kv_bool(result, "healthy", false);
        json_push_kv_bool(result, "serving", false);
        json_push_kv_str(result, "error", "agent_summary_unavailable");
        json_push_kv_str(result, "consensus_authority",
                         "local_consensus_validation");
        json_push_kv_str(result, "candidate_source", "agent_cached_summary");
        json_push_kv_str(result, "candidate_trust", "bounded_cached_status");
        json_push_kv_str(result, "full_mode_command",
                         "z23 healthcheck full");
        agent_push_first_call_simple_json(
            result, "first_call", "healthcheck", "agent_cached_summary",
            ZCL_AGENT_FIRST_CALL_BUDGET_HEALTHCHECK_MS, first_call_started_us,
            true, "agent_summary_unavailable", "z23 healthcheck full");
        json_free(&agent);
        return true;
    }

    const struct json_value *peers = json_get(&agent, "peers");
    const struct json_value *services = json_get(&agent, "services");
    const struct json_value *reducer = json_get(&agent, "reducer");
    const struct json_value *health = json_get(&agent, "health");
    const struct json_value *indexer = json_get(&agent, "indexer");
    const struct json_value *height_contract = json_get(&agent,
                                                        "height_contract");
    const char *height_contract_status =
        json_get_str(json_get(height_contract, "status"));
    bool normal_lookahead =
        json_get_bool(json_get(height_contract, "normal_lookahead"));
    bool sync_fsm_at_tip = sync_get_state() == SYNC_AT_TIP;
    bool chain_serving_ready =
        json_get_bool(json_get(&agent, "chain_serving_ready"));
    bool height_contract_current =
        height_contract_status &&
        (strcmp(height_contract_status, "current") == 0 ||
         strcmp(height_contract_status, "normal_lookahead") == 0);
    bool bounded_synced = chain_serving_ready && height_contract_current;

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.healthcheck.v1");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "status", "ok");
    json_push_kv_str(result, "result_completeness", "bounded");
    json_push_kv_bool(result, "partial_result", true);
    json_push_kv_str(result, "partial_reason",
                     "bounded_first_call_uses_cached_status");
    json_push_kv_str(result, "full_mode_command",
                     "z23 healthcheck full");
    json_push_kv_str(result, "full_mode_params",
                     "{\"mode\":\"full\"}");
    json_push_kv_str(result, "consensus_authority",
                     "local_consensus_validation");
    json_push_kv_str(result, "candidate_source", "agent_cached_summary");
    json_push_kv_str(result, "candidate_trust", "bounded_cached_status");
    agent_push_first_call_simple_json(
        result, "first_call", "healthcheck", "agent_cached_summary",
        ZCL_AGENT_FIRST_CALL_BUDGET_HEALTHCHECK_MS, first_call_started_us,
        true, "bounded_first_call_uses_cached_status",
        "z23 healthcheck full");

    healthcheck_copy_key(result, &agent, "build_commit");
    healthcheck_copy_key(result, &agent, "source_id_sha256");
    healthcheck_copy_key(result, &agent, "runtime_build");
    healthcheck_copy_key(result, &agent, "sync_state");
    healthcheck_copy_key(result, &agent, "readiness_status");
    healthcheck_copy_key(result, &agent, "chain_serving_ready");
    healthcheck_copy_key(result, &agent, "index_projection_ready");
    healthcheck_copy_key(result, &agent, "agent_work_ready");
    json_push_kv_bool(result, "sync_fsm_at_tip", sync_fsm_at_tip);
    json_push_kv_bool(result, "normal_lookahead", normal_lookahead);
    json_push_kv_str(result, "height_contract_status",
                     height_contract_status);
    healthcheck_copy_key(result, &agent, "healthy");
    healthcheck_copy_key(result, &agent, "serving");
    healthcheck_copy_from_object(result, "warning_count", health,
                                 "warning_count");
    healthcheck_copy_key(result, &agent, "mirror_contract");
    healthcheck_copy_key(result, &agent, "security_posture");

    struct json_value checks = {0};
    json_set_object(&checks);
    json_push_kv_bool(&checks, "bounded", true);
    json_push_kv_bool(&checks, "partial_result", true);
    json_push_kv_str(&checks, "partial_reason",
                     "expensive evidence is available in full mode");
    json_push_kv_bool(&checks, "synced", bounded_synced);
    json_push_kv_bool(&checks, "sync_fsm_at_tip", sync_fsm_at_tip);
    json_push_kv_str(&checks, "height_contract_status",
                     height_contract_status);
    json_push_kv_bool(&checks, "normal_lookahead", normal_lookahead);
    json_push_kv_bool(&checks, "chain_serving_ready", chain_serving_ready);
    json_push_kv_bool(&checks, "serving_ready", chain_serving_ready);
    healthcheck_copy_from_object(&checks, "readiness_status", &agent,
                                 "readiness_status");
    healthcheck_copy_from_object(&checks, "index_projection_ready", &agent,
                                 "index_projection_ready");
    healthcheck_copy_from_object(&checks, "agent_work_ready", &agent,
                                 "agent_work_ready");
    healthcheck_copy_from_object(&checks, "has_peers", peers, "has_peers");
    healthcheck_copy_from_object(&checks, "peer_count", peers, "total");
    healthcheck_copy_from_object(&checks, "magicbean_peer_count", peers,
                                 "magicbean");
    healthcheck_copy_from_object(&checks, "zclassic23_peer_count", peers,
                                 "zclassic23");
    healthcheck_copy_from_object(&checks, "tor_enabled", services,
                                 "tor_enabled");
    healthcheck_copy_from_object(&checks, "tor_ready", services,
                                 "tor_ready");
    healthcheck_copy_from_object(&checks, "onion_service_ready", services,
                                 "onion_service_ready");
    healthcheck_copy_key(&checks, &agent, "gap");
    healthcheck_copy_key(&checks, &agent, "index_gap");
    healthcheck_copy_from_object(&checks, "tip_lag_blocks", &agent, "gap");
    healthcheck_copy_from_object(&checks, "log_head", reducer, "log_head");
    healthcheck_copy_from_object(&checks, "log_head_gap", reducer,
                                 "log_head_gap");
    healthcheck_copy_from_object(&checks, "tip_advance_age_seconds",
                                 reducer, "tip_advance_age_seconds");
    healthcheck_copy_from_object(&checks, "serving", &agent, "serving");
    healthcheck_copy_from_object(&checks, "warning_count", health,
                                 "warning_count");
    healthcheck_copy_from_object(&checks, "warning_reasons", health,
                                 "warning_reasons");
    healthcheck_copy_from_object(&checks, "blocking_reason", health,
                                 "blocking_reason");
    healthcheck_copy_from_object(&checks, "last_error_age_seconds", health,
                                 "last_error_age_seconds");
    healthcheck_copy_from_object(&checks, "last_error_type", health,
                                 "last_error_type");
    healthcheck_copy_from_object(&checks, "operator_needed", &agent,
                                 "operator_needed");
    healthcheck_copy_from_object(&checks, "validation_pack_ok", reducer,
                                 "validation_pack_ok");
    healthcheck_copy_from_object(&checks, "validation_pack_detail", reducer,
                                 "validation_pack_detail");
    healthcheck_copy_from_object(&checks, "security_posture", &agent,
                                 "security_posture");
    /* Lock-free atomic read — cheap enough for the bounded first-call
     * path. See services/binary_staleness_service.h. */
    json_push_kv_bool(&checks, "binary_stale", binary_staleness_is_stale());
    {
        struct json_value ca = {0};
        json_set_object(&ca);
        json_push_kv_str(&ca, "source", "cached_first_call");
        json_push_kv_str(&ca, "authority", "local_consensus_validation");
        json_push_kv_str(&ca, "decision", "bounded_cached_status");
        healthcheck_copy_from_object(&ca, "local_height", &agent,
                                     "served_height");
        healthcheck_copy_from_object(&ca, "best_header_height", &agent,
                                     "header_height");
        healthcheck_copy_from_object(&ca, "target_height", &agent,
                                     "target_height");
        healthcheck_copy_from_object(&ca, "projection_height", indexer,
                                     "projection_height");
        healthcheck_copy_from_object(&ca, "projection_lag", indexer,
                                     "projection_lag");
        healthcheck_copy_from_object(&ca, "projection_deferred", indexer,
                                     "projection_deferred");
        healthcheck_copy_from_object(&ca, "projection_state", indexer,
                                     "projection_state");
        healthcheck_copy_from_object(&ca, "block_source_status_cached",
                                     indexer, "block_source_status_cached");
        if (height_contract)
            json_push_kv(&ca, "height_contract", height_contract);
        json_push_kv(&checks, "chain_advance", &ca);
        json_free(&ca);
    }
    json_push_kv(result, "checks", &checks);
    json_free(&checks);
    json_push_kv(result, "agent", &agent);
    json_free(&agent);
    return true;
}

static bool rpc_healthcheck_full(const struct json_value *params,
                                 struct json_value *result)
{
    (void)params;
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.healthcheck.v1");
    json_push_kv_str(result, "api_version", "v1");
    json_push_kv_str(result, "result_completeness", "full");
    json_push_kv_bool(result, "partial_result", false);

    struct node_health_snapshot health;
    node_health_collect(&health, NULL, NULL);
    struct agent_security_posture posture;
    agent_security_posture_collect(&posture, NULL);
    struct blocker_snapshot blockers[BLOCKER_CAP];
    int blocker_count = blocker_snapshot_all(blockers, BLOCKER_CAP);
    const struct blocker_snapshot *dominant =
        blocker_select_dominant(blockers, blocker_count);
    const struct blocker_snapshot *authority_blocker =
        api_blocker_hard_gates_public_serving(dominant) ? dominant : NULL;
    const struct blocker_snapshot *warning_blocker =
        dominant && !authority_blocker ? dominant : NULL;
    bool public_serving = health.serving && !authority_blocker &&
        agent_security_posture_allows_public_serving(&posture);
    bool public_healthy = health.healthy && public_serving;
    json_push_kv_str(result, "status", public_healthy ? "ok" : "blocked");
    json_push_kv_str(result, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    json_push_kv_str(result, "sync_state", sync_state_name(health.sync_state));

    struct json_value checks = {0};
    json_set_object(&checks);

    json_push_kv_bool(&checks, "synced", health.synced);
    json_push_kv_bool(&checks, "has_peers", health.has_peers);
    json_push_kv_bool(&checks, "tor_enabled", health.tor_enabled);
    json_push_kv_bool(&checks, "tor_ready", health.tor_ready);
    json_push_kv_bool(&checks, "onion_service_ready",
                      health.onion_service_ready);
    json_push_kv_bool(&checks, "tip_stale", health.tip_stale);
    json_push_kv_bool(&checks, "queue_backed_up", health.queue_backed_up);
    json_push_kv_int(&checks, "peer_count", (int64_t)health.peer_count);
    json_push_kv_int(&checks, "tip_lag", (int64_t)health.tip_lag);
    json_push_kv_int(&checks, "log_head", (int64_t)health.log_head);
    json_push_kv_int(&checks, "log_head_gap", (int64_t)health.log_head_gap);
    json_push_kv_int(&checks, "error_total", health.error_total);
    json_push_kv_int(&checks, "last_error_age_seconds",
                     health.last_error_age_seconds);
    json_push_kv_bool(&checks, "last_error_recent",
                      health.last_error_recent);
    json_push_kv_bool(&checks, "serving", public_serving);
    if (authority_blocker)
        json_push_kv_str(&checks, "blocking_reason",
                         authority_blocker->id);
    else if (posture.review_required)
        json_push_kv_str(&checks, "blocking_reason", posture.status);
    else if (health.blocking_reason[0])
        json_push_kv_str(&checks, "blocking_reason",
                         health.blocking_reason);
    json_push_kv_bool(&checks, "warning",
                      health.warning || warning_blocker != NULL);
    json_push_kv_int(&checks, "warning_count",
                     (int64_t)health.warning_count +
                     (warning_blocker ? 1 : 0));
    if (health.warning_reasons[0])
        json_push_kv_str(&checks, "warning_reasons",
                         health.warning_reasons);
    if (warning_blocker)
        json_push_kv_str(&checks, "typed_blocker_warning",
                         warning_blocker->id);
    if (health.last_error_type[0])
        json_push_kv_str(&checks, "last_error_type",
                         health.last_error_type);
    if (health.last_error[0])
        json_push_kv_str(&checks, "last_error", health.last_error);
    if (health.onion_address[0])
        json_push_kv_str(&checks, "onion_address", health.onion_address);
    if (health.degraded_reason[0])
        json_push_kv_str(&checks, "degraded_reason", health.degraded_reason);
    json_push_kv_bool(&checks, "operator_needed", health.operator_needed);
    if (health.operator_needed && health.operator_needed_detail[0])
        json_push_kv_str(&checks, "operator_needed_detail",
                         health.operator_needed_detail);

    const char *active_source = "none";
    const char *active_source_trust = "none";
    char active_blocker[128] = "";
    bool non_legacy_source_selected = false;
    {
        struct json_value conditions = {0};
        json_set_object(&conditions);
        if (condition_engine_dump_state_json(&conditions, NULL))
            json_push_kv(&checks, "condition_engine", &conditions);
        json_free(&conditions);
    }
    json_push_kv_bool(&checks, "validation_pack_ok",
                      health.validation_pack_ok);
    if (!health.validation_pack_ok && health.validation_pack_detail[0])
        json_push_kv_str(&checks, "validation_pack_detail",
                         health.validation_pack_detail);
    struct bii_recovery_status bii;
    bii_get_recovery_status(&bii);
    if (bii.degraded)
        json_push_kv_str(&checks, "block_index_integrity",
                         bii_recovery_action_name(bii.action));
    {
        /* ops.binary_stale — the on-disk binary at this process's exec
         * path no longer matches the running image (see
         * services/binary_staleness_service.h). Named blocker + detail
         * so an operator sees exactly what changed without a restart. */
        struct binary_staleness_status bs;
        binary_staleness_status_snapshot(&bs);
        json_push_kv_bool(&checks, "binary_stale", bs.stale);
        if (bs.stale) {
            char detail[256];
            snprintf(detail, sizeof(detail),
                     "running=%.12s on_disk=%.12s path=%.200s",
                     bs.boot_digest_hex, bs.last_disk_digest_hex,
                     bs.exe_path);
            json_push_kv_str(&checks, "binary_stale_detail", detail);
        }
    }
    push_chain_evidence_health_json(&checks);
    {
        struct bsp_decision d;
        struct json_value ca = {0};

        block_source_policy_get_status(&d);
        active_source = bsp_source_name(d.selected_source);
        active_source_trust = bsp_source_trust_name(d.selected_source);
        snprintf(active_blocker, sizeof(active_blocker), "%s", d.blocker);
        non_legacy_source_selected =
            d.result == BSP_DECISION_USE_SOURCE &&
            d.selected_source != BSP_SOURCE_NONE &&
            d.selected_source != BSP_SOURCE_ZCLASSICD_MIRROR;
        json_set_object(&ca);
        json_push_kv_str(&ca, "authority", "local_consensus_validation");
        json_push_kv_str(&ca, "decision",
                         bsp_decision_result_name(d.result));
        json_push_kv_str(&ca, "selected_source",
                         bsp_source_name(d.selected_source));
        json_push_kv_str(&ca, "selected_source_trust",
                         bsp_source_trust_name(d.selected_source));
        json_push_kv_bool(&ca, "activation_allowed", d.activation_allowed);
        json_push_kv_bool(&ca, "mirror_fallback_allowed",
                          d.mirror_fallback_allowed);
        json_push_kv_int(&ca, "local_height", d.local_height);
        json_push_kv_int(&ca, "best_header_height", d.best_header_height);
        json_push_kv_int(&ca, "target_height", d.target_height);
        json_push_kv_int(&ca, "projection_height", d.projection_height);
        json_push_kv_int(&ca, "projection_lag", d.projection_lag);
        json_push_kv_bool(&ca, "projection_deferred",
                          d.projection_deferred);
        json_push_kv_str(&ca, "projection_state", d.projection_state);
        json_push_kv_int(&ca, "projection_deferred_total",
                         d.projection_deferred_total);
        json_push_kv_int(&ca, "last_projection_deferred_height",
                         d.last_projection_deferred_height);
        json_push_kv_int(&ca, "last_projection_deferred_time",
                         d.last_projection_deferred_time);
        json_push_kv_str(&ca, "last_projection_deferred_reason",
                         d.last_projection_deferred_reason);
        if (d.selected_source > BSP_SOURCE_NONE &&
            d.selected_source < BSP_SOURCE_NUM) {
            const struct bsp_source_status *s = &d.sources[d.selected_source];
            json_push_kv_bool(&ca, "selected_source_selectable",
                              s->selectable);
            json_push_kv_str(&ca, "selected_source_selection_blocker",
                             s->selection_reason);
            json_push_kv_int(&ca, "selected_source_score_base",
                             s->score_base);
            json_push_kv_int(&ca, "selected_source_score_health",
                             s->score_health);
            json_push_kv_int(&ca, "selected_source_score_height",
                             s->score_height);
            json_push_kv_int(&ca, "selected_source_score_authorized",
                             s->score_authorized);
            json_push_kv_int(&ca,
                             "selected_source_score_target_lag_penalty",
                             s->score_target_lag_penalty);
            json_push_kv_int(&ca, "selected_source_score_failure_penalty",
                             s->score_failure_penalty);
            json_push_kv_int(&ca,
                             "selected_source_score_mirror_gate_penalty",
                             s->score_mirror_gate_penalty);
        }
        json_push_kv_str(&ca, "reason", d.reason);
        json_push_kv_str(&ca, "blocker", d.blocker);
        {
            struct json_value dump = {0};
            if (block_source_policy_dump_state_json(&dump, NULL)) {
                const struct json_value *has_last =
                    json_get(&dump, "has_last_decision");
                const struct json_value *last =
                    json_get(&dump, "last_decision");
                const struct json_value *sources =
                    json_get(&dump, "sources");
                const struct json_value *initialized =
                    json_get(&dump, "initialized");
                const struct json_value *has_connman =
                    json_get(&dump, "has_connman");
                const struct json_value *has_main_state =
                    json_get(&dump, "has_main_state");
                const struct json_value *has_node_db =
                    json_get(&dump, "has_node_db");
                if (initialized)
                    json_push_kv(&ca, "initialized", initialized);
                if (has_connman)
                    json_push_kv(&ca, "has_connman", has_connman);
                if (has_main_state)
                    json_push_kv(&ca, "has_main_state", has_main_state);
                if (has_node_db)
                    json_push_kv(&ca, "has_node_db", has_node_db);
                if (has_last)
                    json_push_kv(&ca, "has_last_decision", has_last);
                if (last)
                    json_push_kv(&ca, "last_decision", last);
                if (sources)
                    json_push_kv(&ca, "sources", sources);
            }
            json_free(&dump);
        }
        json_push_kv(&checks, "chain_advance", &ca);
        json_free(&ca);
    }
    {
        struct legacy_mirror_sync_stats ms;
        legacy_mirror_sync_stats_snapshot(&ms);
        const char *legacy_blocker = legacy_mirror_sync_blocker_code(&ms);
        bool surface_legacy_blocker =
            legacy_mirror_sync_blocker_should_surface(
                &ms, non_legacy_source_selected);
        json_push_kv_str(result, "consensus_authority",
                         "local_consensus_validation");
        json_push_kv_str(result, "active_source", active_source);
        json_push_kv_str(result, "active_source_trust", active_source_trust);
        json_push_kv_str(result, "active_blocker", active_blocker);
        json_push_kv_str(result, "candidate_source", "legacy_advisory");
        json_push_kv_str(result, "candidate_trust", ms.candidate_trust);
        json_push_kv_bool(result, "candidate_lag_known", ms.lag_known);
        json_push_kv_bool(result, "candidate_lag_valid", ms.lag_valid);
        json_push_kv_bool(result, "mirror_tip_hashes_agree",
                          ms.tip_hashes_agree);
        json_push_kv_bool(result, "mirror_blocker_recovered_by_tip_agreement",
                          ms.blocker_recovered_by_tip_agreement);
        json_push_kv_int(result, "candidate_lag",
                         legacy_mirror_sync_reported_lag(&ms));
        legacy_mirror_sync_push_observed_lag_json(
            result, "candidate_lag_observed", &ms);
        json_push_kv_bool(result, "mirror_lag_known", ms.lag_known);
        json_push_kv_bool(result, "mirror_lag_valid", ms.lag_valid);
        json_push_kv_int(result, "mirror_lag",
                         legacy_mirror_sync_reported_lag(&ms));
        legacy_mirror_sync_push_observed_lag_json(
            result, "mirror_lag_observed", &ms);
        json_push_kv_bool(result, "mirror_monitor_running", ms.running);
        json_push_kv_bool(result, "mirror_reachable", ms.reachable);
        json_push_kv_bool(result, "zclassicd_rpc_transport_reachable",
                          ms.zclassicd_rpc_transport_reachable);
        json_push_kv_bool(result, "legacy_oracle_usable",
                          ms.legacy_oracle_usable);
        json_push_kv_int(result, "zclassicd_rpc_error_code",
                         ms.zclassicd_rpc_error_code);
        json_push_kv_str(result, "zclassicd_rpc_error_message",
                         ms.zclassicd_rpc_error_message);
        json_push_kv_int(result, "mirror_rpc_errors", ms.rpc_errors);
        json_push_kv_int(result, "mirror_last_attempt", ms.last_attempt);
        json_push_kv_str(result, "mirror_active_error_code",
                         legacy_blocker);
        json_push_kv_str(result, "mirror_active_error_detail",
                         legacy_blocker[0] ? ms.last_error : "");
        json_push_kv_str(result, "candidate_blocker",
                         surface_legacy_blocker ? legacy_blocker : "");
        json_push_kv_str(result, "candidate_blocker_scope",
                         surface_legacy_blocker ? "active_or_safety"
                                                : (legacy_blocker[0]
                                                       ? "advisory_only"
                                                       : ""));
        json_push_kv_str(result, "legacy_advisory_blocker",
                         ms.enabled ? legacy_blocker : "");
        json_push_kv_str(result, "mirror_activation_blocker",
                         ms.enabled ? ms.activation_blocker_reason : "");
        json_push_kv_str(result, "mirror_last_blocker_code",
                         ms.enabled ? ms.last_blocker_id : "");
        json_push_kv_int(result, "mirror_blockers_total",
                         ms.enabled ? ms.blockers_total : 0);
        json_push_kv_int(result, "mirror_unsafe_overrides_total",
                         ms.unsafe_overrides_total);
        json_push_kv_int(result, "mirror_stalls_total", ms.stalls_total);
        json_push_kv_int(result, "mirror_overrides_total", ms.overrides_total);
        json_push_kv_bool(result, "mirror_last_override_safe",
                          ms.last_override_safe);
        json_push_kv_str(result, "mirror_last_override_reason",
                         ms.last_override_reason);
        json_push_kv_str(result, "mirror_last_override_scope",
                         ms.last_override_scope);
    }
    json_push_kv_int(&checks, "memory_rss_mb", health.memory_rss_mb);
    json_push_kv_int(&checks, "uptime_seconds", health.uptime_seconds);
    json_push_kv_int(&checks, "tip_advance_age_seconds",
                     health.tip_advance_age_seconds);

    json_push_kv_bool(result, "healthy", public_healthy);
    json_push_kv_bool(result, "serving", public_serving);
    json_push_kv_int(result, "warning_count",
                     (int64_t)health.warning_count +
                     (warning_blocker ? 1 : 0));
    json_push_kv(result, "checks", &checks);
    json_free(&checks);
    agent_push_security_posture_json(result, "security_posture", NULL);

    return true;
}

bool rpc_healthcheck(const struct json_value *params, bool help,
                     struct json_value *result)
{
    RPC_HELP(help, result,
        "healthcheck ( full|{\"mode\":\"full\"} )\n"
        "\nReturn bounded node health status for monitoring. The default\n"
        "path must stay cheap and always return valid JSON before the RPC\n"
        "watchdog deadline; pass full or {\"mode\":\"full\"} for the detailed\n"
        "evidence path.\n"
        "\nResult:\n"
        "  { \"schema\":\"zcl.healthcheck.v1\", \"healthy\": true/false,\n"
        "    \"serving\": true/false, \"result_completeness\":\"bounded\", "
        "\"checks\": { ... } }\n");

    if (healthcheck_params_request_full(params))
        return rpc_healthcheck_full(params, result);
    return rpc_healthcheck_bounded(params, result);
}
