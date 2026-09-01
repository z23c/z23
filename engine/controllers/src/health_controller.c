/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Health Controller — exposes detailed sync progress and service health. */

#include "controllers/health_controller.h"
#include "controllers/strong_params.h"
#include "framework/condition.h"
#include "services/block_source_policy.h"
#include "services/sync_monitor.h"
#include "services/legacy_mirror_sync_service.h"
#include "jobs/reducer_frontier.h"
#include "validation/chainstate.h"
#include "net/p2p_game.h"
#include "net/msgprocessor.h"
#include "json/json.h"
#include <string.h>
#include <time.h>
#include "util/log_macros.h"

/* ── Controller context ──────────────────────────────────────── */

struct health_context {
    struct main_state *main_state;
    struct bg_validation_service *bg_valid;
    struct bg_hash_verification_service *bg_hash;
    struct connman *connman;
};

static struct health_context g_health_ctx = {0};

static void push_watchdog_recovery_fields(struct json_value *result)
{
    if (!result)
        return;

    struct watchdog_stats wd;
    sync_monitor_get_stats(&wd);
    json_push_kv_int(result, "recoveries_total", wd.recoveries_total);
    json_push_kv_int(result, "last_recovery_time",
                     wd.last_recovery_time);
    json_push_kv_str(result, "last_recovery",
                     watchdog_recovery_type_name(wd.last_recovery));
    json_push_kv_int(result, "last_recovery_local_height",
                     wd.last_recovery_local_height);
    json_push_kv_int(result, "last_recovery_peer_height",
                     wd.last_recovery_peer_height);
    json_push_kv_int(result, "last_recovery_peer_count",
                     wd.last_recovery_peer_count);
    json_push_kv_int(result, "last_recovery_target_height",
                     wd.last_recovery_target_height);
    json_push_kv_int(result, "last_recovery_manifest_height",
                     wd.last_recovery_manifest_height);
    json_push_kv_str(result, "last_recovery_reason",
                     wd.last_recovery_reason);
    json_push_kv_str(result, "last_recovery_trigger",
                     wd.last_recovery_trigger);
}

static void push_mirror_sync_fields(struct json_value *result)
{
    if (!result)
        return;
    struct legacy_mirror_sync_stats ms;
    legacy_mirror_sync_stats_snapshot(&ms);
    struct bsp_decision d;
    block_source_policy_get_status(&d);
    bool non_legacy_source_selected =
        d.result == BSP_DECISION_USE_SOURCE &&
        d.selected_source != BSP_SOURCE_NONE &&
        d.selected_source != BSP_SOURCE_ZCLASSICD_MIRROR;
    const char *legacy_blocker = legacy_mirror_sync_blocker_code(&ms);
    bool surface_legacy_blocker =
        legacy_mirror_sync_blocker_should_surface(
            &ms, non_legacy_source_selected);
    json_push_kv_bool(result, "mirror_enabled", ms.enabled);
    json_push_kv_bool(result, "mirror_reachable", ms.reachable);
    json_push_kv_bool(result, "mirror_monitor_running", ms.running);
    json_push_kv_bool(result, "zclassicd_rpc_transport_reachable",
                      ms.zclassicd_rpc_transport_reachable);
    json_push_kv_bool(result, "legacy_oracle_usable",
                      ms.legacy_oracle_usable);
    json_push_kv_int(result, "zclassicd_rpc_error_code",
                     ms.zclassicd_rpc_error_code);
    json_push_kv_str(result, "zclassicd_rpc_error_message",
                     ms.zclassicd_rpc_error_message);
    json_push_kv_str(result, "legacy_mirror_state", ms.state);
    json_push_kv_str(result, "consensus_authority",
                     "local_consensus_validation");
    json_push_kv_str(result, "active_source",
                     bsp_source_name(d.selected_source));
    json_push_kv_str(result, "active_source_trust",
                     bsp_source_trust_name(d.selected_source));
    json_push_kv_str(result, "active_blocker", d.blocker);
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
    legacy_mirror_sync_push_observed_lag_json(result,
                                              "candidate_lag_observed", &ms);
    /* See rpc_healthcheck (event_controller.c): keep legacy/zclassicd mirror
     * dependency failures visible as advisory source state, but do not promote
     * transient mirror RPC failure into the top-level candidate blocker when
     * chain advance is already using a non-legacy source. */
    json_push_kv_str(result, "candidate_blocker",
                     surface_legacy_blocker ? legacy_blocker : "");
    json_push_kv_str(result, "candidate_blocker_scope",
                     surface_legacy_blocker ? "active_or_safety"
                                            : (legacy_blocker[0]
                                                   ? "advisory_only"
                                                   : ""));
    json_push_kv_str(result, "legacy_advisory_blocker",
                     ms.enabled ? legacy_blocker : "");
    json_push_kv_int(result, "mirror_rpc_errors", ms.rpc_errors);
    json_push_kv_int(result, "mirror_last_attempt", ms.last_attempt);
    json_push_kv_str(result, "mirror_active_error_code",
                     legacy_blocker);
    json_push_kv_str(result, "mirror_active_error_detail",
                     legacy_blocker[0] ? ms.last_error : "");
    json_push_kv_int(result, "legacy_height", ms.legacy_height);
    json_push_kv_bool(result, "legacy_advisory_height_known",
                      ms.legacy_advisory_height_known);
    json_push_kv_bool(result, "mirror_lag_known", ms.lag_known);
    json_push_kv_bool(result, "mirror_lag_valid", ms.lag_valid);
    json_push_kv_int(result, "mirror_lag",
                     legacy_mirror_sync_reported_lag(&ms));
    legacy_mirror_sync_push_observed_lag_json(result,
                                              "mirror_lag_observed", &ms);
    json_push_kv_str(result, "mirror_activation_blocker",
                     ms.enabled ? ms.activation_blocker_reason : "");
    json_push_kv_str(result, "mirror_last_blocker_code",
                     ms.enabled ? ms.last_blocker_id : "");
    json_push_kv_int(result, "mirror_blockers_total",
                     ms.enabled ? ms.blockers_total : 0);
    json_push_kv_int(result, "mirror_unsafe_overrides_total",
                     ms.unsafe_overrides_total);
    json_push_kv_int(result, "mirror_stalls_total",
                     ms.stalls_total);
    json_push_kv_bool(result, "mirror_last_override_safe",
                      ms.last_override_safe);
    json_push_kv_str(result, "mirror_last_override_reason",
                     ms.last_override_reason);
    json_push_kv_str(result, "mirror_last_override_scope",
                     ms.last_override_scope);
    json_push_kv_bool(result, "legacy_advisory_gated_by_native_retries",
                      ms.mirror_repair_gated_by_local_retries);
    json_push_kv_bool(result, "mirror_repair_gated_by_local_retries",
                      ms.mirror_repair_gated_by_local_retries);
    json_push_kv_bool(result, "mirror_local_retries_exhausted",
                      ms.local_retries_exhausted);
    json_push_kv_int(result, "last_mirror_catchup", ms.last_catchup);
    /* Lag-SLO surfaces — present on both top-level and svc payloads so
     * native callers and alerting tooling can hinge on a single key path. */
    json_push_kv_int(result, "mirror_lag_sla_breach_blocks",
                     ms.lag_sla_breach_blocks);
    json_push_kv_int(result, "mirror_lag_sla_breach_secs",
                     ms.lag_sla_breach_secs);
    json_push_kv_int(result, "mirror_lag_sla_critical_blocks",
                     ms.lag_sla_critical_blocks);
    json_push_kv_int(result, "mirror_lag_sla_critical_secs",
                     ms.lag_sla_critical_secs);
    json_push_kv_int(result, "mirror_lag_breach_seconds",
                     ms.lag_breach_seconds);
    json_push_kv_int(result, "mirror_lag_critical_seconds",
                     ms.lag_critical_seconds);
    json_push_kv_str(result, "mirror_lag_breach_severity",
                     ms.lag_breach_severity);
}

void rpc_health_set_state(struct main_state *ms,
                          struct bg_validation_service *bg_valid,
                          struct bg_hash_verification_service *bg_hash,
                          struct connman *cm)
{
    g_health_ctx.main_state = ms;
    g_health_ctx.bg_valid = bg_valid;
    g_health_ctx.bg_hash = bg_hash;
    g_health_ctx.connman = cm;
}

/* ── RPC: getsyncdetail ──────────────────────────────────────── */

static bool rpc_getsyncdetail(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getsyncdetail\n"
        "\nReturn detailed sync progress for all phases.\n"
        "\nResult: object with chain, bg_validation, and bg_hash_verify sections.");

    struct health_context *ctx = &g_health_ctx;
    json_set_object(result);

    /* Chain state */
    {
        struct json_value chain = {0};
        json_set_object(&chain);

        /* Operator-facing chain.height = the PROVABLE tip (H*), not the
         * sync-window tip. Cached lock-free atomic; -1 only pre-init. */
        int tip_h = ctx->main_state ?
            reducer_frontier_provable_tip_cached() : -1;
        json_push_kv_int(&chain, "height", tip_h);

        struct block_index *tip = NULL;
        if (ctx->main_state && tip_h >= 0)
            tip = active_chain_at(&ctx->main_state->chain_active, tip_h);
        if (tip && tip->phashBlock) {
            char hex[65];
            uint256_get_hex(tip->phashBlock, hex);
            json_push_kv_str(&chain, "best_block", hex);
        }

        int peer_count = 0;
        int net_height = -1;
        if (ctx->connman) {
            /* cs_nodes: the socket-thread disconnect sweep frees nodes
             * at refcount 0 — never walk nodes[] lock-free. */
            zcl_mutex_lock(&ctx->connman->manager.cs_nodes);
            peer_count = (int)ctx->connman->manager.num_nodes;
            for (size_t i = 0; i < ctx->connman->manager.num_nodes; i++) {
                struct p2p_node *n = ctx->connman->manager.nodes[i];
                if (n && n->starting_height > net_height)
                    net_height = n->starting_height;
            }
            zcl_mutex_unlock(&ctx->connman->manager.cs_nodes);
        }
        json_push_kv_int(&chain, "peers", peer_count);
        json_push_kv_int(&chain, "network_height", net_height);

        json_push_kv(result, "chain", &chain);
        json_free(&chain);
    }

    /* bg_validation progress */
    if (ctx->bg_valid) {
        struct json_value bgv = {0};
        json_set_object(&bgv);

        struct bg_validation_progress p =
            bg_validation_get_progress(ctx->bg_valid);
        json_push_kv_str(&bgv, "state",
            bg_validation_state_name(p.state));
        json_push_kv_int(&bgv, "verified_height", p.verified_height);
        json_push_kv_int(&bgv, "chain_height", p.chain_height);
        json_push_kv_int(&bgv, "sigs_verified", p.sigs_verified);
        json_push_kv_int(&bgv, "proofs_verified", p.proofs_verified);
        json_push_kv_int(&bgv, "blocks_per_sec", p.blocks_per_sec);
        /* Non-coinbase txs that advanced verified_height WITHOUT full script
         * verification (undo missing/mismatched — expected post-snapshot).
         * Makes the "verified" claim honest: >0 means incomplete coverage. */
        json_push_kv_int(&bgv, "script_verif_skipped_no_undo",
            p.script_verif_skipped_no_undo);
        json_push_kv_bool(&bgv, "verification_incomplete",
            p.script_verif_skipped_no_undo > 0);

        if (p.chain_height > 0 && p.verified_height >= 0) {
            double pct = 100.0 * (double)(p.verified_height + 1) /
                         (double)(p.chain_height + 1);
            json_push_kv_real(&bgv, "percent_complete", pct);
        }

        json_push_kv(result, "bg_validation", &bgv);
        json_free(&bgv);
    }

    /* bg_hash_verify progress */
    if (ctx->bg_hash) {
        struct json_value bgh = {0};
        json_set_object(&bgh);

        struct bg_hash_verify_progress p =
            bg_hash_verify_get_progress(ctx->bg_hash);
        json_push_kv_str(&bgh, "state",
            bg_hash_verify_state_name(p.state));
        json_push_kv_int(&bgh, "verified_height", p.verified_height);
        json_push_kv_int(&bgh, "chain_height", p.chain_height);
        json_push_kv_int(&bgh, "mismatches", p.mismatches);

        json_push_kv(result, "bg_hash_verify", &bgh);
        json_free(&bgh);
    }

    push_mirror_sync_fields(result);

    return true;
}

/* ── RPC: getservicehealth ───────────────────────────────────── */

static bool rpc_getservicehealth(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getservicehealth\n"
        "\nReturn health status of all P2P services.\n"
        "\nResult: array of service objects with name, state, and details.");

    struct health_context *ctx = &g_health_ctx;
    json_set_array(result);

    /* P2P networking */
    {
        struct json_value svc = {0};
        json_set_object(&svc);
        json_push_kv_str(&svc, "name", "p2p");
        bool p2p_ok = ctx->connman && ctx->connman->started;
        json_push_kv_str(&svc, "state", p2p_ok ? "running" : "stopped");
        json_push_kv_int(&svc, "peers",
            ctx->connman ? (int64_t)ctx->connman->manager.num_nodes : 0);
        json_push_back(result, &svc);
        json_free(&svc);
    }

    /* bg_validation */
    {
        struct json_value svc = {0};
        json_set_object(&svc);
        json_push_kv_str(&svc, "name", "bg_validation");
        if (ctx->bg_valid) {
            struct bg_validation_progress p =
                bg_validation_get_progress(ctx->bg_valid);
            json_push_kv_str(&svc, "state",
                bg_validation_state_name(p.state));
            json_push_kv_int(&svc, "verified_height", p.verified_height);
            json_push_kv_int(&svc, "sigs_verified", p.sigs_verified);
        } else {
            json_push_kv_str(&svc, "state", "not_initialized");
        }
        json_push_back(result, &svc);
        json_free(&svc);
    }

    /* bg_hash_verify */
    {
        struct json_value svc = {0};
        json_set_object(&svc);
        json_push_kv_str(&svc, "name", "bg_hash_verify");
        if (ctx->bg_hash) {
            struct bg_hash_verify_progress p =
                bg_hash_verify_get_progress(ctx->bg_hash);
            json_push_kv_str(&svc, "state",
                bg_hash_verify_state_name(p.state));
            json_push_kv_int(&svc, "verified_height", p.verified_height);
            json_push_kv_int(&svc, "mismatches", p.mismatches);
        } else {
            json_push_kv_str(&svc, "state", "not_initialized");
        }
        json_push_back(result, &svc);
        json_free(&svc);
    }

    /* Game platform */
    {
        int64_t game_count = (int64_t)game_type_count();
        struct json_value svc = {0};
        json_set_object(&svc);
        json_push_kv_str(&svc, "name", "game_platform");
        /* State is "running" only when at least one game type is
         * registered. Empty registry → "idle", mirroring the
         * conditional pattern used by p2p above. */
        json_push_kv_str(&svc, "state",
                         game_count > 0 ? "running" : "idle");
        json_push_kv_int(&svc, "registered_types", game_count);
        json_push_back(result, &svc);
        json_free(&svc);
    }

    /* Legacy mirror */
    {
        struct legacy_mirror_sync_stats ms;
        legacy_mirror_sync_stats_snapshot(&ms);

        struct json_value svc = {0};
        json_set_object(&svc);
        json_push_kv_str(&svc, "name", "legacy_mirror");
        json_push_kv_str(&svc, "state", ms.enabled ? ms.state : "disabled");
        json_push_kv_bool(&svc, "mirror_enabled", ms.enabled);
        json_push_kv_bool(&svc, "mirror_reachable", ms.reachable);
        json_push_kv_bool(&svc, "mirror_monitor_running", ms.running);
        json_push_kv_bool(&svc, "zclassicd_rpc_transport_reachable",
                          ms.zclassicd_rpc_transport_reachable);
        json_push_kv_bool(&svc, "legacy_oracle_usable",
                          ms.legacy_oracle_usable);
        json_push_kv_int(&svc, "zclassicd_rpc_error_code",
                         ms.zclassicd_rpc_error_code);
        json_push_kv_str(&svc, "zclassicd_rpc_error_message",
                         ms.zclassicd_rpc_error_message);
        json_push_kv_str(&svc, "consensus_authority",
                         ms.consensus_authority);
        json_push_kv_str(&svc, "candidate_source", "legacy_advisory");
        json_push_kv_str(&svc, "candidate_trust",
                         ms.candidate_trust);
        json_push_kv_bool(&svc, "candidate_lag_known", ms.lag_known);
        json_push_kv_bool(&svc, "candidate_lag_valid", ms.lag_valid);
        json_push_kv_bool(&svc, "tip_hashes_agree",
                          ms.tip_hashes_agree);
        json_push_kv_bool(&svc, "blocker_recovered_by_tip_agreement",
                          ms.blocker_recovered_by_tip_agreement);
        json_push_kv_int(&svc, "candidate_lag",
                         legacy_mirror_sync_reported_lag(&ms));
        legacy_mirror_sync_push_observed_lag_json(
            &svc, "candidate_lag_observed", &ms);
        json_push_kv_str(&svc, "candidate_blocker",
                         ms.enabled
                             ? legacy_mirror_sync_blocker_code(&ms)
                             : "");
        json_push_kv_str(&svc, "candidate_blocker_scope",
                         ms.enabled && legacy_mirror_sync_blocker_code(&ms)[0]
                             ? "advisory_source"
                             : "");
        json_push_kv_int(&svc, "legacy_height", ms.legacy_height);
        json_push_kv_int(&svc, "local_height", ms.local_height);
        json_push_kv_bool(&svc, "lag_known", ms.lag_known);
        json_push_kv_bool(&svc, "lag_valid", ms.lag_valid);
        json_push_kv_int(&svc, "lag",
                         legacy_mirror_sync_reported_lag(&ms));
        legacy_mirror_sync_push_observed_lag_json(&svc, "lag_observed", &ms);
        json_push_kv_bool(&svc, "local_recovery_active",
                          ms.local_recovery_active);
        json_push_kv_bool(&svc, "legacy_advisory_gated_by_native_retries",
                          ms.mirror_repair_gated_by_local_retries);
        json_push_kv_bool(&svc, "mirror_repair_gated_by_local_retries",
                          ms.mirror_repair_gated_by_local_retries);
        json_push_kv_bool(&svc, "local_retries_exhausted",
                          ms.local_retries_exhausted);
        json_push_kv_int(&svc, "stalls_total", ms.stalls_total);
        json_push_kv_int(&svc, "lag_sla_breach_blocks",
                         ms.lag_sla_breach_blocks);
        json_push_kv_int(&svc, "lag_sla_breach_secs",
                         ms.lag_sla_breach_secs);
        json_push_kv_int(&svc, "lag_sla_critical_blocks",
                         ms.lag_sla_critical_blocks);
        json_push_kv_int(&svc, "lag_sla_critical_secs",
                         ms.lag_sla_critical_secs);
        json_push_kv_int(&svc, "lag_breach_seconds", ms.lag_breach_seconds);
        json_push_kv_int(&svc, "lag_critical_seconds", ms.lag_critical_seconds);
        json_push_kv_str(&svc, "lag_breach_severity", ms.lag_breach_severity);
        json_push_kv_str(&svc, "activation_blocker",
                         ms.enabled ? ms.activation_blocker_reason : "");
        json_push_kv_str(&svc, "last_blocker_code",
                         ms.enabled ? ms.last_blocker_id : "");
        json_push_kv_str(&svc, "active_error_code",
                         ms.enabled ? legacy_mirror_sync_blocker_code(&ms) : "");
        json_push_kv_str(&svc, "active_error_detail",
                         ms.enabled && legacy_mirror_sync_blocker_code(&ms)[0]
                             ? ms.last_error
                             : "");
        json_push_kv_int(&svc, "rpc_errors", ms.rpc_errors);
        json_push_kv_int(&svc, "overrides_total", ms.overrides_total);
        json_push_kv_int(&svc, "unsafe_overrides_total",
                         ms.unsafe_overrides_total);
        json_push_kv_int(&svc, "blockers_total",
                         ms.enabled ? ms.blockers_total : 0);
        json_push_kv_bool(&svc, "last_override_safe",
                          ms.last_override_safe);
        json_push_kv_str(&svc, "last_override_reason",
                         ms.last_override_reason);
        json_push_kv_str(&svc, "last_override_scope",
                         ms.last_override_scope);
        json_push_kv_int(&svc, "last_catchup", ms.last_catchup);
        json_push_kv_str(&svc, "last_error", ms.last_error);
        json_push_back(result, &svc);
        json_free(&svc);
    }

    /* Canonical chain advance coordinator */
    {
        struct bsp_decision d;
        block_source_policy_get_status(&d);

        struct json_value svc = {0};
        json_set_object(&svc);
        json_push_kv_str(&svc, "name", "chain_advance_coordinator");
        json_push_kv_str(&svc, "state",
                         d.result == BSP_DECISION_USE_SOURCE ? "ready" :
                         d.result == BSP_DECISION_WAIT ? "waiting" :
                         d.result == BSP_DECISION_BLOCKED ? "blocked" :
                         "recovering");
        json_push_kv_str(&svc, "decision",
                         bsp_decision_result_name(d.result));
        json_push_kv_str(&svc, "authority",
                         "local_consensus_validation");
        json_push_kv_str(&svc, "selected_source",
                         bsp_source_name(d.selected_source));
        json_push_kv_str(&svc, "selected_source_trust",
                         bsp_source_trust_name(d.selected_source));
        json_push_kv_bool(&svc, "activation_allowed",
                          d.activation_allowed);
        json_push_kv_bool(&svc, "mirror_fallback_allowed",
                          d.mirror_fallback_allowed);
        json_push_kv_int(&svc, "local_height", d.local_height);
        json_push_kv_int(&svc, "best_header_height",
                         d.best_header_height);
        json_push_kv_int(&svc, "target_height", d.target_height);
        json_push_kv_int(&svc, "projection_height",
                         d.projection_height);
        json_push_kv_int(&svc, "projection_lag", d.projection_lag);
        json_push_kv_bool(&svc, "projection_deferred",
                          d.projection_deferred);
        json_push_kv_str(&svc, "projection_state",
                         d.projection_state);
        json_push_kv_int(&svc, "projection_deferred_total",
                         d.projection_deferred_total);
        json_push_kv_int(&svc, "last_projection_deferred_height",
                         d.last_projection_deferred_height);
        json_push_kv_int(&svc, "last_projection_deferred_time",
                         d.last_projection_deferred_time);
        json_push_kv_str(&svc, "last_projection_deferred_reason",
                         d.last_projection_deferred_reason);
        json_push_kv_int(&svc, "selected_score", d.selected_score);
        if (d.selected_source > BSP_SOURCE_NONE &&
            d.selected_source < BSP_SOURCE_NUM) {
            const struct bsp_source_status *s = &d.sources[d.selected_source];
            json_push_kv_bool(&svc, "selected_source_selectable",
                              s->selectable);
            json_push_kv_str(&svc, "selected_source_selection_blocker",
                             s->selection_reason);
            json_push_kv_int(&svc, "selected_source_score_base",
                             s->score_base);
            json_push_kv_int(&svc, "selected_source_score_health",
                             s->score_health);
            json_push_kv_int(&svc, "selected_source_score_height",
                             s->score_height);
            json_push_kv_int(&svc, "selected_source_score_authorized",
                             s->score_authorized);
            json_push_kv_int(&svc,
                             "selected_source_score_target_lag_penalty",
                             s->score_target_lag_penalty);
            json_push_kv_int(&svc, "selected_source_score_failure_penalty",
                             s->score_failure_penalty);
            json_push_kv_int(&svc,
                             "selected_source_score_mirror_gate_penalty",
                             s->score_mirror_gate_penalty);
        }
        json_push_kv_str(&svc, "reason", d.reason);
        json_push_kv_str(&svc, "blocker", d.blocker);
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
                    json_push_kv(&svc, "initialized", initialized);
                if (has_connman)
                    json_push_kv(&svc, "has_connman", has_connman);
                if (has_main_state)
                    json_push_kv(&svc, "has_main_state", has_main_state);
                if (has_node_db)
                    json_push_kv(&svc, "has_node_db", has_node_db);
                if (has_last)
                    json_push_kv(&svc, "has_last_decision", has_last);
                if (last)
                    json_push_kv(&svc, "last_decision", last);
                if (sources)
                    json_push_kv(&svc, "sources", sources);
            }
            json_free(&dump);
        }
        json_push_back(result, &svc);
        json_free(&svc);
    }

    return true;
}

/* ── RPC: getsyncwatchdog ───────────────────────────────────── */

static bool rpc_getsyncwatchdog(const struct json_value *params, bool help,
                                struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getsyncwatchdog\n"
        "\nReturn sync watchdog status including recovery history.\n"
        "\nResult: object with watchdog state, checks_run, recoveries, etc.");

    json_set_object(result);
    json_push_kv_bool(result, "enabled", true);
    json_push_kv_int(result, "active_conditions",
                     condition_engine_get_active_count());
    json_push_kv_int(result, "unresolved_conditions",
                     condition_engine_get_unresolved_count());
    json_push_kv_str(result, "current_state", sync_state_name(sync_get_state()));
    json_push_kv_int(result, "current_state_duration_secs",
                     sync_get_state_duration());
    /* Always 0 today: entry-height tracking is not yet wired in
     * core/modules/sync/src/sync_state.c. Not a live metric — see
     * sync_get_state_entry_height in sync/sync_state.h. */
    json_push_kv_int(result, "current_state_entry_height",
                     (int64_t)sync_get_state_entry_height());
    push_watchdog_recovery_fields(result);

    return true;
}

/* ── RPC: getsyncdiag ────────────────────────────────────────── */

static bool rpc_getsyncdiag(const struct json_value *params, bool help,
                            struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getsyncdiag\n"
        "\nReturn combined sync diagnostics: watchdog, header counters, sync state.\n"
        "\nResult: object with watchdog, headers, sync_state, chain_height, "
        "best_header_height.");

    json_set_object(result);

    /* Watchdog status now aliases condition-engine health. */
    {
        struct json_value wd = {0};
        json_set_object(&wd);
        json_push_kv_bool(&wd, "enabled", true);
        json_push_kv_int(&wd, "active_conditions",
                         condition_engine_get_active_count());
        json_push_kv_int(&wd, "unresolved_conditions",
                         condition_engine_get_unresolved_count());
        push_watchdog_recovery_fields(&wd);
        json_push_kv(result, "watchdog", &wd);
        json_free(&wd);
    }

    /* Header sync counters */
    {
        struct msg_headers_stats hs;
        msg_headers_get_stats(&hs);

        struct json_value hdr = {0};
        json_set_object(&hdr);
        json_push_kv_int(&hdr, "batches_received", (int64_t)hs.batches_received);
        json_push_kv_int(&hdr, "total_accepted", (int64_t)hs.total_accepted);
        json_push_kv_int(&hdr, "total_rejected", (int64_t)hs.total_rejected);
        json_push_kv_int(&hdr, "newly_added", (int64_t)hs.newly_added);
        json_push_kv_int(&hdr, "already_known", (int64_t)hs.already_known);
        json_push_kv_int(&hdr, "getheaders_suppressed_no_hash",
                         (int64_t)hs.getheaders_suppressed_no_hash);
        json_push_kv_int(&hdr, "getheaders_suppressed_snapshot",
                         (int64_t)hs.getheaders_suppressed_snapshot);
        json_push_kv_int(&hdr, "headers_recv_suppressed_snapshot",
                         (int64_t)hs.headers_recv_suppressed_snapshot);
        json_push_kv_int(&hdr, "push_getheaders_suppressed_snapshot",
                         (int64_t)hs.push_getheaders_suppressed_snapshot);
        json_push_kv_int(&hdr, "push_getheaders_span_suppressed_snapshot",
                         (int64_t)hs.push_getheaders_span_suppressed_snapshot);
        json_push_kv_int(&hdr, "push_getheaders_span_alloc_fail",
                         (int64_t)hs.push_getheaders_span_alloc_fail);
        json_push_kv_int(&hdr, "getheaders_deferred_snapshot_serving",
                         (int64_t)hs.getheaders_deferred_snapshot_serving);
        json_push_kv(result, "headers", &hdr);
        json_free(&hdr);
    }

    /* Sync state */
    enum sync_state ss = sync_get_state();
    json_push_kv_str(result, "sync_state", sync_state_name(ss));
    json_push_kv_int(result, "sync_state_duration_secs",
                     sync_get_state_duration());

    /* Chain and header heights */
    int chain_h = 0;
    int best_header_h = 0;
    if (g_health_ctx.main_state) {
        chain_h = reducer_frontier_provable_tip_cached();
        if (g_health_ctx.main_state->pindex_best_header)
            best_header_h =
                g_health_ctx.main_state->pindex_best_header->nHeight;
    }
    json_push_kv_int(result, "chain_height", (int64_t)chain_h);
    json_push_kv_int(result, "best_header_height", (int64_t)best_header_h);

    push_mirror_sync_fields(result);

    return true;
}

/* ── REST API helpers ─────────────────────────────────────────── */

bool api_getsyncdetail(struct json_value *result)
{
    return rpc_getsyncdetail(NULL, false, result);
}

bool api_getservicehealth(struct json_value *result)
{
    return rpc_getservicehealth(NULL, false, result);
}

/* ── Registration ────────────────────────────────────────────── */

void register_health_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "control", "getsyncdetail",     rpc_getsyncdetail,     true },
        { "control", "getservicehealth",  rpc_getservicehealth,  true },
        { "control", "getsyncwatchdog",   rpc_getsyncwatchdog,   true },
        { "control", "getsyncdiag",       rpc_getsyncdiag,       true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
