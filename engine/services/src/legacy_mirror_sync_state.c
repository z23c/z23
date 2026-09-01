/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Runtime state snapshots, lifecycle wiring, and test hooks for the legacy
 * mirror monitor. The catchup tick logic lives in legacy_mirror_sync_service.c. */
// one-result-type-ok:predicate-and-json-dump-bool —
// legacy_mirror_sync_blocker_should_surface is a pure decision predicate (an
// answer, not a failure: "should this already-recorded blocker be surfaced
// to the operator right now?"), consumed as a raw bool by
// agent_operator_contracts.c, health_controller.c, and
// event_healthcheck_controller.c. It has no fallible surface to convert.

#include "services/legacy_mirror_sync_service.h"
#include "legacy_mirror_sync_internal.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "rpc/legacy_rpc_client.h"
#include "services/mirror_divergence_locator.h"
#include "services/sync_monitor.h"
#include "supervisors/legacy_mirror_supervisor.h"
#include "util/blocker.h"
#include "util/clientversion.h"
#include "util/log_macros.h"
#include "validation/mirror_consensus.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static const char *lms_state_name(const struct legacy_mirror_sync_stats *s)
{
    if (!s || !s->enabled || !s->running)
        return "blocked";
    if (s->activation_blocker_reason[0] || s->last_blocker_id[0] ||
        s->csr_sqlite_rc != 0)
        return "blocked";
    if (s->lag_known &&
        s->lag_sla_breach_blocks > 0 &&
        s->lag >= s->lag_sla_breach_blocks)
        return "concurrent_catchup";
    if (s->mirror_repair_gated_by_local_retries)
        return "gated_by_local_retries";
    if (s->lag_known && s->lag < 0)
        return "observing";
    if (s->lag_known && s->lag <= 1)
        return "healthy";
    if (s->in_flight || s->last_progress_blocks > 0 ||
        (s->lag_known && s->lag > 1))
        return "catching_up";
    return "observing";
}

static bool lms_blocker_cleared_by_catchup(const char *code,
                                           bool lag_known,
                                           int lag)
{
    return code && lag_known &&
           strcmp(code, "activation-no-progress") == 0 && lag <= 0;
}

static bool lms_tips_agree(const struct legacy_mirror_sync_stats *s)
{
    return s && s->lag_known &&
           s->local_height >= 0 &&
           s->legacy_height >= 0 &&
           s->local_height == s->legacy_height &&
           s->zclassic23_hash[0] &&
           s->zclassicd_hash[0] &&
           strcasecmp(s->zclassic23_hash, s->zclassicd_hash) == 0;
}

static bool lms_hash_disagreement_recovered(
    const char *code,
    const struct legacy_mirror_sync_stats *s)
{
    if (!code || strcmp(code, "hash-disagreement") != 0 || !s ||
        s->hash_disagreement_height < 0)
        return false;
    if (s->comparison_known && s->comparison_hashes_agree &&
        s->comparison_height >= s->hash_disagreement_height)
        return true;
    return s->tip_hashes_agree &&
           s->local_height >= s->hash_disagreement_height;
}

static int lms_rpc_error_code(const char *err)
{
    int code = 0;
    if (err && sscanf(err, "rpc error %d", &code) == 1)
        return code;
    return 0;
}

static bool lms_error_implies_transport_reachable(const char *err)
{
    if (!err || !err[0])
        return false;
    return strncmp(err, "rpc error", 9) == 0 ||
           strncmp(err, "missing ", 8) == 0 ||
           strcmp(err, "json parse failed") == 0 ||
           strcmp(err, "no http body separator") == 0;
}

static void lms_rpc_error_message(const char *err, char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return;
    out[0] = '\0';
    if (!err || !err[0])
        return;
    const char *p = strchr(err, ':');
    if (p && p[1] == ' ')
        p += 2;
    else
        p = err;
    snprintf(out, out_sz, "%s", p);
}

int legacy_mirror_sync_reported_lag(
    const struct legacy_mirror_sync_stats *s)
{
    return (s && s->lag_known) ? s->lag : 0;
}

void legacy_mirror_sync_push_observed_lag_json(
    struct json_value *out,
    const char *key,
    const struct legacy_mirror_sync_stats *s)
{
    if (!out || !key)
        return;
    if (s && s->lag_known) {
        json_push_kv_int(out, key, s->lag);
        return;
    }
    struct json_value nullv;
    json_init(&nullv);
    json_set_null(&nullv);
    json_push_kv(out, key, &nullv);
    json_free(&nullv);
}

const char *legacy_mirror_sync_blocker_code(
    const struct legacy_mirror_sync_stats *s)
{
    if (!s)
        return "";
    return s->activation_blocker_reason[0] ? s->activation_blocker_reason
                                           : s->last_blocker_id;
}

bool legacy_mirror_sync_blocker_is_active(
    const struct legacy_mirror_sync_stats *s)
{
    const char *blocker = legacy_mirror_sync_blocker_code(s);
    if (!blocker || !blocker[0])
        return false;
    bool exact_hash_recovery =
        strcmp(blocker, "hash-disagreement") == 0 &&
        (s->blocker_recovered_by_tip_agreement ||
         s->blocker_recovered_by_common_height_agreement);
    return !exact_hash_recovery;
}

bool legacy_mirror_sync_blocker_should_surface(
    const struct legacy_mirror_sync_stats *s,
    bool non_legacy_source_selected)
{
    if (!s || !s->enabled)
        return false;
    const char *code = legacy_mirror_sync_blocker_code(s);
    if (!code[0])
        return false;
    if (s->unsafe_overrides_total > 0)
        return true;
    if (strcmp(code, "rpc-unreachable") == 0 ||
        strcmp(code, "activation-no-progress") == 0)
        return !non_legacy_source_selected;
    if (s->activation_blocker_class == BLOCKER_PERMANENT ||
        s->last_blocker_class == BLOCKER_PERMANENT)
        return true;
    return !non_legacy_source_selected;
}

void legacy_mirror_sync_push_status_contract_json(
    struct json_value *out,
    const struct legacy_mirror_sync_stats *s)
{
    if (!out || !s)
        return;
    const char *blocker = legacy_mirror_sync_blocker_code(s);
    bool blocker_active = legacy_mirror_sync_blocker_is_active(s);
    bool operator_action_required =
        blocker_active && legacy_mirror_sync_blocker_should_surface(s, false);
    struct json_value obj = {0};
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.mirror_status.v2");
    json_push_kv_int(&obj, "schema_version", 1);
    json_push_kv_bool(&obj, "advisory_only", true);
    json_push_kv_str(&obj, "consensus_authority", s->consensus_authority);
    json_push_kv_str(&obj, "status", s->state);
    json_push_kv_bool(&obj, "mirror_running", s->running);
    json_push_kv_bool(&obj, "reachable", s->reachable);
    json_push_kv_bool(&obj, "legacy_oracle_usable",
                      s->legacy_oracle_usable);
    json_push_kv_bool(&obj, "lag_known", s->lag_known);
    json_push_kv_int(&obj, "lag_blocks", legacy_mirror_sync_reported_lag(s));
    json_push_kv_bool(&obj, "same_height",
                      s->lag_known && s->lag == 0);
    json_push_kv_bool(&obj, "tip_hashes_agree", s->tip_hashes_agree);
    json_push_kv_int(&obj, "comparison_height", s->comparison_height);
    json_push_kv_bool(&obj, "comparison_known", s->comparison_known);
    json_push_kv_bool(&obj, "comparison_hashes_agree",
                      s->comparison_hashes_agree);
    json_push_kv_bool(&obj, "same_chain_at_comparison_height",
                      s->comparison_known && s->comparison_hashes_agree);
    json_push_kv_int(&obj, "hash_disagreement_height",
                     s->hash_disagreement_height);
    json_push_kv_bool(&obj, "blocker_active", blocker_active);
    json_push_kv_str(&obj, "blocker_code", blocker_active ? blocker : "");
    json_push_kv_bool(&obj, "blocker_recovered_by_tip_agreement",
                      s->blocker_recovered_by_tip_agreement);
    json_push_kv_bool(
        &obj, "blocker_recovered_by_common_height_agreement",
        s->blocker_recovered_by_common_height_agreement);
    json_push_kv_bool(&obj, "operator_action_required",
                      operator_action_required);
    json_push_kv_str(
        &obj, "semantics",
        "legacy mirror is advisory; local consensus remains authoritative; "
        "tip hashes are comparable only at equal heights, while explicit "
        "comparison fields prove same-chain agreement at one common height");
    json_push_kv(out, "mirror_contract", &obj);
    json_free(&obj);
}

struct zcl_result legacy_mirror_sync_request_catchup_result(const char *reason)
{
    return lms_request_catchup_result_internal(reason);
}

/* zcl_result error band for this file: -200..-209. The -1 code is owned
 * by lms_request_catchup_result_internal in legacy_mirror_sync_service.c. */
struct zcl_result
legacy_mirror_sync_init(const struct legacy_mirror_sync_config *cfg,
                        struct main_state *ms,
                        struct coins_view_cache *coins_tip,
                        const struct chain_params *params,
                        const char *datadir)
{
    pthread_mutex_lock(&g_lms.lock);

    snprintf(g_lms.rpc_host, sizeof(g_lms.rpc_host), "%s",
             (cfg && cfg->rpc_host) ? cfg->rpc_host : LMS_DEFAULT_HOST);
    g_lms.rpc_port = (cfg && cfg->rpc_port > 0)
                         ? cfg->rpc_port : ZCLASSICD_RPC_DEFAULT_PORT;
    g_lms.cadence_secs = (cfg && cfg->cadence_secs > 0)
                         ? cfg->cadence_secs : LMS_DEFAULT_CADENCE;
    g_lms.max_blocks_tick = (cfg && cfg->max_blocks_tick > 0)
                         ? cfg->max_blocks_tick : LMS_DEFAULT_MAX_BLOCKS;
    g_lms.lag_sla = (cfg && cfg->lag_sla >= 0)
                         ? cfg->lag_sla : LMS_DEFAULT_LAG_SLA;
    g_lms.cadence_secs = lms_env_int("ZCL_MIRROR_CADENCE_SECS",
                                     g_lms.cadence_secs, 1, 300);
    g_lms.max_blocks_tick = lms_env_int("ZCL_MIRROR_MAX_BLOCKS_PER_TICK",
                                        g_lms.max_blocks_tick, 1, 20000);
    g_lms.lag_sla = lms_env_int("ZCL_MIRROR_LAG_SLA",
                                g_lms.lag_sla, 0, 10000);

    atomic_store(&g_lms.lag_sla_breach_blocks,
        (cfg && cfg->lag_sla_breach_blocks > 0)
        ? cfg->lag_sla_breach_blocks
        : LMS_DEFAULT_LAG_SLA_BREACH_BLOCKS);
    atomic_store(&g_lms.lag_sla_breach_blocks,
        lms_env_int("ZCL_MIRROR_LAG_SLA_BREACH_BLOCKS",
                    atomic_load(&g_lms.lag_sla_breach_blocks), 1, 100000));

    atomic_store(&g_lms.lag_sla_breach_secs,
        (cfg && cfg->lag_sla_breach_secs > 0)
        ? cfg->lag_sla_breach_secs
        : LMS_DEFAULT_LAG_SLA_BREACH_SECS);
    atomic_store(&g_lms.lag_sla_breach_secs,
        lms_env_int("ZCL_MIRROR_LAG_SLA_BREACH_SECS",
                    atomic_load(&g_lms.lag_sla_breach_secs), 1, 86400));

    atomic_store(&g_lms.lag_sla_critical_blocks,
        (cfg && cfg->lag_sla_critical_blocks > 0)
        ? cfg->lag_sla_critical_blocks
        : LMS_DEFAULT_LAG_SLA_CRITICAL_BLOCKS);
    atomic_store(&g_lms.lag_sla_critical_blocks,
        lms_env_int("ZCL_MIRROR_LAG_SLA_CRITICAL_BLOCKS",
                    atomic_load(&g_lms.lag_sla_critical_blocks), 1, 1000000));

    atomic_store(&g_lms.lag_sla_critical_secs,
        (cfg && cfg->lag_sla_critical_secs > 0)
        ? cfg->lag_sla_critical_secs
        : LMS_DEFAULT_LAG_SLA_CRITICAL_SECS);
    atomic_store(&g_lms.lag_sla_critical_secs,
        lms_env_int("ZCL_MIRROR_LAG_SLA_CRITICAL_SECS",
                    atomic_load(&g_lms.lag_sla_critical_secs), 1, 86400));

    g_lms.ms = ms;
    g_lms.coins_tip = coins_tip;
    g_lms.params = params;
    snprintf(g_lms.datadir, sizeof(g_lms.datadir), "%s",
             datadir ? datadir : "");

    if (cfg && cfg->rpc_user && cfg->rpc_user[0])
        snprintf(g_lms.rpc_user, sizeof(g_lms.rpc_user), "%s",
                 cfg->rpc_user);
    if (cfg && cfg->rpc_password && cfg->rpc_password[0])
        snprintf(g_lms.rpc_password, sizeof(g_lms.rpc_password), "%s",
                 cfg->rpc_password);

    /* Fill any missing credential from zclassic.conf; an explicit port
     * (cfg->rpc_port > 0) is never overridden. A missing set is not
     * fatal here — the have-creds check below decides enablement. */
    bool have_creds = legacy_rpc_fill_missing_creds(
        g_lms.rpc_user, sizeof(g_lms.rpc_user),
        g_lms.rpc_password, sizeof(g_lms.rpc_password),
        &g_lms.rpc_port, cfg && cfg->rpc_port > 0);
    g_lms.enabled = (cfg ? cfg->enabled : true) && have_creds &&
                    !lms_env_disabled();
    mirror_consensus_set_enabled(g_lms.enabled);
    g_lms.initialized = true;
    pthread_mutex_unlock(&g_lms.lock);

    if (!have_creds) {
        lms_set_error("no zclassicd RPC credentials");
        return ZCL_ERR(-200, "no zclassicd RPC credentials");
    }
    return ZCL_OK;
}

void legacy_mirror_sync_reload_from_env(void)
{
    if (!g_lms.initialized)
        return;
    pthread_mutex_lock(&g_lms.lock);
    g_lms.cadence_secs = lms_env_int("ZCL_MIRROR_CADENCE_SECS",
                                     g_lms.cadence_secs, 1, 300);
    g_lms.max_blocks_tick = lms_env_int("ZCL_MIRROR_MAX_BLOCKS_PER_TICK",
                                        g_lms.max_blocks_tick, 1, 20000);
    g_lms.lag_sla = lms_env_int("ZCL_MIRROR_LAG_SLA",
                                g_lms.lag_sla, 0, 10000);
    atomic_store(&g_lms.lag_sla_breach_blocks,
        lms_env_int("ZCL_MIRROR_LAG_SLA_BREACH_BLOCKS",
                    atomic_load(&g_lms.lag_sla_breach_blocks), 1, 100000));
    atomic_store(&g_lms.lag_sla_breach_secs,
        lms_env_int("ZCL_MIRROR_LAG_SLA_BREACH_SECS",
                    atomic_load(&g_lms.lag_sla_breach_secs), 1, 86400));
    atomic_store(&g_lms.lag_sla_critical_blocks,
        lms_env_int("ZCL_MIRROR_LAG_SLA_CRITICAL_BLOCKS",
                    atomic_load(&g_lms.lag_sla_critical_blocks), 1, 1000000));
    atomic_store(&g_lms.lag_sla_critical_secs,
        lms_env_int("ZCL_MIRROR_LAG_SLA_CRITICAL_SECS",
                    atomic_load(&g_lms.lag_sla_critical_secs), 1, 86400));
    pthread_mutex_unlock(&g_lms.lock);
}

struct zcl_result legacy_mirror_sync_start(void)
{
    if (!g_lms.initialized) {
        fprintf(stderr, "[legacy_mirror] start before init\n");
        return ZCL_ERR(-201, "legacy_mirror start before init");
    }
    if (!g_lms.enabled)
        return ZCL_OK;
    int cad = g_lms.cadence_secs > 0 ? g_lms.cadence_secs
                                     : LMS_DEFAULT_CADENCE;
    if (!legacy_mirror_supervisor_start(cad))
        return ZCL_ERR(-202,
                       "legacy_mirror supervisor start failed cadence=%d",
                       cad);
    return ZCL_OK;
}

void legacy_mirror_sync_stop(void)
{
    legacy_mirror_supervisor_stop();
}

static void legacy_mirror_sync_stats_snapshot_impl(
    struct legacy_mirror_sync_stats *out,
    bool refresh_local_heights,
    bool resolve_local_hash)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (refresh_local_heights)
        lms_refresh_local_heights(NULL, NULL);
    pthread_mutex_lock(&g_lms.lock);
    out->enabled = g_lms.enabled;
#ifdef ZCL_TESTING
    out->running = g_lms_test_fake_running ||
                   legacy_mirror_supervisor_running();
#else
    out->running = legacy_mirror_supervisor_running();
#endif
    snprintf(out->zclassicd_hash, sizeof(out->zclassicd_hash), "%s",
             g_lms.zclassicd_hash);
    out->comparison_height = g_lms.comparison_height;
    out->hash_disagreement_height = g_lms.hash_disagreement_height;
    out->comparison_known = g_lms.comparison_known;
    out->comparison_hashes_agree =
        g_lms.comparison_known && g_lms.comparison_hashes_agree;
    snprintf(out->comparison_zclassic23_hash,
             sizeof(out->comparison_zclassic23_hash), "%s",
             g_lms.comparison_zclassic23_hash);
    snprintf(out->comparison_zclassicd_hash,
             sizeof(out->comparison_zclassicd_hash), "%s",
             g_lms.comparison_zclassicd_hash);
    snprintf(out->last_error, sizeof(out->last_error), "%s",
             g_lms.last_error);
    snprintf(out->last_blocker_id, sizeof(out->last_blocker_id), "%s",
             g_lms.last_blocker_id);
    out->last_blocker_class = out->last_blocker_id[0]
                                  ? g_lms.last_blocker_class
                                  : BLOCKER_TRANSIENT;
    snprintf(out->csr_failure_reason, sizeof(out->csr_failure_reason), "%s",
             g_lms.csr_failure_reason);
    snprintf(out->stuck_reason, sizeof(out->stuck_reason), "%s",
             g_lms.stuck_reason);
    snprintf(out->zclassic23_hash, sizeof(out->zclassic23_hash), "%s",
             g_lms.zclassic23_hash);
    pthread_mutex_unlock(&g_lms.lock);
    out->reachable = atomic_load(&g_lms.reachable) != 0;
    out->in_flight = atomic_load(&g_lms.in_flight) != 0;
    out->legacy_height = atomic_load(&g_lms.legacy_height);
    out->legacy_headers = atomic_load(&g_lms.legacy_headers);
    out->local_height = atomic_load(&g_lms.local_height);
    out->best_header_height = atomic_load(&g_lms.best_header_height);
    out->legacy_advisory_height_known =
        out->enabled && out->reachable && out->legacy_height >= 0;
    out->target_height_known = out->legacy_advisory_height_known;
    out->lag_known = out->legacy_advisory_height_known &&
                     out->local_height >= 0;
    out->lag_valid = out->lag_known;
    if (resolve_local_hash &&
        !lms_local_hash_at(out->local_height, out->zclassic23_hash).ok) {
        pthread_mutex_lock(&g_lms.lock);
        snprintf(out->zclassic23_hash, sizeof(out->zclassic23_hash), "%s",
                 g_lms.zclassic23_hash);
        pthread_mutex_unlock(&g_lms.lock);
    }
    out->lag = out->lag_known ? out->legacy_height - out->local_height : 0;
    out->tip_hashes_agree = lms_tips_agree(out);
    out->zclassicd_rpc_transport_reachable =
        out->reachable || lms_error_implies_transport_reachable(out->last_error);
    out->legacy_oracle_usable =
        out->enabled && out->reachable && out->legacy_advisory_height_known &&
        out->comparison_known;
    out->zclassicd_rpc_error_code = lms_rpc_error_code(out->last_error);
    lms_rpc_error_message(out->last_error, out->zclassicd_rpc_error_message,
                          sizeof(out->zclassicd_rpc_error_message));
    out->target_height = atomic_load(&g_lms.target_height);
    out->authority_rewind_target =
        atomic_load(&g_lms.authority_rewind_target);
    out->csr_sqlite_rc = atomic_load(&g_lms.csr_sqlite_rc);
    out->last_advanced_height = atomic_load(&g_lms.last_advanced_height);
    out->last_progress_blocks = atomic_load(&g_lms.last_progress_blocks);
    {
        struct watchdog_local_recovery_stats lr;
        sync_monitor_get_local_recovery_stats(&lr);
        out->local_recovery_active = lr.active;
        out->mirror_repair_gated_by_local_retries =
            lr.mirror_repair_gated;
        out->local_retries_exhausted = lr.retries_exhausted;
        out->local_missing_height = lr.missing_height;
        out->local_retry_count = lr.retry_count;
        out->local_distinct_peer_count = lr.distinct_peer_count;
        out->local_peer_rotation_count = lr.peer_rotation_count;
    }
    out->stuck_height = atomic_load(&g_lms.stuck_height);
    out->stuck_status_flags = atomic_load(&g_lms.stuck_status_flags);
    out->stalls_total = atomic_load(&g_lms.stalls_total);
    out->last_catchup = atomic_load(&g_lms.last_catchup);
    out->last_attempt = atomic_load(&g_lms.last_attempt);
    out->catchups_total = atomic_load(&g_lms.catchups_total);
    out->rpc_errors = atomic_load(&g_lms.rpc_errors);
    out->blocks_applied = atomic_load(&g_lms.blocks_applied);
    out->headers_added = atomic_load(&g_lms.headers_added);
    {
        struct mirror_consensus_stats mcs;
        mirror_consensus_stats_snapshot(&mcs);
        snprintf(out->consensus_authority,
                 sizeof(out->consensus_authority), "%s",
                 "local_consensus_validation");
        snprintf(out->candidate_trust,
                 sizeof(out->candidate_trust), "%s",
                 "bounded_advisory_fallback");
        out->override_active = mcs.override_active;
        out->overrides_total = mcs.overrides_total;
        out->unsafe_overrides_total = mcs.unsafe_overrides_total;
        out->blockers_total = mcs.blockers_total;
        out->last_override_height = mcs.last_override_height;
        out->last_override_safe = mcs.last_override_safe;
        out->activation_blocker_class = mcs.activation_blocker_class;
        snprintf(out->last_override_reason,
                 sizeof(out->last_override_reason), "%s",
                 mcs.last_override_reason);
        snprintf(out->last_override_scope,
                 sizeof(out->last_override_scope), "%s",
                 mcs.last_override_scope);
        snprintf(out->activation_blocker_reason,
                 sizeof(out->activation_blocker_reason), "%s",
                 mcs.activation_blocker_reason);
    }
    if (lms_blocker_cleared_by_catchup(out->activation_blocker_reason,
                                       out->lag_known,
                                       out->lag)) {
        out->activation_blocker_reason[0] = '\0';
    } else if (lms_hash_disagreement_recovered(
                   out->activation_blocker_reason, out)) {
        out->blocker_recovered_by_tip_agreement =
            out->tip_hashes_agree &&
            out->local_height >= out->hash_disagreement_height;
        out->blocker_recovered_by_common_height_agreement =
            out->comparison_known && out->comparison_hashes_agree &&
            out->comparison_height >= out->hash_disagreement_height;
        out->activation_blocker_reason[0] = '\0';
    }
    if (lms_blocker_cleared_by_catchup(out->last_blocker_id,
                                       out->lag_known,
                                       out->lag)) {
        out->last_blocker_id[0] = '\0';
    } else if (lms_hash_disagreement_recovered(out->last_blocker_id, out)) {
        out->blocker_recovered_by_tip_agreement =
            out->tip_hashes_agree &&
            out->local_height >= out->hash_disagreement_height;
        out->blocker_recovered_by_common_height_agreement =
            out->comparison_known && out->comparison_hashes_agree &&
            out->comparison_height >= out->hash_disagreement_height;
        out->last_blocker_id[0] = '\0';
    }
    if (!out->activation_blocker_reason[0])
        out->activation_blocker_class = BLOCKER_TRANSIENT;
    if (!out->last_blocker_id[0])
        out->last_blocker_class = BLOCKER_TRANSIENT;
    out->lag_sla_breach_blocks   = atomic_load(&g_lms.lag_sla_breach_blocks);
    out->lag_sla_breach_secs     = atomic_load(&g_lms.lag_sla_breach_secs);
    out->lag_sla_critical_blocks = atomic_load(&g_lms.lag_sla_critical_blocks);
    out->lag_sla_critical_secs   = atomic_load(&g_lms.lag_sla_critical_secs);
    out->lag_breach_since        = atomic_load(&g_lms.lag_breach_since);
    out->lag_critical_since      = atomic_load(&g_lms.lag_critical_since);
    {
        int64_t now = (int64_t)platform_time_wall_time_t();
        out->lag_breach_seconds =
            out->lag_known &&
            out->lag_breach_since > 0 && now >= out->lag_breach_since
                ? now - out->lag_breach_since : 0;
        out->lag_critical_seconds =
            out->lag_known &&
            out->lag_critical_since > 0 && now >= out->lag_critical_since
                ? now - out->lag_critical_since : 0;
    }
    const char *sev = "none";
    if (out->lag_known &&
        out->lag_critical_since > 0 &&
        out->lag_critical_seconds >= out->lag_sla_critical_secs)
        sev = "fatal";
    else if (out->lag_known && out->lag_critical_since > 0)
        sev = "critical";
    else if (out->lag_known &&
             out->lag_breach_since > 0 &&
             out->lag_breach_seconds >= out->lag_sla_breach_secs)
        sev = "critical";
    else if (out->lag_known && out->lag_breach_since > 0)
        sev = "warn";
    snprintf(out->lag_breach_severity, sizeof(out->lag_breach_severity),
             "%s", sev);
    snprintf(out->state, sizeof(out->state), "%s", lms_state_name(out));
}

void legacy_mirror_sync_stats_snapshot(
    struct legacy_mirror_sync_stats *out)
{
    legacy_mirror_sync_stats_snapshot_impl(out, true, true);
}

void legacy_mirror_sync_stats_cached_snapshot(
    struct legacy_mirror_sync_stats *out)
{
    legacy_mirror_sync_stats_snapshot_impl(out, false, false);
}

void legacy_mirror_sync_reset_for_test(void)
{
#ifdef ZCL_TESTING
    g_lms_test_fake_running = false;
#endif
    legacy_mirror_sync_stop();
    pthread_mutex_lock(&g_lms.lock);
    g_lms.initialized = false;
    g_lms.enabled = false;
    mirror_consensus_set_enabled(false);
    g_lms.rpc_host[0] = '\0';
    g_lms.rpc_port = 0;
    g_lms.rpc_user[0] = '\0';
    g_lms.rpc_password[0] = '\0';
    g_lms.datadir[0] = '\0';
    g_lms.zclassic23_hash[0] = '\0';
    g_lms.zclassicd_hash[0] = '\0';
    g_lms.comparison_known = false;
    g_lms.comparison_hashes_agree = false;
    g_lms.comparison_height = -1;
    g_lms.hash_disagreement_height = -1;
    g_lms.comparison_zclassic23_hash[0] = '\0';
    g_lms.comparison_zclassicd_hash[0] = '\0';
    g_lms.stuck_reason[0] = '\0';
    g_lms.last_blocker_class = BLOCKER_TRANSIENT;
    g_lms.last_blocker_id[0] = '\0';
    g_lms.csr_failure_reason[0] = '\0';
    g_lms.ms = NULL;
    g_lms.coins_tip = NULL;
    g_lms.params = NULL;
    g_lms.last_error[0] = '\0';
    pthread_mutex_unlock(&g_lms.lock);
    atomic_store(&g_lms.reachable, 0);
    atomic_store(&g_lms.in_flight, 0);
    atomic_store(&g_lms.legacy_height, 0);
    atomic_store(&g_lms.legacy_headers, 0);
    atomic_store(&g_lms.local_height, 0);
    atomic_store(&g_lms.best_header_height, 0);
    atomic_store(&g_lms.target_height, 0);
    atomic_store(&g_lms.authority_rewind_target, 0);
    atomic_store(&g_lms.csr_sqlite_rc, 0);
    atomic_store(&g_lms.last_advanced_height, 0);
    atomic_store(&g_lms.last_progress_blocks, 0);
    atomic_store(&g_lms.stuck_height, 0);
    atomic_store(&g_lms.stuck_status_flags, 0);
    atomic_store(&g_lms.stalls_total, 0);
    atomic_store(&g_lms.last_catchup, 0);
    atomic_store(&g_lms.last_attempt, 0);
    atomic_store(&g_lms.catchups_total, 0);
    atomic_store(&g_lms.rpc_errors, 0);
    atomic_store(&g_lms.blocks_applied, 0);
    atomic_store(&g_lms.headers_added, 0);
    atomic_store(&g_lms.lag_breach_since, 0);
    atomic_store(&g_lms.lag_critical_since, 0);
    atomic_store(&g_lms.lag_breach_emitted, 0);
    atomic_store(&g_lms.lag_critical_emitted, 0);
#ifdef ZCL_TESTING
    atomic_store(&g_lms_test_catchup_enabled, 0);
    atomic_store(&g_lms_test_catchup_result, 0);
    atomic_store(&g_lms_test_catchup_clear_stuck, 0);
    atomic_store(&g_lms_test_catchup_calls, 0);
    /* The divergence locator (check 6) fires from the lms verify path;
     * its blocker/HOLD/rate-limit must not leak across test cases. */
    mirror_divergence_reset_for_testing();
#endif
    mirror_consensus_reset_for_test();
}

#ifdef ZCL_TESTING
void legacy_mirror_sync_test_set_stats(
    const struct legacy_mirror_sync_stats *stats,
    struct main_state *ms)
{
    if (!stats)
        return;

    pthread_mutex_lock(&g_lms.lock);
    g_lms.initialized = true;
    g_lms.enabled = stats->enabled;
    g_lms_test_fake_running = stats->running;
    g_lms.ms = ms;
    snprintf(g_lms.zclassic23_hash, sizeof(g_lms.zclassic23_hash), "%s",
             stats->zclassic23_hash);
    snprintf(g_lms.zclassicd_hash, sizeof(g_lms.zclassicd_hash), "%s",
             stats->zclassicd_hash);
    g_lms.comparison_known = stats->comparison_known;
    g_lms.comparison_hashes_agree = stats->comparison_hashes_agree;
    g_lms.comparison_height = stats->comparison_height;
    g_lms.hash_disagreement_height = stats->hash_disagreement_height;
    snprintf(g_lms.comparison_zclassic23_hash,
             sizeof(g_lms.comparison_zclassic23_hash), "%s",
             stats->comparison_zclassic23_hash);
    snprintf(g_lms.comparison_zclassicd_hash,
             sizeof(g_lms.comparison_zclassicd_hash), "%s",
             stats->comparison_zclassicd_hash);
    snprintf(g_lms.stuck_reason, sizeof(g_lms.stuck_reason), "%s",
             stats->stuck_reason);
    snprintf(g_lms.last_blocker_id, sizeof(g_lms.last_blocker_id),
             "%s", stats->last_blocker_id);
    g_lms.last_blocker_class = stats->last_blocker_class;
    snprintf(g_lms.csr_failure_reason, sizeof(g_lms.csr_failure_reason),
             "%s", stats->csr_failure_reason);
    snprintf(g_lms.last_error, sizeof(g_lms.last_error), "%s",
             stats->last_error);
    pthread_mutex_unlock(&g_lms.lock);

    atomic_store(&g_lms.reachable, stats->reachable ? 1 : 0);
    atomic_store(&g_lms.in_flight, stats->in_flight ? 1 : 0);
    atomic_store(&g_lms.legacy_height, stats->legacy_height);
    atomic_store(&g_lms.legacy_headers, stats->legacy_headers);
    atomic_store(&g_lms.local_height, stats->local_height);
    atomic_store(&g_lms.best_header_height, stats->best_header_height);
    atomic_store(&g_lms.target_height, stats->target_height);
    atomic_store(&g_lms.authority_rewind_target,
                 stats->authority_rewind_target);
    atomic_store(&g_lms.csr_sqlite_rc, stats->csr_sqlite_rc);
    atomic_store(&g_lms.last_advanced_height,
                 stats->last_advanced_height);
    atomic_store(&g_lms.last_progress_blocks,
                 stats->last_progress_blocks);
    atomic_store(&g_lms.stuck_height, stats->stuck_height);
    atomic_store(&g_lms.stuck_status_flags, stats->stuck_status_flags);
    atomic_store(&g_lms.stalls_total, stats->stalls_total);
    atomic_store(&g_lms.last_catchup, stats->last_catchup);
    atomic_store(&g_lms.last_attempt, stats->last_attempt);
    atomic_store(&g_lms.catchups_total, stats->catchups_total);
    atomic_store(&g_lms.rpc_errors, stats->rpc_errors);
    atomic_store(&g_lms.blocks_applied, stats->blocks_applied);
    atomic_store(&g_lms.headers_added, stats->headers_added);
}
#endif
