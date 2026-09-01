/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Operator-facing JSON snapshot for the advisory legacy mirror monitor. */
// one-result-type-ok:json-dump-bool — mandated introspection predicate.

#include "services/legacy_mirror_sync_service.h"

#include "json/json.h"
#include "util/blocker.h"
#include "util/clientversion.h"

bool legacy_mirror_sync_dump_state_json(struct json_value *out,
                                        const char *key)
{
    (void)key;
    if (!out)
        return false;
    struct legacy_mirror_sync_stats s;
    legacy_mirror_sync_stats_snapshot(&s);
    json_push_kv_str(out, "source_id_sha256",
                     zcl_build_source_id_sha256());
    json_push_kv_str(out, "build_commit", zcl_build_commit());
    json_push_kv_bool(out, "mirror_enabled", s.enabled);
    json_push_kv_str(out, "state", s.state);
    legacy_mirror_sync_push_status_contract_json(out, &s);
    json_push_kv_bool(out, "mirror_monitor_running", s.running);
    json_push_kv_bool(out, "mirror_running", s.running);
    json_push_kv_bool(out, "running", s.running);
    json_push_kv_bool(out, "reachable", s.reachable);
    json_push_kv_bool(out, "mirror_reachable", s.reachable);
    json_push_kv_bool(out, "zclassicd_rpc_transport_reachable",
                      s.zclassicd_rpc_transport_reachable);
    json_push_kv_bool(out, "legacy_oracle_usable",
                      s.legacy_oracle_usable);
    json_push_kv_int(out, "zclassicd_rpc_error_code",
                     s.zclassicd_rpc_error_code);
    json_push_kv_str(out, "zclassicd_rpc_error_message",
                     s.zclassicd_rpc_error_message);
    json_push_kv_bool(out, "in_flight", s.in_flight);
    json_push_kv_int(out, "zclassic23_height", s.local_height);
    json_push_kv_str(out, "zclassic23_hash", s.zclassic23_hash);
    json_push_kv_int(out, "zclassicd_height", s.legacy_height);
    json_push_kv_str(out, "zclassicd_hash", s.zclassicd_hash);
    json_push_kv_int(out, "legacy_height", s.legacy_height);
    json_push_kv_int(out, "legacy_headers", s.legacy_headers);
    json_push_kv_int(out, "local_height", s.local_height);
    json_push_kv_int(out, "best_header_height", s.best_header_height);
    json_push_kv_bool(out, "legacy_advisory_height_known",
                      s.legacy_advisory_height_known);
    json_push_kv_bool(out, "target_height_known", s.target_height_known);
    json_push_kv_bool(out, "lag_known", s.lag_known);
    json_push_kv_bool(out, "lag_valid", s.lag_valid);
    json_push_kv_bool(out, "tip_hashes_agree", s.tip_hashes_agree);
    json_push_kv_int(out, "comparison_height", s.comparison_height);
    json_push_kv_bool(out, "comparison_known", s.comparison_known);
    json_push_kv_bool(out, "comparison_hashes_agree",
                      s.comparison_hashes_agree);
    json_push_kv_bool(out, "same_chain_at_comparison_height",
                      s.comparison_known && s.comparison_hashes_agree);
    json_push_kv_int(out, "hash_disagreement_height",
                     s.hash_disagreement_height);
    json_push_kv_str(out, "comparison_zclassic23_hash",
                     s.comparison_zclassic23_hash);
    json_push_kv_str(out, "comparison_zclassicd_hash",
                     s.comparison_zclassicd_hash);
    json_push_kv_int(out, "lag", legacy_mirror_sync_reported_lag(&s));
    legacy_mirror_sync_push_observed_lag_json(out, "lag_observed", &s);
    json_push_kv_str(out, "candidate_source", "legacy_advisory");
    json_push_kv_str(out, "candidate_trust", s.candidate_trust);
    json_push_kv_bool(out, "candidate_lag_known", s.lag_known);
    json_push_kv_bool(out, "candidate_lag_valid", s.lag_valid);
    json_push_kv_int(out, "candidate_lag",
                     legacy_mirror_sync_reported_lag(&s));
    legacy_mirror_sync_push_observed_lag_json(out,
                                              "candidate_lag_observed", &s);
    json_push_kv_str(out, "candidate_blocker",
                     legacy_mirror_sync_blocker_code(&s));
    json_push_kv_bool(out, "blocker_recovered_by_tip_agreement",
                      s.blocker_recovered_by_tip_agreement);
    json_push_kv_bool(
        out, "blocker_recovered_by_common_height_agreement",
        s.blocker_recovered_by_common_height_agreement);
    json_push_kv_int(out, "target_height", s.target_height);
    json_push_kv_int(out, "authority_rewind_target",
                     s.authority_rewind_target);
    json_push_kv_int(out, "last_advanced_height", s.last_advanced_height);
    json_push_kv_int(out, "last_progress_blocks", s.last_progress_blocks);
    json_push_kv_bool(out, "local_recovery_active",
                      s.local_recovery_active);
    json_push_kv_bool(out, "legacy_advisory_gated_by_native_retries",
                      s.mirror_repair_gated_by_local_retries);
    json_push_kv_bool(out, "mirror_repair_gated_by_local_retries",
                      s.mirror_repair_gated_by_local_retries);
    json_push_kv_bool(out, "local_retries_exhausted",
                      s.local_retries_exhausted);
    json_push_kv_int(out, "local_missing_height", s.local_missing_height);
    json_push_kv_int(out, "local_retry_count", s.local_retry_count);
    json_push_kv_int(out, "local_distinct_peer_count",
                     s.local_distinct_peer_count);
    json_push_kv_int(out, "local_peer_rotation_count",
                     s.local_peer_rotation_count);
    json_push_kv_int(out, "stuck_height", s.stuck_height);
    json_push_kv_int(out, "stuck_status_flags", s.stuck_status_flags);
    json_push_kv_str(out, "stuck_reason", s.stuck_reason);
    json_push_kv_int(out, "stalls_total", s.stalls_total);
    json_push_kv_int(out, "last_catchup", s.last_catchup);
    json_push_kv_int(out, "last_attempt", s.last_attempt);
    json_push_kv_int(out, "catchups_total", s.catchups_total);
    json_push_kv_int(out, "rpc_errors", s.rpc_errors);
    json_push_kv_int(out, "blocks_applied", s.blocks_applied);
    json_push_kv_int(out, "headers_added", s.headers_added);
    json_push_kv_str(out, "consensus_authority", s.consensus_authority);
    json_push_kv_bool(out, "override_active", s.override_active);
    json_push_kv_int(out, "overrides_total", s.overrides_total);
    json_push_kv_int(out, "unsafe_overrides_total",
                     s.unsafe_overrides_total);
    json_push_kv_int(out, "blockers_total", s.blockers_total);
    json_push_kv_int(out, "last_override_height", s.last_override_height);
    json_push_kv_bool(out, "last_override_safe", s.last_override_safe);
    json_push_kv_str(out, "last_override_reason", s.last_override_reason);
    json_push_kv_str(out, "last_override_scope", s.last_override_scope);
    json_push_kv_str(out, "activation_blocker_class",
                     blocker_class_name(s.activation_blocker_class));
    json_push_kv_str(out, "last_blocker_class",
                     blocker_class_name(s.last_blocker_class));
    json_push_kv_str(out, "activation_blocker", s.activation_blocker_reason);
    json_push_kv_str(out, "last_blocker_code", s.last_blocker_id);
    json_push_kv_str(out, "active_error_code",
                     s.activation_blocker_reason[0] ? s.activation_blocker_reason
                                                    : s.last_blocker_id);
    json_push_kv_str(out, "active_error_detail",
                     (s.activation_blocker_reason[0] || s.last_blocker_id[0])
                         ? s.last_error : "");
    json_push_kv_int(out, "csr_sqlite_rc", s.csr_sqlite_rc);
    json_push_kv_str(out, "csr_failure_reason", s.csr_failure_reason);
    json_push_kv_str(out, "last_error", s.last_error);
    json_push_kv_int(out, "lag_sla_breach_blocks", s.lag_sla_breach_blocks);
    json_push_kv_int(out, "lag_sla_breach_secs", s.lag_sla_breach_secs);
    json_push_kv_int(out, "lag_sla_critical_blocks",
                     s.lag_sla_critical_blocks);
    json_push_kv_int(out, "lag_sla_critical_secs", s.lag_sla_critical_secs);
    json_push_kv_int(out, "lag_breach_since", s.lag_breach_since);
    json_push_kv_int(out, "lag_breach_seconds", s.lag_breach_seconds);
    json_push_kv_int(out, "lag_critical_since", s.lag_critical_since);
    json_push_kv_int(out, "lag_critical_seconds", s.lag_critical_seconds);
    json_push_kv_str(out, "lag_breach_severity", s.lag_breach_severity);

    /* `_health` is the reserved diagnostics roll-up key. The mirror remains
     * advisory: an unhealthy result never authorizes local consensus state. */
    const char *blocker_code = legacy_mirror_sync_blocker_code(&s);
    bool blocker_active = legacy_mirror_sync_blocker_is_active(&s);
    bool operator_action_required =
        blocker_active && legacy_mirror_sync_blocker_should_surface(&s, false);
    diag_push_health(out, !operator_action_required,
                     operator_action_required ? blocker_code : "");
    return true;
}
