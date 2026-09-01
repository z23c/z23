/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Target-owned operator snapshot. The native client process must not stitch
 * verdict-critical state together across eight HTTP requests: a target restart
 * or ordinary progress between calls can manufacture a state that never
 * existed.  This collector copies each subsystem under its own leaf lock,
 * releases it, then renders once.  It deliberately does not claim global
 * transaction linearizability; the capture contract names its bounded
 * component-snapshot model and refuses a healthy verdict when the critical
 * chain tuple changes during collection. */

#include "controllers/event_operator_snapshot_controller.h"

#include "controllers/agent_controller.h"
#include "controllers/network_controller.h"
#include "controllers/strong_params.h"
#include "chain/chainparams.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "services/operator_snapshot_service.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "net/download.h"
#include "net/msgprocessor.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/sync_monitor.h"
#include "sync/sync_state.h"
#include "util/alerts.h"
#include "util/blocker.h"
#include "util/clientversion.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void operator_push_null(struct json_value *object, const char *key)
{
    struct json_value value = {0};
    json_set_null(&value);
    json_push_kv(object, key, &value);
    json_free(&value);
}

static void operator_push_int_known(struct json_value *object,
                                    const char *key,
                                    bool known,
                                    int64_t value)
{
    if (known)
        json_push_kv_int(object, key, value);
    else
        operator_push_null(object, key);
}

static void operator_push_str_known(struct json_value *object,
                                    const char *key,
                                    bool known,
                                    const char *value)
{
    if (known)
        json_push_kv_str(object, key, value);
    else
        operator_push_null(object, key);
}

static void operator_push_string_array(struct json_value *object,
                                       const char *key,
                                       const char *first,
                                       const char *second)
{
    struct json_value values = {0};
    json_set_array(&values);
    if (first && first[0]) {
        struct json_value value = {0};
        json_set_str(&value, first);
        json_push_back(&values, &value);
        json_free(&value);
    }
    if (second && second[0]) {
        struct json_value value = {0};
        json_set_str(&value, second);
        json_push_back(&values, &value);
        json_free(&value);
    }
    json_push_kv(object, key, &values);
    json_free(&values);
}

static void operator_push_blocker(struct json_value *out,
                                  const struct blocker_snapshot *blocker)
{
    json_set_object(out);
    json_push_kv_str(out, "id", blocker->id);
    json_push_kv_str(out, "owner", blocker->owner_subsystem);
    json_push_kv_str(out, "class",
                     blocker_class_name((enum blocker_class)blocker->class));
    json_push_kv_int(out, "age_us", blocker->age_us);
    json_push_kv_int(out, "deadline_remaining_us",
                     blocker->deadline_remaining_us);
    json_push_kv_str(out, "escape_action", blocker->escape_action);
    json_push_kv_int(out, "retry_count", blocker->retry_count);
    json_push_kv_int(out, "retry_budget", blocker->retry_budget);
    json_push_kv_int(out, "fire_count", blocker->fire_count);
    json_push_kv_str(out, "reason", blocker->reason);
}

static void operator_push_blockers(struct json_value *parent,
                                   const struct operator_capture *capture)
{
    struct json_value blockers = {0};
    struct json_value entries = {0};
    json_set_object(&blockers);
    json_push_kv_bool(&blockers, "known", true);
    json_push_kv_str(&blockers, "execution_locus", "target_node");
    json_push_kv_str(&blockers, "authority", "typed_blocker_registry");
    json_push_kv_str(&blockers, "trust", "authoritative_local_state");
    json_push_kv_int(&blockers, "generation",
                     (int64_t)capture->blocker_generation);
    json_push_kv_int(&blockers, "active_count", capture->blocker_count);
    json_push_kv_int(&blockers, "permanent_count",
                     capture->blocker_class_count[BLOCKER_PERMANENT]);
    json_push_kv_int(&blockers, "transient_count",
                     capture->blocker_class_count[BLOCKER_TRANSIENT]);
    json_push_kv_int(&blockers, "dependency_count",
                     capture->blocker_class_count[BLOCKER_DEPENDENCY]);
    json_push_kv_int(&blockers, "resource_count",
                     capture->blocker_class_count[BLOCKER_RESOURCE]);
    json_push_kv_int(&blockers, "escape_dispatched_total",
                     capture->blocker_escape_dispatched);
    json_push_kv_int(&blockers, "rate_limit_ms",
                     capture->blocker_rate_limit_ms);

    json_set_array(&entries);
    for (int i = 0; i < capture->blocker_count; i++) {
        struct json_value entry = {0};
        operator_push_blocker(&entry, &capture->blockers[i]);
        json_push_back(&entries, &entry);
        json_free(&entry);
    }
    json_push_kv(&blockers, "blockers", &entries);
    json_free(&entries);

    const struct blocker_snapshot *dominant =
        operator_snapshot_dominant_blocker(capture);
    if (dominant) {
        struct json_value value = {0};
        operator_push_blocker(&value, dominant);
        json_push_kv(&blockers, "dominant", &value);
        json_free(&value);
    } else {
        operator_push_null(&blockers, "dominant");
    }
    json_push_kv(parent, "blockers", &blockers);
    json_free(&blockers);
}

static void operator_push_frontier(struct json_value *parent,
                                   const char *key,
                                   const struct chain_frontier_value *f,
                                   const char *source,
                                   const char *authority)
{
    struct json_value frontier = {0};
    json_set_object(&frontier);
    json_push_kv_bool(&frontier, "height_known", f->height_known);
    json_push_kv_bool(&frontier, "binding_known", f->binding_known);
    json_push_kv_bool(&frontier, "status_known", f->status_known);
    json_push_kv_bool(&frontier, "validity_sufficient",
                      f->validity_sufficient);
    json_push_kv_bool(&frontier, "failure_free", f->failure_free);
    operator_push_int_known(&frontier, "height", f->height_known, f->height);
    operator_push_str_known(&frontier, "hash", f->binding_known, f->hash);
    operator_push_str_known(&frontier, "chain_work", f->binding_known,
                            f->chain_work);
    operator_push_int_known(&frontier, "block_status", f->status_known,
                            (int64_t)f->status);
    json_push_kv_str(&frontier, "source", source);
    json_push_kv_str(&frontier, "authority", authority);
    json_push_kv(parent, key, &frontier);
    json_free(&frontier);
}

static void operator_push_invariant(struct json_value *parent,
                                    const char *key,
                                    const char *status,
                                    const char *detail)
{
    struct json_value invariant = {0};
    json_set_object(&invariant);
    json_push_kv_str(&invariant, "status", status);
    json_push_kv_str(&invariant, "detail", detail);
    json_push_kv(parent, key, &invariant);
    json_free(&invariant);
}

static void operator_push_lane_safety_fields(struct json_value *summary)
{
    struct json_value holder = {0};
    json_set_object(&holder);
    agent_push_operator_lane_json(&holder, "operator_lane");
    const struct json_value *lane = json_get(&holder, "operator_lane");
    if (lane && lane->type == JSON_OBJ) {
        json_push_kv(summary, "operator_lane", lane);
        json_push_kv_str(summary, "operator_lane_name",
                         json_get_str(json_get(lane, "lane")));
        json_push_kv_bool(summary, "automation_restart_ok",
                          json_get_bool(json_get(lane,
                                                 "automation_restart_ok")));
        json_push_kv_bool(summary, "automation_deploy_ok",
                          json_get_bool(json_get(lane,
                                                 "automation_deploy_ok")));
        json_push_kv_bool(summary, "requires_operator_confirmation",
                          json_get_bool(json_get(
                              lane, "requires_operator_confirmation")));
        const struct json_value *safety =
            json_get(lane, "deployment_safety");
        json_push_kv_str(summary, "preferred_deploy_target",
                         json_get_str(json_get(safety,
                                               "preferred_deploy_target")));
        json_push_kv_str(summary, "safe_default_action",
                         json_get_str(json_get(safety,
                                               "safe_default_action")));
    }
    json_free(&holder);
}

static void operator_push_security_posture(
    struct json_value *parent, const struct operator_capture *capture)
{
    struct json_value posture = {0};

    json_set_object(&posture);
    json_push_kv_str(&posture, "schema", "zcl.security_posture_gate.v1");
    json_push_kv_int(&posture, "schema_version", 1);
    json_push_kv_str(&posture, "status",
                     capture->security_posture_status[0]
                         ? capture->security_posture_status : "unknown");
    json_push_kv_bool(&posture, "review_required",
                      capture->security_review_required);
    json_push_kv_bool(&posture, "public_serving_allowed",
                      !capture->security_review_required);
    json_push_kv_str(&posture, "next_action",
                     capture->security_posture_next_action[0]
                         ? capture->security_posture_next_action
                         : "inspect security posture");
    json_push_kv(parent, "security_posture", &posture);
    json_free(&posture);
}

static void operator_build_summary(struct json_value *summary,
                                   const struct operator_capture *capture,
                                   const struct operator_verdict *verdict)
{
    json_set_object(summary);
    json_push_kv_str(summary, "schema", "zcl.operator_summary.v3");
    json_push_kv_int(summary, "schema_version", 3);
    json_push_kv_str(summary, "api_version", "v3");
    json_push_kv_str(summary, "execution_locus", "target_node");
    json_push_kv_str(summary, "source_rpc", "operatorsnapshot");
    json_push_kv_int(summary, "captured_at",
                     capture->completed_wall_us / 1000000);
    json_push_kv_str(summary, "source_id_sha256",
                     zcl_build_source_id_sha256());
    /* Git metadata is trace/display only.  Snapshot identity and acceptance
     * are bound to source_id_sha256. */
    json_push_kv_str(summary, "build_commit", zcl_build_commit());
    const struct chain_params *params = chain_params_get();
    json_push_kv_str(summary, "network",
                     params ? params->strNetworkID : "unknown");
    json_push_kv_int(summary, "process_id", capture->identity.process_id);
    json_push_kv_str(summary, "node_instance_id",
                     capture->identity.instance_id);
    json_push_kv_int(summary, "identity_initialized_at_unix_us",
                     capture->identity.initialized_at_unix_us);
    json_push_kv_int(summary, "snapshot_sequence",
                     (int64_t)capture->sequence);
    json_push_kv_int(summary, "capture_started_at_unix_us",
                     capture->started_wall_us);
    json_push_kv_int(summary, "capture_completed_at_unix_us",
                     capture->completed_wall_us);
    json_push_kv_int(summary, "component_skew_upper_bound_us",
                     capture->duration_us);
    json_push_kv_bool(summary, "critical_frontier_stable",
                      capture->critical_frontier_stable);
    json_push_kv_bool(summary, "atomic", false);
    json_push_kv_bool(summary, "compatibility_fallback", false);
    json_push_kv_str(summary, "capture_model",
                     "single_target_bounded_component_snapshots");
    json_push_kv_bool(summary, "verdict_complete", verdict->complete);
    json_push_kv_str(summary, "status", verdict->status);
    json_push_kv_bool(summary, "healthy", verdict->healthy);
    json_push_kv_bool(summary, "serving", verdict->serving);
    json_push_kv_bool(summary, "operator_needed",
                      verdict->operator_needed);
    json_push_kv_bool(summary, "security_review_required",
                      capture->security_review_required);
    json_push_kv_bool(summary, "security_posture_ok",
                      !capture->security_review_required);
    json_push_kv_str(summary, "security_posture_status",
                     capture->security_posture_status[0]
                         ? capture->security_posture_status : "unknown");
    json_push_kv_str(summary, "primary_blocker", verdict->primary);
    json_push_kv_str(summary, "blocking_reason", verdict->primary);
    json_push_kv_str(summary, "next_action", verdict->next_action);
    json_push_kv_str(summary, "next_command", verdict->next_command);
    operator_push_string_array(summary, "recommended_commands",
                               verdict->next_command, verdict->next_command2);

    operator_push_int_known(summary, "height",
                            capture->chain.served.height_known,
                            capture->chain.served.height);
    operator_push_int_known(summary, "served_height",
                            capture->chain.served.height_known,
                            capture->chain.served.height);
    operator_push_int_known(summary, "indexed_height",
                            capture->chain.indexed.height_known,
                            capture->chain.indexed.height);
    operator_push_int_known(summary, "header_height",
                            capture->chain.header.height_known,
                            capture->chain.header.height);
    operator_push_int_known(summary, "target_height",
                            capture->chain.header.height_known,
                            capture->chain.header.height);
    json_push_kv_str(summary, "target_height_source",
                     capture->chain.header.height_known
                         ? "target_node.validated_header_tip"
                         : "unavailable");
    operator_push_int_known(summary, "gap", verdict->gap_known,
                            verdict->gap);
    operator_push_int_known(summary, "served_gap", verdict->gap_known,
                            verdict->gap);
    operator_push_int_known(summary, "index_gap", verdict->gap_known,
                            verdict->index_gap);
    if (verdict->chain_values_known)
        json_push_kv_bool(summary, "chain_evidence_consistent",
                          verdict->chain_consistent);
    else
        operator_push_null(summary, "chain_evidence_consistent");
    json_push_kv_str(summary, "sync_state",
                     capture->sync_state_known
                         ? sync_state_name(capture->sync_state) : "unknown");
    json_push_kv_int(summary, "active_conditions",
                     capture->conditions.active_count);
    json_push_kv_int(summary, "unresolved_conditions",
                     capture->conditions.unresolved_count);
    operator_push_lane_safety_fields(summary);

    struct json_value peers = {0};
    json_set_object(&peers);
    json_push_kv_bool(&peers, "known", capture->peers.available);
    json_push_kv_bool(&peers, "stale", capture->peers.stale);
    json_push_kv_int(&peers, "generation",
                     (int64_t)capture->peers.generation);
    json_push_kv_bool(&peers, "direction_known",
                      capture->peers.direction_known);
    json_push_kv_bool(&peers, "ready_known", capture->peers.ready_known);
    operator_push_int_known(&peers, "total", capture->peers.available,
                            (int64_t)capture->peers.peer_count);
    operator_push_int_known(&peers, "inbound",
                            capture->peers.direction_known,
                            (int64_t)capture->peers.inbound_count);
    operator_push_int_known(&peers, "outbound",
                            capture->peers.direction_known,
                            (int64_t)capture->peers.outbound_count);
    operator_push_int_known(&peers, "ready", capture->peers.ready_known,
                            (int64_t)capture->peers.ready_count);
    operator_push_int_known(&peers, "max_height",
                            capture->peers.peer_best_height_known,
                            capture->peers.peer_best_height);
    json_push_kv_bool(&peers, "max_height_known",
                      capture->peers.peer_best_height_known);
    json_push_kv_str(&peers, "max_height_trust",
                     "untrusted_peer_advertisement");
    json_push_kv(summary, "peers", &peers);
    json_free(&peers);

    struct json_value download = {0};
    json_set_object(&download);
    json_push_kv_bool(&download, "known", capture->download_known);
    operator_push_int_known(&download, "in_flight",
                            capture->download_known,
                            (int64_t)capture->download_in_flight);
    operator_push_int_known(&download, "queued", capture->download_known,
                            (int64_t)capture->download_queued);
    json_push_kv_str(&download, "sync_state",
                     capture->sync_state_known
                         ? sync_state_name(capture->sync_state) : "unknown");
    json_push_kv(summary, "download", &download);
    json_free(&download);

    struct json_value mirror_holder = {0};
    json_set_object(&mirror_holder);
    legacy_mirror_sync_push_status_contract_json(&mirror_holder,
                                                  &capture->mirror);
    const struct json_value *mirror =
        json_get(&mirror_holder, "mirror_contract");
    if (mirror)
        json_push_kv(summary, "mirror", mirror);
    json_free(&mirror_holder);
    operator_push_blockers(summary, capture);

    char summary_text[512];
    snprintf(summary_text, sizeof(summary_text),
             "%s: served=%d indexed=%d header=%d gap=%lld sync=%s "
             "peers=%zu blockers=%d primary=%s",
             verdict->status,
             capture->chain.served.height_known
                 ? capture->chain.served.height : -1,
             capture->chain.indexed.height_known
                 ? capture->chain.indexed.height : -1,
             capture->chain.header.height_known
                 ? capture->chain.header.height : -1,
             (long long)(verdict->gap_known ? verdict->gap : -1),
             capture->sync_state_known
                 ? sync_state_name(capture->sync_state) : "unknown",
             capture->peers.peer_count, capture->blocker_count,
             verdict->primary);
    json_push_kv_str(summary, "summary", summary_text);
}

static void operator_build_snapshot(struct json_value *result,
                                    const struct operator_capture *capture)
{
    struct operator_verdict verdict = operator_snapshot_classify(capture);
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.operator_snapshot.v3");
    json_push_kv_int(result, "schema_version", 3);
    json_push_kv_str(result, "api_version", "v3");
    json_push_kv_str(result, "execution_locus", "target_node");
    json_push_kv_str(result, "producer",
                     "event_operator_snapshot_controller");
    json_push_kv_str(result, "authority", "target_node_internal_state");
    json_push_kv_str(result, "trust", "target_owned_evidence");
    json_push_kv_str(result, "source_id_sha256",
                     zcl_build_source_id_sha256());
    /* Optional GitHub trace metadata; never snapshot trust authority. */
    json_push_kv_str(result, "build_commit", zcl_build_commit());
    const struct chain_params *params = chain_params_get();
    json_push_kv_str(result, "network",
                     params ? params->strNetworkID : "unknown");
    json_push_kv_int(result, "process_id", capture->identity.process_id);
    json_push_kv_str(result, "node_instance_id",
                     capture->identity.instance_id);
    json_push_kv_int(result, "identity_initialized_at_unix_us",
                     capture->identity.initialized_at_unix_us);
    json_push_kv_int(result, "snapshot_sequence",
                     (int64_t)capture->sequence);
    json_push_kv_str(result, "status", verdict.status);
    json_push_kv_bool(result, "healthy", verdict.healthy);
    json_push_kv_bool(result, "serving", verdict.serving);
    json_push_kv_bool(result, "verdict_complete", verdict.complete);
    json_push_kv_bool(result, "security_review_required",
                      capture->security_review_required);
    json_push_kv_bool(result, "security_posture_ok",
                      !capture->security_review_required);
    json_push_kv_str(result, "primary_blocker", verdict.primary);
    json_push_kv_str(result, "next_action", verdict.next_action);
    operator_push_security_posture(result, capture);

    struct json_value capture_json = {0};
    json_set_object(&capture_json);
    json_push_kv_str(&capture_json, "model",
                     "single_target_bounded_component_snapshots");
    json_push_kv_bool(&capture_json, "globally_linearizable", false);
    json_push_kv_int(&capture_json, "started_at_unix_us",
                     capture->started_wall_us);
    json_push_kv_int(&capture_json, "completed_at_unix_us",
                     capture->completed_wall_us);
    json_push_kv_int(&capture_json, "duration_us", capture->duration_us);
    json_push_kv_int(&capture_json, "component_skew_upper_bound_us",
                     capture->duration_us);
    json_push_kv_int(&capture_json, "attempts", capture->attempts);
    json_push_kv_bool(&capture_json, "critical_frontier_stable",
                      capture->critical_frontier_stable);
    json_push_kv_bool(&capture_json, "verdict_inputs_complete",
                      verdict.complete);
    json_push_kv_bool(&capture_json, "partial", !verdict.complete);
    json_push_kv(result, "capture", &capture_json);
    json_free(&capture_json);

    struct json_value chain = {0};
    json_set_object(&chain);
    const char *chain_status = !verdict.chain_values_known
        ? "partial"
        : !operator_snapshot_chain_bindings_known(capture)
            ? "partial"
        : !capture->critical_frontier_stable
            ? "unstable"
        : verdict.chain_consistent ? "ok" : "error";
    json_push_kv_str(&chain, "status", chain_status);
    json_push_kv_str(&chain, "authority", "local_consensus_validation");
    json_push_kv_str(&chain, "trust", "authoritative");
    json_push_kv_bool(&chain, "authority_pair_known",
                      capture->chain.authority_pair_known);
    json_push_kv_bool(&chain, "durable_authority_known",
                      capture->chain.durable_authority_known);
    json_push_kv_bool(&chain, "authority_matches_served",
                      capture->chain.authority_matches_served);
    json_push_kv_str(&chain, "served_authority_source",
        chain_frontier_authority_source_name(capture->chain.authority_source));
    json_push_kv_bool(&chain, "ancestry_known",
                      capture->chain.ancestry_known);
    json_push_kv_bool(&chain, "served_ancestor_indexed",
                      capture->chain.served_ancestor_indexed);
    json_push_kv_bool(&chain, "indexed_ancestor_header",
                      capture->chain.indexed_ancestor_header);
    json_push_kv_bool(&chain, "work_known", capture->chain.work_known);
    json_push_kv_bool(&chain, "work_monotone",
                      capture->chain.work_monotone);
    json_push_kv_bool(&chain, "validity_known",
                      capture->chain.validity_known);
    json_push_kv_bool(&chain, "validity_sufficient",
                      capture->chain.validity_sufficient);
    json_push_kv_bool(&chain, "failure_free",
                      capture->chain.failure_free);
    if (verdict.chain_values_known)
        json_push_kv_bool(&chain, "consistent", verdict.chain_consistent);
    else
        operator_push_null(&chain, "consistent");
    operator_push_frontier(&chain, "served", &capture->chain.served,
                           "reducer_frontier_hstar",
                           chain_frontier_authority_source_name(
                               capture->chain.authority_source));
    operator_push_frontier(&chain, "indexed", &capture->chain.indexed,
                           "active_chain_window",
                           "raw_indexed_window");
    operator_push_frontier(&chain, "validated_header",
                           &capture->chain.header,
                           "pindex_best_header",
                           "local_header_validation");
    operator_push_int_known(&chain, "gap", verdict.gap_known, verdict.gap);
    operator_push_int_known(&chain, "index_gap", verdict.gap_known,
                            verdict.index_gap);
    json_push_kv(result, "chain", &chain);
    json_free(&chain);

    struct json_value peers = {0};
    json_set_object(&peers);
    json_push_kv_bool(&peers, "known", capture->peers.available);
    json_push_kv_bool(&peers, "stale", capture->peers.stale);
    json_push_kv_bool(&peers, "direction_known",
                      capture->peers.direction_known);
    json_push_kv_bool(&peers, "ready_known", capture->peers.ready_known);
    json_push_kv_bool(&peers, "advertised_max_height_known",
                      capture->peers.peer_best_height_known);
    json_push_kv_str(&peers, "status",
                     !capture->peers.available ? "error"
                     : capture->peers.stale ? "stale"
                     : !capture->peers.direction_known ||
                       !capture->peers.ready_known ? "partial" : "ok");
    json_push_kv_str(&peers, "authority", "live_connman_snapshot");
    json_push_kv_str(&peers, "peer_height_trust",
                     "untrusted_peer_advertisement");
    json_push_kv_int(&peers, "generation",
                     (int64_t)capture->peers.generation);
    json_push_kv_int(&peers, "age_seconds", capture->peers.age_seconds);
    operator_push_int_known(&peers, "total", capture->peers.available,
                            (int64_t)capture->peers.peer_count);
    operator_push_int_known(&peers, "inbound",
                            capture->peers.direction_known,
                            (int64_t)capture->peers.inbound_count);
    operator_push_int_known(&peers, "outbound",
                            capture->peers.direction_known,
                            (int64_t)capture->peers.outbound_count);
    operator_push_int_known(&peers, "ready", capture->peers.ready_known,
                            (int64_t)capture->peers.ready_count);
    operator_push_int_known(&peers, "advertised_max_height",
                            capture->peers.peer_best_height_known,
                            capture->peers.peer_best_height);
    json_push_kv(result, "peers", &peers);
    json_free(&peers);

    struct json_value download = {0};
    json_set_object(&download);
    json_push_kv_str(&download, "status",
                     capture->download_known ? "ok" : "error");
    json_push_kv_str(&download, "capture_model", "single_leaf_lock");
    operator_push_int_known(&download, "requested", capture->download_known,
                            (int64_t)capture->download_requested);
    operator_push_int_known(&download, "received", capture->download_known,
                            (int64_t)capture->download_received);
    operator_push_int_known(&download, "timed_out", capture->download_known,
                            (int64_t)capture->download_timed_out);
    operator_push_int_known(&download, "in_flight", capture->download_known,
                            (int64_t)capture->download_in_flight);
    operator_push_int_known(&download, "queued", capture->download_known,
                            (int64_t)capture->download_queued);
    json_push_kv(result, "download", &download);
    json_free(&download);

    operator_push_blockers(result, capture);
    struct json_value conditions = {0};
    json_set_object(&conditions);
    json_push_kv_str(&conditions, "status", "ok");
    json_push_kv_str(&conditions, "capture_model",
                     "single_registry_pass_per_condition_atomic_fields");
    json_push_kv_int(&conditions, "registered_count",
                     capture->conditions.registered_count);
    json_push_kv_int(&conditions, "active_count",
                     capture->conditions.active_count);
    json_push_kv_int(&conditions, "unresolved_count",
                     capture->conditions.unresolved_count);
    json_push_kv_int(&conditions, "unresolved_critical_count",
                     capture->conditions.unresolved_critical_count);
    json_push_kv(result, "conditions", &conditions);
    json_free(&conditions);

    struct json_value latch = {0};
    json_set_object(&latch);
    json_push_kv_str(&latch, "status", "ok");
    json_push_kv_bool(&latch, "active", capture->operator_latch_active);
    json_push_kv_int(&latch, "since_unix",
                     capture->operator_latch_since_unix);
    json_push_kv_str(&latch, "detail", capture->operator_latch_detail);
    json_push_kv_bool(&latch, "read_only_capture", true);
    json_push_kv(result, "operator_latch", &latch);
    json_free(&latch);

    struct json_value invariants = {0};
    json_set_object(&invariants);
    operator_push_invariant(
        &invariants, "critical_frontier_stable",
        capture->critical_frontier_stable ? "pass" : "fail",
        "critical chain tuple is equal before and after component capture");
    operator_push_invariant(
        &invariants, "frontier_order",
        !verdict.chain_values_known ? "unknown"
        : verdict.frontier_order_ok ? "pass" : "fail",
        "served H* <= indexed active tip <= locally validated header");
    operator_push_invariant(
        &invariants, "chain_lineage_and_work",
        !operator_snapshot_chain_bindings_known(capture) ? "unknown"
        : verdict.chain_consistent ? "pass" : "fail",
        "durable served hash, ancestry, and cumulative work agree");
    operator_push_invariant(
        &invariants, "frontier_validity",
        !capture->chain.validity_known ? "unknown"
        : capture->chain.validity_sufficient && capture->chain.failure_free
            ? "pass" : "fail",
        "served is script-valid; indexed/header are tree-valid; none failed");
    operator_push_invariant(
        &invariants, "blocker_counts", "pass",
        "per-class counts are derived from one locked blocker entry copy");
    operator_push_invariant(
        &invariants, "security_posture",
        capture->security_review_required ? "fail" : "pass",
        "healthy and serving require a review-free security posture");
    const char *peer_direction_status =
        !capture->peers.direction_known ? "unknown"
        : capture->peers.inbound_count + capture->peers.outbound_count ==
              capture->peers.peer_count ? "pass" : "fail";
    operator_push_invariant(
        &invariants, "peer_direction_sum", peer_direction_status,
        "inbound + outbound equals total when direction is known");
    json_push_kv(result, "invariants", &invariants);
    json_free(&invariants);

    struct json_value summary = {0};
    operator_build_summary(&summary, capture, &verdict);
    json_push_kv(result, "summary", &summary);
    json_free(&summary);
}

bool rpc_operator_snapshot(const struct json_value *params, bool help,
                           struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "operatorsnapshot\n"
        "\nReturn one target-owned, observationally pure operator snapshot.\n"
        "The response names its bounded component-snapshot coherence model;\n"
        "it never claims global transaction linearizability and never emits\n"
        "healthy when verdict-critical evidence is partial or unstable.\n"
        "\nResult: { schema:\"zcl.operator_snapshot.v3\", "
        "source_id_sha256:\"...\", capture:{...}, "
        "chain:{...}, blockers:{...}, summary:{...} }\n");

    struct operator_capture capture;
    operator_snapshot_collect(&capture);
    operator_build_snapshot(result, &capture);
    return true;
}
