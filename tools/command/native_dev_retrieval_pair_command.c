/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: observe one content-addressed retrieval pair without promotion. */
#include "command/native_command.h"
#include "command/native_dev_retrieval_pair.h"

#include "base/hex.h"
#include "base/log_macros.h"

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

static bool rpc_hex(struct json_value *out, const char *key,
                     const uint8_t *bytes, size_t len)
{
    char hex[2u * ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES + 1u];
    if (len > ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES) return false;
    zcl_hex_encode(bytes, len, hex);
    return json_push_kv_str(out, key, hex);
}

static bool rpc_roots(struct json_value *out,
                       const struct zcode_retrieval_science_result_bundle *b)
{
    return rpc_hex(out, "parent_result_root", b->measurement.parent_result_root, 32u) &&
        rpc_hex(out, "child_result_root", b->measurement.child_result_root, 32u) &&
        rpc_hex(out, "feature_snapshot_root", b->measurement.feature_snapshot_root, 32u) &&
        rpc_hex(out, "parent_heuristic_root", b->measurement.parent_heuristic_root, 32u) &&
        rpc_hex(out, "child_heuristic_root", b->measurement.child_heuristic_root, 32u) &&
        rpc_hex(out, "evaluation_input_root", b->observation.evaluation_input_root, 32u) &&
        rpc_hex(out, "workload_root", b->observation.workload_root, 32u) &&
        rpc_hex(out, "action_root", b->action_root, 32u) &&
        rpc_hex(out, "observation_root", b->observation_root, 32u) &&
        rpc_hex(out, "result_root", b->result_root, 32u);
}

static bool rpc_wires(struct json_value *out,
                       const struct zcode_retrieval_science_result_bundle *b)
{
    return rpc_hex(out, "parent_result_wire_hex", b->parent_retrieval_result_wire,
                    sizeof(b->parent_retrieval_result_wire)) &&
        rpc_hex(out, "child_result_wire_hex", b->child_retrieval_result_wire,
                  sizeof(b->child_retrieval_result_wire)) &&
        rpc_hex(out, "observation_wire_hex", b->observation_wire,
                  sizeof(b->observation_wire)) &&
        rpc_hex(out, "result_wire_hex", b->result_wire, sizeof(b->result_wire));
}

static bool rpc_status(struct json_value *out,
                        const struct zcode_retrieval_science_result_bundle *b)
{
    return json_push_kv_int(out, "comparison_status", b->observation.comparison_status) &&
        json_push_kv_int(out, "directional_delta_bp", b->observation.directional_delta_bp) &&
        json_push_kv_int(out, "missing_arms", b->observation.missing_arms) &&
        json_push_kv_int(out, "failed_guards", b->observation.failed_guards) &&
        json_push_kv_int(out, "result_status", b->result.status) &&
        json_push_kv_str(out, "source_provenance_status", "declared_unverified") &&
        json_push_kv_str(out, "run_facts_status", "declared_unverified") &&
        json_push_kv_str(out, "chronology_status", "unverified") &&
        json_push_kv_str(out, "holdout_independence_status", "unverified") &&
        json_push_kv_str(out, "replication_status", "not_run") &&
        json_push_kv_bool(out, "promotion_authorized", false) &&
        json_push_kv_bool(out, "evidence_stored", false);
}

static bool rpc_arm(struct json_value *out, const char *key,
                     const struct zcl_retrieval_experiment_eval_result_v1 *result)
{
    struct json_value arm = {0};
    json_set_object(&arm);
    char bytes[32];
    int n = snprintf(bytes, sizeof(bytes), "%" PRIu64, result->context_bytes_at_5);
    bool ok = n > 0 && (size_t)n < sizeof(bytes) &&
        json_push_kv_int(&arm, "flags", result->flags) &&
        json_push_kv_int(&arm, "recall_at_5_bp", result->recall_at_5_bp) &&
        json_push_kv_int(&arm, "recall_at_20_bp", result->recall_at_20_bp) &&
        json_push_kv_int(&arm, "mrr_bp", result->mrr_bp) &&
        json_push_kv_int(&arm, "wrong_scope_at_5_bp", result->wrong_scope_at_5_bp) &&
        json_push_kv_str(&arm, "context_bytes_at_5", bytes) && json_push_kv(out, key, &arm);
    json_free(&arm);
    return ok;
}

static void rpc_fail(struct zcl_command_reply *reply, const char *code,
                      const char *message)
{
    LOG_ERROR("native.dev.retrieval.pair", "%s: %s", code, message);
    json_free(&reply->data);
    json_init(&reply->data);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "measure", false, false, message,
        "dev.retrieval.pair");
}

static void rpc_run(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply)
{
    struct zcl_native_retrieval_pair pair = {0};
    struct zcode_retrieval_science_result_bundle bundle;
    if (!zcl_native_retrieval_pair_load(request->input, &pair)) {
        json_free(&pair.artifact);
        rpc_fail(reply, "PAIR_ARTIFACT_INVALID",
            "expected a verified bounded retrieval_pair_artifact.v1 with canonical wires and typed rows");
        return;
    }
    enum zcode_retrieval_science_adapter_error error =
        zcode_retrieval_science_result_compose(&pair.request, &bundle);
    json_free(&pair.artifact);
    if (error != ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK) {
        rpc_fail(reply, "PAIR_MEASUREMENT_REFUSED",
            "paired observation refused: profile, lineage, workload, study, candidate or environment binding failed");
        return;
    }
    if (!json_push_kv_str(&reply->data, "artifact_root",
            json_get_str(json_get(request->input, "artifact_root"))) ||
        !rpc_roots(&reply->data, &bundle) || !rpc_wires(&reply->data, &bundle) ||
        !rpc_status(&reply->data, &bundle) ||
        !rpc_arm(&reply->data, "parent", &bundle.measurement.parent_result) ||
        !rpc_arm(&reply->data, "child", &bundle.measurement.child_result))
        rpc_fail(reply, "PAIR_OUTPUT_FAILED", "could not render the complete paired observation");
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

void zcl_native_handle_dev_retrieval_pair(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    rpc_run(request, reply);
#else
    (void)request;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
        ZCL_COMMAND_EXIT_BLOCKED, "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "paired retrieval observation requires the dev binary", "dev.retrieval.pair");
#endif
}
