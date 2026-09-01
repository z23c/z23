/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: relevance-free, source-bound retrieval heuristic projection. */
#include "command/native_command.h"
#include "command/native_dev_retrieval_stream.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "retrieval/retrieval_experiment.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RXC_TAG "native.dev.retrieval.experiment"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

static void rxc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    LOG_ERROR(RXC_TAG, "%s: %s (%s)", code, message,
              evidence ? evidence : "");
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false, false,
                           message, evidence ? evidence : "");
}

static bool rxc_root(const struct json_value *input, const char *key,
                     uint8_t out[32])
{
    const struct json_value *value = json_get(input, key);
    const char *hex = value && value->type == JSON_STR
        ? json_get_str(value) : NULL;
    if (!hex || !zcl_hex_decode_lower(hex, out, 32u)) return false;
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= out[i];
    return aggregate != 0;
}

static bool rxc_profile(const struct json_value *input,
                        struct zcl_retrieval_profile_v1 *out)
{
    const struct json_value *value = json_get(input, "profile_hex");
    const char *hex = value && value->type == JSON_STR
        ? json_get_str(value) : NULL;
    uint8_t wire[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES];
    return hex && zcl_hex_decode_lower(hex, wire, sizeof(wire)) &&
        zcl_retrieval_profile_parse(wire, sizeof(wire), out) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rxc_push_rows(
    struct json_value *object,
    const struct zcl_retrieval_ranked_file *rows, size_t count)
{
    struct json_value ranked;
    json_init(&ranked);
    json_set_array(&ranked);
    size_t displayed = count < ZCL_RETRIEVAL_EXPERIMENT_WINDOW
        ? count : ZCL_RETRIEVAL_EXPERIMENT_WINDOW;
    bool ok = true;
    for (size_t i = 0; i < displayed && ok; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        ok = json_push_kv_int(&row, "rank", (int64_t)i + 1) &&
            json_push_kv_str(&row, "path", rows[i].path) &&
            rows[i].context_bytes <= INT64_MAX &&
            json_push_kv_int(&row, "context_bytes",
                             (int64_t)rows[i].context_bytes) &&
            json_push_back(&ranked, &row);
        json_free(&row);
    }
    if (ok) ok = json_push_kv_int(object, "displayed_files",
                                  (int64_t)displayed) &&
                 json_push_kv(object, "ranking", &ranked);
    json_free(&ranked);
    return ok;
}

static void rxc_run(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply)
{
    if (!request || !request->input || request->input->type != JSON_OBJ) {
        rxc_fail(reply, "INVALID_INPUT", "input",
                 "experiment input must be one JSON object", "input");
        return;
    }
    uint8_t study_root[32], preregistration_root[32], evaluator_root[32];
    if (!rxc_root(request->input, "study_root", study_root) ||
        !rxc_root(request->input, "preregistration_root",
                  preregistration_root) ||
        !rxc_root(request->input, "evaluator_root", evaluator_root)) {
        rxc_fail(reply, "INVALID_SCIENCE_ROOT", "bind",
                 "study, preregistration, and evaluator roots must be "
                 "nonzero lowercase roots", "science_roots");
        return;
    }
    struct zcl_retrieval_profile_v1 profile;
    if (!rxc_profile(request->input, &profile)) {
        rxc_fail(reply, "INVALID_PROFILE", "input",
                 "profile_hex must be one canonical 56-byte retrieval "
                 "profile encoded as 112 lowercase hex characters",
                 "profile_hex");
        return;
    }
    if (profile.feature_mask != ZCL_RETRIEVAL_FEATURE_BIT(
            ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES)) {
        rxc_fail(reply, "PROJECTION_REFUSED", "project",
                 zcl_retrieval_experiment_error_string(
                     ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE),
                 "context_bytes_only");
        return;
    }

    struct zcl_native_dev_retrieval_snapshot snapshot;
    char error_code[64], error_message[256];
    int rc = zcl_native_dev_retrieval_snapshot_compute(
        request->input, &snapshot, error_code, sizeof(error_code),
        error_message, sizeof(error_message));
    if (rc != ZCL_COMMAND_EXIT_OK) {
        rxc_fail(reply, error_code[0] ? error_code : "RANKING_FAILED",
                 "rank", error_message[0] ? error_message
                                            : "source-bound baseline recomputation failed",
                 "generation_joined_baseline");
        return;
    }
    uint8_t recomputed_bm25[32];
    bool rooted = zcl_retrieval_ranked_files_root(
            snapshot.bm25.rows, snapshot.bm25.count,
            snapshot.bm25.complete, recomputed_bm25);
    if (!rooted || memcmp(recomputed_bm25, snapshot.bm25_ranking_root,
                           32u) != 0) {
        rxc_fail(reply, "RANKING_ROOT_RECOMPUTE_FAILED", "bind",
                 "snapshot rows do not reproduce the frozen BM25 root",
                 "ranked_files_root_v1");
        return;
    }

    struct zcl_retrieval_feature_snapshot_v1 feature_snapshot;
    struct zcl_retrieval_feature_row_v1
        feature_rows[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    enum zcl_retrieval_experiment_error extracted =
        zcl_retrieval_context_feature_snapshot(
            snapshot.codeindex_source_root,
            snapshot.retrieval_projection_root, snapshot.query,
            snapshot.bm25.rows, snapshot.bm25.count, snapshot.bm25.complete,
            &feature_snapshot, feature_rows,
            ZCL_RETRIEVAL_EVAL_RANK_MAX);
    if (extracted != ZCL_RETRIEVAL_EXPERIMENT_OK) {
        rxc_fail(reply, "FEATURE_SNAPSHOT_REFUSED", "extract",
                 zcl_retrieval_experiment_error_string(extracted),
                 "context_bytes_only");
        return;
    }
    size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_ranked_file
        candidate[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_profile_report report;
    enum zcl_retrieval_experiment_error projected =
        zcl_retrieval_profile_project(
            &profile, &feature_snapshot, feature_rows, indices,
            ZCL_RETRIEVAL_EVAL_RANK_MAX, &report);
    if (projected != ZCL_RETRIEVAL_EXPERIMENT_OK) {
        rxc_fail(reply, "PROJECTION_REFUSED", "project",
                 zcl_retrieval_experiment_error_string(projected),
                 projected == ZCL_RETRIEVAL_EXPERIMENT_INCOMPLETE
                    ? "context_bytes_only"
                    : ZCL_RETRIEVAL_PROFILE_ALGORITHM);
        return;
    }
    for (size_t i = 0; i < report.ranked_count; i++)
        candidate[i] = snapshot.bm25.rows[indices[i]];
    uint8_t candidate_root[32], feature_snapshot_root[32], profile_root[32];
    uint8_t proposal_root[32];
    if (!zcl_retrieval_ranked_files_root(
            candidate, report.ranked_count, snapshot.bm25.complete,
            candidate_root) ||
        memcmp(candidate_root, report.candidate_ranking_root, 32u) != 0 ||
        zcl_retrieval_profile_root(&profile, profile_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        zcl_retrieval_feature_snapshot_root(
            &feature_snapshot, feature_rows, feature_snapshot_root) !=
            ZCL_RETRIEVAL_EXPERIMENT_OK ||
        memcmp(profile_root, report.profile_root, 32u) != 0 ||
        memcmp(feature_snapshot_root, report.feature_snapshot_root, 32u) != 0 ||
        !zcl_retrieval_profile_proposal_input_root(
            snapshot.source_root, snapshot.codeindex_source_root,
            snapshot.retrieval_projection_root, snapshot.task_id,
            snapshot.query, recomputed_bm25, profile_root,
            feature_snapshot_root, candidate_root, study_root,
            preregistration_root, evaluator_root, proposal_root)) {
        rxc_fail(reply, "PROPOSAL_ROOT_FAILED", "seal",
                 "profile evidence, candidate, or proposal root could not "
                 "be reproduced and sealed", ZCL_RETRIEVAL_PROFILE_ALGORITHM);
        return;
    }

    char source_hex[65], codeindex_source_hex[65], projection_hex[65];
    char baseline_hex[65], profile_hex[65], feature_snapshot_hex[65];
    char candidate_hex[65], proposal_hex[65], study_hex[65], prereg_hex[65];
    char evaluator_hex[65];
    zcl_hex_encode(snapshot.source_root, 32u, source_hex);
    zcl_hex_encode(snapshot.codeindex_source_root, 32u,
                   codeindex_source_hex);
    zcl_hex_encode(snapshot.retrieval_projection_root, 32u,
                   projection_hex);
    zcl_hex_encode(recomputed_bm25, 32u, baseline_hex);
    zcl_hex_encode(profile_root, 32u, profile_hex);
    zcl_hex_encode(feature_snapshot_root, 32u, feature_snapshot_hex);
    zcl_hex_encode(candidate_root, 32u, candidate_hex);
    zcl_hex_encode(proposal_root, 32u, proposal_hex);
    zcl_hex_encode(study_root, 32u, study_hex);
    zcl_hex_encode(preregistration_root, 32u, prereg_hex);
    zcl_hex_encode(evaluator_root, 32u, evaluator_hex);
    bool ok = json_push_kv_str(&reply->data, "schema",
                               "zcl.dev_retrieval_experiment.v3") &&
        json_push_kv_str(&reply->data, "algorithm",
                         ZCL_RETRIEVAL_PROFILE_ALGORITHM) &&
        json_push_kv_str(&reply->data, "task_id", snapshot.task_id) &&
        json_push_kv_str(&reply->data, "query", snapshot.query) &&
        json_push_kv_str(&reply->data, "source_root", source_hex) &&
        json_push_kv_str(&reply->data, "codeindex_source_root",
                         codeindex_source_hex) &&
        json_push_kv_str(&reply->data, "retrieval_projection_root",
                         projection_hex) &&
        json_push_kv_str(&reply->data, "baseline_ranking_root",
                         baseline_hex) &&
        json_push_kv_str(&reply->data, "profile_root", profile_hex) &&
        json_push_kv_str(&reply->data, "feature_snapshot_root",
                         feature_snapshot_hex) &&
        json_push_kv_str(&reply->data, "candidate_ranking_root",
                         candidate_hex) &&
        json_push_kv_str(&reply->data, "proposal_input_root", proposal_hex) &&
        json_push_kv_str(&reply->data, "study_root", study_hex) &&
        json_push_kv_str(&reply->data, "preregistration_root", prereg_hex) &&
        json_push_kv_str(&reply->data, "evaluator_root", evaluator_hex) &&
        json_push_kv_int(&reply->data, "ranked_files",
                         (int64_t)report.ranked_count) &&
        json_push_kv_bool(&reply->data, "ranking_complete",
                          snapshot.bm25.complete) &&
        json_push_kv_int(&reply->data, "requested_rerank_window",
                         profile.rerank_window) &&
        json_push_kv_int(&reply->data, "effective_rerank_window",
                         profile.rerank_window < report.ranked_count
                            ? profile.rerank_window
                            : (int64_t)report.ranked_count) &&
        json_push_kv_int(&reply->data, "requested_top_k", profile.top_k) &&
        json_push_kv_int(&reply->data, "effective_top_k",
                         profile.top_k < report.ranked_count
                            ? profile.top_k
                            : (int64_t)report.ranked_count) &&
        report.baseline_context_bytes_at_top <= INT64_MAX &&
        report.candidate_context_bytes_at_top <= INT64_MAX &&
        json_push_kv_int(&reply->data, "baseline_context_bytes_at_top",
                         (int64_t)report.baseline_context_bytes_at_top) &&
        json_push_kv_int(&reply->data, "candidate_context_bytes_at_top",
                         (int64_t)report.candidate_context_bytes_at_top) &&
        json_push_kv_int(&reply->data, "changed_positions_at_top",
                         (int64_t)report.changed_positions_at_top) &&
        json_push_kv_bool(&reply->data, "used_baseline_fallback",
                          report.used_baseline_fallback) &&
        json_push_kv_bool(&reply->data, "baseline_recomputed", true) &&
        json_push_kv_bool(&reply->data, "observed_retained_set_preserved",
                          report.retained_set_preserved) &&
        json_push_kv_bool(&reply->data, "context_ceiling_preserved",
                          report.candidate_context_bytes_at_top <=
                          report.baseline_context_bytes_at_top) &&
        json_push_kv_str(&reply->data, "feature_evidence",
                         "context_bytes_only") &&
        json_push_kv_str(&reply->data, "gold_basis", "not_supplied") &&
        json_push_kv_str(&reply->data, "scope_basis", "unavailable") &&
        json_push_kv_str(&reply->data, "evaluation_status", "not_run") &&
        json_push_kv_str(&reply->data, "science_binding_status",
                         "opaque_roots_unverified") &&
        json_push_kv_bool(&reply->data, "quality_claim_available", false) &&
        json_push_kv_bool(&reply->data, "promotion_authorized", false) &&
        rxc_push_rows(&reply->data, candidate, report.ranked_count);
    if (!ok)
        rxc_fail(reply, "OUTPUT_ALLOCATION_FAILED", "render",
                 "experiment result could not be rendered completely",
                 snapshot.task_id);
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

void zcl_native_handle_dev_retrieval_experiment(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    rxc_run(request, reply);
#else
    (void)request;
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
        "DEV_BUILD_REQUIRED", "dispatch", false, false,
        "retrieval experiments require the dev binary", "make dev-bin");
#endif
}
