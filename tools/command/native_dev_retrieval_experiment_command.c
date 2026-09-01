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

static bool rxc_prefix(const struct json_value *input, uint8_t *out)
{
    const struct json_value *value = json_get(input, "bm25_prefix");
    if (!value || value->type != JSON_INT) return false;
    int64_t prefix = json_get_int(value);
    if (prefix < 0 || prefix > (int64_t)ZCL_RETRIEVAL_EXPERIMENT_TOP)
        return false;
    *out = (uint8_t)prefix;
    return true;
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
    uint8_t supplied_parent[32], study_root[32], preregistration_root[32];
    uint8_t evaluator_root[32], prefix = 0;
    if (!rxc_root(request->input, "parent_ranking_root", supplied_parent)) {
        rxc_fail(reply, "INVALID_PARENT_RANKING_ROOT", "bind",
                 "parent_ranking_root must be one nonzero lowercase root",
                 "parent_ranking_root");
        return;
    }
    if (!rxc_root(request->input, "study_root", study_root) ||
        !rxc_root(request->input, "preregistration_root",
                  preregistration_root) ||
        !rxc_root(request->input, "evaluator_root", evaluator_root)) {
        rxc_fail(reply, "INVALID_SCIENCE_ROOT", "bind",
                 "study, preregistration, and evaluator roots must be "
                 "nonzero lowercase roots", "science_roots");
        return;
    }
    if (!rxc_prefix(request->input, &prefix)) {
        rxc_fail(reply, "INVALID_BM25_PREFIX", "input",
                 "bm25_prefix must be one integer from 0 through 5",
                 "bm25_prefix");
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
                                            : "parent ranking recomputation failed",
                 "recomputed_parent");
        return;
    }
    uint8_t recomputed_parent[32], recomputed_bm25[32];
    bool rooted = zcl_retrieval_ranked_files_root(
            snapshot.bm25.rows, snapshot.bm25.count,
            snapshot.bm25.complete, recomputed_bm25) &&
        zcl_retrieval_ranked_files_root(
            snapshot.identifier_graph.rows, snapshot.identifier_graph.count,
            snapshot.identifier_graph.complete, recomputed_parent);
    if (!rooted ||
        memcmp(recomputed_bm25, snapshot.bm25_ranking_root, 32u) != 0 ||
        memcmp(recomputed_parent,
               snapshot.identifier_graph_ranking_root, 32u) != 0) {
        rxc_fail(reply, "RANKING_ROOT_RECOMPUTE_FAILED", "bind",
                 "snapshot rows do not reproduce the frozen ranking roots",
                 "ranked_files_root_v1");
        return;
    }
    if (memcmp(supplied_parent, recomputed_parent, 32u) != 0) {
        char observed[65];
        zcl_hex_encode(recomputed_parent, 32u, observed);
        rxc_fail(reply, "PARENT_RANKING_ROOT_MISMATCH", "bind",
                 "parent_ranking_root does not match the freshly recomputed "
                 "identifier-graph ranking", observed);
        return;
    }

    struct zcl_retrieval_ranked_file
        candidate[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_experiment_report report;
    enum zcl_retrieval_experiment_error projected =
        zcl_retrieval_experiment_project(
            snapshot.bm25.rows, snapshot.bm25.count, snapshot.bm25.complete,
            snapshot.identifier_graph.rows, snapshot.identifier_graph.count,
            snapshot.identifier_graph.complete, prefix, candidate,
            ZCL_RETRIEVAL_EVAL_RANK_MAX, &report);
    if (projected != ZCL_RETRIEVAL_EXPERIMENT_OK) {
        rxc_fail(reply, "PROJECTION_REFUSED", "project",
                 zcl_retrieval_experiment_error_string(projected),
                 ZCL_RETRIEVAL_EXPERIMENT_ALGORITHM);
        return;
    }
    uint8_t candidate_root[32], proposal_root[32];
    if (!zcl_retrieval_ranked_files_root(
            candidate, report.ranked_count, snapshot.bm25.complete,
            candidate_root) ||
        !zcl_retrieval_experiment_proposal_input_root(
            snapshot.source_root, snapshot.retrieval_projection_root,
            snapshot.task_id,
            snapshot.query, recomputed_bm25, recomputed_parent, prefix,
            study_root, preregistration_root, evaluator_root, proposal_root)) {
        rxc_fail(reply, "PROPOSAL_ROOT_FAILED", "seal",
                 "candidate or proposal input root could not be sealed",
                 ZCL_RETRIEVAL_EXPERIMENT_ALGORITHM);
        return;
    }

    char source_hex[65], codeindex_source_hex[65], projection_hex[65];
    char bm25_hex[65], parent_hex[65];
    char candidate_hex[65], proposal_hex[65], study_hex[65], prereg_hex[65];
    char evaluator_hex[65];
    zcl_hex_encode(snapshot.source_root, 32u, source_hex);
    zcl_hex_encode(snapshot.codeindex_source_root, 32u,
                   codeindex_source_hex);
    zcl_hex_encode(snapshot.retrieval_projection_root, 32u,
                   projection_hex);
    zcl_hex_encode(recomputed_bm25, 32u, bm25_hex);
    zcl_hex_encode(recomputed_parent, 32u, parent_hex);
    zcl_hex_encode(candidate_root, 32u, candidate_hex);
    zcl_hex_encode(proposal_root, 32u, proposal_hex);
    zcl_hex_encode(study_root, 32u, study_hex);
    zcl_hex_encode(preregistration_root, 32u, prereg_hex);
    zcl_hex_encode(evaluator_root, 32u, evaluator_hex);
    bool ok = json_push_kv_str(&reply->data, "schema",
                               "zcl.dev_retrieval_experiment.v2") &&
        json_push_kv_str(&reply->data, "algorithm",
                         ZCL_RETRIEVAL_EXPERIMENT_ALGORITHM) &&
        json_push_kv_str(&reply->data, "task_id", snapshot.task_id) &&
        json_push_kv_str(&reply->data, "query", snapshot.query) &&
        json_push_kv_int(&reply->data, "bm25_prefix", prefix) &&
        json_push_kv_str(&reply->data, "source_root", source_hex) &&
        json_push_kv_str(&reply->data, "codeindex_source_root",
                         codeindex_source_hex) &&
        json_push_kv_str(&reply->data, "retrieval_projection_root",
                         projection_hex) &&
        json_push_kv_str(&reply->data, "bm25_ranking_root", bm25_hex) &&
        json_push_kv_str(&reply->data, "parent_ranking_root", parent_hex) &&
        json_push_kv_str(&reply->data, "candidate_ranking_root",
                         candidate_hex) &&
        json_push_kv_str(&reply->data, "proposal_input_root", proposal_hex) &&
        json_push_kv_str(&reply->data, "study_root", study_hex) &&
        json_push_kv_str(&reply->data, "preregistration_root", prereg_hex) &&
        json_push_kv_str(&reply->data, "evaluator_root", evaluator_hex) &&
        json_push_kv_int(&reply->data, "ranked_files",
                         (int64_t)report.ranked_count) &&
        report.bm25_context_bytes_at_5 <= INT64_MAX &&
        report.candidate_context_bytes_at_5 <= INT64_MAX &&
        json_push_kv_int(&reply->data, "bm25_context_bytes_at_5",
                         (int64_t)report.bm25_context_bytes_at_5) &&
        json_push_kv_int(&reply->data, "candidate_context_bytes_at_5",
                         (int64_t)report.candidate_context_bytes_at_5) &&
        json_push_kv_int(&reply->data, "changed_positions_at_5",
                         (int64_t)report.changed_positions_at_5) &&
        json_push_kv_bool(&reply->data, "used_bm25_fallback",
                          report.used_bm25_fallback) &&
        json_push_kv_bool(&reply->data, "parent_recomputed", true) &&
        json_push_kv_bool(&reply->data, "top20_membership_preserved",
                          report.top20_membership_preserved) &&
        json_push_kv_bool(&reply->data, "full_retained_set_preserved", true) &&
        json_push_kv_bool(&reply->data, "context_ceiling_preserved",
                          report.candidate_context_bytes_at_5 <=
                          report.bm25_context_bytes_at_5) &&
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
