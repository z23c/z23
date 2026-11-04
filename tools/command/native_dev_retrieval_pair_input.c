/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: verified, bounded CAS input for paired retrieval observation. */
#include "command/native_dev_retrieval_pair.h"

#include "base/hex.h"
#include "sha3/sha3.h"
#include "vcs/vcs_object.h"
#include "zjsonp/zjsonp.h"

#include <stdlib.h>
#include <string.h>

static const char *rpi_text(const struct json_value *v, const char *key)
{
    return json_get_str(json_get(v, key));
}

static bool rpi_root(const struct json_value *v, const char *key, uint8_t out[32])
{
    const char *hex = rpi_text(v, key);
    return hex && zcl_hex_decode_lower(hex, out, 32u);
}

/* DOM strings are C strings. Refuse decoded NUL before that representation
 * can alias a different task, path, key or wire. The pull parser also checks
 * physical UTF-8 and every escape over the entire bounded artifact. */
static bool rpi_strings(const char *raw, size_t len)
{
    zjsonp parser;
    zjsonp_init(&parser, raw, len);
    zjsonp_event event;
    zjsonp_status status;
    while ((status = zjsonp_next(&parser, &event)) == ZJRP_OK) {
        if (event.kind != ZJRP_KEY && event.kind != ZJRP_STR) continue;
        char decoded[2u * VCS_ZCODE_HEURISTIC_WIRE_BYTES + 1u];
        size_t n = zjsonp_str_decode(raw, &event, decoded, sizeof(decoded));
        if (n >= sizeof(decoded) || memchr(decoded, 0, n)) return false;
    }
    return status == ZJRP_DONE;
}

static bool rpi_unique(const struct json_value *v)
{
    if (v->type == JSON_OBJ && json_size(v) > 25u) return false;
    if (v->type == JSON_ARR && json_size(v) > ZCL_RETRIEVAL_EVAL_RANK_MAX) return false;
    for (size_t i = 0; i < json_size(v); i++) {
        if (v->type == JSON_OBJ)
            for (size_t j = 0; j < i; j++)
                if (strcmp(v->keys[i], v->keys[j]) == 0) return false;
        if (!rpi_unique(json_at(v, i))) return false;
    }
    return true;
}

static bool rpi_read(const struct json_value *input, struct json_value *artifact)
{
    uint8_t root[32], checked[32], *raw = NULL;
    size_t len = 0;
    if (!input || input->type != JSON_OBJ || json_size(input) != 2u || !rpi_unique(input))
        return false;
    const char *workspace = rpi_text(input, "workspace");
    if (!workspace || !workspace[0] || !rpi_root(input, "artifact_root", root)) return false;
    if (vcs_object_load_raw_bounded(workspace, root, ZCL_RETRIEVAL_PAIR_ARTIFACT_MAX,
                                    &raw, &len) != 0) return false;
    zcl_sha3_256(raw, len, checked);
    bool ok = memcmp(root, checked, 32u) == 0 && rpi_strings((const char *)raw, len) &&
        json_read(artifact, (const char *)raw, len) && rpi_unique(artifact);
    free(raw);
    return ok;
}

static bool rpi_wire(const struct json_value *artifact, const char *key,
                      uint8_t *wire, size_t len)
{
    const char *hex = rpi_text(artifact, key);
    return hex && zcl_hex_decode_lower(hex, wire, len);
}

#define RPI_PARSE(key_, function_, member_, size_) do { \
    uint8_t wire[size_]; \
    if (!rpi_wire(&pair->artifact, key_, wire, sizeof(wire)) || \
        function_(wire, sizeof(wire), &pair->member_) != 0) return false; \
} while (0)

static bool rpi_wires(struct zcl_native_retrieval_pair *pair)
{
    RPI_PARSE("parent_profile_hex", zcl_retrieval_profile_parse,
              parent_profile, ZCL_RETRIEVAL_PROFILE_WIRE_BYTES);
    RPI_PARSE("child_profile_hex", zcl_retrieval_profile_parse,
              child_profile, ZCL_RETRIEVAL_PROFILE_WIRE_BYTES);
    RPI_PARSE("parent_heuristic_hex", vcs_zcode_heuristic_parse,
              parent_heuristic, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
    RPI_PARSE("child_heuristic_hex", vcs_zcode_heuristic_parse,
              child_heuristic, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
    RPI_PARSE("policy_hex", zcl_retrieval_comparison_policy_v2_parse,
              policy, ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES);
    RPI_PARSE("study_hex", vcs_zcode_study_spec_parse,
              study, VCS_ZCODE_STUDY_SPEC_WIRE_BYTES);
    RPI_PARSE("task_hex", vcs_zcode_task_parse, task, VCS_ZCODE_TASK_WIRE_BYTES);
    RPI_PARSE("candidate_hex", vcs_zcode_candidate_parse,
              candidate, VCS_ZCODE_CANDIDATE_WIRE_BYTES);
    RPI_PARSE("environment_policy_hex", vcs_zcode_environment_policy_v1_parse,
              environment, VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES);
    RPI_PARSE("hardware_profile_hex", vcs_zcode_hardware_profile_parse,
              hardware, VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES);
    return true;
}
#undef RPI_PARSE

static bool rpi_uint(const struct json_value *v, const char *key, int64_t *out)
{
    const struct json_value *n = json_get(v, key);
    if (!n || n->type != JSON_INT || n->val.i < 0) return false;
    *out = n->val.i;
    return true;
}

static bool rpi_baseline(struct zcl_native_retrieval_pair *pair)
{
    const struct json_value *a = &pair->artifact;
    const struct json_value *rows = json_get(a, "baseline");
    const struct json_value *complete = json_get(a, "ranking_complete");
    if (!rows || rows->type != JSON_ARR || json_size(rows) == 0 ||
        json_size(rows) > ZCL_RETRIEVAL_EVAL_RANK_MAX ||
        !complete || complete->type != JSON_BOOL) return false;
    struct zcl_retrieval_ranked_file baseline[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        int64_t bytes;
        if (row->type != JSON_OBJ || json_size(row) != 2u ||
            !rpi_uint(row, "context_bytes", &bytes) || !rpi_text(row, "path")) return false;
        baseline[i] = (struct zcl_retrieval_ranked_file){
            .path = rpi_text(row, "path"), .context_bytes = (uint64_t)bytes};
    }
    uint8_t source[32], projection[32];
    return rpi_root(a, "source_root", source) &&
        rpi_root(a, "retrieval_projection_root", projection) &&
        zcl_retrieval_context_feature_snapshot(source, projection, rpi_text(a, "query"),
            baseline, json_size(rows), complete->val.b, &pair->snapshot,
            pair->rows, ZCL_RETRIEVAL_EVAL_RANK_MAX) == ZCL_RETRIEVAL_EXPERIMENT_OK;
}

static bool rpi_measurement(struct zcl_native_retrieval_pair *pair)
{
    const struct json_value *a = &pair->artifact;
    const struct json_value *gold = json_get(a, "relevant_paths");
    if (!gold || gold->type != JSON_ARR || json_size(gold) == 0 ||
        json_size(gold) > ZCL_RETRIEVAL_EXPERIMENT_RELEVANCE_MAX) return false;
    for (size_t i = 0; i < json_size(gold); i++) {
        pair->gold[i] = json_get_str(json_at(gold, i));
        if (!pair->gold[i]) return false;
    }
    pair->measurement = (struct zcode_retrieval_profile_pair_measure_request){
        .parent_profile = &pair->parent_profile, .child_profile = &pair->child_profile,
        .feature_snapshot = &pair->snapshot, .feature_rows = pair->rows,
        .parent_heuristic = &pair->parent_heuristic, .child_heuristic = &pair->child_heuristic,
        .policy = &pair->policy, .study = &pair->study,
        .task_id = rpi_text(a, "task_id"), .query = rpi_text(a, "query"),
        .relevant_paths = pair->gold, .relevant_count = json_size(gold),
        .workload_version = ZCL_RETRIEVAL_EVALUATION_WORKLOAD_VERSION_V2,
    };
    struct zcode_retrieval_profile_pair_measure_request *m = &pair->measurement;
    memcpy(m->expected_source_root, pair->task.source_root, 32u);
    memcpy(m->expected_snapshot_source_root, pair->snapshot.source_root, 32u);
    memcpy(m->expected_retrieval_projection_root, pair->snapshot.codeindex_root, 32u);
    memcpy(m->expected_evaluator_root, pair->policy.evaluator_root, 32u);
    return m->task_id && m->query &&
        vcs_zcode_task_root(&pair->task, m->expected_task_root) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_study_spec_root(&pair->study, m->expected_study_root) == VCS_ZCODE_SCIENCE_OK &&
        zcl_retrieval_comparison_policy_v2_root(&pair->policy, m->expected_policy_root) ==
            ZCL_RETRIEVAL_COMPARISON_OK;
}

static bool rpi_run_facts(struct zcl_native_retrieval_pair *pair)
{
    const struct json_value *a = &pair->artifact;
    int64_t action, result, height;
    pair->request = (struct zcode_retrieval_science_result_request){
        .measurement = &pair->measurement, .task = &pair->task,
        .candidate = &pair->candidate, .environment_policy = &pair->environment,
        .hardware_profile = &pair->hardware};
    struct zcode_retrieval_science_result_request *r = &pair->request;
    if (!rpi_uint(a, "action_sequence", &action) || !rpi_uint(a, "result_sequence", &result) ||
        !rpi_uint(a, "challenge_block_height", &height)) return false;
    r->action_sequence = (uint64_t)action;
    r->result_sequence = (uint64_t)result;
    r->challenge_block_height = (uint64_t)height;
    return rpi_root(a, "challenge_block_hash", r->challenge_block_hash) &&
        rpi_uint(a, "started_unix", &r->started_unix) &&
        rpi_uint(a, "finished_unix", &r->finished_unix) &&
        rpi_uint(a, "now_unix", &r->now_unix);
}

bool zcl_native_retrieval_pair_load(const struct json_value *input,
                                   struct zcl_native_retrieval_pair *pair)
{
    if (!rpi_read(input, &pair->artifact)) return false;
    const char *schema = rpi_text(&pair->artifact, "schema");
    return pair->artifact.type == JSON_OBJ && json_size(&pair->artifact) == 25u &&
        schema && strcmp(schema, "zcl.retrieval_pair_artifact.v1") == 0 &&
        rpi_wires(pair) && rpi_baseline(pair) && rpi_measurement(pair) && rpi_run_facts(pair);
}
