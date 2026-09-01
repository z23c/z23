/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: adversarial generation-join schedules for retrieval commands. */
#include "test/test_core.h"

#include "base/hex.h"
#include "codeindex/codeindex.h"
#include "command/native_command.h"
#include "command/native_dev_retrieval_stream.h"
#include "config/file_ops.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/temp_directory.h"
#include "retrieval/retrieval_experiment.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RG_CHECK(name, expression)                                      \
    do {                                                                \
        const bool rg_ok_ = (expression);                               \
        printf("retrieval_generation: %s %s\n",                       \
               rg_ok_ ? "OK  " : "FAIL", (name));                    \
        if (!rg_ok_) failures++;                                        \
    } while (0)

static const char rg_source_a[] =
    "/* Purpose: generation join fixture A. */\n"
    "int generation_aaaa(void) { return 1; }\n";
static const char rg_source_b[] =
    "/* Purpose: generation join fixture B. */\n"
    "int generation_bbbb(void) { return 2; }\n";

static bool rg_write(const char *root, const char *relative,
                     const char *bytes)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relative);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    for (char *at = path + 1; *at; at++) {
        if (*at != '/') continue;
        *at = '\0';
        if (!platform_directory_ensure(path, 0700)) {
            *at = '/';
            return false;
        }
        *at = '/';
    }
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t length = strlen(bytes);
    bool ok = fwrite(bytes, 1u, length, file) == length;
    if (fclose(file) != 0) ok = false;
    return ok;
}

static bool rg_manifest_root(const char *workspace, uint8_t out[32])
{
    char index_dir[PATH_MAX];
    int n = snprintf(index_dir, sizeof(index_dir), "%s/.zvcs", workspace);
    if (n <= 0 || (size_t)n >= sizeof(index_dir) ||
        !platform_private_directory_ensure(index_dir))
        return false;
    struct vcs_index *index = vcs_index_open(workspace);
    struct vcs_manifest manifest = {0};
    bool ok = index && vcs_manifest_build(workspace, index, &manifest) &&
        vcs_manifest_tree_hash(&manifest, out);
    vcs_manifest_free(&manifest);
    vcs_index_close(index);
    return ok;
}

static bool rg_root_any(const uint8_t root[32])
{
    uint8_t aggregate = 0;
    for (size_t i = 0; i < 32u; i++) aggregate |= root[i];
    return aggregate != 0;
}

static int case_projection_binding(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    bool ready = platform_temp_directory_create(
            "z23-rg-bind-", temporary, sizeof(temporary)) &&
        platform_directory_canonical_real(
            temporary, workspace, sizeof(workspace)) &&
        rg_write(workspace, "lib/net/src/generation.c", rg_source_a);
    uint8_t expected[32];
    ready = ready && rg_manifest_root(workspace, expected);
    char expected_hex[65];
    if (ready) zcl_hex_encode(expected, sizeof(expected), expected_hex);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    ready = ready && json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "expected_vcs_root", expected_hex) &&
        json_push_kv_str(&input, "task_id", "projection-binding") &&
        json_push_kv_str(&input, "query", "generation function");
    struct zcl_native_dev_retrieval_snapshot snapshot = {0};
    char error_code[64] = {0}, error_message[256] = {0};
    int rc = ready ? zcl_native_dev_retrieval_snapshot_compute(
        &input, &snapshot, error_code, sizeof(error_code),
        error_message, sizeof(error_message)) : ZCL_COMMAND_EXIT_INTERNAL;

    struct codeindex *index = rc == ZCL_COMMAND_EXIT_OK
        ? codeindex_open_retrieval_view(workspace) : NULL;
    uint8_t source_root[32], projection_root[32];
    bool rooted = index && codeindex_source_root_sha3(index, source_root) &&
        codeindex_retrieval_projection_root_sha3(index, projection_root);
    RG_CHECK("snapshot binds distinct source and logical projection roots",
             ready && rc == ZCL_COMMAND_EXIT_OK && rooted &&
             rg_root_any(snapshot.codeindex_source_root) &&
             rg_root_any(snapshot.retrieval_projection_root) &&
             memcmp(snapshot.codeindex_source_root,
                    snapshot.retrieval_projection_root, 32u) != 0);
    RG_CHECK("snapshot roots reproduce the verified retrieval view",
             rooted && memcmp(snapshot.codeindex_source_root,
                              source_root, 32u) == 0 &&
             memcmp(snapshot.retrieval_projection_root,
                    projection_root, 32u) == 0);

    struct zcl_retrieval_profile_v1 profile;
    zcl_retrieval_profile_init(&profile);
    profile.feature_mask = ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_CONTEXT_BYTES] = 100u;
    profile.rerank_window = ZCL_RETRIEVAL_PROFILE_WINDOW_MAX;
    profile.top_k = ZCL_RETRIEVAL_EXPERIMENT_TOP;
    profile.context_byte_scale = 1u;
    uint8_t profile_wire[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES];
    uint8_t profile_root[32] = {0}, feature_root[32] = {0};
    uint8_t candidate_root[32] = {0};
    uint8_t study[32] = {5}, preregistration[32] = {6};
    uint8_t evaluator[32] = {7}, proposal[32] = {0};
    char profile_wire_hex[ZCL_RETRIEVAL_PROFILE_WIRE_BYTES * 2u + 1u];
    char study_hex[65], preregistration_hex[65], evaluator_hex[65];
    char source_hex[65], projection_hex[65], proposal_hex[65];
    enum zcl_retrieval_experiment_error profile_status =
        zcl_retrieval_profile_serialize(&profile, profile_wire);
    if (profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK)
        zcl_hex_encode(profile_wire, sizeof(profile_wire), profile_wire_hex);
    zcl_hex_encode(study, 32u, study_hex);
    zcl_hex_encode(preregistration, 32u, preregistration_hex);
    zcl_hex_encode(evaluator, 32u, evaluator_hex);
    zcl_hex_encode(snapshot.codeindex_source_root, 32u, source_hex);
    zcl_hex_encode(snapshot.retrieval_projection_root, 32u, projection_hex);
    struct zcl_retrieval_feature_snapshot_v1 feature_snapshot;
    struct zcl_retrieval_feature_row_v1
        feature_rows[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    size_t indices[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    struct zcl_retrieval_profile_report profile_report;
    bool experiment_ready = rooted &&
        profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_context_feature_snapshot(
            snapshot.codeindex_source_root,
            snapshot.retrieval_projection_root, snapshot.query,
            snapshot.bm25.rows, snapshot.bm25.count, snapshot.bm25.complete,
            &feature_snapshot, feature_rows,
            ZCL_RETRIEVAL_EVAL_RANK_MAX) == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_profile_project(
            &profile, &feature_snapshot, feature_rows, indices,
            ZCL_RETRIEVAL_EVAL_RANK_MAX, &profile_report) ==
                ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_profile_root(&profile, profile_root) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_feature_snapshot_root(
            &feature_snapshot, feature_rows, feature_root) ==
                ZCL_RETRIEVAL_EXPERIMENT_OK;
    if (experiment_ready)
        memcpy(candidate_root, profile_report.candidate_ranking_root,
               sizeof(candidate_root));
    experiment_ready = experiment_ready &&
        json_push_kv_str(&input, "profile_hex", profile_wire_hex) &&
        json_push_kv_str(&input, "study_root", study_hex) &&
        json_push_kv_str(&input, "preregistration_root",
                         preregistration_hex) &&
        json_push_kv_str(&input, "evaluator_root", evaluator_hex) &&
        zcl_retrieval_profile_proposal_input_root(
            snapshot.source_root, snapshot.codeindex_source_root,
            snapshot.retrieval_projection_root, snapshot.task_id,
            snapshot.query, snapshot.bm25_ranking_root, profile_root,
            feature_root, candidate_root, study, preregistration, evaluator,
            proposal);
    zcl_hex_encode(proposal, 32u, proposal_hex);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    if (experiment_ready)
        zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    const char *schema = json_get_str(json_get(&reply.data, "schema"));
    const char *observed_source = json_get_str(
        json_get(&reply.data, "codeindex_source_root"));
    const char *observed_projection = json_get_str(
        json_get(&reply.data, "retrieval_projection_root"));
    const char *observed_proposal = json_get_str(
        json_get(&reply.data, "proposal_input_root"));
    const char *observed_profile = json_get_str(
        json_get(&reply.data, "profile_root"));
    const char *observed_feature = json_get_str(
        json_get(&reply.data, "feature_snapshot_root"));
    const char *observed_candidate = json_get_str(
        json_get(&reply.data, "candidate_ranking_root"));
    char profile_root_hex[65], feature_root_hex[65], first_candidate[65];
    zcl_hex_encode(profile_root, 32u, profile_root_hex);
    zcl_hex_encode(feature_root, 32u, feature_root_hex);
    zcl_hex_encode(candidate_root, 32u, first_candidate);
    RG_CHECK("experiment v3 binds profile and exact feature evidence",
             experiment_ready && reply.exit_code == ZCL_COMMAND_EXIT_OK &&
             schema && strcmp(schema, "zcl.dev_retrieval_experiment.v3") == 0 &&
             observed_source && strcmp(observed_source, source_hex) == 0 &&
             observed_projection &&
             strcmp(observed_projection, projection_hex) == 0 &&
             observed_proposal &&
             strcmp(observed_proposal, proposal_hex) == 0 &&
             observed_profile && strcmp(observed_profile, profile_root_hex) == 0 &&
             observed_feature && strcmp(observed_feature, feature_root_hex) == 0 &&
             observed_candidate && strcmp(observed_candidate,
                                           first_candidate) == 0 &&
             !json_get_bool(json_get(&reply.data,
                                     "quality_claim_available")) &&
             !json_get_bool(json_get(&reply.data, "promotion_authorized")));
    char first_proposal[65], first_feature[65];
    snprintf(first_proposal, sizeof(first_proposal), "%s",
             observed_proposal ? observed_proposal : "");
    snprintf(first_feature, sizeof(first_feature), "%s",
             observed_feature ? observed_feature : "");
    zcl_command_reply_free(&reply);

    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    if (experiment_ready)
        zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    const char *second_proposal = json_get_str(
        json_get(&reply.data, "proposal_input_root"));
    const char *second_feature = json_get_str(
        json_get(&reply.data, "feature_snapshot_root"));
    const char *second_candidate = json_get_str(
        json_get(&reply.data, "candidate_ranking_root"));
    RG_CHECK("identical profile experiment is root-deterministic",
             reply.exit_code == ZCL_COMMAND_EXIT_OK && second_proposal &&
             strcmp(second_proposal, first_proposal) == 0 && second_feature &&
             strcmp(second_feature, first_feature) == 0 && second_candidate &&
             strcmp(second_candidate, first_candidate) == 0);
    zcl_command_reply_free(&reply);

    profile.feature_mask |= ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_PATH);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PATH] = 100u;
    profile_status = zcl_retrieval_profile_serialize(&profile, profile_wire);
    if (profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK) {
        zcl_hex_encode(profile_wire, sizeof(profile_wire), profile_wire_hex);
        for (size_t i = 0; i < input.num_children; i++)
            if (strcmp(input.keys[i], "profile_hex") == 0)
                json_set_str(&input.children[i], profile_wire_hex);
    }
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    if (profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK)
        zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    RG_CHECK("unobserved profile feature fails incomplete without candidate",
             reply.exit_code != ZCL_COMMAND_EXIT_OK &&
             strcmp(reply.error.code, "PROJECTION_REFUSED") == 0 &&
             strstr(reply.error.message, "unavailable") != NULL &&
             json_get(&reply.data, "candidate_ranking_root") == NULL &&
             json_get(&reply.data, "proposal_input_root") == NULL);
    zcl_command_reply_free(&reply);

    profile.feature_mask &= (uint16_t)~ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_PATH);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PATH] = 0u;
    profile_status = zcl_retrieval_profile_serialize(&profile, profile_wire);
    if (profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK) {
        zcl_hex_encode(profile_wire, sizeof(profile_wire), profile_wire_hex);
        profile_wire_hex[1] = 'A';
        for (size_t i = 0; i < input.num_children; i++)
            if (strcmp(input.keys[i], "profile_hex") == 0)
                json_set_str(&input.children[i], profile_wire_hex);
    }
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    RG_CHECK("noncanonical uppercase profile wire is refused before ranking",
             reply.exit_code != ZCL_COMMAND_EXIT_OK &&
             strcmp(reply.error.code, "INVALID_PROFILE") == 0 &&
             json_get(&reply.data, "source_root") == NULL);
    zcl_command_reply_free(&reply);

    for (size_t i = 0; i < input.num_children; i++)
        if (strcmp(input.keys[i], "profile_hex") == 0)
            json_set_str(&input.children[i], "00");
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    RG_CHECK("wrong-size profile wire is refused before ranking",
             reply.exit_code != ZCL_COMMAND_EXIT_OK &&
             strcmp(reply.error.code, "INVALID_PROFILE") == 0 &&
             json_get(&reply.data, "source_root") == NULL);
    zcl_command_reply_free(&reply);
    codeindex_close(index);
    json_free(&input);
    if (temporary[0]) dir_remove_tree(temporary);
    return failures;
}

struct rg_schedule {
    const char *workspace;
    unsigned before_open;
    unsigned before_post;
};

static bool rg_aba_hook(enum zcl_native_dev_retrieval_test_phase phase,
                        void *opaque)
{
    struct rg_schedule *schedule = opaque;
    if (!schedule) return false;
    if (phase == ZCL_NATIVE_DEV_RETRIEVAL_TEST_BEFORE_CODEINDEX_OPEN) {
        schedule->before_open++;
        return rg_write(schedule->workspace,
                        "lib/net/src/generation.c",
                        rg_source_b);
    }
    if (phase == ZCL_NATIVE_DEV_RETRIEVAL_TEST_BEFORE_POST_CAPTURE) {
        schedule->before_post++;
        return rg_write(schedule->workspace,
                        "lib/net/src/generation.c",
                        rg_source_a);
    }
    return false;
}

static int case_aba_generation_join(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    bool same_size = sizeof(rg_source_a) == sizeof(rg_source_b);
    bool temp_created = platform_temp_directory_create(
        "z23-rg-", temporary, sizeof(temporary));
    bool canonical = temp_created && platform_directory_canonical_real(
        temporary, workspace, sizeof(workspace));
    bool source_written = canonical && rg_write(
        workspace, "lib/net/src/generation.c", rg_source_a);
    uint8_t expected[32];
    bool manifested = source_written && rg_manifest_root(workspace, expected);
    bool ready = same_size && temp_created && source_written && canonical &&
        manifested;
    char expected_hex[65];
    if (ready) zcl_hex_encode(expected, sizeof(expected), expected_hex);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    ready = ready && json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "expected_vcs_root", expected_hex) &&
        json_push_kv_str(&input, "task_id", "aba-generation") &&
        json_push_kv_str(&input, "query", "generation function");
    struct rg_schedule schedule = {.workspace = workspace};
    zcl_native_dev_retrieval_test_set_hook(rg_aba_hook, &schedule);
    struct zcl_native_dev_retrieval_snapshot snapshot, sentinel;
    memset(&sentinel, 0x6d, sizeof(sentinel));
    snapshot = sentinel;
    char error_code[64] = {0}, error_message[256] = {0};
    int rc = ready ? zcl_native_dev_retrieval_snapshot_compute(
        &input, &snapshot, error_code, sizeof(error_code),
        error_message, sizeof(error_message)) : ZCL_COMMAND_EXIT_INTERNAL;
    zcl_native_dev_retrieval_test_set_hook(NULL, NULL);
    if (!ready || schedule.before_open != 1u ||
        schedule.before_post != 1u || rc != ZCL_COMMAND_EXIT_INVALID) {
        printf("retrieval_generation: state ready=%d setup=%d/%d/%d/%d/%d "
               "before_open=%u "
               "before_post=%u rc=%d code=%s message=%s\n",
               ready, same_size, temp_created, canonical, source_written,
               manifested, schedule.before_open, schedule.before_post, rc,
               error_code[0] ? error_code : "(none)",
               error_message[0] ? error_message : "(none)");
    }
    RG_CHECK("A-B-A source schedule reaches both exact phase latches",
             ready && schedule.before_open == 1u &&
             schedule.before_post == 1u);
    RG_CHECK("mixed code-index generation refuses without snapshot output",
             rc == ZCL_COMMAND_EXIT_INVALID &&
             strcmp(error_code,
                    "CODEINDEX_GENERATION_CHANGED_DURING_BENCHMARK") == 0 &&
             memcmp(&snapshot, &sentinel, sizeof(snapshot)) == 0);
    json_free(&input);
    if (temporary[0]) dir_remove_tree(temporary);
    return failures;
}

int test_retrieval_generation(void)
{
    return case_projection_binding() + case_aba_generation_join();
}
