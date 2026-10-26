/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: adversarial generation-join schedules for retrieval commands. */
#include "test/test_core.h"

#include "base/hex.h"
#include "codeindex/codeindex.h"
#include "command/native_command.h"
#include "command/native_dev_retrieval_stream.h"
#include "config/file_ops.h"
#include "controllers/agent_impact_rules.h"
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

struct rg_text_expect {
    const char *observed;
    const char *expected;
};

static int rg_projection_prepare(char *temporary, size_t temporary_n,
                                 char *workspace, size_t workspace_n,
                                 struct json_value *input,
                                 struct zcl_native_dev_retrieval_snapshot *snapshot,
                                 char *error_code, size_t error_code_n,
                                 char *error_message, size_t error_message_n,
                                 bool *ready_out)
{
    uint8_t expected[32];
    char expected_hex[65];
    bool ready = platform_temp_directory_create(
            "z23-rg-bind-", temporary, temporary_n) &&
        platform_directory_canonical_real(
            temporary, workspace, workspace_n) &&
        rg_write(workspace, "lib/net/src/generation.c", rg_source_a);
    ready = ready && rg_manifest_root(workspace, expected);
    if (ready) zcl_hex_encode(expected, sizeof(expected), expected_hex);
    json_init(input);
    json_set_object(input);
    ready = ready && json_push_kv_str(input, "workspace", workspace) &&
        json_push_kv_str(input, "expected_vcs_root", expected_hex) &&
        json_push_kv_str(input, "task_id", "projection-binding") &&
        json_push_kv_str(input, "query", "generation function");
    *ready_out = ready;
    return ready ? zcl_native_dev_retrieval_snapshot_compute(
        input, snapshot, error_code, error_code_n,
        error_message, error_message_n) : ZCL_COMMAND_EXIT_INTERNAL;
}

static bool rg_projection_view_roots(int rc, const char *workspace,
                                     struct codeindex **index_out,
                                     uint8_t source_root[32],
                                     uint8_t projection_root[32])
{
    *index_out = rc == ZCL_COMMAND_EXIT_OK
        ? codeindex_open_retrieval_view(workspace) : NULL;
    return *index_out &&
        codeindex_source_root_sha3(*index_out, source_root) &&
        codeindex_retrieval_projection_root_sha3(*index_out, projection_root);
}

static bool rg_snapshot_roots_distinct(
    bool ready, int rc, bool rooted,
    const struct zcl_native_dev_retrieval_snapshot *snapshot)
{
    return ready && rc == ZCL_COMMAND_EXIT_OK && rooted &&
        rg_root_any(snapshot->codeindex_source_root) &&
        rg_root_any(snapshot->retrieval_projection_root) &&
        memcmp(snapshot->codeindex_source_root,
               snapshot->retrieval_projection_root, 32u) != 0;
}

static bool rg_snapshot_roots_match_view(
    bool rooted, const struct zcl_native_dev_retrieval_snapshot *snapshot,
    const uint8_t source_root[32], const uint8_t projection_root[32])
{
    return rooted &&
        memcmp(snapshot->codeindex_source_root, source_root, 32u) == 0 &&
        memcmp(snapshot->retrieval_projection_root, projection_root, 32u) == 0;
}

static bool rg_profile_features_ready(
    bool rooted, enum zcl_retrieval_experiment_error profile_status,
    const struct zcl_retrieval_profile_v1 *profile,
    const struct zcl_native_dev_retrieval_snapshot *snapshot,
    struct zcl_retrieval_feature_snapshot_v1 *feature_snapshot,
    struct zcl_retrieval_feature_row_v1 *feature_rows, size_t *indices,
    struct zcl_retrieval_profile_report *profile_report,
    uint8_t profile_root[32], uint8_t feature_root[32],
    uint8_t candidate_root[32])
{
    bool experiment_ready = rooted &&
        profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_context_feature_snapshot(
            snapshot->codeindex_source_root,
            snapshot->retrieval_projection_root, snapshot->query,
            snapshot->bm25.rows, snapshot->bm25.count, snapshot->bm25.complete,
            feature_snapshot, feature_rows,
            ZCL_RETRIEVAL_EVAL_RANK_MAX) == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_profile_project(
            profile, feature_snapshot, feature_rows, indices,
            ZCL_RETRIEVAL_EVAL_RANK_MAX, profile_report) ==
                ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_profile_root(profile, profile_root) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_feature_snapshot_root(
            feature_snapshot, feature_rows, feature_root) ==
                ZCL_RETRIEVAL_EXPERIMENT_OK;
    if (experiment_ready)
        memcpy(candidate_root, profile_report->candidate_ranking_root,
               sizeof(profile_report->candidate_ranking_root));
    return experiment_ready;
}

static bool rg_push_experiment_identity(
    bool experiment_ready, struct json_value *input,
    const char *profile_wire_hex, const char *study_hex,
    const char *preregistration_hex, const char *evaluator_hex,
    const struct zcl_native_dev_retrieval_snapshot *snapshot,
    const uint8_t profile_root[32], const uint8_t feature_root[32],
    const uint8_t candidate_root[32], const uint8_t study[32],
    const uint8_t preregistration[32], const uint8_t evaluator[32],
    uint8_t proposal[32])
{
    return experiment_ready &&
        json_push_kv_str(input, "profile_hex", profile_wire_hex) &&
        json_push_kv_str(input, "study_root", study_hex) &&
        json_push_kv_str(input, "preregistration_root",
                         preregistration_hex) &&
        json_push_kv_str(input, "evaluator_root", evaluator_hex) &&
        zcl_retrieval_profile_proposal_input_root(
            snapshot->source_root, snapshot->codeindex_source_root,
            snapshot->retrieval_projection_root, snapshot->task_id,
            snapshot->query, snapshot->bm25_ranking_root, profile_root,
            feature_root, candidate_root, study, preregistration, evaluator,
            proposal);
}

static bool rg_text_expects_match(const struct rg_text_expect *expect,
                                  size_t count)
{
    bool matched = true;
    for (size_t i = 0; i < count; i++)
        matched = matched && expect[i].observed &&
            strcmp(expect[i].observed, expect[i].expected) == 0;
    return matched;
}

static bool rg_experiment_v3_evidence_bound(
    bool experiment_ready, const struct zcl_command_reply *reply,
    const char *schema, const struct rg_text_expect *expect, size_t count)
{
    return experiment_ready &&
        reply->exit_code == ZCL_COMMAND_EXIT_OK &&
        schema && strcmp(schema, "zcl.dev_retrieval_experiment.v3") == 0 &&
        rg_text_expects_match(expect, count) &&
        !json_get_bool(json_get(&reply->data, "quality_claim_available")) &&
        !json_get_bool(json_get(&reply->data, "promotion_authorized"));
}

static bool rg_experiment_roots_repeat(
    int exit_code, const char *second_proposal, const char *first_proposal,
    const char *second_feature, const char *first_feature,
    const char *second_candidate, const char *first_candidate)
{
    const struct rg_text_expect expect[] = {
        {second_proposal, first_proposal},
        {second_feature, first_feature},
        {second_candidate, first_candidate},
    };
    return exit_code == ZCL_COMMAND_EXIT_OK &&
        rg_text_expects_match(expect, sizeof(expect) / sizeof(expect[0]));
}

static bool rg_profile_feature_unavailable(
    const struct zcl_command_reply *reply)
{
    return reply->exit_code != ZCL_COMMAND_EXIT_OK &&
        strcmp(reply->error.code, "PROJECTION_REFUSED") == 0 &&
        strstr(reply->error.message, "unavailable") != NULL &&
        json_get(&reply->data, "candidate_ranking_root") == NULL &&
        json_get(&reply->data, "proposal_input_root") == NULL;
}

static bool rg_profile_wire_refused(const struct zcl_command_reply *reply)
{
    return reply->exit_code != ZCL_COMMAND_EXIT_OK &&
        strcmp(reply->error.code, "INVALID_PROFILE") == 0 &&
        json_get(&reply->data, "source_root") == NULL;
}

static void rg_replace_profile_hex(struct json_value *input, const char *hex)
{
    for (size_t i = 0; i < input->num_children; i++)
        if (strcmp(input->keys[i], "profile_hex") == 0)
            json_set_str(&input->children[i], hex);
}

static int case_projection_binding(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    struct json_value input;
    struct zcl_native_dev_retrieval_snapshot snapshot = {0};
    char error_code[64] = {0}, error_message[256] = {0};
    bool ready = false;
    int rc = rg_projection_prepare(
        temporary, sizeof(temporary), workspace, sizeof(workspace),
        &input, &snapshot, error_code, sizeof(error_code),
        error_message, sizeof(error_message), &ready);
    struct codeindex *index = NULL;
    uint8_t source_root[32] = {0}, projection_root[32] = {0};
    bool rooted = rg_projection_view_roots(
        rc, workspace, &index, source_root, projection_root);
    RG_CHECK("snapshot binds distinct source and logical projection roots",
             rg_snapshot_roots_distinct(ready, rc, rooted, &snapshot));
    RG_CHECK("snapshot roots reproduce the verified retrieval view",
             rg_snapshot_roots_match_view(
                 rooted, &snapshot, source_root, projection_root));

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
    bool experiment_ready = rg_profile_features_ready(
        rooted, profile_status, &profile, &snapshot, &feature_snapshot,
        feature_rows, indices, &profile_report, profile_root, feature_root,
        candidate_root);
    experiment_ready = rg_push_experiment_identity(
        experiment_ready, &input, profile_wire_hex, study_hex,
        preregistration_hex, evaluator_hex, &snapshot, profile_root,
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
    const struct rg_text_expect bound[] = {
        {observed_source, source_hex},
        {observed_projection, projection_hex},
        {observed_proposal, proposal_hex},
        {observed_profile, profile_root_hex},
        {observed_feature, feature_root_hex},
        {observed_candidate, first_candidate},
    };
    RG_CHECK("experiment v3 binds profile and exact feature evidence",
             rg_experiment_v3_evidence_bound(
                 experiment_ready, &reply, schema, bound,
                 sizeof(bound) / sizeof(bound[0])));
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
             rg_experiment_roots_repeat(
                 reply.exit_code, second_proposal, first_proposal,
                 second_feature, first_feature, second_candidate,
                 first_candidate));
    zcl_command_reply_free(&reply);

    profile.feature_mask |= ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_PATH);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PATH] = 100u;
    profile_status = zcl_retrieval_profile_serialize(&profile, profile_wire);
    if (profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK) {
        zcl_hex_encode(profile_wire, sizeof(profile_wire), profile_wire_hex);
        rg_replace_profile_hex(&input, profile_wire_hex);
    }
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    if (profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK)
        zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    RG_CHECK("unobserved profile feature fails incomplete without candidate",
             rg_profile_feature_unavailable(&reply));
    zcl_command_reply_free(&reply);

    profile.feature_mask &= (uint16_t)~ZCL_RETRIEVAL_FEATURE_BIT(
        ZCL_RETRIEVAL_FEATURE_PATH);
    profile.weight_bp[ZCL_RETRIEVAL_FEATURE_PATH] = 0u;
    profile_status = zcl_retrieval_profile_serialize(&profile, profile_wire);
    if (profile_status == ZCL_RETRIEVAL_EXPERIMENT_OK) {
        zcl_hex_encode(profile_wire, sizeof(profile_wire), profile_wire_hex);
        profile_wire_hex[1] = 'A';
        rg_replace_profile_hex(&input, profile_wire_hex);
    }
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    RG_CHECK("noncanonical uppercase profile wire is refused before ranking",
             rg_profile_wire_refused(&reply));
    zcl_command_reply_free(&reply);

    rg_replace_profile_hex(&input, "00");
    zcl_command_reply_init(&reply, "zcl.dev_retrieval_experiment.v3");
    zcl_native_handle_dev_retrieval_experiment(&request, &reply);
    RG_CHECK("wrong-size profile wire is refused before ranking",
             rg_profile_wire_refused(&reply));
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

struct rg_aba_setup {
    bool same_size;
    bool temp_created;
    bool canonical;
    bool source_written;
    bool manifested;
    bool ready;
};

static void rg_aba_bind_workspace(struct rg_aba_setup *setup,
                                  char *temporary, size_t temporary_n,
                                  char *workspace, size_t workspace_n,
                                  char expected_hex[65])
{
    uint8_t expected[32];
    setup->same_size = sizeof(rg_source_a) == sizeof(rg_source_b);
    setup->temp_created = platform_temp_directory_create(
        "z23-rg-", temporary, temporary_n);
    setup->canonical = setup->temp_created &&
        platform_directory_canonical_real(temporary, workspace, workspace_n);
    setup->source_written = setup->canonical &&
        rg_write(workspace, "lib/net/src/generation.c", rg_source_a);
    setup->manifested = setup->source_written &&
        rg_manifest_root(workspace, expected);
    setup->ready = setup->same_size && setup->temp_created &&
        setup->source_written && setup->canonical && setup->manifested;
    if (setup->ready)
        zcl_hex_encode(expected, sizeof(expected), expected_hex);
}

static int rg_aba_run_hooked_snapshot(
    bool *ready, struct json_value *input, const char *workspace,
    const char *expected_hex, struct rg_schedule *schedule,
    struct zcl_native_dev_retrieval_snapshot *snapshot,
    struct zcl_native_dev_retrieval_snapshot *sentinel,
    char *error_code, size_t error_code_n,
    char *error_message, size_t error_message_n)
{
    *ready = *ready &&
        json_push_kv_str(input, "workspace", workspace) &&
        json_push_kv_str(input, "expected_vcs_root", expected_hex) &&
        json_push_kv_str(input, "task_id", "aba-generation") &&
        json_push_kv_str(input, "query", "generation function");
    zcl_native_dev_retrieval_test_set_hook(rg_aba_hook, schedule);
    memset(sentinel, 0x6d, sizeof(*sentinel));
    *snapshot = *sentinel;
    int rc = *ready ? zcl_native_dev_retrieval_snapshot_compute(
        input, snapshot, error_code, error_code_n,
        error_message, error_message_n) : ZCL_COMMAND_EXIT_INTERNAL;
    zcl_native_dev_retrieval_test_set_hook(NULL, NULL);
    return rc;
}

static bool rg_aba_state_unexpected(bool ready, unsigned before_open,
                                    unsigned before_post, int rc)
{
    return !ready || before_open != 1u || before_post != 1u ||
        rc != ZCL_COMMAND_EXIT_INVALID;
}

static bool rg_aba_latches_reached(bool ready, unsigned before_open,
                                   unsigned before_post)
{
    return ready && before_open == 1u && before_post == 1u;
}

static bool rg_aba_snapshot_refused(
    int rc, const char *error_code,
    const struct zcl_native_dev_retrieval_snapshot *snapshot,
    const struct zcl_native_dev_retrieval_snapshot *sentinel)
{
    return rc == ZCL_COMMAND_EXIT_INVALID &&
        strcmp(error_code,
               "CODEINDEX_GENERATION_CHANGED_DURING_BENCHMARK") == 0 &&
        memcmp(snapshot, sentinel, sizeof(*snapshot)) == 0;
}

static int case_aba_generation_join(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    char expected_hex[65];
    struct rg_aba_setup setup;
    rg_aba_bind_workspace(&setup, temporary, sizeof(temporary),
                          workspace, sizeof(workspace), expected_hex);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    struct rg_schedule schedule = {.workspace = workspace};
    struct zcl_native_dev_retrieval_snapshot snapshot, sentinel;
    char error_code[64] = {0}, error_message[256] = {0};
    int rc = rg_aba_run_hooked_snapshot(
        &setup.ready, &input, workspace, expected_hex, &schedule,
        &snapshot, &sentinel, error_code, sizeof(error_code),
        error_message, sizeof(error_message));
    if (rg_aba_state_unexpected(setup.ready, schedule.before_open,
                                schedule.before_post, rc)) {
        printf("retrieval_generation: state ready=%d setup=%d/%d/%d/%d/%d "
               "before_open=%u "
               "before_post=%u rc=%d code=%s message=%s\n",
               setup.ready, setup.same_size, setup.temp_created,
               setup.canonical, setup.source_written, setup.manifested,
               schedule.before_open, schedule.before_post, rc,
               error_code[0] ? error_code : "(none)",
               error_message[0] ? error_message : "(none)");
    }
    RG_CHECK("A-B-A source schedule reaches both exact phase latches",
             rg_aba_latches_reached(setup.ready, schedule.before_open,
                                    schedule.before_post));
    RG_CHECK("mixed code-index generation refuses without snapshot output",
             rg_aba_snapshot_refused(rc, error_code, &snapshot, &sentinel));
    json_free(&input);
    if (temporary[0]) dir_remove_tree(temporary);
    return failures;
}

static FILE *rg_text_output(void)
{
    char path[PATH_MAX];
    int fd = test_mkstemp(path, sizeof(path), "rg-text-stream");
    if (fd < 0) return NULL;
    FILE *out = fdopen(fd, "w+b");
    if (!out) (void)close(fd);
    if (unlink(path) != 0) {
        if (out) (void)fclose(out);
        return NULL;
    }
    return out;
}

static bool rg_text_roundtrip(FILE *out, const char *task, const char *query)
{
    char line[8192];
    struct json_value page;
    json_init(&page);
    rewind(out);
    bool parsed = fgets(line, sizeof(line), out) &&
        json_read(&page, line, strlen(line));
    const struct json_value *data = json_get(&page, "data");
    const char *actual_task = json_get_str(json_get(data, "task_id"));
    const char *actual_query = json_get_str(json_get(data, "query"));
    bool ok = parsed && actual_task && actual_query &&
        strcmp(actual_task, task) == 0 && strcmp(actual_query, query) == 0;
    json_free(&page);
    return ok;
}

static bool rg_text_refused(FILE *out, int rc, const char *code,
                             const char *message)
{
    return out && rc == ZCL_COMMAND_EXIT_INVALID &&
        strcmp(code, "INVALID_TASK") == 0 && message[0] && ftell(out) == 0;
}

static int rg_stream_text(const char *workspace, const char *expected_hex,
                          const char *task, const char *query, bool valid)
{
    int failures = 0;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ready = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "expected_vcs_root", expected_hex) &&
        json_push_kv_str(&input, "task_id", task) &&
        json_push_kv_str(&input, "query", query);
    FILE *out = rg_text_output();
    char code[64] = {0}, message[256] = {0};
    int rc = ready && out ? zcl_native_dev_retrieval_stream_jsonl(
        &input, 4096u, out, code, sizeof(code), message, sizeof(message))
        : ZCL_COMMAND_EXIT_INTERNAL;
    if (valid) {
        RG_CHECK("UTF-8 and escaped text survive stream round trip",
                 rc == ZCL_COMMAND_EXIT_OK && out && rg_text_roundtrip(out, task, query));
    } else {
        RG_CHECK("malformed UTF-8 refuses before writing JSONL",
                 rg_text_refused(out, rc, code, message));
    }
    if (out) RG_CHECK("text stream closes", fclose(out) == 0);
    json_free(&input);
    return failures;
}

static int case_stream_utf8(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    uint8_t expected[32];
    char expected_hex[65];
    bool created = test_mkdtemp(temporary, sizeof(temporary), "rg-text") != NULL;
    bool ready = created &&
        platform_directory_canonical_real(temporary, workspace, sizeof(workspace)) &&
        rg_write(workspace, "lib/net/src/generation.c", rg_source_a) &&
        rg_manifest_root(workspace, expected);
    RG_CHECK("text stream fixture is source bound", ready);
    if (ready) {
        zcl_hex_encode(expected, sizeof(expected), expected_hex);
        static const char *const bad[] = {
            "\xff", "\x80", "\xc0\xaf", "\xe2\x82", "\xed\xa0\x80", "\xf4\x90\x80\x80"
        };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            char task[8], query[8];
            (void)snprintf(task, sizeof(task), "t%s", bad[i]);
            (void)snprintf(query, sizeof(query), "g%s", bad[i]);
            failures += rg_stream_text(workspace, expected_hex, task,
                                       "generation function", false);
            failures += rg_stream_text(workspace, expected_hex, "text-task",
                                       query, false);
        }
        failures += rg_stream_text(workspace, expected_hex,
            "t\xc2\xa2\xe2\x82\xac\xf4\x8f\xbf\xbf\"\\",
            "generation \xc2\xa2\xe2\x82\xac\xf0\x90\x80\x80\"\\", true);
    }
    if (created)
        RG_CHECK("text fixture removes", test_rm_rf_recursive(temporary) == 0);
    return failures;
}

static bool rg_impact_has_group(const struct agent_impact_acc *impact,
                                const char *group)
{
    for (size_t i = 0; i < impact->groups_len; i++)
        if (strcmp(impact->groups[i], group) == 0) return true;
    return false;
}

static int case_text_proof_mapping(void)
{
    int failures = 0;
    static const char *const paths[] = {
        "tools/command/native_dev_retrieval_command.c",
        "tools/command/native_dev_retrieval_stream.h"
    };
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        struct agent_impact_acc impact = {0};
        RG_CHECK("text seam selects generation proof",
                 agent_impact_apply_shared_rules(paths[i], &impact));
        RG_CHECK("text seam includes generation group",
                 rg_impact_has_group(&impact, "retrieval_generation"));
        RG_CHECK("text seam includes source gates",
                 rg_impact_has_group(&impact, "make_lint_gates"));
    }
    return failures;
}

int test_retrieval_generation(void)
{
    return case_projection_binding() + case_aba_generation_join() + case_stream_utf8() +
        case_text_proof_mapping();
}
