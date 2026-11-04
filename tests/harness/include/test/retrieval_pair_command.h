/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exercise the retrieval pair command using the science fixture. */
#ifndef ZCL_TEST_RETRIEVAL_PAIR_COMMAND_H
#define ZCL_TEST_RETRIEVAL_PAIR_COMMAND_H

#include "base/hex.h"
#include "command/native_dev_retrieval_pair.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "sha3/sha3.h"
#include "vcs/vcs_object.h"
#include "zjsonp/zjsonp.h"

#include <stdlib.h>

static bool rpc_fixture_wire(struct json_value *artifact, const char *key,
                              const uint8_t *wire, size_t len)
{
    char hex[2u * VCS_ZCODE_HEURISTIC_WIRE_BYTES + 1u];
    if (len > VCS_ZCODE_HEURISTIC_WIRE_BYTES) return false;
    zcl_hex_encode(wire, len, hex);
    return json_push_kv_str(artifact, key, hex);
}

#define RPC_WIRE(key_, function_, member_, size_) do { \
    uint8_t wire[size_]; \
    if (function_(&fixture->member_, wire) != 0 || \
        !rpc_fixture_wire(artifact, key_, wire, sizeof(wire))) return false; \
} while (0)

static bool rpc_fixture_wires(const struct rsa_fixture *fixture,
                               struct json_value *artifact)
{
    RPC_WIRE("parent_profile_hex", zcl_retrieval_profile_serialize,
             parent_profile, ZCL_RETRIEVAL_PROFILE_WIRE_BYTES);
    RPC_WIRE("child_profile_hex", zcl_retrieval_profile_serialize,
             child_profile, ZCL_RETRIEVAL_PROFILE_WIRE_BYTES);
    RPC_WIRE("parent_heuristic_hex", vcs_zcode_heuristic_serialize,
             parent_heuristic, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
    RPC_WIRE("child_heuristic_hex", vcs_zcode_heuristic_serialize,
             child_heuristic, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
    RPC_WIRE("policy_hex", zcl_retrieval_comparison_policy_v2_serialize,
             comparison_policy, ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES);
    RPC_WIRE("study_hex", vcs_zcode_study_spec_serialize,
             study, VCS_ZCODE_STUDY_SPEC_WIRE_BYTES);
    RPC_WIRE("task_hex", vcs_zcode_task_serialize,
             task, VCS_ZCODE_TASK_WIRE_BYTES);
    RPC_WIRE("candidate_hex", vcs_zcode_candidate_serialize,
             candidate, VCS_ZCODE_CANDIDATE_WIRE_BYTES);
    RPC_WIRE("environment_policy_hex", vcs_zcode_environment_policy_v1_serialize,
             environment_policy, VCS_ZCODE_ENVIRONMENT_POLICY_WIRE_BYTES);
    RPC_WIRE("hardware_profile_hex", vcs_zcode_hardware_profile_serialize,
             hardware_profile, VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES);
    return true;
}
#undef RPC_WIRE

static bool rpc_fixture_rows(struct rsa_fixture *fixture,
                              struct json_value *artifact)
{
    struct zcl_retrieval_ranked_file baseline[5];
    struct json_value rows = {0}, gold = {0};
    json_set_array(&rows);
    json_set_array(&gold);
    bool ok = true;
    for (size_t i = 0; i < 5u; i++) {
        baseline[i] = (struct zcl_retrieval_ranked_file){
            .path = fixture->rows[i].path,
            .context_bytes = fixture->rows[i].context_bytes,
        };
        struct json_value row = {0};
        json_set_object(&row);
        ok = ok && json_push_kv_str(&row, "path", baseline[i].path) &&
            json_push_kv_int(&row, "context_bytes", (int64_t)baseline[i].context_bytes) &&
            json_push_back(&rows, &row);
        json_free(&row);
    }
    struct json_value relevant = {0};
    json_set_str(&relevant, fixture->relevant[0]);
    ok = ok && json_push_back(&gold, &relevant) &&
        json_push_kv(artifact, "baseline", &rows) &&
        json_push_kv(artifact, "relevant_paths", &gold) &&
        zcl_retrieval_context_feature_snapshot(fixture->source_root,
            fixture->projection_root, "find the exact target", baseline, 5u,
            true, &fixture->snapshot, fixture->rows, 5u) == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        rsa_refresh_heuristics(fixture) && rsa_refresh_candidate(fixture);
    json_free(&relevant);
    json_free(&gold);
    json_free(&rows);
    return ok;
}

static bool rpc_fixture_facts(const struct rsa_fixture *fixture,
                               struct json_value *artifact)
{
    return json_push_kv_int(artifact, "action_sequence", 7) &&
        json_push_kv_int(artifact, "result_sequence", 1) &&
        json_push_kv_int(artifact, "challenge_block_height", 100) &&
        rpc_fixture_wire(artifact, "challenge_block_hash", fixture->source_root, 32u) &&
        json_push_kv_int(artifact, "started_unix", 1200) &&
        json_push_kv_int(artifact, "finished_unix", 1201) &&
        json_push_kv_int(artifact, "now_unix", 2000);
}

static bool rpc_fixture_policy(struct rsa_fixture *fixture,
                                struct json_value *artifact,
                                uint8_t metric, uint16_t threshold)
{
    json_set_object(artifact);
    return rsa_fixture_init(fixture, metric, threshold) &&
        rpc_fixture_rows(fixture, artifact) && rpc_fixture_wires(fixture, artifact) &&
        json_push_kv_str(artifact, "schema", "zcl.retrieval_pair_artifact.v1") &&
        json_push_kv_str(artifact, "task_id", "science_pair") &&
        json_push_kv_str(artifact, "query", "find the exact target") &&
        rpc_fixture_wire(artifact, "source_root", fixture->source_root, 32u) &&
        rpc_fixture_wire(artifact, "retrieval_projection_root", fixture->projection_root, 32u) &&
        json_push_kv_bool(artifact, "ranking_complete", true) &&
        rpc_fixture_facts(fixture, artifact);
}

static bool rpc_fixture_artifact(struct rsa_fixture *fixture,
                                  struct json_value *artifact)
{
    return rpc_fixture_policy(fixture, artifact, ZCL_RETRIEVAL_COMPARISON_MRR_BP, 8000u);
}

static bool rpc_store(const char *workspace, const char *raw, size_t len,
                       char hex[65])
{
    uint8_t root[32];
    zcl_sha3_256((const uint8_t *)raw, len, root);
    zcl_hex_encode(root, 32u, hex);
    return vcs_object_store_init(workspace) &&
        vcs_object_put_addressed(workspace, root, (const uint8_t *)raw, len);
}

static bool rpc_execute(const char *workspace, const char *root,
                         struct json_value *reply, enum zcl_command_exit *rc)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = NULL;
    for (size_t i = 0; i < registry->count; i++)
        if (strcmp(registry->commands[i].path, "dev.retrieval.pair") == 0)
            spec = &registry->commands[i];
    if (!spec) return false;
    /* The test catalog has release-style COMPAT dev leaves. Match the
     * established native_api_contract dev-binding seam; the CLI proof uses
     * the actual dev catalog without this adaptation. */
    struct zcl_command_spec executable = *spec;
    executable.availability = ZCL_COMMAND_READY;
    executable.availability_reason = "";
    executable.compat_target = "";
    executable.handler = zcl_native_handle_dev_retrieval_pair;
    struct zcl_command_registry local = {.commands = &executable, .count = 1};
    struct zcl_command_context ctx = {.registry = registry,
        .granted_capabilities = UINT64_MAX, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        .dev_build = true, .source_root = workspace, .operator_lane = "dev"};
    struct json_value input = {0};
    json_set_object(&input);
    char out[16384];
    bool ok = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "artifact_root", root);
    size_t n = ok ? zcl_command_registry_execute_json(&local, &executable, &ctx,
        &input, false, spec->path, "normal", 0, 0, NULL, out, sizeof(out), rc) : 0;
    json_free(&input);
    return n > 0 && n < sizeof(out) && json_read(reply, out, n);
}

static bool rpc_root_equal(const struct json_value *data, const char *key,
                            const uint8_t root[32])
{
    char expected[65];
    zcl_hex_encode(root, 32u, expected);
    const char *actual = json_get_str(json_get(data, key));
    return actual && strcmp(actual, expected) == 0;
}

static bool rpc_refused_code(const char *workspace, const char *raw, size_t len,
                              const char *code)
{
    char root[65];
    struct json_value reply = {0};
    enum zcl_command_exit rc = ZCL_COMMAND_EXIT_OK;
    bool ok = rpc_store(workspace, raw, len, root) &&
        rpc_execute(workspace, root, &reply, &rc) && rc != ZCL_COMMAND_EXIT_OK &&
        !json_get_bool(json_get(&reply, "ok"));
    const char *actual = json_get_str(json_get(json_get(&reply, "error"), "code"));
    if (code) ok = ok && actual && strcmp(actual, code) == 0;
    json_free(&reply);
    return ok;
}

static bool rpc_refused(const char *workspace, const char *raw, size_t len)
{
    return rpc_refused_code(workspace, raw, len, NULL);
}

static bool rpc_replace_wire(struct json_value *artifact, const char *key,
                              const uint8_t *wire, size_t len)
{
    struct json_value *value = (struct json_value *)json_get(artifact, key);
    char hex[2u * VCS_ZCODE_HEURISTIC_WIRE_BYTES + 1u];
    if (!value || len > VCS_ZCODE_HEURISTIC_WIRE_BYTES) return false;
    zcl_hex_encode(wire, len, hex);
    json_set_str(value, hex);
    return value->type == JSON_STR;
}

static int rpc_canonical_cases(const char *workspace, const struct rsa_fixture *original,
                                const struct json_value *artifact)
{
    int failures = 0;
    for (unsigned i = 0; i < 4u; i++) {
        struct rsa_fixture fixture = *original;
        struct json_value changed = {0};
        bool ok = json_copy_checked(&changed, artifact);
        uint8_t wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
        if (i == 0) {
            fixture.candidate.patch_root[0] ^= 1u;
            ok = ok && vcs_zcode_candidate_serialize(&fixture.candidate, wire) == VCS_ZCODE_DEV_OK &&
                rpc_replace_wire(&changed, "candidate_hex", wire, VCS_ZCODE_CANDIDATE_WIRE_BYTES);
        } else if (i == 1) {
            fixture.comparison_policy.threshold_bp = 1u;
            ok = ok && zcl_retrieval_comparison_policy_v2_serialize(&fixture.comparison_policy, wire) ==
                ZCL_RETRIEVAL_COMPARISON_OK && rpc_replace_wire(&changed, "policy_hex", wire,
                    ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES);
        } else if (i == 2) {
            fixture.hardware_profile.physical_cores = 1u;
            ok = ok && vcs_zcode_hardware_profile_serialize(&fixture.hardware_profile, wire) ==
                VCS_ZCODE_SCIENCE_OK && rpc_replace_wire(&changed, "hardware_profile_hex", wire,
                    VCS_ZCODE_HARDWARE_PROFILE_WIRE_BYTES);
        } else {
            fixture.study.workloads_root[0] ^= 1u;
            ok = ok && vcs_zcode_study_spec_serialize(&fixture.study, wire) == VCS_ZCODE_SCIENCE_OK &&
                rpc_replace_wire(&changed, "study_hex", wire, VCS_ZCODE_STUDY_SPEC_WIRE_BYTES);
        }
        char raw[16384];
        size_t len = json_write(&changed, raw, sizeof(raw));
        RSA_CHECK("canonical wire with mismatched binding refused", ok && len < sizeof(raw) &&
            rpc_refused_code(workspace, raw, len, "PAIR_MEASUREMENT_REFUSED"));
        json_free(&changed);
    }
    return failures;
}

static int rpc_lineage_cases(const char *workspace, const struct rsa_fixture *original,
                              const struct json_value *artifact)
{
    int failures = 0;
    for (unsigned i = 0; i < 3u; i++) {
        struct rsa_fixture fixture = *original;
        struct json_value changed = {0};
        bool ok = json_copy_checked(&changed, artifact);
        uint8_t wire[VCS_ZCODE_HEURISTIC_WIRE_BYTES];
        if (i == 0) {
            fixture.child_profile.context_byte_scale = 500u;
            ok = ok && zcl_retrieval_profile_serialize(&fixture.child_profile, wire) ==
                ZCL_RETRIEVAL_EXPERIMENT_OK && rpc_replace_wire(&changed, "child_profile_hex",
                    wire, ZCL_RETRIEVAL_PROFILE_WIRE_BYTES);
        } else if (i == 1) {
            fixture.child_heuristic.parent_roots[0][0] ^= 1u;
            ok = ok && vcs_zcode_heuristic_serialize(&fixture.child_heuristic, wire) ==
                VCS_ZCODE_ATTENTION_OK && rpc_replace_wire(&changed, "child_heuristic_hex",
                    wire, VCS_ZCODE_HEURISTIC_WIRE_BYTES);
        } else {
            fixture.comparison_policy.evaluator_root[0] ^= 1u;
            ok = ok && zcl_retrieval_comparison_policy_v2_serialize(&fixture.comparison_policy, wire) ==
                ZCL_RETRIEVAL_COMPARISON_OK && rpc_replace_wire(&changed, "policy_hex",
                    wire, ZCL_RETRIEVAL_COMPARISON_POLICY_V2_WIRE_BYTES);
        }
        char raw[16384];
        size_t len = json_write(&changed, raw, sizeof(raw));
        RSA_CHECK("profile evaluator or lineage substitution refused", ok && len < sizeof(raw) &&
            rpc_refused_code(workspace, raw, len, "PAIR_MEASUREMENT_REFUSED"));
        json_free(&changed);
    }
    return failures;
}

static int rpc_evidence_cases(const char *workspace, const struct json_value *artifact)
{
    int failures = 0;
    for (unsigned i = 0; i < 2u; i++) {
        struct json_value changed = {0};
        bool ok = json_copy_checked(&changed, artifact);
        if (ok && i == 0) {
            struct json_value *gold = (struct json_value *)json_at(json_get(&changed, "relevant_paths"), 0);
            json_set_str(gold, "src/a.c");
        } else if (ok) {
            struct json_value *row = (struct json_value *)json_at(json_get(&changed, "baseline"), 0);
            json_set_int((struct json_value *)json_get(row, "context_bytes"), 501);
        }
        char raw[16384];
        size_t len = json_write(&changed, raw, sizeof(raw));
        RSA_CHECK("substituted gold workload or baseline rows refused", ok && len < sizeof(raw) &&
            rpc_refused_code(workspace, raw, len, "PAIR_MEASUREMENT_REFUSED"));
        json_free(&changed);
    }
    return failures;
}

static int rpc_binding_cases(const char *workspace, const struct json_value *artifact)
{
    static const char *const keys[] = {"task_id", "query", "source_root",
        "retrieval_projection_root", "parent_profile_hex", "child_profile_hex",
        "policy_hex", "study_hex", "candidate_hex", "hardware_profile_hex"};
    int failures = 0;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        struct json_value changed = {0};
        bool copied = json_copy_checked(&changed, artifact);
        struct json_value *v = (struct json_value *)json_get(&changed, keys[i]);
        if (v && v->type == JSON_STR) v->val.s[0] = v->val.s[0] == '0' ? '1' : '0';
        char raw[16384];
        size_t n = json_write(&changed, raw, sizeof(raw));
        RSA_CHECK(keys[i], copied && n < sizeof(raw) && rpc_refused(workspace, raw, n));
        json_free(&changed);
    }
    return failures;
}

static bool rpc_artifact_shape(const char *raw, size_t len)
{
    zjsonp parser;
    zjsonp_init(&parser, raw, len);
    zjsonp_event event;
    zjsonp_status status;
    size_t depth = 0, fields = 0;
    while ((status = zjsonp_next(&parser, &event)) == ZJRP_OK) {
        if (event.kind == ZJRP_OBJ_OPEN || event.kind == ZJRP_ARR_OPEN) depth++;
        else if (event.kind == ZJRP_OBJ_CLOSE || event.kind == ZJRP_ARR_CLOSE) depth--;
        else if (event.kind == ZJRP_KEY && depth == 1u) fields++;
    }
    return status == ZJRP_DONE && depth == 0 && fields == 25u;
}

static int rpc_framing_cases(const char *workspace, const char *raw, size_t len)
{
    int failures = 0;
    char changed[17000];
    int n = snprintf(changed, sizeof(changed), "{\"schema\":\"zcl.retrieval_pair_artifact.v1\",%s", raw + 1);
    RSA_CHECK("duplicate artifact field refused", n > 0 && (size_t)n < sizeof(changed) &&
        rpc_refused(workspace, changed, (size_t)n));
    memcpy(changed, raw, len);
    changed[len] = 'x';
    RSA_CHECK("trailing artifact bytes refused", rpc_refused_code(workspace, changed, len + 1u,
        "PAIR_ARTIFACT_INVALID"));
    const char *path = strstr(raw, "src/target.c");
    if (!path) return failures + 1;
    size_t prefix = (size_t)(path - raw) + strlen("src/target.c");
    n = snprintf(changed, sizeof(changed), "%.*s\\u0000suffix%s", (int)prefix, raw, raw + prefix);
    /* Check grammar/field count without the DOM's intentional decoded-NUL
     * refusal: that refusal is exactly what this command must preserve. */
    bool same_shape = n > 0 && (size_t)n < sizeof(changed) &&
        rpc_artifact_shape(changed, (size_t)n);
    RSA_CHECK("NUL in existing path preserves shape and is refused", same_shape &&
        rpc_refused_code(workspace, changed, (size_t)n, "PAIR_ARTIFACT_INVALID"));
    memcpy(changed, raw, len);
    /* Replace a byte INSIDE the existing quoted path, not JSON punctuation. */
    changed[(size_t)(path - raw)] = (char)0xff;
    RSA_CHECK("physical invalid UTF8 inside existing path refused",
        rpc_refused_code(workspace, changed, len, "PAIR_ARTIFACT_INVALID"));
    return failures;
}

static bool rpc_eval_reproots(const struct json_value *data, const char *wire_key,
                               const char *root_key)
{
    const char *hex = json_get_str(json_get(data, wire_key));
    uint8_t wire[ZCL_RETRIEVAL_EVAL_RESULT_WIRE_BYTES], root[32];
    struct zcl_retrieval_experiment_eval_result_v1 parsed;
    return hex && zcl_hex_decode_lower(hex, wire, sizeof(wire)) &&
        zcl_retrieval_experiment_eval_result_parse(wire, sizeof(wire), &parsed) ==
            ZCL_RETRIEVAL_EXPERIMENT_OK &&
        zcl_retrieval_experiment_eval_result_root(&parsed, root) == ZCL_RETRIEVAL_EXPERIMENT_OK &&
        rpc_root_equal(data, root_key, root);
}

static bool rpc_observation_reproots(const struct json_value *data,
                                      const struct rsa_fixture *fixture,
                                      const struct zcode_retrieval_science_result_bundle *expected)
{
    const char *hex = json_get_str(json_get(data, "observation_wire_hex"));
    uint8_t wire[ZCL_RETRIEVAL_PAIR_OBSERVATION_WIRE_BYTES], root[32];
    struct zcl_retrieval_pair_observation_v1 parsed;
    return hex && zcl_hex_decode_lower(hex, wire, sizeof(wire)) &&
        zcl_retrieval_pair_observation_parse(wire, sizeof(wire), &parsed) ==
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK &&
        zcl_retrieval_pair_observation_verify(&parsed, &fixture->comparison_policy,
            &expected->measurement.parent_result, &expected->measurement.child_result) ==
            ZCL_RETRIEVAL_PAIR_OBSERVATION_OK &&
        zcl_retrieval_pair_observation_root(&parsed, root) == ZCL_RETRIEVAL_PAIR_OBSERVATION_OK &&
        rpc_root_equal(data, "observation_root", root);
}

static bool rpc_result_reproots(const struct json_value *data, const uint8_t expected[32])
{
    const char *hex = json_get_str(json_get(data, "result_wire_hex"));
    uint8_t wire[VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES], root[32];
    struct vcs_zcode_benchmark_result_v1 parsed;
    return hex && zcl_hex_decode_lower(hex, wire, sizeof(wire)) &&
        vcs_zcode_benchmark_result_parse(wire, sizeof(wire), &parsed) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_result_root(&parsed, root) == VCS_ZCODE_SCIENCE_OK &&
        memcmp(root, expected, 32u) == 0 && rpc_root_equal(data, "result_root", root);
}

static int rpc_success(const struct json_value *reply, struct rsa_fixture *fixture)
{
    int failures = 0;
    const struct json_value *data = json_get(reply, "data");
    const char *holdout = json_get_str(json_get(data, "holdout_independence_status"));
    const struct json_value *promotion = json_get(data, "promotion_authorized");
    RSA_CHECK("pair command refuses promotion claims", promotion && promotion->type == JSON_BOOL &&
        !promotion->val.b &&
        holdout && strcmp(holdout, "unverified") == 0);
    struct zcode_retrieval_profile_pair_measure_request m = rsa_measurement(fixture);
    struct zcode_retrieval_science_result_request request = rsa_result_request(fixture, &m, 1u, 0x12u);
    struct zcode_retrieval_science_result_bundle expected;
    bool composed = zcode_retrieval_science_result_compose(&request, &expected) ==
        ZCODE_RETRIEVAL_SCIENCE_ADAPTER_OK;
    RSA_CHECK("command matches independently composed exact pair roots", composed &&
        rpc_root_equal(data, "parent_result_root", expected.measurement.parent_result_root) &&
        rpc_root_equal(data, "child_result_root", expected.measurement.child_result_root) &&
        rpc_root_equal(data, "observation_root", expected.observation_root) &&
        rpc_root_equal(data, "result_root", expected.result_root));
    RSA_CHECK("command MRR oracle is 2000 to 10000 delta8000", composed &&
        expected.measurement.parent_result.mrr_bp == 2000u &&
        expected.measurement.child_result.mrr_bp == 10000u &&
        json_get_int(json_get(json_get(data, "parent"), "mrr_bp")) == 2000 &&
        json_get_int(json_get(json_get(data, "child"), "mrr_bp")) == 10000 &&
        json_get_int(json_get(data, "directional_delta_bp")) == 8000);
    RSA_CHECK("returned evaluation and observation wires reroot", composed &&
        rpc_eval_reproots(data, "parent_result_wire_hex", "parent_result_root") &&
        rpc_eval_reproots(data, "child_result_wire_hex", "child_result_root") &&
        rpc_observation_reproots(data, fixture, &expected));
    RSA_CHECK("returned science result wire reroots to returned and expected roots",
        composed && rpc_result_reproots(data, expected.result_root));
    return failures;
}

static int rpc_status_cases(const char *workspace)
{
    static const struct { uint8_t metric; uint16_t threshold; uint8_t status; } cases[] = {
        {ZCL_RETRIEVAL_COMPARISON_MRR_BP, 8000u, VCS_ZCODE_BENCHMARK_OBSERVED},
        {ZCL_RETRIEVAL_COMPARISON_MRR_BP, 9000u, VCS_ZCODE_BENCHMARK_NEGATIVE_RESULT},
        {ZCL_RETRIEVAL_COMPARISON_WRONG_SCOPE_AT_5_BP, 0u, VCS_ZCODE_BENCHMARK_NULL_RESULT},
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct rsa_fixture fixture;
        struct json_value artifact = {0}, reply = {0};
        bool ready = rpc_fixture_policy(&fixture, &artifact, cases[i].metric, cases[i].threshold);
        char raw[16384], root[65];
        size_t len = json_write(&artifact, raw, sizeof(raw));
        enum zcl_command_exit rc = ZCL_COMMAND_EXIT_FAILED;
        RSA_CHECK("OBSERVED NEGATIVE NULL remain distinct successful observations", ready &&
            len < sizeof(raw) && rpc_store(workspace, raw, len, root) &&
            rpc_execute(workspace, root, &reply, &rc) && rc == ZCL_COMMAND_EXIT_OK &&
            json_get_int(json_get(json_get(&reply, "data"), "result_status")) == cases[i].status);
        json_free(&artifact);
        json_free(&reply);
    }
    return failures;
}

static int rsa_case_pair_command(void)
{
    int failures = 0;
    size_t json_blocks = json_test_live_blocks();
    struct rsa_fixture fixture;
    struct json_value artifact = {0}, reply = {0};
    char workspace[4096] = {0}, root[65], raw[16384];
    test_make_tmpdir(workspace, sizeof(workspace), "retrieval", "pair-command");
    bool ready = rpc_fixture_artifact(&fixture, &artifact);
    size_t len = json_write(&artifact, raw, sizeof(raw));
    ready = ready && len < sizeof(raw) && rpc_store(workspace, raw, len, root);
    RSA_CHECK("content-addressed pair fixture is ready", ready);
    enum zcl_command_exit rc = ZCL_COMMAND_EXIT_FAILED;
    bool ran = ready && rpc_execute(workspace, root, &reply, &rc);
    RSA_CHECK("declared pair command dev binding computes both arms", ran && rc == ZCL_COMMAND_EXIT_OK);
    if (ran) failures += rpc_success(&reply, &fixture);
    if (ready && ran) {
        failures += rpc_binding_cases(workspace, &artifact);
        failures += rpc_canonical_cases(workspace, &fixture, &artifact);
        failures += rpc_lineage_cases(workspace, &fixture, &artifact);
        failures += rpc_evidence_cases(workspace, &artifact);
        failures += rpc_framing_cases(workspace, raw, len);
        failures += rpc_status_cases(workspace);
        json_free(&reply);
        const char *bad = "{}";
        /* Addressed put is immutable; corruption is injected only in this fixture. */
        char path[4096];
        int n = snprintf(path, sizeof(path), "%s/.zvcs/objects/%.2s/%s", workspace, root, root + 2);
        FILE *f = n > 0 && (size_t)n < sizeof(path) ? fopen(path, "wb") : NULL;
        bool damaged = f && fwrite(bad, 1, 2u, f) == 2u;
        if (f && fclose(f) != 0) damaged = false;
        RSA_CHECK("CAS address mismatch refused", damaged &&
            rpc_execute(workspace, root, &reply, &rc) && rc != ZCL_COMMAND_EXIT_OK);
    }
    json_free(&reply);
    json_free(&artifact);
    RSA_CHECK("command success and refusal allocations released", json_test_live_blocks() == json_blocks);
    RSA_CHECK("pair fixture cleanup", test_rm_rf_recursive(workspace) == 0);
    return failures;
}

#endif /* ZCL_TEST_RETRIEVAL_PAIR_COMMAND_H */
