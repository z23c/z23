/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: hermetic preparation, capsule, and detached sealing proofs. */

#include "test/test_core.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_command.h"
#include "command/native_zcode_join.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/zcode_lane_service.h"
#include "util/file_tree_ops.h"
#include "util/util.h"
#include "chain/chainparams.h"
#include "vcs/package_accept.h"
#include "vcs/package_capsule.h"
#include "vcs/package_prepare.h"
#include "vcs/package_mapping.h"
#include "vcs/package_reuse.h"
#include "vcs/vcs.h"
#include "vcs/vcs_devloop.h"

#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

static bool zpd_symlink_create(const char *target, const char *link,
                               bool directory)
{
#if defined(_WIN32)
    DWORD flags = (directory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0) |
                  SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    if (CreateSymbolicLinkA(link, target, flags) != 0)
        return true;
    flags &= ~SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    return GetLastError() == ERROR_INVALID_PARAMETER &&
           CreateSymbolicLinkA(link, target, flags) != 0;
#else
    (void)directory;
    return symlink(target, link) == 0;
#endif
}

static bool zpd_symlink_remove(const char *path, bool directory)
{
#if defined(_WIN32)
    return directory ? RemoveDirectoryA(path) != 0 : DeleteFileA(path) != 0;
#else
    (void)directory;
    return unlink(path) == 0;
#endif
}

static bool zpd_special_create(const char *path)
{
#if defined(_WIN32)
    return platform_directory_create(path, 0700) == 0;
#else
    return mkfifo(path, 0600) == 0;
#endif
}

static bool zpd_special_remove(const char *path)
{
#if defined(_WIN32)
    return rmdir(path) == 0;
#else
    return unlink(path) == 0;
#endif
}

static bool zpd_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, f) == len;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static char *zpd_read_bounded(const char *path, size_t maximum_bytes)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > maximum_bytes)
        return NULL;
    size_t len = (size_t)st.st_size;
    char *text = zcl_malloc(len + 1u, "zcode.packet.test");
    if (!text) return NULL;
    FILE *f = fopen(path, "rb");
    bool ok = f && fread(text, 1, len, f) == len;
    if (f && fclose(f) != 0) ok = false;
    if (!ok) {
        free(text);
        return NULL;
    }
    text[len] = '\0';
    return text;
}

static bool zpd_next_is(const struct zcl_command_reply *reply,
                        const char *command, const char *workspace,
                        const char *work_id, const char *adapter)
{
    if (!reply || reply->next_count != 1 ||
        strcmp(reply->next[0].command, command) != 0)
        return false;
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, reply->next[0].input_json,
                        strlen(reply->next[0].input_json)) &&
        input.type == JSON_OBJ &&
        strcmp(json_get_str(json_get(&input, "workspace")), workspace) == 0 &&
        strcmp(json_get_str(json_get(&input, "work")), work_id) == 0 &&
        (!adapter || strcmp(json_get_str(json_get(&input, "adapter")),
                            adapter) == 0) &&
        (adapter || json_get(&input, "adapter") == NULL) &&
        json_get(&input, "task_root") == NULL &&
        json_get(&input, "package_root") == NULL &&
        json_get(&input, "candidate_root") == NULL;
    const struct zcl_command_spec *spec = ok
        ? zcl_command_registry_find(zcl_command_catalog(), command, NULL)
        : NULL;
    char why[160] = {0};
    ok = ok && spec && zcl_command_registry_input_validate(
        spec, &input, why, sizeof(why));
    if (!ok)
        printf("next mismatch: count=%zu command=%s input=%s why=%s\n",
               reply->next_count,
               reply->next_count ? reply->next[0].command : "<none>",
               reply->next_count ? reply->next[0].input_json : "<none>",
               why);
    json_free(&input);
    return ok;
}

static bool zpd_plant_build_output(const char *root)
{
    char path[320];
    (void)snprintf(path, sizeof(path), "%s/build", root);
    if (platform_directory_create(path, 0700) != 0) return false;
    (void)snprintf(path, sizeof(path), "%s/build/obj.o", root);
    return zpd_write(path, "not source\n");
}

static bool zpd_next_init_plan_is(const struct zcl_command_reply *reply,
                                  const char *workspace)
{
    if (!reply || reply->next_count != 1 ||
        strcmp(reply->next[0].command, "zcode.project.init.plan") != 0)
        return false;
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, reply->next[0].input_json,
                        strlen(reply->next[0].input_json)) &&
        input.type == JSON_OBJ &&
        strcmp(json_get_str(json_get(&input, "workspace")), workspace) == 0 &&
        json_get(&input, "work") == NULL &&
        json_get(&input, "task_root") == NULL &&
        json_get(&input, "package_root") == NULL;
    const struct zcl_command_spec *spec = ok
        ? zcl_command_registry_find(zcl_command_catalog(),
                                    "zcode.project.init.plan", NULL)
        : NULL;
    char why[160] = {0};
    ok = ok && spec && zcl_command_registry_input_validate(
        spec, &input, why, sizeof(why));
    if (!ok)
        printf("init-plan next mismatch: count=%zu command=%s input=%s why=%s\n",
               reply->next_count,
               reply->next_count ? reply->next[0].command : "<none>",
               reply->next_count ? reply->next[0].input_json : "<none>",
               why);
    json_free(&input);
    return ok;
}

static bool zpd_next_datadir_is(const struct zcl_command_reply *reply,
                                const char *command, const char *workspace,
                                const char *work_id, const char *datadir)
{
    if (!zpd_next_is(reply, command, workspace, work_id, NULL))
        return false;
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, reply->next[0].input_json,
                        strlen(reply->next[0].input_json)) &&
        strcmp(json_get_str(json_get(&input, "datadir")), datadir) == 0;
    json_free(&input);
    return ok;
}

static bool zpd_pubkey(secp256k1_context *ctx, const uint8_t secret[32],
                       uint8_t pubkey[33])
{
    secp256k1_pubkey parsed;
    size_t len = 33;
    return secp256k1_ec_pubkey_create(ctx, &parsed, secret) == 1 &&
           secp256k1_ec_pubkey_serialize(ctx, pubkey, &len, &parsed,
                                        SECP256K1_EC_COMPRESSED) == 1 &&
           len == 33;
}

static bool zpd_signature(secp256k1_context *ctx, const uint8_t secret[32],
                          const uint8_t digest[32], uint8_t out[64])
{
    secp256k1_ecdsa_signature signature, normalized;
    if (secp256k1_ecdsa_sign(ctx, &signature, digest, secret, NULL, NULL) != 1)
        return false;
    (void)secp256k1_ecdsa_signature_normalize(ctx, &normalized, &signature);
    return secp256k1_ecdsa_signature_serialize_compact(ctx, out,
                                                       &normalized) == 1;
}

static void zpd_fixture_cleanup(const char *root)
{
    static const char *const files[] = {
        "link", "special", "LICENSE", "zcode-package.json", "src/x.c",
        "src/unused.c", "include/x.h", "tests/test.c", ".zvcs/control",
        ".codeindex/control", "build/obj.o",
    };
    char path[512];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, files[i]);
        (void)unlink(path);
    }
    static const char *const dirs[] = {
        "src", "include", "tests", ".zvcs", ".codeindex", "build",
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[i]);
        (void)rmdir(path);
    }
    (void)rmdir(root);
}

static bool zpd_fixture(const char *root, bool unknown_key)
{
    char path[512];
    zpd_fixture_cleanup(root);
    if (platform_directory_create(root, 0700) != 0) return false;
    static const char *const dirs[] = { "src", "include", "tests" };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[i]);
        if (platform_directory_create(path, 0700) != 0) return false;
    }
    (void)snprintf(path, sizeof(path), "%s/LICENSE", root);
    if (!zpd_write(path, "MIT\n")) return false;
    (void)snprintf(path, sizeof(path), "%s/src/x.c", root);
    if (!zpd_write(path, "int x(void) { return 1; }\n")) return false;
    (void)snprintf(path, sizeof(path), "%s/include/x.h", root);
    if (!zpd_write(path, "int x(void);\n")) return false;
    (void)snprintf(path, sizeof(path), "%s/tests/test.c", root);
    if (!zpd_write(path, "int main(void) { return 0; }\n")) return false;
    (void)snprintf(path, sizeof(path), "%s/zcode-package.json", root);
    return zpd_write(path, unknown_key
        ? "{\"schema\":1,\"name\":\"zclassic23/fixture\",\"semver\":\"0.1.0-dev.1\",\"language\":\"c23\",\"license\":\"MIT\",\"include_dir\":\"include\",\"source_dir\":\"src\",\"dependencies\":[],\"smuggled\":true}\n"
        : "{\"schema\":1,\"name\":\"zclassic23/fixture\",\"semver\":\"0.1.0-dev.1\",\"language\":\"c23\",\"license\":\"MIT\",\"include_dir\":\"include\",\"source_dir\":\"src\",\"dependencies\":[]}\n");
}

static bool zpd_benchmark_project(const char *root, const char *name,
                                  int value)
{
    ZCL_IGNORE_RESULT(zcl_tree_remove(root), "benchmark fixture reset");
    if (platform_directory_create(root, 0700) != 0) return false;
    char path[512], text[512];
    static const char *const dirs[] = {"src", "include", "tests"};
    for (size_t i = 0; i < 3; i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[i]);
        if (platform_directory_create(path, 0700) != 0) return false;
    }
    (void)snprintf(path, sizeof(path), "%s/LICENSE", root);
    if (!zpd_write(path, "MIT\n")) return false;
    (void)snprintf(path, sizeof(path), "%s/include/x.h", root);
    if (!zpd_write(path, "int x(void);\n")) return false;
    (void)snprintf(text, sizeof(text), "int x(void) { return %d; }\n", value);
    (void)snprintf(path, sizeof(path), "%s/src/x.c", root);
    if (!zpd_write(path, text)) return false;
    (void)snprintf(path, sizeof(path), "%s/tests/test.c", root);
    if (!zpd_write(path, "int main(void) { return 0; }\n")) return false;
    (void)snprintf(text, sizeof(text),
        "{\"schema\":1,\"name\":\"fixture/%s\",\"semver\":\"0.1.0\","
        "\"language\":\"c23\",\"license\":\"MIT\",\"include_dir\":"
        "\"include\",\"source_dir\":\"src\",\"dependencies\":[]}\n",
        name);
    (void)snprintf(path, sizeof(path), "%s/zcode-package.json", root);
    return zpd_write(path, text);
}

struct zpd_benchmark_case {
    const char *kind;
    const char *goal;
    uint8_t project;
    bool refused;
};

static __attribute__((unused)) int zpd_test_twelve_task_benchmark(void)
{
    static const struct zpd_benchmark_case cases[] = {
        {"seeded_repair", "Repair seeded parser branch A", 0, false},
        {"seeded_repair", "Repair seeded parser branch B", 1, false},
        {"seeded_repair", "Repair seeded parser branch C", 2, false},
        {"seeded_repair", "Repair seeded return regression", 0, false},
        {"bounded_api", "Add bounded API behavior A", 1, false},
        {"bounded_api", "Add bounded API behavior B", 2, false},
        {"bounded_api", "Add bounded API behavior C", 0, false},
        {"malformed_ub", "Repair malformed input handling", 1, false},
        {"malformed_ub", "Repair portability boundary", 2, false},
        {"malformed_ub", "Repair undefined behavior guard", 0, false},
        {"impossible", "Modify LICENSE outside the write scope", 1, true},
        {"impossible", "Replace package identity outside scope", 2, true},
    };
    int failures = 0;
    TEST("zcode development benchmark: 12 frozen tasks across 3 projects") {
        int64_t benchmark_started = platform_time_monotonic_us();
        char roots[3][256];
        for (int p = 0; p < 3; p++) {
            (void)snprintf(roots[p], sizeof(roots[p]),
                           "test-tmp/zcode-benchmark-%ld-%d",
                           (long)getpid(), p);
            char name[32];
            (void)snprintf(name, sizeof(name), "benchmark-%d", p);
            ASSERT(zpd_benchmark_project(roots[p], name, p + 1));
        }
        uint8_t source_roots[3][32], source_after[32];
        for (int p = 0; p < 3; p++)
            ASSERT(vcs_tree_capture_path(roots[p], source_roots[p]) == VCS_OK);
        size_t compiling = 0, profile = 0, refused = 0, accepted = 0;
        uint64_t selected_bytes = 0, total_bytes = 0, context_us = 0;
        uint64_t model_context_bytes = 0;
        size_t story_projection_bytes = 0, story_full_bytes = 0;
        size_t story_source_status_bytes = 0;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            struct json_value input;
            json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "workspace",
                                    roots[cases[i].project]));
            ASSERT(json_push_kv_str(&input, "goal", cases[i].goal));
            ASSERT(json_push_kv_str(&input, "profile", "quick"));
            struct zcl_command_request request = {.input = &input};
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.zcode_benchmark_start.v1");
            zcl_native_handle_zcode_work_start(&request, &reply);
            if (reply.status != ZCL_COMMAND_STATUS_PASSED)
                printf("benchmark case %zu start: %s %s\n", i,
                       reply.error.code, reply.error.message);
            ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
            const struct json_value *context =
                json_get(&reply.data, "selected_context");
            ASSERT(context && context->type == JSON_OBJ);
            selected_bytes += (uint64_t)json_get_int(
                json_get(context, "selected_context_bytes"));
            total_bytes += (uint64_t)json_get_int(
                json_get(context, "total_source_bytes"));
            context_us += (uint64_t)json_get_int(
                json_get(context, "generation_us"));
            char work_id[32];
            (void)snprintf(work_id, sizeof(work_id), "%s",
                json_get_str(json_get(&reply.data, "work_id")));
            zcl_command_reply_free(&reply); json_free(&input);

            json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "workspace",
                                    roots[cases[i].project]));
            ASSERT(json_push_kv_str(&input, "work", work_id));
            ASSERT(json_push_kv_str(&input, "adapter", "manual"));
            request.input = &input;
            zcl_command_reply_init(&reply, "zcl.zcode_benchmark_run.v1");
            zcl_native_handle_zcode_work_run(&request, &reply);
            if (reply.status != ZCL_COMMAND_STATUS_PASSED)
                printf("benchmark case %zu handoff: %s %s\n", i,
                       reply.error.code, reply.error.message);
            ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
            model_context_bytes += (uint64_t)json_get_int(
                json_get(&reply.data, "model_context_bytes"));
            char candidate[4500];
            (void)snprintf(candidate, sizeof(candidate), "%s",
                json_get_str(json_get(&reply.data, "candidate_workspace")));
            zcl_command_reply_free(&reply); json_free(&input);
            char changed[4600], contents[128];
            if (cases[i].refused) {
                (void)snprintf(changed, sizeof(changed), "%s/LICENSE",
                               candidate);
                ASSERT(zpd_write(changed, "Proprietary\n"));
            } else {
                (void)snprintf(changed, sizeof(changed), "%s/src/x.c",
                               candidate);
                (void)snprintf(contents, sizeof(contents),
                               "int x(void) { return %zu; }\n", i + 10u);
                ASSERT(zpd_write(changed, contents));
            }
            json_init(&input); json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "workspace",
                                    roots[cases[i].project]));
            ASSERT(json_push_kv_str(&input, "work", work_id));
            ASSERT(json_push_kv_str(&input, "adapter", "manual"));
            request.input = &input;
            zcl_command_reply_init(&reply, "zcl.zcode_benchmark_admit.v1");
            zcl_native_handle_zcode_work_run(&request, &reply);
            if (cases[i].refused) {
                ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
                ASSERT(strcmp(reply.error.code, "PATCH_OUTSIDE_SCOPE") == 0);
                refused++;
            } else {
                ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                              "EVIDENCE_READY") == 0);
                ASSERT(json_get(&reply.data, "candidate_root") == NULL);
                ASSERT(json_get(&reply.data, "expert") == NULL);
                ASSERT(json_get_bool(json_get(
                    &reply.data, "details_available")));
                compiling++;
            }
            zcl_command_reply_free(&reply); json_free(&input);

            if (!cases[i].refused) {
                json_init(&input); json_set_object(&input);
                ASSERT(json_push_kv_str(&input, "workspace",
                                        roots[cases[i].project]));
                ASSERT(json_push_kv_str(&input, "work", work_id));
                request.input = &input;
                zcl_command_reply_init(&reply,
                                       "zcl.zcode_benchmark_accept.v1");
                zcl_native_handle_zcode_work_accept(&request, &reply);
                ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                              "PROVEN") == 0);
                profile++; accepted++;
                zcl_command_reply_free(&reply); json_free(&input);

                json_init(&input); json_set_object(&input);
                ASSERT(json_push_kv_str(&input, "workspace",
                                        roots[cases[i].project]));
                ASSERT(json_push_kv_str(&input, "work", work_id));
                if (i == 0)
                    ASSERT(json_push_kv_bool(&input, "details", true));
                request.input = &input;
                zcl_command_reply_init(&reply,
                                       "zcl.zcode_benchmark_status.v1");
                zcl_native_handle_zcode_work_status(&request, &reply);
                ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                ASSERT(strcmp(json_get_str(json_get(&reply.data, "goal")),
                              cases[i].goal) == 0);
                ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                              "PROVEN") == 0);
                ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                              "Accepted") == 0);
                ASSERT(json_get(&reply.data, "next_safe_command") != NULL);
                if (i == 0)
                    story_source_status_bytes = json_write(
                        &reply.data, NULL, 0);
                zcl_command_reply_free(&reply); json_free(&input);

                if (i == 0) {
                    json_init(&input); json_set_object(&input);
                    ASSERT(json_push_kv_str(&input, "workspace",
                                            roots[cases[i].project]));
                    ASSERT(json_push_kv_str(&input, "work", work_id));
                    request.input = &input; request.view = "normal";
                    zcl_command_reply_init(&reply, "zcl.story_show_test.v1");
                    zcl_native_handle_story_show(&request, &reply);
                    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                    ASSERT(strcmp(json_get_str(json_get(&reply.data, "status")),
                                  "UNKNOWN") == 0);
                    ASSERT(!json_get_bool(json_get(&reply.data, "complete")));
                    ASSERT(strcmp(json_get_str(json_get(
                                      &reply.data, "largest_missing_relation")),
                                  "app_runs") == 0);
                    ASSERT(json_size(json_get(&reply.data, "events")) == 7);
                    story_projection_bytes = json_write(
                        &reply.data, NULL, 0);
                    ASSERT(story_projection_bytes < ZCL_COMMAND_LIST_BUDGET);
                    zcl_command_reply_free(&reply); json_free(&input);

                    json_init(&input); json_set_object(&input);
                    ASSERT(json_push_kv_str(&input, "workspace",
                                            roots[cases[i].project]));
                    ASSERT(json_push_kv_str(&input, "work", work_id));
                    request.input = &input; request.view = "full";
                    zcl_command_reply_init(&reply,
                                           "zcl.story_show_full_test.v1");
                    zcl_native_handle_story_show(&request, &reply);
                    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                    story_full_bytes = json_write(&reply.data, NULL, 0);
                    ASSERT(story_full_bytes > story_projection_bytes);
                    zcl_command_reply_free(&reply); json_free(&input);

                    json_init(&input); json_set_object(&input);
                    ASSERT(json_push_kv_str(&input, "workspace",
                                            roots[cases[i].project]));
                    ASSERT(json_push_kv_str(&input, "work", work_id));
                    ASSERT(json_push_kv_str(&input, "event",
                                            "user_accepts"));
                    request.input = &input; request.view = "normal";
                    zcl_command_reply_init(&reply, "zcl.story_why_test.v1");
                    zcl_native_handle_story_why(&request, &reply);
                    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                    ASSERT(strcmp(json_get_str(json_get(&reply.data, "status")),
                                  "UNKNOWN") == 0);
                    ASSERT(json_size(json_get(&reply.data, "causal_chain")) ==
                           7);
                    zcl_command_reply_free(&reply); json_free(&input);

                    json_init(&input); json_set_object(&input);
                    ASSERT(json_push_kv_str(&input, "workspace",
                                            roots[cases[i].project]));
                    ASSERT(json_push_kv_str(&input, "before", work_id));
                    ASSERT(json_push_kv_str(&input, "after", work_id));
                    request.input = &input; request.view = "normal";
                    zcl_command_reply_init(&reply, "zcl.story_diff_test.v1");
                    zcl_native_handle_story_diff(&request, &reply);
                    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                    ASSERT(strcmp(json_get_str(json_get(&reply.data, "status")),
                                  "PROVED") == 0);
                    ASSERT(json_size(json_get(
                               &reply.data, "added_event_roots")) == 0);
                    ASSERT(json_size(json_get(
                               &reply.data, "removed_event_roots")) == 0);
                    ASSERT(json_size(json_get(
                               &reply.data, "changed_event_roots")) == 0);
                    zcl_command_reply_free(&reply); json_free(&input);
                }

                /* One lifecycle fact, one interpretation: with the work
                 * PROVEN, run is an idempotent observation of the accepted
                 * state — never a fresh candidate attempt. */
                json_init(&input); json_set_object(&input);
                ASSERT(json_push_kv_str(&input, "workspace",
                                        roots[cases[i].project]));
                ASSERT(json_push_kv_str(&input, "work", work_id));
                ASSERT(json_push_kv_str(&input, "adapter", "manual"));
                request.input = &input;
                zcl_command_reply_init(&reply,
                                       "zcl.zcode_benchmark_rerun.v1");
                zcl_native_handle_zcode_work_run(&request, &reply);
                ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
                ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                              "PROVEN") == 0);
                ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                              "Accepted") == 0);
                ASSERT(strcmp(json_get_str(
                                  json_get(&reply.data, "build_result")),
                              "passed") == 0);
                ASSERT(json_get(&reply.data, "candidate_workspace") == NULL);
                zcl_command_reply_free(&reply); json_free(&input);
            }
            char *attempt = strrchr(candidate, '/');
            ASSERT(attempt != NULL); *attempt = '\0';
            ASSERT(zcl_tree_remove(candidate).ok);
        }
        ASSERT(compiling == 10);
        ASSERT(profile == 10);
        ASSERT(accepted == 10);
        ASSERT(refused == 2);
        ASSERT(selected_bytes > 0 && selected_bytes < total_bytes);
        ASSERT(model_context_bytes > selected_bytes);
        ASSERT(context_us > 0);
        ASSERT(story_projection_bytes > 0 && story_full_bytes > 0 &&
               story_source_status_bytes > 0);
        int64_t benchmark_elapsed =
            platform_time_monotonic_us() - benchmark_started;
        ASSERT(benchmark_elapsed > 0);
        printf("benchmark: tasks=12 projects=3 compiling=%zu profile=%zu "
               "accepted=%zu refused=%zu context=%llu/%llu bytes "
               "model_context_bytes=%llu context_us=%llu "
               "story_bytes=%zu story_full_bytes=%zu "
               "story_context_saved_pct=%zu "
               "story_source_status_bytes=%zu "
               "elapsed_us=%llu\n",
               compiling, profile, accepted, refused,
               (unsigned long long)selected_bytes,
               (unsigned long long)total_bytes,
               (unsigned long long)model_context_bytes,
               (unsigned long long)context_us,
               story_projection_bytes, story_full_bytes,
               (story_full_bytes - story_projection_bytes) * 100u /
                   story_full_bytes,
               story_source_status_bytes,
               (unsigned long long)benchmark_elapsed);
        for (int p = 0; p < 3; p++) {
            ASSERT(vcs_tree_capture_path(roots[p], source_after) == VCS_OK);
            ASSERT(memcmp(source_roots[p], source_after,
                          sizeof(source_after)) == 0);
            ASSERT(zcl_tree_remove(roots[p]).ok);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_base(secp256k1_context *ctx, const uint8_t secret[32],
                         const uint8_t pubkey[33])
{
    int failures = 0;
    TEST("zcode package dev prepare: base tree derives all canonical roots") {
        struct vcs_package_prepare_options options = {
            .dir = "lib/base", .publisher_sequence = 1,
            .reward_address = "", .chain_id = "zclassic-main",
        };
        memcpy(options.publisher_pubkey, pubkey, 33);
        struct vcs_package_prepared prepared;
        char detail[256];
        ASSERT(vcs_package_prepare(&options, &prepared, detail,
                                   sizeof(detail)) == VCS_PACKAGE_PREPARE_OK);
        ASSERT(prepared.manifest.count > 10);
        ASSERT(prepared.recipe.sources.count > 0);
        ASSERT(prepared.capsule.count > 0);
        ASSERT(prepared.lock.count == 1 &&
               prepared.lock.nodes[0].depth == 0 &&
               prepared.lock.nodes[0].direct_deps == 0);
        ASSERT(prepared.release_body_len > 64);
        char root_hex[65];
        zcl_hex_encode(prepared.package_root, 32, root_hex);
        printf("base package root: %s\n", root_hex);

        char pubkey_hex[67];
        zcl_hex_encode(pubkey, 33, pubkey_hex);
        struct json_value prepare_input;
        json_init(&prepare_input); json_set_object(&prepare_input);
        ASSERT(json_push_kv_str(&prepare_input, "dir", "lib/base"));
        ASSERT(json_push_kv_str(&prepare_input, "publisher_pubkey",
                                pubkey_hex));
        ASSERT(json_push_kv_int(&prepare_input, "publisher_sequence", 1));
        struct zcl_command_request prepare_request = {
            .input = &prepare_input,
        };
        struct zcl_command_reply prepare_reply;
        zcl_command_reply_init(&prepare_reply,
                               "zcl.zcode_package_dev_test.v1");
        zcl_native_handle_zcode_package_dev_prepare(&prepare_request,
                                                    &prepare_reply);
        ASSERT(prepare_reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *prepared_root =
            json_get(&prepare_reply.data, "package_root");
        ASSERT(prepared_root &&
               strcmp(json_get_str(prepared_root), root_hex) == 0);
        zcl_command_reply_free(&prepare_reply);
        json_free(&prepare_input);

        struct vcs_package_capsule parsed;
        ASSERT(vcs_package_capsule_parse(prepared.capsule_wire,
                                         prepared.capsule_wire_len,
                                         &parsed) == VCS_PACKAGE_CAPSULE_OK);
        uint8_t parsed_root[32];
        ASSERT(vcs_package_capsule_root(&parsed, parsed_root) ==
               VCS_PACKAGE_CAPSULE_OK);
        ASSERT(memcmp(parsed_root, prepared.capsule_root, 32) == 0);
        for (size_t n = 0; n < prepared.capsule_wire_len; n++)
            ASSERT(vcs_package_capsule_parse(prepared.capsule_wire, n,
                                             &parsed) !=
                   VCS_PACKAGE_CAPSULE_OK);
        uint8_t *trailing = malloc(prepared.capsule_wire_len + 1u); // raw-alloc-ok:test-fixture
        ASSERT(trailing != NULL);
        memcpy(trailing, prepared.capsule_wire, prepared.capsule_wire_len);
        trailing[prepared.capsule_wire_len] = 0;
        ASSERT(vcs_package_capsule_parse(trailing,
                                         prepared.capsule_wire_len + 1u,
                                         &parsed) ==
               VCS_PACKAGE_CAPSULE_ERR_TRAILING);
        free(trailing);

        uint8_t signature[64];
        ASSERT(zpd_signature(ctx, secret, prepared.signing_digest, signature));
        char *body_hex = malloc(prepared.release_body_len * 2u + 1u); // raw-alloc-ok:test-fixture
        char signature_hex[129];
        ASSERT(body_hex != NULL);
        zcl_hex_encode(prepared.release_body, prepared.release_body_len,
                       body_hex);
        zcl_hex_encode(signature, sizeof(signature), signature_hex);
        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "release_body_hex", body_hex));
        ASSERT(json_push_kv_str(&input, "signature_hex", signature_hex));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_package_dev_test.v1");
        zcl_native_handle_zcode_package_dev_seal(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *status = json_get(&reply.data,
                                                    "signature_status");
        ASSERT(status && strcmp(json_get_str(status), "verified") == 0);
        zcl_command_reply_free(&reply); json_free(&input); free(body_hex);

        struct vcs_package_prepare_options sha_options = {
            .dir = "lib/sha3", .publisher_sequence = 2,
            .reward_address = "", .chain_id = "zclassic-main",
        };
        memcpy(sha_options.publisher_pubkey, pubkey, 33);
        struct vcs_package_prepared sha_prepared;
        ASSERT(vcs_package_prepare(&sha_options, &sha_prepared, detail,
                                   sizeof(detail)) == VCS_PACKAGE_PREPARE_OK);
        ASSERT(sha_prepared.lock.count == 2);
        ASSERT(sha_prepared.lock.nodes[0].depth == 1 &&
               sha_prepared.lock.nodes[0].direct_deps == 0 &&
               memcmp(sha_prepared.lock.nodes[0].root,
                      prepared.package_root, 32) == 0);
        ASSERT(sha_prepared.lock.nodes[1].depth == 0 &&
               sha_prepared.lock.nodes[1].direct_deps == 1);
        zcl_hex_encode(sha_prepared.package_root, 32, root_hex);
        printf("sha3 package root: %s\n", root_hex);
        vcs_package_prepared_free(&sha_prepared);
        vcs_package_prepared_free(&prepared);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_control_stores(const uint8_t pubkey[33])
{
    int failures = 0;
    TEST("zcode package dev prepare: local control stores do not alter package roots") {
        char root[256], path[320];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-package-control-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        struct vcs_package_prepare_options options = {
            .dir = root, .publisher_sequence = 1,
            .reward_address = "", .chain_id = "zclassic-main",
        };
        memcpy(options.publisher_pubkey, pubkey, 33);
        struct vcs_package_prepared before, after;
        char detail[256];
        ASSERT(vcs_package_prepare(&options, &before, detail,
                                   sizeof(detail)) == VCS_PACKAGE_PREPARE_OK);
        (void)snprintf(path, sizeof(path), "%s/.zvcs", root);
        ASSERT(platform_directory_create(path, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/.zvcs/control", root);
        ASSERT(zpd_write(path, "local vcs state\n"));
        (void)snprintf(path, sizeof(path), "%s/.codeindex", root);
        ASSERT(platform_directory_create(path, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/.codeindex/control", root);
        ASSERT(zpd_write(path, "derived index state\n"));
        ASSERT(zpd_plant_build_output(root));
        ASSERT(vcs_package_prepare(&options, &after, detail,
                                   sizeof(detail)) == VCS_PACKAGE_PREPARE_OK);
        ASSERT(memcmp(before.package_root, after.package_root, 32) == 0);
        vcs_package_prepared_free(&after);
        vcs_package_prepared_free(&before);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

/* A release prepared without an explicit chain_id must name the chain this
 * node is on. The default was the literal "zclassic-main", so on a testnet or
 * regtest node `zcode package dev prepare` produced a release that
 * vcs_package_accept — the very next thing to touch it — could only refuse as
 * wrong-chain-id, on the publishing node as much as on any peer that fetched
 * the carrier. It cost the two-node commons journey a whole fetch-and-import
 * round to find, and it was invisible to every existing test because they all
 * pass chain_id explicitly. This one does not, and it asserts under regtest,
 * where the literal and the truth differ. It goes through the leaf on
 * purpose: vcs_package_prepare is deliberately free of chainparams (several
 * standalone tools link it without them), so the leaf owns the default. */
static int zpd_test_default_chain_id(const uint8_t pubkey[33])
{
    int failures = 0;
    TEST("zcode package dev prepare: an unstated chain_id is the active chain") {
        char root[256], pubkey_hex[67];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-package-chain-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        zcl_hex_encode(pubkey, 33, pubkey_hex);
        chain_params_select(CHAIN_REGTEST);
        char want[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
        ASSERT(vcs_package_accept_chain_id(want, sizeof(want)));
        ASSERT(strcmp(want, "zclassic-main") != 0);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "dir", root));
        ASSERT(json_push_kv_str(&input, "publisher_pubkey", pubkey_hex));
        ASSERT(json_push_kv_int(&input, "publisher_sequence", 1));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_package_dev_test.v1");
        zcl_native_handle_zcode_package_dev_prepare(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *got = json_get(&reply.data, "chain_id");
        ASSERT(got && strcmp(json_get_str(got), want) == 0);
        zcl_command_reply_free(&reply);

        /* An explicit chain_id still wins: preparing a release for another
         * chain stays possible on purpose. */
        ASSERT(json_push_kv_str(&input, "chain_id", "zclassic-main"));
        zcl_command_reply_init(&reply, "zcl.zcode_package_dev_test.v1");
        zcl_native_handle_zcode_package_dev_prepare(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        got = json_get(&reply.data, "chain_id");
        ASSERT(got && strcmp(json_get_str(got), "zclassic-main") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);

        chain_params_select(CHAIN_MAIN);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_exact_file_selection(const uint8_t pubkey[33])
{
    int failures = 0;
    TEST("zcode package dev prepare: exact file selection is closed and root-bound") {
        char root[256], path[320];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-package-files-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        (void)snprintf(path, sizeof(path), "%s/src/unused.c", root);
        ASSERT(zpd_write(path, "int unused(void) { return 1; }\n"));
        (void)snprintf(path, sizeof(path), "%s/zcode-package.json", root);
        ASSERT(zpd_write(path,
            "{\"schema\":1,\"name\":\"zclassic23/fixture\","
            "\"semver\":\"0.1.0-dev.1\",\"language\":\"c23\","
            "\"license\":\"MIT\",\"include_dir\":\"include\","
            "\"source_dir\":\"src\",\"dependencies\":[],"
            "\"files\":[\"LICENSE\",\"include/x.h\",\"src/x.c\","
            "\"tests/test.c\",\"zcode-package.json\"]}\n"));
        struct vcs_package_prepare_options options = {
            .dir = root, .publisher_sequence = 1,
            .reward_address = "", .chain_id = "zclassic-main",
        };
        memcpy(options.publisher_pubkey, pubkey, 33);
        struct vcs_package_prepared before, after;
        char detail[256];
        ASSERT(vcs_package_prepare(&options, &before, detail,
                                   sizeof(detail)) == VCS_PACKAGE_PREPARE_OK);
        ASSERT(before.manifest.count == 5);
        ASSERT(before.recipe.public_headers.count == 1);
        ASSERT(before.recipe.sources.count == 1);
        ASSERT(before.recipe.test_sources.count == 1);
        (void)snprintf(path, sizeof(path), "%s/src/unused.c", root);
        ASSERT(zpd_write(path, "int unused(void) { return 2; }\n"));
        ASSERT(vcs_package_prepare(&options, &after, detail,
                                   sizeof(detail)) == VCS_PACKAGE_PREPARE_OK);
        ASSERT(memcmp(before.package_root, after.package_root, 32) == 0);
        ASSERT(memcmp(before.recipe_root, after.recipe_root, 32) == 0);
        vcs_package_prepared_free(&after);
        vcs_package_prepared_free(&before);

        (void)snprintf(path, sizeof(path), "%s/zcode-package.json", root);
        ASSERT(zpd_write(path,
            "{\"schema\":1,\"name\":\"zclassic23/fixture\","
            "\"semver\":\"0.1.0-dev.1\",\"language\":\"c23\","
            "\"license\":\"MIT\",\"include_dir\":\"include\","
            "\"source_dir\":\"src\",\"dependencies\":[],"
            "\"files\":[\"src/missing.c\",\"zcode-package.json\"]}\n"));
        ASSERT(vcs_package_prepare(&options, &after, detail,
                                   sizeof(detail)) ==
               VCS_PACKAGE_PREPARE_ERR_META);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_fail_closed(const uint8_t pubkey[33])
{
    int failures = 0;
    TEST("zcode package dev prepare: symlink, special and unknown fields fail closed") {
        char root[256], path[320];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-package-dev-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        struct vcs_package_prepare_options options = {
            .dir = root, .publisher_sequence = 1,
            .reward_address = "", .chain_id = "zclassic-main",
        };
        memcpy(options.publisher_pubkey, pubkey, 33);
        struct vcs_package_prepared prepared;
        char detail[256];
#if defined(_WIN32)
        /* CreateSymbolicLinkA fails with ERROR_PRIVILEGE_NOT_HELD without
         * Developer Mode / SeCreateSymbolicLinkPrivilege, and mkfifo does
         * not exist: the non-regular-file refusal fixtures cannot be built
         * here. The portable ERR_META case below still runs. */
        (void)path;
        printf("zcode_package_dev: SKIP (Windows): symlink/FIFO file-type "
               "refusal fixtures (symlink privilege unavailable; no mkfifo)\n");
#else
        (void)snprintf(path, sizeof(path), "%s/link", root);
        ASSERT(zpd_symlink_create("src/x.c", path, false));
        (void)snprintf(path, sizeof(path), "%s/.zvcs", root);
        ASSERT(zpd_symlink_create("src", path, true));
        ASSERT(vcs_package_prepare(&options, &prepared, detail,
                                   sizeof(detail)) ==
               VCS_PACKAGE_PREPARE_ERR_FILE_TYPE);
        ASSERT(zpd_symlink_remove(path, true));
        (void)snprintf(path, sizeof(path), "%s/build", root);
        ASSERT(zpd_symlink_create("src", path, true));
        ASSERT(vcs_package_prepare(&options, &prepared, detail,
                                   sizeof(detail)) ==
               VCS_PACKAGE_PREPARE_ERR_FILE_TYPE);
        ASSERT(zpd_symlink_remove(path, true));
        (void)snprintf(path, sizeof(path), "%s/link", root);
        ASSERT(vcs_package_prepare(&options, &prepared, detail,
                                   sizeof(detail)) ==
               VCS_PACKAGE_PREPARE_ERR_FILE_TYPE);
        ASSERT(zpd_symlink_remove(path, false));
        (void)snprintf(path, sizeof(path), "%s/special", root);
        ASSERT(zpd_special_create(path));
        ASSERT(vcs_package_prepare(&options, &prepared, detail,
                                   sizeof(detail)) ==
               VCS_PACKAGE_PREPARE_ERR_FILE_TYPE);
        ASSERT(zpd_special_remove(path));
#endif
        zpd_fixture_cleanup(root);
        ASSERT(zpd_fixture(root, true));
        ASSERT(vcs_package_prepare(&options, &prepared, detail,
                                   sizeof(detail)) ==
               VCS_PACKAGE_PREPARE_ERR_META);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_project_inspect(void)
{
    int failures = 0;
    TEST("zcode project inspect: human summary is read-only and root-free by default") {
        char root[256], hidden[320];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-project-inspect-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        (void)snprintf(hidden, sizeof(hidden), "%s/.zvcs", root);
        ASSERT(access(hidden, F_OK) != 0);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_project_inspect_test.v1");
        zcl_native_handle_zcode_project_inspect(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(access(hidden, F_OK) != 0);

        const struct json_value *name = json_get(&reply.data, "name");
        const struct json_value *layout = json_get(&reply.data, "layout");
        const struct json_value *headers = layout
            ? json_get(layout, "public_headers") : NULL;
        const struct json_value *sources = layout
            ? json_get(layout, "sources") : NULL;
        const struct json_value *tests = layout
            ? json_get(layout, "tests") : NULL;
        const struct json_value *profile =
            json_get(&reply.data, "suggested_profile");
        const struct json_value *profile_detail =
            json_get(&reply.data, "proof_profile");
        const struct json_value *exact_policy = profile_detail
            ? json_get(profile_detail, "exact_policy") : NULL;
        const struct json_value *expert = json_get(&reply.data, "expert");
        ASSERT(name && strcmp(json_get_str(name), "zclassic23/fixture") == 0);
        ASSERT(layout && layout->type == JSON_OBJ);
        ASSERT(headers && headers->type == JSON_ARR &&
               headers->num_children == 1);
        ASSERT(sources && sources->type == JSON_ARR &&
               sources->num_children == 1);
        ASSERT(tests && tests->type == JSON_ARR && tests->num_children == 1);
        ASSERT(profile && strcmp(json_get_str(profile), "standard") == 0);
        ASSERT(profile_detail && profile_detail->type == JSON_OBJ);
        ASSERT(json_get(profile_detail, "warning_fatal") &&
               json_get_bool(json_get(profile_detail, "warning_fatal")));
        ASSERT(json_get(profile_detail, "sanitizers") &&
               json_get_bool(json_get(profile_detail, "sanitizers")));
        ASSERT(exact_policy && exact_policy->type == JSON_OBJ);
        ASSERT(json_get(exact_policy, "root") != NULL);
        ASSERT(json_get_int(json_get(exact_policy,
                                     "minimum_compile_receipts")) == 2);
        ASSERT(json_get(&reply.data, "recipe_hex") == NULL);
        ASSERT(json_get(&reply.data, "dependency_lock_hex") == NULL);
        ASSERT(expert && expert->type == JSON_OBJ);
        ASSERT(json_get(expert, "package_root") != NULL);
        ASSERT(json_get(&reply.data, "read_only") &&
               json_get_bool(json_get(&reply.data, "read_only")));
        zcl_command_reply_free(&reply);
        json_free(&input);
        zpd_fixture_cleanup(root);

        char absent[256];
        (void)snprintf(absent, sizeof(absent),
                       "test-tmp/zcode-project-absent-%ld", (long)getpid());
        ASSERT(access(absent, F_OK) != 0);
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", absent));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_project_inspect_test.v1");
        zcl_native_handle_zcode_project_inspect(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(access(absent, F_OK) != 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_project_init(void)
{
    int failures = 0;
    TEST("zcode project init: plan is read-only and commit is exact and exclusive") {
        char root[256], meta[320], added[320];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-project-init-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        (void)snprintf(meta, sizeof(meta), "%s/zcode-package.json", root);
        ASSERT(unlink(meta) == 0);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_project_inspect_test.v1");
        zcl_native_handle_zcode_project_inspect(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&reply.data, "existing_package_config") &&
               !json_get_bool(json_get(&reply.data,
                                       "existing_package_config")));
        ASSERT(access(meta, F_OK) != 0);
        zcl_command_reply_free(&reply);

        zcl_command_reply_init(&reply, "zcl.zcode_project_init_plan_test.v1");
        zcl_native_handle_zcode_project_init_plan(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const char *plan_id = json_get_str(json_get(&reply.data, "plan_id"));
        const char *config =
            json_get_str(json_get(&reply.data, "configuration_text"));
        ASSERT(plan_id && strlen(plan_id) == 64);
        ASSERT(config && strstr(config, "\"name\": \"local/zcode-project-init-") != NULL);
        ASSERT(access(meta, F_OK) != 0);
        char saved_plan[65];
        (void)snprintf(saved_plan, sizeof(saved_plan), "%s", plan_id);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "name", "example/parser"));
        ASSERT(json_push_kv_str(&input, "semver", "1.2.3"));
        ASSERT(json_push_kv_str(&input, "license", "MIT"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_project_init_plan_test.v1");
        zcl_native_handle_zcode_project_init_plan(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "name")),
                      "example/parser") == 0);
        plan_id = json_get_str(json_get(&reply.data, "plan_id"));
        ASSERT(plan_id && strlen(plan_id) == 64);
        (void)snprintf(saved_plan, sizeof(saved_plan), "%s", plan_id);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "name", "example/parser"));
        ASSERT(json_push_kv_str(&input, "semver", "1.2.3"));
        ASSERT(json_push_kv_str(&input, "license", "MIT"));
        ASSERT(json_push_kv_str(&input, "plan_id", saved_plan));
        ASSERT(json_push_kv_bool(&input, "confirm", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_project_init_commit_test.v1");
        zcl_native_handle_zcode_project_init_commit(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(access(meta, F_OK) == 0);
        ASSERT(json_get(&reply.data, "created") &&
               json_get_bool(json_get(&reply.data, "created")));
        zcl_command_reply_free(&reply);

        zcl_command_reply_init(&reply, "zcl.zcode_project_status_test.v1");
        zcl_native_handle_zcode_project_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")), "READY") == 0);
        zcl_command_reply_free(&reply);

        zcl_command_reply_init(&reply, "zcl.zcode_project_init_commit_test.v1");
        zcl_native_handle_zcode_project_init_commit(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&reply);
        json_free(&input);

        ASSERT(unlink(meta) == 0);
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_project_init_plan_test.v1");
        zcl_native_handle_zcode_project_init_plan(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        plan_id = json_get_str(json_get(&reply.data, "plan_id"));
        ASSERT(plan_id && strlen(plan_id) == 64);
        (void)snprintf(saved_plan, sizeof(saved_plan), "%s", plan_id);
        zcl_command_reply_free(&reply);
        json_free(&input);

        (void)snprintf(added, sizeof(added), "%s/src/added.c", root);
        ASSERT(zpd_write(added, "int added(void) { return 0; }\n"));
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "plan_id", saved_plan));
        ASSERT(json_push_kv_bool(&input, "confirm", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_project_init_commit_test.v1");
        zcl_native_handle_zcode_project_init_commit(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(access(meta, F_OK) != 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        ASSERT(unlink(added) == 0);

#if defined(_WIN32)
        /* Same constraint as the prepare fail-closed fixtures: no symlink
         * privilege here, so the "symlink in workspace fails init plan"
         * probe cannot be built. */
        printf("zcode_package_dev: SKIP (Windows): init-plan symlink "
               "refusal fixture (symlink privilege unavailable)\n");
#else
        char link[320];
        (void)snprintf(link, sizeof(link), "%s/link", root);
        ASSERT(zpd_symlink_create("LICENSE", link, false));
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_project_init_plan_test.v1");
        zcl_native_handle_zcode_project_init_plan(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(access(meta, F_OK) != 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
#endif
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static void zpd_reuse_entry(struct vcs_package_index_entry *entry,
                            const char *name, const char *semver, char root)
{
    memset(entry, 0, sizeof(*entry));
    (void)snprintf(entry->name, sizeof(entry->name), "%s", name);
    (void)snprintf(entry->semver, sizeof(entry->semver), "%s", semver);
    memset(entry->package_root_hex, root, 64);
    entry->package_root_hex[64] = '\0';
}

static int zpd_test_reuse_plan(void)
{
    int failures = 0;
    TEST("zcode reuse plan: exact, partial, absent, incompatible and conflict") {
        struct vcs_package_index_entry entries[3];
        zpd_reuse_entry(&entries[0], "zclassic23/json", "1.0.0", 'a');
        zpd_reuse_entry(&entries[1], "zclassic23/codec", "1.0.0", 'b');
        zpd_reuse_entry(&entries[2], "other/json", "1.0.0", 'c');
        static const char *json_apis[] = {
            "include/json/json.h", "json_read", "json_write",
        };
        static const char *codec_apis[] = {
            "include/codec/cursor.h", "zcl_cursor_read_u32",
        };
        struct vcs_package_reuse_input inputs[3] = {
            {.package = &entries[0],
             .apis = {json_apis[0], json_apis[1], json_apis[2]},
             .api_count = 3, .locked = true, .installed = true,
             .compatible = true},
            {.package = &entries[1],
             .apis = {codec_apis[0], codec_apis[1]}, .api_count = 2,
             .installed = true, .compatible = true},
            {.package = &entries[2], .apis = {json_apis[0]}, .api_count = 1,
             .compatible = true},
        };
        struct vcs_package_reuse_plan plan;
        ASSERT(vcs_package_reuse_plan_build(
            "use zclassic23/json@1.0.0", inputs, 2, &plan));
        ASSERT(plan.disposition == VCS_PACKAGE_REUSE_COMPLETE);
        ASSERT(!plan.new_code_required);
        ASSERT(plan.selected_count == 1);
        ASSERT(plan.selected[0].input_index == 0);

        ASSERT(vcs_package_reuse_plan_build(
            "Parse JSON with bounded cursor reads", inputs, 2, &plan));
        ASSERT(plan.disposition == VCS_PACKAGE_REUSE_PARTIAL);
        ASSERT(plan.new_code_required);
        ASSERT(plan.selected_count == 2);
        ASSERT(plan.selected[0].input_index == 0);

        ASSERT(vcs_package_reuse_plan_build(
            "Make harness compose zclassic23/json", inputs, 2, &plan));
        ASSERT(plan.disposition == VCS_PACKAGE_REUSE_PARTIAL);
        ASSERT(plan.selected_count == 1);
        ASSERT(plan.selected[0].input_index == 0);

        ASSERT(vcs_package_reuse_plan_build(
            "Render a deterministic flight replay", inputs, 2, &plan));
        ASSERT(plan.disposition == VCS_PACKAGE_REUSE_NONE);
        ASSERT(plan.selected_count == 0);

        ASSERT(vcs_package_reuse_plan_build(
            "use zclassic23/json@2.0.0", inputs, 2, &plan));
        ASSERT(plan.disposition == VCS_PACKAGE_REUSE_INCOMPATIBLE);
        ASSERT(plan.incompatible_matches == 1);

        ASSERT(vcs_package_reuse_plan_build("use json", inputs, 3, &plan));
        ASSERT(plan.disposition == VCS_PACKAGE_REUSE_AMBIGUOUS);
        ASSERT(plan.new_code_required);
        ASSERT(plan.selected_count == 2);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_work_start_package_bounds(void)
{
    int failures = 0;
    TEST("zcode work start: missing package config names init; local build output is ignored") {
        char root[256];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-work-init-%ld", (long)getpid());
        zpd_fixture_cleanup(root);
        ASSERT(platform_directory_create(root, 0700) == 0);
        char path[320];
        (void)snprintf(path, sizeof(path), "%s/src", root);
        ASSERT(platform_directory_create(path, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/src/x.c", root);
        ASSERT(zpd_write(path, "int x(void) { return 1; }\n"));
        ASSERT(zpd_plant_build_output(root));
        char absolute_root[4400];
        ASSERT(platform_directory_canonical_real(
            root, absolute_root, sizeof(absolute_root)));

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "goal", "Fix x"));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_work_start_init_test.v1");
        zcl_native_handle_zcode_work_start(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "work_id")), "") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "goal")),
                      "Fix x") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "INITIALIZATION_REQUIRED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Initialize C23 package") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "next_safe_command")),
                      "zcode project init plan") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "authoritative_workspace")),
                      "unchanged") == 0);
        ASSERT(json_get(&reply.data, "details_available") &&
               !json_get_bool(json_get(&reply.data, "details_available")));
        ASSERT(zpd_next_init_plan_is(&reply, absolute_root));
        zcl_command_reply_free(&reply);
        json_free(&input);
        zpd_fixture_cleanup(root);

        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-work-build-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        ASSERT(zpd_plant_build_output(root));
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "goal", "Fix x"));
        ASSERT(json_push_kv_str(&input, "profile", "quick"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_start_build_test.v1");
        zcl_native_handle_zcode_work_start(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "AWAITING_CANDIDATE") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "next_safe_command")),
                      "zcode work run") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static __attribute__((unused)) int zpd_test_work_start(void)
{
    int failures = 0;
    TEST("zcode work start: goal and profile compose existing task owners") {
        char root[256];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-work-start-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        char absolute_root[4400];
        ASSERT(platform_directory_canonical_real(
            root, absolute_root, sizeof(absolute_root)));
        uint8_t source_before[32], source_after[32];
        ASSERT(vcs_tree_capture_path(root, source_before) == VCS_OK);

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "goal", "Fix x"));
        ASSERT(json_push_kv_str(&input, "profile", "quick"));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_work_start_test.v1");
        zcl_native_handle_zcode_work_start(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(vcs_tree_capture_path(root, source_after) == VCS_OK);
        ASSERT(memcmp(source_before, source_after, sizeof(source_before)) == 0);
        const struct json_value *work_id = json_get(&reply.data, "work_id");
        const struct json_value *state = json_get(&reply.data, "state");
        const struct json_value *context =
            json_get(&reply.data, "selected_context");
        const struct json_value *reuse =
            json_get(&reply.data, "reuse_plan");
        const struct json_value *expert = json_get(&reply.data, "expert");
        ASSERT(work_id && strncmp(json_get_str(work_id), "work-", 5) == 0);
        char saved_work_id[32];
        (void)snprintf(saved_work_id, sizeof(saved_work_id), "%s",
                       json_get_str(work_id));
        ASSERT(state && strcmp(json_get_str(state),
                               "AWAITING_CANDIDATE") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Creating missing code") == 0);
        ASSERT(context && context->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(context, "symbol")), "x") == 0);
        ASSERT(json_get(context, "symbol_id") == NULL);
        ASSERT(reuse && reuse->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(reuse, "search_status")),
                      "datadir_not_provided") == 0);
        ASSERT(json_get_bool(json_get(reuse, "new_code_required")));
        ASSERT(expert == NULL);
        ASSERT(json_get_bool(json_get(&reply.data, "details_available")));
        ASSERT(reply.next_count == 1);
        ASSERT(strcmp(reply.next[0].command, "zcode.work.run") == 0);
        struct json_value next_input;
        json_init(&next_input);
        ASSERT(json_read(&next_input, reply.next[0].input_json,
                         strlen(reply.next[0].input_json)));
        ASSERT(strcmp(json_get_str(json_get(&next_input, "workspace")),
                      absolute_root) == 0);
        ASSERT(strcmp(json_get_str(json_get(&next_input, "work")),
                      saved_work_id) == 0);
        ASSERT(json_get(&next_input, "task_root") == NULL);
        ASSERT(json_get(&next_input, "package_root") == NULL);
        const struct zcl_command_spec *next_spec =
            zcl_command_registry_find(zcl_command_catalog(),
                                      reply.next[0].command, NULL);
        char next_why[160] = {0};
        ASSERT(next_spec && zcl_command_registry_input_validate(
            next_spec, &next_input, next_why, sizeof(next_why)));
        json_free(&next_input);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "goal", "Fix x"));
        ASSERT(json_push_kv_str(&input, "profile", "quick"));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_start_test.v1");
        zcl_native_handle_zcode_work_start(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        expert = json_get(&reply.data, "expert");
        context = json_get(&reply.data, "selected_context");
        const char *detailed_work_id = json_get_str(json_get(
            &reply.data, "work_id"));
        const char *detailed_task_root = expert
            ? json_get_str(json_get(expert, "task_root")) : NULL;
        ASSERT(detailed_work_id && detailed_task_root &&
               strncmp(detailed_work_id + 5, detailed_task_root, 12) == 0);
        ASSERT(context && json_get(context, "symbol_id") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "goal")),
                      "Fix x") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "AWAITING_CANDIDATE") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Creating missing code") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "build_result")),
                      "not_started") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "sanitizer_result")),
                      "not_required") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "reproduction_grade")),
                      "none") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "next_safe_command")),
                      "zcode work run") == 0);
        ASSERT(!json_get_bool(json_get(&reply.data, "confirmation_ready")));
        ASSERT(json_get(&reply.data, "confirmation_identity") == NULL);
        ASSERT(json_get(&reply.data, "proof") == NULL);
        ASSERT(json_get(&reply.data, "expert") == NULL);
        ASSERT(json_get_bool(json_get(&reply.data, "details_available")));
        ASSERT(zpd_next_is(&reply, "zcode.work.run", absolute_root,
                           saved_work_id, NULL));
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        if (reply.status != ZCL_COMMAND_STATUS_PASSED)
            printf("work admission failed: %s: %s\n", reply.error.code,
                   reply.error.message);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const struct json_value *candidate_workspace =
            json_get(&reply.data, "candidate_workspace");
        const struct json_value *packet_path =
            json_get(&reply.data, "adapter_packet_path");
        ASSERT(candidate_workspace &&
               json_get_str(candidate_workspace)[0] == '/');
        char saved_candidate_workspace[4400];
        (void)snprintf(saved_candidate_workspace,
                       sizeof(saved_candidate_workspace), "%s",
                       json_get_str(candidate_workspace));
        ASSERT(packet_path && json_get_str(packet_path)[0] == '/');
        ASSERT(strncmp(json_get_str(packet_path),
                       saved_candidate_workspace,
                       strlen(saved_candidate_workspace)) == 0);
        ASSERT(access(json_get_str(packet_path), F_OK) == 0);
        ASSERT(json_get_int(json_get(
                   &reply.data, "model_context_bytes")) > 0);
        ASSERT(json_get(&reply.data, "adapter_packet_bytes") == NULL);
        ASSERT(json_get(&reply.data, "workspace_created") == NULL);
        ASSERT(json_get(&reply.data, "next_safe_command") == NULL);
        char *packet_text = zpd_read_bounded(json_get_str(packet_path),
                                             2u * 1024u * 1024u);
        ASSERT(packet_text != NULL);
        ASSERT(strstr(packet_text, "\"Write C23 only.") != NULL);
        ASSERT(strstr(packet_text,
                      "\"selected_dependency_context\"") != NULL);
        ASSERT(strstr(packet_text, "\"selected_excerpts\"") != NULL);
        ASSERT(strstr(packet_text, "\"allowed_write_scopes\"") != NULL);
        ASSERT(strstr(packet_text, "\"dependency_lock_root\"") != NULL);
        ASSERT(strstr(packet_text, "\"max_changed_files\"") != NULL);
        ASSERT(strstr(packet_text, "\"max_patch_bytes\"") != NULL);
        ASSERT(strstr(packet_text, "\"candidate_workspace\"") == NULL);
        ASSERT(strstr(packet_text, "\"dependency_context_bytes\"") == NULL);
        ASSERT(strstr(packet_text,
                      "\"dependency_context_headers\"") == NULL);
        ASSERT(strstr(packet_text, "\"max_context_bytes\"") == NULL);
        ASSERT(strstr(packet_text, "\"max_cpu_seconds\"") == NULL);
        ASSERT(strstr(packet_text, "\"max_memory_bytes\"") == NULL);
        ASSERT(strstr(packet_text, "\"max_output_bytes\"") == NULL);
        ASSERT(strstr(packet_text, "\"task_root\"") == NULL);
        ASSERT(strstr(packet_text, "\"source_root\"") == NULL);
        ASSERT(strstr(packet_text, "\"context_root\"") == NULL);
        ASSERT(strstr(packet_text, "\"write_scope_root\"") == NULL);
        ASSERT(strstr(packet_text, "\"package_recipe_root\"") == NULL);
        ASSERT(strstr(packet_text, "\"proof_policy_root\"") == NULL);
        ASSERT(strstr(packet_text, "\"toolchain_capsule_root\"") == NULL);
        free(packet_text);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "authority")),
                      "NONE_MANUAL_HANDOFF") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Creating missing code") == 0);
        ASSERT(json_get_bool(json_get(&reply.data, "details_available")));
        ASSERT(zpd_next_is(&reply, "zcode.work.status", absolute_root,
                           saved_work_id, NULL));
        {
            const struct zcl_command_registry *registry =
                zcl_command_catalog();
            const struct zcl_command_spec *run_spec =
                zcl_command_registry_find(registry, "zcode.work.run", NULL);
            struct zcl_command_context context = {
                .registry = registry,
                .granted_capabilities = ~(uint64_t)0,
                .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
            };
            char rendered[ZCL_COMMAND_RESULT_BUDGET + 1u];
            enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_OK;
            ASSERT(run_spec != NULL);
            size_t rendered_bytes = zcl_command_registry_execute_json(
                registry, run_spec, &context, &input, false, run_spec->path,
                "normal", 0, 0, NULL, rendered, sizeof(rendered),
                &exit_code);
            ASSERT(rendered_bytes > 0);
            ASSERT(exit_code == ZCL_COMMAND_EXIT_OK);
            ASSERT(strstr(rendered, "RESPONSE_BUDGET_EXCEEDED") == NULL);
            ASSERT(strstr(rendered,
                          "\"command\":\"zcode.work.status\"") != NULL);
        }
        ASSERT(vcs_tree_capture_path(root, source_after) == VCS_OK);
        ASSERT(memcmp(source_before, source_after, sizeof(source_before)) == 0);
        struct stat candidate_stat;
        ASSERT(stat(json_get_str(candidate_workspace), &candidate_stat) == 0 &&
               S_ISDIR(candidate_stat.st_mode));
        zcl_command_reply_free(&reply);
        json_free(&input);

        char candidate_license[4500];
        (void)snprintf(candidate_license, sizeof(candidate_license),
                       "%s/LICENSE", saved_candidate_workspace);
        ASSERT(zpd_write(candidate_license, "proprietary\n"));
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "PATCH_OUTSIDE_SCOPE") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        ASSERT(zpd_write(candidate_license, "MIT\n"));

        char candidate_source[4500];
        (void)snprintf(candidate_source, sizeof(candidate_source), "%s/src/x.c",
                       saved_candidate_workspace);
        ASSERT(zpd_write(candidate_source,
                         "int x(void) { return ; broken }\n"));
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        /* The operator's default node is not candidate authority. Omission of
         * datadir must retain the closed scratch worker even when the native
         * bridge has a default node bound. */
        zcl_native_bridge_bind_rpc(absolute_root, 0);
        zcl_native_handle_zcode_work_run(&request, &reply);
        zcl_native_bridge_bind_rpc("", 0);
        if (reply.status != ZCL_COMMAND_STATUS_PASSED)
            printf("failed-candidate admission failed: %s: %s\n", reply.error.code,
                   reply.error.message);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "REPAIR_NEEDED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Creating missing code") == 0);
        ASSERT(json_get(&reply.data, "changed_files") &&
               json_get_int(json_get(&reply.data, "changed_files")) == 1);
        ASSERT(json_get(&reply.data, "candidate_root") != NULL);
        ASSERT(json_get(&reply.data, "work_receipt_root") != NULL);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "failed") == 0);
        const struct json_value *repair_packet =
            json_get(&reply.data, "repair_packet");
        ASSERT(repair_packet && repair_packet->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(repair_packet, "goal")),
                      "Fix x") == 0);
        ASSERT(json_get(repair_packet, "parent_candidate_root") == NULL);
        ASSERT(json_get(repair_packet, "prior_patch_root") == NULL);
        ASSERT(json_get(repair_packet, "selected_excerpts") != NULL);
        const struct json_value *repair_diagnostic =
            json_get(repair_packet, "diagnostic");
        ASSERT(json_get(repair_diagnostic, "evidence_root") == NULL);
        ASSERT(json_get(repair_diagnostic, "work_receipt_root") == NULL);
        const struct json_value *compiler_feedback = repair_diagnostic
            ? json_get(repair_diagnostic, "compiler_feedback") : NULL;
        ASSERT(compiler_feedback &&
               json_get_bool(json_get(compiler_feedback, "available")));
        ASSERT(strcmp(json_get_str(json_get(compiler_feedback, "stage")),
                      "compile") == 0);
        ASSERT(strstr(json_get_str(json_get(compiler_feedback, "path")),
                      "src/x.c") != NULL);
        ASSERT(json_get_int(json_get(compiler_feedback, "line")) > 0);
        ASSERT(json_get_str(json_get(compiler_feedback, "message"))[0]);
        const struct json_value *repair_workspace =
            json_get(&reply.data, "candidate_workspace");
        const struct json_value *repair_packet_path =
            json_get(&reply.data, "repair_packet_path");
        ASSERT(repair_workspace && strstr(json_get_str(repair_workspace),
                                           "/attempt-2") != NULL);
        ASSERT(repair_packet_path &&
               access(json_get_str(repair_packet_path), F_OK) == 0);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "model_context_bytes")) > 0);
        ASSERT(zpd_next_is(&reply, "zcode.work.status", absolute_root,
                           saved_work_id, NULL));
        (void)snprintf(saved_candidate_workspace,
                       sizeof(saved_candidate_workspace), "%s",
                       json_get_str(repair_workspace));
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "REPAIR_NEEDED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "failed") == 0);
        const struct json_value *status_proof =
            json_get(&reply.data, "proof");
        ASSERT(status_proof &&
               json_get_bool(json_get(status_proof, "facts_available")));
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "remaining_risks")),
                      "latest candidate failed confined package build or tests") == 0);
        ASSERT(zpd_next_is(&reply, "zcode.work.run", absolute_root,
                           saved_work_id, NULL));
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "REPAIR_NEEDED") == 0);
        ASSERT(zpd_next_is(&reply, "zcode.work.status", absolute_root,
                           saved_work_id, NULL));
        repair_packet_path = json_get(&reply.data, "adapter_packet_path");
        ASSERT(repair_packet_path != NULL);
        char *repair_packet_text = zpd_read_bounded(
            json_get_str(repair_packet_path), 2u * 1024u * 1024u);
        ASSERT(repair_packet_text != NULL);
        ASSERT(strstr(repair_packet_text, "\"diagnostic\"") != NULL);
        ASSERT(strstr(repair_packet_text,
                      "\"compiler_feedback\"") != NULL);
        ASSERT(strstr(repair_packet_text, "\"parent_candidate_root\"") ==
               NULL);
        ASSERT(strstr(repair_packet_text, "\"prior_patch_root\"") == NULL);
        ASSERT(strstr(repair_packet_text, "\"evidence_root\"") == NULL);
        ASSERT(strstr(repair_packet_text, "\"work_receipt_root\"") == NULL);
        free(repair_packet_text);
        char staged_repair_path[4500];
        (void)snprintf(staged_repair_path, sizeof(staged_repair_path), "%s",
                       json_get_str(repair_packet_path));
        zcl_command_reply_free(&reply);
        json_free(&input);

        ASSERT(chmod(staged_repair_path, 0644) == 0);
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "REPAIR_CONTEXT_REFUSED") == 0);
        ASSERT(access(staged_repair_path, F_OK) != 0);
        zcl_command_reply_free(&reply);
        json_free(&input);

        (void)snprintf(candidate_source, sizeof(candidate_source), "%s/src/x.c",
                       saved_candidate_workspace);
        ASSERT(zpd_write(candidate_source,
                         "int x(void) { return 2; }\n"));
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "EVIDENCE_READY") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Showing result") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "passed") == 0);
        ASSERT(zpd_next_is(&reply, "zcode.work.status", absolute_root,
                           saved_work_id, NULL));
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "async_proof_state")), "REQUESTED") == 0);
        ASSERT(strlen(json_get_str(json_get(
                          &reply.data, "async_proof_event_root"))) == 64);
        ASSERT(json_get_int(json_get(
                   &reply.data, "remote_request_id")) > 0);
        ASSERT(json_get_int(json_get(&reply.data, "local_submit_us")) >= 0);
        ASSERT(json_get_int(
            json_get(&reply.data, "local_first_feedback_us")) >= 0);
        const struct json_value *run_expert = json_get(&reply.data, "expert");
        const struct json_value *run_action = run_expert
            ? json_get(run_expert, "action_id") : NULL;
        ASSERT(run_action && strlen(json_get_str(run_action)) == 64);
        ASSERT(json_write(&reply.data, NULL, 0) < 4096u);
        char saved_action_id[65];
        (void)snprintf(saved_action_id, sizeof(saved_action_id), "%s",
                       json_get_str(run_action));
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "EVIDENCE_READY") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Ready for your decision") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "passed") == 0);
        ASSERT(json_get_int(json_get(&reply.data, "changed_files")) == 1);
        ASSERT(json_get_int(json_get(&reply.data, "added_lines")) == 1);
        ASSERT(json_get_int(json_get(&reply.data, "deleted_lines")) == 1);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "public_api_changes")),
                      "none") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "sanitizer_result")),
                      "not_required") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "next_safe_command")),
                      "ask user to confirm exact candidate") == 0);
        ASSERT(json_get_bool(json_get(&reply.data, "confirmation_ready")));
        ASSERT(zpd_next_is(&reply, "app.presentation.release-confirm",
                           absolute_root, saved_work_id, NULL));
        ASSERT(strlen(json_get_str(json_get(
                   &reply.data, "confirmation_identity"))) == 64);
        status_proof = json_get(&reply.data, "proof");
        ASSERT(status_proof &&
               json_get_bool(json_get(status_proof, "facts_available")));
        ASSERT(json_get_bool(json_get(status_proof, "compile_satisfied")));
        ASSERT(json_get_bool(json_get(status_proof, "test_satisfied")));
        ASSERT(json_get_bool(json_get(status_proof, "policy_satisfied")));
        ASSERT(json_get_int(json_get(status_proof, "compile_receipts")) > 0);
        ASSERT(json_get_int(json_get(status_proof, "test_receipts")) > 0);
        ASSERT(json_write(&reply.data, NULL, 0) < 4096u);
        zcl_command_reply_free(&reply);
        json_free(&input);

        char zbuild_datadir[4400];
        (void)snprintf(zbuild_datadir, sizeof(zbuild_datadir), "%s",
                       saved_candidate_workspace);
        char *attempt_dir = strrchr(zbuild_datadir, '/');
        ASSERT(attempt_dir != NULL);
        (void)snprintf(attempt_dir,
                       (size_t)(zbuild_datadir + sizeof(zbuild_datadir) -
                                attempt_dir), "/zbuild");
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "datadir", zbuild_datadir));
        ASSERT(json_push_kv_str(&input, "action_id", saved_action_id));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_evidence_test.v1");
        zcl_native_handle_zcode_evidence(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&reply.data, "compile_satisfied")));
        ASSERT(json_get_bool(json_get(&reply.data, "test_satisfied")));
        ASSERT(json_get_bool(json_get(&reply.data, "policy_satisfied")));
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        ASSERT(json_push_kv_str(&input, "verdict", "approve"));
        ASSERT(json_push_kv_str(&input, "findings",
                                "Declared build and tests support approval."));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_review_test.v1");
        zcl_native_handle_zcode_work_review(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "verdict")),
                      "approve") == 0);
        ASSERT(json_get_bool(json_get(&reply.data,
                                      "independent_reviewer")));
        ASSERT(json_get_int(json_get(&reply.data, "review_receipts")) == 1);
        ASSERT(strlen(json_get_str(json_get(&reply.data,
                                            "review_root"))) == 64);
        ASSERT(strlen(json_get_str(json_get(&reply.data,
                                            "work_receipt_root"))) == 64);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "review_verdict")),
                      "approve") == 0);
        status_proof = json_get(&reply.data, "proof");
        ASSERT(status_proof &&
               json_get_bool(json_get(status_proof, "facts_available")));
        ASSERT(json_get_int(json_get(status_proof, "review_receipts")) == 1);
        ASSERT(json_get_bool(json_get(status_proof, "review_satisfied")));
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "next_safe_command")),
                      "ask user to confirm exact candidate") == 0);
        ASSERT(zpd_next_is(&reply, "app.presentation.release-confirm",
                           absolute_root, saved_work_id, NULL));
        const char *status_confirmation = json_get_str(json_get(
            &reply.data, "confirmation_identity"));
        ASSERT(status_confirmation && strlen(status_confirmation) == 64);
        char status_confirmation_identity[65];
        (void)snprintf(status_confirmation_identity,
                       sizeof(status_confirmation_identity), "%s",
                       status_confirmation);
        const struct json_value *status_expert =
            json_get(&reply.data, "expert");
        ASSERT(strlen(json_get_str(json_get(
                   status_expert, "review_root"))) == 64);
        const char *status_action = json_get_str(json_get(
            status_expert, "action_id"));
        const char *status_task = json_get_str(json_get(
            status_expert, "task_root"));
        const char *status_candidate = json_get_str(json_get(
            status_expert, "candidate_root"));
        const char *status_policy = json_get_str(json_get(
            status_expert, "proof_policy_root"));
        ASSERT(status_action && status_task && status_candidate &&
               status_policy);
        char status_action_saved[65], status_task_saved[65];
        char status_candidate_saved[65], status_policy_saved[65];
        (void)snprintf(status_action_saved, sizeof(status_action_saved),
                       "%s", status_action);
        (void)snprintf(status_task_saved, sizeof(status_task_saved),
                       "%s", status_task);
        (void)snprintf(status_candidate_saved,
                       sizeof(status_candidate_saved), "%s",
                       status_candidate);
        (void)snprintf(status_policy_saved, sizeof(status_policy_saved),
                       "%s", status_policy);
        zcl_command_reply_free(&reply);
        json_free(&input);

        uint8_t candidate_source_root[32];
        char candidate_source_hex[65];
        ASSERT(vcs_tree_capture_path(
                   saved_candidate_workspace, candidate_source_root) ==
               VCS_OK);
        zcl_hex_encode(candidate_source_root, 32, candidate_source_hex);
        char zbuild_db[4500];
        (void)snprintf(zbuild_db, sizeof(zbuild_db), "%s/node.db",
                       zbuild_datadir);
        struct node_db acceptance_db = {0};
        ASSERT(node_db_open(&acceptance_db, zbuild_db));
        struct zcode_accepted_work_status accepted_status;
        struct build_fabric_proof_evaluation confirmation_facts;
        ASSERT(build_fabric_proof_evaluate_readonly(
                   &acceptance_db, root, status_action_saved,
                   (int64_t)platform_time_wall_unix(),
                   &confirmation_facts).ok);
        ASSERT(confirmation_facts.policy_satisfied);
        uint8_t status_task_root[32], status_candidate_root[32];
        uint8_t status_policy_root[32], status_proof_root[32];
        uint8_t confirmation_root[32];
        ASSERT(zcl_hex_decode_lower(status_task_saved,
                                    status_task_root, 32));
        ASSERT(zcl_hex_decode_lower(status_candidate_saved,
                                    status_candidate_root, 32));
        ASSERT(zcl_hex_decode_lower(status_policy_saved,
                                    status_policy_root, 32));
        ASSERT(zcl_hex_decode_lower(confirmation_facts.proof_set_root_sha3,
                                    status_proof_root, 32));
        ASSERT(vcs_zcode_acceptance_plan_root(
                   status_task_root, status_candidate_root,
                   status_policy_root, status_proof_root,
                   confirmation_root) == VCS_ZCODE_DEV_OK);
        char confirmation_identity[65];
        zcl_hex_encode(confirmation_root, 32, confirmation_identity);
        ASSERT(strcmp(confirmation_identity,
                      status_confirmation_identity) == 0);
        struct json_value release_confirm_input;
        json_init(&release_confirm_input);
        json_set_object(&release_confirm_input);
        ASSERT(json_push_kv_str(&release_confirm_input, "workspace", root));
        ASSERT(json_push_kv_str(&release_confirm_input, "work",
                                saved_work_id));
        ASSERT(json_push_kv_str(&release_confirm_input, "output", "text"));
        struct zcl_command_request release_confirm_request = {
            .input = &release_confirm_input,
        };
        struct zcl_command_reply release_confirm_reply;
        zcl_command_reply_init(
            &release_confirm_reply,
            "zcl.app_presentation_release_confirm.v1");
        zcl_native_handle_presentation_release_confirm(
            &release_confirm_request, &release_confirm_reply);
        ASSERT(release_confirm_reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!json_get_bool(json_get(
            &release_confirm_reply.data, "launched")));
        ASSERT(strcmp(json_get_str(json_get(
                          &release_confirm_reply.data,
                          "confirmation_identity")),
                      confirmation_identity) == 0);
        ASSERT(!json_get_bool(json_get(
            &release_confirm_reply.data, "candidate_accepted")));
        ASSERT(!json_get_bool(json_get(
            &release_confirm_reply.data, "publication_performed")));
        ASSERT(strcmp(json_get_str(json_get(
                          &release_confirm_reply.data, "authority")),
                      "display-only") == 0);
        ASSERT(release_confirm_reply.next_count == 1);
        ASSERT(strcmp(release_confirm_reply.next[0].command,
                      "zcode.work.accept") == 0);
        struct json_value accept_next;
        json_init(&accept_next);
        ASSERT(json_read(
            &accept_next, release_confirm_reply.next[0].input_json,
            strlen(release_confirm_reply.next[0].input_json)));
        ASSERT(strcmp(json_get_str(json_get(&accept_next, "workspace")),
                      absolute_root) == 0);
        ASSERT(strcmp(json_get_str(json_get(&accept_next, "work")),
                      saved_work_id) == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &accept_next, "confirmation_identity")),
                      confirmation_identity) == 0);
        ASSERT(json_get(&accept_next, "task_root") == NULL);
        ASSERT(json_get(&accept_next, "candidate_root") == NULL);
        ASSERT(json_get(&accept_next, "proof_set_root") == NULL);
        const struct zcl_command_spec *accept_next_spec =
            zcl_command_registry_find(
                zcl_command_catalog(),
                release_confirm_reply.next[0].command, NULL);
        char accept_next_why[160] = {0};
        ASSERT(accept_next_spec && zcl_command_registry_input_validate(
            accept_next_spec, &accept_next, accept_next_why,
            sizeof(accept_next_why)));
        json_free(&accept_next);
        zcl_command_reply_free(&release_confirm_reply);
        json_free(&release_confirm_input);
        struct zcl_result before_accept = zcode_accepted_work_find(
            &acceptance_db, root, candidate_source_hex,
            (int64_t)platform_time_wall_unix(), false, &accepted_status);
        ASSERT(!before_accept.ok);
        node_db_close(&acceptance_db);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        char stale_confirmation[65];
        (void)snprintf(stale_confirmation, sizeof(stale_confirmation), "%s",
                       confirmation_identity);
        stale_confirmation[0] = stale_confirmation[0] == '0' ? '1' : '0';
        ASSERT(json_push_kv_str(&input, "confirmation_identity",
                                stale_confirmation));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_accept_test.v1");
        zcl_native_handle_zcode_work_accept(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "CONFIRMATION_IDENTITY_STALE") == 0);
        zcl_command_reply_free(&reply);
        json_set_str((struct json_value *)json_get(
                         &input, "confirmation_identity"),
                     confirmation_identity);
        ASSERT(json_push_kv_bool(&input, "details", true));
        zcl_command_reply_init(&reply, "zcl.zcode_work_accept_test.v1");
        zcl_native_handle_zcode_work_accept(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "PROVEN") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Accepted") == 0);
        ASSERT(json_get_bool(json_get(
            &reply.data, "confirmation_identity_checked")));
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "confirmation_identity")),
                      confirmation_identity) == 0);
        const char *accepted_root_text = json_get_str(json_get(
            json_get(&reply.data, "expert"), "lane_receipt_root"));
        ASSERT(accepted_root_text && strlen(accepted_root_text) == 64);
        char accepted_root_hex[65];
        (void)snprintf(accepted_root_hex, sizeof(accepted_root_hex), "%s",
                       accepted_root_text);
        const char *publication_workspace_text = json_get_str(json_get(
            &reply.data, "publication_workspace"));
        const char *publication_job_text = json_get_str(json_get(
            &reply.data, "publication_job_root"));
        const char *accepted_candidate_workspace = json_get_str(json_get(
            &reply.data, "candidate_workspace"));
        ASSERT(publication_workspace_text && publication_job_text &&
               accepted_candidate_workspace);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "publication_status")),
                      "ACCEPTED_LANE_BOUND") == 0);
        ASSERT(!json_get_bool(json_get(
            &reply.data, "publication_reused")));
        ASSERT(json_get_bool(json_get(
            &reply.data, "details_available")));
        ASSERT(strlen(json_get_str(json_get(
                   &reply.data, "publication_progress_root"))) == 64);
        char accepted_publication_workspace[4400];
        char publication_job_hex[65];
        (void)snprintf(accepted_publication_workspace,
                       sizeof(accepted_publication_workspace), "%s",
                       publication_workspace_text);
        (void)snprintf(publication_job_hex, sizeof(publication_job_hex), "%s",
                       publication_job_text);
        char resolved_authority_workspace[4400];
        ASSERT(platform_directory_canonical_real(
            root, resolved_authority_workspace,
            sizeof(resolved_authority_workspace)));
        ASSERT(reply.next_count == 1);
        ASSERT(strcmp(reply.next[0].command,
                      "dev.publication.advance") == 0);
        struct json_value publication_next;
        json_init(&publication_next);
        ASSERT(json_read(&publication_next, reply.next[0].input_json,
                         strlen(reply.next[0].input_json)));
        ASSERT(strcmp(json_get_str(json_get(
                          &publication_next, "workspace")),
                      resolved_authority_workspace) == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &publication_next, "datadir")),
                      zbuild_datadir) == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &publication_next, "job_root")),
                      publication_job_hex) == 0);
        ASSERT(json_get(&publication_next, "task_root") == NULL);
        ASSERT(json_get(&publication_next, "candidate_root") == NULL);
        const struct zcl_command_spec *publication_next_spec =
            zcl_command_registry_find(
                zcl_command_catalog(), reply.next[0].command, NULL);
        char publication_next_why[160] = {0};
        ASSERT(publication_next_spec && zcl_command_registry_input_validate(
            publication_next_spec, &publication_next,
            publication_next_why, sizeof(publication_next_why)));
        json_free(&publication_next);
        ASSERT(strcmp(accepted_publication_workspace,
                      resolved_authority_workspace) == 0);
        ASSERT(strcmp(accepted_candidate_workspace,
                      saved_candidate_workspace) == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        ASSERT(vcs_tree_capture_path(root, source_after) == VCS_OK);
        ASSERT(memcmp(source_before, source_after, sizeof(source_before)) == 0);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "datadir", zbuild_datadir));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Accepted") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "next_action")),
                      "Continue publishing this accepted version.") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "next_safe_command")),
                      "zcode work accept") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "remaining_risks")),
                      "accepted version is not fully published") == 0);
        ASSERT(!json_get_bool(json_get(
            &reply.data, "confirmation_ready")));
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "confirmation_effect")),
                      "none") == 0);
        ASSERT(zpd_next_datadir_is(
            &reply, "zcode.work.accept", absolute_root,
            saved_work_id, zbuild_datadir));
        struct json_value accepted_next;
        json_init(&accepted_next);
        ASSERT(json_read(&accepted_next, reply.next[0].input_json,
                         strlen(reply.next[0].input_json)));
        zcl_command_reply_free(&reply);
        json_free(&input);

        request.input = &accepted_next;
        zcl_command_reply_init(&reply, "zcl.zcode_work_accept_test.v1");
        zcl_native_handle_zcode_work_accept(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&reply.data, "idempotent")));
        ASSERT(json_get_bool(json_get(
            &reply.data, "publication_reused")));
        ASSERT(reply.next_count == 1);
        ASSERT(strcmp(reply.next[0].command,
                      "dev.publication.advance") == 0);
        struct json_value guided_publication_next;
        json_init(&guided_publication_next);
        ASSERT(json_read(&guided_publication_next,
                         reply.next[0].input_json,
                         strlen(reply.next[0].input_json)));
        ASSERT(strcmp(json_get_str(json_get(
                          &guided_publication_next, "job_root")),
                      publication_job_hex) == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &guided_publication_next, "datadir")),
                      zbuild_datadir) == 0);
        ASSERT(json_get(&guided_publication_next, "task_root") == NULL);
        ASSERT(json_get(&guided_publication_next,
                        "candidate_root") == NULL);
        request.input = &guided_publication_next;
        zcl_command_reply_init(
            &reply, "zcl.dev_publication_advance_test.v1");
        zcl_native_handle_dev_publication_advance(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "status")),
                      "PACKAGE_MAPPING_READY") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Publishing") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "next_action")),
                      "Choose the publisher identity and prepare offline signing.") == 0);
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "next_safe_command")),
                      "zcode package dev publish plan") == 0);
        ASSERT(json_get_bool(json_get(
            &reply.data, "details_available")));
        ASSERT(json_get(&reply.data, "publication_job_root") == NULL);
        ASSERT(json_get(&reply.data, "progress_receipt_root") == NULL);
        ASSERT(json_get(&reply.data, "lane_receipt_root") == NULL);
        ASSERT(json_get(&reply.data, "proof_set_root") == NULL);
        ASSERT(json_get(&reply.data, "package_mapping_root") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&guided_publication_next);
        json_free(&accepted_next);

        ASSERT(node_db_open(&acceptance_db, zbuild_db));
        struct zcl_result accepted_found = zcode_accepted_work_find(
            &acceptance_db, root, candidate_source_hex,
            (int64_t)platform_time_wall_unix(), false, &accepted_status);
        ASSERT(accepted_found.ok);
        char resolved_acceptance_hex[65];
        zcl_hex_encode(accepted_status.accepted.accepted_work_root, 32,
                       resolved_acceptance_hex);
        ASSERT(strcmp(resolved_acceptance_hex, accepted_root_hex) == 0);

        char accepted_worker_id[65];
        (void)snprintf(accepted_worker_id, sizeof(accepted_worker_id), "%s",
                       accepted_status.worker_id);
        ASSERT(build_fabric_worker_revoke(
                   &acceptance_db, accepted_worker_id,
                   (int64_t)platform_time_wall_unix()).ok);
        ASSERT(!zcode_accepted_work_find(
                    &acceptance_db, root, candidate_source_hex,
                    (int64_t)platform_time_wall_unix(), false,
                    &accepted_status).ok);
        struct db_build_worker accepted_worker;
        ASSERT(db_build_worker_find(
            &acceptance_db, accepted_worker_id, &accepted_worker));
        ASSERT(build_fabric_worker_approve(
                   &acceptance_db, &accepted_worker,
                   (int64_t)platform_time_wall_unix()).ok);

        ASSERT(node_db_exec(&acceptance_db,
            "UPDATE zcode_lane_receipts SET task_root_sha3="
            "'0101010101010101010101010101010101010101010101010101010101010101' "
            "WHERE lane=2"));
        ASSERT(!zcode_accepted_work_find(
                    &acceptance_db, root, candidate_source_hex,
                    (int64_t)platform_time_wall_unix(), false,
                    &accepted_status).ok);
        ASSERT(node_db_exec(
            &acceptance_db, "DELETE FROM zcode_lane_receipts"));
        ASSERT(!zcode_accepted_work_find(
                    &acceptance_db, root, candidate_source_hex,
                    (int64_t)platform_time_wall_unix(), false,
                    &accepted_status).ok);
        ASSERT(zcode_accepted_work_find(
                   &acceptance_db, root, candidate_source_hex,
                   (int64_t)platform_time_wall_unix(), true,
                   &accepted_status).ok);
        ASSERT(accepted_status.projection_rebuilt);
        zcl_hex_encode(accepted_status.accepted.accepted_work_root, 32,
                       resolved_acceptance_hex);
        ASSERT(strcmp(resolved_acceptance_hex, accepted_root_hex) == 0);
        node_db_close(&acceptance_db);
        ASSERT(node_db_open(&acceptance_db, zbuild_db));
        ASSERT(zcode_accepted_work_find(
                   &acceptance_db, root, candidate_source_hex,
                   (int64_t)platform_time_wall_unix(), false,
                   &accepted_status).ok);
        zcl_hex_encode(accepted_status.accepted.accepted_work_root, 32,
                       resolved_acceptance_hex);
        ASSERT(strcmp(resolved_acceptance_hex, accepted_root_hex) == 0);
        node_db_close(&acceptance_db);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "job_root", publication_job_hex));
        ASSERT(json_push_kv_str(&input, "datadir", zbuild_datadir));
        ASSERT(json_push_kv_bool(&input, "details", true));
        struct zcl_command_context publication_context = {
            .source_root = accepted_publication_workspace,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
            .dev_build = true,
        };
        request = (struct zcl_command_request) {
            .context = &publication_context, .input = &input,
        };
        zcl_command_reply_init(
            &reply, "zcl.dev_publication_advance_test.v1");
        zcl_native_handle_dev_publication_advance(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "status")),
                      "PACKAGE_MAPPING_READY") == 0);
        ASSERT(json_get_bool(json_get(
            &reply.data, "acceptance_reverified")));
        ASSERT(strcmp(json_get_str(json_get(
                          &reply.data, "lane_receipt_root")),
                      accepted_root_hex) == 0);
        const char *mapping_text = json_get_str(json_get(
            &reply.data, "package_mapping_root"));
        ASSERT(mapping_text && strlen(mapping_text) == 64);
        uint8_t mapping_root[32];
        ASSERT(zcl_hex_decode_lower(mapping_text, mapping_root, 32));
        struct vcs_package_mapping_set mapping;
        ASSERT(vcs_package_mapping_set_load(
            accepted_publication_workspace, mapping_root, &mapping));
        ASSERT(memcmp(mapping.lane_receipt_root,
                      accepted_status.accepted.accepted_work_root, 32) == 0);
        vcs_package_mapping_set_free(&mapping);
        zcl_command_reply_free(&reply); json_free(&input);
        ASSERT(vcs_tree_capture_path(root, source_after) == VCS_OK);
        ASSERT(memcmp(source_before, source_after, 32) == 0);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_accept_test.v1");
        zcl_native_handle_zcode_work_accept(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "PROVEN") == 0);
        ASSERT(json_get_bool(json_get(&reply.data, "idempotent")));
        ASSERT(json_get_bool(json_get(
            &reply.data, "publication_reused")));
        ASSERT(json_get(&reply.data, "publication_job_root") == NULL);
        ASSERT(json_get(&reply.data, "publication_progress_root") == NULL);
        ASSERT(json_get(&reply.data, "expert") == NULL);
        ASSERT(json_get_bool(json_get(&reply.data, "details_available")));
        ASSERT(reply.next_count == 1);
        ASSERT(strcmp(reply.next[0].command,
                      "dev.publication.advance") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        {
            const struct zcl_command_registry *registry =
                zcl_command_catalog();
            const struct zcl_command_spec *spec =
                zcl_command_registry_find(
                    registry, "zcode.work.preflight", NULL);
            struct zcl_command_context command_context = {
                .registry = registry,
                .granted_capabilities = ~(uint64_t)0,
                .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
            };
            char rendered[ZCL_COMMAND_RESULT_BUDGET + 1u];
            enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_OK;
            ASSERT(spec != NULL);
            size_t rendered_bytes = zcl_command_registry_execute_json(
                registry, spec, &command_context, &input, false, spec->path,
                "normal", 0, 0, NULL, rendered, sizeof(rendered),
                &exit_code);
            ASSERT(rendered_bytes > 0);
            ASSERT(exit_code == ZCL_COMMAND_EXIT_OK);
            struct json_value envelope;
            json_init(&envelope);
            ASSERT(json_read(&envelope, rendered, rendered_bytes));
            const struct json_value *data = json_get(&envelope, "data");
            const struct json_value *checks = json_get(data, "checks");
            const struct json_value *packet = json_get(checks, "packet");
            const struct json_value *sandbox = json_get(
                checks, "filesystem_sandbox");
            ASSERT(strcmp(json_get_str(json_get(&envelope, "data_schema")),
                          "zcl.zcode_work_preflight.v1") == 0);
            ASSERT(!json_get_bool(json_get(
                data, "model_request_attempted")));
            ASSERT(packet && json_get_bool(json_get(packet, "ready")));
            ASSERT(json_get_int(json_get(packet, "bytes")) > 0);
            ASSERT(sandbox && !json_get_bool(json_get(
                sandbox, "model_request_attempted")));
            ASSERT(strcmp(json_get_str(json_get(data, "blocker")),
                          json_get_str(json_get(data, "error_code"))) == 0);
            ASSERT(json_get_str(json_get(data, "current_state"))[0]);
            ASSERT(json_get_str(json_get(data, "next_action"))[0]);
            json_free(&envelope);
        }
        json_free(&input);

        ASSERT(unlink(zbuild_db) == 0);
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "PROVEN") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "codex"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "ADAPTER_UNAVAILABLE") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", saved_work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "shell"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_work_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "ADAPTER_REFUSED") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        char session_root[4400];
        (void)snprintf(session_root, sizeof(session_root), "%s",
                       saved_candidate_workspace);
        char *attempt = strrchr(session_root, '/');
        ASSERT(attempt != NULL);
        *attempt = '\0';
        ASSERT(zcl_tree_remove(session_root).ok);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static __attribute__((unused)) int zpd_test_standard_profile(void)
{
    int failures = 0;
    TEST("zcode work standard: warning-fatal sanitizer evidence reaches acceptance") {
        char root[256];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-standard-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "goal", "Make x return two"));
        ASSERT(json_push_kv_str(&input, "profile", "standard"));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_standard_start_test.v1");
        zcl_native_handle_zcode_work_start(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        char work_id[32];
        (void)snprintf(work_id, sizeof(work_id), "%s",
                       json_get_str(json_get(&reply.data, "work_id")));
        zcl_command_reply_free(&reply); json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_standard_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        if (reply.status != ZCL_COMMAND_STATUS_PASSED)
            fprintf(stderr, "standard admission failed: %s: %s\n",
                    reply.error.code, reply.error.message);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        char candidate[4400];
        (void)snprintf(candidate, sizeof(candidate), "%s",
                       json_get_str(json_get(&reply.data,
                                             "candidate_workspace")));
        zcl_command_reply_free(&reply); json_free(&input);

        char source[4500];
        (void)snprintf(source, sizeof(source), "%s/src/x.c", candidate);
        ASSERT(zpd_write(source, "int x(void) { return 2; }\n"));
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_standard_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        if (reply.status != ZCL_COMMAND_STATUS_PASSED)
            fprintf(stderr, "standard execution failed: %s: %s\n",
                    reply.error.code, reply.error.message);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "compile_receipts")) == 2);
        ASSERT(json_get_int(json_get(&reply.data,
                                     "test_receipts")) == 2);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "sanitizer_result")),
                      "passed_asan_ubsan") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_bool(&input, "details", true));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_standard_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "sanitizer_result")),
                      "passed_asan_ubsan") == 0);
        const struct json_value *standard_proof =
            json_get(&reply.data, "proof");
        ASSERT(standard_proof && json_get_bool(json_get(
            standard_proof, "sanitizer_satisfied")));
        ASSERT(json_get_int(json_get(
            standard_proof, "sanitizer_receipts")) == 2);
        zcl_command_reply_free(&reply); json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_standard_accept_test.v1");
        zcl_native_handle_zcode_work_accept(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "PROVEN") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        char session_root[4400];
        (void)snprintf(session_root, sizeof(session_root), "%s", candidate);
        char *attempt = strrchr(session_root, '/');
        ASSERT(attempt != NULL);
        *attempt = '\0';
        char ledger[4500];
        (void)snprintf(ledger, sizeof(ledger), "%s/zbuild/node.db",
                       session_root);
        ASSERT(unlink(ledger) == 0);
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_standard_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "PROVEN") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "sanitizer_result")),
                      "unknown") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        ASSERT(zcl_tree_remove(session_root).ok);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_admitted_single_interpretation(void)
{
    int failures = 0;
    TEST("zcode work: one admitted candidate reads identically from run and status") {
        char root[256];
        (void)snprintf(root, sizeof(root),
                       "test-tmp/zcode-admitted-%ld", (long)getpid());
        ASSERT(zpd_fixture(root, false));
        char absolute_root[4400];
        ASSERT(platform_directory_canonical_real(
            root, absolute_root, sizeof(absolute_root)));
        char datadir[256];
        (void)snprintf(datadir, sizeof(datadir),
                       "test-tmp/zcode-admitted-node-%ld", (long)getpid());
        ZCL_IGNORE_RESULT(zcl_tree_remove(datadir), "datadir fixture reset");
        ASSERT(platform_directory_create(datadir, 0700) == 0);
        char absolute_datadir[4400];
        ASSERT(platform_directory_canonical_real(
            datadir, absolute_datadir, sizeof(absolute_datadir)));

        struct json_value input;
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "goal", "Fix x"));
        ASSERT(json_push_kv_str(&input, "profile", "quick"));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_admitted_start_test.v1");
        zcl_native_handle_zcode_work_start(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        char work_id[32];
        (void)snprintf(work_id, sizeof(work_id), "%s",
                       json_get_str(json_get(&reply.data, "work_id")));
        zcl_command_reply_free(&reply); json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_admitted_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        char candidate[4400];
        (void)snprintf(candidate, sizeof(candidate), "%s",
                       json_get_str(json_get(&reply.data,
                                             "candidate_workspace")));
        zcl_command_reply_free(&reply); json_free(&input);

        char source[4500];
        (void)snprintf(source, sizeof(source), "%s/src/x.c", candidate);
        ASSERT(zpd_write(source, "int x(void) { return 2; }\n"));

        /* Live admission: the named datadir owns the immutable action and
         * the outstanding REQUESTED proof chain; no receipt exists yet. */
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        ASSERT(json_push_kv_str(&input, "datadir", datadir));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_admitted_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        if (reply.status != ZCL_COMMAND_STATUS_PASSED)
            printf("admitted async admission failed: %s: %s\n",
                   reply.error.code, reply.error.message);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "CANDIDATE_ADMITTED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "background_pending") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "async_proof_state")),
                      "REQUESTED") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        /* Regression: repeating run on the same admitted fact used to fail
         * CANDIDATE_EXECUTION_INCOMPLETE while status called the same fact
         * healthy waiting.  One lifecycle fact, one interpretation. */
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        ASSERT(json_push_kv_str(&input, "datadir", datadir));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_admitted_rerun_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "CANDIDATE_ADMITTED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Waiting for independent reproduction") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "background_pending") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "async_proof_state")),
                      "REQUESTED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "next_safe_command")),
                      "zcode work status") == 0);
        ASSERT(zpd_next_is(&reply, "zcode.work.status", absolute_root,
                           work_id, NULL));
        zcl_command_reply_free(&reply); json_free(&input);

        /* Status through the same datadir agrees: waiting, background build,
         * identical async proof state. */
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_str(&input, "datadir", datadir));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_admitted_status_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "CANDIDATE_ADMITTED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "stage")),
                      "Waiting for independent reproduction") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "background_pending") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "test_result")),
                      "background_pending") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                            "async_proof_state")),
                      "REQUESTED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "next_action")),
                      "Run zcode work toolchain here and on the proving node; independent compile evidence needs the same capsule_root.") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        /* Without the admitting datadir both surfaces stay blind, not
         * contradictory: status names the missing ledger, and run stays
         * fail-closed because no supervised proof is visible. */
        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_admitted_blind_test.v1");
        zcl_native_handle_zcode_work_status(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "state")),
                      "CANDIDATE_ADMITTED") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "build_result")),
                      "unknown") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "next_action")),
                      "No proof ledger reachable here shows this candidate's proof; pass the admitting node's datadir.") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "workspace", root));
        ASSERT(json_push_kv_str(&input, "work", work_id));
        ASSERT(json_push_kv_str(&input, "adapter", "manual"));
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.zcode_admitted_blind_run_test.v1");
        zcl_native_handle_zcode_work_run(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "CANDIDATE_EXECUTION_INCOMPLETE") == 0);
        zcl_command_reply_free(&reply); json_free(&input);

        char session_root[4400];
        (void)snprintf(session_root, sizeof(session_root), "%s", candidate);
        char *attempt = strrchr(session_root, '/');
        ASSERT(attempt != NULL);
        *attempt = '\0';
        ASSERT(zcl_tree_remove(session_root).ok);
        ASSERT(zcl_tree_remove(datadir).ok);
        zpd_fixture_cleanup(root);
        PASS();
    } _test_next:;
    return failures;
}

static int zpd_test_work_toolchain(void)
{
    int failures = 0;
    TEST("zcode work toolchain: names capsule and whether this binary can prove") {
        struct json_value extra;
        json_init(&extra); json_set_object(&extra);
        ASSERT(json_push_kv_str(&extra, "unexpected", "1"));
        struct zcl_command_request request = { .input = &extra };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_toolchain_show.v1");
        zcl_native_handle_zcode_toolchain_show(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "BAD_TOOLCHAIN_SHOW_INPUT") == 0);
        zcl_command_reply_free(&reply);
        json_free(&extra);

        request.input = NULL;
        zcl_command_reply_init(&reply, "zcl.zcode_toolchain_show.v1");
        zcl_native_handle_zcode_toolchain_show(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const char *capsule = json_get_str(json_get(&reply.data, "capsule_root"));
        const char *blocker = json_get_str(json_get(&reply.data, "blocker"));
        const char *next = json_get_str(json_get(&reply.data, "next_action"));
        bool present = json_get_bool(json_get(&reply.data, "verifier_present"));
        bool can_prove = json_get_bool(json_get(&reply.data, "can_prove"));
        ASSERT(capsule && strlen(capsule) == 64);
        ASSERT(blocker && (strcmp(blocker, "NONE") == 0 ||
                           strcmp(blocker, "VERIFIER_MISSING") == 0 ||
                           strcmp(blocker, "NOT_JOINED") == 0));
        ASSERT(present == can_prove);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "join_flags")),
                      "-packagehost=1 -buildworker=1") == 0);
        ASSERT(!json_get_bool(json_get(&reply.data, "joined")));
        ASSERT(next && strstr(next, "z23 join") != NULL);
        ASSERT(strstr(next, "-packagehost=1 -buildworker=1") == NULL);
        if (!present)
            ASSERT(strcmp(blocker, "VERIFIER_MISSING") == 0);
        zcl_command_reply_free(&reply);
        PASS();
    }
    TEST("zcode work toolchain: package hosting alone does not prove a "
         "restart will enable compile work") {
        const char *argv[] = { "z23", "-packagehost=1" };
        ParseParameters(2, argv);
        struct zcl_command_request request = { .input = NULL };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_toolchain_show.v1");
        zcl_native_handle_zcode_toolchain_show(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&reply.data, "package_hosting")));
        ASSERT(!json_get_bool(json_get(&reply.data, "joined")));
        {
            const char *next =
                json_get_str(json_get(&reply.data, "next_action"));
            ASSERT(next && strcmp(next, "z23 join") == 0);
            ASSERT(strstr(next, "restart") == NULL);
            ASSERT(strstr(next, "-buildworker=1") == NULL);
            ASSERT(strcmp(json_get_str(json_get(&reply.data,
                                                "next_safe_command")),
                          "join") == 0);
        }
        zcl_command_reply_free(&reply);
        PASS();
    }
    TEST("zcode work toolchain: join next names this datadir") {
        const char *reset[] = { "z23" };
        ParseParameters(1, reset);
        char dir[256], abs[4096];
        test_make_tmpdir(dir, sizeof(dir), "zcode_package_dev",
                         "toolchain-join-dd");
        ASSERT(platform_directory_canonical_real(dir, abs, sizeof(abs)));
        zcl_native_bridge_bind_rpc(abs, 0);
        struct zcl_command_request request = { .input = NULL };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.zcode_toolchain_show.v1");
        zcl_native_handle_zcode_toolchain_show(&request, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
        const char *next = json_get_str(json_get(&reply.data, "next_action"));
        ASSERT(next && strstr(next, "z23 join") != NULL);
        ASSERT(strstr(next, "-datadir=") != NULL);
        ASSERT(strstr(next, abs) != NULL);
        ASSERT(strstr(next, "-packagehost") == NULL);
        ASSERT(strstr(next, "-buildworker") == NULL);
        zcl_command_reply_free(&reply);
        zcl_native_bridge_bind_rpc("", 0);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    {
        const char *reset[] = { "z23" };
        ParseParameters(1, reset);
        zcl_native_bridge_bind_rpc("", 0);
    }
    return failures;
}

static int zpd_test_commons_join_front_doors(void)
{
    int failures = 0;
    TEST("commons join posture is the same on toolchain, offered, and guide") {
        struct zcl_zcode_join_posture join;
        ASSERT(zcl_zcode_join_posture_fill(&join));
        ASSERT(strcmp(join.join_flags, "-packagehost=1 -buildworker=1") == 0);
        ASSERT(strcmp(join.hosting_requirement,
                      "run the full node with -packagehost=1 -buildworker=1")
               == 0);
        ASSERT(!join.joined);
        ASSERT(!join.package_hosting);
        ASSERT(!join.build_worker);
        ASSERT(join.offline_next_command &&
               strcmp(join.offline_next_command, "z23 join") == 0);

        struct zcl_command_request request = { .input = NULL };
        struct zcl_command_reply toolchain;
        zcl_command_reply_init(&toolchain, "zcl.zcode_toolchain_show.v1");
        zcl_native_handle_zcode_toolchain_show(&request, &toolchain);
        ASSERT(toolchain.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&toolchain.data, "join_flags")),
                      "-packagehost=1 -buildworker=1") == 0);
        ASSERT(!json_get_bool(json_get(&toolchain.data, "joined")));
        ASSERT(!json_get_bool(json_get(&toolchain.data, "package_hosting")));
        ASSERT(!json_get_bool(json_get(&toolchain.data, "build_worker")));
        {
            const char *next =
                json_get_str(json_get(&toolchain.data, "next_action"));
            ASSERT(next && strcmp(next, "z23 join") == 0);
            ASSERT(strcmp(json_get_str(json_get(&toolchain.data,
                                                "next_safe_command")),
                          "join") == 0);
        }

        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_package_dev", "join-offered");
        struct json_value offered_input;
        json_init(&offered_input);
        json_set_object(&offered_input);
        ASSERT(json_push_kv_str(&offered_input, "datadir", dd));
        struct zcl_command_request offered_request = {
            .input = &offered_input
        };
        struct zcl_command_reply offered;
        zcl_command_reply_init(&offered, "zcl.zcode_package_offered.v1");
        zcl_native_handle_zcode_package_offered(&offered_request, &offered);
        ASSERT(offered.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(json_get_str(json_get(&offered.data, "join_flags")),
                      "-packagehost=1 -buildworker=1") == 0);
        ASSERT(!json_get_bool(json_get(&offered.data, "joined")));
        ASSERT(!json_get_bool(json_get(&offered.data, "package_hosting")));
        ASSERT(!json_get_bool(json_get(&offered.data, "build_worker")));
        ASSERT(!json_get_bool(json_get(&offered.data, "live")));
        {
            const char *next =
                json_get_str(json_get(&offered.data, "next_command"));
            ASSERT(next && strstr(next, "z23 join") != NULL);
            ASSERT(strstr(next, dd) != NULL);
            ASSERT(strstr(next, "-packagehost=1 -buildworker=1") == NULL);
        }

        struct json_value guide_input;
        json_init(&guide_input);
        json_set_object(&guide_input);
        struct zcl_command_request guide_request = { .input = &guide_input };
        struct zcl_command_reply guide;
        zcl_command_reply_init(&guide, "zcl.zcode_package_guide.v1");
        zcl_native_handle_zcode_package_guide(&guide_request, &guide);
        ASSERT(guide.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strcmp(json_get_str(json_get(&guide.data, "join_flags")),
                      "-packagehost=1 -buildworker=1") == 0);
        ASSERT(strcmp(json_get_str(json_get(&guide.data,
                                            "hosting_requirement")),
                      "run the full node with -packagehost=1 -buildworker=1")
               == 0);
        ASSERT(!json_get_bool(json_get(&guide.data, "joined")));
        ASSERT(!json_get_bool(json_get(&guide.data, "package_hosting")));
        ASSERT(!json_get_bool(json_get(&guide.data, "build_worker")));
        ASSERT(strcmp(json_get_str(json_get(&toolchain.data, "join_flags")),
                      json_get_str(json_get(&offered.data, "join_flags")))
               == 0);
        ASSERT(strcmp(json_get_str(json_get(&toolchain.data, "join_flags")),
                      json_get_str(json_get(&guide.data, "join_flags")))
               == 0);
        {
            static const char datadir[] =
                "/tmp/z23 commons'$(touch SHOULD_NOT_EXIST)\nsecond line";
            static const char expected[] =
                "z23 join -datadir='/tmp/z23 commons'\\''$(touch "
                "SHOULD_NOT_EXIST)\nsecond line'";
            struct json_value input;
            json_init(&input);
            json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "datadir", datadir));
            struct zcl_command_request request = { .input = &input };
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.zcode_package_offered.v1");
            zcl_native_handle_zcode_package_offered(&request, &reply);
            ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
            const char *next = json_get_str(json_get(&reply.data,
                                                     "next_command"));
            ASSERT(next && strcmp(next, expected) == 0);
            zcl_command_reply_free(&reply);
            json_free(&input);
        }
        {
            enum { DATADIR_LEN = 4393 };
            char datadir[DATADIR_LEN + 1];
            memset(datadir, 'a', DATADIR_LEN);
            datadir[0] = '/';
            datadir[DATADIR_LEN] = '\0';
            struct json_value input;
            json_init(&input);
            json_set_object(&input);
            ASSERT(json_push_kv_str(&input, "datadir", datadir));
            struct zcl_command_request request = { .input = &input };
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.zcode_package_offered.v1");
            zcl_native_handle_zcode_package_offered(&request, &reply);
            ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
            const char *next = json_get_str(json_get(&reply.data,
                                                     "next_command"));
            static const char prefix[] = "z23 join -datadir='";
            ASSERT(next && strncmp(next, prefix, sizeof(prefix) - 1u) == 0);
            ASSERT(memcmp(next + sizeof(prefix) - 1u, datadir,
                          DATADIR_LEN) == 0);
            ASSERT(next[sizeof(prefix) - 1u + DATADIR_LEN] == '\'');
            ASSERT(next[sizeof(prefix) + DATADIR_LEN] == '\0');
            zcl_command_reply_free(&reply);
            json_free(&input);
        }
        zcl_command_reply_free(&toolchain);
        zcl_command_reply_free(&offered);
        json_free(&offered_input);
        zcl_command_reply_free(&guide);
        json_free(&guide_input);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_package_dev(void)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t secret[32] = {0}; secret[31] = 1;
    uint8_t pubkey[33] = {0};
    if (!ctx || !zpd_pubkey(ctx, secret, pubkey)) {
        if (ctx) secp256k1_context_destroy(ctx);
        return 1;
    }
    int failures = zpd_test_base(ctx, secret, pubkey) +
                   zpd_test_control_stores(pubkey) +
                   zpd_test_default_chain_id(pubkey) +
                   zpd_test_exact_file_selection(pubkey) +
                   zpd_test_fail_closed(pubkey) +
                   zpd_test_project_inspect() +
                   zpd_test_project_init() +
                   zpd_test_reuse_plan() +
                   zpd_test_work_start_package_bounds() +
                   zpd_test_work_toolchain() +
                   zpd_test_commons_join_front_doors() +
                   zpd_test_admitted_single_interpretation();
#ifndef __APPLE__
    /* These scenarios execute fetched candidate source and assert Linux's
     * FULL Landlock/seccomp build lane.  Darwin deliberately refuses that
     * authority as LOCAL_FALLBACK; portable refusal is pinned by the build
     * fabric contract, while the planning/read-only cases above still run. */
    failures += zpd_test_work_start() +
                zpd_test_standard_profile() +
                zpd_test_twelve_task_benchmark();
#endif
    secp256k1_context_destroy(ctx);
    return failures;
}
