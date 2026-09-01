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
        return rg_write(schedule->workspace, "lib/net/src/generation.c",
                        rg_source_b);
    }
    if (phase == ZCL_NATIVE_DEV_RETRIEVAL_TEST_BEFORE_POST_CAPTURE) {
        schedule->before_post++;
        return rg_write(schedule->workspace, "lib/net/src/generation.c",
                        rg_source_a);
    }
    return false;
}

static int case_aba_generation_join(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    bool ready = sizeof(rg_source_a) == sizeof(rg_source_b) &&
        platform_temp_directory_create("z23-rg-", temporary,
                                       sizeof(temporary)) &&
        rg_write(temporary, "lib/net/src/generation.c", rg_source_a);
    ready = ready && platform_directory_canonical_real(
        temporary, workspace, sizeof(workspace));
    uint8_t expected[32];
    ready = ready && rg_manifest_root(workspace, expected);
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
    char error_code[64], error_message[256];
    int rc = ready ? zcl_native_dev_retrieval_snapshot_compute(
        &input, &snapshot, error_code, sizeof(error_code),
        error_message, sizeof(error_message)) : ZCL_COMMAND_EXIT_INTERNAL;
    zcl_native_dev_retrieval_test_set_hook(NULL, NULL);
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
    return case_aba_generation_join();
}
