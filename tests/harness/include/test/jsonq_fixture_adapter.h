/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Bounded stdin capture for the trusted, locally built jsonq fixture. */
#ifndef ZCL_TEST_JSONQ_FIXTURE_ADAPTER_H
#define ZCL_TEST_JSONQ_FIXTURE_ADAPTER_H
#include "test/test_core.h"
#include "util/spawn.h"
#if defined(_WIN32)
#include "platform/process_lifecycle.h"
#define JSONQ_FIXTURE_BIN "build/bin/jsonq.exe"
#define JSONQ_FIXTURE_EOL "\r\n"
#else
#define JSONQ_FIXTURE_BIN "build/bin/jsonq"
#define JSONQ_FIXTURE_EOL "\n"
#endif

/* argv is a compile-time fixture vector, including argv[0] and terminator.
 * At most four non-NULL arguments (jsonq eq PATH VALUE). Empty path remains
 * an actual empty argv element. Document bytes never enter argv or a shell. */
/* bin is the executable path, which argv[0] must name exactly. The alias
 * tests pass a link path (build/bin/jsonq or a temp-dir link to z23). */
static int jsonq_fixture_run_as(const char *bin, const char *document,
                                const char *const argv[], char *out,
                                size_t out_size)
{
    if (!bin || !document || !argv || !argv[0] || !out || out_size == 0 ||
        strcmp(argv[0], bin) != 0) return -1;
    size_t count = 0;
    while (count < 5u && argv[count]) count++;
    if (count < 2u || count > 4u) return -1;
    size_t length = strlen(document);
    if (length > 64u * 1024u) return -1;
    char dir[4096], input[4608];
    if (!test_mkdtemp(dir, sizeof(dir), "jsonq_stdin")) return -1;
    int result = -1;
    int n = snprintf(input, sizeof(input), "%s/input.json", dir);
    if (n <= 0 || (size_t)n >= sizeof(input)) goto cleanup;
    FILE *file = fopen(input, "wb");
    if (!file) goto cleanup;
    bool written = fwrite(document, 1, length, file) == length;
    int closed = fclose(file);
    if (!written || closed != 0) goto cleanup;
#if defined(_WIN32)
    char cwd[PATH_MAX], image[PATH_MAX], system_root[PATH_MAX + 16];
    char search_path[8192];
    const char *root = getenv("SystemRoot"), *path = getenv("PATH");
    if (!root || !path || !getcwd(cwd, sizeof(cwd))) goto cleanup;
    n = snprintf(image, sizeof(image), "%s/%s", cwd, bin);
    if (n <= 0 || (size_t)n >= sizeof(image)) goto cleanup;
    n = snprintf(system_root, sizeof(system_root), "SystemRoot=%s", root);
    if (n <= 0 || (size_t)n >= sizeof(system_root)) goto cleanup;
    n = snprintf(search_path, sizeof(search_path), "Path=%s", path);
    if (n <= 0 || (size_t)n >= sizeof(search_path)) goto cleanup;
    const char *env[] = {system_root, search_path, NULL};
    struct platform_process_options options = {
        .image = image, .argv = argv, .env = env};
    struct platform_process_capture_result captured = {0};
    if (platform_process_capture_stdout_file_input(&options, input, out,
        out_size, 5000u, &captured) && !captured.timed_out &&
        !captured.output_truncated && captured.exit_code <= INT_MAX)
        result = (int)captured.exit_code;
#else
    const char *shell_argv[11] = {
        "sh", "-c", "input=$1; shift; exec \"$@\" < \"$input\"",
        "jsonq-fixture", input, NULL};
    for (size_t i = 0; i < count; i++) shell_argv[5u + i] = argv[i];
    shell_argv[5u + count] = NULL;
    result = zcl_spawn_capture(shell_argv, out, out_size, 5000);
    if (result >= 0 && strlen(out) == out_size - 1u) result = -1;
#endif
cleanup:
    if (test_rm_rf_recursive(dir) != 0) result = -1;
    return result;
}

static int jsonq_fixture_run(const char *document, const char *const argv[],
                             char *out, size_t out_size)
{
    return jsonq_fixture_run_as(JSONQ_FIXTURE_BIN, document, argv, out,
                                out_size);
}

/* Exact CLI examples for conversion of original tests (no newline stripping):
 * const char *count[] = {JSONQ_FIXTURE_BIN, "count", "", NULL};
 * ASSERT(jsonq_fixture_run("{\"a\":1,\"b\":{\"x\":1}}", count,
 *                          buf, sizeof(buf)) == 0);
 * ASSERT(strcmp(buf, "2" JSONQ_FIXTURE_EOL) == 0);
 * const char *keys[] = {JSONQ_FIXTURE_BIN, "keys", "", NULL};
 * ASSERT(jsonq_fixture_run("{\"a\":1,\"b\":[{\"x\":1}]}", keys,
 *                          buf, sizeof(buf)) == 0);
 * ASSERT(strcmp(buf, "a" JSONQ_FIXTURE_EOL "b" JSONQ_FIXTURE_EOL) == 0);
 * const char *unwrap[] = {JSONQ_FIXTURE_BIN, "unwrap", NULL};
 * ASSERT(jsonq_fixture_run("{not json}", unwrap, buf, sizeof(buf)) == 2);
 * The real host binary is always executed; no embedded renamed main is used.
 */

#endif
