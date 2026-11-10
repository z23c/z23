/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded stdout capture for trusted, locally built harness tools.
 * This is not a package-execution or agent sandbox qualification. */
#ifndef ZCL_TEST_HOST_TOOL_CAPTURE_H
#define ZCL_TEST_HOST_TOOL_CAPTURE_H

#include "test/test_core.h"
#include "util/spawn.h"
#if defined(_WIN32)
#include "platform/process_lifecycle.h"

static inline bool test_host_tool_windows_env(const char *const argv[], char *image,
                                              size_t image_size, char *system_root,
                                              size_t root_size, char *search_path,
                                              size_t path_size)
{
    char cwd[PATH_MAX];
    const char *root = getenv("SystemRoot"), *path = getenv("PATH");
    if (!argv || !argv[0] || !root || !path || !getcwd(cwd, sizeof(cwd)))
        return false;
    int n = snprintf(image, image_size, "%s/%s", cwd, argv[0]);
    if (n <= 0 || (size_t)n >= image_size) return false;
    n = snprintf(system_root, root_size, "SystemRoot=%s", root);
    if (n <= 0 || (size_t)n >= root_size) return false;
    n = snprintf(search_path, path_size, "Path=%s", path);
    return n > 0 && (size_t)n < path_size;
}
#endif

static inline int test_host_tool_capture(const char *const argv[], char *out,
                                         size_t out_size, uint32_t timeout_ms)
{
#if defined(_WIN32)
    char image[PATH_MAX], system_root[PATH_MAX + 16];
    char search_path[8192];
    if (!test_host_tool_windows_env(argv, image, sizeof(image), system_root,
                                    sizeof(system_root), search_path, sizeof(search_path)))
        return -1;
    /* Retain the runner's DLL search route for locally built host tools. */
    const char *env[] = {system_root, search_path, NULL};
    const struct platform_process_options options = {
        .image = image, .argv = argv, .env = env,
    };
    struct platform_process_capture_result result = {0};
    struct platform_process_evidence evidence = {0};
    bool captured = platform_process_capture_evidence(&options, out, out_size,
                                                       timeout_ms, &result, &evidence);
    int rc = !captured || result.timed_out || result.output_truncated ||
             result.exit_code > INT_MAX ? -1 : (int)result.exit_code;
    test_note("child %s exit=%u return=%d observed=%d timeout=%d stdout_truncated=%d",
              argv[0], result.exit_code, rc, captured && !result.timed_out, result.timed_out,
              result.output_truncated);
    test_note("child stdout_observed=%llu complete=%d stderr_observed=%llu complete=%d",
              (unsigned long long)evidence.stdout_observed, evidence.stdout_complete,
              (unsigned long long)evidence.stderr_observed, evidence.stderr_complete);
    test_note_bytes("stdout tail", evidence.stdout_tail, evidence.stdout_len);
    test_note_bytes("stderr tail", evidence.stderr_tail, evidence.stderr_len);
    return rc;
#else
    if (timeout_ms > INT_MAX) return -1;
    struct zcl_spawn_evidence evidence;
    int rc = zcl_spawn_capture_evidence(argv, out, out_size, (int)timeout_ms, &evidence);
    test_note("child %s exit=%d observed=%d timeout=%d stdout_truncated=%d",
              argv && argv[0] ? argv[0] : "host tool", rc,
              evidence.exit_observed, evidence.timed_out, evidence.stdout_truncated);
    test_note("child stdout_observed=%llu complete=%d stderr_observed=%llu complete=%d",
              (unsigned long long)evidence.stdout_observed, evidence.stdout_complete,
              (unsigned long long)evidence.stderr_observed, evidence.stderr_complete);
    test_note_bytes("stdout tail", evidence.stdout_tail, evidence.stdout_len);
    test_note_bytes("stderr tail", evidence.stderr_tail, evidence.stderr_len);
    return rc;
#endif
}

#endif
