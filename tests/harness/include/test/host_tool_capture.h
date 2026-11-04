/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded stdout capture for trusted, locally built harness tools.
 * This is not a package-execution or agent sandbox qualification. */
#ifndef ZCL_TEST_HOST_TOOL_CAPTURE_H
#define ZCL_TEST_HOST_TOOL_CAPTURE_H

#include "test/test_core.h"
#include "util/spawn.h"
#if defined(_WIN32)
#include "platform/process_lifecycle.h"
#endif

static inline int test_host_tool_capture(const char *const argv[], char *out,
                                         size_t out_size, uint32_t timeout_ms)
{
#if defined(_WIN32)
    char cwd[PATH_MAX], image[PATH_MAX], system_root[PATH_MAX + 16];
    char search_path[8192];
    const char *root = getenv("SystemRoot");
    const char *path = getenv("PATH");
    if (!argv || !argv[0] || !root || !path || !getcwd(cwd, sizeof(cwd)))
        return -1;
    int n = snprintf(image, sizeof(image), "%s/%s", cwd, argv[0]);
    if (n <= 0 || (size_t)n >= sizeof(image)) return -1;
    n = snprintf(system_root, sizeof(system_root), "SystemRoot=%s", root);
    if (n <= 0 || (size_t)n >= sizeof(system_root)) return -1;
    n = snprintf(search_path, sizeof(search_path), "Path=%s", path);
    if (n <= 0 || (size_t)n >= sizeof(search_path)) return -1;
    /* Retain the runner's DLL search route for locally built host tools. */
    const char *env[] = {system_root, search_path, NULL};
    const struct platform_process_options options = {
        .image = image, .argv = argv, .env = env,
    };
    struct platform_process_capture_result result = {0};
    if (!platform_process_capture_stdout(&options, out, out_size, timeout_ms,
                                         &result) || result.timed_out ||
        result.output_truncated || result.exit_code > INT_MAX)
        return -1;
    return (int)result.exit_code;
#else
    if (timeout_ms > INT_MAX) return -1;
    int rc = zcl_spawn_capture(argv, out, out_size, (int)timeout_ms);
    test_note_child(argv && argv[0] ? argv[0] : "host tool", rc,
                    out_size && rc >= 0 ? out : NULL);
    return rc;
#endif
}

#endif
