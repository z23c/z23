/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Request a trusted desktop opener for an owner-selected shared file. */
#include "command/native_app_share_reveal.h"
#include "util/spawn.h"
#include <string.h>
#define REVEAL_PATH_MAX 4097u

#if defined(__APPLE__) || defined(__linux__)
typedef bool (*reveal_runner)(void *, const char *, const char *const *);
static bool reveal_run(void *context, const char *image, const char *const *argv)
{
    (void)context;
    if (!image || !argv || strcmp(image, argv[0])) return false;
    unsigned char output[4096];
    struct zcl_spawn_binary_observation observed = {0};
    struct zcl_result result = zcl_spawn_capture_binary(argv, output, sizeof(output), 5000, &observed);
    return result.ok && observed.exit_observed && observed.exit_code == 0;
}
static bool reveal_with(const char *path, reveal_runner runner, void *context)
{
    if (!path || path[0] != '/' || strlen(path) >= REVEAL_PATH_MAX || !runner) return false;
#if defined(__APPLE__)
    const char *image = "/usr/bin/open";
    const char *argv[] = {image, "-R", path, NULL};
#else
    char parent[REVEAL_PATH_MAX];
    size_t n = strlen(path);
    memcpy(parent, path, n + 1u);
    char *slash = strrchr(parent, '/');
    if (!slash || !slash[1]) return false;
    if (slash == parent) slash[1] = 0; else *slash = 0;
    const char *image = "/usr/bin/gio";
    const char *argv[] = {image, "open", parent, NULL};
#endif
    return runner(context, image, argv);
}
#endif
bool app_share_reveal(const char *path)
{
#if defined(__APPLE__) || defined(__linux__)
    return reveal_with(path, reveal_run, NULL);
#else
    (void)path; return false;
#endif
}
#if defined(ZCL_TESTING)
bool zcl_test_app_share_reveal_run(const char *image, const char *const *argv)
{
#if defined(__APPLE__) || defined(__linux__)
    return reveal_run(NULL, image, argv);
#else
    (void)image; (void)argv; return false;
#endif
}
bool zcl_test_app_share_reveal(const char *path, app_share_reveal_runner runner, void *context)
{
#if defined(__APPLE__) || defined(__linux__)
    return reveal_with(path, runner, context);
#else
    (void)path; (void)runner; (void)context; return false;
#endif
}
#endif
