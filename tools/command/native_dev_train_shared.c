/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: shared primitives for the hand-driven dev.train commands and the
 *          unattended train keeper.
 */

#include "command/native_command.h"
#include "command/native_dev_train_command.h"

#include "platform/directory_compat.h"
#include "platform/state_root.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

const char *zcl_dev_train_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

void zcl_dev_train_strip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

bool zcl_dev_train_skip_subject(const char *subject)
{
    static const char *const prefixes[] = {
        "Regenerate the generated docs",
        "Regenerate the capability inventory",
        "Pin today's complexity",
        "Count what the stacked lanes added",
        "Regenerate the catalogs",
        NULL,
    };
    for (size_t i = 0; prefixes[i]; i++) {
        size_t n = strlen(prefixes[i]);
        if (strncmp(subject, prefixes[i], n) == 0)
            return true;
    }
    return false;
}

int zcl_dev_train_git(const char *dir, const char *const args[], char *out,
                      size_t out_cap, int timeout_ms)
{
    const char *argv[20];
    size_t n = 0;
    static char scratch[1];
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (out && out_cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out ? out : scratch,
                             out ? out_cap : sizeof(scratch), timeout_ms);
}

bool zcl_dev_train_is_dir(const char *path)
{
    return platform_directory_probe_real(path) ==
           PLATFORM_DIRECTORY_PROBE_OK;
}

static bool dvt_land_dir(char *out, size_t cap, bool existing)
{
    char root[PATH_MAX];
    if (!out || !cap)
        return false;
    bool resolved = existing ? platform_state_root_existing(root, sizeof(root))
                             : platform_state_root(root, sizeof(root));
    if (!resolved)
        return false;
    int n = snprintf(out, cap, "%s/land", root);
    return n > 0 && (size_t)n < cap;
}

bool zcl_dev_train_land_dir(char *out, size_t cap)
{
    return dvt_land_dir(out, cap, false);
}

bool zcl_dev_train_land_dir_existing(char *out, size_t cap)
{
    return dvt_land_dir(out, cap, true);
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */
