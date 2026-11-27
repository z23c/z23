/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: `z23` is the one command name people type. A developer command
 * (compat_target "z23-dev ...") has no handler in the release binary, which
 * must not link developer code, so the interactive CLI replaces itself with
 * the z23-dev installed in the SAME directory as the running executable,
 * passing the original argv words unchanged. Exit codes and output are
 * therefore the developer binary's own.
 *
 * Custody posture: the only code added to the release binary is this exec of
 * a fixed-name sibling, reachable only from cli_main (zcl_native_handoff_arm)
 * and never from the RPC server, MCP, the node daemon or any in-process
 * caller. The sibling must be a regular file (opened O_NOFOLLOW, so never a
 * symlink), owned by the running user or root, executable and not group- or
 * world-writable; it is executed by descriptor (fexecve). An
 * attacker who can write that directory could already replace z23 itself.
 * ZCL_NO_DEV_HANDOFF=1 restores the plain refusal; ZCL_DEV_HANDOFF_ACTIVE
 * is set across the exec so a misnamed sibling can never hand back.
 * Scope: the lookup is ONLY the directory of the running executable, so it
 * works where z23 and z23-dev sit in one build directory (build/bin in a
 * checkout). Installs put each binary in its own content-addressed directory,
 * so there is no sibling and the refusal names the command to run. No PATH,
 * argv[0] or symlink-following lookup is made. Windows and macOS have no
 * descriptor-bound exec (platform_execve_fd refuses; exec by path would
 * reintroduce a swap-after-check race), so they keep the refusal, and a
 * developer build (which owns the handlers) never hands off. */

#if !defined(_WIN32) && !defined(__APPLE__) && !defined(ZCL_DEV_BUILD)

#include "command/native_command_handoff.h"

#include <stdbool.h>
#include <stddef.h>

static int g_handoff_argc;
static char *const *g_handoff_argv;
#ifdef ZCL_TESTING
static const char *g_handoff_dir;
#endif

#include "base/safe_alloc.h"
#include "platform/os_proc.h"
#include "platform/process_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

#define NC_HANDOFF_TARGET_PREFIX "z23-dev "
#define NC_HANDOFF_SIBLING "z23-dev"
#define NC_HANDOFF_OPT_OUT "ZCL_NO_DEV_HANDOFF"
#define NC_HANDOFF_GUARD "ZCL_DEV_HANDOFF_ACTIVE"

static bool nc_handoff_env_set(const char *name)
{
    const char *v = getenv(name);
    return v && v[0] && strcmp(v, "0") != 0;
}

static bool nc_handoff_eligible(const struct zcl_command_spec *spec)
{
    if (!g_handoff_argv || g_handoff_argc < 2 || !spec ||
        spec->availability != ZCL_COMMAND_COMPAT)
        return false;
    if (zcl_command_registry_effective_handler(spec))
        return false;
    if (!spec->compat_target ||
        strncmp(spec->compat_target, NC_HANDOFF_TARGET_PREFIX,
                strlen(NC_HANDOFF_TARGET_PREFIX)) != 0)
        return false;
    return !nc_handoff_env_set(NC_HANDOFF_OPT_OUT) &&
           !nc_handoff_env_set(NC_HANDOFF_GUARD);
}

/* The directory holding the running executable (or the test override). */
static bool nc_handoff_own_dir(char *dir, size_t cap)
{
#ifdef ZCL_TESTING
    if (g_handoff_dir) {
        int c = snprintf(dir, cap, "%s", g_handoff_dir);
        return c > 0 && (size_t)c < cap;
    }
#endif
    if (!os_proc_exe_path(dir, cap) || dir[0] != '/')
        return false;
    char *deleted = strstr(dir, " (deleted)");
    if (deleted)
        *deleted = '\0';
    char *slash = strrchr(dir, '/');
    if (!slash)
        return false;
    *slash = '\0';
    return true;
}

static const char *nc_handoff_mode_refusal(const struct stat *st)
{
    if (!S_ISREG(st->st_mode))
        return "not a regular file";
    if (st->st_uid != geteuid() && st->st_uid != 0)
        return "owned by another user";
    if (st->st_mode & (S_IWGRP | S_IWOTH))
        return "group or world writable";
    if (!(st->st_mode & S_IXUSR))
        return "not executable";
    return NULL;
}

/* A descriptor on the trusted sibling, or -1. Absence is silent; an existing
 * sibling that fails the trust check is named on stderr, then ignored. */
static int nc_handoff_open_trusted(const char *path)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT && errno != ENOTDIR)
            fprintf(stderr, "z23: ignoring %s: %s\n", path,
                    errno == ELOOP ? "is a symlink" : strerror(errno));
        return -1;
    }
    struct stat st;
    const char *why = fstat(fd, &st) == 0 ? nc_handoff_mode_refusal(&st)
                                          : "cannot stat";
    if (why) {
        fprintf(stderr, "z23: ignoring %s: %s\n", path, why);
        (void)close(fd);
        return -1;
    }
    return fd;
}

static void nc_handoff_exec(int fd, const char *path)
{
    char **args = zcl_calloc((size_t)g_handoff_argc + 1, sizeof(*args),
                             "handoff_argv");
    if (!args) {
        fprintf(stderr, "z23: cannot hand off to %s: out of memory\n", path);
        return;
    }
    args[0] = (char *)path;
    for (int i = 1; i < g_handoff_argc; i++)
        args[i] = g_handoff_argv[i];
    (void)setenv(NC_HANDOFF_GUARD, "1", 1);
    (void)fflush(NULL);
    (void)platform_execve_fd(fd, args, environ);
    fprintf(stderr, "z23: cannot hand off to %s: %s\n", path, strerror(errno));
    (void)unsetenv(NC_HANDOFF_GUARD);
    free(args);
}

static void nc_handoff_run(const struct zcl_command_spec *spec)
{
    char dir[PATH_MAX], path[PATH_MAX + 16];
    if (!nc_handoff_eligible(spec) || !nc_handoff_own_dir(dir, sizeof(dir)))
        return;
    int n = snprintf(path, sizeof(path), "%s/%s", dir, NC_HANDOFF_SIBLING);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return;
    int fd = nc_handoff_open_trusted(path);
    if (fd < 0)
        return;
    nc_handoff_exec(fd, path);
    (void)close(fd);
}

#else /* Windows, macOS and developer builds never hand off. */

#include "command/native_command_handoff.h"

#ifdef ZCL_TESTING
static const char *g_handoff_dir;
#endif

static void nc_handoff_run(const struct zcl_command_spec *spec)
{
    (void)spec;
}

#endif

void zcl_native_handoff_arm(int argc, char *const *argv)
{
#if !defined(_WIN32) && !defined(__APPLE__) && !defined(ZCL_DEV_BUILD)
    g_handoff_argc = argc;
    g_handoff_argv = argv;
#else
    (void)argc;
    (void)argv;
#endif
}

#ifdef ZCL_TESTING
void zcl_native_handoff_set_dir_for_test(const char *dir)
{
    g_handoff_dir = dir;
}
#endif

void zcl_native_handoff_try(const struct zcl_command_spec *spec)
{
    nc_handoff_run(spec);
}
