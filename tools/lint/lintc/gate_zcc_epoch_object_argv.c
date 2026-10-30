/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: epoch compile argv builders and session/expected-marker writers
 * for the check-zcc-epoch-object gate port (split from the util file to
 * keep each file under 800 lines). No heap; fixed ZEO_PATH buffers.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_epoch_object_priv.h"

void zeo_expect_log_output(struct zeo *z, const char *suffix)
{
    char tail[ZEO_PATH];
    if (zeo_tail1(z->zcc_log, tail, sizeof tail) != 0)
        zeo_failf("cache diagnostic did not name expected output: %s",
                  suffix);
    size_t n = strlen(tail), s = strlen(suffix);
    if (n < s + 1 || tail[n - s - 1] != ' ' ||
        strcmp(tail + n - s, suffix) != 0)
        zeo_failf("cache diagnostic did not name expected output: %s",
                  suffix);
}

static int zeo_argv_tail(char *argv[], size_t max, int n,
                         char *const args[])
{
    for (int i = 0; args && args[i]; i++) {
        if ((size_t)n >= max - 1)
            return 2;
        argv[n++] = (char *)args[i];
    }
    argv[n] = NULL;
    return 0;
}

static int zeo_epoch_argv(struct zeo *z, int native,
                          const char *script, const char *mode,
                          const char *output, char *const args[],
                          char *argv[], size_t max)
{
    int n = 0;
    argv[n++] = (char *)script;
    if (native)
        argv[n++] = (char *)"--epoch-object";
    argv[n++] = (char *)mode;
    argv[n++] = (char *)output;
    argv[n++] = z->source;
    argv[n++] = z->source_id;
    argv[n++] = (char *)"1";
    argv[n++] = z->mutation;
    argv[n++] = z->epoch;
    argv[n++] = z->compiler_id;
    argv[n++] = z->session;
    argv[n++] = (char *)"--";
    return zeo_argv_tail(argv, max, n, args);
}

int zeo_compile_x(struct zeo *z, const char *zccpath, const char *mode,
                  const char *output, char *const args[], const char *outf,
                  const char *errf, pid_t *bg, int *rc)
{
    char *argv[40];
    const char *exe = zccpath ? zccpath : z->zcc;
    if (zeo_epoch_argv(z, 1, exe, mode, output, args, argv,
                       sizeof argv / sizeof argv[0]) != 0)
        return 2;
    pid_t pid = zeo_spawn(exe, argv, outf, errf);
    if (pid < 0)
        return -1;
    if (bg) {
        *bg = pid;
        return 0;
    }
    *rc = zeo_wait(pid);
    return 0;
}

int zeo_legacy_x(struct zeo *z, const char *mode, const char *output,
                 char *const args[], const char *outf, const char *errf,
                 pid_t *bg, int *rc)
{
    char script[ZEO_PATH];
    char *argv[40];
    if (ovf(snprintf(script, sizeof script, "%s/tools/dev/compile-epoch-object.sh",
                     z->root), sizeof script))
        return 2;
    if (zeo_epoch_argv(z, 0, script, mode, output, args, argv,
                       sizeof argv / sizeof argv[0]) != 0)
        return 2;
    pid_t pid = zeo_spawn(script, argv, outf, errf);
    if (pid < 0)
        return -1;
    if (bg) {
        *bg = pid;
        return 0;
    }
    *rc = zeo_wait(pid);
    return 0;
}

int zeo_backend_x(struct zeo *z, int native, const char *mode,
                  const char *output, char *const args[], const char *outf,
                  const char *errf, pid_t *bg, int *rc)
{
    return native ? zeo_compile_x(z, NULL, mode, output, args, outf, errf,
                                  bg, rc)
                  : zeo_legacy_x(z, mode, output, args, outf, errf, bg, rc);
}

void zeo_write_session(const struct zeo *z)
{
    char flags[ZEO_HASH], text[1024];
    if (zeo_sha256_hex("flags", flags) != 0)
        zeo_fail("SHA-256 tool is unavailable");
    if (ovf(snprintf(text, sizeof text,
                     "schema=zcl.build_epoch_session.v1\n"
                     "source_id=%s\ncomplete=1\nmutation=%s\n"
                     "compiler_id=%s\nepoch=%s\nprofile=fixture-v1\n"
                     "flags_sha256=%s\n",
                     z->source_id, z->mutation, z->compiler_id, z->epoch,
                     flags), sizeof text))
        zeo_fail("session text exceeds the session buffer");
    if (zeo_write_file(z->session, text) != 0)
        zeo_fail("could not write the build session");
}

void zeo_write_marker(const struct zeo *z, const char *path, char *text,
                      size_t cap, const char *fmt, const char *ovf_msg,
                      const char *write_msg)
{
    if (ovf(snprintf(text, cap, fmt, z->source_id, z->mutation,
                     z->compiler_id, z->epoch),
            cap))
        zeo_fail(ovf_msg);
    if (zeo_write_file(path, text) != 0)
        zeo_fail(write_msg);
}
