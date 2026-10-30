/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-zcc-epoch-batch — compiles the zcc epoch-batch codec
 * test program (tools/lint/fixtures/zcc_epoch_batch_check.c.fixture) against
 * tools/zcc_epoch_batch.c and platform/modules/base/src/safe_alloc.c with
 * the ${CC:-cc} compiler at -std=c23 -Wall -Wextra -Werror -pedantic plus
 * ${CFLAGS} / ${LDFLAGS}, then runs it. Ported from
 * tools/lint/check_zcc_epoch_batch.sh (deleted). Selftest:
 * gate_zcc_epoch_batch_selftest.c.
 *
 * Exit codes match the script: the compiler's status on a build failure, the
 * test binary's status (0 ok / 1 check failure / 2 fixture overflow) on a
 * run, 2 on harness trouble (scratch, spawn, overflow). The test binary and
 * the compiler write to the inherited stdout/stderr exactly as before. No
 * shell is involved: the child processes are exec'd directly.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"

enum { ZEB_WORDS = 32, ZEB_WLEN = 256, ZEB_ARGS = 112, ZEB_ARGLEN = 640,
       ZEB_PATH = 1024, ZEB_FPATH = 1152 };

static const char k_zeb_gate[] = "check_zcc_epoch_batch";
static const char k_zeb_fixture[] =
    "/tools/lint/fixtures/zcc_epoch_batch_check.c.fixture";

struct zeb_words { char w[ZEB_WORDS][ZEB_WLEN]; int n; };
struct zeb_args { char v[ZEB_ARGS][ZEB_ARGLEN]; int n; };

/* Splits s on blanks/tabs/newlines (the shell's unquoted word split of
 * ${CC} / ${CFLAGS} / ${LDFLAGS}). NULL or empty yields zero words. */
static int zeb_split(struct zeb_words *ws, const char *s)
{
    ws->n = 0;
    if (!s)
        return 0;
    while (*s) {
        while (*s == ' ' || *s == '\t' || *s == '\n')
            s++;
        if (!*s)
            break;
        if (ws->n >= ZEB_WORDS) {
            fprintf(stderr, "%s: word list exceeds %d entries\n", k_zeb_gate,
                    ZEB_WORDS);
            return 2;
        }
        size_t i = 0;
        while (*s && *s != ' ' && *s != '\t' && *s != '\n') {
            if (i >= ZEB_WLEN - 1) {
                fprintf(stderr, "%s: word exceeds %d bytes\n", k_zeb_gate,
                        ZEB_WLEN);
                return 2;
            }
            ws->w[ws->n][i++] = *s++;
        }
        ws->w[ws->n][i] = '\0';
        ws->n++;
    }
    return 0;
}

static int zeb_push(struct zeb_args *a, const char *s)
{
    if (a->n >= ZEB_ARGS) {
        fprintf(stderr, "%s: command exceeds %d arguments\n", k_zeb_gate,
                ZEB_ARGS);
        return 2;
    }
    if (ovf(snprintf(a->v[a->n], ZEB_ARGLEN, "%s", s), ZEB_ARGLEN)) {
        fprintf(stderr, "%s: argument exceeds %d bytes\n", k_zeb_gate,
                ZEB_ARGLEN);
        return 2;
    }
    a->n++;
    return 0;
}

static int zeb_push_words(struct zeb_args *a, const struct zeb_words *ws)
{
    for (int i = 0; i < ws->n; i++) {
        int rc = zeb_push(a, ws->w[i]);
        if (rc)
            return rc;
    }
    return 0;
}

static int zeb_argv(char *out[], struct zeb_args *a)
{
    if (a->n >= ZEB_ARGS)
        return 2;
    for (int i = 0; i < a->n; i++)
        out[i] = a->v[i];
    out[a->n] = NULL;
    return 0;
}

/* Fork + execvp; the child inherits stdout/stderr. 0 ok, *st = wait status. */
static int zeb_spawn(char *argv[], int *st)
{
    fflush(NULL);
    pid_t p = fork();
    if (p < 0) {
        fprintf(stderr, "%s: fork failed\n", k_zeb_gate);
        return 2;
    }
    if (p == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    pid_t w;
    do
        w = waitpid(p, st, 0);
    while (w < 0 && errno == EINTR);
    if (w != p) {
        fprintf(stderr, "%s: waitpid failed\n", k_zeb_gate);
        return 2;
    }
    return 0;
}

static int zeb_status(int st)
{
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return 2;
}

static int zeb_scratch(char *out, size_t cap)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(out, cap, "%s/zcc-epoch-batch.XXXXXX", td), cap)) {
        fprintf(stderr, "%s: scratch path exceeds %zu bytes\n", k_zeb_gate,
                cap);
        return 2;
    }
    if (!mkdtemp(out)) {
        fprintf(stderr, "%s: mkdtemp failed for %s\n", k_zeb_gate, out);
        return 2;
    }
    return 0;
}

/* Copies a+b into out, checking the snprintf for truncation. */
static int zeb_join(char *out, size_t cap, const char *a, const char *b)
{
    if (ovf(snprintf(out, cap, "%s%s", a, b), cap)) {
        fprintf(stderr, "%s: path exceeds %zu bytes\n", k_zeb_gate, cap);
        return 2;
    }
    return 0;
}

static int zeb_add_path(struct zeb_args *a, const char *pre, const char *root,
                        const char *rel)
{
    char p[ZEB_FPATH];
    if (ovf(snprintf(p, sizeof p, "%s%s%s", pre, root, rel), sizeof p)) {
        fprintf(stderr, "%s: path exceeds %zu bytes\n", k_zeb_gate,
                sizeof p);
        return 2;
    }
    return zeb_push(a, p);
}

static int zeb_push_all(struct zeb_args *a, const char *const *list)
{
    for (; *list; list++) {
        int rc = zeb_push(a, *list);
        if (rc)
            return rc;
    }
    return 0;
}

static int zeb_load_words(struct zeb_words *cc, struct zeb_words *cflags,
                          struct zeb_words *ldflags)
{
    int rc = zeb_split(cc, getenv("CC"));
    if (rc == 0 && cc->n == 0)
        rc = zeb_split(cc, "cc");
    if (rc == 0)
        rc = zeb_split(cflags, getenv("CFLAGS"));
    if (rc == 0)
        rc = zeb_split(ldflags, getenv("LDFLAGS"));
    return rc;
}

/* Builds the compiler command line exactly as the script did; the embedded
 * program is read from its fixture file (-x c <file>) instead of stdin. */
static int zeb_build(struct zeb_args *a, const char *root, const char *bin)
{
    static const char *const flags[] = {"-std=c23", "-Wall", "-Wextra",
                                        "-Werror", "-pedantic", NULL};
    static const char *const tail[] = {"-x", "c", NULL};
    struct zeb_words cc, cflags, ldflags;
    int rc = zeb_load_words(&cc, &cflags, &ldflags);
    if (rc == 0)
        rc = zeb_push_words(a, &cc);
    if (rc == 0)
        rc = zeb_push_all(a, flags);
    if (rc == 0)
        rc = zeb_push_words(a, &cflags);
    if (rc == 0)
        rc = zeb_add_path(a, "-I", root, "/tools");
    if (rc == 0)
        rc = zeb_add_path(a, "-I", root, "/platform/modules/base/include");
    if (rc == 0)
        rc = zeb_add_path(a, "", root, "/tools/zcc_epoch_batch.c");
    if (rc == 0)
        rc = zeb_add_path(a, "", root,
                          "/platform/modules/base/src/safe_alloc.c");
    if (rc == 0)
        rc = zeb_push_all(a, tail);
    if (rc == 0)
        rc = zeb_add_path(a, "", root, k_zeb_fixture);
    if (rc == 0)
        rc = zeb_push(a, "-o");
    if (rc == 0)
        rc = zeb_push(a, bin);
    if (rc == 0)
        rc = zeb_push_words(a, &ldflags);
    return rc;
}

/* Full gate under root: compile, then run. Returns the script's exit code. */
static int zeb_gate(const char *root)
{
    char work[ZEB_PATH], bin[ZEB_FPATH];
    int rc = zeb_scratch(work, sizeof work);
    if (rc)
        return rc;
    struct zeb_args a;
    a.n = 0;
    rc = zeb_join(bin, sizeof bin, work, "/check_zcc_epoch_batch");
    if (rc == 0)
        rc = zeb_build(&a, root, bin);
    if (rc) {
        rap_rm_rf(work);
        return rc;
    }
    char *cargv[ZEB_ARGS + 1];
    rc = zeb_argv(cargv, &a);
    int st = 0;
    if (rc == 0)
        rc = zeb_spawn(cargv, &st);
    if (rc == 0 && zeb_status(st) != 0) {
        rap_rm_rf(work);
        return zeb_status(st);
    }
    if (rc == 0) {
        char *rargv[2];
        rargv[0] = bin;
        rargv[1] = NULL;
        rc = zeb_spawn(rargv, &st);
    }
    rap_rm_rf(work);
    if (rc)
        return rc;
    return zeb_status(st);
}

int check_zcc_epoch_batch_run(int argc, char **argv)
{
    char cwd[ZEB_PATH];
    const char *root = argc >= 1 ? argv[0] : cwd;
    if (argc < 1 && !getcwd(cwd, sizeof cwd)) {
        fprintf(stderr, "%s: getcwd failed\n", k_zeb_gate);
        return 2;
    }
    return zeb_gate(root);
}
