/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Pinned compile-profile helpers; see fixed_result_profile.h. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "verify/fixed_result_profile.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"

#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRP_TAG "@CWD@"
#define FRP_LINES_MAX (1u << 20)

bool frp_lines_add(struct frp_lines *l, const char *text)
{
    char **grown;
    char *copy;
    if (l->n >= FRP_LINES_MAX) return false;
    grown = zcl_realloc(l->v, (l->n + 1u) * sizeof *grown, "frp_lines");
    if (!grown) return false;
    l->v = grown;
    copy = strdup(text);
    if (!copy) return false;
    l->v[l->n++] = copy;
    return true;
}

void frp_lines_free(struct frp_lines *l)
{
    for (size_t i = 0; i < l->n; ++i) free(l->v[i]);
    free(l->v);
    l->v = nullptr;
    l->n = 0;
}

bool frp_lines_load(const char *path, struct frp_lines *out)
{
    FILE *f = fopen(path, "rb");
    char *buf = nullptr;
    size_t cap = 0;
    ssize_t n;
    bool ok = f != nullptr;
    while (ok && (n = getline(&buf, &cap, f)) >= 0) {
        if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = '\0';
        ok = frp_lines_add(out, buf);
    }
    ok = ok && f && !ferror(f);
    free(buf);
    if (f) fclose(f);
    pu_poll_signal();
    return ok;
}

static char *frp_expand_one(const char *arg, const char *cwd)
{
    size_t tags = 0, tlen = strlen(FRP_TAG), clen = strlen(cwd);
    for (const char *p = arg; (p = strstr(p, FRP_TAG)); p += tlen) ++tags;
    size_t cap = strlen(arg) + tags * clen + 1u;
    char *out = zcl_malloc(cap, "frp_expand"), *w = out;
    if (!out) return nullptr;
    for (const char *p = arg, *hit; ; p = hit + tlen) {
        hit = strstr(p, FRP_TAG);
        if (!hit) {
            size_t room = cap - (size_t)(w - out);
            if (snprintf(w, room, "%s", p) >= (int)room) {
                free(out);
                return nullptr;
            }
            return out;
        }
        memcpy(w, p, (size_t)(hit - p));
        w += hit - p;
        memcpy(w, cwd, clen);
        w += clen;
    }
}

bool frp_expand(const struct frp_lines *in, size_t count, const char *cwd,
                struct frp_lines *out)
{
    for (size_t i = 0; i < count && i < in->n; ++i) {
        char *line = frp_expand_one(in->v[i], cwd);
        bool ok = line && frp_lines_add(out, line);
        free(line);
        if (!ok) return false;
    }
    return true;
}

bool frp_glob(const char *text, const char *pattern)
{
    return fnmatch(pattern, text, 0) == 0;
}

bool frp_sha3_file(const char *path, char out[65])
{
    unsigned char buf[8192], digest[32];
    struct sha3_256_ctx ctx;
    FILE *f = fopen(path, "rb");
    size_t n;
    out[0] = '\0';
    if (!f) return false;
    sha3_256_init(&ctx);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        sha3_256_write(&ctx, buf, n);
    bool ok = !ferror(f);
    fclose(f);
    sha3_256_finalize(&ctx, digest);
    for (size_t i = 0; i < 32u; ++i) snprintf(out + 2u * i, 3u, "%02x", digest[i]);
    pu_poll_signal();
    return ok;
}

/* The logical working directory: $PWD when it names this directory. */
static bool frp_logical_cwd_physical(const char *physical)
{
    const char *logical = getenv("PWD");
    struct stat a, b;
    if (!logical || logical[0] != '/' || stat(logical, &a) != 0 ||
        stat(".", &b) != 0 || a.st_dev != b.st_dev || a.st_ino != b.st_ino)
        return true;
    return strcmp(logical, physical) == 0;
}

const char *frp_checkout(char *repo, size_t cap)
{
    char cwd[PU_PATH_MAX];
    if (!pu_repo_root(repo, cap)) exit(128);
    if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, repo) != 0 ||
        !frp_logical_cwd_physical(cwd))
        return "physical_cwd_mismatch";
    return nullptr;
}

long long frp_size(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? (long long)st.st_size : -1;
}

void frp_env_argv(struct pu_argv *a, const struct frp_lines *args)
{
    static const char *const head[] = {
        "env", "-i", "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp",
        "PATH=/usr/bin:/bin", nullptr};
    pu_argv_addv(a, head);
    for (size_t i = 0; i < args->n; ++i) pu_argv_add(a, args->v[i]);
}

static double frp_seconds(struct timeval tv)
{
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static int frp_run_in(const char *dir, const struct pu_argv *a, const char *out,
                  const char *err)
{
    int back = dir ? open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
    int rc;
    if (dir && (back < 0 || chdir(dir) != 0)) {
        if (back >= 0) close(back);
        return -1;
    }
    rc = pu_run(a, out, err);
    if (back >= 0) {
        if (fchdir(back) != 0) rc = -1;
        close(back);
    }
    return rc;
}

int frp_run(const char *dir, const struct pu_argv *a, const char *out,
            const char *err, struct frp_timing *t)
{
    struct rusage before, after;
    long long start = pu_now_ns();
    getrusage(RUSAGE_CHILDREN, &before);
    int rc = frp_run_in(dir, a, out, err);
    getrusage(RUSAGE_CHILDREN, &after);
    if (t) {
        t->wall = (double)(pu_now_ns() - start) / 1e9;
        t->user = frp_seconds(after.ru_utime) - frp_seconds(before.ru_utime);
        t->sys = frp_seconds(after.ru_stime) - frp_seconds(before.ru_stime);
    }
    return rc;
}

static bool frp_selftest_load(const char *path)
{
    struct frp_lines l = {.v = nullptr, .n = 0};
    FILE *f = fopen(path, "wb");
    if (!f || fputs("a\n@CWD@/b\n\nc@CWD@d@CWD@", f) == EOF || fclose(f) != 0)
        return false;
    bool ok = frp_lines_load(path, &l) && l.n == 4u &&
              strcmp(l.v[0], "a") == 0 && l.v[2][0] == '\0' &&
              strcmp(l.v[3], "c@CWD@d@CWD@") == 0;
    frp_lines_free(&l);
    return ok;
}

static bool frp_selftest_expand(const char *path)
{
    struct frp_lines l = {.v = nullptr, .n = 0}, x = {.v = nullptr, .n = 0};
    bool ok = frp_lines_load(path, &l) && frp_expand(&l, 3u, "/r", &x) &&
              x.n == 3u && strcmp(x.v[1], "/r/b") == 0;
    frp_lines_free(&x);
    ok = ok && frp_expand(&l, 4u, "/r", &x) && strcmp(x.v[3], "c/rd/r") == 0;
    frp_lines_free(&x);
    frp_lines_free(&l);
    return ok;
}

static bool frp_selftest_lines(const char *dir)
{
    struct frp_lines l = {.v = nullptr, .n = 0};
    const char *path = pu_at(dir, "lines");
    bool ok = frp_selftest_load(path) && frp_selftest_expand(path);
    FILE *f = fopen(path, "wb");
    ok = ok && f && fclose(f) == 0 && frp_lines_load(path, &l) && l.n == 0u &&
         !frp_lines_load(pu_at(dir, "absent"), &l);
    frp_lines_free(&l);
    return ok;
}

static bool frp_selftest_hash(const char *dir)
{
    char hex[65];
    const char *path = pu_at(dir, "empty");
    FILE *f = fopen(path, "wb");
    if (!f || fclose(f) != 0) return false;
    return frp_sha3_file(path, hex) &&
           strcmp(hex, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a") == 0 &&
           !frp_sha3_file(pu_at(dir, "absent"), hex);
}

static bool frp_selftest_glob(void)
{
    return frp_glob("build/obj/epochs/aa/bb/x/result.o", "build/obj/epochs/*/x/result.o") &&
           !frp_glob("build/obj/epochs//y/result.o", "build/obj/epochs/*/x/result.o") &&
           !frp_glob("xbuild/obj/epochs/a/x/result.o", "build/obj/epochs/*/x/result.o");
}

static bool frp_selftest_run(const char *dir)
{
    struct pu_argv a = {.n = 0};
    struct frp_timing t = {0, 0, 0};
    struct frp_lines args = {.v = nullptr, .n = 0};
    const char *out = pu_at(dir, "env.out");
    bool ok = frp_lines_add(&args, "sh") && frp_lines_add(&args, "-c") &&
              frp_lines_add(&args, "echo \"$LC_ALL $TZ $TMPDIR $PATH $HOME-\"; pwd");
    frp_env_argv(&a, &args);
    char want[PU_PATH_MAX];
    snprintf(want, sizeof want, "%s", dir);
    ok = ok && frp_run(dir, &a, out, nullptr, &t) == 0 &&
         pu_has_line(out, "C UTC /tmp /usr/bin:/bin -") && pu_has_line(out, want) &&
         t.wall >= 0.0 && t.user >= 0.0 && t.sys >= 0.0;
    frp_lines_free(&args);
    return ok;
}

int frp_selftest(void)
{
    char dir[PU_PATH_MAX];
    if (!pu_scratch_make("/tmp/z23-profile-selftest.XXXXXX", dir, sizeof dir)) {
        puts("fixed_result_profile_selftest=FAIL");
        return 1;
    }
    char phys[PU_PATH_MAX];
    bool ok = realpath(dir, phys) && strcmp(phys, dir) == 0 &&
              frp_selftest_lines(dir) && frp_selftest_hash(dir) && frp_selftest_glob() &&
              frp_selftest_run(dir) && frp_size(pu_at(dir, "lines")) == 0 &&
              frp_size(pu_at(dir, "absent")) == -1;
    pu_scratch_remove(dir);
    puts(ok ? "fixed_result_profile_selftest=PASS"
            : "fixed_result_profile_selftest=FAIL");
    return ok ? 0 : 1;
}
