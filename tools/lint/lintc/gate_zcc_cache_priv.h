/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations of the check-zcc-cache gate family (driver,
 * process and file helpers, and the fixture sections run in order).
 */
#ifndef GATE_ZCC_CACHE_PRIV_H
#define GATE_ZCC_CACHE_PRIV_H

#include <stddef.h>
#include <sys/types.h>

enum { ZC_PATH = 4096, ZC_LINE = 1024, ZC_OUT = 16384, ZC_SHA = 65 };

struct zc_state {
    char work[ZC_PATH];  /* physical scratch directory */
    char zcc[ZC_PATH];   /* bootstrapped compile-cache wrapper */
    char log[ZC_PATH];   /* the shared ZCC_LOG */
    char root[ZC_PATH];  /* repository root (the working directory) */
    char sha_a[ZC_SHA];  /* bytes of the cold build, compared later */
    int failures;
    int overflow;
};
extern struct zc_state zc;

/* One child process. NULL argv entries end the vector; env entries are
 * "K=V" to set or "K" to unset (NULL env keeps the environment). out
 * captures stdout (NULL discards it unless outf or keep_out). */
struct zc_cmd {
    const char *cwd;
    const char *const *argv;
    const char *const *env;
    char *out;
    size_t cap;
    const char *outf;
    const char *errf;
    const char *inf;
    int merge;    /* stderr follows stdout */
    int keep_out; /* leave stdout inherited */
};

#define ZC_ARGV(...) ((const char *const[]){ __VA_ARGS__, NULL })
#define ZC_ENV(...) ((const char *const[]){ __VA_ARGS__, NULL })

/* Formatted strings in a rotating pool; zcw prefixes the work directory. */
const char *zcf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
const char *zcw(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void zc_fail(const char *msg);
int zc_want(int cond, const char *msg);

pid_t zc_start(const struct zc_cmd *c);
int zc_wait(pid_t pid);
int zc_run(const struct zc_cmd *c);
/* stdout discarded, stderr to errf (NULL: inherited); exit code. */
int zc_x(const char *const *argv, const char *const *env, const char *errf);

int zc_line_with_prefix(const char *path, const char *prefix);
int zc_exists(const char *path);
int zc_nonempty(const char *path);
int zc_same(const char *a, const char *b);
int zc_copy(const char *src, const char *dst, int keep_time);
int zc_touch_ref(const char *ref, const char *dst);
int zc_touch_now(const char *path);
int zc_lines(const char *path);
int zc_put(const char *name, const char *text);
/* mkdtemp under $TMPDIR (template ends XXXXXX) into zc.work; 0 ok. */
int zc_mkwork(const char *tmpl);
/* uname -s equals sysname. */
int zc_on(const char *sysname);
int zc_sha(const char *path, char out[ZC_SHA]);
int zc_prog_out(const char *prog, char *out, size_t cap);
int zc_prog_is(const char *prog, const char *want);
int zc_which(const char *name, char *out, size_t cap);
const char *zc_zd(const char *name); /* "ZCC_DIR=<work>/name" env entry */
void zc_str(char *dst, size_t cap, const char *src);
void zc_append(char *dst, size_t cap, const char *sep, const char *s, size_t n);
int zc_sed_first(const char *src, const char *dst, const char *from,
                 const char *to);
int zc_find_suffix(const char *dir, const char *suffix, char *out, size_t cap);
int zc_lookup_after(const char *log, int after, const char *reason);

/* Last-line disposition of a zcc log against the wanted first token. */
int zc_disp_in(const char *log, const char *want, const char *msg);
int zc_disp_not_in(const char *log, const char *unwanted, const char *msg);
int zc_disp(const char *want, const char *msg);

/* Fixture build of main.c; env may override. 0 ok, 1 compile failed. */
int zc_build(const char *label, const char *const *env, char sha[ZC_SHA]);
int zc_stage_build(const char *tag, const char *const *env, char sha[ZC_SHA]);

/* Sections: 0 continue, nonzero stop with exit 1. */
int zc_sec_basic(void);
int zc_sec_header(void);
int zc_sec_envfilter(void);
int zc_sec_compilerversion(void);
int zc_sec_truncated(void);
int zc_sec_racing(void);
int zc_sec_verified(void);
int zc_sec_optional(void);
int zc_sec_search(void);
int zc_sec_explicit(void);
int zc_sec_stage(void);
int zc_sec_artifacts(void);
int zc_sec_rsp(void);
int zc_sec_epoch(void);
int zc_sec_unkey(void);
int zc_sec_envkey(void);
int zc_sec_linux(void);
int zc_sec_apple(void);
int zc_sec_named(void);
int zc_sec_archive(void);
int zc_sec_flight(void);
int zc_sec_boot(void);

#endif
