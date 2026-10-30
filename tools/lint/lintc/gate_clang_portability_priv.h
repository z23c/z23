/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-clang-portability gate port
 * (gate_clang_portability_*.c). Ported from tools/lint/check_clang_portability.sh
 * and the parts of tools/lint/tu_result_cache.sh it uses (deleted by the
 * harness wiring). See gate_clang_portability.c for the gate description.
 */
#ifndef GATE_CLANG_PORTABILITY_PRIV_H
#define GATE_CLANG_PORTABILITY_PRIV_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stddef.h>
#include <stdio.h>

enum {
    CP_PATH = 1024,      /* a path */
    CP_LINE = 8192,      /* one log/makefile line */
    CP_MAXARGS = 1536,   /* compiler argv slots */
    CP_MAXSRC = 4096,    /* translation units in the scan set */
    CP_MAXINC = 1024,    /* include/ roots */
    CP_MAXBASE = 512,    /* baseline / scope / report rows */
    CP_MAXSITES = 4096,  /* diagnostic sites */
    CP_SHA = 65          /* sha256 hex + NUL */
};

struct cp_ctx {
    char root[CP_PATH];            /* repo root (cwd) */
    const char *cc;                /* ZCL_CC or "clang" */
    char cc_buf[CP_PATH];
    char family[8];                /* "clang" or "gcc" */
    char baseline_rel[CP_PATH];    /* tools/lint/portability_baseline.<fam>.txt */
    char work[CP_PATH];            /* scratch dir */
    char out_dir[CP_PATH];         /* per-TU artifacts */
    char flags_nul[CP_PATH];       /* flags file path */
    char makefile[CP_PATH];        /* Makefile (ZCL_..._MAKEFILE override) */
    /* repo shape */
    char product_ctxs[CP_MAXBASE][CP_PATH]; int nprod;
    char app_shapes[CP_MAXBASE][CP_PATH];   int nshape;
    char lib_modules[CP_MAXBASE][CP_PATH];   int nlib;
    char module_dirs[CP_MAXSRC][CP_PATH];    int nmod;
    /* flags */
    char flags[CP_MAXARGS][CP_PATH]; int nflags;
    /* scan set (sorted, unique, '/_' filtered) */
    char srcs[CP_MAXSRC][CP_PATH]; int nsrc;
    /* misses after cache plan */
    char miss[CP_MAXSRC][CP_PATH]; int nmiss;
    int jobs;
    int stub_cc;                   /* selftest: cc is this binary in --stub-cc mode */
    /* per-TU result cache */
    int cache_on;
    char cache_off[192];
    char cache_dir[CP_PATH];
    char events[CP_PATH];
};

/* util */
void cp_sha256_hex(const unsigned char hash[32], char out[CP_SHA]);
int  cp_sha256_data(const void *p, size_t n, char out[CP_SHA]);
/* 0 ok, 1 absent, -1 unreadable */
int  cp_sha256_file(const char *path, char out[CP_SHA]);
int  cp_spawn(const char *file, char *const argv[], const char *so,
              const char *se, int *rc);
int  cp_which(const char *cmd);
int  cp_cc_spawn(const struct cp_ctx *c, char *const tail[], const char *so,
                const char *se, int *rc);
int  cp_version_line(const struct cp_ctx *c, const char *capture, char *out,
                     size_t cap);
void cp_key(const char *src, char *out, size_t cap);
int  cp_first_line(const char *path, char *out, size_t cap);
int  cp_makefile_list(const char *mk, const char *var,
                      char out[][CP_PATH], int max);
int  cp_find_includes(const char *const roots[], int nroots,
                      char out[][CP_PATH], int max);
int  cp_collect_c(const char *dir, char arr[][CP_PATH], int max, int *n);
void cp_sort_uniq(char *arr, size_t width, int *n);
int  cp_mkdirs(const char *path);
int  cp_regcomp(regex_t *re, const char *pat, int flags);
int  cp_file_eq(const char *a, const char *b);
int  cp_appendf(const char *path, const char *fmt, ...);
int  cp_touch(const char *path);
int  cp_count_lines(const char *path);
int  cp_mkscratch(char *out, size_t cap, const char *tag);

/* scan */
int  cp_shape_init(struct cp_ctx *c);
int  cp_build_flags(struct cp_ctx *c);
int  cp_scan_sources(struct cp_ctx *c);
int  cp_coverage(struct cp_ctx *c);

/* cache */
int  cp_include_digest(const char *scratch, const char *root,
                       const char *vanish, char out[CP_SHA]);
int  cp_cache_setup(struct cp_ctx *c, const char *cachedir, const char *root);
int  cp_cache_plan(struct cp_ctx *c);
int  cp_compile_misses(struct cp_ctx *c);
int  cp_cache_summary(const struct cp_ctx *c);
int  cp_compile_one(struct cp_ctx *c, const char *src);

/* run-internal, shared with the selftest */
int  cp_gate_body(struct cp_ctx *c, int argc, char **argv);
int  cp_compiler_result_proven(const char *log, int rc);
int  cp_stub_cc_main(int argc, char **argv);
int  cp_ctx_open(struct cp_ctx *c, int *skip);

/* snprintf into an array; an overflow is reported loudly by ovf(). */
#define cps_snp(buf, ...) \
    ovf(snprintf((buf), sizeof(buf), __VA_ARGS__), sizeof(buf))

/* selftest */
int  cps_static_write(const char *path, const char *text);
int  cp_digest_selftest(const char *scratch);
int  cp_tu_cache_selftest(struct cp_ctx *c, const char *self, const char *real_src);

#endif
