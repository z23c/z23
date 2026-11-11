/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One semantic-facts fuzz case's working state, shared by its compile-and-sense flow (semantic_fuzz_case.c) and its plan-and-judge oracle (semantic_fuzz_oracle.c). */
#ifndef ZCL_TEST_SEMANTIC_FUZZ_CASE_PRIV_H
#define ZCL_TEST_SEMANTIC_FUZZ_CASE_PRIV_H

#include "test/semantic_fuzz.h"

#include "base/format_attribute.h"

#include <stdarg.h>

/* A sorted set of repo-relative paths. */
struct sfz_paths {
    char **v;
    size_t n, cap;
};

bool sfz_paths_add(struct sfz_paths *p, const char *path);
bool sfz_paths_has(const struct sfz_paths *p, const char *path);
void sfz_paths_sort(struct sfz_paths *p);
void sfz_paths_free(struct sfz_paths *p);

struct sfz_run {
    const struct sfz_env *env;
    const struct sfz_case *c;
    struct sfz_outcome *out;
    char tree[PATH_MAX];  /* the project the compiles and the plan see */
    char ob[PATH_MAX];    /* objects before, outside the tree */
    char oa[PATH_MAX];    /* objects after */
    char log[PATH_MAX];   /* compiler and sensor logs */
    struct sfz_paths changed; /* files that differ between the sides */
    struct sfz_paths tus;     /* src/ .c files on either side */
    bool header_changed;      /* a changed file is not a .c */
    size_t killed;            /* compile or sensor runs killed at their deadline */
    /* the whole environment of every compile, sensor and gcc run */
    char env_path[4096], env_home[PATH_MAX + 8], env_tmp[PATH_MAX + 8];
    const char *envp[5];
};

/* Append one line to out->why (bounded; the first lines win). */
void sfz_why(struct sfz_outcome *out, const char *fmt, ...) ZCL_PRINTF_LIKE(2, 3);

/* Read a whole file into a heap buffer. */
bool sfz_slurp(const char *path, uint8_t **out, size_t *len);

/* Object path <dir>/<tu>.o, preserving the full TU path; false on truncation. */
bool sfz_object(char *buf, size_t n, const char *dir, const char *tu);

/* semantic_fuzz_oracle.c: plan the changed files with the facts under
 * <tree>/facts and judge every TU's objects; fills r->out. False only when
 * the planner itself fails. */
bool sfz_plan_and_judge(struct sfz_run *r);

#endif /* ZCL_TEST_SEMANTIC_FUZZ_CASE_PRIV_H */
