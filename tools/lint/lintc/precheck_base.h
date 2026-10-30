/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the shared base tree behind `z23-lint precheck` without --base.
 * precheck_base_open resolves merge-base(HEAD, origin/main) in the current
 * tree, takes an exclusive flock on <cache>/base.lock (held until
 * precheck_base_close), and leaves <cache>/base-tree checked out detached at
 * that sha. <cache> is $ZCL_PRECHECK_CACHE, default
 * $HOME/.cache/development-scratch/z23/precheck. Base gate results are kept in
 * <cache>/base-native-<sha>.txt, one `gate rc` line each.
 */
#ifndef LINTC_PRECHECK_BASE_H
#define LINTC_PRECHECK_BASE_H

#include <limits.h>
#include <stddef.h>

struct precheck_base {
    int lock_fd;
    char sha[72];
    char tree[PATH_MAX];
    char results[PATH_MAX];
};

/* 0 on success; else 2 with a one-line reason in why (no newline). */
int precheck_base_open(struct precheck_base *b, char *why, size_t wcap);
void precheck_base_close(struct precheck_base *b);
/* 0 and *rc when the cached results hold gate name, else 1. */
int precheck_base_lookup(const struct precheck_base *b, const char *name,
                         int *rc);
/* Adds the gates the file lacks (temp file + rename). 0 on success. */
int precheck_base_store(const struct precheck_base *b,
                        const char *const *names, const int *rcs, size_t n);
/* git with an argv array (NULL-terminated args), run in dir (NULL = cwd).
 * stdout goes to out (NUL-terminated, trailing whitespace trimmed; out may be
 * NULL); stderr is discarded. Returns the exit code, -1 on spawn failure. */
int precheck_base_git(const char *dir, const char *const *args, char *out,
                      size_t cap);

#endif
