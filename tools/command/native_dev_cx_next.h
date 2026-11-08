/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the in-process entry to dev.cx.next's selection, so another leaf
 *          (the objectives brief) picks its complexity file by the same rules
 *          instead of keeping its own: sealed, custody, packages, 1300 or more
 *          lines, files a live worktree changes against origin/main, and the
 *          exclude list. The caller adds only its own filter and order. */

#ifndef ZCL_NATIVE_DEV_CX_NEXT_H
#define ZCL_NATIVE_DEV_CX_NEXT_H

#include "command/native_dev_cx.h"

#include <stdbool.h>
#include <stddef.h>

struct zcl_cx_pick_in {
    const char *repo;        /* a path inside the checkout (cwd) */
    const char *baseline;    /* baseline file; NULL = repo/ZCL_CX_BASELINE_REL */
    const char *exclude_csv; /* comma list of excluded files, or NULL */
    /* The caller's own filter (NULL = none): false skips the file. */
    bool (*allow)(const char *file, void *ctx);
    void *allow_ctx;
    /* false (dev cx next): fewest functions first, then lowest max score,
     * then path. true (the brief): files of 3 to 6 functions first, then,
     * inside and outside that band alike, lowest max score, then path; the
     * function count itself does not rank. */
    bool pin_band;
    const char *baseline_bytes; /* optional borrowed baseline snapshot */
    size_t baseline_len;
    int (*count_lines)(const char *file, void *ctx); /* -1 = unavailable */
    void *count_lines_ctx;
};

struct zcl_cx_pick_out {
    char file[ZCL_CX_FILE_MAX];
    int pins;      /* baseline rows of the file */
    int max_score; /* highest score among them */
};

/* 0 found (out filled), 1 no file is eligible, -1 on any failure: not a
 * checkout, no origin/main, unreadable baseline, a worktree that cannot be
 * compared, or out of memory. An unknown is never read as clean. */
int zcl_dev_cx_pick(const struct zcl_cx_pick_in *in,
                    struct zcl_cx_pick_out *out);

#endif
