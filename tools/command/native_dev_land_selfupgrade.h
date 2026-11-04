/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land driver self-upgrade -- slot pointer and decision compare.
 *          See native_dev_land_selfupgrade.c for the design. */

#ifndef ZCL_NATIVE_DEV_LAND_SELFUPGRADE_H
#define ZCL_NATIVE_DEV_LAND_SELFUPGRADE_H

#include <stdbool.h>
#include <stddef.h>

#define ZCL_LAND_SELFUPGRADE_ENV "ZCL_LAND_SELFUPGRADE"
#define ZCL_LAND_SELFUPGRADE_AGREE_ROWS 3
#define ZCL_LAND_SELFUPGRADE_ARGS_MAX 8
#define ZCL_LAND_SELFUPGRADE_PATH_MAX 1024

enum zcl_land_selfupgrade_verdict {
    ZCL_LAND_SU_ERROR = 0, /* unusable candidate or state: nothing changed */
    ZCL_LAND_SU_AGREE,     /* decisions matched; counted, not yet switched */
    ZCL_LAND_SU_DISAGREE,  /* decisions differ or are empty; count reset */
    ZCL_LAND_SU_SWITCHED   /* pointer now names the candidate (trial row) */
};

/* True only when the operator set ZCL_LAND_SELFUPGRADE=1. Default off. */
bool zcl_land_selfupgrade_enabled(void);

/* True when a newline-separated path list (git diff --name-only) names a
 * file of the driver's own sources. */
bool zcl_land_selfupgrade_touches_driver(const char *paths);

/* <root>/slots/<sha>/z23-dev for a 40-char lowercase hex sha; else false. */
bool zcl_land_selfupgrade_slot_path(const char *root, const char *sha,
                                    char *out, size_t cap);

/* Copy src into the slot for sha (content-addressed; an existing slot is
 * kept untouched). The slot appears by rename, never half written. */
bool zcl_land_selfupgrade_slot_install(const char *root, const char *sha,
                                       const char *src);

/* The path <root>/current points at, or false when no pointer is set. */
bool zcl_land_selfupgrade_pointer_read(const char *root, char *out,
                                       size_t cap);

/* Run current and the slot candidate for sha on the same read-only decision
 * args (NULL-terminated, at most ARGS_MAX) and compare. Switch the pointer
 * after AGREE_ROWS consecutive agreeing rows. */
enum zcl_land_selfupgrade_verdict
zcl_land_selfupgrade_observe(const char *root, const char *current_bin,
                             const char *sha, const char *const *args,
                             int need_rows);

/* Report the outcome of the row a switched pointer just ran. A failed row
 * restores the previous pointer; a good row confirms the switch. Returns
 * true when the pointer was restored. */
bool zcl_land_selfupgrade_row_result(const char *root, bool row_ok);

#endif
