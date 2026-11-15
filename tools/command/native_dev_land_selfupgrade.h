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
    ZCL_LAND_SU_ERROR = 0, /* unusable or uncertain state: reconcile before reuse */
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

/* Run current and candidate only with dev land decision --seq=<positive decimal>
 * and optional --json. Compare typed decisions; distinct increasing sequences
 * count once. Switch after need_rows consecutive agreeing rows. */
enum zcl_land_selfupgrade_verdict
zcl_land_selfupgrade_observe(const char *root, const char *current_bin,
                             const char *sha, const char *const *args,
                             int need_rows);

/* Report the outcome of the row a switched pointer just ran. A failed row
 * restores the previous pointer; a good row confirms the switch. Returns
 * true when the pointer was restored. */
bool zcl_land_selfupgrade_row_result(const char *root, bool row_ok);

/* A locator for existing signed proof evidence, not another proof authority. */
struct zcl_land_selfupgrade_binding {
    char commit[41];
    char base[41];
    char proof_root[ZCL_LAND_SELFUPGRADE_PATH_MAX];
};

/* Install bytes already admitted into a sealed Linux descriptor, retain their
 * exact proof locator, and remember the candidate for later shadow rows. */
bool zcl_land_selfupgrade_prepare(const char *root,
    const struct zcl_land_selfupgrade_binding *binding, int sealed_fd);
bool zcl_land_selfupgrade_binding_read(const char *root, bool pending,
    struct zcl_land_selfupgrade_binding *binding);

/* Compare complete responses captured from admitted descriptors. The caller
 * revalidates the selected row before executing it under the drive lock. */
enum zcl_land_selfupgrade_verdict zcl_land_selfupgrade_observe_captured(
    const char *root, const char *sha, long long seq, const char *current,
    const char *candidate, int need_rows);
/* Recovery never retries a row. It restores the previous pointer and lets
 * the existing queue/outcomes decide which work remains. */
bool zcl_land_selfupgrade_recover(const char *root);
/* Bind the real row before any trial execution. Shadow observations do not
 * supply execution identity. A failed write requires recovery, not execution. */
bool zcl_land_selfupgrade_bind_trial(const char *root, const char *sha,
    long long seq, const char *row_sha3);
bool zcl_land_selfupgrade_trial_matches(const char *root, const char *sha,
    long long seq, const char *row_sha3);
bool zcl_land_selfupgrade_finish(const char *root, const char *sha,
    long long seq, const char *row_sha3, bool row_ok);

#if defined(ZCL_TESTING) && !defined(_WIN32)
/* Inject a finish-only directory-sync failure after the state rename. */
void zcl_land_selfupgrade_test_finish_sync_failure(bool fail);
#endif

#endif
