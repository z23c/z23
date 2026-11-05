/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Expected per-group wall seconds that order the parallel test
 *          runner's dispatch longest-first. Ordering only: a weight never
 *          selects, skips, merges, retimes or isolates a group. */

#ifndef ZCL_TEST_GROUP_WEIGHTS_H
#define ZCL_TEST_GROUP_WEIGHTS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The tracked weights file, relative to the checkout root the runner runs
 * from. It is plain text (one "full_id<TAB>seconds" row per line, '#'
 * comments) read at run time, so regenerating it changes no binary and no
 * test-cache key. A fresh proof generation carries it like any tracked file. */
#define ZCL_TEST_GROUP_WEIGHTS_PATH "tools/dev/test_group_weights.tsv"

/* Groups measured below this many seconds are left out of the file; an
 * absent group weighs 0 and keeps its catalog position among the zeros. */
#define ZCL_TEST_GROUP_WEIGHT_MIN_SECONDS 5u

/* A row claiming more than a day is malformed and weighs 0. */
#define ZCL_TEST_GROUP_WEIGHT_MAX_SECONDS 86400u

/* Fill out[i] with the expected seconds of catalog row i for i < n and
 * return how many rows were applied. Every group starts at 0. A missing or
 * unreadable file, a malformed line, an unknown id, or an n that is not the
 * catalog's row count leaves the affected weights at 0: weights never fail a
 * run. A repeated id takes its last row. */
size_t zcl_test_group_weights_read(const char *path, unsigned *out, size_t n);

/* Write the dispatch permutation of 0..n-1 into order[]: descending weight,
 * ties in ascending index (catalog) order. NULL weights, or all-zero weights,
 * give the identity -- plain catalog order. */
void zcl_test_group_order_longest_first(const unsigned *weights, size_t n,
                                        size_t *order);
/* Order-only historical hint: priority first, then the existing longest-first
 * stable order. NULL priority exactly preserves the original ordering. */
void zcl_test_group_order_failure_first(const unsigned *weights,
                                        const bool *priority, size_t n,
                                        size_t *order);

/* Regenerate the weights file from a zcl.test_timing.v1 artifact
 * (.cache/test-timing/last-run.json). Refuses, writing nothing, unless the
 * artifact is a cold run that measured at least half of the catalog, so a
 * focused run can never silently drop the weights of groups it did not run.
 * Rows are emitted in catalog order for stable diffs: registered, measured,
 * uncached, rc 0, rounded to at least ZCL_TEST_GROUP_WEIGHT_MIN_SECONDS.
 * On refusal `why` names the reason. */
bool zcl_test_group_weights_render(const char *timing_path,
                                   const char *out_path, size_t *rows_out,
                                   char *why, size_t why_len);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_TEST_GROUP_WEIGHTS_H */
