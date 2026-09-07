/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_byte_order_codec_single_priv — the seam shared by
 * gate_byte_order_codec_single.c (scan-set collection and the three shape
 * detectors), gate_byte_order_codec_single_report.c (baseline, coverage
 * oracle, MODE handling and check_byte_order_codec_single_run), and
 * gate_byte_order_codec_single_selftest.c (its planted-violation and
 * coverage selftest). NOT a public header: nothing outside
 * tools/lint/lintc/ includes this.
 */
#ifndef ZCL_LINTC_GATE_BYTE_ORDER_CODEC_SINGLE_PRIV_H
#define ZCL_LINTC_GATE_BYTE_ORDER_CODEC_SINGLE_PRIV_H

#include <regex.h>
#include <stdio.h>

enum { BO_NEXCL = 3, BO_SET_MAX = 8192 };

struct bo_regexes {
    regex_t loop, bswap, flat_a, flat_b;
};

struct bo_pathset {
    char p[BO_SET_MAX][RS_PATH];
    int n;
};

int bo_excluded(const char *path);
int bo_default_roots(char out[][RS_PATH], int max, int *n);
int bo_split_ws(const char *s, char out[][RS_PATH], int max, int *n);
int bo_comp_regexes(struct bo_regexes *r);
void bo_drop_regexes(struct bo_regexes *r);
int bo_line_hits(const struct bo_regexes *r, const char *line);
int bo_detect_file(const char *path, const struct bo_regexes *r, int *hit);
int bo_collect(const char roots[][RS_PATH], int nroots, struct bo_pathset *set);
int bo_pathset_add(struct bo_pathset *set, const char *path);
int bo_pathset_has(const struct bo_pathset *set, const char *path);
void bo_pathset_sort(struct bo_pathset *set);
int bo_find_hits(const struct bo_pathset *scan, const struct bo_regexes *r,
                 struct bo_pathset *found);
int bo_pathspec_msg(const char roots[][RS_PATH], int nroots, char *out,
                    size_t cap);

/* Coverage: an independent, git-index-derived expectation for
 * SCAN_ROOTS_DEFAULT (never the possibly-overridden roots actually
 * scanned), compared against the realized scan set. missing > allowance
 * is UNPROVEN (2); missing < allowance is a stale-ratchet VIOLATION (1);
 * missing == allowance passes (0). */
int bo_coverage_check(const struct bo_pathset *scan, int allowance, FILE *err);

struct bo_eval_opts {
    char roots[256][RS_PATH];
    int nroots;
    const char *baseline;
    const char *mode;
    int floor;
    int coverage;
    int coverage_allowance;
};

int bo_eval(const struct bo_eval_opts *opts, FILE *out, FILE *err);

#endif
