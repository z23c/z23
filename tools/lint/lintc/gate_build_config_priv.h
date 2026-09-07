/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_build_config_priv — the seam between gate_build_config.c (the
 * check-tu-random-seed / check-privileged-transition-receipt /
 * check-asan-adx-exception gate bodies) and
 * gate_build_config_selftests.c (their planted-violation selftests).
 * NOT a public header: nothing outside tools/lint/lintc/ includes this.
 */

#ifndef ZCL_LINTC_GATE_BUILD_CONFIG_PRIV_H
#define ZCL_LINTC_GATE_BUILD_CONFIG_PRIV_H

#include <regex.h>
#include <stdio.h>

/* check-tu-random-seed: scans a single Makefile for the seed macro. */
int trs_check(FILE *out);

/* check-privileged-transition-receipt: full scan + env save/restore. */
int ptr_scan(const char *defdir, const char *baseline, const char *workdir,
    FILE *out, FILE *err);
int ptr_st_env(const char *defdir, const char *baseline);
int ptr_st_clear_env(int had_d, const char *oldd, int had_b, const char *oldb);

/* check-asan-adx-exception: fixture Makefile + rewrite helpers. */
const char *aae_makefile(void);
int aae_copy(const char *src, const char *dst);
int aae_rewrite_first(const char *src, const char *dst, const char *from,
    const char *to);
int aae_fail(const char *msg);

#endif
