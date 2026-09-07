/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_hotswap_package_receipt_is_not_authority_priv — the seam between
 * gate_hotswap_package_receipt_is_not_authority.c (the gate body) and
 * gate_hotswap_package_receipt_is_not_authority_selftest.c (its planted-
 * violation selftest). NOT a public header: nothing outside
 * tools/lint/lintc/ includes this.
 */
#ifndef ZCL_LINTC_GATE_HPR_PRIV_H
#define ZCL_LINTC_GATE_HPR_PRIV_H

#include <stdio.h>

struct hpr_ctx {
    const char *src_dir, *inc_dir, *pkg_tool;
    FILE *out, *err;
    int scanned_src, scanned_inc;
};

int hpr_run_checks(struct hpr_ctx *c);
int hpr_list_dir(const char *dir, const char *const *exts, int nexts,
                 char out[][RS_PATH], int cap, int *n);

#endif
