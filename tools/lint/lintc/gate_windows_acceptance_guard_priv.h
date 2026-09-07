/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface between gate_windows_acceptance_guard.c and
 * its selftest sibling gate_windows_acceptance_guard_selftest.c — not
 * listed in lintc.h, which declares only lib.c helpers and gate entry
 * points shared across families.
 */
#ifndef GATE_WINDOWS_ACCEPTANCE_GUARD_PRIV_H
#define GATE_WINDOWS_ACCEPTANCE_GUARD_PRIV_H

#include <stdio.h>
#include "lintc.h"

enum { WAG_ROWS_PRIV = 512 };
struct wag_paths { char v[WAG_ROWS_PRIV][RS_PATH]; int n; };

extern const char k_wag_catalog_rel[];
extern const char k_wag_harness_dir_rel[];

int wag_catalog_sources(const char *path, struct wag_paths *out);
int wag_scan_root(const char *root, FILE *out);

#endif
