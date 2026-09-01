/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: internal contract for the exporter's on-disk bundle GENERATIONS —
 * the "consensus-state-bundle-<height>.sqlite" filename convention, the newest-
 * generation scan, and the keep-N retention rotation — shared between
 * engine/composition/src/bundle_exporter_generations.c (the directory work) and
 * engine/composition/src/bundle_exporter.c (the standing exporter that drives it).
 *
 * Split out of engine/composition/src/bundle_exporter.c when that file passed its shape
 * ceiling. Non-Windows only: engine/composition/src/bundle_exporter.c refuses every export
 * and retention entry point on Windows before a pathname is ever opened.
 */

#ifndef ZCL_BUNDLE_EXPORTER_GENERATIONS_INTERNAL_H
#define ZCL_BUNDLE_EXPORTER_GENERATIONS_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

/* ── Filename convention ────────────────────────────────────────── */

#define BX_BUNDLE_PREFIX "consensus-state-bundle-"
#define BX_BUNDLE_SUFFIX ".sqlite"
#define BX_MAX_GENERATIONS 256

struct bx_gen {
    long h;
    char name[128];
};

/* Parse "consensus-state-bundle-<N>.sqlite" -> height. */
bool bx_parse_bundle_height(const char *name, long *out);

/* Highest bundle height present in `dir` and the mtime (µs) of that newest
 * generation; -1 when none / dir unreadable. `out_mtime_us` may be NULL. */
int32_t bx_scan_newest(const char *dir, int64_t *out_mtime_us);

/* qsort comparator: generations by height, DESCENDING. */
int bx_gen_cmp_desc(const void *a, const void *b);

/* Keep the `keep` newest bundles; deregister-then-unlink older ones, and only
 * after the newest independently re-validates. */
void bx_rotate(const char *dir, int keep, const char *datadir);

#endif /* ZCL_BUNDLE_EXPORTER_GENERATIONS_INTERNAL_H */
