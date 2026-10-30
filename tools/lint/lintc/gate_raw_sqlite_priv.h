/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-raw-sqlite gate port
 * (gate_raw_sqlite.c, gate_raw_sqlite_exec.c, gate_raw_sqlite_ctx.c,
 * gate_raw_sqlite_selftest.c). Ported from tools/scripts/check_raw_sqlite.sh
 * (deleted). See gate_raw_sqlite.c for the full rationale.
 */
#ifndef GATE_RAW_SQLITE_PRIV_H
#define GATE_RAW_SQLITE_PRIV_H

#include <regex.h>

enum {
    CRS_PATH = 1024,
    CRS_LINE = 8192,
    CRS_CHUNK = 16384,
    CRS_ROWS = 256,
    CRS_ROW = 9216,
    CRS_ACC = 1 << 20,
    CRS_ROOMS = 64,
    CRS_FATAL = 2,
    CRS_PROD_ROOTS = 6
};

/* Collected violation rows, printed verbatim on FAIL. Fixed capacity; on
 * overflow the overflow flag is set and the run exits 2 rather than
 * silently dropping a violation. */
struct crs_viol {
    char row[CRS_ROWS][CRS_ROW];
    int n;
    int overflow;
};

/* Context for the raw step scan: where violations go, the whole-file
 * allowlist, and the running count of allowlisted call sites. */
struct crs_raw_ctx {
    struct crs_viol *v;
    const struct bln_set *allowed;
    int *allowed_total;
};

typedef int (*crs_file_fn)(const char *path, void *ctx);

extern const char *const k_crs_prod_roots[CRS_PROD_ROOTS];

int crs_viol_add(struct crs_viol *v, const char *fmt, ...);
int crs_walk(const char *dir, int prune_noise, crs_file_fn fn, void *ctx);
int crs_rx(const regex_t *re, const char *s, regmatch_t *m, int flags);
void crs_chomp(char *s);
int crs_overlong(const char *s);
int crs_ends_c(const char *path);
int crs_ends_ch(const char *path);

int crs_raw_init(void);
int crs_exec_init(void);
/* ctx is a struct crs_raw_ctx pointer. */
int crs_raw_file(const char *path, void *ctx);
/* ctx is a struct crs_viol pointer. */
int crs_exec_file(const char *path, void *ctx);
int crs_ctx_file(const char *path, struct crs_viol *v);

int crs_scan_kernel(int *total);
int crs_scan_exec(struct crs_viol *v);
int crs_scan_context(struct crs_viol *v);

#endif
