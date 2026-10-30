/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check_identity_parser_single gate port
 * (gate_identity_parser_single.c + gate_identity_parser_single_scan.c) and
 * its selftest (gate_identity_parser_single_selftest.c). Ported from
 * tools/lint/check_identity_parser_single.sh (deleted).
 */
#ifndef GATE_IDENTITY_PARSER_SINGLE_PRIV_H
#define GATE_IDENTITY_PARSER_SINGLE_PRIV_H

#include <stdio.h>
#include <stddef.h>

enum {
    IPS_PATH = 1024,
    IPS_LINE = 8192,
    IPS_MAXFILES = 4096,
    IPS_MAXROWS = 4096,
    IPS_MAXMFILES = 64,
    IPS_MAXBASE = 512,
    IPS_MAXMSG = 2048,
    IPS_MAXV = 512,
    IPS_MAXALLOW = 16,
    IPS_BODY_LIMIT = 5,
    IPS_MARKER_WINDOW = 8,
};

/* Full gate configuration. run() fills it from the environment exactly as
 * the shell script read its ZCL_IDENTITY_PARSER_* variables; the selftest
 * fills it directly for the sandbox (the shell selftest ran the script as a
 * subprocess with those variables exported). out/err let the selftest
 * silence the sandbox runs the way the shell did >/dev/null 2>&1. */
struct ips_cfg {
    const char *mode;         /* FAIL | WARN | UPDATE */
    const char *baseline_path;
    const char *scan_root;
    int ceiling;              /* ZCL_IDENTITY_PARSER_CEILING (default 16) */
    int marker_ceiling;       /* default 1 */
    int file_floor;           /* default 5 */
    const char *const *marker_allowed;
    size_t nmarker_allowed;
    FILE *out;
    FILE *err;
};

struct ips_row {              /* one scanned file carrying >= 1 copy */
    char path[IPS_PATH];
    int debt;
};

struct ips_scanres {
    char files[IPS_MAXFILES][IPS_PATH];   /* sorted scan set (.sh files) */
    size_t nfiles;
    struct ips_row rows[IPS_MAXROWS];     /* files with debt > 0 */
    size_t nrows;
    char mfiles[IPS_MAXMFILES][IPS_PATH]; /* files carrying the marker */
    int mcount[IPS_MAXMFILES];
    size_t nm;
    int marker_total;
};

extern const char k_ips_gate[];

int ips_run_cfg(const struct ips_cfg *cfg);
int ips_scan_all(const struct ips_cfg *cfg, struct ips_scanres *r);

#endif
