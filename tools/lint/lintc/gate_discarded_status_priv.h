/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check_discarded_status gate port
 * (gate_discarded_status.c + gate_discarded_status_selftest.c).
 * Ported from tools/lint/check_discarded_status.sh (deleted).
 */
#ifndef GATE_DISCARDED_STATUS_PRIV_H
#define GATE_DISCARDED_STATUS_PRIV_H

#include <stddef.h>
#include <stdio.h>

enum {
    CDS_PATH = 1024,     /* max path length */
    CDS_LINE = 4096,     /* max source line length */
    CDS_SRCN = 8192,     /* max lines per file (lookahead table) */
    CDS_LOGICAL = 65536, /* max joined logical line */
    CDS_NST = 4096,       /* max statements per logical line */
    CDS_ROWS = 512,      /* max violations per prong */
    CDS_ROW = 1200,      /* max formatted violation row */
    CDS_NAME = 128,      /* max heredoc delimiter */
    CDS_SEG = 2048,      /* working copy of a pipe segment */
    CDS_FILES = 4096,    /* max scanned files */
    CDS_NAMES = 1024,    /* max glob matches */
    CDS_NAMELEN = 256    /* max glob entry name */
};

/* Violations, pre-formatted as "path:line - excerpt" (em dash), split by
 * prong exactly like the shell original's neg[]/mkpipe[] arrays. */
struct cds_rows {
    char neg[CDS_ROWS][CDS_ROW];
    int nneg;
    char mkp[CDS_ROWS][CDS_ROW];
    int nmkp;
};

/* Scan one file (fail closed: unreadable file is an error, never a skip).
 * Returns 0 on success, 2 on a broken scan. */
int cds_scan_file(const char *path, struct cds_rows *r);

/* Scan a list of paths; returns 0 or 2. */
int cds_scan_list(char files[][CDS_PATH], size_t n, struct cds_rows *r);

/* Print the verdict (violation blocks and the PASS line) and return the
 * gate exit code: 0 clean, 1 on any violation. */
int cds_report(struct cds_rows *r, size_t nfiles, FILE *out);

/* Collect the scan set (env glob or git ls-files '*.sh' filtered to
 * existing files) and enforce the file floor. Returns 0 or 2. */
int cds_files_collect(char out[][CDS_PATH], size_t cap, size_t *n,
                      int *floor_out);

#endif
