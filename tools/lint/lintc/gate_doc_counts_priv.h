/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by the check-doc-counts gate files
 * (gate_doc_counts.c, gate_doc_counts_scan.c, gate_doc_counts_selftest.c).
 */
#ifndef GATE_DOC_COUNTS_PRIV_H
#define GATE_DOC_COUNTS_PRIV_H

#include <stdbool.h>
#include <stddef.h>

enum { DCN_PATH = 256, DCN_FILES = 2048, DCN_VIOL = 512, DCN_VSZ = 2048 };

/* The eight code-measured counts. */
struct dcn_counts {
    long groups, ports, adapters, conditions;
    long bundles, roots, dumpstate, shapes;
};

/* Accumulated violation lines, in report order. */
struct dcn_viol {
    char t[DCN_VIOL][DCN_VSZ];
    int n;
};

/* Append one formatted line. 0, or 2 after a message when full or too long. */
int dcn_viol_add(struct dcn_viol *v, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Scan files[0..nfiles) for the stale-phrase denylist and the derived
 * "<N> <unit>" claims against c. 0 clean or findings added, 2 on overflow. */
int dcn_scan(const struct dcn_counts *c, char (*files)[DCN_PATH], int nfiles,
             struct dcn_viol *v);

/* Prove the scan matchers still fire on a hermetic fixture. 0 proven, 1
 * broken (message on stderr), 2 on an environment error. */
int dcn_selfcheck(const struct dcn_counts *c);

/* Parse the leading "<digits and commas>[+]" token of a matched claim the way
 * the shell's 10#${tok//,/} arithmetic does (64-bit wraparound); *plus is 1
 * for an at-least claim. */
long dcn_claim_number(const char *m, int *plus);

/* Rewrite the declared values of path in place from c. 0, or 2 after a
 * message. */
int dcn_rewrite_file(const char *path, const struct dcn_counts *c);

#endif
