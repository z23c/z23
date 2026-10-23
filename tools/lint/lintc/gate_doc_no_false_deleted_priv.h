/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface between gate_doc_no_false_deleted.c and its
 * selftest sibling gate_doc_no_false_deleted_selftest.c — not listed in
 * lintc.h, which declares only shared helpers and gate entry points.
 */
#ifndef GATE_DOC_NO_FALSE_DELETED_PRIV_H
#define GATE_DOC_NO_FALSE_DELETED_PRIV_H

/* Runs both checks against the current working directory (the repo root):
 * the no-false-"deleted" claim table and the binary-size band. Prints the
 * FAIL lines and the closing banner to stdout. Returns 0 pass, 1 a false
 * claim or an out-of-band size, 2 when a scan cannot complete (fail closed). */
int dfn_check_tree(void);

#endif
