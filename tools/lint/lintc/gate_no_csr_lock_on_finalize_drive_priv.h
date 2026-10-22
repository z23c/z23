/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface between gate_no_csr_lock_on_finalize_drive.c
 * and its selftest sibling gate_no_csr_lock_on_finalize_drive_selftest.c —
 * not listed in lintc.h, which declares only shared helpers and gate entry
 * points.
 */
#ifndef GATE_NO_CSR_LOCK_ON_FINALIZE_DRIVE_PRIV_H
#define GATE_NO_CSR_LOCK_ON_FINALIZE_DRIVE_PRIV_H

#include <stdio.h>

/* Scans <root>/engine/jobs/src/tip_finalize_post_step.c (whole file) and the
 * chain_evidence_note_finalized_tip() body in
 * <root>/engine/services/src/chain_evidence_live_advance.c. Returns 0 on a
 * clean tree, 1 on a forbidden token, a missing scanned file or a missing
 * note function (fail closed), 2 on an I/O or regex error. Reports go to out. */
int cnf_check_root(const char *root, FILE *out);

#endif
