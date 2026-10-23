/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private interface between gate_no_stale_pinned_facts.c and its
 * selftest sibling gate_no_stale_pinned_facts_selftest.c — not listed in
 * lintc.h, which declares only shared helpers and gate entry points.
 */
#ifndef GATE_NO_STALE_PINNED_FACTS_PRIV_H
#define GATE_NO_STALE_PINNED_FACTS_PRIV_H

#include <stdio.h>

/* Checks the doc files (paths relative to the cwd) for hand-pinned binary
 * sizes and live-state height pins. baseline is the shrink-only height-pin
 * file ("path|normalized text" rows); a missing baseline grandfathers
 * nothing. emit != 0 prints the current height-pin keys to out instead and
 * returns 0 (the ZCL_STALE_FACTS_EMIT_BASELINE mode). Otherwise the summary
 * goes to out and each violation to err. Returns 0 clean, 1 violations,
 * 2 when a listed file cannot be read or a regex or allocation fails. */
int snf_check(char *const *files, int nfiles, const char *baseline, FILE *out,
              FILE *err, int emit);

/* Nonzero when a tracked docs path belongs in the scan set. The set has no
 * exemptions: the live-state page and the archive are scanned too. */
int snf_keep_path(const char *path);

#endif
