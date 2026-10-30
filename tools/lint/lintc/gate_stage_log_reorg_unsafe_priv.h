/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for check-stage-log-reorg-unsafe (ported from
 * tools/scripts/gate_stage_log_reorg_unsafe_ratchet.sh, deleted).
 * gate_stage_log_reorg_unsafe.c holds the gate; _selftest.c the fixture
 * self-test. slr_check runs the whole gate over a caller-supplied file
 * list so the selftest can point it at planted fixtures.
 */
#ifndef GATE_STAGE_LOG_REORG_UNSAFE_PRIV_H
#define GATE_STAGE_LOG_REORG_UNSAFE_PRIV_H

#include <stdio.h>

enum {
    SLR_BASELINE = 8,    /* baked ratchet ceiling, one UPSERT per known store */
    SLR_MAX_FILES = 32,  /* override list capacity */
    SLR_SITES = 256,     /* stored site rows before overflow refuses */
    SLR_PATH = 1024,     /* bytes per scanned path (override tokens) */
    SLR_SITE = 1280,     /* bytes per site row "file:lineno" */
    SLR_LINE = 4096      /* source line buffer */
};

/* Full gate over files[0..nfiles): 0 pass, 1 ratchet violation, 2 fatal
 * (empty/moved scan surface, unreadable file, overflow). Report on out. */
int slr_check(const char *const *files, int nfiles, FILE *out);

#endif
