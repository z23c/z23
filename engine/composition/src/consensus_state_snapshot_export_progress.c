/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Observability-only helpers for the long (30-60+ minute on a full-history
 * datadir) -export-consensus-bundle prove/write path. Split out of
 * consensus_state_snapshot_export.c along the file-size ceiling seam (E1,
 * docs/DEFENSIVE_CODING.md) — a natural seam, since these two functions are
 * a self-contained cross-cutting concern shared by every prove (_proof.c,
 * _proof_rows.c) and write (_write.c) pass, not exporter-entry logic.
 *
 * consensus_export_progress_emit emits identical text to stderr AND
 * LOG_INFO, so both an attended terminal and a log-grep see the same
 * progress. NEVER used in any gate decision — pure side-channel
 * timing/progress markers; removing every call site changes zero exported
 * bytes and zero refusal conditions. */

#include "consensus_state_snapshot_export_internal.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdarg.h>
#include <stdio.h>

#define EXPORT_PROGRESS_SUBSYS "consensus_bundle_export"

int64_t consensus_export_clock_ms(void)
{
    return platform_time_monotonic_ms();
}

void consensus_export_progress_emit(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fprintf(stderr, "[export] %s\n", buf);
    LOG_INFO(EXPORT_PROGRESS_SUBSYS, "%s", buf);
}
