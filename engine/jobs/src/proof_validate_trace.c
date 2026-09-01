/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: ZCL_PV_TRACE diagnostics that narrate why proof_validate declines.
 *
 * Split out of proof_validate_stage.c for the E1 file-size ceiling (the same
 * seam pattern as proof_validate_stage_dump.c). Several of proof_validate's
 * early returns are deliberately silent -- they are normal "not yet" waits in
 * a live sync -- but on an OFFLINE mint the same silence is indistinguishable
 * from a wedge, and because every downstream stage is pinned behind this
 * cursor the mint stall report blames whichever stage sits lowest instead of
 * this one. These helpers exist to make that difference legible on demand. */

#include "proof_validate_trace.h"

#include "models/activerecord.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdlib.h>

/* Trace-only: how many rows script_validate has actually published. Lets the
 * ZCL_PV_TRACE line separate "upstream really is behind" from "the derived
 * frontier went stale while the upstream raced ahead". */
long long pv_trace_log_rows(sqlite3 *db)
{
    if (!db)
        return -1; // raw-return-ok:trace-only-sentinel-no-db
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM script_validate_log",
                           -1, &st, NULL) != SQLITE_OK)
        return -1; // raw-return-ok:trace-only-sentinel-unreadable
    long long n = AR_STEP_ROW(st) ? AR_COL_INT(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

/* Cached once. step_validate runs thousands of times a second during an
 * offline mint, and getenv() is a linear scan of environ; the race here is
 * benign because every racer computes the same answer. */
bool pv_trace_enabled(void)
{
    static _Atomic int cached; /* 0 = unknown, 1 = off, 2 = on */
    int v = atomic_load_explicit(&cached, memory_order_relaxed);
    if (v == 0) {
        v = getenv("ZCL_PV_TRACE") ? 2 : 1;
        atomic_store_explicit(&cached, v, memory_order_relaxed);
    }
    return v == 2;
}
