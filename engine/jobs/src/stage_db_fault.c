/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_db_fault — implementation. See jobs/stage_db_fault.h. */

#include "jobs/stage_db_fault.h"

#include "storage/boot_auto_reindex.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdatomic.h>

bool stage_db_err_is_transient(int rc)
{
    /* Classify on the PRIMARY code (low 8 bits) plus the few extended codes
     * that flip the verdict. */
    int primary = rc & 0xff;
    switch (primary) {
    case SQLITE_OK:        /* unknown / clobbered errcode -> retry, never the
                            * destructive reindex (safe default direction) */
    case SQLITE_BUSY:      /* another connection holds the lock (after the 5 s
                            * busy_timeout already elapsed) */
    case SQLITE_LOCKED:    /* table-level lock contention */
    case SQLITE_PROTOCOL:  /* WAL protocol retry */
    case SQLITE_INTERRUPT: /* interrupted op */
    case SQLITE_NOMEM:     /* momentary memory pressure */
    case SQLITE_FULL:      /* disk full: the disk-reclaim remedy frees space; a
                            * reindex would only WRITE more, so retry */
    case SQLITE_CANTOPEN:  /* transient fs / file-descriptor pressure */
        return true;
    case SQLITE_IOERR:
        /* The IOERR family is a momentary read/write/fsync glitch EXCEPT the
         * filesystem-corruption subcode, which is permanent. */
        return rc != SQLITE_IOERR_CORRUPTFS;
    default:
        /* SQLITE_CORRUPT*, SQLITE_NOTADB, SQLITE_FORMAT, SQLITE_ERROR, ... are
         * not momentary — route to the bounded rebuild. */
        return false;
    }
}

enum stage_db_fault_action
stage_db_fault_note(struct stage_db_fault *f, int rc, const char *datadir,
                    int32_t anchor, const char *ctx)
{
    if (!f) {
        LOG_WARN("stage_db_fault",
                 "[stage_db_fault] NULL fault state ctx=%s rc=%d — escalating",
                 ctx ? ctx : "", rc);
        return STAGE_DB_FAULT_ESCALATE;
    }

    if (stage_db_err_is_transient(rc)) {
        int n = atomic_fetch_add(&f->consecutive, 1) + 1;
        if (n < STAGE_DB_FAULT_MAX_RETRIES) {
            LOG_WARN("stage_db_fault",
                     "[stage_db_fault] transient sqlite fault ctx=%s rc=%d "
                     "attempt=%d/%d — retry (cursor held, JOB_IDLE; backoff is "
                     "the supervisor re-tick cadence)",
                     ctx ? ctx : "", rc, n, STAGE_DB_FAULT_MAX_RETRIES);
            return STAGE_DB_FAULT_RETRY;
        }
        LOG_WARN("stage_db_fault",
                 "[stage_db_fault] transient sqlite fault ctx=%s rc=%d "
                 "persisted %d retries — escalating to bounded auto-reindex "
                 "(anchor=%d)",
                 ctx ? ctx : "", rc, n, (int)anchor);
    } else {
        LOG_WARN("stage_db_fault",
                 "[stage_db_fault] PERMANENT sqlite fault ctx=%s rc=%d — "
                 "escalating to bounded auto-reindex (anchor=%d)",
                 ctx ? ctx : "", rc, (int)anchor);
    }

    /* Persistent: request the bounded, self-terminating rebuild. The request is
     * capped per anchor episode (BOOT_AUTO_REINDEX_MAX) and pages the operator
     * on exhaustion, so escalation can never loop. The count is the CROSS-BOOT
     * attempt budget — if a request is already pending (this lifetime armed it,
     * or the one boot consumed is still converging), do NOT increment it again:
     * repeated runtime fault episodes must not burn boot attempts that never
     * ran (the sticky-escalator reindex rung applies the same gate). */
    if (datadir && datadir[0] && !boot_auto_reindex_pending(datadir)) {
        int req = boot_auto_reindex_request(datadir, anchor);
        if (req == 0)
            LOG_WARN("stage_db_fault",
                     "[stage_db_fault] auto-reindex request write failed ctx=%s "
                     "anchor=%d (next escalation retries the request)",
                     ctx ? ctx : "", (int)anchor);
    }
    /* Reset: the rebuild request is now the next step; a fresh post-rebuild
     * fault starts a new retry budget. */
    atomic_store(&f->consecutive, 0);
    return STAGE_DB_FAULT_ESCALATE;
}

void stage_db_fault_clear(struct stage_db_fault *f)
{
    if (f)
        atomic_store(&f->consecutive, 0);
}

#ifdef ZCL_TESTING
int stage_db_fault_consecutive_for_testing(const struct stage_db_fault *f)
{
    return f ? atomic_load(&f->consecutive) : -1;
}
#endif
