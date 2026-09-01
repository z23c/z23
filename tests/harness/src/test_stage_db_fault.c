/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stage_db_fault — R5 never-stuck: a TRANSIENT sqlite fault at a fold
 * stage must RETRY (not a dead JOB_FATAL) and self-heal; a PERSISTENT/permanent
 * one must route to the BOUNDED auto-reindex. Drives the shared classifier +
 * state machine (jobs/stage_db_fault.h) that validate_headers_stage and
 * script_validate_stage now use at every infra-db failure exit.
 *
 * Parity note: this helper is for INFRA faults only — it never sees a validity
 * verdict, which is why no consensus path is exercised here. */

#include "test/test_core.h"

#include "jobs/stage_db_fault.h"
#include "jobs/job.h"
#include "storage/boot_auto_reindex.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DBF_CHECK(name, expr) do {                       \
    printf("stage_db_fault: %s... ", (name));            \
    if (expr) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

int test_stage_db_fault(void);
int test_stage_db_fault(void)
{
    int failures = 0;

    /* ── (1) classification: transient vs permanent ─────────────────────── */
    DBF_CHECK("BUSY is transient",   stage_db_err_is_transient(SQLITE_BUSY));
    DBF_CHECK("LOCKED is transient", stage_db_err_is_transient(SQLITE_LOCKED));
    DBF_CHECK("IOERR is transient",  stage_db_err_is_transient(SQLITE_IOERR));
    DBF_CHECK("FULL is transient",   stage_db_err_is_transient(SQLITE_FULL));
    DBF_CHECK("CANTOPEN is transient", stage_db_err_is_transient(SQLITE_CANTOPEN));
    DBF_CHECK("OK is transient (safe default for a clobbered errcode)",
              stage_db_err_is_transient(SQLITE_OK));
    DBF_CHECK("CORRUPT is permanent",  !stage_db_err_is_transient(SQLITE_CORRUPT));
    DBF_CHECK("NOTADB is permanent",   !stage_db_err_is_transient(SQLITE_NOTADB));
    DBF_CHECK("generic ERROR is permanent",
              !stage_db_err_is_transient(SQLITE_ERROR));
    DBF_CHECK("IOERR_CORRUPTFS is permanent",
              !stage_db_err_is_transient(SQLITE_IOERR_CORRUPTFS));

    /* Isolated datadir for the bounded auto-reindex routing checks. */
    char dir[] = "/tmp/zcl_dbfault_XXXXXX";
    char *made = mkdtemp(dir);
    DBF_CHECK("temp datadir created", made != NULL);

    /* ── (2) a transient fault RETRIES, then a clean step recovers (no
     *        JOB_FATAL, no reindex requested) — the test (i) scenario ────── */
    struct stage_db_fault f = {0};
    bool all_retry = true;
    for (int i = 1; i < STAGE_DB_FAULT_MAX_RETRIES; i++) {
        if (stage_db_fault_result(&f, SQLITE_BUSY, dir, 100,
                                  "transient-then-heal") != JOB_IDLE)
            all_retry = false;
    }
    DBF_CHECK("transient within budget yields JOB_IDLE (retry, not FATAL)",
              all_retry);
    DBF_CHECK("no auto-reindex requested while merely retrying",
              made && !boot_auto_reindex_pending(dir));
    /* The glitch clears: a successful advancing step resets the budget, so a
     * later transient fault starts fresh and does NOT prematurely escalate. */
    stage_db_fault_clear(&f);
    DBF_CHECK("clear() resets the retry counter",
              stage_db_fault_consecutive_for_testing(&f) == 0);
    DBF_CHECK("post-recovery transient retries again (JOB_IDLE)",
              stage_db_fault_result(&f, SQLITE_BUSY, dir, 100,
                                    "post-heal") == JOB_IDLE);

    /* ── (3) a transient fault that NEVER clears escalates at the bound and
     *        routes to the bounded auto-reindex (never an infinite retry) ── */
    struct stage_db_fault g = {0};
    job_result_t last = JOB_IDLE;
    for (int i = 0; i < STAGE_DB_FAULT_MAX_RETRIES; i++)
        last = stage_db_fault_result(&g, SQLITE_BUSY, dir, 200, "stuck-lock");
    DBF_CHECK("budget-exhausted transient escalates to JOB_FATAL",
              last == JOB_FATAL);
    DBF_CHECK("escalation requested the bounded auto-reindex",
              made && boot_auto_reindex_pending(dir));
    DBF_CHECK("counter reset after escalation",
              stage_db_fault_consecutive_for_testing(&g) == 0);

    if (made)
        boot_auto_reindex_clear(dir);

    /* ── (4) a permanent error escalates IMMEDIATELY (no wasted retries) ─── */
    struct stage_db_fault p = {0};
    DBF_CHECK("permanent fault escalates on the first occurrence",
              stage_db_fault_result(&p, SQLITE_CORRUPT, dir, 300,
                                    "corrupt") == JOB_FATAL);
    DBF_CHECK("permanent fault requested the bounded auto-reindex",
              made && boot_auto_reindex_pending(dir));

    /* cleanup */
    if (made) {
        char reqpath[512];
        snprintf(reqpath, sizeof(reqpath), "%s/auto_reindex_request", dir);
        unlink(reqpath);
        rmdir(dir);
    }

    if (failures == 0)
        printf("stage_db_fault: ALL PASSED\n");
    return failures;
}
