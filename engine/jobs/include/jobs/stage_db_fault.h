/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_db_fault — classify a sqlite failure at a fold stage as TRANSIENT
 * (a momentary db-busy / lock / IO glitch a retry can clear) vs PERMANENT
 * (corruption / not-a-db) and pick the bounded, self-terminating recovery.
 *
 * WHY THIS EXISTS
 * ---------------
 * validate_headers_stage and script_validate_stage (and any fold stage) used to
 * return a DEAD JOB_FATAL on ANY sqlite read/write failure. A momentary
 * SQLITE_BUSY / SQLITE_LOCKED / transient SQLITE_IOERR then latched the stage
 * FATAL forever — a one-off glitch became "needs a human", which is exactly the
 * class the never-stuck doctrine forbids. This helper turns that dead FATAL into
 * a bounded ladder:
 *
 *   - transient + within the retry budget   -> STAGE_DB_FAULT_RETRY: the caller
 *     leaves the cursor untouched and returns JOB_IDLE; the supervisor re-ticks
 *     the stage. The inter-attempt BACKOFF is the supervisor re-tick cadence on
 *     purpose — the fold/drive thread must never block-sleep (the reducer-drive
 *     lock-order / liveness law). A momentary glitch self-heals, no operator.
 *
 *   - transient + budget exhausted, OR a permanent error -> STAGE_DB_FAULT_
 *     ESCALATE: the helper records a BOUNDED auto-reindex request
 *     (boot_auto_reindex_request — capped per anchor episode, then it pages the
 *     operator; it can never loop) and the caller returns JOB_FATAL. The FATAL
 *     is no longer dead: the next boot consumes the request and rebuilds the
 *     derived state from blocks/.
 *
 * CONSENSUS PARITY (INVIOLABLE)
 * -----------------------------
 * This is for INFRASTRUCTURE faults ONLY. A validity verdict (script_invalid,
 * bad-PoW, proof_invalid, reorg_detected, ...) is NEVER a db fault — those are
 * written as ok=0/ok=1 log rows and ADVANCE the cursor, and they must stay
 * terminal. Call this ONLY at a site whose failure is a sqlite
 * read/write/prepare/step/exec error, NEVER at a consensus accept/reject site.
 * It never turns an "invalid" verdict into a retry; it only converts a "stage
 * machinery failed" dead-stop into a bounded retry-then-rebuild.
 */
#ifndef ZCL_JOBS_STAGE_DB_FAULT_H
#define ZCL_JOBS_STAGE_DB_FAULT_H

#include "jobs/job.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Max consecutive transient faults a stage retries before it escalates to the
 * bounded auto-reindex. A "transient" lock held for minutes (a genuinely stuck
 * external writer) must not spin forever — after this many retries it is
 * treated as persistent and routed to the rebuild. */
#define STAGE_DB_FAULT_MAX_RETRIES 8

enum stage_db_fault_action {
    STAGE_DB_FAULT_RETRY    = 0, /* caller: hold the cursor, return JOB_IDLE */
    STAGE_DB_FAULT_ESCALATE = 1, /* caller: return JOB_FATAL (reindex requested) */
};

/* Per-stage fault state. One file-static instance per stage; zero-initialised
 * (consecutive starts at 0). */
struct stage_db_fault {
    _Atomic int consecutive;
};

/* True iff `sqlite_rc` (primary or extended) is a TRANSIENT / retryable fault.
 * SQLITE_OK is treated as transient: a clobbered or unknown errcode must retry,
 * never trigger a destructive reindex. Pure; no side effects. */
bool stage_db_err_is_transient(int sqlite_rc);

/* Note ONE infrastructure db fault for a stage and return the bounded action.
 *   `sqlite_rc` — sqlite3_extended_errcode(db) captured AT the failing call
 *                 (pass SQLITE_ERROR if genuinely unknown).
 *   `datadir`   — routes an escalation to the bounded auto-reindex request; may
 *                 be NULL/"" (then escalation skips the request and the caller
 *                 still FATALs).
 *   `anchor`    — the wedged height (keys the bounded reindex episode).
 *   `ctx`       — names the failing operation for the log line.
 * The escalation request is capped per anchor (BOOT_AUTO_REINDEX_MAX) and pages
 * the operator on exhaustion, so this ladder ALWAYS terminates. */
enum stage_db_fault_action
stage_db_fault_note(struct stage_db_fault *f, int sqlite_rc,
                    const char *datadir, int32_t anchor, const char *ctx);

/* Reset the consecutive-fault counter after a clean advancing step (the glitch
 * cleared). */
void stage_db_fault_clear(struct stage_db_fault *f);

/* Convenience for a stage step body: classify a db fault and return the
 * job_result_t the step must return (JOB_IDLE to retry, JOB_FATAL to escalate).
 * Equivalent to mapping stage_db_fault_note() RETRY->JOB_IDLE,
 * ESCALATE->JOB_FATAL. */
static inline job_result_t
stage_db_fault_result(struct stage_db_fault *f, int sqlite_rc,
                      const char *datadir, int32_t anchor, const char *ctx)
{
    return stage_db_fault_note(f, sqlite_rc, datadir, anchor, ctx) ==
                   STAGE_DB_FAULT_RETRY
               ? JOB_IDLE
               : JOB_FATAL;
}

#ifdef ZCL_TESTING
/* Test-only: read the live consecutive-fault count. */
int stage_db_fault_consecutive_for_testing(const struct stage_db_fault *f);
#endif

#endif /* ZCL_JOBS_STAGE_DB_FAULT_H */
