/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lib-side AR step wrappers for single-shot sqlite3_step calls that
 * don't go through the full AR_BEGIN_SAVE lifecycle (which lives in
 * engine/models/include/models/activerecord.h and is the right tool for
 * saves of structured model records with validators + lifecycle hooks).
 *
 * Each macro below is exempt from the `check-raw-sqlite` lint by name.
 * Use the one that matches intent — the lint cares about getting raw
 * sqlite3_step out of source text; the human reader cares about what
 * the call is doing.
 *
 * Read paths:
 *   AR_STEP_ROW_READONLY — single-shot read step. Use in SELECT loops,
 *   SELECT-one queries, and count(*) reads.
 *
 * Write paths that don't fit AR_BEGIN_SAVE:
 *   AR_STEP_WRITE — single-shot write step for scalar UPDATEs,
 *   fire-and-forget INSERTs, canary writes, or schema-level state
 *   key/value writes that don't have a structured model record. If
 *   the write is saving a domain object (struct file_offer,
 *   struct swap_contract, struct zmsg_message, etc.) use AR_BEGIN_SAVE
 *   instead — it adds validate / before_save / after_save lifecycle
 *   coverage that AR_STEP_WRITE deliberately skips.
 *
 * Both macros return the raw rc (SQLITE_ROW / SQLITE_DONE / SQLITE_MISUSE
 * / SQLITE_CORRUPT / ...). Callers compare against the expected sentinel
 * exactly as they would with a raw step.
 *
 * Tri-state reads (the closed class):
 *   ar_step_checked — ZCL_STEP_ROW, ZCL_STEP_DONE or ZCL_STEP_ERROR. A step
 *   that is neither ROW nor DONE (BUSY, LOCKED, IOERR, CORRUPT, INTERRUPT,
 *   MISUSE ...) is an ERROR, never "no row": it is logged with the caller's
 *   context, errcode, extended errcode and errmsg, optionally copied into a
 *   zcl_result, and the statement is reset so a failed step never leaves a
 *   read snapshot open on the connection (the ar_step_done invariant in
 *   engine/models/include/models/activerecord.h). Comparing a raw step to
 *   SQLITE_ROW folds every error into "no row"; the check-sqlite-step-row
 *   lint gate refuses new instances of that comparison. */

#ifndef ZCL_UTIL_AR_STEP_READONLY_H
#define ZCL_UTIL_AR_STEP_READONLY_H

#include <stddef.h>
#include <sqlite3.h>

#include "base/result.h"
#include "util/log_macros.h"

#define AR_STEP_ROW_READONLY(stmt) (sqlite3_step((stmt)))
#define AR_STEP_WRITE(stmt)        (sqlite3_step((stmt)))

enum zcl_step {
    ZCL_STEP_ERROR = -1,
    ZCL_STEP_DONE  = 0,
    ZCL_STEP_ROW   = 1,
};

/* The error branch, out of line of the hot ROW/DONE path. `what` names the
 * caller's query; err (optional) receives the same context. */
static inline enum zcl_step ar_step_fail(sqlite3_stmt *stmt, int rc,
                                         const char *what,
                                         struct zcl_result *err)
{
    sqlite3 *db = sqlite3_db_handle(stmt);
    const char *msg = db ? sqlite3_errmsg(db) : sqlite3_errstr(rc);
    int ext = db ? sqlite3_extended_errcode(db) : rc;
    const char *ctx = what ? what : "sqlite step";
    LOG_WARN("sqlite", "%s: step failed rc=%d ext=%d (%s): %s", ctx, rc, ext,
             sqlite3_errstr(rc), msg ? msg : "?");
    if (err)
        *err = ZCL_ERR(rc, "%s: sqlite step failed rc=%d ext=%d: %s", ctx, rc,
                       ext, msg ? msg : "?");
    sqlite3_reset(stmt);
    return ZCL_STEP_ERROR;
}

/* Step once: ZCL_STEP_ROW, ZCL_STEP_DONE, or ZCL_STEP_ERROR (logged, reset,
 * copied into *err when err is non-NULL). A NULL statement is an error. */
static inline enum zcl_step ar_step_checked(sqlite3_stmt *stmt,
                                            const char *what,
                                            struct zcl_result *err)
{
    if (!stmt) {
        LOG_WARN("sqlite", "%s: step on a NULL statement",
                 what ? what : "sqlite step");
        if (err)
            *err = ZCL_ERR(SQLITE_MISUSE, "%s: step on a NULL statement",
                           what ? what : "sqlite step");
        return ZCL_STEP_ERROR;
    }
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW)
        return ZCL_STEP_ROW;
    if (rc == SQLITE_DONE)
        return ZCL_STEP_DONE;
    return ar_step_fail(stmt, rc, what, err);
}

static inline int ar_exec_write_sql(sqlite3 *db, const char *sql)
{
    if (!db || !sql)
        return SQLITE_MISUSE;

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return rc;
    if (!stmt)
        return SQLITE_MISUSE;

    rc = AR_STEP_WRITE(stmt);
    int finalize_rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
        return rc;
    return finalize_rc;
}

#endif /* ZCL_UTIL_AR_STEP_READONLY_H */
