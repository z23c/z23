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
 * exactly as they would with a raw step. */

#ifndef ZCL_UTIL_AR_STEP_READONLY_H
#define ZCL_UTIL_AR_STEP_READONLY_H

#include <stddef.h>
#include <sqlite3.h>

#define AR_STEP_ROW_READONLY(stmt) (sqlite3_step((stmt)))
#define AR_STEP_WRITE(stmt)        (sqlite3_step((stmt)))

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
