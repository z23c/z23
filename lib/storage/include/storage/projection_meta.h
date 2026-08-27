/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * projection_meta — the shared `projection_meta(k,v)` bootstrap DDL.
 *
 * Every event-log projection (the *_projection.c files under
 * lib/storage/src) owns its domain tables but stores the same two rows in
 * the same shared meta table: 'schema_version' and 'last_consumed_offset'.
 * This header states that table's CREATE + seed preamble once, so the
 * projections that still run their own open() (contacts, hodl_history,
 * mempool, onion_announcements, wallet) stop carrying byte-identical
 * copies of it. storage/projection_consumer.c holds the same DDL for the
 * projections built on that skeleton.
 *
 * `static inline`, not plain `static` — see storage/projection_util.h for
 * the -Wunused-function rationale. Like apply_pragmas there, this routes
 * every statement through the including TU's 3-arg module-tagged
 * `exec_sql` so failure logs keep the projection's own prefix.
 */

#ifndef ZCL_STORAGE_PROJECTION_META_H
#define ZCL_STORAGE_PROJECTION_META_H

#include "storage/projection_util.h"

/* Creates projection_meta(k,v) when absent and seeds — INSERT OR IGNORE,
 * so an existing database is never rewritten — the two rows every
 * event-log projection reads: 'schema_version'='1' and
 * 'last_consumed_offset'='0'. Statement order is fixed: CREATE TABLE,
 * schema_version, last_consumed_offset. Returns true iff all three
 * statements succeeded. */
static inline bool projection_meta_ensure(sqlite3 *db)
{
    return exec_sql(db,
        "CREATE TABLE IF NOT EXISTS projection_meta ("
        " k TEXT PRIMARY KEY,"
        " v TEXT NOT NULL"
        ")",
        "create projection_meta") &&
        exec_sql(db,
        "INSERT OR IGNORE INTO projection_meta(k,v) "
        "VALUES('schema_version','1')",
        "insert schema_version") &&
        exec_sql(db,
        "INSERT OR IGNORE INTO projection_meta(k,v) "
        "VALUES('last_consumed_offset','0')",
        "insert last_consumed_offset");
}

#endif /* ZCL_STORAGE_PROJECTION_META_H */
