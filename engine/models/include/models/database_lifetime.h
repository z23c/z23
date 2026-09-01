/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Central SQLite backing-file ownership and lifetime instrumentation.
 *
 * A connection owns its sqlite3 handle.  Only the canonical backing owner may
 * retire/replace a live node.db WAL generation.  The VFS implementation is
 * process-wide so raw SQLite callers cannot bypass the invariant. */

#ifndef ZCL_DATABASE_LIFETIME_H
#define ZCL_DATABASE_LIFETIME_H

#include <stdbool.h>
#include <stdint.h>

enum db_lifetime_authority {
    DB_LIFETIME_BORROWED = 0,
    DB_LIFETIME_HANDLE_OWNER = 1,
    DB_LIFETIME_BACKING_OWNER = 2,
};

struct db_lifetime_scope {
    const char *previous_owner;
    enum db_lifetime_authority previous_authority;
    uint64_t previous_generation;
};

/* Idempotent, process-lifetime registration of the default-VFS wrapper. */
bool db_lifetime_install(void);

/* Attribute all SQLite filesystem work in the dynamic extent to one owner. */
void db_lifetime_scope_enter(struct db_lifetime_scope *scope,
                             const char *owner,
                             enum db_lifetime_authority authority,
                             uint64_t generation);
void db_lifetime_scope_leave(struct db_lifetime_scope *scope);

/* Generation selected by the most recent tracked main-file open in scope. */
uint64_t db_lifetime_scope_generation(void);

/* Permanent invariant telemetry.  A non-zero count is an acceptance failure. */
uint64_t db_lifetime_unauthorized_count(void);

/* Explicit database filesystem lifecycle operations use the same boundary. */
int db_lifetime_rename(const char *from, const char *to, const char *owner,
                       enum db_lifetime_authority authority,
                       uint64_t generation);
int db_lifetime_unlink(const char *path, const char *owner,
                       enum db_lifetime_authority authority,
                       uint64_t generation);

#endif
