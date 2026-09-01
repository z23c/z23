/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Schema Migration Framework
 *
 * Replaces the monolithic if/else chain in database.c with a
 * registry of self-contained migration functions. Each migration
 * has a version number, a name, an "up" function, and an optional
 * "down" function for rollback.
 *
 * How it works
 * ------------
 * 1. Migrations are registered at program startup via
 *    `schema_migration_register()` (typically in a static init
 *    function or from boot code).
 *
 * 2. At boot, `schema_migration_run_pending()` reads the current
 *    schema version from `node_state`, compares against registered
 *    migrations, and applies any with version > current in order.
 *
 * 3. Each migration runs inside a transaction. If up() fails, the
 *    transaction is rolled back, and migration stops. No partial
 *    schema state.
 *
 * 4. On success, the framework records the migration in
 *    `schema_migrations` and bumps `schema_version` in `node_state`.
 *
 * Backward compatibility
 * ----------------------
 * Migrations v1-v18 were applied by the old system in database.c.
 * They remain there as-is. This framework handles v19+ migrations.
 * `schema_migration_run_pending()` reads the current version from
 * `node_state` (which the old system also uses), so there's no
 * version gap.
 *
 * Writing a migration
 * -------------------
 *   static bool migrate_019_up(struct node_db *ndb) {
 *       return node_db_exec(ndb, "ALTER TABLE peers ADD COLUMN foo TEXT");
 *   }
 *   static bool migrate_019_down(struct node_db *ndb) {
 *       // SQLite can't DROP COLUMN before 3.35 — just leave it
 *       (void)ndb;
 *       return true;
 *   }
 *
 *   // In an init function:
 *   schema_migration_register(19, "add_peers_foo", migrate_019_up, migrate_019_down);
 *
 * The version number MUST be unique and monotonically increasing.
 * Gaps are allowed (e.g., 19, 21, 25).
 */

#ifndef ZCL_MODELS_SCHEMA_MIGRATION_H
#define ZCL_MODELS_SCHEMA_MIGRATION_H

#include <stdbool.h>
#include <stdint.h>

/* Forward-declare to avoid circular includes. The actual struct
 * lives in models/database.h — migrations receive the open handle. */
struct node_db;

/* ── Migration function signatures ─────────────────────────── */

/* up(): apply the migration. Return true on success.
 * The framework wraps the call in BEGIN/COMMIT. */
typedef bool (*schema_migrate_fn)(struct node_db *ndb);

/* ── Migration descriptor ──────────────────────────────────── */

struct schema_migration {
    int         version;     /* unique, monotonically increasing */
    const char *name;        /* short description (e.g., "add_peers_foo") */
    schema_migrate_fn up;    /* required — apply migration */
    schema_migrate_fn down;  /* optional — rollback (NULL = irreversible) */
};

/* ── Registration ──────────────────────────────────────────── */

/* Maximum number of registered migrations. Increase if needed. */
#define SCHEMA_MIGRATION_MAX 256

/* Register a migration. Must be called before run_pending().
 * Returns false if the registry is full, version is <= 0, or
 * a migration with the same version already exists. */
bool schema_migration_register(int version, const char *name,
                               schema_migrate_fn up,
                               schema_migrate_fn down);

/* Convenience: register from a struct. */
bool schema_migration_register_entry(const struct schema_migration *m);

/* Clear all registered migrations (for testing). */
void schema_migration_clear(void);

/* Number of currently registered migrations. */
int schema_migration_count(void);

/* ── Execution ─────────────────────────────────────────────── */

/* Run all pending migrations (version > current schema version).
 * Returns the number of migrations applied, or -1 on error.
 * Migrations are applied in version order. Each runs in its own
 * transaction; a failure stops further migrations. */
int schema_migration_run_pending(struct node_db *ndb);

/* Roll back the most recent migration (if it has a down function).
 * Returns true if rollback succeeded, false if no down function
 * or the down function failed. */
bool schema_migration_rollback_last(struct node_db *ndb);

/* ── Query ─────────────────────────────────────────────────── */

/* Get the current schema version from node_state. */
int schema_migration_current_version(struct node_db *ndb);

/* Get a registered migration by version. Returns NULL if not found. */
const struct schema_migration *schema_migration_get(int version);

/* Get the highest registered version. Returns 0 if none. */
int schema_migration_latest_version(void);

/* Check if a specific migration has been applied. */
bool schema_migration_is_applied(struct node_db *ndb, int version);

#endif /* ZCL_MODELS_SCHEMA_MIGRATION_H */
