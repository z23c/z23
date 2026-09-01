/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Schema Migration Framework — see header for design rationale.
 * ar-validate-skip:migration-registry-not-a-row
 *
 * Implementation
 * --------------
 * Migrations are stored in a static array sorted by version.
 * Registration appends to the array; run_pending() iterates in
 * version order. Each migration is wrapped in BEGIN/COMMIT with
 * ROLLBACK on failure.
 *
 * Thread safety: the registry is written at startup before any
 * threads are spawned, and read-only thereafter. No mutex needed.
 */

#include "models/schema_migration.h"
#include "models/database.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Static registry ───────────────────────────────────────── */

static struct schema_migration g_migrations[SCHEMA_MIGRATION_MAX];
static int g_migration_count = 0;

/* ── Sorting helper ────────────────────────────────────────── */

static int cmp_migration_version(const void *a, const void *b)
{
    const struct schema_migration *ma = a;
    const struct schema_migration *mb = b;
    return (ma->version > mb->version) - (ma->version < mb->version);
}

static void sort_migrations(void)
{
    if (g_migration_count > 1)
        qsort(g_migrations, (size_t)g_migration_count,
              sizeof(g_migrations[0]), cmp_migration_version);
}

/* ── Registration ──────────────────────────────────────────── */

bool schema_migration_register(int version, const char *name,
                               schema_migrate_fn up,
                               schema_migrate_fn down)
{
    if (version <= 0)
        LOG_FAIL("schema_migration", "register: version must be > 0 (got %d)", version);
    if (!up)
        LOG_FAIL("schema_migration", "register: up function is NULL for v%d", version);
    if (!name)
        LOG_FAIL("schema_migration", "register: name is NULL for v%d", version);
    if (g_migration_count >= SCHEMA_MIGRATION_MAX)
        LOG_FAIL("schema_migration", "register: registry full (%d migrations)",
                 SCHEMA_MIGRATION_MAX);

    /* Check for duplicate version */
    for (int i = 0; i < g_migration_count; i++) {
        if (g_migrations[i].version == version)
            LOG_FAIL("schema_migration", "register: duplicate version %d (%s vs %s)",
                     version, g_migrations[i].name, name);
    }

    g_migrations[g_migration_count++] = (struct schema_migration){
        .version = version,
        .name    = name,
        .up      = up,
        .down    = down,
    };
    sort_migrations();
    return true;
}

bool schema_migration_register_entry(const struct schema_migration *m)
{
    if (!m)
        LOG_FAIL("schema_migration", "register_entry: NULL migration");
    return schema_migration_register(m->version, m->name, m->up, m->down);
}

void schema_migration_clear(void)
{
    g_migration_count = 0;
    memset(g_migrations, 0, sizeof(g_migrations));
}

int schema_migration_count(void)
{
    return g_migration_count;
}

/* ── Query ─────────────────────────────────────────────────── */

int schema_migration_current_version(struct node_db *ndb)
{
    return node_db_schema_version(ndb);
}

const struct schema_migration *schema_migration_get(int version)
{
    for (int i = 0; i < g_migration_count; i++) {
        if (g_migrations[i].version == version)
            return &g_migrations[i];
    }
    return NULL;
}

int schema_migration_latest_version(void)
{
    if (g_migration_count == 0) return 0;
    /* Array is sorted, last entry has highest version */
    return g_migrations[g_migration_count - 1].version;
}

bool schema_migration_is_applied(struct node_db *ndb, int version)
{
    return schema_migration_current_version(ndb) >= version;
}

/* ── Execution ─────────────────────────────────────────────── */

int schema_migration_run_pending(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return -1;

    /* Ensure schema_migrations table exists (idempotent).  The old
     * migration system also creates this, but we do it here too so
     * the framework works standalone.  If this CREATE fails we have
     * no durable way to record which migrations ran — refuse to
     * proceed rather than silently advance. */
    if (!node_db_exec(ndb,
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "  version TEXT PRIMARY KEY,"
            "  applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))"
            ")")) {
        fprintf(stderr,
            "[migrate] CREATE schema_migrations FAILED — refusing to "
            "apply any migrations (bookkeeping table unavailable)\n");
        return -1;
    }

    int current_ver = schema_migration_current_version(ndb);
    int applied = 0;

    for (int i = 0; i < g_migration_count; i++) {
        const struct schema_migration *m = &g_migrations[i];

        if (m->version <= current_ver)
            continue;  /* already applied */

        printf("[migrate] applying v%d: %s\n", m->version, m->name);

        /* Wrap in transaction for atomicity */
        if (!node_db_begin(ndb)) {
            fprintf(stderr, "[migrate] v%d: BEGIN failed\n", m->version);
            return applied > 0 ? applied : -1;
        }

        if (!m->up(ndb)) {
            fprintf(stderr, "[migrate] v%d (%s): up() FAILED — rolling back\n",
                    m->version, m->name);
            node_db_rollback(ndb);
            return applied > 0 ? applied : -1;
        }

        /* Record in schema_migrations table.  If this INSERT fails
         * we CANNOT commit — the migration body already ran but
         * would not be recorded, so next boot would replay it and
         * either crash on CREATE IF NOT EXISTS drift or duplicate
         * the change.  Roll back the whole migration atomically. */
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT OR IGNORE INTO schema_migrations(version) VALUES('%03d')",
                 m->version);
        if (!node_db_exec(ndb, sql)) {
            fprintf(stderr,
                "[migrate] v%d: INSERT schema_migrations FAILED — "
                "rolling back the migration body too\n", m->version);
            node_db_rollback(ndb);
            return applied > 0 ? applied : -1;
        }

        /* Bump schema_version in node_state — same invariant as
         * above: without this the version pointer lies and the next
         * boot re-applies the migration. */
        int32_t ver32 = (int32_t)m->version;
        if (!node_db_state_set(ndb, "schema_version", &ver32, sizeof(ver32))) {
            fprintf(stderr,
                "[migrate] v%d: node_state schema_version UPDATE FAILED — "
                "rolling back\n", m->version);
            node_db_rollback(ndb);
            return applied > 0 ? applied : -1;
        }

        if (!node_db_commit(ndb)) {
            fprintf(stderr, "[migrate] v%d: COMMIT failed\n", m->version);
            node_db_rollback(ndb);
            return applied > 0 ? applied : -1;
        }

        current_ver = m->version;
        applied++;
        printf("[migrate] v%d: %s — OK\n", m->version, m->name);
    }

    if (applied > 0)
        printf("[migrate] applied %d migration(s), now at version %d\n",
               applied, current_ver);

    return applied;
}

bool schema_migration_rollback_last(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("schema_migration", "rollback: db not open");

    int current_ver = schema_migration_current_version(ndb);
    if (current_ver <= 0)
        LOG_FAIL("schema_migration", "rollback: no migrations to roll back");

    /* Find the migration matching current version */
    const struct schema_migration *m = schema_migration_get(current_ver);
    if (!m)
        LOG_FAIL("schema_migration", "rollback: v%d not in registry "
                 "(may be from old migration system)", current_ver);
    if (!m->down)
        LOG_FAIL("schema_migration", "rollback: v%d (%s) has no down function",
                 m->version, m->name);

    printf("[migrate] rolling back v%d: %s\n", m->version, m->name);

    if (!node_db_begin(ndb)) {
        fprintf(stderr, "[migrate] rollback v%d: BEGIN failed\n", m->version);
        return false;
    }

    if (!m->down(ndb)) {
        fprintf(stderr, "[migrate] rollback v%d (%s): down() FAILED\n",
                m->version, m->name);
        node_db_rollback(ndb);
        return false;
    }

    /* Remove from schema_migrations table.  The rollback body ran
     * already; if we can't record the rollback we'd have a node_state
     * pointer that says "current version is N" but a
     * schema_migrations row that says N was applied — internally
     * inconsistent and a trap for any future migration.  Treat any
     * failure as a hard bail. */
    char sql[256];
    snprintf(sql, sizeof(sql),
             "DELETE FROM schema_migrations WHERE version = '%03d'",
             m->version);
    if (!node_db_exec(ndb, sql)) {
        fprintf(stderr,
            "[migrate] rollback v%d: DELETE schema_migrations FAILED — "
            "aborting rollback\n", m->version);
        node_db_rollback(ndb);
        return false;
    }

    /* Find previous version and set it */
    int prev_ver = 0;
    for (int i = 0; i < g_migration_count; i++) {
        if (g_migrations[i].version < m->version &&
            g_migrations[i].version > prev_ver)
            prev_ver = g_migrations[i].version;
    }
    /* If no registered migration before this, fall back to the
     * version just below this one (could be from old system). */
    if (prev_ver == 0 && m->version > 1)
        prev_ver = m->version - 1;

    int32_t ver32 = (int32_t)prev_ver;
    if (!node_db_state_set(ndb, "schema_version", &ver32, sizeof(ver32))) {
        fprintf(stderr,
            "[migrate] rollback v%d: node_state schema_version UPDATE "
            "FAILED — aborting rollback\n", m->version);
        node_db_rollback(ndb);
        return false;
    }

    if (!node_db_commit(ndb)) {
        fprintf(stderr, "[migrate] rollback v%d: COMMIT failed\n", m->version);
        node_db_rollback(ndb);
        return false;
    }

    printf("[migrate] rolled back v%d: %s — now at v%d\n",
           m->version, m->name, prev_ver);
    return true;
}
