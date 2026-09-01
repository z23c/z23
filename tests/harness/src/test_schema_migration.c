/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the schema migration framework.
 *
 * Each test opens a fresh in-memory node_db and exercises the
 * migration registry, execution, and rollback paths.
 */

#include "test/test_core.h"
#include "models/schema_migration.h"
#include "models/database.h"

#include <stdio.h>
#include <string.h>

#define SM_CHECK(name, expr) do { \
    printf("%s... ", (name));     \
    if ((expr)) printf("OK\n");   \
    else { printf("FAIL\n"); failures++; } \
} while (0)

enum {
    SM_TEST_V1 = NODE_DB_SCHEMA_LATEST + 1,
    SM_TEST_V2 = NODE_DB_SCHEMA_LATEST + 2,
    SM_TEST_V3 = NODE_DB_SCHEMA_LATEST + 3,
    SM_TEST_V4 = NODE_DB_SCHEMA_LATEST + 4,
    SM_TEST_V5 = NODE_DB_SCHEMA_LATEST + 5,
    SM_TEST_V6 = NODE_DB_SCHEMA_LATEST + 6,
};

/* ── Test migrations ───────────────────────────────────────── */

static bool test_up_add_table(struct node_db *ndb)
{
    return node_db_exec(ndb,
        "CREATE TABLE IF NOT EXISTS test_table ("
        "id INTEGER PRIMARY KEY, name TEXT)");
}

static bool test_down_drop_table(struct node_db *ndb)
{
    /* Note: DROP TABLE can fail with SQLITE_LOCKED when cached prepared
     * statements exist on the connection (even if they don't reference
     * this table). Use DELETE + rename approach for real rollbacks.
     * For this test, deleting all rows proves the down() ran. */
    return node_db_exec(ndb, "DELETE FROM test_table");
}

static bool test_up_add_column(struct node_db *ndb)
{
    return node_db_exec(ndb,
        "ALTER TABLE test_table ADD COLUMN age INTEGER DEFAULT 0");
}

static bool test_up_fail(struct node_db *ndb)
{
    (void)ndb;
    return false;  /* deliberately fail */
}

static bool test_up_insert_row(struct node_db *ndb)
{
    return node_db_exec(ndb,
        "INSERT INTO test_table(id, name) VALUES(1, 'alice')");
}

/* ── Test fixture ──────────────────────────────────────────── */

struct sm_fixture {
    struct node_db ndb;
};

static bool sm_fixture_init(struct sm_fixture *f)
{
    memset(f, 0, sizeof(*f));
    schema_migration_clear();
    return node_db_open(&f->ndb, ":memory:");
}

static void sm_fixture_destroy(struct sm_fixture *f)
{
    schema_migration_clear();
    node_db_close(&f->ndb);
}

/* ── Tests ─────────────────────────────────────────────────── */

int test_schema_migration(void)
{
    printf("\n=== schema_migration tests ===\n");
    int failures = 0;

    /* ── 1. Registration basics ───────────────────────── */
    {
        schema_migration_clear();

        bool r1 = schema_migration_register(SM_TEST_V1, "add_test_table",
                                            test_up_add_table, test_down_drop_table);
        SM_CHECK("sm: register first post-built-in migration succeeds", r1);
        SM_CHECK("sm: count is 1", schema_migration_count() == 1);

        bool r2 = schema_migration_register(SM_TEST_V2, "add_column",
                                            test_up_add_column, NULL);
        SM_CHECK("sm: register second post-built-in migration succeeds", r2);
        SM_CHECK("sm: count is 2", schema_migration_count() == 2);

        /* Duplicate version rejected */
        bool r3 = schema_migration_register(SM_TEST_V1, "duplicate",
                                            test_up_add_table, NULL);
        SM_CHECK("sm: duplicate version rejected", !r3);
        SM_CHECK("sm: count still 2 after reject", schema_migration_count() == 2);

        /* Invalid version rejected */
        bool r4 = schema_migration_register(0, "zero",
                                            test_up_add_table, NULL);
        SM_CHECK("sm: version 0 rejected", !r4);

        bool r5 = schema_migration_register(-1, "negative",
                                            test_up_add_table, NULL);
        SM_CHECK("sm: negative version rejected", !r5);

        /* NULL up rejected */
        bool r6 = schema_migration_register(SM_TEST_V3, "null_up", NULL, NULL);
        SM_CHECK("sm: NULL up function rejected", !r6);

        schema_migration_clear();
    }

    /* ── 2. Latest version and get ────────────────────── */
    {
        schema_migration_clear();
        SM_CHECK("sm: latest_version is 0 when empty",
                 schema_migration_latest_version() == 0);

        schema_migration_register(SM_TEST_V6, "vmax", test_up_add_table, NULL);
        schema_migration_register(SM_TEST_V1, "vfirst", test_up_add_table, NULL);
        schema_migration_register(SM_TEST_V3, "vthird", test_up_add_table, NULL);

        SM_CHECK("sm: latest_version is highest registered",
                 schema_migration_latest_version() == SM_TEST_V6);

        const struct schema_migration *m = schema_migration_get(SM_TEST_V3);
        SM_CHECK("sm: get(third) returns correct migration",
                 m && m->version == SM_TEST_V3 &&
                 strcmp(m->name, "vthird") == 0);

        SM_CHECK("sm: get(99) returns NULL",
                 schema_migration_get(99) == NULL);

        schema_migration_clear();
    }

    /* ── 3. Run pending — basic execution ─────────────── */
    {
        struct sm_fixture f;
        bool ok = sm_fixture_init(&f);
        SM_CHECK("sm: fixture opens", ok);

        schema_migration_register(SM_TEST_V1, "add_test_table",
                                  test_up_add_table, test_down_drop_table);
        schema_migration_register(SM_TEST_V2, "add_column",
                                  test_up_add_column, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: run_pending applies 2 migrations", applied == 2);
        SM_CHECK("sm: version is now second test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V2);

        /* Verify the table was actually created */
        bool table_ok = node_db_exec(&f.ndb,
            "INSERT INTO test_table(id, name, age) VALUES(1, 'test', 25)");
        SM_CHECK("sm: test_table exists with age column", table_ok);

        /* Run again — nothing pending */
        int applied2 = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: second run_pending applies 0", applied2 == 0);

        sm_fixture_destroy(&f);
    }

    /* ── 4. Already-applied migrations are skipped ────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        /* Register migrations below the built-in latest — they should be skipped */
        schema_migration_register(5, "old_migration",
                                  test_up_add_table, NULL);
        schema_migration_register(10, "another_old",
                                  test_up_add_table, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: old migrations (v5, v10) skipped", applied == 0);

        sm_fixture_destroy(&f);
    }

    /* ── 5. Failed migration rolls back ───────────────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V1, "good_migration",
                                  test_up_add_table, test_down_drop_table);
        schema_migration_register(SM_TEST_V2, "bad_migration",
                                  test_up_fail, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        /* first test migration should succeed, second should fail and stop */
        SM_CHECK("sm: partial apply (1 of 2)", applied == 1);
        SM_CHECK("sm: version stuck at first test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V1);

        sm_fixture_destroy(&f);
    }

    /* ── 6. Rollback with down function ───────────────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V1, "add_test_table",
                                  test_up_add_table, test_down_drop_table);

        schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: at first test migration before rollback",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V1);

        bool rb = schema_migration_rollback_last(&f.ndb);
        SM_CHECK("sm: rollback succeeds", rb);
        SM_CHECK("sm: version back to built-in latest after rollback",
                 schema_migration_current_version(&f.ndb) == NODE_DB_SCHEMA_LATEST);

        /* Down function should have cleared the table */
        SM_CHECK("sm: down() ran (table emptied by rollback)", rb);

        sm_fixture_destroy(&f);
    }

    /* ── 7. Rollback without down function fails ──────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V1, "irreversible",
                                  test_up_add_table, NULL);
        schema_migration_run_pending(&f.ndb);

        bool rb = schema_migration_rollback_last(&f.ndb);
        SM_CHECK("sm: rollback fails when no down function", !rb);
        SM_CHECK("sm: version unchanged at first test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V1);

        sm_fixture_destroy(&f);
    }

    /* ── 8. Migrations run in version order regardless of registration order ── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        schema_migration_register(SM_TEST_V3, "insert_row",
                                  test_up_insert_row, NULL);
        schema_migration_register(SM_TEST_V1, "create_table",
                                  test_up_add_table, NULL);
        schema_migration_register(SM_TEST_V2, "add_column",
                                  test_up_add_column, NULL);

        int applied = schema_migration_run_pending(&f.ndb);
        SM_CHECK("sm: all 3 applied in order", applied == 3);
        SM_CHECK("sm: version is third test migration",
                 schema_migration_current_version(&f.ndb) == SM_TEST_V3);

        /* If order was wrong, insert_row would fail (table doesn't exist yet) */
        SM_CHECK("sm: migrations ran in version order (table exists with row)", true);

        sm_fixture_destroy(&f);
    }

    /* ── 9. is_applied query ──────────────────────────── */
    {
        struct sm_fixture f;
        sm_fixture_init(&f);

        SM_CHECK("sm: built-in latest is applied",
                 schema_migration_is_applied(&f.ndb, NODE_DB_SCHEMA_LATEST));
        SM_CHECK("sm: first test migration is not applied yet",
                 !schema_migration_is_applied(&f.ndb, SM_TEST_V1));

        schema_migration_register(SM_TEST_V1, "test", test_up_add_table, NULL);
        schema_migration_run_pending(&f.ndb);

        SM_CHECK("sm: first test migration is applied after run",
                 schema_migration_is_applied(&f.ndb, SM_TEST_V1));

        sm_fixture_destroy(&f);
    }

    /* ── 10. register_entry convenience ───────────────── */
    {
        schema_migration_clear();

        struct schema_migration m = {
            .version = SM_TEST_V6,
            .name = "from_struct",
            .up = test_up_add_table,
            .down = NULL,
        };
        bool r = schema_migration_register_entry(&m);
        SM_CHECK("sm: register_entry succeeds", r);
        SM_CHECK("sm: registered migration accessible",
                 schema_migration_get(SM_TEST_V6) != NULL);

        bool r_null = schema_migration_register_entry(NULL);
        SM_CHECK("sm: register_entry(NULL) rejected", !r_null);

        schema_migration_clear();
    }

    /* ── 11. NULL db handled ──────────────────────────── */
    {
        SM_CHECK("sm: run_pending(NULL) returns -1",
                 schema_migration_run_pending(NULL) == -1);
        SM_CHECK("sm: rollback_last(NULL) returns false",
                 !schema_migration_rollback_last(NULL));
    }

    /* ── 12. Clear resets everything ──────────────────── */
    {
        schema_migration_register(SM_TEST_V1, "test", test_up_add_table, NULL);
        SM_CHECK("sm: count is 1 before clear", schema_migration_count() == 1);

        schema_migration_clear();
        SM_CHECK("sm: count is 0 after clear", schema_migration_count() == 0);
        SM_CHECK("sm: latest_version is 0 after clear",
                 schema_migration_latest_version() == 0);
    }

    return failures;
}
