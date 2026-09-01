/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for coins_kv_reset_for_reseed — the truncate+unstamp helper the
 * reindex epilogue runs before reseeding coins_kv from the freshly-replayed
 * node.db `utxos` mirror. The load-bearing assertion: after a reset, a
 * previously-populated+migration-stamped store reports count==0, the migration
 * stamp absent, and coins_applied_height absent — so a subsequent
 * coins_kv_seed_from_node_db (which short-circuits when the stamp is set) does
 * a FRESH copy rather than a no-op over a stale set. */

#include "test/test_core.h"

#include "core/uint256.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define CKR_CHECK(name, expr) do {                                       \
    if (expr) { printf("  coins_kv_reset: %s... OK\n", (name)); }         \
    else { printf("  coins_kv_reset: %s... FAIL\n", (name)); failures++; }\
} while (0)

static struct uint256 ckr_txid(uint8_t tag)
{
    struct uint256 t; uint256_set_null(&t);
    t.data[0] = tag; t.data[1] = 0xC0; t.data[31] = 0x77;
    return t;
}

/* Stamp the migration-complete key (own txn) — mirrors what the seed path
 * does so the test can prove the reset clears it. */
static bool ckr_stamp_migration(sqlite3 *db)
{
    uint8_t one = 1;
    return progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
}

static bool ckr_migration_stamped(sqlite3 *db)
{
    uint8_t v = 0; size_t n = 0; bool found = false;
    if (!progress_meta_get(db, COINS_KV_MIGRATION_COMPLETE_KEY,
                           &v, sizeof(v), &n, &found))
        return false;
    return found && n >= 1 && v == 1;
}

int test_coins_kv_reset_for_reseed(void);
int test_coins_kv_reset_for_reseed(void)
{
    printf("\n=== coins_kv_reset_for_reseed tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "coins_kv_reset", "main");

    CKR_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    CKR_CHECK("db handle", db != NULL);

    /* NULL handle -> graceful false (no crash). */
    CKR_CHECK("reset(NULL) -> false", !coins_kv_reset_for_reseed(NULL));

    /* Reset on a virgin store is a clean no-op (creates schema, deletes
     * nothing, clears absent keys) and returns true. */
    CKR_CHECK("reset on virgin store -> true", coins_kv_reset_for_reseed(db));
    CKR_CHECK("virgin: count == 0", coins_kv_count(db) == 0);
    uint64_t generation = 0;
    CKR_CHECK("virgin reset establishes authority generation",
              coins_kv_get_authority_generation(db, &generation) &&
              generation == 1);

    /* Populate a small set, set the applied frontier, and stamp migration —
     * the exact pre-reindex shape a reset must discard. */
    struct uint256 t1 = ckr_txid(0x31);
    unsigned char sc[4] = {0xD0, 0xD0, 0xD0, 0xD0};
    CKR_CHECK("add t1.0", coins_kv_add(db, t1.data, 0, 1234, 50, true, sc, sizeof(sc)));
    CKR_CHECK("add t1.1", coins_kv_add(db, t1.data, 1, 5678, 50, true, sc, sizeof(sc)));
    CKR_CHECK("count == 2 before reset", coins_kv_count(db) == 2);
    {
        char *err = NULL;
        bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
                  && coins_kv_set_applied_height_in_tx(db, 51)
                  && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
        if (err) sqlite3_free(err);
        CKR_CHECK("seed applied_height=51", ok);
    }
    CKR_CHECK("stamp migration complete", ckr_stamp_migration(db));

    /* Sanity: before reset the proven-authority predicate fires. */
    CKR_CHECK("proven authority before reset",
              coins_kv_is_proven_authority(db, NULL));

    /* THE reset. */
    CKR_CHECK("reset_for_reseed -> true", coins_kv_reset_for_reseed(db));
    CKR_CHECK("destructive reset advances authority generation",
              coins_kv_get_authority_generation(db, &generation) &&
              generation == 2);

    /* AFTER: the coin set is empty, the migration stamp is gone, and the
     * applied frontier is absent (a clean "unknown", not 0-as-applied). */
    CKR_CHECK("count == 0 after reset", coins_kv_count(db) == 0);
    CKR_CHECK("migration stamp cleared", !ckr_migration_stamped(db));
    {
        int32_t cur = -999; bool found = true;
        bool ok = coins_kv_get_applied_height(db, &cur, &found);
        CKR_CHECK("applied_height read ok", ok);
        CKR_CHECK("applied_height ABSENT after reset", !found);
    }
    CKR_CHECK("proven authority FALSE after reset",
              !coins_kv_is_proven_authority(db, NULL));

    /* Idempotent: a second reset on the now-empty store is still a clean
     * no-op true. */
    CKR_CHECK("reset idempotent", coins_kv_reset_for_reseed(db));
    CKR_CHECK("every reset advances authority generation",
              coins_kv_get_authority_generation(db, &generation) &&
              generation == 3);
    CKR_CHECK("count still 0", coins_kv_count(db) == 0);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
