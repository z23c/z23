/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for the sovereign-cure G-SOV groundwork (storage/coins_kv.h):
 *   - coins_kv_mark_self_folded / coins_kv_clear_self_folded / the reader
 *     coins_kv_contains_refold_marker (the durable "this coin set is
 *     self-derived, not the borrowed node.db copy" provenance bit), and
 *   - coins_kv_tip_is_self_derived(db, hstar) — the composite predicate for
 *     G-SOV parts 2 (coins_applied_height == hstar+1) and 3 (NOT
 *     borrowed-and-stamped, OR the self-folded marker is present).
 *
 * THE point of the predicate: coins_kv_is_proven_authority() is TRUE for BOTH a
 * self-folded set and the BORROWED zclassicd-chainstate copy (both stamp the
 * migration key), so the migration stamp alone cannot prove sovereignty. The
 * load-bearing assertions below pin the borrowed trap (proven authority + NO
 * marker => NOT self-derived) and the marker rescue (marker present => derived),
 * plus the not-yet-stamped branch (an un-stamped applied frontier is sovereign
 * by part 3's first disjunct).
 *
 * Part 1 of G-SOV (H* CLIMB) is a two-sample runtime fact the copy-prove
 * harness owns; this unit covers only the two single-snapshot parts. */

#include "test/test_core.h"

#include "core/uint256.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SOV_CHECK(name, expr) do {                                          \
    if (expr) { printf("  coins_kv_sovereign: %s... OK\n", (name)); }        \
    else { printf("  coins_kv_sovereign: %s... FAIL\n", (name)); failures++; }\
} while (0)

static struct uint256 sov_txid(uint8_t tag)
{
    struct uint256 t; uint256_set_null(&t);
    t.data[0] = tag; t.data[1] = 0x50; t.data[31] = 0x77;
    return t;
}

/* Stamp the migration-complete key (own txn) — mirrors what the borrowed seed
 * path does so the test can prove the marker is what separates borrowed from
 * self-derived. */
static bool sov_stamp_migration(sqlite3 *db)
{
    uint8_t one = 1;
    return progress_meta_set(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1);
}

static bool sov_set_applied(sqlite3 *db, int32_t h)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
              && coins_kv_set_applied_height_in_tx(db, h)
              && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

int test_coins_kv_sovereign_gate(void);
int test_coins_kv_sovereign_gate(void)
{
    printf("\n=== coins_kv sovereign gate (G-SOV parts 2+3) tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "coins_kv_sovereign", "main");

    SOV_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    SOV_CHECK("db handle", db != NULL);
    /* coins_kv_add writes the coins table — ensure its schema exists first
     * (progress_store_open does not create it). */
    SOV_CHECK("coins_kv schema", db && coins_kv_ensure_schema(db));

    /* NULL-db hardening: graceful false, no crash. */
    SOV_CHECK("contains_refold_marker(NULL) -> false",
              !coins_kv_contains_refold_marker(NULL));
    SOV_CHECK("mark_self_folded(NULL) -> false",
              !coins_kv_mark_self_folded(NULL));
    SOV_CHECK("clear_self_folded(NULL) -> false",
              !coins_kv_clear_self_folded(NULL));
    {
        char r[64] = {0};
        SOV_CHECK("tip_is_self_derived(NULL) -> false",
                  !coins_kv_tip_is_self_derived(NULL, 50, r, sizeof(r)));
        SOV_CHECK("null_db reason", strcmp(r, "null_db") == 0);
    }

    /* Virgin store: no applied frontier yet => NOT self-derived (part 2 fails),
     * and the marker is absent. */
    SOV_CHECK("virgin: marker absent", !coins_kv_contains_refold_marker(db));
    {
        char r[64] = {0};
        SOV_CHECK("virgin: tip not self-derived (applied absent)",
                  !coins_kv_tip_is_self_derived(db, 50, r, sizeof(r)));
        SOV_CHECK("virgin reason applied_height_absent",
                  strcmp(r, "applied_height_absent") == 0);
    }

    /* Populate a small live set + set applied_height=51 (so the matching H* is
     * 50), but DO NOT stamp the migration key. is_proven_authority is false, so
     * G-SOV part 3's FIRST disjunct (NOT borrowed-and-stamped) holds: a freshly
     * folded set whose migration stamp has not been written is sovereign. */
    struct uint256 t1 = sov_txid(0x51);
    unsigned char sc[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    SOV_CHECK("add t1.0", coins_kv_add(db, t1.data, 0, 1234, 50, true, sc, sizeof(sc)));
    SOV_CHECK("add t1.1", coins_kv_add(db, t1.data, 1, 5678, 50, true, sc, sizeof(sc)));
    SOV_CHECK("seed applied_height=51", sov_set_applied(db, 51));

    SOV_CHECK("not proven authority (migration unstamped)",
              !coins_kv_is_proven_authority(db, NULL));
    SOV_CHECK("unstamped: marker still absent",
              !coins_kv_contains_refold_marker(db));
    {
        char r[64] = {0};
        SOV_CHECK("unstamped: self-derived at hstar=50 (part 3 first disjunct)",
                  coins_kv_tip_is_self_derived(db, 50, r, sizeof(r)));
        /* part 2 must reject a mismatched H*. */
        SOV_CHECK("wrong hstar=49 -> not self-derived",
                  !coins_kv_tip_is_self_derived(db, 49, r, sizeof(r)));
        SOV_CHECK("wrong-hstar reason applied!=hstar+1",
                  strncmp(r, "applied_height=51", 17) == 0);
    }

    /* Now stamp migration — this is exactly the BORROWED-seed shape
     * (coins_kv_seed_from_node_db stamps the migration key). is_proven_authority
     * becomes true and, with NO self-folded marker, the tip is borrowed-and-
     * stamped: G-SOV part 3 must REJECT it (the trap the cure exists to close). */
    SOV_CHECK("stamp migration", sov_stamp_migration(db));
    SOV_CHECK("proven authority after stamp",
              coins_kv_is_proven_authority(db, NULL));
    {
        char r[64] = {0};
        SOV_CHECK("borrowed-stamped + no marker -> NOT self-derived",
                  !coins_kv_tip_is_self_derived(db, 50, r, sizeof(r)));
        SOV_CHECK("borrowed reason",
                  strcmp(r, "borrowed_seed_no_refold_marker") == 0);
    }

    /* Stamp the self-folded marker (the SET edge the cutover wires onto the
     * self-derived reseed/fold). Now the same proven-authority store is proven
     * SELF-DERIVED: part 3's SECOND disjunct holds. */
    SOV_CHECK("mark_self_folded -> true", coins_kv_mark_self_folded(db));
    SOV_CHECK("marker now present", coins_kv_contains_refold_marker(db));
    {
        char r[64] = {0};
        SOV_CHECK("borrowed-stamped + marker -> self-derived",
                  coins_kv_tip_is_self_derived(db, 50, r, sizeof(r)));
    }

    /* mark is idempotent. */
    SOV_CHECK("mark_self_folded idempotent", coins_kv_mark_self_folded(db));
    SOV_CHECK("marker still present", coins_kv_contains_refold_marker(db));

    /* Clearing the marker drops the set back to borrowed-and-stamped (the cure
     * clears on any borrowed reseed so a stale claim cannot survive). */
    SOV_CHECK("clear_self_folded -> true", coins_kv_clear_self_folded(db));
    SOV_CHECK("marker cleared", !coins_kv_contains_refold_marker(db));
    {
        char r[64] = {0};
        SOV_CHECK("after clear -> NOT self-derived again",
                  !coins_kv_tip_is_self_derived(db, 50, r, sizeof(r)));
    }
    SOV_CHECK("clear_self_folded idempotent (absent key)",
              coins_kv_clear_self_folded(db));

    /* A reseed reset is a stronger clear edge: it drops coins/frontier plus both
     * provenance keys so a future borrowed seed cannot inherit a stale
     * self-folded claim. */
    SOV_CHECK("mark_self_folded before reset", coins_kv_mark_self_folded(db));
    SOV_CHECK("marker present before reset", coins_kv_contains_refold_marker(db));
    SOV_CHECK("reset_for_reseed clears store", coins_kv_reset_for_reseed(db));
    SOV_CHECK("reset cleared marker", !coins_kv_contains_refold_marker(db));
    SOV_CHECK("reset removed coins", coins_kv_count(db) == 0);
    {
        char r[64] = {0};
        SOV_CHECK("reset -> NOT self-derived (applied absent)",
                  !coins_kv_tip_is_self_derived(db, 50, r, sizeof(r)));
        SOV_CHECK("reset reason applied_height_absent",
                  strcmp(r, "applied_height_absent") == 0);
    }

    /* The coins_kv_mark_migration_complete primitive is the earned-fact edge the
     * mint finalize + ratify paths write: with an applied frontier + a non-empty
     * set present, stamping it FLIPS coins_kv_is_proven_authority to true (rung 2
     * of the three rungs). The store was cleared by reset_for_reseed above. */
    SOV_CHECK("mark_migration_complete(NULL) -> false",
              !coins_kv_mark_migration_complete(NULL));
    struct uint256 t2 = sov_txid(0x62);
    SOV_CHECK("re-add t2.0", coins_kv_add(db, t2.data, 0, 4321, 60, true, sc, sizeof(sc)));
    SOV_CHECK("re-seed applied_height=61", sov_set_applied(db, 61));
    SOV_CHECK("not proven authority before migration stamp",
              !coins_kv_is_proven_authority(db, NULL));
    SOV_CHECK("mark_migration_complete -> true",
              coins_kv_mark_migration_complete(db));
    {
        int32_t applied = -1;
        SOV_CHECK("proven authority after migration stamp",
                  coins_kv_is_proven_authority(db, &applied));
        SOV_CHECK("proven authority reports applied=61", applied == 61);
    }
    SOV_CHECK("mark_migration_complete idempotent",
              coins_kv_mark_migration_complete(db));
    SOV_CHECK("still proven authority after idempotent stamp",
              coins_kv_is_proven_authority(db, NULL));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
