/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for seal_kv — the state-seal ring in progress.kv. The
 * load-bearing properties: a serialized record round-trips byte-stable; a
 * single flipped byte is caught by the self-hash; the ring is raise-only by
 * height, wraps at 4 slots, and steps over a corrupt newest slot to return
 * the prior good one. These are the guarantees window_rebuild (M2) leans on
 * when it selects "the newest self-hash-valid ratified seal". */

#include "test/test_core.h"

#include "storage/seal_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SK_CHECK(name, expr) do {                                       \
    if (expr) { printf("  seal_kv: %s... OK\n", (name)); }              \
    else { printf("  seal_kv: %s... FAIL\n", (name)); failures++; }     \
} while (0)

/* Build a deterministic seal_record for grid point g (height + every hash
 * field seeded distinctly so a field swap would be visible). */
static struct seal_record sk_make(int32_t g)
{
    struct seal_record r;
    memset(&r, 0, sizeof(r));
    r.height = g;
    for (int i = 0; i < 32; i++) {
        r.block_hash[i]    = (uint8_t)(g + i + 1);
        r.coins_sha3[i]    = (uint8_t)(g + i + 0x40);
        r.nullifier_sha3[i] = 0; /* M1: always zero */
        r.anchor_window_sha3[i] = (uint8_t)(g + i + 0x80);
    }
    r.utxo_count = (int64_t)g * 7 + 11;
    r.supply     = (int64_t)g * 1000000 + 333;
    r.ratified   = 0;
    r.sealed_at  = 1700000000 + g;
    return r;
}

/* Wrap seal_kv_insert_candidate_in_tx in its own BEGIN IMMEDIATE/COMMIT
 * exactly as the stage txn would. */
static bool sk_insert_committed(sqlite3 *db, const struct seal_record *r)
{
    progress_store_tx_lock();
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = seal_kv_insert_candidate_in_tx(db, r);
    sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    return ok;
}

int test_seal_kv(void);
int test_seal_kv(void)
{
    printf("\n=== seal_kv tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "seal_kv", "main");

    SK_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    SK_CHECK("db handle", db != NULL);
    SK_CHECK("ensure_schema", seal_kv_ensure_schema(db));
    SK_CHECK("ensure_schema idempotent", seal_kv_ensure_schema(db));

    /* ── serialize → deserialize roundtrip, byte-stable, all fields ── */
    {
        struct seal_record a = sk_make(2000);
        a.ratified = 1;
        uint8_t buf[SEAL_RECORD_BYTES];
        SK_CHECK("serialize", seal_serialize(&a, buf));

        struct seal_record b;
        bool self_ok = false;
        SK_CHECK("deserialize", seal_deserialize(buf, sizeof(buf), &b, &self_ok));
        SK_CHECK("self_sha3 valid on clean record", self_ok);

        bool fields_ok =
            b.height == a.height &&
            memcmp(b.block_hash, a.block_hash, 32) == 0 &&
            memcmp(b.coins_sha3, a.coins_sha3, 32) == 0 &&
            memcmp(b.nullifier_sha3, a.nullifier_sha3, 32) == 0 &&
            memcmp(b.anchor_window_sha3, a.anchor_window_sha3, 32) == 0 &&
            b.utxo_count == a.utxo_count &&
            b.supply == a.supply &&
            b.ratified == a.ratified &&
            b.sealed_at == a.sealed_at;
        SK_CHECK("all fields preserved", fields_ok);

        /* Re-serialize b → byte-identical buffer. */
        uint8_t buf2[SEAL_RECORD_BYTES];
        SK_CHECK("re-serialize", seal_serialize(&b, buf2));
        SK_CHECK("serialize is byte-stable",
                 memcmp(buf, buf2, SEAL_RECORD_BYTES) == 0);
    }

    /* ── self_sha3 tamper detection ── */
    {
        struct seal_record a = sk_make(2000);
        uint8_t buf[SEAL_RECORD_BYTES];
        seal_serialize(&a, buf);
        buf[10] ^= 0x01; /* flip a byte inside block_hash */
        struct seal_record b;
        bool self_ok = true;
        SK_CHECK("deserialize tampered record returns true",
                 seal_deserialize(buf, sizeof(buf), &b, &self_ok));
        SK_CHECK("tampered record self_ok==false", !self_ok);

        /* wrong length and bad version are hard-rejected. */
        SK_CHECK("short blob rejected",
                 !seal_deserialize(buf, SEAL_RECORD_BYTES - 1, &b, &self_ok));
        uint8_t buf3[SEAL_RECORD_BYTES];
        seal_serialize(&a, buf3);
        buf3[0] = 0xFE; /* bad version */
        SK_CHECK("bad version rejected",
                 !seal_deserialize(buf3, sizeof(buf3), &b, &self_ok));
    }

    /* ── ring raise-only by height ── */
    {
        struct seal_record g2000 = sk_make(2000);
        struct seal_record g1000 = sk_make(1000);
        struct seal_record g3000 = sk_make(3000);

        SK_CHECK("insert G=2000", sk_insert_committed(db, &g2000));
        struct seal_record n; bool found = false;
        SK_CHECK("newest read after 2000",
                 seal_kv_newest(db, &n, &found) && found);
        SK_CHECK("newest is 2000", n.height == 2000);

        /* lower G is a raise-only no-op (returns true, newest unchanged). */
        SK_CHECK("insert G=1000 (no-op)", sk_insert_committed(db, &g1000));
        SK_CHECK("newest still 2000",
                 seal_kv_newest(db, &n, &found) && found && n.height == 2000);

        SK_CHECK("insert G=3000", sk_insert_committed(db, &g3000));
        SK_CHECK("newest is 3000",
                 seal_kv_newest(db, &n, &found) && found && n.height == 3000);
    }

    /* ── ring wrap: 4 slots, oldest evicted, head advances mod 4 ── */
    {
        /* Fresh datadir for a clean ring count. */
        char dir2[256];
        test_make_tmpdir(dir2, sizeof(dir2), "seal_kv", "wrap");
        progress_store_close();
        SK_CHECK("reopen for wrap test", progress_store_open(dir2));
        sqlite3 *db2 = progress_store_db();
        seal_kv_ensure_schema(db2);

        int heights[5] = { 1000, 2000, 3000, 4000, 5000 };
        for (int i = 0; i < 5; i++) {
            struct seal_record r = sk_make(heights[i]);
            sk_insert_committed(db2, &r);
        }
        /* After 5 inserts into a 4-slot ring: heights 2000..5000 retained,
         * 1000 evicted. newest == 5000; get_at_height(1000) absent. */
        struct seal_record n; bool found = false;
        SK_CHECK("wrap: newest is 5000",
                 seal_kv_newest(db2, &n, &found) && found && n.height == 5000);
        bool f1000 = false; int slot = -1;
        SK_CHECK("wrap: 1000 evicted",
                 seal_kv_get_at_height(db2, 1000, &n, &f1000, &slot) && !f1000);
        bool f2000 = false;
        SK_CHECK("wrap: 2000 retained",
                 seal_kv_get_at_height(db2, 2000, &n, &f2000, &slot) && f2000);

        test_cleanup_tmpdir(dir2);
        /* reopen the original for the remaining checks. */
        progress_store_close();
        SK_CHECK("reopen original", progress_store_open(dir));
        db = progress_store_db();
    }

    /* ── corrupt-slot-skip: garbage in the newest slot → newest steps back ── */
    {
        /* Ring currently holds 2000 and 3000 (from raise-only test). Find the
         * slot holding 3000 (the newest) and overwrite it with garbage. */
        struct seal_record n; bool found = false; int slot = -1;
        SK_CHECK("locate newest slot",
                 seal_kv_get_at_height(db, 3000, &n, &found, &slot) && found);

        char key[24];
        snprintf(key, sizeof(key), "%s%d", SEAL_SLOT_KEY_PREFIX, slot);
        uint8_t garbage[SEAL_RECORD_BYTES];
        memset(garbage, 0xAB, sizeof(garbage));
        garbage[0] = (uint8_t)SEAL_RECORD_VERSION; /* keep version, break hash */
        SK_CHECK("write garbage into newest slot",
                 progress_meta_set(db, key, garbage, sizeof(garbage)));

        bool f = false;
        SK_CHECK("newest skips corrupt slot",
                 seal_kv_newest(db, &n, &f) && f && n.height == 2000);
    }

    /* ── newest_ratified: highest ratified among mixed slots ── */
    {
        char dir3[256];
        test_make_tmpdir(dir3, sizeof(dir3), "seal_kv", "ratify");
        progress_store_close();
        SK_CHECK("reopen for ratify test", progress_store_open(dir3));
        sqlite3 *db3 = progress_store_db();
        seal_kv_ensure_schema(db3);

        /* Insert 1000 (will ratify), 2000 (candidate). */
        struct seal_record r1 = sk_make(1000);
        struct seal_record r2 = sk_make(2000);
        sk_insert_committed(db3, &r1);
        sk_insert_committed(db3, &r2);

        bool nr_found = false; struct seal_record nr;
        SK_CHECK("no ratified yet",
                 seal_kv_newest_ratified(db3, &nr, &nr_found) && !nr_found);

        /* Ratify slot holding 1000. */
        struct seal_record at; bool found = false; int slot = -1;
        SK_CHECK("locate 1000", seal_kv_get_at_height(db3, 1000, &at, &found, &slot) && found);
        progress_store_tx_lock();
        sqlite3_exec(db3, "BEGIN IMMEDIATE", NULL, NULL, NULL);
        bool mok = seal_kv_mark_ratified_in_tx(db3, slot, &at);
        sqlite3_exec(db3, mok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock();
        SK_CHECK("mark 1000 ratified", mok);

        SK_CHECK("newest_ratified is 1000",
                 seal_kv_newest_ratified(db3, &nr, &nr_found) && nr_found
                 && nr.height == 1000 && nr.ratified == 1);
        /* newest (any) is still 2000. */
        struct seal_record n; bool found2 = false;
        SK_CHECK("newest (any) still 2000",
                 seal_kv_newest(db3, &n, &found2) && found2 && n.height == 2000);

        test_cleanup_tmpdir(dir3);
        progress_store_close();
        SK_CHECK("reopen original 2", progress_store_open(dir));
        db = progress_store_db();
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
