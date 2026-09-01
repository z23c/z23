/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_repair_marker — unit tests for the consolidated repair_marker table:
 * note/have/forget, payload roundtrip + truncation, gc_below, the raise-only
 * progress_meta_raise_u64_in_tx primitive, and the one-time progress_meta
 * migration (correctness + idempotency + convergence on a half-migrated store,
 * plus preservation of out-of-scope keys). */

#include "test/test_core.h"

#include "core/uint256.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RM_CHECK(name, expr) do {                                      \
    if (expr) { printf("  repair_marker: %s... OK\n", (name)); }        \
    else { printf("  repair_marker: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* A distinct deterministic 32-byte hash for seed g. */
static void rm_hash(int g, uint8_t out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = (uint8_t)(g * 7 + i + 3);
}

/* Wrap the raise-only _in_tx primitive in its own BEGIN IMMEDIATE/COMMIT,
 * exactly as the tip_finalize anchor txn does. */
static bool rm_raise(sqlite3 *db, const char *key, uint64_t v,
                     bool *raised, uint64_t *winner)
{
    progress_store_tx_lock();
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    if (ok)
        ok = progress_meta_raise_u64_in_tx(db, key, v, raised, winner);
    sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    return ok;
}

static bool rm_meta_present(sqlite3 *db, const char *key)
{
    uint8_t buf[128];
    size_t len = 0;
    bool found = false;
    return progress_meta_get(db, key, buf, sizeof(buf), &len, &found) && found;
}

int test_repair_marker(void);
int test_repair_marker(void)
{
    printf("\n=== repair_marker tests ===\n");
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "repair_marker", "main");

    RM_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    RM_CHECK("db handle", db != NULL);
    if (!db) return failures;
    /* The table is ensured at open; a second ensure must be a clean no-op. */
    RM_CHECK("table ensure idempotent", repair_marker_table_ensure(db));

    uint8_t h1[32], h2[32];
    rm_hash(1, h1);
    rm_hash(2, h2);
    bool have = false;

    /* ── presence note / have / forget ── */
    RM_CHECK("note presence", repair_marker_note(db, "k.a", 100, h1, NULL, 0));
    RM_CHECK("have present",
             repair_marker_have(db, "k.a", 100, h1, &have, NULL, 0, NULL) &&
             have);
    RM_CHECK("other height absent",
             repair_marker_have(db, "k.a", 101, h1, &have, NULL, 0, NULL) &&
             !have);
    RM_CHECK("other hash absent",
             repair_marker_have(db, "k.a", 100, h2, &have, NULL, 0, NULL) &&
             !have);
    RM_CHECK("other kind absent",
             repair_marker_have(db, "k.b", 100, h1, &have, NULL, 0, NULL) &&
             !have);
    RM_CHECK("forget", repair_marker_forget(db, "k.a", 100, h1));
    RM_CHECK("gone after forget",
             repair_marker_have(db, "k.a", 100, h1, &have, NULL, 0, NULL) &&
             !have);
    RM_CHECK("forget missing is no-op ok",
             repair_marker_forget(db, "k.a", 100, h1));

    /* ── payload roundtrip + upsert + truncation ── */
    {
        uint8_t pay[5] = { 1, 2, 3, 4, 5 };
        uint8_t out[16] = {0};
        size_t plen = 0;
        RM_CHECK("note payload", repair_marker_note(db, "k.p", 7, h1, pay, 5));
        RM_CHECK("have payload",
                 repair_marker_have(db, "k.p", 7, h1, &have, out, sizeof(out),
                                    &plen) &&
                 have && plen == 5 && memcmp(out, pay, 5) == 0);
        uint8_t pay2[3] = { 9, 9, 9 };
        RM_CHECK("upsert payload", repair_marker_note(db, "k.p", 7, h1, pay2, 3));
        memset(out, 0, sizeof(out));
        RM_CHECK("payload replaced on upsert",
                 repair_marker_have(db, "k.p", 7, h1, &have, out, sizeof(out),
                                    &plen) &&
                 have && plen == 3 && memcmp(out, pay2, 3) == 0);
        uint8_t small[2] = {0};
        RM_CHECK("truncation reports full stored length",
                 repair_marker_have(db, "k.p", 7, h1, &have, small, sizeof(small),
                                    &plen) &&
                 have && plen == 3 && small[0] == 9 && small[1] == 9);
    }

    /* ── gc_below ── */
    {
        for (int hgt = 10; hgt <= 40; hgt += 10)
            (void)repair_marker_note(db, "k.g", hgt, h1, NULL, 0);
        int del = repair_marker_gc_below(db, "k.g", 25);
        RM_CHECK("gc deletes strictly-below count", del == 2);
        RM_CHECK("gc kept at/above threshold (30)",
                 repair_marker_have(db, "k.g", 30, h1, &have, NULL, 0, NULL) &&
                 have);
        RM_CHECK("gc removed below threshold (20)",
                 repair_marker_have(db, "k.g", 20, h1, &have, NULL, 0, NULL) &&
                 !have);
        RM_CHECK("gc left other kind untouched",
                 repair_marker_have(db, "k.p", 7, h1, &have, NULL, 0, NULL) &&
                 have);
        RM_CHECK("gc with nothing below returns 0",
                 repair_marker_gc_below(db, "k.g", 0) == 0);
        RM_CHECK("gc bad input returns -1",
                 repair_marker_gc_below(db, NULL, 100) == -1);
    }

    /* ── raise-only u64 primitive ── */
    {
        bool raised = false;
        uint64_t winner = 0;
        RM_CHECK("raise absent writes",
                 rm_raise(db, "rk", 5, &raised, &winner) && raised &&
                 winner == 5);
        RM_CHECK("raise lower is no-op",
                 rm_raise(db, "rk", 3, &raised, &winner) && !raised &&
                 winner == 5);
        RM_CHECK("raise equal is no-op",
                 rm_raise(db, "rk", 5, &raised, &winner) && !raised &&
                 winner == 5);
        RM_CHECK("raise higher raises",
                 rm_raise(db, "rk", 9, &raised, &winner) && raised &&
                 winner == 9);
        /* Malformed floor (wrong length) fails closed, no side effect. */
        uint8_t four[4] = { 1, 2, 3, 4 };
        RM_CHECK("seed malformed floor", progress_meta_set(db, "rk2", four, 4));
        RM_CHECK("raise over malformed floor fails closed",
                 !rm_raise(db, "rk2", 100, &raised, &winner));
        uint8_t back[8] = {0};
        size_t bl = 0;
        bool found = false;
        RM_CHECK("malformed floor unchanged",
                 progress_meta_get(db, "rk2", back, sizeof(back), &bl, &found) &&
                 found && bl == 4);
    }

    /* ── one-time migration from the four legacy progress_meta namespaces ── */
    {
        struct uint256 u;
        rm_hash(9, u.data);
        char hex[65];
        uint256_get_hex(&u, hex);

        char k_ref[192], k_rf[192], k_uo[192], k_scan[192], k_rounds[192];
        snprintf(k_ref, sizeof(k_ref), "coin_backfill.refused.%d.%s", 42, hex);
        snprintf(k_rf, sizeof(k_rf),
                 "reducer_frontier.tipfin_backfill_repair.%d.%s", 50, hex);
        snprintf(k_uo, sizeof(k_uo),
                 "utxo_apply.value_overflow_repair.%d.%s", 60, hex);
        snprintf(k_scan, sizeof(k_scan), "coin_backfill.scan.%d.%s", 70, hex);
        snprintf(k_rounds, sizeof(k_rounds), "coin_backfill.rounds.%d.%s", 80,
                 hex);

        uint8_t one = 1;
        uint8_t scanblob[72];
        memset(scanblob, 0xAB, sizeof(scanblob));
        uint8_t rounds4[4] = { 3, 0, 0, 0 };
        uint8_t wit8[8] = { 5, 0, 0, 0, 1, 0, 0, 0 };

        /* Out-of-scope keys that MUST survive the migration untouched. */
        char k_outpoint[200];
        snprintf(k_outpoint, sizeof(k_outpoint),
                 "utxo_apply.coin_backfill.outpoint.%s:0", hex);

        bool seeded =
            progress_meta_set(db, k_ref, "spent:v2", 8) &&
            progress_meta_set(db, k_rf, &one, 1) &&
            progress_meta_set(db, k_uo, &one, 1) &&
            progress_meta_set(db, k_scan, scanblob, sizeof(scanblob)) &&
            progress_meta_set(db, k_rounds, rounds4, sizeof(rounds4)) &&
            progress_meta_set(db, "tipfin_backfill.progress", wit8, 8) &&
            progress_meta_set(db, k_outpoint, &one, 1) &&
            progress_meta_set(db, "coins_applied_height", wit8, 8);
        RM_CHECK("seed legacy keys", seeded);

        RM_CHECK("migrate runs", repair_marker_migrate_from_progress_meta(db));

        uint8_t out[128];
        size_t plen = 0;

        RM_CHECK("refused migrated w/ payload",
                 repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                                    42, u.data, &have, out, sizeof(out), &plen) &&
                 have && plen == 8 && memcmp(out, "spent:v2", 8) == 0);
        RM_CHECK("refused old key deleted", !rm_meta_present(db, k_ref));

        RM_CHECK("reducer_frontier repair migrated",
                 repair_marker_have(db, REPAIR_MARKER_KIND_RF_TIPFIN_BACKFILL,
                                    50, u.data, &have, NULL, 0, NULL) && have);
        RM_CHECK("reducer_frontier old key deleted", !rm_meta_present(db, k_rf));

        RM_CHECK("utxo value_overflow migrated",
                 repair_marker_have(db, REPAIR_MARKER_KIND_UTXO_VALUE_OVERFLOW,
                                    60, u.data, &have, NULL, 0, NULL) && have);
        RM_CHECK("utxo old key deleted", !rm_meta_present(db, k_uo));

        RM_CHECK("scan migrated w/ blob",
                 repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                                    70, u.data, &have, out, sizeof(out), &plen) &&
                 have && plen == sizeof(scanblob) && out[0] == 0xAB);
        RM_CHECK("scan old key deleted", !rm_meta_present(db, k_scan));

        RM_CHECK("rounds migrated w/ le32",
                 repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_ROUNDS,
                                    80, u.data, &have, out, sizeof(out), &plen) &&
                 have && plen == 4 && out[0] == 3);
        RM_CHECK("rounds old key deleted", !rm_meta_present(db, k_rounds));

        static const uint8_t zero_hash[32] = {0};
        RM_CHECK("tipfin witness migrated to (0,zero)",
                 repair_marker_have(db, REPAIR_MARKER_KIND_TIPFIN_PROGRESS,
                                    REPAIR_MARKER_TIPFIN_HEIGHT, zero_hash, &have,
                                    out, sizeof(out), &plen) &&
                 have && plen == 8 && out[0] == 5);
        RM_CHECK("tipfin witness old key deleted",
                 !rm_meta_present(db, "tipfin_backfill.progress"));

        /* Out-of-scope keys preserved. */
        RM_CHECK("outpoint marker preserved", rm_meta_present(db, k_outpoint));
        RM_CHECK("coins_applied_height preserved",
                 rm_meta_present(db, "coins_applied_height"));

        /* Idempotency: a second run is a clean no-op. */
        RM_CHECK("migrate idempotent (2nd run)",
                 repair_marker_migrate_from_progress_meta(db));
        RM_CHECK("refused still present after 2nd migrate",
                 repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                                    42, u.data, &have, NULL, 0, NULL) && have);

        /* Convergence on a half-migrated store: re-plant the old key (the row
         * already exists in repair_marker) and re-run — the old key must be
         * consumed again and the row must remain. */
        RM_CHECK("re-plant old key (half-migrated)",
                 progress_meta_set(db, k_ref, "spent:v2", 8));
        RM_CHECK("migrate converges half-migrated",
                 repair_marker_migrate_from_progress_meta(db));
        RM_CHECK("half-migrated old key consumed", !rm_meta_present(db, k_ref));
        RM_CHECK("half-migrated row intact",
                 repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                                    42, u.data, &have, out, sizeof(out), &plen) &&
                 have && plen == 8 && memcmp(out, "spent:v2", 8) == 0);
    }

    progress_store_close();
    printf("=== repair_marker tests complete: %d failure(s) ===\n", failures);
    return failures;
}
