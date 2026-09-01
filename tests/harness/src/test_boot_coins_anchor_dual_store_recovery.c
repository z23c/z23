/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The §3 dual-store tear shape (node.db `utxos` has rows but the legacy
 * `coins_best_block` anchor is UNSET while coins_kv committed every block
 * atomically), under the wave-2 derived coins-best gate:
 *
 * GREEN (canonical datadir, coins_applied_height present): the boot gate
 * derives the coins-best fact from coins_kv's own co-committed state and
 * PASSES the open directly — the legacy-anchor tear is unrepresentable as
 * a boot failure, with ZERO mutations (no guess-repair of the cache). The
 * L1 heal (utxo_recovery_heal_torn_legacy_coins_anchor) is unreachable by
 * construction on this shape: boot gates it on !derived while its own
 * proven-authority predicate requires coins_applied_height (= derived).
 *
 * RED controls (legacy datadirs) prove no safety gate weakened:
 *   (RED-1) empty coins_kv -> open FAILS, heal REFUSES -> FATAL stands.
 *   (RED-2) coins_kv rows but migration_complete UNSET -> REFUSES -> FATAL.
 *
 * Reset-safe: coins_kv rows + applied_height asserted UNTOUCHED throughout.
 */

#include "test/test_core.h"

#include "models/database.h"
#include "models/block.h"
#include "services/utxo_recovery_service.h"
#include "storage/coins_view_sqlite.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Deterministic per-height block hash (distinct, non-null). */
static void bdsr_block_hash(uint8_t out[32], int height)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(height & 0xff);
    out[1] = (uint8_t)((height >> 8) & 0xff);
    out[2] = (uint8_t)((height >> 16) & 0xff);
    out[31] = 0xBD;
}

/* Seed node.db: utxos rows spanning H1-3..H1, a connected (status>=3) blocks
 * row at H1, and NO coins_best_block anchor — the torn-legacy shape. */
static bool bdsr_seed_node_db(struct node_db *ndb, int H1, uint8_t out_hash[32])
{
    bdsr_block_hash(out_hash, H1);

    sqlite3_stmt *s = NULL;
    for (int h = H1 - 3; h <= H1; h++) {
        for (int k = 0; k < 2; k++) {
            uint8_t txid[32];
            memset(txid, 0, 32);
            txid[0] = (uint8_t)h;
            txid[1] = (uint8_t)k;
            txid[31] = 0x55;
            /* script is BLOB NOT NULL — bind a non-null (empty) blob. */
            static const uint8_t empty_script[1] = {0};
            if (sqlite3_prepare_v2(ndb->db,
                    "INSERT INTO utxos(txid,vout,value,script,script_type,"
                    " address_hash,height,is_coinbase) "
                    "VALUES(?,0,1000,?,0,NULL,?,0)",
                    -1, &s, NULL) != SQLITE_OK)
                return false;
            sqlite3_bind_blob(s, 1, txid, 32, SQLITE_TRANSIENT);
            sqlite3_bind_blob(s, 2, empty_script, 0, SQLITE_STATIC);
            sqlite3_bind_int(s, 3, h);
            bool ok = sqlite3_step(s) == SQLITE_DONE;
            sqlite3_finalize(s);
            if (!ok) return false;
        }
    }

    /* Connected (status=3) blocks row at H1. db_block_save validates presence
     * of prev_hash (height!=0), merkle_root, non-zero time + bits. */
    struct db_block b;
    memset(&b, 0, sizeof(b));
    memcpy(b.hash, out_hash, 32);
    b.height = H1;
    b.prev_hash[0] = (uint8_t)((H1 - 1) & 0xff);
    b.prev_hash[31] = 0xBD;
    b.merkle_root[0] = 0xAB;
    b.time = 1700000000u;
    b.bits = 0x1d00ffffu;
    b.status = 3;
    /* blocks.solution is NOT NULL — supply a non-null Equihash solution blob. */
    uint8_t solution[8] = {0xE9, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    b.solution = solution;
    b.solution_len = sizeof(solution);
    if (!db_block_save(ndb, &b))
        return false;

    /* NO coins_best_block — leave the anchor UNSET (the tear). */
    return true;
}

/* Seed coins_kv in progress.kv with the same UTXO rows + applied_height = H1.
 * `mark_migration` controls whether coins_kv_migration_complete is set. */
static bool bdsr_seed_progress_kv(sqlite3 *pdb, int H1, bool mark_migration)
{
    if (!coins_kv_ensure_schema(pdb))
        return false;

    for (int h = H1 - 3; h <= H1; h++) {
        for (int k = 0; k < 2; k++) {
            uint8_t txid[32];
            memset(txid, 0, 32);
            txid[0] = (uint8_t)h;
            txid[1] = (uint8_t)k;
            txid[31] = 0x55;
            if (!coins_kv_add(pdb, txid, 0, 1000LL, h, false, NULL, 0))
                return false;
        }
    }

    /* applied_height via the production encoder (matches the reader exactly). */
    if (sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    bool ok = coins_kv_set_applied_height_in_tx(pdb, H1);
    if (sqlite3_exec(pdb, ok ? "COMMIT" : "ROLLBACK",
                     NULL, NULL, NULL) != SQLITE_OK)
        return false;
    if (!ok) return false;

    if (mark_migration) {
        uint8_t flag = 1;
        if (!progress_meta_set(pdb, "coins_kv_migration_complete", &flag, 1))
            return false;
    }
    return true;
}

/* True iff node.db coins_best_block is absent / empty. */
static bool bdsr_anchor_absent(struct node_db *ndb)
{
    uint8_t got[32];
    size_t len = 0;
    bool found = node_db_state_get(ndb, "coins_best_block",
                                   got, sizeof(got), &len);
    return !found || len == 0;
}

/* CASE 1 — GREEN: torn-legacy shape + proven-healthy coins_kv.
 *
 * Wave 2 (derived coins-best): with coins_applied_height present in
 * progress.kv, the boot gate's verdict is "derivation resolvable" — the
 * open PASSES DIRECTLY despite the torn legacy anchor, with ZERO mutations
 * (the cache stays torn; it is a diagnostic now, not a decision input).
 * The L1 torn-anchor heal is no longer needed here — and is in fact
 * unreachable by construction on this shape: boot gates the heal on
 * !derived, while the heal's own proven-authority predicate requires
 * coins_applied_height present (= derived). It survives only as the
 * legacy-datadir rung (RED cases below) until the wave-3 deletion. */
static int bdsr_green(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir),
                     "boot_coins_anchor_dual_store", "green");
    char node_path[512];
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    const int H1 = 100;

    TEST("bdsr GREEN: torn anchor + healthy coins_kv -> derived gate PASSES, "
         "zero mutations, no heal needed") {
        uint8_t want_hash[32];

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, node_path));
        ASSERT(bdsr_seed_node_db(&ndb, H1, want_hash));

        ASSERT(progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        ASSERT(pdb != NULL);
        ASSERT(bdsr_seed_progress_kv(pdb, H1, /*mark_migration=*/true));

        /* The open PASSES directly: the coins-best fact is DERIVED from
         * coins_kv's co-committed applied frontier; the torn legacy anchor
         * cannot wedge boot. */
        struct coins_view_sqlite cvs;
        ASSERT(coins_view_sqlite_open(&cvs, ndb.db));
        coins_view_sqlite_close(&cvs);

        /* ZERO mutations: the anchor cache is still torn (no guess-repair
         * wrote it) — caches are diagnostics, not decisions. */
        ASSERT(bdsr_anchor_absent(&ndb));

        /* Idempotent: a second open also passes. */
        ASSERT(coins_view_sqlite_open(&cvs, ndb.db));
        coins_view_sqlite_close(&cvs);

        /* Reset-safe: coins_kv rows + applied_height UNTOUCHED. */
        ASSERT(coins_kv_count(pdb) == 8);
        int32_t applied = 0; bool applied_found = false;
        ASSERT(coins_kv_get_applied_height(pdb, &applied, &applied_found));
        ASSERT(applied_found && applied == H1);

        node_db_close(&ndb);
        progress_store_close();
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* CASE 2 — RED: torn shape but NO coins_kv proof (empty/absent) -> refuses. */
static int bdsr_red_no_coins_kv(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir),
                     "boot_coins_anchor_dual_store", "red_no_kv");
    char node_path[512];
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    const int H1 = 100;

    TEST("bdsr RED: torn anchor + empty coins_kv -> refuses (FATAL preserved)") {
        uint8_t want_hash[32];

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, node_path));
        ASSERT(bdsr_seed_node_db(&ndb, H1, want_hash));

        /* progress.kv exists but coins_kv is EMPTY + migration unmarked. */
        ASSERT(progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        ASSERT(pdb != NULL);
        ASSERT(coins_kv_ensure_schema(pdb));

        struct coins_view_sqlite cvs;
        ASSERT(!coins_view_sqlite_open(&cvs, ndb.db));

        /* Recovery REFUSES: no proof coins_kv is the authority. */
        ASSERT(!utxo_recovery_heal_torn_legacy_coins_anchor(&ndb, pdb, dir));

        /* Anchor still UNSET -> the boot FATAL path stands unchanged. */
        ASSERT(bdsr_anchor_absent(&ndb));
        ASSERT(!coins_view_sqlite_open(&cvs, ndb.db));

        node_db_close(&ndb);
        progress_store_close();
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

/* CASE 3 — RED: coins_kv populated but migration_complete UNSET -> refuses. */
static int bdsr_red_migration_incomplete(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir),
                     "boot_coins_anchor_dual_store", "red_no_migration");
    char node_path[512];
    snprintf(node_path, sizeof(node_path), "%s/node.db", dir);
    const int H1 = 100;

    TEST("bdsr RED: coins_kv rows but migration unmarked -> refuses") {
        uint8_t want_hash[32];

        struct node_db ndb;
        ASSERT(node_db_open(&ndb, node_path));
        ASSERT(bdsr_seed_node_db(&ndb, H1, want_hash));

        ASSERT(progress_store_open(dir));
        sqlite3 *pdb = progress_store_db();
        ASSERT(pdb != NULL);
        /* Seed coins_kv rows + applied_height but DO NOT mark migration. */
        ASSERT(bdsr_seed_progress_kv(pdb, H1, /*mark_migration=*/false));

        struct coins_view_sqlite cvs;
        ASSERT(!coins_view_sqlite_open(&cvs, ndb.db));

        /* Refuses: migration flag absent -> coins_kv authority unproven. */
        ASSERT(!utxo_recovery_heal_torn_legacy_coins_anchor(&ndb, pdb, dir));
        ASSERT(bdsr_anchor_absent(&ndb));
        ASSERT(!coins_view_sqlite_open(&cvs, ndb.db));

        node_db_close(&ndb);
        progress_store_close();
        PASS();
    } _test_next:;
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_boot_coins_anchor_dual_store_recovery(void);
int test_boot_coins_anchor_dual_store_recovery(void)
{
    printf("\n=== boot_coins_anchor_dual_store_recovery (L1 torn-anchor) ===\n");
    int failures = 0;
    failures += bdsr_green();
    failures += bdsr_red_no_coins_kv();
    failures += bdsr_red_migration_incomplete();
    printf("boot_coins_anchor_dual_store_recovery: %d failures\n", failures);
    return failures;
}
