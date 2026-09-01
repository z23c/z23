/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit + fixture tests for consensus_db — the one-time, integrity-verified
 * migration of the reducer's consensus kernel atomic set out of progress.kv
 * into a dedicated consensus.db.
 *
 * The load-bearing assertions:
 *   1. A populated progress.kv migrates into a consensus.db whose kernel
 *      fingerprint (SHA3 UTXO commitment + every kernel-table row count)
 *      equals the source byte-for-byte.
 *   2. The migration is idempotent (no-op once consensus.db exists) and a
 *      clean no-op on a fresh node (no progress.kv), never creating an empty
 *      consensus.db.
 *   3. REFUSAL: the verify predicate the migration gates on
 *      (consensus_db_kernel_stats_match) rejects a diverging SHA3 commitment
 *      and a diverging row count with a typed message, and a migration whose
 *      copy fails leaves NO consensus.db behind (fail fast, never half-state). */

#include "test/test_core.h"

#include "storage/anchor_kv.h"
#include "storage/consensus_db.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/stage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CK(name, expr) do {                                                 \
    if (expr) { printf("  consensus_db_migrate: %s... OK\n", (name)); }      \
    else { printf("  consensus_db_migrate: %s... FAIL\n", (name)); failures++; } \
} while (0)

static void cdbt_txid(uint8_t out[32], uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = tag;
    out[31] = 0xC0;
}

static bool cdbt_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK && err) {
        printf("    (exec failed: %s)\n", err);
    }
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

/* Build a populated progress.kv at <dir>/progress.kv with a small but complete
 * kernel: 3 coins, 1 sprout + 1 sapling anchor, 2 anchor_state rows, 2
 * nullifiers, 2 stage cursors, 1 progress_meta row. Returns true on success. */
static bool cdbt_build_source(const char *dir)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = coins_kv_ensure_schema(db) && anchor_kv_ensure_schema(db) &&
              nullifier_kv_ensure_schema(db) && progress_meta_table_ensure(db) &&
              stage_table_ensure(db);

    for (int i = 0; ok && i < 3; i++) {
        uint8_t txid[32];
        cdbt_txid(txid, (uint8_t)(0x10 + i));
        uint8_t script[4] = {0x76, 0xa9, 0x14, (uint8_t)i};
        ok = coins_kv_add(db, txid, (uint32_t)i, 5000 + i, 100 + i,
                          i == 0, script, sizeof(script));
    }

    ok = ok &&
         cdbt_exec(db,
             "INSERT INTO sprout_anchors(anchor,height,tree) "
             "VALUES(x'aa01',101,x'01')") &&
         cdbt_exec(db,
             "INSERT INTO sapling_anchors(anchor,height,tree) "
             "VALUES(x'bb01',102,x'02')") &&
         cdbt_exec(db,
             "INSERT INTO anchor_state(pool,activation_cursor) VALUES(0,0)") &&
         cdbt_exec(db,
             "INSERT INTO anchor_state(pool,activation_cursor) VALUES(1,102)") &&
         cdbt_exec(db,
             "INSERT INTO nullifiers(nf,pool,height) VALUES(x'cc01',0,50)") &&
         cdbt_exec(db,
             "INSERT INTO nullifiers(nf,pool,height) VALUES(x'cc02',1,51)") &&
         cdbt_exec(db,
             "INSERT INTO stage_cursor(name,cursor,updated_at) "
             "VALUES('utxo_apply',100,1)") &&
         cdbt_exec(db,
             "INSERT INTO stage_cursor(name,cursor,updated_at) "
             "VALUES('proof_validate',101,1)") &&
         cdbt_exec(db,
             "INSERT INTO progress_meta(key,value) "
             "VALUES('coins_applied_height',x'64')");

    sqlite3_close(db);
    return ok;
}

/* Read the source kernel fingerprint by reopening <dir>/progress.kv. */
static bool cdbt_source_stats(const char *dir,
                              struct consensus_db_kernel_stats *out)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    bool ok = consensus_db_read_kernel_stats(db, out, NULL, 0);
    sqlite3_close(db);
    return ok;
}

int test_consensus_db_migrate(void);
int test_consensus_db_migrate(void)
{
    int failures = 0;
    char err[256];

    /* ── Fresh node: no progress.kv ──────────────────────────────── */
    char fresh[256];
    test_make_tmpdir(fresh, sizeof(fresh), "consensus_db_migrate", "fresh");
    char fresh_c[300];
    snprintf(fresh_c, sizeof(fresh_c), "%s/consensus.db", fresh);
    CK("fresh node migrate returns success",
       consensus_db_migrate_from_progress(fresh, err, sizeof(err)));
    CK("fresh node creates no consensus.db", access(fresh_c, F_OK) != 0);
    test_cleanup_tmpdir(fresh);

    /* ── Populated progress.kv migrates + verifies ───────────────── */
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "consensus_db_migrate", "main");
    char cpath[300];
    snprintf(cpath, sizeof(cpath), "%s/consensus.db", dir);

    CK("source progress.kv builds", cdbt_build_source(dir));

    struct consensus_db_kernel_stats src_stats;
    CK("source fingerprint reads", cdbt_source_stats(dir, &src_stats));

    err[0] = '\0';
    CK("migrate succeeds",
       consensus_db_migrate_from_progress(dir, err, sizeof(err)));
    CK("consensus.db created", access(cpath, F_OK) == 0);

    struct consensus_db_kernel_stats dst_stats;
    {
        sqlite3 *cdb = NULL;
        CK("consensus.db opens",
           sqlite3_open_v2(cpath, &cdb, SQLITE_OPEN_READONLY, NULL) ==
               SQLITE_OK);
        CK("dst fingerprint reads",
           cdb && consensus_db_read_kernel_stats(cdb, &dst_stats, NULL, 0));
        if (cdb) sqlite3_close(cdb);
    }

    err[0] = '\0';
    CK("migrated fingerprint matches source byte-for-byte",
       consensus_db_kernel_stats_match(&src_stats, &dst_stats, err, sizeof(err)));
    /* Stable table order: coins,sprout,sapling,anchor_state,nullifiers,meta,stage */
    CK("coins rows copied (3)", dst_stats.table_rows[0] == 3);
    CK("sprout_anchors copied (1)", dst_stats.table_rows[1] == 1);
    CK("sapling_anchors copied (1)", dst_stats.table_rows[2] == 1);
    CK("anchor_state copied (2)", dst_stats.table_rows[3] == 2);
    CK("nullifiers copied (2)", dst_stats.table_rows[4] == 2);
    CK("progress_meta copied (1)", dst_stats.table_rows[5] == 1);
    CK("stage_cursor copied (2)", dst_stats.table_rows[6] == 2);

    /* ── Idempotent ─────────────────────────────────────────────── */
    CK("idempotent second migrate is a no-op success",
       consensus_db_migrate_from_progress(dir, err, sizeof(err)));

    /* ── Refusal: verify predicate rejects divergence ───────────── */
    {
        struct consensus_db_kernel_stats bad = src_stats;
        bad.coins_commit[0] ^= 0xffu;
        err[0] = '\0';
        CK("diverging SHA3 commitment refused",
           !consensus_db_kernel_stats_match(&src_stats, &bad, err, sizeof(err)) &&
               strstr(err, "sha3") != NULL);
    }
    {
        struct consensus_db_kernel_stats bad = src_stats;
        bad.table_rows[6] += 1; /* stage_cursor count off by one */
        err[0] = '\0';
        CK("diverging row count refused",
           !consensus_db_kernel_stats_match(&src_stats, &bad, err, sizeof(err)) &&
               strstr(err, "count") != NULL);
    }
    test_cleanup_tmpdir(dir);

    /* ── Refusal end-to-end: a copy that cannot faithfully reproduce the
     *    source leaves NO consensus.db. Model it with a source `coins` table
     *    that carries an extra column, so `INSERT ... SELECT *` fails. ── */
    {
        char bdir[256];
        test_make_tmpdir(bdir, sizeof(bdir), "consensus_db_migrate", "refuse");
        char bpath[300], bc[300];
        snprintf(bpath, sizeof(bpath), "%s/progress.kv", bdir);
        snprintf(bc, sizeof(bc), "%s/consensus.db", bdir);
        sqlite3 *sdb = NULL;
        bool built = sqlite3_open(bpath, &sdb) == SQLITE_OK &&
                     cdbt_exec(sdb,
                         "CREATE TABLE coins (txid BLOB NOT NULL, vout INTEGER "
                         "NOT NULL, value INTEGER NOT NULL, height INTEGER NOT "
                         "NULL, is_coinbase INTEGER NOT NULL, script BLOB NOT "
                         "NULL, extra INTEGER NOT NULL, PRIMARY KEY(txid,vout)) "
                         "WITHOUT ROWID") &&
                     cdbt_exec(sdb,
                         "INSERT INTO coins VALUES(x'01',0,1,1,0,x'00',7)");
        if (sdb) sqlite3_close(sdb);
        CK("refusal fixture builds", built);
        err[0] = '\0';
        CK("migrate refuses a non-reproducible copy",
           !consensus_db_migrate_from_progress(bdir, err, sizeof(err)));
        CK("refused migrate leaves no consensus.db", access(bc, F_OK) != 0);
        char btmp[320];
        snprintf(btmp, sizeof(btmp), "%s/consensus.db.tmp", bdir);
        CK("refused migrate leaves no consensus.db.tmp",
           access(btmp, F_OK) != 0);
        test_cleanup_tmpdir(bdir);
    }

    printf("consensus_db_migrate: %d failures\n", failures);
    return failures;
}
