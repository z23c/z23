/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the wallet-backup storage seam.
 *
 * wallet_backup_service.c performs its sqlite work (source-path lookup,
 * row counts, and the ATTACH + CREATE-TABLE-AS-SELECT snapshot + verify
 * reopen) through wallet_backup_store_port. This file exercises the sqlite
 * adapter that now backs those ops — against ISOLATED file-backed fixture
 * DBs in ./test-tmp, never the live node DB.
 *
 * The adapter ATTACHes the source by its on-disk path, so the fixtures are
 * real files (an in-memory source has no path — that case is asserted to
 * fail source_path()).
 *
 * Coverage:
 *   - source_path resolves a file-backed source; false for in-memory.
 *   - count_rows over the source counts wallet_keys exactly.
 *   - write_snapshot copies every wallet table that exists, skips missing
 *     ones, and returns WB_STORE_OK; the backup file is created.
 *   - count_rows_in_file reopens the backup and counts rows.
 *   - SECURITY: the private-key BLOB bytes round-trip byte-for-byte into
 *     the backup file (no decode/decrypt/transform across the boundary),
 *     and NO port method ever surfaces key material — only paths/counts.
 *   - Driving wallet_backup_run_once over the same fixture produces a
 *     verified backup whose keys match the source bit-for-bit.
 *   - NULL / bad-arg guards.
 *
 * NOTE on coupling: test_wallet_backup.c drives the full service over its
 * own fixtures and is left untouched; this file is hermetic.
 */

#include "test/test_core.h"
#include "platform/private_directory.h"

#include "adapters/outbound/persistence/wallet_backup_store_sqlite.h"
#include "ports/wallet_backup_store_port.h"
#include "services/wallet_backup_service.h"
#include "models/database.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WBP_DIR "./test-tmp"

#define WBP_CHECK(name, expr) do {                       \
    printf("wallet_backup_port: %s... ", (name));        \
    if ((expr)) { printf("OK\n"); }                      \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* The full wallet table set the service snapshots, mirrored here so the
 * test exercises the same list (missing tables must be skipped, present
 * ones copied). */
static const char *const WBP_TABLES[] = {
    "wallet_keys",
    "wallet_sapling_keys",
    "wallet_seed",
    "wallet_scripts",
    "wallet_transactions",
    "wallet_utxos",
    "wallet_sapling_notes",
};
#define WBP_TABLE_COUNT (sizeof(WBP_TABLES) / sizeof(WBP_TABLES[0]))

/* Deterministic private-key bytes for row i; the security assertion later
 * recomputes these and demands an exact match in the backup file. */
static void wbp_privkey_for(int i, uint8_t out[32])
{
    for (int b = 0; b < 32; b++)
        out[b] = (uint8_t)((i * 31 + b * 7 + 0x80) & 0xff);
}

/* Seed N wallet_keys rows into an open node_db. Uses raw sqlite here only
 * because this is TEST fixture code seeding the source, not the adapter. */
static int wbp_seed_keys(struct node_db *ndb, int n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
        "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed) "
        "VALUES(?,?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return 0;
    int wrote = 0;
    for (int i = 0; i < n; i++) {
        uint8_t hash[20] = {0}, pub[33] = {0}, priv[32];
        hash[0] = (uint8_t)(i + 1);
        pub[0] = 0x02; pub[1] = (uint8_t)(i + 1);
        wbp_privkey_for(i, priv);
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, hash, sizeof(hash), SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, pub,  sizeof(pub),  SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, priv, sizeof(priv), SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_DONE) wrote++;
    }
    sqlite3_finalize(st);
    return wrote;
}

/* Fetch privkey BLOB for pubkey_hash[0]==tag from a backup FILE opened
 * read-only. Returns true and fills out[32] on an exact 32-byte hit. */
static bool wbp_file_privkey(const char *path, uint8_t tag, uint8_t out[32])
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *st = NULL;
    bool got = false;
    if (sqlite3_prepare_v2(db,
        "SELECT privkey FROM wallet_keys WHERE pubkey_hash=?",
        -1, &st, NULL) == SQLITE_OK) {
        uint8_t hash[20] = {0};
        hash[0] = tag;
        sqlite3_bind_blob(st, 1, hash, sizeof(hash), SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const void *blob = sqlite3_column_blob(st, 0);
            int len = sqlite3_column_bytes(st, 0);
            if (blob && len == 32) {
                memcpy(out, blob, 32);
                got = true;
            }
        }
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return got;
}

static void wbp_rm(const char *path)
{
    if (path && path[0]) unlink(path);
}

int test_wallet_backup_port(void)
{
    int failures = 0;
    mkdir(WBP_DIR, 0755);

    char src_db_path[256];
    char dst_path[256];
    snprintf(src_db_path, sizeof(src_db_path),
             WBP_DIR "/wbp_%d_src.db", (int)getpid());
    snprintf(dst_path, sizeof(dst_path),
             WBP_DIR "/wbp_%d_backup.sqlite", (int)getpid());
    wbp_rm(src_db_path);
    wbp_rm(dst_path);

    /* ---- file-backed source: bind + the four methods ---- */
    struct node_db ndb;
    bool opened = node_db_open(&ndb, src_db_path);
    WBP_CHECK("source node_db opens", opened);
    if (!opened) return failures + 1;

    int seeded = wbp_seed_keys(&ndb, 5);
    WBP_CHECK("seeded 5 wallet_keys", seeded == 5);

    struct wallet_backup_store_sqlite_ctx ctx;
    struct wallet_backup_store_port port = {0};
    WBP_CHECK("bind ok",
              wallet_backup_store_sqlite_bind(&ctx, ndb.db, &port));

    /* source_path resolves the on-disk file. */
    char resolved[1024] = {0};
    bool sp_ok = port.source_path(port.self, resolved, sizeof(resolved));
    WBP_CHECK("source_path returns true on file db", sp_ok);
    WBP_CHECK("source_path is non-empty", resolved[0] != '\0');

    /* count_rows over the source. */
    int64_t src_keys = -1;
    bool cr_ok = port.count_rows(port.self, "wallet_keys", &src_keys);
    WBP_CHECK("count_rows ok", cr_ok);
    WBP_CHECK("count_rows == 5", src_keys == 5);

    /* count_rows on a non-existent table returns false, leaves *out. */
    int64_t bogus = -123;
    bool cr_bad = port.count_rows(port.self, "no_such_table", &bogus);
    WBP_CHECK("count_rows missing table false", !cr_bad);
    WBP_CHECK("count_rows missing leaves out untouched", bogus == -123);

    /* write_snapshot copies present tables and RECORDS missing ones. */
    char copy_err[256] = {0};
    struct wallet_backup_table_stat stats[WBP_TABLE_COUNT];
    enum wallet_backup_store_status st =
        port.write_snapshot(port.self, dst_path, resolved,
                            WBP_TABLES, WBP_TABLE_COUNT,
                            stats, copy_err, sizeof(copy_err));
    WBP_CHECK("write_snapshot WB_STORE_OK", st == WB_STORE_OK);

    /* Every requested table gets a stat entry naming it, whether or not
     * the source had it — the "silently skipped" behaviour is gone. */
    bool stats_named = true;
    for (size_t i = 0; i < WBP_TABLE_COUNT; i++)
        if (strcmp(stats[i].table, WBP_TABLES[i]) != 0)
            stats_named = false;
    WBP_CHECK("write_snapshot names every requested table in stats",
              stats_named);
    WBP_CHECK("wallet_keys stat: present with 5 rows",
              stats[0].present_in_source && stats[0].rows == 5);

    /* The manifest lands in the backup file and describes all seven. */
    int64_t manifest_rows = port.count_rows_in_file(
        port.self, dst_path, WALLET_BACKUP_MANIFEST_TABLE);
    WBP_CHECK("backup carries a manifest row per requested table",
              manifest_rows == (int64_t)WBP_TABLE_COUNT);

    struct stat fst;
    WBP_CHECK("backup file exists, non-empty",
              stat(dst_path, &fst) == 0 && fst.st_size > 0);

    /* count_rows_in_file reads the backup. */
    int64_t dst_keys = port.count_rows_in_file(port.self, dst_path,
                                               "wallet_keys");
    WBP_CHECK("count_rows_in_file == 5", dst_keys == 5);

    /* SECURITY: every seeded privkey BLOB is byte-identical in the
     * backup file. The bytes were never decoded across the boundary. */
    bool all_keys_identical = true;
    for (int i = 0; i < seeded; i++) {
        uint8_t want[32];
        uint8_t got[32];
        wbp_privkey_for(i, want);
        if (!wbp_file_privkey(dst_path, (uint8_t)(i + 1), got) ||
            memcmp(want, got, 32) != 0) {
            all_keys_identical = false;
            break;
        }
    }
    WBP_CHECK("privkey BLOBs round-trip byte-for-byte into backup",
              all_keys_identical);

    /* ---- drive the SERVICE primitive over the same fixture ---- */
    {
        char svc_dir[256];
        snprintf(svc_dir, sizeof(svc_dir),
                 WBP_DIR "/wbp_%d_svc_out", (int)getpid());
        /* A plain Windows mkdir inherits the parent DACL.  Create this leaf
         * through the production owner-private seam so run_once can validate
         * the exact directory object on every platform. */
        WBP_CHECK("service output directory is owner-private",
                  platform_private_directory_ensure(svc_dir));

        char out_path[512] = {0};
        int64_t out_keys = -1;
        char err[256] = {0};
        struct zcl_result r = wallet_backup_run_once(svc_dir, &ndb,
                                  out_path, sizeof(out_path),
                                  &out_keys, err, sizeof(err));
        WBP_CHECK("service run_once ok over port", r.ok);
        WBP_CHECK("service run_once key_count == 5", out_keys == 5);

        /* The service's verified backup carries the same key bytes. */
        bool svc_key_match = true;
        for (int i = 0; i < seeded && r.ok; i++) {
            uint8_t want[32], got[32];
            wbp_privkey_for(i, want);
            if (!wbp_file_privkey(out_path, (uint8_t)(i + 1), got) ||
                memcmp(want, got, 32) != 0) {
                svc_key_match = false;
                break;
            }
        }
        WBP_CHECK("service backup preserves privkey bytes", svc_key_match);

        wbp_rm(out_path);
        test_cleanup_tmpdir(svc_dir);
    }

    /* ---- NULL / bad-arg guards ---- */
    {
        struct wallet_backup_store_sqlite_ctx c2;
        struct wallet_backup_store_port p2 = {0};
        WBP_CHECK("bind rejects NULL ctx",
                  !wallet_backup_store_sqlite_bind(NULL, ndb.db, &p2));
        WBP_CHECK("bind rejects NULL out_port",
                  !wallet_backup_store_sqlite_bind(&c2, ndb.db, NULL));

        /* NULL src_db is permitted by bind; the source-reading methods
         * then fail safely (mirroring "db not open"). */
        struct wallet_backup_store_port pnull = {0};
        WBP_CHECK("bind accepts NULL src_db",
                  wallet_backup_store_sqlite_bind(&c2, NULL, &pnull));
        char buf[64] = "x";
        WBP_CHECK("source_path false on NULL src_db",
                  !pnull.source_path(pnull.self, buf, sizeof(buf)));
        int64_t n = -7;
        WBP_CHECK("count_rows false on NULL src_db",
                  !pnull.count_rows(pnull.self, "wallet_keys", &n));
        WBP_CHECK("count_rows leaves out on NULL src_db", n == -7);

        /* count_rows_in_file on a missing file returns -1. */
        WBP_CHECK("count_rows_in_file missing file == -1",
                  port.count_rows_in_file(port.self,
                      WBP_DIR "/does_not_exist.sqlite", "wallet_keys") == -1);
    }

    /* ---- in-memory source has no on-disk path ---- */
    {
        sqlite3 *mem = NULL;
        if (sqlite3_open(":memory:", &mem) == SQLITE_OK && mem) {
            struct wallet_backup_store_sqlite_ctx cm;
            struct wallet_backup_store_port pm = {0};
            wallet_backup_store_sqlite_bind(&cm, mem, &pm);
            char buf[64] = "x";
            WBP_CHECK("source_path false for in-memory db",
                      !pm.source_path(pm.self, buf, sizeof(buf)));
            sqlite3_close(mem);
        } else {
            if (mem) sqlite3_close(mem);
            WBP_CHECK("in-memory db opens", false);
        }
    }

    node_db_close(&ndb);
    wbp_rm(src_db_path);
    wbp_rm(dst_path);
    return failures;
}
