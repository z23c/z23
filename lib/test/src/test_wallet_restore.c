/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the wallet RESTORE path — the half that did not exist.
 *
 * Everything here runs against isolated fixtures under ./test-tmp: a
 * throwaway source node.db, a backup file taken from it, and a throwaway
 * target datadir. No live datadir, no running node, no network.
 *
 * What is proven, in the order a user would hit it:
 *   - a backup file carries a per-table manifest, including rows for the
 *     tables the SOURCE did not have (the "silently skipped" bug)
 *   - a dry run reports exact per-table counts and writes NOTHING
 *   - a commit lands those exact rows, into SCHEMA-CORRECT tables (the
 *     target keeps its primary keys — the thing CREATE TABLE AS SELECT
 *     destroys)
 *   - keep-existing: a second restore inserts nothing and reports every
 *     row as a collision, and an existing row is never overwritten
 *   - shielded rows (wallet_sapling_keys / wallet_seed /
 *     wallet_sapling_notes) survive the round trip — the tables the old
 *     one-table verification could drop without noticing
 *   - a short-copied backup is DETECTED after the fact via the manifest
 *   - encrypted backups round-trip with a password
 *
 * And the refusals, each one its own assertion:
 *   - a datadir held by another writer (the pidfile flock)
 *   - a backup path that does not exist
 *   - a file that is not a SQLite database
 *   - a SQLite database holding none of the wallet tables
 *   - an encrypted backup with no password available
 */

#include "platform/directory_compat.h"
#include "platform/environment_compat.h"
#include "platform/private_directory.h"
#include "test/test_core.h"

#include "adapters/outbound/persistence/wallet_backup_store_sqlite.h"
#include "models/database.h"
#include "ports/wallet_backup_store_port.h"
#include "services/wallet_backup_service.h"
#include "services/wallet_restore_service.h"
#include "validation/chainstate.h"
#include "wallet/wallet.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/file.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static int wr_environment_unset(const char *name)
{
#if defined(_WIN32)
    return platform_environment_set(name, "", 1);
#else
    return unsetenv(name);
#endif
}

/* Fixture scratch root, as an ABSOLUTE path.
 *
 * wallet_backup_encrypt_file and the restore service write through
 * wbs_write_file_atomic -> platform_private_path_resolve, which realpath()s
 * the destination's parent and refuses any pathname that does not start at
 * the root. A relative fixture path is rejected before a byte is written, so
 * every path built here is anchored at the working directory. */
#define WR_DIR_REL "./test-tmp"

static const char *wr_dir(void)
{
    static char dir[512];
    platform_directory_create(WR_DIR_REL, 0755);
    if (dir[0])
        return dir;
    char cwd[384];
    if (!getcwd(cwd, sizeof(cwd)))
        return WR_DIR_REL;   /* caller's write then fails loudly */
    snprintf(dir, sizeof(dir), "%s/test-tmp", cwd);
    return dir;
}

#define WR_CHECK(name, expr) do {                    \
    printf("wallet_restore: %s... ", (name));        \
    if ((expr)) { printf("OK\n"); }                  \
    else { printf("FAIL\n"); failures++; }           \
} while (0)

/* ── fixture helpers ────────────────────────────────────────── */

static void wr_rm(const char *path)
{
    if (path && path[0])
        unlink(path);
}

/* Deterministic 32-byte blob for row i of kind `salt`. */
static void wr_blob(int i, uint8_t salt, uint8_t *out, size_t n)
{
    for (size_t b = 0; b < n; b++)
        out[b] = (uint8_t)((i * 31 + (int)b * 7 + salt) & 0xff);
}

/* Test fixture code seeds the SOURCE directly; the adapter under test is
 * the thing that must not use raw sqlite, not the fixture. */
static bool wr_exec(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static int wr_seed_keys(sqlite3 *db, int n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed) "
        "VALUES(?,?,?,1)", -1, &st, NULL) != SQLITE_OK)
        return 0;
    int wrote = 0;
    for (int i = 0; i < n; i++) {
        uint8_t hash[20], pub[33], priv[32];
        wr_blob(i, 0x10, hash, sizeof(hash));
        wr_blob(i, 0x20, pub, sizeof(pub));
        wr_blob(i, 0x30, priv, sizeof(priv));
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, hash, sizeof(hash), SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, pub, sizeof(pub), SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, priv, sizeof(priv), SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_DONE) wrote++;
    }
    sqlite3_finalize(st);
    return wrote;
}

static int wr_seed_sapling_keys(sqlite3 *db, int n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO wallet_sapling_keys"
        "(ivk,xsk,xfvk,diversifier,pk_d,child_index,address) "
        "VALUES(?,?,?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return 0;
    int wrote = 0;
    for (int i = 0; i < n; i++) {
        uint8_t ivk[32], xsk[32], xfvk[32], div[11], pkd[32];
        wr_blob(i, 0x41, ivk, sizeof(ivk));
        wr_blob(i, 0x42, xsk, sizeof(xsk));
        wr_blob(i, 0x43, xfvk, sizeof(xfvk));
        wr_blob(i, 0x44, div, sizeof(div));
        wr_blob(i, 0x45, pkd, sizeof(pkd));
        char addr[64];
        snprintf(addr, sizeof(addr), "zs1fixture%d", i);
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, ivk, sizeof(ivk), SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, xsk, sizeof(xsk), SQLITE_STATIC);
        sqlite3_bind_blob(st, 3, xfvk, sizeof(xfvk), SQLITE_STATIC);
        sqlite3_bind_blob(st, 4, div, sizeof(div), SQLITE_STATIC);
        sqlite3_bind_blob(st, 5, pkd, sizeof(pkd), SQLITE_STATIC);
        sqlite3_bind_int(st, 6, i);
        sqlite3_bind_text(st, 7, addr, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_DONE) wrote++;
    }
    sqlite3_finalize(st);
    return wrote;
}

static bool wr_seed_seed_row(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO wallet_seed(id,seed,next_child) VALUES(1,?,7)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    uint8_t seed[32];
    wr_blob(0, 0x55, seed, sizeof(seed));
    sqlite3_bind_blob(st, 1, seed, sizeof(seed), SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static int wr_seed_notes(sqlite3 *db, int n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO wallet_sapling_notes"
        "(txid,output_index,value,rcm,ivk,diversifier,pk_d,cm,nullifier,"
        "block_height,address) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        -1, &st, NULL) != SQLITE_OK)
        return 0;
    int wrote = 0;
    for (int i = 0; i < n; i++) {
        uint8_t txid[32], rcm[32], ivk[32], div[11], pkd[32], cm[32], nf[32];
        wr_blob(i, 0x61, txid, sizeof(txid));
        wr_blob(i, 0x62, rcm, sizeof(rcm));
        wr_blob(i, 0x41, ivk, sizeof(ivk));   /* matches key 0's ivk shape */
        wr_blob(i, 0x64, div, sizeof(div));
        wr_blob(i, 0x65, pkd, sizeof(pkd));
        wr_blob(i, 0x66, cm, sizeof(cm));
        wr_blob(i, 0x67, nf, sizeof(nf));
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, txid, sizeof(txid), SQLITE_STATIC);
        sqlite3_bind_int(st, 2, 0);
        sqlite3_bind_int64(st, 3, 100000 + i);
        sqlite3_bind_blob(st, 4, rcm, sizeof(rcm), SQLITE_STATIC);
        sqlite3_bind_blob(st, 5, ivk, sizeof(ivk), SQLITE_STATIC);
        sqlite3_bind_blob(st, 6, div, sizeof(div), SQLITE_STATIC);
        sqlite3_bind_blob(st, 7, pkd, sizeof(pkd), SQLITE_STATIC);
        sqlite3_bind_blob(st, 8, cm, sizeof(cm), SQLITE_STATIC);
        sqlite3_bind_blob(st, 9, nf, sizeof(nf), SQLITE_STATIC);
        sqlite3_bind_int(st, 10, 1000 + i);
        sqlite3_bind_text(st, 11, "zs1fixture0", -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_DONE) wrote++;
    }
    sqlite3_finalize(st);
    return wrote;
}

/* count(*) over a table in a file, -1 when the table/file is unusable. */
static int64_t wr_count_in_file(const char *path, const char *table)
{
    sqlite3 *db = NULL;
    int64_t n = -1;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        char sql[160];
        snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s", table);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && st) {
            if (sqlite3_step(st) == SQLITE_ROW)
                n = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
        }
    }
    if (db) sqlite3_close(db);
    return n;
}

/* Does <table> in <path> declare a primary key? This is what separates a
 * schema-correct restore target from a CREATE-TABLE-AS-SELECT artifact. */
static bool wr_table_has_pk(const char *path, const char *table)
{
    sqlite3 *db = NULL;
    bool has_pk = false;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        char sql[160];
        snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && st) {
            while (sqlite3_step(st) == SQLITE_ROW)
                if (sqlite3_column_int(st, 5) > 0)
                    has_pk = true;
            sqlite3_finalize(st);
        }
    }
    if (db) sqlite3_close(db);
    return has_pk;
}

static const struct wallet_restore_table_report *wr_find(
    const struct wallet_restore_report *rep, const char *table)
{
    for (size_t i = 0; i < rep->n_tables; i++)
        if (strcmp(rep->tables[i].table, table) == 0)
            return &rep->tables[i];
    return NULL;
}

static void wr_rmdir_datadir(const char *dir)
{
    char p[512];
    snprintf(p, sizeof(p), "%s/node.db", dir);      unlink(p);
    snprintf(p, sizeof(p), "%s/node.db-wal", dir);  unlink(p);
    snprintf(p, sizeof(p), "%s/node.db-shm", dir);  unlink(p);
    snprintf(p, sizeof(p), "%s/zclassic23.pid", dir); unlink(p);
    rmdir(dir);
}

/* ── rescan honesty ─────────────────────────────────────────── */

/* struct wallet is large; keep it out of the group's stack frame. */
static struct wallet g_wr_wallet;

/* A rescan over heights whose bodies are NOT on disk — the exact shape a
 * snapshot-bootstrapped node has, because snapshot_controller_import
 * deliberately strips BLOCK_HAVE_DATA when the source's block files were
 * not copied. It used to report "0 wallet outputs found" and nothing else,
 * which reads as an empty wallet. It must now say it could not look. */
static int wr_test_rescan_reports_missing_bodies(void)
{
    int failures = 0;

    struct active_chain chain;
    active_chain_init(&chain);
    static struct block_index bis[5];
    bool built = true;
    for (int i = 0; i < 5 && built; i++) {
        block_index_init(&bis[i]);
        bis[i].nHeight = i;
        memset(bis[i].hashBlock.data, (uint8_t)(0x90 + i), 32);
        bis[i].phashBlock = &bis[i].hashBlock;
        /* nStatus stays 0: BLOCK_HAVE_DATA CLEAR — no body on disk. */
        built = active_chain_install_tip_slot(&chain, &bis[i]);
    }
    WR_CHECK("built a 5-height chain with no block bodies", built);

    memset(&g_wr_wallet, 0, sizeof(g_wr_wallet));
    struct wallet_rescan_report rep;
    int found = wallet_rescan_report(&g_wr_wallet, &chain, 0, 4,
                                     wr_dir(), &rep);

    WR_CHECK("rescan over body-less heights finds nothing", found == 0);
    WR_CHECK("rescan counted a non-empty range", rep.blocks_in_range >= 1);
    WR_CHECK("rescan scanned ZERO blocks (no bodies on disk)",
             rep.blocks_scanned == 0);
    WR_CHECK("rescan reports every height as missing-body, not as empty",
             rep.blocks_missing_data == rep.blocks_in_range);
    WR_CHECK("rescan read no unreadable bodies", rep.blocks_read_failed == 0);
    WR_CHECK("rescan refuses to call a body-less scan trustworthy",
             !rep.coverage_ok);
    WR_CHECK("rescan names RESCAN_NO_BLOCK_DATA",
             strcmp(rep.blocker, WALLET_RESCAN_BLOCKER_NO_BLOCK_DATA) == 0);
    WR_CHECK("rescan reports zero sapling keys", rep.sapling_key_count == 0);

    active_chain_free(&chain);
    return failures;
}

/* ── the group ──────────────────────────────────────────────── */

int test_wallet_restore(void)
{
#if defined(_WIN32)
    /* Production native-Windows wallet restore is FAIL-CLOSED by design:
     * wallet_restore_datadir_free/_hold refuse (-58) until current-SID
     * single-writer qualification passes (app/services/src/
     * wallet_restore_service.c:69-72 and :128-132). Every case below runs
     * through those gates, so none can pass here. The refusal contract
     * itself is proven by the Windows-lane acceptance
     * (lib/test/src/wallet_restore_windows_refusal_acceptance.c). */
    printf("wallet_restore: SKIP (Windows): restore is fail-closed on "
           "native Windows; refusal proven by "
           "wallet_restore_windows_refusal_acceptance\n");
    return 0;
#else
    int failures = 0;
    char src_db[256], backup_dir[256], target[256], target_db[320];
    const char *scratch = wr_dir();
    snprintf(src_db, sizeof(src_db), "%s/wr_%d_src.db", scratch, (int)getpid());
    snprintf(backup_dir, sizeof(backup_dir), "%s/wr_%d_bk", scratch, (int)getpid());
    snprintf(target, sizeof(target), "%s/wr_%d_target", scratch, (int)getpid());
    snprintf(target_db, sizeof(target_db), "%s/node.db", target);
    wr_rm(src_db);
    wr_rmdir_datadir(target);
    /* wallet_backup_run_once -> wbs_ensure_backup_dir ->
     * platform_private_directory_ensure requires exactly 0700 and refuses a
     * wider directory. mkdir is umask-masked, so restate the mode. */
    if (!platform_private_directory_ensure(backup_dir))
        return false;

    /* ---- source wallet with transparent AND shielded rows ---- */
    struct node_db ndb;
    bool opened = node_db_open(&ndb, src_db);
    WR_CHECK("source node_db opens", opened);
    if (!opened) return failures + 1;

    WR_CHECK("seeded 4 transparent keys", wr_seed_keys(ndb.db, 4) == 4);
    WR_CHECK("seeded 3 sapling keys", wr_seed_sapling_keys(ndb.db, 3) == 3);
    WR_CHECK("seeded the sapling seed row", wr_seed_seed_row(ndb.db));
    WR_CHECK("seeded 2 sapling notes", wr_seed_notes(ndb.db, 2) == 2);

    /* wallet_scripts is left EMPTY on purpose: a table that exists with no
     * rows must restore as zero, not as "missing". */

    /* ---- take a backup ---- */
    char backup_path[512] = "";
    int64_t key_count = -1;
    char err[256] = "";
    struct zcl_result br = wallet_backup_run_once(backup_dir, &ndb,
                                                  backup_path,
                                                  sizeof(backup_path),
                                                  &key_count, err, sizeof(err));
    WR_CHECK("backup run_once ok", br.ok);
    WR_CHECK("backup counted 4 keys", key_count == 4);
    node_db_close(&ndb);
    if (!br.ok) {
        printf("  backup error: %s\n", err);
        return failures + 1;
    }

    /* ---- (B) the manifest exists and covers EVERY wallet table ---- */
    size_t n_wallet_tables = 0;
    (void)wallet_backup_tables(&n_wallet_tables);
    WR_CHECK("backup carries a manifest row per wallet table",
             wr_count_in_file(backup_path, WALLET_BACKUP_MANIFEST_TABLE)
                 == (int64_t)n_wallet_tables);
    WR_CHECK("backup captured the sapling keys",
             wr_count_in_file(backup_path, "wallet_sapling_keys") == 3);
    WR_CHECK("backup captured the seed row",
             wr_count_in_file(backup_path, "wallet_seed") == 1);
    WR_CHECK("backup captured the sapling notes",
             wr_count_in_file(backup_path, "wallet_sapling_notes") == 2);

    /* ---- refusals, before any successful restore ---- */
    struct wallet_restore_request req = {0};
    struct wallet_restore_report rep;

    req = (struct wallet_restore_request){ .backup_path = backup_path,
                                           .datadir = target, .dry_run = true };

    {   /* a path that does not exist */
        struct wallet_restore_request bad = req;
        char missing[512];
        snprintf(missing, sizeof(missing), "%s/no_such_backup.sqlite",
                 wr_dir());
        bad.backup_path = missing;
        WR_CHECK("refuses a backup path that does not exist",
                 !wallet_restore_run(&bad, &rep).ok);
    }
    {   /* a file that is not a SQLite database */
        char junk[320];
        snprintf(junk, sizeof(junk), "%s/junk.bin", backup_dir);
        FILE *f = fopen(junk, "wb");
        if (f) { fputs("this is not a database", f); fclose(f); }
        struct wallet_restore_request bad = req;
        bad.backup_path = junk;
        struct zcl_result r = wallet_restore_run(&bad, &rep);
        WR_CHECK("refuses a file that is not a SQLite database", !r.ok);
        wr_rm(junk);
    }
    {   /* a real SQLite db holding none of the wallet tables */
        char empty[320];
        snprintf(empty, sizeof(empty), "%s/empty.sqlite", backup_dir);
        wr_rm(empty);
        sqlite3 *e = NULL;
        if (sqlite3_open(empty, &e) == SQLITE_OK) {
            (void)wr_exec(e, "CREATE TABLE unrelated(x INTEGER)");
            sqlite3_close(e);
        }
        struct wallet_restore_request bad = req;
        bad.backup_path = empty;
        struct zcl_result r = wallet_restore_run(&bad, &rep);
        WR_CHECK("refuses a database holding no wallet tables", !r.ok);
        wr_rm(empty);
    }
    {   /* a datadir another writer is holding
         *
         * flock(2) and O_CLOEXEC have no Windows equivalent in this shape;
         * this sub-test is not exercised on Windows, only kept
         * syntactically valid there. */
#if !defined(_WIN32)
        platform_directory_create(target, 0700);
        char pidfile[400];
        snprintf(pidfile, sizeof(pidfile), "%s/zclassic23.pid", target);
        int fd = open(pidfile, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        WR_CHECK("test can create the pidfile", fd >= 0);
        if (fd >= 0) {
            WR_CHECK("test can hold the datadir lock",
                     flock(fd, LOCK_EX | LOCK_NB) == 0);
            struct zcl_result lr = wallet_restore_datadir_free(target);
            WR_CHECK("datadir_free is not ok while the lock is held", !lr.ok);
            WR_CHECK("the refusal names the datadir",
                     strstr(lr.message, target) != NULL);
            struct zcl_result r = wallet_restore_run(&req, &rep);
            WR_CHECK("restore refuses a held datadir", !r.ok);
            WR_CHECK("nothing was written to the held datadir",
                     access(target_db, F_OK) != 0);
            (void)flock(fd, LOCK_UN);
            close(fd);
        }
        unlink(pidfile);
        WR_CHECK("datadir_free is ok once the lock is released",
                 wallet_restore_datadir_free(target).ok);
#endif /* !defined(_WIN32) */
    }

    /* ---- (A) dry run: exact counts, nothing written ---- */
    struct zcl_result r = wallet_restore_run(&req, &rep);
    WR_CHECK("dry run ok", r.ok);
    WR_CHECK("dry run reports itself as a dry run", rep.dry_run);
    WR_CHECK("dry run found all eight wallet tables in the backup",
             rep.tables_in_backup == (int)n_wallet_tables);
    WR_CHECK("dry run would insert 4+3+1+2 = 10 rows",
             rep.total_inserted == 10);
    WR_CHECK("dry run collides with nothing", rep.total_collided == 0);
    WR_CHECK("dry run rejects nothing", rep.total_rejected == 0);
    WR_CHECK("dry run sees a clean manifest", rep.manifest_mismatches == 0);
    {
        const struct wallet_restore_table_report *t =
            wr_find(&rep, "wallet_sapling_keys");
        WR_CHECK("dry run reports the sapling key table",
                 t && t->in_backup && t->rows_in_backup == 3 &&
                 t->rows_inserted == 3);
        const struct wallet_restore_table_report *s =
            wr_find(&rep, "wallet_scripts");
        WR_CHECK("an empty-but-present table reports zero, not missing",
                 s && s->in_backup && s->rows_in_backup == 0);
    }
    WR_CHECK("dry run left node.db with no wallet rows",
             wr_count_in_file(target_db, "wallet_keys") == 0);

    /* ---- (A) commit: the rows land, in schema-correct tables ---- */
    req.dry_run = false;
    r = wallet_restore_run(&req, &rep);
    WR_CHECK("commit ok", r.ok);
    WR_CHECK("commit inserted 10 rows", rep.total_inserted == 10);
    WR_CHECK("target holds the 4 transparent keys",
             wr_count_in_file(target_db, "wallet_keys") == 4);
    WR_CHECK("target holds the 3 sapling keys",
             wr_count_in_file(target_db, "wallet_sapling_keys") == 3);
    WR_CHECK("target holds the seed row",
             wr_count_in_file(target_db, "wallet_seed") == 1);
    WR_CHECK("target holds the 2 sapling notes",
             wr_count_in_file(target_db, "wallet_sapling_notes") == 2);

    /* The point of merging instead of copying the file into place. */
    WR_CHECK("restored wallet_keys keeps its PRIMARY KEY",
             wr_table_has_pk(target_db, "wallet_keys"));
    WR_CHECK("restored wallet_utxos keeps its PRIMARY KEY",
             wr_table_has_pk(target_db, "wallet_utxos"));
    WR_CHECK("restored wallet_sapling_notes keeps its PRIMARY KEY",
             wr_table_has_pk(target_db, "wallet_sapling_notes"));
    WR_CHECK("the BACKUP file, by contrast, lost its primary key",
             !wr_table_has_pk(backup_path, "wallet_keys"));

    /* A different wrapped DEK must refuse before importing unreadable WKD1
     * ciphertext. The normal source fixture leaves this table empty, so plant
     * distinct identities only for this negative restore. */
    {
        sqlite3 *t = NULL;
        if (sqlite3_open(target_db, &t) == SQLITE_OK) {
            (void)wr_exec(t, "INSERT OR REPLACE INTO wallet_key_encryption "
                             "(id,wrapped_dek) VALUES(1,X'01020304')");
            sqlite3_close(t);
        }
        char conflict[512];
        snprintf(conflict, sizeof(conflict), "%s/dek-conflict.sqlite",
                 backup_dir);
        wr_rm(conflict);
        FILE *in = fopen(backup_path, "rb");
        FILE *out = fopen(conflict, "wb");
        bool copied = in && out;
        if (copied) {
            char bytes[4096];
            size_t n;
            while ((n = fread(bytes, 1, sizeof(bytes), in)) > 0)
                if (fwrite(bytes, 1, n, out) != n) {
                    copied = false;
                    break;
                }
        }
        if (in) fclose(in);
        if (out) fclose(out);
        WR_CHECK("copied backup for wrapped-DEK conflict", copied);
        sqlite3 *c = NULL;
        if (copied && sqlite3_open(conflict, &c) == SQLITE_OK) {
            (void)wr_exec(c, "INSERT INTO wallet_key_encryption "
                             "(id,wrapped_dek) VALUES(1,X'05060708')");
            sqlite3_close(c);
        }
        struct wallet_restore_request conflict_req = req;
        conflict_req.backup_path = conflict;
        struct zcl_result conflict_result =
            wallet_restore_run(&conflict_req, &rep);
        WR_CHECK("restore refuses a conflicting wrapped wallet DEK",
                 !conflict_result.ok);
        WR_CHECK("DEK conflict imports no wallet keys",
                 wr_count_in_file(target_db, "wallet_keys") == 4);
        wr_rm(conflict);
    }

    /* ---- keep-existing: a second restore changes nothing ---- */
    r = wallet_restore_run(&req, &rep);
    WR_CHECK("second commit ok", r.ok);
    WR_CHECK("second commit inserts nothing", rep.total_inserted == 0);
    WR_CHECK("second commit reports 10 collisions",
             rep.total_collided == 10);
    WR_CHECK("target row count is unchanged",
             wr_count_in_file(target_db, "wallet_keys") == 4);

    /* An existing target row must WIN. Mutate one privkey in the target,
     * restore again, and prove the mutation survived. */
    {
        sqlite3 *t = NULL;
        uint8_t marker[32];
        memset(marker, 0xAB, sizeof(marker));
        if (sqlite3_open(target_db, &t) == SQLITE_OK) {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(t,
                    "UPDATE wallet_keys SET privkey=? WHERE rowid=1",
                    -1, &st, NULL) == SQLITE_OK) {
                sqlite3_bind_blob(st, 1, marker, sizeof(marker), SQLITE_STATIC);
                (void)sqlite3_step(st);
                sqlite3_finalize(st);
            }
            sqlite3_close(t);
        }
        ZCL_IGNORE_RESULT(wallet_restore_run(&req, &rep),
                          "the assertion below is about the row, not the run");
        bool kept = false;
        if (sqlite3_open_v2(target_db, &t, SQLITE_OPEN_READONLY, NULL)
                == SQLITE_OK) {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(t,
                    "SELECT privkey FROM wallet_keys WHERE rowid=1",
                    -1, &st, NULL) == SQLITE_OK) {
                if (sqlite3_step(st) == SQLITE_ROW) {
                    const void *b = sqlite3_column_blob(st, 0);
                    kept = b && sqlite3_column_bytes(st, 0) == 32 &&
                           memcmp(b, marker, 32) == 0;
                }
                sqlite3_finalize(st);
            }
            sqlite3_close(t);
        }
        WR_CHECK("keep-existing: the target's row was NOT overwritten", kept);
    }

    /* ---- (B) a short-copied backup is detected via the manifest ---- */
    {
        char shorted[512];
        snprintf(shorted, sizeof(shorted), "%s/shorted.sqlite", backup_dir);
        wr_rm(shorted);
        char cp[1200];
        /* Copy the backup byte-for-byte, then delete rows behind the
         * manifest's back — exactly what a truncated/damaged copy looks
         * like from the outside. */
        FILE *in = fopen(backup_path, "rb");
        FILE *outf = fopen(shorted, "wb");
        bool copied = in && outf;
        if (copied) {
            size_t n;
            while ((n = fread(cp, 1, sizeof(cp), in)) > 0)
                if (fwrite(cp, 1, n, outf) != n) { copied = false; break; }
        }
        if (in) fclose(in);
        if (outf) fclose(outf);
        WR_CHECK("copied the backup for the short-copy case", copied);

        sqlite3 *s = NULL;
        if (sqlite3_open(shorted, &s) == SQLITE_OK) {
            (void)wr_exec(s, "DELETE FROM wallet_sapling_keys");
            sqlite3_close(s);
        }
        struct wallet_restore_request sreq = req;
        sreq.backup_path = shorted;
        sreq.dry_run = true;
        struct zcl_result sr = wallet_restore_run(&sreq, &rep);
        WR_CHECK("short-copied backup still restores what it has", sr.ok);
        WR_CHECK("short copy is DETECTED as a manifest mismatch",
                 rep.manifest_mismatches >= 1);
        WR_CHECK("short copy raises a warning",
                 strstr(rep.warnings, "manifest_mismatch") != NULL);
        wr_rm(shorted);
    }

    /* ---- encrypted backups ---- */
    {
        char enc[512];
        snprintf(enc, sizeof(enc), "%s/encrypted.sqlite.enc", backup_dir);
        wr_rm(enc);
        struct zcl_result er =
            wallet_backup_encrypt_file(backup_path, enc, "restore-test-pw");
        WR_CHECK("encrypt the backup", er.ok);

        struct wallet_restore_request ereq = req;
        ereq.backup_path = enc;
        ereq.dry_run = true;
        ereq.password = NULL;
        (void)wr_environment_unset("WALLET_BACKUP_PASSWORD");
        struct zcl_result nr = wallet_restore_run(&ereq, &rep);
        WR_CHECK("refuses an encrypted backup with no password", !nr.ok);
        WR_CHECK("the refusal says the file is encrypted",
                 rep.source_was_encrypted);

        ereq.password = "restore-test-pw";
        struct zcl_result pr = wallet_restore_run(&ereq, &rep);
        WR_CHECK("restores an encrypted backup with the password", pr.ok);
        WR_CHECK("encrypted restore sees all eight tables",
                 rep.tables_in_backup == (int)n_wallet_tables);
        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s.restore-%ld.tmp", target_db,
                 (long)getpid());
        WR_CHECK("encrypted restore leaves no plaintext temp behind",
                 access(tmp, F_OK) != 0);
        wr_rm(enc);
    }

    failures += wr_test_rescan_reports_missing_bodies();

    /* ---- cleanup ---- */
    {
        char paths[8][512];
        int n = wallet_backup_list(backup_dir, paths, 8);
        for (int i = 0; i < n; i++)
            wr_rm(paths[i]);
    }
    wr_rm(backup_path);
    wr_rm(src_db);
    wr_rmdir_datadir(target);
    rmdir(backup_dir);
    return failures;
#endif
}
