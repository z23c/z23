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
 *   - a held pidfile whose valid datadir path exceeds the probe buffer
 *   - a backup path that does not exist
 *   - backup and target paths that cannot fit the report
 *   - a file that is not a SQLite database
 *   - a SQLite database holding none of the wallet tables
 *   - an encrypted backup with no password available
 *   - a target path that cannot be represented without truncation
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
#include <errno.h>
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
    /* Darwin keeps the owner lease in a sidecar file next to the database. */
    snprintf(p, sizeof(p), "%s/node.db.owner-lock", dir); unlink(p);
    rmdir(dir);
}

#if !defined(_WIN32)
/* Remove only the nested directories created below, leaving the root alone. */
static void wr_remove_long_datadir(char *datadir, size_t root_len)
{
    while (strlen(datadir) > root_len) {
        (void)rmdir(datadir);
        char *slash = strrchr(datadir, '/');
        if (!slash || (size_t)(slash - datadir) < root_len)
            break;
        *slash = '\0';
    }
}

/* A valid datadir can be longer than the lock probe's fixed pathname buffer.
 * The probe must refuse that input, never truncate it and inspect a different
 * file while the real pidfile remains locked. */
static int wr_test_long_datadir_lock(void)
{
    int failures = 0;
#if defined(__APPLE__)
    /* Darwin PATH_MAX is 1024, so the 1185-byte datadir cannot be created.
     * The probe's capacity check (datadir plus pidfile name beyond its
     * 1200-byte buffer) runs before any file is opened, so the same refusal
     * is driven with a synthetic name: it must be the "too long" refusal, not
     * a free datadir. Holding a lock at that depth is Linux-only coverage. */
    {
        char datadir[1400];
        memset(datadir, 'l', 1185);
        datadir[0] = '/';
        datadir[1185] = '\0';
        struct zcl_result r = wallet_restore_datadir_free(datadir);
        WR_CHECK("long datadir is refused as too long, never free",
                 !r.ok && strstr(r.message, "too long") != NULL);
        return failures;
    }
#endif
    char datadir[1400];
    char pidfile[1450];
    size_t root_len;
    size_t target_len = 1185;

    int n = snprintf(datadir, sizeof(datadir), "%s", wr_dir());
    WR_CHECK("represented the fixture root exactly",
             n > 0 && (size_t)n < sizeof(datadir));
    if (failures)
        return failures;
    root_len = strlen(datadir);
    if (root_len >= target_len) {
        WR_CHECK("fixture root leaves room for the long datadir", false);
        return failures;
    }
    if ((target_len - root_len) % 17 == 1)
        target_len++;
    while (strlen(datadir) < target_len) {
        size_t used = strlen(datadir);
        size_t remaining = target_len - used;
        size_t component = remaining > 17 ? 16 : remaining - 1;
        datadir[used++] = '/';
        memset(datadir + used, 'l', component);
        datadir[used + component] = '\0';
        if (mkdir(datadir, 0700) != 0) {
            /* Do not remove a directory this invocation did not create. */
            datadir[used - 1] = '\0';
            break;
        }
    }
    WR_CHECK("built a valid datadir beyond the lock probe capacity",
             strlen(datadir) == target_len);
    if (failures) {
        wr_remove_long_datadir(datadir, root_len);
        return failures;
    }

    n = snprintf(pidfile, sizeof(pidfile), "%s/zclassic23.pid", datadir);
    WR_CHECK("represented the real long-datadir pidfile exactly",
             n > 0 && (size_t)n < sizeof(pidfile));
    if (failures) {
        wr_remove_long_datadir(datadir, root_len);
        return failures;
    }
    int fd = open(pidfile, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    WR_CHECK("opened the real long-datadir pidfile", fd >= 0);
    if (fd >= 0) {
        bool held = flock(fd, LOCK_EX | LOCK_NB) == 0;
        WR_CHECK("held the real long-datadir pidfile", held);
        if (held) {
            struct zcl_result r = wallet_restore_datadir_free(datadir);
            WR_CHECK("long datadir never bypasses the held pidfile", !r.ok);
            (void)flock(fd, LOCK_UN);
        }
        close(fd);
        unlink(pidfile);
    }

    wr_remove_long_datadir(datadir, root_len);
    return failures;
}
#endif

#if !defined(_WIN32)
/* Private nested fixture: every component is below the filename limit. */
static bool wr_long_path_fixture(char dirs[8][1100], size_t *count)
{
    *count = 0;
    if (!test_mkdtemp(dirs[0], 1100, "wr_paths")) return false;
    *count = 1;
    if (strlen(dirs[0]) >= 1018) return false;
    while (strlen(dirs[*count - 1]) < 1018) {
        size_t len = strlen(dirs[*count - 1]);
        size_t part = 1018 - len - 1;
        if (part > 180) part = 180;
        if (1018 - len - 1 - part == 1) --part;
        if (*count >= 8 || part == 0) return false;
        memcpy(dirs[*count], dirs[*count - 1], len);
        dirs[*count][len++] = '/';
        memset(dirs[*count] + len, 'p', part);
        dirs[*count][len + part] = '\0';
        if (mkdir(dirs[*count], 0700) != 0) return false;
        ++*count;
    }
    return true;
}

static int wr_path_backup(const char *path)
{
    int failures = 0;
    sqlite3 *db = NULL;
    bool opened = sqlite3_open(path, &db) == SQLITE_OK;
    WR_CHECK("opened synthetic path backup", opened);
    bool seeded = opened && wr_exec(db,
        "CREATE TABLE wallet_transactions (id INTEGER)");
    WR_CHECK("created non-secret wallet table", seeded);
    WR_CHECK("closed synthetic path backup", sqlite3_close(db) == SQLITE_OK);
    return failures;
}

static int wr_path_refusal(const char *backup, const char *datadir)
{
    int failures = 0;
    struct wallet_restore_request req = {
        .backup_path = backup, .datadir = datadir, .dry_run = true
    };
    struct wallet_restore_report rep;
    memset(&rep, 0xa5, sizeof(rep));
    struct zcl_result r = wallet_restore_run(&req, &rep);
    WR_CHECK("refuses unrepresentable restore path", !r.ok);
    WR_CHECK("names path capacity refusal",
             strstr(r.message, "path exceeds report capacity") != NULL);
    WR_CHECK("refusal leaves report locators empty",
             rep.backup_path[0] == '\0' && rep.target_db[0] == '\0');
    char path[1200];
    snprintf(path, sizeof(path), "%s/node", datadir);
    WR_CHECK("refusal creates no clipped target", access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/node.db", datadir);
    WR_CHECK("refusal creates no requested target", access(path, F_OK) != 0);
    return failures;
}

/* Also removes artifacts left by the deliberate path-check mutation. */
static void wr_path_target_cleanup(const char *dir)
{
    static const char *const names[] = {
        "node", "node-wal", "node-shm", "node-journal",
        "node.db", "node.db-wal", "node.db-shm", "node.db-journal"
    };
    char path[1200];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        wr_rm(path);
    }
}

static int wr_test_report_path_capacity(void)
{
    int failures = 0;
#if defined(__APPLE__)
    /* Darwin PATH_MAX is 1024, so no directory this deep can exist; the
     * capacity check runs before any file is touched, so the same refusals
     * are driven with synthetic names that exist nowhere. */
    {
        char deep[1100], long_backup[1100], short_backup[1100];
        memset(deep, 'p', 1018);
        deep[0] = '/';
        deep[1018] = '\0';
        memset(long_backup, 'q', 1050);
        long_backup[0] = '/';
        long_backup[1050] = '\0';
        snprintf(short_backup, sizeof(short_backup), "%s/absent.sqlite",
                 wr_dir());
        failures += wr_path_refusal(short_backup, deep);
        failures += wr_path_refusal(long_backup, wr_dir());
        return failures;
    }
#endif
    char dirs[8][1100], backup[1200], long_backup[1200];
    size_t count;
    bool built = wr_long_path_fixture(dirs, &count);
    WR_CHECK("built private 1018-byte datadir", built);
    if (built) {
        const char *deep = dirs[count - 1];
        snprintf(backup, sizeof(backup), "%s/backup.sqlite", dirs[0]);
        snprintf(long_backup, sizeof(long_backup),
                 "%s/123456789012345678901234.sqlite", deep);
        WR_CHECK("datadir witness is exactly 1018 bytes", strlen(deep) == 1018);
        WR_CHECK("backup witness is exactly 1050 bytes", strlen(long_backup) == 1050);
        int seeded = wr_path_backup(backup);
        failures += seeded;
        /* SQLite's VFS has its own pathname limit. Seed through the short
         * name, then give those same non-secret bytes a long filesystem name
         * without asking SQLite to open it. */
        bool linked = link(backup, long_backup) == 0;
        WR_CHECK("linked synthetic backup at the long path", linked);
        if (seeded == 0 && linked) {
            failures += wr_path_refusal(backup, deep);
            failures += wr_path_refusal(long_backup, dirs[0]);
        }
        wr_path_target_cleanup(deep);
        wr_path_target_cleanup(dirs[0]);
        WR_CHECK("removed short synthetic backup", unlink(backup) == 0);
        WR_CHECK("removed long synthetic backup", unlink(long_backup) == 0);
    }
    while (count > 0) {
        --count;
        WR_CHECK("removed private path fixture directory", rmdir(dirs[count]) == 0);
    }
    return failures;
}
#endif

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
#if !defined(_WIN32)
    failures += wr_test_report_path_capacity();
#endif

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

#if !defined(_WIN32)
static int wr_test_restore_refusals(struct wallet_restore_request req, const char *backup_dir,
                                    const char *target, const char *target_db)
{
    int failures = 0;
    struct wallet_restore_report rep;
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

    return failures;
}
#endif

#if !defined(_WIN32)
static int wr_test_dek_conflict(struct wallet_restore_request req, const char *backup_path,
                                const char *backup_dir, const char *target_db)
{
    int failures = 0;
    struct wallet_restore_report rep;
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

    return failures;
}
#endif

#if !defined(_WIN32)
static int wr_test_keep_existing(struct wallet_restore_request req, const char *target_db)
{
    int failures = 0;
    struct wallet_restore_report rep;
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

    return failures;
}
#endif

#if !defined(_WIN32)
static int wr_test_short_copy(struct wallet_restore_request req, const char *backup_path,
                              const char *backup_dir)
{
    int failures = 0;
    struct wallet_restore_report rep;
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

    return failures;
}
#endif

#if !defined(_WIN32)
static int wr_test_encrypted(struct wallet_restore_request req, const char *backup_path,
                             const char *backup_dir, const char *target_db,
                             size_t n_wallet_tables)
{
    int failures = 0;
    struct wallet_restore_report rep;
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

    return failures;
}
#endif

#if !defined(_WIN32)
/* Grow only an owned fixture, keeping each component below NAME_MAX. */
static bool wr_extend_target(char *datadir, size_t capacity, size_t length)
{
    size_t used = strlen(datadir);
    if (length >= capacity || used >= length || length - used < 2)
        return false;
    while (used < length) {
        size_t remaining = length - used;
        size_t component = remaining > 17 ? 16 : remaining - 1;
        /* Do not leave a final slash with an empty component. */
        if (remaining > 17 && remaining % 17 == 1)
            component = 15;
        datadir[used++] = '/';
        memset(datadir + used, 'd', component);
        used += component;
        datadir[used] = '\0';
        if (mkdir(datadir, 0700) != 0) {
            datadir[used - component - 1] = '\0';
            return false;
        }
        if (chmod(datadir, 0700) != 0)
            return false;
    }
    return true;
}

/* Inspect and clean by directory descriptor: the complete oversized path
 * can exceed the host's PATH_MAX even though its datadir fits. */
static int wr_check_long_target_empty(const char *datadir)
{
    int failures = 0;
    int fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    WR_CHECK("opened the long-path fixture for absence checks", fd >= 0);
    if (fd < 0)
        return failures;
    struct stat st;
    WR_CHECK("refusal creates no database at the truncated target",
             fstatat(fd, "node.d", &st, AT_SYMLINK_NOFOLLOW) != 0 &&
             errno == ENOENT);
    WR_CHECK("refusal creates no database at the complete target",
             fstatat(fd, "node.db", &st, AT_SYMLINK_NOFOLLOW) != 0 &&
             errno == ENOENT);
    WR_CHECK("closed the long-path fixture after absence checks", close(fd) == 0);
    return failures;
}

static int wr_remove_long_target_files(const char *datadir)
{
    int failures = 0;
    static const char *const names[] = {
        "node.db", "node.db-wal", "node.db-shm",
        "node.d", "node.d-wal", "node.d-shm",
    };
    int fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    WR_CHECK("opened the long-path fixture for cleanup", fd >= 0);
    if (fd < 0)
        return failures;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        WR_CHECK("removed long-path fixture file or it was absent",
                 unlinkat(fd, names[i], 0) == 0 || errno == ENOENT);
    }
    WR_CHECK("closed the long-path fixture after cleanup", close(fd) == 0);
    return failures;
}

static int wr_remove_long_target(char *datadir, size_t root_len)
{
    int failures = wr_remove_long_target_files(datadir);
    while (strlen(datadir) > root_len) {
        WR_CHECK("removed long-path fixture component", rmdir(datadir) == 0);
        char *slash = strrchr(datadir, '/');
        if (!slash || (size_t)(slash - datadir) < root_len) {
            WR_CHECK("long-path cleanup remains inside its fixture root", false);
            return failures;
        }
        *slash = '\0';
    }
    WR_CHECK("removed long-path fixture root", rmdir(datadir) == 0);
    return failures;
}

/* Test the real service at the last fitting and first truncated pathname.
 * Refusal cases use a valid backup; the fitting control reaches the existing
 * missing-source check without depending on SQLite's separate path limit. */
static int wr_test_target_path_case(const char *backup_path, bool fits,
                                    bool dry_run)
{
    int failures = 0;
    char datadir[1100];
    size_t target_capacity = sizeof(((struct wallet_restore_report *)0)->target_db);
    char full_db[1200];
    if (!test_mkdtemp(datadir, sizeof(datadir), "wr_long_target")) {
        WR_CHECK("created an isolated long-path fixture root", false);
        return failures;
    }
    size_t root_len = strlen(datadir);
    /* "/node.db" occupies eight bytes, plus its NUL terminator. */
    size_t target_len = target_capacity - sizeof("/node.db");
    if (!fits)
        target_len++;
    bool built = wr_extend_target(datadir, sizeof(datadir), target_len);
    WR_CHECK("built the exact boundary-length datadir", built);
    if (!built) {
        failures += wr_remove_long_target(datadir, root_len);
        return failures;
    }
    int n = snprintf(full_db, sizeof(full_db), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(full_db)) {
        WR_CHECK("full fixture database path fits", false);
        failures += wr_remove_long_target(datadir, root_len);
        return failures;
    }

    struct wallet_restore_request req = {
        .backup_path = fits ? full_db : backup_path,
        .datadir = datadir, .dry_run = dry_run,
    };
    struct wallet_restore_report rep;
    memset(&rep, 0xA5, sizeof(rep));
    struct zcl_result r = wallet_restore_run(&req, &rep);
    if (fits) {
        WR_CHECK("last fitting target reaches source checks without path changes",
                 !r.ok && r.code == -33 && strcmp(rep.target_db, full_db) == 0);
    } else {
        WR_CHECK("refuses the first target that cannot fit exactly",
                 !r.ok && r.code == -59);
        WR_CHECK("refusal clears the reported target", rep.target_db[0] == '\0');
        failures += wr_check_long_target_empty(datadir);
    }
    failures += wr_remove_long_target(datadir, root_len);
    return failures;
}
#endif

/* ── the group ──────────────────────────────────────────────── */

int test_wallet_restore(void)
{
#if defined(_WIN32)
    /* Production native-Windows wallet restore is FAIL-CLOSED by design:
     * wallet_restore_datadir_free/_hold refuse (-58) until current-SID
     * single-writer qualification passes (engine/services/src/
     * wallet_restore_service.c:69-72 and :128-132). Every case below runs
     * through those gates, so none can pass here. The refusal contract
     * itself is proven by the Windows-lane acceptance
     * (tests/harness/src/wallet_restore_windows_refusal_acceptance.c). */
    printf("wallet_restore: SKIP (Windows): restore is fail-closed on "
           "native Windows; refusal proven by "
           "wallet_restore_windows_refusal_acceptance\n");
    return 0;
#else
    int failures = 0;
    char src_db[256], backup_dir[256], target[256], target_db[320];
    char scratch[200];
    if (!test_mkdtemp(scratch, sizeof(scratch), "wr_restore"))
        return 1;
    snprintf(src_db, sizeof(src_db), "%s/source.db", scratch);
    snprintf(backup_dir, sizeof(backup_dir), "%s/backup", scratch);
    snprintf(target, sizeof(target), "%s/target", scratch);
    snprintf(target_db, sizeof(target_db), "%s/node.db", target);
    wr_rm(src_db);
    wr_rmdir_datadir(target);
    /* wallet_backup_run_once -> wbs_ensure_backup_dir ->
     * platform_private_directory_ensure requires exactly 0700 and refuses a
     * wider directory. mkdir is umask-masked, so restate the mode. */
    if (!platform_private_directory_ensure(backup_dir)) {
        WR_CHECK("created the private backup fixture directory", false);
        return failures;
    }

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

    failures += wr_test_long_datadir_lock();

    failures += wr_test_target_path_case(backup_path, true, true);
    failures += wr_test_target_path_case(backup_path, true, false);
    failures += wr_test_target_path_case(backup_path, false, true);
    failures += wr_test_target_path_case(backup_path, false, false);

    failures += wr_test_restore_refusals(req, backup_dir, target, target_db);

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

    failures += wr_test_dek_conflict(req, backup_path, backup_dir, target_db);

    /* ---- keep-existing: a second restore changes nothing ---- */
    r = wallet_restore_run(&req, &rep);
    WR_CHECK("second commit ok", r.ok);
    WR_CHECK("second commit inserts nothing", rep.total_inserted == 0);
    WR_CHECK("second commit reports 10 collisions",
             rep.total_collided == 10);
    WR_CHECK("target row count is unchanged",
             wr_count_in_file(target_db, "wallet_keys") == 4);

    failures += wr_test_keep_existing(req, target_db);

    failures += wr_test_short_copy(req, backup_path, backup_dir);

    failures += wr_test_encrypted(req, backup_path, backup_dir, target_db, n_wallet_tables);

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
    {
        char lease[512];
        snprintf(lease, sizeof(lease), "%s.owner-lock", src_db);
        wr_rm(lease);   /* Darwin's owner-lease sidecar; absent elsewhere */
    }
    wr_rmdir_datadir(target);
    rmdir(backup_dir);
    WR_CHECK("removed the isolated restore fixture root", rmdir(scratch) == 0);
    return failures;
#endif
}
