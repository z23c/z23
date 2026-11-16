/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A wallet backup is published only after it is complete and verified.
 *
 * Each failure fixture first makes three verified backups, then drives one
 * run that fails (copy failure after the first table, a verify mismatch) or
 * observes the directory as a crash would leave it (mid-copy, before
 * verify). After each: wallet_backup_list returns exactly the three verified
 * files, wallet_backup_rotate(dir, 3) deletes none of them, every one is
 * byte-for-byte untouched and no partial or temporary file is left. The
 * sweep fixture pins the temporary-name rule and its age bound; the shape
 * fixture pins that a successful run still produces the same final file.
 * Included once by test_wallet_backup.c after its fixtures. */

#ifndef WALLET_BACKUP_ATOMIC_TEST_H
#define WALLET_BACKUP_ATOMIC_TEST_H

#include "adapters/outbound/persistence/wallet_backup_store_sqlite.h"
#include "ports/wallet_backup_store_port.h"

/* Narrow ZCL_TESTING seams implemented by wallet_backup_store_sqlite.c and
 * wallet_backup_run.c. */
void wallet_backup_store_sqlite_test_set_copy_hook(
    bool (*fn)(size_t copied, const char *dst_path));
void wallet_backup_test_set_snapshot_hook(void (*fn)(const char *written_path));
void wallet_backup_test_set_publish_hook(int (*fn)(int stage,
                                                   const char *final_path));

#include "platform/time_compat.h"

#define WBA_KEEP 3
#define WBA_TEMP_SUFFIX ".tmp"
#define WBA_STAGE_RENAME 0
#define WBA_STAGE_PARENT_FLUSH 1

struct wba_state {
    struct wb_fixture f;
    char paths[WBA_KEEP][512];       /* oldest first */
    uint8_t *blobs[WBA_KEEP];
    size_t lens[WBA_KEEP];
};

static struct wba_state *g_wba;
static _Atomic int g_wba_seen_listed;
static _Atomic int g_wba_seen_deleted;

static bool wba_begin(struct wba_state *s, const char *tag)
{
    memset(s, 0, sizeof(*s));
    wb_install_observer();
    if (!wb_fixture_init(&s->f, tag) || wb_seed_keys(&s->f.ndb, 3) != 3)
        return false;
    for (int i = 0; i < WBA_KEEP; i++) {
        if (!wallet_backup_run_once(s->f.backup_dir, &s->f.ndb, s->paths[i],
                                    sizeof(s->paths[i]), NULL, NULL, 0).ok ||
            !wb_read_blob(s->paths[i], &s->blobs[i], &s->lens[i]))
            return false;
    }
    atomic_store(&g_wb_ok, 0);
    atomic_store(&g_wb_fail, 0);
    atomic_store(&g_wba_seen_listed, -1);
    atomic_store(&g_wba_seen_deleted, -1);
    g_wba = s;
    return true;
}

static void wba_end(struct wba_state *s)
{
    wallet_backup_store_sqlite_test_set_copy_hook(NULL);
    wallet_backup_test_set_snapshot_hook(NULL);
    g_wba = NULL;
    for (int i = 0; i < WBA_KEEP; i++)
        free(s->blobs[i]);
    wb_fixture_tear_down(&s->f);
}

/* Directory entries other than "." and "..". */
static int wba_dir_entries(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    closedir(d);
    return n;
}

/* wallet_backup_list returns exactly the three verified files, newest
 * first. */
static bool wba_lists_only_verified(const struct wba_state *s)
{
    char listing[8][512];
    int n = wallet_backup_list(s->f.backup_dir, listing, 8);
    if (n != WBA_KEEP)
        return false;
    for (int i = 0; i < WBA_KEEP; i++)
        if (strcmp(listing[i], s->paths[WBA_KEEP - 1 - i]) != 0)
            return false;
    return true;
}

/* Every earlier backup still holds exactly the bytes it was made with. */
static bool wba_earlier_intact(const struct wba_state *s)
{
    for (int i = 0; i < WBA_KEEP; i++) {
        uint8_t *now = NULL;
        size_t len = 0;
        bool same = wb_read_blob(s->paths[i], &now, &len) &&
                    len == s->lens[i] &&
                    memcmp(now, s->blobs[i], len) == 0;
        free(now);
        if (!same)
            return false;
    }
    return true;
}

static int wba_check_after_failure(const struct wba_state *s,
                                   const char *what)
{
    int failures = 0;
    char name[192];
    bool listed = wba_lists_only_verified(s);
    snprintf(name, sizeof(name), "wb atomic: %s lists only the verified "
             "backups", what);
    WB_RUN(name, listed);
    int deleted = wallet_backup_rotate(s->f.backup_dir, WBA_KEEP);
    snprintf(name, sizeof(name), "wb atomic: %s then rotate(3) deletes no "
             "verified backup (deleted=%d)", what, deleted);
    WB_RUN(name, deleted == 0);
    int entries = wba_dir_entries(s->f.backup_dir);
    snprintf(name, sizeof(name), "wb atomic: %s leaves earlier backups "
             "untouched and no other file (entries=%d)", what, entries);
    WB_RUN(name, wba_earlier_intact(s) && entries == WBA_KEEP);
    return failures;
}

/* Directory as seen at this instant: what listing and rotation would do if
 * the process died right now. */
static void wba_observe_dir(void)
{
    if (!g_wba)
        return;
    char listing[8][512];
    atomic_store(&g_wba_seen_listed,
                 wallet_backup_list(g_wba->f.backup_dir, listing, 8));
    atomic_store(&g_wba_seen_deleted,
                 wallet_backup_rotate(g_wba->f.backup_dir, WBA_KEEP));
}

static bool wba_copy_fail_after_first(size_t copied, const char *dst_path)
{
    (void)dst_path;
    return copied < 1;
}

static bool wba_copy_observe_after_first(size_t copied, const char *dst_path)
{
    (void)dst_path;
    if (copied == 1)
        wba_observe_dir();
    return true;
}

static void wba_snapshot_observe(const char *written_path)
{
    (void)written_path;
    wba_observe_dir();
}

/* The wallet changes between the copy and its verification. */
static void wba_snapshot_grow_source(const char *written_path)
{
    (void)written_path;
    if (!g_wba)
        return;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_wba->f.ndb.db,
            "INSERT INTO wallet_keys(pubkey_hash,pubkey,privkey,compressed) "
            "VALUES(?,?,?,1)", -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        return;
    }
    uint8_t hash[20] = {0x77}, pub[33] = {0x02, 0x77}, priv[32] = {0xf7};
    sqlite3_bind_blob(st, 1, hash, sizeof(hash), SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, pub, sizeof(pub), SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, priv, sizeof(priv), SQLITE_STATIC);
    (void)sqlite3_step(st);
    sqlite3_finalize(st);
}

static int t_atomic_copy_failure(void)
{
    int failures = 0;
    struct wba_state s;
    bool began = wba_begin(&s, "atomic_copy");
    wallet_backup_store_sqlite_test_set_copy_hook(wba_copy_fail_after_first);
    char path[512] = "", err[256] = "";
    bool ran = began && !wallet_backup_run_once(
        s.f.backup_dir, &s.f.ndb, path, sizeof(path), NULL, err,
        sizeof(err)).ok;
    wallet_backup_store_sqlite_test_set_copy_hook(NULL);
    WB_RUN("wb atomic: copy failure after the first table fails the run "
           "with its reason",
           ran && strstr(err, "injected test failure") != NULL &&
           path[0] == '\0' && atomic_load(&g_wb_fail) == 1 &&
           atomic_load(&g_wb_ok) == 0);
    failures += began ? wba_check_after_failure(&s, "copy failure") : 1;
    wba_end(&s);
    return failures;
}

static int t_atomic_verify_mismatch(void)
{
    int failures = 0;
    struct wba_state s;
    bool began = wba_begin(&s, "atomic_verify");
    wallet_backup_test_set_snapshot_hook(wba_snapshot_grow_source);
    char path[512] = "", err[256] = "";
    bool ran = began && !wallet_backup_run_once(
        s.f.backup_dir, &s.f.ndb, path, sizeof(path), NULL, err,
        sizeof(err)).ok;
    wallet_backup_test_set_snapshot_hook(NULL);
    WB_RUN("wb atomic: verify mismatch fails the run with its reason",
           ran && strstr(err, "verify row count mismatch") != NULL &&
           path[0] == '\0' && atomic_load(&g_wb_fail) == 1 &&
           atomic_load(&g_wb_ok) == 0);
    failures += began ? wba_check_after_failure(&s, "verify mismatch") : 1;
    wba_end(&s);
    return failures;
}

/* A crash at the observed instant leaves exactly the directory the hook
 * saw. Listing must show only the three verified files and rotation must
 * delete none of them. */
static int wba_crash_case(const char *tag, const char *what, bool mid_copy)
{
    int failures = 0;
    struct wba_state s;
    bool began = wba_begin(&s, tag);
    if (mid_copy)
        wallet_backup_store_sqlite_test_set_copy_hook(
            wba_copy_observe_after_first);
    else
        wallet_backup_test_set_snapshot_hook(wba_snapshot_observe);
    bool ran = began && wallet_backup_run_once(
        s.f.backup_dir, &s.f.ndb, NULL, 0, NULL, NULL, 0).ok;
    wallet_backup_store_sqlite_test_set_copy_hook(NULL);
    wallet_backup_test_set_snapshot_hook(NULL);
    int listed = atomic_load(&g_wba_seen_listed);
    int deleted = atomic_load(&g_wba_seen_deleted);
    char name[192];
    snprintf(name, sizeof(name), "wb atomic: crash %s lists only the "
             "verified backups and rotate(3) deletes none "
             "(listed=%d deleted=%d)", what, listed, deleted);
    WB_RUN(name, ran && listed == WBA_KEEP && deleted == 0);
    wba_end(&s);
    return failures;
}

static int t_atomic_crash_points(void)
{
    return wba_crash_case("atomic_crash_copy", "mid-copy", true) +
           wba_crash_case("atomic_crash_verify", "before verify", false);
}

static bool wba_plant(const char *dir, const char *leaf, int64_t age_s,
                      char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    const uint8_t byte = 0x5a;
    if (n <= 0 || (size_t)n >= cap || !wb_write_blob(out, &byte, 1))
        return false;
    if (age_s == 0)
        return true;
    /* The sweep reads platform_time_wall_unix; age from the same clock. */
    time_t then = (time_t)(platform_time_wall_unix() - age_s);
    struct utimbuf when = { .actime = then, .modtime = then };
    return utime(out, &when) == 0;
}

static bool wba_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

struct wba_temps {
    char stale[512], fresh[512], near1[512], near2[512];
};

/* An exact temporary name two hours old, a fresh one (a live run, perhaps
 * another node's), and two near-miss names two hours old. */
static bool wba_plant_temps(const char *dir, struct wba_temps *t)
{
    return wba_plant(dir, "wallet_backup_1_000001.sqlite" WBA_TEMP_SUFFIX,
                     2 * 3600, t->stale, sizeof(t->stale)) &&
           wba_plant(dir, "wallet_backup_2_000002.sqlite" WBA_TEMP_SUFFIX,
                     0, t->fresh, sizeof(t->fresh)) &&
           wba_plant(dir,
                     "wallet_backup_3_000003.sqlite" WBA_TEMP_SUFFIX ".old",
                     2 * 3600, t->near1, sizeof(t->near1)) &&
           wba_plant(dir, "wallet_backup_4_04.sqlite" WBA_TEMP_SUFFIX,
                     2 * 3600, t->near2, sizeof(t->near2));
}

/* Rotation with temporaries present: exactly max_versions verified files
 * remain, the newest first, and the oldest verified file is the one gone. */
static bool wba_rotation_keeps_max(const struct wba_state *s,
                                   const char *newest)
{
    char listing[8][512];
    int deleted = wallet_backup_rotate(s->f.backup_dir, WBA_KEEP);
    int after = wallet_backup_list(s->f.backup_dir, listing, 8);
    return deleted == 1 && after == WBA_KEEP &&
           strcmp(listing[0], newest) == 0 && !wba_exists(s->paths[0]);
}

/* Stale temporaries: an exact temporary name older than the bound goes; a
 * fresh one and any near-miss name stay. Listing never shows any of them,
 * and rotation still keeps exactly max_versions verified files. */
static int t_atomic_sweep(void)
{
    int failures = 0;
    struct wba_state s;
    char newest[512] = "";
    struct wba_temps t;
    bool planted = wba_begin(&s, "atomic_sweep") &&
        wallet_backup_run_once(s.f.backup_dir, &s.f.ndb, newest,
                               sizeof(newest), NULL, NULL, 0).ok &&
        wba_plant_temps(s.f.backup_dir, &t);
    char listing[8][512];
    int before = planted ? wallet_backup_list(s.f.backup_dir, listing, 8) : -1;
    WB_RUN("wb atomic: listing never returns a temporary file",
           before == WBA_KEEP + 1);
    WB_RUN("wb atomic: rotation with temporaries present keeps exactly "
           "max_versions verified files",
           planted && wba_rotation_keeps_max(&s, newest));
    WB_RUN("wb atomic: sweep removes an exact temporary name older than "
           "the bound", planted && !wba_exists(t.stale));
    WB_RUN("wb atomic: sweep keeps a fresh temporary and near-miss names",
           planted && wba_exists(t.fresh) && wba_exists(t.near1) &&
           wba_exists(t.near2));
    wba_end(&s);
    return failures;
}

/* True when `leaf` is wallet_backup_<digits>_<6 digits>.sqlite exactly. */
static bool wba_final_name(const char *leaf)
{
    size_t pl = strlen(WALLET_BACKUP_FILENAME_PREFIX);
    if (strncmp(leaf, WALLET_BACKUP_FILENAME_PREFIX, pl) != 0)
        return false;
    const char *p = leaf + pl;
    const char *ts = p;
    while (*p >= '0' && *p <= '9')
        p++;
    if (p == ts || *p++ != '_')
        return false;
    for (int i = 0; i < 6; i++, p++)
        if (*p < '0' || *p > '9')
            return false;
    return strcmp(p, WALLET_BACKUP_FILENAME_SUFFIX) == 0;
}

static int64_t wba_scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int64_t v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static bool wba_table_equal(sqlite3 *db, const char *table)
{
    char sql[640];
    snprintf(sql, sizeof(sql),
        "SELECT (SELECT count(*) FROM main.\"%s\") = "
        "(SELECT count(*) FROM b.\"%s\") AND NOT EXISTS "
        "(SELECT * FROM main.\"%s\" EXCEPT SELECT * FROM b.\"%s\") AND "
        "NOT EXISTS (SELECT * FROM b.\"%s\" EXCEPT SELECT * FROM main.\"%s\")",
        table, table, table, table, table, table);
    return wba_scalar(db, sql) == 1;
}

/* Same schema (tables and manifest) and the same rows in every table. */
static bool wba_same_content(const char *a, const char *b)
{
    sqlite3 *db = NULL;
    bool same = sqlite3_open_v2(a, &db, SQLITE_OPEN_READONLY, NULL) ==
                SQLITE_OK;
    char att[600];
    snprintf(att, sizeof(att), "ATTACH DATABASE '%s' AS b", b);
    same = same && sqlite3_exec(db, att, NULL, NULL, NULL) == SQLITE_OK;
    same = same && wba_scalar(db,
        "SELECT count(*) FROM (SELECT type,name,sql FROM main.sqlite_master "
        "EXCEPT SELECT type,name,sql FROM b.sqlite_master)") == 0;
    same = same && wba_scalar(db,
        "SELECT count(*) FROM (SELECT type,name,sql FROM b.sqlite_master "
        "EXCEPT SELECT type,name,sql FROM main.sqlite_master)") == 0;
    sqlite3_stmt *st = NULL;
    int tables = 0;
    if (same && sqlite3_prepare_v2(db, "SELECT name FROM main.sqlite_master "
                                   "WHERE type='table'", -1, &st, NULL) ==
                    SQLITE_OK) {
        while (same && sqlite3_step(st) == SQLITE_ROW) {
            tables++;
            same = wba_table_equal(db,
                                   (const char *)sqlite3_column_text(st, 0));
        }
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return same && tables > 0;
}

/* A base-shaped snapshot: the store writes straight to its final path, as
 * every run did before the temporary name. */
static bool wba_base_snapshot(struct node_db *ndb, const char *dst)
{
    struct wallet_backup_store_sqlite_ctx ctx;
    struct wallet_backup_store_port port = {0};
    char src[1024];
    size_t n_tables = 0;
    const char *const *tables = wallet_backup_tables(&n_tables);
    struct wallet_backup_table_stat stats[16];
    char err[256] = "";
    return n_tables <= 16 &&
           wallet_backup_store_sqlite_bind(&ctx, ndb->db, &port) &&
           port.source_path(port.self, src, sizeof(src)) &&
           port.write_snapshot(port.self, dst, src, tables, n_tables, stats,
                               err, sizeof(err)) == WB_STORE_OK;
}

/* The published file and a base-shaped snapshot of the same source carry
 * the same permission bits and the same tables, manifest and rows. */
static bool wba_matches_base_shape(struct wb_fixture *f, const char *path)
{
    char base[384];
    snprintf(base, sizeof(base), "%s/base_shape.sqlite", f->datadir);
    struct stat a, b;
    return wba_base_snapshot(&f->ndb, base) && stat(path, &a) == 0 &&
           stat(base, &b) == 0 &&
           (a.st_mode & 07777) == (b.st_mode & 07777) &&
           wba_same_content(path, base);
}

/* One run published under the final name pattern, with nothing else in the
 * backup directory and exactly one success event. */
static bool wba_published_cleanly(const struct wb_fixture *f,
                                  const char *path, int64_t keys)
{
    const char *leaf = strrchr(path, '/');
    return leaf && wba_final_name(leaf + 1) &&
           wba_dir_entries(f->backup_dir) == 1 && keys == 3 &&
           atomic_load(&g_wb_ok) == 1 && atomic_load(&g_wb_fail) == 0;
}

static int t_atomic_success_shape(void)
{
    int failures = 0;
    wb_install_observer();
    struct wb_fixture f;
    char path[512] = "";
    int64_t keys = -1;
    bool ok = wb_fixture_init(&f, "atomic_shape") &&
              wb_seed_keys(&f.ndb, 3) == 3 &&
              wallet_backup_run_once(f.backup_dir, &f.ndb, path,
                                     sizeof(path), &keys, NULL, 0).ok;
    WB_RUN("wb atomic: success publishes the final name with no temporary "
           "left", ok && wba_published_cleanly(&f, path, keys));
    WB_RUN("wb atomic: published file matches a base-shaped snapshot in "
           "tables, manifest and mode",
           ok && wba_matches_base_shape(&f, path));
    wb_fixture_tear_down(&f);
    return failures;
}

/* ── Sweep spares everything but its exact names ───────────────── */

/* Sets a file's modification time `age_s` seconds into the past, its bytes
 * kept, on the clock the sweep reads. */
static bool wba_age(const char *path, int64_t age_s)
{
    time_t then = (time_t)(platform_time_wall_unix() - age_s);
    struct utimbuf when = { .actime = then, .modtime = then };
    return utime(path, &when) == 0;
}

struct wba_spared {
    char sqlite[512], enc[512], enc_staging[512];
    char stale_tmp[512], stale_journal[512], fresh_journal[512];
};

/* Two hours old unless noted: a verified backup under its own name (the
 * bytes of a real one), an encrypted backup, the encrypt step's staging
 * name, an exact stale temporary, and the temporary's rollback journal both
 * stale and fresh. */
static bool wba_plant_spared(const struct wba_state *s, struct wba_spared *p)
{
    const char *dir = s->f.backup_dir;
    const int64_t old = 2 * 3600;
    int n = snprintf(p->sqlite, sizeof(p->sqlite), "%s/%s", dir,
                     "wallet_backup_5_000005.sqlite");
    return n > 0 && (size_t)n < sizeof(p->sqlite) &&
           wb_write_blob(p->sqlite, s->blobs[0], s->lens[0]) &&
           wba_age(p->sqlite, old) &&
           wba_plant(dir, "wallet_backup_6_000006.sqlite.enc", old, p->enc,
                     sizeof(p->enc)) &&
           wba_plant(dir, "wallet_backup_7_000007.sqlite.enc.tmp.1", old,
                     p->enc_staging, sizeof(p->enc_staging)) &&
           wba_plant(dir, "wallet_backup_8_000008.sqlite" WBA_TEMP_SUFFIX,
                     old, p->stale_tmp, sizeof(p->stale_tmp)) &&
           wba_plant(dir, "wallet_backup_9_000009.sqlite" WBA_TEMP_SUFFIX
                     "-journal", old, p->stale_journal,
                     sizeof(p->stale_journal)) &&
           wba_plant(dir, "wallet_backup_9_000010.sqlite" WBA_TEMP_SUFFIX
                     "-journal", 0, p->fresh_journal,
                     sizeof(p->fresh_journal));
}

static int t_atomic_sweep_spares(void)
{
    int failures = 0;
    struct wba_state s;
    struct wba_spared p;
    bool planted = wba_begin(&s, "atomic_spares") &&
                   wba_plant_spared(&s, &p) && wba_age(s.paths[1], 2 * 3600);
    /* Three real backups, the planted .sqlite and .sqlite.enc: five, within
     * a max_versions of eight, so rotation itself deletes nothing. */
    int deleted = planted ? wallet_backup_rotate(s.f.backup_dir, 8) : -1;
    WB_RUN("wb atomic: sweep and rotation within max_versions keep aged "
           "verified, encrypted and encrypt-staging files",
           planted && deleted == 0 && wba_earlier_intact(&s) &&
           wba_exists(p.sqlite) && wba_exists(p.enc) &&
           wba_exists(p.enc_staging));
    WB_RUN("wb atomic: sweep removes a stale temporary and its stale "
           "rollback journal",
           planted && !wba_exists(p.stale_tmp) &&
           !wba_exists(p.stale_journal));
    WB_RUN("wb atomic: sweep keeps a fresh temporary rollback journal",
           planted && wba_exists(p.fresh_journal));
    wba_end(&s);
    return failures;
}

/* ── Two-tier publish and the directory flush after it ─────────── */

static char g_wba_planted_final[512];

static int wba_rename_einval(int stage, const char *final_path)
{
    (void)final_path;
    return stage == WBA_STAGE_RENAME ? EINVAL : 0;
}

static int wba_rename_enosys(int stage, const char *final_path)
{
    (void)final_path;
    return stage == WBA_STAGE_RENAME ? ENOSYS : 0;
}

static int wba_rename_eio(int stage, const char *final_path)
{
    (void)final_path;
    return stage == WBA_STAGE_RENAME ? EIO : 0;
}

/* Another writer took the final name just before the publish, on a
 * directory that rejects the no-clobber flag. */
static int wba_rename_einval_planted(int stage, const char *final_path)
{
    if (stage != WBA_STAGE_RENAME)
        return 0;
    const uint8_t mark[4] = {0xde, 0xad, 0xbe, 0xef};
    snprintf(g_wba_planted_final, sizeof(g_wba_planted_final), "%s",
             final_path);
    (void)wb_write_blob(final_path, mark, sizeof(mark));
    return EINVAL;
}

static int wba_parent_flush_eio(int stage, const char *final_path)
{
    (void)final_path;
    return stage == WBA_STAGE_PARENT_FLUSH ? EIO : 0;
}

/* Runs once on a fresh three-key fixture with `hook` installed. */
static bool wba_run_hooked(struct wb_fixture *f, const char *tag,
                           int (*hook)(int, const char *),
                           char *path, size_t path_cap, int64_t *keys,
                           char *err, size_t err_cap, bool *ran_ok)
{
    wb_install_observer();
    if (!wb_fixture_init(f, tag) || wb_seed_keys(&f->ndb, 3) != 3)
        return false;
    atomic_store(&g_wb_ok, 0);
    atomic_store(&g_wb_fail, 0);
    wallet_backup_test_set_publish_hook(hook);
    *ran_ok = wallet_backup_run_once(f->backup_dir, &f->ndb, path, path_cap,
                                     keys, err, err_cap).ok;
    wallet_backup_test_set_publish_hook(NULL);
    return true;
}

static int wba_unsupported_case(const char *tag, const char *what,
                                int (*hook)(int, const char *))
{
    int failures = 0;
    struct wb_fixture f;
    char path[512] = "", name[192];
    int64_t keys = -1;
    bool ok = false;
    bool set = wba_run_hooked(&f, tag, hook, path, sizeof(path), &keys,
                              NULL, 0, &ok);
    snprintf(name, sizeof(name), "wb atomic: no-clobber flag unsupported "
             "(%s) publishes by checked plain rename, base-shaped", what);
    WB_RUN(name, set && ok && wba_published_cleanly(&f, path, keys) &&
                 wba_matches_base_shape(&f, path));
    wb_fixture_tear_down(&f);
    return failures;
}

static int t_atomic_unsupported_flag(void)
{
    return wba_unsupported_case("atomic_einval", "EINVAL",
                                wba_rename_einval) +
           wba_unsupported_case("atomic_enosys", "ENOSYS",
                                wba_rename_enosys);
}

static int t_atomic_unsupported_planted(void)
{
    int failures = 0;
    struct wb_fixture f;
    char path[512] = "", err[256] = "";
    bool ok = true;
    g_wba_planted_final[0] = '\0';
    bool set = wba_run_hooked(&f, "atomic_planted",
                              wba_rename_einval_planted, path, sizeof(path),
                              NULL, err, sizeof(err), &ok);
    uint8_t *now = NULL;
    size_t len = 0;
    const uint8_t mark[4] = {0xde, 0xad, 0xbe, 0xef};
    bool untouched = g_wba_planted_final[0] &&
                     wb_read_blob(g_wba_planted_final, &now, &len) &&
                     len == sizeof(mark) && memcmp(now, mark, len) == 0;
    free(now);
    WB_RUN("wb atomic: flag unsupported and final name taken fails, the "
           "planted file untouched, no temporary left",
           set && !ok && path[0] == '\0' && untouched &&
           strstr(err, "not confirmed absent") != NULL &&
           wba_dir_entries(f.backup_dir) == 1 &&
           atomic_load(&g_wb_fail) == 1 && atomic_load(&g_wb_ok) == 0);
    wb_fixture_tear_down(&f);
    return failures;
}

static int t_atomic_rename_io_error(void)
{
    int failures = 0;
    struct wb_fixture f;
    char path[512] = "", err[256] = "";
    bool ok = true;
    bool set = wba_run_hooked(&f, "atomic_rename_eio", wba_rename_eio, path,
                              sizeof(path), NULL, err, sizeof(err), &ok);
    WB_RUN("wb atomic: an I/O error from the no-clobber rename never falls "
           "back; the run fails and leaves no file",
           set && !ok && path[0] == '\0' &&
           strstr(err, "cannot rename verified backup") != NULL &&
           wba_dir_entries(f.backup_dir) == 0);
    wb_fixture_tear_down(&f);
    return failures;
}

/* Every wallet table's row count in `path` equals the source's; a table
 * the source lacks is absent from the file too. */
static bool wba_counts_verify(struct node_db *ndb, const char *path)
{
    struct wallet_backup_store_sqlite_ctx ctx;
    struct wallet_backup_store_port port = {0};
    size_t n = 0;
    const char *const *tables = wallet_backup_tables(&n);
    if (!wallet_backup_store_sqlite_bind(&ctx, ndb->db, &port))
        return false;
    for (size_t i = 0; i < n; i++) {
        int64_t src = -1;
        bool has = port.count_rows(port.self, tables[i], &src);
        int64_t dst = port.count_rows_in_file(port.self, path, tables[i]);
        if (has ? dst != src : dst >= 0)
            return false;
    }
    return n > 0;
}

static int t_atomic_parent_flush_failure(void)
{
    int failures = 0;
    struct wb_fixture f;
    char path[512] = "", err[256] = "", listing[4][512];
    bool ok = true;
    bool set = wba_run_hooked(&f, "atomic_dirflush", wba_parent_flush_eio,
                              path, sizeof(path), NULL, err, sizeof(err),
                              &ok);
    int listed = set ? wallet_backup_list(f.backup_dir, listing, 4) : -1;
    const char *leaf = listed == 1 ? strrchr(listing[0], '/') : NULL;
    WB_RUN("wb atomic: directory flush failure after the rename fails the "
           "run and says the verified file was kept",
           set && !ok && path[0] == '\0' &&
           strstr(err, "complete and verified and was kept, but its "
                       "directory entry may not survive a power loss") !=
               NULL &&
           atomic_load(&g_wb_fail) == 1 && atomic_load(&g_wb_ok) == 0);
    WB_RUN("wb atomic: after that failure the final file is listed, its row "
           "counts verify and no temporary remains",
           leaf && wba_final_name(leaf + 1) &&
           wba_counts_verify(&f.ndb, listing[0]) &&
           wba_dir_entries(f.backup_dir) == 1);
    wb_fixture_tear_down(&f);
    return failures;
}

static int t_wallet_backup_atomic(void)
{
    int failures = 0;
    failures += t_atomic_copy_failure();
    failures += t_atomic_verify_mismatch();
    failures += t_atomic_crash_points();
    failures += t_atomic_sweep();
    failures += t_atomic_sweep_spares();
    failures += t_atomic_success_shape();
    failures += t_atomic_unsupported_flag();
    failures += t_atomic_unsupported_planted();
    failures += t_atomic_rename_io_error();
    failures += t_atomic_parent_flush_failure();
    return failures;
}

#endif
