/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ldb_snapshot: exercises the snapshot-dir helper against a LevelDB
 * tree this test builds and owns.
 *
 * Hermetic by construction. The fixture LevelDB is created under the
 * per-process ./test-tmp/ directory, populated, and flushed to on-disk SST
 * files with leveldb_compact_range. The test then keeps the source DB OPEN
 * — so the source LOCK is genuinely held, which is the exact condition
 * ldb_snapshot_make exists to work around — snapshots it, opens the
 * snapshot, and iterates it.
 *
 * This test reads and writes NOTHING outside its own temp directory. It
 * used to build a source path from $HOME/.zclassic/blocks/index and open
 * that if present, which made the result depend on whether the live
 * zclassicd oracle was running and what it had written. Holding our own
 * LOCK reproduces the same "source is locked by someone else" condition
 * deterministically, and every count below is exact instead of a floor.
 */

#include "test/test_core.h"
#include "storage/ldb_snapshot.h"

#include <leveldb/c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Fixture shape: half the keys carry the 'b' prefix that a real block index
 * uses, so the iteration assertions below are exact, not floors. */
#define LS_RECORDS  400
#define LS_B_KEYS   (LS_RECORDS / 2)

static void ls_key(char *buf, size_t n, int i)
{
    snprintf(buf, n, "%c%08d", (i % 2) ? 'b' : 'f', i);
}

/* Count "*.ldb" SST files in a directory. -1 if the directory is unreadable. */
static int ls_count_sst(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t l = strlen(e->d_name);
        if (l >= 4 && strcmp(e->d_name + l - 4, ".ldb") == 0) n++;
    }
    closedir(d);
    return n;
}

/* Build a LevelDB at `dir` holding LS_RECORDS records, force the memtable
 * out to SST files, then reopen and RETURN THE OPEN HANDLE so the caller
 * holds the source LOCK for the duration of the snapshot. */
static leveldb_t *ls_build_fixture(const char *dir)
{
    char *err = NULL;
    leveldb_options_t *opts = leveldb_options_create();
    leveldb_options_set_create_if_missing(opts, 1);
    leveldb_options_set_error_if_exists(opts, 1);

    leveldb_t *db = leveldb_open(opts, dir, &err);
    if (err || !db) {
        printf("FAIL (fixture open: %s)\n", err ? err : "null db");
        leveldb_free(err);
        leveldb_options_destroy(opts);
        return NULL;
    }

    leveldb_writeoptions_t *wo = leveldb_writeoptions_create();
    for (int i = 0; i < LS_RECORDS; i++) {
        char k[32], v[64];
        ls_key(k, sizeof(k), i);
        snprintf(v, sizeof(v), "value-%08d", i);
        leveldb_put(db, wo, k, strlen(k), v, strlen(v), &err);
        if (err) {
            printf("FAIL (fixture put %d: %s)\n", i, err);
            leveldb_free(err);
            leveldb_writeoptions_destroy(wo);
            leveldb_close(db);
            leveldb_options_destroy(opts);
            return NULL;
        }
    }
    leveldb_writeoptions_destroy(wo);

    /* Flush the memtable into real .ldb SST files — ldb_snapshot_make
     * hardlinks SSTs and copies metadata, it does not carry write-ahead
     * logs, so a fixture left only in the memtable would snapshot empty. */
    leveldb_compact_range(db, NULL, 0, NULL, 0);
    leveldb_close(db);

    /* Reopen: drops the now-obsolete log, and gives us the live LOCK. */
    leveldb_options_set_create_if_missing(opts, 0);
    leveldb_options_set_error_if_exists(opts, 0);
    db = leveldb_open(opts, dir, &err);
    leveldb_options_destroy(opts);
    if (err || !db) {
        printf("FAIL (fixture reopen: %s)\n", err ? err : "null db");
        leveldb_free(err);
        return NULL;
    }
    return db;
}

/* Iterate a LevelDB directory read-only; report total keys and 'b'-keys. */
static bool ls_iterate(const char *dir, int *n_out, int *b_out, char *why,
                       size_t why_sz)
{
    char *err = NULL;
    leveldb_options_t *opts = leveldb_options_create();
    leveldb_options_set_create_if_missing(opts, 0);
    leveldb_options_set_max_open_files(opts, 64);
    leveldb_t *db = leveldb_open(opts, dir, &err);
    if (err || !db) {
        snprintf(why, why_sz, "open: %s", err ? err : "null db");
        leveldb_free(err);
        leveldb_options_destroy(opts);
        return false;
    }

    leveldb_readoptions_t *ro = leveldb_readoptions_create();
    leveldb_iterator_t *it = leveldb_create_iterator(db, ro);
    int n = 0, b_keys = 0;
    for (leveldb_iter_seek_to_first(it);
         leveldb_iter_valid(it) && n < LS_RECORDS * 4;
         leveldb_iter_next(it)) {
        size_t klen = 0;
        const char *k = leveldb_iter_key(it, &klen);
        if (klen >= 1 && k[0] == 'b') b_keys++;
        n++;
    }
    leveldb_iter_get_error(it, &err);
    bool ok = (err == NULL);
    if (!ok) {
        snprintf(why, why_sz, "iter: %s", err);
        leveldb_free(err);
    }
    leveldb_iter_destroy(it);
    leveldb_readoptions_destroy(ro);
    leveldb_close(db);
    leveldb_options_destroy(opts);

    *n_out = n;
    *b_out = b_keys;
    return ok;
}

int test_ldb_snapshot(void)
{
    int failures = 0;
    char src[512], dst[512], scratch[512];

    test_fmt_tmpdir(scratch, sizeof(scratch), "ldb_snapshot", "scratch");
    mkdir("test-tmp", 0755);

    /* NULL-arg path. */
    printf("ldb_snapshot: NULL args... ");
    {
        char err[64] = {0};
        bool ok = ldb_snapshot_make(NULL, NULL, err, sizeof(err));
        if (ok) { printf("FAIL (returned true)\n"); failures++; }
        else printf("OK (err=%s)\n", err);
    }

    /* Missing-src path. Destination is per-process: a second suite running
     * concurrently must not be able to observe or race this path. */
    printf("ldb_snapshot: missing src... ");
    {
        char missing_dst[600];
        snprintf(missing_dst, sizeof(missing_dst), "%s_missing_dst", scratch);
        char err[128] = {0};
        bool ok = ldb_snapshot_make("/no/such/path/zcl_test_missing_src",
                                    missing_dst, err, sizeof(err));
        if (ok) { printf("FAIL (returned true)\n"); failures++; }
        else printf("OK (err=%s)\n", err);
        struct stat st;
        if (stat(missing_dst, &st) == 0) {
            printf("ldb_snapshot: missing src left dst behind — FAIL\n");
            failures++;
            rmdir(missing_dst);
        }
    }

    /* Destroy of non-existent is safe. */
    printf("ldb_snapshot: destroy nonexistent... ");
    {
        char nope[600];
        snprintf(nope, sizeof(nope), "%s_nope", scratch);
        ldb_snapshot_destroy(nope);
        printf("OK\n");
    }

    /* ── Self-owned fixture: build a real LevelDB, hold its LOCK, snapshot
     * it, and read the snapshot back. ─────────────────────────────────── */
    test_fmt_tmpdir(src, sizeof(src), "ldb_snapshot", "src");
    test_fmt_tmpdir(dst, sizeof(dst), "ldb_snapshot", "dst");
    test_rm_rf(src);
    ldb_snapshot_destroy(dst);

    printf("ldb_snapshot: build fixture leveldb (%d records)... ",
           LS_RECORDS);
    leveldb_t *srcdb = ls_build_fixture(src);
    if (!srcdb) {
        test_rm_rf(src);
        return failures + 1;
    }
    printf("OK\n");

    printf("ldb_snapshot: fixture has SST files... ");
    {
        int ssts = ls_count_sst(src);
        if (ssts <= 0) {
            printf("FAIL (%d *.ldb files — nothing for the snapshot to "
                   "hardlink)\n", ssts);
            leveldb_close(srcdb);
            test_rm_rf(src);
            return failures + 1;
        }
        printf("OK (%d)\n", ssts);
    }

    /* The source LOCK is genuinely held by srcdb right now — prove it, so a
     * future change that quietly stops holding it cannot make the snapshot
     * path below vacuous. */
    printf("ldb_snapshot: src LOCK is held (direct open must fail)... ");
    {
        char *err = NULL;
        leveldb_options_t *o = leveldb_options_create();
        leveldb_options_set_create_if_missing(o, 0);
        leveldb_t *blocked = leveldb_open(o, src, &err);
        leveldb_options_destroy(o);
        if (blocked || !err) {
            printf("FAIL (opened the locked source)\n");
            failures++;
            if (blocked) leveldb_close(blocked);
        } else {
            printf("OK (%s)\n", err);
        }
        leveldb_free(err);
    }

    printf("ldb_snapshot: make (source still locked)... ");
    {
        char err[256] = {0};
        bool ok = false;
        for (int try = 0; try < 3 && !ok; try++) {
            ok = ldb_snapshot_make(src, dst, err, sizeof(err));
            if (!ok && strcmp(err, "manifest_changed") != 0) break;
        }
        if (!ok) {
            printf("FAIL (%s)\n", err);
            leveldb_close(srcdb);
            test_rm_rf(src);
            ldb_snapshot_destroy(dst);
            return failures + 1;
        }
        printf("OK\n");
    }

    printf("ldb_snapshot: open + iterate the snapshot... ");
    {
        int n = 0, b_keys = 0;
        char why[256] = {0};
        if (!ls_iterate(dst, &n, &b_keys, why, sizeof(why))) {
            printf("FAIL (%s)\n", why);
            failures++;
        } else if (n != LS_RECORDS || b_keys != LS_B_KEYS) {
            printf("FAIL (n=%d want %d, b_keys=%d want %d)\n",
                   n, LS_RECORDS, b_keys, LS_B_KEYS);
            failures++;
        } else {
            printf("OK n=%d b_keys=%d\n", n, b_keys);
        }
    }

    /* Hardlinks are names for the same inode: tearing the snapshot down must
     * not disturb the source, which is still open and serving reads. */
    printf("ldb_snapshot: source intact after snapshot... ");
    {
        leveldb_readoptions_t *ro = leveldb_readoptions_create();
        char k[32];
        ls_key(k, sizeof(k), LS_RECORDS / 2);
        size_t vlen = 0;
        char *err = NULL;
        char *v = leveldb_get(srcdb, ro, k, strlen(k), &vlen, &err);
        char want[64];
        snprintf(want, sizeof(want), "value-%08d", LS_RECORDS / 2);
        if (err || !v || vlen != strlen(want) || memcmp(v, want, vlen) != 0) {
            printf("FAIL (%s)\n", err ? err : "value mismatch");
            failures++;
        } else {
            printf("OK\n");
        }
        leveldb_free(err);
        leveldb_free(v);
        leveldb_readoptions_destroy(ro);
    }

    /* Teardown. */
    printf("ldb_snapshot: teardown... ");
    ldb_snapshot_destroy(dst);
    {
        struct stat st;
        if (stat(dst, &st) == 0) {
            printf("FAIL (dir still exists)\n");
            failures++;
        } else {
            printf("OK\n");
        }
    }

    /* Source must still be readable after the snapshot was destroyed —
     * dropping a hardlink only decrements the link count. */
    printf("ldb_snapshot: source survives snapshot teardown... ");
    {
        leveldb_close(srcdb);
        srcdb = NULL;
        int n = 0, b_keys = 0;
        char why[256] = {0};
        if (!ls_iterate(src, &n, &b_keys, why, sizeof(why))) {
            printf("FAIL (%s)\n", why);
            failures++;
        } else if (n != LS_RECORDS || b_keys != LS_B_KEYS) {
            printf("FAIL (n=%d b_keys=%d)\n", n, b_keys);
            failures++;
        } else {
            printf("OK\n");
        }
    }

    if (srcdb) leveldb_close(srcdb);
    test_rm_rf(src);
    return failures;
}
