/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ldb_snapshot: exercises the snapshot-dir helper against a LevelDB
 * tree this test builds and owns.
 *
 * Hermetic: the fixture LevelDB is created under ./test-tmp/, populated, and
 * flushed to SST files with leveldb_compact_range. The test keeps the source
 * DB OPEN so the source LOCK is genuinely held (the condition ldb_snapshot_make
 * exists to work around), snapshots it, opens the snapshot and iterates it.
 * Nothing outside its own temp directory is read or written, and every count
 * below is exact.
 */

#include "test/test_core.h"
#include "storage/ldb_snapshot.h"

#include <dirent.h>
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

/* NULL-arg path. */
static int ls_check_null_args(void)
{
    int failures = 0;
    printf("ldb_snapshot: NULL args... ");
    {
        char err[64] = {0};
        bool ok = ldb_snapshot_make(NULL, NULL, err, sizeof(err));
        if (ok) { printf("FAIL (returned true)\n"); failures++; }
        else printf("OK (err=%s)\n", err);
    }
    return failures;
}

/* Missing-src path. Destination is per-process: a second suite running
 * concurrently must not be able to observe or race this path. */
static int ls_check_missing_src(const char *scratch)
{
    int failures = 0;
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
    return failures;
}

/* Destroy of non-existent is safe. */
static void ls_check_destroy_nonexistent(const char *scratch)
{
    printf("ldb_snapshot: destroy nonexistent... ");
    {
        char nope[600];
        snprintf(nope, sizeof(nope), "%s_nope", scratch);
        ldb_snapshot_destroy(nope);
        printf("OK\n");
    }
}

/* True when the fixture left at least one *.ldb SST file behind. */
static bool ls_check_fixture_ssts(const char *src)
{
    printf("ldb_snapshot: fixture has SST files... ");
    int ssts = ls_count_sst(src);
    if (ssts <= 0) {
        printf("FAIL (%d *.ldb files — nothing for the snapshot to "
               "hardlink)\n", ssts);
        return false;
    }
    printf("OK (%d)\n", ssts);
    return true;
}

/* Opening the locked source directly must fail; returns failures added. */
static int ls_check_src_locked(const char *src)
{
    int failures = 0;
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
    return failures;
}

/* Snapshot the locked source, retrying on manifest_changed. True on success. */
static bool ls_check_make_snapshot(const char *src, const char *dst)
{
    printf("ldb_snapshot: make (source still locked)... ");
    char err[256] = {0};
    bool ok = false;
    for (int try = 0; try < 3 && !ok; try++) {
        ok = ldb_snapshot_make(src, dst, err, sizeof(err));
        if (!ok && strcmp(err, "manifest_changed") != 0) break;
    }
    if (!ok) {
        printf("FAIL (%s)\n", err);
        return false;
    }
    printf("OK\n");
    return true;
}

/* Open the snapshot read-only and check exact record counts. */
static int ls_check_snapshot_iterate(const char *dst)
{
    int failures = 0;
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
    return failures;
}

/* Reads the still-open source for a known record; returns failures added. */
static int ls_check_source_intact(leveldb_t *srcdb)
{
    int failures = 0;
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
    return failures;
}

/* Destroy the snapshot dir and confirm it is gone; returns failures added. */
static int ls_check_teardown(const char *dst)
{
    int failures = 0;
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
    return failures;
}

/* Closes the source handle (setting it NULL) and re-iterates the source. */
static int ls_check_source_survives(leveldb_t **srcdb, const char *src)
{
    int failures = 0;
    printf("ldb_snapshot: source survives snapshot teardown... ");
    {
        leveldb_close(*srcdb);
        *srcdb = NULL;
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
    return failures;
}

/* ---- plain-directory edge cases: no LevelDB needed, every name is chosen
 * to sit on one side of a name-classification or error-path boundary ---- */

#define LS_CHECK(label, expression) do {                                  \
    if (expression) printf("ldb_snapshot: %s... OK\n", label);            \
    else { printf("ldb_snapshot: %s... FAIL\n", label); failures++; }     \
} while (0)

static const char *const ls_meta_names[] = {
    "CURRENT", "MANIFEST-000002", "LOG", "LOG.old"};
static const char *const ls_ldb_names[] = {".ldb", "000005.ldb"};
static const char *const ls_skip_names[] = {
    "LOCK", "000003.log", "OPTIONS", "LOGX", "LOG.older", "MANIFEST_x",
    "xldb", "a.sst", "ldb"};

static void ls_join(char *out, size_t n, const char *dir, const char *name)
{
    snprintf(out, n, "%s/%s", dir, name);
}

static bool ls_write_file(const char *dir, const char *name, size_t size,
                          unsigned seed)
{
    char p[1024];
    ls_join(p, sizeof(p), dir, name);
    FILE *f = fopen(p, "wb");
    if (!f)
        return false;
    bool ok = true;
    for (size_t i = 0; ok && i < size; i++)
        ok = fputc((int)((i * 7 + seed) & 0xff), f) != EOF;
    return fclose(f) == 0 && ok;
}

static bool ls_build_edge_src(const char *src)
{
    test_rm_rf(src);
    bool ok = mkdir(src, 0700) == 0 &&
              ls_write_file(src, "CURRENT", 16, 1) &&
              ls_write_file(src, "MANIFEST-000002", 150000, 2) &&
              ls_write_file(src, "LOG", 1, 3) &&
              ls_write_file(src, "LOG.old", 300, 4) &&
              ls_write_file(src, ".ldb", 100, 5) &&
              ls_write_file(src, "000005.ldb", 10, 6);
    for (size_t i = 0; ok && i < sizeof(ls_skip_names) / sizeof(ls_skip_names[0]); i++)
        ok = ls_write_file(src, ls_skip_names[i], 4 + i, 7);
    return ok;
}

static bool ls_same_bytes(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    bool same = fa && fb;
    while (same) {
        unsigned char ba[4096], bb[4096];
        size_t na = fread(ba, 1, sizeof(ba), fa);
        size_t nb = fread(bb, 1, sizeof(bb), fb);
        same = na == nb && memcmp(ba, bb, na) == 0;
        if (na == 0 || !same)
            break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return same;
}

/* 1 = same inode (hard link), 0 = different file, -1 = either is missing. */
static int ls_same_inode(const char *a, const char *b)
{
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0)
        return -1;
    return sa.st_ino == sb.st_ino && sa.st_dev == sb.st_dev;
}

static bool ls_entry_is(const char *src, const char *dst, const char *name,
                        int want_link)
{
    char a[1024], b[1024];
    ls_join(a, sizeof(a), src, name);
    ls_join(b, sizeof(b), dst, name);
    return ls_same_bytes(a, b) && ls_same_inode(a, b) == want_link;
}

static bool ls_exists(const char *dir, const char *name)
{
    char p[1024];
    struct stat st;
    ls_join(p, sizeof(p), dir, name);
    return lstat(p, &st) == 0;
}

static bool ls_all_entries(const char *src, const char *dst,
                           const char *const *names, size_t count,
                           int want_link)
{
    bool ok = true;
    for (size_t i = 0; i < count; i++)
        ok = ok && ls_entry_is(src, dst, names[i], want_link);
    return ok;
}

static bool ls_none_present(const char *dir, const char *const *names,
                            size_t count)
{
    bool none = true;
    for (size_t i = 0; i < count; i++)
        none = none && !ls_exists(dir, names[i]);
    return none;
}

/* Metadata names are byte-copied (new inode), *.ldb are hardlinked (same
 * inode), everything else is skipped, and a stale file in dst is wiped. */
static int ls_check_name_classes(const char *src, const char *dst)
{
    int failures = 0;
    char err[256] = {0};
    bool staged = ls_build_edge_src(src);
    test_rm_rf(dst);
    staged = staged && mkdir(dst, 0700) == 0 &&
             ls_write_file(dst, "stale.ldb", 3, 0);
    LS_CHECK("edge fixture staged", staged);
    if (!staged)
        return failures;
    LS_CHECK("make succeeds on the edge fixture",
             ldb_snapshot_make(src, dst, err, sizeof(err)));
    LS_CHECK("metadata files are byte copies with new inodes",
             ls_all_entries(src, dst, ls_meta_names,
                            sizeof(ls_meta_names) / sizeof(ls_meta_names[0]), 0));
    LS_CHECK("*.ldb files (including a bare .ldb) are hard links",
             ls_all_entries(src, dst, ls_ldb_names,
                            sizeof(ls_ldb_names) / sizeof(ls_ldb_names[0]), 1));
    LS_CHECK("other names are not copied",
             ls_none_present(dst, ls_skip_names,
                             sizeof(ls_skip_names) / sizeof(ls_skip_names[0])));
    LS_CHECK("stale dst entry is wiped", !ls_exists(dst, "stale.ldb"));
    ldb_snapshot_destroy(dst);
    LS_CHECK("destroy removes the directory itself", !ls_exists(dst, "."));
    return failures;
}

static bool ls_fails_with(const char *src, const char *dst, const char *prefix)
{
    char err[256] = {0};
    bool ok = ldb_snapshot_make(src, dst, err, sizeof(err));
    return !ok && strncmp(err, prefix, strlen(prefix)) == 0;
}

static int ls_check_arg_errors(const char *src, const char *dst)
{
    int failures = 0;
    char big[64] = "XXXXXXXX";
    char one[1] = {'X'};
    bool no_buf = !ldb_snapshot_make(NULL, NULL, NULL, 64);
    LS_CHECK("NULL args with no error buffer", no_buf);
    LS_CHECK("NULL src names null args", ls_fails_with(NULL, dst, "null args"));
    LS_CHECK("NULL dst names null args", ls_fails_with(src, NULL, "null args"));
    LS_CHECK("error text is written",
             !ldb_snapshot_make(NULL, dst, big, sizeof(big)) &&
                 strcmp(big, "null args") == 0);
    LS_CHECK("one-byte error buffer is terminated",
             !ldb_snapshot_make(NULL, dst, one, sizeof(one)) && one[0] == '\0');
    LS_CHECK("regular file as src is missing",
             ls_fails_with("/dev/null", dst, "src missing: "));
    LS_CHECK("dst under a missing parent fails at mkdir",
             ls_fails_with(src, "/no/such/parent/zcl_ldb_dst", "mkdir("));
    return failures;
}

static int ls_check_current_errors(const char *src, const char *dst)
{
    int failures = 0;
    char err[256] = {0};
    test_rm_rf(src);
    bool staged = mkdir(src, 0700) == 0;
    LS_CHECK("current fixture staged", staged);
    if (!staged)
        return failures;
    LS_CHECK("missing CURRENT is refused",
             ls_fails_with(src, dst, "read CURRENT"));
    ldb_snapshot_destroy(dst);
    LS_CHECK("empty CURRENT staged", ls_write_file(src, "CURRENT", 0, 0));
    LS_CHECK("empty CURRENT is refused",
             ls_fails_with(src, dst, "read CURRENT"));
    ldb_snapshot_destroy(dst);
    LS_CHECK("one-byte CURRENT staged", ls_write_file(src, "CURRENT", 1, 9));
    LS_CHECK("one-byte CURRENT is accepted",
             ldb_snapshot_make(src, dst, err, sizeof(err)));
    ldb_snapshot_destroy(dst);
    return failures;
}

/* Stage src with a CURRENT and a directory called `dirname` in it. */
static bool ls_stage_with_dir(const char *src, const char *dirname)
{
    char d[1024];
    test_rm_rf(src);
    ls_join(d, sizeof(d), src, dirname);
    return mkdir(src, 0700) == 0 && ls_write_file(src, "CURRENT", 16, 1) &&
           mkdir(d, 0700) == 0;
}

/* A directory standing where a file belongs makes link() or read() fail.
 * The make must fail with the matching message. The partial dst removal is
 * asserted in ls_check_failure_cleanup. */
static int ls_check_entry_failures(const char *src, const char *dst)
{
    int failures = 0;
    bool staged = ls_stage_with_dir(src, "bad.ldb");
    LS_CHECK("unlinkable *.ldb fixture staged", staged);
    if (staged) {
        LS_CHECK("unlinkable *.ldb entry fails with the link message",
                 ls_fails_with(src, dst, "link_or_copy(bad.ldb): link("));
    }
    staged = ls_stage_with_dir(src, "LOG.old");
    LS_CHECK("unreadable metadata fixture staged", staged);
    if (staged) {
        LS_CHECK("unreadable metadata entry fails with the copy message",
                 ls_fails_with(src, dst, "copy(LOG.old): read("));
    }
    return failures;
}

static int ls_fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d)
        return -1;
    int n = 0;
    while (readdir(d) != NULL)
        n++;
    closedir(d);
    return n;
}

static bool ls_dst_gone(const char *dst)
{
    struct stat st;
    return stat(dst, &st) != 0;
}

/* A failed make must remove the dst it created and close its DIR handle.
 * `what` names the case; fd counts are compared only when /proc is there. */
static int ls_check_failed_cleanup(const char *what, const char *src,
                                   const char *dst)
{
    int failures = 0;
    char err[256] = {0};
    int fds_before = ls_fd_count();
    bool ok = ldb_snapshot_make(src, dst, err, sizeof(err));
    int fds_after = ls_fd_count();
    LS_CHECK(what, !ok);
    LS_CHECK("failed make leaves no dst behind", ls_dst_gone(dst));
    if (fds_before >= 0 && fds_after >= 0)
        LS_CHECK("failed make leaks no descriptor", fds_after == fds_before);
    ldb_snapshot_destroy(dst);
    return failures;
}

static int ls_check_failure_cleanup(const char *src, const char *dst)
{
    int failures = 0;
    ldb_snapshot_destroy(dst);
    bool staged = ls_stage_with_dir(src, "bad.ldb");
    LS_CHECK("cleanup link fixture staged", staged);
    if (!staged)
        return failures;
    failures += ls_check_failed_cleanup("link failure refuses", src, dst);
    staged = ls_stage_with_dir(src, "LOG.old");
    LS_CHECK("cleanup copy fixture staged", staged);
    if (!staged)
        return failures;
    failures += ls_check_failed_cleanup("copy failure refuses", src, dst);
    test_rm_rf(src);
    staged = mkdir(src, 0700) == 0;
    LS_CHECK("cleanup no-CURRENT fixture staged", staged);
    if (!staged)
        return failures;
    failures += ls_check_failed_cleanup("missing CURRENT refuses", src, dst);
    if (geteuid() == 0) {
        printf("ldb_snapshot: opendir cleanup case skipped (root)\n");
        return failures;
    }
    staged = ls_write_file(src, "CURRENT", 16, 1) && chmod(src, 0300) == 0;
    LS_CHECK("cleanup unlistable src staged", staged);
    if (staged)
        failures += ls_check_failed_cleanup("unlistable src refuses", src, dst);
    chmod(src, 0700);
    return failures;
}

/* An undestroyable dst (holds a subdirectory) is tolerated as EEXIST. */
static int ls_check_existing_dst(const char *src, const char *dst)
{
    int failures = 0;
    char keep[1024];
    char err[256] = {0};
    test_rm_rf(src);
    test_rm_rf(dst);
    ls_join(keep, sizeof(keep), dst, "keep");
    bool staged = mkdir(src, 0700) == 0 && ls_write_file(src, "CURRENT", 16, 1) &&
                  mkdir(dst, 0700) == 0 && mkdir(keep, 0700) == 0;
    LS_CHECK("existing-dst fixture staged", staged);
    if (!staged)
        return failures;
    LS_CHECK("existing non-empty dst is tolerated",
             ldb_snapshot_make(src, dst, err, sizeof(err)));
    LS_CHECK("CURRENT copied into the existing dst",
             ls_entry_is(src, dst, "CURRENT", 0));
    test_rm_rf(dst);
    return failures;
}

/* Permission-driven failures; a root runner bypasses the modes, so skip. */
static int ls_check_permission_failures(const char *src, const char *dst)
{
    int failures = 0;
    if (geteuid() == 0) {
        printf("ldb_snapshot: permission cases skipped (root)\n");
        return failures;
    }
    char p[1024];
    test_rm_rf(src);
    bool staged = mkdir(src, 0700) == 0 && ls_write_file(src, "CURRENT", 16, 1) &&
                  chmod(src, 0300) == 0;
    LS_CHECK("unlistable src staged", staged);
    if (!staged) {
        chmod(src, 0700);
        return failures;
    }
    LS_CHECK("unlistable src fails at opendir",
             ls_fails_with(src, dst, "opendir("));
    chmod(src, 0700);
    ldb_snapshot_destroy(dst);
    ls_join(p, sizeof(p), src, "LOG");
    staged = ls_write_file(src, "LOG", 5, 1) && chmod(p, 0) == 0;
    LS_CHECK("unreadable LOG staged", staged);
    LS_CHECK("unreadable metadata fails at open",
             staged && ls_fails_with(src, dst, "copy(LOG): open("));
    return failures;
}

static int ls_check_dst_unwritable(const char *src, const char *dst)
{
    int failures = 0;
    if (geteuid() == 0)
        return failures;
    char keep[1024];
    test_rm_rf(src);
    test_rm_rf(dst);
    ls_join(keep, sizeof(keep), dst, "keep");
    bool staged = mkdir(src, 0700) == 0 && ls_write_file(src, "CURRENT", 16, 1) &&
                  mkdir(dst, 0700) == 0 && mkdir(keep, 0700) == 0 &&
                  chmod(dst, 0500) == 0;
    LS_CHECK("read-only dst staged", staged);
    if (staged)
        LS_CHECK("uncreatable dst file fails with the create message",
                 ls_fails_with(src, dst, "copy(CURRENT): create("));
    chmod(dst, 0700);
    test_rm_rf(dst);
    return failures;
}

static int ldb_snapshot_edge_tests(const char *scratch)
{
    int failures = 0;
    char src[600], dst[600];
    snprintf(src, sizeof(src), "%s_edge_src", scratch);
    snprintf(dst, sizeof(dst), "%s_edge_dst", scratch);
    failures += ls_check_name_classes(src, dst);
    failures += ls_check_arg_errors(src, dst);
    failures += ls_check_current_errors(src, dst);
    failures += ls_check_entry_failures(src, dst);
    failures += ls_check_failure_cleanup(src, dst);
    failures += ls_check_existing_dst(src, dst);
    failures += ls_check_permission_failures(src, dst);
    failures += ls_check_dst_unwritable(src, dst);
    test_rm_rf(src);
    test_rm_rf(dst);
    return failures;
}

int test_ldb_snapshot(void)
{
    int failures = 0;
    char src[512], dst[512], scratch[512];

    test_fmt_tmpdir(scratch, sizeof(scratch), "ldb_snapshot", "scratch");
    mkdir("test-tmp", 0755);

    /* NULL-arg path. */
    failures += ls_check_null_args();

    /* Missing-src path. Destination is per-process: a second suite running
     * concurrently must not be able to observe or race this path. */
    failures += ls_check_missing_src(scratch);

    /* Destroy of non-existent is safe. */
    ls_check_destroy_nonexistent(scratch);

    /* Name classification and error paths on plain directories. */
    failures += ldb_snapshot_edge_tests(scratch);

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

    if (!ls_check_fixture_ssts(src)) {
        leveldb_close(srcdb);
        test_rm_rf(src);
        return failures + 1;
    }

    /* The source LOCK is genuinely held by srcdb right now — prove it, so a
     * future change that quietly stops holding it cannot make the snapshot
     * path below vacuous. */
    failures += ls_check_src_locked(src);

    if (!ls_check_make_snapshot(src, dst)) {
        leveldb_close(srcdb);
        test_rm_rf(src);
        ldb_snapshot_destroy(dst);
        return failures + 1;
    }

    failures += ls_check_snapshot_iterate(dst);

    /* Hardlinks are names for the same inode: tearing the snapshot down must
     * not disturb the source, which is still open and serving reads. */
    failures += ls_check_source_intact(srcdb);

    /* Teardown. */
    failures += ls_check_teardown(dst);

    /* Source must still be readable after the snapshot was destroyed —
     * dropping a hardlink only decrements the link count. */
    failures += ls_check_source_survives(&srcdb, src);

    if (srcdb) leveldb_close(srcdb);
    test_rm_rf(src);
    return failures;
}
