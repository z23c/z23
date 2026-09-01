/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ldb_reader: differential + adversarial coverage for the C23
 * read-only LevelDB reader (engine/modules/storage/src/ldb_reader_*.c).
 *
 * Hermetic. The fixture LevelDB is built by the vendored C++ library
 * inside this process's own ./test-tmp/ directory, then copied so each
 * implementation reads its own tree — the C++ open recovers and rewrites
 * its target, and letting it touch the tree the C23 side reads would
 * quietly erase the write-ahead-log replay this test exists to prove.
 *
 * Two questions are asked:
 *
 *   1. Does the C23 reader return EXACTLY what libleveldb.a returns? The
 *      fixture deliberately contains overwrites (a user key at several
 *      sequence numbers) and deletions (tombstones that must hide older
 *      values), plus unflushed writes left in the .log. Those are the
 *      three ways a reader can be subtly wrong and still look fine on a
 *      write-once fixture.
 *
 *   2. Does it REFUSE damaged input instead of inventing an answer? A
 *      truncated table, a flipped bit inside a data block, a corrupted
 *      write-ahead-log record, a garbage CURRENT, and a shredded footer
 *      each have to produce a named error and no crash. Silently wrong
 *      chain-state bytes are the worst failure this project can have, so
 *      "returned something" is not a passing result here.
 */

#include "test/test_core.h"

#include "storage/ldb_reader.h"
#include "util/file_tree_ops.h"
#include "util/safe_alloc.h"

#include <leveldb/c.h>

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Large enough to spill past the default 4 MB write buffer, so the
 * fixture ends up with real SSTables AND a populated write-ahead log. */
#define LR_RECORDS      6000
#define LR_VALUE_BYTES  900
#define LR_DELETE_EVERY 7
#define LR_REWRITE_EVERY 3

static void lr_key(char *buf, size_t n, int i)
{
    snprintf(buf, n, "%c%08d", (i % 2) ? 'b' : 'c', i);
}

static void lr_value(char *buf, size_t n, int i, int generation)
{
    memset(buf, 'a' + (i % 23), n);
    snprintf(buf, 24, "v-%08d-gen%d", i, generation);
    buf[23] = (char)('0' + (i % 10));
}

/* Build a fixture whose visible content exercises overwrite + tombstone
 * resolution, and leave the last writes unflushed in the .log. */
static bool lr_build_fixture(const char *dir)
{
    char *err = NULL;
    leveldb_options_t *opts = leveldb_options_create();
    leveldb_options_set_create_if_missing(opts, 1);
    leveldb_options_set_error_if_exists(opts, 1);
    leveldb_options_set_compression(opts, leveldb_no_compression);
    leveldb_t *db = leveldb_open(opts, dir, &err);
    leveldb_options_destroy(opts);
    if (!db) {
        printf("FAIL (fixture open: %s)\n", err ? err : "null db");
        leveldb_free(err);
        return false;
    }

    char *value = zcl_malloc(LR_VALUE_BYTES, "ldb_reader_test_value");
    if (!value) {
        leveldb_close(db);
        return false;
    }
    leveldb_writeoptions_t *wo = leveldb_writeoptions_create();
    bool ok = true;

    /* Pass 0 — every key, then an explicit compaction so these land in
     * real SSTables that the MANIFEST records. Relying on the automatic
     * 4 MB memtable flush is not enough: leveldb abandons an in-flight
     * memtable compaction when the database is closing, leaving an
     * orphan .ldb the MANIFEST never references. */
    for (int i = 0; i < LR_RECORDS && ok; i++) {
        char k[32];
        lr_key(k, sizeof(k), i);
        lr_value(value, LR_VALUE_BYTES, i, 0);
        leveldb_put(db, wo, k, strlen(k), value, LR_VALUE_BYTES, &err);
        if (err) {
            printf("FAIL (fixture put 0/%d: %s)\n", i, err);
            leveldb_free(err);
            ok = false;
        }
    }
    if (ok)
        leveldb_compact_range(db, NULL, 0, NULL, 0);

    /* Pass 1 — rewrite a third of the keys and delete every seventh, then
     * compact again. Now the tables themselves carry several sequence
     * numbers per user key plus real tombstones. */
    for (int i = 0; i < LR_RECORDS && ok; i += LR_REWRITE_EVERY) {
        char k[32];
        lr_key(k, sizeof(k), i);
        lr_value(value, LR_VALUE_BYTES, i, 1);
        leveldb_put(db, wo, k, strlen(k), value, LR_VALUE_BYTES, &err);
        if (err) {
            leveldb_free(err);
            ok = false;
        }
    }
    for (int i = 0; i < LR_RECORDS && ok; i += LR_DELETE_EVERY) {
        char k[32];
        lr_key(k, sizeof(k), i);
        leveldb_delete(db, wo, k, strlen(k), &err);
        if (err) {
            leveldb_free(err);
            ok = false;
        }
    }
    if (ok)
        leveldb_compact_range(db, NULL, 0, NULL, 0);

    /* Pass 2 — left UNFLUSHED on purpose. These writes exist only in the
     * write-ahead log, so a reader that parses tables alone returns the
     * pass-1 values here and reports no error at all. The tombstones in
     * this pass additionally have to hide values that ARE in a table. */
    for (int i = 0; i < LR_RECORDS / 4 && ok; i++) {
        char k[32];
        lr_key(k, sizeof(k), i);
        lr_value(value, LR_VALUE_BYTES, i, 2);
        leveldb_put(db, wo, k, strlen(k), value, LR_VALUE_BYTES, &err);
        if (err) {
            leveldb_free(err);
            ok = false;
        }
    }
    for (int i = 1; i < LR_RECORDS && ok; i += LR_DELETE_EVERY * 3) {
        char k[32];
        lr_key(k, sizeof(k), i);
        leveldb_delete(db, wo, k, strlen(k), &err);
        if (err) {
            leveldb_free(err);
            ok = false;
        }
    }
    for (int i = 0; i < 64 && ok; i++) {
        char k[32];
        snprintf(k, sizeof(k), "z-unflushed-%04d", i);
        lr_value(value, LR_VALUE_BYTES, i, 9);
        leveldb_put(db, wo, k, strlen(k), value, LR_VALUE_BYTES, &err);
        if (err) {
            leveldb_free(err);
            ok = false;
        }
    }

    leveldb_writeoptions_destroy(wo);
    free(value);
    leveldb_close(db);   /* does NOT flush the memtable: the log survives */
    return ok;
}

/* Compare the whole ordered stream and every point read. Returns the
 * number of records compared, or -1 on any difference. */
static long lr_compare(const char *cxx_dir, const char *c23_dir)
{
    char *err = NULL;
    leveldb_options_t *copts = leveldb_options_create();
    leveldb_options_set_create_if_missing(copts, 0);
    leveldb_t *cdb = leveldb_open(copts, cxx_dir, &err);
    leveldb_options_destroy(copts);
    if (!cdb) {
        printf("FAIL (cxx open: %s)\n", err ? err : "null");
        leveldb_free(err);
        return -1;
    }
    leveldb_readoptions_t *cro = leveldb_readoptions_create();
    leveldb_readoptions_set_verify_checksums(cro, 1);

    ldbr_options_t *ropts = ldbr_options_create();
    ldbr_options_set_create_if_missing(ropts, 0);
    ldbr_t *rdb = ldbr_open(ropts, c23_dir, &err);
    ldbr_options_destroy(ropts);
    if (!rdb) {
        printf("FAIL (c23 open: %s)\n", err ? err : "null");
        free(err);
        leveldb_readoptions_destroy(cro);
        leveldb_close(cdb);
        return -1;
    }
    ldbr_readoptions_t *rro = ldbr_readoptions_create();

    leveldb_iterator_t *ci = leveldb_create_iterator(cdb, cro);
    ldbr_iterator_t *ri = ldbr_create_iterator(rdb, rro);
    leveldb_iter_seek_to_first(ci);
    ldbr_iter_seek_to_first(ri);

    long n = 0;
    bool bad = false;
    while (!bad) {
        unsigned char cv = leveldb_iter_valid(ci);
        unsigned char rv = ldbr_iter_valid(ri);
        if (cv != rv) {
            printf("FAIL (stream ends differently at %ld: cxx=%u c23=%u)\n",
                   n, cv, rv);
            bad = true;
            break;
        }
        if (!cv)
            break;
        size_t ck = 0, rk = 0, cvl = 0, rvl = 0;
        const char *ckey = leveldb_iter_key(ci, &ck);
        const char *rkey = ldbr_iter_key(ri, &rk);
        const char *cval = leveldb_iter_value(ci, &cvl);
        const char *rval = ldbr_iter_value(ri, &rvl);
        if (ck != rk || memcmp(ckey, rkey, ck) != 0) {
            printf("FAIL (key differs at record %ld)\n", n);
            bad = true;
            break;
        }
        if (cvl != rvl || memcmp(cval, rval, cvl) != 0) {
            printf("FAIL (value differs at record %ld)\n", n);
            bad = true;
            break;
        }
        n++;
        leveldb_iter_next(ci);
        ldbr_iter_next(ri);
    }
    char *cerr = NULL, *rerr = NULL;
    leveldb_iter_get_error(ci, &cerr);
    ldbr_iter_get_error(ri, &rerr);
    if (cerr || rerr) {
        printf("FAIL (iterator error cxx=%s c23=%s)\n", cerr ? cerr : "clean",
               rerr ? rerr : "clean");
        bad = true;
    }
    leveldb_free(cerr);
    free(rerr);
    leveldb_iter_destroy(ci);
    ldbr_iter_destroy(ri);

    /* Point reads: every fixture key, including the deleted ones (which
     * must be absent on BOTH sides) and keys that never existed. */
    for (int i = 0; !bad && i < LR_RECORDS; i++) {
        char k[32];
        lr_key(k, sizeof(k), i);
        size_t cn = 0, rn = 0;
        char *ce = NULL, *re = NULL;
        char *cv2 = leveldb_get(cdb, cro, k, strlen(k), &cn, &ce);
        char *rv2 = ldbr_get(rdb, rro, k, strlen(k), &rn, &re);
        if (ce || re || (cv2 == NULL) != (rv2 == NULL) ||
            (cv2 && (cn != rn || memcmp(cv2, rv2, cn) != 0))) {
            printf("FAIL (get differs for key %s: cxx=%s c23=%s)\n", k,
                   cv2 ? "found" : "absent", rv2 ? "found" : "absent");
            bad = true;
        }
        leveldb_free(cv2);
        ldbr_free(rv2);
        leveldb_free(ce);
        free(re);
    }
    for (int i = 0; !bad && i < 64; i++) {
        char k[48];
        snprintf(k, sizeof(k), "never-written-%04d", i);
        size_t cn = 0, rn = 0;
        char *ce = NULL, *re = NULL;
        char *cv2 = leveldb_get(cdb, cro, k, strlen(k), &cn, &ce);
        char *rv2 = ldbr_get(rdb, rro, k, strlen(k), &rn, &re);
        if (ce || re || cv2 || rv2) {
            printf("FAIL (absent key %s reported present)\n", k);
            bad = true;
        }
        leveldb_free(cv2);
        ldbr_free(rv2);
        leveldb_free(ce);
        free(re);
    }

    ldbr_readoptions_destroy(rro);
    ldbr_close(rdb);
    leveldb_readoptions_destroy(cro);
    leveldb_close(cdb);
    return bad ? -1 : n;
}

/* ── damage helpers ─────────────────────────────────────────────────── */

/* Apply `fn` to the first file in `dir` whose name ends in `suffix`. */
static bool lr_first_with_suffix(const char *dir, const char *suffix,
                                 char *out, size_t out_sz)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    struct dirent *e;
    while (!found && (e = readdir(d)) != NULL) {
        size_t l = strlen(e->d_name), s = strlen(suffix);
        if (l >= s && strcmp(e->d_name + l - s, suffix) == 0) {
            snprintf(out, out_sz, "%s/%s", dir, e->d_name);
            found = true;
        }
    }
    closedir(d);
    return found;
}

static bool lr_truncate_file(const char *path, off_t keep)
{
    return truncate(path, keep) == 0;
}

static bool lr_flip_byte(const char *path, off_t at)
{
    int fd = open(path, O_RDWR);
    if (fd < 0)
        return false;
    unsigned char b = 0;
    bool ok = pread(fd, &b, 1, at) == 1;
    if (ok) {
        b ^= 0x40;
        ok = pwrite(fd, &b, 1, at) == 1;
    }
    close(fd);
    return ok;
}

/* Open the damaged copy and demand a refusal: either the open fails, or
 * iteration surfaces an error. Returning a short-but-clean stream is the
 * failure this checks for. */
static bool lr_refuses(const char *dir, const char *what)
{
    char *err = NULL;
    ldbr_options_t *o = ldbr_options_create();
    ldbr_options_set_create_if_missing(o, 0);
    ldbr_t *db = ldbr_open(o, dir, &err);
    ldbr_options_destroy(o);
    if (!db) {
        printf("  %s -> refused at open (%s)\n", what,
               err ? err : "no message");
        free(err);
        return true;
    }
    ldbr_readoptions_t *ro = ldbr_readoptions_create();
    ldbr_iterator_t *it = ldbr_create_iterator(db, ro);
    long n = 0;
    for (ldbr_iter_seek_to_first(it); ldbr_iter_valid(it); ldbr_iter_next(it))
        n++;
    char *ierr = NULL;
    ldbr_iter_get_error(it, &ierr);
    bool refused = ierr != NULL;
    if (refused)
        printf("  %s -> refused during iteration after %ld records (%s)\n",
               what, n, ierr);
    else
        printf("  %s -> NOT REFUSED (%ld records read clean)\n", what, n);
    free(ierr);
    ldbr_iter_destroy(it);
    ldbr_readoptions_destroy(ro);
    ldbr_close(db);
    return refused;
}

static bool lr_copy(const char *src, const char *dst)
{
    test_rm_rf(dst);
    struct zcl_result r = zcl_tree_copy(src, dst, 0, NULL, NULL);
    return r.ok;
}

int test_ldb_reader(void)
{
    int failures = 0;
    char src[512], cxx[512], c23[512], dmg[512];

    mkdir("test-tmp", 0755);
    test_fmt_tmpdir(src, sizeof(src), "ldb_reader", "src");
    test_fmt_tmpdir(cxx, sizeof(cxx), "ldb_reader", "cxx");
    test_fmt_tmpdir(c23, sizeof(c23), "ldb_reader", "c23");
    test_fmt_tmpdir(dmg, sizeof(dmg), "ldb_reader", "dmg");
    test_rm_rf(src);
    test_rm_rf(cxx);
    test_rm_rf(c23);
    test_rm_rf(dmg);

    printf("ldb_reader: build fixture (%d keys, overwrites + tombstones + "
           "unflushed log)... ", LR_RECORDS);
    if (!lr_build_fixture(src)) {
        test_rm_rf(src);
        return failures + 1;
    }
    printf("OK\n");

    printf("ldb_reader: fixture has both SSTables and a write-ahead log... ");
    {
        char probe[600];
        bool has_sst = lr_first_with_suffix(src, ".ldb", probe, sizeof(probe));
        bool has_log = lr_first_with_suffix(src, ".log", probe, sizeof(probe));
        if (!has_sst || !has_log) {
            printf("FAIL (sst=%d log=%d — the fixture would not exercise "
                   "both paths)\n", has_sst, has_log);
            test_rm_rf(src);
            return failures + 1;
        }
        printf("OK\n");
    }

    printf("ldb_reader: byte-identical stream + point reads vs libleveldb... ");
    if (!lr_copy(src, cxx) || !lr_copy(src, c23)) {
        printf("FAIL (could not copy the fixture)\n");
        test_rm_rf(src);
        return failures + 1;
    }
    {
        long n = lr_compare(cxx, c23);
        if (n < 0) {
            failures++;
        } else if (n < LR_RECORDS / 2) {
            printf("FAIL (only %ld records — the fixture went missing)\n", n);
            failures++;
        } else {
            printf("OK (%ld records identical)\n", n);
        }
    }

    /* The C23 side above read a tree the C++ library never recovered, so
     * matching it proves the write-ahead log was replayed. Make that
     * explicit rather than implied. */
    printf("ldb_reader: write-ahead log actually replayed... ");
    {
        char *err = NULL;
        ldbr_options_t *o = ldbr_options_create();
        ldbr_options_set_create_if_missing(o, 0);
        ldbr_t *db = ldbr_open(o, c23, &err);
        ldbr_options_destroy(o);
        if (!db) {
            printf("FAIL (open: %s)\n", err ? err : "null");
            free(err);
            failures++;
        } else {
            size_t entries = ldbr_stat_memtable_entries(db);
            size_t tables = ldbr_stat_table_count(db);
            if (entries == 0 || tables == 0) {
                printf("FAIL (memtable=%zu tables=%zu — one path was never "
                       "taken)\n", entries, tables);
                failures++;
            } else {
                printf("OK (%zu log entries over %zu tables)\n", entries,
                       tables);
            }
            ldbr_close(db);
        }
    }

    printf("ldb_reader: missing CURRENT is an empty database, not a crash... ");
    {
        char empty[600];
        snprintf(empty, sizeof(empty), "%s_empty", src);
        test_rm_rf(empty);
        mkdir(empty, 0755);
        char *err = NULL;
        ldbr_options_t *o = ldbr_options_create();
        ldbr_options_set_create_if_missing(o, 1);
        ldbr_t *db = ldbr_open(o, empty, &err);
        ldbr_options_destroy(o);
        if (!db) {
            printf("FAIL (%s)\n", err ? err : "null");
            free(err);
            failures++;
        } else {
            ldbr_readoptions_t *ro = ldbr_readoptions_create();
            ldbr_iterator_t *it = ldbr_create_iterator(db, ro);
            ldbr_iter_seek_to_first(it);
            bool any = ldbr_iter_valid(it) != 0;
            ldbr_iter_destroy(it);
            ldbr_readoptions_destroy(ro);
            ldbr_close(db);
            if (any) {
                printf("FAIL (empty database yielded a record)\n");
                failures++;
            } else {
                printf("OK\n");
            }
        }
        test_rm_rf(empty);
    }

    printf("ldb_reader: refuses damaged input rather than inventing data\n");
    {
        struct {
            const char *what;
            int kind;       /* 0 truncate table, 1 flip in table, 2 flip in
                             * log, 3 clobber CURRENT, 4 shred footer */
        } cases[] = {
            { "table truncated mid-file", 0 },
            { "bit flipped inside a data block", 1 },
            { "bit flipped inside a write-ahead-log record", 2 },
            { "CURRENT names a nonexistent manifest", 3 },
            { "table footer magic destroyed", 4 },
        };
        for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
            if (!lr_copy(src, dmg)) {
                printf("  %s -> FAIL (copy)\n", cases[c].what);
                failures++;
                continue;
            }
            char path[600];
            bool prepared = false;
            struct stat st;
            switch (cases[c].kind) {
            case 0:
                prepared = lr_first_with_suffix(dmg, ".ldb", path,
                                                sizeof(path)) &&
                           stat(path, &st) == 0 &&
                           lr_truncate_file(path, st.st_size / 2);
                break;
            case 1:
                prepared = lr_first_with_suffix(dmg, ".ldb", path,
                                                sizeof(path)) &&
                           lr_flip_byte(path, 32);
                break;
            case 2:
                prepared = lr_first_with_suffix(dmg, ".log", path,
                                                sizeof(path)) &&
                           lr_flip_byte(path, 40);
                break;
            case 3: {
                snprintf(path, sizeof(path), "%s/CURRENT", dmg);
                int fd = open(path, O_WRONLY | O_TRUNC);
                if (fd >= 0) {
                    prepared = write(fd, "MANIFEST-999999\n", 16) == 16;
                    close(fd);
                }
                break;
            }
            case 4:
                prepared = lr_first_with_suffix(dmg, ".ldb", path,
                                                sizeof(path)) &&
                           stat(path, &st) == 0 && st.st_size > 8 &&
                           lr_flip_byte(path, st.st_size - 4);
                break;
            default:
                break;
            }
            if (!prepared) {
                printf("  %s -> FAIL (could not stage the damage)\n",
                       cases[c].what);
                failures++;
                continue;
            }
            if (!lr_refuses(dmg, cases[c].what))
                failures++;
        }
    }

    test_rm_rf(src);
    test_rm_rf(cxx);
    test_rm_rf(c23);
    test_rm_rf(dmg);
    return failures;
}
