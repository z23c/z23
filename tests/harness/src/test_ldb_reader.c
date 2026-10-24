/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_ldb_reader: differential + adversarial coverage for the C23
 * read-only LevelDB reader (engine/modules/storage/src/ldb_reader_*.c).
 *
 * Hermetic. The fixture LevelDB is built by the vendored C++ library in
 * ./test-tmp/, then copied so each implementation reads its own tree (the C++
 * open recovers and rewrites its target, which would erase the write-ahead-log
 * replay this test proves).
 *
 *   1. Does the C23 reader return EXACTLY what libleveldb.a returns? The
 *      fixture has overwrites (several sequence numbers per user key),
 *      deletions (tombstones hiding older values), and unflushed writes in
 *      the .log.
 *
 *   2. Does it REFUSE damaged input? A truncated table, a flipped bit in a
 *      data block, a corrupted write-ahead-log record, a garbage CURRENT, and
 *      a shredded footer each must produce a named error and no crash.
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

static bool lr_build_unflushed(leveldb_t *db, leveldb_writeoptions_t *wo,
                                char *value, bool ok)
{
    char *err = NULL;
    /* Pass 2 — left UNFLUSHED: these writes exist only in the write-ahead
     * log, and its tombstones must hide values that ARE in a table. */
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

    return ok;
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
     * SSTables the MANIFEST records (leveldb abandons an in-flight memtable
     * compaction on close, leaving an unreferenced .ldb). */
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

    ok = lr_build_unflushed(db, wo, value, ok);

    leveldb_writeoptions_destroy(wo);
    free(value);
    leveldb_close(db);   /* does NOT flush the memtable: the log survives */
    return ok;
}

static long lr_compare_stream(leveldb_t *cdb, leveldb_readoptions_t *cro,
                                ldbr_t *rdb, ldbr_readoptions_t *rro)
{
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

    return bad ? -1 : n;
}

static bool lr_compare_points(leveldb_t *cdb, leveldb_readoptions_t *cro,
                                ldbr_t *rdb, ldbr_readoptions_t *rro,
                                bool bad)
{
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
    return bad;
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

    long n = lr_compare_stream(cdb, cro, rdb, rro);
    bool bad = n < 0;

    /* Point reads: every fixture key, including the deleted ones (which
     * must be absent on BOTH sides) and keys that never existed. */
    bad = lr_compare_points(cdb, cro, rdb, rro, bad);
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

static bool lr_current_open_result(const char *dir, bool valid)
{
    char *err = NULL;
    ldbr_options_t *o = ldbr_options_create();
    if (!o) {
        printf("FAIL (CURRENT test options allocation)\n");
        return false;
    }
    ldbr_options_set_create_if_missing(o, 0);
    ldbr_t *db = ldbr_open(o, dir, &err);
    ldbr_options_destroy(o);
    bool ok = valid ? db != NULL && err == NULL :
                     db == NULL && err != NULL && err[0] != '\0';
    printf("  CURRENT %s -> %s (%s)\n", valid ? "valid" : "hidden suffix",
           ok ? "OK" : "FAIL", err ? err : "opened without error");
    if (db)
        ldbr_close(db);
    ldbr_free(err);
    return ok;
}

static size_t lr_current_read(const char *dir, char *bytes, size_t cap)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/CURRENT", dir);
    FILE *f = fopen(path, "rb");
    if (!f) {
        printf("FAIL (CURRENT fixture read)\n");
        return 0;
    }
    size_t n = fread(bytes, 1, cap, f);
    bool complete = !ferror(f) && feof(f);
    int closed = fclose(f);
    if (!complete || closed != 0 || n == 0 || n > cap - 40 ||
        bytes[n - 1] != '\n') {
        printf("FAIL (CURRENT fixture extent)\n");
        return 0;
    }
    return n;
}

static bool lr_current_write(const char *dir, const char *bytes, size_t len)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/CURRENT", dir);
    FILE *f = fopen(path, "wb");
    if (!f) {
        printf("FAIL (CURRENT fixture write)\n");
        return false;
    }
    bool written = fwrite(bytes, 1, len, f) == len;
    int closed = fclose(f);
    if (!written || closed != 0) {
        printf("FAIL (CURRENT fixture write extent)\n");
        return false;
    }
    return true;
}

static int lr_current_extent(const char *src, const char *dst)
{
    char current[512];
    size_t n = lr_current_read(src, current, sizeof(current));
    if (n == 0)
        return 1;
    static const char *const suffixes[] = {
        "", "\0junk", "\0MANIFEST-999999", "\0/hidden"
    };
    static const size_t sizes[] = {0, 5, 16, 8};
    int failures = 0;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        if (!lr_copy(src, dst)) {
            printf("FAIL (CURRENT fixture copy)\n");
            return failures + 1;
        }
        char bytes[512];
        memcpy(bytes, current, n - 1);
        memcpy(bytes + n - 1, suffixes[i], sizes[i]);
        bytes[n - 1 + sizes[i]] = '\n';
        if (!lr_current_write(dst, bytes, n + sizes[i]))
            return failures + 1;
        failures += !lr_current_open_result(dst, i == 0);
    }
    return failures;
}

static bool lr_test_log_span_bounds(void)
{
    size_t end = SIZE_MAX;
    bool ok = ldbr_test_log_span_end(0, 0, 0, &end) && end == 0;
    ok = ok && ldbr_test_log_span_end(SIZE_MAX, SIZE_MAX - 7, 7, &end) &&
         end == SIZE_MAX;
    end = SIZE_MAX;
    ok = ok && !ldbr_test_log_span_end(SIZE_MAX, SIZE_MAX, 1, &end) && end == 0;
    end = SIZE_MAX;
    ok = ok && !ldbr_test_log_span_end(SIZE_MAX - 1, SIZE_MAX, 0, &end) && end == 0;
    return ok && !ldbr_test_log_span_end(0, 0, 0, NULL);
}

static bool lr_test_log_scratch_growth_bounds(void)
{
    size_t len = SIZE_MAX, cap = SIZE_MAX;
    if (!ldbr_test_log_scratch_plan(0, 0, 0, &len, &cap) || len != 0 || cap != 0)
        return false;
    if (!ldbr_test_log_scratch_plan(0, 1, 0, &len, &cap) || len != 1 || cap != 4096)
        return false;
    return ldbr_test_log_scratch_plan(4096, 1, 4096, &len, &cap) &&
           len == 4097 && cap == 8192;
}

static bool lr_test_log_scratch_refusal_bounds(void)
{
    size_t len = 0, cap = 0;
    if (!ldbr_test_log_scratch_plan(SIZE_MAX - 1, 1, SIZE_MAX - 1, &len, &cap) ||
        len != SIZE_MAX || cap != SIZE_MAX)
        return false;
    len = cap = SIZE_MAX;
    if (ldbr_test_log_scratch_plan(SIZE_MAX, 1, SIZE_MAX, &len, &cap) || len != 0 || cap != 0)
        return false;
    if (ldbr_test_log_scratch_plan(2, 0, 1, &len, &cap) || len != 0 || cap != 0)
        return false;
    cap = SIZE_MAX;
    if (ldbr_test_log_scratch_plan(0, 0, 0, NULL, &cap) || cap != 0)
        return false;
    len = SIZE_MAX;
    return !ldbr_test_log_scratch_plan(0, 0, 0, &len, NULL) && len == 0;
}

static bool lr_test_log_production_appends(void)
{
    size_t len = 0, cap = 0;
    if (!ldbr_test_log_scratch_append(0, 0, &len, &cap) ||
        len != 0 || cap != 0)
        return false;
    if (!ldbr_test_log_scratch_append(0, 1, &len, &cap) ||
        len != 1 || cap != 4096)
        return false;
    if (!ldbr_test_log_scratch_append(1, 1, &len, &cap) ||
        len != 2 || cap != 4096)
        return false;
    return true;
}

static bool lr_test_log_production_bounds(void)
{
    size_t len = 0, cap = 0;
    if (!lr_test_log_production_appends())
        return false;
    if (ldbr_test_log_scratch_append(SIZE_MAX, 1, &len, &cap) ||
        len != SIZE_MAX || cap != SIZE_MAX)
        return false;
    if (ldbr_test_log_scratch_append(1, 2, &len, &cap) ||
        len != 1 || cap != 4096)
        return false;
    return true;
}

static bool lr_test_log_tail_case(size_t size, size_t start, size_t expected)
{
    size_t pos = 0;
    if (ldbr_test_log_tail(size, start, &pos) && pos == expected)
        return true;
    printf("FAIL (tail size=%zu start=%zu: retained position %zu, expected %zu)\n",
           size, start, pos, expected);
    return false;
}

static bool lr_test_log_production_tails(void)
{
    return lr_test_log_tail_case(6, 0, 0) &&
           lr_test_log_tail_case(32766, 32766, 32766) &&
           lr_test_log_tail_case(32767, 32766, 32766) &&
           lr_test_log_tail_case(32768, 32766, 32768) &&
           lr_test_log_tail_case(SIZE_MAX, SIZE_MAX, SIZE_MAX);
}

static int lr_test_log_arithmetic_bounds(void)
{
    printf("ldb_reader: log arithmetic bounds... ");
    bool ok = lr_test_log_span_bounds() && lr_test_log_scratch_growth_bounds() &&
              lr_test_log_scratch_refusal_bounds() && lr_test_log_production_bounds() &&
              lr_test_log_production_tails();
    printf(ok ? "OK\n" : "FAIL\n");
    return ok ? 0 : 1;
}

static int lr_test_internal_key_size_bounds(void)
{
    printf("ldb_reader: internal-key size bounds... ");
    size_t size = SIZE_MAX;
    bool ok = ldbr_test_internal_key_size(0, &size) && size == 8;
    ok = ok && ldbr_test_internal_key_size(SIZE_MAX - 8, &size) &&
         size == SIZE_MAX;
    size = SIZE_MAX;
    ok = ok && !ldbr_test_internal_key_size(SIZE_MAX - 7, &size) && size == 0;
    size = SIZE_MAX;
    ok = ok && !ldbr_test_internal_key_size(SIZE_MAX, &size) && size == 0;
    ok = ok && !ldbr_test_internal_key_size(0, NULL);
    if (ok)
        printf("OK\n");
    else
        printf("FAIL\n");
    return ok ? 0 : 1;
}

static bool lr_point_key_refused(ldbr_t *db, ldbr_readoptions_t *ro,
                                 size_t key_len)
{
    char key = 0;
    char *err = NULL;
    size_t value_len = SIZE_MAX;
    char *value = ldbr_get(db, ro, &key, key_len, &value_len, &err);
    bool get_refused = !value && value_len == 0 && err &&
                       strstr(err, "could not build a lookup key");
    ldbr_free(value);
    ldbr_free(err);
    return get_refused;
}

static bool lr_extreme_key_refused(ldbr_t *db, ldbr_readoptions_t *ro,
                                   size_t key_len)
{
    bool get_refused = lr_point_key_refused(db, ro, key_len);
    char key = 0;
    char *err = NULL;

    ldbr_iterator_t *it = ldbr_create_iterator(db, ro);
    if (!it)
        return false;
    /* Allocate a seek buffer through the real caller before refusing a size. */
    ldbr_iter_seek(it, &key, 1);
    bool positioned = ldbr_iter_valid(it) != 0;
    ldbr_iter_seek(it, &key, key_len);
    ldbr_iter_get_error(it, &err);
    bool seek_refused = err && strstr(err, "could not build a seek key");
    bool invalid = ldbr_iter_valid(it) == 0;
    ldbr_free(err);
    ldbr_iter_destroy(it);
    return get_refused && positioned && seek_refused && invalid;
}

static int lr_test_extreme_key_length_refusals(const char *dir)
{
    printf("ldb_reader: extreme point/seek key lengths fail closed... ");
    char *err = NULL;
    ldbr_options_t *o = ldbr_options_create();
    if (!o) {
        printf("FAIL\n");
        return 1;
    }
    ldbr_options_set_create_if_missing(o, 0);
    ldbr_t *db = ldbr_open(o, dir, &err);
    ldbr_options_destroy(o);
    if (!db) {
        ldbr_free(err);
        printf("FAIL\n");
        return 1;
    }

    ldbr_readoptions_t *ro = ldbr_readoptions_create();
    if (!ro) {
        ldbr_close(db);
        printf("FAIL\n");
        return 1;
    }
    bool first = lr_extreme_key_refused(db, ro, SIZE_MAX - 7);
    bool last = lr_extreme_key_refused(db, ro, SIZE_MAX);
    ldbr_readoptions_destroy(ro);
    ldbr_close(db);
    bool ok = first && last;
    printf(ok ? "OK\n" : "FAIL\n");
    return ok ? 0 : 1;
}

static int lr_test_wal_replayed(const char *c23)
{
    int failures = 0;
    /* The C23 side read a tree the C++ library never recovered, so matching
     * it proves the write-ahead log was replayed. */
    printf("ldb_reader: write-ahead log actually replayed... ");
    {
        char *err = NULL;
        ldbr_options_t *o = ldbr_options_create();
        if (!o) {
            printf("FAIL (options allocation)\n");
            return 1;
        }
        ldbr_options_set_create_if_missing(o, 0);
        ldbr_t *db = ldbr_open(o, c23, &err);
        ldbr_options_destroy(o);
        if (!db) {
            printf("FAIL (open: %s)\n", err ? err : "null");
            ldbr_free(err);
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

    return failures;
}

static bool lr_empty_point_reads(ldbr_t *db, ldbr_readoptions_t *ro)
{
    char key = 0;
    char *err = NULL;
    size_t value_len = SIZE_MAX;
    char *value = ldbr_get(db, ro, &key, 1, &value_len, &err);
    bool absent = !value && value_len == 0 && !err;
    ldbr_free(value);
    ldbr_free(err);
    bool first = lr_point_key_refused(db, ro, SIZE_MAX - 7);
    bool last = lr_point_key_refused(db, ro, SIZE_MAX);
    printf("ldb_reader: empty point reads reject overflowing key lengths... ");
    bool ok = absent && first && last;
    printf(ok ? "OK\n" : "FAIL\n");
    return ok;
}

static int lr_test_empty_database(void)
{
    int failures = 0;
    printf("ldb_reader: missing CURRENT is an empty database, not a crash... ");
    {
        char empty[600];
        test_make_tmpdir(empty, sizeof(empty), "ldb_reader", "empty");
        char *err = NULL;
        ldbr_options_t *o = ldbr_options_create();
        if (!o) {
            printf("FAIL (options allocation)\n");
            test_rm_rf(empty);
            return 1;
        }
        ldbr_options_set_create_if_missing(o, 1);
        ldbr_t *db = ldbr_open(o, empty, &err);
        ldbr_options_destroy(o);
        if (!db) {
            printf("FAIL (%s)\n", err ? err : "null");
            ldbr_free(err);
            failures++;
        } else {
            ldbr_readoptions_t *ro = ldbr_readoptions_create();
            if (!ro) {
                printf("FAIL (read options allocation)\n");
                ldbr_close(db);
                test_rm_rf(empty);
                return 1;
            }
            ldbr_iterator_t *it = ldbr_create_iterator(db, ro);
            if (!it) {
                printf("FAIL (iterator allocation)\n");
                ldbr_readoptions_destroy(ro);
                ldbr_close(db);
                test_rm_rf(empty);
                return 1;
            }
            ldbr_iter_seek_to_first(it);
            bool any = ldbr_iter_valid(it) != 0;
            ldbr_iter_destroy(it);
            bool point_reads = lr_empty_point_reads(db, ro);
            ldbr_readoptions_destroy(ro);
            ldbr_close(db);
            if (any || !point_reads) {
                printf("FAIL (empty iteration or point-read contract)\n");
                failures++;
            } else {
                printf("OK\n");
            }
        }
        test_rm_rf(empty);
    }

    return failures;
}

static bool lr_stage_damage(const char *dmg, int kind)
{
    char path[600];
    bool prepared = false;
    struct stat st;
    switch (kind) {
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
    return prepared;
}

static int lr_test_damaged_input(const char *src, const char *dmg)
{
    int failures = 0;
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
            bool prepared = lr_stage_damage(dmg, cases[c].kind);
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

    return failures;
}

int test_ldb_reader(void)
{
    int failures = lr_test_internal_key_size_bounds();
    failures += lr_test_log_arithmetic_bounds();
    char src[512], cxx[512], c23[512], dmg[512];

    if (!test_ensure_tmproot()) {
        printf("ldb_reader: FAIL (temporary root)\n");
        return failures + 1;
    }
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

    failures += lr_test_extreme_key_length_refusals(c23);

    failures += lr_test_wal_replayed(c23);

    failures += lr_test_empty_database();

    failures += lr_current_extent(src, dmg);
    failures += lr_test_damaged_input(src, dmg);

    test_rm_rf(src);
    test_rm_rf(cxx);
    test_rm_rf(c23);
    test_rm_rf(dmg);
    return failures;
}
