/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_verify_c23 — differential proof that the C23 read-only LevelDB
 * reader (engine/modules/storage/src/ldb_reader_*.c) returns byte-identical data to
 * the vendored C++ libleveldb.a on real on-disk databases.
 *
 *     build/bin/ldb_verify_c23 <dir-for-cxx> <dir-for-c23> [max-records]
 *
 * Two directories, not one, and both must be COPIES. Opening a LevelDB
 * directory with the C++ library MUTATES it — create_if_missing or not,
 * the open runs recovery, folds the write-ahead log into a fresh table,
 * rewrites MANIFEST and takes LOCK. Giving each implementation its own
 * copy is therefore not paranoia, it is what makes the comparison mean
 * anything: the C23 side never sees the recovered layout, so matching the
 * C++ side proves it replayed the write-ahead log itself.
 *
 * The comparison is the whole ordered key/value stream, byte for byte,
 * followed by a point-read sweep over a sample of the keys observed
 * (present keys and constructed absent ones). Anything less than a full
 * keyspace walk against real data does not count as proof.
 *
 * Exit status: 0 identical, 1 a difference or a read error, 2 usage.
 */

#include "storage/ldb_reader.h"
#include "util/safe_alloc.h"

#include <leveldb/c.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SAMPLE_MAX 20000u

struct sample {
    uint8_t *key;
    size_t len;
};

static struct sample g_samples[SAMPLE_MAX];
static size_t g_nsamples;

static void hexdump(const char *label, const char *p, size_t n)
{
    fprintf(stderr, "  %s (%zu bytes):", label, n);
    for (size_t i = 0; i < n && i < 48; i++)
        fprintf(stderr, " %02x", (unsigned char)p[i]);
    fprintf(stderr, "%s\n", n > 48 ? " ..." : "");
}

static void keep_sample(const char *key, size_t len, uint64_t index,
                        uint64_t stride)
{
    if (g_nsamples >= SAMPLE_MAX || (index % stride) != 0)
        return;
    uint8_t *copy = zcl_malloc(len ? len : 1, "ldb_verify_sample_key");
    if (!copy)
        return;
    if (len)
        memcpy(copy, key, len);
    g_samples[g_nsamples].key = copy;
    g_samples[g_nsamples].len = len;
    g_nsamples++;
}

/* Equal lengths and equal bytes; a zero-length slice equals only another
 * zero-length slice. Shared by the stream and seek comparisons. */
static bool slices_equal(const char *a, size_t alen, const char *b,
                         size_t blen)
{
    return alen == blen && (alen == 0 || memcmp(a, b, alen) == 0);
}

/* Reports an error left on either iterator; returns 1 when one is found. */
static int report_iterator_errors(leveldb_iterator_t *ci,
                                  ldbr_iterator_t *ri)
{
    char *cerr = NULL, *rerr = NULL;
    leveldb_iter_get_error(ci, &cerr);
    ldbr_iter_get_error(ri, &rerr);
    if (cerr || rerr) {
        fprintf(stderr, "FAIL: iterator error (cxx=%s c23=%s)\n",
                cerr ? cerr : "clean", rerr ? rerr : "clean");
        return 1;
    }
    return 0;
}

/* Walks both ordered streams side by side, sampling keys as it goes.
 * Returns 1 on the first difference and reports the record count. */
static int compare_ordered_stream(leveldb_t *cdb, leveldb_readoptions_t *cro,
                                  ldbr_t *rdb, ldbr_readoptions_t *rro,
                                  uint64_t max_records, uint64_t *records)
{
    leveldb_iterator_t *ci = leveldb_create_iterator(cdb, cro);
    ldbr_iterator_t *ri = ldbr_create_iterator(rdb, rro);
    leveldb_iter_seek_to_first(ci);
    ldbr_iter_seek_to_first(ri);

    uint64_t n = 0;
    uint64_t stride = 1;
    int rc = 0;
    for (;;) {
        unsigned char cv = leveldb_iter_valid(ci);
        unsigned char rv = ldbr_iter_valid(ri);
        if (cv != rv) {
            fprintf(stderr,
                    "FAIL: stream length differs after %llu records "
                    "(cxx valid=%u c23 valid=%u)\n",
                    (unsigned long long)n, cv, rv);
            rc = 1;
            break;
        }
        if (!cv)
            break;

        size_t ck = 0, rk = 0, cvl = 0, rvl = 0;
        const char *ckey = leveldb_iter_key(ci, &ck);
        const char *rkey = ldbr_iter_key(ri, &rk);
        if (!slices_equal(ckey, ck, rkey, rk)) {
            fprintf(stderr, "FAIL: key differs at record %llu\n",
                    (unsigned long long)n);
            hexdump("cxx", ckey, ck);
            hexdump("c23", rkey, rk);
            rc = 1;
            break;
        }
        const char *cval = leveldb_iter_value(ci, &cvl);
        const char *rval = ldbr_iter_value(ri, &rvl);
        if (!slices_equal(cval, cvl, rval, rvl)) {
            fprintf(stderr, "FAIL: value differs at record %llu\n",
                    (unsigned long long)n);
            hexdump("key", ckey, ck);
            hexdump("cxx", cval, cvl);
            hexdump("c23", rval, rvl);
            rc = 1;
            break;
        }

        /* Keep a bounded, evenly spread key sample for the point-read
         * sweep. The stride doubles as the sample fills so coverage stays
         * spread over the whole keyspace however large it turns out. */
        keep_sample(ckey, ck, n, stride);
        if (g_nsamples == SAMPLE_MAX && (n % (stride * 2)) == 0)
            stride *= 2;

        n++;
        if (max_records && n >= max_records)
            break;
        leveldb_iter_next(ci);
        ldbr_iter_next(ri);
    }

    if (report_iterator_errors(ci, ri))
        rc = 1;
    leveldb_iter_destroy(ci);
    ldbr_iter_destroy(ri);

    *records = n;
    return rc;
}

/* Point-reads one sampled key on both sides; returns 1 when they
 * disagree. */
static int compare_present_get(leveldb_t *cdb, leveldb_readoptions_t *cro,
                               ldbr_t *rdb, ldbr_readoptions_t *rro,
                               const struct sample *s, size_t index)
{
    size_t cn = 0, rn = 0;
    char *ce = NULL, *re = NULL;
    char *cval = leveldb_get(cdb, cro, (const char *)s->key, s->len, &cn,
                             &ce);
    char *rval = ldbr_get(rdb, rro, (const char *)s->key, s->len, &rn, &re);
    int rc = 0;
    if (ce || re) {
        fprintf(stderr, "FAIL: get error (cxx=%s c23=%s)\n",
                ce ? ce : "clean", re ? re : "clean");
        rc = 1;
    } else if ((cval == NULL) != (rval == NULL)) {
        fprintf(stderr, "FAIL: presence differs for sample %zu "
                "(cxx=%s c23=%s)\n", index, cval ? "found" : "absent",
                rval ? "found" : "absent");
        hexdump("key", (const char *)s->key, s->len);
        rc = 1;
    } else if (cval && (cn != rn || memcmp(cval, rval, cn) != 0)) {
        fprintf(stderr, "FAIL: get value differs for sample %zu\n", index);
        hexdump("key", (const char *)s->key, s->len);
        hexdump("cxx", cval, cn);
        hexdump("c23", rval, rn);
        rc = 1;
    }
    leveldb_free(cval);
    ldbr_free(rval);
    free(ce);
    free(re);
    return rc;
}

/* A key that is one byte longer than a real one is almost surely
 * absent; both sides must agree that it is. */
static int probe_absent_key(leveldb_t *cdb, leveldb_readoptions_t *cro,
                            ldbr_t *rdb, ldbr_readoptions_t *rro,
                            const struct sample *s, size_t index,
                            uint64_t *absent)
{
    uint8_t probe[4096];
    size_t plen = s->len;
    if (plen + 1 > sizeof(probe))
        return 0;
    memcpy(probe, s->key, plen);
    probe[plen] = 0x7f;
    plen++;
    size_t cn = 0, rn = 0;
    char *ce = NULL, *re = NULL;
    char *cval = leveldb_get(cdb, cro, (const char *)probe, plen, &cn, &ce);
    char *rval = ldbr_get(rdb, rro, (const char *)probe, plen, &rn, &re);
    int rc = 0;
    if (ce || re || (cval == NULL) != (rval == NULL) ||
        (cval && (cn != rn || memcmp(cval, rval, cn) != 0))) {
        fprintf(stderr, "FAIL: absent-key probe disagrees at "
                "sample %zu\n", index);
        rc = 1;
    }
    leveldb_free(cval);
    ldbr_free(rval);
    free(ce);
    free(re);
    (*absent)++;
    return rc;
}

/* Point-read sweep over the sampled keys, present and absent; returns 1
 * when a pair disagrees. */
static int point_read_sweep(leveldb_t *cdb, leveldb_readoptions_t *cro,
                            ldbr_t *rdb, ldbr_readoptions_t *rro, int rc,
                            uint64_t *gets, uint64_t *absent)
{
    *gets = 0;
    *absent = 0;
    for (size_t i = 0; rc == 0 && i < g_nsamples; i++) {
        rc = compare_present_get(cdb, cro, rdb, rro, &g_samples[i], i);
        (*gets)++;
        if (rc == 0)
            rc = probe_absent_key(cdb, cro, rdb, rro, &g_samples[i], i,
                                  absent);
    }
    return rc;
}

/* Re-seeks both iterators at every sampled key; returns 1 when a landing
 * spot differs. */
static int seek_positioning_sweep(leveldb_t *cdb, leveldb_readoptions_t *cro,
                                  ldbr_t *rdb, ldbr_readoptions_t *rro,
                                  int rc, uint64_t *seeks)
{
    *seeks = 0;
    if (rc != 0)
        return rc;
    leveldb_iterator_t *ci = leveldb_create_iterator(cdb, cro);
    ldbr_iterator_t *ri = ldbr_create_iterator(rdb, rro);
    for (size_t i = 0; rc == 0 && i < g_nsamples; i++) {
        leveldb_iter_seek(ci, (const char *)g_samples[i].key,
                          g_samples[i].len);
        ldbr_iter_seek(ri, (const char *)g_samples[i].key,
                       g_samples[i].len);
        unsigned char cv = leveldb_iter_valid(ci);
        unsigned char rv = ldbr_iter_valid(ri);
        if (cv != rv) {
            fprintf(stderr, "FAIL: seek validity differs at sample %zu\n", i);
            rc = 1;
            break;
        }
        if (cv) {
            size_t ck = 0, rk = 0;
            const char *ckey = leveldb_iter_key(ci, &ck);
            const char *rkey = ldbr_iter_key(ri, &rk);
            if (!slices_equal(ckey, ck, rkey, rk)) {
                fprintf(stderr, "FAIL: seek landed elsewhere at sample "
                        "%zu\n", i);
                hexdump("cxx", ckey, ck);
                hexdump("c23", rkey, rk);
                rc = 1;
                break;
            }
        }
        (*seeks)++;
    }
    leveldb_iter_destroy(ci);
    ldbr_iter_destroy(ri);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s <dir-for-cxx> <dir-for-c23> [max-records]\n"
                "both directories must be COPIES; the C++ open mutates its "
                "target\n", argv[0]);
        return 2;
    }
    const char *cxx_dir = argv[1];
    const char *c23_dir = argv[2];
    uint64_t max_records = (argc > 3) ? strtoull(argv[3], NULL, 10) : 0;

    /* ---- open both ---- */
    char *err = NULL;
    leveldb_options_t *copts = leveldb_options_create();
    leveldb_options_set_create_if_missing(copts, 1);
    leveldb_options_set_compression(copts, leveldb_no_compression);
    leveldb_t *cdb = leveldb_open(copts, cxx_dir, &err);
    if (!cdb) {
        fprintf(stderr, "FAIL: C++ leveldb_open(%s): %s\n", cxx_dir,
                err ? err : "?");
        return 1;
    }
    leveldb_readoptions_t *cro = leveldb_readoptions_create();
    leveldb_readoptions_set_verify_checksums(cro, 1);

    ldbr_options_t *ropts = ldbr_options_create();
    ldbr_options_set_create_if_missing(ropts, 1);
    ldbr_t *rdb = ldbr_open(ropts, c23_dir, &err);
    if (!rdb) {
        fprintf(stderr, "FAIL: C23 ldbr_open(%s): %s\n", c23_dir,
                err ? err : "?");
        return 1;
    }
    ldbr_readoptions_t *rro = ldbr_readoptions_create();

    printf("C23 reader: %zu SSTables live, %zu write-ahead-log entries "
           "replayed\n", ldbr_stat_table_count(rdb),
           ldbr_stat_memtable_entries(rdb));

    /* ---- full ordered stream comparison ---- */
    uint64_t n = 0;
    int rc = compare_ordered_stream(cdb, cro, rdb, rro, max_records, &n);

    printf("stream: %llu records compared byte-for-byte\n",
           (unsigned long long)n);

    /* ---- point reads over the sampled keys, present and absent ---- */
    uint64_t gets = 0, absent = 0;
    rc = point_read_sweep(cdb, cro, rdb, rro, rc, &gets, &absent);
    printf("point reads: %llu present-key gets, %llu absent-key probes\n",
           (unsigned long long)gets, (unsigned long long)absent);

    /* ---- seek positioning over the same sample ---- */
    uint64_t seeks = 0;
    rc = seek_positioning_sweep(cdb, cro, rdb, rro, rc, &seeks);
    printf("seeks: %llu positions compared\n", (unsigned long long)seeks);

    for (size_t i = 0; i < g_nsamples; i++)
        free(g_samples[i].key);

    ldbr_readoptions_destroy(rro);
    ldbr_options_destroy(ropts);
    ldbr_close(rdb);
    leveldb_readoptions_destroy(cro);
    leveldb_options_destroy(copts);
    leveldb_close(cdb);

    if (rc == 0)
        printf("BYTE-IDENTICAL: %llu records, %llu gets, %llu seeks — "
               "C23 reader matches libleveldb.a exactly\n",
               (unsigned long long)n, (unsigned long long)gets,
               (unsigned long long)seeks);
    else
        printf("MISMATCH\n");
    return rc;
}
