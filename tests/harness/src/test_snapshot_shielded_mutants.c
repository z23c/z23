/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_shielded mutation-gap cases: exact record layout, exact section
 * bytes and hash, refusals that must not write, collect failure paths that
 * must not hand back a half-built shielded section, and a nullifier scan that
 * dies mid-way must fail the whole collect. Called from test_snapshot_shielded
 * through snapshot_shielded_gap_tests. */

#include "test/test_core.h"
#include "test/seed_gap_tests.h"

#include "core/uint256.h"
#include "crypto/sha3.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/snapshot_shielded.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SG_CHECK(name, expr) do {                                   \
    printf("snapshot_shielded_gap: %s... ", (name));                \
    if ((expr)) printf("OK\n");                                     \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

enum { SG_H = 100, SG_NF = SNAPSHOT_NF_RECORD_BYTES };

static int sg_record_layout(void)
{
    int failures = 0;
    uint8_t nf[32], rec[SG_NF], want[SG_NF];
    for (int i = 0; i < 32; i++)
        nf[i] = (uint8_t)(0x10 + i);
    memset(rec, 0xaa, sizeof(rec));
    snapshot_shielded_pack_nf(rec, 7, nf, 0x0102030405060708LL);
    want[0] = 7;
    memcpy(want + 1, nf, 32);
    for (int i = 0; i < 8; i++)
        want[33 + i] = (uint8_t)(8 - i);
    SG_CHECK("pack_nf writes pool, nf, then little-endian height",
             memcmp(rec, want, sizeof(rec)) == 0);

    uint8_t pool = 0, out[33], in[SG_NF];
    int64_t height = 0;
    memset(out, 0xaa, sizeof(out));
    snapshot_shielded_pack_nf(in, 3, nf, -2);
    snapshot_shielded_unpack_nf(in, &pool, out, &height);
    SG_CHECK("unpack_nf returns pool and a negative height exactly",
             pool == 3 && height == -2);
    SG_CHECK("unpack_nf copies all 32 nf bytes and no more",
             memcmp(out, nf, 32) == 0 && out[32] == 0xaa);
    snapshot_shielded_unpack_nf(in, NULL, NULL, NULL);
    SG_CHECK("unpack_nf accepts NULL outputs", true);
    return failures;
}

static bool sg_stream_is(FILE *f, const uint8_t *want, size_t n)
{
    uint8_t got[128];
    if (n > sizeof(got) || fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0)
        return false;
    return fread(got, 1, sizeof(got), f) == n && memcmp(got, want, n) == 0;
}

static bool sg_hash_is(struct sha3_256_ctx *ctx, const uint8_t *want, size_t n)
{
    uint8_t a[32], b[32];
    struct sha3_256_ctx ref;
    sha3_256_init(&ref);
    sha3_256_write(&ref, want, n);
    sha3_256_finalize(&ref, b);
    sha3_256_finalize(ctx, a);
    return memcmp(a, b, 32) == 0;
}

static int sg_write_exact(void)
{
    int failures = 0;
    uint8_t want[128] = {0};
    struct sha3_256_ctx ctx;
    struct snapshot_shielded s = {0};
    FILE *f = tmpfile();
    sha3_256_init(&ctx);
    SG_CHECK("write: zero-length sections write 16 bytes",
             f && snapshot_shielded_write(f, &ctx, &s) &&
             sg_stream_is(f, want, 16) && sg_hash_is(&ctx, want, 16));
    if (f) fclose(f);

    /* One-byte sections and one nullifier record, byte for byte. */
    static const uint8_t sap[1] = {0xab}, spr[1] = {0xcd};
    uint8_t rec[SG_NF], nf[32];
    memset(nf, 0x66, sizeof(nf));
    snapshot_shielded_pack_nf(rec, 1, nf, 9);
    s = (struct snapshot_shielded){sap, 1, spr, 1, rec, 1};
    size_t at = 0;
    want[at++] = 1; at += 3;
    want[at++] = 0xab;
    want[at++] = 1; at += 3;
    want[at++] = 0xcd;
    want[at++] = 1; at += 7;
    memcpy(want + at, rec, SG_NF);
    at += SG_NF;
    f = tmpfile();
    sha3_256_init(&ctx);
    SG_CHECK("write: one-byte sections and one record, bytes and hash exact",
             f && snapshot_shielded_write(f, &ctx, &s) && at == 59 &&
             sg_stream_is(f, want, at) && sg_hash_is(&ctx, want, at));
    if (f) fclose(f);
    return failures;
}

static int sg_write_refusals(void)
{
    int failures = 0;
    static const uint8_t blob[1] = {1};
    uint8_t rec[SG_NF] = {0};
    struct snapshot_shielded cases[3] = {
        {NULL, 1, blob, 1, rec, 1},
        {blob, 1, NULL, 1, rec, 1},
        {blob, 1, blob, 1, NULL, 1},
    };
    static const char *const names[3] = {
        "write refuses a sapling length with no blob",
        "write refuses a sprout length with no blob",
        "write refuses a nullifier count with no records",
    };
    for (int i = 0; i < 3; i++) {
        struct sha3_256_ctx ctx;
        FILE *f = tmpfile();
        sha3_256_init(&ctx);
        SG_CHECK(names[i], f && !snapshot_shielded_write(f, &ctx, &cases[i]) &&
                 ftell(f) == 0);
        if (f) fclose(f);
    }
    struct sha3_256_ctx ctx;
    struct snapshot_shielded none = {0};
    FILE *ro = fopen("/dev/null", "r");
    sha3_256_init(&ctx);
    SG_CHECK("write reports a short write", ro &&
             !snapshot_shielded_write(ro, &ctx, &none));
    if (ro) fclose(ro);
    return failures;
}

static int sg_free_collected_zeroes(void)
{
    int failures = 0;
    struct snapshot_shielded s;
    memset(&s, 0, sizeof(s));
    s.sapling = (uint8_t *)malloc(4);
    s.sapling_len = 4;
    s.sprout = (uint8_t *)malloc(4);
    s.sprout_len = 4;
    s.nf_records = (uint8_t *)malloc(SG_NF);
    s.nf_count = 1;
    snapshot_shielded_free_collected(&s);
    static const struct snapshot_shielded zero = {0};
    SG_CHECK("free_collected leaves an all-zero struct",
             memcmp(&s, &zero, sizeof(s)) == 0);
    snapshot_shielded_free_collected(NULL);
    return failures;
}

/* A db carrying the frontier rows of `pools` (bit 0 sprout, bit 1 sapling) and,
 * when with_nf, a nullifier table holding n_nf rows at height <= SG_H. */
static bool sg_make_db(sqlite3 **db, unsigned pools, bool with_nf, int n_nf)
{
    struct incremental_merkle_tree sap, spr;
    struct uint256 leaf = {{0}}, root;
    sapling_tree_init(&sap);
    sprout_tree_init(&spr);
    leaf.data[0] = 0x41;
    incremental_tree_append(&sap, &leaf);
    incremental_tree_append(&spr, &leaf);
    incremental_tree_root(&sap, &root);
    bool ok = sqlite3_open(":memory:", db) == SQLITE_OK;
    /* A complete history folds an absent frontier forward as FOUND, so only a
     * both-pools db gets that mark; the others must really lack a frontier. */
    if (ok)
        ok = pools == 3 ? anchor_kv_reset_mark_complete_in_tx(*db)
                        : anchor_kv_reset_mark_empty_below_in_tx(*db, SG_H);
    if (ok && (pools & 2))
        ok = anchor_kv_seed_frontier_row(*db, ANCHOR_POOL_SAPLING, &sap, SG_H,
                                         &root);
    if (ok && (pools & 1))
        ok = anchor_kv_add_tree(*db, ANCHOR_POOL_SPROUT, &spr, SG_H);
    if (ok && with_nf)
        ok = nullifier_kv_ensure_schema(*db);
    for (int i = 0; ok && i < n_nf; i++) {
        uint8_t nf[32] = {0};
        nf[0] = (uint8_t)(i & 0xff);
        nf[1] = (uint8_t)(i >> 8);
        ok = nullifier_kv_add(*db, nf,
                              (i & 1) ? NULLIFIER_POOL_SAPLING
                                      : NULLIFIER_POOL_SPROUT,
                              (i % SG_H) + 1);
    }
    return ok;
}

static bool sg_collect_fails_zeroed(sqlite3 *db)
{
    struct snapshot_shielded out;
    static const struct snapshot_shielded zero = {0};
    memset(&out, 0xaa, sizeof(out));
    bool rejected = !snapshot_shielded_collect_from_db(db, SG_H, &out);
    return rejected && memcmp(&out, &zero, sizeof(out)) == 0;
}

static int sg_collect_failures(void)
{
    int failures = 0;
    struct snapshot_shielded out;
    memset(&out, 0xaa, sizeof(out));
    SG_CHECK("collect rejects a NULL db",
             !snapshot_shielded_collect_from_db(NULL, SG_H, &out));
    sqlite3 *db = NULL;
    SG_CHECK("collect rejects a NULL out",
             sg_make_db(&db, 3, true, 0) &&
             !snapshot_shielded_collect_from_db(db, SG_H, NULL));
    sqlite3_close(db);
    db = NULL;
    SG_CHECK("collect with no frontier fails and clears out",
             sg_make_db(&db, 0, true, 0) && sg_collect_fails_zeroed(db));
    sqlite3_close(db);
    db = NULL;
    SG_CHECK("collect with only a sprout frontier fails (no sapling)",
             sg_make_db(&db, 1, true, 0) && sg_collect_fails_zeroed(db));
    sqlite3_close(db);
    db = NULL;
    SG_CHECK("collect with only a sapling frontier fails (no sprout)",
             sg_make_db(&db, 2, true, 0) && sg_collect_fails_zeroed(db));
    sqlite3_close(db);
    return failures;
}

static bool sg_records_sorted(const struct snapshot_shielded *c, int n)
{
    if (c->nf_count != (uint64_t)n)
        return false;
    for (int i = 0; i < n; i++) {
        uint8_t pool, nf[32];
        int64_t h;
        snapshot_shielded_unpack_nf(c->nf_records + (size_t)i * SG_NF, &pool,
                                    nf, &h);
        /* Sprout (pool 0) rows are the even ids, sapling the odd ones. */
        int odd = pool == NULLIFIER_POOL_SAPLING;
        int id = nf[0] | (nf[1] << 8);
        if ((id & 1) != odd || h != (id % SG_H) + 1)
            return false;
        if (i > 0 && c->nf_records[(size_t)(i - 1) * SG_NF] > pool)
            return false;
    }
    return true;
}

static int sg_collect_many(void)
{
    int failures = 0;
    enum { N = 600 };   /* crosses the 256 and 512 record growth steps */
    sqlite3 *db = NULL;
    struct snapshot_shielded c = {0};
    bool built = sg_make_db(&db, 3, true, N);
    SG_CHECK("collect fixture with 600 nullifiers", built);
    if (!built) { sqlite3_close(db); return failures; }
    SG_CHECK("collect returns all 600 records, ordered, intact",
             snapshot_shielded_collect_from_db(db, SG_H, &c) &&
             c.sapling_len > 0 && c.sprout_len > 0 &&
             sg_records_sorted(&c, N));
    snapshot_shielded_free_collected(&c);
    SG_CHECK("collect leaves no statement open",
             sqlite3_close(db) == SQLITE_OK);

    SG_CHECK("collect without a nullifier table succeeds with none",
             sg_make_db(&db, 3, false, 0) &&
             snapshot_shielded_collect_from_db(db, SG_H, &c) &&
             c.nf_count == 0 && c.nf_records == NULL && c.sapling_len > 0 &&
             c.sprout_len > 0);
    snapshot_shielded_free_collected(&c);
    sqlite3_close(db);
    return failures;
}

static int g_sg_armed;

static int sg_authorizer(void *u, int action, const char *a, const char *b,
                         const char *c, const char *d)
{
    (void)u; (void)b; (void)c; (void)d;
    if (action == SQLITE_READ && a && strcmp(a, "nullifiers") == 0)
        g_sg_armed = 1;
    return SQLITE_OK;
}

static int sg_progress(void *u)
{
    (void)u;
    return g_sg_armed;
}

/* The nullifier scan is interrupted after its statement is prepared: a scan
 * that did not finish must fail the collect, never ship a partial set. */
static int sg_scan_error(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    bool built = sg_make_db(&db, 3, true, 8);
    SG_CHECK("scan-error fixture", built);
    if (!built) { sqlite3_close(db); return failures; }
    g_sg_armed = 0;
    sqlite3_set_authorizer(db, sg_authorizer, NULL);
    sqlite3_progress_handler(db, 1, sg_progress, NULL);
    bool failed_zeroed = sg_collect_fails_zeroed(db);
    sqlite3_progress_handler(db, 0, NULL, NULL);
    sqlite3_set_authorizer(db, NULL, NULL);
    SG_CHECK("collect fails when the nullifier scan is interrupted",
             g_sg_armed == 1 && failed_zeroed);
    sqlite3_close(db);
    return failures;
}

int snapshot_shielded_gap_tests(void)
{
    return sg_record_layout() + sg_write_exact() + sg_write_refusals() +
           sg_free_collected_zeroes() + sg_collect_failures() +
           sg_collect_many() + sg_scan_error();
}
