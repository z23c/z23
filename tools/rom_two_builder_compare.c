/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_two_builder_compare — the ROM two-builder gate. Independently
 * RE-DERIVES the three consensus-state section digests from the raw rows of
 * two `zcl.consensus_state_bundle.v1` files and asserts:
 *
 *   (a) each bundle's recomputed digests equal its own bundle_meta manifest
 *       (the bundle is internally consistent), and
 *   (b) the two bundles' chain-content fields are byte-identical (the
 *       two-builder proof: two independent producers folded the same
 *       immutable history to the same complete state).
 *
 * The byte preimages mirror engine/modules/storage/src/consensus_state_bundle_codec.c
 * and core/modules/coins/src/utxo_commitment.c EXACTLY:
 *
 *   coins      — bare SHA3-256 (NO domain separator), rows ORDER BY txid,vout;
 *                record = txid(32) | vout LE4 | value LE8 | script_len LE4 |
 *                script | height LE4 | is_coinbase(1).  Also accumulates
 *                count and total_supply.
 *   anchors    — domain "zcl.consensus_state_bundle.v1/anchors" (NUL included),
 *                rows ORDER BY pool,anchor;
 *                row = pool(1) | root(32) | height LE8 | tree_len LE4 | tree.
 *                Frontier per pool = the root at the max height.
 *   nullifiers — domain "zcl.consensus_state_bundle.v1/nullifiers" (NUL
 *                included), rows ORDER BY pool,nf;
 *                row = pool(1) | nf(32) | height LE8.
 *
 * Provenance fields (source receipt, proof manifest, artifact digest) are
 * REPORTED-ONLY: they legitimately differ across builders (different
 * binaries/source epochs) and are not chain content.
 *
 * Usage: rom_two_builder_compare BUNDLE_A.sqlite BUNDLE_B.sqlite
 *        rom_two_builder_compare --rom-root BUNDLE.sqlite
 * Exit: 0 = two-builder proof PASSES (bake sheet printed on stdout);
 *       1 = mismatch (details on stderr); 2 = usage/IO error.
 *
 * --rom-root prints the folded rom_state_root for ONE bundle: SHA3-256 over
 * the domain "zcl.rom_state_checkpoint.v1/root" (NUL included) followed by
 * the chain-content fields in pinned order (height LE8 | block_hash |
 * utxo_root | utxo_count LE8 | total_supply LE8 | anchor_digest |
 * anchor_count LE8 | sprout_frontier_root | sprout_frontier_height LE8 |
 * sapling_frontier_root | sapling_frontier_height LE8 | nullifier_digest |
 * nullifier_count LE8). This is the constant baked into
 * core/chainparams/src/checkpoints.c; the parity test re-derives it
 * independently as the bake's cross-check.
 *
 * Standalone build (see the Makefile target): vendored sqlite + core/modules/crypto
 * sha3 only. Reads both bundles read-only; never opens a datadir. */

#include "crypto/sha3.h"

#include <sqlite3.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RTB_ANCHOR_DOMAIN "zcl.consensus_state_bundle.v1/anchors"
#define RTB_NULLIFIER_DOMAIN "zcl.consensus_state_bundle.v1/nullifiers"
#define RTB_ROM_ROOT_DOMAIN "zcl.rom_state_checkpoint.v1/root"

struct rtb_manifest {
    int64_t height;
    uint8_t block_hash[32];
    int64_t history_complete;
    int64_t validation_profile;
    int64_t activation_boundary;
    uint8_t utxo_root[32];
    int64_t utxo_count;
    int64_t total_supply;
    uint8_t anchor_digest[32];
    int64_t anchor_count;
    uint8_t sprout_frontier_root[32];
    int64_t sprout_frontier_height;
    uint8_t sapling_frontier_root[32];
    int64_t sapling_frontier_height;
    uint8_t nullifier_digest[32];
    int64_t nullifier_count;
    int64_t source_fold_cursor;
};

struct rtb_derived {
    uint8_t utxo_root[32];
    int64_t utxo_count;
    int64_t total_supply;
    uint8_t anchor_digest[32];
    int64_t anchor_count;
    uint8_t sprout_frontier_root[32];
    int64_t sprout_frontier_height;
    uint8_t sapling_frontier_root[32];
    int64_t sapling_frontier_height;
    uint8_t nullifier_digest[32];
    int64_t nullifier_count;
};

static void rtb_u32le(struct sha3_256_ctx *c, uint32_t v)
{
    unsigned char b[4];
    b[0] = (unsigned char)(v & 0xff);
    b[1] = (unsigned char)((v >> 8) & 0xff);
    b[2] = (unsigned char)((v >> 16) & 0xff);
    b[3] = (unsigned char)((v >> 24) & 0xff);
    sha3_256_write(c, b, sizeof(b));
}

static void rtb_u64le(struct sha3_256_ctx *c, uint64_t v)
{
    unsigned char b[8];
    for (int i = 0; i < 8; i++)
        b[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    sha3_256_write(c, b, sizeof(b));
}

static void rtb_hex(const uint8_t *b, char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", b[i]);
}

/* Fold the complete chain-content commitment into one root. The preimage
 * order is pinned — the baked constant in core/chainparams/src/checkpoints.c
 * and the parity test's independent re-derivation must reproduce this exact
 * value for the bake to be admissible. */
static void rtb_rom_state_root(const struct rtb_derived *d, int64_t height,
                               const uint8_t block_hash[32], uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)RTB_ROM_ROOT_DOMAIN,
                   sizeof(RTB_ROM_ROOT_DOMAIN)); /* trailing NUL included */
    rtb_u64le(&c, (uint64_t)height);
    sha3_256_write(&c, block_hash, 32);
    sha3_256_write(&c, d->utxo_root, 32);
    rtb_u64le(&c, (uint64_t)d->utxo_count);
    rtb_u64le(&c, (uint64_t)d->total_supply);
    sha3_256_write(&c, d->anchor_digest, 32);
    rtb_u64le(&c, (uint64_t)d->anchor_count);
    sha3_256_write(&c, d->sprout_frontier_root, 32);
    rtb_u64le(&c, (uint64_t)d->sprout_frontier_height);
    sha3_256_write(&c, d->sapling_frontier_root, 32);
    rtb_u64le(&c, (uint64_t)d->sapling_frontier_height);
    sha3_256_write(&c, d->nullifier_digest, 32);
    rtb_u64le(&c, (uint64_t)d->nullifier_count);
    sha3_256_finalize(&c, out);
}

/* coins: strict (txid,vout) order is itself part of the canonical fold — a
 * bundle whose rows are not strictly increasing is rejected, mirroring the
 * production validator. */
static int rtb_derive_coins(sqlite3 *db, struct rtb_derived *d, char *err,
                            size_t errlen)
{
    static const char sql[] =
        "SELECT txid,vout,value,script,height,is_coinbase FROM coins "
        "ORDER BY txid,vout";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errlen, "coins prepare: %s", sqlite3_errmsg(db));
        return 0;
    }
    struct sha3_256_ctx c;
    sha3_256_init(&c); /* NO domain prefix — matches the codec exactly. */
    int64_t count = 0, supply = 0;
    int have_prev = 0;
    uint8_t prev_txid[32];
    int64_t prev_vout = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:standalone-dev-tool
        const void *txid = sqlite3_column_blob(st, 0);
        int64_t vout = sqlite3_column_int64(st, 1);
        int64_t value = sqlite3_column_int64(st, 2);
        const void *script = sqlite3_column_blob(st, 3);
        int script_len = sqlite3_column_bytes(st, 3);
        int64_t height = sqlite3_column_int64(st, 4);
        int64_t is_cb = sqlite3_column_int64(st, 5);
        if (!txid || sqlite3_column_bytes(st, 0) != 32 ||
            vout < 0 || height < 0 || (is_cb != 0 && is_cb != 1)) {
            snprintf(err, errlen, "coins row %" PRId64 ": malformed", count);
            sqlite3_finalize(st);
            return 0;
        }
        if (have_prev) {
            int cmp = memcmp(prev_txid, txid, 32);
            if (cmp > 0 || (cmp == 0 && prev_vout >= vout)) {
                snprintf(err, errlen,
                         "coins row %" PRId64 ": not strictly increasing",
                         count);
                sqlite3_finalize(st);
                return 0;
            }
        }
        memcpy(prev_txid, txid, 32);
        prev_vout = vout;
        have_prev = 1;

        sha3_256_write(&c, txid, 32);
        rtb_u32le(&c, (uint32_t)vout);
        rtb_u64le(&c, (uint64_t)value);
        rtb_u32le(&c, (uint32_t)(script ? script_len : 0));
        if (script && script_len > 0)
            sha3_256_write(&c, script, (size_t)script_len);
        rtb_u32le(&c, (uint32_t)height);
        sha3_256_write(&c, is_cb ? (const unsigned char *)"\x01"
                                 : (const unsigned char *)"\x00", 1);
        count++;
        supply += value;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        snprintf(err, errlen, "coins step: %s", sqlite3_errmsg(db));
        return 0;
    }
    sha3_256_finalize(&c, d->utxo_root);
    d->utxo_count = count;
    d->total_supply = supply;
    return 1;
}

static int rtb_derive_anchors(sqlite3 *db, struct rtb_derived *d, char *err,
                              size_t errlen)
{
    static const char sql[] =
        "SELECT pool,anchor,height,tree FROM anchors ORDER BY pool,anchor";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errlen, "anchors prepare: %s", sqlite3_errmsg(db));
        return 0;
    }
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)RTB_ANCHOR_DOMAIN,
                   sizeof(RTB_ANCHOR_DOMAIN)); /* trailing NUL included */
    int64_t count = 0;
    int64_t best_h[2] = {-1, -1};
    int have_prev = 0;
    int64_t prev_pool = 0;
    uint8_t prev_anchor[32];
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:standalone-dev-tool
        int64_t pool = sqlite3_column_int64(st, 0);
        const void *anchor = sqlite3_column_blob(st, 1);
        int64_t height = sqlite3_column_int64(st, 2);
        const void *tree = sqlite3_column_blob(st, 3);
        int tree_len = sqlite3_column_bytes(st, 3);
        if ((pool != 0 && pool != 1) || !anchor ||
            sqlite3_column_bytes(st, 1) != 32 || height < 0 || !tree) {
            snprintf(err, errlen, "anchors row %" PRId64 ": malformed", count);
            sqlite3_finalize(st);
            return 0;
        }
        if (have_prev) {
            int cmp = 0;
            if (prev_pool > pool)
                cmp = 1;
            else if (prev_pool < pool)
                cmp = -1;
            else
                cmp = memcmp(prev_anchor, anchor, 32);
            if (cmp >= 0) {
                snprintf(err, errlen,
                         "anchors row %" PRId64 ": not strictly increasing",
                         count);
                sqlite3_finalize(st);
                return 0;
            }
        }
        prev_pool = pool;
        memcpy(prev_anchor, anchor, 32);
        have_prev = 1;

        unsigned char p = (unsigned char)pool;
        sha3_256_write(&c, &p, 1);
        sha3_256_write(&c, anchor, 32);
        rtb_u64le(&c, (uint64_t)height);
        rtb_u32le(&c, (uint32_t)tree_len);
        sha3_256_write(&c, tree, (size_t)tree_len);
        count++;
        if (height > best_h[pool]) {
            best_h[pool] = height;
            if (pool == 0)
                memcpy(d->sprout_frontier_root, anchor, 32);
            else
                memcpy(d->sapling_frontier_root, anchor, 32);
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        snprintf(err, errlen, "anchors step: %s", sqlite3_errmsg(db));
        return 0;
    }
    sha3_256_finalize(&c, d->anchor_digest);
    d->anchor_count = count;
    d->sprout_frontier_height = best_h[0];
    d->sapling_frontier_height = best_h[1];
    return 1;
}

static int rtb_derive_nullifiers(sqlite3 *db, struct rtb_derived *d, char *err,
                                 size_t errlen)
{
    static const char sql[] =
        "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errlen, "nullifiers prepare: %s", sqlite3_errmsg(db));
        return 0;
    }
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)RTB_NULLIFIER_DOMAIN,
                   sizeof(RTB_NULLIFIER_DOMAIN)); /* trailing NUL included */
    int64_t count = 0;
    int have_prev = 0;
    int64_t prev_pool = 0;
    uint8_t prev_nf[32];
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:standalone-dev-tool
        int64_t pool = sqlite3_column_int64(st, 0);
        const void *nf = sqlite3_column_blob(st, 1);
        int64_t height = sqlite3_column_int64(st, 2);
        if ((pool != 0 && pool != 1) || !nf ||
            sqlite3_column_bytes(st, 1) != 32 || height < 0) {
            snprintf(err, errlen, "nullifiers row %" PRId64 ": malformed",
                     count);
            sqlite3_finalize(st);
            return 0;
        }
        if (have_prev) {
            int cmp = 0;
            if (prev_pool > pool)
                cmp = 1;
            else if (prev_pool < pool)
                cmp = -1;
            else
                cmp = memcmp(prev_nf, nf, 32);
            if (cmp >= 0) {
                snprintf(err, errlen,
                         "nullifiers row %" PRId64 ": not strictly increasing",
                         count);
                sqlite3_finalize(st);
                return 0;
            }
        }
        prev_pool = pool;
        memcpy(prev_nf, nf, 32);
        have_prev = 1;

        unsigned char p = (unsigned char)pool;
        sha3_256_write(&c, &p, 1);
        sha3_256_write(&c, nf, 32);
        rtb_u64le(&c, (uint64_t)height);
        count++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        snprintf(err, errlen, "nullifiers step: %s", sqlite3_errmsg(db));
        return 0;
    }
    sha3_256_finalize(&c, d->nullifier_digest);
    d->nullifier_count = count;
    return 1;
}

static int rtb_read_manifest(sqlite3 *db, struct rtb_manifest *m, char *err,
                             size_t errlen)
{
    static const char sql[] =
        "SELECT height,block_hash,history_complete,validation_profile,"
        "activation_boundary,utxo_root,utxo_count,total_supply,anchor_digest,"
        "anchor_count,sprout_frontier_root,sprout_frontier_height,"
        "sapling_frontier_root,sapling_frontier_height,nullifier_digest,"
        "nullifier_count,source_fold_cursor FROM bundle_meta WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        snprintf(err, errlen, "bundle_meta prepare: %s", sqlite3_errmsg(db));
        return 0;
    }
    if (sqlite3_step(st) != SQLITE_ROW) { // raw-sql-ok:standalone-dev-tool
        snprintf(err, errlen, "bundle_meta singleton missing");
        sqlite3_finalize(st);
        return 0;
    }
    m->height = sqlite3_column_int64(st, 0);
    m->history_complete = sqlite3_column_int64(st, 2);
    m->validation_profile = sqlite3_column_int64(st, 3);
    m->activation_boundary = sqlite3_column_int64(st, 4);
    m->utxo_count = sqlite3_column_int64(st, 6);
    m->total_supply = sqlite3_column_int64(st, 7);
    m->anchor_count = sqlite3_column_int64(st, 9);
    m->sprout_frontier_height = sqlite3_column_int64(st, 11);
    m->sapling_frontier_height = sqlite3_column_int64(st, 13);
    m->nullifier_count = sqlite3_column_int64(st, 15);
    m->source_fold_cursor = sqlite3_column_int64(st, 16);
    const struct { int col; uint8_t *dst; } blobs[] = {
        {1, m->block_hash}, {5, m->utxo_root}, {8, m->anchor_digest},
        {10, m->sprout_frontier_root}, {12, m->sapling_frontier_root},
        {14, m->nullifier_digest},
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(blobs) / sizeof(blobs[0]); i++) {
        const void *b = sqlite3_column_blob(st, blobs[i].col);
        if (!b || sqlite3_column_bytes(st, blobs[i].col) != 32) {
            snprintf(err, errlen, "bundle_meta blob col %d malformed",
                     blobs[i].col);
            ok = 0;
            break;
        }
        memcpy(blobs[i].dst, b, 32);
    }
    sqlite3_finalize(st);
    return ok;
}

static int rtb_fail(const char *label, const char *field, const char *got,
                    const char *want)
{
    fprintf(stderr, "  - %s: %s mismatch (%s != %s)\n", label, field, got,
            want);
    return 1;
}

static int rtb_check32(const char *label, const char *field,
                       const uint8_t got[32], const uint8_t want[32])
{
    if (memcmp(got, want, 32) == 0)
        return 0;
    char g[65], w[65];
    rtb_hex(got, g);
    rtb_hex(want, w);
    return rtb_fail(label, field, g, w);
}

static int rtb_checki64(const char *label, const char *field, int64_t got,
                        int64_t want)
{
    if (got == want)
        return 0;
    char g[32], w[32];
    snprintf(g, sizeof(g), "%" PRId64, got);
    snprintf(w, sizeof(w), "%" PRId64, want);
    return rtb_fail(label, field, g, w);
}

static int rtb_self_consistent(const char *label, const struct rtb_manifest *m,
                               const struct rtb_derived *d)
{
    int fails = 0;
    fails += rtb_check32(label, "utxo_root", d->utxo_root, m->utxo_root);
    fails += rtb_checki64(label, "utxo_count", d->utxo_count, m->utxo_count);
    fails += rtb_checki64(label, "total_supply", d->total_supply,
                          m->total_supply);
    fails += rtb_check32(label, "anchor_digest", d->anchor_digest,
                         m->anchor_digest);
    fails += rtb_checki64(label, "anchor_count", d->anchor_count,
                          m->anchor_count);
    fails += rtb_check32(label, "sprout_frontier_root",
                         d->sprout_frontier_root, m->sprout_frontier_root);
    fails += rtb_checki64(label, "sprout_frontier_height",
                          d->sprout_frontier_height, m->sprout_frontier_height);
    fails += rtb_check32(label, "sapling_frontier_root",
                         d->sapling_frontier_root, m->sapling_frontier_root);
    fails += rtb_checki64(label, "sapling_frontier_height",
                          d->sapling_frontier_height,
                          m->sapling_frontier_height);
    fails += rtb_check32(label, "nullifier_digest", d->nullifier_digest,
                         m->nullifier_digest);
    fails += rtb_checki64(label, "nullifier_count", d->nullifier_count,
                          m->nullifier_count);
    return fails;
}

static void rtb_print_field32(const char *name, const uint8_t v[32])
{
    char h[65];
    rtb_hex(v, h);
    printf("  %-26s %s\n", name, h);
}

static void rtb_print_fieldi64(const char *name, int64_t v)
{
    printf("  %-26s %" PRId64 "\n", name, v);
}

static void rtb_print_sheet(const char *label, const struct rtb_manifest *m)
{
    printf("=== %s chain content ===\n", label);
    rtb_print_fieldi64("height", m->height);
    rtb_print_field32("block_hash", m->block_hash);
    rtb_print_fieldi64("history_complete", m->history_complete);
    rtb_print_fieldi64("activation_boundary", m->activation_boundary);
    rtb_print_field32("utxo_root", m->utxo_root);
    rtb_print_fieldi64("utxo_count", m->utxo_count);
    rtb_print_fieldi64("total_supply", m->total_supply);
    rtb_print_field32("anchor_digest", m->anchor_digest);
    rtb_print_fieldi64("anchor_count", m->anchor_count);
    rtb_print_field32("sprout_frontier_root", m->sprout_frontier_root);
    rtb_print_fieldi64("sprout_frontier_height", m->sprout_frontier_height);
    rtb_print_field32("sapling_frontier_root", m->sapling_frontier_root);
    rtb_print_fieldi64("sapling_frontier_height", m->sapling_frontier_height);
    rtb_print_field32("nullifier_digest", m->nullifier_digest);
    rtb_print_fieldi64("nullifier_count", m->nullifier_count);
    rtb_print_fieldi64("source_fold_cursor", m->source_fold_cursor);
    rtb_print_fieldi64("validation_profile", m->validation_profile);
}

static int rtb_open_ro(const char *path, sqlite3 **out, char *err,
                       size_t errlen)
{
    char uri[4096];
    snprintf(uri, sizeof(uri), "file:%s?mode=ro", path);
    if (sqlite3_open_v2(uri, out, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI,
                        NULL) != SQLITE_OK) {
        snprintf(err, errlen, "open %s: %s", path,
                 *out ? sqlite3_errmsg(*out) : "unknown");
        if (*out)
            sqlite3_close(*out);
        *out = NULL;
        return 0;
    }
    return 1;
}

static int rtb_derive_all(const char *label, const char *path,
                          struct rtb_manifest *m, struct rtb_derived *d,
                          int *fails)
{
    char err[256];
    err[0] = '\0';
    sqlite3 *db = NULL;
    if (!rtb_open_ro(path, &db, err, sizeof(err))) {
        fprintf(stderr, "  - %s: %s\n", label, err);
        (*fails)++;
        return 0;
    }
    int ok = rtb_read_manifest(db, m, err, sizeof(err)) &&
             rtb_derive_coins(db, d, err, sizeof(err)) &&
             rtb_derive_anchors(db, d, err, sizeof(err)) &&
             rtb_derive_nullifiers(db, d, err, sizeof(err));
    sqlite3_close(db);
    if (!ok) {
        fprintf(stderr, "  - %s: %s\n", label, err);
        (*fails)++;
        return 0;
    }
    *fails += rtb_self_consistent(label, m, d);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--rom-root") == 0) {
        int fails = 0;
        struct rtb_manifest m;
        struct rtb_derived d;
        memset(&m, 0, sizeof(m));
        memset(&d, 0, sizeof(d));
        if (!rtb_derive_all("bundle", argv[2], &m, &d, &fails) || fails) {
            fprintf(stderr, "rom-root: bundle failed self-consistency\n");
            return 1;
        }
        uint8_t root[32];
        rtb_rom_state_root(&d, m.height, m.block_hash, root);
        char h[65];
        rtb_hex(root, h);
        printf("rom_state_root %s\n", h);
        printf("  (height=%" PRId64 " anchors=%" PRId64
               " nullifiers=%" PRId64 " coins=%" PRId64 ")\n",
               m.height, d.anchor_count, d.nullifier_count, d.utxo_count);
        return 0;
    }
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s BUNDLE_A.sqlite BUNDLE_B.sqlite\n"
                "       %s --rom-root BUNDLE.sqlite\n"
                "  exit 0 = two-builder proof PASSES; 1 = mismatch; "
                "2 = usage/IO error\n",
                argv[0], argv[0]);
        return 2;
    }
    int fails = 0;
    struct rtb_manifest ma, mb;
    struct rtb_derived da, db;
    memset(&ma, 0, sizeof(ma));
    memset(&mb, 0, sizeof(mb));
    memset(&da, 0, sizeof(da));
    memset(&db, 0, sizeof(db));

    int have_a = rtb_derive_all("A", argv[1], &ma, &da, &fails);
    int have_b = rtb_derive_all("B", argv[2], &mb, &db, &fails);

    if (have_a)
        rtb_print_sheet("A", &ma);
    if (have_b)
        rtb_print_sheet("B", &mb);

    if (have_a && have_b) {
        fails += rtb_checki64("A-vs-B", "height", ma.height, mb.height);
        fails += rtb_check32("A-vs-B", "block_hash", ma.block_hash,
                             mb.block_hash);
        fails += rtb_checki64("A-vs-B", "history_complete",
                              ma.history_complete, mb.history_complete);
        fails += rtb_checki64("A-vs-B", "activation_boundary",
                              ma.activation_boundary, mb.activation_boundary);
        fails += rtb_check32("A-vs-B", "utxo_root", da.utxo_root,
                             db.utxo_root);
        fails += rtb_checki64("A-vs-B", "utxo_count", da.utxo_count,
                              db.utxo_count);
        fails += rtb_checki64("A-vs-B", "total_supply", da.total_supply,
                              db.total_supply);
        fails += rtb_check32("A-vs-B", "anchor_digest", da.anchor_digest,
                             db.anchor_digest);
        fails += rtb_checki64("A-vs-B", "anchor_count", da.anchor_count,
                              db.anchor_count);
        fails += rtb_check32("A-vs-B", "sprout_frontier_root",
                             da.sprout_frontier_root, db.sprout_frontier_root);
        fails += rtb_checki64("A-vs-B", "sprout_frontier_height",
                              da.sprout_frontier_height,
                              db.sprout_frontier_height);
        fails += rtb_check32("A-vs-B", "sapling_frontier_root",
                             da.sapling_frontier_root,
                             db.sapling_frontier_root);
        fails += rtb_checki64("A-vs-B", "sapling_frontier_height",
                              da.sapling_frontier_height,
                              db.sapling_frontier_height);
        fails += rtb_check32("A-vs-B", "nullifier_digest",
                             da.nullifier_digest, db.nullifier_digest);
        fails += rtb_checki64("A-vs-B", "nullifier_count",
                              da.nullifier_count, db.nullifier_count);
        fails += rtb_checki64("A-vs-B", "source_fold_cursor",
                              ma.source_fold_cursor, mb.source_fold_cursor);
        fails += rtb_checki64("A-vs-B", "validation_profile",
                              ma.validation_profile, mb.validation_profile);
    }

    if (fails) {
        fprintf(stderr, "\nTWO-BUILDER: FAIL (%d mismatch(es))\n", fails);
        return 1;
    }
    printf("\nTWO-BUILDER: PASS — chain content byte-identical; every "
           "digest re-derived from raw rows equals its manifest\n");
    return 0;
}
