/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Checkpoint ladder rung — fold, self-digest, serialize/parse, bundle
 * derivation, and C-fragment emit. See storage/checkpoint_rung.h. The
 * rom_state_root fold here is byte-identical to
 * tools/rom_two_builder_compare.c (rtb_rom_state_root) and to the value baked
 * as g_rom_state_checkpoint.rom_state_root, so a rung that reproduces the
 * keystone fields reproduces the keystone root.
 */

#include "storage/checkpoint_rung.h"

#include "crypto/sha3.h"
#include "util/log_macros.h"

/* NOTE: this TU is deliberately free of the chain/ include tree so it can be
 * compiled standalone into tools/checkpoint_rung_export. The one function that
 * needs `struct rom_state_checkpoint` (from_rom_checkpoint) lives in
 * checkpoint_rung_rom.c. */

#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define RUNG_SUBSYS "checkpoint_rung"

#define RUNG_ROOT_DOMAIN "zcl.rom_state_checkpoint.v1/root"
#define RUNG_SELF_DOMAIN "zcl.checkpoint_rung.v1/self"
#define RUNG_ANCHOR_DOMAIN "zcl.consensus_state_bundle.v1/anchors"
#define RUNG_NULLIFIER_DOMAIN "zcl.consensus_state_bundle.v1/nullifiers"

static const uint8_t RUNG_MAGIC[8] = { 'Z', 'C', 'L', 'R', 'U', 'N', 'G', '1' };

/* ── little-endian scalar writers (SHA3 preimage) ─────────────────── */

static void sha3_u32le(struct sha3_256_ctx *c, uint32_t v)
{
    unsigned char b[4];
    for (int i = 0; i < 4; i++)
        b[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    sha3_256_write(c, b, sizeof(b));
}

static void sha3_u64le(struct sha3_256_ctx *c, uint64_t v)
{
    unsigned char b[8];
    for (int i = 0; i < 8; i++)
        b[i] = (unsigned char)((v >> (8 * i)) & 0xff);
    sha3_256_write(c, b, sizeof(b));
}

/* ── little-endian scalar writers (fixed-buffer serialize) ────────── */

static size_t put_u32le(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
    return 4;
}

static size_t put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
    return 8;
}

static uint32_t get_u32le(const uint8_t *p)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++)
        v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* ── fold / digest ────────────────────────────────────────────────── */

void checkpoint_rung_compute_rom_state_root(const struct checkpoint_rung *r,
                                            uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)RUNG_ROOT_DOMAIN,
                   sizeof(RUNG_ROOT_DOMAIN)); /* trailing NUL included */
    sha3_u64le(&c, (uint64_t)r->height);
    sha3_256_write(&c, r->block_hash, 32);
    sha3_256_write(&c, r->utxo_root, 32);
    sha3_u64le(&c, r->utxo_count);
    sha3_u64le(&c, (uint64_t)r->total_supply);
    sha3_256_write(&c, r->anchor_digest, 32);
    sha3_u64le(&c, r->anchor_count);
    sha3_256_write(&c, r->sprout_frontier_root, 32);
    sha3_u64le(&c, (uint64_t)r->sprout_frontier_height);
    sha3_256_write(&c, r->sapling_frontier_root, 32);
    sha3_u64le(&c, (uint64_t)r->sapling_frontier_height);
    sha3_256_write(&c, r->nullifier_digest, 32);
    sha3_u64le(&c, r->nullifier_count);
    sha3_256_finalize(&c, out);
}

/* Serialize everything EXCEPT the trailing self_digest into buf, returning the
 * byte length written (the self-digest preimage). Shared by serialize and
 * compute_self_digest so the two can never disagree. */
static size_t rung_serialize_body(const struct checkpoint_rung *r, uint8_t *buf)
{
    uint8_t *p = buf;
    memcpy(p, RUNG_MAGIC, 8);            p += 8;
    p += put_u32le(p, CHECKPOINT_RUNG_WIRE_VERSION);
    p += put_u32le(p, 0);                /* reserved */
    p += put_u32le(p, (uint32_t)r->height);
    memcpy(p, r->block_hash, 32);        p += 32;
    memcpy(p, r->utxo_root, 32);         p += 32;
    p += put_u64le(p, r->utxo_count);
    p += put_u64le(p, (uint64_t)r->total_supply);
    memcpy(p, r->anchor_digest, 32);     p += 32;
    p += put_u64le(p, r->anchor_count);
    memcpy(p, r->sprout_frontier_root, 32); p += 32;
    p += put_u64le(p, (uint64_t)r->sprout_frontier_height);
    memcpy(p, r->sapling_frontier_root, 32); p += 32;
    p += put_u64le(p, (uint64_t)r->sapling_frontier_height);
    memcpy(p, r->nullifier_digest, 32);  p += 32;
    p += put_u64le(p, r->nullifier_count);
    memcpy(p, r->rom_state_root, 32);    p += 32;
    memcpy(p, r->chainwork, 32);         p += 32;
    return (size_t)(p - buf);            /* == CHECKPOINT_RUNG_WIRE_SIZE - 32 */
}

void checkpoint_rung_compute_self_digest(const struct checkpoint_rung *r,
                                         uint8_t out[32])
{
    uint8_t body[CHECKPOINT_RUNG_WIRE_SIZE];
    size_t body_len = rung_serialize_body(r, body);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)RUNG_SELF_DOMAIN,
                   sizeof(RUNG_SELF_DOMAIN)); /* trailing NUL included */
    sha3_256_write(&c, body, body_len);
    sha3_256_finalize(&c, out);
}

void checkpoint_rung_finalize(struct checkpoint_rung *r)
{
    checkpoint_rung_compute_rom_state_root(r, r->rom_state_root);
    checkpoint_rung_compute_self_digest(r, r->self_digest);
}

bool checkpoint_rung_self_consistent(const struct checkpoint_rung *r)
{
    if (!r)
        return false;
    uint8_t root[32], self[32];
    checkpoint_rung_compute_rom_state_root(r, root);
    checkpoint_rung_compute_self_digest(r, self);
    return memcmp(root, r->rom_state_root, 32) == 0 &&
           memcmp(self, r->self_digest, 32) == 0;
}

/* ── serialize / parse ────────────────────────────────────────────── */

bool checkpoint_rung_serialize(struct checkpoint_rung *r,
                               uint8_t buf[CHECKPOINT_RUNG_WIRE_SIZE])
{
    if (!r || !buf)
        LOG_FAIL(RUNG_SUBSYS, "serialize: NULL arg (r=%p buf=%p)",
                 (const void *)r, (const void *)buf);
    /* Zero the whole framed buffer FIRST so the reserved tail
     * (CHECKPOINT_RUNG_WIRE_SIZE is 404; body + self_digest fill only 356) is
     * defined. Without this the 48 trailing bytes are whatever the caller's
     * stack held, making the on-disk artifact and any full-buffer memcmp/hash
     * non-deterministic (surfaced intermittently by the "serialize is
     * deterministic" test under load). */
    memset(buf, 0, CHECKPOINT_RUNG_WIRE_SIZE);
    checkpoint_rung_finalize(r);
    size_t body_len = rung_serialize_body(r, buf);
    memcpy(buf + body_len, r->self_digest, 32);
    return true;
}

bool checkpoint_rung_parse(const uint8_t *buf, size_t len,
                           struct checkpoint_rung *out)
{
    if (!buf || !out)
        LOG_FAIL(RUNG_SUBSYS, "parse: NULL arg (buf=%p out=%p)",
                 (const void *)buf, (const void *)out);
    if (len != CHECKPOINT_RUNG_WIRE_SIZE)
        LOG_FAIL(RUNG_SUBSYS, "parse: bad length %zu (want %u)", len,
                 CHECKPOINT_RUNG_WIRE_SIZE);
    if (memcmp(buf, RUNG_MAGIC, 8) != 0)
        LOG_FAIL(RUNG_SUBSYS, "parse: bad magic");
    const uint8_t *p = buf + 8;
    uint32_t version = get_u32le(p); p += 4;
    if (version != CHECKPOINT_RUNG_WIRE_VERSION)
        LOG_FAIL(RUNG_SUBSYS, "parse: unsupported version %u", version);
    p += 4; /* reserved */
    memset(out, 0, sizeof(*out));
    out->height = (int32_t)get_u32le(p); p += 4;
    memcpy(out->block_hash, p, 32); p += 32;
    memcpy(out->utxo_root, p, 32); p += 32;
    out->utxo_count = get_u64le(p); p += 8;
    out->total_supply = (int64_t)get_u64le(p); p += 8;
    memcpy(out->anchor_digest, p, 32); p += 32;
    out->anchor_count = get_u64le(p); p += 8;
    memcpy(out->sprout_frontier_root, p, 32); p += 32;
    out->sprout_frontier_height = (int64_t)get_u64le(p); p += 8;
    memcpy(out->sapling_frontier_root, p, 32); p += 32;
    out->sapling_frontier_height = (int64_t)get_u64le(p); p += 8;
    memcpy(out->nullifier_digest, p, 32); p += 32;
    out->nullifier_count = get_u64le(p); p += 8;
    memcpy(out->rom_state_root, p, 32); p += 32;
    memcpy(out->chainwork, p, 32); p += 32;
    memcpy(out->self_digest, p, 32); p += 32;
    if (!checkpoint_rung_self_consistent(out))
        LOG_FAIL(RUNG_SUBSYS,
                 "parse: rung at height %d fails self-consistency "
                 "(rom_state_root or self_digest does not recompute)",
                 out->height);
    return true;
}

/* ── bundle derivation (read-only) ────────────────────────────────── */

static bool rung_derive_coins(sqlite3 *db, struct checkpoint_rung *out)
{
    static const char sql[] =
        "SELECT txid,vout,value,script,height,is_coinbase FROM coins "
        "ORDER BY txid,vout";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "coins prepare: %s", sqlite3_errmsg(db));
    struct sha3_256_ctx c;
    sha3_256_init(&c); /* NO domain prefix — matches the coins codec exactly. */
    uint64_t count = 0;
    int64_t supply = 0;
    bool have_prev = false;
    uint8_t prev_txid[32];
    int64_t prev_vout = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const void *txid = sqlite3_column_blob(st, 0);
        int64_t vout = sqlite3_column_int64(st, 1);
        int64_t value = sqlite3_column_int64(st, 2);
        const void *script = sqlite3_column_blob(st, 3);
        int script_len = sqlite3_column_bytes(st, 3);
        int64_t height = sqlite3_column_int64(st, 4);
        int64_t is_cb = sqlite3_column_int64(st, 5);
        if (!txid || sqlite3_column_bytes(st, 0) != 32 || vout < 0 ||
            height < 0 || (is_cb != 0 && is_cb != 1)) {
            ok = false;
            break;
        }
        if (have_prev) {
            int cmp = memcmp(prev_txid, txid, 32);
            if (cmp > 0 || (cmp == 0 && prev_vout >= vout)) {
                ok = false;
                break;
            }
        }
        memcpy(prev_txid, txid, 32);
        prev_vout = vout;
        have_prev = true;
        sha3_256_write(&c, txid, 32);
        sha3_u32le(&c, (uint32_t)vout);
        sha3_u64le(&c, (uint64_t)value);
        sha3_u32le(&c, (uint32_t)(script ? script_len : 0));
        if (script && script_len > 0)
            sha3_256_write(&c, script, (size_t)script_len);
        sha3_u32le(&c, (uint32_t)height);
        sha3_256_write(&c, is_cb ? (const unsigned char *)"\x01"
                                 : (const unsigned char *)"\x00", 1);
        count++;
        supply += value;
    }
    sqlite3_finalize(st);
    if (!ok || rc != SQLITE_DONE)
        LOG_FAIL(RUNG_SUBSYS, "coins fold failed (ok=%d rc=%d)", ok ? 1 : 0, rc);
    sha3_256_finalize(&c, out->utxo_root);
    out->utxo_count = count;
    out->total_supply = supply;
    return true;
}

static bool rung_derive_anchors(sqlite3 *db, struct checkpoint_rung *out)
{
    static const char sql[] =
        "SELECT pool,anchor,height,tree FROM anchors ORDER BY pool,anchor";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "anchors prepare: %s", sqlite3_errmsg(db));
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)RUNG_ANCHOR_DOMAIN,
                   sizeof(RUNG_ANCHOR_DOMAIN)); /* trailing NUL included */
    uint64_t count = 0;
    int64_t best_h[2] = { -1, -1 };
    bool have_prev = false;
    int64_t prev_pool = 0;
    uint8_t prev_anchor[32];
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        int64_t pool = sqlite3_column_int64(st, 0);
        const void *anchor = sqlite3_column_blob(st, 1);
        int64_t height = sqlite3_column_int64(st, 2);
        const void *tree = sqlite3_column_blob(st, 3);
        int tree_len = sqlite3_column_bytes(st, 3);
        if ((pool != 0 && pool != 1) || !anchor ||
            sqlite3_column_bytes(st, 1) != 32 || height < 0 || !tree) {
            ok = false;
            break;
        }
        if (have_prev) {
            int cmp = prev_pool > pool ? 1
                    : prev_pool < pool ? -1
                    : memcmp(prev_anchor, anchor, 32);
            if (cmp >= 0) {
                ok = false;
                break;
            }
        }
        prev_pool = pool;
        memcpy(prev_anchor, anchor, 32);
        have_prev = true;
        unsigned char p = (unsigned char)pool;
        sha3_256_write(&c, &p, 1);
        sha3_256_write(&c, anchor, 32);
        sha3_u64le(&c, (uint64_t)height);
        sha3_u32le(&c, (uint32_t)tree_len);
        sha3_256_write(&c, tree, (size_t)tree_len);
        count++;
        if (height > best_h[pool]) {
            best_h[pool] = height;
            if (pool == 0)
                memcpy(out->sprout_frontier_root, anchor, 32);
            else
                memcpy(out->sapling_frontier_root, anchor, 32);
        }
    }
    sqlite3_finalize(st);
    if (!ok || rc != SQLITE_DONE)
        LOG_FAIL(RUNG_SUBSYS, "anchors fold failed (ok=%d rc=%d)", ok ? 1 : 0,
                 rc);
    sha3_256_finalize(&c, out->anchor_digest);
    out->anchor_count = count;
    out->sprout_frontier_height = best_h[0];
    out->sapling_frontier_height = best_h[1];
    return true;
}

static bool rung_derive_nullifiers(sqlite3 *db, struct checkpoint_rung *out)
{
    static const char sql[] =
        "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "nullifiers prepare: %s", sqlite3_errmsg(db));
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)RUNG_NULLIFIER_DOMAIN,
                   sizeof(RUNG_NULLIFIER_DOMAIN)); /* trailing NUL included */
    uint64_t count = 0;
    bool have_prev = false;
    int64_t prev_pool = 0;
    uint8_t prev_nf[32];
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        int64_t pool = sqlite3_column_int64(st, 0);
        const void *nf = sqlite3_column_blob(st, 1);
        int64_t height = sqlite3_column_int64(st, 2);
        if ((pool != 0 && pool != 1) || !nf ||
            sqlite3_column_bytes(st, 1) != 32 || height < 0) {
            ok = false;
            break;
        }
        if (have_prev) {
            int cmp = prev_pool > pool ? 1
                    : prev_pool < pool ? -1
                    : memcmp(prev_nf, nf, 32);
            if (cmp >= 0) {
                ok = false;
                break;
            }
        }
        prev_pool = pool;
        memcpy(prev_nf, nf, 32);
        have_prev = true;
        unsigned char p = (unsigned char)pool;
        sha3_256_write(&c, &p, 1);
        sha3_256_write(&c, nf, 32);
        sha3_u64le(&c, (uint64_t)height);
        count++;
    }
    sqlite3_finalize(st);
    if (!ok || rc != SQLITE_DONE)
        LOG_FAIL(RUNG_SUBSYS, "nullifiers fold failed (ok=%d rc=%d)",
                 ok ? 1 : 0, rc);
    sha3_256_finalize(&c, out->nullifier_digest);
    out->nullifier_count = count;
    return true;
}

static bool rung_read_bundle_meta(sqlite3 *db, struct checkpoint_rung *out)
{
    static const char sql[] =
        "SELECT height,block_hash FROM bundle_meta WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "bundle_meta prepare: %s", sqlite3_errmsg(db));
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW &&
              sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_type(st, 1) == SQLITE_BLOB &&
              sqlite3_column_bytes(st, 1) == 32;
    if (ok) {
        out->height = (int32_t)sqlite3_column_int64(st, 0);
        memcpy(out->block_hash, sqlite3_column_blob(st, 1), 32);
    }
    sqlite3_finalize(st);
    if (!ok)
        LOG_FAIL(RUNG_SUBSYS, "bundle_meta singleton missing/malformed");
    return true;
}

bool checkpoint_rung_derive_from_bundle(struct sqlite3 *bundle,
                                        const uint8_t chainwork[32],
                                        struct checkpoint_rung *out)
{
    if (!bundle || !out)
        LOG_FAIL(RUNG_SUBSYS, "derive_from_bundle: NULL arg (bundle=%p out=%p)",
                 (const void *)bundle, (const void *)out);
    memset(out, 0, sizeof(*out));
    if (!rung_read_bundle_meta(bundle, out) ||
        !rung_derive_coins(bundle, out) ||
        !rung_derive_anchors(bundle, out) ||
        !rung_derive_nullifiers(bundle, out))
        return false; // raw-return-ok:logged-by-callee
    if (chainwork)
        memcpy(out->chainwork, chainwork, 32);
    checkpoint_rung_finalize(out);
    return true;
}

/* ── C-fragment emit ──────────────────────────────────────────────── */

/* Bounded append cursor: snprintf into the remaining space, always tracking
 * the full would-be length so the return value is truncation-safe. */
struct frag_cursor {
    char  *buf;
    size_t cap;
    int    pos;   /* total bytes that WOULD be written (may exceed cap) */
};

static void frag_appendf(struct frag_cursor *fc, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void frag_appendf(struct frag_cursor *fc, const char *fmt, ...)
{
    size_t off = (size_t)fc->pos < fc->cap ? (size_t)fc->pos : fc->cap;
    size_t rem = fc->cap - off;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(fc->buf + off, rem, fmt, ap);
    va_end(ap);
    if (n > 0)
        fc->pos += n;
}

static void frag_hex_array(struct frag_cursor *fc, const char *name,
                           const uint8_t v[32])
{
    /* display-order hex comment (reverse of stored bytes, matching the
     * block_hash convention in checkpoints.c) then the stored bytes. */
    char disp[65];
    for (int i = 0; i < 32; i++)
        snprintf(disp + 2 * i, 3, "%02x", v[31 - i]);
    frag_appendf(fc, "    .%s = {\n        /* %s */\n        ", name, disp);
    for (int i = 0; i < 32; i++)
        frag_appendf(fc, "0x%02x,%s", v[i],
                     (i % 8 == 7) ? (i == 31 ? "\n" : "\n        ") : " ");
    frag_appendf(fc, "    },\n");
}

int checkpoint_rung_emit_c_fragment(const struct checkpoint_rung *r,
                                    char *out, size_t cap)
{
    if (!r || !out)
        LOG_ERR(RUNG_SUBSYS, "emit_c_fragment: NULL arg (r=%p out=%p)",
                (const void *)r, (const void *)out);
    char cw_hex[65], self_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(cw_hex + 2 * i, 3, "%02x", r->chainwork[i]);
        snprintf(self_hex + 2 * i, 3, "%02x", r->self_digest[i]);
    }
    struct frag_cursor fc = { .buf = out, .cap = cap, .pos = 0 };
    frag_appendf(&fc,
        "/* Checkpoint ladder rung at height %d.\n"
        " * candidate_unbaked: this record is self-attestation until re-derived\n"
        " * and baked under the two-builder ritual. chainwork (BE) = %s\n"
        " * rung self_digest = %s */\n"
        "static const struct rom_state_checkpoint g_rom_state_rung_%d = {\n"
        "    .height = %d,\n",
        r->height, cw_hex, self_hex, r->height, r->height);
    frag_hex_array(&fc, "block_hash", r->block_hash);
    frag_hex_array(&fc, "utxo_root", r->utxo_root);
    frag_appendf(&fc, "    .utxo_count = %llu,\n    .total_supply = %lldLL,\n",
                 (unsigned long long)r->utxo_count, (long long)r->total_supply);
    frag_hex_array(&fc, "anchor_digest", r->anchor_digest);
    frag_appendf(&fc, "    .anchor_count = %llu,\n",
                 (unsigned long long)r->anchor_count);
    frag_hex_array(&fc, "sprout_frontier_root", r->sprout_frontier_root);
    frag_appendf(&fc, "    .sprout_frontier_height = %lld,\n",
                 (long long)r->sprout_frontier_height);
    frag_hex_array(&fc, "sapling_frontier_root", r->sapling_frontier_root);
    frag_appendf(&fc, "    .sapling_frontier_height = %lld,\n",
                 (long long)r->sapling_frontier_height);
    frag_hex_array(&fc, "nullifier_digest", r->nullifier_digest);
    frag_appendf(&fc, "    .nullifier_count = %llu,\n",
                 (unsigned long long)r->nullifier_count);
    frag_hex_array(&fc, "rom_state_root", r->rom_state_root);
    frag_appendf(&fc, "};\n");
    return fc.pos;
}
