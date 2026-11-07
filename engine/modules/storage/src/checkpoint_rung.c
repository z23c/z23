/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Checkpoint ladder rung — fold, self-digest, serialize/parse, bundle
 * derivation, and C-fragment emit. See storage/checkpoint_rung.h.
 * V1 reproduces the existing ROM root; V2 additionally binds pool totals.
 */

#include "storage/checkpoint_rung.h"
#include "base/format_attribute.h"

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
#define RUNG_ROOT_V2_DOMAIN "zcl.rom_state_checkpoint.v2/root"
#define RUNG_SELF_V2_DOMAIN "zcl.checkpoint_rung.v2/self"
#define RUNG_ANCHOR_DOMAIN "zcl.consensus_state_bundle.v1/anchors"
#define RUNG_NULLIFIER_DOMAIN "zcl.consensus_state_bundle.v1/nullifiers"

static const uint8_t RUNG_MAGIC[8] = { 'Z', 'C', 'L', 'R', 'U', 'N', 'G', '1' };
static const uint8_t RUNG_MAGIC_V2[8] = { 'Z', 'C', 'L', 'R', 'U', 'N', 'G', '2' };

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

static bool rung_valid(const struct checkpoint_rung *r)
{
    return r && (r->format_version == CHECKPOINT_RUNG_VERSION_V1 ||
        (r->format_version == CHECKPOINT_RUNG_VERSION_V2 &&
         r->sprout_pool_total >= 0 && r->sapling_pool_total >= 0));
}

void checkpoint_rung_compute_rom_state_root(const struct checkpoint_rung *r,
                                            uint8_t out[32])
{
    if (!rung_valid(r)) {
        memset(out, 0, 32);
        return;
    }
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    if (r->format_version == CHECKPOINT_RUNG_VERSION_V2)
        sha3_256_write(&c, (const unsigned char *)RUNG_ROOT_V2_DOMAIN, sizeof(RUNG_ROOT_V2_DOMAIN));
    else
        sha3_256_write(&c, (const unsigned char *)RUNG_ROOT_DOMAIN, sizeof(RUNG_ROOT_DOMAIN));
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
    if (r->format_version == CHECKPOINT_RUNG_VERSION_V2) {
        sha3_u64le(&c, (uint64_t)r->sprout_pool_total);
        sha3_u64le(&c, (uint64_t)r->sapling_pool_total);
    }
    sha3_256_finalize(&c, out);
}

/* Serialize everything EXCEPT the trailing self_digest into buf, returning the
 * byte length written (the self-digest preimage). Shared by serialize and
 * compute_self_digest so the two can never disagree. */
static size_t rung_serialize_body(const struct checkpoint_rung *r, uint8_t *buf)
{
    uint8_t *p = buf;
    memcpy(p, r->format_version == CHECKPOINT_RUNG_VERSION_V2 ? RUNG_MAGIC_V2 : RUNG_MAGIC, 8); p += 8;
    p += put_u32le(p, r->format_version);
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
    if (r->format_version == CHECKPOINT_RUNG_VERSION_V2) {
        p += put_u64le(p, (uint64_t)r->sprout_pool_total);
        p += put_u64le(p, (uint64_t)r->sapling_pool_total);
    }
    memcpy(p, r->rom_state_root, 32);    p += 32;
    memcpy(p, r->chainwork, 32);         p += 32;
    return (size_t)(p - buf);
}

void checkpoint_rung_compute_self_digest(const struct checkpoint_rung *r,
                                         uint8_t out[32])
{
    if (!rung_valid(r)) {
        memset(out, 0, 32);
        return;
    }
    uint8_t body[CHECKPOINT_RUNG_V2_WIRE_SIZE];
    size_t body_len = rung_serialize_body(r, body);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    if (r->format_version == CHECKPOINT_RUNG_VERSION_V2)
        sha3_256_write(&c, (const unsigned char *)RUNG_SELF_V2_DOMAIN, sizeof(RUNG_SELF_V2_DOMAIN));
    else
        sha3_256_write(&c, (const unsigned char *)RUNG_SELF_DOMAIN, sizeof(RUNG_SELF_DOMAIN));
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
    if (!rung_valid(r))
        return false;
    uint8_t root[32], self[32];
    checkpoint_rung_compute_rom_state_root(r, root);
    checkpoint_rung_compute_self_digest(r, self);
    return memcmp(root, r->rom_state_root, 32) == 0 &&
           memcmp(self, r->self_digest, 32) == 0;
}

/* ── serialize / parse ────────────────────────────────────────────── */

bool checkpoint_rung_serialize_sized(struct checkpoint_rung *r, uint8_t *buf,
                                     size_t cap, size_t *written)
{
    if (written) *written = 0;
    if (!rung_valid(r) || !buf || !written)
        LOG_FAIL(RUNG_SUBSYS, "serialize: invalid argument or rung");
    size_t len = r->format_version == CHECKPOINT_RUNG_VERSION_V2
        ? CHECKPOINT_RUNG_V2_WIRE_SIZE : CHECKPOINT_RUNG_WIRE_SIZE;
    if (cap < len)
        LOG_FAIL(RUNG_SUBSYS, "serialize: insufficient capacity");
    memset(buf, 0, len);
    checkpoint_rung_finalize(r);
    size_t body_len = rung_serialize_body(r, buf);
    memcpy(buf + body_len, r->self_digest, 32);
    *written = len;
    return true;
}

bool checkpoint_rung_serialize(struct checkpoint_rung *r,
                               uint8_t buf[CHECKPOINT_RUNG_WIRE_SIZE])
{
    if (!r || r->format_version != CHECKPOINT_RUNG_VERSION_V1)
        LOG_FAIL(RUNG_SUBSYS, "serialize: legacy serializer requires v1");
    size_t written;
    return checkpoint_rung_serialize_sized(r, buf, CHECKPOINT_RUNG_WIRE_SIZE,
                                           &written);
}

static bool rung_v2_padding_zero(const uint8_t *buf)
{
    for (size_t i = 12; i < 16; i++)
        if (buf[i] != 0) return false;
    for (size_t i = CHECKPOINT_RUNG_V2_WIRE_SIZE - 48; i < CHECKPOINT_RUNG_V2_WIRE_SIZE; i++)
        if (buf[i] != 0) return false;
    return true;
}

static uint32_t rung_wire_version(const uint8_t *buf, size_t len)
{
    if (len != CHECKPOINT_RUNG_WIRE_SIZE && len != CHECKPOINT_RUNG_V2_WIRE_SIZE)
        return CHECKPOINT_RUNG_VERSION_INVALID;
    uint32_t version = get_u32le(buf + 8);
    if (version == CHECKPOINT_RUNG_VERSION_V1 && len == CHECKPOINT_RUNG_WIRE_SIZE &&
        memcmp(buf, RUNG_MAGIC, 8) == 0)
        return version;
    if (version == CHECKPOINT_RUNG_VERSION_V2 && len == CHECKPOINT_RUNG_V2_WIRE_SIZE &&
        memcmp(buf, RUNG_MAGIC_V2, 8) == 0 && rung_v2_padding_zero(buf))
        return version;
    return CHECKPOINT_RUNG_VERSION_INVALID;
}

static bool rung_parse_pools(const uint8_t **cursor, struct checkpoint_rung *out)
{
    uint64_t sprout = get_u64le(*cursor);
    uint64_t sapling = get_u64le(*cursor + 8);
    if (sprout > INT64_MAX || sapling > INT64_MAX)
        LOG_FAIL(RUNG_SUBSYS, "parse: invalid pool total");
    out->sprout_pool_total = (int64_t)sprout;
    out->sapling_pool_total = (int64_t)sapling;
    *cursor += 16;
    return true;
}

bool checkpoint_rung_parse(const uint8_t *buf, size_t len,
                           struct checkpoint_rung *out)
{
    if (!buf || !out)
        LOG_FAIL(RUNG_SUBSYS, "parse: NULL arg (buf=%p out=%p)",
                 (const void *)buf, (const void *)out);
    uint32_t version = rung_wire_version(buf, len);
    if (version == CHECKPOINT_RUNG_VERSION_INVALID)
        LOG_FAIL(RUNG_SUBSYS, "parse: invalid magic, version, or length");
    const uint8_t *p = buf + 12;
    p += 4; /* reserved */
    memset(out, 0, sizeof(*out));
    out->format_version = (uint8_t)version;
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
    if (version == CHECKPOINT_RUNG_VERSION_V2 && !rung_parse_pools(&p, out))
        return false; // raw-return-ok:logged-by-callee
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

static bool coins_row_is_well_formed(sqlite3_stmt *st, const void *txid,
                                     int64_t vout, int64_t height,
                                     int64_t is_cb)
{
    return txid != NULL && sqlite3_column_bytes(st, 0) == 32 && vout >= 0 &&
           height >= 0 && (is_cb == 0 || is_cb == 1);
}

static int coins_row_compare(const uint8_t prev_txid[32], int64_t prev_vout,
                             const void *txid, int64_t vout)
{
    int cmp = memcmp(prev_txid, txid, 32);
    if (cmp != 0)
        return cmp;
    if (prev_vout < vout)
        return -1;
    if (prev_vout > vout)
        return 1;
    return 0;
}

static void coins_fold_row(struct sha3_256_ctx *c, const void *txid,
                           int64_t vout, int64_t value, const void *script,
                           int script_len, int64_t height, int64_t is_cb)
{
    sha3_256_write(c, txid, 32);
    sha3_u32le(c, (uint32_t)vout);
    sha3_u64le(c, (uint64_t)value);
    sha3_u32le(c, (uint32_t)(script ? script_len : 0));
    if (script && script_len > 0)
        sha3_256_write(c, script, (size_t)script_len);
    sha3_u32le(c, (uint32_t)height);
    sha3_256_write(c, is_cb ? (const unsigned char *)"\x01"
                            : (const unsigned char *)"\x00", 1);
}

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
        if (!coins_row_is_well_formed(st, txid, vout, height, is_cb)) {
            ok = false;
            break;
        }
        if (have_prev &&
            coins_row_compare(prev_txid, prev_vout, txid, vout) >= 0) {
            ok = false;
            break;
        }
        memcpy(prev_txid, txid, 32);
        prev_vout = vout;
        have_prev = true;
        coins_fold_row(&c, txid, vout, value, script, script_len, height,
                       is_cb);
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

static bool anchors_row_is_well_formed(sqlite3_stmt *st, int64_t pool,
                                       const void *anchor, int64_t height,
                                       const void *tree)
{
    return (pool == 0 || pool == 1) && anchor != NULL &&
           sqlite3_column_bytes(st, 1) == 32 &&
           height >= 0 && tree != NULL;
}

static int anchors_row_compare(int64_t prev_pool,
                               const uint8_t prev_anchor[32], int64_t pool,
                               const void *anchor)
{
    if (prev_pool > pool)
        return 1;
    if (prev_pool < pool)
        return -1;
    return memcmp(prev_anchor, anchor, 32);
}

static void anchors_track_frontier(int64_t best_h[2],
                                   struct checkpoint_rung *out, int64_t pool,
                                   int64_t height, const void *anchor)
{
    if (height > best_h[pool]) {
        best_h[pool] = height;
        if (pool == 0)
            memcpy(out->sprout_frontier_root, anchor, 32);
        else
            memcpy(out->sapling_frontier_root, anchor, 32);
    }
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
        if (!anchors_row_is_well_formed(st, pool, anchor, height, tree)) {
            ok = false;
            break;
        }
        if (have_prev &&
            anchors_row_compare(prev_pool, prev_anchor, pool, anchor) >= 0) {
            ok = false;
            break;
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
        anchors_track_frontier(best_h, out, pool, height, anchor);
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

static bool rung_read_bundle_pools(sqlite3 *db, struct checkpoint_rung *out)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT sprout_pool_total,sapling_pool_total FROM bundle_meta WHERE singleton=1";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "bundle pool totals prepare: %s", sqlite3_errmsg(db));
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW && sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_type(st, 1) == SQLITE_INTEGER &&
              sqlite3_column_int64(st, 0) >= 0 && sqlite3_column_int64(st, 1) >= 0;
    if (ok) {
        out->sprout_pool_total = sqlite3_column_int64(st, 0);
        out->sapling_pool_total = sqlite3_column_int64(st, 1);
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    }
    int final_rc = sqlite3_finalize(st);
    if (!ok || final_rc != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "bundle pool totals missing/malformed or finalize failed");
    return true;
}

/* Kept local because the standalone rung exporter does not link the codec. */
static uint8_t rung_schema_version(sqlite3_stmt *st)
{
    static const char v1[] = "zcl.consensus_state_bundle.v1";
    static const char v2[] = "zcl.consensus_state_bundle.v2";
    if (sqlite3_column_type(st, 2) != SQLITE_TEXT)
        return CHECKPOINT_RUNG_VERSION_INVALID;
    const void *schema = sqlite3_column_text(st, 2);
    int n = sqlite3_column_bytes(st, 2);
    if (!schema)
        return CHECKPOINT_RUNG_VERSION_INVALID;
    if (n == (int)sizeof(v1) - 1 && memcmp(schema, v1, sizeof(v1) - 1) == 0)
        return CHECKPOINT_RUNG_VERSION_V1;
    if (n == (int)sizeof(v2) - 1 && memcmp(schema, v2, sizeof(v2) - 1) == 0)
        return CHECKPOINT_RUNG_VERSION_V2;
    return CHECKPOINT_RUNG_VERSION_INVALID;
}

static bool rung_meta_row(sqlite3_stmt *st, struct checkpoint_rung *out)
{
    if (sqlite3_column_type(st, 0) != SQLITE_INTEGER ||
        sqlite3_column_type(st, 1) != SQLITE_BLOB || sqlite3_column_bytes(st, 1) != 32)
        return false;
    int64_t height = sqlite3_column_int64(st, 0);
    const void *hash = sqlite3_column_blob(st, 1);
    uint8_t version = rung_schema_version(st);
    if (height < 0 || height > INT32_MAX || !hash ||
        version == CHECKPOINT_RUNG_VERSION_INVALID)
        return false;
    out->height = (int32_t)height;
    out->format_version = version;
    memcpy(out->block_hash, hash, 32);
    return true;
}

static bool rung_read_bundle_meta(sqlite3 *db, struct checkpoint_rung *out)
{
    static const char sql[] = "SELECT height,block_hash,schema FROM bundle_meta WHERE singleton=1";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "bundle_meta prepare: %s", sqlite3_errmsg(db));
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_ROW && rung_meta_row(st, out);
    if (ok)
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:read-only-introspection
    int final_rc = sqlite3_finalize(st);
    if (!ok || final_rc != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "bundle_meta singleton missing/malformed or finalize failed");
    return out->format_version != CHECKPOINT_RUNG_VERSION_V2 ||
           rung_read_bundle_pools(db, out);
}

static bool rung_finish_transaction(sqlite3 *bundle, bool own_transaction, bool ok)
{
    if (own_transaction) {
        if (ok && sqlite3_exec(bundle, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
            LOG_WARN(RUNG_SUBSYS, "derive_from_bundle: commit: %s", sqlite3_errmsg(bundle));
            ok = false;
        }
        if (!ok && sqlite3_get_autocommit(bundle) == 0 &&
            sqlite3_exec(bundle, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            LOG_WARN(RUNG_SUBSYS, "derive_from_bundle: rollback: %s", sqlite3_errmsg(bundle));
    }
    return ok;
}

/* Derive all fields from one SQLite snapshot, retaining a caller's transaction. */
bool checkpoint_rung_derive_from_bundle(struct sqlite3 *bundle,
                                        const uint8_t chainwork[32],
                                        struct checkpoint_rung *out)
{
    if (!bundle || !out)
        LOG_FAIL(RUNG_SUBSYS, "derive_from_bundle: NULL argument");
    memset(out, 0, sizeof(*out));
    bool own_transaction = sqlite3_get_autocommit(bundle) != 0;
    if (own_transaction && sqlite3_exec(bundle, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
        LOG_FAIL(RUNG_SUBSYS, "derive_from_bundle: begin: %s", sqlite3_errmsg(bundle));
    bool ok = rung_read_bundle_meta(bundle, out) &&
              rung_derive_coins(bundle, out) &&
              rung_derive_anchors(bundle, out) &&
              rung_derive_nullifiers(bundle, out);
    ok = rung_finish_transaction(bundle, own_transaction, ok);
    if (!ok) {
        memset(out, 0, sizeof(*out));
        return false; // raw-return-ok:logged-by-callee
    }
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
    ZCL_PRINTF_LIKE(2, 3);

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
    frag_appendf(&fc, "    .format_version = %u,\n", r->format_version);
    if (r->format_version == CHECKPOINT_RUNG_VERSION_V2)
        frag_appendf(&fc, "    .sprout_pool_total = %lldLL,\n    .sapling_pool_total = %lldLL,\n",
                     (long long)r->sprout_pool_total, (long long)r->sapling_pool_total);
    frag_hex_array(&fc, "rom_state_root", r->rom_state_root);
    frag_appendf(&fc, "};\n");
    return fc.pos;
}
