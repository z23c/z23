/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord model for the OP_RETURN catalog projection
 * (op_return_index) — see models/op_return_index.h for the field
 * semantics and the threading contract. The extract/digest logic here is
 * pure (no IO); the SQLite plumbing follows the same
 * AR_ADHOC_SAVE/AR_QUERY_* shape as models/zanc.c. */

#include "models/op_return_index.h"
#include "models/database_internal.h"
#include "models/query_builder.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/op_return_push.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* ── Persisted cursor state ─────────────────────────────────────────
 *
 * v1 (superseded) wrote TWO keys and declared no range: an int cursor
 * height and a 32-byte running digest, implicitly rooted at genesis.
 * v2 writes ONE key holding the whole record — version byte, base height,
 * base digest, cursor height, cursor digest — so the range a digest covers
 * travels with the digest and can never be inferred wrongly.
 *
 * The v1 keys are NEVER read. They are only PROBED, so a v1 record is
 * refused loudly instead of being reinterpreted as a genesis-rooted v2
 * chain (docs/spec/sovereign-identity-layer.md, "Versioning doctrine"). */
#define OP_RETURN_INDEX_STATE_KEY_V2 "op_return_index_state.v2"
#define OP_RETURN_INDEX_CURSOR_KEY_V1 "op_return_index_cursor_height"
#define OP_RETURN_INDEX_DIGEST_KEY_V1 "op_return_index_digest"

/* version(1) | base_height(8 LE) | base_digest(32) | height(8 LE) |
 * digest(32) */
#define OP_RETURN_INDEX_STATE_RECORD_LEN 81
#define OP_RETURN_INDEX_STATE_VERSION_BYTE 2

/* Domain-separation tag for the v2 digest preimage. A v1 digest can never
 * collide with a v2 one: v1 hashed prev||height||hash||n||rows with no
 * prefix at all. */
static const char OP_RETURN_INDEX_FOLD_TAG_V2[] = "ZCL.op_return_index.fold.v2";
static const char OP_RETURN_INDEX_BASE_TAG_V2[] = "ZCL.op_return_index.base.v2";

DEFINE_MODEL_CALLBACKS(op_return_index)

/* ── Pure extraction ───────────────────────────────────────────────── */

/* Render `tag[0..tag_len)` into `out` (OP_RETURN_INDEX_TAG_TEXT_MAX bytes):
 * ASCII (trailing NUL bytes trimmed first — ZSLP's lokad is "SLP\0") when
 * every remaining byte is printable, else lowercase hex of the raw bytes. */
static void tag_to_text(const uint8_t *tag, uint8_t tag_len,
                        char out[OP_RETURN_INDEX_TAG_TEXT_MAX])
{
    uint8_t n = tag_len;
    while (n > 0 && tag[n - 1] == 0x00) n--;

    bool printable = (n > 0);
    for (uint8_t i = 0; i < n && printable; i++)
        if (tag[i] < 0x20 || tag[i] > 0x7e) printable = false;

    if (printable) {
        memcpy(out, tag, n);
        out[n] = '\0';
        return;
    }

    zcl_hex_encode(tag, tag_len, out);
}

bool op_return_index_extract(const uint8_t *script, size_t script_len,
                             struct op_return_index_row *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!script || script_len == 0 || script[0] != 0x6a)
        return false;

    const uint8_t *payload = script + 1;
    size_t payload_len = script_len - 1;
    /* Scripts are far smaller than UINT32_MAX (MAX_SCRIPT_SIZE); the clamp
     * is a defensive belt, not an expected path. */
    out->payload_len = (uint32_t)(payload_len > UINT32_MAX
                                       ? UINT32_MAX : payload_len);
    zcl_sha3_256(payload, payload_len, out->payload_sha3);

    const uint8_t *end = script + script_len;
    const uint8_t *data = NULL;
    size_t len = 0;
    const uint8_t *after = read_push(payload, end, &data, &len);
    if (after && len <= OP_RETURN_INDEX_TAG_MAX) {
        /* A well-formed push, including the canonical empty push (OP_0,
         * len==0) — do NOT fall through to the raw-byte fallback below,
         * which would otherwise mistake "OP_RETURN OP_0" for a malformed
         * script and catalog a 1-byte tag instead of the true 0-byte one. */
        if (len > 0) memcpy(out->tag, data, len);
        out->tag_len = (uint8_t)len;
    } else {
        size_t n = payload_len < OP_RETURN_INDEX_TAG_MAX
                       ? payload_len : OP_RETURN_INDEX_TAG_MAX;
        memcpy(out->tag, payload, n);
        out->tag_len = (uint8_t)n;
    }

    tag_to_text(out->tag, out->tag_len, out->tag_text);
    return true;
}

void op_return_index_make_base_digest(int32_t base_height,
                                      const uint8_t base_anchor_hash[32],
                                      uint8_t out_digest[32])
{
    if (!out_digest) return;
    static const uint8_t zero32[32] = {0};
    /* A from-genesis chain keeps the natural all-zero IV so its digests
     * stay the plain "everything from height 0" object; only a chain that
     * genuinely starts above genesis carries a derived IV. */
    if (base_height <= 0 && !base_anchor_hash) {
        memset(out_digest, 0, 32);
        return;
    }
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)OP_RETURN_INDEX_BASE_TAG_V2,
                   sizeof(OP_RETURN_INDEX_BASE_TAG_V2) - 1);
    uint8_t le8[8];
    zcl_write_i64_le(le8, (int64_t)base_height);
    sha3_256_write(&ctx, le8, 8);
    sha3_256_write(&ctx, base_anchor_hash ? base_anchor_hash : zero32, 32);
    sha3_256_finalize(&ctx, out_digest);
}

void op_return_index_fold_block_digest(int32_t base_height,
                                       const uint8_t base_digest[32],
                                       const uint8_t prev_digest[32],
                                       int32_t height,
                                       const uint8_t block_hash[32],
                                       const struct op_return_index_row *rows,
                                       size_t n_rows, uint8_t out_digest[32])
{
    static const uint8_t zero32[32] = {0};
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    /* Tag + declared range FIRST, then the running chain: the range a
     * digest covers is part of every preimage, so no verifier can read a
     * partial-coverage digest as a genesis-rooted one. */
    sha3_256_write(&ctx, (const uint8_t *)OP_RETURN_INDEX_FOLD_TAG_V2,
                   sizeof(OP_RETURN_INDEX_FOLD_TAG_V2) - 1);
    uint8_t base_le8[8];
    zcl_write_i64_le(base_le8, (int64_t)base_height);
    sha3_256_write(&ctx, base_le8, 8);
    sha3_256_write(&ctx, base_digest ? base_digest : zero32, 32);
    sha3_256_write(&ctx, prev_digest ? prev_digest : zero32, 32);

    uint8_t le8[8];
    zcl_write_i64_le(le8, (int64_t)height);
    sha3_256_write(&ctx, le8, 8);
    sha3_256_write(&ctx, block_hash ? block_hash : zero32, 32);

    uint8_t le4[4];
    uint32_t nrows32 = (uint32_t)n_rows;
    zcl_write_u32_le(le4, nrows32);
    sha3_256_write(&ctx, le4, 4);

    for (size_t i = 0; i < n_rows; i++) {
        const struct op_return_index_row *r = &rows[i];
        sha3_256_write(&ctx, r->txid, 32);
        uint8_t vle[4];
        zcl_write_u32_le(vle, r->vout_n);
        sha3_256_write(&ctx, vle, 4);
        sha3_256_write(&ctx, &r->tag_len, 1);
        sha3_256_write(&ctx, r->tag, r->tag_len);
        uint8_t ple[4];
        zcl_write_u32_le(ple, r->payload_len);
        sha3_256_write(&ctx, ple, 4);
        sha3_256_write(&ctx, r->payload_sha3, 32);
    }
    sha3_256_finalize(&ctx, out_digest);
}

/* ── AR plumbing ───────────────────────────────────────────────────── */

bool db_op_return_index_validate(const struct op_return_index_row *r,
                                 struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!r) {
        ar_errors_add(errors, "row", "is NULL");
        return false;
    }
    validates_non_negative(errors, r, height);
    validates_custom(errors, r->tag_len <= OP_RETURN_INDEX_TAG_MAX,
                     "tag_len", "exceeds OP_RETURN_INDEX_TAG_MAX");
    return !ar_errors_any(errors);
}

bool db_op_return_index_save(struct node_db *ndb,
                             const struct op_return_index_row *row)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("op_return_index", "db_op_return_index_save: db not open");
    if (!row)
        LOG_FAIL("op_return_index", "db_op_return_index_save: row is NULL");

    struct ar_callbacks *cbs = db_op_return_index_callbacks();
    struct qb q;
    qb_insert(&q, QB_T_op_return_index, QB_INSERT_OR_IGNORE);
    qb_value_blob(&q, QB_C_op_return_index_txid, row->txid, 32);
    qb_value_int(&q, QB_C_op_return_index_vout_n, (int64_t)row->vout_n);
    qb_value_int(&q, QB_C_op_return_index_height, row->height);
    qb_value_blob(&q, QB_C_op_return_index_tag, row->tag, row->tag_len);
    qb_value_text(&q, QB_C_op_return_index_tag_text, row->tag_text);
    qb_value_int(&q, QB_C_op_return_index_payload_len,
                 (int64_t)row->payload_len);
    qb_value_blob(&q, QB_C_op_return_index_payload_sha3, row->payload_sha3,
                  32);
    /* ar-lifecycle-ok:qb-adhoc-save-expands-to-AR_BEGIN_SAVE-and-AR_FINISH_SAVE */
    QB_ADHOC_SAVE(ndb, &q, s, cbs, "op_return_index", row,
                  db_op_return_index_validate);
}

bool op_return_index_apply_block_rows(struct node_db *ndb,
                                      const struct block *blk, int32_t height,
                                      struct op_return_index_row *rows_out,
                                      size_t rows_cap,
                                      size_t *rows_count_out)
{
    if (!ndb || !ndb->open || !blk)
        LOG_FAIL("op_return_index",
                 "apply_block_rows: invalid args (ndb=%p blk=%p)",
                 (void *)ndb, (const void *)blk);

    size_t n = 0;
    for (size_t ti = 0; ti < blk->num_vtx; ti++) {
        const struct transaction *tx = &blk->vtx[ti];
        for (size_t vo = 0; vo < tx->num_vout; vo++) {
            const struct tx_out *o = &tx->vout[vo];
            const uint8_t *script = o->script_pub_key.data;
            size_t slen = o->script_pub_key.size;
            if (slen == 0 || script[0] != 0x6a)
                continue;

            struct op_return_index_row row;
            if (!op_return_index_extract(script, slen, &row))
                continue;
            memcpy(row.txid, tx->hash.data, 32);
            row.vout_n = (uint32_t)vo;
            row.height = height;

            if (!db_op_return_index_save(ndb, &row))
                LOG_WARN("op_return_index",
                         "apply_block_rows: save failed h=%d tx=%zu vout=%zu",
                         height, ti, vo);

            if (rows_out && n < rows_cap)
                rows_out[n] = row;
            n++;
        }
    }
    if (rows_count_out) *rows_count_out = n;
    return true;
}

/* ── Cursor / digest state ────────────────────────────────────────── */

const char *op_return_index_state_version_name(
    enum op_return_index_state_version v)
{
    switch (v) {
    case OP_RETURN_INDEX_STATE_EMPTY:     return "empty";
    case OP_RETURN_INDEX_STATE_V2:        return "v2";
    case OP_RETURN_INDEX_STATE_LEGACY_V1: return "legacy_v1";
    case OP_RETURN_INDEX_STATE_UNKNOWN:   break;
    }
    return "unknown";
}

/* Read the raw v2 blob. *present=false when the key is absent. Returns
 * false when the key exists but is not a well-formed v2 record. */
static bool read_v2_record(struct node_db *ndb,
                           uint8_t rec[OP_RETURN_INDEX_STATE_RECORD_LEN],
                           bool *present)
{
    *present = false;
    /* One byte of slack so an OVER-long blob is detected rather than
     * silently truncated to a plausible record (node_db_state_get clamps
     * the copy to max_len and reports the clamped length). */
    uint8_t buf[OP_RETURN_INDEX_STATE_RECORD_LEN + 1];
    size_t len = 0;
    if (!node_db_state_get(ndb, OP_RETURN_INDEX_STATE_KEY_V2, buf,
                           sizeof(buf), &len))
        return true;                       /* absent — not an error */
    *present = true;
    if (len != OP_RETURN_INDEX_STATE_RECORD_LEN)
        return false;
    if (buf[0] != OP_RETURN_INDEX_STATE_VERSION_BYTE)
        return false;
    memcpy(rec, buf, OP_RETURN_INDEX_STATE_RECORD_LEN);
    return true;
}

enum op_return_index_state_version
op_return_index_state_version(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        return OP_RETURN_INDEX_STATE_UNKNOWN;

    uint8_t rec[OP_RETURN_INDEX_STATE_RECORD_LEN];
    bool present = false;
    if (!read_v2_record(ndb, rec, &present))
        return OP_RETURN_INDEX_STATE_UNKNOWN;
    if (present)
        return OP_RETURN_INDEX_STATE_V2;

    /* No v2 record. A v1 record left by an older binary is a DIFFERENT
     * object (genesis-rooted, no declared range) — refuse, never adopt. */
    int64_t legacy_h = 0;
    uint8_t legacy_d[32];
    size_t len = 0;
    if (node_db_state_get_int(ndb, OP_RETURN_INDEX_CURSOR_KEY_V1, &legacy_h) ||
        node_db_state_get(ndb, OP_RETURN_INDEX_DIGEST_KEY_V1, legacy_d,
                          sizeof(legacy_d), &len))
        return OP_RETURN_INDEX_STATE_LEGACY_V1;

    return OP_RETURN_INDEX_STATE_EMPTY;
}

bool op_return_index_get_cursor(struct node_db *ndb,
                                struct op_return_index_cursor *out)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("op_return_index", "get_cursor: db not open");
    if (!out)
        LOG_FAIL("op_return_index", "get_cursor: out is NULL");

    memset(out, 0, sizeof(*out));
    out->base_height = 0;
    out->height = -1;

    enum op_return_index_state_version v = op_return_index_state_version(ndb);
    switch (v) {
    case OP_RETURN_INDEX_STATE_EMPTY:
        return true;                       /* fresh chain — valid state */
    case OP_RETURN_INDEX_STATE_V2:
        break;
    case OP_RETURN_INDEX_STATE_LEGACY_V1:
    case OP_RETURN_INDEX_STATE_UNKNOWN:
        /* Loud refusal, never a silent reinterpretation: a v1 digest makes
         * a genesis-rooted claim this binary cannot verify or extend. The
         * operator's escape is `oprindex_rebuild` (op_return_index_
         * truncate), which drops the v1 record and re-derives. */
        LOG_FAIL("op_return_index",
                 "get_cursor: REFUSING persisted state version '%s' — this "
                 "binary writes op_return_index_state.v2 (range-declared "
                 "base_height+base_digest) and will not reinterpret an older "
                 "or unrecognized record as a v2 chain. Rebuild the catalog "
                 "(`z23 app oprindex rebuild`) to re-derive it.",
                 op_return_index_state_version_name(v));
    }

    uint8_t rec[OP_RETURN_INDEX_STATE_RECORD_LEN];
    bool present = false;
    if (!read_v2_record(ndb, rec, &present) || !present)
        LOG_FAIL("op_return_index",
                 "get_cursor: v2 record vanished or malformed between "
                 "classify and decode");

    out->base_height = (int32_t)zcl_read_i64_le(rec + 1);
    memcpy(out->base_digest, rec + 9, 32);
    out->height = (int32_t)zcl_read_i64_le(rec + 41);
    memcpy(out->digest, rec + 49, 32);
    return true;
}

bool op_return_index_set_cursor(struct node_db *ndb,
                                const struct op_return_index_cursor *cur)
{
    if (!ndb || !ndb->open || !cur)
        LOG_FAIL("op_return_index", "set_cursor: invalid args");
    if (cur->height < cur->base_height - 1)
        LOG_FAIL("op_return_index",
                 "set_cursor: height=%d is below base_height=%d - 1 — the "
                 "cursor may never sit outside its declared range",
                 cur->height, cur->base_height);

    uint8_t rec[OP_RETURN_INDEX_STATE_RECORD_LEN];
    rec[0] = OP_RETURN_INDEX_STATE_VERSION_BYTE;
    zcl_write_i64_le(rec + 1, (int64_t)cur->base_height);
    memcpy(rec + 9, cur->base_digest, 32);
    zcl_write_i64_le(rec + 41, (int64_t)cur->height);
    memcpy(rec + 49, cur->digest, 32);

    if (!node_db_state_set(ndb, OP_RETURN_INDEX_STATE_KEY_V2, rec,
                           sizeof(rec)))
        LOG_FAIL("op_return_index",
                 "set_cursor: failed to persist state base=%d height=%d",
                 cur->base_height, cur->height);
    return true;
}

bool op_return_index_get_cursor_heights(struct node_db *ndb,
                                        int32_t *out_height,
                                        int32_t *out_base_height)
{
    struct op_return_index_cursor cur;
    if (!op_return_index_get_cursor(ndb, &cur)) {
        if (out_height) *out_height = -1;
        if (out_base_height) *out_base_height = -1;
        return false;  // raw-return-ok:get_cursor already logged the refusal
    }
    if (out_height) *out_height = cur.height;
    if (out_base_height) *out_base_height = cur.base_height;
    return true;
}

bool op_return_index_prune_below(struct node_db *ndb, int32_t base_height)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("op_return_index", "prune_below: db not open");
    if (base_height <= 0)
        return true;                       /* nothing can be below height 0 */

    /* Was an snprintf'd statement ("... WHERE height<%d"). The value was a
     * machine-derived int32_t so it was never exploitable, but it was the
     * one place in the models layer where a value reached SQL as TEXT. The
     * builder binds it. */
    struct qb q;
    qb_delete(&q, QB_T_op_return_index);
    qb_where_int(&q, QB_C_op_return_index_height, QB_LT, base_height);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s))
        LOG_FAIL("op_return_index", "prune_below: %s", qb_error(&q));
    bool ok = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    node_db_note_activity(ndb, "op_return_index_prune_below",
                          ok ? SQLITE_OK : SQLITE_ERROR);
    if (!ok)
        LOG_FAIL("op_return_index",
                 "prune_below: DELETE below base_height=%d failed",
                 base_height);
    return true;
}

bool op_return_index_truncate(struct node_db *ndb)
{
    if (!ndb || !ndb->open)
        LOG_FAIL("op_return_index", "truncate: db not open");
    struct qb q;
    qb_delete(&q, QB_T_op_return_index);
    sqlite3_stmt *s = NULL;
    if (!QB_PREPARE(ndb, &q, s))
        LOG_FAIL("op_return_index", "truncate: %s", qb_error(&q));
    bool truncated = AR_STEP_DONE(s);
    AR_FINALIZE(s);
    /* This DELETE used to run through node_db_exec(), which records the
     * operation on the handle. Keep that observability. */
    node_db_note_activity(ndb, "op_return_index_truncate",
                          truncated ? SQLITE_OK : SQLITE_ERROR);
    if (!truncated)
        LOG_FAIL("op_return_index", "truncate: DELETE failed");
    struct op_return_index_cursor empty;
    memset(&empty, 0, sizeof(empty));
    empty.base_height = 0;
    empty.height = -1;
    if (!op_return_index_set_cursor(ndb, &empty))
        LOG_FAIL("op_return_index", "truncate: failed to reset cursor state");
    /* Retire any v1 record so the refusal above cannot survive a rebuild —
     * this is the operator's documented escape from a legacy record. */
    (void)node_db_state_delete(ndb, OP_RETURN_INDEX_CURSOR_KEY_V1);
    (void)node_db_state_delete(ndb, OP_RETURN_INDEX_DIGEST_KEY_V1);
    return true;
}

/* ── Queries ───────────────────────────────────────────────────────── */

int64_t op_return_index_count(struct node_db *ndb)
{
    if (!ndb || !ndb->open) return 0;
    struct qb q;
    qb_select(&q, QB_T_op_return_index);
    qb_select_count_star(&q);
    QB_QUERY_INT64(ndb, &q, s);
}

int64_t op_return_index_count_by_tag_text(struct node_db *ndb,
                                          const char *tag_text)
{
    if (!ndb || !ndb->open || !tag_text) return 0;
    struct qb q;
    qb_select(&q, QB_T_op_return_index);
    qb_select_count_star(&q);
    qb_where_text(&q, QB_C_op_return_index_tag_text, QB_EQ, tag_text);
    QB_QUERY_INT64(ndb, &q, s);
}

static void row_from_stmt(sqlite3_stmt *s, struct op_return_index_row *out)
{
    memset(out, 0, sizeof(*out));
    const void *txid = sqlite3_column_blob(s, 0);
    int txid_len = sqlite3_column_bytes(s, 0);
    if (txid && txid_len == 32) memcpy(out->txid, txid, 32);
    out->vout_n = (uint32_t)sqlite3_column_int(s, 1);
    out->height = sqlite3_column_int(s, 2);
    const void *tag = sqlite3_column_blob(s, 3);
    int tag_len = sqlite3_column_bytes(s, 3);
    if (tag && tag_len > 0 && tag_len <= OP_RETURN_INDEX_TAG_MAX) {
        memcpy(out->tag, tag, (size_t)tag_len);
        out->tag_len = (uint8_t)tag_len;
    }
    const char *tt = (const char *)sqlite3_column_text(s, 4);
    if (tt) snprintf(out->tag_text, sizeof(out->tag_text), "%s", tt);
    out->payload_len = (uint32_t)sqlite3_column_int(s, 5);
    const void *ps = sqlite3_column_blob(s, 6);
    int ps_len = sqlite3_column_bytes(s, 6);
    if (ps && ps_len == 32) memcpy(out->payload_sha3, ps, 32);
}

int op_return_index_query(struct node_db *ndb, int32_t h_min, int32_t h_max,
                          const char *tag_text_filter,
                          struct op_return_index_row *out, size_t max)
{
    if (!ndb || !ndb->open) return 0;
    if (!out && max > 0)
        LOG_RETURN(0, "op_return_index", "query: out is NULL");

    /* One statement with an OPTIONAL predicate, instead of two nearly
     * identical SQL literals that had to be kept in step by hand. */
    static const enum qb_column k_cols[] = {
        QB_C_op_return_index_txid,        QB_C_op_return_index_vout_n,
        QB_C_op_return_index_height,      QB_C_op_return_index_tag,
        QB_C_op_return_index_tag_text,    QB_C_op_return_index_payload_len,
        QB_C_op_return_index_payload_sha3,
    };
    struct qb q;
    qb_select(&q, QB_T_op_return_index);
    qb_select_columns(&q, k_cols, sizeof(k_cols) / sizeof(k_cols[0]));
    qb_where_int(&q, QB_C_op_return_index_height, QB_GE, h_min);
    qb_where_int(&q, QB_C_op_return_index_height, QB_LE, h_max);
    if (tag_text_filter && tag_text_filter[0])
        qb_where_text(&q, QB_C_op_return_index_tag_text, QB_EQ,
                      tag_text_filter);
    qb_order_by(&q, QB_C_op_return_index_height, QB_DESC);
    qb_order_by(&q, QB_C_op_return_index_txid, QB_ASC);
    qb_order_by(&q, QB_C_op_return_index_vout_n, QB_ASC);
    qb_limit(&q, (int64_t)max);
    QB_QUERY_LIST(ndb, &q, s, out, max, row_from_stmt(s, &out[count]));
}
