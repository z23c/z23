/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chainstate_legacy_reader.c — see header for the API contract.
 *
 * On-disk format (Bitcoin Core 0.8+, used unchanged by zclassicd):
 *
 *   key:   'c' || <32-byte txid in raw byte order>
 *   value: VARINT(version)
 *          VARINT(code)          -- bits: cb=1, avail0=2, avail1=4,
 *                                          rest -> nMaskCode
 *          <mask bytes>          -- one byte per 8 vouts past index 1
 *                                   (continues until nMaskCode non-zero
 *                                    mask bytes have been seen)
 *          for each available vout (in ascending vout-index order):
 *              VARINT(compressed_amount)
 *              VARINT(nSize)
 *              if nSize < 6  : GetSpecialSize(nSize) bytes (compressed
 *                              P2PKH / P2SH / P2PK form)
 *              else           : nSize - 6 raw script bytes
 *          VARINT(height)
 *
 * Best-block hash is stored under the single-byte key 'B'.
 *
 * We deobfuscate via the existing dbwrapper layer (it auto-reads the
 * "obfuscate_key" record on open), reuse compressor.c's amount + script
 * decompression, and reuse serialize.c's Bitcoin-style varint reader.
 */

#include "storage/chainstate_legacy_reader.h"

#include "coins_record_codec.h"
#include "core/serialize.h"
#include "sapling/incremental_merkle_tree.h"
#include "script/script.h"
#include "storage/dbwrapper.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

/* --- handle --- */

struct chainstate_legacy_handle {
    struct db_wrapper db;
    /* Decode scratch reused across records to avoid alloc churn. */
    struct legacy_coins_vout *vouts_buf;
    size_t vouts_cap;
    /* Decompressed script storage — each vout points into here. */
    struct script *scripts_buf;
    size_t scripts_cap;
    struct coins_record_scratch codec_scratch;
};

/* --- helpers --- */

static bool ensure_vouts_cap(struct chainstate_legacy_handle *h, size_t n)
{
    if (n <= h->vouts_cap) return true;
    size_t cap = h->vouts_cap ? h->vouts_cap : 4;
    while (cap < n) cap *= 2;
    struct legacy_coins_vout *p =
        zcl_realloc(h->vouts_buf, cap * sizeof(*p),
                    "chainstate_legacy_vouts");
    if (!p) return false;
    struct script *q =
        zcl_realloc(h->scripts_buf, cap * sizeof(*q),
                    "chainstate_legacy_scripts");
    if (!q) return false;
    h->vouts_buf = p;
    h->scripts_buf = q;
    h->vouts_cap = cap;
    h->scripts_cap = cap;
    return true;
}

struct chainstate_decode_ctx {
    struct chainstate_legacy_handle *h;
    struct legacy_coins *out;
    size_t live_idx;
};

static bool chainstate_decode_begin(const struct coins_record_header *hdr,
                                    void *ctx)
{
    struct chainstate_decode_ctx *c = (struct chainstate_decode_ctx *)ctx;
    if (!hdr || !c || !c->h || !c->out)
        return false;
    if (!ensure_vouts_cap(c->h, hdr->live_outputs ? hdr->live_outputs : 1))
        return false;
    c->live_idx = 0;
    return true;
}

static bool chainstate_decode_output(const struct coins_record_output *out,
                                     void *ctx)
{
    struct chainstate_decode_ctx *c = (struct chainstate_decode_ctx *)ctx;
    if (!out || !c || !c->h || !c->out || c->live_idx >= c->h->vouts_cap)
        return false;

    struct script *sc = &c->h->scripts_buf[c->live_idx];
    script_set(sc, out->script, out->script_len);

    c->h->vouts_buf[c->live_idx].n = out->vout;
    c->h->vouts_buf[c->live_idx].value = out->value;
    c->h->vouts_buf[c->live_idx].script = sc->data;
    c->h->vouts_buf[c->live_idx].script_len = sc->size;
    c->live_idx++;
    return true;
}

/* Decode a single CCoins record into the handle's scratch.  Returns
 * true on success and fills *out (which borrows from the handle's
 * scratch — valid until the next decode). */
static bool decode_record(struct chainstate_legacy_handle *h,
                          const uint8_t *val, size_t vlen,
                          struct legacy_coins *out)
{
    struct chainstate_decode_ctx ctx = {
        .h = h,
        .out = out,
        .live_idx = 0,
    };
    struct coins_record_decode_options opts = {
        .mode = COINS_RECORD_DECODE_CHAINSTATE_LEGACY,
        .max_outputs = 0,
        .scratch = &h->codec_scratch,
    };
    struct coins_record_decode_ops ops = {
        .begin = chainstate_decode_begin,
        .output = chainstate_decode_output,
    };
    struct coins_record_decode_result res;
    enum coins_record_decode_status st =
        coins_record_decode(val, vlen, &opts, &ops, &ctx, &res);
    if (st != COINS_RECORD_DECODE_OK)
        LOG_FAIL("chainstate_legacy", "CCoins decode failed: %s",
                 coins_record_decode_status_name(st));

    out->version  = res.version;
    out->coinbase = res.is_coinbase;
    out->height   = res.height;
    out->vouts    = h->vouts_buf;
    out->num_vouts = ctx.live_idx;
    return true;
}

/* --- public API --- */

bool chainstate_legacy_open(const char *chainstate_path, void **out_handle)
{
    if (!chainstate_path || !out_handle)
        LOG_FAIL("chainstate_legacy", "open: NULL arg");

    struct chainstate_legacy_handle *h =
        zcl_malloc(sizeof(*h), "chainstate_legacy_handle");
    if (!h) LOG_FAIL("chainstate_legacy", "malloc handle");
    memset(h, 0, sizeof(*h));

    /* cache_size=8MB, memory=false, wipe=false.  No write traffic from
     * us — read-only walk. */
    if (!db_wrapper_open(&h->db, chainstate_path, 8u << 20, false, false)) {
        free(h);
        LOG_FAIL("chainstate_legacy", "db_wrapper_open failed");
    }

    /* Pre-size scratch for the common case (one vout). */
    if (!ensure_vouts_cap(h, 4)) {
        db_wrapper_close(&h->db);
        free(h);
        LOG_FAIL("chainstate_legacy", "init scratch alloc");
    }

    *out_handle = h;
    return true;
}

void chainstate_legacy_close(void *handle)
{
    if (!handle) return;
    struct chainstate_legacy_handle *h = handle;
    db_wrapper_close(&h->db);
    free(h->vouts_buf);
    free(h->scripts_buf);
    coins_record_scratch_free(&h->codec_scratch);
    free(h);
}

bool chainstate_legacy_get_best_block(void *handle, struct uint256 *out)
{
    if (!handle || !out)
        LOG_FAIL("chainstate_legacy", "get_best_block: NULL arg");
    struct chainstate_legacy_handle *h = handle;

    const char key = 'B';
    char *val = NULL;
    size_t vlen = 0;
    if (!db_read(&h->db, &key, 1, &val, &vlen) || !val) {
        if (val) free(val);
        LOG_FAIL("chainstate_legacy", "'B' key not found");
    }
    if (vlen != 32) {
        free(val);
        LOG_FAIL("chainstate_legacy", "'B' value not 32 bytes");
    }
    memcpy(out->data, val, 32);
    free(val);
    return true;
}

/* ── Historical Sapling anchor lookup ─────────────────────────────────
 *
 * ATTRIBUTION.  The zcashd/zclassicd chainstate anchor key schema
 * (DB_SAPLING_ANCHOR = 'Z', value = serialized SaplingMerkleTree) is
 * derived from the Zcash reference implementation:
 *   Copyright (c) The Zcash developers / Electric Coin Company
 *   zcash/src/txdb.cpp (`static const char DB_SAPLING_ANCHOR = 'Z';`)
 *   MIT / Apache-2.0.
 * This is a clean-room C23 reader over our own dbwrapper + the
 * boost::optional-compatible incremental_tree_deserialize; the reference
 * C++ is a format oracle only and is never linked into the binary. */
enum chainstate_anchor_result chainstate_legacy_get_sapling_anchor(
    void *handle, const struct uint256 *root,
    struct incremental_merkle_tree *tree_out)
{
    if (!handle || !root || !tree_out) {
        LOG_ERR("chainstate_legacy", "get_sapling_anchor: NULL arg");
        return CHAINSTATE_ANCHOR_ERROR;
    }
    struct chainstate_legacy_handle *h = handle;

    /* key = 'Z' || root (raw 32 bytes) */
    char key[33];
    key[0] = 'Z';
    memcpy(key + 1, root->data, 32);

    char *val = NULL;
    size_t vlen = 0;
    if (!db_read(&h->db, key, sizeof(key), &val, &vlen)) {
        if (val) free(val);
        return CHAINSTATE_ANCHOR_MISSING;   /* absent root, not an error */
    }
    if (!val || vlen == 0) {
        if (val) free(val);
        return CHAINSTATE_ANCHOR_MISSING;
    }

    struct byte_stream s;
    stream_init_from_data(&s, (const unsigned char *)val, vlen);
    sapling_tree_init(tree_out);
    if (!incremental_tree_deserialize(tree_out, &s) ||
        stream_remaining(&s) != 0) {
        /* Fail-closed on a short/torn record OR trailing bytes after a valid
         * tree — matches the bulk iterator's completeness bar so a forged blob
         * that merely prefixes a real tree cannot slip through. */
        free(val);
        LOG_ERR("chainstate_legacy",
                "get_sapling_anchor: deserialize failed / trailing bytes "
                "(vlen=%zu)", vlen);
        return CHAINSTATE_ANCHOR_ERROR;
    }
    free(val);

    /* Fail-closed: the deserialized tree's own computed root MUST equal the
     * key we looked it up under.  A borrowed tree is never returned unless
     * it hashes back to the requested anchor. */
    struct uint256 computed;
    incremental_tree_root(tree_out, &computed);
    if (memcmp(computed.data, root->data, 32) != 0) {
        LOG_ERR("chainstate_legacy",
                "get_sapling_anchor: root mismatch (stored tree does not hash "
                "back to key) — refusing");
        return CHAINSTATE_ANCHOR_ERROR;
    }
    return CHAINSTATE_ANCHOR_FOUND;
}

int64_t chainstate_legacy_iter(void *handle,
                               legacy_chainstate_cb cb,
                               void *ctx)
{
    if (!handle || !cb)
        return -1;
    struct chainstate_legacy_handle *h = handle;

    struct db_iterator it;
    db_iter_init(&it, &h->db);

    /* Seek to the start of the 'c' keyspace. */
    const char seek_key = 'c';
    db_iter_seek(&it, &seek_key, 1);

    int64_t count = 0;
    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 1 || k[0] != 'c') break;
        if (klen != 33) {
            /* malformed 'c' record — skip but don't fail the whole
             * scan (gives operators a chance to inspect). */
            db_iter_next(&it);
            continue;
        }

        struct uint256 txid;
        memcpy(txid.data, k + 1, 32);

        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        if (!v || vlen == 0) {
            db_iter_next(&it);
            continue;
        }

        struct legacy_coins coins = (struct legacy_coins){0};
        if (!decode_record(h, (const uint8_t *)v, vlen, &coins)) {
            db_iter_free(&it);
            return -1;
        }

        if (!cb(&txid, &coins, ctx)) {
            db_iter_free(&it);
            return count + 1; /* callback "consumed" this record */
        }

        count++;
        db_iter_next(&it);
    }

    /* A torn SST, block-CRC mismatch, or I/O error ends iteration early —
     * db_iter_valid() goes false and we would otherwise return a
     * silently-truncated UTXO set. That short set becomes the SHA3 boot seed
     * (engine/entry/main.c), which is exactly the torn-coins class that wedges the
     * reducer. Refuse it. (Mirrors node_db_import_service.c's check.) */
    if (!db_iter_check_error(&it)) {
        db_iter_free(&it);
        return -1;
    }

    db_iter_free(&it);
    return count;
}

/* ── Bulk historical anchor + nullifier iteration ─────────────────────
 *
 * ATTRIBUTION. The chainstate key schema iterated below (DB_SPROUT_ANCHOR='A',
 * DB_SAPLING_ANCHOR='Z', DB_SAPLING_NULLIFIER='S', DB_NULLIFIER='s',
 * DB_BEST_SAPLING_ANCHOR='z', DB_BEST_SPROUT_ANCHOR='a') is ported from the
 * Zcash reference implementation (zcash/src/txdb.cpp; MIT / Apache-2.0). This
 * is a clean-room C23 reader over our own dbwrapper + the boost::optional-
 * compatible incremental tree codec; the reference C++ is a format oracle only
 * and is never linked into the binary. */

/* Hard ceiling on rows a single anchor/nullifier keyspace walk will import.
 * Real ZClassic mainnet has ~3.17M blocks total and shielded pool usage is a
 * small fraction of that (see test_chainstate_legacy_reader's [400k..2M]
 * UTXO-record sanity band for the order of magnitude) — this cap is several
 * orders of magnitude above any real dataset. It exists purely to fail closed
 * on a corrupted or pathological chainstate (e.g. a torn/looping key range)
 * with a NAMED refusal instead of an unbounded walk — never a silent
 * truncation: the caller (shielded_history_import_service.c) treats any -1
 * here as "roll back the whole atomic import, cursors stay positive". */
#define LEGACY_CHAINSTATE_ITER_MAX_ROWS 50000000LL

/* Shared anchor-keyspace walker. `prefix` is 'Z' (Sapling) or 'A' (Sprout);
 * `is_sprout` selects the tree init/depth. FAIL-CLOSED on every anomaly:
 * returns -1 without delivering a partial verified set. */
/* `verify_root`: when true, recompute each stored tree's Pedersen root and
 * refuse a mismatch (the sovereign fail-closed check). When false (bulk import
 * of zclassicd's complete historical set), SKIP that per-anchor recompute: the
 * O(anchors × Pedersen-hash) cost is intractable on the real mainnet anchor set
 * (~14 min pegged, gdb: incremental_tree_root→pedersen_merkle_hash). The
 * byte-integrity floor still holds — leveldb block-CRC (verify_checksums=ON),
 * a successful incremental_tree_deserialize, and stream_remaining()==0 — and the
 * anchor's root IS its key. Historical anchor tree CONTENTS are not
 * consensus-load-bearing (ZClassic headers commit none of them); only PRESENCE
 * of each root and the TIP FRONTIER are, and the caller must Pedersen-verify the
 * tip frontier once against the header-committed hashFinalSaplingRoot. This is
 * the release-assisted trust boundary; the fully-sovereign path folds from
 * genesis. */
static int64_t iter_anchor_keyspace(struct chainstate_legacy_handle *h,
                                    char prefix, bool is_sprout, bool verify_root,
                                    legacy_anchor_cb cb, void *ctx)
{
    if (!h || !cb)
        return -1;

    struct db_iterator it;
    db_iter_init(&it, &h->db);
    db_iter_seek(&it, &prefix, 1);

    int64_t count = 0;
    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 1 || k[0] != prefix)
            break;
        if (count >= LEGACY_CHAINSTATE_ITER_MAX_ROWS) {
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "anchor iter '%c': row count reached the %lld sane cap — "
                    "refusing (pathological/corrupt chainstate?)", prefix,
                    (long long)LEGACY_CHAINSTATE_ITER_MAX_ROWS);
        }
        if (klen != 33) {
            /* A stray non-33 key inside the anchor prefix is a corrupt/foreign
             * record; a completeness-critical import cannot silently skip it. */
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "anchor iter '%c': malformed key length=%zu — refusing",
                    prefix, klen);
        }

        struct uint256 root;
        memcpy(root.data, k + 1, 32);

        size_t vlen = 0;
        const char *v = db_iter_value(&it, &vlen);
        if (!v || vlen == 0) {
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "anchor iter '%c': empty value — refusing", prefix);
        }

        struct incremental_merkle_tree tree;
        if (is_sprout)
            sprout_tree_init(&tree);
        else
            sapling_tree_init(&tree);
        struct byte_stream s;
        stream_init_from_data(&s, (const unsigned char *)v, vlen);
        if (!incremental_tree_deserialize(&tree, &s) ||
            stream_remaining(&s) != 0) {
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "anchor iter '%c': deserialize failed vlen=%zu — refusing",
                    prefix, vlen);
        }

        /* Fail-closed: the stored tree MUST hash back to its own key, exactly
         * like the point lookup (a torn/forged tree cannot pass). Skipped on the
         * bulk-import path (see iter_anchor_keyspace header) — byte-integrity is
         * still enforced above and the tip frontier is verified by the caller. */
        if (verify_root) {
            struct uint256 computed;
            incremental_tree_root(&tree, &computed);
            if (memcmp(computed.data, root.data, 32) != 0) {
                db_iter_free(&it);
                LOG_ERR("chainstate_legacy",
                        "anchor iter '%c': root mismatch (stored tree does not "
                        "hash to key) — refusing", prefix);
            }
        }

        if (!cb(&root, &tree, ctx)) {
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "anchor iter '%c': consumer refused record — aborting",
                    prefix);
        }
        count++;
        db_iter_next(&it);
    }

    if (!db_iter_check_error(&it)) {
        db_iter_free(&it);
        LOG_ERR("chainstate_legacy",
                "anchor iter '%c': torn SST / status error — refusing", prefix);
    }
    db_iter_free(&it);
    return count;
}

int64_t chainstate_legacy_iter_sapling_anchors(void *handle,
                                               legacy_anchor_cb cb, void *ctx)
{
    return iter_anchor_keyspace(handle, 'Z', false, true, cb, ctx);
}

int64_t chainstate_legacy_iter_sprout_anchors(void *handle,
                                              legacy_anchor_cb cb, void *ctx)
{
    return iter_anchor_keyspace(handle, 'A', true, true, cb, ctx);
}

/* Bulk-import variants: skip the per-anchor Pedersen root recompute (see
 * iter_anchor_keyspace header). The caller MUST Pedersen-verify the tip frontier
 * against the header-committed root separately. */
int64_t chainstate_legacy_iter_sapling_anchors_bulk(void *handle,
                                                    legacy_anchor_cb cb, void *ctx)
{
    return iter_anchor_keyspace(handle, 'Z', false, false, cb, ctx);
}

int64_t chainstate_legacy_iter_sprout_anchors_bulk(void *handle,
                                                   legacy_anchor_cb cb, void *ctx)
{
    return iter_anchor_keyspace(handle, 'A', true, false, cb, ctx);
}

/* Shared nullifier-keyspace walker. `prefix` is 'S' (Sapling) or 's' (Sprout).
 * The chainstate value is presence-only; the key IS the spent marker. */
static int64_t iter_nullifier_keyspace(struct chainstate_legacy_handle *h,
                                       char prefix, legacy_nullifier_cb cb,
                                       void *ctx)
{
    if (!h || !cb)
        return -1;

    struct db_iterator it;
    db_iter_init(&it, &h->db);
    db_iter_seek(&it, &prefix, 1);

    int64_t count = 0;
    while (db_iter_valid(&it)) {
        size_t klen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 1 || k[0] != prefix)
            break;
        if (count >= LEGACY_CHAINSTATE_ITER_MAX_ROWS) {
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "nullifier iter '%c': row count reached the %lld sane cap "
                    "— refusing (pathological/corrupt chainstate?)", prefix,
                    (long long)LEGACY_CHAINSTATE_ITER_MAX_ROWS);
        }
        if (klen != 33) {
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "nullifier iter '%c': malformed key length=%zu — refusing",
                    prefix, klen);
        }
        uint8_t nf[32];
        memcpy(nf, k + 1, 32);
        if (!cb(nf, ctx)) {
            db_iter_free(&it);
            LOG_ERR("chainstate_legacy",
                    "nullifier iter '%c': consumer refused — aborting", prefix);
        }
        count++;
        db_iter_next(&it);
    }

    if (!db_iter_check_error(&it)) {
        db_iter_free(&it);
        LOG_ERR("chainstate_legacy",
                "nullifier iter '%c': torn SST / status error — refusing",
                prefix);
    }
    db_iter_free(&it);
    return count;
}

int64_t chainstate_legacy_iter_sapling_nullifiers(void *handle,
                                                  legacy_nullifier_cb cb,
                                                  void *ctx)
{
    return iter_nullifier_keyspace(handle, 'S', cb, ctx);
}

int64_t chainstate_legacy_iter_sprout_nullifiers(void *handle,
                                                 legacy_nullifier_cb cb,
                                                 void *ctx)
{
    return iter_nullifier_keyspace(handle, 's', cb, ctx);
}

static bool get_best_anchor_pointer(void *handle, char key_byte,
                                    struct uint256 *root_out)
{
    if (root_out)
        uint256_set_null(root_out);
    if (!handle || !root_out)
        LOG_FAIL("chainstate_legacy", "get_best_anchor: NULL arg");
    struct chainstate_legacy_handle *h = handle;

    char *val = NULL;
    size_t vlen = 0;
    if (!db_read(&h->db, &key_byte, 1, &val, &vlen) || !val) {
        if (val) free(val);
        return false;   /* absent pointer = empty pool, not an error */
    }
    if (vlen != 32) {
        free(val);
        LOG_FAIL("chainstate_legacy",
                 "get_best_anchor '%c': value not 32 bytes (%zu)",
                 key_byte, vlen);
    }
    memcpy(root_out->data, val, 32);
    free(val);
    return true;
}

bool chainstate_legacy_get_best_sapling_anchor(void *handle,
                                               struct uint256 *root_out)
{
    return get_best_anchor_pointer(handle, 'z', root_out);
}

bool chainstate_legacy_get_best_sprout_anchor(void *handle,
                                              struct uint256 *root_out)
{
    return get_best_anchor_pointer(handle, 'a', root_out);
}
