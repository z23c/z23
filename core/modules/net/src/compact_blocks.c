/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP152 Compact Block Relay — construction, reconstruction, serialization.
 *
 * SipHash-2-4 reference: Jean-Philippe Aumasson & Daniel J. Bernstein,
 * "SipHash: a fast short-input PRF" (2012). Public domain implementation
 * adapted from the reference C code. */

#include "net/compact_blocks.h"
#include "net/msg_bounds_guard.h"
#include "core/hash.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <string.h>
#include <stdio.h>

/* ── SipHash-2-4 ───────────────────────────────────────────────── */

static inline uint64_t rotl64(uint64_t x, int b)
{
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND do { \
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32); \
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32); \
} while (0)

uint64_t siphash_2_4(const uint8_t key[16],
                     const uint8_t *data, size_t len)
{
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);

    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t *end = data + len - (len % 8);
    size_t left = len & 7;

    for (const uint8_t *p = data; p < end; p += 8) {
        uint64_t m;
        memcpy(&m, p, 8);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }

    uint64_t b = (uint64_t)len << 56;
    switch (left) {
    case 7: b |= (uint64_t)end[6] << 48; /* fallthrough */
    case 6: b |= (uint64_t)end[5] << 40; /* fallthrough */
    case 5: b |= (uint64_t)end[4] << 32; /* fallthrough */
    case 4: b |= (uint64_t)end[3] << 24; /* fallthrough */
    case 3: b |= (uint64_t)end[2] << 16; /* fallthrough */
    case 2: b |= (uint64_t)end[1] << 8;  /* fallthrough */
    case 1: b |= (uint64_t)end[0]; break;
    case 0: break;
    }

    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;

    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

/* ── Key derivation ────────────────────────────────────────────── */

void compact_block_derive_key(const struct block_header *header,
                              uint64_t nonce,
                              uint8_t key_out[16])
{
    /* BIP152: key = SHA256d(header || nonce), take first 16 bytes.
     * Serialize the header, append the 8-byte LE nonce, double-SHA256. */
    struct byte_stream s;
    stream_init(&s, 2048);
    block_header_serialize(header, &s);
    stream_write_u64_le(&s, nonce);

    uint8_t hash[32];
    hash256(s.data, s.size, hash);
    memcpy(key_out, hash, 16);
    stream_free(&s);
}

/* ── Short txid computation ────────────────────────────────────── */

void compact_block_short_txid(const uint8_t siphash_key[16],
                              const struct uint256 *txhash,
                              uint8_t out[SHORT_TXID_LEN])
{
    /* BIP152: short_id = SipHash-2-4(txhash) & 0xFFFFFFFFFFFF (6 bytes LE) */
    uint64_t h = siphash_2_4(siphash_key, txhash->data, 32);
    memcpy(out, &h, SHORT_TXID_LEN);
}

/* ── Lifecycle ─────────────────────────────────────────────────── */

void compact_block_msg_init(struct compact_block_msg *cb)
{
    memset(cb, 0, sizeof(*cb));
    block_header_init(&cb->header);
}

void compact_block_msg_free(struct compact_block_msg *cb)
{
    free(cb->short_txids);
    cb->short_txids = NULL;
    cb->num_short_txids = 0;
    if (cb->prefilled) {
        for (size_t i = 0; i < cb->num_prefilled; i++)
            transaction_free(&cb->prefilled[i].tx);
        free(cb->prefilled);
        cb->prefilled = NULL;
    }
    cb->num_prefilled = 0;
}

void block_txn_request_init(struct block_txn_request *req)
{
    memset(req, 0, sizeof(*req));
}

void block_txn_request_free(struct block_txn_request *req)
{
    free(req->indices);
    req->indices = NULL;
    req->num_indices = 0;
}

void block_txn_response_init(struct block_txn_response *resp)
{
    memset(resp, 0, sizeof(*resp));
}

void block_txn_response_free(struct block_txn_response *resp)
{
    if (resp->txs) {
        for (size_t i = 0; i < resp->num_txs; i++)
            transaction_free(&resp->txs[i]);
        free(resp->txs);
        resp->txs = NULL;
    }
    resp->num_txs = 0;
}

/* ── Construction ──────────────────────────────────────────────── */

bool compact_block_from_block(struct compact_block_msg *cb,
                              const struct block *blk,
                              uint64_t nonce)
{
    if (!blk || blk->num_vtx == 0)
        LOG_FAIL("compact", "cannot build compact block from empty block");

    compact_block_msg_init(cb);
    cb->header = blk->header;
    cb->nonce = nonce;

    /* Derive SipHash key */
    compact_block_derive_key(&cb->header, nonce, cb->siphash_key);

    /* Prefill coinbase (index 0) — always required by BIP152 */
    cb->num_prefilled = 1;
    cb->prefilled = zcl_calloc(1, sizeof(struct prefilled_tx), "compact_prefilled");
    if (!cb->prefilled)
        LOG_FAIL("compact", "alloc failed for prefilled tx");
    cb->prefilled[0].index = 0;
    if (!transaction_copy(&cb->prefilled[0].tx, &blk->vtx[0])) {
        free(cb->prefilled);
        cb->prefilled = NULL;
        cb->num_prefilled = 0;
        LOG_FAIL("compact", "failed to copy coinbase tx");
    }

    /* Short txids for all non-prefilled transactions */
    size_t num_short = blk->num_vtx - 1;  /* skip coinbase */
    cb->num_short_txids = num_short;
    if (num_short > 0) {
        cb->short_txids = zcl_malloc(num_short * SHORT_TXID_LEN, "compact_short_txids");
        if (!cb->short_txids) {
            compact_block_msg_free(cb);
            LOG_FAIL("compact", "alloc failed for %zu short txids", num_short);
        }
        for (size_t i = 0; i < num_short; i++) {
            /* Ensure tx hash is computed */
            struct uint256 txhash = blk->vtx[i + 1].hash;
            if (uint256_is_null(&txhash)) {
                struct transaction tmp;
                transaction_init(&tmp);
                transaction_copy(&tmp, &blk->vtx[i + 1]);
                transaction_compute_hash(&tmp);
                txhash = tmp.hash;
                transaction_free(&tmp);
            }
            compact_block_short_txid(cb->siphash_key, &txhash,
                                     &cb->short_txids[i * SHORT_TXID_LEN]);
        }
    }
    return true;
}

/* ── Reconstruction ────────────────────────────────────────────── */

/* Short-id lookup table: open addressing, linear probe (same idiom as
 * download.c's qset). Built once per cmpctblock so reconstruction costs
 * O(sources + slots) SipHash instead of O(slots * sources) — a hostile
 * peer must not be able to pin a core by pairing 50k short ids with a
 * large mempool. src < num_mempool indexes mempool_txs; otherwise
 * extra_txs[src - num_mempool]. */
struct cb_sid_entry {
    uint64_t sid;    /* 48-bit BIP152 short id */
    size_t src;
    uint8_t state;   /* 0=empty, 1=live, 2=ambiguous (short-id collision) */
};

/* Short ids are compared as the same 6 wire bytes compact_block_short_txid
 * emits, packed LE, so table keys and wire targets agree by construction. */
static uint64_t cb_sid_from_bytes(const uint8_t b[SHORT_TXID_LEN])
{
    uint64_t v = 0;
    for (size_t i = 0; i < SHORT_TXID_LEN; i++)
        v |= (uint64_t)b[i] << (8 * i);
    return v;
}

static const struct transaction *cb_src_tx(size_t src,
                                           const struct transaction *mempool_txs,
                                           size_t num_mempool,
                                           const struct transaction *extra_txs)
{
    return src < num_mempool ? &mempool_txs[src]
                             : &extra_txs[src - num_mempool];
}

/* Table is sized to load factor <= 1/2, so probing always reaches an
 * empty slot. BIP152: two distinct txs sharing a short id make the id
 * ambiguous — mark it so lookup misses and the slot is fetched via
 * getblocktxn instead of guessing (a first-match guess can reconstruct
 * a wrong block that then fails validation). */
static void cb_sid_insert(struct cb_sid_entry *tab, size_t slots,
                          uint64_t sid, size_t src,
                          const struct transaction *mempool_txs,
                          size_t num_mempool,
                          const struct transaction *extra_txs)
{
    size_t mask = slots - 1;
    for (size_t i = 0; i < slots; i++) {
        struct cb_sid_entry *e = &tab[(sid + i) & mask];
        if (e->state == 0) {
            e->sid = sid;
            e->src = src;
            e->state = 1;
            return;
        }
        if (e->sid == sid) {
            if (e->state == 1) {
                const struct transaction *a =
                    cb_src_tx(e->src, mempool_txs, num_mempool, extra_txs);
                const struct transaction *b =
                    cb_src_tx(src, mempool_txs, num_mempool, extra_txs);
                if (memcmp(a->hash.data, b->hash.data, 32) != 0)
                    e->state = 2;
            }
            return;
        }
    }
}

static bool cb_sid_lookup(const struct cb_sid_entry *tab, size_t slots,
                          uint64_t sid, size_t *src_out)
{
    if (!tab || slots == 0)
        return false;
    size_t mask = slots - 1;
    for (size_t i = 0; i < slots; i++) {
        const struct cb_sid_entry *e = &tab[(sid + i) & mask];
        if (e->state == 0)
            return false;
        if (e->sid == sid) {
            if (e->state != 1)
                return false;   /* ambiguous: resolve via getblocktxn */
            *src_out = e->src;
            return true;
        }
    }
    return false;
}

bool compact_block_reconstruct(const struct compact_block_msg *cb,
                               const struct transaction *mempool_txs,
                               size_t num_mempool_txs,
                               const struct transaction *extra_txs,
                               size_t num_extra_txs,
                               struct block *out_block,
                               uint64_t **missing_indices,
                               size_t *num_missing)
{
    *missing_indices = NULL;
    *num_missing = 0;

    /* Initialize out_block BEFORE the first thing that can fail. Every
     * caller block_free()s it on the not-complete/no-missing path, so a
     * return that leaves it untouched hands block_free() whatever the
     * caller's stack happened to hold — a stale pointer plus a stale
     * count, i.e. a wild walk through transaction_free(). That is not
     * theoretical: a peer-supplied cmpctblock carrying zero short txids
     * and zero prefilled txs makes total == 0 and takes exactly this
     * return. See tests/harness/fuzz_seeds/p2p/crash-478b30c0...bin. */
    block_init(out_block);

    /* Total txs = prefilled + short_txids */
    size_t total = cb->num_prefilled + cb->num_short_txids;
    if (total == 0 || total > MAX_COMPACT_BLOCK_TXNS)
        LOG_FAIL("compact", "invalid compact block tx count: %zu", total);

    out_block->header = cb->header;
    out_block->num_vtx = total;
    out_block->vtx = zcl_calloc(total, sizeof(struct transaction), "compact_reconstruct");
    if (!out_block->vtx)
        LOG_FAIL("compact", "alloc failed for %zu reconstructed txs", total);

    /* Initialize all tx slots */
    for (size_t i = 0; i < total; i++)
        transaction_init(&out_block->vtx[i]);

    /* Place prefilled transactions at their absolute positions.
     * BIP152 uses differential encoding, so we convert to absolute. */
    bool *filled = zcl_calloc(total, sizeof(bool), "compact_filled_map");
    if (!filled) {
        block_free(out_block);
        LOG_FAIL("compact", "alloc failed for filled bitmap");
    }

    uint64_t abs_idx = 0;
    for (size_t i = 0; i < cb->num_prefilled; i++) {
        abs_idx += cb->prefilled[i].index;
        if (i > 0) abs_idx++;  /* BIP152 differential: add 1 for non-first */
        if (abs_idx >= total) {
            free(filled);
            block_free(out_block);
            LOG_FAIL("compact", "prefilled index %lu out of range (total=%zu)",
                     (unsigned long)abs_idx, total);
        }
        if (!transaction_copy(&out_block->vtx[abs_idx], &cb->prefilled[i].tx)) {
            free(filled);
            block_free(out_block);
            LOG_FAIL("compact", "failed to copy prefilled tx %zu", i);
        }
        filled[abs_idx] = true;
    }

    /* Hash mempool + extra short ids ONCE (table bounded by source
     * count), then resolve each slot with an O(1) lookup. */
    size_t num_sources = num_mempool_txs + num_extra_txs;
    struct cb_sid_entry *sid_tab = NULL;
    size_t sid_slots = 0;
    if (num_sources > 0) {
        sid_slots = 16;
        while (sid_slots < num_sources * 2)
            sid_slots <<= 1;
        sid_tab = zcl_calloc(sid_slots, sizeof(*sid_tab), "compact_sid_table");
        if (!sid_tab) {
            free(filled);
            block_free(out_block);
            LOG_FAIL("compact", "alloc failed for %zu short-id slots", sid_slots);
        }
        for (size_t i = 0; i < num_sources; i++) {
            const struct transaction *tx =
                cb_src_tx(i, mempool_txs, num_mempool_txs, extra_txs);
            uint8_t sidb[SHORT_TXID_LEN];
            compact_block_short_txid(cb->siphash_key, &tx->hash, sidb);
            cb_sid_insert(sid_tab, sid_slots, cb_sid_from_bytes(sidb), i,
                          mempool_txs, num_mempool_txs, extra_txs);
        }
    }

    size_t short_idx = 0;
    for (size_t slot = 0; slot < total; slot++) {
        if (filled[slot])
            continue;

        if (short_idx >= cb->num_short_txids) {
            free(sid_tab);
            free(filled);
            block_free(out_block);
            LOG_FAIL("compact", "ran out of short txids at slot %zu", slot);
        }

        const uint8_t *target = &cb->short_txids[short_idx * SHORT_TXID_LEN];
        size_t src;
        if (cb_sid_lookup(sid_tab, sid_slots, cb_sid_from_bytes(target), &src)) {
            const struct transaction *tx =
                cb_src_tx(src, mempool_txs, num_mempool_txs, extra_txs);
            if (!transaction_copy(&out_block->vtx[slot], tx)) {
                free(sid_tab);
                free(filled);
                block_free(out_block);
                LOG_FAIL("compact", "failed to copy source tx %zu", src);
            }
            filled[slot] = true;
        }

        short_idx++;
    }
    free(sid_tab);

    /* Collect missing indices */
    size_t miss_count = 0;
    for (size_t i = 0; i < total; i++) {
        if (!filled[i])
            miss_count++;
    }

    if (miss_count > 0) {
        *missing_indices = zcl_malloc(miss_count * sizeof(uint64_t), "compact_missing");
        if (!*missing_indices) {
            free(filled);
            block_free(out_block);
            LOG_FAIL("compact", "alloc failed for %zu missing indices", miss_count);
        }
        *num_missing = miss_count;
        size_t mi = 0;
        for (size_t i = 0; i < total; i++) {
            if (!filled[i])
                (*missing_indices)[mi++] = i;
        }
    }

    free(filled);
    return miss_count == 0;
}

bool compact_block_fill_missing(struct block *partial_block,
                                const struct block_txn_response *resp,
                                const uint64_t *missing_indices,
                                size_t num_missing)
{
    if (resp->num_txs != num_missing)
        LOG_FAIL("compact", "blocktxn response has %zu txs, expected %zu",
                 resp->num_txs, num_missing);

    for (size_t i = 0; i < num_missing; i++) {
        uint64_t idx = missing_indices[i];
        if (idx >= partial_block->num_vtx)
            LOG_FAIL("compact", "missing index %lu out of range", (unsigned long)idx);
        transaction_free(&partial_block->vtx[idx]);
        if (!transaction_copy(&partial_block->vtx[idx], &resp->txs[i]))
            LOG_FAIL("compact", "failed to copy blocktxn tx %zu", i);
    }
    return true;
}

/* ── Serialization: compact block ──────────────────────────────── */

bool compact_block_msg_serialize(const struct compact_block_msg *cb,
                                 struct byte_stream *s)
{
    if (!block_header_serialize(&cb->header, s))
        LOG_FAIL("compact", "failed to serialize header");
    if (!stream_write_u64_le(s, cb->nonce))
        LOG_FAIL("compact", "failed to write nonce");

    /* Short txids */
    if (!stream_write_compact_size(s, cb->num_short_txids))
        LOG_FAIL("compact", "failed to write short txid count");
    for (size_t i = 0; i < cb->num_short_txids; i++) {
        if (!stream_write_bytes(s, &cb->short_txids[i * SHORT_TXID_LEN], SHORT_TXID_LEN))
            LOG_FAIL("compact", "failed to write short txid %zu", i);
    }

    /* Prefilled transactions (differential index encoding) */
    if (!stream_write_compact_size(s, cb->num_prefilled))
        LOG_FAIL("compact", "failed to write prefilled count");

    uint64_t last_abs = 0;
    for (size_t i = 0; i < cb->num_prefilled; i++) {
        uint64_t abs = cb->prefilled[i].index;
        uint64_t diff = (i == 0) ? abs : (abs - last_abs - 1);
        if (!stream_write_compact_size(s, diff))
            LOG_FAIL("compact", "failed to write prefilled diff index %zu", i);
        if (!transaction_serialize(&cb->prefilled[i].tx, s))
            LOG_FAIL("compact", "failed to serialize prefilled tx %zu", i);
        last_abs = abs;
    }
    return true;
}

bool compact_block_msg_deserialize(struct compact_block_msg *cb,
                                   struct byte_stream *s)
{
    compact_block_msg_init(cb);

    if (!block_header_deserialize(&cb->header, s))
        LOG_FAIL("compact", "failed to deserialize header");
    if (!stream_read_u64_le(s, &cb->nonce))
        LOG_FAIL("compact", "failed to read nonce");

    /* Derive SipHash key */
    compact_block_derive_key(&cb->header, cb->nonce, cb->siphash_key);

    /* Short txids */
    uint64_t num_short;
    if (!stream_read_compact_size(s, &num_short))
        LOG_FAIL("compact", "failed to read short txid count");
    if (msg_count_exceeds("compact", "short txids", num_short,
                          MAX_COMPACT_BLOCK_TXNS, NULL))
        return false;
    cb->num_short_txids = (size_t)num_short;
    if (num_short > 0) {
        cb->short_txids = zcl_malloc(num_short * SHORT_TXID_LEN, "compact_deser_stxids");
        if (!cb->short_txids) {
            compact_block_msg_free(cb);
            LOG_FAIL("compact", "alloc failed for %lu short txids", (unsigned long)num_short);
        }
        for (size_t i = 0; i < (size_t)num_short; i++) {
            if (!stream_read_bytes(s, &cb->short_txids[i * SHORT_TXID_LEN], SHORT_TXID_LEN)) {
                compact_block_msg_free(cb);
                LOG_FAIL("compact", "failed to read short txid %zu", i);
            }
        }
    }

    /* Prefilled transactions */
    uint64_t num_prefilled;
    if (!stream_read_compact_size(s, &num_prefilled)) {
        compact_block_msg_free(cb);
        LOG_FAIL("compact", "failed to read prefilled count");
    }
    if (msg_count_exceeds("compact", "prefilled txs", num_prefilled,
                          MAX_COMPACT_BLOCK_TXNS, NULL)) {
        compact_block_msg_free(cb);
        return false;
    }
    cb->num_prefilled = (size_t)num_prefilled;
    if (num_prefilled > 0) {
        cb->prefilled = zcl_calloc(num_prefilled, sizeof(struct prefilled_tx),
                                    "compact_deser_prefilled");
        if (!cb->prefilled) {
            compact_block_msg_free(cb);
            LOG_FAIL("compact", "alloc failed for %lu prefilled txs",
                     (unsigned long)num_prefilled);
        }
        uint64_t abs_idx = 0;
        for (size_t i = 0; i < (size_t)num_prefilled; i++) {
            uint64_t diff;
            if (!stream_read_compact_size(s, &diff)) {
                compact_block_msg_free(cb);
                LOG_FAIL("compact", "failed to read prefilled diff index %zu", i);
            }
            abs_idx += diff;
            if (i > 0) abs_idx++;
            cb->prefilled[i].index = (uint16_t)abs_idx;
            transaction_init(&cb->prefilled[i].tx);
            if (!transaction_deserialize(&cb->prefilled[i].tx, s)) {
                compact_block_msg_free(cb);
                LOG_FAIL("compact", "failed to deserialize prefilled tx %zu", i);
            }
        }
    }
    return true;
}

/* ── Serialization: getblocktxn ────────────────────────────────── */

bool block_txn_request_serialize(const struct block_txn_request *req,
                                 struct byte_stream *s)
{
    if (!stream_write_bytes(s, req->block_hash.data, 32))
        LOG_FAIL("compact", "failed to write blocktxn request hash");

    /* BIP152: differential index encoding */
    if (!stream_write_compact_size(s, req->num_indices))
        LOG_FAIL("compact", "failed to write index count");

    uint64_t last = 0;
    for (size_t i = 0; i < req->num_indices; i++) {
        uint64_t diff = (i == 0) ? req->indices[i] : (req->indices[i] - last - 1);
        if (!stream_write_compact_size(s, diff))
            LOG_FAIL("compact", "failed to write index diff %zu", i);
        last = req->indices[i];
    }
    return true;
}

bool block_txn_request_deserialize(struct block_txn_request *req,
                                   struct byte_stream *s)
{
    block_txn_request_init(req);

    if (!stream_read_bytes(s, req->block_hash.data, 32))
        LOG_FAIL("compact", "failed to read blocktxn request hash");

    uint64_t count;
    if (!stream_read_compact_size(s, &count))
        LOG_FAIL("compact", "failed to read index count");
    if (msg_count_exceeds("compact", "blocktxn indices", count,
                          MAX_GETBLOCKTXN_INDICES, NULL))
        return false;

    req->num_indices = (size_t)count;
    if (count > 0) {
        req->indices = zcl_malloc(count * sizeof(uint64_t), "compact_req_indices");
        if (!req->indices)
            LOG_FAIL("compact", "alloc failed for %lu indices", (unsigned long)count);

        uint64_t abs = 0;
        for (size_t i = 0; i < (size_t)count; i++) {
            uint64_t diff;
            if (!stream_read_compact_size(s, &diff)) {
                block_txn_request_free(req);
                LOG_FAIL("compact", "failed to read index diff %zu", i);
            }
            abs += diff;
            if (i > 0) abs++;
            req->indices[i] = abs;
        }
    }
    return true;
}

/* ── Serialization: blocktxn ───────────────────────────────────── */

bool block_txn_response_serialize(const struct block_txn_response *resp,
                                  struct byte_stream *s)
{
    if (!stream_write_bytes(s, resp->block_hash.data, 32))
        LOG_FAIL("compact", "failed to write blocktxn response hash");
    if (!stream_write_compact_size(s, resp->num_txs))
        LOG_FAIL("compact", "failed to write tx count");
    for (size_t i = 0; i < resp->num_txs; i++) {
        if (!transaction_serialize(&resp->txs[i], s))
            LOG_FAIL("compact", "failed to serialize blocktxn tx %zu", i);
    }
    return true;
}

bool block_txn_response_deserialize(struct block_txn_response *resp,
                                    struct byte_stream *s)
{
    block_txn_response_init(resp);

    if (!stream_read_bytes(s, resp->block_hash.data, 32))
        LOG_FAIL("compact", "failed to read blocktxn response hash");

    uint64_t count;
    if (!stream_read_compact_size(s, &count))
        LOG_FAIL("compact", "failed to read tx count");
    if (msg_count_exceeds("compact", "blocktxn txs", count,
                          MAX_COMPACT_BLOCK_TXNS, NULL))
        return false;

    resp->num_txs = (size_t)count;
    if (count > 0) {
        resp->txs = zcl_calloc(count, sizeof(struct transaction), "compact_resp_txs");
        if (!resp->txs)
            LOG_FAIL("compact", "alloc failed for %lu txs", (unsigned long)count);

        for (size_t i = 0; i < (size_t)count; i++) {
            transaction_init(&resp->txs[i]);
            if (!transaction_deserialize(&resp->txs[i], s)) {
                block_txn_response_free(resp);
                LOG_FAIL("compact", "failed to deserialize blocktxn tx %zu", i);
            }
        }
    }
    return true;
}
