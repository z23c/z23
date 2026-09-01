/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdlib.h>

bool block_header_serialize(const struct block_header *h, struct byte_stream *s)
{
    if (!stream_write_i32_le(s, h->nVersion)) return false;
    if (!stream_write_bytes(s, h->hashPrevBlock.data, 32)) return false;
    if (!stream_write_bytes(s, h->hashMerkleRoot.data, 32)) return false;
    if (!stream_write_bytes(s, h->hashFinalSaplingRoot.data, 32)) return false;
    if (!stream_write_u32_le(s, h->nTime)) return false;
    if (!stream_write_u32_le(s, h->nBits)) return false;
    if (!stream_write_bytes(s, h->nNonce.data, 32)) return false;
    if (!stream_write_compact_size(s, h->nSolutionSize)) return false;
    if (h->nSolutionSize > 0) {
        if (!stream_write_bytes(s, h->nSolution, h->nSolutionSize)) return false;
    }
    return true;
}

void block_header_get_hash(const struct block_header *h, struct uint256 *out)
{
    struct byte_stream s;
    stream_init(&s, 256);
    block_header_serialize(h, &s);
    hash256(s.data, s.size, out->data);
    stream_free(&s);
}

bool block_header_deserialize(struct block_header *h, struct byte_stream *s)
{
    if (!stream_read_i32_le(s, &h->nVersion)) return false;
    if (!stream_read_bytes(s, h->hashPrevBlock.data, 32)) return false;
    if (!stream_read_bytes(s, h->hashMerkleRoot.data, 32)) return false;
    if (!stream_read_bytes(s, h->hashFinalSaplingRoot.data, 32)) return false;
    if (!stream_read_u32_le(s, &h->nTime)) return false;
    if (!stream_read_u32_le(s, &h->nBits)) return false;
    if (!stream_read_bytes(s, h->nNonce.data, 32)) return false;
    uint64_t sol_size;
    if (!stream_read_compact_size(s, &sol_size)) return false;
    if (sol_size > MAX_SOLUTION_SIZE)
        LOG_FAIL("block", "Equihash solution size %llu exceeds MAX_SOLUTION_SIZE %d",
                 (unsigned long long)sol_size, MAX_SOLUTION_SIZE);
    h->nSolutionSize = (size_t)sol_size;
    if (h->nSolutionSize > 0) {
        if (!stream_read_bytes(s, h->nSolution, h->nSolutionSize)) return false;
    }
    return true;
}

bool block_serialize(const struct block *b, struct byte_stream *s)
{
    if (!block_header_serialize(&b->header, s)) return false;
    if (!stream_write_compact_size(s, b->num_vtx)) return false;
    for (size_t i = 0; i < b->num_vtx; i++) {
        if (!transaction_serialize(&b->vtx[i], s)) return false;
    }
    return true;
}

bool block_deserialize(struct block *b, struct byte_stream *s)
{
    if (!block_header_deserialize(&b->header, s)) return false;
    uint64_t count;
    if (!stream_read_compact_size(s, &count)) return false;
    if (count > MAX_BLOCK_TRANSACTIONS)
        LOG_FAIL("block", "tx count %llu exceeds MAX_BLOCK_TRANSACTIONS %d",
                 (unsigned long long)count, MAX_BLOCK_TRANSACTIONS);
    /* Reject before the calloc when the remaining stream cannot hold `count`
     * transactions. The smallest valid tx serialization is 10 bytes (4-byte
     * version + 1-byte vin count + 1-byte vout count + 4-byte lock_time).
     * count is already <=MAX_BLOCK_TRANSACTIONS(50000), so count*10 cannot
     * overflow. This refuses only counts the per-tx loop would fail to read
     * anyway (accept set unchanged) before the ~14 MB slot allocation. */
    if (count * 10 > stream_remaining(s))
        LOG_FAIL("block", "tx count %llu exceeds remaining bytes %zu (>=10/tx)",
                 (unsigned long long)count, stream_remaining(s));
    b->num_vtx = (size_t)count;
    b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "block_vtx");
    if (!b->vtx && b->num_vtx > 0)
        LOG_FAIL("block", "alloc failed for %zu tx slots", b->num_vtx);
    for (size_t i = 0; i < b->num_vtx; i++) {
        transaction_init(&b->vtx[i]);
        if (!transaction_deserialize(&b->vtx[i], s)) return false;
    }
    return true;
}

void block_get_hash(const struct block *b, struct uint256 *out)
{
    block_header_get_hash(&b->header, out);
}

bool block_clone(struct block *dst, const struct block *src)
{
    block_init(dst);
    /* The header is a flat POD struct (fixed nSolution[] buffer, no pointers),
     * so a struct copy is a complete deep copy of it. */
    dst->header = src->header;

    if (src->num_vtx == 0)
        return true; /* no vtx array to allocate; dst stays block_free-safe */

    dst->vtx = zcl_calloc(src->num_vtx, sizeof(struct transaction),
                          "block_clone_vtx");
    if (!dst->vtx) {
        block_free(dst);
        LOG_FAIL("block", "block_clone alloc failed for %zu tx slots",
                 src->num_vtx);
        return false; /* dst is block_free-safe; do NOT fall into the copy loop
                       * with dst->vtx == NULL (SIGSEGV on dst->vtx[0]). */
    }
    /* Set num_vtx incrementally so a mid-loop failure leaves dst with exactly
     * the entries that were successfully transaction_copy'd — block_free then
     * frees precisely those and the array, with no read of an uninitialized
     * (calloc-zeroed but not transaction_init'd) slot. */
    for (size_t i = 0; i < src->num_vtx; i++) {
        if (!transaction_copy(&dst->vtx[i], &src->vtx[i])) {
            block_free(dst);
            return false; /* transaction_copy already logged the cause */
        }
        dst->num_vtx = i + 1;
    }
    return true;
}

bool block_locator_serialize(const struct block_locator *loc,
                             struct byte_stream *s)
{
    /* CBlockLocator serializes nVersion + vector<uint256> */
    if (!stream_write_i32_le(s, 170011)) return false;
    if (!stream_write_compact_size(s, loc->num_hashes)) return false;
    for (size_t i = 0; i < loc->num_hashes; i++) {
        if (!stream_write_bytes(s, loc->vhave[i].data, 32)) return false;
    }
    return true;
}

bool block_locator_deserialize(struct block_locator *loc,
                               struct byte_stream *s)
{
    int32_t nVersion;
    if (!stream_read_i32_le(s, &nVersion)) return false;
    (void)nVersion;
    uint64_t count;
    if (!stream_read_compact_size(s, &count)) return false;
    /* Legacy ZClassic/MagicBean peers routinely send locators one entry past
     * MAX_LOCATOR_HASHES (65 observed on mainnet), and zclassicd's
     * CBlockLocator deserialization has no count limit at all — rejecting
     * here silently drops honest getblocks/getheaders requests (the peer
     * waits forever on a reply that never comes) and stalls its sync.
     * Tolerate instead: keep the first MAX_LOCATOR_HASHES (tip-most)
     * entries, which are the ones the common-ancestor scan needs, and
     * read-and-discard the remainder so the stream cursor still lands on
     * the trailing hash_stop. The cap still bounds the vhave allocation
     * against hostile peers; an overclaimed count simply fails on a short
     * read below. */
    if (count > MAX_LOCATOR_HASHES)
        LOG_WARN("block",
                 "locator hash count %llu exceeds MAX_LOCATOR_HASHES %d; "
                 "keeping tip-most %d and discarding %llu",
                 (unsigned long long)count, MAX_LOCATOR_HASHES,
                 MAX_LOCATOR_HASHES,
                 (unsigned long long)(count - MAX_LOCATOR_HASHES));
    loc->num_hashes = count < MAX_LOCATOR_HASHES ? (size_t)count
                                                 : MAX_LOCATOR_HASHES;
    loc->vhave = zcl_calloc(loc->num_hashes, sizeof(struct uint256), "locator_hashes");
    if (!loc->vhave && loc->num_hashes > 0)
        LOG_FAIL("block", "alloc failed for %zu locator hashes", loc->num_hashes);
    for (size_t i = 0; i < loc->num_hashes; i++) {
        if (!stream_read_bytes(s, loc->vhave[i].data, 32)) return false;
    }
    unsigned char discard[32];
    for (uint64_t i = loc->num_hashes; i < count; i++) {
        if (!stream_read_bytes(s, discard, 32)) return false;
    }
    return true;
}
