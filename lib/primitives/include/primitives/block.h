/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2013 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_PRIMITIVES_BLOCK_H
#define ZCL_PRIMITIVES_BLOCK_H

#include "core/uint256.h"
#include "primitives/transaction.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_HEADER_SIZE (4 + 32 + 32 + 32 + 4 + 4 + 32)
#define MAX_SOLUTION_SIZE 1344

struct block_header {
    int32_t nVersion;
    struct uint256 hashPrevBlock;
    struct uint256 hashMerkleRoot;
    struct uint256 hashFinalSaplingRoot;
    uint32_t nTime;
    uint32_t nBits;
    struct uint256 nNonce;
    unsigned char nSolution[MAX_SOLUTION_SIZE];
    size_t nSolutionSize;
};

static inline void block_header_init(struct block_header *h)
{
    memset(h, 0, sizeof(*h));
    h->nVersion = 4;
}

static inline bool block_header_is_null(const struct block_header *h)
{
    return h->nBits == 0;
}

static inline int64_t block_header_get_time(const struct block_header *h)
{
    return (int64_t)h->nTime;
}

struct byte_stream;

/* Serialize a header in canonical ZClassic wire order. Writes, in order:
 *   nVersion(i32 LE), hashPrevBlock(32), hashMerkleRoot(32),
 *   hashFinalSaplingRoot(32), nTime(u32 LE), nBits(u32 LE), nNonce(32),
 *   then a compact-size of nSolutionSize followed by exactly that many
 *   solution bytes (the Equihash solution is omitted entirely when
 *   nSolutionSize == 0). The fixed prefix is BLOCK_HEADER_SIZE bytes; the
 *   compact-size + solution are variable-length and NOT counted in that
 *   constant. Appends to `s`; returns false on the first stream write
 *   failure, leaving `s` partially written. */
bool block_header_serialize(const struct block_header *h, struct byte_stream *s);

/* Inverse of block_header_serialize, reading from the current `s` cursor.
 * DESERIALIZATION INVARIANT (consensus, must-never-fork): the compact-size
 * solution length is rejected with a logged failure (returns false) when it
 * exceeds MAX_SOLUTION_SIZE (1344) — this caps the fixed nSolution[] buffer
 * and bounds peer-supplied input. A short stream (truncated solution or any
 * fixed field) also returns false. On false `*h` is left partially filled;
 * callers must discard it. On success every field of `*h` is overwritten
 * (no field is preserved from a prior call). */
bool block_header_deserialize(struct block_header *h, struct byte_stream *s);

/* Block hash = HASH256 (double-SHA256, hash256()) over the canonical
 * header serialization, INCLUDING the compact-size + Equihash solution.
 * This is the PoW / block-identity hash; it depends on the full header
 * wire form, so two headers that serialize identically hash identically.
 * Output is the 32-byte little-endian internal form in out->data. */
void block_header_get_hash(const struct block_header *h, struct uint256 *out);

#define MAX_LOCATOR_HASHES 64

struct block_locator {
    struct uint256 *vhave;
    size_t num_hashes;
};

static inline void block_locator_init(struct block_locator *loc)
{
    loc->vhave = NULL;
    loc->num_hashes = 0;
}

static inline void block_locator_free(struct block_locator *loc)
{
    free(loc->vhave);
    loc->vhave = NULL;
    loc->num_hashes = 0;
}

/* CBlockLocator wire form: a fixed nVersion (the constant 170011 is written
 * verbatim here) followed by a compact-size vector of 32-byte hashes. */
bool block_locator_serialize(const struct block_locator *loc,
                             struct byte_stream *s);

/* Reads the leading nVersion and IGNORES it (deserialization is
 * version-agnostic for locators), then a compact-size count and that many
 * 32-byte hashes. DESERIALIZATION INVARIANT (P2P wire, not consensus):
 * legacy ZClassic/MagicBean peers routinely send one more hash than
 * MAX_LOCATOR_HASHES (64), and zclassicd's CBlockLocator has no count
 * limit, so an oversized count is TOLERATED — the first
 * MAX_LOCATOR_HASHES (tip-most) entries are kept and the remainder is
 * read and discarded, leaving the stream cursor on the trailing
 * hash_stop. The cap still bounds the allocation against hostile peers;
 * an overclaimed count fails on a short read. On success `loc->vhave` is
 * a freshly heap-allocated array of `loc->num_hashes` entries that the
 * caller owns and must release with block_locator_free; the prior contents
 * of `*loc` are overwritten (NOT freed) — pass a fresh/zeroed locator. */
bool block_locator_deserialize(struct block_locator *loc,
                               struct byte_stream *s);

#define MAX_BLOCK_SIZE 2000000
#define MAX_BLOCK_TRANSACTIONS 50000

struct block {
    struct block_header header;
    struct transaction *vtx;
    size_t num_vtx;
};

static inline void block_init(struct block *b)
{
    block_header_init(&b->header);
    b->vtx = NULL;
    b->num_vtx = 0;
}

static inline void block_free(struct block *b)
{
    if (b->vtx) {
        for (size_t i = 0; i < b->num_vtx; i++)
            transaction_free(&b->vtx[i]);
        free(b->vtx);
        b->vtx = NULL;
    }
    b->num_vtx = 0;
}

/* Full block wire form: the header serialization (block_header_serialize),
 * then a compact-size of num_vtx, then each transaction in order via
 * transaction_serialize. Appends to `s`; returns false on the first failed
 * field/tx, leaving `s` partially written. */
bool block_serialize(const struct block *b, struct byte_stream *s);

/* Inverse of block_serialize. DESERIALIZATION INVARIANT: the compact-size
 * transaction count is rejected with a logged failure (returns false) when
 * it exceeds MAX_BLOCK_TRANSACTIONS (50000), bounding the vtx allocation.
 * On success `b->vtx` is a freshly zcl_calloc'd array of `b->num_vtx`
 * transactions that the caller owns and must release via block_free; pass a
 * fresh/block_init'd block (prior vtx is overwritten, NOT freed). A short
 * stream or a malformed transaction returns false with `b` partially built —
 * still safe to block_free. */
bool block_deserialize(struct block *b, struct byte_stream *s);

/* Block hash == header hash: forwards to block_header_get_hash(&b->header).
 * The transaction list does NOT enter the block hash directly (it is bound
 * only through hashMerkleRoot inside the header). */
void block_get_hash(const struct block *b, struct uint256 *out);

/* Deep copy: `dst` is re-initialized (block_init), the header is copied
 * verbatim (it is a flat POD struct — fixed nSolution[] buffer, no pointers),
 * and `dst->vtx` is a freshly zcl_calloc'd array of `src->num_vtx`
 * transactions each produced by transaction_copy (a deep copy that allocates
 * its own vin/vout/shielded/joinsplit arrays). The result is byte-identical
 * under block_serialize to `src` (transaction_copy preserves every
 * wire-affecting field and copies tx->hash verbatim) and owns nothing in
 * common with `src` — caller releases `dst` with block_free exactly as for a
 * freshly block_deserialize'd block. Returns false on any allocation failure
 * with `dst` already freed to an empty, block_free-safe record. */
bool block_clone(struct block *dst, const struct block *src);

#endif
