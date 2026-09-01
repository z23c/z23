/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "bloom/merkleblock.h"
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

bool merkle_tree_serialize(const struct partial_merkle_tree *t,
                           struct byte_stream *s)
{
    if (!stream_write_u32_le(s, t->num_transactions)) return false;

    if (!stream_write_compact_size(s, t->num_hashes)) return false;
    for (size_t i = 0; i < t->num_hashes; i++)
        if (!stream_write_bytes(s, t->hashes[i].data, 32)) return false;

    size_t num_bytes = (t->num_bits + 7) / 8;
    unsigned char *packed = zcl_calloc(num_bytes > 0 ? num_bytes : 1, 1, "merkle_packed_bits");
    if (!packed) return false;
    for (size_t p = 0; p < t->num_bits; p++)
        packed[p / 8] |= (unsigned char)(t->bits[p] << (p % 8));
    if (!stream_write_compact_size(s, num_bytes)) { free(packed); return false; }
    bool ok = stream_write_bytes(s, packed, num_bytes);
    free(packed);
    return ok;
}

bool merkle_tree_deserialize(struct partial_merkle_tree *t,
                             struct byte_stream *s)
{
    merkle_tree_free(t);

    if (!stream_read_u32_le(s, &t->num_transactions)) return false;

    uint64_t num_hashes;
    if (!stream_read_compact_size(s, &num_hashes)) return false;
    if (num_hashes > MAX_MERKLE_HASHES) return false;
    t->num_hashes = (size_t)num_hashes;
    t->hashes = zcl_calloc(t->num_hashes > 0 ? t->num_hashes : 1,
                           sizeof(struct uint256), "merkle_hashes");
    if (!t->hashes) return false;
    for (size_t i = 0; i < t->num_hashes; i++)
        if (!stream_read_bytes(s, t->hashes[i].data, 32)) return false;

    uint64_t num_bytes;
    if (!stream_read_compact_size(s, &num_bytes)) return false;
    if (num_bytes > MAX_MERKLE_BITS / 8) return false;
    unsigned char *packed = zcl_calloc((size_t)num_bytes > 0 ? (size_t)num_bytes : 1, 1, "merkle_packed_read");
    if (!packed) return false;
    if (!stream_read_bytes(s, packed, (size_t)num_bytes)) { free(packed); return false; }

    t->num_bits = (size_t)num_bytes * 8;
    t->bits = zcl_calloc(t->num_bits > 0 ? t->num_bits : 1, 1, "merkle_bits");
    if (!t->bits) { free(packed); return false; }
    for (size_t p = 0; p < t->num_bits; p++)
        t->bits[p] = (packed[p / 8] >> (p % 8)) & 1;
    free(packed);

    t->bad = false;
    return true;
}

bool merkle_block_serialize(const struct merkle_block *mb,
                            struct byte_stream *s)
{
    if (!block_header_serialize(&mb->header, s)) return false;
    if (!merkle_tree_serialize(&mb->txn, s)) return false;
    return true;
}

bool merkle_block_deserialize(struct merkle_block *mb,
                              struct byte_stream *s)
{
    if (!block_header_deserialize(&mb->header, s)) return false;
    if (!merkle_tree_deserialize(&mb->txn, s)) return false;
    return true;
}
