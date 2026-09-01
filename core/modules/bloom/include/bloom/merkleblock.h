/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_MERKLEBLOCK_H
#define ZCL_MERKLEBLOCK_H

#include "bloom/merkle.h"
#include "primitives/block.h"
#include "core/serialize.h"
#include <stdbool.h>
#include <stddef.h>

#define MAX_MATCHED_TXN 4096

struct matched_txn {
    unsigned int index;
    struct uint256 hash;
};

struct merkle_block {
    struct block_header header;
    struct partial_merkle_tree txn;
    struct matched_txn *matched;
    size_t num_matched;
};

static inline void merkle_block_init(struct merkle_block *mb)
{
    block_header_init(&mb->header);
    merkle_tree_init(&mb->txn);
    mb->matched = NULL;
    mb->num_matched = 0;
}

static inline void merkle_block_free(struct merkle_block *mb)
{
    merkle_tree_free(&mb->txn);
    free(mb->matched);
    mb->matched = NULL;
    mb->num_matched = 0;
}

bool merkle_tree_serialize(const struct partial_merkle_tree *t,
                           struct byte_stream *s);
bool merkle_tree_deserialize(struct partial_merkle_tree *t,
                             struct byte_stream *s);

bool merkle_block_serialize(const struct merkle_block *mb,
                            struct byte_stream *s);
bool merkle_block_deserialize(struct merkle_block *mb,
                              struct byte_stream *s);

#endif
