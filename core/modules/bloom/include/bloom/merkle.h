/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_MERKLE_H
#define ZCL_MERKLE_H

#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_MERKLE_HASHES 65536
#define MAX_MERKLE_BITS (MAX_MERKLE_HASHES * 2)

struct partial_merkle_tree {
    unsigned int num_transactions;
    unsigned char *bits;
    size_t num_bits;
    struct uint256 *hashes;
    size_t num_hashes;
    bool bad;
};

void merkle_tree_init(struct partial_merkle_tree *t);
void merkle_tree_free(struct partial_merkle_tree *t);

bool merkle_tree_build(struct partial_merkle_tree *t,
                       const struct uint256 *txids, size_t num_txids,
                       const bool *match, size_t num_match);

bool merkle_tree_extract(struct partial_merkle_tree *t,
                         struct uint256 *matched_out, size_t *num_matched,
                         struct uint256 *merkle_root_out);

void merkle_hash_pair(const struct uint256 *left, const struct uint256 *right,
                      struct uint256 *out);

struct uint256 compute_merkle_root(const struct uint256 *txids, size_t count);
struct uint256 compute_merkle_root_mutated(const struct uint256 *txids,
                                           size_t count, bool *mutated);

#endif
