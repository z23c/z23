/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "bloom/merkle.h"
#include "core/hash.h"
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"

void merkle_tree_init(struct partial_merkle_tree *t)
{
    t->num_transactions = 0;
    t->bits = NULL;
    t->num_bits = 0;
    t->hashes = NULL;
    t->num_hashes = 0;
    t->bad = false;
}

void merkle_tree_free(struct partial_merkle_tree *t)
{
    free(t->bits);
    free(t->hashes);
    t->bits = NULL;
    t->hashes = NULL;
    t->num_bits = 0;
    t->num_hashes = 0;
}

void merkle_hash_pair(const struct uint256 *left, const struct uint256 *right,
                      struct uint256 *out)
{
    unsigned char combined[64];
    memcpy(combined, left->data, 32);
    memcpy(combined + 32, right->data, 32);
    hash256(combined, 64, out->data);
}

static unsigned int calc_tree_width(unsigned int n_transactions, int height)
{
    return (n_transactions + (1u << height) - 1) >> height;
}

static struct uint256 calc_hash(unsigned int n_tx, int height, unsigned int pos,
                                const struct uint256 *txids)
{
    if (height == 0)
        return txids[pos];

    struct uint256 left = calc_hash(n_tx, height - 1, pos * 2, txids);
    struct uint256 right;
    if (pos * 2 + 1 < calc_tree_width(n_tx, height - 1))
        right = calc_hash(n_tx, height - 1, pos * 2 + 1, txids);
    else
        right = left;

    struct uint256 result;
    merkle_hash_pair(&left, &right, &result);
    return result;
}

struct build_state {
    unsigned char *bits;
    size_t num_bits;
    size_t bits_cap;
    struct uint256 *hashes;
    size_t num_hashes;
    size_t hashes_cap;
};

static void build_add_bit(struct build_state *s, bool bit)
{
    if (s->num_bits >= s->bits_cap) return;
    s->bits[s->num_bits++] = bit ? 1 : 0;
}

static void build_add_hash(struct build_state *s, struct uint256 h)
{
    if (s->num_hashes >= s->hashes_cap) return;
    s->hashes[s->num_hashes++] = h;
}

static void traverse_and_build(unsigned int n_tx, int height, unsigned int pos,
                               const struct uint256 *txids, const bool *match,
                               struct build_state *s)
{
    bool parent_of_match = false;
    unsigned int start = pos << height;
    unsigned int end = (pos + 1) << height;
    for (unsigned int p = start; p < end && p < n_tx; p++)
        parent_of_match |= match[p];

    build_add_bit(s, parent_of_match);

    if (height == 0 || !parent_of_match) {
        build_add_hash(s, calc_hash(n_tx, height, pos, txids));
    } else {
        traverse_and_build(n_tx, height - 1, pos * 2, txids, match, s);
        if (pos * 2 + 1 < calc_tree_width(n_tx, height - 1))
            traverse_and_build(n_tx, height - 1, pos * 2 + 1, txids, match, s);
    }
}

bool merkle_tree_build(struct partial_merkle_tree *t,
                       const struct uint256 *txids, size_t num_txids,
                       const bool *match, size_t num_match)
{
    if (num_txids == 0 || num_txids != num_match || num_txids > MAX_MERKLE_HASHES)
        return false;

    t->num_transactions = (unsigned int)num_txids;
    t->bad = false;

    int height = 0;
    while (calc_tree_width((unsigned int)num_txids, height) > 1)
        height++;

    struct build_state s;
    s.bits_cap = MAX_MERKLE_BITS;
    s.bits = zcl_calloc(s.bits_cap, 1, "merkle_build_bits");
    s.num_bits = 0;
    s.hashes_cap = num_txids;
    s.hashes = zcl_calloc(s.hashes_cap, sizeof(struct uint256), "merkle_build_hashes");
    s.num_hashes = 0;

    if (!s.bits || !s.hashes) {
        free(s.bits);
        free(s.hashes);
        return false;
    }

    traverse_and_build((unsigned int)num_txids, height, 0, txids, match, &s);

    free(t->bits);
    free(t->hashes);
    t->bits = s.bits;
    t->num_bits = s.num_bits;
    t->hashes = s.hashes;
    t->num_hashes = s.num_hashes;
    return true;
}

static struct uint256 traverse_and_extract(struct partial_merkle_tree *t,
                                           int height, unsigned int pos,
                                           unsigned int *bits_used,
                                           unsigned int *hash_used,
                                           struct uint256 *matched,
                                           size_t *num_matched,
                                           size_t matched_cap)
{
    struct uint256 zero;
    uint256_set_null(&zero);

    if (*bits_used >= t->num_bits) {
        t->bad = true;
        return zero;
    }

    bool parent_of_match = t->bits[(*bits_used)++];

    if (height == 0 || !parent_of_match) {
        if (*hash_used >= t->num_hashes) {
            t->bad = true;
            return zero;
        }
        struct uint256 h = t->hashes[(*hash_used)++];
        if (height == 0 && parent_of_match) {
            if (*num_matched < matched_cap)
                matched[(*num_matched)++] = h;
        }
        return h;
    }

    struct uint256 left = traverse_and_extract(t, height - 1, pos * 2,
                                               bits_used, hash_used,
                                               matched, num_matched, matched_cap);
    struct uint256 right;
    if (pos * 2 + 1 < calc_tree_width(t->num_transactions, height - 1)) {
        right = traverse_and_extract(t, height - 1, pos * 2 + 1,
                                     bits_used, hash_used,
                                     matched, num_matched, matched_cap);
        if (uint256_cmp(&right, &left) == 0)
            t->bad = true;
    } else {
        right = left;
    }

    struct uint256 result;
    merkle_hash_pair(&left, &right, &result);
    return result;
}

bool merkle_tree_extract(struct partial_merkle_tree *t,
                         struct uint256 *matched_out, size_t *num_matched,
                         struct uint256 *merkle_root_out)
{
    *num_matched = 0;

    if (t->num_transactions == 0 || t->num_hashes > t->num_transactions ||
        t->num_bits < t->num_hashes)
        return false;

    int height = 0;
    while (calc_tree_width(t->num_transactions, height) > 1)
        height++;

    unsigned int bits_used = 0, hash_used = 0;
    size_t matched_cap = t->num_transactions;
    t->bad = false;

    *merkle_root_out = traverse_and_extract(t, height, 0, &bits_used, &hash_used,
                                            matched_out, num_matched, matched_cap);

    if (t->bad) return false;
    if ((bits_used + 7) / 8 != (t->num_bits + 7) / 8) return false;
    if (hash_used != t->num_hashes) return false;
    return true;
}

struct uint256 compute_merkle_root(const struct uint256 *txids, size_t count)
{
    bool unused;
    return compute_merkle_root_mutated(txids, count, &unused);
}

struct uint256 compute_merkle_root_mutated(const struct uint256 *txids,
                                           size_t count, bool *mutated)
{
    *mutated = false;
    struct uint256 zero;
    uint256_set_null(&zero);
    if (count == 0) return zero;
    if (count == 1) return txids[0];

    size_t level_size = count;
    struct uint256 *level = zcl_malloc(level_size * sizeof(struct uint256), "merkle_level");
    if (!level) return zero;
    memcpy(level, txids, count * sizeof(struct uint256));

    while (level_size > 1) {
        size_t next_size = (level_size + 1) / 2;
        for (size_t i = 0; i < level_size; i += 2) {
            size_t i2 = (i + 1 < level_size) ? i + 1 : level_size - 1;
            if (i2 == i + 1 && i2 + 1 == level_size &&
                uint256_eq(&level[i], &level[i2])) {
                *mutated = true;
            }
            merkle_hash_pair(&level[i], &level[i2], &level[i / 2]);
        }
        level_size = next_size;
    }

    struct uint256 root = level[0];
    free(level);
    return root;
}
