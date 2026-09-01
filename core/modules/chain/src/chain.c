/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "chain/chain.h"
#include <assert.h>

static inline int invert_lowest_one(int n) { return n & (n - 1); }

static inline int get_skip_height(int height)
{
    if (height < 2)
        return 0;
    return (height & 1) ? invert_lowest_one(invert_lowest_one(height - 1)) + 1
                        : invert_lowest_one(height);
}

struct block_index *block_index_get_ancestor(struct block_index *bi, int height)
{
    if (height > bi->nHeight || height < 0)
        return NULL;

    struct block_index *walk = bi;
    int h = bi->nHeight;
    while (h > height) {
        int skip_h = get_skip_height(h);
        int skip_h_prev = get_skip_height(h - 1);
        if (walk->pskip != NULL &&
            (skip_h == height ||
             (skip_h > height && !(skip_h_prev < skip_h - 2 &&
                                    skip_h_prev >= height)))) {
            walk = walk->pskip;
            h = skip_h;
        } else {
            if (!walk->pprev) return NULL;
            walk = walk->pprev;
            h--;
        }
    }
    return walk;
}

void block_index_build_skip(struct block_index *bi)
{
    if (bi->pprev)
        bi->pskip = block_index_get_ancestor(bi->pprev,
                                              get_skip_height(bi->nHeight));
}
