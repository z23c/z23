/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Synthetic active chain for MMB leaf-store tests: n block indexes with
 * distinct hashes, times, bits, sapling roots and chain work, installed as the
 * active chain window. */
#ifndef TEST_MMB_CHAIN_FIXTURE_H
#define TEST_MMB_CHAIN_FIXTURE_H

#include "chain/chain.h"
#include "validation/chainstate.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct mmb_chain_fixture {
    struct block_index *bi;
    struct uint256 *hashes;
    int n;
    struct active_chain chain;
};

static inline bool mmb_chain_fixture_init(struct mmb_chain_fixture *fx, int n)
{
    memset(fx, 0, sizeof(*fx));
    fx->bi = calloc((size_t)n, sizeof(*fx->bi));
    fx->hashes = calloc((size_t)n, sizeof(*fx->hashes));
    if (!fx->bi || !fx->hashes) {
        free(fx->bi);
        free(fx->hashes);
        memset(fx, 0, sizeof(*fx));
        return false;
    }
    fx->n = n;
    for (int i = 0; i < n; i++) {
        block_index_init(&fx->bi[i]);
        fx->hashes[i].data[0] = (unsigned char)(i & 0xFF);
        fx->hashes[i].data[1] = (unsigned char)((i >> 8) & 0xFF);
        fx->hashes[i].data[2] = 0x5a;
        fx->bi[i].phashBlock = &fx->hashes[i];
        fx->bi[i].nHeight = i;
        fx->bi[i].nTime = 1600000000u + (unsigned)i * 75u;
        fx->bi[i].nBits = 0x1d00ffffu;
        fx->bi[i].hashFinalSaplingRoot.data[0] = (unsigned char)(i * 7);
        fx->bi[i].nChainWork.pn[0] = (uint32_t)i + 1u;
        if (i > 0) fx->bi[i].pprev = &fx->bi[i - 1];
    }
    active_chain_init(&fx->chain);
    active_chain_move_window_tip(&fx->chain, &fx->bi[n - 1]);
    return true;
}

static inline void mmb_chain_fixture_free(struct mmb_chain_fixture *fx)
{
    active_chain_free(&fx->chain);
    free(fx->bi);
    free(fx->hashes);
    memset(fx, 0, sizeof(*fx));
}

#endif
