/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_MINING_GEN_H
#define ZCL_MINING_GEN_H

#include "mining/miner.h"
#include "script/script.h"
#include <stdbool.h>
#include <stdatomic.h>

typedef bool (*gen_block_found_fn)(struct block *pblock, void *ctx);

struct gen_context {
    struct main_state *ms;
    struct coins_view_cache *coins_tip;
    struct tx_mempool *mempool;
    const struct chain_params *params;
    struct script coinbase_script;
    gen_block_found_fn block_found;
    void *block_found_ctx;
    int num_threads;
    _Atomic bool running;
};

void gen_start(struct gen_context *ctx);
void gen_stop(struct gen_context *ctx);

#endif
