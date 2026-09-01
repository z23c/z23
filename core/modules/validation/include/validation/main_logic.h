/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_VALIDATION_MAIN_LOGIC_H
#define ZCL_VALIDATION_MAIN_LOGIC_H

#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "core/utiltime.h"
#include <stdbool.h>
#include <stdatomic.h>

static inline bool is_initial_block_download(struct main_state *ms)
{
    static _Atomic bool latched = false;
    if (atomic_load_explicit(&latched, memory_order_relaxed))
        return false;

    zcl_mutex_lock(&ms->cs_main);
    if (atomic_load_explicit(&latched, memory_order_relaxed)) {
        zcl_mutex_unlock(&ms->cs_main);
        return false;
    }
    if (atomic_load(&ms->fImporting) || atomic_load(&ms->fReindex)) {
        zcl_mutex_unlock(&ms->cs_main);
        return true;
    }
    const struct block_index *tip = active_chain_tip(&ms->chain_active);
    if (!tip) {
        zcl_mutex_unlock(&ms->cs_main);
        return true;
    }
    const struct chain_params *params = chain_params_get();
    struct arith_uint256 min_work;
    uint256_to_arith(&min_work, &params->consensus.nMinimumChainWork);
    if (arith_uint256_compare(&tip->nChainWork, &min_work) < 0) {
        zcl_mutex_unlock(&ms->cs_main);
        return true;
    }
    if (block_index_get_time(tip) < (GetTime() - ms->nMaxTipAge)) {
        zcl_mutex_unlock(&ms->cs_main);
        return true;
    }
    atomic_store_explicit(&latched, true, memory_order_relaxed);
    zcl_mutex_unlock(&ms->cs_main);
    return false;
}

#endif
