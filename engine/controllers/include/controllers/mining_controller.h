/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_MINING_H
#define ZCL_RPC_MINING_H

#include "rpc/server.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "coins/coins_view.h"

void rpc_mining_set_state(struct main_state *ms, struct tx_mempool *mp,
                           struct coins_view_cache *coins_tip);

void register_mining_rpc_commands(struct rpc_table *t);

#endif
