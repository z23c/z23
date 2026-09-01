/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_RAWTRANSACTION_H
#define ZCL_RPC_RAWTRANSACTION_H

#include "rpc/server.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "coins/coins_view.h"
#include "wallet/keystore.h"

void rpc_rawtx_set_state(struct main_state *ms, struct tx_mempool *mp,
                          struct coins_view_cache *coins_tip,
                          const char *datadir);
void rpc_rawtx_set_keystore(struct basic_keystore *ks);
struct connman;
void rpc_rawtx_set_connman(struct connman *cm);

void register_rawtransaction_rpc_commands(struct rpc_table *t);

#endif
