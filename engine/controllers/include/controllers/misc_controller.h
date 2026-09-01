/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_MISC_H
#define ZCL_RPC_MISC_H

#include "rpc/server.h"
#include "validation/main_state.h"

struct wallet;

void rpc_misc_set_state(struct main_state *ms);
void rpc_misc_set_wallet(struct wallet *w);
void register_misc_rpc_commands(struct rpc_table *t);

#endif
