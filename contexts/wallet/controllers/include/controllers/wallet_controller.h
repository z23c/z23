/* Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_WALLET_RPC_H
#define ZCL_RPC_WALLET_RPC_H

#include "rpc/server.h"

struct wallet;
struct main_state;
struct wallet_sqlite;
struct tx_mempool;
struct connman;
struct node_db;
struct coins_view_cache;

void rpc_wallet_set_state(struct wallet *w, struct main_state *ms,
                          const char *datadir, struct wallet_sqlite *wdb,
                          struct tx_mempool *mempool,
                          struct connman *connman);
void rpc_wallet_set_coins_tip(struct coins_view_cache *tip);
void rpc_wallet_set_node_db(struct node_db *ndb);
void register_wallet_rpc_commands(struct rpc_table *t);

/* Direct C API for wallet view controller (no RPC round-trip) */
bool wallet_direct_sendtoaddress(const char *address, int64_t amount_sat,
                                  char *txid_out, size_t txid_out_size,
                                  char *error_out, size_t error_out_size);

/* Mint a fresh transparent receive address, persisted BEFORE it is returned.
 * Same implementation as getnewaddress — the store's transparent order path
 * needs an address it can bind an order to, and one that is not durable would
 * lose the buyer's payment on the next restart. `addr_out` must be >= 80
 * bytes. On refusal returns false with the reason in `err_out` and an empty
 * `addr_out`; never returns an address it could not persist. */
bool wallet_direct_getnewaddress(char *addr_out, size_t addr_max,
                                 char *err_out, size_t err_max);

/* Mint 1..50 transparent receive addresses with bounded incremental key
 * persistence. Every returned address is backed by an encrypted persisted
 * private key before this returns; on failure all outputs are empty and no
 * unpersisted direct-generated key is left in the wallet. This is the fanout
 * path's bounded batch primitive. */
#define WALLET_DIRECT_ADDRESS_MAX 128
#define WALLET_DIRECT_ADDRESS_BATCH_MAX 50
bool wallet_direct_getnewaddresses(
    char (*addresses)[WALLET_DIRECT_ADDRESS_MAX], size_t count,
    char *err_out, size_t err_max);

#endif
