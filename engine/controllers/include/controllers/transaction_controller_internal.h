/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal shared includes + raw-transaction context accessor for the
 * raw-transaction RPC controller. Included by transaction_controller*.c
 * only — not part of the public API. */

#ifndef ZCL_CONTROLLERS_TRANSACTION_CONTROLLER_INTERNAL_H
#define ZCL_CONTROLLERS_TRANSACTION_CONTROLLER_INTERNAL_H

#include "platform/time_compat.h"
#include "views/format_helpers.h"
#include "controllers/rpc_chainstate_guard.h"
#include "controllers/transaction_controller.h"
#include "controllers/strong_params.h"
#include "controllers/wallet_helpers.h"
#include "chain/chainparams.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "core/core_io.h"
#include "core/serialize.h"
#include "encoding/utilstrencodings.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "json/json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "storage/disk_block_io.h"
#include "storage/txdb.h"
#include "validation/check_transaction.h"
#include "validation/accept_to_mempool.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "coins/coins_view.h"
#include "models/database.h"
#include "models/utxo.h"
#include "net/connman.h"
#include "wallet/keystore.h"
#include "support/cleanse.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "util/log_macros.h"
#include "util/safe_alloc.h"

struct rawtx_context {
    struct main_state *main_state;
    struct tx_mempool *mempool;
    struct coins_view_cache *coins_tip;
    const char *datadir;
    char datadir_storage[4096];
    struct basic_keystore *keystore;
    struct connman *connman;
};

extern struct rawtx_context g_rawtx_ctx;

static inline struct rawtx_context *rawtx_ctx(void)
{
    return &g_rawtx_ctx;
}

static inline struct node_db *rawtx_node_db(void)
{
    return g_wallet_ctx.node_db;
}

/* transaction_controller_sign.c — signrawtransaction + its helpers */
bool rpc_signrawtransaction(const struct json_value *params, bool help,
                            struct json_value *result);

/* transaction_controller_wallet_lookup.c — bounded wallet/active-chain
 * fallbacks used while repairable transaction projections catch up. */
bool rawtx_find_in_wallet_db(struct rawtx_context *ctx,
                             const struct uint256 *hash,
                             struct transaction *tx,
                             struct uint256 *hash_block);
bool rawtx_find_by_wallet_note(struct rawtx_context *ctx,
                               const struct uint256 *hash,
                               struct transaction *tx,
                               struct uint256 *hash_block);
bool rawtx_find_in_recent_chain(struct rawtx_context *ctx,
                                const struct uint256 *hash,
                                struct transaction *tx,
                                struct uint256 *hash_block);
bool rawtx_find_in_wallet(struct rawtx_context *ctx,
                          const struct uint256 *hash,
                          struct transaction *tx,
                          struct uint256 *hash_block);
int64_t rawtx_confirmations(struct rawtx_context *ctx,
                            const struct uint256 *hash_block);

#endif /* ZCL_CONTROLLERS_TRANSACTION_CONTROLLER_INTERNAL_H */
