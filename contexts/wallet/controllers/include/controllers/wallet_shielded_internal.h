/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal shared includes + handler declarations for the Sapling
 * shielded wallet RPC controller. Included by wallet_shielded_*.c
 * files only — not part of the public API. The public registration
 * entry point stays in controllers/wallet_shielded_controller.h. */

#ifndef ZCL_CONTROLLERS_WALLET_SHIELDED_INTERNAL_H
#define ZCL_CONTROLLERS_WALLET_SHIELDED_INTERNAL_H

#include "platform/time_compat.h"
#include "controllers/wallet_shielded_controller.h"
#include "controllers/wallet_helpers.h"
#include "controllers/strong_params.h"
#include "views/format_helpers.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "chain/chainparams.h"
#include "encoding/utilmoneystr.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "keys/key_io.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "core/utiltime.h"
#include "core/random.h"
#include "core/serialize.h"
#include "validation/main_state.h"
#include "validation/sighash.h"
#include "validation/txmempool.h"
#include "wallet/wallet_sqlite.h"
#include "net/connman.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"
#include "sapling/incremental_merkle_tree.h"
#include "sapling/sapling_prover.h"
#include "consensus/upgrades.h"
#include "services/wallet_backup_service.h"
#include "models/database.h"
#include "models/block.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "models/mempool_entry.h"
#include "models/peer.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_scan.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Shared accessor for the current wallet RPC context. */
static inline struct wallet_rpc_context *wallet_ctx(void)
{
    return wallet_rpc_context_current();
}

/* ── Handlers (each grouped into a sibling .c file) ───────── */

/* wallet_shielded_controller.c — addresses / balances / listing */
bool rpc_z_getnewaddress(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_z_listaddresses(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_z_getbalance(const struct json_value *params, bool help,
                      struct json_value *result);
bool rpc_z_listunspent(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_z_gettotalbalance(const struct json_value *params, bool help,
                           struct json_value *result);
bool rpc_z_listreceivedbyaddress(const struct json_value *params, bool help,
                                 struct json_value *result);
bool rpc_z_listallnotes(const struct json_value *params, bool help,
                        struct json_value *result);

/* wallet_shielded_send.c — z_sendmany (t/z spend + build + broadcast) and
 * wallet_addr_is_sapling() (chain-aware Sapling prefix test) are BOTH
 * declared in the public controllers/wallet_shielded_controller.h, included
 * above: z_sendmany because the store buyer calls it in-process, the prefix
 * test because its owning test group asserts it across all three networks. */

/* wallet_shielded_send_shielded.c — z_sendmany shielded-spend branch.
 * Recipients are pre-parsed into the transparent/shielded output
 * arrays by rpc_z_sendmany. */
struct chain_params;
struct sapling_key_entry;
struct tx_destination;
bool z_sendmany_shielded(
    struct wallet_rpc_context *ctx,
    const struct chain_params *cp,
    const struct sapling_key_entry *from_z_key,
    int64_t total_amount,
    const struct tx_destination *t_dests, const int64_t *t_amounts,
    size_t num_t_out,
    const uint8_t (*z_diversifiers)[11], const uint8_t (*z_pk_ds)[32],
    const int64_t *z_amounts, const uint8_t (*z_memos)[512],
    const bool *z_has_memo, size_t num_z_out,
    struct wallet_tx *prepared, struct json_value *result);

/* wallet_shielded_keys.c — key/viewing-key import/export + memo */
bool rpc_z_exportkey(const struct json_value *params, bool help,
                     struct json_value *result);
bool rpc_z_importkey(const struct json_value *params, bool help,
                     struct json_value *result);
bool rpc_z_exportviewingkey(const struct json_value *params, bool help,
                            struct json_value *result);
bool rpc_z_getmemo(const struct json_value *params, bool help,
                   struct json_value *result);

#endif /* ZCL_CONTROLLERS_WALLET_SHIELDED_INTERNAL_H */
