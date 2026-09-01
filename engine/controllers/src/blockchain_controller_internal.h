/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Internal cross-translation-unit glue for the blockchain controller.
 *
 * The public surface lives in controllers/blockchain_controller.h. This
 * header is private to engine/controllers/src/blockchain_controller*.c and
 * declares helpers that needed to become non-static so the blockchain
 * controller could be split across multiple files. Do not include from
 * outside engine/controllers/src/. */

#ifndef ZCL_APP_CONTROLLERS_SRC_BLOCKCHAIN_CONTROLLER_INTERNAL_H
#define ZCL_APP_CONTROLLERS_SRC_BLOCKCHAIN_CONTROLLER_INTERNAL_H

#include "controllers/blockchain_controller.h"
#include "coins/coins_view.h"
#include "json/json.h"
#include "models/database.h"
#include "models/utxo.h"
#include "primitives/block.h"
#include "storage/coins_db.h"
#include "validation/main_state.h"
#include "validation/txmempool.h"

#include <stdbool.h>

/* ── Shared controller context ──────────────────────────── */

struct blockchain_context {
    struct main_state *main_state;
    struct tx_mempool *mempool;
    const char *datadir;
    char datadir_storage[4096];
    struct coins_view_db *coins_db;
    struct coins_view_cache *coins_tip;
    struct node_db *node_db;
};

/* Returns the singleton context. Definition lives in blockchain_controller.c. */
struct blockchain_context *blockchain_ctx(void);

/* ── Shared helpers (definitions in blockchain_controller.c) ──
 * Block difficulty: use difficulty_from_index() from chain/pow.h. */

void block_header_to_json(const struct block_index *bi,
                          struct json_value *result);

/* ── RPC handler declarations (defined in sibling files) ── */

/* blockchain_controller_blocks.c */
bool rpc_getblockcount(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_getbestblockhash(const struct json_value *params, bool help,
                          struct json_value *result);
bool rpc_getdifficulty(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_getblockhash(const struct json_value *params, bool help,
                      struct json_value *result);
bool rpc_getblockheader(const struct json_value *params, bool help,
                        struct json_value *result);
bool rpc_getblock(const struct json_value *params, bool help,
                  struct json_value *result);
bool rpc_getchaintip(const struct json_value *params, bool help,
                     struct json_value *result);

/* blockchain_controller_chain.c */
bool rpc_getblockchaininfo(const struct json_value *params, bool help,
                           struct json_value *result);
bool rpc_getmempoolinfo(const struct json_value *params, bool help,
                        struct json_value *result);
bool rpc_getrawmempool(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_getmempoolfeestats(const struct json_value *params, bool help,
                            struct json_value *result);
bool rpc_gettxoutsetinfo(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_getutxocommitment(const struct json_value *params, bool help,
                           struct json_value *result);
bool rpc_getutxoaudit(const struct json_value *params, bool help,
                      struct json_value *result);
bool rpc_verifycheckpoint(const struct json_value *params, bool help,
                          struct json_value *result);
bool rpc_getdataintegrity(const struct json_value *params, bool help,
                          struct json_value *result);
bool rpc_getmmrroot(const struct json_value *params, bool help,
                    struct json_value *result);
bool rpc_getcommitmentmmr(const struct json_value *params, bool help,
                          struct json_value *result);
bool rpc_auditchain(const struct json_value *params, bool help,
                    struct json_value *result);
bool rpc_rebuildsaplingtree(const struct json_value *params, bool help,
                            struct json_value *result);

/* blockchain_controller_admin.c */
bool rpc_reindexchainstate(const struct json_value *params, bool help,
                           struct json_value *result);
bool rpc_importchainstate(const struct json_value *params, bool help,
                          struct json_value *result);

/* blockchain_controller_recovery.c — invalidateblock / reconsiderblock */
bool rpc_invalidateblock(const struct json_value *params, bool help,
                         struct json_value *result);
bool rpc_reconsiderblock(const struct json_value *params, bool help,
                         struct json_value *result);

/* blockchain_controller_wait.c — long-poll waitfor* methods */
bool rpc_waitforheight(const struct json_value *params, bool help,
                       struct json_value *result);
bool rpc_waitforhalt(const struct json_value *params, bool help,
                     struct json_value *result);
bool rpc_waitforblocker(const struct json_value *params, bool help,
                        struct json_value *result);

#endif
