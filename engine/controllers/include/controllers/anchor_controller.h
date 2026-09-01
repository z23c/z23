/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Anchor Controller — RPC commands for ZCL Anchors (ZANC).
 *
 * Commands:
 *   anchor_publish  — anchor a file/digest into the chain via OP_RETURN
 *   anchor_verify   — recompute a file/digest and find its chain anchor
 *   anchor_list     — list recent anchors
 *   anchor_self     — digest the running binary and verify it against chain */

#ifndef ZCL_CONTROLLERS_ANCHOR_H
#define ZCL_CONTROLLERS_ANCHOR_H

#include "rpc/server.h"
#include "models/database.h"

struct wallet;
struct tx_mempool;
struct main_state;
struct coins_view_cache;

void rpc_anchor_set_state(struct node_db *ndb);
void rpc_anchor_set_wallet(struct wallet *w, struct tx_mempool *mp,
                           struct main_state *main_state,
                           struct coins_view_cache *coins_tip);
void register_anchor_rpc_commands(struct rpc_table *t);

#endif /* ZCL_CONTROLLERS_ANCHOR_H */
