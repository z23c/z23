/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Identity Controller — RPC commands for sovereign identity anchors (ZID).
 *
 * Commands:
 *   identity_anchor  — bind a 32-byte ed25519 master key to the chain
 *   identity_rotate  — supersede an anchored key with a successor
 *   identity_revoke  — retire an anchored key with no successor
 *   identity_resolve — read one identity row out of the projection
 *
 * Same compose+return shape as the ZANC/ZNAM controllers: with a wallet
 * loaded the mutating commands compose and broadcast a tx carrying the
 * ZID OP_RETURN; with no wallet they return the OP_RETURN hex for manual
 * inclusion (the branch the unit tests exercise — no broadcast).
 *
 * rotate/revoke build their base tx through
 * zslp_command_build_owner_base_tx, so the tx's SOLE input pays the
 * address the projection recorded as the row's owner — the same
 * ownership proof explorer_index_apply_zid_overlay checks when it later
 * folds the confirmed tx. A wallet that cannot spend under that address
 * fails closed with NOT_OWNER rather than broadcasting a tx the
 * projection would refuse. */

#ifndef ZCL_CONTROLLERS_IDENTITY_H
#define ZCL_CONTROLLERS_IDENTITY_H

#include "rpc/server.h"
#include "models/database.h"

struct wallet;
struct tx_mempool;
struct main_state;
struct coins_view_cache;

void rpc_identity_set_state(struct node_db *ndb);
void rpc_identity_set_wallet(struct wallet *w, struct tx_mempool *mp,
                             struct main_state *main_state,
                             struct coins_view_cache *coins_tip);
void register_identity_rpc_commands(struct rpc_table *t);
void register_zid_intent_rpc_command(struct rpc_table *table);

#endif /* ZCL_CONTROLLERS_IDENTITY_H */
