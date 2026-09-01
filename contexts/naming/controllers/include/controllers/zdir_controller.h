/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZDIR Controller — RPC commands that PUBLISH an on-chain node directory
 * record. This is the write half zdir/zdir.h documented as missing: the
 * codec and the projection fold have always been wired, but until now
 * nothing in this binary composed, funded, signed or broadcast a record,
 * so the onion_directory projection read empty forever.
 *
 * Commands:
 *   zdir_register   — announce "this v3 onion hostname is a node", with an
 *                     optional ed25519 master-key binding
 *   zdir_deregister — retire a hostname the caller registered
 *
 * There is deliberately NO transfer. Command byte 3 is reserved for it and
 * zdir_parse rejects it, because a parsed-but-unhandled command would be a
 * silent stub. Handing a hostname to a new operator is expressed as
 * deregister by the current owner, then register by the new one.
 *
 * Same compose+return shape as the identity/anchor/name controllers: with a
 * wallet loaded the commands build a base tx, attach the ZDIR OP_RETURN and
 * broadcast; with NO wallet they return the OP_RETURN hex and status
 * "ready" — that no-wallet branch is the one the unit tests exercise, and
 * nothing here broadcasts in a test.
 *
 * Ownership. explorer_index_apply_zdir_overlay will only fold a mutation of
 * an EXISTING row when the confirming tx's first input pays the row's
 * recorded owner_address. So a re-register and every deregister build their
 * base tx with zslp_command_build_owner_base_tx(owner_address) — the same
 * proof, constructed up front. A first registration of an unclaimed
 * hostname has no owner to prove and uses the genesis base tx. A row with
 * no recorded owner is permanently immutable by design and fails closed
 * with NOT_OWNER rather than broadcasting a tx the projection would refuse.
 *
 * NEVER ON A TIMER. Nothing calls these except an operator: no boot path,
 * no background service, no re-announce cadence. Publishing spends a real
 * UTXO, so it stays an explicit decision. */

#ifndef ZCL_CONTROLLERS_ZDIR_H
#define ZCL_CONTROLLERS_ZDIR_H

#include "rpc/server.h"
#include "models/database.h"

struct wallet;
struct tx_mempool;
struct main_state;
struct coins_view_cache;

/* Bind the projection + wallet context and register the verbs, in ONE call.
 * The sibling overlays (name/anchor/identity) each spend three boot lines on
 * two setters and a register; this takes one, because there is no legitimate
 * order to call them in other than all-three-then-register, and a half-bound
 * controller would compose transactions it cannot broadcast.
 *
 * `w`/`mp` NULL is the supported no-wallet configuration, not an error: the
 * commands then return the OP_RETURN hex for the operator to include, which
 * is also the branch the unit tests drive. */
void register_zdir_rpc_commands(struct rpc_table *t, struct node_db *ndb,
                                struct wallet *w, struct tx_mempool *mp,
                                struct main_state *main_state,
                                struct coins_view_cache *coins_tip);
void register_zdir_intent_rpc_command(struct rpc_table *table);

#endif /* ZCL_CONTROLLERS_ZDIR_H */
