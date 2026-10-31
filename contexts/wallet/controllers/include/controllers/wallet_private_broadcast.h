/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Controller glue between the wallet's own send paths and the private relay
 * (services/wallet_private_relay.h). Only sendtoaddress, sendmany and
 * z_sendmany call it; every other transaction author keeps public relay. */

#ifndef ZCL_CONTROLLERS_WALLET_PRIVATE_BROADCAST_H
#define ZCL_CONTROLLERS_WALLET_PRIVATE_BROADCAST_H

#include "rpc/server.h"
#include "services/wallet_private_relay.h"

#include <stdbool.h>

struct wallet_rpc_context;
struct wallet_tx;

/* The context a wallet send runs against. In private mode it is a copy of ctx
 * in *view with the private pool as mempool and no connman, so commit,
 * rollback and the legacy relay line cannot touch the main pool or a peer. In
 * public mode it is ctx itself. */
struct wallet_rpc_context *wallet_send_view(struct wallet_rpc_context *ctx,
                                            struct wallet_rpc_context *view);
struct wallet_rpc_context *wallet_send_view_unless_prepared(
    struct wallet_rpc_context *ctx, struct wallet_rpc_context *view,
    const void *prepared);

/* Broadcast a committed, durable send. Public mode announces to every peer.
 * Private mode queues it for one delayed onion push; if it cannot be queued
 * the send is rolled back and false is returned. */
bool wallet_send_relay(struct wallet_rpc_context *ctx, struct wallet_tx *wtx);

#define WALLET_PBCAST_TICK_MS 1000
/* Spacing of the held-send warning, which carries a count only. */
#define WALLET_PBCAST_HELD_WARN_S 300


/* Configure the relay, resume the pending set and start the tick thread, in
 * either mode: a send held in private mode must still expire after a restart
 * in public mode. Nothing is pushed unless the mode is private. */
bool wallet_private_broadcast_start(enum wpr_mode mode,
                                    const struct wpr_env *env);

/* One relay tick plus wallet rollback of expired transactions, at the height
 * through which the wallet has read blocks. */
void wallet_private_broadcast_tick(void);
/* The same with an explicit wallet height (-1 when unknown). */
void wallet_private_broadcast_tick_at(int wallet_height);
/* Roll back one expired send through the wallet's persisted rollback and keep a
 * terminal expired record. A send the wallet shows confirmed is marked seen
 * instead and false is returned. */
bool wallet_private_broadcast_expire(const struct uint256 *txid);
/* Stop the tick thread; waits briefly for it to exit. */
void wallet_private_broadcast_stop(void);

void register_wallet_private_broadcast_rpc_commands(struct rpc_table *t);

#endif
