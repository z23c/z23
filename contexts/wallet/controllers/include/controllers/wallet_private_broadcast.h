/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Controller glue between the wallet's own send paths and the private relay
 * (services/wallet_private_relay.h). Only sendtoaddress, sendmany and
 * z_sendmany call it; every other transaction author keeps public relay. */

#ifndef ZCL_CONTROLLERS_WALLET_PRIVATE_BROADCAST_H
#define ZCL_CONTROLLERS_WALLET_PRIVATE_BROADCAST_H

#include "base/result.h"
#include "json/json.h"
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
 * terminal expired record. Returns false, leaving the record, when the wallet
 * shows the send confirmed (marked seen), when the chain view shows an input
 * spent or cannot show it unspent (held: it may be on chain), or when the
 * database row could not be deleted yet (retried). */
bool wallet_private_broadcast_expire(const struct uint256 *txid);

/* Called by the wallet commit funnel BEFORE the wallet admits a send. In
 * private mode it records the send durably so a crash after the wallet write
 * still leaves a record to resume. Fails closed: when the record cannot be
 * made durable the send is refused. A public-mode context passes. */
struct zcl_result wallet_private_broadcast_before_commit(
    const struct wallet_rpc_context *ctx, const struct uint256 *txid);

/* Transactions authored outside the wallet send paths (vault intents, ZSLP,
 * ZDIR, ZNAM, ZID, blog anchors, swaps, sendrawtransaction, yardsale) are
 * announced to every peer. In private mode they are refused with the typed
 * error PRIVATE_BROADCAST_UNSUPPORTED rather than leak the sender. */
#define WALLET_PBCAST_UNSUPPORTED_CODE (-9301)
struct zcl_result wallet_private_broadcast_unsupported(const char *what);
/* The same for handlers that answer with a JSON string: sets the error and
 * returns true when the refusal applies. */
bool wallet_private_broadcast_refuse_json(const char *what,
                                          struct json_value *result);
/* Stop the tick thread; waits briefly for it to exit. */
void wallet_private_broadcast_stop(void);

void register_wallet_private_broadcast_rpc_commands(struct rpc_table *t);

#endif
