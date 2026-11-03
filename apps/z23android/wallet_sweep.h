/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SWEEP_H
#define ZAPP_WALLET_SWEEP_H
#include "wallet_send_node.h"

/* The node side of Make private: the typed wss_node_ops for a sweep of one public address into the wallet's own newest
 * private address, over the send adapter. A request with sweep false goes to the send adapter unchanged.
 *
 * The node command is `core wallet shielded shield`. Its plan request holds the wallet scope and the idempotency key and
 * nothing else: no destination, no amount, no memo and no source address (the node picks the address with the largest
 * mature total). Its commit holds what the plan quoted and the app never chose: the source and the private destination the
 * node named, the number of coins and their total, the fee, the key, the plan token and confirm. A commit for any plan this
 * adapter did not make is refused here and reaches no node call.
 *
 * Node message text never leaves this module: a refusal reaches the screen as a typed reason (enum ws_why) and the machine
 * writes its own sentence. A reply that is not exactly the documented shape is a failure, never a default. */

struct wsw {
    struct wsn node;                   /* first, so the send adapter's operations take this address as their context */
    struct wss_node_ops send;          /* the operations of a payment */
    char from[ZAPP_PAY_ADDRESS_MAX];   /* the plan of the last sweep, sent unchanged with its commit */
    char to[ZAPP_PAY_ADDRESS_MAX];
    int64_t inputs;
    uint64_t total_zat, fee_zat;
    char token[WS_TOKEN_MAX];
};

void wsw_init(struct wsw *sweep, const struct wsn_runner *runner, enum zapp_pay_network network);
/* Fills ops with the node calls of a payment and of a sweep. The runner's ops "shieldplan" and "shieldcommit" are the plan and
 * the commit of the sweep; the input of both is the request, on standard input. */
void wsw_ops(struct wsw *sweep, struct wss_node_ops *ops);

#endif
