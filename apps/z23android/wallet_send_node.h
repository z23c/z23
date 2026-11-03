/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_SEND_NODE_H
#define ZAPP_WALLET_SEND_NODE_H
#include "wallet_send_screen.h"

/* The node side of a send: the typed wss_node_ops over a command runner. It builds each request as JSON for the
 * node's standard input, reads each reply by exact shape and maps the node's error codes to the typed outcomes of
 * the screen. It performs no I/O of its own, so the tests fake the runner.
 *
 * Node message text never leaves this module: every refusal reaches the screen as a typed value and the machine
 * shows its own wording. A reply that is not exactly the documented shape is a failure, never a default.
 *
 * Known limit: the sender (`from`) is the wallet's latest shielded address, read with `core wallet shielded latest`
 * when the payment is planned; an account-wide spend comes with the receive lane. */

#define WSN_REPLY_MAX 16384
#define WSN_INPUT_MAX 4096
#define WSN_STEP_TIMEOUT_MS 60000u
/* A commit builds a proof: about 100 seconds on a phone. The runner never kills it sooner than 300 seconds. */
#define WSN_COMMIT_TIMEOUT_MS 360000u

struct wsn_runner {
    void *ctx;
    /* Runs one command and leaves its reply in out. op is "summary", "fleet", "latest", "broadcast", "plan", "commit",
     * "unlock" or "lock", or "validateaddress" with input the JSON-RPC parameter array of the node's validateaddress.
     * input is NULL for a read and for lock. False when the command failed, was killed or does not exist; out may still
     * hold a typed error reply. */
    bool (*run)(void *ctx, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
    /* The phone's thermal pause has stopped the node. */
    bool (*paused)(void *ctx);
};

struct wsn {
    struct wsn_runner runner;
    enum zapp_pay_network network;
    char from[ZAPP_PAY_ADDRESS_MAX];   /* the sender of the last plan, sent unchanged with its commit */
    char token[WS_TOKEN_MAX];          /* the token of that plan */
    char txid[WS_TXID_MAX];            /* the transaction that commit reported, empty when it reported none */
};

void wsn_init(struct wsn *node, const struct wsn_runner *runner, enum zapp_pay_network network);
/* Fills ops with the node calls of a send. route reads
 * the pending sends of core wallet broadcast status: the machine leaves WS_BROADCAST for WS_DONE when the payment is
 * listed as sent or seen, or is not pending. A failed read keeps it waiting. */
void wsn_ops(struct wsn *node, struct wss_node_ops *ops);

/* The wallet_scope the node requires for the network the app is built for: mainnet "prod"; testnet and regtest "test",
 * the scope of the operator lane "test" (wallet_money_scope_for_lane in wallet_money_service.c; the send command
 * accepts only dev, prod or test, wallet_money_scope_valid). */
const char *wsn_scope(enum zapp_pay_network network);
/* The exact amount text of both plan and commit: "1.25000000". Returns the length, or 0 when cap is too small. */
size_t wsn_format_amount(uint64_t zat, char *out, size_t cap);

#endif
