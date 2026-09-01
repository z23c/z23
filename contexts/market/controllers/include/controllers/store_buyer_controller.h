/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store BUYER RPC surface — the in-node half of the programmatic buyer.
 *
 * These run INSIDE the node, which is the whole reason they exist: a
 * purchase mints a one-time Sapling payment address and sends a shielded
 * payment, and both need the running node's wallet. The typed `app.store.*`
 * leaves execute in a short-lived CLI process with no wallet and no open
 * database, so they call these over the loopback JSON-RPC path rather than
 * trying to do the work themselves.
 *
 * Every method answers with a structured object carrying `ok` plus, when
 * ok is false, a stable `code` (services/store_buyer.h) and a human
 * `message`. A refusal is a successful call that reports a refusal — not a
 * transport error — so the caller can tell "the node said no, and here is
 * exactly why" from "the node did not answer".
 *
 * Methods:
 *   storebuy_catalog                                  products for sale
 *   storebuy_order   product_id addr [output_path]    place an order
 *   storebuy_pay     purchase_id from_address         pay it (shielded)
 *   storebuy_status  [purchase_id]                    one purchase, or all
 *   storebuy_collect purchase_id [output_path]        download + verify */

#ifndef ZCL_CONTROLLERS_STORE_BUYER_CONTROLLER_H
#define ZCL_CONTROLLERS_STORE_BUYER_CONTROLLER_H

struct rpc_table;

/* Bind the data directory whose store these methods buy from. Must be called
 * before registration; without it every method refuses rather than guessing
 * at a directory. */
void rpc_store_buyer_set_state(const char *datadir);

void register_store_buyer_rpc_commands(struct rpc_table *t);

#endif /* ZCL_CONTROLLERS_STORE_BUYER_CONTROLLER_H */
