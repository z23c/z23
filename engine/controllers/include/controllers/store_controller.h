/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store controller — ZSLP token commerce over .onion.
 *
 * Routes:
 *   GET  /store               List products
 *   GET  /store/products      List products
 *   GET  /store/products/:id  Product detail
 *   POST /store/orders        Create order, generate z-address
 *   GET  /store/orders/:id    Check payment status
 *
 * Compatibility aliases:
 *   GET  /store/product/:id
 *   POST /store/buy/:id
 *   GET  /store/order/:id
 *
 * Payment flow:
 *   1. Customer browses products (GET /store)
 *   2. Customer selects product (GET /store/product/1)
 *   3. Node generates unique z-address for payment
 *   4. Customer sends shielded ZCL to z-address
 *   5. Background thread detects payment (z_listunspent)
 *   6. Node mints ZSLP tokens to customer's t-address
 *   7. Customer accesses token-gated services */

#ifndef ZCL_CONTROLLERS_STORE_H
#define ZCL_CONTROLLERS_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;

/* Handle a store request. Returns HTTP response bytes written. */
size_t store_handle_request(const char *method, const char *path,
                             const uint8_t *body, size_t body_len,
                             uint8_t *response, size_t response_max,
                             const char *datadir);

/* Background: check pending orders for payments, mint tokens. */
void store_process_payments(const char *datadir);
/* Live-node form: caller supplies the canonical DB-service-owned ledger.
 * The path-only wrapper above remains for stopped test fixtures. */
void store_process_payments_with_db(struct node_db *ndb,
                                    const char *datadir);

/* Check if customer has enough ZSLP tokens for a service.
 * Used as before_action hook on protected routes. */
bool store_check_token_access(const char *datadir,
                               const char *customer_addr,
                               const char *token_id,
                               uint64_t required);

/* The balance answer behind the access gate: max() of the chain-derived
 * zslp_ledger holding (the only production source — zslp_balances is
 * deliberately left empty by the chain-scan path) and the credit-only
 * legacy table (fixture path). Exposed so the view's denial page reports
 * the same number the gate used. */
uint64_t store_access_token_balance(const char *datadir,
                                    const char *customer_addr,
                                    const char *token_id);

/* Confirmed value credited to order `order_id` at its one-time payment
 * address, under the order binding that the address type implies:
 *
 *   z-address -> Sapling memo bind (db_store_received_payment_for_memo)
 *   t-address -> address bind      (db_store_received_payment_taddr)
 *
 * THE reconcile for a store order. Both the merchant's payment processor and
 * the buyer's status poll go through this one function on purpose: if they
 * each picked their own matcher, a buyer could believe an order paid that the
 * merchant will never credit. `max_height` is the confirmation ceiling
 * (tip - 3 at both call sites). Returns 0 on any error. */
int64_t store_confirmed_payment(struct node_db *ndb, const char *pay_addr,
                                int64_t order_id, int64_t max_height);

#endif
