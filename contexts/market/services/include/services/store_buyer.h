/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store BUYER service — the buying half of the store, with no browser.
 *
 * The selling half already worked end to end: a merchant lists a product,
 * the store mints a one-time Sapling payment address per order, a background
 * worker credits the order from the note whose memo names it, and the file is
 * served token-gated. What did not exist was a buyer that a program could be:
 * the order form is HTML with a CSRF token and a proof-of-work puzzle solved
 * by embedded JavaScript, and the download is an HTTP GET. A human with a Tor
 * Browser was the only client.
 *
 * This service is that client, in-process. It drives the SAME surfaces:
 *   store_handle_request()                — the real order-create route, so
 *                                           CSRF, the PoW gate, and the
 *                                           pending-pool caps all apply
 *   db_store_received_payment_for_memo()  — the existing memo-bound matcher;
 *                                           there is no second payment finder
 *   /store/access                         — the real token gate
 * and records what it is owed in `store_purchases` (models/store_purchase.h)
 * so a purchase paid for but not yet collected survives a restart.
 *
 * Every entry point answers with struct zcl_result whose `code` is one of
 * enum store_buyer_status, so the reason travels with the failure and a
 * caller can branch on it rather than on prose. Nothing here half-writes: the
 * delivery step verifies the SHA3-256 of the received bytes against the
 * product's content hash BEFORE any byte reaches the output path, and on a
 * mismatch it writes nothing at all rather than leaving a partial or wrong
 * file behind.
 *
 * MAINNET REFUSES THE SPEND. Paying a merchant with real value from a
 * scripted buyer is not a thing this ships enabled, so
 * store_buyer_prepare_payment refuses on mainnet before anything else — and
 * since that is the only path from here to z_sendmany, there is nothing to
 * route around. Browsing, ordering and collecting are not gated: they move no
 * value, and gating them would only stop an operator seeing their own store. */

#ifndef ZCL_SERVICES_STORE_BUYER_H
#define ZCL_SERVICES_STORE_BUYER_H

#include "base/result.h"
#include "models/store_purchase.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Distinguishable outcomes, carried as struct zcl_result's `code`. Each maps
 * to one stable UPPER_SNAKE token (store_buyer_status_code). Ordered roughly
 * by where in a purchase they can occur. */
enum store_buyer_status {
    STORE_BUYER_OK = 0,
    STORE_BUYER_ERR_ARGS,                 /* caller passed nonsense */
    STORE_BUYER_ERR_MAINNET_REFUSED,      /* not on the real chain */
    STORE_BUYER_ERR_DB,                   /* node.db unavailable */
    STORE_BUYER_ERR_UNKNOWN_PRODUCT,      /* no such active product */
    STORE_BUYER_ERR_ORDER_CREATE_FAILED,  /* the store refused the order */
    STORE_BUYER_ERR_UNKNOWN_PURCHASE,     /* no such buyer purchase row */
    STORE_BUYER_ERR_ALREADY_PAID,         /* payment already submitted */
    STORE_BUYER_ERR_PROVER_UNAVAILABLE,   /* no Sapling proving backend */
    STORE_BUYER_ERR_SPEND_REFUSED,        /* sovereignty guard said no */
    STORE_BUYER_ERR_INSUFFICIENT_FUNDS,   /* wallet cannot cover the order */
    STORE_BUYER_ERR_PAYMENT_NOT_CONFIRMED,/* merchant has not credited it */
    STORE_BUYER_ERR_DELIVERY_FAILED,      /* paid, but no bytes came back */
    STORE_BUYER_ERR_HASH_MISMATCH,        /* bytes are not the product */
    STORE_BUYER_ERR_WRITE_FAILED,         /* verified bytes would not land */
    STORE_BUYER_ERR_INTERNAL              /* out of memory / impossible state */
};

/* Stable machine token for a result code, e.g. "HASH_MISMATCH". Never NULL;
 * an unrecognised code answers "UNKNOWN" rather than indexing past the
 * table. */
const char *store_buyer_status_code(int code);

/* One-line human explanation for the same code. Never NULL. */
const char *store_buyer_status_message(int code);

/* ── discover ───────────────────────────────────────────────────────── */

struct store_buyer_offer {
    int64_t product_id;
    char name[STORE_PURCHASE_NAME_MAX + 1];
    char token_id[STORE_PURCHASE_TOKEN_MAX + 1];
    int64_t price_zatoshi;
    int tokens_per_purchase;
    bool has_content;              /* a file payload is attached */
};

/* Active products offered by the store in `datadir`, in id order.
 * `*n_out` receives the row count written (0 is a valid answer: a store with
 * nothing for sale is not an error). */
struct zcl_result store_buyer_catalog(const char *datadir,
                                      struct store_buyer_offer *out,
                                      size_t max, size_t *n_out);

/* ── place an order ─────────────────────────────────────────────────── */

struct store_buyer_order {
    int64_t purchase_id;
    int64_t order_id;
    char payment_addr[STORE_PURCHASE_ADDR_MAX + 1];
    char memo[STORE_PURCHASE_MEMO_MAX + 1];   /* "ZCL23ORDER:<order_id>" */
    int64_t amount_zatoshi;
};

/* Place an order for `product_id` through the store's real order-create
 * route — CSRF token, proof-of-work puzzle and pending-pool caps included —
 * and record the buyer's side of it. `customer_addr` is the transparent
 * address the merchant mints access tokens to; `output_path` is where the
 * purchased bytes will be written when they are collected (may be NULL now
 * and supplied at collect time).
 *
 * `transparent` asks the merchant to mint a one-time t-address for this
 * order instead of a one-time z-address, which is the only kind of order a
 * build with no Sapling proving backend can actually pay: a shielded SPEND
 * needs a proof, a transparent one does not. The order is then bound by that
 * address rather than by a payment memo. */
struct zcl_result store_buyer_order(const char *datadir, int64_t product_id,
                                    const char *customer_addr,
                                    const char *output_path,
                                    bool transparent,
                                    struct store_buyer_order *out);

/* ── pay ────────────────────────────────────────────────────────────── */

struct store_buyer_payment {
    char from_addr[STORE_PURCHASE_ADDR_MAX + 1];
    char to_addr[STORE_PURCHASE_ADDR_MAX + 1];
    int64_t amount_zatoshi;
    /* The order memo as hex WITH an explicit trailing 00. The merchant's
     * matcher requires the byte after "ZCL23ORDER:<id>" to be NUL or ';',
     * so the terminator is part of the instruction, not an afterthought. */
    char memo_hex[2 * (STORE_PURCHASE_MEMO_MAX + 1) + 1];
};

/* Everything needed to pay a purchase, after every refusal that can be
 * decided without moving value: mainnet, unknown purchase, already paid,
 * missing Sapling proving backend, and the sovereignty spend guard. Writes
 * nothing. The caller performs the shielded send and then calls
 * store_buyer_record_payment (or store_buyer_fail if the send did not
 * happen).
 *
 * The funds check here is a WHOLE-WALLET floor, not coin selection: it
 * refuses when the wallet's total balance in the right pool cannot possibly
 * cover the order. Per-address selection stays where it belongs, in
 * z_sendmany, and its refusal is mapped back onto the same status. */
struct zcl_result store_buyer_prepare_payment(const char *datadir,
                                              int64_t purchase_id,
                                              const char *from_addr,
                                              struct store_buyer_payment *out);

/* Stamp a submitted payment onto the purchase: stage PAYING, operation id
 * recorded, last_error cleared. */
struct zcl_result store_buyer_record_payment(const char *datadir,
                                             int64_t purchase_id,
                                             const char *operation_id);

/* Stamp a refusal onto the purchase so the reason survives the process.
 * Only moves the row to FAILED for a code that means "stuck"; a "not yet"
 * (payment unconfirmed, no prover, no funds) records the reason and leaves
 * the stage alone, because such a purchase is still resumable and a
 * paid-but-uncollected row losing its stage is the exact outcome this
 * service exists to prevent. */
struct zcl_result store_buyer_fail(const char *datadir, int64_t purchase_id,
                                   int why, const char *detail);

/* ── poll ───────────────────────────────────────────────────────────── */

struct store_buyer_state {
    struct db_store_purchase purchase;
    bool merchant_order_found;
    int merchant_order_status;      /* enum store_order_status */
    int64_t confirmed_zatoshi;      /* memo-bound, confirmation-depth bound */
    int64_t tip_height;
    bool ready_to_collect;
};

/* Re-read a purchase against the merchant's current view and advance the
 * stage when the merchant has credited the order. Idempotent; safe to call
 * on any stage; never clears a recorded failure reason. */
struct zcl_result store_buyer_refresh(const char *datadir,
                                      int64_t purchase_id,
                                      struct store_buyer_state *out);

/* Newest-first list of this node's purchases. `*n_out` gets the count. */
struct zcl_result store_buyer_list(const char *datadir,
                                   struct db_store_purchase *out,
                                   size_t max, size_t *n_out);

/* ── collect ────────────────────────────────────────────────────────── */

struct store_buyer_delivery {
    char output_path[STORE_PURCHASE_PATH_MAX + 1];
    int64_t bytes;
    uint8_t content_hash[32];
    bool hash_verified;
};

/* Fetch the purchased bytes through the real token gate, verify their
 * SHA3-256 against the product's content hash, and only then write them to
 * `output_path` (or the path recorded at order time when NULL).
 *
 * The write is atomic-by-rename via a sibling temporary file, and a hash
 * mismatch leaves NOTHING behind: no temporary, no partial, no stale
 * overwrite of an existing file. */
struct zcl_result store_buyer_collect(const char *datadir,
                                      int64_t purchase_id,
                                      const char *output_path,
                                      struct store_buyer_delivery *out);

#endif /* ZCL_SERVICES_STORE_BUYER_H */
