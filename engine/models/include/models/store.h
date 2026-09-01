/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_DB_MODEL_STORE_H
#define ZCL_DB_MODEL_STORE_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    STORE_PRODUCT_NAME_MAX = 255,
    STORE_PRODUCT_DESC_MAX = 1023,
    /* 64 admits a ZSLP genesis token id (32 bytes, 64 hex chars) verbatim —
     * the access-gate settles in ZSLP and zslp_mint takes only the hex id. */
    STORE_PRODUCT_TOKEN_MAX = 64,
    STORE_ORDER_ADDR_MAX = 127,
    STORE_ORDER_TXID_MAX = 127
};

enum store_order_status {
    STORE_ORDER_PENDING = 0,
    STORE_ORDER_PAID = 1,
    STORE_ORDER_SENT = 2,
    STORE_ORDER_FAILED = 3
};

/* Resource-exhaustion bounds on the pending-order pool (see the
 * order-create gate in engine/controllers/src/store_controller.c). Every
 * unpaid order costs a minted Sapling z-address + a DB row; before this
 * cap existed, an unauthenticated flood could grow `orders` without
 * limit. These bound the TOTAL pending pool and the pool for any single
 * product, so a flood against one product cannot exhaust capacity that
 * legitimate buyers of other products need. */
enum {
    STORE_ORDER_MAX_PENDING_GLOBAL = 1000,
    STORE_ORDER_MAX_PENDING_PER_PRODUCT = 200,
    /* An unpaid order older than this already fell outside the payment
     * scan window (store_process_payments only looks back 3600s), so
     * pruning at the same threshold discards nothing a late-but-legit
     * payer could still complete. */
    STORE_ORDER_PENDING_EXPIRE_SECS = 3600
};

struct db_store_product {
    int64_t id;
    char name[STORE_PRODUCT_NAME_MAX + 1];
    char description[STORE_PRODUCT_DESC_MAX + 1];
    int64_t price_zatoshi;
    char token_id[STORE_PRODUCT_TOKEN_MAX + 1];
    int tokens_per_purchase;
    bool active;
    /* Optional content-addressed file payload (migration v20). When
     * has_content is set, content_hash is the SHA3-256 key into the
     * store_blobs table; the gated-download path streams those bytes.
     * NULL content_hash in the DB ⇒ has_content=false ⇒ HTML fallback. */
    uint8_t content_hash[32];
    bool has_content;
};

struct db_store_order {
    int64_t id;
    int64_t product_id;
    char customer_addr[STORE_ORDER_ADDR_MAX + 1];
    char payment_addr[STORE_ORDER_ADDR_MAX + 1];
    int64_t amount_zatoshi;
    char payment_txid[STORE_ORDER_TXID_MAX + 1];
    char mint_txid[STORE_ORDER_TXID_MAX + 1];
    int status;
    int64_t created_at;
    int64_t paid_at;
    bool has_paid_at;
};

struct db_store_order_summary {
    int64_t id;
    int status;
    int64_t amount_zatoshi;
    char product_name[STORE_PRODUCT_NAME_MAX + 1];
};

struct db_store_order_view {
    int64_t id;
    int status;
    int64_t amount_zatoshi;
    char payment_addr[STORE_ORDER_ADDR_MAX + 1];
    char customer_addr[STORE_ORDER_ADDR_MAX + 1];
    char payment_txid[STORE_ORDER_TXID_MAX + 1];
    char mint_txid[STORE_ORDER_TXID_MAX + 1];
    char product_name[STORE_PRODUCT_NAME_MAX + 1];
};

struct db_store_pending_payment {
    int64_t id;
    char payment_addr[STORE_ORDER_ADDR_MAX + 1];
    int64_t amount_zatoshi;
    char customer_addr[STORE_ORDER_ADDR_MAX + 1];
    char token_id[STORE_PRODUCT_TOKEN_MAX + 1];
    int64_t tokens_per_purchase;
};

struct ar_callbacks *db_store_product_callbacks(void);
struct ar_callbacks *db_store_order_callbacks(void);

bool db_store_product_validate(const struct db_store_product *p,
                               struct ar_errors *errors);
bool db_store_order_validate(const struct db_store_order *o,
                             struct ar_errors *errors);

bool db_store_product_save(struct node_db *ndb, const struct db_store_product *p);
bool db_store_product_find_active(struct node_db *ndb, int64_t id,
                                  struct db_store_product *out);

/* Resolve an active product by its token id (case-insensitive: token ids
 * are stored upcased). The gated-download path uses this to join a
 * `token=X` access request to the product whose file payload it serves.
 * Returns false (out zeroed) if no active product carries that token. */
bool db_store_product_find_by_token(struct node_db *ndb, const char *token_id,
                                    struct db_store_product *out);

/* Attach (or clear) a content-addressed file payload on a product. Pass
 * the 32-byte SHA3-256 blob hash to attach, or NULL to clear. The bytes
 * themselves must already be stored via db_store_blob_put. */
bool db_store_product_save_content(struct node_db *ndb, int64_t id,
                                   const uint8_t content_hash[32]);
int db_store_product_list_active(struct node_db *ndb,
                                 struct db_store_product *out, size_t max);
int db_store_product_count(struct node_db *ndb);
bool db_store_order_save(struct node_db *ndb, struct db_store_order *o);
bool db_store_order_find_view(struct node_db *ndb, int64_t id,
                              struct db_store_order_view *out);
int db_store_order_list_recent(struct node_db *ndb,
                               struct db_store_order_summary *out, size_t max);
int db_store_order_list_pending_payments(struct node_db *ndb,
                                         struct db_store_pending_payment *out,
                                         size_t max,
                                         int64_t min_created_at);
bool db_store_order_mark_paid(struct node_db *ndb, int64_t id, int status);

/* Total STORE_ORDER_PENDING rows currently in the table. Used by the
 * order-create gate to refuse new orders once the pending pool is full
 * (see STORE_ORDER_MAX_PENDING_GLOBAL). Returns 0 on any error. */
int db_store_order_count_pending(struct node_db *ndb);

/* STORE_ORDER_PENDING rows for a single product_id. Bounds any one
 * product from exhausting the whole pending pool (see
 * STORE_ORDER_MAX_PENDING_PER_PRODUCT). Returns 0 on any error. */
int db_store_order_count_pending_for_product(struct node_db *ndb,
                                             int64_t product_id);

/* Delete STORE_ORDER_PENDING rows older than `max_age_secs` (an unpaid
 * order that old is abandoned — store_process_payments already stops
 * scanning for its payment after the same window). This is what keeps
 * the orders table bounded instead of growing forever: caps alone only
 * refuse NEW rows, they don't reclaim old ones. Returns the number of
 * rows deleted (0 on no-op or error). */
int db_store_order_prune_expired(struct node_db *ndb, int64_t max_age_secs);

/* Payment-check reads. The store payment processor needs the current
 * chain tip (to compute confirmation depth) and the confirmed shielded
 * balance received at a one-time order z-address. These read the
 * consensus `blocks` table and the wallet `wallet_sapling_notes` table
 * with store-specific semantics (no block status filter on the tip; a
 * confirmation-depth ceiling on received notes), so the SQL lives here
 * in the store model rather than in the controller. Both return 0 on
 * any error or no-row. */
int64_t db_store_chain_tip_height(struct node_db *ndb);
int64_t db_store_received_payment(struct node_db *ndb, const char *pay_addr,
                                  int64_t max_height);

/* Memo-bound variant of db_store_received_payment: sums only the confirmed,
 * unspent notes at `pay_addr` whose recovered Sapling memo binds them to this
 * `order_id` (memo prefix "ZCL23ORDER:<order_id>" terminated by NUL or ';').
 * The memo is recovered by the wallet's ivk-decrypt of the paying output
 * (wallet.c memcpy(note.memo, plaintext+52, 512)), so a payment whose memo
 * names a DIFFERENT order — or a fabricated note that never ivk-decrypted —
 * cannot be credited to this order. This closes the "an unrelated same-amount
 * payment to the same address could satisfy the order" hole that the
 * address+amount-only db_store_received_payment leaves open. Returns 0 on any
 * error / no matching row. App-layer only (no consensus path). */
int64_t db_store_received_payment_for_memo(struct node_db *ndb,
                                           const char *pay_addr,
                                           int64_t order_id,
                                           int64_t max_height);

/* Transparent counterpart of db_store_received_payment_for_memo: sums the
 * confirmed, unspent, non-coinbase transparent value the wallet holds at
 * `address_hash` (the 20-byte hash160 of a one-time order t-address).
 *
 * A transparent output carries no Sapling memo, so the order binding here is
 * the ADDRESS ITSELF: the merchant mints a fresh t-address per order and uses
 * it for that order only, so "value at this address" and "value paid for this
 * order" are the same set. That is exactly as tight as the memo bind — order 1
 * cannot be satisfied by a payment to order 12's address — and it is why this
 * must never be pointed at a reused or wallet-default address.
 *
 * Callers pass the hash160 rather than the address text because wallet_utxos
 * keys on address_hash, and decoding an address is a controller-layer concern
 * (wallet_decode_address) that the model deliberately does not depend on.
 * Returns 0 on any error / no matching row. App-layer only (no consensus
 * path). */
int64_t db_store_received_payment_taddr(struct node_db *ndb,
                                        const uint8_t address_hash[20],
                                        int64_t max_height);

#endif
