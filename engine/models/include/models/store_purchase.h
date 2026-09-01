/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store PURCHASE model — the BUYER's side of a store transaction.
 *
 * `orders` (models/store.h) is the MERCHANT's row: what was asked for and
 * whether the merchant credited it. This table is the buyer's own ledger of
 * a purchase it started, and it exists for one reason: a purchase spans a
 * shielded payment, a confirmation wait, and a file download, so a buyer that
 * crashes (or is restarted, or simply walks away) between paying and
 * collecting must be able to come back and finish. Without a persisted buyer
 * row, "paid but never delivered" is money spent with nothing on disk and no
 * name for the state.
 *
 * Every field here is what resuming needs and nothing else:
 *   order_id/payment_addr/memo  — re-poll the merchant for this exact order
 *   amount_zatoshi              — what confirmation must cover
 *   token_id/customer_addr      — re-request the gated bytes
 *   content_hash                — verify the bytes before writing them
 *   output_path                 — where the verified bytes land
 *   stage/last_error            — where we got to, and why we stopped
 *
 * Schema lives in migration v40 (database_migrate_features_v30_up.c).
 * App-layer only: never read by consensus, safe to drop and re-create. */

#ifndef ZCL_DB_MODEL_STORE_PURCHASE_H
#define ZCL_DB_MODEL_STORE_PURCHASE_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    STORE_PURCHASE_NAME_MAX = 255,
    /* 64 admits a ZSLP genesis token id (32 bytes, 64 hex chars) verbatim —
     * mirror of STORE_PRODUCT_TOKEN_MAX; the access gate settles in ZSLP. */
    STORE_PURCHASE_TOKEN_MAX = 64,
    STORE_PURCHASE_ADDR_MAX = 127,
    STORE_PURCHASE_MEMO_MAX = 63,
    STORE_PURCHASE_PATH_MAX = 511,
    STORE_PURCHASE_OPID_MAX = 127,
    STORE_PURCHASE_ERROR_MAX = 191
};

/* Stage ladder. Monotonic in the happy path; FAILED is terminal-until-retried
 * and always carries a last_error naming the refusal. PAID is the one that
 * makes this table load-bearing: value has left the buyer's wallet and the
 * merchant has credited the order, but no bytes are on disk yet. */
enum store_purchase_stage {
    STORE_PURCHASE_CREATED = 0,   /* order placed, nothing paid */
    STORE_PURCHASE_PAYING = 1,    /* shielded send submitted, not confirmed */
    STORE_PURCHASE_PAID = 2,      /* merchant credited the order; undelivered */
    STORE_PURCHASE_DELIVERED = 3, /* bytes verified against the hash + written */
    STORE_PURCHASE_FAILED = 4     /* stopped; last_error says why */
};

struct db_store_purchase {
    int64_t id;
    int64_t order_id;
    int64_t product_id;
    char product_name[STORE_PURCHASE_NAME_MAX + 1];
    char token_id[STORE_PURCHASE_TOKEN_MAX + 1];
    char payment_addr[STORE_PURCHASE_ADDR_MAX + 1];
    char customer_addr[STORE_PURCHASE_ADDR_MAX + 1];
    char memo[STORE_PURCHASE_MEMO_MAX + 1];
    int64_t amount_zatoshi;
    uint8_t content_hash[32];
    bool has_content_hash;
    char output_path[STORE_PURCHASE_PATH_MAX + 1];
    char operation_id[STORE_PURCHASE_OPID_MAX + 1];
    int stage;
    char last_error[STORE_PURCHASE_ERROR_MAX + 1];
    int64_t created_at;
    int64_t updated_at;
};

struct ar_callbacks *db_store_purchase_callbacks(void);

/* Stable lowercase token for a stage ("created", "paying", "paid",
 * "delivered", "failed"). Never NULL — an out-of-range stage answers
 * "unknown" rather than indexing past the table. */
const char *store_purchase_stage_name(int stage);

bool db_store_purchase_validate(const struct db_store_purchase *p,
                                struct ar_errors *errors);

/* Insert (id == 0) or update (id > 0). On insert the assigned rowid is
 * written back to p->id, so the caller can address the row it just made.
 * created_at/updated_at are stamped here when unset/always respectively. */
bool db_store_purchase_save(struct node_db *ndb, struct db_store_purchase *p);

bool db_store_purchase_find(struct node_db *ndb, int64_t id,
                            struct db_store_purchase *out);

/* One purchase by the MERCHANT order id it tracks. order_id is UNIQUE, so
 * this is what makes "start the same order twice" idempotent instead of
 * minting a second buyer row for one payment obligation. */
bool db_store_purchase_find_by_order(struct node_db *ndb, int64_t order_id,
                                     struct db_store_purchase *out);

/* Newest first, bounded by `max`. Returns the row count written. */
int db_store_purchase_list(struct node_db *ndb, struct db_store_purchase *out,
                           size_t max);

/* Purchases that owe the buyer something: stage in (CREATED, PAYING, PAID).
 * This is the "nothing silently vanished" counter — a non-zero answer means
 * there is unfinished business a resume pass can act on. Returns 0 on error,
 * which is indistinguishable from "nothing outstanding" ON PURPOSE only for
 * display; the resume path lists rows rather than trusting this count. */
int db_store_purchase_count_unfinished(struct node_db *ndb);

#endif /* ZCL_DB_MODEL_STORE_PURCHASE_H */
