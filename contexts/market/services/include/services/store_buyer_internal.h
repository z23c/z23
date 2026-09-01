/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internals shared by the two store-buyer service files
 * (store_buyer.c: vocabulary + browse + order; store_buyer_pay.c: pay, poll
 * and collect). Not part of the service API — callers use
 * services/store_buyer.h. The split is a file-size boundary, not a
 * conceptual one: both halves talk to the same store and the same purchase
 * row. */

#ifndef ZCL_SERVICES_STORE_BUYER_INTERNAL_H
#define ZCL_SERVICES_STORE_BUYER_INTERNAL_H

#include "services/store_buyer.h"
#include "models/database.h"
#include "util/log_macros.h"

#include <stdint.h>

#define SB_TAG "store_buyer"

/* One store HTTP exchange fits in this. The gated-download response is the
 * largest: STORE_BLOB_INLINE_MAX bytes of payload plus headers, and the
 * dynhost buffer the live path uses is 64 KiB, so anything the real store
 * can answer with fits here too. Heap, not stack — it is 96 KiB. */
enum { SB_RESP_MAX = 96 * 1024 };

/* Failure literal carrying one store_buyer_status as the result code and its
 * canonical one-line explanation as the message. */
#define SB_FAIL(st) ZCL_ERR((int)(st), "%s", store_buyer_status_message(st))

/* Same, with extra context appended — use whenever the caller would
 * otherwise have to guess which product, purchase or path was involved. */
#define SB_FAILF(st, ...) ZCL_ERR((int)(st), __VA_ARGS__)

/* Open the node database that backs `datadir`'s store. A runtime reopen, not
 * a boot ceremony — the same call the store's own request path makes.
 * Answers struct zcl_result like everything else here: a service that
 * reports "could not open <path>" is strictly more useful than one that
 * reports false, and it keeps this file free of exported bool surfaces. */
struct zcl_result sb_open_db(const char *datadir, struct node_db *ndb,
                             const char *tag);

/* Load one purchase row, or fail with UNKNOWN_PURCHASE / INVALID_ARGS. */
struct zcl_result sb_load_purchase(struct node_db *ndb, int64_t purchase_id,
                                   struct db_store_purchase *out);

/* Ask the store for its product page and throw the answer away — see the
 * definition in store_buyer.c for why a buyer has to do this. */
void sb_warm_store(const char *datadir);

#endif /* ZCL_SERVICES_STORE_BUYER_INTERNAL_H */
