/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store BUYER service, part 1 of 2: the result vocabulary, the shared store
 * plumbing, browsing a catalog, and placing an order. Paying, polling and
 * collecting live in store_buyer_pay.c. See services/store_buyer.h for what
 * this is and why it drives the shipped store surfaces rather than
 * shortcutting past them.
 *
 * The three upward includes below are the shape of the thing on purpose: a
 * buyer is a CLIENT of the store's request handler and of the node's spend
 * guard. Reaching around either — building an order row directly, or paying
 * without asking the guard — is exactly what this service must not do. */

#include "services/store_buyer_internal.h"

#include "controllers/store_controller.h" // shape-layer-ok:buyer-is-a-store-client
#include "chain/chainparams.h"
#include "encoding/utilstrencodings.h"
#include "models/store.h"
#include "net/puzzle.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── status vocabulary ──────────────────────────────────────────────── */

const char *store_buyer_status_code(int code)
{
    switch ((enum store_buyer_status)code) {
    case STORE_BUYER_OK:                    return "OK";
    case STORE_BUYER_ERR_ARGS:              return "INVALID_ARGS";
    case STORE_BUYER_ERR_MAINNET_REFUSED:   return "MAINNET_REFUSED";
    case STORE_BUYER_ERR_DB:                return "NODE_DB_UNAVAILABLE";
    case STORE_BUYER_ERR_UNKNOWN_PRODUCT:   return "UNKNOWN_PRODUCT";
    case STORE_BUYER_ERR_ORDER_CREATE_FAILED: return "ORDER_CREATE_FAILED";
    case STORE_BUYER_ERR_UNKNOWN_PURCHASE:  return "UNKNOWN_PURCHASE";
    case STORE_BUYER_ERR_ALREADY_PAID:      return "ALREADY_PAID";
    case STORE_BUYER_ERR_PROVER_UNAVAILABLE: return "PROVER_UNAVAILABLE";
    case STORE_BUYER_ERR_SPEND_REFUSED:     return "SPEND_REFUSED";
    case STORE_BUYER_ERR_INSUFFICIENT_FUNDS: return "INSUFFICIENT_FUNDS";
    case STORE_BUYER_ERR_PAYMENT_NOT_CONFIRMED: return "PAYMENT_NOT_CONFIRMED";
    case STORE_BUYER_ERR_DELIVERY_FAILED:   return "DELIVERY_FAILED";
    case STORE_BUYER_ERR_HASH_MISMATCH:     return "HASH_MISMATCH";
    case STORE_BUYER_ERR_WRITE_FAILED:      return "WRITE_FAILED";
    case STORE_BUYER_ERR_INTERNAL:          return "INTERNAL";
    }
    return "UNKNOWN";
}

const char *store_buyer_status_message(int code)
{
    switch ((enum store_buyer_status)code) {
    case STORE_BUYER_OK:
        return "ok";
    case STORE_BUYER_ERR_ARGS:
        return "the request is missing a required value or one is out of range";
    case STORE_BUYER_ERR_MAINNET_REFUSED:
        return "scripted store payments are refused on mainnet; "
               "run this on regtest or testnet";
    case STORE_BUYER_ERR_DB:
        return "the node database is not open";
    case STORE_BUYER_ERR_UNKNOWN_PRODUCT:
        return "no active product with that id";
    case STORE_BUYER_ERR_ORDER_CREATE_FAILED:
        return "the store refused to create the order";
    case STORE_BUYER_ERR_UNKNOWN_PURCHASE:
        return "no purchase with that id";
    case STORE_BUYER_ERR_ALREADY_PAID:
        return "a payment for this purchase was already submitted";
    case STORE_BUYER_ERR_PROVER_UNAVAILABLE:
        return "this build has no Sapling proving backend, so it cannot "
               "send a shielded payment";
    case STORE_BUYER_ERR_SPEND_REFUSED:
        return "the node refuses to spend from this tip";
    case STORE_BUYER_ERR_INSUFFICIENT_FUNDS:
        return "the wallet cannot cover the order amount";
    case STORE_BUYER_ERR_PAYMENT_NOT_CONFIRMED:
        return "the merchant has not credited this order yet";
    case STORE_BUYER_ERR_DELIVERY_FAILED:
        return "the store did not return the purchased bytes";
    case STORE_BUYER_ERR_HASH_MISMATCH:
        return "the delivered bytes do not match the product content hash; "
               "nothing was written";
    case STORE_BUYER_ERR_WRITE_FAILED:
        return "the verified bytes could not be written to the output path";
    case STORE_BUYER_ERR_INTERNAL:
        return "the node ran out of working memory for this purchase step";
    }
    return "unknown store buyer status";
}

/* ── shared plumbing ────────────────────────────────────────────────── */

struct zcl_result sb_open_db(const char *datadir, struct node_db *ndb,
                             const char *tag)
{
    char db_path[1024];
    if (!datadir || !*datadir || !ndb)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    (void)snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    memset(ndb, 0, sizeof(*ndb));
    if (!node_db_open_runtime(ndb, db_path, tag))
        return SB_FAILF(STORE_BUYER_ERR_DB, "cannot open %s", db_path);
    return ZCL_OK;
}

/* Ask the store for its product page and throw the answer away.
 *
 * This is not a formality. A store's catalog is materialised the first time
 * the store is asked for it (store_ensure_schema runs on the request path,
 * not at boot), so a buyer that read the products table directly on a
 * never-visited store would see an empty catalog and conclude there was
 * nothing for sale. A browser warms the store simply by loading the page;
 * doing the same here keeps the buyer an ordinary client rather than
 * something that reaches behind the counter. Best-effort: a store that
 * cannot answer leaves the caller's own DB read to report the truth. */
void sb_warm_store(const char *datadir)
{
    uint8_t *page = zcl_malloc(SB_RESP_MAX, "store_buyer_warm");
    if (!page)
        return;
    (void)store_handle_request("GET", "/store/products", NULL, 0, page,
                               SB_RESP_MAX, datadir);
    free(page);
}

struct zcl_result sb_load_purchase(struct node_db *ndb, int64_t purchase_id,
                                   struct db_store_purchase *out)
{
    if (purchase_id <= 0)
        return SB_FAILF(STORE_BUYER_ERR_ARGS,
                        "purchase id must be positive, got %lld",
                        (long long)purchase_id);
    if (!db_store_purchase_find(ndb, purchase_id, out))
        return SB_FAILF(STORE_BUYER_ERR_UNKNOWN_PURCHASE,
                        "no purchase %lld on this node",
                        (long long)purchase_id);
    return ZCL_OK;
}

/* ── catalog ────────────────────────────────────────────────────────── */

struct zcl_result store_buyer_catalog(const char *datadir,
                                      struct store_buyer_offer *out,
                                      size_t max, size_t *n_out)
{
    struct node_db ndb;
    struct db_store_product *rows;
    struct zcl_result r;
    int count;

    if (n_out)
        *n_out = 0;
    if (!datadir || !out || max == 0 || !n_out)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);

    sb_warm_store(datadir);
    r = sb_open_db(datadir, &ndb, "store_buyer.catalog");
    if (!r.ok)
        return r;

    rows = zcl_calloc(max, sizeof(*rows), "store_buyer_catalog_rows");
    if (!rows) {
        node_db_close(&ndb);
        return SB_FAILF(STORE_BUYER_ERR_INTERNAL,
                        "could not allocate %zu product rows", max);
    }

    count = db_store_product_list_active(&ndb, rows, max);
    for (int i = 0; i < count; i++) {
        /* list_active does not read content_hash; re-read the row by id so
         * the buyer learns whether there is a file to collect at all. That
         * is the difference between "buy this" and "buy this and get an
         * HTML page", and it decides whether a collect can ever succeed. */
        struct db_store_product full;
        bool have_full = db_store_product_find_active(&ndb, rows[i].id, &full);
        out[i].product_id = rows[i].id;
        (void)snprintf(out[i].name, sizeof(out[i].name), "%s", rows[i].name);
        (void)snprintf(out[i].token_id, sizeof(out[i].token_id), "%s",
                       rows[i].token_id);
        out[i].price_zatoshi = rows[i].price_zatoshi;
        out[i].tokens_per_purchase = rows[i].tokens_per_purchase;
        out[i].has_content = have_full && full.has_content;
    }
    free(rows);
    node_db_close(&ndb);
    *n_out = (size_t)(count > 0 ? count : 0);
    return ZCL_OK;
}

/* ── order-create: the browser's job, done by a program ─────────────── */

/* Read the value of `attr='...'` out of an already-fetched page. */
static bool sb_scrape_attr(const char *page, const char *attr,
                           char *out, size_t out_size)
{
    char needle[64];
    const char *p, *end;
    size_t len;

    (void)snprintf(needle, sizeof(needle), "%s='", attr);
    p = strstr(page, needle);
    if (!p)
        return false;
    p += strlen(needle);
    end = strchr(p, '\'');
    if (!end)
        return false;
    len = (size_t)(end - p);
    if (len >= out_size)
        return false;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

/* Fetch the product page once and take from it BOTH things the order form
 * carries: the CSRF token and the live proof-of-work challenge. One fetch,
 * because each render issues a fresh challenge — reading the two from
 * different pages would submit a nonce for a seed the server has moved past.
 *
 * The puzzle is solved with puzzle_solve_random, the same primitive
 * store_pow_verify_and_claim checks against, from a random start (a search
 * from zero is a pure function of the challenge, so two orders for one
 * product inside one second would produce the same nonce and the store's
 * single-use ring would refuse the second).
 *
 * Note what is deliberately NOT done here: the difficulty ramp is not reset
 * and the gate is not bypassed. A scripted buyer pays the same admission
 * cost as a browser, which is the point of the gate. */
static bool sb_solve_order_form(const char *datadir, int64_t product_id,
                                char *csrf, size_t csrf_max,
                                char *pow_ts, size_t ts_max,
                                char *pow_nonce, size_t nonce_max)
{
    uint8_t *page;
    char path[64];
    char seed_hex[65], token_hex[65], ts_str[32], bits_str[16];
    uint8_t seed[32], token[32];
    uint64_t nonce = 0;
    int64_t ts;
    int bits;
    size_t n;
    bool ok = false;

    page = zcl_malloc(SB_RESP_MAX, "store_buyer_product_page");
    if (!page)
        return false;

    (void)snprintf(path, sizeof(path), "/store/product/%lld",
                   (long long)product_id);
    n = store_handle_request("GET", path, NULL, 0, page, SB_RESP_MAX, datadir);
    if (n == 0)
        goto out;
    page[(n < SB_RESP_MAX) ? n : (SB_RESP_MAX - 1)] = '\0';

    if (!sb_scrape_attr((const char *)page, "name='csrf_token' value",
                        csrf, csrf_max) ||
        !sb_scrape_attr((const char *)page, "data-pow-seed",
                        seed_hex, sizeof(seed_hex)) ||
        !sb_scrape_attr((const char *)page, "data-pow-token",
                        token_hex, sizeof(token_hex)) ||
        !sb_scrape_attr((const char *)page, "data-pow-ts",
                        ts_str, sizeof(ts_str)) ||
        !sb_scrape_attr((const char *)page, "data-pow-bits",
                        bits_str, sizeof(bits_str)))
        goto out;
    if (strlen(seed_hex) != 64 || strlen(token_hex) != 64)
        goto out;
    if (ParseHex(seed_hex, seed, sizeof(seed)) != sizeof(seed) ||
        ParseHex(token_hex, token, sizeof(token)) != sizeof(token))
        goto out;

    ts = strtoll(ts_str, NULL, 10);
    bits = (int)strtol(bits_str, NULL, 10);
    if (bits <= 0)
        goto out;
    if (!puzzle_solve_random(seed, token, ts, bits, &nonce))
        goto out;

    (void)snprintf(pow_ts, ts_max, "%lld", (long long)ts);
    (void)snprintf(pow_nonce, nonce_max, "%llu", (unsigned long long)nonce);
    ok = true;
out:
    free(page);
    return ok;
}

/* Pull the order id out of the store's "Order #<n>" payment page. That
 * heading is the response's identity, and everything else the buyer needs
 * (payment address, amount) is then read from the order row rather than
 * scraped — the memo format is a contract of the merchant's matcher
 * (db_store_received_payment_for_memo), not of this HTML. */
static bool sb_scrape_order_id(const char *page, int64_t *out)
{
    const char *p = strstr(page, "Order #");
    char *end = NULL;
    long long v;

    if (!p)
        return false;
    p += strlen("Order #");
    v = strtoll(p, &end, 10);
    if (!end || end == p || v <= 0)
        return false;
    *out = (int64_t)v;
    return true;
}

struct zcl_result store_buyer_order(const char *datadir, int64_t product_id,
                                    const char *customer_addr,
                                    const char *output_path,
                                    bool transparent,
                                    struct store_buyer_order *out)
{
    struct node_db ndb;
    struct db_store_product product;
    struct db_store_order_view order_view;
    struct db_store_purchase purchase;
    char csrf[80] = "", pow_ts[32] = "", pow_nonce[32] = "";
    char body[512];
    uint8_t *resp = NULL;
    size_t n;
    int64_t order_id = 0;
    struct zcl_result r;

    if (!datadir || product_id <= 0 || !customer_addr || !customer_addr[0] ||
        !out)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    memset(out, 0, sizeof(*out));
    sb_warm_store(datadir);

    /* Refuse an unknown product before spending a proof-of-work solve on it. */
    r = sb_open_db(datadir, &ndb, "store_buyer.order_precheck");
    if (!r.ok)
        return r;
    bool known = db_store_product_find_active(&ndb, product_id, &product);
    node_db_close(&ndb);
    if (!known)
        return SB_FAILF(STORE_BUYER_ERR_UNKNOWN_PRODUCT,
                        "product %lld is not on sale", (long long)product_id);

    if (!sb_solve_order_form(datadir, product_id, csrf, sizeof(csrf),
                             pow_ts, sizeof(pow_ts),
                             pow_nonce, sizeof(pow_nonce)))
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "could not obtain a CSRF token and a solved "
                        "proof-of-work for product %lld",
                        (long long)product_id);

    resp = zcl_malloc(SB_RESP_MAX, "store_buyer_order_resp");
    if (!resp)
        return SB_FAIL(STORE_BUYER_ERR_INTERNAL);

    (void)snprintf(body, sizeof(body),
                   "product_id=%lld&customer_addr=%s&csrf_token=%s"
                   "&pow_ts=%s&pow_nonce=%s&payment_kind=%s",
                   (long long)product_id, customer_addr, csrf, pow_ts,
                   pow_nonce, transparent ? "transparent" : "shielded");
    n = store_handle_request("POST", "/store/orders",
                             (const uint8_t *)body, strlen(body),
                             resp, SB_RESP_MAX, datadir);
    if (n == 0) {
        free(resp);
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "the store did not answer an order for product %lld",
                        (long long)product_id);
    }
    resp[(n < SB_RESP_MAX) ? n : (SB_RESP_MAX - 1)] = '\0';
    if (!strstr((const char *)resp, "HTTP/1.1 200 OK") ||
        !sb_scrape_order_id((const char *)resp, &order_id)) {
        char head[64];
        (void)snprintf(head, sizeof(head), "%.40s", (const char *)resp);
        free(resp);
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "the store refused product %lld: %s",
                        (long long)product_id, head);
    }
    free(resp);

    r = sb_open_db(datadir, &ndb, "store_buyer.order_record");
    if (!r.ok)
        return r;
    if (!db_store_order_find_view(&ndb, order_id, &order_view)) {
        node_db_close(&ndb);
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "the store answered with order %lld but no such "
                        "order row exists", (long long)order_id);
    }

    /* Idempotent by merchant order id: if this order already has a buyer
     * row, update that one rather than minting a second obligation. */
    if (!db_store_purchase_find_by_order(&ndb, order_id, &purchase))
        memset(&purchase, 0, sizeof(purchase));

    purchase.order_id = order_id;
    purchase.product_id = product_id;
    (void)snprintf(purchase.product_name, sizeof(purchase.product_name), "%s",
                   product.name);
    (void)snprintf(purchase.token_id, sizeof(purchase.token_id), "%s",
                   product.token_id);
    (void)snprintf(purchase.payment_addr, sizeof(purchase.payment_addr), "%s",
                   order_view.payment_addr);
    (void)snprintf(purchase.customer_addr, sizeof(purchase.customer_addr),
                   "%s", customer_addr);
    (void)snprintf(purchase.memo, sizeof(purchase.memo), "ZCL23ORDER:%lld",
                   (long long)order_id);
    purchase.amount_zatoshi = order_view.amount_zatoshi;
    purchase.has_content_hash = product.has_content;
    if (product.has_content)
        memcpy(purchase.content_hash, product.content_hash,
               sizeof(purchase.content_hash));
    if (output_path && output_path[0])
        (void)snprintf(purchase.output_path, sizeof(purchase.output_path),
                       "%s", output_path);
    if (purchase.id == 0)
        purchase.stage = STORE_PURCHASE_CREATED;
    purchase.last_error[0] = '\0';

    bool saved = db_store_purchase_save(&ndb, &purchase);
    node_db_close(&ndb);
    if (!saved)
        return SB_FAILF(STORE_BUYER_ERR_DB,
                        "created merchant order %lld but could not record "
                        "the buyer purchase row", (long long)order_id);

    out->purchase_id = purchase.id;
    out->order_id = order_id;
    (void)snprintf(out->payment_addr, sizeof(out->payment_addr), "%s",
                   purchase.payment_addr);
    (void)snprintf(out->memo, sizeof(out->memo), "%s", purchase.memo);
    out->amount_zatoshi = purchase.amount_zatoshi;
    r = ZCL_OK;
    return r;
}
