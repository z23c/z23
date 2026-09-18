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
#include "core/amount.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/store.h"
#include "net/puzzle.h"
#include "net/tor_integration.h" // shape-layer-ok:remote-buyer-rides-the-onion-fetch
#include "util/safe_alloc.h"

#include <errno.h>
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
        return false; // raw-return-ok:pure bounded page parser; caller reports the journey failure
    len = (size_t)(end - p);
    if (len >= out_size)
        return false;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

/* Parse and bound the seller-supplied proof-of-work parameters.
 *
 * Pure (no I/O, no solving) so tests can drive it directly. Both fields
 * must be strict base-10 integers: empty, trailing junk, and out-of-range
 * are refused. bits is additionally bounded by what the server can ever
 * issue (1..PUZZLE_MAX_BITS); anything larger would send
 * puzzle_solve_random into an effectively unbounded search on a hostile or
 * broken seller's say-so. */
static bool sb_strict_ll(const char *s, long long lo, long long hi,
                         long long *out)
{
    char *end = NULL;
    long long v;
    if (!s || !s[0])
        return false; // raw-return-ok:empty field is the refused-challenge outcome, named by the caller
    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0' || v < lo || v > hi)
        return false; // raw-return-ok:junk or out-of-range field is the refused-challenge outcome, named by the caller
    *out = v;
    return true;
}

bool store_buyer_pow_params(const char *ts_str, const char *bits_str,
                            int64_t *ts, int *bits)
{
    long long ts_v, bits_v;
    if (!ts || !bits || !sb_strict_ll(ts_str, INT64_MIN, INT64_MAX, &ts_v) ||
        !sb_strict_ll(bits_str, 1, PUZZLE_MAX_BITS, &bits_v))
        return false; // raw-return-ok:a seller challenge outside the bound refuses the order form; remotebuy names it
    *ts = (int64_t)ts_v;
    *bits = (int)bits_v;
    return true;
}

/* Take from an already-fetched product page BOTH things the order form
 * carries: the CSRF token and the live proof-of-work challenge. One page,
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
static bool sb_solve_order_form_page(const char *page,
                                     char *csrf, size_t csrf_max,
                                     char *pow_ts, size_t ts_max,
                                     char *pow_nonce, size_t nonce_max)
{
    char seed_hex[65], token_hex[65], ts_str[32], bits_str[16];
    uint8_t seed[32], token[32];
    uint64_t nonce = 0;
    int64_t ts;
    int bits;

    if (!sb_scrape_attr(page, "name='csrf_token' value",
                        csrf, csrf_max) ||
        !sb_scrape_attr(page, "data-pow-seed",
                        seed_hex, sizeof(seed_hex)) ||
        !sb_scrape_attr(page, "data-pow-token",
                        token_hex, sizeof(token_hex)) ||
        !sb_scrape_attr(page, "data-pow-ts",
                        ts_str, sizeof(ts_str)) ||
        !sb_scrape_attr(page, "data-pow-bits",
                        bits_str, sizeof(bits_str)))
        return false;
    if (strlen(seed_hex) != 64 || strlen(token_hex) != 64)
        return false;
    if (ParseHex(seed_hex, seed, sizeof(seed)) != sizeof(seed) ||
        ParseHex(token_hex, token, sizeof(token)) != sizeof(token))
        return false;

    if (!store_buyer_pow_params(ts_str, bits_str, &ts, &bits))
        return false; // raw-return-ok:an unbounded or malformed seller challenge is refused like an unreadable form; remotebuy names the order-form failure
    if (!puzzle_solve_random(seed, token, ts, bits, &nonce))
        return false; // raw-return-ok:bounded PoW solve failure propagates to the command error body

    (void)snprintf(pow_ts, ts_max, "%lld", (long long)ts);
    (void)snprintf(pow_nonce, nonce_max, "%llu", (unsigned long long)nonce);
    return true;
}

/* Fetch the product page from THIS node's store and solve its order form. */
static bool sb_solve_order_form(const char *datadir, int64_t product_id,
                                char *csrf, size_t csrf_max,
                                char *pow_ts, size_t ts_max,
                                char *pow_nonce, size_t nonce_max)
{
    uint8_t *page;
    char path[64];
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

    ok = sb_solve_order_form_page((const char *)page, csrf, csrf_max,
                                  pow_ts, ts_max, pow_nonce, nonce_max);
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

/* ── remote order: the same buyer, across Tor ───────────────────────── */

/* Validate and normalize a seller onion address into "…56 base32….onion"
 * form. Strict on purpose: this string scopes the purchase row's
 * uniqueness and every later poll/collect fetch, so a malformed seller is
 * refused here rather than parked on a durable row. */
static bool sb_normalize_seller_onion(const char *in, char *out, size_t out_size)
{
    static const char alph[] = "abcdefghijklmnopqrstuvwxyz234567";
    size_t len;

    if (!in || !out || out_size < 63)
        return false;
    len = strlen(in);
    if (len == 62 && strcmp(in + 56, ".onion") == 0)
        len = 56;
    if (len != 56)
        return false;
    for (size_t i = 0; i < 56; i++) {
        if (!strchr(alph, in[i]))
            return false; // raw-return-ok:pure bounded onion-address validator
    }
    (void)snprintf(out, out_size, "%.56s.onion", in);
    return true;
}

/* One blocking GET against the seller's onion service. Returns the HTTP
 * status (200, 404, …) with the response body owned by res->body (caller
 * frees), or 0 when no response arrived at all (Tor down, timeout, fetch
 * refused). The blocking layer hands back the body even for error
 * statuses, so the caller can name the merchant's refusal. */
static int sb_onion_get(const char *seller_onion, const char *path,
                        struct onion_fetch_result *res)
{
    memset(res, 0, sizeof(*res));
    (void)tor_integration_fetch_onion_blocking(seller_onion, path, res,
                                               SB_ONION_TIMEOUT_SECS);
    if (res->status < 100 || res->status > 599) {
        free(res->body);
        res->body = NULL;
        res->body_len = 0;
        return 0;
    }
    return res->status;
}

/* Scrape the first <div class='addr'>…</div> AFTER `marker` out of a store
 * page. On the payment page the marker is "Send exactly", and the first
 * address div after it is the one-time payment address; anchoring on the
 * marker keeps a stray address elsewhere in the chrome from being picked. */
static bool sb_scrape_addr_after(const char *page, const char *marker,
                                 char *out, size_t out_size)
{
    const char *p, *end;
    size_t len;

    p = page ? strstr(page, marker) : NULL;
    if (!p)
        return false;
    p = strstr(p, "class='addr'>");
    if (!p)
        return false;
    p += strlen("class='addr'>");
    end = strchr(p, '<');
    if (!end)
        return false; // raw-return-ok:pure bounded page parser; caller reports the journey failure
    len = (size_t)(end - p);
    if (len == 0 || len >= out_size)
        return false;
    memcpy(out, p, len);
    out[len] = '\0';
    return true;
}

/* Parse the product detail JSON twin (/store/products/<id>.json): the
 * remote buyer's price, access token and content hash — everything the
 * local buyer reads from the products table. Refuses a document whose id
 * is not the product that was asked for. */
bool store_buyer_parse_product_json(const char *text, int64_t want_id,
                                    char *name, size_t name_max,
                                  char *token_id, size_t token_max,
                                  int64_t *price_zatoshi,
                                  bool *has_content_hash,
                                  uint8_t content_hash[32])
{
    struct json_value doc;
    const char *hash_hex;
    const char *s;

    if (!text || !json_read(&doc, text, strlen(text)))
        return false;
    if (json_get_int(json_get(&doc, "id")) != want_id) {
        json_free(&doc);
        return false;
    }
    s = json_get_str(json_get(&doc, "name"));
    (void)snprintf(name, name_max, "%s", s ? s : "");
    s = json_get_str(json_get(&doc, "token_id"));
    (void)snprintf(token_id, token_max, "%s", s ? s : "");
    *price_zatoshi = json_get_int(json_get(&doc, "price_zatoshi"));
    *has_content_hash = false;
    hash_hex = json_get_str(json_get(&doc, "content_hash"));
    bool claims = json_get_bool(json_get(&doc, "has_content"));
    bool hash_ok = hash_hex && strlen(hash_hex) == 64 &&
        ParseHex(hash_hex, content_hash, 32) == 32;
    json_free(&doc);
    if (claims && !hash_ok)
        return false; // raw-return-ok:a seller claiming a file without a verifiable hash is refused before payment; the caller names it
    *has_content_hash = claims;
    return *price_zatoshi > 0 && MoneyRange(*price_zatoshi);
}

/* Step 1 of a remote order: the product detail JSON twin — price, token and
 * content hash, the remote answer to the local buyer's products-table
 * precheck. A 404 is an unknown product; no answer at all names the
 * transport. */
static struct zcl_result sb_remote_product_info(const char *seller,
                                                int64_t product_id,
                                                char *name, size_t name_size,
                                                char *token_id,
                                                size_t token_id_size,
                                                int64_t *price_zatoshi,
                                                bool *has_content_hash,
                                                uint8_t content_hash[32])
{
    struct onion_fetch_result res;
    char path[128];
    (void)snprintf(path, sizeof(path), "/store/products/%lld.json",
                   (long long)product_id);
    int status = sb_onion_get(seller, path, &res);
    if (status == 0)
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "no answer from %s — is this node running -tor, and "
                        "is the seller's store reachable?", seller);
    if (status != 200 || !res.body) {
        free(res.body);
        return SB_FAILF(STORE_BUYER_ERR_UNKNOWN_PRODUCT,
                        "product %lld is not on sale at %s (HTTP %d)",
                        (long long)product_id, seller, status);
    }
    bool parsed = store_buyer_parse_product_json((const char *)res.body,
                                        product_id, name, name_size, token_id,
                                        token_id_size, price_zatoshi,
                                        has_content_hash, content_hash);
    free(res.body);
    if (!parsed)
        return SB_FAILF(STORE_BUYER_ERR_UNKNOWN_PRODUCT,
                        "the store at %s did not describe product %lld",
                        seller, (long long)product_id);
    return ZCL_OK;
}

/* Step 2: the product page yields a CSRF token + live proof-of-work, solved
 * with the same primitive the merchant verifies — the scripted buyer pays
 * the same admission cost as a browser. */
static struct zcl_result sb_remote_order_form(const char *seller,
                                              int64_t product_id,
                                              char *csrf, size_t csrf_size,
                                              char *pow_ts, size_t pow_ts_size,
                                              char *pow_nonce,
                                              size_t pow_nonce_size)
{
    struct onion_fetch_result res;
    char path[128];
    (void)snprintf(path, sizeof(path), "/store/product/%lld",
                   (long long)product_id);
    int status = sb_onion_get(seller, path, &res);
    bool solved = status == 200 && res.body &&
        sb_solve_order_form_page((const char *)res.body, csrf, csrf_size,
                                 pow_ts, pow_ts_size,
                                 pow_nonce, pow_nonce_size);
    free(res.body);
    if (!solved)
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "could not obtain a CSRF token and a solved "
                        "proof-of-work for product %lld at %s (HTTP %d)",
                        (long long)product_id, seller, status);
    return ZCL_OK;
}

/* Step 3: the order POST itself — the wire gap this service exists to close.
 * The merchant's CSRF check, PoW gate, pending-pool caps and onion
 * front-door rate limits all see an ordinary browser-shaped order. */
static struct zcl_result sb_remote_post_order(const char *seller,
                                              int64_t product_id,
                                              const char *customer_addr,
                                              bool transparent,
                                              const char *csrf,
                                              const char *pow_ts,
                                              const char *pow_nonce,
                                              int64_t *order_id,
                                              char *payment_addr,
                                              size_t payment_addr_size)
{
    struct onion_fetch_result res;
    char body[512];
    (void)snprintf(body, sizeof(body),
                   "product_id=%lld&customer_addr=%s&csrf_token=%s"
                   "&pow_ts=%s&pow_nonce=%s&payment_kind=%s",
                   (long long)product_id, customer_addr, csrf, pow_ts,
                   pow_nonce, transparent ? "transparent" : "shielded");
    memset(&res, 0, sizeof(res));
    (void)tor_integration_fetch_onion_post_blocking(seller, "/store/orders",
                                                    (const uint8_t *)body,
                                                    strlen(body), &res,
                                                    SB_ONION_TIMEOUT_SECS);
    bool placed = res.status == 200 && res.body &&
        sb_scrape_order_id((const char *)res.body, order_id) &&
        sb_scrape_addr_after((const char *)res.body, "Send exactly",
                             payment_addr, payment_addr_size);
    if (!placed) {
        char head[64];
        (void)snprintf(head, sizeof(head), "%.40s",
                       res.body ? (const char *)res.body : "(no response)");
        int status = res.status;
        free(res.body);
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "the store at %s refused product %lld (HTTP %d): %s",
                        seller, (long long)product_id, status, head);
    }
    if (!store_buyer_remote_addr_matches(payment_addr, transparent)) {
        free(res.body);
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "store_buyer: the store at %s answered a %s order "
                        "with a %s payment address; refusing to pay",
                        seller, transparent ? "transparent" : "shielded",
                        transparent ? "non-transparent" : "non-shielded");
    }
    free(res.body);
    return ZCL_OK;
}

bool store_buyer_remote_reuse_ok(const struct db_store_purchase *existing,
                                 int64_t product_id, int64_t price_zatoshi,
                                 bool has_content_hash,
                                 const uint8_t *content_hash)
{
    if (!existing || existing->stage != STORE_PURCHASE_CREATED)
        return false;
    if (existing->product_id != product_id ||
        existing->amount_zatoshi != price_zatoshi ||
        existing->has_content_hash != has_content_hash)
        return false;
    return !has_content_hash ||
           (content_hash && memcmp(existing->content_hash, content_hash,
                                   sizeof(existing->content_hash)) == 0);
}

/* Step 4: record the buyer's side, scoped to THIS seller: merchant order ids
 * are per-merchant, so (seller_onion, order_id) is the idempotence key — a
 * retry of the same unpaid order refreshes the existing row rather than
 * minting a second obligation. Anything else reusing the id is refused
 * before the row is touched (store_buyer_remote_reuse_ok). */
static struct zcl_result sb_remote_record_purchase(const char *datadir,
                                                   const char *seller,
                                                   int64_t product_id,
                                                   int64_t order_id,
                                                   const char *name,
                                                   const char *token_id,
                                                   const char *payment_addr,
                                                   const char *customer_addr,
                                                   const char *output_path,
                                                   int64_t price_zatoshi,
                                                   bool has_content_hash,
                                                   const uint8_t *content_hash,
                                                   struct db_store_purchase *purchase)
{
    struct node_db ndb;
    struct zcl_result r =
        sb_open_db(datadir, &ndb, "store_buyer.remote_order_record");
    if (!r.ok)
        return r;
    if (!db_store_purchase_find_by_order_seller(&ndb, seller, order_id,
                                                purchase))
        memset(purchase, 0, sizeof(*purchase));
    else if (!store_buyer_remote_reuse_ok(purchase, product_id, price_zatoshi,
                                          has_content_hash, content_hash)) {
        node_db_close(&ndb);
        return SB_FAILF(STORE_BUYER_ERR_ORDER_CREATE_FAILED,
                        "store_buyer: seller reused order id %lld for a "
                        "different purchase (existing row %lld kept)",
                        (long long)order_id, (long long)purchase->id);
    }

    purchase->order_id = order_id;
    purchase->product_id = product_id;
    (void)snprintf(purchase->product_name, sizeof(purchase->product_name),
                   "%s", name);
    (void)snprintf(purchase->token_id, sizeof(purchase->token_id), "%s",
                   token_id);
    (void)snprintf(purchase->payment_addr, sizeof(purchase->payment_addr),
                   "%s", payment_addr);
    (void)snprintf(purchase->customer_addr, sizeof(purchase->customer_addr),
                   "%s", customer_addr);
    (void)snprintf(purchase->memo, sizeof(purchase->memo), "ZCL23ORDER:%lld",
                   (long long)order_id);
    purchase->amount_zatoshi = price_zatoshi;
    purchase->has_content_hash = has_content_hash;
    if (has_content_hash)
        memcpy(purchase->content_hash, content_hash,
               sizeof(purchase->content_hash));
    if (output_path && output_path[0])
        (void)snprintf(purchase->output_path, sizeof(purchase->output_path),
                       "%s", output_path);
    (void)snprintf(purchase->seller_onion, sizeof(purchase->seller_onion),
                   "%s", seller);
    if (purchase->id == 0)
        purchase->stage = STORE_PURCHASE_CREATED;
    purchase->last_error[0] = '\0';

    bool saved = db_store_purchase_save(&ndb, purchase);
    node_db_close(&ndb);
    if (!saved)
        return SB_FAILF(STORE_BUYER_ERR_DB,
                        "created merchant order %lld at %s but could not "
                        "record the buyer purchase row",
                        (long long)order_id, seller);
    return ZCL_OK;
}

struct zcl_result store_buyer_remote_order(const char *datadir,
                                           const char *seller_onion,
                                           int64_t product_id,
                                           const char *customer_addr,
                                           const char *output_path,
                                           bool transparent,
                                           struct store_buyer_order *out)
{
    struct db_store_purchase purchase;
    char seller[STORE_PURCHASE_ONION_MAX + 1];
    char csrf[80] = "", pow_ts[32] = "", pow_nonce[32] = "";
    char name[STORE_PURCHASE_NAME_MAX + 1];
    char token_id[STORE_PURCHASE_TOKEN_MAX + 1];
    char payment_addr[STORE_PURCHASE_ADDR_MAX + 1];
    uint8_t content_hash[32];
    int64_t price_zatoshi = 0;
    bool has_content_hash = false;
    int64_t order_id = 0;
    struct zcl_result r;

    if (!datadir || !seller_onion || product_id <= 0 || !customer_addr ||
        !customer_addr[0] || !out)
        return SB_FAIL(STORE_BUYER_ERR_ARGS);
    memset(out, 0, sizeof(*out));
    if (!sb_normalize_seller_onion(seller_onion, seller, sizeof(seller)))
        return SB_FAILF(STORE_BUYER_ERR_ARGS,
                        "seller_onion must be a v3 onion address (56 base32 "
                        "characters, optional .onion suffix)");

    r = sb_remote_product_info(seller, product_id, name, sizeof(name),
                               token_id, sizeof(token_id), &price_zatoshi,
                               &has_content_hash, content_hash);
    if (!r.ok)
        return r;
    r = sb_remote_order_form(seller, product_id, csrf, sizeof(csrf),
                             pow_ts, sizeof(pow_ts),
                             pow_nonce, sizeof(pow_nonce));
    if (!r.ok)
        return r;
    r = sb_remote_post_order(seller, product_id, customer_addr, transparent,
                             csrf, pow_ts, pow_nonce, &order_id,
                             payment_addr, sizeof(payment_addr));
    if (!r.ok)
        return r;
    r = sb_remote_record_purchase(datadir, seller, product_id, order_id, name,
                                  token_id, payment_addr, customer_addr,
                                  output_path, price_zatoshi, has_content_hash,
                                  content_hash, &purchase);
    if (!r.ok)
        return r;

    out->purchase_id = purchase.id;
    out->order_id = order_id;
    (void)snprintf(out->payment_addr, sizeof(out->payment_addr), "%s",
                   purchase.payment_addr);
    (void)snprintf(out->memo, sizeof(out->memo), "%s", purchase.memo);
    out->amount_zatoshi = purchase.amount_zatoshi;
    r = ZCL_OK;
    return r;
}
