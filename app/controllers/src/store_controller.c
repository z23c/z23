/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store controller — ZSLP token commerce. */


#include "base/hex.h"
#include "controllers/store_controller_internal.h"
#include "controllers/web_form.h"
#include "controllers/zslp_controller.h"
/* store_confirmed_payment tells a shielded order address from a transparent
 * one (wallet_addr_is_sapling), and turns a t-address into the hash160 that
 * wallet_utxos keys on (wallet_decode_address). */
#include "controllers/wallet_shielded_controller.h"
#include "controllers/wallet_helpers.h"
/* wallet_direct_getnewaddress — the one-time t-address a transparent order
 * binds to, persisted before it is handed out. */
#include "controllers/wallet_controller.h"

/* Forward declarations (helpers that stay static to this file) */
static bool store_csrf_verify(const char *context, const char *provided);
static bool store_parse_access_query(const char *path,
                                     char *addr, size_t addr_max,
                                     char *token, size_t token_max);
/* POST /store/buy/:id — create order. This is a request action (it mints a
 * one-time payment address and writes the order row), so it lives in the
 * controller; it calls the store view's render helpers to build the response
 * page.
 *
 * `transparent` picks which kind of one-time address the order binds to. Both
 * are one-time and neither is ever reused: the shielded order is bound by the
 * payment memo, the transparent order by the address itself, so a reused
 * transparent address would silently merge two orders' payments. */
static size_t serve_create_order(sqlite3 *db, int64_t product_id,
                                  const char *customer_addr,
                                  const char *datadir,
                                  bool transparent,
                                  uint8_t *resp, size_t max)
{
    struct node_db ndb = { .db = db, .open = true };
    struct db_store_product product;
    memset(&product, 0, sizeof(product));

    if (!db_store_product_find_active(&ndb, product_id, &product)) {
        return (size_t)snprintf((char *)resp, max,
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n"
            "Connection: close\r\n\r\n<h1>Product not found</h1>");
    }

    /* Generate the unique payment address for this order.
     * NEVER fall back to a fake address — that loses user funds. */
    char payment_addr[128];
    bool minted;
    if (transparent) {
        char mint_err[256] = "";
        minted = wallet_direct_getnewaddress(payment_addr,
                                             sizeof(payment_addr),
                                             mint_err, sizeof(mint_err));
        if (!minted) {
            printf("store: CRITICAL — t-address generation failed for "
                   "product %lld: %s\n",
                   (long long)product_id,
                   mint_err[0] ? mint_err : "(no reason given)");
            fflush(stdout);
        }
    } else {
        minted = zslp_generate_payment_address(datadir, payment_addr,
                                               sizeof(payment_addr));
        if (!minted) {
            printf("store: CRITICAL — z-address generation failed for "
                   "product %lld\n", (long long)product_id);
            fflush(stdout);
        }
    }
    if (!minted) {
        return (size_t)snprintf((char *)resp, max,
            "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            "<h1>Payment Temporarily Unavailable</h1>"
            "<p>The node is still loading cryptographic keys. "
            "Please try again in a few minutes.</p>"
            "<p><a href='/store/products'>Back to Store</a></p>");
    }

    struct db_store_order order;
    memset(&order, 0, sizeof(order));
    order.product_id = product_id;
    snprintf(order.customer_addr, sizeof(order.customer_addr), "%s",
             customer_addr ? customer_addr : "");
    snprintf(order.payment_addr, sizeof(order.payment_addr), "%s", payment_addr);
    order.amount_zatoshi = product.price_zatoshi;
    order.status = STORE_ORDER_PENDING;
    if (!db_store_order_save(&ndb, &order)) {
        printf("store: order INSERT failed: %s\n", sqlite3_errmsg(db));
        return (size_t)snprintf((char *)resp, max,
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n"
            "Connection: close\r\n\r\n<h1>Order creation failed</h1>");
    }
    int64_t order_id = order.id;

    /* Show payment page */
    char body[24576];
    size_t off = 0;
    int n = html_body_start(body, sizeof(body), "Payment");
    if (n > 0) off = (size_t)n;

    char safe_pay[256], safe_cust[256];
    html_escape(safe_pay, sizeof(safe_pay), payment_addr);
    html_escape(safe_cust, sizeof(safe_cust),
                customer_addr ? customer_addr : "(not provided)");

    char order_price[32];
    format_zcl_price(order_price, sizeof(order_price), product.price_zatoshi);

    n = snprintf(body + off, sizeof(body) - off,
        "<h1>Order #%lld</h1>"
        "<div class='product'>"
        "<p>Send exactly <span class='price'>%s ZCL</span> to:</p>"
        "<div class='addr'>%s</div>"
        "<button class='btn' style='font-size:12px;padding:6px 12px;cursor:pointer;border:none' "
        "onclick=\"navigator.clipboard?navigator.clipboard.writeText('%s'):void(0);"
        "this.textContent='Copied!'\">Copy Address</button>"
        "<p><strong>You must include this memo</strong> so your payment is "
        "matched to this order:</p>"
        "<div class='addr'>ZCL23ORDER:%lld</div>"
        "<button class='btn' style='font-size:12px;padding:6px 12px;cursor:pointer;border:none' "
        "onclick=\"navigator.clipboard?navigator.clipboard.writeText('ZCL23ORDER:%lld'):void(0);"
        "this.textContent='Copied!'\">Copy Memo</button>"
        "<p>After payment confirms, tokens will be sent to:</p>"
        "<div class='addr'>%s</div>"
        "<p><a href='/store/orders/%lld'>Check payment status</a></p>"
        "</div>"
        "<p><a href='/store/products'>&larr; Back to store</a></p>",
        (long long)order_id,
        order_price,
        safe_pay,
        safe_pay,
        (long long)order_id,
        (long long)order_id,
        safe_cust,
        (long long)order_id);
    if (n > 0) off += (size_t)n;

    n = html_body_end(body + off, sizeof(body) - off);
    if (n > 0) off += (size_t)n;

    return store_html_response(body, off, resp, max);
}


/* Parse resource id from the last path segment and reject malformed ids. */
static bool parse_positive_path_id(const char *path, int64_t *id_out)
{
    const char *last = strrchr(path, '/');
    char *end = NULL;
    long long value;

    if (!id_out)
        return false;
    *id_out = -1;
    if (!last || !last[1])
        return false;
    value = strtoll(last + 1, &end, 10);
    if (!end || *end != '\0' || value <= 0)
        return false;
    *id_out = (int64_t)value;
    return true;
}

static bool path_eq(const char *path, const char *expected)
{
    return path && expected && strcmp(path, expected) == 0;
}

static bool path_has_prefix(const char *path, const char *prefix)
{
    return path && prefix && strncmp(path, prefix, strlen(prefix)) == 0;
}

static bool route_is_product_index(const char *path)
{
    return path_eq(path, "/store") || path_eq(path, "/store/") ||
           path_eq(path, "/store/products") || path_eq(path, "/store/products/");
}

static bool route_is_product_show(const char *path)
{
    return path_has_prefix(path, "/store/product/") ||
           path_has_prefix(path, "/store/products/");
}

static bool route_is_order_show(const char *path)
{
    return path_has_prefix(path, "/store/order/") ||
           path_has_prefix(path, "/store/orders/");
}

static bool route_is_order_index(const char *path)
{
    return path_eq(path, "/store/orders") || path_eq(path, "/store/orders/");
}

static bool route_is_order_create(const char *method, const char *path)
{
    return method && strcmp(method, "POST") == 0 &&
           (path_eq(path, "/store/orders") ||
            path_eq(path, "/store/orders/") ||
            path_has_prefix(path, "/store/buy/"));
}

/* Validate address: must be a valid ZClassic t-address or z-address,
 * with the Base58Check / Bech32 *checksum* verified — not just a
 * syntactically-plausible prefix.  A one-character typo in a t-addr
 * passes a syntactic prefix check but decodes to a random 20-byte hash
 * whose payments are unspendable: funds sent to such an order are
 * burned.  Also prevents XSS via customer_addr in HTML output.
 *
 * Implementation: zcl_validate_zcl_address in app/models/src/shared_validators.c. */

bool store_validate_access_addr(const char *addr)
{
    return addr && addr[0] &&
           zslp_service_validate_recipient_addr(addr, false).ok;
}

bool store_validate_access_token(const char *token)
{
    return token && token[0] &&
           zslp_service_validate_token_key(token).ok;
}

static bool store_parse_query_field(const char *path, const char *field,
                                    char *out, size_t out_max)
{
    const char *p;
    size_t i = 0;
    char needle[32];

    if (!path || !field || !out || out_max == 0)
        return false;
    out[0] = '\0';
    snprintf(needle, sizeof(needle), "%s=", field);
    p = strstr(path, needle);
    if (!p)
        return false;
    p += strlen(needle);
    while (p[i] && p[i] != '&' && i < out_max - 1) {
        if ((unsigned char)p[i] < 32 || (unsigned char)p[i] > 126)
            return false;
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
    return i > 0;
}

static bool store_parse_access_query(const char *path,
                                     char *addr, size_t addr_max,
                                     char *token, size_t token_max)
{
    if (!addr || !token || addr_max == 0 || token_max == 0)
        return false;
    addr[0] = '\0';
    token[0] = '\0';

    if (!store_parse_query_field(path, "addr", addr, addr_max))
        return false; // raw-return-ok:malformed-client-query-not-a-server-error
    if (!store_parse_query_field(path, "token", token, token_max))
        snprintf(token, token_max, "%s", "ZCL23ACCESS");

    return store_validate_access_addr(addr) &&
           store_validate_access_token(token);
}

/* ── CSRF form token ─────────────────────────────────────
 *
 * Without a token, a malicious third-party page can `<form action=
 * 'http://<onion>/store/orders'>` and trick any visiting browser into
 * silently POSTing an unwanted order.  The store has no login/session
 * cookie to bind to, so classical per-session CSRF isn't reachable
 * without plumbing cookies through onion_service.c.  Instead, sign a
 * small context string (order form scope + product-id) with a
 * per-process random HMAC key and embed it as a hidden field.  The
 * browser's same-origin policy prevents JS on a third-party page from
 * reading our GET response body, so it cannot learn the signed token.
 * A server-side attacker with their own curl can, but that's the same
 * capability as direct submission — no amplification from the victim
 * browser. */
static unsigned char s_csrf_key[32];
static bool s_csrf_key_ready = false;

static void store_csrf_init(void)
{
    if (s_csrf_key_ready) return;
    GetRandBytes(s_csrf_key, sizeof(s_csrf_key));
    s_csrf_key_ready = true;
}

/* Write 32-char lowercase-hex token for `context` into out (33 bytes incl NUL). */
void store_csrf_token(const char *context, char out[33])
{
    store_csrf_init();
    struct hmac_sha256_ctx ctx;
    unsigned char mac[HMAC_SHA256_OUTPUT_SIZE];
    hmac_sha256_init(&ctx, s_csrf_key, sizeof(s_csrf_key));
    hmac_sha256_write(&ctx, (const unsigned char *)context, strlen(context));
    hmac_sha256_finalize(&ctx, mac);
    zcl_hex_encode(mac, 16, out);
}

/* Constant-time check: does `provided` match the token for `context`? */
static bool store_csrf_verify(const char *context, const char *provided)
{
    if (!context || !provided) return false;
    if (strlen(provided) != 32) return false;
    char expected[33];
    store_csrf_token(context, expected);
    unsigned char diff = 0;
    for (size_t i = 0; i < 32; i++)
        diff |= (unsigned char)(expected[i] ^ provided[i]);
    return diff == 0;
}

/* Context string — the token is bound to the specific order form so a
 * leaked token from one product page can't be replayed to another.
 * Format: "store:order:<product_id>".  Writes into a caller buffer. */
void store_csrf_context(char *out, size_t outmax, int64_t product_id)
{
    snprintf(out, outmax, "store:order:%lld", (long long)product_id);
}

/* Proof-of-work order gate — store_pow_challenge() / store_pow_verify_and_claim()
 * are defined in store_controller_pow.c (split out to stay under the
 * file-size ceiling) and declared in store_controller_internal.h. See
 * that file for the full design rationale. */

/* Form fields are parsed by web_form.h: bodies are length-delimited
 * slices without a NUL sentinel, so a bounded scan (not strstr) is the
 * only safe reader here. */

static bool parse_positive_form_id(const char *body, size_t body_len,
                                   const char *field, int64_t *id_out)
{
    char raw[32];
    char *end = NULL;
    long long value;

    if (!id_out)
        return false;
    *id_out = -1;
    if (!web_form_field(body, body_len, field, raw, sizeof(raw)))
        return false; // raw-return-ok:form-field-absent-not-a-server-error
    value = strtoll(raw, &end, 10);
    if (!end || *end != '\0' || value <= 0)
        return false;
    *id_out = (int64_t)value;
    return true;
}

/* Main request handler */
size_t store_handle_request(const char *method, const char *path,
                             const uint8_t *body, size_t body_len,
                             uint8_t *response, size_t response_max,
                             const char *datadir)
{
    if (!path || !response) return 0;

    char db_path[1024];
    snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_runtime(&ndb, db_path, "store.request")) return 0;
    sqlite3 *db = ndb.db;
    store_ensure_schema(db, datadir);

    size_t result = 0;

    if (route_is_product_index(path)) {
        result = serve_product_list(db, response, response_max);

    } else if (route_is_product_show(path)) {
        int64_t id = -1;
        if (!parse_positive_path_id(path, &id)) {
            const char *err_body = "<h1>Invalid product</h1>"
                "<p>Product id must be a positive integer.</p>"
                "<p><a href='/store/products'>&larr; Back to store</a></p>";
            result = store_error_response("400 Bad Request",
                err_body, strlen(err_body), response, response_max);
        } else {
            result = serve_product_detail(db, id, response, response_max);
        }

    } else if (route_is_order_index(path) &&
               method && strcmp(method, "GET") == 0) {
        result = serve_order_index(db, response, response_max);

    } else if (route_is_order_create(method, path)) {
        int64_t id = -1;
        char addr[128] = "";
        char csrf[64] = "";
        char pow_ts[32] = "";
        char pow_nonce[32] = "";
        char pay_kind[16] = "";
        if (body && body_len > 0) {
            web_form_field((const char *)body, body_len,
                             "customer_addr", addr, sizeof(addr));
            web_form_field((const char *)body, body_len,
                             "csrf_token", csrf, sizeof(csrf));
            web_form_field((const char *)body, body_len,
                             "pow_ts", pow_ts, sizeof(pow_ts));
            web_form_field((const char *)body, body_len,
                             "pow_nonce", pow_nonce, sizeof(pow_nonce));
            /* Absent ⇒ shielded, so every existing caller and the HTML form
             * keep the shielded default. Only the exact string "transparent"
             * opts in; anything else is shielded rather than a guess. */
            web_form_field((const char *)body, body_len,
                             "payment_kind", pay_kind, sizeof(pay_kind));
        }
        bool want_transparent = (strcmp(pay_kind, "transparent") == 0);
        if (path_has_prefix(path, "/store/buy/")) {
            if (!parse_positive_path_id(path, &id))
                id = -1;
        } else if (!parse_positive_form_id((const char *)body, body_len,
                                           "product_id", &id)) {
            const char *err_body = "<h1>Invalid product</h1>"
                "<p>product_id must be a positive integer.</p>"
                "<p><a href='/store/products'>&larr; Back to store</a></p>";
            result = store_error_response("400 Bad Request",
                err_body, strlen(err_body), response, response_max);
            node_db_close(&ndb);
            return result;
        }
        char csrf_ctx[64];
        store_csrf_context(csrf_ctx, sizeof(csrf_ctx), id);
        if (!store_csrf_verify(csrf_ctx, csrf)) {
            const char *err_body = "<h1>Invalid CSRF token</h1>"
                "<p>Form token missing or did not verify. "
                "Please reload the product page and resubmit.</p>"
                "<p><a href='/store/products'>&larr; Back to store</a></p>";
            result = store_error_response("400 Bad Request",
                err_body, strlen(err_body), response, response_max);
            node_db_close(&ndb);
            return result;
        }
        if (!zcl_validate_zcl_address(addr)) {
            const char *err_body = "<h1>Invalid address</h1>"
                "<p>Must be a ZClassic t-address (t1.../t3...) or "
                "z-address (zs1...).</p>"
                "<p><a href='/store/products'>&larr; Back to store</a></p>";
            result = store_error_response("400 Bad Request",
                err_body, strlen(err_body), response, response_max);
        } else if (!store_pow_verify_and_claim(id, pow_ts, pow_nonce)) {
            /* Refused BEFORE the expensive z-address mint + DB write —
             * CSRF alone no longer suffices for this path. */
            const char *err_body = "<h1>Proof of work required</h1>"
                "<p>This order requires a small proof-of-work puzzle to "
                "be solved before submission (this prevents automated "
                "flooding of the order queue). Reload the product page "
                "and submit again — the page solves the puzzle "
                "automatically. The challenge seed rotates and its "
                "difficulty rises with load, so a stale page must be "
                "reloaded. Programmatic callers: see the pow_ts / "
                "pow_nonce protocol documented next to "
                "store_pow_verify_and_claim() in store_controller_pow.c.</p>"
                "<p><a href='/store/products'>&larr; Back to store</a></p>";
            result = store_error_response("402 Payment Required",
                err_body, strlen(err_body), response, response_max);
        } else {
            /* Bound the pending pool BEFORE the expensive mint. An
             * opportunistic prune runs first so a pool that's merely
             * full of already-expired unpaid orders (waiting on the
             * ~30s background sweep in store_process_payments) doesn't
             * wedge a legitimate buyer behind rows that are already
             * dead — belt-and-suspenders with that background sweep,
             * not a replacement for it. */
            int pending_global = db_store_order_count_pending(&ndb);
            int pending_product =
                db_store_order_count_pending_for_product(&ndb, id);
            if (pending_global >= STORE_ORDER_MAX_PENDING_GLOBAL ||
                pending_product >= STORE_ORDER_MAX_PENDING_PER_PRODUCT) {
                db_store_order_prune_expired(&ndb,
                    STORE_ORDER_PENDING_EXPIRE_SECS);
                pending_global = db_store_order_count_pending(&ndb);
                pending_product =
                    db_store_order_count_pending_for_product(&ndb, id);
            }
            if (pending_global >= STORE_ORDER_MAX_PENDING_GLOBAL) {
                const char *err_body = "<h1>Store busy</h1>"
                    "<p>The order queue is at capacity. Please try "
                    "again shortly.</p>"
                    "<p><a href='/store/products'>&larr; Back to store</a></p>";
                result = store_error_response("503 Service Unavailable",
                    err_body, strlen(err_body), response, response_max);
            } else if (pending_product >= STORE_ORDER_MAX_PENDING_PER_PRODUCT) {
                const char *err_body = "<h1>Product busy</h1>"
                    "<p>Too many pending orders for this product. "
                    "Please try again shortly.</p>"
                    "<p><a href='/store/products'>&larr; Back to store</a></p>";
                result = store_error_response("503 Service Unavailable",
                    err_body, strlen(err_body), response, response_max);
            } else {
                result = serve_create_order(db, id, addr, datadir,
                                              want_transparent,
                                              response, response_max);
            }
        }

    } else if (route_is_order_show(path)) {
        int64_t id = -1;
        if (!parse_positive_path_id(path, &id)) {
            const char *err_body = "<h1>Invalid order</h1>"
                "<p>Order id must be a positive integer.</p>"
                "<p><a href='/store/orders'>&larr; Back to orders</a></p>";
            result = store_error_response("400 Bad Request",
                err_body, strlen(err_body), response, response_max);
        } else {
            result = serve_order_status(db, id, response, response_max);
        }

    } else if (strncmp(path, "/store/access", 13) == 0) {
        /* Token-gated content: /store/access?addr=t1...&token=ZCL23ACCESS
         * The token buffer must hold the canonical 64-hex-char txid form
         * PLUS the NUL — store_parse_query_field caps a field at
         * out_max-1 chars, so token[64] silently truncates a full txid to
         * 63 chars, the validator then rejects it as a truncated-txid look-
         * alike, and the gate 400s every real token holder (the C5 collect
         * wedge's second half). */
        char addr[128] = "", token[65] = "";
        if (!store_parse_access_query(path, addr, sizeof(addr),
                                      token, sizeof(token))) {
            const char *err_body = "<h1>Invalid access request</h1>"
                "<p>addr must be a valid ZClassic address and token must be a valid token id.</p>"
                "<p><a href='/store/products'>&larr; Back to store</a></p>";
            result = store_error_response("400 Bad Request",
                err_body, strlen(err_body), response, response_max);
        } else {
            result = serve_gated_content(db, addr, token, 1, datadir,
                                          response, response_max);
        }
    }

    node_db_close(&ndb);
    return result;
}

int64_t store_confirmed_payment(struct node_db *ndb, const char *pay_addr,
                                int64_t order_id, int64_t max_height)
{
    struct tx_destination dest;

    if (!ndb || !pay_addr || !pay_addr[0])
        return 0;

    if (wallet_addr_is_sapling(pay_addr))
        return db_store_received_payment_for_memo(ndb, pay_addr, order_id,
                                                  max_height);

    /* Transparent: the order bind is the one-time address itself, so the
     * hash160 is the whole key. Refuse anything that is not a plain
     * pay-to-pubkey-hash destination rather than guessing — a script
     * destination here would mean the order was minted by a path that does
     * not exist yet, and crediting it would be crediting an unknown. */
    if (!wallet_decode_address(pay_addr, &dest) || dest.type != DEST_KEY_ID) {
        LOG_WARN("store", "reconcile: order %lld payment address is neither a "
                 "shielded address nor a p2pkh t-address — not crediting",
                 (long long)order_id);
        return 0;
    }
    return db_store_received_payment_taddr(ndb, dest.id.key.id.data,
                                           max_height);
}

/* Background payment processor — called periodically from boot.c.
 * Checks pending orders for payments, mints tokens when paid. */
void store_process_payments_with_db(struct node_db *ndb,
                                    const char *datadir)
{
    if (!ndb || !ndb->open || !datadir) return;

    struct db_store_pending_payment pending_orders[64];
    int pending_count = db_store_order_list_pending_payments(ndb,
        pending_orders, sizeof(pending_orders) / sizeof(pending_orders[0]),
        (int64_t)platform_time_wall_time_t() - 3600);

    for (int i = 0; i < pending_count; ++i) {
        int64_t order_id = pending_orders[i].id;
        const char *pay_addr = pending_orders[i].payment_addr;
        int64_t expected = pending_orders[i].amount_zatoshi;
        const char *cust_addr = pending_orders[i].customer_addr;
        const char *token_id = pending_orders[i].token_id;
        int64_t tokens = pending_orders[i].tokens_per_purchase;

        if (!pay_addr[0] || !cust_addr[0] || !token_id[0])
            continue;

        /* Credit only payments BOUND to THIS order — by the recovered Sapling
         * memo ("ZCL23ORDER:<order_id>") for a shielded order, or by the
         * one-time address itself for a transparent one. Either way an
         * unrelated same-amount payment cannot satisfy this order, which the
         * legacy address-only finder over a REUSED address would.
         * Require minimum 3 confirmations to prevent reorg-based double-spend
         * (payment reversed but tokens already minted). */
        int64_t tip_height = db_store_chain_tip_height(ndb);
        int64_t min_height = tip_height - 3; /* 3 confirmations */

        int64_t received = store_confirmed_payment(ndb, pay_addr, order_id,
                                                   min_height);

        if (received >= expected) {
            /* Payment confirmed — mint tokens FIRST, then update status.
             * This ensures we never show "Tokens Sent" if mint failed.
             * A mint failure is NOT terminal: the common cause is
             * projection lag (the ZSLP ledger backfill has not folded the
             * token's block yet, so the baton is not VALID — self-heals
             * once the tip settles and the catchup projection advances),
             * and a CONFIRMED payment must never strand an order as FAILED
             * for a transient cause. Leave the order in the pending scan so
             * the next cycle retries; the 1 h pending-scan window bounds
             * retries for genuinely unmintable orders. */
            bool mint_ok = zslp_mint(datadir, token_id, cust_addr,
                                      (uint64_t)tokens);
            if (!mint_ok) {
                printf("Store: order #%lld paid but mint not yet possible "
                       "(projection lag?) — retrying next scan for %s\n",
                       (long long)order_id, cust_addr);
                fflush(stdout);
                continue;
            }
            if (!db_store_order_mark_paid(ndb, order_id, STORE_ORDER_SENT)) {
                printf("Store: order #%lld payment processed but status "
                       "persist failed\n", (long long)order_id);
                fflush(stdout);
            }
            printf("Store: order #%lld paid, minted %lld %s -> %s\n",
                   (long long)order_id, (long long)tokens,
                   token_id, cust_addr);
            fflush(stdout);
        }
    }

    /* Bounded background sweep: reclaim unpaid orders old enough that
     * store_process_payments itself has stopped scanning for their
     * payment (see the (now - 3600) window above). Without this, the
     * pending-order caps in store_handle_request only refuse NEW rows
     * once the pool fills — the table itself would still grow forever. */
    {
        int pruned = db_store_order_prune_expired(ndb,
            STORE_ORDER_PENDING_EXPIRE_SECS);
        if (pruned > 0) {
            printf("Store: pruned %d expired unpaid order(s)\n", pruned);
            fflush(stdout);
        }
    }

}

void store_process_payments(const char *datadir)
{
    if (!datadir) return;
    char db_path[1024];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db ndb = {0};
    if (n <= 0 || (size_t)n >= sizeof(db_path) ||
        !node_db_open_existing_runtime(&ndb, db_path,
                                       "store.payment_fixture"))
        return;
    store_process_payments_with_db(&ndb, datadir);
    node_db_close(&ndb);
}
