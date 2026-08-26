/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Store controller + ZSLP token + template engine tests. */

#include "test/test_core.h"
#include "coins/undo.h"
#include "controllers/store_controller.h"
#include "controllers/web_form.h"
#include "controllers/zslp_controller.h"
#include "services/zslp_command_service.h"
#include "services/zslp_service.h"
#include "util/template.h"
#include "wallet/wallet.h"
#include "wallet/sapling_keys.h"
#include "config/runtime.h"
#include "net/puzzle.h"
#include "views/store_internal.h"
#include "models/store.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include <time.h>
#include <unistd.h>

/* CSRF token + PoW-challenge generation are internal controller security
 * machinery (defined in store_controller.c, declared in the controller's
 * private store_controller_internal.h — not part of the public store
 * surface). Most tests below exercise them end-to-end via HTTP scraping
 * (fetch_csrf_token / fetch_pow_attrs), matching the real client
 * path; the cap tests use a SYNTHETIC product_id with no real product
 * row (so there is no page to scrape a token from) and call these
 * directly instead, mirroring the same forward-declare-only pattern
 * app/views/src/store_view.c already uses for store_csrf_token/context.
 * store_pow_challenge() itself is declared in views/store_internal.h
 * (included above) since the view embeds its output. */
void store_csrf_token(const char *context, char out[33]);
void store_csrf_context(char *out, size_t outmax, int64_t product_id);
void store_pow_reset_state(void);

static char test_datadir[256];

static void setup_datadir(void)
{
    test_make_tmpdir(test_datadir, sizeof(test_datadir), "store", "main");
}

static void cleanup_datadir(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_datadir);
    system(cmd);
}

/* Fetch the CSRF token embedded in the purchase form for product_id.
 * GET /store/product/<id> and scrape value='...' from the
 * name='csrf_token' hidden input.  Returns true on success. */
static bool fetch_csrf_token(int64_t product_id, char *out, size_t outmax)
{
    uint8_t page[65536];  /* design-system pages inline ~14 KB of CSS */
    char path[64];
    snprintf(path, sizeof(path), "/store/product/%lld", (long long)product_id);
    size_t n = store_handle_request("GET", path, NULL, 0,
                                     page, sizeof(page), test_datadir);
    if (n == 0) return false;
    page[sizeof(page) - 1] = 0;
    const char *needle = "name='csrf_token' value='";
    const char *p = strstr((char *)page, needle);
    if (!p) return false;
    p += strlen(needle);
    const char *end = strchr(p, '\'');
    if (!end) return false;
    size_t tlen = (size_t)(end - p);
    if (tlen >= outmax) return false;
    memcpy(out, p, tlen);
    out[tlen] = '\0';
    return true;
}

/* Read one data-pow-* attribute out of an already-fetched page. */
static bool scrape_pow_attr(const char *page, const char *attr,
                            char *out, size_t outmax)
{
    char needle[48];
    snprintf(needle, sizeof(needle), "%s='", attr);
    const char *p = strstr(page, needle);
    if (!p) return false;
    p += strlen(needle);
    const char *end = strchr(p, '\'');
    if (!end) return false;
    size_t tlen = (size_t)(end - p);
    if (tlen >= outmax) return false;
    memcpy(out, p, tlen);
    out[tlen] = '\0';
    return true;
}

/* GET /store/product/<id> ONCE and pull the whole live challenge out of
 * <form id='orderForm'>. One fetch on purpose: every render is a real
 * challenge issuance (it can rotate the seed and re-reads the adaptive
 * difficulty), so scraping the four attributes from four separate pages
 * could mix a seed from one issuance with a difficulty from another. */
static bool fetch_pow_attrs(int64_t product_id,
                            char seed_hex[65], char token_hex[65],
                            char ts_str[32], char bits_str[16])
{
    uint8_t page[65536];  /* design-system pages inline ~14 KB of CSS */
    char path[64];
    snprintf(path, sizeof(path), "/store/product/%lld", (long long)product_id);
    size_t n = store_handle_request("GET", path, NULL, 0,
                                     page, sizeof(page), test_datadir);
    if (n == 0) return false;
    page[sizeof(page) - 1] = 0;
    return scrape_pow_attr((char *)page, "data-pow-seed", seed_hex, 65) &&
           scrape_pow_attr((char *)page, "data-pow-token", token_hex, 65) &&
           scrape_pow_attr((char *)page, "data-pow-ts", ts_str, 32) &&
           scrape_pow_attr((char *)page, "data-pow-bits", bits_str, 16);
}

static bool hex32_to_bytes(const char *hex, uint8_t out[32])
{
    if (!hex || strlen(hex) != 64) return false;
    for (int i = 0; i < 32; i++) {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
    return true;
}

/* Block until the wall clock crosses into the next whole second. Used by
 * the order-pruning cases, whose "created before right now" cutoff is
 * second-granular and would otherwise tie with rows created a moment ago. */
static void wait_for_next_wall_second(void)
{
    int64_t start = (int64_t)platform_time_wall_time_t();
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
    while ((int64_t)platform_time_wall_time_t() == start)
        nanosleep(&ts, NULL);
}

/* Solve the live product-bound puzzle for product_id — scraping the
 * server-issued seed, the product token, the difficulty and the server
 * timestamp out of the REAL rendered page, then running the same
 * primitive store_pow_verify_and_claim() checks with — and format the
 * pow_ts / pow_nonce form-field values a real client would submit.
 *
 * puzzle_solve_RANDOM, matching the browser solver: a search from zero is
 * a pure function of (seed, token, ts), so this file's repeated solves for
 * product 1 inside one wall second would all return the same nonce and the
 * gate's single-use ring would refuse every one after the first.
 *
 * The gate is reset first. Not to weaken the check — the challenge is
 * issued AFTER the reset and solved at whatever difficulty it names — but
 * to keep this file's runtime bounded and deterministic. The gate is
 * load-adaptive: a test that fires order after order looks exactly like the
 * flood it is designed to price, so difficulty (and therefore solve time)
 * would climb with how many cases ran before. The ramp itself is proven in
 * lib/test/src/test_puzzle.c; this file proves the ORDER path. */
static bool solve_store_pow_fields(int64_t product_id,
                                   char *pow_ts_out, size_t ts_max,
                                   char *pow_nonce_out, size_t nonce_max)
{
    char seed_hex[65] = "", token_hex[65] = "", ts_str[32] = "", bits_str[16] = "";
    uint8_t seed[32], token[32];
    uint64_t nonce = 0;
    int64_t ts;
    int bits;

    store_pow_reset_state();
    if (!fetch_pow_attrs(product_id, seed_hex, token_hex, ts_str, bits_str))
        return false;
    if (!hex32_to_bytes(seed_hex, seed) || !hex32_to_bytes(token_hex, token))
        return false;
    ts = strtoll(ts_str, NULL, 10);
    bits = (int)strtol(bits_str, NULL, 10);
    if (bits <= 0)
        return false;
    if (!puzzle_solve_random(seed, token, ts, bits, &nonce))
        return false;
    snprintf(pow_ts_out, ts_max, "%lld", (long long)ts);
    snprintf(pow_nonce_out, nonce_max, "%llu", (unsigned long long)nonce);
    return true;
}

int test_store(void)
{
    int failures = 0;
    setup_datadir();

    /* Wire a seeded merchant wallet as the current runtime so the
     * order-creation path (serve_create_order → zslp_generate_payment_address
     * → app_runtime_wallet) can mint a REAL, recoverable Sapling z-address —
     * exactly as production does. Without a seeded keystore the order-create
     * tests would (correctly) be refused with a 503, since the placeholder
     * fallback has been removed. Static storage: the runtime pointer must
     * outlive every call below. */
    static struct wallet g_store_test_wallet;
    static struct app_runtime_context g_store_test_rt;
    memset(&g_store_test_wallet, 0, sizeof(g_store_test_wallet));
    wallet_init(&g_store_test_wallet);
    {
        uint8_t seed[32];
        memset(seed, 0x5A, sizeof(seed));
        if (!sapling_keystore_set_seed(&g_store_test_wallet.sapling_keys, seed)) {
            printf("store: FAIL (could not seed merchant wallet)\n");
            failures++;
        }
    }
    memset(&g_store_test_rt, 0, sizeof(g_store_test_rt));
    g_store_test_rt.wallet = &g_store_test_wallet;
    app_runtime_set_current(&g_store_test_rt);

    uint8_t resp[65536];  /* styled pages inline ~14 KB CSS */

    /* ── Product listing ──────────────────────────────────── */

    printf("store: GET /store returns product listing... ");
    {
        size_t n = store_handle_request("GET", "/store", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "HTTP/1.1 200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "ZCL Store") != NULL);
        ok = ok && (strstr((char *)resp, "ZCL23 Access Token") != NULL);
        ok = ok && (strstr((char *)resp, "VPN Credit") != NULL);
        ok = ok && (strstr((char *)resp, "Storage") != NULL);
        if (ok) printf("OK (%zu bytes, 3 products)\n", n);
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("store: GET /store/ (trailing slash) works... ");
    {
        size_t n = store_handle_request("GET", "/store/", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "200 OK") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/products REST index works... ");
    {
        size_t n = store_handle_request("GET", "/store/products", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "ZCL23 Access Token") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Product detail ───────────────────────────────────── */

    printf("store: GET /store/product/1 returns detail page... ");
    {
        size_t n = store_handle_request("GET", "/store/product/1", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "ZCL23 Access Token") != NULL);
        ok = ok && (strstr((char *)resp, "customer_addr") != NULL);
        ok = ok && (strstr((char *)resp, "action='/store/orders'") != NULL);
        if (ok) printf("OK (%zu bytes)\n", n);
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/products/1 REST show works... ");
    {
        size_t n = store_handle_request("GET", "/store/products/1", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "ZCL23 Access Token") != NULL);
        ok = ok && (strstr((char *)resp, "name='product_id' value='1'") != NULL);
        ok = ok && (strstr((char *)resp, "action='/store/orders'") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/product/999 returns 404... ");
    {
        size_t n = store_handle_request("GET", "/store/product/999", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "404") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/products/not-a-number returns 400... ");
    {
        size_t n = store_handle_request("GET", "/store/products/not-a-number",
                                         NULL, 0, resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400 Bad Request") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Create order ─────────────────────────────────────── */

    char csrf1[64] = "";
    bool have_csrf1 = fetch_csrf_token(1, csrf1, sizeof(csrf1));

    printf("store: POST /store/buy/1 creates order (valid CSRF + PoW)... ");
    {
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        char body[384];
        snprintf(body, sizeof(body),
            "customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&csrf_token=%s"
            "&pow_ts=%s&pow_nonce=%s",
            csrf1, pow_ts, pow_nonce);
        size_t n = store_handle_request("POST", "/store/buy/1",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && have_csrf1 && have_pow;
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Order #") != NULL);
        ok = ok && (strstr((char *)resp, "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn") != NULL);
        ok = ok && (strstr((char *)resp, "0.01") != NULL);
        if (ok) printf("OK (%zu bytes)\n", n);
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: POST /store/orders REST create works (valid CSRF + PoW)... ");
    {
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        char body[384];
        snprintf(body, sizeof(body),
            "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
            "&csrf_token=%s&pow_ts=%s&pow_nonce=%s",
            csrf1, pow_ts, pow_nonce);
        size_t n = store_handle_request("POST", "/store/orders",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && have_pow;
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Order #") != NULL);
        ok = ok && (strstr((char *)resp, "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Length-delimited form parsing ────────────────────────────
     * HTTP dispatch hands store_handle_request body slices WITHOUT a
     * NUL terminator, so the form scanner may not rely on any sentinel
     * and may not read past body_len. Each fixture below plants a live
     * non-NUL byte exactly AT body_len: a sentinel-based scanner reads
     * it (and whatever follows) and misparses; the bounded scanner in
     * controllers/web_form.h must ignore it completely. */
    printf("store: sentinel-free body with trailing customer_addr parses... ");
    {
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        char body[320];
        int blen = snprintf(body, sizeof(body),
            "product_id=1&csrf_token=%s&pow_ts=%s&pow_nonce=%s"
            "&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn",
            csrf1, pow_ts, pow_nonce);
        bool ok = blen > 0;
        if (ok) {
            body[blen] = 'X';      /* garbage where a sentinel would sit */
            body[blen + 1] = '\0';
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body,
                                             (size_t)blen,
                                             resp, sizeof(resp),
                                             test_datadir);
            memset(&body[blen], 0, sizeof(body) - (size_t)blen);
            ok = have_pow && (n > 0) &&
                 (strstr((char *)resp, "200 OK") != NULL) &&
                 (strstr((char *)resp, "Order #") != NULL) &&
                 (strstr((char *)resp, "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn") != NULL);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: body missing customer_addr names the refusal (no sentinel luck)... ");
    {
        char pow_ts[32] = "", pow_nonce[32] = "";
        /* The gate never runs — address validation precedes it in
         * serve_create_order — so the solve's outcome is not consulted. */
        (void)solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                     pow_nonce, sizeof(pow_nonce));
        char body[256];
        int blen = snprintf(body, sizeof(body),
            "product_id=1&csrf_token=%s&pow_ts=%s&pow_nonce=%s",
            csrf1, pow_ts, pow_nonce);
        bool ok = blen > 0;
        if (ok) {
            body[blen] = 'G';
            body[blen + 1] = '\0';
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body,
                                             (size_t)blen,
                                             resp, sizeof(resp),
                                             test_datadir);
            memset(&body[blen], 0, sizeof(body) - (size_t)blen);
            ok = (n > 0) &&
                 (strstr((char *)resp, "400 Bad Request") != NULL) &&
                 (strstr((char *)resp, "Invalid address") != NULL) &&
                 (strstr((char *)resp, "Order #") == NULL);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: decoy prefix cannot shadow a properly delimited field... ");
    {
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        /* A value containing "customer_addr=x" used to win a plain
         * substring search before the real field ever matched; the
         * bounded scanner requires '&' boundaries and must pick the
         * real, valid address from the properly delimited slot. */
        char body[400];
        int blen = snprintf(body, sizeof(body),
            "product_id=1&note=ecustomer_addr=x&csrf_token=%s&pow_ts=%s"
            "&pow_nonce=%s&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn",
            csrf1, pow_ts, pow_nonce);
        bool ok = blen > 0;
        if (ok) {
            body[blen] = 'Y';
            body[blen + 1] = '\0';
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body,
                                             (size_t)blen,
                                             resp, sizeof(resp),
                                             test_datadir);
            memset(&body[blen], 0, sizeof(body) - (size_t)blen);
            ok = have_pow && (n > 0) &&
                 (strstr((char *)resp, "200 OK") != NULL) &&
                 (strstr((char *)resp, "Order #") != NULL);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: duplicate customer_addr field refuses ambiguity... ");
    {
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        char body[384];
        int blen = snprintf(body, sizeof(body),
            "product_id=1&csrf_token=%s&pow_ts=%s&pow_nonce=%s"
            "&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
            "&customer_addr=t1FloodFakeSecond9PzqT4VdKh5sYVnQnSm",
            csrf1, pow_ts, pow_nonce);
        bool ok = blen > 0;
        if (ok) {
            body[blen] = 'D';    /* live byte where a sentinel would sit */
            body[blen + 1] = '\0';
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body,
                                             (size_t)blen,
                                             resp, sizeof(resp),
                                             test_datadir);
            memset(&body[blen], 0, sizeof(body) - (size_t)blen);
            /* A name supplied twice is ambiguous input: neither value is
             * trusted — not first-wins, not last-wins. */
            ok = have_pow && (n > 0) &&
                 (strstr((char *)resp, "400 Bad Request") != NULL) &&
                 (strstr((char *)resp, "Invalid address") != NULL) &&
                 (strstr((char *)resp, "Order #") == NULL);
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: shared form scanner uses ampersand boundaries only... ");
    {
        static const char body[] =
            "memo=x?confirm=true&literal=true anything";
        char confirm[16] = "dirty", literal[32] = "dirty";
        bool ok = !web_form_field(body, sizeof(body) - 1, "confirm",
                                  confirm, sizeof(confirm)) &&
            confirm[0] == '\0' &&
            web_form_field(body, sizeof(body) - 1, "literal", literal,
                           sizeof(literal)) &&
            strcmp(literal, "true anything") == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: shared form scanner refuses NUL and malformed escapes... ");
    {
        static const char raw_nul[] = {'f','e','e','=','1','\0','2'};
        static const char encoded_nul[] = "fee=1%00junk";
        static const char bad_hex[] = "fee=1%XZ";
        static const char short_hex[] = "fee=1%2";
        char out[16] = "dirty";
        bool ok = !web_form_field(raw_nul, sizeof(raw_nul), "fee", out,
                                  sizeof(out)) && out[0] == '\0';
        snprintf(out, sizeof(out), "dirty");
        ok = ok && !web_form_field(encoded_nul, sizeof(encoded_nul) - 1,
                                   "fee", out, sizeof(out)) && out[0] == '\0';
        snprintf(out, sizeof(out), "dirty");
        ok = ok && !web_form_field(bad_hex, sizeof(bad_hex) - 1, "fee",
                                   out, sizeof(out)) && out[0] == '\0';
        snprintf(out, sizeof(out), "dirty");
        ok = ok && !web_form_field(short_hex, sizeof(short_hex) - 1, "fee",
                                   out, sizeof(out)) && out[0] == '\0';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: shared form scanner refuses output truncation... ");
    {
        static const char body[] = "fee=1234";
        char exact[5] = "", short_out[4] = "bad";
        bool ok = web_form_field(body, sizeof(body) - 1, "fee", exact,
                                 sizeof(exact)) && strcmp(exact, "1234") == 0;
        ok = ok && !web_form_field(body, sizeof(body) - 1, "fee", short_out,
                                   sizeof(short_out)) && short_out[0] == '\0';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── PoW order gate (resource-exhaustion mitigation) ──────────
     * Verified threat: POST /store/orders and /store/buy/:id minted a
     * z-address + wrote a DB row per request behind CSRF alone. These
     * prove CSRF no longer suffices for the expensive path, that a
     * valid puzzle still completes normally, that a solved puzzle
     * cannot be replayed, and that the mint truly never runs on a
     * rejected request (order count in the DB is unchanged). */
    {
        char dbpath[320];
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", test_datadir);

        printf("store: order WITHOUT pow_ts/pow_nonce refused (CSRF alone insufficient)... ");
        {
            struct node_db ndb;
            memset(&ndb, 0, sizeof(ndb));
            bool have_db = node_db_open(&ndb, dbpath);
            int before = have_db ? db_store_order_count_pending(&ndb) : -1;
            if (have_db) node_db_close(&ndb);

            char body[256];
            snprintf(body, sizeof(body),
                "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                "&csrf_token=%s",
                csrf1);
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body, strlen(body),
                                             resp, sizeof(resp), test_datadir);
            memset(&ndb, 0, sizeof(ndb));
            have_db = node_db_open(&ndb, dbpath);
            int after = have_db ? db_store_order_count_pending(&ndb) : -2;
            if (have_db) node_db_close(&ndb);

            bool ok = (n > 0);
            ok = ok && (strstr((char *)resp, "402") != NULL);
            ok = ok && (strstr((char *)resp, "Proof of work required") != NULL);
            ok = ok && (strstr((char *)resp, "Order #") == NULL);
            /* The strongest proof the mint never ran: the pending-order
             * row count in the DB is byte-for-byte unchanged. */
            ok = ok && (before >= 0) && (after == before);
            if (ok) printf("OK (pending count unchanged: %d)\n", before);
            else { printf("FAIL (before=%d after=%d)\n", before, after); failures++; }
        }

        printf("store: order WITH garbage pow_nonce refused (unsolved puzzle)... ");
        {
            char body[384];
            snprintf(body, sizeof(body),
                "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                "&csrf_token=%s&pow_ts=%lld&pow_nonce=0",
                csrf1, (long long)platform_time_wall_time_t());
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body, strlen(body),
                                             resp, sizeof(resp), test_datadir);
            bool ok = (n > 0);
            ok = ok && (strstr((char *)resp, "402") != NULL);
            ok = ok && (strstr((char *)resp, "Order #") == NULL);
            if (ok) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }

        printf("store: order with valid PoW puzzle succeeds (legitimate flow intact)... ");
        {
            char pow_ts[32] = "", pow_nonce[32] = "";
            bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                                   pow_nonce, sizeof(pow_nonce));
            char body[384];
            snprintf(body, sizeof(body),
                "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                "&csrf_token=%s&pow_ts=%s&pow_nonce=%s",
                csrf1, pow_ts, pow_nonce);
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body, strlen(body),
                                             resp, sizeof(resp), test_datadir);
            bool ok = (n > 0) && have_pow;
            ok = ok && (strstr((char *)resp, "200 OK") != NULL);
            ok = ok && (strstr((char *)resp, "Order #") != NULL);
            if (ok) printf("OK\n");
            else { printf("FAIL\n"); failures++; }

            /* Replay: resubmitting the EXACT SAME solved puzzle for a
             * second order must be refused — a flood cannot solve once
             * and replay for unlimited orders within the ~5-min window. */
            printf("store: replaying the same solved PoW puzzle is refused... ");
            size_t n2 = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body, strlen(body),
                                             resp, sizeof(resp), test_datadir);
            bool ok2 = (n2 > 0) && have_pow;
            ok2 = ok2 && (strstr((char *)resp, "402") != NULL);
            ok2 = ok2 && (strstr((char *)resp, "Order #") == NULL);
            if (ok2) printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        }
    }

    printf("store: POST /store/buy/999 returns 404... ");
    {
        /* id=999 routes through a path id, so the CSRF context will be
         * "store:order:999" — fetch that token separately. */
        char csrf999[64] = "";
        bool have_csrf999 = fetch_csrf_token(999, csrf999, sizeof(csrf999));
        char body[256];
        snprintf(body, sizeof(body),
            "customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&csrf_token=%s",
            csrf999);
        size_t n = store_handle_request("POST", "/store/buy/999",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        /* Either the 404 happens before the CSRF check (fine) or after
         * a valid CSRF is accepted (also fine).  Key property: the
         * server does NOT create an order.  */
        bool ok = (n > 0) && (strstr((char *)resp, "404") != NULL ||
                              strstr((char *)resp, "Invalid CSRF") != NULL);
        (void)have_csrf999;
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* reject t-addr with bad Base58Check. */
    printf("store: POST /store/buy rejects t-addr with bad checksum... ");
    {
        char body[256];
        snprintf(body, sizeof(body),
            "customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXAA&csrf_token=%s",
            csrf1);
        size_t n = store_handle_request("POST", "/store/buy/1",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400") != NULL);
        ok = ok && (strstr((char *)resp, "Invalid address") != NULL);
        ok = ok && (strstr((char *)resp, "Order #") == NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: POST /store/orders rejects z-addr with bad bech32... ");
    {
        char body[384];
        snprintf(body, sizeof(body),
            "product_id=1&customer_addr=zs1"
            "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
            "&csrf_token=%s",
            csrf1);
        size_t n = store_handle_request("POST", "/store/orders",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400") != NULL);
        ok = ok && (strstr((char *)resp, "Invalid address") != NULL);
        ok = ok && (strstr((char *)resp, "Order #") == NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* CSRF: POST without any csrf_token must be rejected. */
    printf("store: POST /store/orders without csrf_token returns 400... ");
    {
        const char *body =
            "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn";
        size_t n = store_handle_request("POST", "/store/orders",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400") != NULL);
        ok = ok && (strstr((char *)resp, "Invalid CSRF") != NULL);
        ok = ok && (strstr((char *)resp, "Order #") == NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* CSRF: token bound to product-id; replaying product 1's token
     * when POSTing for a different id must fail. */
    printf("store: CSRF token for one product_id rejected for another... ");
    {
        char body[256];
        snprintf(body, sizeof(body),
            "product_id=2&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&csrf_token=%s",
            csrf1);
        size_t n = store_handle_request("POST", "/store/orders",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400") != NULL);
        ok = ok && (strstr((char *)resp, "Invalid CSRF") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* URL-decode: percent-encoded address must decode to the raw
     * string before validation.  Before the fix, `%74` was kept as the
     * three literal bytes and the address failed length/shape checks
     * (now it fails checksum instead — so we encode a VALID t-addr
     * that decodes correctly and expect a 200 OK with the decoded
     * address round-tripped). */
    printf("store: POST body with %%-encoded customer_addr decodes before validation... ");
    {
        /* Encode the 't' in t1YRB... as %74. */
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        char body[384];
        snprintf(body, sizeof(body),
            "customer_addr=%%74%%31YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&csrf_token=%s"
            "&pow_ts=%s&pow_nonce=%s",
            csrf1, pow_ts, pow_nonce);
        size_t n = store_handle_request("POST", "/store/buy/1",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && have_pow && (strstr((char *)resp, "200 OK") != NULL);
        /* The decoded address — not the %-encoded form — should be in
         * the order confirmation. */
        ok = ok && (strstr((char *)resp, "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn") != NULL);
        ok = ok && (strstr((char *)resp, "%74") == NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Order status ─────────────────────────────────────── */

    printf("store: GET /store/order/1 returns status page... ");
    {
        size_t n = store_handle_request("GET", "/store/order/1", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Order #1") != NULL);
        ok = ok && (strstr((char *)resp, "Pending") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/orders/1 REST show works... ");
    {
        size_t n = store_handle_request("GET", "/store/orders/1", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Order #1") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/orders REST index works... ");
    {
        size_t n = store_handle_request("GET", "/store/orders", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Recent Orders") != NULL);
        ok = ok && (strstr((char *)resp, "Order #1") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/order/999 returns 404... ");
    {
        size_t n = store_handle_request("GET", "/store/order/999", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "404") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: GET /store/orders/not-a-number returns 400... ");
    {
        size_t n = store_handle_request("GET", "/store/orders/not-a-number",
                                         NULL, 0, resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400 Bad Request") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── ZSLP token operations ────────────────────────────── */

    printf("store: zslp_create_token returns token_id... ");
    {
        const char *tid = zslp_create_token(test_datadir, "TESTCOIN",
                                             "Test Coin", 8, 1000000);
        bool ok = (tid != NULL) && (strlen(tid) > 0);
        if (ok) printf("OK (token_id=%s)\n", tid);
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp_mint credits tokens... ");
    {
        bool ok = zslp_mint(test_datadir, "TESTCOIN", "t1Buyer123", 500);
        uint64_t bal = zslp_balance(test_datadir, "TESTCOIN", "t1Buyer123");
        ok = ok && (bal == 500);
        if (ok) printf("OK (balance=500)\n");
        else { printf("FAIL (balance=%llu)\n", (unsigned long long)bal); failures++; }
    }

    printf("store: zslp_mint accumulates... ");
    {
        zslp_mint(test_datadir, "TESTCOIN", "t1Buyer123", 250);
        uint64_t bal = zslp_balance(test_datadir, "TESTCOIN", "t1Buyer123");
        bool ok = (bal == 750);
        if (ok) printf("OK (balance=750)\n");
        else { printf("FAIL (balance=%llu)\n", (unsigned long long)bal); failures++; }
    }

    printf("store: zslp_balance returns 0 for unknown addr... ");
    {
        uint64_t bal = zslp_balance(test_datadir, "TESTCOIN", "t1Nobody");
        bool ok = (bal == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp_balance returns 0 for unknown token... ");
    {
        uint64_t bal = zslp_balance(test_datadir, "NOTOKEN", "t1Buyer123");
        bool ok = (bal == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp_send transfers tokens... ");
    {
        bool ok = zslp_send(test_datadir, "TESTCOIN", "t1Seller456", 100);
        uint64_t bal = zslp_balance(test_datadir, "TESTCOIN", "t1Seller456");
        ok = ok && (bal == 100);
        if (ok) printf("OK (t1Seller456 balance=100)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp_generate_payment_address mints a real z-address... ");
    {
        /* The seeded merchant runtime wallet (wired above) lets the
         * controller mint a REAL, recoverable bech32 z-address — never the
         * old synthetic "zs1_pay_" placeholder. */
        char addr[128] = "";
        bool ok = zslp_generate_payment_address(test_datadir, addr, sizeof(addr));
        ok = ok && (strncmp(addr, "zs1", 3) == 0);
        ok = ok && (strstr(addr, "zs1_pay_") == NULL);
        ok = ok && (strlen(addr) > 20);
        if (ok) printf("OK (%s)\n", addr);
        else { printf("FAIL (got '%s')\n", addr); failures++; }
    }

    printf("store: payment mint refused when runtime wallet is unseeded... ");
    {
        /* Temporarily drop the runtime wallet to prove the controller path
         * refuses (no fake fallback) when no seeded keystore is available —
         * the exact production "node still loading keys" case that must
         * yield a 503 rather than bind an order to an unrecoverable addr. */
        app_runtime_set_current(NULL);
        char addr[128] = "sentinel";
        bool ok = !zslp_generate_payment_address(test_datadir, addr, sizeof(addr));
        ok = ok && (addr[0] == '\0');
        app_runtime_set_current(&g_store_test_rt);
        if (ok) printf("OK (refused, no fake address)\n");
        else { printf("FAIL (got '%s')\n", addr); failures++; }
    }

    /* ── TEETH: the service-layer mint, called directly with the wallet ──
     * Proves both halves of the fix in one place (no runtime needed, since
     * zslp_payment_generate_address takes the wallet by argument):
     *   (a) NULL / keyless wallet  → ZCL_ERR, buffer cleared (no fake addr)
     *   (b) real seeded Sapling key → ZCL_OK, a real bech32 z-address */
    printf("store: payment mint refuses a NULL/keyless wallet (no fake)... ");
    {
        char addr[128] = "sentinel";
        struct zcl_result r =
            zslp_payment_generate_address(NULL, addr, sizeof(addr));
        bool ok = (!r.ok) && (addr[0] == '\0');

        struct wallet *w = zcl_calloc(1, sizeof(struct wallet),
                                      "test_store_keyless_wallet");
        if (w) {
            wallet_init(w);  /* zero sapling keys */
            char addr2[128] = "sentinel";
            struct zcl_result r2 =
                zslp_payment_generate_address(w, addr2, sizeof(addr2));
            ok = ok && (!r2.ok) && (addr2[0] == '\0');
            free(w);
        } else {
            ok = false;
        }
        if (ok) printf("OK (both refused)\n");
        else { printf("FAIL (got '%s')\n", addr); failures++; }
    }

    printf("store: payment mint yields a real z-address with a key... ");
    {
        struct wallet *w = zcl_calloc(1, sizeof(struct wallet),
                                      "test_store_real_wallet");
        bool ok = (w != NULL);
        if (ok) {
            wallet_init(w);
            uint8_t seed[32];
            memset(seed, 0x42, sizeof(seed));
            ok = sapling_keystore_set_seed(&w->sapling_keys, seed);

            char addr[128] = "";
            struct zcl_result r =
                zslp_payment_generate_address(w, addr, sizeof(addr));
            ok = ok && r.ok;
            /* A genuine Sapling payment address is bech32 "zs1..." and is
             * NEVER the old synthetic "zs1_pay_" placeholder. */
            ok = ok && (strncmp(addr, "zs1", 3) == 0);
            ok = ok && (strstr(addr, "zs1_pay_") == NULL);
            ok = ok && (strlen(addr) > 20);
            if (ok) printf("OK (%s)\n", addr);
            else { printf("FAIL (got '%s')\n", addr); failures++; }
            free(w);
        } else {
            printf("FAIL (wallet alloc)\n"); failures++;
        }
    }

    /* ── Token-gated access ───────────────────────────────── */

    printf("store: token-gated access denied without tokens... ");
    {
        size_t n = store_handle_request("GET",
            "/store/access?addr=t1Nobody&token=TESTCOIN",
            NULL, 0, resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "403") != NULL);
        ok = ok && (strstr((char *)resp, "Access Denied") != NULL);
        if (ok) printf("OK (403)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: token-gated access granted with tokens... ");
    {
        size_t n = store_handle_request("GET",
            "/store/access?addr=t1Buyer123&token=TESTCOIN",
            NULL, 0, resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Premium Service") != NULL);
        if (ok) printf("OK (200)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: token-gated access rejects malformed addr... ");
    {
        size_t n = store_handle_request("GET",
            "/store/access?addr=<script>&token=TESTCOIN",
            NULL, 0, resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400 Bad Request") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: token-gated access rejects malformed token id... ");
    {
        size_t n = store_handle_request("GET",
            "/store/access?addr=t1Buyer123&token=BAD-TOKEN!",
            NULL, 0, resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "400 Bad Request") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── NULL safety ──────────────────────────────────────── */

    printf("store: NULL path returns 0... ");
    {
        size_t n = store_handle_request("GET", NULL, NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp NULL params safe... ");
    {
        bool ok = true;
        ok = ok && (zslp_create_token(NULL, "X", "X", 0, 0) == NULL);
        ok = ok && (zslp_create_token(test_datadir, NULL, "X", 0, 0) == NULL);
        ok = ok && (zslp_balance(NULL, "X", "X") == 0);
        ok = ok && (zslp_balance(test_datadir, NULL, "X") == 0);
        ok = ok && (!zslp_mint(NULL, "X", "X", 1));
        ok = ok && (!zslp_mint(test_datadir, NULL, "X", 1));
        ok = ok && (!zslp_send(NULL, "X", "X", 1));
        char addr[128];
        ok = ok && (!zslp_generate_payment_address(NULL, addr, sizeof(addr)));
        ok = ok && (zslp_check_payment(NULL, "X", 0) == 0);
        if (ok) printf("OK (all NULL cases safe)\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Payment processor ────────────────────────────────── */

    printf("store: store_process_payments runs safely... ");
    {
        store_process_payments(test_datadir);
        store_process_payments(NULL);
        printf("OK (no crash)\n");
    }

    /* ── Multiple products with different tokens ──────────── */

    printf("store: multiple token types isolated... ");
    {
        zslp_create_token(test_datadir, "TOKENA", "Token A", 0, 1000);
        zslp_create_token(test_datadir, "TOKENB", "Token B", 0, 2000);
        zslp_mint(test_datadir, "TOKENA", "t1Multi", 100);
        zslp_mint(test_datadir, "TOKENB", "t1Multi", 200);
        uint64_t a = zslp_balance(test_datadir, "TOKENA", "t1Multi");
        uint64_t b = zslp_balance(test_datadir, "TOKENB", "t1Multi");
        bool ok = (a == 100) && (b == 200);
        if (ok) printf("OK (A=100, B=200)\n");
        else { printf("FAIL (A=%llu, B=%llu)\n",
                       (unsigned long long)a, (unsigned long long)b); failures++; }
    }

    /* ── ZSLP input validation ────────────────────────────── */

    printf("store: reject ticker > 10 chars... ");
    {
        const char *tid = zslp_create_token(test_datadir, "ABCDEFGHIJK",
                                             "Valid Name", 0, 1000);
        bool ok = (tid == NULL);
        if (ok) printf("OK (rejected)\n");
        else { printf("FAIL (should reject)\n"); failures++; }
    }

    printf("store: reject empty ticker... ");
    {
        const char *tid = zslp_create_token(test_datadir, "",
                                             "Valid Name", 0, 1000);
        bool ok = (tid == NULL);
        if (ok) printf("OK (rejected)\n");
        else { printf("FAIL (should reject)\n"); failures++; }
    }

    printf("store: reject decimals > 8... ");
    {
        const char *tid = zslp_create_token(test_datadir, "GOOD",
                                             "Good Token", 9, 1000);
        bool ok = (tid == NULL);
        if (ok) printf("OK (rejected)\n");
        else { printf("FAIL (should reject)\n"); failures++; }
    }

    printf("store: reject amount=0 mint... ");
    {
        bool ok = !zslp_mint(test_datadir, "TESTCOIN", "t1Buyer123", 0);
        if (ok) printf("OK (rejected)\n");
        else { printf("FAIL (should reject)\n"); failures++; }
    }

    printf("store: reject empty recipient address on mint... ");
    {
        bool ok = !zslp_mint(test_datadir, "TESTCOIN", "", 100);
        if (ok) printf("OK (rejected)\n");
        else { printf("FAIL (should reject)\n"); failures++; }
    }

    printf("store: zslp create validator rejects bad ticker... ");
    {
        struct zslp_token_create_request req = {
            .ticker = "BAD-TICKER",
            .name = "Valid Name",
            .decimals = 0,
            .initial_supply = 1000
        };
        bool ok = (zslp_service_validate_create_request(&req) != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp transfer validator rejects zero amount... ");
    {
        struct zslp_token_transfer_request req = {
            .token_id = "TESTCOIN",
            .recipient_addr = "t1Buyer123",
            .amount = 0,
            .strict_chain_addr = false
        };
        bool ok = (zslp_service_validate_transfer_request(&req) != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp command service finalizes genesis metadata... ");
    {
        struct zslp_token_create_request req = {
            .ticker = "METATEST",
            .name = "Meta Test",
            .decimals = 0,
            .initial_supply = 77
        };
        char token_id[ZSLP_TOKEN_KEY_MAX + 1];
        bool ok = zslp_command_finalize_genesis(test_datadir, NULL, &req, token_id).ok;
        ok = ok && (strcmp(token_id, "METATEST") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: zslp command service credits transfer balance... ");
    {
        struct zslp_token_transfer_request req = {
            .token_id = "METATEST",
            .recipient_addr = "t1MetaBuyer",
            .amount = 12,
            .strict_chain_addr = false
        };
        bool ok = zslp_command_credit_transfer(test_datadir, &req).ok;
        ok = ok && (zslp_balance(test_datadir, "METATEST", "t1MetaBuyer") == 12);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── End-to-end purchase flow ────────────────────────────── */

    printf("store: e2e: GET /store lists 3 products... ");
    {
        size_t n = store_handle_request("GET", "/store", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "ZCL23 Access Token") != NULL);
        ok = ok && (strstr((char *)resp, "VPN Credit") != NULL);
        ok = ok && (strstr((char *)resp, "Storage") != NULL);
        if (ok) printf("OK (3 products listed)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: e2e: GET /store/product/1 shows price + form... ");
    {
        size_t n = store_handle_request("GET", "/store/product/1", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "0.01") != NULL);
        ok = ok && (strstr((char *)resp, "customer_addr") != NULL);
        ok = ok && (strstr((char *)resp, "<form") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: e2e: POST /store/buy/1 creates order with z-addr (valid PoW)... ");
    {
        char csrf_e2e[64] = "";
        bool have_csrf = fetch_csrf_token(1, csrf_e2e, sizeof(csrf_e2e));
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        char body[384];
        snprintf(body, sizeof(body),
            "customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&csrf_token=%s"
            "&pow_ts=%s&pow_nonce=%s",
            csrf_e2e, pow_ts, pow_nonce);
        size_t n = store_handle_request("POST", "/store/buy/1",
                                         (const uint8_t *)body, strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && have_csrf && have_pow;
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Order #") != NULL);
        ok = ok && (strstr((char *)resp, "t1YRBXKYLhrb") != NULL);
        ok = ok && (strstr((char *)resp, "zs1") != NULL);
        if (ok) printf("OK (z-address generated)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: e2e: GET /store/order shows Pending status... ");
    {
        /* Order created above; query the latest order */
        size_t n = store_handle_request("GET", "/store/order/2", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Pending") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("store: e2e: mint ZCL23ACCESS + verify gated access 200... ");
    {
        zslp_create_token(test_datadir, "ZCL23ACCESS", "Access Token", 0, 1000);
        zslp_mint(test_datadir, "ZCL23ACCESS", "t1Test", 10);
        size_t n = store_handle_request("GET",
            "/store/access?addr=t1Test&token=ZCL23ACCESS",
            NULL, 0, resp, sizeof(resp), test_datadir);
        bool ok = (n > 0);
        ok = ok && (strstr((char *)resp, "200 OK") != NULL);
        ok = ok && (strstr((char *)resp, "Premium Service") != NULL);
        if (ok) printf("OK (access granted)\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── ZSLP edge cases ─────────────────────────────────────── */

    printf("store: zslp multiple mints accumulate... ");
    {
        zslp_create_token(test_datadir, "ACCUM", "Accumulate", 0, 10000);
        zslp_mint(test_datadir, "ACCUM", "t1Accum", 100);
        zslp_mint(test_datadir, "ACCUM", "t1Accum", 200);
        zslp_mint(test_datadir, "ACCUM", "t1Accum", 300);
        uint64_t bal = zslp_balance(test_datadir, "ACCUM", "t1Accum");
        bool ok = (bal == 600);
        if (ok) printf("OK (balance=600)\n");
        else { printf("FAIL (balance=%llu)\n", (unsigned long long)bal); failures++; }
    }

    printf("store: zslp separate addresses keep independent balances... ");
    {
        zslp_create_token(test_datadir, "SPLIT", "Split Token", 0, 10000);
        zslp_mint(test_datadir, "SPLIT", "t1Alice", 100);
        zslp_mint(test_datadir, "SPLIT", "t1Bob", 250);
        uint64_t a = zslp_balance(test_datadir, "SPLIT", "t1Alice");
        uint64_t b = zslp_balance(test_datadir, "SPLIT", "t1Bob");
        bool ok = (a == 100) && (b == 250);
        if (ok) printf("OK (Alice=100, Bob=250)\n");
        else { printf("FAIL (Alice=%llu, Bob=%llu)\n",
                       (unsigned long long)a, (unsigned long long)b); failures++; }
    }

    printf("store: zslp balance 0 for existing token, missing addr... ");
    {
        uint64_t bal = zslp_balance(test_datadir, "SPLIT", "t1Ghost");
        bool ok = (bal == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (balance=%llu)\n", (unsigned long long)bal); failures++; }
    }

    printf("store: zslp two tokens with different tickers independent... ");
    {
        zslp_create_token(test_datadir, "COINX", "Coin X", 2, 5000);
        zslp_create_token(test_datadir, "COINY", "Coin Y", 4, 9000);
        zslp_mint(test_datadir, "COINX", "t1Holder", 42);
        zslp_mint(test_datadir, "COINY", "t1Holder", 99);
        uint64_t x = zslp_balance(test_datadir, "COINX", "t1Holder");
        uint64_t y = zslp_balance(test_datadir, "COINY", "t1Holder");
        bool ok = (x == 42) && (y == 99);
        /* Cross-check: minting one doesn't affect the other */
        zslp_mint(test_datadir, "COINX", "t1Holder", 8);
        x = zslp_balance(test_datadir, "COINX", "t1Holder");
        y = zslp_balance(test_datadir, "COINY", "t1Holder");
        ok = ok && (x == 50) && (y == 99);
        if (ok) printf("OK (X=50, Y=99)\n");
        else { printf("FAIL (X=%llu, Y=%llu)\n",
                       (unsigned long long)x, (unsigned long long)y); failures++; }
    }

    /* ── Template engine tests ────────────────────────────────── */

    printf("template: basic variable substitution... ");
    {
        char out[256];
        struct template_var vars[] = {
            { "name", "Alice" },
            { "greeting", "Hello" },
        };
        size_t n = template_render("{{greeting}}, {{name}}!",
            vars, 2, out, sizeof(out));
        bool ok = (n > 0) && (strcmp(out, "Hello, Alice!") == 0);
        if (ok) printf("OK (%s)\n", out);
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    printf("template: HTML escaping of < > & \" '... ");
    {
        char out[256];
        struct template_var vars[] = {
            { "val", "<b>A&B \"C\" 'D'</b>" },
        };
        size_t n = template_render("{{val}}", vars, 1, out, sizeof(out));
        bool ok = (n > 0);
        ok = ok && (strstr(out, "&lt;b&gt;") != NULL);
        ok = ok && (strstr(out, "&amp;") != NULL);
        ok = ok && (strstr(out, "&quot;") != NULL);
        ok = ok && (strstr(out, "&#39;") != NULL);
        ok = ok && (strstr(out, "<b>") == NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    printf("template: triple-brace raw output (no escaping)... ");
    {
        char out[256];
        struct template_var vars[] = {
            { "html", "<b>bold</b>" },
        };
        size_t n = template_render("{{{html}}}", vars, 1, out, sizeof(out));
        bool ok = (n > 0) && (strcmp(out, "<b>bold</b>") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    printf("template: missing variable leaves placeholder... ");
    {
        char out[256];
        struct template_var vars[] = {
            { "exists", "yes" },
        };
        size_t n = template_render("{{exists}} {{missing}}",
            vars, 1, out, sizeof(out));
        bool ok = (n > 0);
        ok = ok && (strstr(out, "yes") != NULL);
        ok = ok && (strstr(out, "{{missing}}") != NULL);
        if (ok) printf("OK (%s)\n", out);
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    printf("template: empty template returns empty... ");
    {
        char out[64];
        size_t n = template_render("", NULL, 0, out, sizeof(out));
        bool ok = (n == 0) && (out[0] == '\0');
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("template: NULL safety... ");
    {
        char out[64];
        bool ok = true;
        ok = ok && (template_render(NULL, NULL, 0, out, sizeof(out)) == 0);
        ok = ok && (template_render("hello", NULL, 0, NULL, 0) == 0);
        ok = ok && (template_render("hello", NULL, 0, out, 0) == 0);
        /* NULL vars with non-zero count: no crash, placeholders unchanged */
        size_t n = template_render("{{x}}", NULL, 0, out, sizeof(out));
        ok = ok && (n > 0) && (strcmp(out, "{{x}}") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("template: mixed escaped and raw in same template... ");
    {
        char out[512];
        struct template_var vars[] = {
            { "safe", "<script>alert(1)</script>" },
            { "raw", "<div class='x'>" },
        };
        size_t n = template_render("{{{raw}}}{{safe}}{{{raw}}}",
            vars, 2, out, sizeof(out));
        bool ok = (n > 0);
        ok = ok && (strstr(out, "<div class='x'>") != NULL);
        ok = ok && (strstr(out, "&lt;script&gt;") != NULL);
        ok = ok && (strstr(out, "<script>") == NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    printf("template: value with NULL treated as empty string... ");
    {
        char out[64];
        struct template_var vars[] = {
            { "key", NULL },
        };
        size_t n = template_render("[{{key}}]", vars, 1, out, sizeof(out));
        bool ok = (n > 0) && (strcmp(out, "[]") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    /* ── Product card template tests ─────────────────────────── */

    printf("template: product card renders with all variables... ");
    {
        static const char CARD[] =
            "<div class='product'>"
            "<h3><a href='/store/product/{{id}}'>{{name}}</a></h3>"
            "<p>{{description}}</p>"
            "<div class='price'>{{price}} ZCL</div>"
            "<a href='/store/product/{{id}}' class='btn'>View</a>"
            "</div>";
        char out[1024];
        struct template_var vars[] = {
            { "id",          "42" },
            { "name",        "Test Product" },
            { "description", "A fine product." },
            { "price",       "0.01000000" },
        };
        size_t n = template_render(CARD, vars, 4, out, sizeof(out));
        bool ok = (n > 0);
        ok = ok && (strstr(out, "/store/product/42") != NULL);
        ok = ok && (strstr(out, ">Test Product</a>") != NULL);
        ok = ok && (strstr(out, "<p>A fine product.</p>") != NULL);
        ok = ok && (strstr(out, "0.01000000 ZCL") != NULL);
        ok = ok && (strstr(out, "class='btn'") != NULL);
        if (ok) printf("OK (%zu bytes)\n", n);
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    printf("template: product card escapes HTML in name... ");
    {
        static const char CARD[] =
            "<h3>{{name}}</h3><p>{{description}}</p>";
        char out[512];
        struct template_var vars[] = {
            { "name",        "<script>alert('xss')</script>" },
            { "description", "Safe & sound \"always\"" },
        };
        size_t n = template_render(CARD, vars, 2, out, sizeof(out));
        bool ok = (n > 0);
        ok = ok && (strstr(out, "<script>") == NULL);
        ok = ok && (strstr(out, "&lt;script&gt;") != NULL);
        ok = ok && (strstr(out, "&#39;xss&#39;") != NULL);
        ok = ok && (strstr(out, "Safe &amp; sound") != NULL);
        ok = ok && (strstr(out, "&quot;always&quot;") != NULL);
        if (ok) printf("OK (XSS neutralized)\n");
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    printf("template: multiple variables in complex template... ");
    {
        char out[1024];
        struct template_var vars[] = {
            { "title",  "My Page" },
            { "user",   "Bob" },
            { "count",  "7" },
            { "link",   "/home" },
            { "footer", "2026" },
        };
        size_t n = template_render(
            "<h1>{{title}}</h1>"
            "<p>Welcome, {{user}}! You have {{count}} items.</p>"
            "<a href='{{link}}'>Home</a>"
            "<footer>{{footer}}</footer>",
            vars, 5, out, sizeof(out));
        bool ok = (n > 0);
        ok = ok && (strstr(out, "<h1>My Page</h1>") != NULL);
        ok = ok && (strstr(out, "Welcome, Bob!") != NULL);
        ok = ok && (strstr(out, "7 items") != NULL);
        ok = ok && (strstr(out, "href='/home'") != NULL);
        ok = ok && (strstr(out, "<footer>2026</footer>") != NULL);
        if (ok) printf("OK (5 variables rendered)\n");
        else { printf("FAIL (%s)\n", out); failures++; }
    }

    /* ── Sapling z-address generation ────────────────────────── */

    printf("store: zslp_generate_payment_address rejects small buffer... ");
    {
        /* Buffer-size guard fires before any key check, regardless of
         * whether a seeded wallet is wired. */
        char tiny[16] = "";
        bool ok = !zslp_generate_payment_address(test_datadir, tiny, sizeof(tiny));
        if (ok) printf("OK (rejected buffer < 80)\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Refusal teeth (no seeded keystore) ─────────────────────
     * Drop the runtime wallet so the controller path has no seeded
     * keystore, then prove EVERY entry point refuses (no synthetic
     * fallback) and the buy page returns 503 rather than binding an order
     * to an unrecoverable address. Restore the seeded wallet afterwards. */
    app_runtime_set_current(NULL);

    printf("store: payment-address mint refused when no seeded keystore... ");
    {
        char addr1[128] = "x", addr2[128] = "y";
        bool ok1 = !zslp_generate_payment_address(test_datadir, addr1,
                                                  sizeof(addr1));
        bool ok2 = !zslp_generate_payment_address(test_datadir, addr2,
                                                  sizeof(addr2));
        /* Both calls refuse and clear the buffer; no synthetic address is
         * ever produced regardless of timestamp. */
        bool ok = ok1 && ok2 && addr1[0] == '\0' && addr2[0] == '\0';
        if (ok) printf("OK (both refused)\n");
        else { printf("FAIL (a1='%s' a2='%s')\n", addr1, addr2); failures++; }
    }

    printf("store: buy serves 503 rather than bind a fake address... ");
    {
        uint8_t resp[4096];
        char csrf_rb[64] = "";
        fetch_csrf_token(1, csrf_rb, sizeof(csrf_rb));
        char pow_ts[32] = "", pow_nonce[32] = "";
        bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                               pow_nonce, sizeof(pow_nonce));
        char body[384];
        int blen = snprintf(body, sizeof(body),
            "customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&csrf_token=%s"
            "&pow_ts=%s&pow_nonce=%s",
            csrf_rb, pow_ts, pow_nonce);
        size_t n = store_handle_request("POST", "/store/buy/1",
            (const uint8_t *)body, (size_t)blen,
            resp, sizeof(resp), test_datadir);
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        /* With no seeded keystore the order MUST NOT be created. The
         * controller serves 503 and NEVER emits a synthetic placeholder
         * address (zs1_pay_ / zs1_order_). This also proves the PoW
         * gate ran and passed here — the 503 comes from INSIDE
         * serve_create_order (zslp_generate_payment_address failing),
         * which the gate only reaches after a valid puzzle. */
        bool ok = (n > 0) && have_pow;
        ok = ok && (strstr((char *)resp, "503") != NULL);
        ok = ok && (strstr((char *)resp, "zs1_order_") == NULL);
        ok = ok && (strstr((char *)resp, "zs1_pay_") == NULL);
        if (ok) printf("OK (503, no fake address)\n");
        else { printf("FAIL (no 503 / contains fake address)\n"); failures++; }
    }

    /* Restore the seeded merchant wallet for any subsequent tests. */
    app_runtime_set_current(&g_store_test_rt);

    /* ── Pending-order pool caps + pruning ──────────────────────
     * Seed rows directly via db_store_order_save (bypassing HTTP/PoW —
     * these are DB-shape preconditions, not proof the HTTP path can
     * reach them; that's proven separately above) to reach the cap
     * WITHOUT solving hundreds of real puzzles, then prove ONE real
     * HTTP order-create attempt is refused while the pool is full, and
     * that pruning reclaims expired rows so it un-refuses. */
    {
        char dbpath[320];
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", test_datadir);
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool have_db = node_db_open(&ndb, dbpath);

        printf("store: per-product pending cap refuses a real order when full... ");
        {
            /* Fill product 77's (synthetic — no real product row needed,
             * `orders.product_id` carries no FK) pending pool to the cap. */
            for (int i = 0; have_db && i < STORE_ORDER_MAX_PENDING_PER_PRODUCT; i++) {
                struct db_store_order o;
                memset(&o, 0, sizeof(o));
                o.product_id = 77;
                snprintf(o.customer_addr, sizeof(o.customer_addr),
                         "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn");
                snprintf(o.payment_addr, sizeof(o.payment_addr),
                         "zs1capfill%06d", i);
                o.amount_zatoshi = 1000000;
                o.status = STORE_ORDER_PENDING;
                if (!db_store_order_save(&ndb, &o)) { have_db = false; break; }
            }
            int pending77 = have_db
                ? db_store_order_count_pending_for_product(&ndb, 77) : -1;

            char csrf_ctx77[64], csrf77[33];
            store_csrf_context(csrf_ctx77, sizeof(csrf_ctx77), 77);
            store_csrf_token(csrf_ctx77, csrf77);
            /* Synthetic product 77 has no page to scrape, so ask the gate
             * for its live challenge directly — same call the view makes.
             * Reset first, same reason as solve_store_pow_fields(). */
            store_pow_reset_state();
            struct store_pow_challenge ch77;
            store_pow_challenge(77, &ch77);
            uint8_t seed77[32], token77[32];
            uint64_t nonce77 = 0;
            bool solved77 =
                hex32_to_bytes(ch77.seed_hex, seed77) &&
                hex32_to_bytes(ch77.token_hex, token77) &&
                puzzle_solve_random(seed77, token77, ch77.server_time,
                                    ch77.bits, &nonce77);

            char body[384];
            snprintf(body, sizeof(body),
                "product_id=77&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                "&csrf_token=%s&pow_ts=%lld&pow_nonce=%llu",
                csrf77, (long long)ch77.server_time,
                (unsigned long long)nonce77);
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body, strlen(body),
                                             resp, sizeof(resp), test_datadir);
            bool ok = have_db && solved77 &&
                      pending77 == STORE_ORDER_MAX_PENDING_PER_PRODUCT;
            ok = ok && (n > 0);
            ok = ok && (strstr((char *)resp, "503") != NULL);
            ok = ok && (strstr((char *)resp, "Product busy") != NULL);
            ok = ok && (strstr((char *)resp, "Order #") == NULL);
            if (ok) printf("OK (pending77=%d, refused)\n", pending77);
            else { printf("FAIL (have_db=%d solved77=%d pending77=%d)\n",
                          have_db, solved77, pending77); failures++; }
        }

        printf("store: prune_expired evicts the cap-filling rows, unblocking a real order... ");
        {
            /* The seeded rows above have created_at="now" (db_store_order_save
             * defaults it), so pruning at the real expiry window would NOT
             * evict them yet — prove prune is a no-op on FRESH rows, then
             * age them out with a 0-second window (still >= created_at,
             * i.e. "everything") to prove the DELETE path itself works and
             * actually shrinks the count. */
            int fresh_pruned = have_db
                ? db_store_order_prune_expired(&ndb, STORE_ORDER_PENDING_EXPIRE_SECS)
                : -1;
            int before = have_db
                ? db_store_order_count_pending_for_product(&ndb, 77) : -1;
            /* A 0-second window means "created before right now" — cross
             * into the next wall-clock second first so rows created a
             * moment ago (same second as this call) are strictly older
             * than the cutoff, not tied with it. */
            if (have_db) wait_for_next_wall_second();
            int aged_pruned = have_db
                ? db_store_order_prune_expired(&ndb, 0) : -1;
            int after = have_db
                ? db_store_order_count_pending_for_product(&ndb, 77) : -1;

            bool ok = have_db && fresh_pruned == 0 &&
                      before == STORE_ORDER_MAX_PENDING_PER_PRODUCT &&
                      aged_pruned >= STORE_ORDER_MAX_PENDING_PER_PRODUCT &&
                      after == 0;
            if (ok) printf("OK (fresh_pruned=%d before=%d aged_pruned=%d after=%d)\n",
                            fresh_pruned, before, aged_pruned, after);
            else {
                printf("FAIL (fresh_pruned=%d before=%d aged_pruned=%d after=%d)\n",
                       fresh_pruned, before, aged_pruned, after);
                failures++;
            }
        }

        printf("store: global pending cap refuses a real order when full (product cap not tripped)... ");
        {
            /* Spread STORE_ORDER_MAX_PENDING_GLOBAL rows across many
             * synthetic product_ids so each stays under the PER-PRODUCT
             * cap while the GLOBAL total reaches its cap — isolates the
             * "Store busy" (global) message from "Product busy". */
            enum { SPREAD = 10 };
            bool seed_ok = have_db;
            for (int i = 0; seed_ok && i < STORE_ORDER_MAX_PENDING_GLOBAL; i++) {
                struct db_store_order o;
                memset(&o, 0, sizeof(o));
                o.product_id = 9000 + (i % SPREAD);
                snprintf(o.customer_addr, sizeof(o.customer_addr),
                         "t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn");
                snprintf(o.payment_addr, sizeof(o.payment_addr),
                         "zs1globalfill%06d", i);
                o.amount_zatoshi = 1000000;
                o.status = STORE_ORDER_PENDING;
                if (!db_store_order_save(&ndb, &o)) { seed_ok = false; break; }
            }
            int pending_global = seed_ok
                ? db_store_order_count_pending(&ndb) : -1;
            /* Product 1 (a real, unrelated product) has 0 rows of its own. */
            int pending1 = seed_ok
                ? db_store_order_count_pending_for_product(&ndb, 1) : -1;

            char pow_ts[32] = "", pow_nonce[32] = "";
            bool have_pow = solve_store_pow_fields(1, pow_ts, sizeof(pow_ts),
                                                   pow_nonce, sizeof(pow_nonce));
            char body[384];
            snprintf(body, sizeof(body),
                "product_id=1&customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn"
                "&csrf_token=%s&pow_ts=%s&pow_nonce=%s",
                csrf1, pow_ts, pow_nonce);
            size_t n = store_handle_request("POST", "/store/orders",
                                             (const uint8_t *)body, strlen(body),
                                             resp, sizeof(resp), test_datadir);
            bool ok = seed_ok && have_pow &&
                      pending_global >= STORE_ORDER_MAX_PENDING_GLOBAL &&
                      pending1 < STORE_ORDER_MAX_PENDING_PER_PRODUCT;
            ok = ok && (n > 0);
            ok = ok && (strstr((char *)resp, "503") != NULL);
            ok = ok && (strstr((char *)resp, "Store busy") != NULL);
            ok = ok && (strstr((char *)resp, "Order #") == NULL);
            if (ok) printf("OK (pending_global=%d, refused)\n", pending_global);
            else { printf("FAIL (seed_ok=%d have_pow=%d pending_global=%d pending1=%d)\n",
                          seed_ok, have_pow, pending_global, pending1); failures++; }

            /* Clean up: the pruning test above only ages out product 77's
             * rows via an explicit test call; these globalfill rows are
             * still "fresh" by created_at, so remove them directly here
             * rather than leaving 1000 rows for every later test in this
             * function to scan past. Cross a wall-clock second first —
             * same reasoning as the prune test above. */
            if (seed_ok) {
                wait_for_next_wall_second();
                db_store_order_prune_expired(&ndb, 0);
            }
        }

        if (have_db) node_db_close(&ndb);
    }

    /* ── Robustness: products.json loading ── */
    printf("store: loads products from JSON file... ");
    {
        /* Create a store directory with products.json */
        char store_dir[512], json_path[512];
        snprintf(store_dir, sizeof(store_dir), "%s/store", test_datadir);
        mkdir(store_dir, 0755);
        snprintf(json_path, sizeof(json_path), "%s/products.json", store_dir);
        FILE *f = fopen(json_path, "w");
        if (f) {
            fprintf(f, "[{\"name\":\"Test Product\","
                    "\"description\":\"A test\","
                    "\"price_zcl\":0.5,"
                    "\"token_id\":\"TEST\","
                    "\"tokens_per_purchase\":3}]");
            fclose(f);
        }
        /* Delete existing products so schema re-seeds from JSON */
        char db_path2[512];
        snprintf(db_path2, sizeof(db_path2), "%s/node.db", test_datadir);
        sqlite3 *db2 = NULL;
        if (sqlite3_open(db_path2, &db2) == SQLITE_OK) {
            sqlite3_exec(db2, "DELETE FROM products", NULL, NULL, NULL);
            sqlite3_close(db2);
        }
        /* Trigger schema check via a store request */
        uint8_t resp[65536];  /* styled listing inlines ~14 KB CSS */
        size_t n = store_handle_request("GET", "/store", NULL, 0,
            resp, sizeof(resp), test_datadir);
        resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = '\0';
        bool ok = (n > 0 && strstr((char *)resp, "Test Product") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (product not found in response)\n"); failures++; }
        unlink(json_path);
        test_cleanup_tmpdir(store_dir);
    }

    /* Tear down the seeded merchant runtime wallet. */
    app_runtime_set_current(NULL);
    sapling_keystore_free(&g_store_test_wallet.sapling_keys);

    if (failures > 0)
        printf("Store: debug datadir preserved at %s\n", test_datadir);
    else
        cleanup_datadir();

    printf("Store + ZSLP + Template: %d failures\n", failures);
    return failures;
}
