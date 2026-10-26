/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bot — headless wallet bot driver. Pure C, no display, no GTK.
 *
 * Renders every page via wallet_view_handle_request(), parses HTML,
 * simulates form submissions, verifies data matches zclassicd,
 * checks for UX bugs. Zero dependencies beyond the C23 binary.
 *
 * Usage: make bot
 *
 * This is the definitive test: if the bot passes, the app works. */

#include "json/json.h"
#include "zutf8/zutf8.h"
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#ifndef Z23_BOT_RPC_ONLY
#include "platform/time_compat.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include "chain/chainparams.h"
#include "keys/key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <time.h>

volatile sig_atomic_t g_shutdown_requested = 0;

/* ── Rendering engine ──────────────────────────────────── */

static uint8_t _buf[262144];
static size_t _len;
static char _body[262144]; /* body only (headers stripped) */
static size_t _blen;

static size_t GET(const char *path) {
    memset(_buf, 0, sizeof(_buf));
    _len = wallet_view_handle_request("GET", path, NULL, 0,
                                       _buf, sizeof(_buf));
    const char *b = strstr((char *)_buf, "\r\n\r\n");
    if (b) { b += 4; _blen = _len - (size_t)(b - (char *)_buf); }
    else { b = (char *)_buf; _blen = _len; }
    if (_blen >= sizeof(_body)) _blen = sizeof(_body) - 1;
    memcpy(_body, b, _blen);
    _body[_blen] = '\0';
    return _len;
}

static size_t POST(const char *path, const char *body) {
    memset(_buf, 0, sizeof(_buf));
    _len = wallet_view_handle_request("POST", path,
        body ? (const uint8_t *)body : NULL,
        body ? strlen(body) : 0, _buf, sizeof(_buf));
    const char *b = strstr((char *)_buf, "\r\n\r\n");
    if (b) { b += 4; _blen = _len - (size_t)(b - (char *)_buf); }
    else { b = (char *)_buf; _blen = _len; }
    if (_blen >= sizeof(_body)) _blen = sizeof(_body) - 1;
    memcpy(_body, b, _blen);
    _body[_blen] = '\0';
    return _len;
}

/* HTML checks */
static int has(const char *s) { return strstr(_body, s) != NULL; }
static int has_not(const char *s) { return strstr(_body, s) == NULL; }

/* Extract a value after a key like: var BAL=0.12345678; */
static double extract_js_var(const char *var_name) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=", var_name);
    const char *p = strstr(_body, pattern);
    if (!p) return -1;
    return strtod(p + strlen(pattern), NULL);
}

/* ── Test framework ────────────────────────────────────── */

static int _num, _pass, _fail;
static struct timespec _t0;

static void start_timer(void) { platform_time_monotonic_timespec(&_t0); }
static double elapsed_ms(void) {
    struct timespec t1;
    platform_time_monotonic_timespec(&t1);
    return (t1.tv_sec - _t0.tv_sec) * 1000.0 +
           (t1.tv_nsec - _t0.tv_nsec) / 1e6;
}

#define CHECK(desc, cond) do { \
    _num++; \
    if (cond) { _pass++; printf("  ✓  %-55s\n", desc); } \
    else { _fail++; printf("  ✗  %-55s\n", desc); } \
} while(0)

#define SECTION(name) printf("\n── %s ──\n", name)

#endif /* Z23_BOT_RPC_ONLY */

/* ── RPC queries ───────────────────────────────────────── */

static double rpc_t, rpc_z, rpc_total;
static int rpc_height, rpc_peers;

static int rpc_decimal_exponent(const char *p, const char *end)
{
    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        const char *first = p;
        while (p < end && *p >= '0' && *p <= '9') p++;
        if (p == first) return 0;
    }
    return p == end;
}

static int rpc_decimal_span(const char *value, const char *end)
{
    const char *p = value;
    if (p < end && *p == '-') p++;
    if (p == end) return 0;
    if (*p == '0') p++;
    else {
        const char *first = p;
        while (p < end && *p >= '0' && *p <= '9') p++;
        if (p == first) return 0;
    }
    if (p < end && *p == '.') {
        const char *first = ++p;
        while (p < end && *p >= '0' && *p <= '9') p++;
        if (p == first) return 0;
    }
    return rpc_decimal_exponent(p, end);
}

static int rpc_balance_number(const struct json_value *obj,
                              const char *key, double *out)
{
    *out = 0.0;
    const struct json_value *v = json_get(obj, key);
    if (!v) return 0;
    if (v->type == JSON_INT || v->type == JSON_REAL) {
        double number = json_get_real(v);
        if (!isfinite(number)) return 0;
        *out = number;
        return 1;
    }
    if (v->type != JSON_STR) return 0;
    const char *value = json_get_str(v);
    const char *end = value + strlen(value);
    if (!rpc_decimal_span(value, end)) return 0;
    char *converted_end = NULL;
    errno = 0;
    double number = strtod(value, &converted_end);
    if (converted_end != end || errno == ERANGE || !isfinite(number)) return 0;
    *out = number;
    return 1;
}

static void rpc_query_info(void)
{
    char info[4096] = "";
    if (wv_rpc_call("getinfo", "[]", info, sizeof(info)) > 0) {
        const char *h = strstr(info, "\"blocks\"");
        const char *p = strstr(info, "\"connections\"");
        if (h) rpc_height = (int)strtol(h + 9, NULL, 10);
        if (p) rpc_peers = (int)strtol(p + 14, NULL, 10);
    }
}

static int query_rpc(void)
{
    char buf[4096] = "";
    int reply_len = wv_rpc_call("z_gettotalbalance", "[]", buf, sizeof(buf));
    if (reply_len <= 0 || (size_t)reply_len >= sizeof(buf)) return 0;
    size_t n = (size_t)reply_len;
    if (memchr(buf, '\0', n) || !zutf8_validate_n(buf, n) ||
        !json_valid(buf, n)) return 0;
    buf[n] = '\0';
    struct json_value reply = {0};
    if (!json_read(&reply, buf, n)) return 0;
    const struct json_value *balances = json_get(&reply, "result");
    if (!balances) balances = &reply;
    double t, z, total;
    int valid = balances->type == JSON_OBJ &&
        rpc_balance_number(balances, "transparent", &t) &&
        rpc_balance_number(balances, "private", &z) &&
        rpc_balance_number(balances, "total", &total);
    json_free(&reply);
    if (!valid) return 0;
    rpc_t = t;
    rpc_z = z;
    rpc_total = total;
    rpc_query_info();
    return 1;
}

#ifndef Z23_BOT_RPC_ONLY
/* ═══════════════════════════════════════════════════════ */

/* ── Per-page checks ───────────────────────────────────── */

static double check_dashboard_renders(void)
{
    start_timer();
    GET("/wallet");
    double dash_ms = elapsed_ms();

    CHECK("renders (>1000 bytes)", _len > 1000);
    CHECK("renders fast (<500ms)", dash_ms < 500);
    CHECK("shows ZCL balance", has("ZCL"));
    CHECK("has Send button", has("href='/wallet/send'"));
    CHECK("has Receive button", has("href='/wallet/receive'"));
    CHECK("has privacy meter", has("private"));
    return dash_ms;
}

static void check_dashboard_markup(void)
{
    CHECK("has nav: Home/Send/Receive/History/Node",
          has(">Home<") && has(">Send<") && has(">Receive<") &&
          has(">History<") && has(">Node<"));
    CHECK("no SQL leaks", has_not("sqlite3") && has_not("SELECT "));
    CHECK("no template leaks", has_not("{{{"));
}

static void check_dashboard_rpc_balance(int have_rpc)
{
    CHECK("no 'untraceable' at <100%",
          !have_rpc || rpc_z / (rpc_t + rpc_z + 0.0001) > 0.999 ||
          has_not("untraceable"));

    if (have_rpc) {
        char expected[32];
        snprintf(expected, sizeof(expected), "%.8f", rpc_total);
        CHECK("balance matches zclassicd", has(expected));

        int pct = (int)(100.0 * rpc_z / (rpc_t + rpc_z + 0.0001));
        char pct_s[8]; snprintf(pct_s, sizeof(pct_s), "%d%%", pct);
        char pct_lo[8]; snprintf(pct_lo, sizeof(pct_lo), "%d%%", pct > 0 ? pct-1 : 0);
        char pct_hi[8]; snprintf(pct_hi, sizeof(pct_hi), "%d%%", pct < 100 ? pct+1 : 100);
        CHECK("privacy % accurate",
              has(pct_s) || has(pct_lo) || has(pct_hi));
    }
}

static void check_dashboard_rpc_nudge(int have_rpc)
{
    if (have_rpc) {
        if (rpc_t < 0.00011)
            CHECK("no shield nudge for dust", has_not("Shield All"));
        else
            CHECK("shield nudge shown", has("Shield All") || has("/wallet/shield"));
    }
}

static double check_send_page_render(void)
{
    start_timer();
    GET("/wallet/send");
    double send_ms = elapsed_ms();

    CHECK("renders", _len > 1000);
    CHECK("has address input", has("name=\"address\"") || has("name='address'"));
    CHECK("has amount input", has("name=\"amount\"") || has("name='amount'"));
    CHECK("shows fee", has("0.0001"));
    CHECK("Send tab active", has("active'>Send"));
    CHECK("no SQL leaks", has_not("sqlite3"));
    return send_ms;
}

static void check_send_page_rpc(int have_rpc)
{
    if (have_rpc) {
        /* THE BIG CHECK: JS BAL must include shielded balance */
        double bal = extract_js_var("var BAL");
        CHECK("JS BAL > 0 (has funds)", bal > 0.0001 || rpc_total < 0.001);
        if (rpc_total > 0.001) {
            CHECK("JS BAL includes shielded",
                  fabs(bal - rpc_total) < 0.001);
        }

        char tot_s[32]; snprintf(tot_s, sizeof(tot_s), "%.8f", rpc_total);
        CHECK("spendable shows total balance", has(tot_s));
    }
}

static void check_send_flow(void)
{
    POST("/wallet/send/review", "address=bad&amount=1.0");
    CHECK("bad address → error page", has("Invalid") || has("invalid") || has("short"));
    CHECK("error page has retry", has("Try Again") || has("/wallet/send"));

    POST("/wallet/send/review",
        "address=zs19hc6ghlrzklr7y82u9w6822zuvrpfmgzlqz7alx8eqtwh2rvzgykl6m3lu8gwarpflcczgyse2p&amount=0.001");
    CHECK("valid z-addr review renders", _len > 200);
    CHECK("review shows amount", has("0.001"));
    CHECK("review no 'Insufficient'", has_not("Insufficient"));

    POST("/wallet/send/review", "address=&amount=0");
    CHECK("empty form → no crash", _len > 200);

    POST("/wallet/send/review", NULL);
    CHECK("NULL body → no crash", _len > 0);
}

static void check_receive_page(void)
{
    GET("/wallet/receive");

    CHECK("renders", _len > 500);
    CHECK("private tab recommended", has("recommended"));
    CHECK("zero-knowledge proof described", has("zero-knowledge proof"));
    CHECK("on-chain warning for t-addr", has("on-chain"));
    CHECK("has QR SVG", has("<svg"));
    CHECK("Receive tab active", has("active'>Receive"));
}

static void check_history_page(void)
{
    GET("/wallet/history");

    CHECK("renders", _len > 500);
    CHECK("History tab active", has("active'>History"));
    CHECK("no 'Secured Secured' duplicate", has_not("Secured Secured"));
    CHECK("no zero-value entries", has_not("+0.00000000"));
    CHECK("no SQL leaks", has_not("sqlite3") && has_not("SELECT "));

    GET("/wallet/history?page=0");
    CHECK("page 0 works", _len > 200);
    GET("/wallet/history?page=99999");
    CHECK("huge page → no crash", _len > 200);
    GET("/wallet/history?filter=sent");
    CHECK("filter=sent works", _len > 200);
    GET("/wallet/history?q=<script>alert(1)</script>");
    CHECK("XSS in search escaped", has_not("<script>alert"));
}

static void check_node_page(void)
{
    GET("/wallet/node");

    CHECK("renders", _len > 1000);
    CHECK("Command Center heading", has("Command Center"));
    CHECK("sovereignty statement", has("sovereign"));
    CHECK("block height shown", has("Block Height"));
    CHECK("peers shown", has("Connected Peers"));
    CHECK("version shown", has("ZClassic23:0.1.0"));
    CHECK("Node tab active", has("active'>Node"));
}

static void check_coins_page(void)
{
    GET("/wallet/coins");

    CHECK("renders", _len > 200);
    CHECK("Coin Audit heading", has("Coin Audit"));
    CHECK("no SQL leaks", has_not("sqlite3"));
}

static void check_shield_page(int have_rpc)
{
    GET("/wallet/shield");

    CHECK("renders", _len > 200);
    if (have_rpc && rpc_t < 0.00011) {
        CHECK("nothing to shield (dust)", has("Nothing to shield"));
    } else {
        CHECK("shield form or nothing-to-shield",
              has("Amount") || has("Nothing to shield"));
    }
}

static void check_shield_confirm_flow(void)
{
    GET("/wallet/shield?amount=0.5");
    CHECK("confirm page renders", _len > 500);
    CHECK("confirm shows amount", has("0.5"));

    POST("/wallet/shield/confirm", "amount=0");
    CHECK("zero amount → invalid", has("Invalid") || has("invalid"));

    POST("/wallet/shield/confirm", "amount=-1");
    CHECK("negative amount → invalid", has("Invalid") || has("invalid"));
}

static void check_tx_detail_page(void)
{
    GET("/wallet/tx/0000000000000000000000000000000000000000000000000000000000000000");
    CHECK("valid txid renders", _len > 200);

    GET("/wallet/tx/<script>alert(1)</script>");
    CHECK("XSS in txid escaped", has_not("<script>alert"));

    GET("/wallet/tx/short");
    CHECK("short txid → error", _len > 200);
}

static void check_pulse_api(void)
{
    GET("/api/wallet/pulse");

    CHECK("returns JSON", has("{"));
    CHECK("has height", has("\"height\""));
    CHECK("has balance", has("\"balance\""));
    CHECK("has shielded", has("\"shielded\""));
    CHECK("has peers", has("\"peers\""));
    CHECK("is not HTML", has_not("<!DOCTYPE"));
}

static void check_unknown_routes(void)
{
    { size_t n = GET("/wallet/doesnotexist");
      CHECK("/wallet/doesnotexist → empty", n == 0); }
    { size_t n = GET("/wallet/send/badpath");
      CHECK("/wallet/send/badpath → empty", n == 0); }
}

int main(int argc, char **argv)
{
    const char *datadir = NULL;
    if (argc > 1) datadir = argv[1];
    else {
        static char dd[512];
        const char *home = getenv("HOME");
        if (home) { snprintf(dd, sizeof(dd), "%s/.zclassic-c23", home); datadir = dd; }
    }

    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();

    printf("═══════════════════════════════════════════════════\n");
    printf("  Z23 Bot Driver (headless, pure C)\n");
    printf("  datadir: %s\n", datadir ? datadir : "(none)");
    printf("═══════════════════════════════════════════════════\n");

    wallet_view_enable_sync();
    wallet_view_init(datadir);

    /* Query zclassicd */
    int have_rpc = query_rpc();
    if (have_rpc) {
        printf("  zclassicd: t=%.8f z=%.8f total=%.8f\n",
               rpc_t, rpc_z, rpc_total);
        printf("  height=%d peers=%d\n", rpc_height, rpc_peers);
        wv_sync_wallet_from_zclassicd();
    } else {
        printf("  zclassicd: not reachable (testing render only)\n");
    }

    _num = 0; _pass = 0; _fail = 0;

    /* ═══ DASHBOARD ═══ */
    SECTION("Dashboard");
    double dash_ms = check_dashboard_renders();
    check_dashboard_markup();
    check_dashboard_rpc_balance(have_rpc);
    check_dashboard_rpc_nudge(have_rpc);
    printf("  (%.0f ms)\n", dash_ms);

    /* ═══ SEND ═══ */
    SECTION("Send page");
    double send_ms = check_send_page_render();
    check_send_page_rpc(have_rpc);
    printf("  (%.0f ms)\n", send_ms);

    /* ═══ SEND FORM SUBMISSION ═══ */
    SECTION("Send flow (form submission)");
    check_send_flow();

    /* ═══ RECEIVE ═══ */
    SECTION("Receive page");
    check_receive_page();

    /* ═══ HISTORY ═══ */
    SECTION("History");
    check_history_page();

    /* ═══ NODE ═══ */
    SECTION("Node / Command Center");
    check_node_page();

    /* ═══ COINS ═══ */
    SECTION("Coins / Audit");
    check_coins_page();

    /* ═══ SHIELD ═══ */
    SECTION("Shield");
    check_shield_page(have_rpc);
    check_shield_confirm_flow();

    /* ═══ TX DETAIL ═══ */
    SECTION("Transaction detail");
    check_tx_detail_page();

    /* ═══ PULSE API ═══ */
    SECTION("Pulse API");
    check_pulse_api();

    /* ═══ UNKNOWN ROUTES ═══ */
    SECTION("Unknown routes");
    check_unknown_routes();

    /* ═══ RESULTS ═══ */
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  %d passed, %d failed (%d total)\n", _pass, _fail, _num);
    if (_fail)
        printf("  STATUS: ✗ FAILED\n");
    else
        printf("  STATUS: ✓ ALL CHECKS PASSED\n");
    printf("═══════════════════════════════════════════════════\n");

    ecc_verify_destroy();
    ecc_stop();
    return _fail > 0 ? 1 : 0;
}
#endif /* Z23_BOT_RPC_ONLY */
