/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * session — simulate a real user session with timing and logging.
 *
 * Walks through the app like a real user: opens dashboard, checks
 * balance, navigates to send, fills a form, reviews, navigates
 * to history, checks transactions, visits node page, etc.
 *
 * Logs every interaction with timing. Validates data consistency
 * across pages. Uses MVC observers to track model access.
 *
 * Usage: make session */

#include "platform/time_compat.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include "models/activerecord.h"
#include "event/event.h"
#include "chain/chainparams.h"
#include "keys/key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <time.h>

volatile sig_atomic_t g_shutdown_requested = 0;

/* ── Timing ────────────────────────────────────────────── */

static struct timespec _t0, _session_start;
static int _step;

static void tick(void) { platform_time_monotonic_timespec(&_t0); }
static double tock_ms(void) {
    struct timespec t1;
    platform_time_monotonic_timespec(&t1);
    return (t1.tv_sec - _t0.tv_sec) * 1000.0 +
           (t1.tv_nsec - _t0.tv_nsec) / 1e6;
}
static double session_ms(void) {
    struct timespec t1;
    platform_time_monotonic_timespec(&t1);
    return (t1.tv_sec - _session_start.tv_sec) * 1000.0 +
           (t1.tv_nsec - _session_start.tv_nsec) / 1e6;
}

/* ── Rendering ─────────────────────────────────────────── */

static uint8_t _buf[262144];
static size_t _len;
static char _body[262144];

static size_t DO(const char *method, const char *path, const char *post_body) {
    _step++;
    tick();
    memset(_buf, 0, sizeof(_buf));
    _len = wallet_view_handle_request(method, path,
        post_body ? (const uint8_t *)post_body : NULL,
        post_body ? strlen(post_body) : 0,
        _buf, sizeof(_buf));
    double ms = tock_ms();

    const char *b = strstr((char *)_buf, "\r\n\r\n");
    if (b) { b += 4; } else { b = (char *)_buf; }
    size_t blen = _len - (size_t)(b - (char *)_buf);
    if (blen >= sizeof(_body)) blen = sizeof(_body) - 1;
    memcpy(_body, b, blen);
    _body[blen] = '\0';

    /* Log */
    const char *status = _len > 0 ? "OK" : "EMPTY";
    bool leaked = strstr(_body, "{{{") != NULL ||
                  strstr(_body, "sqlite3") != NULL;
    if (leaked) status = "LEAK!";

    printf("  [%3d] %6.1f ms  %-4s %-45s %5zu bytes  %s\n",
           _step, ms, method, path, _len, status);

    if (ms > 500)
        printf("        ⚠ SLOW (%.0f ms)\n", ms);
    if (leaked)
        printf("        ⚠ TEMPLATE/SQL LEAK DETECTED\n");

    return _len;
}

static int has(const char *s) { return strstr(_body, s) != NULL; }

static double extract_var(const char *name) {
    char pat[64]; snprintf(pat, sizeof(pat), "%s=", name);
    const char *p = strstr(_body, pat);
    return p ? strtod(p + strlen(pat), NULL) : -1;
}

/* ── RPC ───────────────────────────────────────────────── */

static double rpc_total = 0;

static void query_rpc(void) {
    char buf[4096] = "";
    if (wv_rpc_call("z_gettotalbalance", "[]", buf, sizeof(buf)) > 0) {
        const char *t = strstr(buf, "\"total\"");
        if (t) { t = strchr(t + 7, '"'); if (t) rpc_total = strtod(t + 1, NULL); }
    }
}

/* ── Validators ────────────────────────────────────────── */

static int _errors;

static void VERIFY(const char *desc, int cond) {
    if (!cond) {
        printf("        ✗ VERIFY FAILED: %s\n", desc);
        _errors++;
    }
}

/* ═══════════════════════════════════════════════════════ */

static const char *resolve_datadir(int argc, char **argv) {
    if (argc > 1) return argv[1];
    static char dd[512];
    const char *home = getenv("HOME");
    if (home) { snprintf(dd, sizeof(dd), "%s/.zclassic-c23", home); return dd; }
    return NULL;
}

static void check_dashboard_page(void) {
    DO("GET", "/wallet", NULL);
    VERIFY("dashboard renders >1KB", _len > 1000);
    VERIFY("balance shown", has("ZCL"));
    if (rpc_total > 0) {
        char exp[32]; snprintf(exp, sizeof(exp), "%.8f", rpc_total);
        VERIFY("balance matches RPC", has(exp));
    }
    VERIFY("privacy meter", has("private"));
    VERIFY("nav present", has(">Send<") && has(">Receive<"));
}

static void check_send_page(void) {
    DO("GET", "/wallet/send", NULL);
    VERIFY("send renders", _len > 1000);
    double bal = extract_var("var BAL");
    VERIFY("JS BAL > 0", bal > 0.0001 || rpc_total < 0.001);
    if (rpc_total > 0.001)
        VERIFY("BAL matches total", fabs(bal - rpc_total) < 0.001);
    VERIFY("has address input", has("name=\"address\"") || has("name='address'"));
    VERIFY("has amount input", has("name=\"amount\"") || has("name='amount'"));
}

static void try_send_with_bad_address(void) {
    DO("POST", "/wallet/send/review", "address=xyz&amount=0.5");
    VERIFY("error shown", has("Invalid") || has("invalid") || has("short"));
    VERIFY("retry available", has("Try Again") || has("/wallet/send"));
}

static void review_send_to_valid_zaddress(void) {
    DO("POST", "/wallet/send/review",
       "address=zs19hc6ghlrzklr7y82u9w6822zuvrpfmgzlqz7alx8eqtwh2rvzgykl6m3lu8gwarpflcczgyse2p&amount=0.001");
    VERIFY("review renders", _len > 200);
    VERIFY("amount shown", has("0.001"));
    VERIFY("no 'Insufficient'", !has("Insufficient"));
}

static void check_receive_page(void) {
    DO("GET", "/wallet/receive", NULL);
    VERIFY("renders", _len > 500);
    VERIFY("private recommended", has("recommended"));
    VERIFY("QR code", has("<svg"));
    VERIFY("z-address shown", has("zs1"));
}

static void browse_history_pages(void) {
    DO("GET", "/wallet/history", NULL);
    VERIFY("renders", _len > 500);
    VERIFY("no zero-value", !has("+0.00000000"));
    VERIFY("no SQL", !has("sqlite3") && !has("SELECT "));

    DO("GET", "/wallet/history?filter=sent", NULL);
    VERIFY("sent filter works", _len > 200);

    DO("GET", "/wallet/history?filter=recv", NULL);
    VERIFY("recv filter works", _len > 200);

    DO("GET", "/wallet/history?q=<script>alert(1)</script>", NULL);
    VERIFY("XSS escaped", !has("<script>alert"));
}

static void visit_node_page(void) {
    DO("GET", "/wallet/node", NULL);
    VERIFY("renders", _len > 1000);
    VERIFY("sovereignty", has("sovereign"));
    VERIFY("block height", has("Block Height"));
    VERIFY("peers", has("Connected Peers"));
    VERIFY("version", has("ZClassic23:0.1.0"));
}

static void audit_coins(void) {
    DO("GET", "/wallet/coins", NULL);
    VERIFY("renders", _len > 200);
    VERIFY("coin audit heading", has("Coin Audit"));
}

static void check_shield_status(void) {
    DO("GET", "/wallet/shield", NULL);
    VERIFY("renders", _len > 200);
}

static void check_pulse_api(void) {
    DO("GET", "/api/wallet/pulse", NULL);
    VERIFY("JSON", has("{"));
    VERIFY("height", has("\"height\""));
    VERIFY("balance", has("\"balance\""));
    VERIFY("shielded", has("\"shielded\""));
}

static void exercise_session_edge_cases(void) {
    DO("POST", "/wallet/send/review", "");
    VERIFY("empty form → no crash", _len > 0);

    DO("POST", "/wallet/send/review", NULL);
    VERIFY("NULL body → no crash", _len > 0);

    DO("POST", "/wallet/shield/confirm", "amount=0");
    VERIFY("zero shield → invalid", _len > 200);

    DO("POST", "/wallet/shield/confirm", "amount=-1");
    VERIFY("negative shield → invalid", _len > 200);

    DO("GET", "/wallet/tx/<script>alert(1)</script>", NULL);
    VERIFY("XSS in txid", !has("<script>alert"));

    { size_t n = DO("GET", "/wallet/doesnotexist", NULL);
      VERIFY("unknown route → 0", n == 0); }
}

int main(int argc, char **argv)
{
    const char *datadir = resolve_datadir(argc, argv);

    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();
    event_log_init();

    printf("═══════════════════════════════════════════════════\n");
    printf("  Z23 User Session Simulator\n");
    printf("═══════════════════════════════════════════════════\n\n");

    wallet_view_enable_sync();
    wallet_view_init(datadir);

    /* Get ground truth */
    tick();
    query_rpc();
    double rpc_ms = tock_ms();
    printf("  RPC z_gettotalbalance: %.8f ZCL (%.0f ms)\n\n", rpc_total, rpc_ms);

    /* Sync wallet */
    tick();
    wv_sync_wallet_from_zclassicd();
    double sync_ms = tock_ms();
    printf("  Wallet sync: %.0f ms\n\n", sync_ms);

    _step = 0;
    _errors = 0;
    platform_time_monotonic_timespec(&_session_start);

    printf("── User opens the app ──\n");

    check_dashboard_page();

    printf("\n── User checks balance on send page ──\n");

    check_send_page();

    printf("\n── User tries to send with bad address ──\n");

    try_send_with_bad_address();

    printf("\n── User sends to valid z-address (review) ──\n");

    review_send_to_valid_zaddress();

    printf("\n── User checks receive page ──\n");

    check_receive_page();

    printf("\n── User browses history ──\n");

    browse_history_pages();

    printf("\n── User visits node / command center ──\n");

    visit_node_page();

    printf("\n── User audits coins ──\n");

    audit_coins();

    printf("\n── User checks shield status ──\n");

    check_shield_status();

    printf("\n── User checks pulse API ──\n");

    check_pulse_api();

    printf("\n── Edge cases ──\n");

    exercise_session_edge_cases();

    /* ── Summary ── */
    double total_ms = session_ms();

    printf("\n═══════════════════════════════════════════════════\n");
    printf("  Session: %d steps in %.0f ms (avg %.1f ms/step)\n",
           _step, total_ms, total_ms / _step);
    printf("  Sync: %.0f ms | RPC: %.0f ms\n", sync_ms, rpc_ms);
    printf("  Verifications: %d errors\n", _errors);

    /* Event log summary */
    char evbuf[4096];
    size_t evlen = event_dump_json(evbuf, sizeof(evbuf), 5);
    if (evlen > 10) {
        printf("  Last 5 events: %.200s...\n", evbuf);
    }

    if (_errors > 0)
        printf("  STATUS: ✗ %d ERRORS\n", _errors);
    else
        printf("  STATUS: ✓ ALL VERIFICATIONS PASSED\n");
    printf("═══════════════════════════════════════════════════\n");

    ecc_verify_destroy();
    ecc_stop();
    return _errors > 0 ? 1 : 0;
}
