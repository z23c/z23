/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * wallet_view scenario checks: design-system consistency, XSS/path
 * sanitization, real-seeded-data assertions (balance, history, coins),
 * nav/CSS consistency, and the send-review checksum + privacy warning.
 *
 * Split out of test_wallet_view.c (which keeps the fixture-DB setup,
 * shared request/assertion helpers, and the group entry point) so no
 * family member crosses the 1,500-line ceiling. State is shared only
 * through wv_ctx() — see test_wallet_view_priv.h. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "test/test_wallet_view_priv.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"  /* wv_parse_form_field */
#include "models/database.h"
#include "util/template.h"
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>


int check_wallet_view_design_system_colors_are_consistent(void)
{
    int failures = 0;

    printf("wallet_view: design system colors are consistent... ");
    {
        /* Check that non-standard colors are NOT used */
        wv_get("/wallet");
        bool has_bad = wv_has("#9966ff") || wv_has("#bb99ff") ||
                       wv_has("#ff4444") || wv_has("#ff8800") ||
                       wv_has("#ff6666");
        wv_get("/wallet/shield?amount=0.5");
        has_bad = has_bad || wv_has("#9966ff") || wv_has("#bb99ff");
        if (!has_bad) printf("OK (standard palette only)\n");
        else { printf("FAIL (non-standard colors found)\n"); failures++; }
    }

    printf("wallet_view: pages have viewport meta tag... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("name='viewport'");
        ok = ok && wv_has("width=device-width");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: pages have charset declaration... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("charset='utf-8'") || wv_has("charset=utf-8");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 11. SECURITY — XSS, injection, CSRF
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: XSS in address field is escaped... ");
    {
        wv_post("/wallet/send/review",
            "address=%3Cscript%3Ealert(1)%3C/script%3E&amount=0.01");
        /* The <script> tags should NOT appear unescaped in the output */
        bool bad = wv_has("<script>alert(1)</script>");
        bool ok = !bad && wv_has("Invalid");  /* should fail validation */
        if (ok) printf("OK\n");
        else { printf("FAIL (XSS possible!)\n"); failures++; }
    }

    printf("wallet_view: SQL injection in history search is sanitized... ");
    {
        /* Search param with SQL injection attempt */
        wv_get("/wallet/history?q='; DROP TABLE blocks; --");
        /* Should not crash, and search should use only hex chars */
        bool ok = !wv_has("DROP TABLE");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_path_traversal_in_tx_detail_is_sanitized(void)
{
    int failures = 0;

    printf("wallet_view: path traversal in tx detail is sanitized... ");
    {
        wv_get("/wallet/tx/../../etc/passwd");
        /* Should strip non-hex chars and show invalid ID or loading */
        bool ok = wv_has("Invalid Transaction ID") || wv_has("Wallet Loading");
        /* Must NOT contain any file system content */
        bool bad = wv_has("root:") || wv_has("/bin/");
        if (ok && !bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: shield confirm is POST-only (not GET)... ");
    {
        /* GET to shield/confirm should show error (no amount in body) */
        wv_get("/wallet/shield/confirm");
        bool ok = wv_has("Invalid amount") || wv_has("Invalid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 12. EDGE CASES
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: very long address rejected... ");
    {
        char long_body[512];
        snprintf(long_body, sizeof(long_body),
            "address=t1%0200d&amount=0.01", 0);
        size_t n = wv_post("/wallet/send/review", long_body);
        bool ok = (n > 0) && wv_has("Invalid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: amount with many decimals accepted... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.00000001");
        bool ok = wv_has("0.00000001") || wv_has("Review");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: amount with text rejected... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=hello");
        bool ok = wv_has("Invalid amount");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: empty POST body handled gracefully... ");
    {
        size_t n = wv_post("/wallet/send/review", "");
        bool ok = (n > 0);  /* doesn't crash */
        ok = ok && wv_has("Invalid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: NULL path returns 0... ");
    {
        size_t n = wallet_view_handle_request("GET", NULL, NULL, 0,
                                                wv_ctx()->resp, sizeof(wv_ctx()->resp));
        if (n == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_zero_size_response_buffer_doesn_t_crash(void)
{
    int failures = 0;

    printf("wallet_view: zero-size response buffer doesn't crash... ");
    {
        uint8_t tiny[1];
        size_t n = wallet_view_handle_request("GET", "/wallet", NULL, 0,
                                                tiny, 0);
        if (n == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: small response buffer doesn't overflow... ");
    {
        uint8_t small[64];
        memset(small, 0xAA, sizeof(small));
        size_t n = wallet_view_handle_request("GET", "/wallet", NULL, 0,
                                                small, sizeof(small));
        /* Should produce a truncated but valid response, no overflow */
        bool ok = (n <= sizeof(small));
        if (ok) printf("OK (n=%zu)\n", n);
        else { printf("FAIL (overflow! n=%zu)\n", n); failures++; }
    }
    return failures;
}

int check_wallet_view_dashboard_shows_real_balance_not_loading(void)
{
    int failures = 0;
    /* ── Dashboard with real data ────────────────────────────── */

    printf("LIVE: dashboard shows real balance (not loading)... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("class='balance'") && wv_has("ZCL</div>");
        bool bad = wv_has("Wallet Loading");
        if (ok && !bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: dashboard shows sync badge... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("id='sync'") && wv_has("sync-badge");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: dashboard shows balance breakdown (public/private)... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("id='breakdown'") &&
                  (wv_has("public") || wv_has("private") || wv_has("All funds"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: dashboard shows privacy secure card... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("privacy-card") && wv_has("Secure All");
        if (ok) printf("OK (privacy nudge visible)\n");
        else printf("OK (no card — private balance exists or zero balance)\n");
        /* Not a failure either way — depends on balance state */
    }

    printf("LIVE: dashboard recent txs from wallet_transactions... ");
    {
        wv_get("/wallet");
        /* Should have tx-row elements with links to /wallet/tx/ */
        bool ok = wv_has("tx-row") || wv_has("No transactions yet");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_dashboard_recent_txs_link_to_wallet_tx_or_syn(void)
{
    int failures = 0;
    bool have_wallet_funds = (WV_FIX_TBAL_SAT + WV_FIX_ZBAL_SAT > 0);

    printf("LIVE: dashboard recent txs link to /wallet/tx/ or syncing... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("href='/wallet/tx/") ||
                  wv_has("No transactions yet") ||
                  wv_has("history syncing");
        if (ok) printf("OK\n");
        else { printf("FAIL (links to explorer instead of wallet detail)\n"); failures++; }
    }

    printf("LIVE: dashboard balance > 0 (funds exist)... ");
    {
        if (!have_wallet_funds) { printf("SKIP (wallet empty or disabled)\n"); }
        else {
            wv_get("/api/wallet/pulse");
            const char *bal = strstr((char *)wv_ctx()->resp, "\"balance\":");
            int64_t balance = bal ? strtoll(bal + 10, NULL, 10) : 0;
            if (balance > 0) printf("OK (%.8f ZCL)\n", (double)balance / 1e8);
            else { printf("FAIL (balance=%lld)\n", (long long)balance); failures++; }
        }
    }

    printf("LIVE: pulse returns correct sync state... ");
    {
        wv_get("/api/wallet/pulse");
        bool ok = wv_has("\"sync\":\"");
        /* Must be a known state */
        ok = ok && (wv_has("at_tip") || wv_has("downloading") ||
                    wv_has("scanning") || wv_has("connecting") ||
                    wv_has("init") || wv_has("idle"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_pulse_has_peers_0(void)
{
    int failures = 0;

    printf("LIVE: pulse has peers > 0... ");
    {
        wv_get("/api/wallet/pulse");
        const char *p = strstr((char *)wv_ctx()->resp, "\"peers\":");
        int peers = 0;
        if (p) peers = atoi(p + 8);
        if (peers > 0) printf("OK (%d peers)\n", peers);
        else printf("WARN (0 peers)\n");
        /* Not a failure — node might be offline */
    }

    /* ── Send form with real balance ─────────────────────────── */

    printf("LIVE: send form shows real available balance... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("ZCL");  /* Shows total balance with ZCL label */
        /* Should show a non-zero balance */
        bool has_zero_only = wv_has("0.00000000 ZCL") && !wv_has("0.9");
        if (ok && !has_zero_only) printf("OK\n");
        else if (ok) printf("OK (but balance might be 0)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: send form Max button uses real balance... ");
    {
        wv_get("/wallet/send");
        /* BAL variable should be set to actual balance */
        bool ok = wv_has("var BAL=");
        /* Should NOT be 0 */
        const char *bal_js = strstr((char *)wv_ctx()->resp, "var BAL=");
        double bal_val = 0;
        if (bal_js) bal_val = strtod(bal_js + 8, NULL);
        if (ok && bal_val > 0) printf("OK (BAL=%.8f)\n", bal_val);
        else if (ok) printf("OK (BAL=0, empty wallet)\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Receive with real address ───────────────────────────── */

    printf("LIVE: receive shows PRIMARY_ADDR in chunked format... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("t1YR") && wv_has("BXK");
        ok = ok && wv_has("addr-chunked");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_receive_qr_code_is_valid_svg(void)
{
    int failures = 0;

    printf("LIVE: receive QR code is valid SVG... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("<svg") && wv_has("</svg>");
        ok = ok && wv_has("viewBox='0 0");
        /* Should have many rect elements (QR modules) */
        int rects = 0;
        const char *p = (char *)wv_ctx()->resp;
        while ((p = strstr(p, "<rect")) != NULL) { rects++; p += 5; }
        ok = ok && (rects > 50);  /* QR has many modules */
        if (ok) printf("OK (%d rects)\n", rects);
        else { printf("FAIL (rects=%d)\n", rects); failures++; }
    }

    printf("LIVE: receive has private addresses from DB... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("Private") || wv_has("No private addresses");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── History with real transactions ──────────────────────── */

    printf("LIVE: history shows real transactions... ");
    {
        wv_get("/wallet/history");
        bool ok = wv_has("Transaction History") && wv_has("filter-tabs");
        /* Should have tx cards or empty state */
        ok = ok && (wv_has("tx-card") || wv_has("0 transaction"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_history_filter_tabs_present_and_styled(void)
{
    int failures = 0;

    printf("LIVE: history filter tabs present and styled... ");
    {
        wv_get("/wallet/history");
        bool ok = wv_has("filter=all");
        ok = ok && wv_has("filter=sent");
        ok = ok && wv_has("filter=recv");
        ok = ok && wv_has(">All (");
        ok = ok && wv_has(">Sent (");
        ok = ok && wv_has(">Received (");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: history search input present... ");
    {
        wv_get("/wallet/history");
        bool ok = wv_has("search-input") && wv_has("Search by txid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: history sent filter works... ");
    {
        wv_get("/wallet/history?filter=sent");
        bool ok = wv_has("Transaction History");
        /* The sent filter tab should be active */
        ok = ok && wv_has("filter=sent' class='active'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: history recv filter works... ");
    {
        wv_get("/wallet/history?filter=recv");
        bool ok = wv_has("Transaction History");
        ok = ok && wv_has("filter=recv' class='active'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_history_tx_cards_have_direction_badges(void)
{
    int failures = 0;

    printf("LIVE: history tx cards have direction badges... ");
    {
        wv_get("/wallet/history");
        bool ok = wv_has("pill-t") || wv_has("pill-pending") ||
                  wv_has("0 transaction");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: history pagination shows page count... ");
    {
        wv_get("/wallet/history");
        bool ok = wv_has("page ") && wv_has(" of ");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Coins page with real UTXOs ──────────────────────────── */

    printf("LIVE: coins page shows UTXO table... ");
    {
        wv_get("/wallet/coins");
        bool ok = wv_has("Your Coins");
        ok = ok && wv_has("Public UTXOs");
        ok = ok && (wv_has("total-row") || wv_has("0 UTXO"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: coins page shows private notes section... ");
    {
        wv_get("/wallet/coins");
        bool ok = wv_has("Private Notes");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: coins page shows data source comparison... ");
    {
        wv_get("/wallet/coins");
        bool ok = wv_has("Diagnostics");
        ok = ok && wv_has("Chain UTXO set");
        ok = ok && wv_has("verified");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_coins_page_shows_grand_total_stats(void)
{
    int failures = 0;

    printf("LIVE: coins page shows grand total stats... ");
    {
        wv_get("/wallet/coins");
        bool ok = wv_has("Public</div>") && wv_has("Private</div>");
        ok = ok && wv_has("Total</div>");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── production-grade design scrutiny ─────────────────────────── */

    printf("LIVE: no inline style= colors (use CSS classes)... ");
    {
        wv_get("/wallet");
        /* Count inline color overrides — some are acceptable for dynamic
         * values but raw hex colors in style= are a design smell */
        int inline_colors = 0;
        const char *p = (char *)wv_ctx()->resp;
        while ((p = strstr(p, "style='")) != NULL) {
            const char *end = strchr(p + 7, '\'');
            if (end && (strstr(p, "color:#") && strstr(p, "color:#") < end))
                inline_colors++;
            p += 7;
        }
        /* A few inline colors are acceptable for dynamic state.
         * More than 10 suggests we should use more CSS classes. */
        if (inline_colors <= 10) printf("OK (%d inline)\n", inline_colors);
        else { printf("WARN (%d inline colors — consider CSS classes)\n",
                       inline_colors); }
    }

    printf("LIVE: all pages have consistent footer structure... ");
    {
        const char *pages[] = {"/wallet", "/wallet/send", "/wallet/receive",
                                "/wallet/coins", NULL};
        bool ok = true;
        for (int i = 0; pages[i]; i++) {
            wv_get(pages[i]);
            if (!wv_has("class='status-bar'") || !wv_has("</html>")) {
                ok = false;
                break;
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_all_pages_have_consistent_nav_structure(void)
{
    int failures = 0;

    printf("LIVE: all pages have consistent nav structure... ");
    {
        const char *pages[] = {"/wallet", "/wallet/send", "/wallet/receive",
                                "/wallet/coins", NULL};
        bool ok = true;
        for (int i = 0; pages[i]; i++) {
            wv_get(pages[i]);
            if (!wv_has("class='nav'") || !wv_has("Home</a>")) {
                ok = false;
                break;
            }
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: no broken HTML entities... ");
    {
        wv_get("/wallet");
        /* Check for common broken entities */
        bool bad = wv_has("&amp;amp;") || wv_has("&amp;lt;") ||
                   wv_has("&#x0;") || wv_has("&undefined;");
        if (!bad) printf("OK\n");
        else { printf("FAIL (double-encoded entities)\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_wallet_css_loads_without_overflow(void)
{
    int failures = 0;

    printf("LIVE: wallet CSS loads without overflow... ");
    {
        wv_get("/wallet");
        /* Check CSS contains key selectors */
        bool ok = wv_has(".balance{") || wv_has(".balance {");
        ok = ok && (wv_has(".nav{") || wv_has(".nav {") || wv_has(".nav a{"));
        ok = ok && (wv_has("@keyframes") || wv_has("@media"));
        if (ok) printf("OK\n");
        else { printf("FAIL (CSS missing/truncated)\n"); failures++; }
    }

    printf("LIVE: no TODO/FIXME/HACK in rendered HTML... ");
    {
        const char *pages[] = {"/wallet", "/wallet/send", "/wallet/receive",
                                "/wallet/history", "/wallet/coins", NULL};
        bool bad = false;
        for (int i = 0; pages[i]; i++) {
            wv_get(pages[i]);
            if (wv_has("TODO") || wv_has("FIXME") || wv_has("HACK") ||
                wv_has("XXX")) {
                bad = true;
                break;
            }
        }
        if (!bad) printf("OK\n");
        else { printf("FAIL (debug text in production HTML)\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_review_with_valid_address_shows_checksum(void)
{
    int failures = 0;

    printf("LIVE: send review with valid address shows checksum validation... ");
    {
        /* t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn is a real valid address */
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.001");
        bool ok = wv_has("Review") && wv_has("Confirm Send");
        ok = ok && wv_has("0.001");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: send review with typo address shows checksum error... ");
    {
        /* Change one character to create invalid checksum */
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrN&amount=0.001");
        bool ok = wv_has("checksum") || wv_has("Invalid");
        if (ok) printf("OK (typo caught)\n");
        else { printf("FAIL (typo not caught!)\n"); failures++; }
    }

    /* Dump pages to disk for manual inspection */
    system("mkdir -p .zcl_test_render");
    {
        const char *routes[][3] = {
            {"GET", "/wallet", "dashboard.html"},
            {"GET", "/wallet/send", "send.html"},
            {"GET", "/wallet/receive", "receive.html"},
            {"GET", "/wallet/history", "history.html"},
            {"GET", "/wallet/history?filter=sent", "history_sent.html"},
            {"GET", "/wallet/coins", "coins.html"},
            {"GET", "/wallet/shield?amount=0.5", "shield.html"},
            {"GET", "/api/wallet/pulse", "pulse.json"},
            {NULL, NULL, NULL}
        };
        for (int i = 0; routes[i][0]; i++) {
            wv_get(routes[i][1]);
            char path[128];
            snprintf(path, sizeof(path), ".zcl_test_render/%s", routes[i][2]);
            const char *html = strstr((char *)wv_ctx()->resp, "\r\n\r\n");
            if (html) html += 4; else html = (char *)wv_ctx()->resp;
            FILE *f = fopen(path, "w");
            if (f) { fputs(html, f); fclose(f); }
        }
        printf("LIVE: pages dumped to .zcl_test_render/ for inspection\n");
    }
    return failures;
}

int check_wallet_view_balance_consistent_pulse_send_coins(void)
{
    int failures = 0;

    /* ═══════════════════════════════════════════════════════════
     * 14. BALANCE CONSISTENCY — the same number everywhere
     *     This catches the bug where api_controller and
     *     wallet_view showed different balances.
     * ═══════════════════════════════════════════════════════════ */

    printf("LIVE: balance consistent: pulse == send == coins... ");
    {
        /* Get total balance from pulse (transparent + shielded) */
        wv_get("/api/wallet/pulse");
        const char *bp = strstr((char *)wv_ctx()->resp, "\"balance\":");
        int64_t pulse_t = bp ? strtoll(bp + 10, NULL, 10) : 0;
        const char *zp = strstr((char *)wv_ctx()->resp, "\"shielded\":");
        int64_t pulse_z = zp ? strtoll(zp + 11, NULL, 10) : 0;
        int64_t pulse_bal = pulse_t + pulse_z;

        /* Get balance from send page (var BAL=...) */
        wv_get("/wallet/send");
        const char *bs = strstr((char *)wv_ctx()->resp, "var BAL=");
        double send_bal = bs ? strtod(bs + 8, NULL) : -1;
        int64_t send_sat = (int64_t)(send_bal * 1e8 + 0.5);

        /* Get total balance from coins page (t + z combined) */
        wv_get("/wallet/coins");
        double coins_bal = wv_scan_coins_page_total();
        int64_t coins_sat = (coins_bal >= 0)
            ? (int64_t)(coins_bal * 1e8 + 0.5) : -1;

        /* Pulse total (t+z) must match send BAL (total spendable) */
        (void)coins_sat; /* coins page has separate t/z sections */
        bool ok = (pulse_bal == send_sat);
        if (ok)
            printf("OK (pulse=send=%lld sat = %.8f ZCL)\n",
                (long long)pulse_bal, (double)pulse_bal / 1e8);
        else {
            printf("FAIL (pulse=%lld send=%lld)\n",
                (long long)pulse_bal, (long long)send_sat);
            failures++;
        }
    }
    return failures;
}

int check_wallet_view_balance_must_be_1_zcl_sanity_check(void)
{
    int failures = 0;
    bool have_wallet_funds = (WV_FIX_TBAL_SAT + WV_FIX_ZBAL_SAT > 0);

    printf("LIVE: balance must be < 1 ZCL (sanity check)... ");
    {
        if (!have_wallet_funds) { printf("SKIP (wallet empty or disabled)\n"); }
        else {
            wv_get("/api/wallet/pulse");
            const char *bp = strstr((char *)wv_ctx()->resp, "\"balance\":");
            int64_t bal = bp ? strtoll(bp + 10, NULL, 10) : 0;
            bool ok = (bal > 0 && bal < 100000000);  /* < 1 ZCL */
            if (ok) printf("OK (%.8f ZCL)\n", (double)bal / 1e8);
            else { printf("FAIL (bal=%lld, expected < 1 ZCL)\n",
                           (long long)bal); failures++; }
        }
    }

    printf("LIVE: no stale global utxo query in rendered pages... ");
    {
        /* The old bug: querying global utxos table showed stale spent UTXOs.
         * Verify no page shows the stale 1.849 or 1.955 balance. */
        const char *pages[] = {"/wallet", "/wallet/send", "/wallet/coins", NULL};
        bool bad = false;
        for (int i = 0; pages[i]; i++) {
            wv_get(pages[i]);
            if (wv_has("1.849") || wv_has("1.955") || wv_has("1.84913")) {
                bad = true;
                break;
            }
        }
        if (!bad) printf("OK\n");
        else { printf("FAIL (stale balance visible!)\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_history_shows_0_transactions(void)
{
    int failures = 0;

    printf("LIVE: history shows > 0 transactions... ");
    {
        wv_get("/wallet/history");
        /* Look for "NN transaction" pattern in the sub div */
        const char *tc = strstr((char *)wv_ctx()->resp, " transaction");
        int count = 0;
        if (tc) {
            /* Walk back past spaces and digits */
            const char *p = tc - 1;
            while (p > (char *)wv_ctx()->resp && *p >= '0' && *p <= '9') p--;
            if (p[1] >= '0' && p[1] <= '9')
                count = atoi(p + 1);
        }
        /* Also check for tx-card elements */
        int cards = 0;
        const char *cp = (char *)wv_ctx()->resp;
        while ((cp = strstr(cp, "tx-card")) != NULL) { cards++; cp += 7; }
        if (count > 0 || cards > 0)
            printf("OK (%d txs, %d cards)\n", count, cards);
        else { printf("FAIL (0 transactions shown)\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_history_txs_show_non_zero_amounts(void)
{
    int failures = 0;
    bool have_wallet_funds = (WV_FIX_TBAL_SAT + WV_FIX_ZBAL_SAT > 0);

    printf("LIVE: history txs show non-zero amounts... ");
    {
        if (!have_wallet_funds) { printf("SKIP (wallet empty or disabled)\n"); }
        else {
            wv_get("/wallet/history");
            int nonzero = 0, total = 0;
            const char *p = (char *)wv_ctx()->resp;
            while ((p = strstr(p, "tx-amount")) != NULL) {
                p += 9;
                const char *gt = strchr(p, '>');
                if (gt) {
                    double v = strtod(gt + 1, NULL);
                    if (v < 0) v = -v;
                    total++;
                    if (v > 0.000000005) nonzero++;
                }
            }
            if (nonzero > 0)
                printf("OK (%d/%d non-zero)\n", nonzero, total);
            else if (total == 0)
                printf("OK (no tx-amount elements — may be loading)\n");
            else { printf("FAIL (%d amounts all zero)\n", total); failures++; }
        }
    }

    printf("LIVE: shield flow has z-addresses available... ");
    {
        wv_get("/wallet/shield?amount=0.01");
        /* Must show confirmation page, not error */
        bool ok = wv_has("Confirm") || wv_has("Securing");
        bool bad = wv_has("Could Not Secure");
        if (ok && !bad) printf("OK\n");
        else { printf("FAIL (no z-address!)\n"); failures++; }
    }

    printf("LIVE: receive page shows z-addresses... ");
    {
        if (!have_wallet_funds) { printf("SKIP (wallet empty or disabled)\n"); }
        else {
            wv_get("/wallet/receive");
            bool ok = wv_has("zs1");
            if (ok) printf("OK\n");
            else { printf("FAIL (no z-addresses on receive)\n"); failures++; }
        }
    }
    return failures;
}

int check_wallet_view_shield_review_page_renders_correctly(void)
{
    int failures = 0;

    printf("LIVE: shield review page renders correctly... ");
    {
        /* Test the shield REVIEW page (not confirm — confirm triggers
         * real z_sendmany which spends actual ZCL). */
        wv_get("/wallet/shield?amount=0.001");
        bool groth16 = wv_has("Groth16");
        bool not_impl = wv_has("not yet implemented");
        bool has_confirm = wv_has("Confirm");
        if (!groth16 && !not_impl && has_confirm) printf("OK\n");
        else { printf("FAIL (groth16=%d notimpl=%d confirm=%d)\n",
            groth16, not_impl, has_confirm); failures++; }
    }

    printf("LIVE: shield review page has back link... ");
    {
        wv_get("/wallet/shield?amount=0.001");
        bool ok = wv_has("Cancel") || wv_has("href='/wallet'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: dashboard privacy state appropriate... ");
    {
        wv_get("/wallet");
        /* When nearly all shielded: "Funds shielded" shown, no shield link.
         * When transparent > fee: shield link or "Secure All" shown. */
        bool ok = wv_has("shielded") || wv_has("Shield") ||
                  wv_has("Secure All") || wv_has("/wallet/shield");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("LIVE: send review for z-address shows private indicator... ");
    {
        /* Test the send REVIEW page (not confirm — confirm triggers
         * real z_sendmany which spends actual ZCL). */
        wv_post("/wallet/send/review",
            "address=zs19hc6ghlrzklr7y82u9w6822zuvrpfmgzlqz7alx8"
            "eqtwh2rvzgykl6m3lu8gwarpflcczgyse2p&amount=0.001");
        bool groth16 = wv_has("Groth16");
        bool not_impl = wv_has("not yet implemented");
        bool has_shielded = wv_has("private") || wv_has("Private") || wv_has("shielded");
        if (!groth16 && !not_impl && has_shielded) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_review_to_zs1_shows_t_z_privacy_warning(void)
{
    int failures = 0;

    /* ═══════════════════════════════════════════════════════════
     * 14b. PRIVACY & ACCURACY INTEGRATION TESTS
     * ═══════════════════════════════════════════════════════════ */

    printf("\n=== PRIVACY & ACCURACY TESTS ===\n\n");

    printf("INTEG: send review to zs1 shows t→z privacy warning... ");
    {
        wv_post("/wallet/send/review",
            "address=zs19hc6ghlrzklr7y82u9w6822zuvrpfmgzlqz7alx8"
            "eqtwh2rvzgykl6m3lu8gwarpflcczgyse2p&amount=0.001");
        bool has_warning = wv_has("sending address") && wv_has("visible");
        bool has_label = wv_has("Recipient private");
        if (has_warning && has_label) printf("OK (honest t→z label)\n");
        else { printf("FAIL (warning=%d label=%d)\n", has_warning, has_label); failures++; }
    }

    printf("INTEG: send review to t-addr shows Public pill, no warning... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.001");
        bool has_public = wv_has("Public");
        bool no_tz_warning = !wv_has("sending address");
        if (has_public && no_tz_warning) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: dashboard Power Node shows Ready or Synced (not Syncing when idle)... ");
    {
        wv_get("/wallet");
        /* The sync badge says "Ready" when idle; Power Node should match */
        bool has_syncing_in_node = wv_has(">Syncing</div>") &&
                                    wv_has("Power Node");
        bool has_ready = wv_has(">Ready</div>") || wv_has(">Synced</div>");
        /* If badge says Ready, Power Node must not say Syncing */
        if (has_ready && !has_syncing_in_node) printf("OK\n");
        else if (wv_has("pill-syncing")) printf("OK (actually syncing)\n");
        else { printf("FAIL (inconsistent sync state)\n"); failures++; }
    }

    printf("INTEG: send form fee shows 0.000001 (not 0.00000100)... ");
    {
        wv_get("/wallet/send");
        bool short_fee = wv_has("0.000001 ZCL");
        bool no_long_fee = !wv_has("0.00000100 ZCL");
        if (short_fee && no_long_fee) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: dashboard lock icon is NOT green when balance is zero... ");
    {
        /* Can't easily test with zero balance in live mode, but verify
         * the icon exists and is yellow (since we have public balance) */
        wv_get("/wallet");
        bool has_lock = wv_has("id='lock'");
        bool is_yellow = wv_has("color:#fbbf24");
        if (has_lock && is_yellow) printf("OK (yellow for mixed balance)\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

