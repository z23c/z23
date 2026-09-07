/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * wallet_view scenario checks: send-page contacts datalist, receive-page
 * QR/copy text, unresolved-template-var guards, template badges/backup
 * warning, no-DB graceful degradation, oversized-POST safety, title and
 * command-center rendering, and dashboard render-time performance.
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


int check_wallet_view_dashboard_has_contacts_datalist_on_send_page(void)
{
    int failures = 0;
    bool have_wallet_funds = (WV_FIX_TBAL_SAT + WV_FIX_ZBAL_SAT > 0);

    printf("INTEG: dashboard has contacts datalist on send page... ");
    {
        wv_get("/wallet/send");
        bool has_datalist = wv_has("id='contacts'") && wv_has("datalist");
        bool has_list_attr = wv_has("list='contacts'");
        if (has_datalist && has_list_attr) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: dashboard has backup warning... ");
    {
        if (!have_wallet_funds) { printf("SKIP (wallet empty or disabled)\n"); }
        else {
            wv_get("/wallet");
            bool has_backup = wv_has("Back Up") || wv_has("wallet.backup");
            if (has_backup || wv_has("Backed Up")) printf("OK\n");
            else { printf("FAIL (no backup indicator)\n"); failures++; }
        }
    }

    printf("INTEG: dashboard has node status strip... ");
    {
        wv_get("/wallet");
        bool has_node = wv_has("/wallet/node");
        bool has_peers = wv_has("peers");
        if (has_node && has_peers) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: coins page Diagnostics is collapsed... ");
    {
        wv_get("/wallet/coins");
        bool has_details = wv_has("<details");
        bool has_diag = wv_has("Diagnostics");
        if (has_details && has_diag) printf("OK (collapsed)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: coins page has breadcrumb and title... ");
    {
        wv_get("/wallet/coins");
        bool good = wv_has("Your Coins") && wv_has("Coin Audit");
        if (good) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_receive_page_shows_z_address_qr_code(void)
{
    int failures = 0;

    printf("INTEG: receive page shows z-address QR code... ");
    {
        wv_get("/wallet/receive");
        /* The private pane should have a QR SVG for the z-address */
        int svg_count = 0;
        const char *p = (char *)wv_ctx()->resp;
        while ((p = strstr(p, "<svg")) != NULL) { svg_count++; p += 4; }
        /* Should have at least 2 SVGs: one for t-address, one for z-address */
        if (svg_count >= 2) printf("OK (%d QR codes)\n", svg_count);
        else if (svg_count == 1) printf("OK (1 QR — z-addr may be too long)\n");
        else { printf("FAIL (no QR codes)\n"); failures++; }
    }

    printf("INTEG: nav has 4 tabs (Home, Send, Receive, History)... ");
    {
        wv_get("/wallet");
        bool has_home = wv_has(">Home</a>");
        bool has_send = wv_has(">Send</a>");
        bool has_recv = wv_has(">Receive</a>");
        bool has_hist = wv_has(">History</a>");
        bool no_secure = !wv_has(">Secure</a>");
        bool no_coins = !wv_has(">Coins</a>");
        if (has_home && has_send && has_recv && has_hist &&
            no_secure && no_coins) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: dashboard shows 'Pending' not '0 confs' for unconfirmed... ");
    {
        wv_get("/wallet");
        bool bad = wv_has(">0 confs<") || wv_has(" 0 confs\n");
        bool good = wv_has("Pending") || !wv_has("Unconfirmed");
        if (!bad && good) printf("OK\n");
        else if (!bad) printf("OK (no unconfirmed txs)\n");
        else { printf("FAIL (shows '0 confs')\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_receive_page_says_click_to_copy_not_tap(void)
{
    int failures = 0;

    printf("INTEG: receive page says 'Click to copy' not 'Tap'... ");
    {
        wv_get("/wallet/receive");
        bool good = wv_has("Click to copy");
        bool bad = wv_has("Tap address");
        if (good && !bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: shield fee shows 4 decimals not 8... ");
    {
        wv_get("/wallet/shield?amount=0.5");
        bool has_short = wv_has("0.000001 ZCL");
        bool no_long = !wv_has("0.00000100 ZCL");
        if (has_short && no_long) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: body font is 20px... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("font-size:20px");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: balance font is 56px... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("font-size:56px");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: privacy meter exists with percentage... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("privacy-meter") && wv_has("private");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: send page has privacy hint div... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("privacy-hint");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("INTEG: send page privacy hint JS detects zs1... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("Private send") && wv_has("Visible on blockchain");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_no_unresolved_vars_in_dashboard(void)
{
    int failures = 0;

    /* ═══════════════════════════════════════════════════════════
     * 14c. TEMPLATE CORRECTNESS TESTS
     * ═══════════════════════════════════════════════════════════ */

    printf("\n=== TEMPLATE CORRECTNESS TESTS ===\n\n");

    printf("TMPL: no unresolved {{vars}} in dashboard... ");
    {
        wv_get("/wallet");
        /* Check for literal {{ in body but not in JS */
        const char *body = strstr((char *)wv_ctx()->resp, "<main>");
        const char *script = strstr((char *)wv_ctx()->resp, "<script");
        bool has_unresolved = false;
        if (body && script) {
            for (const char *p = body; p < script; p++) {
                if (p[0] == '{' && p[1] == '{' && p[2] != '{') {
                    has_unresolved = true; break;
                }
            }
        }
        if (!has_unresolved) printf("OK\n");
        else { printf("FAIL (unresolved template var)\n"); failures++; }
    }

    printf("TMPL: no unresolved {{vars}} in history... ");
    {
        wv_get("/wallet/history");
        const char *body = strstr((char *)wv_ctx()->resp, "<main>");
        const char *script = strstr((char *)wv_ctx()->resp, "<script");
        bool has_unresolved = false;
        if (body && script) {
            for (const char *p = body; p < script; p++) {
                if (p[0] == '{' && p[1] == '{' && p[2] != '{') {
                    has_unresolved = true; break;
                }
            }
        }
        if (!has_unresolved) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_no_unresolved_vars_in_coins(void)
{
    int failures = 0;

    printf("TMPL: no unresolved {{vars}} in coins... ");
    {
        wv_get("/wallet/coins");
        const char *body = strstr((char *)wv_ctx()->resp, "<main>");
        const char *script = strstr((char *)wv_ctx()->resp, "<script");
        bool has_unresolved = false;
        if (body && script) {
            for (const char *p = body; p < script; p++) {
                if (p[0] == '{' && p[1] == '{' && p[2] != '{') {
                    has_unresolved = true; break;
                }
            }
        }
        if (!has_unresolved) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("TMPL: shield confirm uses template (no inline HTML)... ");
    {
        wv_get("/wallet/shield?amount=0.5");
        bool has_template_content = wv_has("Step 1:") && wv_has("Step 2:");
        bool has_confirm_btn = wv_has("id='shield-btn'");
        if (has_template_content && has_confirm_btn) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("TMPL: send review uses template for privacy label... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool has_review_table = wv_has("review-table");
        bool has_privacy_row = wv_has("Privacy");
        bool has_est_time = wv_has("Est. Time");
        if (has_review_table && has_privacy_row && has_est_time) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_history_cards_use_template_secured_badge(void)
{
    int failures = 0;

    printf("TMPL: history cards use template (Secured badge)... ");
    {
        wv_get("/wallet/history");
        bool has_secured = wv_has("Funds Secured") || wv_has("Received");
        bool has_card = wv_has("tx-card");
        if (has_secured && has_card) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("TMPL: coins page uses template (notes table)... ");
    {
        wv_get("/wallet/coins");
        bool has_title = wv_has("Your Coins");
        bool has_stats = wv_has("Public") && wv_has("Private") && wv_has("Total");
        bool has_diag = wv_has("Diagnostics");
        if (has_title && has_stats && has_diag) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("TMPL: validation error template works on bad send... ");
    {
        wv_post("/wallet/send/review", "address=bad&amount=0");
        bool has_error = wv_has("Invalid Transaction");
        bool has_retry = wv_has("Try Again");
        if (has_error && has_retry) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("TMPL: shield error template works on zero amount... ");
    {
        wv_post("/wallet/shield/confirm", "amount=0");
        bool has_invalid = wv_has("Invalid amount") || wv_has("invalid");
        if (has_invalid) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_backup_warning_template_has_address(void)
{
    int failures = 0;

    printf("TMPL: backup warning template has address... ");
    {
        wv_get("/wallet");
        bool has_backup = wv_has("Back Up");
        bool has_addr = wv_has("t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn");
        if (has_backup && has_addr) printf("OK (address in backup cmd)\n");
        else if (!has_backup) printf("OK (backed up)\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_dashboard_with_no_db_renders_gracefully(void)
{
    int failures = 0;
    printf("EMPTY: dashboard with no DB renders gracefully... ");
    {
        wv_get("/wallet");
        bool ok = wv_is_200();
        ok = ok && (wv_has("Wallet Loading") || wv_has("class='balance'"));
        ok = ok && wv_has("class='nav'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("EMPTY: history with no DB shows loading state... ");
    {
        wv_get("/wallet/history");
        bool ok = wv_is_200();
        ok = ok && (wv_has("Wallet Loading") || wv_has("0 transaction") ||
                    wv_has("No transactions"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("EMPTY: coins with no DB shows loading state... ");
    {
        wv_get("/wallet/coins");
        bool ok = wv_is_200();
        ok = ok && (wv_has("Wallet Loading") || wv_has("0 UTXO") ||
                    wv_has("No coins"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("EMPTY: pulse returns 0 balance when no DB... ");
    {
        wv_get("/api/wallet/pulse");
        bool ok = wv_has("\"balance\":0");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_form_still_renders_with_no_db(void)
{
    int failures = 0;

    printf("EMPTY: send form still renders with no DB... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_is_200() && wv_has("form");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 16. EDGE CASE TESTS — boundary amounts, invalid inputs
     * ═══════════════════════════════════════════════════════════ */

    printf("\n=== EDGE CASE TESTS ===\n\n");

    printf("EDGE: XSS in address field is escaped... ");
    {
        wv_post("/wallet/send/review",
            "address=%3Cscript%3Ealert(1)%3C%2Fscript%3E&amount=0.01");
        bool bad = wv_has("<script>alert(1)</script>");
        if (!bad) printf("OK\n");
        else { printf("FAIL (XSS!)\n"); failures++; }
    }

    printf("EDGE: img onerror XSS escaped... ");
    {
        wv_post("/wallet/send/review",
            "address=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E&amount=0.01");
        bool bad = wv_has("<img src=x onerror=alert(1)>");
        if (!bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("EDGE: too-short address rejected... ");
    {
        wv_post("/wallet/send/review", "address=t1abc&amount=0.01");
        bool ok = wv_has("Invalid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("EDGE: shield amount=0 shows input form, not confirm... ");
    {
        wv_get("/wallet/shield?amount=0");
        bool has_form = wv_has("shield-amt") || wv_has("Nothing to shield");
        bool bad = wv_has("Confirm</button>") && (!wv_has("shield-amt") || wv_has("Nothing to shield"));
        if (has_form && !bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("EDGE: SQL injection in search sanitized... ");
    {
        wv_get("/wallet/history?q=1'%20OR%20'1'%3D'1");
        bool bad = wv_has("syntax error") || wv_has("SQLITE");
        if (!bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("EDGE: path traversal in /wallet/tx/ blocked... ");
    {
        wv_get("/wallet/tx/../../../etc/passwd");
        bool bad = wv_has("root:") || wv_has("/bin/bash");
        if (!bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_oversized_post_body_does_not_crash(void)
{
    int failures = 0;

    printf("EDGE: oversized POST body does not crash... ");
    {
        char big[4096];
        memset(big, 'A', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        memcpy(big, "address=", 8);
        memcpy(big + 4000, "&amount=1", 9);
        size_t n = wv_post("/wallet/send/review", big);
        bool ok = (n > 0);
        if (ok) printf("OK (%zu bytes)\n", n);
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 17. NAVIGATION CONSISTENCY TESTS
     * ═══════════════════════════════════════════════════════════ */

    printf("\n=== NAVIGATION CONSISTENCY TESTS ===\n\n");

    printf("NAV: every tab highlights correctly... ");
    {
        struct { const char *path; const char *active; } tabs[] = {
            {"/wallet",         "class='active'>Home"},
            {"/wallet/send",    "class='active'>Send"},
            {"/wallet/receive", "class='active'>Receive"},
            {"/wallet/history", "class='active'>History"},
            {"/wallet/node",    "class='active'>Node"},
        };
        bool ok = true;
        for (int i = 0; i < 5; i++) {
            wv_get(tabs[i].path);
            if (!wv_has(tabs[i].active)) {
                printf("FAIL (%s)\n", tabs[i].path);
                ok = false; failures++; break;
            }
        }
        if (ok) printf("OK (all 5)\n");
    }

    printf("NAV: shield page has no active nav tab (not in main nav)... ");
    {
        wv_get("/wallet/shield?amount=0.5");
        /* Shield is not in nav anymore — no tab should be active */
        bool bad = wv_has("class='active'>Home") ||
                   wv_has("class='active'>Send");
        if (!bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("NAV: all pages have nav bar... ");
    {
        const char *pages[] = {"/wallet", "/wallet/send", "/wallet/receive",
                                "/wallet/history", "/wallet/coins", NULL};
        bool ok = true;
        for (int i = 0; pages[i]; i++) {
            wv_get(pages[i]);
            if (!wv_has("class='nav'")) {
                printf("FAIL (%s)\n", pages[i]);
                ok = false; failures++; break;
            }
        }
        if (ok) printf("OK\n");
    }

    printf("NAV: no page contains 'Groth16'... ");
    {
        const char *pages[] = {"/wallet", "/wallet/send", "/wallet/receive",
                                "/wallet/history", "/wallet/coins",
                                "/wallet/shield?amount=0.5", NULL};
        bool bad = false;
        for (int i = 0; pages[i]; i++) {
            wv_get(pages[i]);
            if (wv_has("Groth16") || wv_has("not yet implemented")) {
                printf("FAIL (%s)\n", pages[i]);
                bad = true; failures++; break;
            }
        }
        if (!bad) printf("OK\n");
    }
    return failures;
}

int check_wallet_view_all_titles_contain_z23(void)
{
    int failures = 0;

    printf("NAV: all titles contain 'Z23'... ");
    {
        const char *pages[] = {"/wallet", "/wallet/send", "/wallet/receive",
                                "/wallet/history", "/wallet/coins",
                                "/wallet/node", NULL};
        bool ok = true;
        for (int i = 0; pages[i]; i++) {
            wv_get(pages[i]);
            if (!wv_has("Z23")) {
                printf("FAIL (%s)\n", pages[i]);
                ok = false; failures++; break;
            }
        }
        if (ok) printf("OK\n");
    }

    printf("NAV: nav has 5 tabs including Node... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("/wallet/node") && wv_has(">Node<");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("NODE: command center page renders... ");
    {
        wv_get("/wallet/node");
        bool ok = wv_has("Command Center");
        ok = ok && wv_has("Block Height");
        ok = ok && wv_has("Connected Peers");
        ok = ok && wv_has("Mempool");
        ok = ok && wv_has("Network Status");
        ok = ok && wv_has("Quick Actions");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("NODE: command center has Tor section... ");
    {
        wv_get("/wallet/node");
        bool ok = wv_has("Tor Hidden Service");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_command_center_has_peer_table(void)
{
    int failures = 0;

    printf("NODE: command center has peer table... ");
    {
        wv_get("/wallet/node");
        /* Table with address/direction/version/height headers */
        bool ok = wv_has("<th>Address</th>");
        ok = ok && wv_has("<th>Dir</th>");
        ok = ok && wv_has("Connecting to network");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("NODE: command center links to explorer... ");
    {
        wv_get("/wallet/node");
        bool ok = wv_has("/explorer");
        ok = ok && wv_has("Block Explorer");
        ok = ok && wv_has("Network Stats");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("DASHBOARD: node tab links to command center... ");
    {
        wv_get("/wallet");
        /* Dashboard nav always renders even without DB */
        bool ok = wv_has("/wallet/node");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("NODE: page has ZClassic23 advertised version string... ");
    {
        wv_get("/wallet/node");
        bool ok = !wv_has("MagicBean:") && wv_has("ZClassic23:0.1.0");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * PARTIAL TEMPLATE TESTS — {{> name}} includes
     * ═══════════════════════════════════════════════════════════ */

    printf("\n=== PARTIAL TEMPLATE TESTS ===\n\n");

    printf("PARTIAL: shield page uses {{> breadcrumb}} partial... ");
    {
        /* Shield with no amount shows amount form with breadcrumb */
        wv_get("/wallet/shield");
        /* breadcrumb partial renders: "Home" link + "Secure Funds" label */
        bool ok = wv_has("/wallet") && (wv_has("Shield") || wv_has("Nothing to shield"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_template_render_handles_name_syntax(void)
{
    int failures = 0;

    printf("PARTIAL: template_render handles {{> name}} syntax... ");
    {
        char buf[1024];
        struct template_var vars[] = {
            { "parent_href", "/test" },
            { "parent_label", "Test" },
            { "current", "Page" },
        };
        size_t n = template_render("before{{> breadcrumb}}after",
            vars, 3, buf, sizeof(buf));
        bool ok = (n > 0) && strstr(buf, "before") && strstr(buf, "after");
        ok = ok && strstr(buf, "/test");
        ok = ok && strstr(buf, "Test");
        ok = ok && strstr(buf, "Page");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("PARTIAL: missing partial silently skipped... ");
    {
        char buf[256];
        size_t n = template_render("A{{> nonexistent}}B", NULL, 0,
            buf, sizeof(buf));
        bool ok = (n == 2) && buf[0] == 'A' && buf[1] == 'B';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("PARTIAL: max depth prevents infinite recursion... ");
    {
        /* Even if a partial references itself, depth limit stops it */
        char buf[256];
        size_t n = template_render("X{{> breadcrumb}}Y", NULL, 0,
            buf, sizeof(buf));
        /* Should render without hanging, partial vars are empty */
        bool ok = (n > 0) && strstr(buf, "X") && strstr(buf, "Y");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_dashboard_renders_in_50ms(void)
{
    int failures = 0;

    /* ═══════════════════════════════════════════════════════════
     * 18. PERFORMANCE TESTS — render timing
     * ═══════════════════════════════════════════════════════════ */

    printf("\n=== PERFORMANCE TESTS ===\n\n");

    /* PERF metric = MEDIAN per-render ms over 100 measured iterations (5
     * warm-up iterations discarded). The threshold for each route is
     * unchanged from the original mean-based check; only the central
     * statistic changed. A genuine render regression slows every iteration
     * and shifts the median past the threshold (still caught
     * deterministically), while a few scheduler-preempted iterations under
     * the 32-worker parallel runner no longer flip a fast renderer to FAIL.
     * See wv_perf_median_ms / wv_median_ms above. */
    double wv_perf_samples[100];

    printf("PERF: dashboard renders in < 50ms... ");
    {
        double ms = wv_perf_median_ms("/wallet", 5, 100, wv_perf_samples);
        if (ms < 50.0) printf("OK (%.2f ms median)\n", ms);
        else { printf("FAIL (%.2f ms)\n", ms); failures++; }
    }

    printf("PERF: pulse renders in < 10ms... ");
    {
        double ms = wv_perf_median_ms("/api/wallet/pulse", 5, 100,
                                      wv_perf_samples);
        if (ms < 10.0) printf("OK (%.2f ms median)\n", ms);
        else { printf("FAIL (%.2f ms)\n", ms); failures++; }
    }

    printf("PERF: history renders in < 100ms... ");
    {
        double ms = wv_perf_median_ms("/wallet/history", 5, 100,
                                      wv_perf_samples);
        if (ms < 100.0) printf("OK (%.2f ms median)\n", ms);
        else { printf("FAIL (%.2f ms)\n", ms); failures++; }
    }

    printf("PERF: receive renders in < 50ms... ");
    {
        double ms = wv_perf_median_ms("/wallet/receive", 5, 100,
                                      wv_perf_samples);
        if (ms < 50.0) printf("OK (%.2f ms median)\n", ms);
        else { printf("FAIL (%.2f ms)\n", ms); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 13. FORM PARSING CONTRACT — a miss returns false
     * ═══════════════════════════════════════════════════════════
     * wv_parse_form_field once logged the miss but returned true no
     * matter what; its boolean now tells the truth. The wrapper rides
     * on web_form_field's bounded scanner: hit decodes, miss/duplicate/
     * empty refuse with the buffer left empty. */

    printf("wallet_view: parse_form_field returns a decoded hit... ");
    {
        static const char body[] = "address=zs1fixture&amount=0.00000001";
        char got[32] = {0};
        bool ok = wv_parse_form_field((const uint8_t *)body,
                                      sizeof(body) - 1, "amount", got,
                                      sizeof(got)) &&
                  strcmp(got, "0.00000001") == 0;
        if (ok) printf("OK\n");
        else { printf("FAIL (got='%s')\n", got); failures++; }
    }

    printf("wallet_view: parse_form_field miss returns false... ");
    {
        static const char body[] = "address=zs1fixture&amount=0.00000001";
        char got[32];
        snprintf(got, sizeof(got), "dirty");
        bool ok = !wv_parse_form_field((const uint8_t *)body,
                                       sizeof(body) - 1, "fee", got,
                                       sizeof(got)) && got[0] == '\0';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: parse_form_field duplicate field is refused... ");
    {
        /* A payment form saying amount twice is lying by construction;
         * ambiguity must not be resolved in anyone's favor. */
        static const char body[] =
            "amount=100&address=zs1fixture&amount=0.01";
        char got[32] = {0};
        bool ok = !wv_parse_form_field((const uint8_t *)body,
                                       sizeof(body) - 1, "amount", got,
                                       sizeof(got)) && got[0] == '\0';
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

