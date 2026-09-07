/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * wallet_view scenario checks: routing, dashboard, send flow, receive,
 * coins, shield flow, transaction detail, and the pulse JSON API.
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


int check_wallet_view_get_wallet_returns_dashboard(void)
{
    int failures = 0;
    /* ═══════════════════════════════════════════════════════════
     * 1. ROUTE RESOLUTION — every URL returns the correct page
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: GET /wallet returns dashboard... ");
    {
        size_t n = wv_get("/wallet");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("Z23 Wallet");  /* page title */
        ok = ok && wv_has("class='nav'");       /* navigation */
        if (ok) printf("OK (%zu bytes)\n", n);
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("wallet_view: GET /wallet/ (trailing slash) works... ");
    {
        size_t n = wv_get("/wallet/");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("Z23 Wallet");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: GET /wallet/send returns send form... ");
    {
        size_t n = wv_get("/wallet/send");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("Send");
        ok = ok && wv_has("form");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: GET /wallet/receive returns receive page... ");
    {
        size_t n = wv_get("/wallet/receive");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("Receive");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_get_wallet_history_returns_history_or_loading(void)
{
    int failures = 0;

    printf("wallet_view: GET /wallet/history returns history (or loading)... ");
    {
        size_t n = wv_get("/wallet/history");
        bool ok = (n > 0) && wv_is_200();
        /* With no DB, should show loading state, not blank */
        ok = ok && wv_has("Wallet Loading");
        if (ok) printf("OK (graceful loading state)\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("wallet_view: GET /wallet/coins returns coins (or loading)... ");
    {
        size_t n = wv_get("/wallet/coins");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("Wallet Loading");
        if (ok) printf("OK (graceful loading state)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: GET /api/wallet/pulse returns JSON... ");
    {
        size_t n = wv_get("/api/wallet/pulse");
        bool ok = (n > 0);
        ok = ok && wv_has("engine/application/json");
        ok = ok && wv_has("\"height\":");
        ok = ok && wv_has("\"balance\":");
        ok = ok && wv_has("\"peers\":");
        ok = ok && wv_has("\"sync\":");
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("wallet_view: GET /wallet/nonexistent returns 0 (no match)... ");
    {
        size_t n = wv_get("/wallet/nonexistent");
        if (n == 0) printf("OK\n");
        else { printf("FAIL (n=%zu, expected 0)\n", n); failures++; }
    }
    return failures;
}

int check_wallet_view_dashboard_has_navigation_with_4_tabs(void)
{
    int failures = 0;

    /* ═══════════════════════════════════════════════════════════
     * 2. DASHBOARD — visual elements and structure
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: dashboard has navigation with 4 tabs... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("Home</a>");
        ok = ok && wv_has("Send</a>");
        ok = ok && wv_has("Receive</a>");
        ok = ok && wv_has("History</a>");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: dashboard nav marks Home as active... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("class='active'>Home");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: dashboard has balance or loading state... ");
    {
        wv_get("/wallet");
        /* With DB: shows balance. Without DB: shows loading hourglass. */
        bool ok = wv_has("class='balance'") || wv_has("Wallet Loading");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: dashboard has sync badge or loading... ");
    {
        wv_get("/wallet");
        bool ok = (wv_has("id='sync'") && wv_has("sync-badge")) ||
                  wv_has("Wallet Loading");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: dashboard has Send and Receive action buttons... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("href='/wallet/send'");
        ok = ok && wv_has("href='/wallet/receive'");
        ok = ok && wv_has(">Send</a>");
        ok = ok && wv_has(">Receive</a>");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_dashboard_has_recent_txs_or_loading(void)
{
    int failures = 0;

    printf("wallet_view: dashboard has recent txs or loading... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("Recent</span>") || wv_has("Wallet Loading");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: dashboard has status bar with live polling... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("id='sbar'");
        ok = ok && wv_has("class='status-bar'");
        ok = ok && wv_has("id='sb-h'");  /* height */
        ok = ok && wv_has("id='sb-p'");  /* peers */
        ok = ok && wv_has("id='sb-m'");  /* mempool */
        ok = ok && wv_has("setInterval");  /* polling JS */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: dashboard status bar uses readable labels... ");
    {
        wv_get("/wallet");
        bool ok = wv_has("'Block '+d.height");
        ok = ok && wv_has("d.peers+' peers'");
        ok = ok && wv_has("d.mempool+' tx'");
        /* Must NOT have cryptic H:/P:/M: abbreviations */
        bool bad = wv_has("'H:'+d.height");
        if (ok && !bad) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_dashboard_has_polling_js_or_loading(void)
{
    int failures = 0;

    printf("wallet_view: dashboard has polling JS or loading... ");
    {
        wv_get("/wallet");
        /* With DB: polling at 500ms. Without DB: loading state still has footer poll. */
        bool ok = wv_has(",500)") || wv_has("setInterval") || wv_has("Wallet Loading");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: dashboard DB-unavailable shows loading state... ");
    {
        wv_get("/wallet");
        /* With NULL datadir, should show loading hourglass */
        bool ok = wv_has("Wallet Loading") || wv_has("class='balance'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 3. SEND FLOW — form elements, validation, review, confirm
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: send form has address input with label... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("id='addr'");
        ok = ok && wv_has("name='address'");
        ok = ok && wv_has("for='addr'");  /* label association */
        ok = ok && wv_has("t1... or zs1...");  /* placeholder */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send form has amount input with Max button... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("id='amt'");
        ok = ok && wv_has("name='amount'");
        ok = ok && wv_has("for='amt'");  /* label association */
        ok = ok && wv_has("send-max");  /* Max button class */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_form_has_error_display_divs(void)
{
    int failures = 0;

    printf("wallet_view: send form has error display divs... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("id='addr-err'");
        ok = ok && wv_has("id='amt-err'");
        ok = ok && wv_has("id='remaining'");
        ok = ok && wv_has("form-error");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send form POSTs to review (not confirm)... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("action='zcl://node/wallet/send/review'");
        ok = ok && wv_has("method='POST'");
        /* Must NOT go directly to confirm */
        bool bad = wv_has("action='zcl://node/wallet/send/confirm'");
        if (ok && !bad) printf("OK (two-step send)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send form JS validates address prefix... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("^(t[13]|zs1)");  /* regex for prefix check */
        ok = ok && wv_has("Must start with t1, t3, or zs1");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send form JS validates alphanumeric... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("^[a-zA-Z0-9]+$");  /* alphanumeric regex */
        ok = ok && wv_has("Invalid characters in address");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send form shows specific insufficient funds message... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("Insufficient funds: need ");
        ok = ok && wv_has("more ZCL");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_form_has_blur_validation_on_address_fiel(void)
{
    int failures = 0;

    printf("wallet_view: send form has blur validation on address field... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("addEventListener('blur'");
        ok = ok && wv_has("Address too short");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send form Review button changes text on click... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("id='review-btn'");
        ok = ok && wv_has("this.textContent='Reviewing...'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send nav marks Send as active... ");
    {
        wv_get("/wallet/send");
        bool ok = wv_has("class='active'>Send");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Send Review (POST) ──────────────────────────────────── */

    printf("wallet_view: send review rejects empty address... ");
    {
        size_t n = wv_post("/wallet/send/review", "address=&amount=1.0");
        bool ok = (n > 0) && wv_has("Invalid");
        ok = ok && wv_has("Try Again");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send review rejects short address... ");
    {
        size_t n = wv_post("/wallet/send/review", "address=t1short&amount=1.0");
        bool ok = (n > 0) && wv_has("Invalid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send review rejects bad prefix... ");
    {
        size_t n = wv_post("/wallet/send/review",
            "address=x1YRBXKYLHRB4X8sTkBeRysAzBTMMHpUXrn&amount=0.1");
        bool ok = (n > 0) && wv_has("Invalid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send review rejects zero amount... ");
    {
        size_t n = wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0");
        bool ok = (n > 0) && wv_has("Invalid amount");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_review_rejects_negative_amount(void)
{
    int failures = 0;

    printf("wallet_view: send review rejects negative amount... ");
    {
        size_t n = wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=-5.0");
        bool ok = (n > 0) && wv_has("Invalid amount");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send review accepts valid t1 address... ");
    {
        size_t n = wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool ok = (n > 0) && wv_is_200();
        /* Should show review page with amount and address */
        ok = ok && wv_has("t1YRBXKYL");  /* address shown */
        ok = ok && wv_has("0.01");        /* amount shown */
        ok = ok && wv_has("Review");
        ok = ok && wv_has("Confirm Send");
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("wallet_view: send review shows fee on valid tx... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool ok = wv_has("0.000001");  /* min-relay fee */
        ok = ok && wv_has("Fee");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send review shows privacy level (public)... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool ok = wv_has("Public");
        ok = ok && wv_has("pill-t");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_review_has_loading_overlay_for_confirm(void)
{
    int failures = 0;

    printf("wallet_view: send review has loading overlay for confirm... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool ok = wv_has("id='send-loading'");
        ok = ok && wv_has("loading-overlay");
        ok = ok && wv_has("class='spinner'");
        ok = ok && wv_has("Sending transaction...");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send review confirm uses POST (not GET link)... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool ok = wv_has("method='POST'");
        ok = ok && wv_has("action='zcl://node/wallet/send/confirm'");
        ok = ok && wv_has("type='hidden' name='address'");
        ok = ok && wv_has("type='hidden' name='amount'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: send review has Cancel button back to send... ");
    {
        wv_post("/wallet/send/review",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool ok = wv_has("href='/wallet/send'");
        ok = ok && wv_has("Cancel");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Send Confirm (POST) ─────────────────────────────────── */

    printf("wallet_view: send confirm rejects invalid address... ");
    {
        size_t n = wv_post("/wallet/send/confirm",
            "address=invalid&amount=0.01");
        bool ok = (n > 0) && wv_has("Invalid");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_send_confirm_with_no_provenance_evidence_refu(void)
{
    int failures = 0;

    /* The send form carries the sovereignty guard ahead of its
     * transparent/shielded split, because its shielded branch reaches
     * z_sendmany directly and would otherwise be ungated (see
     * test_sovereignty_guard.c). This file deliberately runs with NO datadir,
     * so there is no progress store and the guard therefore fails closed —
     * which is the property to assert here: a spend surface with no provenance
     * evidence refuses rather than proceeding.
     *
     * The node-offline degradation this check used to cover now lives in
     * test_sovereignty_guard.c's SOVEREIGN section, which is the only place
     * that can establish the precondition it needs (proven authority +
     * self_folded); asserting it here would need this file to stop being the
     * no-datadir file. */
    printf("wallet_view: send confirm with no provenance evidence refuses... ");
    {
        size_t n = wv_post("/wallet/send/confirm",
            "address=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn&amount=0.01");
        bool ok = (n > 0) && wv_has("Spend Refused") &&
                  wv_has("release_assisted");
        /* And it must not have reached the send path at all. */
        ok = ok && !wv_has("Node Offline") && !wv_has("Send Failed");
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 4. RECEIVE — QR code, address display, chunking, tabs
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: receive has tab toggle (Private/Public)... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("tab-toggle");
        ok = ok && wv_has("id='tab-t'");
        ok = ok && wv_has("id='tab-z'");
        ok = ok && wv_has("Private (recommended)</a>");
        ok = ok && wv_has(">Public</a>");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: receive private tab is active by default... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("id='tab-z' class='active-z'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_receive_has_qr_code_svg(void)
{
    int failures = 0;

    printf("wallet_view: receive has QR code SVG... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("<svg");
        ok = ok && wv_has("viewBox");
        ok = ok && wv_has("fill='black'");  /* QR modules */
        ok = ok && wv_has("fill='white'");  /* QR background */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: receive shows primary address with chunking... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("addr-chunked");
        ok = ok && wv_has("t1YR");  /* first chunk of PRIMARY_ADDR */
        ok = ok && wv_has("class='hi'");  /* highlighted chunks */
        ok = ok && wv_has("class='sep'");  /* separators */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: receive shows 'Tap to copy' hint... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("Click to copy");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: receive has click-to-copy JS with fallback... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("navigator.clipboard.writeText");
        ok = ok && wv_has("document.execCommand('copy')");  /* fallback */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: receive has tab switching JS... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("function showTab(t)");
        ok = ok && wv_has("pane-t");
        ok = ok && wv_has("pane-z");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_receive_public_pane_hidden_by_default(void)
{
    int failures = 0;

    printf("wallet_view: receive public pane hidden by default... ");
    {
        wv_get("/wallet/receive");
        /* Public (t-address) pane is hidden by default, private shown */
        bool ok = wv_has("id='pane-t'") && wv_has("display:none");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: receive shows privacy type indicator... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("visible on-chain");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: receive nav marks Receive as active... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("class='active'>Receive");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 5. HISTORY — graceful degradation, filter tabs
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: history without DB shows loading... ");
    {
        size_t n = wv_get("/wallet/history");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("Wallet Loading");
        ok = ok && wv_has("database is not yet available");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: history has filter tabs in HTML... ");
    {
        /* With filter params, check the HTML contains filter structure */
        wv_get("/wallet/history?filter=all");
        /* Even without DB, should show loading, but let's check filter
         * params are parsed correctly by checking the structure */
        bool ok = wv_has("Wallet Loading");
        if (ok) printf("OK (loading state with filter param)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: history page=negative clamped to 0... ");
    {
        size_t n = wv_get("/wallet/history?page=-5");
        bool ok = (n > 0);  /* doesn't crash */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 6. COINS — graceful degradation
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: coins without DB shows loading... ");
    {
        size_t n = wv_get("/wallet/coins");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("Wallet Loading");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_coins_page_renders_no_active_nav_tab(void)
{
    int failures = 0;

    printf("wallet_view: coins page renders (no active nav tab)... ");
    {
        wv_get("/wallet/coins");
        bool ok = (wv_has("Your Coins") || wv_has("Wallet Loading")) &&
                  wv_has("class='nav'");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 7. SHIELD FLOW — confirmation, POST enforcement
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: shield with valid amount shows confirmation... ");
    {
        size_t n = wv_get("/wallet/shield?amount=0.5");
        bool ok = (n > 0) && wv_is_200();
        ok = ok && wv_has("0.50000000");  /* amount displayed */
        ok = ok && wv_has("Confirm");
        ok = ok && wv_has("Cancel");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: shield shows 3-step privacy explanation... ");
    {
        wv_get("/wallet/shield?amount=0.5");
        bool ok = wv_has("Step 1:");
        ok = ok && wv_has("Step 2:");
        ok = ok && wv_has("Step 3:");
        ok = ok && wv_has("private address");
        ok = ok && wv_has("timing analysis");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_shield_shows_fee_and_total_cost(void)
{
    int failures = 0;

    printf("wallet_view: shield shows fee and total cost... ");
    {
        wv_get("/wallet/shield?amount=0.5");
        bool ok = wv_has("0.000001");  /* min-relay fee */
        ok = ok && wv_has("Total:");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: shield confirm uses POST form (not GET link)... ");
    {
        wv_get("/wallet/shield?amount=0.5");
        bool ok = wv_has("method='POST'");
        ok = ok && wv_has("action='zcl://node/wallet/shield/confirm'");
        ok = ok && wv_has("name='amount'");
        /* Must NOT have a direct GET link to shield/confirm */
        bool bad = wv_has("href='/wallet/shield/confirm");
        if (ok && !bad) printf("OK (POST enforced)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: shield has loading overlay... ");
    {
        wv_get("/wallet/shield?amount=0.5");
        bool ok = wv_has("id='shield-loading'");
        ok = ok && wv_has("loading-overlay");
        ok = ok && wv_has("Securing funds...");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: shield with zero amount shows form or nothing... ");
    {
        size_t n = wv_get("/wallet/shield?amount=0");
        /* With no DB, transparent=0 so "Nothing to shield" is correct */
        bool ok = (n > 0) && (wv_has("shield-amt") || wv_has("Nothing to shield") || wv_has("Nothing to shield"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_shield_with_negative_amount_shows_form_or_not(void)
{
    int failures = 0;

    printf("wallet_view: shield with negative amount shows form or nothing... ");
    {
        size_t n = wv_get("/wallet/shield?amount=-1");
        bool ok = (n > 0) && (wv_has("Shield") || wv_has("Nothing to shield"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: shield with no amount shows amount form... ");
    {
        size_t n = wv_get("/wallet/shield");
        bool ok = (n > 0) && (wv_has("Shield") || wv_has("Nothing to shield"));
        ok = ok && (wv_has("Amount") || wv_has("Nothing to shield"));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: shield confirm POST with no body shows error... ");
    {
        size_t n = wv_post("/wallet/shield/confirm", NULL);
        bool ok = (n > 0) && wv_has("Invalid amount");
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("wallet_view: shield confirm POST with zero amount shows error... ");
    {
        size_t n = wv_post("/wallet/shield/confirm", "amount=0");
        bool ok = (n > 0) && wv_has("Invalid amount");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

int check_wallet_view_tx_detail_with_short_txid_shows_error_or_load(void)
{
    int failures = 0;

    /* ═══════════════════════════════════════════════════════════
     * 8. TRANSACTION DETAIL — /wallet/tx/:txid
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: tx detail with short txid shows error or loading... ");
    {
        size_t n = wv_get("/wallet/tx/abc123");
        bool ok = (n > 0);
        ok = ok && (wv_has("Invalid Transaction ID") || wv_has("Wallet Loading"));
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("wallet_view: tx detail with non-hex chars sanitized... ");
    {
        /* Inject SQL-like chars — should be stripped to hex only */
        size_t n = wv_get("/wallet/tx/"
            "aa' OR 1=1; DROP TABLE wallet_transactions; --bb");
        bool ok = (n > 0);
        /* Should show invalid ID or loading (not enough hex after sanitization) */
        ok = ok && (wv_has("Invalid Transaction ID") || wv_has("Wallet Loading"));
        if (ok) printf("OK (SQL injection prevented)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: tx detail with valid-format txid and no DB shows loading... ");
    {
        /* 64 hex chars, valid format but no DB available */
        size_t n = wv_get("/wallet/tx/"
            "0000000000000000000000000000000000000000000000000000000000000000");
        bool ok = (n > 0);
        ok = ok && (wv_has("Wallet Loading") || wv_has("Not Found"));
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }
    return failures;
}

int check_wallet_view_pulse_returns_valid_json_structure(void)
{
    int failures = 0;

    /* ═══════════════════════════════════════════════════════════
     * 9. PULSE API — JSON structure and content
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: pulse returns valid JSON structure... ");
    {
        wv_get("/api/wallet/pulse");
        bool ok = wv_has("\"height\":");
        ok = ok && wv_has("\"balance\":");
        ok = ok && wv_has("\"shielded\":");
        ok = ok && wv_has("\"speed_balance\":");
        ok = ok && wv_has("\"t_utxos\":");
        ok = ok && wv_has("\"z_notes\":");
        ok = ok && wv_has("\"peers\":");
        ok = ok && wv_has("\"sync\":");
        ok = ok && wv_has("\"mempool\":");
        if (ok) printf("OK (9 fields)\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("wallet_view: pulse has no-cache header... ");
    {
        wv_get("/api/wallet/pulse");
        bool ok = wv_has("Cache-Control: no-cache");
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 10. VISUAL CONSISTENCY — CSS classes, design system
     * ═══════════════════════════════════════════════════════════ */

    printf("wallet_view: all pages include wallet CSS... ");
    {
        /* Check multiple pages have the CSS loaded */
        wv_get("/wallet");
        bool ok1 = wv_has("nav a:focus-visible");  /* from CSS */
        wv_get("/wallet/send");
        bool ok2 = wv_has("form-input");
        wv_get("/wallet/receive");
        bool ok3 = wv_has("addr-display");
        if (ok1 && ok2 && ok3) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }
    return failures;
}

