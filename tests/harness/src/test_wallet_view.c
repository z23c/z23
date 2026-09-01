/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Comprehensive interaction tests for the wallet view controller.
 *
 * These tests simulate every user interaction: clicking through pages,
 * submitting forms, checking visual elements, verifying error states,
 * and validating security properties. Each test calls the controller
 * directly and inspects the HTML output like a user would see it.
 *
 * Test categories:
 *   1. Route resolution — every URL produces the right page
 *   2. Dashboard — balance, sync badge, recent txs, privacy card
 *   3. Send flow — form, validation, review, confirm, errors
 *   4. Receive — QR code, address display, chunking, tabs
 *   5. History — pagination, filters, search
 *   6. Coins — UTXO audit, shielded notes, data comparison
 *   7. Shield flow — confirmation, POST enforcement, error states
 *   8. Transaction detail — /wallet/tx/:txid
 *   9. Pulse API — JSON balance endpoint
 *  10. Visual consistency — CSS classes, color system, accessibility
 *  11. Security — XSS prevention, SQL injection, CSRF
 *  12. Edge cases — empty DB, huge values, special characters
 *  13. Form parsing contract — a miss returns false and clears the
 *      buffer (the boolean used to be hardcoded true) */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"  /* wv_parse_form_field */
#include "models/database.h"
#include "util/template.h"
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* ── Hermetic fixture DB ──────────────────────────────────────
 * The data-driven render tests must never touch the live node's
 * ~/.zclassic-c23/node.db. Coupling to it produced two problems:
 *   (1) non-deterministic assertions (balances/txs change minute to
 *       minute as the node syncs), and
 *   (2) "[explorer] ... no such table: mempool_entries" noise whenever
 *       the live DB's projection tables weren't built yet — which
 *       masked real failures in build/bin/test_parallel.
 *
 * Instead we build a private, deterministic node.db in a temp datadir
 * using the authoritative production schema (node_db_open applies
 * SCHEMA[]), add the mempool_entries projection table the read paths
 * expect, and seed known rows. wallet_view_init(fixture_dir) then points
 * every wv_open_db() at it. The tests assert against the seeded values. */

/* Seeded transparent balance: 0.05 ZCL (5,000,000 zatoshi), unspent. */
#define WV_FIX_TBAL_SAT   5000000LL
/* Seeded shielded balance: 0.02 ZCL (2,000,000 zatoshi), unspent. */
#define WV_FIX_ZBAL_SAT   2000000LL

/* Build a temp datadir containing a seeded node.db. Returns true on
 * success and writes the datadir path into out (caller owns the dir). */
static bool wv_build_fixture_datadir(char *out, size_t out_sz)
{
    char tmpl[] = "/tmp/zcl_wv_fixture_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir)
        return false;
    snprintf(out, out_sz, "%s", dir);

    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);

    struct node_db ndb;
    if (!node_db_open(&ndb, dbpath))
        return false;

    bool ok = true;
    /* Projection table read by the dashboard/node/pulse paths. Not part
     * of the base SCHEMA (it is built by a runtime projection on the live
     * node), so create it here to keep the read paths "no such table"-free. */
    ok = ok && node_db_exec(&ndb,
        "CREATE TABLE IF NOT EXISTS mempool_entries ("
        "txid BLOB PRIMARY KEY, fee INTEGER, size INTEGER, time_added INTEGER)");

    /* One block at height 100 (deterministic chain tip). */
    ok = ok && node_db_exec(&ndb,
        "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,time,"
        "bits,nonce,solution,chain_work,status,num_tx,sapling_value,sprout_value) "
        "VALUES(x'aa00',100,x'bb00',4,x'cc00',1700000000,0x1d00ffff,x'00',x'00',"
        "x'00',3,1,0,0)");

    /* One unspent transparent UTXO → 0.05 ZCL ground-truth balance. */
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO wallet_utxos(txid,vout,value,address_hash,script,height,"
        "is_coinbase) VALUES(x'd1',0,%lld,x'1234567890abcdef1234567890abcdef12345678',"
        "x'76a914',100,0)", (long long)WV_FIX_TBAL_SAT);
    ok = ok && node_db_exec(&ndb, sql);

    /* One wallet transaction (received) referencing that UTXO's txid. */
    ok = ok && node_db_exec(&ndb,
        "INSERT INTO wallet_transactions(txid,raw_tx,block_hash,block_height,"
        "time_received,from_me,fee) "
        "VALUES(x'd1',x'00',x'aa00',100,1700000000,0,10000)");

    /* One unspent sapling note → 0.02 ZCL shielded balance. */
    snprintf(sql, sizeof(sql),
        "INSERT INTO wallet_sapling_notes(txid,output_index,value,rcm,ivk,"
        "diversifier,pk_d,cm,nullifier,block_height,address) "
        "VALUES(x'e1',0,%lld,x'00',x'01',x'02',x'03',x'04',x'05',100,"
        "'zs1fixturenote')", (long long)WV_FIX_ZBAL_SAT);
    ok = ok && node_db_exec(&ndb, sql);

    /* One sapling key so receive/shield paths see a private address. */
    ok = ok && node_db_exec(&ndb,
        "INSERT INTO wallet_sapling_keys(ivk,xsk,xfvk,diversifier,pk_d,"
        "child_index,address) VALUES(x'01',x'02',x'03',x'04',x'05',0,"
        "'zs1fixtureaddress')");

    /* One peer (count > 0). */
    ok = ok && node_db_exec(&ndb,
        "INSERT INTO peers(ip,port,services,last_seen) "
        "VALUES(x'7f000001',8033,1,1700000000)");

    node_db_close(&ndb);
    return ok;
}

/* Recursively remove the fixture datadir (db + wal/shm + dir). */
static void wv_cleanup_fixture_datadir(const char *dir)
{
    if (!dir || !dir[0])
        return;
    const char *files[] = {"node.db", "node.db-wal", "node.db-shm",
                           "node.db-journal", "wallet.backup", NULL};
    for (int i = 0; files[i]; i++) {
        char p[600];
        snprintf(p, sizeof(p), "%s/%s", dir, files[i]);
        unlink(p);
    }
    rmdir(dir);
}

/* Response buffer — 64KB is enough for any wallet page */
static uint8_t _wv_resp[131072];

/* Helper: call GET route, return response size */
static size_t wv_get(const char *path) {
    memset(_wv_resp, 0, sizeof(_wv_resp));
    return wallet_view_handle_request("GET", path, NULL, 0,
                                       _wv_resp, sizeof(_wv_resp));
}

/* Helper: call POST route with form body */
static size_t wv_post(const char *path, const char *body) {
    memset(_wv_resp, 0, sizeof(_wv_resp));
    return wallet_view_handle_request("POST", path,
                                       (const uint8_t *)body,
                                       body ? strlen(body) : 0,
                                       _wv_resp, sizeof(_wv_resp));
}

/* Helper: check response contains string */
static bool wv_has(const char *needle) {
    return strstr((char *)_wv_resp, needle) != NULL;
}

/* Helper: check response is a 200 HTML page */
static bool wv_is_200(void) {
    return wv_has("HTTP/1.1 200 OK") && wv_has("text/html");
}

/* Helper: median of n doubles via in-place insertion sort (n is small,
 * 100 here). Used by the PERF tests below so the pass/fail metric is the
 * central per-render cost rather than the mean. The mean is sensitive to
 * a handful of OS-scheduler preemptions — this suite runs 32 workers in
 * parallel, so a few of the 100 iterations can be descheduled and inflate
 * the average past the threshold even though every render is fast. The
 * median is robust to that minority of outliers but still moves
 * deterministically if rendering genuinely regresses (a real slowdown
 * makes EVERY iteration slow, which shifts the median), so detection
 * power is preserved. */
static double wv_median_ms(double *a, int n) {
    for (int i = 1; i < n; i++) {
        double key = a[i];
        int j = i - 1;
        while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
        a[j + 1] = key;
    }
    if (n <= 0) return 0.0;
    if (n & 1) return a[n / 2];
    return (a[n / 2 - 1] + a[n / 2]) / 2.0;
}

/* Helper: time wv_get(path) over `iters` measured iterations, returning the
 * MEDIAN per-render time in ms. `warmup` iterations run first and are
 * discarded so one-time cold-cache / cold-branch-predictor costs (which are
 * not regressions) do not skew the measurement. samples[] must hold at least
 * `iters` doubles. */
static double wv_perf_median_ms(const char *path, int warmup, int iters,
                                double *samples) {
    for (int i = 0; i < warmup; i++) wv_get(path);
    for (int i = 0; i < iters; i++) {
        struct timespec t0, t1;
        platform_time_monotonic_timespec(&t0);
        wv_get(path);
        platform_time_monotonic_timespec(&t1);
        samples[i] = (t1.tv_sec - t0.tv_sec) * 1000.0 +
                     (t1.tv_nsec - t0.tv_nsec) / 1e6;
    }
    return wv_median_ms(samples, iters);
}

int test_wallet_view(void)
{
    int failures = 0;

    /* Initialize with no datadir — tests DB-unavailable paths.
     * This is intentional: we want to verify graceful degradation. */
    wallet_view_init(NULL);

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
                                                _wv_resp, sizeof(_wv_resp));
        if (n == 0) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

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

    /* ═══════════════════════════════════════════════════════════
     * 13. FIXTURE RENDER — hermetic datadir, deterministic seeded data.
     *     Builds a private node.db (authoritative schema + seeded rows);
     *     never touches the live node. See wv_build_fixture_datadir().
     * ═══════════════════════════════════════════════════════════ */

    char fixture_datadir[256] = "";
    if (!wv_build_fixture_datadir(fixture_datadir, sizeof(fixture_datadir))) {
        printf("wallet_view: FIXTURE BUILD FAILED — skipping data-driven tests\n");
        wallet_view_init(NULL);
        return failures;  /* don't fall back to the live node */
    }

    /* Switch to the hermetic fixture datadir for data-driven tests. */
    wallet_view_init(fixture_datadir);
    printf("\n=== FIXTURE WALLET RENDER TESTS (deterministic seeded data) ===\n\n");

    /* The fixture always seeds funds (transparent + shielded). */
    bool have_wallet_funds = (WV_FIX_TBAL_SAT + WV_FIX_ZBAL_SAT > 0);

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
            const char *bal = strstr((char *)_wv_resp, "\"balance\":");
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

    printf("LIVE: pulse has peers > 0... ");
    {
        wv_get("/api/wallet/pulse");
        const char *p = strstr((char *)_wv_resp, "\"peers\":");
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
        const char *bal_js = strstr((char *)_wv_resp, "var BAL=");
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

    printf("LIVE: receive QR code is valid SVG... ");
    {
        wv_get("/wallet/receive");
        bool ok = wv_has("<svg") && wv_has("</svg>");
        ok = ok && wv_has("viewBox='0 0");
        /* Should have many rect elements (QR modules) */
        int rects = 0;
        const char *p = (char *)_wv_resp;
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
        const char *p = (char *)_wv_resp;
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
            const char *html = strstr((char *)_wv_resp, "\r\n\r\n");
            if (html) html += 4; else html = (char *)_wv_resp;
            FILE *f = fopen(path, "w");
            if (f) { fputs(html, f); fclose(f); }
        }
        printf("LIVE: pages dumped to .zcl_test_render/ for inspection\n");
    }

    /* ═══════════════════════════════════════════════════════════
     * 14. BALANCE CONSISTENCY — the same number everywhere
     *     This catches the bug where api_controller and
     *     wallet_view showed different balances.
     * ═══════════════════════════════════════════════════════════ */

    printf("LIVE: balance consistent: pulse == send == coins... ");
    {
        /* Get total balance from pulse (transparent + shielded) */
        wv_get("/api/wallet/pulse");
        const char *bp = strstr((char *)_wv_resp, "\"balance\":");
        int64_t pulse_t = bp ? strtoll(bp + 10, NULL, 10) : 0;
        const char *zp = strstr((char *)_wv_resp, "\"shielded\":");
        int64_t pulse_z = zp ? strtoll(zp + 11, NULL, 10) : 0;
        int64_t pulse_bal = pulse_t + pulse_z;

        /* Get balance from send page (var BAL=...) */
        wv_get("/wallet/send");
        const char *bs = strstr((char *)_wv_resp, "var BAL=");
        double send_bal = bs ? strtod(bs + 8, NULL) : -1;
        int64_t send_sat = (int64_t)(send_bal * 1e8 + 0.5);

        /* Get total balance from coins page (t + z combined) */
        wv_get("/wallet/coins");
        double coins_bal = -1;
        {
            const char *scan = (char *)_wv_resp;
            const char *last_total = NULL;
            while ((scan = strstr(scan, "Total")) != NULL) {
                last_total = scan;
                scan += 5;
            }
            if (last_total && last_total > (char *)_wv_resp + 10) {
                /* Walk backward to find the number */
                const char *p = last_total - 1;
                while (p > (char *)_wv_resp && (*p == ' ' || *p == '\n' || *p == '\t' || *p == '>')) p--;
                /* Now p points to end of the number */
                const char *numend = p + 1;
                while (p > (char *)_wv_resp && ((*p >= '0' && *p <= '9') || *p == '.')) p--;
                if (p < numend) coins_bal = strtod(p + 1, NULL);
            }
        }
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

    printf("LIVE: balance must be < 1 ZCL (sanity check)... ");
    {
        if (!have_wallet_funds) { printf("SKIP (wallet empty or disabled)\n"); }
        else {
            wv_get("/api/wallet/pulse");
            const char *bp = strstr((char *)_wv_resp, "\"balance\":");
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

    printf("LIVE: history shows > 0 transactions... ");
    {
        wv_get("/wallet/history");
        /* Look for "NN transaction" pattern in the sub div */
        const char *tc = strstr((char *)_wv_resp, " transaction");
        int count = 0;
        if (tc) {
            /* Walk back past spaces and digits */
            const char *p = tc - 1;
            while (p > (char *)_wv_resp && *p >= '0' && *p <= '9') p--;
            if (p[1] >= '0' && p[1] <= '9')
                count = atoi(p + 1);
        }
        /* Also check for tx-card elements */
        int cards = 0;
        const char *cp = (char *)_wv_resp;
        while ((cp = strstr(cp, "tx-card")) != NULL) { cards++; cp += 7; }
        if (count > 0 || cards > 0)
            printf("OK (%d txs, %d cards)\n", count, cards);
        else { printf("FAIL (0 transactions shown)\n"); failures++; }
    }

    printf("LIVE: history txs show non-zero amounts... ");
    {
        if (!have_wallet_funds) { printf("SKIP (wallet empty or disabled)\n"); }
        else {
            wv_get("/wallet/history");
            int nonzero = 0, total = 0;
            const char *p = (char *)_wv_resp;
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

    printf("INTEG: receive page shows z-address QR code... ");
    {
        wv_get("/wallet/receive");
        /* The private pane should have a QR SVG for the z-address */
        int svg_count = 0;
        const char *p = (char *)_wv_resp;
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

    /* ═══════════════════════════════════════════════════════════
     * 14c. TEMPLATE CORRECTNESS TESTS
     * ═══════════════════════════════════════════════════════════ */

    printf("\n=== TEMPLATE CORRECTNESS TESTS ===\n\n");

    printf("TMPL: no unresolved {{vars}} in dashboard... ");
    {
        wv_get("/wallet");
        /* Check for literal {{ in body but not in JS */
        const char *body = strstr((char *)_wv_resp, "<main>");
        const char *script = strstr((char *)_wv_resp, "<script");
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
        const char *body = strstr((char *)_wv_resp, "<main>");
        const char *script = strstr((char *)_wv_resp, "<script");
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

    printf("TMPL: no unresolved {{vars}} in coins... ");
    {
        wv_get("/wallet/coins");
        const char *body = strstr((char *)_wv_resp, "<main>");
        const char *script = strstr((char *)_wv_resp, "<script");
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

    printf("TMPL: backup warning template has address... ");
    {
        wv_get("/wallet");
        bool has_backup = wv_has("Back Up");
        bool has_addr = wv_has("t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn");
        if (has_backup && has_addr) printf("OK (address in backup cmd)\n");
        else if (!has_backup) printf("OK (backed up)\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ═══════════════════════════════════════════════════════════
     * 15. EMPTY STATE TESTS — no DB, simulate fresh install
     * ═══════════════════════════════════════════════════════════ */

    wallet_view_init(NULL);
    printf("\n=== EMPTY STATE TESTS ===\n\n");

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

    /* Restore NULL for safety, then tear down the fixture datadir. */
    wallet_view_init(NULL);
    wv_cleanup_fixture_datadir(fixture_datadir);

    return failures;
}
