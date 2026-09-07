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
#include "test/test_wallet_view_priv.h"

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

/* The shared scenario context, handed out only through a pointer. */
struct wv_test_ctx *wv_ctx(void)
{
    static struct wv_test_ctx ctx;
    return &ctx;
}

/* Helper: call GET route, return response size */
size_t wv_get(const char *path) {
    memset(wv_ctx()->resp, 0, sizeof(wv_ctx()->resp));
    return wallet_view_handle_request("GET", path, NULL, 0,
                                       wv_ctx()->resp, sizeof(wv_ctx()->resp));
}

/* Helper: call POST route with form body */
size_t wv_post(const char *path, const char *body) {
    memset(wv_ctx()->resp, 0, sizeof(wv_ctx()->resp));
    return wallet_view_handle_request("POST", path,
                                       (const uint8_t *)body,
                                       body ? strlen(body) : 0,
                                       wv_ctx()->resp, sizeof(wv_ctx()->resp));
}

/* Helper: check response contains string */
bool wv_has(const char *needle) {
    return strstr((char *)wv_ctx()->resp, needle) != NULL;
}

/* Helper: check response is a 200 HTML page */
bool wv_is_200(void) {
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
double wv_perf_median_ms(const char *path, int warmup, int iters,
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

double wv_scan_coins_page_total(void)
{
    double coins_bal = -1;
    const char *scan = (char *)wv_ctx()->resp;
    const char *last_total = NULL;
    while ((scan = strstr(scan, "Total")) != NULL) {
        last_total = scan;
        scan += 5;
    }
    if (last_total && last_total > (char *)wv_ctx()->resp + 10) {
        /* Walk backward to find the number */
        const char *p = last_total - 1;
        while (p > (char *)wv_ctx()->resp && (*p == ' ' || *p == '\n' || *p == '\t' || *p == '>')) p--;
        /* Now p points to end of the number */
        const char *numend = p + 1;
        while (p > (char *)wv_ctx()->resp && ((*p >= '0' && *p <= '9') || *p == '.')) p--;
        if (p < numend) coins_bal = strtod(p + 1, NULL);
    }
    return coins_bal;
}

int test_wallet_view(void)
{
    int failures = 0;

    /* Initialize with no datadir — tests DB-unavailable paths.
     * This is intentional: we want to verify graceful degradation. */
    wallet_view_init(NULL);

    failures += check_wallet_view_get_wallet_returns_dashboard();
    failures += check_wallet_view_get_wallet_history_returns_history_or_loading();
    failures += check_wallet_view_dashboard_has_navigation_with_4_tabs();
    failures += check_wallet_view_dashboard_has_recent_txs_or_loading();
    failures += check_wallet_view_dashboard_has_polling_js_or_loading();
    failures += check_wallet_view_send_form_has_error_display_divs();
    failures += check_wallet_view_send_form_has_blur_validation_on_address_fiel();
    failures += check_wallet_view_send_review_rejects_negative_amount();
    failures += check_wallet_view_send_review_has_loading_overlay_for_confirm();
    failures += check_wallet_view_send_confirm_with_no_provenance_evidence_refu();
    failures += check_wallet_view_receive_has_qr_code_svg();
    failures += check_wallet_view_receive_public_pane_hidden_by_default();
    failures += check_wallet_view_coins_page_renders_no_active_nav_tab();
    failures += check_wallet_view_shield_shows_fee_and_total_cost();
    failures += check_wallet_view_shield_with_negative_amount_shows_form_or_not();
    failures += check_wallet_view_tx_detail_with_short_txid_shows_error_or_load();
    failures += check_wallet_view_pulse_returns_valid_json_structure();
    failures += check_wallet_view_design_system_colors_are_consistent();
    failures += check_wallet_view_path_traversal_in_tx_detail_is_sanitized();
    failures += check_wallet_view_zero_size_response_buffer_doesn_t_crash();

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

    failures += check_wallet_view_dashboard_shows_real_balance_not_loading();
    failures += check_wallet_view_dashboard_recent_txs_link_to_wallet_tx_or_syn();
    failures += check_wallet_view_pulse_has_peers_0();
    failures += check_wallet_view_receive_qr_code_is_valid_svg();
    failures += check_wallet_view_history_filter_tabs_present_and_styled();
    failures += check_wallet_view_history_tx_cards_have_direction_badges();
    failures += check_wallet_view_coins_page_shows_grand_total_stats();
    failures += check_wallet_view_all_pages_have_consistent_nav_structure();
    failures += check_wallet_view_wallet_css_loads_without_overflow();
    failures += check_wallet_view_send_review_with_valid_address_shows_checksum();
    failures += check_wallet_view_balance_consistent_pulse_send_coins();
    failures += check_wallet_view_balance_must_be_1_zcl_sanity_check();
    failures += check_wallet_view_history_shows_0_transactions();
    failures += check_wallet_view_history_txs_show_non_zero_amounts();
    failures += check_wallet_view_shield_review_page_renders_correctly();
    failures += check_wallet_view_send_review_to_zs1_shows_t_z_privacy_warning();
    failures += check_wallet_view_dashboard_has_contacts_datalist_on_send_page();
    failures += check_wallet_view_receive_page_shows_z_address_qr_code();
    failures += check_wallet_view_receive_page_says_click_to_copy_not_tap();
    failures += check_wallet_view_no_unresolved_vars_in_dashboard();
    failures += check_wallet_view_no_unresolved_vars_in_coins();
    failures += check_wallet_view_history_cards_use_template_secured_badge();
    failures += check_wallet_view_backup_warning_template_has_address();

    /* ═══════════════════════════════════════════════════════════
     * 15. EMPTY STATE TESTS — no DB, simulate fresh install
     * ═══════════════════════════════════════════════════════════ */

    wallet_view_init(NULL);
    printf("\n=== EMPTY STATE TESTS ===\n\n");

    failures += check_wallet_view_dashboard_with_no_db_renders_gracefully();
    failures += check_wallet_view_send_form_still_renders_with_no_db();
    failures += check_wallet_view_oversized_post_body_does_not_crash();
    failures += check_wallet_view_all_titles_contain_z23();
    failures += check_wallet_view_command_center_has_peer_table();
    failures += check_wallet_view_template_render_handles_name_syntax();
    failures += check_wallet_view_dashboard_renders_in_50ms();

    /* Restore NULL for safety, then tear down the fixture datadir. */
    wallet_view_init(NULL);
    wv_cleanup_fixture_datadir(fixture_datadir);
    return failures;
}
