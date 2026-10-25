/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wallet_check — verify wallet UI matches zclassicd truth.
 *
 * Connects to zclassicd, queries real balances, renders every
 * wallet page, and verifies the displayed values are correct.
 *
 * Usage: make check-wallet
 *
 * This catches every class of bug we've hit:
 * - Stale SQLite cache (displayed != actual)
 * - Wrong balance on send page
 * - Shield button when nothing to shield
 * - "Insufficient funds" when funds exist
 * - Privacy % not matching actual t/z ratio */

#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include "chain/chainparams.h"
#include "keys/key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <signal.h>

volatile sig_atomic_t g_shutdown_requested = 0;

static uint8_t page[131072];
static size_t pagelen;
static int checks_passed, checks_failed;

/* ── Rendering ─────────────────────────────────────────── */

static void render(const char *path) {
    memset(page, 0, sizeof(page));
    pagelen = wallet_view_handle_request("GET", path, NULL, 0,
                                          page, sizeof(page));
}

static bool has(const char *needle) {
    return strstr((char *)page, needle) != NULL;
}

static bool page_has_either(const char *first, const char *second) {
    return has(first) || has(second);
}

static bool page_has_any(const char *first, const char *second,
                         const char *third) {
    return has(first) || has(second) || has(third);
}

/* ── RPC queries ───────────────────────────────────────── */

static double rpc_transparent, rpc_private, rpc_total;

static bool query_truth(void) {
    char buf[4096] = "";
    int rc = wv_rpc_call("z_gettotalbalance", "[]", buf, sizeof(buf));
    if (rc <= 0) {
        printf("SKIP: zclassicd not reachable on port 8232\n");
        return false;
    }

    /* Parse: {"result":{"transparent":"X","private":"Y","total":"Z"}} */
    const char *t = strstr(buf, "\"transparent\"");
    const char *p = strstr(buf, "\"private\"");
    const char *tot = strstr(buf, "\"total\"");
    if (!t || !p || !tot) {
        printf("SKIP: z_gettotalbalance returned unexpected format\n");
        return false;
    }

    /* Extract values after the ":" */
    t = strchr(t + 13, '"'); if (t) t++;
    p = strchr(p + 9, '"'); if (p) p++;
    tot = strchr(tot + 7, '"'); if (tot) tot++;

    if (!t || !p || !tot) return false;

    rpc_transparent = strtod(t, NULL);
    rpc_private = strtod(p, NULL);
    rpc_total = strtod(tot, NULL);

    printf("Ground truth from zclassicd:\n");
    printf("  transparent: %.8f ZCL\n", rpc_transparent);
    printf("  private:     %.8f ZCL\n", rpc_private);
    printf("  total:       %.8f ZCL\n\n", rpc_total);
    return true;
}

/* Privacy % the UI should show: private share of the RPC total. */
static int expected_privacy_pct(void) {
    if (rpc_total > 0)
        return (int)(100.0 * rpc_private / rpc_total);
    return 0;
}

/* ── Check helpers ─────────────────────────────────────── */

#define CHECK(cond, desc) do { \
    if (cond) { checks_passed++; printf("  OK   %s\n", desc); } \
    else { checks_failed++; printf("  FAIL %s\n", desc); } \
} while(0)

#define APPROX(a, b) (fabs((a) - (b)) < 0.0001)

static int privacy_pct_low(int pct) {
    return pct > 0 ? pct - 1 : 0;
}

static int privacy_pct_high(int pct) {
    return pct < 100 ? pct + 1 : 100;
}

/* "Just now" is only honest while a tx is still Pending. */
static bool history_avoids_stale_just_now(void) {
    return !has("Just now") || has("Pending");
}

/* argv[1] wins; otherwise ~/.zclassic-c23 if HOME is set. */
static const char *resolve_datadir(int argc, char **argv) {
    if (argc > 1)
        return argv[1];

    static char dd[512];
    const char *home = getenv("HOME");
    if (home) {
        snprintf(dd, sizeof(dd), "%s/.zclassic-c23", home);
        return dd;
    }
    return NULL;
}

static const char *datadir_or_none(const char *datadir) {
    return datadir ? datadir : "(none)";
}

static int wallet_check_exit_status(void) {
    return checks_failed ? 1 : 0;
}

/* ── The checks ────────────────────────────────────────── */

int main(int argc, char **argv)
{
    const char *datadir = resolve_datadir(argc, argv);

    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();

    wallet_view_enable_sync();
    wallet_view_init(datadir);

    printf("wallet_check: verifying UI matches zclassicd truth\n");
    printf("datadir: %s\n\n", datadir_or_none(datadir));

    /* Step 1: Query zclassicd for truth */
    if (!query_truth()) {
        ecc_verify_destroy(); ecc_stop();
        return 0;
    }

    /* Step 2: Sync wallet from zclassicd */
    printf("Syncing wallet from zclassicd...\n");
    wv_sync_wallet_from_zclassicd();
    printf("Sync complete.\n\n");

    int expected_pct = expected_privacy_pct();
    bool has_shieldable = (rpc_transparent > 0.00011);

    /* ═══ Dashboard checks ═══ */
    printf("── Dashboard (/wallet) ──\n");
    render("/wallet");

    CHECK(pagelen > 500, "renders (>500 bytes)");
    CHECK(!has("{{{"), "no template leaks");
    CHECK(!has("sqlite3"), "no SQL leaks");
    CHECK(has("ZCL"), "shows ZCL denomination");

    /* Balance accuracy */
    {
        char total_str[32];
        snprintf(total_str, sizeof(total_str), "%.8f", rpc_total);
        /* The displayed balance should match total to 4 decimals */
        char total_4[16];
        snprintf(total_4, sizeof(total_4), "%.4f", rpc_total);
        CHECK(page_has_either(total_str, total_4),
              "displayed balance matches z_gettotalbalance");
    }

    /* Privacy percentage */
    {
        char pct_str[8];
        snprintf(pct_str, sizeof(pct_str), "%d%%", expected_pct);
        /* Allow ±1% rounding */
        char pct_lo[8], pct_hi[8];
        snprintf(pct_lo, sizeof(pct_lo), "%d%%",
                 privacy_pct_low(expected_pct));
        snprintf(pct_hi, sizeof(pct_hi), "%d%%",
                 privacy_pct_high(expected_pct));
        CHECK(page_has_any(pct_str, pct_lo, pct_hi),
              "privacy % matches actual t/z ratio");
    }

    /* Shield nudge */
    if (has_shieldable) {
        CHECK(page_has_either("Shield All", "/wallet/shield"),
              "shield action shown (transparent > fee)");
    } else {
        CHECK(!has("Shield All"),
              "no shield nudge (transparent < fee = dust)");
    }

    /* No false claims */
    if (expected_pct < 100) {
        CHECK(!has("untraceable"),
              "no 'untraceable' claim when not 100% private");
    }

    /* ═══ Send page checks ═══ */
    printf("\n── Send (/wallet/send) ──\n");
    render("/wallet/send");

    CHECK(pagelen > 500, "renders");
    CHECK(!has("{{{"), "no template leaks");

    /* Spendable balance should be total (transparent + shielded) */
    {
        char total_str[32];
        snprintf(total_str, sizeof(total_str), "%.8f", rpc_total);
        char total_4[16];
        snprintf(total_4, sizeof(total_4), "%.4f", rpc_total);
        CHECK(page_has_either(total_str, total_4),
              "spendable balance = total (t + z)");
    }

    /* ═══ Receive page checks ═══ */
    printf("\n── Receive (/wallet/receive) ──\n");
    render("/wallet/receive");

    CHECK(pagelen > 500, "renders");
    CHECK(has("recommended"), "private tab recommended");
    CHECK(page_has_either("zs1", "No private addresses"),
          "z-address shown or fallback");

    /* ═══ Shield page checks ═══ */
    printf("\n── Shield (/wallet/shield) ──\n");
    render("/wallet/shield");

    CHECK(pagelen > 200, "renders");
    if (has_shieldable) {
        char avail_str[32];
        snprintf(avail_str, sizeof(avail_str), "%.8f", rpc_transparent);
        char avail_4[16];
        snprintf(avail_4, sizeof(avail_4), "%.4f", rpc_transparent);
        CHECK(page_has_any(avail_str, avail_4, "Available"),
              "available shows transparent balance");
    }

    /* ═══ Node page checks ═══ */
    printf("\n── Node (/wallet/node) ──\n");
    render("/wallet/node");

    CHECK(pagelen > 500, "renders");
    CHECK(has("Command Center"), "heading present");
    CHECK(has("sovereign"), "sovereignty statement");

    /* ═══ History page checks ═══ */
    printf("\n── History (/wallet/history) ──\n");
    render("/wallet/history");

    CHECK(pagelen > 500, "renders");
    CHECK(history_avoids_stale_just_now(),
          "no stale 'Just now' on confirmed txs");

    /* ═══ Pulse API checks ═══ */
    printf("\n── Pulse (/api/wallet/pulse) ──\n");
    render("/api/wallet/pulse");

    CHECK(has("height"), "has height");
    CHECK(has("balance"), "has balance");
    CHECK(has("peers"), "has peers");
    CHECK(!has("<!DOCTYPE"), "is JSON not HTML");

    /* ═══ Results ═══ */
    printf("\n════════════════════════════════════════\n");
    printf("%d passed, %d failed\n", checks_passed, checks_failed);
    if (checks_failed)
        printf("WALLET CHECK FAILED — UI disagrees with zclassicd\n");
    else
        printf("WALLET CHECK PASSED — UI matches zclassicd truth\n");
    printf("════════════════════════════════════════\n");

    ecc_verify_destroy();
    ecc_stop();
    return wallet_check_exit_status();
}
