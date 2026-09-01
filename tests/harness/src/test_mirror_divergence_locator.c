/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the fail-loud validation pack check 6
 * (engine/services/src/mirror_divergence_locator.c) with injected probes:
 *
 *   - agree-all (transient disagreement re-verifies as agreement):
 *     abort, no blocker, no event storm (non-fire);
 *   - diverge-at-k: bisect lands exactly on k, PERMANENT
 *     mirror.divergence_located blocker + HOLD at k, probe count within
 *     the ~2*22 bound;
 *   - RPC error mid-bisect: silent abort, no blocker;
 *   - rate limit: a second locate inside the window is skipped;
 *   - crash-only: every outcome is a return code, process alive. */

#include "test/test_core.h"
#include "json/json.h"

#include "services/mirror_divergence_locator.h"
#include "util/blocker.h"
#include "validation/chain_linkage_check.h"

#include <stdio.h>
#include <string.h>

#define MDL_CHECK(name, expr) do {                          \
    printf("mirror_divergence_locator: %s... ", (name));    \
    if (expr) printf("OK\n");                                 \
    else { printf("FAIL\n"); failures++; }                    \
} while (0)

/* Probe model: local and remote agree below g_div_height, disagree at and
 * above it. g_div_height < 0 = full agreement. g_fail_at >= 0 makes the
 * REMOTE probe fail at that height (RPC error). */
static int g_div_height = -1;
static int g_fail_at = -1;

static bool probe_local_mock(int height, char out_hex[65])
{
    snprintf(out_hex, 65,
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%08x",
             height);
    return true;
}

static bool probe_remote_mock(int height, char out_hex[65])
{
    if (g_fail_at >= 0 && height == g_fail_at)
        return false;
    if (g_div_height >= 0 && height >= g_div_height)
        snprintf(out_hex, 65,
                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb%08x",
                 height);
    else
        snprintf(out_hex, 65,
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa%08x",
                 height);
    return true;
}

int test_mirror_divergence_locator(void)
{
    printf("\n=== mirror_divergence_locator tests ===\n");
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    chain_linkage_reset_for_testing();
    mirror_divergence_reset_for_testing();
    mirror_divergence_set_probes_for_testing(probe_local_mock,
                                             probe_remote_mock);

    /* 1. Transient: the reported disagreement re-verifies as agreement
     * (flap) -> abort, no blocker. */
    {
        g_div_height = -1;
        g_fail_at = -1;
        int r = mirror_divergence_locate(3140000);
        MDL_CHECK("transient flap: abort, no blocker",
                  r == -1 &&
                  !blocker_exists("mirror.divergence_located") &&
                  !chain_linkage_hold_active());
    }

    /* 2. Real divergence at k=3137373: bisect finds exactly k. */
    {
        mirror_divergence_reset_for_testing();
        g_div_height = 3137373;
        g_fail_at = -1;
        int r = mirror_divergence_locate(3143355);
        MDL_CHECK("diverge-at-k: located exactly", r == 3137373);
        MDL_CHECK("PERMANENT mirror.divergence_located registered",
                  blocker_exists("mirror.divergence_located") &&
                  blocker_class_for("mirror.divergence_located") ==
                      BLOCKER_PERMANENT);
        MDL_CHECK("HOLD latched at first_div",
                  chain_linkage_hold_active() &&
                  chain_linkage_hold_refuse_from() == 3137373);
        int probes = mirror_divergence_probes_last_run_for_testing();
        MDL_CHECK("probe budget: <= 2*(22+2) probes", probes > 0 &&
                  probes <= 48);

        /* 3. Rate limit: immediate re-locate is skipped. */
        int r2 = mirror_divergence_locate(3143355);
        MDL_CHECK("rate limit: immediate re-locate skipped", r2 == -1);
        mirror_divergence_reset_for_testing();
    }

    /* 4. Divergence from genesis: even h=0 disagrees -> first_div=0,
     * blocker + page but NO HOLD (the reference is on a different
     * network; our compiled-in genesis cannot be poisoned — a
     * misconfigured zclassicd must never freeze this node). */
    {
        mirror_divergence_reset_for_testing();
        g_div_height = 0;
        int r = mirror_divergence_locate(1000);
        MDL_CHECK("diverged-from-genesis: first_div=0", r == 0);
        MDL_CHECK("genesis divergence: blocker yes, HOLD no",
                  blocker_exists("mirror.divergence_located") &&
                  !chain_linkage_hold_active());
        mirror_divergence_reset_for_testing();
    }

    /* 5. RPC error mid-bisect: silent abort, no blocker. */
    {
        mirror_divergence_reset_for_testing();
        g_div_height = 500000;
        /* hi=1000000 disagrees; first mid-probe is 500000 — fail there */
        g_fail_at = 500000;
        int r = mirror_divergence_locate(1000000);
        MDL_CHECK("rpc error mid-bisect: abort, no blocker",
                  r == -1 &&
                  !blocker_exists("mirror.divergence_located") &&
                  !chain_linkage_hold_active());
        mirror_divergence_reset_for_testing();
    }

    /* 6. HEALTHY TRANSIENT FORK (the FP class): divergence exactly at
     * the tip — located but NOT escalated (no blocker, no HOLD). A HOLD
     * here would refuse the resolving reorg at h. */
    {
        mirror_divergence_reset_for_testing();
        g_div_height = 3143355;
        g_fail_at = -1;
        int r = mirror_divergence_locate(3143355);
        MDL_CHECK("tip fork: located, returned", r == 3143355);
        MDL_CHECK("tip fork: NO blocker, NO HOLD (healthy-fork window)",
                  !blocker_exists("mirror.divergence_located") &&
                  !chain_linkage_hold_active());

        /* 6b. Fork resolves (next verify agrees at the same tip):
         * pending divergence clears; nothing ever latched. */
        mirror_divergence_note_agreement(3143356);
        int r2 = mirror_divergence_locate(3143355);
        /* rate-limited (window not aged): skipped — and still no latch */
        MDL_CHECK("tip fork resolved: still nothing latched",
                  r2 == -1 &&
                  !blocker_exists("mirror.divergence_located") &&
                  !chain_linkage_hold_active());
        mirror_divergence_reset_for_testing();
    }

    /* 7. WEDGED-AT-TIP persistence: the SAME tip-window first_div across
     * repeated locates spanning >= MDL_CONFIRM_PERSIST_SECS escalates. */
    {
        mirror_divergence_reset_for_testing();
        g_div_height = 3143355;
        int r = mirror_divergence_locate(3143355);
        MDL_CHECK("persist: first locate pends, no latch",
                  r == 3143355 &&
                  !blocker_exists("mirror.divergence_located"));
        /* age past both the rate limit and the persistence threshold */
        mirror_divergence_backdate_pending_for_testing(
            MDL_CONFIRM_PERSIST_SECS + 1);
        r = mirror_divergence_locate(3143355);
        MDL_CHECK("persist: unmoving first_div escalates after persist "
                  "window",
                  r == 3143355 &&
                  blocker_exists("mirror.divergence_located") &&
                  chain_linkage_hold_active() &&
                  chain_linkage_hold_refuse_from() == 3143355);

        /* 7b. Mirror agreement at/above the located height self-clears
         * the latched blocker + HOLD (e.g. zclassicd adopted our branch). */
        mirror_divergence_note_agreement(3143356);
        MDL_CHECK("persist: agreement self-clears blocker + HOLD",
                  !blocker_exists("mirror.divergence_located") &&
                  !chain_linkage_hold_active());
        mirror_divergence_reset_for_testing();
    }

    /* 8. Agreement BELOW a latched deep divergence does NOT clear it. */
    {
        mirror_divergence_reset_for_testing();
        g_div_height = 3137373;
        int r = mirror_divergence_locate(3143355);
        MDL_CHECK("below-agree: deep divergence latched", r == 3137373 &&
                  blocker_exists("mirror.divergence_located"));
        mirror_divergence_note_agreement(3137000); /* below first_div */
        MDL_CHECK("below-agree: agreement below first_div keeps the latch",
                  blocker_exists("mirror.divergence_located") &&
                  chain_linkage_hold_active());
        mirror_divergence_reset_for_testing();
    }

    /* 9. dump_state_json (`z23 dumpstate mirror_divergence`) reflects
     * a located-and-latched divergence. */
    {
        mirror_divergence_reset_for_testing();
        g_div_height = 3137373;
        int r = mirror_divergence_locate(3143355);
        MDL_CHECK("dump setup: located k", r == 3137373);

        struct json_value v = {0};
        json_set_object(&v);
        bool ok = mirror_divergence_dump_state_json(&v, NULL);
        const struct json_value *latched = json_get(&v, "divergence_latched");
        const struct json_value *first_div = json_get(&v, "last_first_div");
        bool shape_ok = ok && latched && json_get_bool(latched) == true &&
                        first_div && json_get_int(first_div) == 3137373;
        json_free(&v);
        MDL_CHECK("dump_state_json reports divergence_latched + last_first_div",
                  shape_ok);
        mirror_divergence_reset_for_testing();
    }

    /* crash-only: all outcomes above were return codes; reaching here is
     * the alive proof. */
    mirror_divergence_set_probes_for_testing(NULL, NULL);
    blocker_reset_for_testing();
    chain_linkage_reset_for_testing();
    return failures;
}
