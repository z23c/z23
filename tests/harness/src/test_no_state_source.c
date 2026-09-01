/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_no_state_source — the LOUD no-state-source blocker. A fresh node with
 * NO bundle, NO fetchable manifest, and
 * NO block bodies must not silently fall through to folding an empty genesis
 * datadir and pin on a MISLEADING downstream symptom (proof_validate.stale_upstream_
 * hash at h=0). boot_select_state_source must name the REAL problem the
 * instant it concludes with no state source — the typed bootstrap.no_state_source
 * blocker — carrying the fetch outcome, bundle status, and the operator hint,
 * and clear it on the honest witness (H* climb / a state source landing), never
 * on wall time.
 *
 * Scenarios:
 *   (a) fresh, genesis-only, opt-out fetch: boot_select_state_source RAISES
 *       bootstrap.no_state_source with reason fetch=skipped bundle=none + the
 *       -fileservice / bundles/ hint; the condition's detect() sees it.
 *   (b) witness: NOT resolved at the genesis baseline; resolved (and the blocker
 *       cleared) the instant the provable tip climbs past it; detect() goes
 *       false after the clear.
 *   (c) warm reboot (active chain already past genesis): NO raise — the
 *       no-meaningful-chain-state guard is not tripped by a synced node.
 *
 * make t ONLY=no_state_source
 */

#include "test/test_core.h"

#include "chain/chain.h"                       /* block_index_init */
#include "conditions/no_state_source.h"
#include "config/boot.h"                        /* struct app_context */
#include "config/consensus_state_install_runtime.h" /* boot_select_state_source */
#include "core/uint256.h"
#include "jobs/reducer_frontier.h"             /* provable-tip cache drive */
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define NSS_ID "bootstrap.no_state_source"

#define NSS_CHECK(name, expr) do {                         \
    printf("no_state_source: %s... ", (name));              \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

static int nss_mkdir_p(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    return 0; /* EEXIST or best-effort — the fixture only needs it to exist */
}

/* Snapshot the reason string of the raised blocker (empty if absent). */
static void nss_reason(char *out, size_t cap)
{
    out[0] = '\0';
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strcmp(snaps[i].id, NSS_ID) == 0) {
            snprintf(out, cap, "%s", snaps[i].reason);
            return;
        }
    }
}

/* ── (a) fresh, genesis-only, opt-out fetch → raise ─────────────────────────── */

static int test_nss_scenario_a_raise(void)
{
    int failures = 0;

    blocker_module_init();
    no_state_source_test_reset();
    reducer_frontier_provable_tip_reset();

    /* Force the DB-fallback path in active_chain_height to read c->height (a
     * fresh main_state, -1) rather than a stale prior-test progress store. */
    progress_store_close();

    char dir[256];
    nss_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "no_state_source", "a_raise");
    nss_mkdir_p(dir);

    /* Opt out of the network fetch so the boot seam is hermetic. */
    setenv("ZCL_NO_BUNDLE_FETCH", "1", 1);

    struct main_state ms;
    main_state_init(&ms);

    struct app_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = dir;

    struct boot_state_source_selection ssel;
    memset(&ssel, 0, sizeof(ssel));
    boot_select_state_source(NULL, &ms, &ctx, &ssel);

    NSS_CHECK("(a) no state source selected", !ssel.auto_installed_bundle &&
              !ssel.consumed_auto_refold && !ssel.do_from_anchor);
    NSS_CHECK("(a) bootstrap.no_state_source blocker raised",
              blocker_exists(NSS_ID));
    NSS_CHECK("(a) blocker class is DEPENDENCY (waits on a source, not a TTL)",
              blocker_class_for(NSS_ID) == (int)BLOCKER_DEPENDENCY);

    char reason[BLOCKER_REASON_MAX];
    nss_reason(reason, sizeof(reason));
    NSS_CHECK("(a) reason names fetch=skipped (opt-out)",
              strstr(reason, "fetch=skipped") != NULL);
    NSS_CHECK("(a) reason names bundle=none",
              strstr(reason, "bundle=none") != NULL);
    NSS_CHECK("(a) reason carries the -fileservice operator hint",
              strstr(reason, "-fileservice=HOST:PORT") != NULL);
    NSS_CHECK("(a) reason carries the bundles/ drop-in hint",
              strstr(reason, "<datadir>/bundles/") != NULL);
    if (strstr(reason, "fetch=skipped") == NULL)
        printf("  >> (a) reason: %s\n", reason);

    NSS_CHECK("(a) condition detect() sees the raised blocker",
              no_state_source_test_detect());

    no_state_source_test_reset();
    unsetenv("ZCL_NO_BUNDLE_FETCH");
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── (b) witness clears on H* climb, never wall time ────────────────────────── */

static int test_nss_scenario_b_witness_clears_on_hstar_climb(void)
{
    int failures = 0;

    blocker_module_init();
    no_state_source_test_reset();
    reducer_frontier_provable_tip_reset(); /* cached H* -> 0 (genesis baseline) */

    char dir[256];
    nss_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "no_state_source", "b_witness");
    nss_mkdir_p(dir);
    /* A datadir with no sovereign marker so the witness reads only the H* path. */
    no_state_source_test_set_datadir(dir);

    struct no_state_source_facts f = {
        .fetch = NO_STATE_SOURCE_FETCH_NO_SEED,
        .bundle = NO_STATE_SOURCE_BUNDLE_NONE,
        .baseline_hstar = 0, /* fresh node baseline */
    };
    no_state_source_raise(&f);
    NSS_CHECK("(b) blocker raised", blocker_exists(NSS_ID));

    /* Provable tip still at the baseline → NOT resolved, blocker stands. */
    NSS_CHECK("(b) witness false while H* == baseline (no wall-time clear)",
              !no_state_source_test_witness());
    NSS_CHECK("(b) blocker still stands after a non-witnessing tick",
              blocker_exists(NSS_ID));

    /* Fold advanced past the baseline → resolved, blocker cleared. */
    reducer_frontier_provable_tip_set(128);
    NSS_CHECK("(b) witness true once H* climbs past baseline",
              no_state_source_test_witness());
    NSS_CHECK("(b) blocker cleared on the H* witness",
              !blocker_exists(NSS_ID));
    NSS_CHECK("(b) condition detect() goes false after the clear",
              !no_state_source_test_detect());

    reducer_frontier_provable_tip_reset();
    no_state_source_test_reset();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── (c) warm reboot (active chain past genesis) → no raise ──────────────────── */

static int test_nss_scenario_c_warm_reboot_no_raise(void)
{
    int failures = 0;
    enum { N = 3 };

    blocker_module_init();
    no_state_source_test_reset();
    progress_store_close();

    char dir[256];
    nss_mkdir_p("./test-tmp");
    test_fmt_tmpdir(dir, sizeof(dir), "no_state_source", "c_warm");
    nss_mkdir_p(dir);
    setenv("ZCL_NO_BUNDLE_FETCH", "1", 1);

    struct main_state ms;
    main_state_init(&ms);

    /* Synthetic header window heights 0..N-1 (pprev-chained) — the warm-reboot
     * shape active_chain_height reports > genesis for, so the guard holds. */
    static struct block_index nss_blocks[N];
    static struct uint256     nss_hashes[N];
    for (int i = 0; i < N; i++) {
        block_index_init(&nss_blocks[i]);
        memset(&nss_hashes[i], 0, sizeof(nss_hashes[i]));
        nss_hashes[i].data[0] = (uint8_t)(i & 0xFF);
        nss_hashes[i].data[1] = (uint8_t)((i >> 8) & 0xFF);
        nss_hashes[i].data[2] = 0x5C;     /* tag distinct from other fixtures */
        nss_blocks[i].phashBlock = &nss_hashes[i];
        nss_blocks[i].hashBlock  = nss_hashes[i];
        nss_blocks[i].nHeight = i;
        if (i > 0) nss_blocks[i].pprev = &nss_blocks[i - 1];
    }
    active_chain_move_window_tip(&ms.chain_active, &nss_blocks[N - 1]);
    NSS_CHECK("(c) active chain window is past genesis",
              active_chain_height(&ms.chain_active) > 0);

    struct app_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = dir;

    struct boot_state_source_selection ssel;
    memset(&ssel, 0, sizeof(ssel));
    boot_select_state_source(NULL, &ms, &ctx, &ssel);

    NSS_CHECK("(c) NO no_state_source blocker on a warm reboot",
              !blocker_exists(NSS_ID));

    no_state_source_test_reset();
    unsetenv("ZCL_NO_BUNDLE_FETCH");
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_no_state_source(void);
int test_no_state_source(void)
{
    int failures = 0;
    printf("\n=== test_no_state_source: a boot with no fast-start state source "
           "NAMES the real cause (bootstrap.no_state_source) instead of pinning "
           "on a downstream symptom ===\n");

    failures += test_nss_scenario_a_raise();
    failures += test_nss_scenario_b_witness_clears_on_hstar_climb();
    failures += test_nss_scenario_c_warm_reboot_no_raise();

    printf("=== test_no_state_source complete: %d failure(s) ===\n", failures);
    return failures;
}
