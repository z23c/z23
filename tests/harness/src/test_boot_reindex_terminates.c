/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for the boot crash-only reindex TERMINATION invariant.
 *
 * At BOOT_AUTO_REINDEX_MAX+1 the exhausted handler REWRITES the sentinel as a
 * TERMINAL marker (count = -1) instead of deleting it, so a stable corrupt
 * blocks/ cannot re-arm the budget and loop; boot_auto_reindex_pending() and
 * the crash-only consume treat the terminal marker as "do not re-request".
 *
 * (A) the cap terminates on a fixed anchor; (B) a recoverable datadir is not
 * falsely exhausted and the budget keys on a stable identity; (G)-(K) the
 * budget is counted against the FINDING (not the request file, which sibling
 * paths delete) and link-damage findings do not arm -reindex-chainstate.
 */

#include "test/test_core.h"

#include "config/boot_crashonly.h"
#include "config/boot_error.h"
#include "storage/boot_auto_reindex.h"
#include "platform/environment_compat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define BR_CHECK(name, expr) do {                          \
    printf("  boot_reindex_term: %s... ", (name));         \
    if (expr) printf("OK\n");                              \
    else { printf("FAIL\n"); failures++; }                \
} while (0)

static int mkdir_p_br(const char *p)
{
    if (mkdir(p, 0700) == 0) return 0;
    return (errno == EEXIST) ? 0 : -1;
}

static bool br_exists(const char *dir, const char *leaf)
{
    char p[512];
    struct stat st;
    snprintf(p, sizeof(p), "%s/%s", dir, leaf);
    return stat(p, &st) == 0;
}

static void br_env(const char *name, const char *value)
{
    if (value) (void)platform_environment_set(name, value, 1);
    else (void)unsetenv(name);
}

/* The 2026-10-22 canonical-datadir write: under the test harness the request
 * writers refuse the canonical datadir (and anything under it, or an alias of
 * it) and still serve a fixture datadir; with the harness variables absent
 * (production) the same path is written exactly as before. */
static int br_writer_guard(void)
{
    int failures = 0;
    char canon[256], other[256], alias[300];
    test_fmt_tmpdir(canon, sizeof(canon), "boot_reindex_guard", "canon");
    test_fmt_tmpdir(other, sizeof(other), "boot_reindex_guard", "fixture");
    mkdir_p_br(canon);
    mkdir_p_br(other);
    snprintf(alias, sizeof(alias), "%s.alias", canon);
    (void)unlink(alias);
#if defined(_WIN32)
    bool aliased = false;
#else
    bool aliased = symlink(canon, alias) == 0;
#endif

    char *saved_h = getenv("ZCL_TEST_HARNESS")
        ? strdup(getenv("ZCL_TEST_HARNESS")) : NULL;
    char *saved_c = getenv("ZCL_TEST_CANONICAL_DATADIR")
        ? strdup(getenv("ZCL_TEST_CANONICAL_DATADIR")) : NULL;

    br_env("ZCL_TEST_HARNESS", "1");
    br_env("ZCL_TEST_CANONICAL_DATADIR", canon);
    BR_CHECK("guard: request refused on the canonical datadir",
             boot_auto_reindex_request(
                 canon, 7, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED) == 0);
    BR_CHECK("guard: no request file appeared there",
             !br_exists(canon, "auto_reindex_request"));
    BR_CHECK("guard: request refused through a symlink alias",
             !aliased || boot_auto_reindex_request(
                 alias, 7, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED) == 0);
    BR_CHECK("guard: terminal marker refused",
             !boot_auto_reindex_mark_terminal(canon, 7));
    BR_CHECK("guard: repair-episode note refused",
             boot_repair_episode_note(canon, 99) == 0 &&
             !br_exists(canon, "boot_repair_episode"));
    BR_CHECK("guard: nothing was armed", !boot_auto_reindex_pending(canon));
    BR_CHECK("guard: a fixture datadir is still written",
             boot_auto_reindex_request(
                 other, 7, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED) == 1 &&
             boot_auto_reindex_pending(other));
    boot_auto_reindex_clear(other);
    BR_CHECK("guard: a fixture datadir is still cleared",
             !boot_auto_reindex_pending(other));

    /* Production: no harness variable, no behaviour change. */
    br_env("ZCL_TEST_HARNESS", NULL);
    BR_CHECK("guard: without the harness variable the same path is written",
             boot_auto_reindex_request(
                 canon, 7, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED) == 1);
    /* An armed request on the canonical path is not cleared by a test. */
    br_env("ZCL_TEST_HARNESS", "1");
    boot_auto_reindex_clear(canon);
    BR_CHECK("guard: clear refused on the canonical datadir",
             br_exists(canon, "auto_reindex_request"));

    br_env("ZCL_TEST_HARNESS", saved_h);
    br_env("ZCL_TEST_CANONICAL_DATADIR", saved_c);
    free(saved_h);
    free(saved_c);
    if (aliased) (void)unlink(alias);
    test_cleanup_tmpdir(canon);
    test_cleanup_tmpdir(other);
    return failures;
}

static int br_term_fixed_anchor(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (A) The cap TERMINATES on a FIXED anchor: count climbs 1..MAX, then
     * the exhausted handler writes the TERMINAL marker, and consume stops
     * re-requesting (no unbounded loop).
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "fixed");
        mkdir_p_br(dir);

        const int32_t ANCHOR = 1234567;

        /* Attempts 1..MAX return a climbing count and PEND as reindex requests. */
        bool climb_ok = true;
        bool pend_ok = true;
        for (int i = 1; i <= BOOT_AUTO_REINDEX_MAX; i++) {
            int n = boot_auto_reindex_request(dir, ANCHOR, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
            climb_ok &= (n == i);
            pend_ok &= boot_auto_reindex_pending(dir);
        }
        BR_CHECK("attempts 1..MAX return a climbing count", climb_ok);
        BR_CHECK("attempts 1..MAX each PEND as a reindex request", pend_ok);
        BR_CHECK("not terminal while budget remains",
                 !boot_auto_reindex_is_terminal(dir));

        /* MAX+1 is over the cap: the crash-only handler must return false
         * (stay up degraded) and persist the terminal marker. */
        bool exit_boot = boot_crashonly_handle_unrecoverable(
            dir, (int)ANCHOR, /*zero_nbits=*/0, /*mismatches=*/0,
            /*first_mismatch_h=*/0, /*reindex_executable=*/true);
        BR_CHECK("exhausted handler returns false (stay-up-degraded, no exit)",
                 !exit_boot);
        BR_CHECK("exhausted writes the TERMINAL marker (NOT deleted)",
                 boot_auto_reindex_is_terminal(dir));

        /* After the terminal marker pending() and consume must both be false. */
        BR_CHECK("terminal: pending() is false (consume stops re-requesting)",
                 !boot_auto_reindex_pending(dir));
        BR_CHECK("terminal: consume_reindex_request returns false (no loop)",
                 !boot_crashonly_consume_reindex_request(dir));

        /* A fresh request at the SAME anchor stays terminal; the sentinel is
         * not deleted. */
        int after = boot_auto_reindex_request(dir, ANCHOR, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("terminal: request does NOT re-arm (returns TERMINAL)",
                 after == BOOT_AUTO_REINDEX_TERMINAL);
        BR_CHECK("terminal: still terminal after a re-request attempt",
                 boot_auto_reindex_is_terminal(dir));
        BR_CHECK("terminal: still not pending after a re-request attempt",
                 !boot_auto_reindex_pending(dir));

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_recoverable(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (B) A RECOVERABLE datadir is NOT falsely exhausted: terminal fires ONLY
     * after BOOT_AUTO_REINDEX_MAX failures at a stable anchor.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "recoverable");
        mkdir_p_br(dir);

        const int32_t ANCHOR = 7654321;

        int n1 = boot_auto_reindex_request(dir, ANCHOR, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("recoverable: attempt 1 -> count 1, pends, not terminal",
                 n1 == 1 && boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* Recovery on attempt 2 clears the budget; the next wedge starts a
         * fresh episode at count=1 (only EXHAUSTION must not clear). */
        BR_CHECK("recoverable: attempt 1 consume requests reindex (true)",
                 boot_crashonly_consume_reindex_request(dir));
        int n2 = boot_auto_reindex_request(dir, ANCHOR, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("recoverable: attempt 2 -> count 2 (NOT falsely exhausted)",
                 n2 == 2 && boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* Clean boot clears the budget (the rebuild converged). */
        boot_crashonly_clear(dir);
        BR_CHECK("recoverable: clean boot clears -> not pending, not terminal",
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* A genuinely-new wedge starts a fresh count=1. */
        int n3 = boot_auto_reindex_request(dir, ANCHOR + 50, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("recoverable: post-clear new wedge starts fresh at count 1",
                 n3 == 1);

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_moving_tip(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (C) Moving-tip budget cannot re-arm the cap: the budget keys on the
     * MINIMUM anchor seen this episode.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "moving");
        mkdir_p_br(dir);

        /* A different (lower) tip on each boot of the SAME corrupt episode. */
        int n_a = boot_auto_reindex_request(dir, 5000, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        int n_b = boot_auto_reindex_request(dir, 4990, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        int n_c = boot_auto_reindex_request(dir, 4980, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("moving tip: count climbs 1,2,3 despite a moving anchor",
                 n_a == 1 && n_b == 2 && n_c == 3);
        BR_CHECK("moving tip: budget reaches the cap (== MAX)",
                 n_c == BOOT_AUTO_REINDEX_MAX);

        /* Over the cap: the exhausted handler marks terminal. */
        bool exit_boot = boot_crashonly_handle_unrecoverable(
            dir, 4970, /*zero_nbits=*/0, /*mismatches=*/0,
            /*first_mismatch_h=*/0, /*reindex_executable=*/true);
        BR_CHECK("moving tip: exhausted handler stays-up-degraded (false)",
                 !exit_boot);
        BR_CHECK("moving tip: terminal marker persisted (loop terminated)",
                 boot_auto_reindex_is_terminal(dir) &&
                 !boot_auto_reindex_pending(dir));

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_covered_anchor(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (D) A stale tip-height request self-clears once durable coins authority
     * COVERS its anchor: progress above the anchor, or a HASH-VERIFIED
     * coins-best exactly AT it. An unverified at-anchor coins-best keeps
     * consuming. Boot-storage anchor 0 and terminal markers are not cleared.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "covered");
        mkdir_p_br(dir);

        const int32_t ANCHOR = 4321;
        int n1 = boot_auto_reindex_request(dir, ANCHOR, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("covered: request starts pending",
                 n1 == 1 && boot_auto_reindex_pending(dir));
        BR_CHECK("covered: below-anchor coins-best does not clear (even verified)",
                 !boot_crashonly_clear_reindex_request_if_covered(
                     dir, ANCHOR - 1, true) &&
                 boot_auto_reindex_pending(dir));
        BR_CHECK("covered: at-anchor but UNVERIFIED keeps request (maybe torn)",
                 !boot_crashonly_clear_reindex_request_if_covered(
                     dir, ANCHOR, false) &&
                 boot_auto_reindex_pending(dir));
        BR_CHECK("covered: at-anchor and HASH-VERIFIED clears "
                 "(transparent set intact — wiping it would be destructive)",
                 boot_crashonly_clear_reindex_request_if_covered(
                     dir, ANCHOR, true) &&
                 !boot_auto_reindex_pending(dir));

        /* Above-anchor progress clears regardless of hash verification. */
        (void)boot_auto_reindex_request(dir, ANCHOR, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("covered: above-anchor clears stale request (reducer moved on)",
                 boot_crashonly_clear_reindex_request_if_covered(
                     dir, ANCHOR + 1, false) &&
                 !boot_auto_reindex_pending(dir));

        int n2 = boot_auto_reindex_request(dir, 0, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("covered: boot-storage anchor 0 starts pending",
                 n2 == 1 && boot_auto_reindex_pending(dir));
        BR_CHECK("covered: boot-storage anchor 0 is never stale-cleared",
                 !boot_crashonly_clear_reindex_request_if_covered(
                     dir, 999999, true) &&
                 boot_auto_reindex_pending(dir));
        boot_auto_reindex_clear(dir);

        (void)boot_auto_reindex_mark_terminal(dir, ANCHOR);
        BR_CHECK("covered: terminal marker is not stale-cleared",
                 !boot_crashonly_clear_reindex_request_if_covered(
                     dir, ANCHOR + 100, true) &&
                 boot_auto_reindex_is_terminal(dir));

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_storage_gate(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (E) The boot-storage gate REFUSES to arm on an unreadable-genesis
     * (bodyless) datadir: reindex_executable=false writes no sentinel, CLEARS
     * any stale one, and PARKS. reindex_executable=true still arms in budget.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "storage_gate");
        mkdir_p_br(dir);

        enum boot_gate_action a = boot_crashonly_storage_gate(
            dir, "coins_view_integrity", /*reindex_executable=*/false);
        BR_CHECK("storage gate: unreadable genesis parks (no crash-loop)",
                 a == BOOT_GATE_PARK_DEGRADED);
        BR_CHECK("storage gate: unreadable genesis does NOT arm a reindex",
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* A stale sentinel from a prior boot is cleared by the refusal. */
        (void)boot_auto_reindex_request(dir, 0, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("storage gate: stale sentinel present before refusal",
                 boot_auto_reindex_pending(dir));
        a = boot_crashonly_storage_gate(dir, "coins_view_integrity",
                                        /*reindex_executable=*/false);
        BR_CHECK("storage gate: refusal clears the stale sentinel (no re-arm)",
                 a == BOOT_GATE_PARK_DEGRADED &&
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* Executable genesis arms within budget. */
        a = boot_crashonly_storage_gate(dir, "coins_view_integrity",
                                        /*reindex_executable=*/true);
        BR_CHECK("storage gate: executable genesis arms (exit-for-reindex)",
                 a == BOOT_GATE_EXIT_FOR_REINDEX &&
                 boot_auto_reindex_pending(dir));

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_body_coverage(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (F) The body-coverage gate refuses a from-genesis reindex when coins are
     * seeded but bodies do not cover [0..target], and CLEARS the sentinel.
     * Dense coverage, or an unseeded datadir, proceeds.
     * ────────────────────────────────────────────────────────────────── */
    {
        /* Pure predicate. */
        BR_CHECK("coverage: sparse bodies (target 3M, count ~0) insufficient",
                 !boot_reindex_body_coverage_sufficient(3000000, 0, 1));
        BR_CHECK("coverage: dense bodies (target 100k, full) sufficient",
                 boot_reindex_body_coverage_sufficient(100000, 100000, 100001));
        BR_CHECK("coverage: small tail gap still sufficient (gap-fill heals)",
                 boot_reindex_body_coverage_sufficient(100000, 99999, 100000));
        BR_CHECK("coverage: trivial span (target<=0) always sufficient",
                 boot_reindex_body_coverage_sufficient(0, 0, 0));

        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "coverage");
        mkdir_p_br(dir);

        /* a pending sentinel */
        (void)boot_auto_reindex_request(
            dir, 0, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        bool ok = boot_crashonly_reindex_coverage_ok(dir, 3000000, 0, 1,
                                                     /*coins_seeded=*/true);
        BR_CHECK("coverage decision: seeded+sparse refuses reindex", !ok);
        BR_CHECK("coverage decision: refusal clears the sentinel (no re-arm)",
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* A second boot with the same sparse coverage refuses+clears again. */
        (void)boot_auto_reindex_request(dir, 0, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        ok = boot_crashonly_reindex_coverage_ok(dir, 3000000, 0, 1, true);
        BR_CHECK("coverage decision: second boot still refuses + stays cleared",
                 !ok && !boot_auto_reindex_pending(dir));

        BR_CHECK("coverage decision: unseeded datadir proceeds (true)",
                 boot_crashonly_reindex_coverage_ok(dir, 3000000, 0, 1,
                                                    /*coins_seeded=*/false));
        BR_CHECK("coverage decision: seeded+dense proceeds (true)",
                 boot_crashonly_reindex_coverage_ok(dir, 100000, 100000, 100001,
                                                    /*coins_seeded=*/true));

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_link_damage_exhausted(const char *dir)
{
    int failures = 0;
    {
        const int TIP = 3172671;
        const int MISMATCHES = 630;
        const int FIRST_MISMATCH = 2004318;

        /* Boot 4, budget spent: stop with a typed blocker naming the datadir
         * action; never exit into another restart. */
        boot_error_reset_for_testing();
        bool exit4 = boot_crashonly_handle_unrecoverable(
            dir, TIP, 0, MISMATCHES, FIRST_MISMATCH, true);
        BR_CHECK("integrity: the 4th identical finding stops the ladder",
                 !exit4);
        BR_CHECK("integrity: exhaustion persists the terminal marker",
                 boot_auto_reindex_is_terminal(dir) &&
                 !boot_auto_reindex_pending(dir));
        {
            char render[BOOT_ERROR_RENDER_MAX];
            bool got = boot_error_last_render(render, sizeof(render)) > 0;
            BR_CHECK("integrity: exhaustion renders the TYPED blocker",
                     got && strstr(render, "BOOT_REINDEX_BUDGET_EXHAUSTED"));
            BR_CHECK("integrity: the typed blocker names the datadir action",
                     got && strstr(render, dir) && strstr(render, "next[1]"));
            BR_CHECK("integrity: the typed blocker carries the measurement",
                     got && strstr(render, "mismatches=630") &&
                     strstr(render, "first_mismatch_h=2004318"));
        }
        BR_CHECK("integrity: a typed code is latched (not the untyped FATAL)",
                 boot_error_reported() &&
                 strcmp(boot_error_first_code(),
                        "BOOT_REINDEX_BUDGET_EXHAUSTED") == 0);
        boot_error_reset_for_testing();
    }
    return failures;
}

static int br_term_link_damage(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (G) Link-damage findings, both halves.
     *
     * Verb: active_chain MISMATCHES are broken height/pprev LINKS, which
     * -reindex-chainstate cannot repair, so the gate asks for the in-place
     * band repair and keeps serving.
     *
     * Budget: the attempt count is taken against the FINDING in a ledger no
     * repair-request path clears, so the cap is reachable however the request
     * file is treated. An INDEX_INTEGRITY request survives coins-best
     * coverage, which cannot witness a block-index link.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "integrity");
        mkdir_p_br(dir);

        /* The live shape: tip above the extent (zero_nbits=0) WITH mismatches
         * below it. reindex_executable=true — blocks/ can serve the replay. */
        const int TIP = 3172671;
        const int MISMATCHES = 630;
        const int FIRST_MISMATCH = 2004318;
        /* Coins-best AT the anchor and hash-verified is still no evidence
         * about the index. */
        const int COINS_BEST = TIP;

        boot_error_reset_for_testing();

        /* Boot 1: the finding must not restart the node nor arm the
         * chainstate reindex. */
        bool exit1 = boot_crashonly_handle_unrecoverable(
            dir, TIP, /*zero_nbits=*/0, MISMATCHES, FIRST_MISMATCH,
            /*reindex_executable=*/true);
        BR_CHECK("integrity: boot 1 keeps serving (no restart-for-reindex)",
                 !exit1);
        BR_CHECK("integrity: boot 1 arms no -reindex-chainstate request",
                 !boot_auto_reindex_pending(dir));

        /* The decision carries a typed code with the measurement. */
        {
            char render[BOOT_ERROR_RENDER_MAX];
            bool got = boot_error_last_render(render, sizeof(render)) > 0;
            BR_CHECK("integrity: the in-place repair decision is TYPED",
                     got &&
                     strstr(render, "BOOT_INDEX_LINK_REPAIR_REQUESTED") &&
                     strstr(render, "mismatches=630") &&
                     strstr(render, "first_mismatch_h=2004318"));
        }

        /* A request armed for the wrong verb is retired, not consumed. */
        (void)boot_auto_reindex_request(
            dir, TIP, BOOT_AUTO_REINDEX_REASON_INDEX_INTEGRITY);
        BR_CHECK("integrity: an INDEX_INTEGRITY request survives coins-best "
                 "coverage (7d04b3662, unchanged)",
                 !boot_crashonly_clear_reindex_request_if_covered(
                     dir, COINS_BEST, /*coins_best_hash_verified=*/true) &&
                 boot_auto_reindex_pending(dir));
        BR_CHECK("integrity: above-anchor coins-best does not clear it either",
                 !boot_crashonly_clear_reindex_request_if_covered(
                     dir, COINS_BEST + 5000, true) &&
                 boot_auto_reindex_pending(dir));
        boot_error_reset_for_testing();
        (void)boot_crashonly_handle_unrecoverable(
            dir, TIP, 0, MISMATCHES, FIRST_MISMATCH, true);
        BR_CHECK("integrity: the stale wrong-verb request is retired, not "
                 "left for the next boot to consume",
                 !boot_auto_reindex_pending(dir));

        /* The budget climbs on the FINDING: each lap wipes the request file
         * and the ledger must still reach the cap. */
        uint64_t sig = 0;
        int attempts = 0;
        BR_CHECK("integrity: the durable ledger counts the finding",
                 boot_repair_episode_status(dir, &sig, &attempts) &&
                 attempts == 2 &&
                 sig == boot_repair_episode_signature(TIP, 0, MISMATCHES,
                                                      FIRST_MISMATCH));

        boot_error_reset_for_testing();
        bool exit3 = boot_crashonly_handle_unrecoverable(
            dir, TIP, 0, MISMATCHES, FIRST_MISMATCH, true);
        BR_CHECK("integrity: boot 3 is still in budget and still serving",
                 !exit3 && boot_repair_episode_status(dir, &sig, &attempts) &&
                 attempts == BOOT_REPAIR_EPISODE_MAX);

        failures += br_term_link_damage_exhausted(dir);

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_coins_shaped(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (H) The fix is NARROW: a coins-shaped wedge (derived tip above the
     * validated extent, NO mismatches) carries no integrity class and
     * coins-best coverage still retires it.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "coins_shaped");
        mkdir_p_br(dir);

        const int TIP = 800000;
        boot_error_reset_for_testing();

        bool exit1 = boot_crashonly_handle_unrecoverable(
            dir, TIP, /*zero_nbits=*/0, /*mismatches=*/0,
            /*first_mismatch_h=*/-1, /*reindex_executable=*/true);
        BR_CHECK("coins-shaped: arms a request and exits for reindex",
                 exit1 && boot_auto_reindex_pending(dir));
        BR_CHECK("coins-shaped: no mismatches => reason stays UNSPECIFIED",
                 boot_auto_reindex_reason_of(dir) ==
                     BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("coins-shaped: hash-verified coins-best at the anchor CLEARS "
                 "it (unchanged behaviour)",
                 boot_crashonly_clear_reindex_request_if_covered(dir, TIP,
                                                                 true) &&
                 !boot_auto_reindex_pending(dir));
        boot_error_reset_for_testing();

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_legacy_request(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (I) On-disk compatibility: a two-field request from an older binary
     * still parses, keeps its budget, and reads back as UNSPECIFIED.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "legacy");
        mkdir_p_br(dir);

        char path[512];
        (void)snprintf(path, sizeof(path), "%s/auto_reindex_request", dir);
        FILE *f = fopen(path, "w");
        bool wrote = f && fprintf(f, "4321 2\n") > 0;
        if (f) fclose(f);

        int32_t anchor = 0;
        int count = 0;
        BR_CHECK("legacy: a 2-field request still parses with its budget",
                 wrote && boot_auto_reindex_status(dir, &anchor, &count) &&
                 anchor == 4321 && count == 2);
        BR_CHECK("legacy: it reads back as UNSPECIFIED (historical clear)",
                 boot_auto_reindex_reason_of(dir) ==
                     BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("legacy: the next arming continues the budget at 3",
                 boot_auto_reindex_request(
                     dir, 4321, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED) == 3);

        /* Escalating a legacy request to INDEX_INTEGRITY sticks. */
        boot_auto_reindex_clear(dir);
        f = fopen(path, "w");
        if (f) { (void)fprintf(f, "4321 1\n"); fclose(f); }
        (void)boot_auto_reindex_request(
            dir, 4321, BOOT_AUTO_REINDEX_REASON_INDEX_INTEGRITY);
        BR_CHECK("legacy: escalation to INDEX_INTEGRITY sticks",
                 boot_auto_reindex_reason_of(dir) ==
                     BOOT_AUTO_REINDEX_REASON_INDEX_INTEGRITY);
        /* ...and never demotes when a later boot re-arms with a weaker class. */
        (void)boot_auto_reindex_request(
            dir, 4321, BOOT_AUTO_REINDEX_REASON_UNSPECIFIED);
        BR_CHECK("legacy: a weaker later arming does NOT demote the class",
                 boot_auto_reindex_reason_of(dir) ==
                     BOOT_AUTO_REINDEX_REASON_INDEX_INTEGRITY);

        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_holes_only(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (J) THE HOLES-ONLY RESTART LOOP. An identical post-restore finding
     * (tip_window_holes, mismatches>0, zero_nbits=0) repeated across restarts
     * must ADVANCE toward the cap whatever happens to
     * <datadir>/auto_reindex_request (sibling paths delete it), and at the
     * cap boot must STOP restarting and leave a typed blocker carrying the
     * numbers.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "holesonly");
        mkdir_p_br(dir);

        const int SOAK_TIP = 3172671;
        const int SOAK_MISMATCHES = 630;
        const int SOAK_FIRST_MISMATCH = 2004318;

        /* Six "boots" on the identical finding, each followed by a sibling
         * clear path wiping the request file. */
        bool restarted[7] = { false };
        for (int b = 1; b <= 6; b++) {
            boot_error_reset_for_testing();
            restarted[b] = boot_crashonly_handle_unrecoverable(
                dir, SOAK_TIP, /*zero_nbits=*/0, SOAK_MISMATCHES,
                SOAK_FIRST_MISMATCH, /*reindex_executable=*/true);
            /* A sibling clear path fires between boots. */
            boot_auto_reindex_clear(dir);
        }

        BR_CHECK("holes-only: the restart loop TERMINATES within the cap "
                 "(no 4th restart on the identical finding)",
                 !restarted[4] && !restarted[5] && !restarted[6]);

        /* The attempt count is durable against the FINDING. */
        uint64_t sig = 0;
        int attempts = 0;
        BR_CHECK("holes-only: the attempt count ADVANCES across restarts even "
                 "though every clear path wiped the request file",
                 boot_repair_episode_status(dir, &sig, &attempts) &&
                 attempts > BOOT_REPAIR_EPISODE_MAX);
        BR_CHECK("holes-only: the signature is the finding, not the request",
                 sig == boot_repair_episode_signature(
                            SOAK_TIP, 0, SOAK_MISMATCHES, SOAK_FIRST_MISMATCH));

        /* The stop is typed and carries the measurement. */
        char render[BOOT_ERROR_RENDER_MAX];
        boot_error_reset_for_testing();
        (void)boot_crashonly_handle_unrecoverable(
            dir, SOAK_TIP, 0, SOAK_MISMATCHES, SOAK_FIRST_MISMATCH, true);
        size_t n = boot_error_last_render(render, sizeof(render));
        BR_CHECK("holes-only: the terminal stop is a typed blocker carrying "
                 "the numbers",
                 n > 0 && strstr(render, "mismatches=630") != NULL &&
                 strstr(render, "first_mismatch_h=2004318") != NULL &&
                 strstr(render, "BOOT_REINDEX_RESTART_REQUESTED") == NULL);

        /* A DIFFERENT finding is a new episode with its own allowance. */
        boot_error_reset_for_testing();
        (void)boot_crashonly_handle_unrecoverable(
            dir, SOAK_TIP, 0, /*mismatches=*/1, /*first_mismatch_h=*/9, true);
        BR_CHECK("holes-only: a CHANGED finding starts a fresh episode at 1",
                 boot_repair_episode_status(dir, &sig, &attempts) &&
                 attempts == 1);

        /* And a boot that reaches clean integrity retires the episode. */
        boot_crashonly_clear(dir);
        BR_CHECK("holes-only: clean integrity retires the episode ledger",
                 !boot_repair_episode_status(dir, &sig, &attempts));

        boot_error_reset_for_testing();
        test_cleanup_tmpdir(dir);
    }
    return failures;
}

static int br_term_reindex_verb(void)
{
    int failures = 0;
    /* ──────────────────────────────────────────────────────────────────
     * (K) THE VERB. A holes-only / mismatch-only finding must not arm a
     * from-genesis -reindex-chainstate (it cannot repair links); the finalize
     * gate asks for the in-place band repair. The tip-above-extent shape
     * (holes, NO link mismatch) still arms the chainstate reindex.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "verb");
        mkdir_p_br(dir);

        boot_error_reset_for_testing();
        bool restart = boot_crashonly_handle_unrecoverable(
            dir, 3172671, /*zero_nbits=*/0, /*mismatches=*/630,
            /*first_mismatch_h=*/2004318, /*reindex_executable=*/true);
        BR_CHECK("link damage: boot does NOT exit for a chainstate reindex",
                 !restart);
        BR_CHECK("link damage: no -reindex-chainstate request is armed",
                 !boot_auto_reindex_pending(dir));

        char dir2[256];
        test_fmt_tmpdir(dir2, sizeof(dir2), "boot_reindex_term", "extent");
        mkdir_p_br(dir2);
        boot_error_reset_for_testing();
        bool restart2 = boot_crashonly_handle_unrecoverable(
            dir2, 1234567, /*zero_nbits=*/0, /*mismatches=*/0,
            /*first_mismatch_h=*/-1, /*reindex_executable=*/true);
        BR_CHECK("tip-above-extent: still exits to run the chainstate reindex",
                 restart2);
        BR_CHECK("tip-above-extent: the request is armed",
                 boot_auto_reindex_pending(dir2));

        /* That ladder terminates too under request-file wiping: three
         * restarts, then the typed exhausted blocker. */
        bool restarted4 = true;
        for (int b = 2; b <= 4; b++) {
            boot_auto_reindex_clear(dir2);   /* a sibling clear path fires */
            boot_error_reset_for_testing();
            restarted4 = boot_crashonly_handle_unrecoverable(
                dir2, 1234567, 0, 0, -1, true);
        }
        BR_CHECK("tip-above-extent: the 4th identical boot does NOT restart",
                 !restarted4);
        char render2[BOOT_ERROR_RENDER_MAX];
        (void)boot_error_last_render(render2, sizeof(render2));
        BR_CHECK("tip-above-extent: the cap leaves the typed exhausted blocker",
                 strstr(render2, "BOOT_REINDEX_BUDGET_EXHAUSTED") != NULL);

        boot_error_reset_for_testing();
        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(dir2);
    }
    return failures;
}

int test_boot_reindex_terminates(void);
int test_boot_reindex_terminates(void)
{
    test_reset_shared_globals();
    printf("\n=== boot_reindex_terminates tests ===\n");
    int failures = 0;

    mkdir_p_br("./test-tmp");

    failures += br_term_fixed_anchor();
    failures += br_term_recoverable();
    failures += br_term_moving_tip();
    failures += br_term_covered_anchor();
    failures += br_term_storage_gate();
    failures += br_term_body_coverage();
    failures += br_term_link_damage();
    failures += br_term_coins_shaped();
    failures += br_term_legacy_request();
    failures += br_term_holes_only();
    failures += br_term_reindex_verb();

    failures += br_writer_guard();

    return failures;
}
