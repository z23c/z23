/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for the boot crash-only reindex TERMINATION invariant.
 * The failure shape this guards against: on a genuinely-corrupt
 * blocks/ at a STABLE tip, an unbounded reindex budget never TERMINATES — if
 * at BOOT_AUTO_REINDEX_MAX+1 the exhausted handler DELETES the only durable
 * record (boot_auto_reindex_clear) and pages, the next restart finds NO
 * sentinel, re-detects the same damage, and writes a FRESH count=1, re-arming
 * the budget from scratch → an UNBOUNDED reindex loop throttled only by
 * systemd backoff.
 *
 * The fix: at exhaustion the sentinel is REWRITTEN as a TERMINAL marker
 * (count = -1) rather than deleted; boot_auto_reindex_pending() / the crash-only
 * consume treat the terminal marker as "do NOT re-request reindex" (false). This
 * matches chain_tip_watchdog: exhaustion is PERSISTED and the node stays-up
 * degraded, paging the operator ONCE.
 *
 * The load-bearing assertions:
 *   (A) the cap TERMINATES — driving boot_auto_reindex_request N times on a
 *       FIXED anchor writes the terminal marker at the cap, and after that
 *       consume returns false (no re-arm, no unbounded loop);
 *   (B) a RECOVERABLE datadir is NOT falsely exhausted — attempts 1..MAX still
 *       pend as reindex requests (a datadir that recovers on attempt 2 still
 *       recovers); the budget is keyed on a STABLE identity so a moving tip
 *       cannot re-arm the cap.
 */

#include "test/test_core.h"

#include "config/boot_crashonly.h"
#include "storage/boot_auto_reindex.h"

#include <errno.h>
#include <stdio.h>
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

int test_boot_reindex_terminates(void);
int test_boot_reindex_terminates(void)
{
    test_reset_shared_globals();
    printf("\n=== boot_reindex_terminates tests ===\n");
    int failures = 0;

    mkdir_p_br("./test-tmp");

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

        /* Attempts 1..MAX must each return a climbing count and PEND as a real
         * reindex request (the node is allowed to retry up to the cap). */
        bool climb_ok = true;
        bool pend_ok = true;
        for (int i = 1; i <= BOOT_AUTO_REINDEX_MAX; i++) {
            int n = boot_auto_reindex_request(dir, ANCHOR);
            climb_ok &= (n == i);
            pend_ok &= boot_auto_reindex_pending(dir);
        }
        BR_CHECK("attempts 1..MAX return a climbing count", climb_ok);
        BR_CHECK("attempts 1..MAX each PEND as a reindex request", pend_ok);
        BR_CHECK("not terminal while budget remains",
                 !boot_auto_reindex_is_terminal(dir));

        /* The MAX+1 request must NOT yield an in-budget count (it is over the
         * cap). The crash-only handler is what converts this to a terminal
         * marker; drive it directly with the reindex-recoverable shape
         * (zero_nbits==0, reindex_executable=true). It must return false
         * (stay-up-degraded, not exit) and persist the terminal marker. */
        bool exit_boot = boot_crashonly_handle_unrecoverable(
            dir, (int)ANCHOR, /*zero_nbits=*/0, /*mismatches=*/0,
            /*first_mismatch_h=*/0, /*reindex_executable=*/true);
        BR_CHECK("exhausted handler returns false (stay-up-degraded, no exit)",
                 !exit_boot);
        BR_CHECK("exhausted writes the TERMINAL marker (NOT deleted)",
                 boot_auto_reindex_is_terminal(dir));

        /* THE bug's teeth: after the terminal marker, the next boot must NOT
         * re-arm. pending() and the crash-only consume must both be false. */
        BR_CHECK("terminal: pending() is false (consume stops re-requesting)",
                 !boot_auto_reindex_pending(dir));
        BR_CHECK("terminal: consume_reindex_request returns false (no loop)",
                 !boot_crashonly_consume_reindex_request(dir));

        /* And a fresh request at the SAME anchor must NOT re-arm a count=1 — it
         * stays terminal (this is exactly the unbounded-loop re-arm the fix
         * kills). The sentinel is NOT deleted across this call. */
        int after = boot_auto_reindex_request(dir, ANCHOR);
        BR_CHECK("terminal: request does NOT re-arm (returns TERMINAL)",
                 after == BOOT_AUTO_REINDEX_TERMINAL);
        BR_CHECK("terminal: still terminal after a re-request attempt",
                 boot_auto_reindex_is_terminal(dir));
        BR_CHECK("terminal: still not pending after a re-request attempt",
                 !boot_auto_reindex_pending(dir));

        test_cleanup_tmpdir(dir);
    }

    /* ──────────────────────────────────────────────────────────────────
     * (B) A RECOVERABLE datadir is NOT falsely exhausted. A node that would
     * recover on attempt 2 must still be allowed to reindex on attempt 2 —
     * exhaustion+terminal fires ONLY after BOOT_AUTO_REINDEX_MAX failures at a
     * stable anchor, never before.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "recoverable");
        mkdir_p_br(dir);

        const int32_t ANCHOR = 7654321;

        int n1 = boot_auto_reindex_request(dir, ANCHOR);
        BR_CHECK("recoverable: attempt 1 -> count 1, pends, not terminal",
                 n1 == 1 && boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* Simulate "the rebuild converged on attempt 2": consume fires, the
         * node boots clean, the budget is CLEARED. The next genuinely-new
         * wedge must then start a FRESH episode at count=1 (the clear path is
         * still the success path — only EXHAUSTION must not clear). */
        BR_CHECK("recoverable: attempt 1 consume requests reindex (true)",
                 boot_crashonly_consume_reindex_request(dir));
        int n2 = boot_auto_reindex_request(dir, ANCHOR);
        BR_CHECK("recoverable: attempt 2 -> count 2 (NOT falsely exhausted)",
                 n2 == 2 && boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* Clean boot clears the budget (the rebuild converged). */
        boot_crashonly_clear(dir);
        BR_CHECK("recoverable: clean boot clears -> not pending, not terminal",
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* A genuinely-new wedge starts a fresh count=1. */
        int n3 = boot_auto_reindex_request(dir, ANCHOR + 50);
        BR_CHECK("recoverable: post-clear new wedge starts fresh at count 1",
                 n3 == 1);

        test_cleanup_tmpdir(dir);
    }

    /* ──────────────────────────────────────────────────────────────────
     * (C) Moving-tip budget cannot re-arm the cap. A partial replay that
     * leaves a DIFFERENT tip each boot must NOT reset count=1 — the budget
     * keys on the MINIMUM anchor seen this episode, so the count climbs to
     * the cap even as the tip moves.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "moving");
        mkdir_p_br(dir);

        /* A different (lower) tip on each boot of the SAME corrupt episode. */
        int n_a = boot_auto_reindex_request(dir, 5000);
        int n_b = boot_auto_reindex_request(dir, 4990);
        int n_c = boot_auto_reindex_request(dir, 4980);
        BR_CHECK("moving tip: count climbs 1,2,3 despite a moving anchor",
                 n_a == 1 && n_b == 2 && n_c == 3);
        BR_CHECK("moving tip: budget reaches the cap (== MAX)",
                 n_c == BOOT_AUTO_REINDEX_MAX);

        /* The 4th request is over the cap; the exhausted handler must mark
         * terminal — the moving tip did NOT let it loop forever. */
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

    /* ──────────────────────────────────────────────────────────────────
     * (D) A stale tip-height request self-clears once durable coins authority
     * COVERS its anchor: above-anchor progress proves the live reducer moved on
     * without the request, and a HASH-VERIFIED coins-best exactly AT the anchor
     * proves the transparent set is intact through the wedge tip (so consuming
     * reindex-chainstate would only destructively wipe a healthy near-tip coins
     * set without fixing a downstream/shielded wedge). An UNVERIFIED at-anchor
     * coins-best could still be torn, so it keeps consuming. The special
     * boot-storage anchor 0 and terminal markers are not cleared by this guard.
     * ────────────────────────────────────────────────────────────────── */
    {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "boot_reindex_term", "covered");
        mkdir_p_br(dir);

        const int32_t ANCHOR = 4321;
        int n1 = boot_auto_reindex_request(dir, ANCHOR);
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

        /* Re-arm to check the above-anchor path (reducer moved on) clears
         * regardless of hash verification. */
        (void)boot_auto_reindex_request(dir, ANCHOR);
        BR_CHECK("covered: above-anchor clears stale request (reducer moved on)",
                 boot_crashonly_clear_reindex_request_if_covered(
                     dir, ANCHOR + 1, false) &&
                 !boot_auto_reindex_pending(dir));

        int n2 = boot_auto_reindex_request(dir, 0);
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

    /* ──────────────────────────────────────────────────────────────────
     * (E) The boot-storage gate REFUSES to arm on an unreadable-genesis
     * (cold-import / bodyless) datadir. reindex_executable=false must NOT write
     * a sentinel, must CLEAR any stale one (so the per-boot consume→wipe→refuse
     * cycle stops), and must PARK — never crash-loop into a wipe it cannot
     * rebuild. reindex_executable=true still arms within budget (the verb check
     * must not suppress a legitimate reindex).
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
        (void)boot_auto_reindex_request(dir, 0);
        BR_CHECK("storage gate: stale sentinel present before refusal",
                 boot_auto_reindex_pending(dir));
        a = boot_crashonly_storage_gate(dir, "coins_view_integrity",
                                        /*reindex_executable=*/false);
        BR_CHECK("storage gate: refusal clears the stale sentinel (no re-arm)",
                 a == BOOT_GATE_PARK_DEGRADED &&
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* Executable genesis → arm within budget (regression guard). */
        a = boot_crashonly_storage_gate(dir, "coins_view_integrity",
                                        /*reindex_executable=*/true);
        BR_CHECK("storage gate: executable genesis arms (exit-for-reindex)",
                 a == BOOT_GATE_EXIT_FOR_REINDEX &&
                 boot_auto_reindex_pending(dir));

        test_cleanup_tmpdir(dir);
    }

    /* ──────────────────────────────────────────────────────────────────
     * (F) The body-coverage gate refuses a from-genesis reindex when coins are
     * seeded but bodies do not cover [0..target] (a cold-import seed), and the
     * refusal CLEARS the sentinel so it does not re-arm every boot. Dense
     * coverage — or an unseeded datadir — proceeds.
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

        (void)boot_auto_reindex_request(dir, 0);   /* a pending sentinel */
        bool ok = boot_crashonly_reindex_coverage_ok(dir, 3000000, 0, 1,
                                                     /*coins_seeded=*/true);
        BR_CHECK("coverage decision: seeded+sparse refuses reindex", !ok);
        BR_CHECK("coverage decision: refusal clears the sentinel (no re-arm)",
                 !boot_auto_reindex_pending(dir) &&
                 !boot_auto_reindex_is_terminal(dir));

        /* A simulated SECOND boot re-derives the same sparse coverage: it must
         * again refuse+clear (idempotent), never leaving a reindex armed. */
        (void)boot_auto_reindex_request(dir, 0);
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
