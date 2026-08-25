/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the boot-stage state machine (lib/util/src/boot_phase.c).
 *
 * Cannot test misorder paths — boot_stage_advance_to() calls abort() on
 * backward moves or out-of-range targets, which would kill the test
 * runner. Coverage focuses on the legal transitions, idempotent
 * re-advance, name lookup, and the read-only predicates.
 *
 * Uses boot_stage_reset_for_testing() (only available under -DZCL_TESTING)
 * to restore the global stage between sub-tests and at function exit,
 * so the sequential test driver (test.c) can run this alongside other
 * tests without polluting their view of the boot stage. */

#include "test/test_core.h"
#include "config/boot.h"
#include "util/boot_phase.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>

#define BP_CHECK(name, expr) do { \
    printf("boot_phase: %s... ", (name)); \
    if ((expr)) printf("OK\n");           \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_boot_phase(void)
{
    printf("\n=== boot_phase tests ===\n");
    int failures = 0;

    boot_stage_reset_for_testing();

    /* ── name lookup ────────────────────────────────────────────── */
    BP_CHECK("name(INIT) is \"init\"",
        strcmp(boot_stage_name(BOOT_STAGE_INIT), "init") == 0);
    BP_CHECK("name(DB_OPEN) is \"db_open\"",
        strcmp(boot_stage_name(BOOT_STAGE_DB_OPEN), "db_open") == 0);
    BP_CHECK("name(READY) is \"ready\"",
        strcmp(boot_stage_name(BOOT_STAGE_READY), "ready") == 0);
    BP_CHECK("name(SHUTDOWN_COMPLETE) is \"shutdown_complete\"",
        strcmp(boot_stage_name(BOOT_STAGE_SHUTDOWN_COMPLETE),
               "shutdown_complete") == 0);

    /* Negative and >= MAX targets return "(invalid)". */
    BP_CHECK("name(-1) is \"(invalid)\"",
        strcmp(boot_stage_name((enum boot_stage)-1), "(invalid)") == 0);
    BP_CHECK("name(__MAX) is \"(invalid)\"",
        strcmp(boot_stage_name(BOOT_STAGE__MAX), "(invalid)") == 0);

    /* Every legal enum has a non-empty name (no gaps in the table). */
    {
        bool all_named = true;
        for (int s = 0; s < (int)BOOT_STAGE__MAX; s++) {
            const char *n = boot_stage_name((enum boot_stage)s);
            if (!n || !*n || strcmp(n, "(invalid)") == 0) {
                all_named = false;
                break;
            }
        }
        BP_CHECK("every legal stage has a non-empty name", all_named);
    }

    /* ── current + predicate at INIT ────────────────────────────── */
    BP_CHECK("current() is INIT after reset",
        boot_stage_current() == BOOT_STAGE_INIT);
    BP_CHECK("is(INIT) true at INIT",
        boot_stage_is(BOOT_STAGE_INIT));
    BP_CHECK("is(DB_OPEN) false at INIT",
        !boot_stage_is(BOOT_STAGE_DB_OPEN));

    /* ── idempotent re-advance ──────────────────────────────────── */
    boot_stage_advance_to(BOOT_STAGE_INIT);  /* same stage — no-op */
    BP_CHECK("idempotent re-advance keeps stage at INIT",
        boot_stage_current() == BOOT_STAGE_INIT);

    /* ── forward step ───────────────────────────────────────────── */
    boot_stage_advance_to(BOOT_STAGE_DATADIR_LOCKED);
    BP_CHECK("advance to DATADIR_LOCKED",
        boot_stage_current() == BOOT_STAGE_DATADIR_LOCKED);
    BP_CHECK("is(DATADIR_LOCKED) true after advance",
        boot_stage_is(BOOT_STAGE_DATADIR_LOCKED));
    BP_CHECK("is(INIT) false after advance",
        !boot_stage_is(BOOT_STAGE_INIT));

    boot_stage_advance_to(BOOT_STAGE_CRYPTO_READY);
    boot_stage_advance_to(BOOT_STAGE_DB_OPEN);
    BP_CHECK("step through CRYPTO_READY -> DB_OPEN",
        boot_stage_current() == BOOT_STAGE_DB_OPEN);

    /* ZK params are consensus-critical on mainnet. If the background loader
     * thread cannot even start, boot must name params_missing and park before
     * CRYPTO_READY rather than silently continuing. */
    BP_CHECK("mainnet params thread failure is fatal",
        boot_test_params_thread_failure_is_fatal(true, true, false));
    BP_CHECK("missing params dir has no thread failure",
        !boot_test_params_thread_failure_is_fatal(false, true, false));
    BP_CHECK("mint-anchor-fast keeps params thread failure nonfatal",
        !boot_test_params_thread_failure_is_fatal(true, true, true));
    BP_CHECK("non-mainnet params thread failure stays warning-only",
        !boot_test_params_thread_failure_is_fatal(true, false, false));

    /* ── boot_need_legacy_header_pull (fresh-datadir need_zcd fix) ──
     * MEMORY/bug: on a genuinely fresh/empty datadir both
     * active_chain_height() and db_block_max_height() are 0, so the
     * ratio-only test `local < chain_h*9/10` degenerates to `0 < 0` and
     * never fires — the fresh node silently falls back to a slow P2P
     * header crawl instead of the ~60s legacy import. The fix adds an
     * explicit empty-datadir trigger (local_index_size == 0) gated on a
     * legacy source actually being present. */
    BP_CHECK("empty datadir + legacy present fires the pull (the fix)",
        boot_need_legacy_header_pull(0, 0, true));
    BP_CHECK("empty datadir + no legacy source does NOT fire",
        !boot_need_legacy_header_pull(0, 0, false));
    BP_CHECK("empty datadir + no legacy source, nonzero chain_h estimate",
        !boot_need_legacy_header_pull(0, 3000000, false));
    BP_CHECK("local at 90pct of chain height does not fire (at threshold)",
        !boot_need_legacy_header_pull(2700000, 3000000, true));
    BP_CHECK("local just below 90pct of chain height fires (ratio trigger)",
        boot_need_legacy_header_pull(2699999, 3000000, true));
    BP_CHECK("local far below chain height fires even with tiny local>0",
        boot_need_legacy_header_pull(3, 3000000, true));
    BP_CHECK("local at chain height does not fire",
        !boot_need_legacy_header_pull(3000000, 3000000, true));
    BP_CHECK("ratio trigger requires legacy source present",
        !boot_need_legacy_header_pull(3, 3000000, false));

    /* ── boot_need_blocks_table_hydrate (importblockindex determinism) ──
     * MEMORY/bug: the `blocks`-table bulk-hydrate rung (config/src/boot.c,
     * the sink --importblockindex CLI-bulk-loads header rows into) used to
     * be gated on `!loaded && map_size<=1`. An EARLIER loader rung (flat
     * file / block_index_cache) can succeed ("loaded=true") with a small
     * STALE map left over from a partial P2P header sync that predates the
     * CLI import — the `!loaded` guard then PERMANENTLY skips the bulk
     * rung even though the blocks table holds millions of complete rows,
     * and the node falls back to a P2P/getheaders header crawl to re-fetch
     * headers it already has on disk (~90 min instead of ~74s). The fix
     * keys the rung on the blocks-table row count vs the CURRENTLY loaded
     * map size instead of the `loaded` flag — a stale small map never
     * blocks it. */
    BP_CHECK("empty map + blocks table populated fires (fresh datadir "
             "chooses bulk)",
        boot_need_blocks_table_hydrate(0, 3100000));
    BP_CHECK("genesis-only map + blocks table populated fires",
        boot_need_blocks_table_hydrate(1, 3100000));
    BP_CHECK("stale small map (200) far below blocks table fires — the "
             "exact `loaded=true` stale-map defect this closes",
        boot_need_blocks_table_hydrate(200, 3100000));
    BP_CHECK("blocks table empty never fires (nothing to hydrate)",
        !boot_need_blocks_table_hydrate(0, 0));
    BP_CHECK("map at 90pct of blocks table rows does not fire (at threshold)",
        !boot_need_blocks_table_hydrate(2790000, 3100000));
    BP_CHECK("map just below 90pct of blocks table rows fires (ratio "
             "trigger)",
        boot_need_blocks_table_hydrate(2789999, 3100000));
    BP_CHECK("fully-loaded map (warm restart) does not re-fire — preserves "
             "existing warm-datadir behavior",
        !boot_need_blocks_table_hydrate(3100000, 3100000));

    /* ── forward-jump (legal, emits WARN) ──────────────────────── */
    boot_stage_reset_for_testing();
    boot_stage_advance_to(BOOT_STAGE_READY);
    BP_CHECK("forward-jump from INIT to READY (skipped intermediate)",
        boot_stage_current() == BOOT_STAGE_READY);

    /* ── shutdown entry from mid-boot ──────────────────────────── */
    boot_stage_reset_for_testing();
    boot_stage_advance_to(BOOT_STAGE_DB_OPEN);
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_REQUESTED);
    BP_CHECK("shutdown can be entered from mid-boot (DB_OPEN)",
        boot_stage_current() == BOOT_STAGE_SHUTDOWN_REQUESTED);

    /* Within the shutdown range, advance to SHUTDOWN_COMPLETE is a normal
     * forward step. */
    boot_stage_advance_to(BOOT_STAGE_SHUTDOWN_COMPLETE);
    BP_CHECK("advance SHUTDOWN_REQUESTED -> SHUTDOWN_COMPLETE",
        boot_stage_current() == BOOT_STAGE_SHUTDOWN_COMPLETE);

    /* ── illegal transitions abort() (fork-isolated) ─────────────────
     * boot_stage_advance_to() calls abort() on a BACKWARD move and on an
     * OUT-OF-RANGE target (lib/util/src/boot_phase.c:112-118 and
     * :140-147). abort() raises SIGABRT with no handler installed in the
     * test process, so it would kill the runner. We fork a child, have it
     * perform the illegal advance, and assert the child is *terminated by
     * SIGABRT* (WIFSIGNALED && WTERMSIG==SIGABRT). The child redirects its
     * own stderr to /dev/null so the abort's diagnostic fprintf does not
     * pollute the test log, and falls through to a distinct _exit() code
     * if abort() did NOT fire — a real regression then surfaces as a clean
     * exit instead of a signal. Mirrors the fork+SIGABRT idiom in
     * lib/test/src/test_postmortem.c:104-121. */

    /* (a) BACKWARD move: DB_OPEN -> INIT must abort. */
    fflush(stdout);
    fflush(stderr);
    {
        pid_t pid = fork();
        if (pid == 0) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
            boot_stage_reset_for_testing();           /* -> INIT */
            boot_stage_advance_to(BOOT_STAGE_DB_OPEN); /* legal forward jump */
            boot_stage_advance_to(BOOT_STAGE_INIT);    /* illegal: backward */
            _exit(99); /* reached only if the abort() did NOT fire */
        }
        BP_CHECK("fork backward-move child", pid > 0);
        if (pid > 0) {
            int status = 0;
            pid_t got = waitpid(pid, &status, 0);
            BP_CHECK("wait backward-move child", got == pid);
            BP_CHECK("backward move (DB_OPEN -> INIT) aborts via SIGABRT",
                     got == pid && WIFSIGNALED(status) &&
                     WTERMSIG(status) == SIGABRT);
        }
    }

    /* (b) OUT-OF-RANGE target: BOOT_STAGE__MAX must abort. */
    fflush(stdout);
    fflush(stderr);
    {
        pid_t pid = fork();
        if (pid == 0) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, STDERR_FILENO); close(dn); }
            boot_stage_reset_for_testing();              /* -> INIT */
            boot_stage_advance_to(BOOT_STAGE__MAX);       /* illegal: >= MAX */
            _exit(99); /* reached only if the abort() did NOT fire */
        }
        BP_CHECK("fork out-of-range child", pid > 0);
        if (pid > 0) {
            int status = 0;
            pid_t got = waitpid(pid, &status, 0);
            BP_CHECK("wait out-of-range child", got == pid);
            BP_CHECK("out-of-range target (__MAX) aborts via SIGABRT",
                     got == pid && WIFSIGNALED(status) &&
                     WTERMSIG(status) == SIGABRT);
        }
    }

    /* ── boot step reporter: slow, stuck, and failed are three states ──
     *
     * The incident: a boot step ran for four hours with no record of its
     * own, because the only marker for a step is printed after it
     * returns. The reporter now names a step on the way in and reports
     * it every budget window until it finishes.
     *
     * The property pinned here is the ANTI-CENTRALIZATION one. Two of
     * this network's four nodes are 7200 rpm HDD boxes whose disks sit
     * at 57-91% IO pressure while their CPUs idle; steps that take
     * seconds on NVMe take minutes there. If "over budget" were graded
     * as failure, those nodes would be graded off the network for being
     * honest about their hardware. So: no elapsed time, however large,
     * may ever produce a failure verdict. Failure is reported by the
     * step, never inferred from the clock. */
    {
        const int64_t B = BOOT_STEP_BUDGET_MS;

        /* Under budget: nothing is wrong. */
        BP_CHECK("step: inside budget is running",
            boot_step_classify(B - 1, B, 0) == BOOT_STEP_RUNNING);
        BP_CHECK("step: inside budget with progress is still running",
            boot_step_classify(0, B, 9) == BOOT_STEP_RUNNING);

        /* Over budget WITH progress: slow. The HDD case. */
        enum boot_step_state slow = boot_step_classify(B * 20, B, 7);
        BP_CHECK("step: 20x over budget but progressing is slow",
            slow == BOOT_STEP_SLOW);
        BP_CHECK("step: slow is NOT a failure",
            !boot_step_state_is_failure(slow));
        BP_CHECK("step: slow carries verdict=telemetry",
            strcmp(boot_step_state_verdict(slow), "telemetry") == 0);
        BP_CHECK("step: slow is not spelled the same as failed",
            strcmp(boot_step_state_name(slow),
                   boot_step_state_name(BOOT_STEP_FAILED)) != 0);

        /* Over budget WITHOUT progress: stuck — distinct from slow, and
         * still only an observation. */
        enum boot_step_state stuck = boot_step_classify(B * 20, B, 0);
        BP_CHECK("step: over budget with no progress is stuck",
            stuck == BOOT_STEP_STUCK);
        BP_CHECK("step: stuck is distinguishable from slow", stuck != slow);
        BP_CHECK("step: stuck is NOT a failure either",
            !boot_step_state_is_failure(stuck));
        BP_CHECK("step: stuck carries verdict=telemetry",
            strcmp(boot_step_state_verdict(stuck), "telemetry") == 0);

        /* The clock can never manufacture a failure — not at an hour,
         * not at a day, not with any progress value. */
        {
            bool clock_can_fail = false;
            const int64_t elapsed[] = {
                0, B, B + 1, 3600LL * 1000, 86400LL * 1000, INT64_MAX / 2,
            };
            for (size_t i = 0; i < sizeof(elapsed) / sizeof(elapsed[0]); i++)
                for (uint64_t d = 0; d < 3; d++)
                    if (boot_step_state_is_failure(
                            boot_step_classify(elapsed[i], B, d)))
                        clock_can_fail = true;
            BP_CHECK("step: no elapsed time can produce a failure verdict",
                !clock_can_fail);
        }

        /* Failure is its own state, reported explicitly. */
        BP_CHECK("step: failed is the only failure state",
            boot_step_state_is_failure(BOOT_STEP_FAILED) &&
            !boot_step_state_is_failure(BOOT_STEP_DONE) &&
            !boot_step_state_is_failure(BOOT_STEP_RUNNING));
        BP_CHECK("step: failed carries verdict=failure",
            strcmp(boot_step_state_verdict(BOOT_STEP_FAILED),
                   "failure") == 0);
        BP_CHECK("step: done carries verdict=ok",
            strcmp(boot_step_state_verdict(BOOT_STEP_DONE), "ok") == 0);

        /* A budget of zero must not divide by, or fall back into, chaos. */
        BP_CHECK("step: zero budget falls back to the default budget",
            boot_step_classify(BOOT_STEP_BUDGET_MS + 1, 0, 1) ==
                BOOT_STEP_SLOW);

        /* Every state has a distinct, non-empty name; out-of-range is
         * named rather than read off the end of the table. */
        {
            bool all_named = true;
            for (int s = 0; s < (int)BOOT_STEP_STATE__MAX; s++) {
                const char *n = boot_step_state_name((enum boot_step_state)s);
                if (!n || !*n || strcmp(n, "(invalid)") == 0)
                    all_named = false;
                for (int t = s + 1; t < (int)BOOT_STEP_STATE__MAX; t++)
                    if (strcmp(n, boot_step_state_name(
                                   (enum boot_step_state)t)) == 0)
                        all_named = false;
            }
            BP_CHECK("step: every state has a distinct non-empty name",
                all_named);
            BP_CHECK("step: out-of-range state names as (invalid)",
                strcmp(boot_step_state_name(BOOT_STEP_STATE__MAX),
                       "(invalid)") == 0);
        }

        /* The tracked-step API must be safe to drive with no step open
         * and must not leave one behind. boot_step_fail always returns
         * false so a boot exit can name its failure and return on the
         * statement it was already returning on. */
        boot_step_done();                 /* nothing open — no-op */
        boot_step_note();
        BP_CHECK("step: fail() returns false even with no step open",
            !boot_step_fail("nothing open"));
    }

    /* ── An extension must be EARNED ──────────────────────────────
     * The stall reporter re-arms every budget window, so any state that
     * extends the systemd start deadline extends it FOREVER. That is
     * fine for a step that is moving and fatal for one that is not:
     * TimeoutStartSec stops being reachable, and Restart=always — the
     * only thing that recovers a wedged boot — never gets its turn.
     *
     * These pin the rule at the seam boot_step_emit() actually consults,
     * so a future edit that makes STUCK "just a bit more patient" has to
     * delete an assertion rather than silently reintroduce the hang. */
    {
        BP_CHECK("budget: SLOW earns more start budget (moving, just slow)",
            boot_step_state_earns_budget(BOOT_STEP_SLOW));
        BP_CHECK("budget: RUNNING earns more start budget",
            boot_step_state_earns_budget(BOOT_STEP_RUNNING));
        BP_CHECK("budget: STUCK earns NOTHING — zero progress must not "
                 "push the deadline out",
            !boot_step_state_earns_budget(BOOT_STEP_STUCK));
        BP_CHECK("budget: FAILED earns nothing",
            !boot_step_state_earns_budget(BOOT_STEP_FAILED));
        BP_CHECK("budget: DONE earns nothing",
            !boot_step_state_earns_budget(BOOT_STEP_DONE));

        /* Composed with the classifier: the ONLY way to reach the
         * non-earning STUCK state is genuine zero progress, so an honest
         * slow box (any delta > 0) always keeps its budget no matter how
         * far over budget it runs. */
        BP_CHECK("budget: over budget WITH progress stays earning",
            boot_step_state_earns_budget(
                boot_step_classify(3600000, BOOT_STEP_BUDGET_MS, 1)));
        BP_CHECK("budget: over budget with ZERO progress stops earning",
            !boot_step_state_earns_budget(
                boot_step_classify(3600000, BOOT_STEP_BUDGET_MS, 0)));
        BP_CHECK("budget: under budget always earning",
            boot_step_state_earns_budget(
                boot_step_classify(1, BOOT_STEP_BUDGET_MS, 0)));
        /* A non-earning state is still REPORTED — telemetry is
         * unconditional, only the budget is conditional. */
        BP_CHECK("budget: STUCK still reports as telemetry, not failure",
            strcmp(boot_step_state_verdict(BOOT_STEP_STUCK),
                   "telemetry") == 0 &&
            !boot_step_state_is_failure(BOOT_STEP_STUCK));
    }

    /* Restore for any subsequent tests in this process. */
    boot_stage_reset_for_testing();
    return failures;
}
