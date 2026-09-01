/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Truthful, bounded shutdown watchdog (util/shutdown_stagewatch.h).
 *
 * Proves the properties that make a forced shutdown TRUTHFUL and BOUNDED, so a
 * unit whose work SUCCEEDED can never be mis-reported as failed:
 *
 *   (a) shutdown_deadline_decide() escalation matrix — the pure core:
 *       durability secured => EXIT_CLEAN (never a false failure); a
 *       durability-critical stall before durability => bounded GRACE then
 *       EXIT_UNCLEAN (never skipped); a non-critical pre-durable stall =>
 *       fail-fast EXIT_UNCLEAN.
 *   (b) the never-skip invariant: a durability-critical stage NEVER yields
 *       EXIT_CLEAN before durability (it is graced, never abandoned).
 *   (c) truthful exit codes: only forced-unclean maps to a non-zero code.
 *   (d) per-stage instrumentation with an injected fake clock: durations,
 *       durability flags, and the over-budget flag are recorded per stage.
 *   (e) receipt content: the rich CLEAN receipt and the async-signal-safe
 *       terminal receipt carry the truthful verdict.
 *   (f) end-to-end: begin -> stages -> mark_durable -> complete_clean writes a
 *       durable `shutdown-receipt.v1` with outcome=clean into the datadir.
 *
 * Hermetic: injected clock, arm_alarm=false everywhere (no real SIGALRM), temp
 * files only. */

#include "test/test_core.h"
#include "util/shutdown_stagewatch.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* ── Injected monotonic clock (microseconds) ─────────────────────────── */
static int64_t g_fake_us;
static int64_t fake_clock(void) { return g_fake_us; }
static void clock_advance_s(int64_t s) { g_fake_us += s * 1000000LL; }

static bool file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char buf[8192];
    size_t rd = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[rd] = '\0';
    return strstr(buf, needle) != NULL;
}

int test_shutdown_stagewatch(void)
{
    int failures = 0;

    /* (a) escalation matrix + (b) never-skip invariant. */
    printf("shutdown_stagewatch decide escalation matrix ... ");
    {
        bool ok = true;
        const int GMAX = 2;

        /* durability secured => always EXIT_CLEAN, regardless of stage kind /
         * graces. Never a false failure. */
        for (int crit = 0; crit <= 1; crit++)
            for (int g = 0; g <= GMAX + 1; g++)
                ok &= shutdown_deadline_decide(true, crit, g, GMAX)
                      == SHUTDOWN_DEADLINE_EXIT_CLEAN;

        /* durability NOT secured, durability-critical stage: bounded graces,
         * then unclean — and NEVER EXIT_CLEAN (the fsync is never skipped). */
        ok &= shutdown_deadline_decide(false, true, 0, GMAX) == SHUTDOWN_DEADLINE_GRACE;
        ok &= shutdown_deadline_decide(false, true, 1, GMAX) == SHUTDOWN_DEADLINE_GRACE;
        ok &= shutdown_deadline_decide(false, true, 2, GMAX) == SHUTDOWN_DEADLINE_EXIT_UNCLEAN;
        ok &= shutdown_deadline_decide(false, true, 3, GMAX) == SHUTDOWN_DEADLINE_EXIT_UNCLEAN;
        for (int g = 0; g <= GMAX + 1; g++)
            ok &= shutdown_deadline_decide(false, true, g, GMAX)
                  != SHUTDOWN_DEADLINE_EXIT_CLEAN;

        /* durability NOT secured, non-critical stage: fail fast (unclean). */
        ok &= shutdown_deadline_decide(false, false, 0, GMAX) == SHUTDOWN_DEADLINE_EXIT_UNCLEAN;
        ok &= shutdown_deadline_decide(false, false, 5, GMAX) == SHUTDOWN_DEADLINE_EXIT_UNCLEAN;

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* Escalation ORDER for a slow durability-critical stage across repeated
     * deadline fires: GRACE, GRACE, then EXIT_UNCLEAN — never abandoned early,
     * never a false clean. */
    printf("shutdown_stagewatch escalation order (critical, pre-durable) ... ");
    {
        const int GMAX = 2;
        enum shutdown_deadline_action seq[3];
        for (int g = 0; g < 3; g++)
            seq[g] = shutdown_deadline_decide(false, true, g, GMAX);
        bool ok = seq[0] == SHUTDOWN_DEADLINE_GRACE &&
                  seq[1] == SHUTDOWN_DEADLINE_GRACE &&
                  seq[2] == SHUTDOWN_DEADLINE_EXIT_UNCLEAN;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (c) truthful exit codes. */
    printf("shutdown_stagewatch truthful exit codes ... ");
    {
        bool ok = shutdown_stagewatch_exit_code(SHUTDOWN_OUTCOME_CLEAN) == 0 &&
                  shutdown_stagewatch_exit_code(SHUTDOWN_OUTCOME_FORCED_AFTER_DURABLE) == 0 &&
                  shutdown_stagewatch_exit_code(SHUTDOWN_OUTCOME_FORCED_UNCLEAN) == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (d) per-stage instrumentation with an injected clock (no real alarm). */
    printf("shutdown_stagewatch per-stage timing + over-budget flag ... ");
    {
        shutdown_stagewatch_reset_for_test();
        g_fake_us = 1000000LL;                 /* arbitrary monotonic origin */
        shutdown_stagewatch_set_clock_for_test(fake_clock);
        shutdown_stagewatch_begin(NULL);       /* NULL datadir: timing still works */

        shutdown_stagewatch_enter("stage-a", 30, true, false);
        clock_advance_s(5);                    /* 5s < 30s budget: within */
        shutdown_stagewatch_enter("stage-b", 10, false, false);
        clock_advance_s(25);                   /* 25s > 10s budget: over */
        shutdown_stagewatch_enter("stage-c", 0, false, false);
        clock_advance_s(1);
        shutdown_stagewatch_complete_clean();  /* closes stage-c */

        bool ok = shutdown_stagewatch_stage_count() == 3;
        const struct shutdown_stage_record *a = shutdown_stagewatch_stage(0);
        const struct shutdown_stage_record *b = shutdown_stagewatch_stage(1);
        const struct shutdown_stage_record *c = shutdown_stagewatch_stage(2);
        ok = ok && a && b && c;
        if (ok) {
            ok = ok && strcmp(a->name, "stage-a") == 0 &&
                 a->elapsed_us == 5000000LL &&
                 a->durability_critical && !a->over_budget;
            ok = ok && strcmp(b->name, "stage-b") == 0 &&
                 b->elapsed_us == 25000000LL &&
                 !b->durability_critical && b->over_budget;   /* blew 10s budget */
            ok = ok && strcmp(c->name, "stage-c") == 0 &&
                 !c->over_budget;                             /* budget 0 => n/a */
        }
        shutdown_stagewatch_set_clock_for_test(NULL);
        shutdown_stagewatch_reset_for_test();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (e) rich CLEAN receipt content. */
    printf("shutdown_stagewatch format_receipt content ... ");
    {
        struct shutdown_stage_record stages[2] = {
            { .name = "runtime-persist", .elapsed_us = 94000000LL,
              .durability_critical = true, .over_budget = true },
            { .name = "release-resources", .elapsed_us = 2000000LL,
              .durability_critical = false, .over_budget = false },
        };
        char buf[2048];
        int n = shutdown_stagewatch_format_receipt(
            buf, sizeof(buf), SHUTDOWN_OUTCOME_CLEAN, "release-resources",
            true, 100000000LL, stages, 2);
        bool ok = n > 0 &&
                  strstr(buf, "magic=ZCLSHUTRCPT\n") &&
                  strstr(buf, "outcome=clean\n") &&
                  strstr(buf, "durable=1\n") &&
                  strstr(buf, "last_stage=release-resources\n") &&
                  strstr(buf, "total_ms=100000\n") &&
                  strstr(buf, "stage.runtime-persist_ms=94000 critical=1 over_budget=1\n") &&
                  strstr(buf, "stage.release-resources_ms=2000 critical=0 over_budget=0\n");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (e2) async-signal-safe terminal receipt writer — the forced-exit path's
     * "write a terminal state marker first". Driven via a temp fd (no signal). */
    printf("shutdown_stagewatch terminal receipt (AS-safe writer) ... ");
    {
        char path[] = "/tmp/zcl_swrcpt_XXXXXX";
        int fd = mkstemp(path);
        bool ok = fd >= 0;
        if (ok) {
            int w = shutdown_stagewatch_write_terminal_receipt_fd(
                fd, SHUTDOWN_OUTCOME_FORCED_AFTER_DURABLE, "runtime-persist", true);
            close(fd);
            ok = w > 0 &&
                 file_contains(path, "magic=ZCLSHUTRCPT\n") &&
                 file_contains(path, "outcome=forced-after-durable\n") &&
                 file_contains(path, "durable=1\n") &&
                 file_contains(path, "forced_at_stage=runtime-persist\n");
            unlink(path);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* (f) end-to-end clean flow writes a durable receipt into the datadir. */
    printf("shutdown_stagewatch end-to-end clean receipt on disk ... ");
    {
        char dir[] = "/tmp/zcl_swdd_XXXXXX";
        bool ok = mkdtemp(dir) != NULL;
        if (ok) {
            shutdown_stagewatch_reset_for_test();
            g_fake_us = 5000000LL;
            shutdown_stagewatch_set_clock_for_test(fake_clock);
            shutdown_stagewatch_begin(dir);
            shutdown_stagewatch_enter("emergency-coins-flush", 30, true, false);
            clock_advance_s(2);
            shutdown_stagewatch_enter("runtime-persist", 45, true, false);
            clock_advance_s(3);
            shutdown_stagewatch_mark_durable();
            ok = ok && shutdown_stagewatch_is_durable();
            shutdown_stagewatch_enter("release-resources", 15, false, false);
            clock_advance_s(1);
            shutdown_stagewatch_complete_clean();

            char rpath[512];
            snprintf(rpath, sizeof(rpath), "%s/shutdown-receipt.v1", dir);
            ok = ok &&
                 file_contains(rpath, "outcome=clean\n") &&
                 file_contains(rpath, "durable=1\n") &&
                 file_contains(rpath, "last_stage=release-resources\n") &&
                 file_contains(rpath, "stage.emergency-coins-flush_ms=2000 critical=1 over_budget=0\n");
            unlink(rpath);
            rmdir(dir);
            shutdown_stagewatch_set_clock_for_test(NULL);
            shutdown_stagewatch_reset_for_test();
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
