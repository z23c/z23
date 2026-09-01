/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the independent supervisor-sweep-heartbeat backstop
 * (platform/modules/util/src/supervisor_backstop.c — Pillar 7, "supervise the
 * supervisor").
 *
 * Coverage:
 *   - decision function: heartbeat advancing every poll never fires,
 *     however long the wall-clock span
 *   - decision function: heartbeat frozen for >= threshold fires exactly
 *     ONCE (edge-triggered), not on every subsequent poll
 *   - decision function: heartbeat resumes moving after a declared
 *     freeze re-arms the episode (a later freeze fires again)
 *   - decision function: freeze_threshold_us <= 0 disables the gate
 *   - respawn latch via the production poll seam
 *     (supervisor_backstop_test_poll), against the REAL
 *     supervisor_sweep_heartbeat(): forced off-systemd + an injected
 *     frozen span latches supervisor_backstop_respawn_requested();
 *     forced ON-systemd does NOT latch it (systemd's own WatchdogSec
 *     path handles that case instead — see boot_sd_watchdog.c)
 *   - dump_state_json shape
 *
 * This is the decision function, not the real 30 s wall-clock wait or an
 * actual re-exec — every case injects its own heartbeat/clock values, so
 * the whole file runs in well under a second. */

#include "test/test_core.h"
#include "util/supervisor_backstop.h"
#include "util/supervisor.h"
#include "util/boot_phase.h"
#include "json/json.h"

#define BS_CHECK(name, expr) do { \
    printf("supervisor_backstop: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_supervisor_backstop(void)
{
    int failures = 0;

    /* ── pure decision function: heartbeat keeps advancing ─────────── */
    {
        struct supervisor_backstop_state st = {0};
        int64_t threshold = 30 * 1000000LL;
        bool any_fired = false;

        /* First observation only seeds state. */
        any_fired |= supervisor_backstop_test_check(&st, 1, 0, threshold);

        /* Heartbeat advances every 5 s of injected clock — never crosses
         * the freeze threshold because last_change_us keeps resetting. */
        for (int i = 2; i <= 50; i++) {
            int64_t now_us = (int64_t)i * 5 * 1000000LL;
            any_fired |= supervisor_backstop_test_check(&st, (uint64_t)i,
                                                        now_us, threshold);
        }
        BS_CHECK("advancing heartbeat never fires", !any_fired);
    }

    /* ── pure decision function: frozen heartbeat fires once ───────── */
    {
        struct supervisor_backstop_state st = {0};
        int64_t threshold = 30 * 1000000LL;

        BS_CHECK("seed poll does not fire",
            !supervisor_backstop_test_check(&st, 7, 0, threshold));

        /* Heartbeat stays at 7 the whole time — inject clock advances
         * without the freeze crossing yet. */
        BS_CHECK("under threshold does not fire",
            !supervisor_backstop_test_check(&st, 7, 10 * 1000000LL, threshold));
        BS_CHECK("just under threshold does not fire",
            !supervisor_backstop_test_check(&st, 7, 29 * 1000000LL, threshold));

        /* Crossing the threshold fires exactly once. */
        BS_CHECK("crossing threshold fires",
            supervisor_backstop_test_check(&st, 7, 30 * 1000000LL, threshold));
        BS_CHECK("still-frozen next poll does NOT re-fire (edge-triggered)",
            !supervisor_backstop_test_check(&st, 7, 45 * 1000000LL, threshold));
        BS_CHECK("still-frozen far later still does NOT re-fire",
            !supervisor_backstop_test_check(&st, 7, 300 * 1000000LL, threshold));
    }

    /* ── pure decision function: resumed movement re-arms the episode ─ */
    {
        struct supervisor_backstop_state st = {0};
        int64_t threshold = 30 * 1000000LL;

        (void)supervisor_backstop_test_check(&st, 1, 0, threshold);
        BS_CHECK("first freeze fires",
            supervisor_backstop_test_check(&st, 1, 30 * 1000000LL, threshold));

        /* The counter starts moving again — the sweep recovered. */
        BS_CHECK("heartbeat moving clears the fired latch (no fire)",
            !supervisor_backstop_test_check(&st, 2, 31 * 1000000LL, threshold));

        /* A second, independent freeze episode fires again. */
        BS_CHECK("under new threshold does not fire",
            !supervisor_backstop_test_check(&st, 2, 50 * 1000000LL, threshold));
        BS_CHECK("second freeze episode fires again",
            supervisor_backstop_test_check(&st, 2, 61 * 1000000LL, threshold));
    }

    /* ── pure decision function: threshold <= 0 disables the gate ──── */
    {
        struct supervisor_backstop_state st = {0};
        (void)supervisor_backstop_test_check(&st, 1, 0, 0);
        BS_CHECK("threshold<=0 never fires however long frozen",
            !supervisor_backstop_test_check(&st, 1, 1000LL * 1000000LL, 0));
    }

    /* ── production poll seam: off-systemd frozen span latches respawn ─
     *
     * This test process never starts the real supervisor thread (no
     * supervisor_start() call in this test group), so the REAL
     * supervisor_sweep_heartbeat() is constant for the whole test — the
     * exact "frozen sweep" precondition, with no thread/timing races.
     * Seed the state from that real value (NOT an arbitrary sentinel —
     * backstop_decide compares by equality, so a mismatched seed would
     * look like "the counter just moved" on every poll and never fire). */
    {
        supervisor_backstop_test_reset();
        supervisor_backstop_test_force_off_systemd(true);
        /* Pin the serving stage so the 30 s bar (not the generous
         * pre-serving boot budget) applies — this test exercises the
         * serving-time escalation plumbing. */
        supervisor_backstop_test_force_boot_stage(BOOT_STAGE_SERVICES_RUNNING);
        struct supervisor_backstop_state st = {0};
        int64_t threshold = 30 * 1000000LL;

        supervisor_backstop_test_poll(&st, 0, threshold);
        BS_CHECK("respawn not yet requested before the freeze crosses",
            !supervisor_backstop_respawn_requested());

        supervisor_backstop_test_poll(&st, 31 * 1000000LL, threshold);
        BS_CHECK("off-systemd frozen span latches respawn_requested",
            supervisor_backstop_respawn_requested());

        supervisor_backstop_test_reset();
    }

    /* ── production poll seam: on-systemd never latches respawn ────── */
    {
        supervisor_backstop_test_reset();
        supervisor_backstop_test_force_off_systemd(false);
        supervisor_backstop_test_force_boot_stage(BOOT_STAGE_SERVICES_RUNNING);
        struct supervisor_backstop_state st = {0};
        int64_t threshold = 30 * 1000000LL;

        supervisor_backstop_test_poll(&st, 0, threshold);
        supervisor_backstop_test_poll(&st, 31 * 1000000LL, threshold);
        BS_CHECK("on-systemd frozen span does NOT latch respawn "
                 "(systemd's own WatchdogSec path owns that case)",
            !supervisor_backstop_respawn_requested());

        supervisor_backstop_test_reset();
    }

    /* ── boot-stage-aware: a chunk-pumping boot loop survives past 30 s ─
     *
     * Reproduces the live false-kill: a single-threaded PRE-serving boot
     * stage (the ~3.1M-entry block-index verify) whose supervisor sweep
     * heartbeat is FROZEN (background threads don't exist yet), but which
     * pumps boot_progress_note() at chunk boundaries. The combined
     * liveness (sweep_hb + boot_progress) keeps advancing, so the backstop
     * must NOT fire — even as the injected wall clock runs far past both
     * the 30 s serving bar AND the generous boot budget. */
    {
        struct supervisor_backstop_state st = {0};
        int64_t serving_bar = SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US; /* 30 s */
        int     stage = BOOT_STAGE_BLOCK_INDEX_LOADED;              /* pre-serving */
        uint64_t sweep = 5;   /* frozen: boot is single-threaded */
        uint64_t prog  = 0;
        bool any_fired = false;

        any_fired |= supervisor_backstop_test_check_staged(
            &st, sweep, prog, stage, 0, serving_bar);   /* seed */

        /* 40 chunks, each pumps progress once and advances the clock 10 s
         * (=400 s total, well past the 300 s boot budget). A progressing
         * loop must never look like a hang. */
        for (int c = 1; c <= 40; c++) {
            prog++;   /* chunk-tick: boot_progress_note() bumped the marker */
            any_fired |= supervisor_backstop_test_check_staged(
                &st, sweep, prog, stage, (int64_t)c * 10 * 1000000LL,
                serving_bar);
        }
        BS_CHECK("chunk-pumping pre-serving boot loop never false-fires "
                 "past the 30 s bar", !any_fired);
    }

    /* ── boot-stage-aware: frozen sweep DURING SERVING still dies at 30 s ─
     *
     * The invariant the fix must preserve: once the process is serving,
     * boot_progress is static and the 30 s bar applies unchanged, so a
     * genuinely frozen supervisor sweep is killed on time. */
    {
        struct supervisor_backstop_state st = {0};
        int64_t serving_bar = SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US;
        int     stage = BOOT_STAGE_READY;   /* serving */
        uint64_t sweep = 7;                 /* frozen */
        uint64_t prog  = 100;               /* static: no boot loop runs */

        BS_CHECK("serving seed poll does not fire",
            !supervisor_backstop_test_check_staged(&st, sweep, prog, stage,
                                                   0, serving_bar));
        BS_CHECK("serving just-under-30s does not fire",
            !supervisor_backstop_test_check_staged(&st, sweep, prog, stage,
                                                   29 * 1000000LL, serving_bar));
        BS_CHECK("serving frozen sweep fires at exactly the 30 s bar",
            supervisor_backstop_test_check_staged(&st, sweep, prog, stage,
                                                  30 * 1000000LL, serving_bar));
    }

    /* ── boot-stage-aware: a genuinely wedged boot is bounded, not silent ─
     *
     * A pre-serving stage that makes ZERO progress (no sweep, no pump, no
     * stage advance) must NOT be killed at the 30 s serving bar (that was
     * the false-kill), but IS still caught at the generous boot budget —
     * a wedge is always eventually named, never a silent halt. */
    {
        struct supervisor_backstop_state st = {0};
        int64_t serving_bar = SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US;
        int     stage = BOOT_STAGE_BLOCK_INDEX_LOADED;  /* pre-serving */
        uint64_t sweep = 5;                             /* frozen */
        uint64_t prog  = 0;                             /* wedged: nothing pumps */

        (void)supervisor_backstop_test_check_staged(&st, sweep, prog, stage,
                                                    0, serving_bar);   /* seed */
        BS_CHECK("wedged pre-serving boot NOT killed at the 30 s serving bar",
            !supervisor_backstop_test_check_staged(&st, sweep, prog, stage,
                                                   30 * 1000000LL, serving_bar));
        BS_CHECK("wedged pre-serving boot still survives just under boot budget",
            !supervisor_backstop_test_check_staged(
                &st, sweep, prog, stage,
                SUPERVISOR_BACKSTOP_BOOT_FREEZE_US - 1000000LL, serving_bar));
        BS_CHECK("wedged pre-serving boot IS caught at the boot budget",
            supervisor_backstop_test_check_staged(
                &st, sweep, prog, stage,
                SUPERVISOR_BACKSTOP_BOOT_FREEZE_US, serving_bar));
    }

    /* Watcher observation gap: process suspension is not a wedge. The
     * production watcher must distinguish a supervisor thread that stays
     * frozen while the watcher continues to poll from SIGSTOP/host suspend,
     * where the watcher itself made no observations for the entire budget. */
    {
        int64_t threshold = SUPERVISOR_BACKSTOP_DEFAULT_FREEZE_US;
        BS_CHECK("ordinary poll cadence is continuous observation",
            !supervisor_backstop_test_observation_gap(
                5 * 1000000LL, 10 * 1000000LL, threshold));
        BS_CHECK("whole-budget watcher absence names an observation gap",
            supervisor_backstop_test_observation_gap(
                5 * 1000000LL, 35 * 1000000LL, threshold));
        BS_CHECK("disabled threshold never classifies a suspension",
            !supervisor_backstop_test_observation_gap(
                5 * 1000000LL, 1000 * 1000000LL, 0));

        struct supervisor_backstop_state st = {0};
        (void)supervisor_backstop_test_check_staged(
            &st, 7, 100, BOOT_STAGE_READY, 5 * 1000000LL, threshold);
        /* Mirror production's rebase after the watcher itself was absent. */
        if (supervisor_backstop_test_observation_gap(
                5 * 1000000LL, 105 * 1000000LL, threshold))
            st.initialized = false;
        BS_CHECK("process suspension rebases instead of false-firing",
            !supervisor_backstop_test_check_staged(
                &st, 7, 100, BOOT_STAGE_READY,
                105 * 1000000LL, threshold));
        BS_CHECK("continuously observed post-resume wedge remains bounded",
            supervisor_backstop_test_check_staged(
                &st, 7, 100, BOOT_STAGE_READY,
                135 * 1000000LL, threshold));
    }

    /* dump_state_json shape. */
    {
        struct json_value out;
        json_init(&out);
        bool ok = supervisor_backstop_dump_state_json(&out, NULL);
        ok = ok && json_get(&out, "running") != NULL;
        ok = ok && json_get(&out, "poll_interval_us") != NULL;
        ok = ok && json_get(&out, "freeze_threshold_us") != NULL;
        ok = ok && json_get(&out, "respawn_requested") != NULL;
        ok = ok && json_get(&out, "sweep_heartbeat") != NULL;
        ok = ok && json_get(&out, "sweep_last_age_us") != NULL;
        ok = ok && json_get(&out, "boot_progress") != NULL;
        ok = ok && json_get(&out, "boot_stage") != NULL;
        ok = ok && json_get(&out, "effective_freeze_threshold_us") != NULL;
        BS_CHECK("dump_state_json exposes the full contract", ok);
        json_free(&out);
    }

    supervisor_backstop_test_reset();
    return failures;
}
