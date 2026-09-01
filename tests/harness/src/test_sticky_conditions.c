/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic engine test for the stickiness conditions (sticky-node-plan #13):
 * disk_full_pause, clock_skew_reconcile, and memory_pressure_high (Rung 1
 * follow-on, docs/adr/0003-os-substrate-verdict.md). Drives each through the
 * real condition engine: detect -> remedy -> witness -> cleared, and proves
 * NEITHER latches operator_needed on its recoverable class (constraint b:
 * no new give-up). The fault-injection spawn MATRIX (rows that need a real
 * node) lives in tools/scripts/sticky_matrix.sh; this is its unit-level
 * complement for the rows that cannot be injected from outside the process
 * (binary clock, mounted tmpfs, forced /proc memory readings). */

#include "test/test_core.h"

#include "conditions/clock_skew_reconcile.h"
#include "conditions/disk_full_pause.h"
#include "conditions/disk_low_pause.h"
#include "conditions/memory_pressure_high.h"
#include "framework/condition.h"
#include "platform/clock.h"
#include "platform/os_proc.h"
#include "services/disk_monitor.h"
#include "services/index_fold_guard.h"
#include "util/blocker.h"
#include "util/mem_pressure.h"

#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

#define SC_CHECK(name, expr) do { \
    printf("sticky_conditions: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Injected wall clock: monotonic stays real; we step wall on demand. ──
 * IMPORTANT: monotonic_us must read the RAW clock directly (clock_gettime),
 * NOT clock_now_monotonic_ns() — once this source is installed the latter
 * routes back through monotonic_us, which would recurse infinitely (stack
 * overflow / SIGKILL). The injected source only overrides the WALL clock. */
static _Atomic int64_t g_inj_wall_unix;
static int64_t inj_wall(void *user) { (void)user; return atomic_load(&g_inj_wall_unix); }
static int64_t inj_mono(void *user)
{
    (void)user;
    struct timespec ts;
    /* RAW clock by necessity: platform.clock's reader routes back through THIS
     * source once installed (would recurse infinitely). This fixture only
     * overrides the WALL clock; monotonic must stay the real syscall. */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)  // platform-ok:test-injected-wall-clock-source-must-not-recurse-monotonic
        return 0;
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}
static struct platform_clock_source g_inj_src = { .monotonic_us = inj_mono,
                                                  .wall_unix = inj_wall };

int test_sticky_conditions(void);
int test_sticky_conditions(void)
{
    int failures = 0;

    /* ───────────────── clock_skew_reconcile ───────────────── */
    {
        condition_engine_reset_for_testing();
        clock_skew_reconcile_test_reset();

        /* Seed the injected wall clock at a known epoch and install it. */
        atomic_store(&g_inj_wall_unix, 1700000000);
        platform_clock_set_source(&g_inj_src);

        register_clock_skew_reconcile();

        /* Poll 1: seeds the baseline, no skew yet. */
        condition_engine_tick();
        SC_CHECK("clock_skew: no false-positive on first poll",
                 condition_engine_get_active_count() == 0);

        /* Inject a +1 hour wall jump (monotonic barely moved): a real step. */
        atomic_store(&g_inj_wall_unix, 1700000000 + 3600);
        condition_engine_tick();   /* detect fires; remedy + witness run */
        struct condition_runtime_snapshot snap;
        bool got = condition_engine_get_registered_snapshot(
                       "clock_skew_reconcile", &snap);
        SC_CHECK("clock_skew: remedy ran on the injected jump",
                 clock_skew_reconcile_test_remedy_calls() >= 1);
        SC_CHECK("clock_skew: did NOT latch operator_needed (recoverable class)",
                 got && !snap.operator_needed_emitted);

        /* Steady the clock; the condition must clear (witness Δwall≈Δmono). */
        condition_engine_tick();
        SC_CHECK("clock_skew: clears once the clock is stable again",
                 condition_engine_get_active_count() == 0);

        platform_clock_clear_source();
        condition_engine_reset_for_testing();
        clock_skew_reconcile_test_reset();
    }

    /* ───────────────── disk_full_pause ───────────────── */
    {
        condition_engine_reset_for_testing();
        disk_full_pause_test_reset();

        /* Drive disk_monitor against a temp dir with tiny thresholds so we can
         * flip CRITICAL on/off deterministically. refuse=huge -> CRITICAL;
         * refuse=1 -> OK (any real fs has >=1 byte free). */
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir = "/tmp";
        cfg.warn_free_bytes = (int64_t)1 << 62;   /* always warn */
        cfg.refuse_free_bytes = (int64_t)1 << 62; /* always CRITICAL */
        cfg.poll_seconds = 3600;                  /* we poll_now manually */
        (void)disk_monitor_start(&cfg);
        disk_monitor_poll_now();
        SC_CHECK("disk_full: monitor reports CRITICAL under impossible threshold",
                 disk_monitor_is_critical());

        register_disk_full_pause();
        condition_engine_tick();   /* detect CRITICAL -> remedy */
        SC_CHECK("disk_full: remedy ran while disk critical",
                 disk_full_pause_test_remedy_calls() >= 1);
        struct condition_runtime_snapshot dsnap;
        bool dgot = condition_engine_get_registered_snapshot(
                        "disk_full_pause", &dsnap);
        SC_CHECK("disk_full: did NOT latch operator_needed (transient resource)",
                 dgot && !dsnap.operator_needed_emitted);

        /* Free space: lower the refuse threshold so the next poll is OK. */
        disk_monitor_stop();
        disk_monitor_config_defaults(&cfg);
        cfg.datadir = "/tmp";
        cfg.warn_free_bytes = 1;
        cfg.refuse_free_bytes = 1;
        cfg.poll_seconds = 3600;
        (void)disk_monitor_start(&cfg);
        disk_monitor_poll_now();
        SC_CHECK("disk_full: monitor reports OK once space returns",
                 !disk_monitor_is_critical());

        condition_engine_tick();   /* detect false + witness -> cleared */
        SC_CHECK("disk_full: condition clears once space returns",
                 condition_engine_get_active_count() == 0);

        disk_monitor_stop();
        condition_engine_reset_for_testing();
        disk_full_pause_test_reset();
    }

    /* ───────────────── disk_low_pause ───────────────── */
    {
        condition_engine_reset_for_testing();
        disk_low_pause_test_reset();
        blocker_clear("address_index.disk_low");
        blocker_clear("txindex.disk_low");

        /* Force the fold's own free-space floor absurdly high so
         * index_fold_disk_ok() latches its "<index_id>.disk_low" blocker
         * regardless of the real free space on /tmp — deterministic,
         * independent of the (unrelated, unstarted here) disk_monitor
         * background thread. */
        index_fold_set_min_free_for_test((int64_t)1 << 62);
        bool fold_ok = index_fold_disk_ok("address_index", "test", "/tmp");
        SC_CHECK("disk_low: index_fold_disk_ok raises the blocker under "
                 "an impossible floor",
                 !fold_ok && blocker_exists("address_index.disk_low"));

        register_disk_low_pause();
        condition_engine_tick();   /* detect blocker present -> remedy */
        SC_CHECK("disk_low: remedy ran while the index-fold blocker is set",
                 disk_low_pause_test_remedy_calls() >= 1);
        struct condition_runtime_snapshot lsnap;
        bool lgot = condition_engine_get_registered_snapshot(
                        "disk_low_pause", &lsnap);
        SC_CHECK("disk_low: did NOT latch operator_needed (transient resource)",
                 lgot && !lsnap.operator_needed_emitted);

        /* Restore the real floor and re-run the fold gate so it clears its
         * own blocker (disk_low_pause never clears "<index_id>.disk_low"
         * itself — the fold's own next pass does, per index_fold_guard.c). */
        index_fold_set_min_free_for_test(-1);
        disk_monitor_set_free_bytes_for_test((int64_t)200 << 30);
        fold_ok = index_fold_disk_ok("address_index", "test", "/tmp");
        disk_monitor_set_free_bytes_for_test(-1);
        SC_CHECK("disk_low: index_fold_disk_ok clears the blocker once the "
                 "floor is realistic again",
                 fold_ok && !blocker_exists("address_index.disk_low"));

        condition_engine_tick();   /* detect false + witness -> cleared */
        SC_CHECK("disk_low: condition clears once the index-fold blocker "
                 "is gone",
                 condition_engine_get_active_count() == 0);

        condition_engine_reset_for_testing();
        disk_low_pause_test_reset();
        blocker_clear("address_index.disk_low");
        blocker_clear("txindex.disk_low");
    }

    /* ───────────────── memory_pressure_high ───────────────── */
    {
        condition_engine_reset_for_testing();
        memory_pressure_high_test_reset();
        mem_pressure_reset_for_testing();

        /* Force CRITICAL via the os_proc override seam (platform/os_proc.h):
         * no cgroup, sys_total=1000, rss=950 -> 95%, well above the default
         * 90% critical threshold. */
        struct os_proc_mem forced_high = {
            .rss_bytes = 950, .vsize_bytes = 950,
            .cgroup_current = -1, .cgroup_high = -1, .cgroup_max = -1,
            .sys_total_bytes = 1000, .sys_avail_bytes = 50,
        };
        os_proc_mem_set_override(&forced_high);
        mem_pressure_poll_tick();
        SC_CHECK("memory_pressure: mem_pressure reports CRITICAL under forced override",
                 mem_pressure_current() == MEM_CRITICAL);

        register_memory_pressure_high();
        condition_engine_tick();   /* detect CRITICAL -> remedy */
        SC_CHECK("memory_pressure: remedy ran while pressure critical",
                 memory_pressure_high_test_remedy_calls() >= 1);
        struct condition_runtime_snapshot msnap;
        bool mgot = condition_engine_get_registered_snapshot(
                        "memory_pressure_high", &msnap);
        SC_CHECK("memory_pressure: did NOT latch operator_needed (transient resource)",
                 mgot && !msnap.operator_needed_emitted);

        /* Usage drops back below HIGH: the next witness poll must clear. */
        struct os_proc_mem forced_low = {
            .rss_bytes = 100, .vsize_bytes = 100,
            .cgroup_current = -1, .cgroup_high = -1, .cgroup_max = -1,
            .sys_total_bytes = 1000, .sys_avail_bytes = 900,
        };
        os_proc_mem_set_override(&forced_low);
        mem_pressure_poll_tick();
        SC_CHECK("memory_pressure: mem_pressure reports NOMINAL once usage drops",
                 mem_pressure_current() == MEM_NOMINAL);

        condition_engine_tick();   /* detect false + witness -> cleared */
        SC_CHECK("memory_pressure: condition clears once usage drops",
                 condition_engine_get_active_count() == 0);

        os_proc_mem_set_override(NULL);
        mem_pressure_reset_for_testing();
        condition_engine_reset_for_testing();
        memory_pressure_high_test_reset();
    }

    printf("\n=== sticky_conditions: %d failure(s) ===\n", failures);
    return failures;
}
