/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the disk_monitor service.
 *
 * The trick used here to exercise the LOW and CRITICAL branches
 * without actually filling a filesystem is to set the thresholds
 * above the real free-space number on the test host. A LOW test
 * uses `warn = INT64_MAX, refuse = 1` — every real filesystem
 * satisfies `free >= 1 && free < INT64_MAX`, so we land in LOW.
 * CRITICAL uses `refuse = INT64_MAX` so every value lands in
 * CRITICAL. OK uses `warn = 1` so `free >= warn` → OK.
 *
 * These tests don't rely on the background poll thread — they
 * call `disk_monitor_poll_now()` synchronously so the test
 * doesn't have to sleep. The start/stop lifecycle is covered
 * separately.
 */

#include "test/test_core.h"
#include "services/disk_monitor.h"
#include "event/event.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test/setup_result.h"

#define DM_SCRATCH_DIR "./test-tmp"

static _Atomic int g_ev_low;
static _Atomic int g_ev_crit;
static _Atomic int g_ev_ok;

static void dm_ev_observer(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_DISK_LOW)      atomic_fetch_add(&g_ev_low, 1);
    if (type == EV_DISK_CRITICAL) atomic_fetch_add(&g_ev_crit, 1);
    if (type == EV_DISK_OK)       atomic_fetch_add(&g_ev_ok, 1);
}

static void dm_reset_observer(void)
{
    event_clear_observers(EV_DISK_LOW);
    event_clear_observers(EV_DISK_CRITICAL);
    event_clear_observers(EV_DISK_OK);
    atomic_store(&g_ev_low, 0);
    atomic_store(&g_ev_crit, 0);
    atomic_store(&g_ev_ok, 0);
    event_observe(EV_DISK_LOW,      dm_ev_observer, NULL);
    event_observe(EV_DISK_CRITICAL, dm_ev_observer, NULL);
    event_observe(EV_DISK_OK,       dm_ev_observer, NULL);
}

#define DM_CHECK(name, expr) do { \
    printf("%s... ", (name));    \
    if ((expr)) printf("OK\n");  \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_disk_monitor(void)
{
    printf("\n=== disk_monitor tests ===\n");
    int failures = 0;

    mkdir(DM_SCRATCH_DIR, 0755);

    /* ── 1. free_bytes returns positive for a real path ───── */
    {
        int64_t free_b = disk_monitor_free_bytes(DM_SCRATCH_DIR);
        DM_CHECK("dm: disk_monitor_free_bytes returns positive for a real dir",
                 free_b > 0);
    }

    /* ── 2. free_bytes returns -1 for a bogus path ───────── */
    {
        int64_t free_b = disk_monitor_free_bytes("/nonexistent-path-for-dm-test-12345");
        DM_CHECK("dm: free_bytes returns -1 for a path that can't be stat'd",
                 free_b == -1);
        int64_t null_b = disk_monitor_free_bytes(NULL);
        DM_CHECK("dm: free_bytes returns -1 for NULL path", null_b == -1);
    }

    /* ── 3. OK classification ───────────────────────────── */
    {
        dm_reset_observer();
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir           = DM_SCRATCH_DIR;
        cfg.warn_free_bytes   = 1;   /* any real fs has >= 1 byte free */
        cfg.refuse_free_bytes = 1;
        cfg.poll_seconds      = 3600;
        bool started = disk_monitor_start(&cfg).ok;
        DM_CHECK("dm: start succeeds with small thresholds",
                 started && disk_monitor_level() == DISK_MONITOR_OK);
        disk_monitor_stop();
    }

    /* ── 4. LOW classification fires EV_DISK_LOW once ────── */
    {
        dm_reset_observer();
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir           = DM_SCRATCH_DIR;
        cfg.warn_free_bytes   = INT64_MAX;  /* free < warn → LOW */
        cfg.refuse_free_bytes = 1;
        cfg.poll_seconds      = 3600;
        bool started = disk_monitor_start(&cfg).ok;
        bool is_low  = disk_monitor_level() == DISK_MONITOR_LOW;
        int  low_count = atomic_load(&g_ev_low);

        /* Second poll at the same level should NOT re-fire (edge trigger). */
        disk_monitor_poll_now();
        int low_after = atomic_load(&g_ev_low);

        DM_CHECK("dm: LOW threshold flips level to DISK_MONITOR_LOW",
                 started && is_low);
        DM_CHECK("dm: EV_DISK_LOW fires exactly once on first transition",
                 low_count == 1);
        DM_CHECK("dm: second poll at same level does NOT re-fire EV_DISK_LOW",
                 low_after == 1);
        DM_CHECK("dm: is_critical() is false when level is LOW",
                 !disk_monitor_is_critical());
        disk_monitor_stop();
    }

    /* ── 5. CRITICAL classification + is_critical() flag ── */
    {
        dm_reset_observer();
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir           = DM_SCRATCH_DIR;
        cfg.warn_free_bytes   = INT64_MAX;
        cfg.refuse_free_bytes = INT64_MAX;  /* free < refuse → CRITICAL */
        cfg.poll_seconds      = 3600;
        bool started = disk_monitor_start(&cfg).ok;
        bool is_crit = disk_monitor_level() == DISK_MONITOR_CRITICAL;
        int  crit_count = atomic_load(&g_ev_crit);
        DM_CHECK("dm: CRITICAL threshold flips level to DISK_MONITOR_CRITICAL",
                 started && is_crit);
        DM_CHECK("dm: EV_DISK_CRITICAL fires on first transition",
                 crit_count == 1);
        DM_CHECK("dm: is_critical() returns true immediately",
                 disk_monitor_is_critical());
        disk_monitor_stop();
    }

    /* ── 6. Recovery: critical → OK fires EV_DISK_OK ────── */
    {
        dm_reset_observer();
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir           = DM_SCRATCH_DIR;
        cfg.warn_free_bytes   = INT64_MAX;
        cfg.refuse_free_bytes = INT64_MAX;
        cfg.poll_seconds      = 3600;
        ZCL_TEST_SETUP(disk_monitor_start(&cfg));
        bool was_crit = disk_monitor_is_critical();
        disk_monitor_stop();

        /* Start over with thresholds that classify as OK. */
        dm_reset_observer();
        cfg.warn_free_bytes   = 1;
        cfg.refuse_free_bytes = 1;
        ZCL_TEST_SETUP(disk_monitor_start(&cfg));
        bool now_ok = disk_monitor_level() == DISK_MONITOR_OK;
        /* EV_DISK_OK only fires on a *transition*. Since each
         * fresh start() begins at last_level=DISK_MONITOR_OK, an
         * initial OK poll produces no edge. Verify the atomic
         * flag cleared, and that no stale CRITICAL event leaked. */
        DM_CHECK("dm: critical state cleared after restart with OK thresholds",
                 was_crit && now_ok && !disk_monitor_is_critical());
        DM_CHECK("dm: restart with OK thresholds emits no CRITICAL",
                 atomic_load(&g_ev_crit) == 0);
        disk_monitor_stop();
    }

    /* ── 7. start() rejects when already running ─────────── */
    {
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir      = DM_SCRATCH_DIR;
        cfg.poll_seconds = 3600;
        bool first  = disk_monitor_start(&cfg).ok;
        bool second = disk_monitor_start(&cfg).ok;
        DM_CHECK("dm: start() rejects when already running",
                 first && !second);
        disk_monitor_stop();
    }

    /* ── 8. start() rejects an un-statable datadir ───────── */
    {
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir      = "/nonexistent-path-for-dm-test-67890";
        cfg.poll_seconds = 3600;
        bool rejected = !disk_monitor_start(&cfg).ok;
        DM_CHECK("dm: start() refuses a datadir that can't be stat'd",
                 rejected);
    }

    /* ── 9. stop() is a safe no-op before start ──────────── */
    {
        disk_monitor_stop();
        disk_monitor_stop();
        DM_CHECK("dm: stop() is a safe no-op when not running", true);
    }

    /* ── 10. status snapshot reflects the last poll ──────── */
    {
        struct disk_monitor_config cfg;
        disk_monitor_config_defaults(&cfg);
        cfg.datadir           = DM_SCRATCH_DIR;
        cfg.warn_free_bytes   = 42;
        cfg.refuse_free_bytes = 21;
        cfg.poll_seconds      = 3600;
        ZCL_TEST_SETUP(disk_monitor_start(&cfg));
        struct disk_monitor_status st;
        disk_monitor_status_snapshot(&st);
        DM_CHECK("dm: status snapshot records running + thresholds + datadir",
                 st.running &&
                 st.warn_free_bytes   == 42 &&
                 st.refuse_free_bytes == 21 &&
                 st.last_free_bytes    > 0  &&
                 strcmp(st.datadir, DM_SCRATCH_DIR) == 0);
        disk_monitor_stop();
    }

    event_clear_observers(EV_DISK_LOW);
    event_clear_observers(EV_DISK_CRITICAL);
    event_clear_observers(EV_DISK_OK);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
