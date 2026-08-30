/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the memory-pressure organ (lib/util/src/mem_pressure.c) —
 * Rung 1 follow-on, docs/adr/0003-os-substrate-verdict.md.
 *
 * Coverage:
 *   - level classification walks NOMINAL -> ELEVATED -> HIGH -> CRITICAL as
 *     the os_proc_mem override's usage/denominator ratio crosses the
 *     default 50/75/90 thresholds
 *   - denominator priority: cgroup_high > cgroup_max > system availability
 *   - host-wide pressure outranks a low process RSS when availability exists
 *   - registered sinks fire at HIGH and CRITICAL, NOT at NOMINAL/ELEVATED
 *   - shrink_calls / last_shrink_unix bookkeeping increments correctly
 *   - dump_state_json reports the current level + sink stats
 *
 * Drives mem_pressure_poll_tick() directly (not via the health ring) so the
 * test is synchronous and deterministic, per the os_proc test override
 * seam (platform/os_proc.h).
 */

#include "test/test_core.h"
#include "util/mem_pressure.h"
#include "platform/os_proc.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MP_CHECK(name, expr) do { \
    printf("mem_pressure: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* File-scope shrink callback for the sink-firing test below (a static
 * struct field initializer cannot reference a nested/local function). */
static void mp_test_shrink(enum mem_pressure_level level, void *ctx)
{
    (void)level;
    (void)ctx;
}

static void set_override(int64_t rss, int64_t cgroup_current,
                         int64_t cgroup_high, int64_t cgroup_max,
                         int64_t sys_total, int64_t sys_avail)
{
    struct os_proc_mem forced = {
        .rss_bytes = rss,
        .vsize_bytes = rss,
        .cgroup_current = cgroup_current,
        .cgroup_high = cgroup_high,
        .cgroup_max = cgroup_max,
        .sys_total_bytes = sys_total,
        .sys_avail_bytes = sys_avail,
    };
    os_proc_mem_set_override(&forced);
}

int test_mem_pressure(void);
int test_mem_pressure(void)
{
    printf("\n=== mem_pressure tests ===\n");
    int failures = 0;

    mem_pressure_reset_for_testing();

    /* ── level transitions via sys_total denominator (no cgroup) ────── */
    {
        set_override(100, -1, -1, -1, 1000, 900);   /* 10% */
        mem_pressure_poll_tick();
        MP_CHECK("10% usage -> NOMINAL",
                 mem_pressure_current() == MEM_NOMINAL);

        set_override(600, -1, -1, -1, 1000, 400);   /* 60% */
        mem_pressure_poll_tick();
        MP_CHECK("60% usage -> ELEVATED (>=50%, <75%)",
                 mem_pressure_current() == MEM_ELEVATED);

        set_override(800, -1, -1, -1, 1000, 200);   /* 80% */
        mem_pressure_poll_tick();
        MP_CHECK("80% usage -> HIGH (>=75%, <90%)",
                 mem_pressure_current() == MEM_HIGH);

        set_override(950, -1, -1, -1, 1000, 50);    /* 95% */
        mem_pressure_poll_tick();
        MP_CHECK("95% usage -> CRITICAL (>=90%)",
                 mem_pressure_current() == MEM_CRITICAL);

        set_override(100, -1, -1, -1, 1000, 900);   /* back to 10% */
        mem_pressure_poll_tick();
        MP_CHECK("dropping back to 10% -> NOMINAL again",
                 mem_pressure_current() == MEM_NOMINAL);
    }

    /* ── host availability captures pressure outside this process ───── */
    {
        set_override(10, -1, -1, -1, 1000, 100); /* host is 90% used */
        mem_pressure_poll_tick();
        MP_CHECK("host-wide pressure outranks this process's low RSS",
                 mem_pressure_current() == MEM_CRITICAL);

        struct json_value out;
        json_init(&out);
        json_set_object(&out);
        MP_CHECK("host-wide pressure dump succeeds",
                 mem_pressure_dump_state_json(&out, NULL));
        const struct json_value *basis = json_get(&out, "denominator_basis");
        MP_CHECK("host-wide pressure reports system_available basis",
                 basis &&
                 strcmp(json_get_str(basis), "system_available") == 0);
        json_free(&out);

        set_override(800, -1, -1, -1, 1000, -1);
        mem_pressure_poll_tick();
        MP_CHECK("RSS fallback remains active when availability is unknown",
                 mem_pressure_current() == MEM_HIGH);
    }

    /* ── denominator priority: cgroup_high beats cgroup_max/sys_total ── */
    {
        /* cgroup_current=80/cgroup_high=100 -> 80% (HIGH), even though
         * sys_total-based usage would read differently (RSS unused here
         * since a cgroup denominator was selected). */
        set_override(999999 /* rss, ignored */, 80, 100, 10000,
                     1000000, 900000);
        mem_pressure_poll_tick();
        MP_CHECK("cgroup_high selected over cgroup_max/sys_total when set",
                 mem_pressure_current() == MEM_HIGH);

        /* No cgroup_high, cgroup_max=100, current=95 -> 95% CRITICAL via
         * cgroup_max. */
        set_override(999999, 95, -1, 100, 1000000, 900000);
        mem_pressure_poll_tick();
        MP_CHECK("cgroup_max used when cgroup_high unset",
                 mem_pressure_current() == MEM_CRITICAL);
    }

    /* ── sink firing: only at HIGH/CRITICAL ──────────────────────────── */
    {
        static struct mem_pressure_sink sink;
        sink = (struct mem_pressure_sink){
            .name = "test_sink",
            .shrink = mp_test_shrink,
            .ctx = NULL,
        };

        bool reg_ok = mem_pressure_register_sink(&sink);
        MP_CHECK("register_sink succeeds", reg_ok);

        /* Idempotent re-registration. */
        bool reg_ok2 = mem_pressure_register_sink(&sink);
        MP_CHECK("re-registering the same pointer is a no-op success",
                 reg_ok2);

        set_override(100, -1, -1, -1, 1000, 900);  /* NOMINAL */
        mem_pressure_poll_tick();
        MP_CHECK("sink does NOT fire at NOMINAL",
                 atomic_load(&sink.shrink_calls) == 0);

        set_override(600, -1, -1, -1, 1000, 400);  /* ELEVATED */
        mem_pressure_poll_tick();
        MP_CHECK("sink does NOT fire at ELEVATED",
                 atomic_load(&sink.shrink_calls) == 0);

        set_override(800, -1, -1, -1, 1000, 200);  /* HIGH */
        mem_pressure_poll_tick();
        MP_CHECK("sink fires at HIGH",
                 atomic_load(&sink.shrink_calls) == 1);
        MP_CHECK("last_shrink_unix set after firing",
                 atomic_load(&sink.last_shrink_unix) > 0);

        set_override(950, -1, -1, -1, 1000, 50);   /* CRITICAL */
        mem_pressure_poll_tick();
        MP_CHECK("sink fires again at CRITICAL",
                 atomic_load(&sink.shrink_calls) == 2);
    }

    /* ── dump_state_json ──────────────────────────────────────────── */
    {
        set_override(800, -1, -1, -1, 1000, 200);  /* HIGH */
        mem_pressure_poll_tick();

        struct json_value out;
        json_init(&out);
        json_set_object(&out);
        bool ok = mem_pressure_dump_state_json(&out, NULL);
        MP_CHECK("dump_state_json returns true", ok);

        const struct json_value *level = json_get(&out, "level");
        MP_CHECK("dump has level=high",
                 level && strcmp(json_get_str(level), "high") == 0);

        const struct json_value *sinks = json_get(&out, "sinks");
        MP_CHECK("dump has a non-empty sinks array",
                 sinks && json_size(sinks) >= 1);

        json_free(&out);
    }

    /* ── unavailable readings default to NOMINAL, never crash ───────── */
    {
        set_override(-1, -1, -1, -1, -1, -1);
        mem_pressure_poll_tick();
        MP_CHECK("all-unavailable reading classifies as NOMINAL (fail-quiet)",
                 mem_pressure_current() == MEM_NOMINAL);
    }

    os_proc_mem_set_override(NULL);
    mem_pressure_reset_for_testing();

    if (failures == 0) {
        printf("=== mem_pressure tests: ALL PASS ===\n\n");
    } else {
        printf("=== mem_pressure tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
