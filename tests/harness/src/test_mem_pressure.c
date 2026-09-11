/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the memory-pressure organ (platform/modules/util/src/mem_pressure.c) —
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
 *   - on a cgroup basis the numerator excludes the droppable page cache
 *     (memory.stat `file` less `shmem`, `unevictable`, `file_dirty` and
 *     `file_writeback`), so a cache pinned by a bulk flush still reads as
 *     pressure, and falls back to the raw memory.current when any one row is
 *     unreadable or the read is torn
 *   - that fallback publishes evictable_bytes as -1 (unknown), which an
 *     operator can tell from a readable 0 (no droppable cache at all)
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

/* Sibling of set_override() for the cgroup memory.stat tier: set_override()
 * has 20+ call sites, so the droppable-cache cases get their own seam
 * instead of widening it. */
static void set_cgroup_override(int64_t cgroup_current, int64_t cgroup_high,
                                struct os_proc_cgroup_mem_stat stat)
{
    struct os_proc_mem forced = {
        .rss_bytes = 3951034368,
        .vsize_bytes = 3951034368,
        .cgroup_current = cgroup_current,
        .cgroup_high = cgroup_high,
        .cgroup_max = -1,
        .cgroup_stat = stat,
        .sys_total_bytes = -1,
        .sys_avail_bytes = -1,
    };
    os_proc_mem_set_override(&forced);
}

/* memory.stat rows for a cgroup with nothing dirty and nothing under
 * writeback — the page-cache-only shapes. The dirty/writeback cases below
 * spell their rows out instead. */
static struct os_proc_cgroup_mem_stat clean_stat(int64_t file, int64_t shmem,
                                                 int64_t unevictable)
{
    return (struct os_proc_cgroup_mem_stat){
        .file = file,
        .shmem = shmem,
        .unevictable = unevictable,
        .file_dirty = 0,
        .file_writeback = 0,
    };
}

/* One field of the organ's published ops-state document, or -2 when the
 * document has no such field. This is the surface an operator reads, and
 * the only place the "unknown" (-1) and "readable, none droppable" (0)
 * states of the droppable tier are distinguishable. */
static int64_t dumped_state_int(const char *key)
{
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    int64_t value = -2;
    if (mem_pressure_dump_state_json(&doc, NULL)) {
        const struct json_value *field = json_get(&doc, key);
        if (field)
            value = json_get_int(field);
    }
    json_free(&doc);
    return value;
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

    /* ── page cache is not pressure (node3 2026-09-10 shape) ────────── */
    {
        /* Denominator is 12884901888 (12 GiB memory.high) throughout;
         * default thresholds 50/75/90. */

        /* A sequential scan walked 7 GiB of droppable page cache into the
         * charge. Numerator 3416776704 = 26% -> NOMINAL. Before this fix
         * the raw charge read 84% -> HIGH and fired every shrink sink. */
        set_cgroup_override(10932969472, 12884901888,
                            clean_stat(7516192768, 0, 0));
        mem_pressure_poll_tick();
        MP_CHECK("scan-warmed page cache is not pressure",
                 mem_pressure_current() == MEM_NOMINAL);

        /* Anon-dominated charge: 11945377792 = 92% -> CRITICAL, the same
         * level the raw charge (93%) produced. */
        set_cgroup_override(12079595520, 12884901888,
                            clean_stat(134217728, 0, 0));
        mem_pressure_poll_tick();
        MP_CHECK("anon-dominated charge still reads CRITICAL",
                 mem_pressure_current() == MEM_CRITICAL);

        /* No memory.stat at all: every row -1, so the organ falls back to
         * the raw charge -> 84% -> HIGH, exactly the shipped behaviour. */
        set_cgroup_override(10932969472, 12884901888,
                            (struct os_proc_cgroup_mem_stat){
                                .file = -1, .shmem = -1, .unevictable = -1,
                                .file_dirty = -1, .file_writeback = -1 });
        mem_pressure_poll_tick();
        MP_CHECK("unreadable memory.stat keeps the raw memory.current",
                 mem_pressure_current() == MEM_HIGH);
        MP_CHECK("unreadable memory.stat publishes unknown, not zero",
                 dumped_state_int("evictable_bytes") == -1);

        /* One row unreadable is still an unreadable memory.stat: `file` is
         * present but `shmem` is -1, so the share of the cache that needs
         * swap is unknown and nothing may be subtracted -> raw charge,
         * 84% -> HIGH. Subtracting the whole `file` row here would read
         * 26% -> NOMINAL and silence every sink. */
        set_cgroup_override(10932969472, 12884901888,
                            clean_stat(7516192768, -1, 0));
        mem_pressure_poll_tick();
        MP_CHECK("an unreadable shmem row keeps the raw memory.current",
                 mem_pressure_current() == MEM_HIGH);

        /* Same rule for an unreadable `unevictable`: charge 11811160064 =
         * 91% -> CRITICAL. Subtracting the 4 GiB `file` row would read
         * 58% -> ELEVATED. */
        set_cgroup_override(11811160064, 12884901888,
                            clean_stat(4294967296, 0, -1));
        mem_pressure_poll_tick();
        MP_CHECK("an unreadable unevictable row keeps the raw memory.current",
                 mem_pressure_current() == MEM_CRITICAL);

        /* And for an unreadable `file_writeback`, the row a kernel too old
         * to report it simply omits. */
        set_cgroup_override(10932969472, 12884901888,
                            (struct os_proc_cgroup_mem_stat){
                                .file = 7516192768, .shmem = 0,
                                .unevictable = 0, .file_dirty = 0,
                                .file_writeback = -1 });
        mem_pressure_poll_tick();
        MP_CHECK("an unreadable file_writeback row keeps the raw charge",
                 mem_pressure_current() == MEM_HIGH);
        MP_CHECK("one unreadable row makes the whole tier unknown",
                 dumped_state_int("evictable_bytes") == -1);

        /* All of `file` is shmem: tmpfs/shm needs swap, not a drop, so the
         * evictable tier is empty and the charge stands -> HIGH. Here the
         * tier is a READABLE zero, which the operator surface must spell
         * differently from the unknown above. */
        set_cgroup_override(10932969472, 12884901888,
                            clean_stat(7516192768, 7516192768, 0));
        mem_pressure_poll_tick();
        MP_CHECK("an all-shmem page cache is still pressure",
                 mem_pressure_current() == MEM_HIGH);
        MP_CHECK("no droppable cache publishes zero, not unknown",
                 dumped_state_int("evictable_bytes") == 0);

        /* shmem + unevictable both come out of the droppable tier:
         * numerator 5027389440 = 39% -> NOMINAL. */
        set_cgroup_override(10932969472, 12884901888,
                            clean_stat(7516192768, 1073741824, 536870912));
        mem_pressure_poll_tick();
        MP_CHECK("shmem and unevictable leave the droppable tier",
                 mem_pressure_current() == MEM_NOMINAL);

        /* HDD box mid bulk block/WAL flush: the whole 7 GiB `file` tier is
         * dirty or under writeback, so none of it can be dropped and the
         * cgroup is throttled against it. 84% -> HIGH. Counting dirty and
         * writeback pages as droppable read 0% -> NOMINAL here, which is
         * the hole this case closes. */
        set_cgroup_override(10932969472, 12884901888,
                            (struct os_proc_cgroup_mem_stat){
                                .file = 7516192768, .shmem = 0,
                                .unevictable = 0, .file_dirty = 5368709120,
                                .file_writeback = 2147483648 });
        mem_pressure_poll_tick();
        MP_CHECK("a dirty/writeback-pinned page cache is still pressure",
                 mem_pressure_current() == MEM_HIGH);
        MP_CHECK("a fully pinned cache publishes zero droppable bytes",
                 dumped_state_int("evictable_bytes") == 0);

        /* Partly pinned: 7516192768 - 1073741824 dirty - 536870912
         * writeback = 5905580032 droppable, numerator 5027389440 = 39%
         * -> NOMINAL. The flush pages stay charged, the clean ones do not. */
        set_cgroup_override(10932969472, 12884901888,
                            (struct os_proc_cgroup_mem_stat){
                                .file = 7516192768, .shmem = 0,
                                .unevictable = 0, .file_dirty = 1073741824,
                                .file_writeback = 536870912 });
        mem_pressure_poll_tick();
        MP_CHECK("only the clean part of the cache leaves the numerator",
                 mem_pressure_current() == MEM_NOMINAL);
        MP_CHECK("the published droppable tier is the clean part",
                 dumped_state_int("evictable_bytes") == 5905580032);

        /* Torn read: cache exceeds the charge. Falls back to the raw charge
         * rather than producing a negative numerator, and says so. */
        set_cgroup_override(10932969472, 12884901888,
                            clean_stat(10932969473, 0, 0));
        mem_pressure_poll_tick();
        MP_CHECK("a cache larger than the charge falls back to the charge",
                 mem_pressure_current() == MEM_HIGH);
        MP_CHECK("a torn read publishes unknown, not zero",
                 dumped_state_int("evictable_bytes") == -1);

        /* node3 2026-09-10 exact shape: a DERIVED-only guard (comparing
         * file-minus-exclusions against the charge) misses this one --
         * shmem=3 GiB, file=12 GiB, current=10.18 GiB derives evictable =
         * 12 GiB - 3 GiB = 9 GiB, which reads as UNDER the 10.18 GiB charge
         * and never trips. The raw `file` row alone (12 GiB) already
         * exceeds `current` (10.18 GiB), which is what a RAW-row check must
         * catch: UNKNOWN, raw charge classified -> 84% -> HIGH. */
        set_cgroup_override(10932969472, 12884901888,
                            clean_stat(12884901888, 3221225472, 0));
        mem_pressure_poll_tick();
        MP_CHECK("shmem>0 with file>current still catches the torn read",
                 mem_pressure_current() == MEM_HIGH);
        MP_CHECK("shmem>0 with file>current publishes unknown",
                 dumped_state_int("evictable_bytes") == -1);

        /* Every individual row here is <= the charge, so a per-row-vs-
         * current check alone would pass every row -- but shmem+unevictable
         * (1610612736) exceeds `file` (1073741824), which is impossible for
         * a consistent read: the exclusions cannot legitimately be more of
         * the tier than the tier itself. UNKNOWN, raw charge -> 84% -> HIGH. */
        set_cgroup_override(10932969472, 12884901888,
                            clean_stat(1073741824, 805306368, 805306368));
        mem_pressure_poll_tick();
        MP_CHECK("shmem+unevictable exceeding file is still a torn read",
                 mem_pressure_current() == MEM_HIGH);
        MP_CHECK("shmem+unevictable exceeding file publishes unknown",
                 dumped_state_int("evictable_bytes") == -1);

        /* The operator surface carries the split that produced the level.
         * charged_bytes is the raw cgroup_current every fixture above used,
         * whether or not the read was torn. */
        MP_CHECK("dump carries the raw cgroup charge",
                 dumped_state_int("charged_bytes") == 10932969472);
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
