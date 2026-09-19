/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the CPU topology organ (platform/modules/util/src/cpu_topology.c).
 *
 * Coverage:
 *   - init: idempotent, succeeds on the real box AND on the sysconf
 *     fallback path (sysfs root pointed at a nonexistent directory)
 *   - counts are sane: physical_cores <= logical_cpus, every logical cpu
 *     maps to a domain, per-domain cpu_count sums to logical_cpus
 *   - fallback path: source == "fallback", one synthetic domain, L3 size
 *     unknown (0), logical_cpus matches sysconf(_SC_NPROCESSORS_ONLN)
 *   - largest_l3_domain_cpus: returns the domain with the biggest L3
 *   - domain_at / domain_of: valid + out-of-range behavior
 *   - pin_thread: succeeds for a valid domain on the real box, fails
 *     (advisory, no crash) for an invalid domain
 *   - Darwin performance levels: host-published counts are sane and exact
 *   - dump_state_json: keys present, domains and performance arrays formed
 *   - platform_available_cpu_count: tracks the live affinity mask, not the
 *     online-processor count (the seam cpu_topology's own fallback and every
 *     build-job sizer reads; see platform/logical_cpu.h) */

/* sched_getaffinity/CPU_COUNT are glibc extensions, and this file takes the
 * affinity oracle at the same feature set the seam under test compiles at. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "test/test_core.h"
#include "util/cpu_topology.h"
#include "json/json.h"
#include "platform/logical_cpu.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#if defined(__linux__)
#include <sched.h>
#endif

#define CPT_CHECK(name, expr) do { \
    printf("cpu_topology: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* platform_available_cpu_count: the affinity-aware seam beside
 * platform_logical_cpu_count, which cpu_topology's own fallback and every
 * build-job sizer read. Its own function rather than a block inside
 * test_cpu_topology so the branch-heavy mask manipulation below does not
 * push that function past its complexity pin. */
static int cpt_available_cpu_count_checks(void)
{
    int failures = 0;
    uint32_t online = platform_logical_cpu_count();
    uint32_t available = platform_available_cpu_count();
    CPT_CHECK("available_cpu_count >= 1", available >= 1);
#if defined(__linux__)
    cpu_set_t saved;
    CPU_ZERO(&saved);
    if (sched_getaffinity(0, sizeof saved, &saved) != 0) {
        printf("cpu_topology: sched_getaffinity oracle unavailable... FAIL\n");
        return failures + 1;
    }
    /* Exact equality against the oracle read the same way, not a bound: a
     * seam that quietly went back to reporting the host count is only caught
     * under a restricting mask, and this box may or may not carry one. */
    CPT_CHECK("available_cpu_count equals the live affinity mask",
              available == (uint32_t)CPU_COUNT(&saved));

    /* Narrow the mask to one processor and confirm the seam moves with it.
     * This is the property the whole function exists for: under taskset or a
     * systemd scope's AllowedCPUs the online count is unchanged and only the
     * mask tells the truth. */
    int first = -1;
    for (int c = 0; c < CPU_SETSIZE; c++)
        if (CPU_ISSET(c, &saved)) { first = c; break; }
    CPT_CHECK("the live mask names at least one processor", first >= 0);
    if (first < 0) return failures;

    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(first, &one);
    /* sched_setaffinity can be denied outright (seccomp, a restricted
     * container). That is not a defect in the seam under test, so the
     * narrowing checks are skipped rather than failed; the equality check
     * above still ran. */
    if (sched_setaffinity(0, sizeof one, &one) != 0) return failures;

    CPT_CHECK("available_cpu_count follows a narrowed mask",
              platform_available_cpu_count() == UINT32_C(1));
    CPT_CHECK("logical_cpu_count ignores the narrowed mask",
              platform_logical_cpu_count() == online);
    CPT_CHECK("the saved mask restores",
              sched_setaffinity(0, sizeof saved, &saved) == 0);
    CPT_CHECK("available_cpu_count is back to the wide mask",
              platform_available_cpu_count() == (uint32_t)CPU_COUNT(&saved));
#else
    /* Everywhere without sched_getaffinity the header promises the two seams
     * agree exactly, so assert that rather than a bound. */
    CPT_CHECK("available_cpu_count delegates to the online count",
              available == online);
#endif
    return failures;
}

int test_cpu_topology(void)
{
    int failures = 0;

    /* The affinity seam first: the pin_thread checks further down leave this
     * thread bound to domain 0, and these assertions own the mask while they
     * run and hand back exactly what they found. */
    failures += cpt_available_cpu_count_checks();

    /* ── real /sys scan (or whatever this box/container actually has) ── */
    cpu_topology_reset_for_testing();
    cpu_topology_set_sysfs_root_for_testing(NULL); /* default root */

    CPT_CHECK("init succeeds", cpu_topology_init());
    CPT_CHECK("init idempotent (second call also true)", cpu_topology_init());

    int logical = cpu_topology_logical_cpus();
    int cores   = cpu_topology_physical_cores();
    int domains = cpu_topology_l3_domains();
    const char *source = cpu_topology_source();

    CPT_CHECK("logical_cpus >= 1", logical >= 1);
    CPT_CHECK("physical_cores >= 1", cores >= 1);
    CPT_CHECK("physical_cores <= logical_cpus", cores <= logical);
    CPT_CHECK("l3_domains >= 1", domains >= 1);
    CPT_CHECK("source is a native authority or fallback",
              strcmp(source, "sysfs") == 0 ||
              strcmp(source, "darwin_sysctl") == 0 ||
              strcmp(source, "windows") == 0 ||
              strcmp(source, "fallback") == 0);

    int performance_levels = cpu_topology_performance_levels();
    CPT_CHECK("performance level count is bounded",
              performance_levels >= 0 &&
              performance_levels <= CPU_TOPOLOGY_MAX_PERFORMANCE_LEVELS);
    {
        int level_logical = 0;
        int level_physical = 0;
        bool levels_sane = true;
        for (int i = 0; i < performance_levels; i++) {
            struct cpu_topology_performance_level level;
            if (!cpu_topology_performance_level_at(i, &level) ||
                level.name[0] == '\0' || level.logical_cpus < 0 ||
                level.physical_cores < 0 || level.l2_size_bytes < 0) {
                levels_sane = false;
                break;
            }
            level_logical += level.logical_cpus;
            level_physical += level.physical_cores;
        }
        CPT_CHECK("published performance levels are sane", levels_sane);
        if (performance_levels > 0) {
            CPT_CHECK("performance-level logical CPUs cover the host",
                      level_logical == logical);
            CPT_CHECK("performance-level physical cores cover the host",
                      level_physical == cores);
        }
    }
    {
        struct cpu_topology_performance_level sentinel = {
            .name = "unchanged", .logical_cpus = 23,
            .physical_cores = 23, .l2_size_bytes = 23,
        };
        CPT_CHECK("performance_level_at(-1) refuses",
                  !cpu_topology_performance_level_at(-1, &sentinel));
        CPT_CHECK("refusal leaves performance-level output unchanged",
                  strcmp(sentinel.name, "unchanged") == 0 &&
                  sentinel.logical_cpus == 23);
        CPT_CHECK("performance_level_at(count) refuses",
                  !cpu_topology_performance_level_at(performance_levels,
                                                     &sentinel));
    }
#if defined(__APPLE__) && defined(__aarch64__)
    CPT_CHECK("Apple Silicon publishes Darwin sysctl topology",
              strcmp(source, "darwin_sysctl") == 0);
    CPT_CHECK("Apple Silicon publishes at least one performance level",
              performance_levels >= 1);
#endif

    /* Every logical cpu resolves to a valid domain id, and per-domain
     * cpu_count sums to exactly logical_cpus (no cpu double-counted or
     * dropped). */
    {
        int sum = 0;
        bool all_mapped = true;
        for (int c = 0; c < logical; c++) {
            int d = cpu_topology_domain_of(c);
            if (d < 0 || d >= domains) { all_mapped = false; break; }
        }
        CPT_CHECK("every logical cpu maps to a valid domain", all_mapped);

        for (int i = 0; i < domains; i++) {
            struct cpu_topology_domain snap;
            if (!cpu_topology_domain_at(i, &snap)) { failures++; continue; }
            sum += snap.cpu_count;
            for (int j = 0; j < snap.cpu_count; j++) {
                int c = snap.cpus[j];
                CPT_CHECK("domain member's domain_of agrees with domain_at",
                          cpu_topology_domain_of(c) == snap.id);
            }
        }
        CPT_CHECK("per-domain cpu_count sums to logical_cpus", sum == logical);
    }

    /* Out-of-range domain_of. */
    CPT_CHECK("domain_of(-1) == -1", cpu_topology_domain_of(-1) == -1);
    CPT_CHECK("domain_of(huge) == -1",
              cpu_topology_domain_of(CPU_TOPOLOGY_MAX_CPUS + 5) == -1);

    /* Out-of-range domain_at. */
    {
        struct cpu_topology_domain snap;
        CPT_CHECK("domain_at(-1) fails", !cpu_topology_domain_at(-1, &snap));
        CPT_CHECK("domain_at(domains) fails",
                  !cpu_topology_domain_at(domains, &snap));
    }

    /* largest_l3_domain_cpus: non-empty, matches the domain with the max
     * L3 size (ties -> lowest id), and is a subset of some domain's
     * member cpus. */
    {
        int buf[CPU_TOPOLOGY_MAX_CPUS];
        int n = cpu_topology_largest_l3_domain_cpus(buf, CPU_TOPOLOGY_MAX_CPUS);
        CPT_CHECK("largest_l3_domain_cpus returns >0 cpus", n > 0);
        CPT_CHECK("largest_l3_domain_cpus <= logical_cpus", n <= logical);

        int64_t best_size = -1;
        int best_id = -1;
        for (int i = 0; i < domains; i++) {
            struct cpu_topology_domain snap;
            if (!cpu_topology_domain_at(i, &snap)) continue;
            if (snap.l3_size_bytes > best_size) {
                best_size = snap.l3_size_bytes;
                best_id = snap.id;
            }
        }
        bool matches_best = (n > 0) && (cpu_topology_domain_of(buf[0]) == best_id);
        CPT_CHECK("largest_l3_domain_cpus picks the max-L3 domain", matches_best);

        /* cap smaller than the domain truncates, never overruns. */
        int small[1];
        int n2 = cpu_topology_largest_l3_domain_cpus(small, 1);
        CPT_CHECK("largest_l3_domain_cpus respects cap", n2 <= 1);
    }

    /* pin_thread: valid domain succeeds (advisory — always attempted on
     * the calling thread itself, which is always affinity-settable). */
#ifdef __APPLE__
    CPT_CHECK("pin_thread refuses where Darwin exposes no affinity API",
              !cpu_topology_pin_thread(pthread_self(), 0));
#else
    CPT_CHECK("pin_thread succeeds for domain 0",
              cpu_topology_pin_thread(pthread_self(), 0));
#endif
    CPT_CHECK("pin_thread fails for an invalid (negative) domain",
              !cpu_topology_pin_thread(pthread_self(), -1));
    CPT_CHECK("pin_thread fails for an out-of-range domain",
              !cpu_topology_pin_thread(pthread_self(), domains + 100));

    /* dump_state_json: well-formed, keys present, domains array matches
     * l3_domains(). */
    {
        struct json_value v;
        json_init(&v);
        CPT_CHECK("dump_state_json succeeds",
                  cpu_topology_dump_state_json(&v, NULL));
        CPT_CHECK("dump has logical_cpus",
                  json_get(&v, "logical_cpus") &&
                  json_get_int(json_get(&v, "logical_cpus")) == logical);
        CPT_CHECK("dump has physical_cores",
                  json_get(&v, "physical_cores") &&
                  json_get_int(json_get(&v, "physical_cores")) == cores);
        CPT_CHECK("dump has l3_domains",
                  json_get(&v, "l3_domains") &&
                  json_get_int(json_get(&v, "l3_domains")) == domains);
        CPT_CHECK("dump has source",
                  json_get(&v, "source") &&
                  strcmp(json_get_str(json_get(&v, "source")), source) == 0);
        CPT_CHECK("dump has domains array",
                  json_get(&v, "domains") != NULL);
        CPT_CHECK("dump has largest_l3_domain",
                  json_get(&v, "largest_l3_domain") != NULL);
        CPT_CHECK("dump has exact performance_level_count",
                  json_get(&v, "performance_level_count") &&
                  json_get_int(json_get(&v, "performance_level_count")) ==
                      performance_levels);
        CPT_CHECK("dump has exact performance_levels array",
                  json_get(&v, "performance_levels") &&
                  (int)json_size(json_get(&v, "performance_levels")) ==
                      performance_levels);
        json_free(&v);
    }

    /* ── fallback path: point sysfs root at a directory that cannot
     * exist, force a re-scan, and confirm graceful degradation. ── */
    cpu_topology_reset_for_testing();
    cpu_topology_set_sysfs_root_for_testing(
        "/nonexistent/zcl_cpu_topology_test_root_does_not_exist_12345");

    CPT_CHECK("init still succeeds with an unreadable sysfs root",
              cpu_topology_init());
    CPT_CHECK("source is fallback", strcmp(cpu_topology_source(), "fallback") == 0);

    long expect_n = sysconf(_SC_NPROCESSORS_ONLN);
    if (expect_n <= 0) expect_n = 1;
    CPT_CHECK("fallback logical_cpus matches sysconf",
              cpu_topology_logical_cpus() == (int)expect_n);
    CPT_CHECK("fallback physical_cores == logical_cpus (SMT unknown)",
              cpu_topology_physical_cores() == cpu_topology_logical_cpus());
    CPT_CHECK("fallback has exactly one L3 domain",
              cpu_topology_l3_domains() == 1);
    CPT_CHECK("fallback does not invent performance levels",
              cpu_topology_performance_levels() == 0);

    {
        struct cpu_topology_domain snap;
        CPT_CHECK("fallback domain_at(0) succeeds",
                  cpu_topology_domain_at(0, &snap));
        CPT_CHECK("fallback domain L3 size is unknown (0)",
                  snap.l3_size_bytes == 0);
        CPT_CHECK("fallback domain covers every logical cpu",
                  snap.cpu_count == cpu_topology_logical_cpus());
    }

    for (int c = 0; c < cpu_topology_logical_cpus(); c++) {
        if (cpu_topology_domain_of(c) != 0) {
            failures++;
            printf("cpu_topology: fallback domain_of(%d) != 0... FAIL\n", c);
            break;
        }
    }

#ifdef __APPLE__
    CPT_CHECK("fallback pin still refuses without a Darwin affinity API",
              !cpu_topology_pin_thread(pthread_self(), 0));
#else
    CPT_CHECK("pin_thread still works on the fallback single domain",
              cpu_topology_pin_thread(pthread_self(), 0));
#endif

    /* ── restore default root + re-scan the real box for any test that
     * runs after this one in the same process. ── */
    cpu_topology_reset_for_testing();
    cpu_topology_set_sysfs_root_for_testing(NULL);
    cpu_topology_init();

    if (failures == 0) {
        printf("=== cpu_topology tests: ALL PASS ===\n\n");
    } else {
        printf("=== cpu_topology tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
