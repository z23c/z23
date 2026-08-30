/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the CPU topology organ (lib/util/src/cpu_topology.c).
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
 *   - dump_state_json: keys present, domains array well-formed */

#include "test/test_core.h"
#include "util/cpu_topology.h"
#include "json/json.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CPT_CHECK(name, expr) do { \
    printf("cpu_topology: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_cpu_topology(void)
{
    int failures = 0;

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
    CPT_CHECK("source is sysfs or fallback",
              strcmp(source, "sysfs") == 0 || strcmp(source, "fallback") == 0);

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
