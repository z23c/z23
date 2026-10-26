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
#include "platform/os_proc.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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
#if defined(__linux__)
/* The answer the seam must give for a mask of `mask` CPUs: the mask, capped
 * by this process's cgroup CPU quota when one applies. */
static uint32_t cpt_expected(uint32_t mask)
{
    const uint32_t quota = platform_cpu_quota_limit();
    return quota < mask ? quota : mask;
}
#endif

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
    /* A cgroup CPU quota may lower the answer below the mask (the live clause
     * in cpt_cpu_quota_live_checks pins that), so the mask is the ceiling. */
    /* Exact equality against the oracle read the same way, not a bound: the
     * mask, lowered only by a finite cgroup quota. */
    CPT_CHECK("available_cpu_count equals the live affinity mask (quota-capped)",
              available == cpt_expected((uint32_t)CPU_COUNT(&saved)));

    /* Narrow the mask to one processor and confirm the seam follows it: under
     * taskset or a systemd scope's AllowedCPUs only the mask tells the truth. */
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
    CPT_CHECK("available_cpu_count is back to the wide mask (quota-capped)",
              platform_available_cpu_count() ==
                  cpt_expected((uint32_t)CPU_COUNT(&saved)));
#else
    /* Everywhere without sched_getaffinity the header promises the two seams
     * agree exactly, so assert that rather than a bound. */
    CPT_CHECK("available_cpu_count delegates to the online count",
              available == online);
#endif
    return failures;
}

/* The pure cpu.max parser: "<quota> <period>" microseconds, or "max ...". */
static int cpt_cpu_max_parse_checks(void)
{
    int failures = 0;
    uint32_t n = 0;
    CPT_CHECK("cpu_max 800000/100000 is 8",
              platform_cpu_max_parse("800000 100000\n", &n) && n == 8);
    CPT_CHECK("cpu_max 150000/100000 rounds up to 2",
              platform_cpu_max_parse("150000 100000", &n) && n == 2);
    CPT_CHECK("cpu_max 50000/100000 is at least 1",
              platform_cpu_max_parse("50000 100000", &n) && n == 1);
    CPT_CHECK("cpu_max 100000/100000 is 1",
              platform_cpu_max_parse("100000 100000", &n) && n == 1);
    n = 77;
    CPT_CHECK("cpu_max max is no limit",
              !platform_cpu_max_parse("max 100000", &n) && n == 77);
    CPT_CHECK("cpu_max empty refused", !platform_cpu_max_parse("", &n));
    CPT_CHECK("cpu_max NULL refused", !platform_cpu_max_parse(NULL, &n));
    CPT_CHECK("cpu_max garbage refused",
              !platform_cpu_max_parse("abc 100000", &n));
    CPT_CHECK("cpu_max zero period refused",
              !platform_cpu_max_parse("800000 0", &n));
    CPT_CHECK("cpu_max negative quota refused",
              !platform_cpu_max_parse("-1 100000", &n));
    CPT_CHECK("cpu_max zero quota refused",
              !platform_cpu_max_parse("0 100000", &n));
    CPT_CHECK("cpu_max missing period refused",
              !platform_cpu_max_parse("800000", &n));
    CPT_CHECK("cpu_max overflow refused",
              !platform_cpu_max_parse("99999999999999999999 1", &n));
    CPT_CHECK("cpu_max result above uint32 refused",
              !platform_cpu_max_parse("9999999999 1", &n));
    return failures;
}

#if defined(__linux__)
/* The live answer never exceeds the affinity count, nor this process's own
 * cgroup cpu.max when that is a finite quota. */
static int cpt_cpu_quota_live_checks(void)
{
    int failures = 0;
    cpu_set_t set;
    CPU_ZERO(&set);
    uint32_t available = platform_available_cpu_count();
    if (sched_getaffinity(0, sizeof set, &set) == 0)
        CPT_CHECK("available_cpu_count <= affinity count",
                  available >= 1 && available <= (uint32_t)CPU_COUNT(&set));
    char dir[512];
    char path[600];
    char text[128] = "";
    FILE *f = NULL;
    if (os_proc_cgroup_dir(dir, sizeof dir) &&
        snprintf(path, sizeof path, "%s/cpu.max", dir) > 0)
        f = fopen(path, "r");
    if (f) {
        if (!fgets(text, sizeof text, f)) text[0] = '\0';
        fclose(f);
    }
    uint32_t quota = 0;
    if (platform_cpu_max_parse(text, &quota))
        CPT_CHECK("available_cpu_count <= own cgroup cpu.max",
                  available <= quota);
    else
        printf("cpu_topology: own cgroup cpu.max absent or max; quota clause skipped\n");
    return failures;
}
#endif

/* The build-job derivation, graded through the PURE function so no particular
 * host CPU count or memory grant is needed. */
static int cpt_build_job_count_checks(void)
{
    int failures = 0;
    const int64_t mib = INT64_C(1024) * 1024;

    CPT_CHECK("explicit Mac job cap reduces parallelism",
              platform_build_job_cap(10, "2") == 2);
    CPT_CHECK("cap cannot widen an existing grant",
              platform_build_job_cap(2, "32") == 2);
    CPT_CHECK("absent cap preserves the grant",
              platform_build_job_cap(8, NULL) == 8);
    CPT_CHECK("uint32 maximum is a valid non-widening cap",
              platform_build_job_cap(8, "4294967295") == 8);
    static const char *const invalid[] = {
        "", "0", "-2", "+2", " 2", "2 ", "2x", "4294967296",
        "9999999999999999999999999999999999999"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        CPT_CHECK("invalid cap refuses", platform_build_job_cap(8, invalid[i]) == 0);

    /* No budget named: the CPU count stands alone. */
    CPT_CHECK("no budget: 28 processors buy 28 jobs",
              platform_build_job_count(28, 0) == 28);
    CPT_CHECK("an unreadable budget is not a ceiling",
              platform_build_job_count(28, -1) == 28);
    /* 96 processors: nothing clamps the count below the mask. */
    CPT_CHECK("no ceiling below the mask survives",
              platform_build_job_count(96, 0) == 96);
    CPT_CHECK("one processor buys one job",
              platform_build_job_count(1, 0) == 1);

    /* A zero CPU count can only come from a broken host answer. One job still
     * builds; zero would spawn a make that never finishes. */
    CPT_CHECK("zero processors still build, one file at a time",
              platform_build_job_count(0, 0) == 1);

    /* This project's own build grant: 24 GiB against 28 processors; memory
     * does not bind. */
    CPT_CHECK("24 GiB against 28 processors is bound by the processors",
              platform_build_job_count(28, INT64_C(24) * 1024 * mib) == 28);

    /* A small-memory host is where the budget arm earns its place: at 64 MiB
     * per job, 512 MiB buys 8 jobs even on a 28-processor mask. */
    CPT_CHECK("512 MiB against 28 processors is bound by the memory",
              platform_build_job_count(28, 512 * mib) == 8);
    CPT_CHECK("the memory arm never raises the count above the mask",
              platform_build_job_count(4, 512 * mib) == 4);
    /* A budget smaller than one job still yields one, never zero. */
    CPT_CHECK("a budget below one job still builds",
              platform_build_job_count(28, 1) == 1);

    /* The formatted argument is exactly what the derivation says, so the
     * spawn sites and the arithmetic can never drift apart silently. */
    {
        char arg[16];
        char expect[16];
        CPT_CHECK("build_jobs_arg formats", platform_build_jobs_arg(arg));
        (void)snprintf(expect, sizeof expect, "-j%u",
                       platform_build_job_cap(platform_build_job_count(
                           platform_available_cpu_count(),
                           platform_build_memory_budget_bytes()), getenv("ZCL_BUILD_MAX_JOBS")));
        CPT_CHECK("build_jobs_arg is the derivation, formatted",
                  strcmp(arg, expect) == 0);
        /* And it is a real job count, never "-j0". */
        CPT_CHECK("build_jobs_arg is never -j0", strcmp(arg, "-j0") != 0);
        CPT_CHECK("build_jobs_arg is -jN with N >= 1",
                  strncmp(arg, "-j", 2) == 0 && atoi(arg + 2) >= 1);
    }

    /* The host's own budget is either a real number or an honest -1; a zero
     * would divide the job count to one on every machine. */
    {
        int64_t budget = platform_build_memory_budget_bytes();
        CPT_CHECK("the host budget is a real ceiling or an honest -1",
                  budget > 0 || budget == -1);
    }
    return failures;
}

/* The published performance levels against the host counts. */
static int cpt_performance_level_checks(int logical, int cores,
                                        int performance_levels)
{
    int failures = 0;
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
    return failures;
}

/* Mapping between logical cpus and L3 domains, plus out-of-range refusals. */
static int cpt_domain_mapping_checks(int logical, int domains)
{
    int failures = 0;

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
    return failures;
}

/* largest_l3_domain_cpus against a hand-computed max-L3 scan. */
static int cpt_largest_l3_domain_checks(int logical, int domains)
{
    int failures = 0;

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
    return failures;
}

/* The JSON dump of the live topology. */
static int cpt_dump_json_checks(int logical, int cores, int domains,
                                int performance_levels, const char *source)
{
    int failures = 0;

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
    return failures;
}

int test_cpu_topology(void)
{
    int failures = 0;

    /* The affinity seam first: the pin_thread checks further down leave this
     * thread bound to domain 0, and these assertions own the mask while they
     * run and hand back exactly what they found. */
    failures += cpt_available_cpu_count_checks();
    failures += cpt_cpu_max_parse_checks();
#if defined(__linux__)
    failures += cpt_cpu_quota_live_checks();
#endif
    failures += cpt_build_job_count_checks();

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
    failures += cpt_performance_level_checks(logical, cores,
                                             performance_levels);
#if defined(__APPLE__) && defined(__aarch64__)
    CPT_CHECK("Apple Silicon publishes Darwin sysctl topology",
              strcmp(source, "darwin_sysctl") == 0);
    CPT_CHECK("Apple Silicon publishes at least one performance level",
              performance_levels >= 1);
#endif

    failures += cpt_domain_mapping_checks(logical, domains);
    failures += cpt_largest_l3_domain_checks(logical, domains);

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

    failures += cpt_dump_json_checks(logical, cores, domains,
                                     performance_levels, source);

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
