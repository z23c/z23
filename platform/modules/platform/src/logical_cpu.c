/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Win32 (GetActiveProcessorCount/GetSystemInfo) and POSIX
 * (sysconf) implementation of platform_logical_cpu_count(); see
 * platform/logical_cpu.h for the deliberate undercount-over-overcount
 * contract this preserves. Also the Linux sched_getaffinity() answer for
 * platform_available_cpu_count(). */
/* sched_getaffinity() and CPU_COUNT() are glibc extensions; this is the same
 * placement and guard platform/modules/platform/src/process_lifecycle.c and
 * platform/modules/util/src/cpu_topology.c use, and it is ahead of every
 * include so no system header is first parsed at a narrower feature set. */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "platform/logical_cpu.h"

#include "platform/os_proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
/* Ahead of the platform split below because platform_available_cpu_count()
 * lives after it, as one definition for every arm. */
#include <sched.h>
#endif

#if defined(_WIN32)
/* GetActiveProcessorCount and ALL_PROCESSOR_GROUPS are declared only when the
 * SDK target is Windows 7 or newer. Z23's native baseline is Windows 10
 * (ZCL_PLATFORM_CPPFLAGS pins -D_WIN32_WINNT=0x0A00), but a standalone strict
 * TU check does not necessarily supply a global _WIN32_WINNT, so define the
 * baseline here and REFUSE an SDK target below the floor rather than silently
 * compiling against a different API surface than the product ships. */
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0A00
#elif _WIN32_WINNT < 0x0601
#error "platform_logical_cpu_count requires a Windows 7 or newer SDK target"
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

uint32_t platform_logical_cpu_count(void)
{
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
    /* Counts every online logical processor across ALL processor groups, so
     * this is the preferred answer. The guard is redundant against the #error
     * above and is kept on purpose: if the SDK floor is ever lowered again,
     * this translation unit keeps compiling and falls through to GetSystemInfo
     * instead of calling a function mingw would not have declared. */
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (count > 0)
        return (uint32_t)count;
#endif
    /* Reached when the call above fails, or when the SDK floor is below
     * 0x0601. GetSystemInfo reports only the CALLING THREAD's processor
     * group, so on a host with more than 64 logical processors this
     * UNDERCOUNTS. That direction is deliberate: every consumer sizes worker
     * pools from this number, and undercounting shrinks a pool while
     * overcounting oversubscribes a machine that cannot honour it. */
    SYSTEM_INFO si;
    memset(&si, 0, sizeof si);
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors > 0 ? (uint32_t)si.dwNumberOfProcessors
                                       : UINT32_C(1);
}

#else

#include <limits.h>
#include <unistd.h>

uint32_t platform_logical_cpu_count(void)
{
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count < 1) return UINT32_C(1);
    if ((unsigned long)count > UINT32_MAX) return UINT32_MAX;
    return (uint32_t)count;
}

#endif

/* Parse a run of decimal digits at *p into *out, advancing *p. False when
 * there is no digit or the value overflows uint64. */
static bool cpu_max_digits(const char **p, uint64_t *out)
{
    const char *s = *p;
    uint64_t v = 0;
    for (; *s >= '0' && *s <= '9'; s++) {
        uint64_t d = (uint64_t)(*s - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    if (s == *p) return false;
    *p = s;
    *out = v;
    return true;
}

/* "<quota> <period>" from a cgroup v2 cpu.max: whole CPUs, rounded up. */
bool platform_cpu_max_parse(const char *text, uint32_t *cpus_out)
{
    if (!text || !cpus_out) return false;
    uint64_t quota = 0;
    uint64_t period = 0;
    const char *p = text;
    if (!cpu_max_digits(&p, &quota) || *p != ' ') return false;
    while (*p == ' ') p++;
    if (!cpu_max_digits(&p, &period)) return false;
    if (quota == 0 || period == 0) return false;
    if (*p != '\0' && *p != '\n' && *p != ' ') return false;
    uint64_t cpus = quota / period + (quota % period != 0 ? 1 : 0);
    if (cpus > UINT32_MAX) return false;
    *cpus_out = (uint32_t)cpus;
    return true;
}

#if defined(__linux__)
/* Same root os_proc_cgroup_dir() resolves under (os_proc_mem.c). */
#define CPU_QUOTA_CGROUP_ROOT "/sys/fs/cgroup"

/* The CPU count one cgroup directory's cpu.max allows, or UINT32_MAX when it
 * names no limit or cannot be read: never smaller, never zero. */
static uint32_t cpu_quota_at(const char *dir)
{
    char path[640];
    char text[128];
    if (snprintf(path, sizeof path, "%s/cpu.max", dir) >= (int)sizeof path)
        return UINT32_MAX;
    FILE *f = fopen(path, "r");
    if (!f) return UINT32_MAX;
    bool got = fgets(text, sizeof text, f) != NULL;
    fclose(f);
    uint32_t cpus = 0;
    if (!got || !platform_cpu_max_parse(text, &cpus)) return UINT32_MAX;
    return cpus;
}

/* Tightest cpu.max from this process's cgroup up to the cgroup root: a
 * parent's limit binds its children. UINT32_MAX when none applies. */
static uint32_t cpu_quota_limit(void)
{
    char dir[512];
    if (!os_proc_cgroup_dir(dir, sizeof dir)) return UINT32_MAX;
    uint32_t best = UINT32_MAX;
    for (;;) {
        uint32_t here = cpu_quota_at(dir);
        if (here < best) best = here;
        if (strcmp(dir, CPU_QUOTA_CGROUP_ROOT) == 0) break;
        char *slash = strrchr(dir, '/');
        if (!slash || slash == dir) break;
        *slash = '\0';
        if (strlen(dir) < strlen(CPU_QUOTA_CGROUP_ROOT)) break;
    }
    return best;
}
#endif

/* One definition for every platform (check-arm-symbol-single), like the
 * availability count below. */
uint32_t platform_cpu_quota_limit(void)
{
#if defined(__linux__)
    return cpu_quota_limit();
#else
    return UINT32_MAX;
#endif
}

/* ONE definition for every platform, deliberately outside the split above:
 * check-arm-symbol-single refuses a non-static function defined once per
 * #if arm, and the strictest semantics of every arm here is the same
 * sentence -- "the affinity mask when the host publishes one, otherwise the
 * online count". Only the Linux body differs, so only the Linux body is
 * guarded. */
uint32_t platform_available_cpu_count(void)
{
#if defined(__linux__)
    /* pid 0 means the calling thread, which is the process for every caller
     * here: taskset and a systemd scope's AllowedCPUs install the mask before
     * the program starts and every thread inherits it, and
     * sysconf(_SC_NPROCESSORS_ONLN) never sees it. CPU_COUNT of that mask is
     * the number of processors the kernel will ever schedule this on. */
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof set, &set) == 0) {
        int count = CPU_COUNT(&set);
        /* A zero or negative count means the mask said nothing usable, which
         * is not a number to size a pool from; fall through to the host count
         * rather than clamp it to one and serialise the caller. */
        if (count >= 1) {
            /* A cgroup v2 CPU quota (systemd CPUQuota=, docker --cpus, k8s
             * limits) leaves the mask wide but caps the CPU time: workers
             * past the quota only add memory. */
            uint32_t quota = cpu_quota_limit();
            return quota < (uint32_t)count ? quota : (uint32_t)count;
        }
    }
    /* sched_getaffinity fails when the mask is wider than cpu_set_t (more than
     * CPU_SETSIZE=1024 processors) or under a seccomp policy that denies it.
     * Both mean "no better answer than the host count". */
#endif
    /* Windows arrives here too: Win32 has no process-wide affinity count worth
     * reporting (see the header), so the two seams answer the same number on
     * the platform where nothing restricts the mask. */
    return platform_logical_cpu_count();
}

/* ── Build parallelism ────────────────────────────────────────────────────
 * See platform/logical_cpu.h for why one answer exists at all. */

/* Peak resident bytes one make job costs this tree, used only to divide a
 * memory grant into a job count. MEASURED, not estimated: peak RSS sampled
 * per compile job across 101 translation units driven with the real release
 * command line (-O3 -march=x86-64-v3 -flto=auto) against an EMPTY ZCC_DIR,
 * so every job did full front-end and codegen work instead of hitting the
 * object cache. Max 54.9 MiB, p99 42.2 MiB, median 27.0 MiB. This rounds the
 * MAX up to 64 MiB, so the divisor stays conservative against a translation
 * unit heavier than any in that sample.
 *
 * ON THE PROJECT'S OWN BUILD HOST THIS ARM NEVER BINDS, and the comment says
 * so rather than implying a bound it does not carry: the grant is
 * 25_769_803_776 bytes (24 GiB) against an affinity mask of 28 processors,
 * which divides to 384 jobs. CPU binds by roughly 14x. The arm is kept for a
 * small-memory grant -- a 512 MB container, a builder on a 2 GB board --
 * where it is the limit that should win and where the CPU count is the one
 * that would oversubscribe into swap. */
/* Parenthesised, and the suffix on the leading factor: INT64_C(64 * 1024 *
 * 1024) expands to a bare `64 * 1024 * 1024L`, so `budget / PEAK` at the use
 * site below silently parses as `budget / 64 * 1024 * 1024L` and the ceiling
 * stops existing. The test beside this in tests/harness/src/test_cpu_topology.c
 * asserts an exact job count for exactly that reason. */
#define PLATFORM_BUILD_JOB_PEAK_BYTES (INT64_C(64) * 1024 * 1024)

uint32_t platform_build_job_count(uint32_t available_cpus,
                                  int64_t memory_budget_bytes)
{
    /* The affinity mask is the first limit. A caller that somehow reports
     * zero processors still gets a build, one file at a time; zero would
     * spawn a make that never finishes. */
    uint32_t jobs = available_cpus > 0 ? available_cpus : UINT32_C(1);

    /* The second limit applies only where the host actually names a grant.
     * <= 0 means nobody said, and silence is not a ceiling. */
    if (memory_budget_bytes > 0) {
        int64_t by_memory = memory_budget_bytes / PLATFORM_BUILD_JOB_PEAK_BYTES;
        if (by_memory < 1) by_memory = 1;
        if (by_memory < (int64_t)jobs) jobs = (uint32_t)by_memory;
    }
    return jobs;
}

int64_t platform_build_memory_budget_bytes(void)
{
    struct os_proc_mem mem;
    if (!os_proc_mem_read(&mem)) return -1;
    /* memory.max is the hard ceiling the kernel enforces with the OOM killer,
     * so it is the number a job pool must respect. memory.high only throttles
     * -- exceeding it costs reclaim pressure, not death -- but a build that
     * lives above it crawls, so it is the next best answer when max is unset.
     * The host total is last: on a scheduled build host it is the number that
     * is NOT enforced on this process, and preferring it would hand a 512 MB
     * container the whole machine's worth of jobs. */
    if (mem.cgroup_max > 0) return mem.cgroup_max;
    if (mem.cgroup_high > 0) return mem.cgroup_high;
    if (mem.sys_total_bytes > 0) return mem.sys_total_bytes;
    return -1;
}

uint32_t platform_build_job_cap(uint32_t jobs, const char *limit)
{
    if (!limit) return jobs;
    uint32_t cap = 0;
    for (const char *p = limit; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
        uint32_t digit = (uint32_t)(*p - '0');
        if (cap > (UINT32_MAX - digit) / 10) return 0;
        cap = cap * 10 + digit;
    }
    if (cap == 0) return 0;
    return cap < jobs ? cap : jobs;
}

bool platform_build_jobs_arg(char out[16])
{
    uint32_t jobs = platform_build_job_count(platform_available_cpu_count(),
                                             platform_build_memory_budget_bytes());
    jobs = platform_build_job_cap(jobs, getenv("ZCL_BUILD_MAX_JOBS"));
    if (!jobs)
        return false;
    int written = snprintf(out, 16, "-j%u", jobs);
    return written > 0 && written < 16;
}
