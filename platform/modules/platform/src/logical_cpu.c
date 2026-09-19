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
        if (count >= 1) return (uint32_t)count;
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

bool platform_build_jobs_arg(char out[16])
{
    uint32_t jobs = platform_build_job_count(platform_available_cpu_count(),
                                             platform_build_memory_budget_bytes());
    int written = snprintf(out, 16, "-j%u", jobs);
    return written > 0 && written < 16;
}
