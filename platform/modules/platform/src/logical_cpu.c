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
