/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Win32 (GetActiveProcessorCount/GetSystemInfo) and POSIX
 * (sysconf) implementation of platform_logical_cpu_count(); see
 * platform/logical_cpu.h for the deliberate undercount-over-overcount
 * contract this preserves. */
#include "platform/logical_cpu.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

uint32_t platform_logical_cpu_count(void)
{
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
    /* Counts every online logical processor across all processor groups.
     * Preferred, but mingw declares GetActiveProcessorCount and
     * ALL_PROCESSOR_GROUPS only at _WIN32_WINNT >= 0x0601, and this project
     * compiles the Windows target at 0x0600 (ZCL_PLATFORM_CPPFLAGS), so it
     * cannot be called unconditionally. */
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (count > 0)
        return (uint32_t)count;
#endif
    /* The 0x0600 floor, and the fallback if the call above fails.
     * GetSystemInfo reports only the CALLING THREAD's processor group, so on
     * a host with more than 64 logical processors this UNDERCOUNTS. That
     * direction is deliberate: every consumer sizes worker pools from this
     * number, and undercounting shrinks a pool while overcounting
     * oversubscribes a machine that cannot honour it. */
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
