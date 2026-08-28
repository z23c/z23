/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Report the host's usable logical processor count portably. */
#include "platform/logical_cpu.h"

#if defined(_WIN32)
/* GetActiveProcessorCount is declared only when the SDK target is Windows 7
 * or newer.  Z23's native baseline is Windows 10, but standalone strict TU
 * checks do not necessarily provide a global _WIN32_WINNT definition. */
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0A00
#elif _WIN32_WINNT < 0x0601
#error "platform_logical_cpu_count requires a Windows 7 or newer SDK target"
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

uint32_t platform_logical_cpu_count(void)
{
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (count != 0)
        return (uint32_t)count;

    /* Defensive fallback for an unexpected API failure. GetSystemInfo is
     * available on every supported Windows version, though it sees only the
     * caller's processor group on group-partitioned hosts. */
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwNumberOfProcessors == 0
               ? UINT32_C(1) : (uint32_t)info.dwNumberOfProcessors;
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
