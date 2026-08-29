/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: total physical RAM in bytes, for boot_memory_guard,
 * boot_mint_anchor_preflight's percentage-of-RAM budget checks, and
 * hw_profile's published hardware profile — sysinfo()'s totalram*mem_unit on
 * Linux, sysctlbyname("hw.memsize") on Darwin, GlobalMemoryStatusEx()'s
 * ullTotalPhys on Windows — so those budget checks stay one syscall away
 * instead of duplicating the per-host incantation at each call site.
 *
 * The bool return is the honesty contract: on a host whose total-RAM
 * primitive this header does not know, or whose call fails, it returns false
 * and leaves *out untouched. Callers must treat that as "unknown" and must
 * NOT substitute a plausible default — a made-up RAM figure silently
 * mis-sizes every budget derived from it, and a peer reading a published
 * profile cannot tell an invented number from a measured one. */

#ifndef ZCL_PLATFORM_SYSTEM_MEMORY_H
#define ZCL_PLATFORM_SYSTEM_MEMORY_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__APPLE__)
#include <stddef.h>
#include <sys/sysctl.h>
#elif defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <sys/sysinfo.h>
#endif

static inline bool platform_system_memory_bytes(uint64_t *out)
{
    if (!out)
        return false;
#if defined(__APPLE__)
    uint64_t bytes = 0;
    size_t size = sizeof(bytes);
    if (sysctlbyname("hw.memsize", &bytes, &size, NULL, 0) != 0 ||
        size != sizeof(bytes))
        return false;
    *out = bytes;
    return true;
#elif defined(_WIN32)
    /* ullTotalPhys is the physical memory the OS reports as usable — the
     * figure Task Manager shows, and the closest Windows analogue of Linux
     * MemTotal. dwLength MUST be set before the call or the API rejects it.
     * Available since Windows 2000, so it needs no _WIN32_WINNT bump. */
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx(&status))
        return false;
    *out = (uint64_t)status.ullTotalPhys;
    return true;
#elif defined(__linux__)
    struct sysinfo info;
    if (sysinfo(&info) != 0)
        return false;
    *out = (uint64_t)info.totalram * (uint64_t)info.mem_unit;
    return true;
#else
    return false;
#endif
}

#endif
