/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: total physical RAM in bytes, for boot_memory_guard and
 * boot_mint_anchor_preflight's percentage-of-RAM budget checks — sysinfo()'s
 * totalram*mem_unit on Linux, sysctlbyname("hw.memsize") on Darwin — so those
 * budget checks stay one syscall away instead of duplicating the per-host
 * incantation at each call site. */

#ifndef ZCL_PLATFORM_SYSTEM_MEMORY_H
#define ZCL_PLATFORM_SYSTEM_MEMORY_H

#include <stdbool.h>
#include <stdint.h>

#if defined(__APPLE__)
#include <stddef.h>
#include <sys/sysctl.h>
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
