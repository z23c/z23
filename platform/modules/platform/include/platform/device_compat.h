/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable extraction of major and minor device identifiers. */

#ifndef ZCLASSIC_PLATFORM_DEVICE_COMPAT_H
#define ZCLASSIC_PLATFORM_DEVICE_COMPAT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

static inline unsigned platform_device_major(dev_t device)
{
#if defined(_WIN32)
    (void)device;
    return 0u;
#elif defined(__APPLE__)
    return (unsigned)(((uint32_t)device >> 24) & 0xffu);
#else
    return (unsigned)major(device);
#endif
}

static inline unsigned platform_device_minor(dev_t device)
{
#if defined(_WIN32)
    /* MSVCRT's st_dev is an implementation-defined volume token, not a
     * Unix device number. Preserve its low bits as a stable diagnostic
     * placeholder, but never claim major/minor semantics are available. */
    return (unsigned)((uint64_t)device & UINT32_MAX);
#elif defined(__APPLE__)
    return (unsigned)((uint32_t)device & 0x00ffffffu);
#else
    return (unsigned)minor(device);
#endif
}

static inline bool platform_device_major_minor_available(void)
{
#if defined(_WIN32)
    return false;
#else
    return true;
#endif
}

#endif
