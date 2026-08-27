/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable extraction of major and minor device identifiers. */

#ifndef ZCLASSIC_PLATFORM_DEVICE_COMPAT_H
#define ZCLASSIC_PLATFORM_DEVICE_COMPAT_H

#include <stdint.h>
#include <sys/types.h>

#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

static inline unsigned platform_device_major(dev_t device)
{
#if defined(__APPLE__)
    return (unsigned)(((uint32_t)device >> 24) & 0xffu);
#else
    return (unsigned)major(device);
#endif
}

static inline unsigned platform_device_minor(dev_t device)
{
#if defined(__APPLE__)
    return (unsigned)((uint32_t)device & 0x00ffffffu);
#else
    return (unsigned)minor(device);
#endif
}

#endif
