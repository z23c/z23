/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded online logical-processor count across host platforms. */
#ifndef ZCL_PLATFORM_LOGICAL_CPU_H
#define ZCL_PLATFORM_LOGICAL_CPU_H

#include <stdint.h>

/* Count online logical processors across every Windows processor group.
 * The result is always in [1, UINT32_MAX]; unavailable or invalid host data
 * deterministically falls back to one. */
uint32_t platform_logical_cpu_count(void);

#endif
