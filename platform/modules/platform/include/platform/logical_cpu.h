/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded online logical-processor count across host platforms. */
#ifndef ZCL_PLATFORM_LOGICAL_CPU_H
#define ZCL_PLATFORM_LOGICAL_CPU_H

#include <stdint.h>

/* Count online logical processors.
 *
 * On Windows this spans every processor group when the build's API floor
 * allows it (_WIN32_WINNT >= 0x0601); at this project's actual 0x0600 floor
 * it reports the calling thread's group only, which undercounts above 64
 * logical processors rather than over-reporting. Callers size worker pools
 * from this, so the error direction is the safe one.
 *
 * The result is always in [1, UINT32_MAX]; unavailable or invalid host data
 * deterministically falls back to one. */
uint32_t platform_logical_cpu_count(void);

#endif
