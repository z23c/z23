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

/* Count the logical processors this PROCESS is actually allowed to run on.
 *
 * platform_logical_cpu_count() answers "how big is the host", which is the
 * wrong question for sizing a build: a process launched under taskset, a
 * systemd scope with AllowedCPUs, or a container CPU set sees every online
 * processor through sysconf() while the kernel will only ever schedule it on
 * the subset in its affinity mask. Sizing a job pool from the host count
 * oversubscribes exactly the cores that were deliberately withheld.
 *
 * On Linux the answer is CPU_COUNT() of sched_getaffinity(0, ...). Everywhere
 * else -- including Windows -- this delegates to platform_logical_cpu_count():
 * Win32 has no process-wide equivalent (SetProcessAffinityMask's companion
 * getter reports a mask this codebase never sets, and real placement control
 * there is the per-thread group-affinity API), and no Z23 caller runs under a
 * taskset-equivalent wrapper on Windows. A separate Windows implementation
 * would be untested surface, so it waits for a caller that needs it.
 *
 * The result is always in [1, UINT32_MAX]; an unavailable or empty mask
 * deterministically falls back to platform_logical_cpu_count(). */
uint32_t platform_available_cpu_count(void);

#endif
