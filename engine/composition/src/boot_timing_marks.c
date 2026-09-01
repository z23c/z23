/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the boot phase-timing marks — read the monotonic boot clock and
 * emit/record a "[boot]" phase or sub-phase marker.
 *
 * Split out of engine/composition/src/boot.c when that file passed its shape ceiling.
 * Pure move: the bodies below are byte-identical to the ones boot.c carried;
 * only their linkage changed (static -> external) so app_init can still chain
 * them across the TU boundary. Contract: boot_timing_marks_internal.h.
 */

#include "boot_timing_marks_internal.h"

#include "config/boot_flight_recorder.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <time.h>

/* Boot timing helper */
int64_t boot_clock_ms(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Emit an indented [boot] sub-phase marker + feed boot_flight_recorder;
 * return a fresh clock reading so the caller can chain: t = boot_submark("x", t). */
int64_t boot_submark(const char *name, int64_t since)
{
    int64_t ms = boot_clock_ms() - since;
    printf("[boot]   %-28s %lldms\n", name, (long long)ms);
    boot_flight_recorder_mark(name, ms);
    return boot_clock_ms();
}

/* Top-level [boot] phase marker + boot_flight_recorder feed (boot_submark, one indent level up). */
void boot_topmark(const char *name, int64_t since)
{
    int64_t ms = boot_clock_ms() - since;
    printf("[boot] %-30s %lldms\n", name, (long long)ms);
    boot_flight_recorder_mark(name, ms);
}
