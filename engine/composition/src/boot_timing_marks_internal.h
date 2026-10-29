/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: internal boot timing marks used by app_init and mint-anchor
 * preflight, emitted by engine/composition/src/boot_timing_marks.c.
 *
 * Split out of engine/composition/src/boot.c when that file passed its shape ceiling.
 * The three helpers are one self-contained surface: read the monotonic boot
 * clock, and print + record a phase / sub-phase marker.
 */

#ifndef ZCL_BOOT_TIMING_MARKS_INTERNAL_H
#define ZCL_BOOT_TIMING_MARKS_INTERNAL_H

#include <stdint.h>

int64_t boot_clock_ms(void);
int64_t boot_submark(const char *name, int64_t since);
void boot_topmark(const char *name, int64_t since);

#endif /* ZCL_BOOT_TIMING_MARKS_INTERNAL_H */
