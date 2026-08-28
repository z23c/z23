/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the cold-start driver's private cross-TU contract — the log
 * subsystem tag plus the two bounded single-line reason copiers that the
 * pure layer defines and the live layer consumes.
 *
 * boot_cold_start.c owns layer (1), the PURE half: stage naming, receipt
 * path/write/read/match, and the resume decision. boot_cold_start_driver.c
 * owns layer (2), the LIVE half: fork/exec of each prep stage as a child,
 * refusal classification, and the exec of the plain serving boot. The split
 * happened when the combined file passed the 800-line shape ceiling. These
 * three declarations are all that crosses that seam, so they live here and
 * nowhere else — nothing outside those two translation units may include
 * this header.
 */

#ifndef ZCL_CONFIG_BOOT_COLD_START_INTERNAL_H
#define ZCL_CONFIG_BOOT_COLD_START_INTERNAL_H

#include <stddef.h>

#define COLD_START_SUBSYS  "cold_start"

/* Copy at most `in_len` bytes of `in` into `out`, collapsing every control
 * character to a space so a reason can never break the single-line receipt
 * or log format. Always NUL-terminates. Defined in boot_cold_start.c. */
void cold_start_singleline_bounded(const char *in, size_t in_len,
                                   char *out, size_t out_n);

/* Copy `src` into `dst` (bounded, single-lined, always NUL-terminated).
 * Defined in boot_cold_start.c. */
void cold_start_reason_copy(char *dst, size_t dst_n, const char *src);

#endif /* ZCL_CONFIG_BOOT_COLD_START_INTERNAL_H */
