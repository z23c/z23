/* zhuman — human-readable sizes and durations (C23).
 *
 * Format byte counts as "1.5 MiB" / "1.5 MB" and parse them back;
 * format millisecond durations as "2h 3m 4.5s" and parse them back.
 * Exact integer arithmetic where possible; parsing is strict and
 * overflow-checked.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZHUMAN_H
#define ZHUMAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ZHUMAN_OK = 0,
    ZHUMAN_ERR_NULL,
    ZHUMAN_ERR_FORMAT,   /* unrecognized input */
    ZHUMAN_ERR_OVERFLOW, /* value does not fit in uint64 */
    ZHUMAN_ERR_SMALL     /* output buffer too small */
} zhuman_err;

/* --- Sizes ----------------------------------------------------------- */

/* Format bytes using binary units (KiB..EiB, 1024-based) with one
 * decimal place when fractional, e.g. "512 B", "1.5 KiB".
 * out is NUL-terminated; recommended size 32. */
zhuman_err zhuman_format_bytes_iec(uint64_t bytes, char *out, size_t cap);

/* Same with SI units (kB..EB, 1000-based). */
zhuman_err zhuman_format_bytes_si(uint64_t bytes, char *out, size_t cap);

/* Parse "1.5 KiB", "200 MB", "512 B", "1024" (bare = bytes).
 * Accepts both unit families, optional space, any case. Fractional
 * values are truncated toward zero (integer result). */
zhuman_err zhuman_parse_bytes(const char *str, uint64_t *out);

/* --- Durations ------------------------------------------------------- */

/* Format milliseconds as "1d 2h 3m 4.567s", dropping zero leading
 * units; "0 ms" for zero. Recommended size 64. */
zhuman_err zhuman_format_duration(uint64_t ms, char *out, size_t cap);

/* Parse "1d 2h 3m 4.5s", "90m", "250ms", "1h30m" (spaces optional
 * between components). Units: d, h, m, s, ms. Components may appear
 * at most once and in any order; total must fit in uint64 ms. */
zhuman_err zhuman_parse_duration(const char *str, uint64_t *out_ms);

const char *zhuman_err_str(zhuman_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZHUMAN_H */
