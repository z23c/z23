/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * time_select — choose the agreed time from several clock sources.
 *
 * Each source reports a time as a closed interval [mid - radius, mid + radius]
 * in microseconds. time_select_intersect() applies Marzullo's algorithm: it
 * finds the interval contained in the largest number of source intervals,
 * requires a strict majority to agree, and reports the sources that do not
 * overlap the agreed interval as falsetickers.
 *
 * Pure computation: no clock reads, no I/O, no allocation. The endpoint
 * table lives on the stack and is sorted deterministically, so the same set
 * of sources yields the same result struct whatever order it arrives in.
 * Operational time only; consensus time is untouched. */

#ifndef ZCL_UTIL_TIME_SELECT_H
#define ZCL_UTIL_TIME_SELECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TIME_SELECT_MAX_SOURCES 64u

typedef struct {
    int64_t midpoint_us;
    int64_t radius_us;    /* must be >= 0 */
    uint32_t source_id;
} time_select_source_t;

typedef enum {
    TIME_SELECT_OK = 0,
    TIME_SELECT_REFUSE_NULL,
    TIME_SELECT_REFUSE_EMPTY,
    TIME_SELECT_REFUSE_TOO_MANY,
    TIME_SELECT_REFUSE_NEGATIVE_RADIUS,
    TIME_SELECT_REFUSE_OVERFLOW,
    TIME_SELECT_REFUSE_NO_MAJORITY
} time_select_status_t;

typedef struct {
    bool ok;
    int64_t lo_us;
    int64_t hi_us;
    int64_t mid_us;
    uint32_t agree_count;                              /* sources containing [lo, hi] */
    uint32_t falseticker_ids[TIME_SELECT_MAX_SOURCES]; /* ascending by source_id */
    uint32_t n_false;
} time_select_result_t;

/* Fold n sources (1 <= n <= TIME_SELECT_MAX_SOURCES) into one agreed interval.
 * On any refusal, *out is zeroed with ok=false and the typed status is
 * returned. On TIME_SELECT_OK, out->ok is true. */
time_select_status_t time_select_intersect(const time_select_source_t *sources,
                                           size_t n,
                                           time_select_result_t *out);

#endif /* ZCL_UTIL_TIME_SELECT_H */
