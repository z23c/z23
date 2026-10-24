/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The one bounded-wait helper the dev wait leaves share
 * (dev.agent.mail.wait, dev.job.wait): clamp a requested timeout into a
 * range, start a monotonic deadline, and sleep one slice that never
 * overshoots it. Pure arithmetic over the monotonic clock; no I/O. */
#ifndef ZCL_NATIVE_DEV_BOUNDED_WAIT_H
#define ZCL_NATIVE_DEV_BOUNDED_WAIT_H

#include <stdbool.h>
#include <stdint.h>

struct zcl_bounded_wait {
    int64_t deadline_ms; /* platform_time_monotonic_ms() value */
};

/* Clamp `requested` into [min_ms, max_ms]; `requested` < 1 selects
 * `default_ms`. *clamped is set when the result differs from a positive
 * request. */
int64_t zcl_bounded_wait_clamp(int64_t requested, int64_t min_ms,
                               int64_t max_ms, int64_t default_ms,
                               bool *clamped);

/* Arm the deadline `timeout_ms` from now. */
void zcl_bounded_wait_begin(struct zcl_bounded_wait *w, int64_t timeout_ms);

/* Milliseconds left; 0 once the deadline has passed. */
int64_t zcl_bounded_wait_remaining(const struct zcl_bounded_wait *w);

/* The slice a caller should wait now: min(want_ms, remaining), >= 0. */
int64_t zcl_bounded_wait_slice(const struct zcl_bounded_wait *w,
                               int64_t want_ms);

/* Sleep one slice (see zcl_bounded_wait_slice). Returns the remaining
 * milliseconds after the sleep. */
int64_t zcl_bounded_wait_sleep(const struct zcl_bounded_wait *w,
                               int64_t want_ms);

#endif
