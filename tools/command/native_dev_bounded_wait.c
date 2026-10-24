/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared bounded-wait arithmetic for the dev wait leaves. See
 * native_dev_bounded_wait.h. */

#include "command/native_dev_bounded_wait.h"

#include "platform/time_compat.h"

int64_t zcl_bounded_wait_clamp(int64_t requested, int64_t min_ms,
                               int64_t max_ms, int64_t default_ms,
                               bool *clamped)
{
    int64_t v = requested < 1 ? default_ms : requested;
    if (clamped)
        *clamped = false;
    if (v < min_ms) {
        v = min_ms;
        if (clamped && requested >= 1)
            *clamped = true;
    }
    if (v > max_ms) {
        v = max_ms;
        if (clamped)
            *clamped = true;
    }
    return v;
}

void zcl_bounded_wait_begin(struct zcl_bounded_wait *w, int64_t timeout_ms)
{
    w->deadline_ms = platform_time_monotonic_ms() + timeout_ms;
}

int64_t zcl_bounded_wait_remaining(const struct zcl_bounded_wait *w)
{
    int64_t left = w->deadline_ms - platform_time_monotonic_ms();
    return left > 0 ? left : 0;
}

int64_t zcl_bounded_wait_slice(const struct zcl_bounded_wait *w,
                               int64_t want_ms)
{
    int64_t left = zcl_bounded_wait_remaining(w);
    if (want_ms < 0)
        want_ms = 0;
    return want_ms < left ? want_ms : left;
}

int64_t zcl_bounded_wait_sleep(const struct zcl_bounded_wait *w,
                               int64_t want_ms)
{
    int64_t slice = zcl_bounded_wait_slice(w, want_ms);
    if (slice > 0)
        platform_sleep_ms((int)slice);
    return zcl_bounded_wait_remaining(w);
}
