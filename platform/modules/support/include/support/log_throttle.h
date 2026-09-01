/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * log_throttle — the shared "de-storm" idiom for a WARN that would otherwise
 * repeat the SAME line every reducer pass (millions of times in minutes) while
 * a held frontier / pending-tear / suppressed-gate condition persists.
 *
 * This dependency-free decision primitive is low-level runtime support so
 * crypto and every higher-ranked module can share it without an upward module
 * edge. The caller still owns the clock and message text.
 *
 * Cadence:
 *   - First key, or a changed key: emit and report the prior key's suppressed
 *     count; reset the count and stamp `now`.
 *   - Same key: increment the count and emit only after `keepalive_secs`.
 *     Keepalive emission does not reset the cumulative count.
 *
 * All state is atomic. A real key must not equal LOG_THROTTLE_KEY_NONE.
 */
#ifndef ZCL_SUPPORT_LOG_THROTTLE_H
#define ZCL_SUPPORT_LOG_THROTTLE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#define LOG_THROTTLE_KEY_NONE ((uint64_t)UINT64_MAX)

struct log_throttle {
    _Atomic uint64_t last_key;
    _Atomic uint64_t reps;
    _Atomic int64_t last_emit_unix;
};

#define LOG_THROTTLE_INIT \
    { .last_key = LOG_THROTTLE_KEY_NONE, .reps = 0, .last_emit_unix = 0 }

bool log_throttle_should_emit(struct log_throttle *t, uint64_t key,
                              int64_t now_unix, int64_t keepalive_secs,
                              uint64_t *out_reps);
bool log_throttle_should_emit_changed(struct log_throttle *t, bool changed,
                                      int64_t now_unix,
                                      int64_t keepalive_secs,
                                      uint64_t *out_reps);
void log_throttle_reset(struct log_throttle *t);
uint64_t log_throttle_reps(const struct log_throttle *t);

#endif /* ZCL_SUPPORT_LOG_THROTTLE_H */
