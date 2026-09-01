/* zrate — token-bucket rate limiter (C23).
 *
 * A classic token bucket: capacity in tokens, refill rate in tokens
 * per second, caller-supplied monotonic time. Try-consume, penalty
 * (sleep-until) computation, and a sliding-window counter for exact
 * "N per interval" checks.
 *
 * No wall clock inside — the caller injects time, which makes the
 * limiter fully deterministic and unit-testable.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZRATE_H
#define ZRATE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Token bucket ---------------------------------------------------- */

typedef struct {
    double   capacity;     /* max tokens */
    double   tokens;       /* current tokens */
    double   rate_per_sec; /* refill rate */
    uint64_t last_ms;      /* last update timestamp */
} zrate_bucket;

/* Initialize full (tokens == capacity). now_ms is the caller's
 * monotonic clock in milliseconds. */
void zrate_bucket_init(zrate_bucket *b, double capacity,
                       double rate_per_sec, uint64_t now_ms);

/* Try to take n tokens at now_ms (refilling first). On success the
 * tokens are spent and true returned; on failure nothing is spent. */
bool zrate_bucket_take(zrate_bucket *b, double n, uint64_t now_ms);

/* Milliseconds until n tokens will be available; 0 if available now.
 * UINT64_MAX when n > capacity (never available). */
uint64_t zrate_bucket_wait_ms(zrate_bucket *b, double n, uint64_t now_ms);

/* Current token count after refilling to now_ms (not persisted). */
double zrate_bucket_peek(const zrate_bucket *b, uint64_t now_ms);

/* --- Sliding-window counter ------------------------------------------ */

/* Exact N-per-interval accounting over a circular log of event
 * timestamps. events must have room for limit entries. */
typedef struct {
    uint64_t *events;   /* circular log, caller storage */
    uint32_t  limit;    /* max events per interval */
    uint32_t  count;    /* live entries */
    uint32_t  head;     /* oldest entry index */
    uint64_t  interval_ms;
} zrate_window;

void zrate_window_init(zrate_window *w, uint64_t *events,
                       uint32_t limit, uint64_t interval_ms);

/* Record an event at now_ms. False when the window already holds
 * `limit` events within the last interval. */
bool zrate_window_hit(zrate_window *w, uint64_t now_ms);

/* Events still live in the window at now_ms. */
uint32_t zrate_window_count(const zrate_window *w, uint64_t now_ms);

/* Milliseconds until the oldest live event expires; 0 when the window
 * has room now. */
uint64_t zrate_window_wait_ms(const zrate_window *w, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* ZRATE_H */
