/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-peer bandwidth quotas — implementation.  See
 * core/modules/net/include/net/peer_bandwidth.h for design notes.
 */

#include "platform/time_compat.h"
#include "net/peer_bandwidth.h"
#include "event/event.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_UP_BPS     (10LL * 1024 * 1024)   /* 10 MB/s */
#define DEFAULT_DOWN_BPS   (20LL * 1024 * 1024)   /* 20 MB/s */
#define DEFAULT_BURST      ( 1LL * 1024 * 1024)   /*  1 MB   */

static int64_t mono_us(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}

void peer_bandwidth_init(struct peer_bandwidth *pb)
{
    if (!pb) return;
    memset(pb, 0, sizeof(*pb));
    pb->up_bps      = DEFAULT_UP_BPS;
    pb->down_bps    = DEFAULT_DOWN_BPS;
    pb->burst_bytes = DEFAULT_BURST;
    pthread_mutex_init(&pb->lock, NULL);
    pb->initialized = true;
}

void peer_bandwidth_destroy(struct peer_bandwidth *pb)
{
    if (!pb || !pb->initialized) return;
    pthread_mutex_destroy(&pb->lock);
    pb->initialized = false;
}

static int64_t read_env_i64(const char *name, int64_t fallback,
                             int64_t min, int64_t max)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long long parsed = strtoll(v, &end, 10);
    if (end == v) return fallback;
    if (parsed < min) parsed = min;
    if (parsed > max) parsed = max;
    return (int64_t)parsed;
}

void peer_bandwidth_load_from_env(struct peer_bandwidth *pb)
{
    if (!pb) return;
    if (!pb->initialized) peer_bandwidth_init(pb);

    pthread_mutex_lock(&pb->lock);
    /* 0 disables the layer; otherwise clamp to a sensible range.
     * 10GB/s upper bound is "don't crash on typo", not an actual
     * capacity check. */
    pb->up_bps      = read_env_i64("ZCL_PEER_UP_BPS",   DEFAULT_UP_BPS,
                                    0, 10LL * 1024 * 1024 * 1024);
    pb->down_bps    = read_env_i64("ZCL_PEER_DOWN_BPS", DEFAULT_DOWN_BPS,
                                    0, 10LL * 1024 * 1024 * 1024);
    pb->burst_bytes = read_env_i64("ZCL_PEER_BURST",    DEFAULT_BURST,
                                    1024LL, 1024LL * 1024 * 1024);
    pthread_mutex_unlock(&pb->lock);
}

/* ── Bucket lookup ──────────────────────────────────────────── */

static struct peer_bw_bucket *
find_peer_locked(struct peer_bandwidth *pb, uint32_t peer_id)
{
    for (size_t i = 0; i < pb->num_peers; i++)
        if (pb->peers[i].peer_id == peer_id)
            return &pb->peers[i];
    return NULL;
}

static struct peer_bw_bucket *
get_or_create_peer_locked(struct peer_bandwidth *pb, uint32_t peer_id)
{
    struct peer_bw_bucket *e = find_peer_locked(pb, peer_id);
    if (e) return e;

    if (pb->num_peers < PEER_BW_MAX_PEERS) {
        e = &pb->peers[pb->num_peers++];
    } else {
        /* LRU eviction: replace the slot with the oldest last_seen_us. */
        size_t lru = 0;
        for (size_t i = 1; i < pb->num_peers; i++) {
            if (pb->peers[i].last_seen_us < pb->peers[lru].last_seen_us)
                lru = i;
        }
        e = &pb->peers[lru];
    }
    memset(e, 0, sizeof(*e));
    e->peer_id = peer_id;
    e->up_tokens             = (double)pb->burst_bytes;
    e->down_tokens           = (double)pb->burst_bytes;
    e->up_last_refill_us     = mono_us();
    e->down_last_refill_us   = mono_us();
    e->last_seen_us          = mono_us();
    return e;
}

/* ── Token bucket math ──────────────────────────────────────── */

static void refill_locked(struct peer_bandwidth *pb,
                           struct peer_bw_bucket *e,
                           enum peer_bandwidth_dir dir)
{
    int64_t  *last = (dir == PEER_BW_UP) ? &e->up_last_refill_us
                                         : &e->down_last_refill_us;
    double   *tok  = (dir == PEER_BW_UP) ? &e->up_tokens
                                         : &e->down_tokens;
    int64_t   bps  = (dir == PEER_BW_UP) ? pb->up_bps
                                         : pb->down_bps;
    if (bps <= 0) {
        *tok = (double)pb->burst_bytes;
        return;
    }
    int64_t now = mono_us();
    int64_t dt  = now - *last;
    if (dt <= 0) return;
    *tok += ((double)bps * (double)dt) / 1000000.0;
    if (*tok > (double)pb->burst_bytes)
        *tok = (double)pb->burst_bytes;
    *last = now;
}

void peer_bandwidth_mark_trusted(struct peer_bandwidth *pb,
                                  uint32_t peer_id, bool trusted)
{
    if (!pb || !pb->initialized) return;
    pthread_mutex_lock(&pb->lock);
    struct peer_bw_bucket *e = get_or_create_peer_locked(pb, peer_id);
    e->trusted      = trusted;
    e->last_seen_us = mono_us();
    pthread_mutex_unlock(&pb->lock);
}

bool peer_bandwidth_consume(struct peer_bandwidth *pb,
                             uint32_t peer_id,
                             enum peer_bandwidth_dir dir,
                             size_t bytes)
{
    if (!pb || !pb->initialized) return true;
    if (bytes == 0) return true;

    pthread_mutex_lock(&pb->lock);

    struct peer_bw_bucket *e = get_or_create_peer_locked(pb, peer_id);
    e->last_seen_us = mono_us();

    int64_t bps = (dir == PEER_BW_UP) ? pb->up_bps : pb->down_bps;

    /* Disabled layer OR trusted peer → always allow. */
    if (bps <= 0 || e->trusted) {
        if (dir == PEER_BW_UP) pb->stat_allowed_bytes_up   += bytes;
        else                   pb->stat_allowed_bytes_down += bytes;
        pthread_mutex_unlock(&pb->lock);
        return true;
    }

    refill_locked(pb, e, dir);

    double *tok = (dir == PEER_BW_UP) ? &e->up_tokens : &e->down_tokens;
    if (*tok < (double)bytes) {
        /* Throttle.  Do NOT consume tokens — caller will retry. */
        if (dir == PEER_BW_UP) {
            pb->stat_throttled_events_up++;
            pb->stat_throttled_bytes_up  += bytes;
            e->up_throttled_bytes        += bytes;
        } else {
            pb->stat_throttled_events_down++;
            pb->stat_throttled_bytes_down += bytes;
            e->down_throttled_bytes       += bytes;
        }

        char dir_str[8];
        snprintf(dir_str, sizeof(dir_str), "%s",
                 dir == PEER_BW_UP ? "up" : "down");
        int64_t bucket_now = (int64_t)*tok;
        int64_t bucket_cap = pb->burst_bytes;

        /* Release lock before event emit to avoid observer deadlocks. */
        pthread_mutex_unlock(&pb->lock);

        event_emitf(EV_PEER_THROTTLED, peer_id,
            "peer=%u dir=%s bytes=%zu bucket=%lld/%lld",
            peer_id, dir_str, bytes,
            (long long)bucket_now, (long long)bucket_cap);
        return false;
    }

    *tok -= (double)bytes;
    if (dir == PEER_BW_UP) pb->stat_allowed_bytes_up   += bytes;
    else                   pb->stat_allowed_bytes_down += bytes;
    pthread_mutex_unlock(&pb->lock);
    return true;
}

size_t peer_bandwidth_available(struct peer_bandwidth *pb,
                                 uint32_t peer_id,
                                 enum peer_bandwidth_dir dir)
{
    if (!pb || !pb->initialized) return SIZE_MAX;
    pthread_mutex_lock(&pb->lock);
    struct peer_bw_bucket *e = find_peer_locked(pb, peer_id);
    if (!e) {
        /* No bucket yet → full burst available. */
        size_t v = (size_t)pb->burst_bytes;
        pthread_mutex_unlock(&pb->lock);
        return v;
    }
    int64_t bps = (dir == PEER_BW_UP) ? pb->up_bps : pb->down_bps;
    if (bps <= 0 || e->trusted) {
        pthread_mutex_unlock(&pb->lock);
        return SIZE_MAX;
    }
    refill_locked(pb, e, dir);
    double tok = (dir == PEER_BW_UP) ? e->up_tokens : e->down_tokens;
    if (tok < 0) tok = 0;
    size_t v = (size_t)tok;
    pthread_mutex_unlock(&pb->lock);
    return v;
}

void peer_bandwidth_reset_state(struct peer_bandwidth *pb)
{
    if (!pb || !pb->initialized) return;
    pthread_mutex_lock(&pb->lock);
    memset(pb->peers, 0, sizeof(pb->peers));
    pb->num_peers                    = 0;
    pb->stat_allowed_bytes_up        = 0;
    pb->stat_allowed_bytes_down      = 0;
    pb->stat_throttled_events_up     = 0;
    pb->stat_throttled_events_down   = 0;
    pb->stat_throttled_bytes_up      = 0;
    pb->stat_throttled_bytes_down    = 0;
    pthread_mutex_unlock(&pb->lock);
}

size_t peer_bandwidth_tracked_peers(struct peer_bandwidth *pb)
{
    if (!pb || !pb->initialized) return 0;
    pthread_mutex_lock(&pb->lock);
    size_t n = pb->num_peers;
    pthread_mutex_unlock(&pb->lock);
    return n;
}

uint64_t peer_bandwidth_throttled_events(struct peer_bandwidth *pb,
                                          enum peer_bandwidth_dir dir)
{
    if (!pb || !pb->initialized) return 0;
    pthread_mutex_lock(&pb->lock);
    uint64_t v = (dir == PEER_BW_UP) ? pb->stat_throttled_events_up
                                     : pb->stat_throttled_events_down;
    pthread_mutex_unlock(&pb->lock);
    return v;
}

uint64_t peer_bandwidth_throttled_bytes(struct peer_bandwidth *pb,
                                         enum peer_bandwidth_dir dir)
{
    if (!pb || !pb->initialized) return 0;
    pthread_mutex_lock(&pb->lock);
    uint64_t v = (dir == PEER_BW_UP) ? pb->stat_throttled_bytes_up
                                     : pb->stat_throttled_bytes_down;
    pthread_mutex_unlock(&pb->lock);
    return v;
}
