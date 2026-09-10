/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Per-address daily byte cap and throttle for the beta6 bootstrap serve path.
 *
 * Port of the quota half of bootstrap.cpp:4675-4790. Buckets key on address
 * GROUP, not address: IPv4 collapses to its /24 and IPv6 to its /64, so an
 * attacker rotating inside one network counts as one bucket instead of
 * multiplying the cap by 256 (or by 2^64). Over the cap the server either
 * spaces sends out to approximately the configured rate or, when throttling is
 * off, stops serving that bucket for the rest of the window.
 *
 * The tracked-bucket map is hard-bounded: expired windows are swept first, and
 * if every window is still live the oldest is evicted, so an attacker cycling
 * through unbounded distinct groups cannot grow it without limit.
 */
#include "services/beta6_bootstrap.h"

#include "util/sync.h"

#include <stdio.h>
#include <string.h>

#define BETA6_QUOTA_KEY_LEN 80

struct beta6_quota_bucket {
    char key[BETA6_QUOTA_KEY_LEN];
    int64_t window_start_ms;
    uint64_t bytes_served;
    int64_t next_allowed_ms;
    bool used;
};

static zcl_mutex_t g_quota_lock;
static bool g_quota_lock_ready;
static struct beta6_quota_bucket g_buckets[BETA6_BS_QUOTA_MAX_TRACKED];
static size_t g_bucket_count;
static int64_t g_max_bytes_per_day = BETA6_BS_DEFAULT_MAX_BYTES_PER_DAY;
static int64_t g_throttle_kbps = BETA6_BS_DEFAULT_THROTTLE_KBPS;

static void quota_lock_init_once(void)
{
    if (!g_quota_lock_ready) {
        zcl_mutex_init(&g_quota_lock);
        g_quota_lock_ready = true;
    }
}

void beta6_bs_quota_configure(int64_t max_bytes_per_day, int64_t throttle_kbps)
{
    quota_lock_init_once();
    LOCK(g_quota_lock);
    g_max_bytes_per_day = max_bytes_per_day;
    g_throttle_kbps = throttle_kbps;
    UNLOCK(g_quota_lock);
}

void beta6_bs_quota_clear(void)
{
    quota_lock_init_once();
    LOCK(g_quota_lock);
    memset(g_buckets, 0, sizeof(g_buckets));
    g_bucket_count = 0;
    UNLOCK(g_quota_lock);
}

/* An IPv4 dotted quad, strictly: four 0-255 decimal fields and nothing else. */
static bool parse_ipv4(const char *ip, unsigned int octets[4])
{
    unsigned int a = 0, b = 0, c = 0, d = 0;
    char tail = '\0';
    if (sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4)
        return false;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return false;
    octets[0] = a;
    octets[1] = b;
    octets[2] = c;
    octets[3] = d;
    return true;
}

/* The IPv6 /64: everything up to and including the fourth ':'-separated
 * group. Rendered under a "v6/64:" tag that no IPv4 form can produce. */
static bool ipv6_prefix_key(const char *ip, char *out, size_t out_size)
{
    size_t groups = 0;
    size_t cut = strlen(ip);
    for (size_t i = 0; ip[i]; i++) {
        if (ip[i] != ':')
            continue;
        groups++;
        if (groups == 4) {
            cut = i;
            break;
        }
    }
    int written = snprintf(out, out_size, "v6/64:%.*s", (int)cut, ip);
    return written > 0 && (size_t)written < out_size;
}

bool beta6_bs_quota_key(const char *ip, char *out, size_t out_size)
{
    if (!ip || !out || out_size == 0)
        return false;
    unsigned int octets[4];
    int written;
    if (parse_ipv4(ip, octets)) {
        written = snprintf(out, out_size, "v4/24:%u.%u.%u", octets[0], octets[1],
                           octets[2]);
    } else if (strchr(ip, ':')) {
        return ipv6_prefix_key(ip, out, out_size);
    } else {
        written = snprintf(out, out_size, "%s", ip);
    }
    return written > 0 && (size_t)written < out_size;
}

static struct beta6_quota_bucket *bucket_find(const char *key)
{
    for (size_t i = 0; i < g_bucket_count; i++) {
        if (g_buckets[i].used && strcmp(g_buckets[i].key, key) == 0)
            return &g_buckets[i];
    }
    return NULL;
}

/* Drop every bucket whose 24h window has fully expired, compacting the array. */
static void buckets_sweep_expired(int64_t now_ms)
{
    size_t kept = 0;
    for (size_t i = 0; i < g_bucket_count; i++) {
        if (!g_buckets[i].used)
            continue;
        if (now_ms - g_buckets[i].window_start_ms >= BETA6_BS_QUOTA_WINDOW_MS)
            continue;
        if (kept != i)
            g_buckets[kept] = g_buckets[i];
        kept++;
    }
    for (size_t i = kept; i < g_bucket_count; i++)
        memset(&g_buckets[i], 0, sizeof(g_buckets[i]));
    g_bucket_count = kept;
}

/* Evict the least-recently-reset bucket. Only reached when the sweep freed
 * nothing, i.e. every tracked window is still live. */
static void bucket_evict_oldest(void)
{
    size_t oldest = 0;
    for (size_t i = 1; i < g_bucket_count; i++) {
        if (g_buckets[i].window_start_ms < g_buckets[oldest].window_start_ms)
            oldest = i;
    }
    g_buckets[oldest] = g_buckets[g_bucket_count - 1];
    memset(&g_buckets[g_bucket_count - 1], 0, sizeof(g_buckets[g_bucket_count - 1]));
    g_bucket_count--;
}

static struct beta6_quota_bucket *bucket_insert(const char *key, int64_t now_ms)
{
    if (g_bucket_count >= BETA6_BS_QUOTA_MAX_TRACKED)
        buckets_sweep_expired(now_ms);
    if (g_bucket_count >= BETA6_BS_QUOTA_MAX_TRACKED)
        bucket_evict_oldest();
    struct beta6_quota_bucket *bucket = &g_buckets[g_bucket_count++];
    memset(bucket, 0, sizeof(*bucket));
    snprintf(bucket->key, sizeof(bucket->key), "%s", key);
    /* Stamp the window at insertion rather than leaving it 0 and treating 0 as
     * "fresh" later: a caller whose clock origin IS 0 would otherwise reset
     * the counter on every charge and never reach its cap. */
    bucket->window_start_ms = now_ms;
    bucket->used = true;
    return bucket;
}

bool beta6_bs_quota_allow(const char *key, bool whitelisted, int64_t now_ms, bool *stop)
{
    if (stop)
        *stop = false;
    if (!key)
        return false;
    quota_lock_init_once();
    LOCK(g_quota_lock);
    bool allowed = true;
    if (!whitelisted && g_max_bytes_per_day > 0) {
        struct beta6_quota_bucket *bucket = bucket_find(key);
        if (bucket && now_ms - bucket->window_start_ms < BETA6_BS_QUOTA_WINDOW_MS &&
            bucket->bytes_served >= (uint64_t)g_max_bytes_per_day) {
            if (g_throttle_kbps <= 0) {
                if (stop)
                    *stop = true;
                allowed = false;
            } else {
                allowed = now_ms >= bucket->next_allowed_ms;
            }
        }
    }
    UNLOCK(g_quota_lock);
    return allowed;
}

void beta6_bs_quota_charge(const char *key, bool whitelisted, int64_t now_ms,
                           uint64_t bytes)
{
    if (!key || whitelisted)
        return;
    quota_lock_init_once();
    LOCK(g_quota_lock);
    if (g_max_bytes_per_day <= 0) {
        UNLOCK(g_quota_lock);
        return;
    }
    struct beta6_quota_bucket *bucket = bucket_find(key);
    if (!bucket)
        bucket = bucket_insert(key, now_ms);
    if (now_ms - bucket->window_start_ms >= BETA6_BS_QUOTA_WINDOW_MS) {
        bucket->window_start_ms = now_ms;
        bucket->bytes_served = 0;
        bucket->next_allowed_ms = 0;
    }
    bucket->bytes_served += bytes;
    if (bucket->bytes_served >= (uint64_t)g_max_bytes_per_day && g_throttle_kbps > 0) {
        int64_t delay_ms = (int64_t)((bytes * 1000ULL) / ((uint64_t)g_throttle_kbps * 1024ULL));
        bucket->next_allowed_ms = now_ms + (delay_ms > 1 ? delay_ms : 1);
    }
    UNLOCK(g_quota_lock);
}
