/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HTTP RPC middleware — implementation.  See http_middleware.h for the
 * design notes. */

#include "platform/time_compat.h"
#include "rpc/http_middleware.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_GLOBAL_RPS         50
#define DEFAULT_GLOBAL_BURST       100
#define DEFAULT_PER_IP_RPS         5
#define DEFAULT_PER_IP_BURST       10
#define DEFAULT_AUTH_FAIL_THRESHOLD 5
#define DEFAULT_BAN_SECONDS        3600

static int64_t mono_us(void)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}

static int64_t now_unix(void)
{
    return platform_time_wall_unix();
}

/* Loopback check: 127.0.0.0/8 in network byte order.  ip_be is in
 * network byte order so the high byte is the first octet. */
static bool is_loopback_be(uint32_t ip_be)
{
    return (ip_be & 0x000000FFu) == 0x0000007Fu;  /* first octet == 127 */
}

void rpc_http_middleware_init(struct rpc_http_middleware *mw)
{
    if (!mw) return;
    memset(mw, 0, sizeof(*mw));

    mw->global_rps           = DEFAULT_GLOBAL_RPS;
    mw->global_burst         = DEFAULT_GLOBAL_BURST;
    mw->per_ip_rps           = DEFAULT_PER_IP_RPS;
    mw->per_ip_burst         = DEFAULT_PER_IP_BURST;
    mw->auth_fail_threshold  = DEFAULT_AUTH_FAIL_THRESHOLD;
    mw->ban_seconds          = DEFAULT_BAN_SECONDS;

    mw->global_bucket          = (double)mw->global_burst;
    mw->global_last_refill_us  = mono_us();

    pthread_mutex_init(&mw->lock, NULL);
    mw->initialized = true;
}

void rpc_http_middleware_destroy(struct rpc_http_middleware *mw)
{
    if (!mw || !mw->initialized) return;
    pthread_mutex_destroy(&mw->lock);
    mw->initialized = false;
}

static int read_env_int(const char *name, int fallback, int min, int max)
{
    const char *v = getenv(name);
    if (!v || !*v) return fallback;
    char *end = NULL;
    long parsed = strtol(v, &end, 10);
    if (end == v) return fallback;
    if (parsed < (long)min) parsed = (long)min;
    if (parsed > (long)max) parsed = (long)max;
    return (int)parsed;
}

void rpc_http_middleware_load_from_env(struct rpc_http_middleware *mw)
{
    if (!mw) return;
    if (!mw->initialized) rpc_http_middleware_init(mw);

    pthread_mutex_lock(&mw->lock);
    /* 0 disables the layer (caller can set ZCL_RPC_RPS=0 to skip
     * the global bucket entirely; ditto for per_ip). */
    mw->global_rps   = read_env_int("ZCL_RPC_RPS",   DEFAULT_GLOBAL_RPS,   0, 1000000);
    mw->global_burst = read_env_int("ZCL_RPC_BURST", DEFAULT_GLOBAL_BURST, 0, 1000000);
    mw->per_ip_rps   = read_env_int("ZCL_RPC_PER_IP_RPS",   DEFAULT_PER_IP_RPS,   0, 1000000);
    mw->per_ip_burst = read_env_int("ZCL_RPC_PER_IP_BURST", DEFAULT_PER_IP_BURST, 0, 1000000);
    mw->auth_fail_threshold = read_env_int("ZCL_RPC_AUTH_FAIL_THRESHOLD",
                                            DEFAULT_AUTH_FAIL_THRESHOLD, 1, 1000);
    mw->ban_seconds  = read_env_int("ZCL_RPC_BAN_SECONDS",  DEFAULT_BAN_SECONDS,  1, 30 * 86400);

    /* Reset bucket so a tightening change is enforced immediately. */
    if (mw->global_bucket > (double)mw->global_burst)
        mw->global_bucket = (double)mw->global_burst;
    pthread_mutex_unlock(&mw->lock);
}

/* ── Token bucket math ──────────────────────────────────────── */

static void refill(double *bucket, int64_t *last_us, int rps, int burst)
{
    if (rps <= 0 || burst <= 0) {
        /* Disabled — bucket is "always full". */
        *bucket = (double)burst;
        return;
    }
    int64_t now = mono_us();
    int64_t dt  = now - *last_us;
    if (dt < 0) {
        /* Monotonic clock went backwards (NTP step / VM migration /
         * suspend-resume). Without re-baselining, dt stays negative
         * forever and the bucket never refills again — a silent
         * rate-limit wedge. Snap the baseline to now and continue. */
        LOG_WARN("rpc", "clock rewound %lld us; resetting refill baseline",
                 (long long)(-dt));
        *last_us = now;
        return;
    }
    if (dt == 0) return;  /* same-microsecond reading; nothing to add */
    *bucket += ((double)rps * (double)dt) / 1000000.0;
    if (*bucket > (double)burst) *bucket = (double)burst;
    *last_us = now;
}

/* ── Per-IP table ───────────────────────────────────────────── */

static struct rpc_http_mw_ip_entry *
find_ip_locked(struct rpc_http_middleware *mw, uint32_t ip_be)
{
    for (size_t i = 0; i < mw->num_ips; i++)
        if (mw->ips[i].ip_be == ip_be)
            return &mw->ips[i];
    return NULL;
}

/* Get-or-create the per-IP entry, evicting the least-recently-seen
 * slot when the table is full.  Returns NULL only on a logic bug
 * (the table has at least one slot). */
static struct rpc_http_mw_ip_entry *
get_or_create_ip_locked(struct rpc_http_middleware *mw, uint32_t ip_be)
{
    struct rpc_http_mw_ip_entry *e = find_ip_locked(mw, ip_be);
    if (e) return e;

    if (mw->num_ips < RPC_HTTP_MW_MAX_IPS) {
        e = &mw->ips[mw->num_ips++];
    } else {
        /* Evict the LRU slot. */
        size_t lru = 0;
        for (size_t i = 1; i < mw->num_ips; i++) {
            if (mw->ips[i].last_seen_us < mw->ips[lru].last_seen_us)
                lru = i;
        }
        e = &mw->ips[lru];
    }
    memset(e, 0, sizeof(*e));
    e->ip_be          = ip_be;
    e->bucket         = (double)mw->per_ip_burst;
    e->last_refill_us = mono_us();
    return e;
}

/* ── Ban table ──────────────────────────────────────────────── */

static void prune_expired_bans_locked(struct rpc_http_middleware *mw, int64_t now)
{
    size_t w = 0;
    for (size_t r = 0; r < mw->num_bans; r++) {
        if (mw->bans[r].expires_unix > now) {
            if (w != r) mw->bans[w] = mw->bans[r];
            w++;
        }
    }
    mw->num_bans = w;
}

static bool is_banned_locked(struct rpc_http_middleware *mw, uint32_t ip_be)
{
    int64_t now = now_unix();
    prune_expired_bans_locked(mw, now);
    for (size_t i = 0; i < mw->num_bans; i++)
        if (mw->bans[i].ip_be == ip_be) return true;
    return false;
}

static void issue_ban_locked(struct rpc_http_middleware *mw, uint32_t ip_be)
{
    if (mw->num_bans >= RPC_HTTP_MW_MAX_BANS) {
        /* Replace the soonest-to-expire entry. */
        size_t soonest = 0;
        for (size_t i = 1; i < mw->num_bans; i++) {
            if (mw->bans[i].expires_unix < mw->bans[soonest].expires_unix)
                soonest = i;
        }
        mw->bans[soonest].ip_be        = ip_be;
        mw->bans[soonest].expires_unix = now_unix() + mw->ban_seconds;
    } else {
        mw->bans[mw->num_bans].ip_be        = ip_be;
        mw->bans[mw->num_bans].expires_unix = now_unix() + mw->ban_seconds;
        mw->num_bans++;
    }
    mw->stat_bans_issued++;
}

/* ── Public API ─────────────────────────────────────────────── */

enum rpc_http_decision rpc_http_middleware_check(
    struct rpc_http_middleware *mw, uint32_t client_ip_be)
{
    if (!mw || !mw->initialized) return RPC_HTTP_ALLOW;

    pthread_mutex_lock(&mw->lock);

    bool loopback = is_loopback_be(client_ip_be);

    /* 1. Banned IP */
    if (!loopback && is_banned_locked(mw, client_ip_be)) {
        mw->stat_banned_rejected++;
        pthread_mutex_unlock(&mw->lock);
        return RPC_HTTP_BANNED;
    }

    /* 2. Global bucket */
    if (mw->global_rps > 0 && mw->global_burst > 0) {
        refill(&mw->global_bucket, &mw->global_last_refill_us,
               mw->global_rps, mw->global_burst);
        if (mw->global_bucket < 1.0) {
            mw->stat_rate_limited_global++;
            pthread_mutex_unlock(&mw->lock);
            return RPC_HTTP_RATE_LIMITED_GLOBAL;
        }
        mw->global_bucket -= 1.0;
    }

    /* 3. Per-IP bucket (loopback exempt) */
    if (!loopback && mw->per_ip_rps > 0 && mw->per_ip_burst > 0) {
        struct rpc_http_mw_ip_entry *e =
            get_or_create_ip_locked(mw, client_ip_be);
        refill(&e->bucket, &e->last_refill_us,
               mw->per_ip_rps, mw->per_ip_burst);
        e->last_seen_us = mono_us();
        if (e->bucket < 1.0) {
            mw->stat_rate_limited_per_ip++;
            /* Refund the global token so a single bursty client doesn't
             * also drain the global bucket they've already been kicked
             * off of. */
            mw->global_bucket += 1.0;
            if (mw->global_bucket > (double)mw->global_burst)
                mw->global_bucket = (double)mw->global_burst;
            pthread_mutex_unlock(&mw->lock);
            return RPC_HTTP_RATE_LIMITED_PER_IP;
        }
        e->bucket -= 1.0;
    }

    mw->stat_allowed++;
    pthread_mutex_unlock(&mw->lock);
    return RPC_HTTP_ALLOW;
}

void rpc_http_middleware_record_auth_fail(
    struct rpc_http_middleware *mw, uint32_t client_ip_be)
{
    if (!mw || !mw->initialized) return;
    if (is_loopback_be(client_ip_be)) return;

    pthread_mutex_lock(&mw->lock);
    mw->stat_auth_failures++;
    struct rpc_http_mw_ip_entry *e =
        get_or_create_ip_locked(mw, client_ip_be);
    e->auth_fails++;
    e->last_seen_us = mono_us();
    if (e->auth_fails >= mw->auth_fail_threshold)
        issue_ban_locked(mw, client_ip_be);
    pthread_mutex_unlock(&mw->lock);
}

void rpc_http_middleware_record_success(
    struct rpc_http_middleware *mw, uint32_t client_ip_be)
{
    if (!mw || !mw->initialized) return;
    pthread_mutex_lock(&mw->lock);
    struct rpc_http_mw_ip_entry *e = find_ip_locked(mw, client_ip_be);
    if (e) {
        e->auth_fails  = 0;
        e->last_seen_us = mono_us();
    }
    pthread_mutex_unlock(&mw->lock);
}

bool rpc_http_middleware_is_banned(struct rpc_http_middleware *mw,
                                    uint32_t client_ip_be)
{
    if (!mw || !mw->initialized) return false;
    if (is_loopback_be(client_ip_be)) return false;
    pthread_mutex_lock(&mw->lock);
    bool b = is_banned_locked(mw, client_ip_be);
    pthread_mutex_unlock(&mw->lock);
    return b;
}

size_t rpc_http_middleware_active_bans(struct rpc_http_middleware *mw)
{
    if (!mw || !mw->initialized) return 0;
    pthread_mutex_lock(&mw->lock);
    prune_expired_bans_locked(mw, now_unix());
    size_t n = mw->num_bans;
    pthread_mutex_unlock(&mw->lock);
    return n;
}

size_t rpc_http_middleware_tracked_ips(struct rpc_http_middleware *mw)
{
    if (!mw || !mw->initialized) return 0;
    pthread_mutex_lock(&mw->lock);
    size_t n = mw->num_ips;
    pthread_mutex_unlock(&mw->lock);
    return n;
}

int rpc_http_middleware_ip_auth_fails(struct rpc_http_middleware *mw,
                                       uint32_t client_ip_be)
{
    if (!mw || !mw->initialized) return 0;
    pthread_mutex_lock(&mw->lock);
    struct rpc_http_mw_ip_entry *e = find_ip_locked(mw, client_ip_be);
    int n = e ? e->auth_fails : 0;
    pthread_mutex_unlock(&mw->lock);
    return n;
}

void rpc_http_middleware_reset_state(struct rpc_http_middleware *mw)
{
    if (!mw || !mw->initialized) return;
    pthread_mutex_lock(&mw->lock);
    memset(mw->ips, 0, sizeof(mw->ips));
    memset(mw->bans, 0, sizeof(mw->bans));
    mw->num_ips                    = 0;
    mw->num_bans                   = 0;
    mw->global_bucket              = (double)mw->global_burst;
    mw->global_last_refill_us      = mono_us();
    mw->stat_allowed               = 0;
    mw->stat_rate_limited_global   = 0;
    mw->stat_rate_limited_per_ip   = 0;
    mw->stat_banned_rejected       = 0;
    mw->stat_bans_issued           = 0;
    mw->stat_auth_failures         = 0;
    pthread_mutex_unlock(&mw->lock);
}

/* ── Global handle ─────────────────────────────────────────────
 *
 * Guarded by its own mutex so the setter/getter don't race with the
 * RPC server's init/destroy path.  The pointer itself is never
 * dereferenced under this lock — observers read the stats via the
 * middleware's own internal mutex inside rpc_http_middleware_stats_snapshot.
 */
static struct rpc_http_middleware *g_global_mw = NULL;
static pthread_mutex_t              g_global_mw_lock = PTHREAD_MUTEX_INITIALIZER;

void rpc_http_middleware_set_global(struct rpc_http_middleware *mw)
{
    pthread_mutex_lock(&g_global_mw_lock);
    g_global_mw = mw;
    pthread_mutex_unlock(&g_global_mw_lock);
}

struct rpc_http_middleware *rpc_http_middleware_get_global(void)
{
    pthread_mutex_lock(&g_global_mw_lock);
    struct rpc_http_middleware *mw = g_global_mw;
    pthread_mutex_unlock(&g_global_mw_lock);
    return mw;
}

void rpc_http_middleware_stats_snapshot(struct rpc_http_middleware *mw,
                                         struct rpc_http_stats_snapshot *out)
{
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!mw || !mw->initialized) return;

    pthread_mutex_lock(&mw->lock);
    /* Prune expired bans inside the lock so active_bans is accurate. */
    prune_expired_bans_locked(mw, now_unix());

    out->global_rps           = mw->global_rps;
    out->global_burst         = mw->global_burst;
    out->per_ip_rps           = mw->per_ip_rps;
    out->per_ip_burst         = mw->per_ip_burst;
    out->auth_fail_threshold  = mw->auth_fail_threshold;
    out->ban_seconds          = mw->ban_seconds;

    out->allowed              = mw->stat_allowed;
    out->rate_limited_global  = mw->stat_rate_limited_global;
    out->rate_limited_per_ip  = mw->stat_rate_limited_per_ip;
    out->banned_rejected      = mw->stat_banned_rejected;
    out->bans_issued          = mw->stat_bans_issued;
    out->auth_failures        = mw->stat_auth_failures;

    out->tracked_ips          = mw->num_ips;
    out->active_bans          = mw->num_bans;
    pthread_mutex_unlock(&mw->lock);
}
