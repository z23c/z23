/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * HTTP RPC middleware — rate limit, IP ban, request timeout.
 *
 * The HTTP RPC server has basic auth (username/password or cookie) and a
 * 5-second slowloris receive timeout. An attacker who gets past auth (or a
 * misbehaving operator script) can otherwise pound the server as fast as the
 * worker pool can handle.
 *
 * This module adds three guard layers keyed on IP address:
 *
 *   1. Global token bucket — caps total RPC requests per second
 *      across the whole server.  Defaults to 50 rps / 100 burst.
 *
 *   2. Per-IP token bucket — bounded LRU table of IP→bucket so a
 *      single misbehaving client can't starve everyone else.  Defaults
 *      to 5 rps / 10 burst per IP.
 *
 *   3. IP ban — counts auth failures per source IP and auto-bans
 *      after the threshold (default 5 failures → 1h ban).  A
 *      successful request resets the failure counter so a single
 *      mistyped password doesn't trip the trap.  Localhost
 *      (127.0.0.0/8) is NEVER banned — operators routinely run
 *      `zcl-rpc` against the cookie auth from the same machine.
 *
 * Config is read from environment via rpc_http_middleware_load_from_env():
 *
 *   ZCL_RPC_RPS                  global rps   (default 50)
 *   ZCL_RPC_BURST                global burst (default 100)
 *   ZCL_RPC_PER_IP_RPS           per-IP rps   (default 5)
 *   ZCL_RPC_PER_IP_BURST         per-IP burst (default 10)
 *   ZCL_RPC_AUTH_FAIL_THRESHOLD  bans after N auth failures (default 5)
 *   ZCL_RPC_BAN_SECONDS          ban duration in seconds (default 3600)
 *
 * Setting any value to 0 disables the corresponding guard.
 *
 * Thread safety: every public function is safe to call from multiple
 * worker threads concurrently.  All state is guarded by a single
 * internal mutex (the RPC server is not hot enough to need lock
 * sharding).
 */

#ifndef ZCL_RPC_HTTP_MIDDLEWARE_H
#define ZCL_RPC_HTTP_MIDDLEWARE_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bounded — keep memory predictable.  256 distinct client IPs is
 * generous for an RPC endpoint that's almost always loopback-only. */
#define RPC_HTTP_MW_MAX_IPS    256
#define RPC_HTTP_MW_MAX_BANS   1024

struct rpc_http_mw_ip_entry {
    uint32_t  ip_be;            /* IPv4 in network byte order; 0 = empty slot */
    double    bucket;
    int64_t   last_refill_us;
    int       auth_fails;
    int64_t   last_seen_us;     /* for LRU eviction */
};

struct rpc_http_mw_ban_entry {
    uint32_t  ip_be;
    int64_t   expires_unix;
};

enum rpc_http_decision {
    RPC_HTTP_ALLOW              = 0,
    RPC_HTTP_RATE_LIMITED_GLOBAL,
    RPC_HTTP_RATE_LIMITED_PER_IP,
    RPC_HTTP_BANNED,
};

struct rpc_http_middleware {
    /* Config */
    int     global_rps;
    int     global_burst;
    int     per_ip_rps;
    int     per_ip_burst;
    int     auth_fail_threshold;
    int     ban_seconds;

    /* Global token bucket */
    double  global_bucket;
    int64_t global_last_refill_us;

    /* Per-IP token bucket table (linear scan with LRU eviction) */
    struct rpc_http_mw_ip_entry ips[RPC_HTTP_MW_MAX_IPS];
    size_t                       num_ips;

    /* Ban table */
    struct rpc_http_mw_ban_entry bans[RPC_HTTP_MW_MAX_BANS];
    size_t                        num_bans;

    /* Stats — read by tests and native RPC diagnostics. */
    uint64_t stat_allowed;
    uint64_t stat_rate_limited_global;
    uint64_t stat_rate_limited_per_ip;
    uint64_t stat_banned_rejected;
    uint64_t stat_bans_issued;
    uint64_t stat_auth_failures;

    pthread_mutex_t lock;
    bool            initialized;
};

/* Initialise with defaults.  Safe to call once at boot. */
void rpc_http_middleware_init(struct rpc_http_middleware *mw);
void rpc_http_middleware_destroy(struct rpc_http_middleware *mw);

/* Pull config overrides from the environment.  Safe to call after
 * init(); also safe to call from tests after each setenv() block. */
void rpc_http_middleware_load_from_env(struct rpc_http_middleware *mw);

/* Pre-flight check called before authenticating an incoming request.
 *
 *   - Returns RPC_HTTP_BANNED if the IP is in the ban table.
 *   - Returns RPC_HTTP_RATE_LIMITED_GLOBAL or _PER_IP if the
 *     corresponding bucket is empty.
 *   - Otherwise consumes one token from each bucket and returns
 *     RPC_HTTP_ALLOW.
 *
 * Localhost (127.0.0.0/8) bypasses ban + per-IP buckets but still
 * counts against the global bucket — operators get a freebie on the
 * abuse-prevention layers but can't accidentally DoS the server. */
enum rpc_http_decision rpc_http_middleware_check(
    struct rpc_http_middleware *mw, uint32_t client_ip_be);

/* Record an authentication failure (HTTP 401).  Increments the
 * per-IP failure counter and adds the IP to the ban table once it
 * reaches `auth_fail_threshold`.  Localhost is never banned. */
void rpc_http_middleware_record_auth_fail(
    struct rpc_http_middleware *mw, uint32_t client_ip_be);

/* Record a successful request — resets the per-IP failure counter
 * so a legitimate user who mistyped their password earlier isn't
 * permanently one strike away from a ban. */
void rpc_http_middleware_record_success(
    struct rpc_http_middleware *mw, uint32_t client_ip_be);

/* Inspection helpers for tests and native RPC diagnostics. */
bool   rpc_http_middleware_is_banned(struct rpc_http_middleware *mw,
                                      uint32_t client_ip_be);
size_t rpc_http_middleware_active_bans(struct rpc_http_middleware *mw);
size_t rpc_http_middleware_tracked_ips(struct rpc_http_middleware *mw);
int    rpc_http_middleware_ip_auth_fails(struct rpc_http_middleware *mw,
                                          uint32_t client_ip_be);

/* Reset all state (config preserved).  Tests use this between cases. */
void rpc_http_middleware_reset_state(struct rpc_http_middleware *mw);

/* Global middleware handle.  The RPC server owns the singleton (a
 * file-scope struct in httpserver.c) and registers its pointer here at
 * startup so observability code and native RPC diagnostics can read
 * the live config + counters without having to reach into httpserver.c.
 *
 * `rpc_http_middleware_set_global(NULL)` at shutdown clears the pointer
 * so read paths see a clean "not initialized" state.  Thread-safe: the
 * getter/setter are guarded by an internal mutex, and the returned
 * pointer is stable for the lifetime of the RPC server.
 */
void                        rpc_http_middleware_set_global(
    struct rpc_http_middleware *mw);
struct rpc_http_middleware *rpc_http_middleware_get_global(void);

/* A lock-consistent snapshot of the live stats + config, for rendering
 * into Prometheus text or a JSON report.  Reads all fields under the
 * middleware mutex so counters and config can't shear.  `tracked_ips`
 * and `active_bans` are computed after pruning expired bans. */
struct rpc_http_stats_snapshot {
    /* Config */
    int      global_rps;
    int      global_burst;
    int      per_ip_rps;
    int      per_ip_burst;
    int      auth_fail_threshold;
    int      ban_seconds;

    /* Counters since last reset_state */
    uint64_t allowed;
    uint64_t rate_limited_global;
    uint64_t rate_limited_per_ip;
    uint64_t banned_rejected;
    uint64_t bans_issued;
    uint64_t auth_failures;

    /* Gauges */
    size_t   tracked_ips;
    size_t   active_bans;
};

void rpc_http_middleware_stats_snapshot(
    struct rpc_http_middleware *mw,
    struct rpc_http_stats_snapshot *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_RPC_HTTP_MIDDLEWARE_H */
