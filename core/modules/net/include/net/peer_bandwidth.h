/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-peer bandwidth quotas — token bucket with separate up/down
 * directions, localhost/trusted-peer bypass, and `EV_PEER_THROTTLED`
 * event emission on quota exhaustion.
 *
 * Why: today a single misbehaving or overly-eager peer can drain the
 * uplink by spamming `getdata` for every block, or saturate the
 * download path by pushing headers too fast.  We have peer_scoring
 * for correctness-level offences (invalid_block, flood), but nothing
 * that caps raw byte throughput on a per-peer basis.  This module
 * gives the connman send/recv paths a cheap `peer_bandwidth_consume`
 * call they can gate traffic through without understanding protocol
 * semantics.
 *
 * Config from the environment:
 *
 *   ZCL_PEER_UP_BPS    upload tokens-per-second per peer   (default 10 MB/s)
 *   ZCL_PEER_DOWN_BPS  download tokens-per-second per peer (default 20 MB/s)
 *   ZCL_PEER_BURST     burst window in bytes               (default 1 MB)
 *
 * Setting a direction's bps to 0 disables that layer entirely for
 * that direction (tokens always flow).  Localhost + explicitly
 * trusted peers always bypass the quota and are treated as
 * unlimited — this mirrors the peer_scoring contract and keeps the
 * operator's local zcl-rpc path fast regardless of whatever the env
 * caps say.
 *
 * Thread safety: every public function takes the module's internal
 * mutex, safe to call from multiple connman worker threads.
 *
 * NB: this commit ships the primitives + event emission + test
 * coverage.  Wire-up into `core/modules/net/src/connman.c` send/recv hot
 * paths is a follow-up — that touches tens of call sites and
 * deserves its own regression coverage on top of these unit tests.
 */

#ifndef ZCL_NET_PEER_BANDWIDTH_H
#define ZCL_NET_PEER_BANDWIDTH_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum peer_bandwidth_dir {
    PEER_BW_UP   = 0,
    PEER_BW_DOWN = 1,
};

/* Bounded per-peer table — 1024 concurrent peers is comfortably
 * above the default ~200-peer cap and keeps memory predictable. */
#define PEER_BW_MAX_PEERS 1024

struct peer_bw_bucket {
    uint32_t  peer_id;             /* 0 = empty slot */
    bool      trusted;             /* bypass quota entirely */
    double    up_tokens;
    double    down_tokens;
    int64_t   up_last_refill_us;
    int64_t   down_last_refill_us;
    uint64_t  up_throttled_bytes;  /* cumulative bytes that got throttled */
    uint64_t  down_throttled_bytes;
    int64_t   last_seen_us;        /* for LRU eviction */
};

struct peer_bandwidth {
    /* Config */
    int64_t  up_bps;               /* bytes per second */
    int64_t  down_bps;
    int64_t  burst_bytes;

    /* Bucket table (linear scan with LRU eviction) */
    struct peer_bw_bucket peers[PEER_BW_MAX_PEERS];
    size_t                 num_peers;

    /* Aggregate stats (all buckets, since last reset_state) */
    uint64_t stat_allowed_bytes_up;
    uint64_t stat_allowed_bytes_down;
    uint64_t stat_throttled_events_up;
    uint64_t stat_throttled_events_down;
    uint64_t stat_throttled_bytes_up;
    uint64_t stat_throttled_bytes_down;

    pthread_mutex_t lock;
    bool            initialized;
};

/* Initialise with defaults.  Idempotent — safe to call at boot. */
void peer_bandwidth_init(struct peer_bandwidth *pb);
void peer_bandwidth_destroy(struct peer_bandwidth *pb);

/* Pull config overrides from the environment.  Safe to call after
 * init() and from tests after each setenv() block.  Bytes-per-second
 * fields accept 0 to disable that direction. */
void peer_bandwidth_load_from_env(struct peer_bandwidth *pb);

/* Mark a peer as trusted so it bypasses the quota.  Call this for
 * addnode-configured peers and for the loopback peers connman
 * creates to wire up the local zcl-rpc path.  NULL-safe. */
void peer_bandwidth_mark_trusted(struct peer_bandwidth *pb,
                                  uint32_t peer_id, bool trusted);

/* Attempt to charge `bytes` against the peer's `dir` bucket.  If the
 * bucket has enough tokens, they are consumed and the function
 * returns true.  Otherwise the tokens are NOT consumed, an
 * EV_PEER_THROTTLED event is emitted with a diagnostic payload, and
 * the function returns false — the caller should drop the write (or
 * pause the read) and try again after the bucket refills.
 *
 * Trusted peers + a bucket with bps=0 always return true and do not
 * charge tokens. */
bool peer_bandwidth_consume(struct peer_bandwidth *pb,
                             uint32_t peer_id,
                             enum peer_bandwidth_dir dir,
                             size_t bytes);

/* How many whole bytes the peer could consume right now without
 * being throttled.  Used by tests and by future flow-control code
 * that wants to pick a send chunk size. */
size_t peer_bandwidth_available(struct peer_bandwidth *pb,
                                 uint32_t peer_id,
                                 enum peer_bandwidth_dir dir);

/* Clear all bucket state (config preserved).  Tests call this
 * between cases. */
void peer_bandwidth_reset_state(struct peer_bandwidth *pb);

/* Introspection helpers. */
size_t   peer_bandwidth_tracked_peers(struct peer_bandwidth *pb);
uint64_t peer_bandwidth_throttled_events(struct peer_bandwidth *pb,
                                          enum peer_bandwidth_dir dir);
uint64_t peer_bandwidth_throttled_bytes(struct peer_bandwidth *pb,
                                         enum peer_bandwidth_dir dir);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_NET_PEER_BANDWIDTH_H */
