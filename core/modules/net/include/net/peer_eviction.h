/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * peer_eviction.h — inbound-slot eviction selection (Bitcoin-Core-inspired
 * protection classes). Pure, allocation-free, no locks: the caller snapshots
 * peer stats (typically under nm->cs_nodes) and calls peer_eviction_select()
 * with the snapshot. */

#ifndef ZCL_NET_PEER_EVICTION_H
#define ZCL_NET_PEER_EVICTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Candidates beyond this count are ignored (defensive truncation, not an
 * error) — well above DEFAULT_MAX_PEER_CONNECTIONS (net.h). */
#define PEER_EVICTION_MAX_CANDIDATES 256

/* Protection window: a candidate that relayed a novel block or tx within
 * this many seconds of `now` is protected from eviction. */
#define PEER_EVICTION_RECENT_RELAY_SECS 300

struct peer_eviction_candidate {
    bool is_outbound;         /* never a candidate */
    bool whitelisted;         /* never a candidate */
    int64_t connected_time;   /* unix seconds */
    int64_t last_block_time;  /* unix seconds of last novel block relay, 0 = never */
    int64_t last_tx_time;     /* unix seconds of last novel tx relay, 0 = never */
};

/* Selects the inbound peer to evict to make room for a new inbound
 * connection. Protection, applied in order over the inbound
 * (non-outbound, non-whitelisted) candidates:
 *   1. the longest-connected quartile (by connected_time).
 *   2. any candidate that relayed a novel block or tx within
 *      PEER_EVICTION_RECENT_RELAY_SECS of `now`.
 * Among what remains, the most-recently-connected (newest) candidate is
 * evicted.
 *
 * Returns the index into candidates[0..n) to evict, or -1 when nothing can
 * be evicted (n == 0, every candidate is outbound/whitelisted, or every
 * inbound candidate is protected — the caller should reject the new
 * connection in that case, same as before eviction existed). */
int peer_eviction_select(const struct peer_eviction_candidate *candidates,
                          size_t n, int64_t now);

#endif
