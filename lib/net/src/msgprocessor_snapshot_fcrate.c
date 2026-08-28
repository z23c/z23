/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The fc_rate_* per-peer FlyClient-challenge rate limiter, split out of
 * msgprocessor_snapshot.c — pure code motion, no behavior change. It earns
 * its own translation unit because it shares nothing with the rest of the
 * dispatcher except the two calls the MSG_FC_CHALLENGE branch makes into
 * it: fc_rate_acquire and fc_rate_should_score (declared in
 * msgprocessor_snapshot_internal.h). See net/msgprocessor.h for the
 * FC_CHALLENGE_RATE_PER_SEC / FC_CHALLENGE_BURST constants and the
 * msgprocessor_test_fc_rate_* test surface this file defines. */

#include "msgprocessor_snapshot_internal.h"

#include "net/msgprocessor.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

/* per-peer FlyClient challenge rate limit.
 *
 * Every zfcchallenge forces snapsync_build_fc_response() to reconstruct
 * 50 MMB proofs over our full block index, which on a ~3M-block chain
 * pins a CPU for tens of milliseconds. Left unchecked, a single hostile
 * peer can throttle header sync for everyone — 1000 challenges/sec and
 * the message thread falls behind its queue.
 *
 * We use a small side table (no changes to struct p2p_node) mapping
 * node_id → token bucket. FC_CHALLENGE_RATE_PER_SEC tokens/sec refill,
 * burst FC_CHALLENGE_BURST — a legit IBD client issues exactly one
 * challenge per snapshot offer, so this comfortably absorbs reconnect
 * churn while still dropping sustained floods. When the bucket hits
 * zero we drop silently (no proof reply) and register PEER_OFFENCE_FLOOD
 * once per flood episode (resets when the peer next consumes a token),
 * so the sustained offender eventually crosses the ban threshold
 * without legitimate bursts costing anyone. Table size is fixed, and
 * an LRU slot is reused when full — a peer churning connections can't
 * force unbounded memory growth. Constants exposed via msgprocessor.h
 * so tests and operators can see the chosen thresholds. */
#define FC_RATE_TABLE_SIZE        64u

struct fc_rate_entry {
    bool      in_use;
    node_id_t peer_id;
    int64_t   refill_time_ms;
    uint32_t  tokens;
    uint32_t  dropped_count;
    bool      flood_scored;
};

static struct fc_rate_entry g_fc_rate_table[FC_RATE_TABLE_SIZE];
static pthread_mutex_t g_fc_rate_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Acquire the token for peer_id at now_ms, returning true on success.
 * New entries start full (burst=30) so a freshly-connected peer can
 * issue its single legitimate challenge without waiting. On a miss we
 * bump dropped_count and keep flood_scored pinned at true until the
 * next successful consume, so ban-score accrues once per flood episode
 * not per dropped challenge. */
bool fc_rate_acquire(node_id_t peer_id, int64_t now_ms)
{
    pthread_mutex_lock(&g_fc_rate_mutex);

    struct fc_rate_entry *e = NULL;
    struct fc_rate_entry *lru = &g_fc_rate_table[0];

    for (size_t i = 0; i < FC_RATE_TABLE_SIZE; i++) {
        struct fc_rate_entry *slot = &g_fc_rate_table[i];
        if (slot->in_use && slot->peer_id == peer_id) { e = slot; break; }
        if (!slot->in_use || slot->refill_time_ms < lru->refill_time_ms)
            lru = slot;
    }

    if (!e) {
        e = lru;
        e->in_use = true;
        e->peer_id = peer_id;
        e->tokens = FC_CHALLENGE_BURST;
        e->refill_time_ms = now_ms;
        e->dropped_count = 0;
        e->flood_scored = false;
    } else {
        int64_t elapsed = now_ms - e->refill_time_ms;
        if (elapsed > 0) {
            uint64_t refill = ((uint64_t)elapsed
                * FC_CHALLENGE_RATE_PER_SEC) / 1000u;
            if (refill > 0) {
                uint64_t cap = (uint64_t)e->tokens + refill;
                if (cap > FC_CHALLENGE_BURST) cap = FC_CHALLENGE_BURST;
                e->tokens = (uint32_t)cap;
                e->refill_time_ms = now_ms;
            }
        }
    }

    bool granted = e->tokens > 0;
    if (granted) {
        e->tokens--;
        e->flood_scored = false;
    } else {
        e->dropped_count++;
    }
    pthread_mutex_unlock(&g_fc_rate_mutex);
    return granted;
}

/* Returns true the first time this function is called after a peer's
 * bucket empties, letting the caller register a single PEER_OFFENCE_FLOOD
 * per episode; subsequent calls within the same flood return false.
 * dropped_out is set to the current lifetime drop count for logging. */
bool fc_rate_should_score(node_id_t peer_id, uint32_t *dropped_out)
{
    bool should = false;
    pthread_mutex_lock(&g_fc_rate_mutex);
    for (size_t i = 0; i < FC_RATE_TABLE_SIZE; i++) {
        struct fc_rate_entry *slot = &g_fc_rate_table[i];
        if (slot->in_use && slot->peer_id == peer_id) {
            if (!slot->flood_scored) {
                slot->flood_scored = true;
                should = true;
            }
            if (dropped_out) *dropped_out = slot->dropped_count;
            break;
        }
    }
    pthread_mutex_unlock(&g_fc_rate_mutex);
    return should;
}

/* Test-only handles. Declared in msgprocessor.h so the test harness can
 * drive the rate limiter with an explicit clock (real tests run faster
 * than peer_scoring_now_ms() can resolve) and then clear it between
 * cases without pulling in the whole P2P stack. */
bool msgprocessor_test_fc_rate_acquire(node_id_t peer_id, int64_t now_ms)
{
    return fc_rate_acquire(peer_id, now_ms);
}

uint32_t msgprocessor_test_fc_rate_dropped(node_id_t peer_id)
{
    uint32_t out = 0;
    pthread_mutex_lock(&g_fc_rate_mutex);
    for (size_t i = 0; i < FC_RATE_TABLE_SIZE; i++) {
        struct fc_rate_entry *slot = &g_fc_rate_table[i];
        if (slot->in_use && slot->peer_id == peer_id) {
            out = slot->dropped_count;
            break;
        }
    }
    pthread_mutex_unlock(&g_fc_rate_mutex);
    return out;
}

bool msgprocessor_test_fc_rate_should_score(node_id_t peer_id)
{
    return fc_rate_should_score(peer_id, NULL);
}

void msgprocessor_test_fc_rate_reset(void)
{
    pthread_mutex_lock(&g_fc_rate_mutex);
    memset(g_fc_rate_table, 0, sizeof(g_fc_rate_table));
    pthread_mutex_unlock(&g_fc_rate_mutex);
}
