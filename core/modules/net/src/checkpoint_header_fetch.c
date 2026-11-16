/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_header_fetch — see net/checkpoint_header_fetch.h.
 *
 * NET-thread mechanism only: arm/offer/take/maybe_send. The frozen-Equihash
 * verify and the durable persist live in the app-layer condition
 * checkpoint_header_solution_repair (which OWNS the trust decision); this TU
 * never validates a solution — capture is a HASH-PIN comparison, and take()
 * requires the caller to re-verify. */

#include "net/checkpoint_header_fetch.h"

#include "net/msgprocessor.h"          /* struct msg_processor, main_state */
#include "net/msg_internal.h"          /* push_getheaders_span */
#include "net/net.h"                   /* struct p2p_node, enum peer_state */
#include "chain/chain.h"               /* struct block_index */
#include "chain/checkpoints.h"         /* get_sha3_utxo_checkpoint */
#include "core/uint256.h"
#include "primitives/block.h"          /* struct block_header */
#include "validation/chainstate.h"     /* block_map_find */
#include "validation/main_state.h"     /* struct main_state */
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#define CHF_SUBSYS "checkpoint_fetch"

/* At most one span request per this interval, across ALL peers — the checkpoint
 * header is a single wire header; one honest peer answers in one round trip. */
#define CHF_SEND_INTERVAL_US (5 * 1000000)

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool    g_armed = false;
static _Atomic bool    g_captured = false;
static _Atomic int32_t g_target_height = -1;
static uint8_t         g_target_hash[32];        /* guarded by g_lock */
static struct block_header g_captured_header;    /* guarded by g_lock */
static _Atomic int64_t g_last_send_us = 0;
static _Atomic uint64_t g_sends = 0;
static _Atomic uint64_t g_captures = 0;

/* Window mode (see the header). g_window_depth == 0 is single mode, exactly
 * the behavior before window mode existed. */
static _Atomic int     g_window_depth = 0;
static _Atomic int     g_window_have = 0;
static struct block_header g_window[CHECKPOINT_HEADER_FETCH_WINDOW_MAX]; /* g_lock */
static int32_t         g_window_top_height = -1;  /* guarded by g_lock */
/* Peers already asked for the current window target, so a retry goes to a
 * different peer when one exists (a peer that answers an empty locator with
 * something other than the hash_stop header must not absorb every retry). */
#define CHF_ASKED_MAX 8
static int64_t         g_asked[CHF_ASKED_MAX];    /* guarded by g_lock */
static int             g_asked_n = 0;             /* guarded by g_lock */
/* Window span: at most one bounded getheaders span per armed window asks for
 * the whole window at once. Its reply arrives in ascending height order while
 * the capture is pinned top-down, so after the span went out the headers that
 * do not match yet wait in this ring; each capture drains from it the header
 * that hashes to the new target. The ring only holds candidates: a header
 * leaves it only by hashing to the pinned target, exactly as on the wire. */
static bool            g_window_span_tried = false;               /* g_lock */
static struct block_header g_ring[CHECKPOINT_HEADER_FETCH_WINDOW_MAX]; /* g_lock */
static struct uint256  g_ring_hash[CHECKPOINT_HEADER_FETCH_WINDOW_MAX]; /* g_lock */
static bool            g_ring_used[CHECKPOINT_HEADER_FETCH_WINDOW_MAX]; /* g_lock */
static int             g_ring_next = 0;                            /* g_lock */

void checkpoint_header_fetch_arm(int32_t height, const struct uint256 *hash)
{
    if (!hash || height < 0)
        return; // raw-return-ok:invalid-arm-args
    pthread_mutex_lock(&g_lock);
    memcpy(g_target_hash, hash->data, 32);
    atomic_store(&g_window_depth, 0);
    atomic_store(&g_window_have, 0);
    pthread_mutex_unlock(&g_lock);
    atomic_store(&g_target_height, height);
    atomic_store(&g_armed, true);
}

void checkpoint_header_fetch_arm_compiled(void)
{
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp || cp->height < 0)
        return; // raw-return-ok:no-compiled-checkpoint
    struct uint256 hash;
    memcpy(hash.data, cp->block_hash, 32);
    checkpoint_header_fetch_arm(cp->height, &hash);
    LOG_INFO(CHF_SUBSYS,
             "armed compiled-checkpoint header capture h=%d — IBD headers "
             "that hash-pin to the checkpoint keep nSolution for instant-on",
             cp->height);
}

void checkpoint_header_fetch_disarm(void)
{
    atomic_store(&g_armed, false);
    atomic_store(&g_captured, false);
    atomic_store(&g_window_depth, 0);
    atomic_store(&g_window_have, 0);
}

bool checkpoint_header_fetch_is_armed(void)
{
    return atomic_load(&g_armed);
}

bool checkpoint_header_fetch_has_capture(void)
{
    /* Non-consuming peek: unlike take(), never clears the slot. Relaxed is
     * fine — the caller (the repair remedy) re-checks + consumes under the
     * lock via take(); this only decides whether to run the remedy now. */
    return atomic_load_explicit(&g_captured, memory_order_relaxed) &&
           atomic_load(&g_window_depth) == 0;
}

bool checkpoint_header_fetch_take(struct block_header *out, int32_t *out_height)
{
    if (!out)
        return false; // raw-return-ok:null-out
    if (!atomic_load(&g_captured))
        return false; // raw-return-ok:nothing-captured
    pthread_mutex_lock(&g_lock);
    bool have = atomic_load(&g_captured) && atomic_load(&g_window_depth) == 0;
    if (have) {
        *out = g_captured_header;
        if (out_height)
            *out_height = atomic_load(&g_target_height);
        atomic_store(&g_captured, false); /* consume: one take per capture */
    }
    pthread_mutex_unlock(&g_lock);
    return have;
}

/* Under g_lock: drop every waiting span candidate. */
static void chf_ring_clear_locked(void)
{
    memset(g_ring_used, 0, sizeof(g_ring_used));
    g_ring_next = 0;
}

/* Under g_lock: keep a not-yet-matching header, overwriting the oldest, so a
 * hostile batch of any length costs the fixed ring and nothing more. */
static void chf_ring_put_locked(const struct block_header *hdr,
                                const struct uint256 *hash)
{
    g_ring[g_ring_next] = *hdr;
    g_ring_hash[g_ring_next] = *hash;
    g_ring_used[g_ring_next] = true;
    g_ring_next = (g_ring_next + 1) % CHECKPOINT_HEADER_FETCH_WINDOW_MAX;
}

/* Under g_lock: the ring slot whose hash is the pinned target, or -1. */
static int chf_ring_find_target_locked(void)
{
    for (int i = 0; i < CHECKPOINT_HEADER_FETCH_WINDOW_MAX; i++)
        if (g_ring_used[i] && memcmp(g_ring_hash[i].data, g_target_hash, 32) == 0)
            return i;
    return -1;
}

/* Under g_lock: store a header whose hash IS the pinned target and re-target
 * its hashPrevBlock one height lower. True once `depth` headers are held. */
static bool chf_window_capture_locked(const struct block_header *hdr)
{
    int have = atomic_load(&g_window_have);
    int depth = atomic_load(&g_window_depth);
    g_window[have] = *hdr;
    have++;
    atomic_store(&g_window_have, have);
    atomic_fetch_add(&g_captures, 1);
    g_asked_n = 0;
    if (have >= depth) {
        atomic_store(&g_captured, true);
        return true;
    }
    memcpy(g_target_hash, hdr->hashPrevBlock.data, 32);
    atomic_store(&g_target_height, atomic_load(&g_target_height) - 1);
    atomic_store(&g_last_send_us, 0); /* next step goes out at once */
    return false;
}

/* Under g_lock: after a capture, take from the ring each header that hashes to
 * the new target. True once the window is complete. */
static bool chf_ring_drain_locked(void)
{
    bool complete = false;
    int i = chf_ring_find_target_locked();
    while (!complete && i >= 0) {
        g_ring_used[i] = false;
        complete = chf_window_capture_locked(&g_ring[i]);
        i = complete ? -1 : chf_ring_find_target_locked();
    }
    return complete;
}

/* Window-mode capture: HASH-PIN ONLY, like single mode. A match stores the
 * header and re-targets its hashPrevBlock one height lower; the walk is
 * complete (g_captured) once `depth` headers are held. After a window span
 * went out, a header that does not match yet waits in the ring for the
 * capture to reach it (one ascending headers message completes the window). */
static void chf_window_offer(const struct block_header *hdr,
                             const struct uint256 *hash)
{
    bool complete = false;
    pthread_mutex_lock(&g_lock);
    int depth = atomic_load(&g_window_depth);
    bool open = atomic_load(&g_armed) && !atomic_load(&g_captured) &&
                depth > 0 && atomic_load(&g_window_have) < depth;
    if (open && memcmp(hash->data, g_target_hash, 32) == 0)
        complete = chf_window_capture_locked(hdr) || chf_ring_drain_locked();
    else if (open && g_window_span_tried)
        chf_ring_put_locked(hdr, hash);
    int32_t at = atomic_load(&g_target_height);
    pthread_mutex_unlock(&g_lock);
    if (complete)
        LOG_INFO(CHF_SUBSYS,
                 "header window complete: %d headers down to h=%d, "
                 "hash-pinned from the armed top; app will verify",
                 depth, at);
}

void checkpoint_header_fetch_arm_window(int32_t height,
                                        const struct uint256 *hash, int depth)
{
    if (!hash || height < 0 || depth < 1 ||
        depth > CHECKPOINT_HEADER_FETCH_WINDOW_MAX || height + 1 < depth)
        return; // raw-return-ok:invalid-arm-args
    pthread_mutex_lock(&g_lock);
    memcpy(g_target_hash, hash->data, 32);
    g_window_top_height = height;
    g_asked_n = 0;
    g_window_span_tried = false;
    chf_ring_clear_locked();
    atomic_store(&g_window_have, 0);
    atomic_store(&g_window_depth, depth);
    atomic_store(&g_captured, false);
    atomic_store(&g_target_height, height);
    atomic_store(&g_last_send_us, 0);
    atomic_store(&g_armed, true);
    pthread_mutex_unlock(&g_lock);
    LOG_INFO(CHF_SUBSYS,
             "armed header window walk: %d headers down from h=%d by one "
             "bounded getheaders span when the index holds the row below, "
             "else empty-locator getheaders", depth, height);
}

int checkpoint_header_fetch_window_progress(void)
{
    return atomic_load(&g_window_depth) > 0 ? atomic_load(&g_window_have) : 0;
}

int checkpoint_header_fetch_take_window(struct block_header *out, int cap,
                                        int32_t *out_top_height)
{
    if (!out || cap <= 0)
        return 0;
    int n = 0;
    pthread_mutex_lock(&g_lock);
    int depth = atomic_load(&g_window_depth);
    if (depth > 0 && depth <= cap && atomic_load(&g_captured) &&
        atomic_load(&g_window_have) == depth) {
        memcpy(out, g_window, (size_t)depth * sizeof(out[0]));
        if (out_top_height)
            *out_top_height = g_window_top_height;
        n = depth;
        atomic_store(&g_captured, false);
        atomic_store(&g_armed, false);
        atomic_store(&g_window_depth, 0);
        atomic_store(&g_window_have, 0);
    }
    pthread_mutex_unlock(&g_lock);
    return n;
}

/* True when this peer was already asked for the current window target and a
 * different peer should get the retry; otherwise records it. A full list, or
 * three silent intervals, starts over so no peer is shut out for good. */
static bool chf_window_already_asked(int64_t peer_id, bool stale)
{
    bool asked = false;
    pthread_mutex_lock(&g_lock);
    if (stale)
        g_asked_n = 0;
    for (int i = 0; i < g_asked_n; i++)
        asked = asked || g_asked[i] == peer_id;
    if (!asked) {
        if (g_asked_n >= CHF_ASKED_MAX)
            g_asked_n = 0;
        g_asked[g_asked_n++] = peer_id;
    }
    pthread_mutex_unlock(&g_lock);
    return asked;
}

void checkpoint_header_fetch_offer(const struct block_header *hdr,
                                   const struct uint256 *hash)
{
    /* Fast path: one relaxed load when disarmed (every received header hits
     * this). */
    if (!atomic_load_explicit(&g_armed, memory_order_relaxed))
        return; // raw-return-ok:not-armed-hot-path
    if (!hdr || !hash)
        return; // raw-return-ok:null-args
    if (atomic_load(&g_captured))
        return; // raw-return-ok:already-captured

    if (atomic_load(&g_window_depth) > 0) {
        chf_window_offer(hdr, hash);
        return;
    }

    bool match = false;
    pthread_mutex_lock(&g_lock);
    if (atomic_load(&g_armed) && !atomic_load(&g_captured) &&
        memcmp(hash->data, g_target_hash, 32) == 0) {
        /* HASH-PIN ONLY. The block hash commits to nSolution, so a matching
         * hash IS the checkpoint header with its real solution. The app-layer
         * condition still re-verifies (hash-pin + frozen Equihash) before it
         * persists — this only copies the wire bytes off the net thread. */
        g_captured_header = *hdr;
        atomic_store(&g_captured, true);
        atomic_fetch_add(&g_captures, 1);
        match = true;
    }
    pthread_mutex_unlock(&g_lock);

    if (match)
        LOG_INFO(CHF_SUBSYS,
                 "captured checkpoint header h=%d hash-pinned from a peer's "
                 "headers message — app will frozen-verify + persist its "
                 "Equihash solution",
                 atomic_load(&g_target_height));
}

/* Window-mode send: the walk knows the target hash but none of its ancestors,
 * so it asks with an empty locator and hash_stop = target. One peer per
 * interval, preferring a peer not yet asked for this target. */
static void chf_window_send(struct msg_processor *mp, struct p2p_node *node,
                            const struct uint256 *target_hash, int32_t height,
                            int64_t now_us, int64_t last)
{
    bool stale = last != 0 && now_us - last >= 3 * CHF_SEND_INTERVAL_US;
    if (chf_window_already_asked((int64_t)node->id, stale))
        return; // raw-return-ok:retry-goes-to-another-peer
    if (!atomic_compare_exchange_strong(&g_last_send_us, &last, now_us))
        return; // raw-return-ok:another-peer-claimed-this-interval
    push_getheaders_by_hash(mp, node, target_hash);
    atomic_fetch_add(&g_sends, 1);
    LOG_INFO(CHF_SUBSYS,
             "requested window header h=%d from %s (empty locator, "
             "hash_stop=target)", height, node->addr_name);
}

/* The hash of the index row `n` below `top` on top's own chain. A hint for the
 * peer only: a wrong row costs one useless reply, never an acceptance (the
 * capture stays a hash-pin from the armed top). */
static bool chf_index_row_below(const struct main_state *ms,
                                const struct uint256 *top, int32_t top_h,
                                int n, struct uint256 *out)
{
    const struct block_index *bi = block_map_find(&ms->map_block_index, top);
    for (int i = 0; bi && i < n; i++)
        bi = bi->pprev;
    if (!bi || !bi->phashBlock || bi->nHeight != top_h - n)
        return false;
    *out = *bi->phashBlock;
    return true;
}

/* Window span: ask for the whole remaining window with ONE bounded getheaders
 * (locator = the index row below it, hash_stop = the current target), at most
 * once per armed window. Not while outgoing header sync is held or a snapshot
 * is active (push_getheaders_span would drop it): the walk goes instead. True
 * when this tick belongs to the span (sent, or another peer took the slot). */
static bool chf_window_try_span(struct msg_processor *mp, struct p2p_node *node,
                                const struct uint256 *target_hash,
                                int32_t height, int remaining, int64_t now_us,
                                int64_t last)
{
    pthread_mutex_lock(&g_lock);
    bool tried = g_window_span_tried;
    pthread_mutex_unlock(&g_lock);
    if (tried || remaining < 1 || msg_processor_header_sync_held() ||
        msg_processor_snapshot_active(mp))
        return false;
    struct uint256 row;
    if (!chf_index_row_below(mp->main_state, target_hash, height, remaining,
                             &row))
        return false; // raw-return-ok:no-index-row-walk-instead
    if (!atomic_compare_exchange_strong(&g_last_send_us, &last, now_us))
        return true; // raw-return-ok:another-peer-claimed-this-interval
    pthread_mutex_lock(&g_lock);
    g_window_span_tried = true;
    pthread_mutex_unlock(&g_lock);
    push_getheaders_span(mp, node, &row, target_hash);
    atomic_fetch_add(&g_sends, 1);
    LOG_INFO(CHF_SUBSYS,
             "requested header window h=%d..%d from %s via one bounded "
             "getheaders span (locator=index row h=%d, hash_stop=target)",
             height - remaining + 1, height, node->addr_name,
             height - remaining);
    return true;
}

/* Window-mode send tick: the span when it applies, else one walk step. */
static void chf_window_tick(struct msg_processor *mp, struct p2p_node *node,
                            const struct uint256 *target_hash, int32_t height,
                            int remaining, int64_t now_us, int64_t last)
{
    if (!chf_window_try_span(mp, node, target_hash, height, remaining, now_us,
                             last))
        chf_window_send(mp, node, target_hash, height, now_us, last);
}

/* A peer usable as a checkpoint-header source: outbound, handshaked, not
 * tearing down, and tall enough to hold the checkpoint block. */
static bool chf_peer_usable(const struct p2p_node *node, int32_t height)
{
    if (node->inbound || atomic_load(&node->disconnect))
        return false;
    enum peer_state st = atomic_load(&node->state);
    if (st != PEER_HANDSHAKE_COMPLETE && st != PEER_ACTIVE &&
        st != PEER_SYNCING_HEADERS && st != PEER_SYNCING_BLOCKS)
        return false;
    return node->starting_height >= height;
}

void checkpoint_header_fetch_maybe_send(struct msg_processor *mp,
                                        struct p2p_node *node,
                                        int64_t now_seconds)
{
    if (!atomic_load_explicit(&g_armed, memory_order_relaxed))
        return; // raw-return-ok:not-armed
    if (atomic_load(&g_captured))
        return; // raw-return-ok:already-captured-condition-consumes
    if (!mp || !node || !mp->main_state)
        return; // raw-return-ok:runtime-not-wired

    int32_t height = atomic_load(&g_target_height);
    if (height < 0 || !chf_peer_usable(node, height))
        return; // raw-return-ok:peer-not-a-usable-source

    /* Global throttle: claim the send slot before doing any work. */
    int64_t now_us = now_seconds * 1000000;
    int64_t last = atomic_load(&g_last_send_us);
    if (last != 0 && now_us - last < CHF_SEND_INTERVAL_US)
        return; // raw-return-ok:throttled

    /* Resolve the checkpoint header's parent hash from the imported block map:
     * the span locator must FORK at the parent so the peer returns exactly the
     * checkpoint header (hash_stop bounds it to that one). */
    struct uint256 target_hash;
    int remaining;
    pthread_mutex_lock(&g_lock);
    memcpy(target_hash.data, g_target_hash, 32);
    height = atomic_load(&g_target_height); /* one snapshot with hash/remaining */
    remaining = atomic_load(&g_window_depth) - atomic_load(&g_window_have);
    pthread_mutex_unlock(&g_lock);

    if (atomic_load(&g_window_depth) > 0) {
        chf_window_tick(mp, node, &target_hash, height, remaining, now_us,
                        last);
        return;
    }

    struct block_index *bi =
        block_map_find(&mp->main_state->map_block_index, &target_hash);
    if (!bi || !bi->pprev || !bi->pprev->phashBlock)
        return; // raw-return-ok:checkpoint-header-or-parent-not-imported-yet
    struct uint256 parent_hash = *bi->pprev->phashBlock;

    /* Only ONE peer per interval issues the request. */
    if (!atomic_compare_exchange_strong(&g_last_send_us, &last, now_us))
        return; // raw-return-ok:another-peer-claimed-this-interval

    push_getheaders_span(mp, node, &parent_hash, &target_hash);
    atomic_fetch_add(&g_sends, 1);
    LOG_INFO(CHF_SUBSYS,
             "requested checkpoint header h=%d from %s via bounded getheaders "
             "span (fork at parent, hash_stop=checkpoint)",
             height, node->addr_name);
}

#ifdef ZCL_TESTING
void checkpoint_header_fetch_test_reset(void)
{
    checkpoint_header_fetch_disarm();
    pthread_mutex_lock(&g_lock);
    g_asked_n = 0;
    g_window_span_tried = false;
    chf_ring_clear_locked();
    pthread_mutex_unlock(&g_lock);
    atomic_store(&g_last_send_us, 0);
    atomic_store(&g_sends, 0);
    atomic_store(&g_captures, 0);
}

void checkpoint_header_fetch_test_span_state(bool *tried, int *ring_held)
{
    int n = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < CHECKPOINT_HEADER_FETCH_WINDOW_MAX; i++)
        n += g_ring_used[i] ? 1 : 0;
    if (tried)
        *tried = g_window_span_tried;
    pthread_mutex_unlock(&g_lock);
    if (ring_held)
        *ring_held = n;
}
#endif
