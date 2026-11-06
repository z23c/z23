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

/* Window-mode capture: HASH-PIN ONLY, like single mode. A match stores the
 * header and re-targets its hashPrevBlock one height lower; the walk is
 * complete (g_captured) once `depth` headers are held. */
static void chf_window_offer(const struct block_header *hdr,
                             const struct uint256 *hash)
{
    int have = 0;
    int depth = 0;
    int32_t at = -1;
    pthread_mutex_lock(&g_lock);
    depth = atomic_load(&g_window_depth);
    have = atomic_load(&g_window_have);
    if (atomic_load(&g_armed) && !atomic_load(&g_captured) && depth > 0 &&
        have < depth && memcmp(hash->data, g_target_hash, 32) == 0) {
        g_window[have] = *hdr;
        at = atomic_load(&g_target_height);
        have++;
        atomic_store(&g_window_have, have);
        atomic_fetch_add(&g_captures, 1);
        g_asked_n = 0;
        if (have >= depth) {
            atomic_store(&g_captured, true);
        } else {
            memcpy(g_target_hash, hdr->hashPrevBlock.data, 32);
            atomic_store(&g_target_height, at - 1);
            atomic_store(&g_last_send_us, 0); /* next step goes out at once */
        }
    }
    pthread_mutex_unlock(&g_lock);
    if (at >= 0 && have >= depth)
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
    atomic_store(&g_window_have, 0);
    atomic_store(&g_window_depth, depth);
    atomic_store(&g_captured, false);
    atomic_store(&g_target_height, height);
    atomic_store(&g_last_send_us, 0);
    atomic_store(&g_armed, true);
    pthread_mutex_unlock(&g_lock);
    LOG_INFO(CHF_SUBSYS,
             "armed header window walk: %d headers down from h=%d by "
             "empty-locator getheaders", depth, height);
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
    pthread_mutex_lock(&g_lock);
    memcpy(target_hash.data, g_target_hash, 32);
    pthread_mutex_unlock(&g_lock);

    if (atomic_load(&g_window_depth) > 0) {
        chf_window_send(mp, node, &target_hash, height, now_us, last);
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
    pthread_mutex_unlock(&g_lock);
    atomic_store(&g_last_send_us, 0);
    atomic_store(&g_sends, 0);
    atomic_store(&g_captures, 0);
}
#endif
