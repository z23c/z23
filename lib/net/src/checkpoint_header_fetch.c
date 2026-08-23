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

void checkpoint_header_fetch_arm(int32_t height, const struct uint256 *hash)
{
    if (!hash || height < 0)
        return; // raw-return-ok:invalid-arm-args
    pthread_mutex_lock(&g_lock);
    memcpy(g_target_hash, hash->data, 32);
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
    return atomic_load_explicit(&g_captured, memory_order_relaxed);
}

bool checkpoint_header_fetch_take(struct block_header *out, int32_t *out_height)
{
    if (!out)
        return false; // raw-return-ok:null-out
    if (!atomic_load(&g_captured))
        return false; // raw-return-ok:nothing-captured
    pthread_mutex_lock(&g_lock);
    bool have = atomic_load(&g_captured);
    if (have) {
        *out = g_captured_header;
        if (out_height)
            *out_height = atomic_load(&g_target_height);
        atomic_store(&g_captured, false); /* consume: one take per capture */
    }
    pthread_mutex_unlock(&g_lock);
    return have;
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
    atomic_store(&g_last_send_us, 0);
    atomic_store(&g_sends, 0);
    atomic_store(&g_captures, 0);
}
#endif
