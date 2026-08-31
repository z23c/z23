/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "services/operator_peer_snapshot_service.h"

#include "net/protocol.h"
#include "net/version.h"
#include "platform/time_compat.h"

#include <limits.h>
#include <stdatomic.h>

static _Atomic int g_agent_peer_cache_valid;
/* Even = stable, odd = writer active.  The peer cache used to publish each
 * field through an unrelated atomic, allowing readers to combine two samples
 * into a peer snapshot that never existed.  One short seqlock makes the
 * fallback cache a coherent record without blocking the first-call path. */
static _Atomic uint64_t g_agent_peer_cache_seq;
static _Atomic int g_agent_peer_cache_total;
static _Atomic int g_agent_peer_cache_inbound;
static _Atomic int g_agent_peer_cache_outbound;
static _Atomic int g_agent_peer_cache_ready;
static _Atomic int g_agent_peer_cache_best_height;
static _Atomic int g_agent_peer_cache_magicbean;
static _Atomic int g_agent_peer_cache_zclassic23;
static _Atomic int64_t g_agent_peer_cache_sampled_at;
static _Atomic bool g_agent_peer_cache_direction_known;
static _Atomic bool g_agent_peer_cache_ready_known;
static _Atomic bool g_agent_peer_cache_best_height_known;

static uint64_t agent_peer_store_cache(int peer_count,
                                   int inbound_count,
                                   int outbound_count,
                                   int ready_count,
                                   int peer_best_height,
                                   int magicbean_peer_count,
                                   int zclassic23_peer_count,
                                   bool direction_known,
                                   bool ready_known,
                                   bool peer_best_height_known,
                                   int64_t sampled_at)
{
    uint64_t seq;
    for (;;) {
        seq = atomic_load_explicit(&g_agent_peer_cache_seq,
                                   memory_order_acquire);
        if ((seq & 1U) != 0)
            continue;
        if (atomic_compare_exchange_weak_explicit(
                &g_agent_peer_cache_seq, &seq, seq + 1,
                memory_order_acq_rel, memory_order_acquire))
            break;
    }
    atomic_store_explicit(&g_agent_peer_cache_total, peer_count,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_inbound, inbound_count,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_outbound, outbound_count,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_ready, ready_count,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_best_height, peer_best_height,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_magicbean,
                          magicbean_peer_count, memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_zclassic23,
                          zclassic23_peer_count, memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_direction_known,
                          direction_known, memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_ready_known, ready_known,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_best_height_known,
                          peer_best_height_known, memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_sampled_at, sampled_at,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_valid, 1,
                          memory_order_relaxed);
    atomic_store_explicit(&g_agent_peer_cache_seq, seq + 2,
                          memory_order_release);
    return (seq + 2) / 2;
}

static bool agent_peer_load_cache(int *peer_count,
                                  int *inbound_count,
                                  int *outbound_count,
                                  int *ready_count,
                                  int *peer_best_height,
                                  int *magicbean_peer_count,
                                  int *zclassic23_peer_count,
                                  bool *direction_known,
                                  bool *ready_known,
                                  bool *peer_best_height_known,
                                  uint64_t *generation,
                                  int64_t *sampled_at)
{
    for (int attempt = 0; attempt < 8; attempt++) {
        uint64_t before = atomic_load_explicit(&g_agent_peer_cache_seq,
                                               memory_order_acquire);
        if ((before & 1U) != 0)
            continue;
        bool valid = atomic_load_explicit(&g_agent_peer_cache_valid,
                                          memory_order_relaxed) != 0;
        *peer_count = atomic_load_explicit(&g_agent_peer_cache_total,
                                           memory_order_relaxed);
        *inbound_count = atomic_load_explicit(&g_agent_peer_cache_inbound,
                                              memory_order_relaxed);
        *outbound_count = atomic_load_explicit(&g_agent_peer_cache_outbound,
                                               memory_order_relaxed);
        *ready_count = atomic_load_explicit(&g_agent_peer_cache_ready,
                                            memory_order_relaxed);
        *peer_best_height = atomic_load_explicit(
            &g_agent_peer_cache_best_height, memory_order_relaxed);
        *magicbean_peer_count = atomic_load_explicit(
            &g_agent_peer_cache_magicbean, memory_order_relaxed);
        *zclassic23_peer_count = atomic_load_explicit(
            &g_agent_peer_cache_zclassic23, memory_order_relaxed);
        *direction_known = atomic_load_explicit(
            &g_agent_peer_cache_direction_known, memory_order_relaxed);
        *ready_known = atomic_load_explicit(
            &g_agent_peer_cache_ready_known, memory_order_relaxed);
        *peer_best_height_known = atomic_load_explicit(
            &g_agent_peer_cache_best_height_known, memory_order_relaxed);
        *sampled_at = atomic_load_explicit(&g_agent_peer_cache_sampled_at,
                                           memory_order_relaxed);
        /* The leading acquire keeps these payload loads after the first
         * sequence sample.  ARM also needs a trailing read barrier so none of
         * them can move after the validation sample and make a torn record
         * appear stable. */
        atomic_thread_fence(memory_order_acquire);
        uint64_t after = atomic_load_explicit(&g_agent_peer_cache_seq,
                                              memory_order_acquire);
        if (valid && before == after && (after & 1U) == 0) {
            *generation = after / 2;
            return true;
        }
    }
    return false; // raw-return-ok:cache-miss-or-concurrent-writer
}

void agent_peer_snapshot_collect(struct agent_peer_snapshot *out,
                                 struct connman *cm)
{
    struct agent_peer_snapshot empty = {
        .peer_best_height = -1,
        .age_seconds = -1,
    };
    if (!out)
        return;
    *out = empty;
    if (!cm)
        return;

    int peer_count = 0;
    int inbound_count = 0;
    int outbound_count = 0;
    int ready_count = 0;
    int peer_best_height = -1;
    int magicbean_peer_count = 0;
    int zclassic23_peer_count = 0;
    bool direction_known = true;
    bool ready_known = true;
    bool peer_best_height_known = false;
    uint64_t generation = 0;
    int64_t sampled_at = 0;

    if (zcl_mutex_trylock(&cm->manager.cs_nodes)) {
        for (size_t i = 0; i < cm->manager.num_nodes; i++) {
            struct p2p_node *node = cm->manager.nodes[i];
            if (!node) {
                direction_known = false;
                ready_known = false;
                continue;
            }
            enum peer_state state = atomic_load_explicit(
                &node->state, memory_order_acquire);
            if (atomic_load_explicit(&node->disconnect,
                                     memory_order_acquire))
                continue;
            if (peer_count < INT_MAX)
                peer_count++;
            if (node->inbound)
                inbound_count++;
            else
                outbound_count++;
            bool handshake_ready = state == PEER_HANDSHAKE_COMPLETE ||
                                   state == PEER_ACTIVE;
            if (handshake_ready && (node->services & NODE_NETWORK) != 0)
                ready_count++;
            else if (state < 0 || state >= PEER_NUM_STATES)
                ready_known = false;
            if (state < PEER_HANDSHAKE_COMPLETE)
                continue;
            if ((node->services & NODE_NETWORK) != 0 &&
                node->starting_height >= 0) {
                if (!peer_best_height_known ||
                    node->starting_height > peer_best_height)
                    peer_best_height = node->starting_height;
                peer_best_height_known = true;
            }
            bool is_mb = false, is_z23 = false;
            msg_version_classify_peer(node->sub_ver, node->services,
                                      &is_mb, &is_z23);
            if (is_mb)
                magicbean_peer_count++;
            if (is_z23)
                zclassic23_peer_count++;
        }
        zcl_mutex_unlock(&cm->manager.cs_nodes);
        sampled_at = (int64_t)platform_time_wall_time_t();
        direction_known = direction_known &&
            inbound_count + outbound_count == peer_count;
        generation = agent_peer_store_cache(
            peer_count, inbound_count, outbound_count, ready_count,
            peer_best_height, magicbean_peer_count, zclassic23_peer_count,
            direction_known, ready_known, peer_best_height_known, sampled_at);
        out->available = true;
        out->stale = false;
        out->age_seconds = 0;
    } else if (agent_peer_load_cache(&peer_count, &inbound_count,
                                     &outbound_count, &ready_count,
                                     &peer_best_height,
                                     &magicbean_peer_count,
                                     &zclassic23_peer_count,
                                     &direction_known, &ready_known,
                                     &peer_best_height_known,
                                     &generation,
                                     &sampled_at)) {
        int64_t now = (int64_t)platform_time_wall_time_t();
        out->available = true;
        out->stale = true;
        out->age_seconds = now >= sampled_at ? now - sampled_at : -1;
        out->warning_reason = "peer_snapshot_busy";
    } else {
        out->available = false;
        out->stale = true;
        out->age_seconds = -1;
        out->warning_reason = "peer_snapshot_unavailable";
        return;
    }

    out->peer_count = peer_count > 0 ? (size_t)peer_count : 0;
    out->inbound_count = inbound_count > 0 ? (size_t)inbound_count : 0;
    out->outbound_count = outbound_count > 0 ? (size_t)outbound_count : 0;
    out->ready_count = ready_count > 0 ? (size_t)ready_count : 0;
    out->peer_best_height = peer_best_height;
    out->generation = generation;
    out->direction_known = direction_known;
    out->ready_known = ready_known;
    out->peer_best_height_known = peer_best_height_known;
    out->magicbean_peer_count =
        magicbean_peer_count > 0 ? (size_t)magicbean_peer_count : 0;
    out->zclassic_c23_peer_count =
        zclassic23_peer_count > 0 ? (size_t)zclassic23_peer_count : 0;
}
