/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * See net/header_serve_repair.h. */

#include "net/header_serve_repair.h"

#include "net/msg_internal.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "net/net.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#define HSR_SUBSYS "headers"
#define HSR_BATCH_HEADERS 64u
#define HSR_SEND_INTERVAL_US (5 * 1000000)

static pthread_mutex_t g_hsr_lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool g_hsr_armed;
static _Atomic int64_t g_hsr_last_send_us;
static int32_t g_hsr_target_height;
static struct uint256 g_hsr_target_hash;
static struct uint256 g_hsr_expected[HSR_BATCH_HEADERS];
static bool g_hsr_cached[HSR_BATCH_HEADERS];
static size_t g_hsr_expected_count;
static bool g_hsr_span_published;

void header_serve_repair_arm(struct main_state *ms,
                             const struct block_index *target)
{
    if (!ms || !target || target->nHeight <= 0 || !target->phashBlock)
        return; // raw-return-ok:invalid-serve-repair-target
    if (atomic_load_explicit(&g_hsr_armed, memory_order_relaxed))
        return; // raw-return-ok:single-bounded-repair-already-armed

    /* A remote locator may reach a stale branch, but it must not pin the one
     * global repair flight on arbitrary map entries. Only the active chain or
     * the selected best-header path is a local request authority. */
    bool authoritative = false;
    zcl_mutex_lock(&ms->cs_main);
    struct block_index *active =
        active_chain_at(&ms->chain_active, target->nHeight);
    if (active && active->phashBlock &&
        uint256_eq(active->phashBlock, target->phashBlock)) {
        authoritative = true;
    } else if (ms->pindex_best_header &&
               ms->pindex_best_header->nHeight >= target->nHeight) {
        struct block_index *best = block_index_get_ancestor(
            ms->pindex_best_header, target->nHeight);
        authoritative = best && best->phashBlock &&
            uint256_eq(best->phashBlock, target->phashBlock);
    }
    zcl_mutex_unlock(&ms->cs_main);
    if (!authoritative)
        return; // raw-return-ok:off-authority-serve-request

    int32_t height = target->nHeight;
    struct uint256 hash = *target->phashBlock;

    bool armed = false;
    pthread_mutex_lock(&g_hsr_lock);
    if (!atomic_load_explicit(&g_hsr_armed, memory_order_relaxed)) {
        g_hsr_target_height = height;
        g_hsr_target_hash = hash;
        g_hsr_expected[0] = hash;
        g_hsr_cached[0] = false;
        g_hsr_expected_count = 1;
        g_hsr_span_published = false;
        atomic_store_explicit(&g_hsr_last_send_us, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&g_hsr_armed, true, memory_order_release);
        armed = true;
    }
    pthread_mutex_unlock(&g_hsr_lock);

    if (armed)
        LOG_INFO(HSR_SUBSYS,
                 "getheaders: armed bounded header-only repair h=%d",
                 height);
}

bool header_serve_repair_wants(const struct block_index *bi)
{
    if (!bi || !bi->phashBlock ||
        !atomic_load_explicit(&g_hsr_armed, memory_order_acquire))
        return false;

    bool wanted = false;
    pthread_mutex_lock(&g_hsr_lock);
    if (atomic_load_explicit(&g_hsr_armed, memory_order_relaxed)) {
        for (size_t i = 0; i < g_hsr_expected_count; i++) {
            if (uint256_eq(bi->phashBlock, &g_hsr_expected[i])) {
                wanted = true;
                break;
            }
        }
    }
    pthread_mutex_unlock(&g_hsr_lock);
    return wanted;
}

void header_serve_repair_note_cached(const struct block_index *bi)
{
    if (!bi || !bi->phashBlock ||
        !atomic_load_explicit(&g_hsr_armed, memory_order_acquire))
        return; // raw-return-ok:not-an-armed-repair-candidate

    bool completed = false;
    int32_t target_height = -1;
    size_t completed_count = 0;
    pthread_mutex_lock(&g_hsr_lock);
    if (atomic_load_explicit(&g_hsr_armed, memory_order_relaxed)) {
        for (size_t i = 0; i < g_hsr_expected_count; i++) {
            if (uint256_eq(bi->phashBlock, &g_hsr_expected[i])) {
                g_hsr_cached[i] = true;
                break;
            }
        }
        completed = g_hsr_expected_count > 0;
        for (size_t i = 0; i < g_hsr_expected_count; i++)
            completed = completed && g_hsr_cached[i];
        if (completed) {
            target_height = g_hsr_target_height;
            completed_count = g_hsr_expected_count;
            g_hsr_span_published = false;
            atomic_store_explicit(&g_hsr_armed, false,
                                  memory_order_release);
        }
    }
    pthread_mutex_unlock(&g_hsr_lock);

    if (completed)
        LOG_INFO(HSR_SUBSYS,
                 "getheaders: header-only repair completed h=%d count=%zu",
                 target_height, completed_count);
}

static bool hsr_peer_usable(const struct p2p_node *node, int32_t height)
{
    if (!node || node->inbound || atomic_load(&node->disconnect))
        return false;
    enum peer_state state = atomic_load(&node->state);
    if (state != PEER_HANDSHAKE_COMPLETE && state != PEER_ACTIVE &&
        state != PEER_SYNCING_HEADERS && state != PEER_SYNCING_BLOCKS)
        return false;
    return node->starting_height >= height;
}

void header_serve_repair_maybe_send(struct msg_processor *mp,
                                    struct p2p_node *node,
                                    int64_t now_seconds)
{
    if (!atomic_load_explicit(&g_hsr_armed, memory_order_acquire) ||
        !mp || !mp->main_state)
        return; // raw-return-ok:no-armed-runtime

    struct uint256 target_hash;
    int32_t target_height;
    pthread_mutex_lock(&g_hsr_lock);
    target_hash = g_hsr_target_hash;
    target_height = g_hsr_target_height;
    pthread_mutex_unlock(&g_hsr_lock);
    if (!hsr_peer_usable(node, target_height))
        return; // raw-return-ok:peer-cannot-serve-target

    int64_t now_us = now_seconds * 1000000;
    int64_t last = atomic_load_explicit(&g_hsr_last_send_us,
                                        memory_order_relaxed);
    if (last != 0 && now_us - last < HSR_SEND_INTERVAL_US)
        return; // raw-return-ok:bounded-repair-throttled

    struct block_index *target =
        block_map_find(&mp->main_state->map_block_index, &target_hash);
    if (!target || target->nHeight != target_height || !target->pprev ||
        !target->pprev->phashBlock)
        return; // raw-return-ok:target-authority-changed

    struct uint256 stop_hash;
    size_t count;
    pthread_mutex_lock(&g_hsr_lock);
    if (!atomic_load_explicit(&g_hsr_armed, memory_order_relaxed) ||
        !uint256_eq(&g_hsr_target_hash, &target_hash)) {
        pthread_mutex_unlock(&g_hsr_lock);
        return; // raw-return-ok:target-changed-before-span-build
    }
    if (g_hsr_span_published) {
        count = g_hsr_expected_count;
        stop_hash = g_hsr_expected[count - 1];
        pthread_mutex_unlock(&g_hsr_lock);
    } else {
        pthread_mutex_unlock(&g_hsr_lock);

        struct block_index *span[HSR_BATCH_HEADERS];
        count = 0;
        struct block_index *cursor = target;
        while (cursor && cursor->phashBlock && count < HSR_BATCH_HEADERS &&
               cursor->nHeight <= node->starting_height) {
            span[count++] = cursor;
            cursor = main_state_best_known_successor(mp->main_state, cursor);
        }
        if (count == 0)
            return; // raw-return-ok:no-bounded-span

        /* The first usable peer publishes one immutable exact-hash span.
         * Later peers retry that same span and preserve already verified
         * members instead of resetting partial progress. */
        pthread_mutex_lock(&g_hsr_lock);
        if (!atomic_load_explicit(&g_hsr_armed, memory_order_relaxed) ||
            !uint256_eq(&g_hsr_target_hash, &target_hash)) {
            pthread_mutex_unlock(&g_hsr_lock);
            return; // raw-return-ok:target-changed-during-span-build
        }
        if (!g_hsr_span_published) {
            g_hsr_expected_count = count;
            for (size_t i = 0; i < count; i++) {
                g_hsr_expected[i] = *span[i]->phashBlock;
                g_hsr_cached[i] = false;
            }
            g_hsr_span_published = true;
        }
        count = g_hsr_expected_count;
        stop_hash = g_hsr_expected[count - 1];
        pthread_mutex_unlock(&g_hsr_lock);
    }

    if (!atomic_compare_exchange_strong(&g_hsr_last_send_us, &last, now_us))
        return; // raw-return-ok:another-peer-claimed-repair-send

    struct uint256 parent_hash = *target->pprev->phashBlock;
    push_getheaders_span(mp, node, &parent_hash, &stop_hash);
    LOG_INFO(HSR_SUBSYS,
             "getheaders: requested header-only repair h=%d..%d count=%zu "
             "from %s",
             target_height, target_height + (int32_t)count - 1, count,
             node->addr_name);
}

#ifdef ZCL_TESTING
void header_serve_repair_test_reset(void)
{
    pthread_mutex_lock(&g_hsr_lock);
    atomic_store_explicit(&g_hsr_armed, false, memory_order_release);
    atomic_store_explicit(&g_hsr_last_send_us, 0, memory_order_relaxed);
    g_hsr_target_height = -1;
    uint256_set_null(&g_hsr_target_hash);
    g_hsr_expected_count = 0;
    g_hsr_span_published = false;
    memset(g_hsr_cached, 0, sizeof(g_hsr_cached));
    pthread_mutex_unlock(&g_hsr_lock);
}

bool header_serve_repair_test_armed(void)
{
    return atomic_load_explicit(&g_hsr_armed, memory_order_acquire);
}

size_t header_serve_repair_test_expected_count(void)
{
    pthread_mutex_lock(&g_hsr_lock);
    size_t count = g_hsr_expected_count;
    pthread_mutex_unlock(&g_hsr_lock);
    return count;
}

size_t header_serve_repair_test_cached_count(void)
{
    size_t count = 0;
    pthread_mutex_lock(&g_hsr_lock);
    for (size_t i = 0; i < g_hsr_expected_count; i++)
        count += g_hsr_cached[i] ? 1u : 0u;
    pthread_mutex_unlock(&g_hsr_lock);
    return count;
}
#endif
