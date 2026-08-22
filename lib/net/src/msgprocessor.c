/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* P2P message processor — orchestration and dispatch only.
 *
 * The per-message-family bodies live in:
 *   msgprocessor_handshake.c  — version, verack, sendheaders
 *   msgprocessor_inv.c        — inv, getdata, notfound, addr, getaddr
 *   msg_headers.c / msg_blocks.c / msg_compact.c
 *                             — headers/getheaders/getblocks/block + BIP152
 *                               (dispatched directly via process_*)
 *   msgprocessor_pingpong.c   — ping/pong/feefilter/reject
 *   msgprocessor_snapshot.c   — every ZCL23 fast-sync/snapshot message
 *
 * The ZCL Messaging (zmsg), ZCL Market (zfile*) and ZCL Game (zgame)
 * handlers stay here because they are independent application
 * protocols layered on the ZCL23 service bit and share no state with
 * the snapshot/sync engine. They're each <200 lines. */

#include "platform/time_compat.h"
#include "storage/body_history.h"
#include "msgprocessor_internal.h"
#include "net/addrman.h"
#include "net/checkpoint_header_fetch.h"
#include "net/dandelion.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "net/file_manifest.h"
#include "net/file_market.h"
#include "net/rom_seed.h"
#include "net/p2p_game.h"
#include "net/net_fault.h"
#include "net/peer_lifecycle.h"
#include "net/peer_liveness.h"
#include "net/peer_scoring.h"
#include "net/tip_watchdog.h"
#include "net/zmsg.h"
#include "zswap/zswap_ceremony.h"
#include "zswap/zswap_yardsale.h"
#include "primitives/block.h"
#include "sync/sync_planner.h"
/* lib/net still reaches the controller-owned manifest cache for P2P file
 * challenge responses. The manifest protocol types live in net/file_manifest.h;
 * the remaining controller dependency is the cache ownership boundary. */
#include "controllers/file_controller.h"  // lib-layer-ok:file_manifest-cache
#include "util/hw_profile.h"
#include "util/util.h"  /* GetDataDir — net-specific block-body serve dir */
#include "validation/main_state.h"
#include "validation/txmempool.h"
#include "net/net_runtime_port.h"
#include "core/uint256.h"
#include "core/hash.h"
#include "core/random.h"
#include "core/serialize.h"
#include "crypto/sha3.h"
#include "consensus/validation.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"
#include "util/sync.h"
#include "util/thread_liveness.h"
#include "util/thread_registry.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The delivered-then-dark body-stall rule (Rule D, below) enforces the
 * download manager's own stall constant, which was previously
 * defined-but-unenforced. The sync-layer window it evicts on
 * (SYNC_BODY_STALL_TIMEOUT_SECS) MUST equal DL_STALL_TIMEOUT_SECS so the
 * "no body for the download-manager stall window" contract is a single
 * value, not two that can silently drift apart. */
_Static_assert(DL_STALL_TIMEOUT_SECS == SYNC_BODY_STALL_TIMEOUT_SECS,
               "delivered-then-dark eviction window must match the "
               "download-manager stall constant DL_STALL_TIMEOUT_SECS");

/* ── Download manager singleton ─────────────────────────────────── */
static struct download_manager g_download_mgr;
static bool g_download_mgr_init = false;
static pthread_once_t g_download_mgr_once = PTHREAD_ONCE_INIT;

static void msg_download_mgr_init_once(void)
{
    dl_init(&g_download_mgr);
    g_download_mgr_init = true;
}

struct download_manager *msg_get_download_mgr(void)
{
    pthread_once(&g_download_mgr_once, msg_download_mgr_init_once);
    return &g_download_mgr;
}

/* ── Header sync stall tracking (used by msg_send_messages) ───── */
static int g_header_stall_last_height = 0;
static int64_t g_header_stall_last_advance = 0;

/* ── Shared accessors used across split files ─────────────────── */

struct node_db *msg_node_db(const struct msg_processor *mp)
{
    if (!mp || !mp->runtime)
        LOG_NULL("net", "mp or mp->runtime is NULL");
    return net_runtime_node_db(mp->runtime);
}

/* ── Recent-block / recent-tx dedup ring buffers ─────────────── */
/* Used by msg_blocks.c and msg_tx.c via the helpers declared in
 * net/msg_internal.h. Kept here because both families consume them. */

#define MAX_RECENT_BLOCKS 128
#define MAX_RECENT_TXS 4096
static struct uint256 g_recent_blocks[MAX_RECENT_BLOCKS];
static _Atomic int g_recent_block_count = 0;
static struct uint256 g_recent_txs[MAX_RECENT_TXS];
static _Atomic int g_recent_tx_count = 0;

bool block_already_seen(const struct uint256 *hash) {
    int limit = g_recent_block_count < MAX_RECENT_BLOCKS
                ? g_recent_block_count : MAX_RECENT_BLOCKS;
    for (int i = 0; i < limit; i++) {
        if (uint256_eq(hash, &g_recent_blocks[i])) return true;
    }
    return false;
}

void block_mark_seen(const struct uint256 *hash) {
    g_recent_blocks[g_recent_block_count % MAX_RECENT_BLOCKS] = *hash;
    g_recent_block_count++;
}

void block_clear_seen(const struct uint256 *hash) {
    int limit = g_recent_block_count < MAX_RECENT_BLOCKS
                ? g_recent_block_count : MAX_RECENT_BLOCKS;
    for (int i = 0; i < limit; i++) {
        if (uint256_eq(hash, &g_recent_blocks[i])) {
            memset(&g_recent_blocks[i], 0, sizeof(struct uint256));
            return;
        }
    }
}

void msg_processor_clear_seen_block(const struct uint256 *hash)
{
    if (!hash)
        return;
    block_clear_seen(hash);
}

bool tx_already_seen(const struct uint256 *hash) {
    int limit = g_recent_tx_count < MAX_RECENT_TXS
                ? g_recent_tx_count : MAX_RECENT_TXS;
    for (int i = 0; i < limit; i++) {
        if (uint256_eq(hash, &g_recent_txs[i])) return true;
    }
    return false;
}

void tx_mark_seen(const struct uint256 *hash) {
    g_recent_txs[g_recent_tx_count % MAX_RECENT_TXS] = *hash;
    g_recent_tx_count++;
}

/* Expose internals for unit testing via weak-linked test helpers. */
bool msgprocessor_test_block_already_seen(const struct uint256 *hash) {
    return block_already_seen(hash);
}
void msgprocessor_test_block_mark_seen(const struct uint256 *hash) {
    block_mark_seen(hash);
}
bool msgprocessor_test_accept_block_for_processing(const struct uint256 *hash,
                                                   bool snapshot_active) {
    if (!hash)
        LOG_FAIL("net", "hash is NULL in accept_block_for_processing");
    if (snapshot_active)
        LOG_FAIL("net", "block rejected: snapshot sync is active");
    if (block_already_seen(hash))
        LOG_FAIL("net", "block rejected: already seen");
    block_mark_seen(hash);
    return true;
}
void msgprocessor_test_reset_recent_blocks(void) {
    g_recent_block_count = 0;
    memset(g_recent_blocks, 0, sizeof(g_recent_blocks));
}
int msgprocessor_test_get_recent_block_count(void) {
    return g_recent_block_count;
}
bool msgprocessor_test_tx_already_seen(const struct uint256 *hash) {
    return tx_already_seen(hash);
}
void msgprocessor_test_tx_mark_seen(const struct uint256 *hash) {
    tx_mark_seen(hash);
}

/* ── Catch-up block intake worker ────────────────────────────────
 *
 * During IBD/catch-up, reducer_ingest_block can block for seconds inside
 * header validation and SQLite-backed stage drains. Calling it inline from
 * process_block_msg stalls the P2P message cycle, which in turn stops getdata
 * dispatch and looks like a peer/download wedge. At the live tip we still use
 * the synchronous path so peer scoring, relay, and tip transition semantics
 * remain unchanged; only historical catch-up block bodies are deep-cloned into
 * this bounded worker queue. */
#define MSG_BLOCK_INTAKE_CAP 128
#define MSG_BLOCK_INTAKE_DRAIN_BATCH 128
#define MSG_BLOCK_INTAKE_LOG_KEEPALIVE_SECS 15
#define MSG_BLOCK_INTAKE_DROP_BLOCKER_ID "net.block_intake_body_dropped"

struct msg_block_intake_item {
    struct block block;
    struct uint256 hash;
    uint32_t peer_id;
    int64_t enqueued_unix;
};

struct msg_block_intake {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    pthread_t thread;
    bool thread_started;
    bool running;
    bool stopping;
    size_t head;
    size_t tail;
    size_t depth;
    struct msg_block_intake_item queue[MSG_BLOCK_INTAKE_CAP];
    struct msg_processor *mp;
    _Atomic uint64_t enqueued;
    _Atomic uint64_t dropped;
    _Atomic uint64_t processed;
    _Atomic uint64_t accepted;
    _Atomic uint64_t rejected;
    _Atomic uint64_t retryable;
    _Atomic uint64_t clone_failed;
    _Atomic uint64_t spawn_failed;
    _Atomic uint64_t max_depth;
    _Atomic int64_t last_enqueue_unix;
    _Atomic int64_t last_process_unix;
};

static pthread_mutex_t g_block_intake_create_lock = PTHREAD_MUTEX_INITIALIZER;
static struct log_throttle g_block_intake_worker_log = LOG_THROTTLE_INIT;
static struct log_throttle g_block_intake_dispatch_log = LOG_THROTTLE_INIT;
static struct log_throttle g_block_intake_drop_blocker_log = LOG_THROTTLE_INIT;

/* Supervisor liveness (root child — lib/net cannot include the app-side
 * supervisors/domains.h, see util/thread_liveness.h). Liveness-only: the
 * ingest loop condvar-waits with no messages queued, so it idles
 * indefinitely and legitimately; no deadline, no progress-quiet gate. */
static struct thread_liveness_child g_p2p_ingest_liveness = { .id = SUPERVISOR_INVALID_ID };
static _Atomic uint64_t g_p2p_ingest_beat_count = 0;

static void msg_block_intake_item_init(struct msg_block_intake_item *item)
{
    if (!item)
        return;
    block_init(&item->block);
    memset(&item->hash, 0, sizeof(item->hash));
    item->peer_id = 0;
    item->enqueued_unix = 0;
}

static void msg_block_intake_item_free(struct msg_block_intake_item *item)
{
    if (!item)
        return;
    block_free(&item->block);
    msg_block_intake_item_init(item);
}

/* Name the destroyed-body loss as a typed blocker. Throttled to one write per
 * MSG_BLOCK_INTAKE_LOG_KEEPALIVE_SECS so the hot drop path stays cheap; the
 * cumulative count travels in the reason so a reader sees the real volume,
 * not just "it happened". TRANSIENT: the caller re-queues the hash at priority
 * (msg_blocks.c::msg_block_requeue_after_intake_backpressure), so it clears
 * once intake drains. */
static void msg_block_intake_name_drop_blocker(uint64_t dropped_total)
{
    uint64_t suppressed = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (!log_throttle_should_emit(&g_block_intake_drop_blocker_log, 1, now,
                                  MSG_BLOCK_INTAKE_LOG_KEEPALIVE_SECS,
                                  &suppressed))
        return;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "block bodies received and DESTROYED because the %d-slot P2P "
             "intake ring was full: dropped=%llu cumulative. Every drop is a "
             "body paid for on the wire and thrown away, then re-downloaded. "
             "The reducer is not draining bodies as fast as peers deliver "
             "them; if the successor of the tip is among the dropped, the "
             "chain cannot advance at all.",
             MSG_BLOCK_INTAKE_CAP, (unsigned long long)dropped_total);
    struct blocker_record rec;
    if (blocker_init(&rec, MSG_BLOCK_INTAKE_DROP_BLOCKER_ID, "net.block_intake",
                     BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&rec);
}

static void msg_block_intake_stats_bump_max(struct msg_block_intake *in,
                                            uint64_t depth)
{
    uint64_t prev = atomic_load_explicit(&in->max_depth,
                                         memory_order_relaxed);
    while (depth > prev &&
           !atomic_compare_exchange_weak_explicit(&in->max_depth, &prev,
                                                  depth,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed)) {
        /* retry with the observed value */
    }
}

static void msg_block_intake_handle_accept(struct msg_processor *mp,
                                           const struct uint256 *hash,
                                           uint32_t peer_id)
{
    if (!mp || !mp->main_state || !hash)
        return;

    struct block_index *landed = block_map_find(
        &mp->main_state->map_block_index, hash);
    if (msg_blocks_should_mark_seen(&mp->main_state->chain_active, landed))
        block_mark_seen(hash);

    struct block_index *new_tip = active_chain_tip(
        &mp->main_state->chain_active);
    if (new_tip) {
        event_emitf(EV_BLOCK_CONNECTED, peer_id,
                    "h=%d async_p2p", new_tip->nHeight);
        msg_processor_note_block_connected(mp, new_tip->nHeight);
    }
}

static void msg_block_intake_process_one(struct msg_block_intake *in,
                                         struct msg_block_intake_item *item)
{
    if (!in || !item)
        return;

    struct msg_processor *mp = in->mp;
    struct validation_state state;
    validation_state_init(&state);

    if (!mp || !mp->block_submit) {
        validation_state_error(&state, "p2p-block-submit-unavailable");
    } else {
        (void)mp->block_submit(&item->block, &state, mp->block_submit_ctx);
    }

    atomic_fetch_add_explicit(&in->processed, 1, memory_order_relaxed);
    atomic_store_explicit(&in->last_process_unix,
                          (int64_t)platform_time_wall_time_t(),
                          memory_order_relaxed);

    if (validation_state_is_valid(&state)) {
        atomic_fetch_add_explicit(&in->accepted, 1, memory_order_relaxed);
        msg_block_intake_handle_accept(mp, &item->hash, item->peer_id);
    } else if (msg_block_validation_is_retryable(&state)) {
        char hex[65];
        uint256_get_hex(&item->hash, hex);
        atomic_fetch_add_explicit(&in->retryable, 1, memory_order_relaxed);
        uint64_t suppressed = 0;
        int64_t now = (int64_t)platform_time_wall_time_t();
        if (log_throttle_should_emit(&g_block_intake_worker_log, 1, now,
                                     MSG_BLOCK_INTAKE_LOG_KEEPALIVE_SECS,
                                     &suppressed)) {
            const char *detail = state.debug_message[0]
                ? state.debug_message
                : state.reject_reason;
            LOG_INFO("net",
                     "async block intake pending reducer finalization "
                     "(latest=%s detail=%s suppressed=%llu)",
                     hex, detail[0] ? detail : "retryable",
                     (unsigned long long)suppressed);
        }
    } else {
        char hex[65];
        uint256_get_hex(&item->hash, hex);
        atomic_fetch_add_explicit(&in->rejected, 1, memory_order_relaxed);
        block_mark_seen(&item->hash);
        event_emitf(EV_BLOCK_REJECTED, item->peer_id,
                    "hash=%s async_reason=%s", hex,
                    state.reject_reason[0] ? state.reject_reason : "unknown");
    }
}

static void msg_block_intake_maybe_drain_catchup(
    struct msg_block_intake *in,
    unsigned *processed_since_drain)
{
    if (!in || !processed_since_drain)
        return;

    struct msg_processor *mp = in->mp;
    if (!mp || !mp->catchup_drain)
        return;

    /* An item can enter this worker in BLOCKS_DOWNLOAD and finish after a
     * periodic evaluator commits AT_TIP. It may already have staged reducer
     * work, so the final catch-up drain remains mandatory across that edge.
     * Skipping solely because the label changed can strand the last body. */

    pthread_mutex_lock(&in->mu);
    size_t queued = in->depth;
    pthread_mutex_unlock(&in->mu);

    if (*processed_since_drain < MSG_BLOCK_INTAKE_DRAIN_BATCH && queued > 0)
        return;

    *processed_since_drain = 0;
    (void)mp->catchup_drain(mp->catchup_drain_ctx);
}

static void msg_block_intake_drain_locked(struct msg_block_intake *in)
{
    while (in && in->depth > 0) {
        msg_block_intake_item_free(&in->queue[in->head]);
        in->head = (in->head + 1) % MSG_BLOCK_INTAKE_CAP;
        in->depth--;
    }
    if (in) {
        in->head = 0;
        in->tail = 0;
    }
}

static void *msg_block_intake_worker(void *arg)
{
    struct msg_block_intake *in = arg;
    unsigned processed_since_drain = 0;
    bool batch_scope_open = false;
    if (!in)
        return NULL;

    for (;;) {
        struct msg_block_intake_item item;
        msg_block_intake_item_init(&item);

        pthread_mutex_lock(&in->mu);
        while (in->depth == 0 && !in->stopping &&
               !thread_registry_shutdown_requested()) {
            pthread_cond_wait(&in->cv, &in->mu);
        }
        if (in->stopping || thread_registry_shutdown_requested()) {
            in->running = false;
            pthread_mutex_unlock(&in->mu);
            if (batch_scope_open && in->mp && in->mp->catchup_batch_end)
                in->mp->catchup_batch_end(in->mp->catchup_batch_scope_ctx);
            break;
        }

        item = in->queue[in->head];
        msg_block_intake_item_init(&in->queue[in->head]);
        in->head = (in->head + 1) % MSG_BLOCK_INTAKE_CAP;
        in->depth--;
        pthread_mutex_unlock(&in->mu);

        if (!batch_scope_open && in->mp && in->mp->catchup_batch_begin) {
            in->mp->catchup_batch_begin(in->mp->catchup_batch_scope_ctx);
            batch_scope_open = true;
        }

        msg_block_intake_process_one(in, &item);
        msg_block_intake_item_free(&item);
        processed_since_drain++;

        pthread_mutex_lock(&in->mu);
        size_t queued = in->depth;
        pthread_mutex_unlock(&in->mu);
        if (processed_since_drain >= MSG_BLOCK_INTAKE_DRAIN_BATCH ||
            queued == 0) {
            if (batch_scope_open && in->mp && in->mp->catchup_batch_end)
                in->mp->catchup_batch_end(in->mp->catchup_batch_scope_ctx);
            batch_scope_open = false;
        }
        msg_block_intake_maybe_drain_catchup(in, &processed_since_drain);
        thread_liveness_beat(&g_p2p_ingest_liveness,
                             (int64_t)atomic_fetch_add(&g_p2p_ingest_beat_count, 1) + 1);
    }

    return NULL;
}

static struct msg_block_intake *msg_block_intake_start(struct msg_processor *mp)
{
    if (!mp)
        return NULL;

    pthread_mutex_lock(&g_block_intake_create_lock);
    if (mp->block_intake) {
        pthread_mutex_unlock(&g_block_intake_create_lock);
        return mp->block_intake;
    }

    struct msg_block_intake *in = zcl_calloc(1, sizeof(*in),
                                             "msg_block_intake");
    if (!in) {
        pthread_mutex_unlock(&g_block_intake_create_lock);
        LOG_NULL("net", "block intake allocation failed");
    }
    pthread_mutex_init(&in->mu, NULL);
    pthread_cond_init(&in->cv, NULL);
    in->running = true;
    in->mp = mp;
    for (size_t i = 0; i < MSG_BLOCK_INTAKE_CAP; i++)
        msg_block_intake_item_init(&in->queue[i]);

    mp->block_intake = in;
    int rc = thread_registry_spawn("zcl_p2p_ingest",
                                      msg_block_intake_worker, in,
                                      &in->thread);
    if (rc != 0) {
        atomic_fetch_add_explicit(&in->spawn_failed, 1,
                                  memory_order_relaxed);
        mp->block_intake = NULL;
        pthread_cond_destroy(&in->cv);
        pthread_mutex_destroy(&in->mu);
        free(in);
        pthread_mutex_unlock(&g_block_intake_create_lock);
        LOG_NULL("net", "block intake worker spawn failed rc=%d", rc);
    }
    in->thread_started = true;
    thread_liveness_register(&g_p2p_ingest_liveness, "zcl_p2p_ingest", 0, 0);

    /* -pin-reducer (default OFF): "zcl_p2p_ingest" is the thread that
     * synchronously runs reducer_ingest_block for every P2P-delivered
     * block (see msg_block_intake_process_one below) — the cache-
     * sensitive hot loop this flag exists to pin onto the large-L3 CCD on
     * asymmetric multi-CCD hosts (e.g. the 7950X3D's 96 MB V-Cache CCD).
     * Advisory only: hw_profile_pin_reducer_thread logs its own outcome
     * and never fails this spawn. */
    if (GetBoolArg("-pin-reducer", false))
        hw_profile_pin_reducer_thread(in->thread);
    pthread_mutex_unlock(&g_block_intake_create_lock);
    return in;
}

bool msg_processor_enqueue_p2p_block(struct msg_processor *mp,
                                     const struct block *blk,
                                     const struct uint256 *hash,
                                     uint32_t peer_id,
                                     struct validation_state *out)
{
    if (!mp || !blk || !hash || !out)
        return false;
    if (!mp->main_state || !mp->params)
        return false;
    if (sync_get_state() == SYNC_AT_TIP)
        return false;

    struct msg_block_intake *in = msg_block_intake_start(mp);
    if (!in) {
        validation_state_error(out, "p2p-block-intake-unavailable");
        return true;
    }

    struct msg_block_intake_item item;
    msg_block_intake_item_init(&item);
    if (!block_clone(&item.block, blk)) {
        atomic_fetch_add_explicit(&in->clone_failed, 1,
                                  memory_order_relaxed);
        validation_state_error(out, "p2p-block-clone-failed");
        return true;
    }
    item.hash = *hash;
    item.peer_id = peer_id;
    item.enqueued_unix = (int64_t)platform_time_wall_time_t();

    pthread_mutex_lock(&in->mu);
    if (in->stopping) {
        pthread_mutex_unlock(&in->mu);
        msg_block_intake_item_free(&item);
        atomic_fetch_add_explicit(&in->dropped, 1, memory_order_relaxed);
        validation_state_error(out, "p2p-block-intake-stopped");
        return true;
    }
    if (in->depth >= MSG_BLOCK_INTAKE_CAP) {
        pthread_mutex_unlock(&in->mu);
        msg_block_intake_item_free(&item);
        uint64_t dropped = atomic_fetch_add_explicit(&in->dropped, 1,
                                                     memory_order_relaxed) + 1;
        /* A destroyed body is lost work, and losing the tip's successor here
         * freezes the whole chain, so it must never be silent (CLAUDE.md: a
         * stall is a named blocker, never a quiet stop). The getdata window is
         * bounded by the ring's free space
         * (msg_processor_block_intake_request_room), so reaching here means
         * bodies arrived that no bound accounted for. */
        msg_block_intake_name_drop_blocker(dropped);
        validation_state_error(out, "p2p-block-intake-full");
        return true;
    }

    in->queue[in->tail] = item;
    in->tail = (in->tail + 1) % MSG_BLOCK_INTAKE_CAP;
    in->depth++;
    size_t depth = in->depth;
    pthread_cond_signal(&in->cv);
    pthread_mutex_unlock(&in->mu);

    atomic_fetch_add_explicit(&in->enqueued, 1, memory_order_relaxed);
    atomic_store_explicit(&in->last_enqueue_unix, item.enqueued_unix,
                          memory_order_relaxed);
    msg_block_intake_stats_bump_max(in, (uint64_t)depth);
    validation_state_error(out, "p2p-block-queued-for-reducer");
    return true;
}

void msg_processor_stop_block_intake(struct msg_processor *mp)
{
    if (!mp)
        return;

    pthread_mutex_lock(&g_block_intake_create_lock);
    struct msg_block_intake *in = mp->block_intake;
    mp->block_intake = NULL;
    pthread_mutex_unlock(&g_block_intake_create_lock);
    if (!in)
        return;

    pthread_mutex_lock(&in->mu);
    in->stopping = true;
    pthread_cond_broadcast(&in->cv);
    pthread_mutex_unlock(&in->mu);

    if (in->thread_started) {
        pthread_join(in->thread, NULL);
        thread_liveness_retire(&g_p2p_ingest_liveness);
    }

    pthread_mutex_lock(&in->mu);
    msg_block_intake_drain_locked(in);
    in->running = false;
    pthread_mutex_unlock(&in->mu);

    pthread_cond_destroy(&in->cv);
    pthread_mutex_destroy(&in->mu);
    free(in);
}

void msg_processor_get_block_intake_stats(
    const struct msg_processor *mp,
    struct msg_block_intake_stats *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!mp)
        return;

    pthread_mutex_lock(&g_block_intake_create_lock);
    struct msg_block_intake *in = mp->block_intake;
    if (!in) {
        pthread_mutex_unlock(&g_block_intake_create_lock);
        return;
    }
    pthread_mutex_lock(&in->mu);
    out->current_depth = (uint64_t)in->depth;
    out->capacity = MSG_BLOCK_INTAKE_CAP;
    out->running = in->running;
    out->stopping = in->stopping;
    pthread_mutex_unlock(&in->mu);

    out->enqueued = atomic_load_explicit(&in->enqueued,
                                         memory_order_relaxed);
    out->dropped = atomic_load_explicit(&in->dropped,
                                        memory_order_relaxed);
    out->processed = atomic_load_explicit(&in->processed,
                                          memory_order_relaxed);
    out->accepted = atomic_load_explicit(&in->accepted,
                                         memory_order_relaxed);
    out->rejected = atomic_load_explicit(&in->rejected,
                                         memory_order_relaxed);
    out->retryable = atomic_load_explicit(&in->retryable,
                                          memory_order_relaxed);
    out->clone_failed = atomic_load_explicit(&in->clone_failed,
                                             memory_order_relaxed);
    out->spawn_failed = atomic_load_explicit(&in->spawn_failed,
                                             memory_order_relaxed);
    out->max_depth = atomic_load_explicit(&in->max_depth,
                                          memory_order_relaxed);
    out->last_enqueue_unix = atomic_load_explicit(&in->last_enqueue_unix,
                                                  memory_order_relaxed);
    out->last_process_unix = atomic_load_explicit(&in->last_process_unix,
                                                  memory_order_relaxed);
    pthread_mutex_unlock(&g_block_intake_create_lock);
}

/* How many MORE block bodies may be outstanding on the wire right now.
 *
 * Every body a peer sends during catch-up must land in this fixed ring or be
 * destroyed (msg_processor_enqueue_p2p_block's "p2p-block-intake-full" arm).
 * So the honest request ceiling is the ring's free space MINUS what is already
 * in flight — anything beyond that has been paid for on the wire and will be
 * thrown away, then re-requested.
 *
 * Measured before this bound existed (C3 stopwatch, one loopback fixture peer,
 * 256-block getdata batches against a 128-slot ring): enqueued=7038
 * dropped=8867, i.e. 56% of every body received was destroyed. The block the
 * chain needed next (h=3058182) was destroyed on delivery, re-requested 19
 * times, and H* never moved again for the remaining 405 s of the run.
 * `fallback` is returned unchanged when the async ring is not in use (at tip,
 * or worker not started), where bodies go down the synchronous path and cannot
 * be dropped. */
static size_t msg_processor_block_intake_request_room(struct msg_processor *mp,
                                                     uint64_t in_flight,
                                                     size_t fallback)
{
    struct msg_block_intake_stats st;
    msg_processor_get_block_intake_stats(mp, &st);
    if (!st.running || st.stopping || st.capacity == 0)
        return fallback;
    uint64_t committed = st.current_depth + in_flight;
    if (committed >= st.capacity)
        return 0;
    uint64_t room = st.capacity - committed;
    return room < fallback ? (size_t)room : fallback;
}

static void msg_processor_log_block_intake_backpressure(
        const struct p2p_node *node)
{
    uint64_t suppressed = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    if (!log_throttle_should_emit(&g_block_intake_dispatch_log, 1, now,
                                  MSG_BLOCK_INTAKE_LOG_KEEPALIVE_SECS,
                                  &suppressed))
        return;
    LOG_INFO("net",
             "block intake queue saturated; pausing getdata assignment%s%s "
             "(suppressed=%llu)",
             node ? " for " : "",
             node ? node->addr_name : "",
             (unsigned long long)suppressed);
}

/* ── Tip-stall watchdog observers ──────────────────────────── */

/* feed tip-advance signals into the watchdog. Both
 * EV_BLOCK_CONNECTED (per-block during IBD) and EV_TIP_UPDATED
 * (caught-up-to-peer transitions) count as forward progress. The
 * payload is informational; only the timestamp matters. */
void msgprocessor_watchdog_tip_observer(enum event_type type, uint32_t peer_id,
                                        const void *payload,
                                        uint32_t payload_len, void *ctx)
{
    (void)type; (void)peer_id; (void)payload;
    (void)payload_len; (void)ctx;
    tip_watchdog_note_tip_advance(0);
}

/* ── mempool dispatch wrapper ──────────────────────────────────── */

static bool handle_mempool(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s)
{
    (void)s;
    return process_mempool(mp, node);
}

static bool handle_tx_msg(struct msg_processor *mp, struct p2p_node *node,
                          struct byte_stream *s)
{
    return process_tx_msg(mp, node, s);
}

/* ── BIP37 bloom filter handlers ─────────────────────────────────
 * BIP37 is a known privacy leak: a peer can probe which addresses a
 * node owns by watching false-positive rates across crafted filters.
 * Default OFF — enable only with ZCL_ENABLE_BIP37=1. When disabled,
 * filterload/filteradd/filterclear score the peer as misbehaving. */

/* Shared reject path for the three BIP37 filter commands. When BIP37 is
 * disabled (the default) the peer is scored as misbehaving and dropped.
 * Full BIP37 filter loading is not implemented — reject even when enabled
 * until a use case justifies it. */
static bool handle_bip37_rejected(struct msg_processor *mp, struct p2p_node *node,
                                  struct byte_stream *s, const char *cmd)
{
    (void)s;
    if (!bip37_enabled()) {
        char reason[64];
        snprintf(reason, sizeof(reason), "%s rejected: BIP37 disabled", cmd);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_PROTOCOL_VIOLATION, reason);
        LOG_FAIL("bip37", "%s from %s — BIP37 disabled, disconnecting",
                 cmd, node->addr_name);
    }
    return true;
}

static bool handle_filterload(struct msg_processor *mp, struct p2p_node *node,
                               struct byte_stream *s)
{
    return handle_bip37_rejected(mp, node, s, "filterload");
}

static bool handle_filteradd(struct msg_processor *mp, struct p2p_node *node,
                              struct byte_stream *s)
{
    return handle_bip37_rejected(mp, node, s, "filteradd");
}

static bool handle_filterclear(struct msg_processor *mp, struct p2p_node *node,
                                struct byte_stream *s)
{
    return handle_bip37_rejected(mp, node, s, "filterclear");
}

/* ── ZCL Messaging handlers ───────────────────────────────────── */

static bool handle_zmsg(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s)
{
    struct zmsg_message msg;
    if (!zmsg_deserialize(&msg, s))
        return true;

    msg.direction = ZMSG_INBOUND;
    msg.channel = ZMSG_CHANNEL_P2P;

    /* Store locally */
    bool is_new = zmsg_store_add(&msg);

    if (mp->zmsg_save)
        (void)mp->zmsg_save(&msg, mp->zmsg_save_ctx);

    /* Send acknowledgment */
    struct byte_stream os;
    stream_init(&os, 64);
    stream_write(&os, msg.msg_id, 32);
    p2p_node_begin_message(node, MSG_ZMSG_ACK,
                           mp->params->pchMessageStart);
    p2p_node_write_message_data(node, os.data, os.size);
    p2p_node_end_message(node);
    stream_free(&os);

    if (is_new) {
        printf("zmsg: received message from %s via peer %s\n",
               msg.sender, node->addr_name);
    }
    return true;
}

static bool handle_zmsgack(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s)
{
    (void)mp;
    uint8_t ack_id[32];
    if (!stream_read(s, ack_id, 32))
        return true;

    printf("zmsg: delivery ack from peer %s\n", node->addr_name);
    return true;
}

/* ── ZCL Market: file sharing handlers ─────────────────────────── */

static bool handle_zfilelist(struct msg_processor *mp, struct p2p_node *node,
                             struct byte_stream *s)
{
    /* Deserialize one or more file offers from the message */
    uint64_t count = 0;
    if (!stream_read_compact_size(s, &count))
        return true;
    if (count > 50) count = 50; /* limit per message */

    for (uint64_t i = 0; i < count; i++) {
        struct file_offer offer;
        if (!file_offer_deserialize(&offer, s))
            break;

        /* zfilelist predates seller authentication. It remains a compatibility
         * carrier for price-zero ROM artifacts only; accepting a paid row here
         * would let any relay rewrite price/address/endpoint. */
        if (offer.price_per_mb != 0) {
            LOG_WARN("market", "unsigned paid zfilelist offer from peer %s "
                     "dropped", node->addr_name);
            continue;
        }

        /* Clamp the peer-supplied hop count: an attacker could set ttl=255 to
         * drive a ~255-hop re-gossip amplification across the network. Cap it
         * to the protocol maximum so propagation is bounded regardless of input. */
        if (offer.ttl > FILE_MARKET_MAX_TTL)
            offer.ttl = FILE_MARKET_MAX_TTL;

        /* Reject expired TTL */
        if (offer.ttl == 0) continue;

        /* Store locally */
        bool is_new = file_market_add_offer(&offer);

        if (mp->file_offer_save)
            (void)mp->file_offer_save(&offer, mp->file_offer_save_ctx);

        /* Re-gossip to other peers if new and TTL > 1 */
        if (is_new && offer.ttl > 1 && mp->net_mgr) {
            struct file_offer fwd = offer;
            fwd.ttl--;

            struct byte_stream os;
            stream_init(&os, 512);
            stream_write_compact_size(&os, 1);
            file_offer_serialize(&fwd, &os);

            zcl_mutex_lock(&mp->net_mgr->cs_nodes);
            for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
                struct p2p_node *peer = mp->net_mgr->nodes[pi];
                if (peer->id != node->id &&
                    peer->state >= PEER_HANDSHAKE_COMPLETE &&
                    !peer->disconnect &&
                    peer_supports_fast_sync(peer->services)) {
                    p2p_node_begin_message(peer, MSG_FILE_LIST,
                                           mp->params->pchMessageStart);
                    p2p_node_write_message_data(peer, os.data, os.size);
                    p2p_node_end_message(peer);
                }
            }
            zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
            stream_free(&os);
        }

        printf("market: %s offer '%s' (%.1f MB, %lld zat/MB) from peer %s\n",
               is_new ? "new" : "updated",
               offer.filename,
               offer.size_bytes / (1024.0 * 1024.0),
               (long long)offer.price_per_mb,
               node->addr_name);
    }
    return true;
}

static bool handle_zfilechal(struct msg_processor *mp, struct p2p_node *node,
                             struct byte_stream *s)
{
    struct file_challenge chal;
    if (!file_challenge_deserialize(&chal, s))
        return true;

    /* Free-tier ROM artifact: answer the proof-of-possession challenge from the
     * registered per-chunk SHA3 (the chunk's data digest). Keeps the challenge
     * machinery intact for ROM artifacts, which aren't in the block-file
     * manifest the priced path reads. */
    struct rom_artifact rart;
    if (rom_seed_find_by_root(chal.root_hash, &rart)) {
        if (chal.chunk_index >= rart.num_chunks) {
            printf("market: ROM challenge for invalid chunk %u/%u from peer %s\n",
                   chal.chunk_index, rart.num_chunks, node->addr_name);
            return true;
        }
        struct file_proof rproof;
        memset(&rproof, 0, sizeof(rproof));
        memcpy(rproof.root_hash, chal.root_hash, 32);
        rproof.chunk_index = chal.chunk_index;
        memcpy(rproof.chunk_hash, rart.chunk_sha3[chal.chunk_index], 32);

        struct byte_stream ros;
        stream_init(&ros, 128);
        file_proof_serialize(&rproof, &ros);
        p2p_node_begin_message(node, MSG_FILE_PROOF,
                               mp->params->pchMessageStart);
        p2p_node_write_message_data(node, ros.data, ros.size);
        p2p_node_end_message(node);
        stream_free(&ros);
        printf("market: answered ROM chunk challenge %u for '%s' from peer %s\n",
               chal.chunk_index, rart.filename, node->addr_name);
        return true;
    }

    /* Check if we're offering this file */
    struct file_offer offer;
    if (!file_market_find_offer(chal.root_hash, &offer)) {
        printf("market: challenge for unknown file from peer %s\n",
               node->addr_name);
        return true;
    }

    if (chal.chunk_index >= offer.num_chunks) {
        printf("market: challenge for invalid chunk %u/%u from peer %s\n",
               chal.chunk_index, offer.num_chunks, node->addr_name);
        return true;
    }

    /* Read actual chunk from disk and SHA3-256 hash it */
    struct file_proof proof;
    memset(&proof, 0, sizeof(proof));
    memcpy(proof.root_hash, chal.root_hash, 32);
    proof.chunk_index = chal.chunk_index;

    struct file_manifest fm;
    if (file_controller_get_manifest_copy(&fm) &&
        chal.chunk_index < fm.num_chunks) {
        uint8_t *chunk_data = NULL;
        uint32_t chunk_size = 0;
        if (file_chunk_read(&fm.chunks[chal.chunk_index],
                            mp->datadir, &chunk_data, &chunk_size)) {
            struct sha3_256_ctx sha3;
            sha3_256_init(&sha3);
            sha3_256_write(&sha3, chunk_data, chunk_size);
            sha3_256_finalize(&sha3, proof.chunk_hash);
            free(chunk_data);
        } else {
            /* Fallback: derive hash from root_hash + index */
            uint8_t preimage[36];
            memcpy(preimage, chal.root_hash, 32);
            memcpy(preimage + 32, &chal.chunk_index, 4);
            struct sha3_256_ctx sha3;
            sha3_256_init(&sha3);
            sha3_256_write(&sha3, preimage, 36);
            sha3_256_finalize(&sha3, proof.chunk_hash);
            printf("market: chunk %u read failed, using derived hash\n",
                   chal.chunk_index);
        }
    } else {
        /* No manifest — derive hash as placeholder */
        uint8_t preimage[36];
        memcpy(preimage, chal.root_hash, 32);
        memcpy(preimage + 32, &chal.chunk_index, 4);
        struct sha3_256_ctx sha3;
        sha3_256_init(&sha3);
        sha3_256_write(&sha3, preimage, 36);
        sha3_256_finalize(&sha3, proof.chunk_hash);
    }

    struct byte_stream os;
    stream_init(&os, 128);
    file_proof_serialize(&proof, &os);
    p2p_node_begin_message(node, MSG_FILE_PROOF,
                           mp->params->pchMessageStart);
    p2p_node_write_message_data(node, os.data, os.size);
    p2p_node_end_message(node);
    stream_free(&os);

    printf("market: responded to chunk challenge %u for '%s' from peer %s\n",
           chal.chunk_index, offer.filename, node->addr_name);
    return true;
}

static bool handle_zfileproof(struct msg_processor *mp, struct p2p_node *node,
                              struct byte_stream *s)
{
    (void)mp;
    struct file_proof proof;
    if (!file_proof_deserialize(&proof, s))
        return true;

    printf("market: received chunk proof %u from peer %s\n",
           proof.chunk_index, node->addr_name);

    /* Verify proof against active download session */
    struct file_download dl;
    if (file_market_get_download(proof.root_hash, &dl)) {
        if (dl.state == FDL_CHALLENGING) {
            /* Verify chunk hash matches our manifest */
            struct file_manifest fm;
            bool hash_ok = false;
            if (file_controller_get_manifest_copy(&fm) &&
                proof.chunk_index < fm.num_chunks) {
                hash_ok = (memcmp(proof.chunk_hash,
                                  fm.chunks[proof.chunk_index].sha3, 32) == 0);
            }
            if (hash_ok) {
                file_market_download_challenge_passed(proof.root_hash);
                uint32_t passed = dl.challenges_passed + 1;
                printf("market: challenge %u/%u passed for '%s'\n",
                       passed, dl.challenges_sent, dl.offer.filename);
                if (passed >= dl.challenges_sent) {
                    file_market_update_download(proof.root_hash, FDL_PAYING,
                                               dl.chunks_received, dl.chunks_paid_through);
                    printf("market: all challenges passed, advancing to payment\n");
                }
            } else {
                printf("market: challenge FAILED for chunk %u from peer %s\n",
                       proof.chunk_index, node->addr_name);
                file_market_update_download(proof.root_hash, FDL_FAILED,
                                           dl.chunks_received, dl.chunks_paid_through);
            }
        }
    }
    return true;
}

static bool handle_zfilepay(struct msg_processor *mp, struct p2p_node *node,
                            struct byte_stream *s)
{
    struct file_payment pay;
    if (!file_payment_deserialize(&pay, s))
        return true;

    enum file_payment_auth_error auth = file_payment_auth_verify(
        &pay, mp && mp->params
            ? mp->params->consensus.hashGenesisBlock.data : NULL);
    if (auth != FILE_PAYMENT_AUTH_OK) {
        LOG_WARN("market", "zfilepay rejected before ingress: %s",
                 file_payment_auth_error_string(auth));
        return true;
    }
    if (!mp->file_payment_ingest) {
        LOG_WARN("market", "zfilepay rejected: payment authority is not wired");
        return true;
    }

    int result = mp->file_payment_ingest(
        &pay, (int64_t)node->id,
        (int64_t)platform_time_wall_time_t(), mp->file_payment_ingest_ctx);
    if (result == FILE_PAYMENT_INGEST_CONFIRMED)
        LOG_INFO("market", "zfilepay reconciled as confirmed");
    else if (result == FILE_PAYMENT_INGEST_PENDING)
        LOG_INFO("market", "zfilepay recorded pending confirmation");
    else if (result == FILE_PAYMENT_INGEST_UNKNOWN)
        LOG_WARN("market", "zfilepay money state is unknown; unlock refused");
    else if (result == FILE_PAYMENT_INGEST_CONFLICTED)
        LOG_WARN("market", "zfilepay conflicts with authoritative payment state");
    else
        LOG_WARN("market", "zfilepay rejected by payment authority");
    return true;
}

static bool handle_zfileaddr(struct msg_processor *mp, struct p2p_node *node,
                             struct byte_stream *s)
{
    uint8_t faddr[2];
    if (stream_read_bytes(s, faddr, 2)) {
        uint16_t fport;
        memcpy(&fport, faddr, 2);
        uint8_t fip[16];
        memcpy(fip, node->addr.svc.addr.ip, 16);

        if (mp->file_service_save)
            (void)mp->file_service_save(
                fip, fport, node->addr.svc.port,
                (int64_t)platform_time_wall_time_t(), true,
                mp->file_service_save_ctx);
        char ipbuf[NET_ADDR_STR_MAX + 1];
        net_addr_to_string(&node->addr.svc.addr, ipbuf, sizeof(ipbuf));
        printf("Peer %s: file service at port %d (saved)\n",
               ipbuf, fport);
    }
    return true;
}

/* ── ZCL Market: zswap yardsale (atomic ZSLP/ZCL swap ads) ──────── */

static void mp_flood_wire(struct msg_processor *mp, const char *command,
                          const uint8_t *wire, size_t wire_len,
                          int64_t exclude_peer_id);

static bool handle_zfileoffer(struct msg_processor *mp,
                              struct p2p_node *node,
                              struct byte_stream *s)
{
    /* One message carries exactly one signed offer wire: v1 (535) or v2
     * (568). Any other size is drop-and-ignore (never disconnect a peer
     * over an application-gossip payload). */
    size_t remaining = s->size - s->read_pos;
    if (remaining != FILE_MARKET_OFFER_WIRE_BYTES &&
        remaining != FILE_MARKET_OFFER_WIRE_BYTES_V2)
        return true;
    uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    if (!stream_read(s, wire, remaining) || !mp->params)
        return true;

    struct file_offer offer;
    enum file_market_offer_ingest result = file_market_ingest_offer_wire(
        wire, remaining, mp->params->consensus.hashGenesisBlock.data,
        (int64_t)node->id, (int64_t)platform_time_wall_time_t(), &offer);
    if (result != FILE_MARKET_INGEST_NEW &&
        result != FILE_MARKET_INGEST_DEDUP)
        return true;

    if (mp->file_offer_save)
        (void)mp->file_offer_save(&offer, mp->file_offer_save_ctx);
    if (result == FILE_MARKET_INGEST_NEW && mp->net_mgr)
        mp_flood_wire(mp, MSG_FILE_OFFER, wire, remaining,
                      (int64_t)node->id);
    return true;
}

static bool handle_zswapquote(struct msg_processor *mp, struct p2p_node *node,
                              struct byte_stream *s)
{
    /* One message carries exactly one signed yardsale ad: the exact
     * 210-byte zswap_quote.v1 wire. Pre-check the length before decode —
     * short/trailing payloads are drop-and-ignore (Bitcoin Core parity:
     * never disconnect a peer over an application-gossip payload). */
    if (s->size - s->read_pos != ZSWAP_QUOTE_WIRE_BYTES)
        return true;

    uint8_t wire[ZSWAP_QUOTE_WIRE_BYTES];
    if (!stream_read(s, wire, sizeof(wire)))
        return true;

    if (!mp->params) {
        LOG_WARN("zswap", "zswapquote from peer %s dropped: no chainparams",
                 node->addr_name);
        return true;
    }

    /* The ad's network_genesis_root pins the chain it lives on: our
     * consensus genesis hash (core/chainparams) is the expected root. */
    const uint8_t *net_root = mp->params->consensus.hashGenesisBlock.data;
    int64_t now = (int64_t)platform_time_wall_time_t();

    /* Verify at ingress (signature + network + validity window), dedup on
     * the quote root, per-peer flood clamp — all inside the yardsale,
     * reached through the injected ingest port (module-order seam: lib/net
     * never names a lib/zswap symbol). An invalid/expired ad is dropped
     * here and NEVER forwarded or stored. */
    if (!mp->zswap_ad_ingest) {
        LOG_WARN("zswap",
                 "zswapquote from peer %s dropped: ingest port unwired",
                 node->addr_name);
        return true;
    }
    struct zswap_yardsale_ad ad;
    int result = mp->zswap_ad_ingest(wire, sizeof(wire), net_root,
                                     (int64_t)node->id, now, &ad,
                                     mp->zswap_ad_ingest_ctx);

    if (result != ZSWAP_YARDSALE_INGEST_NEW &&
        result != ZSWAP_YARDSALE_INGEST_DEDUP)
        return true;

    /* Persist the rebuildable AR projection (new insert or seen bump). */
    if (mp->zswap_ad_save)
        (void)mp->zswap_ad_save(&ad, mp->zswap_ad_save_ctx);

    /* Relay-forward only NEW ads (the zfilelist re-gossip idiom adapted to
     * signed content: the wire has no TTL field — a relay must never alter
     * signed bytes — so propagation is bounded by dedup-on-root instead;
     * every node forwards a given quote root at most once). */
    if (result == ZSWAP_YARDSALE_INGEST_NEW && mp->net_mgr) {
        mp_flood_wire(mp, ZSWAP_MSG_QUOTE, wire, sizeof(wire),
                      (int64_t)node->id);
    }
    return true;
}

/* ── ZCL Market: the yardsale swap ceremony wires ───────────────── */

/* One flood loop for every zswap gossip wire: forward to every fast-sync
 * peer except exclude_peer_id (-1 excludes nobody). The yardsale's
 * dedup-on-content ring bounds loops — a wire is offered to the flood at
 * most once per node, so this never amplifies. */
static void mp_flood_wire(struct msg_processor *mp, const char *command,
                          const uint8_t *wire, size_t wire_len,
                          int64_t exclude_peer_id)
{
    if (!mp->net_mgr || !mp->params)
        return;
    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
    for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
        struct p2p_node *peer = mp->net_mgr->nodes[pi];
        if ((int64_t)peer->id != exclude_peer_id &&
            peer->state >= PEER_HANDSHAKE_COMPLETE &&
            !peer->disconnect &&
            peer_supports_fast_sync(peer->services)) {
            p2p_node_begin_message(peer, command,
                                   mp->params->pchMessageStart);
            p2p_node_write_message_data(peer, wire, wire_len);
            p2p_node_end_message(peer);
        }
    }
    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
}

void msg_processor_flood_message(struct msg_processor *mp,
                                 const char *command,
                                 const uint8_t *wire, size_t wire_len)
{
    if (!mp || !command || !wire || wire_len == 0)
        return;
    mp_flood_wire(mp, command, wire, wire_len, -1);
}

static bool handle_zswapaccept(struct msg_processor *mp,
                               struct p2p_node *node,
                               struct byte_stream *s)
{
    /* One message carries exactly one zswap_accept.v1 wire (bounded,
     * variable width by buyer input count). Same drop-and-ignore parity
     * as zswapquote: never disconnect over an application-gossip payload. */
    size_t plen = s->size - s->read_pos;
    if (plen == 0 || plen > ZSWAP_ACCEPT_WIRE_MAX_BYTES)
        return true;

    uint8_t wire[ZSWAP_ACCEPT_WIRE_MAX_BYTES];
    if (!stream_read(s, wire, plen))
        return true;

    if (!mp->zswap_accept_ingest) {
        LOG_WARN("zswap",
                 "zswapaccept from peer %s dropped: ingress port unwired",
                 node->addr_name);
        return true;
    }

    uint8_t respond[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    size_t respond_len = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    int result = mp->zswap_accept_ingest(wire, plen, (int64_t)node->id, now,
                                         respond, sizeof(respond),
                                         &respond_len,
                                         mp->zswap_accept_ingest_ctx);

    if (result == ZSWAP_CEREMONY_WIRE_RESPOND && respond_len > 0) {
        /* We are the seller: answer with our partial. */
        mp_flood_wire(mp, ZSWAP_MSG_PARTIAL, respond, respond_len,
                      (int64_t)node->id);
    } else if (result == ZSWAP_CEREMONY_WIRE_RELAY) {
        /* Intermediary: forward the accept once, byte-identically. */
        mp_flood_wire(mp, ZSWAP_MSG_ACCEPT, wire, plen,
                      (int64_t)node->id);
    }
    return true;
}

static bool handle_zswappartial(struct msg_processor *mp,
                                struct p2p_node *node,
                                struct byte_stream *s)
{
    /* One message carries exactly one zswap_partial.v1 wire. */
    size_t plen = s->size - s->read_pos;
    if (plen == 0 || plen > ZSWAP_PARTIAL_WIRE_MAX_BYTES)
        return true;

    uint8_t wire[ZSWAP_PARTIAL_WIRE_MAX_BYTES];
    if (!stream_read(s, wire, plen))
        return true;

    if (!mp->zswap_partial_ingest) {
        LOG_WARN("zswap",
                 "zswappartial from peer %s dropped: ingress port unwired",
                 node->addr_name);
        return true;
    }

    int64_t now = (int64_t)platform_time_wall_time_t();
    int result = mp->zswap_partial_ingest(wire, plen, (int64_t)node->id,
                                          now,
                                          mp->zswap_partial_ingest_ctx);
    if (result == ZSWAP_CEREMONY_WIRE_RELAY) {
        /* Someone else's ceremony: forward the partial once. */
        mp_flood_wire(mp, ZSWAP_MSG_PARTIAL, wire, plen,
                      (int64_t)node->id);
    }
    return true;
}

static bool handle_game_msg(struct msg_processor *mp, struct p2p_node *node,
                            struct byte_stream *s)
{
    (void)mp;
    uint8_t game_type = 0, position = 0;
    struct ttt_state peer_state;
    memset(&peer_state, 0, sizeof(peer_state));
    enum game_action action = game_deserialize(
        s->data + s->read_pos, s->size - s->read_pos,
        &game_type, &position, &peer_state);

    switch (action) {
    case GAME_INVITE:
        printf("Peer %s: game invite (type=%d)\n",
               node->addr_name, game_type);
        /* Auto-accept for now */
        {
            uint8_t resp[8];
            size_t rn = game_serialize_accept(resp, sizeof(resp), 2);
            p2p_node_begin_message(node, MSG_GAME,
                                    mp->params->pchMessageStart);
            p2p_node_write_message_data(node, resp, rn);
            p2p_node_end_message(node);
            printf("Peer %s: auto-accepted game as O\n",
                   node->addr_name);
        }
        break;
    case GAME_ACCEPT:
        printf("Peer %s: game accepted\n", node->addr_name);
        break;
    case GAME_MOVE:
        printf("Peer %s: game move position=%d\n",
               node->addr_name, position);
        /* Measure latency from timestamp in message */
        if (s->size - s->read_pos >= 11) {
            int64_t send_ts = 0;
            memcpy(&send_ts, s->data + s->read_pos + 3, 8);
            int64_t now_us = platform_time_realtime_us();
            int64_t latency = now_us - send_ts;
            if (latency > 0 && latency < 60000000)
                printf("Peer %s: P2P latency = %lld us (%.1f ms)\n",
                       node->addr_name, (long long)latency,
                       (double)latency / 1000.0);
        }
        break;
    case GAME_STATE:
        {
            char board[256];
            ttt_render(&peer_state, board, sizeof(board));
            printf("Peer %s: game state\n%s\n",
                   node->addr_name, board);
        }
        break;
    case GAME_RESULT:
        printf("Peer %s: game result\n", node->addr_name);
        break;
    default:
        break;
    }
    return true;
}

/* ── P2P Message Dispatch Table ──────────────────────────────────
 * Maps command strings to handler functions. The mp_handle_* entries
 * live in the split files; the chain-sync family (getblocks, getheaders,
 * block, headers, cmpctblock, getblocktxn, blocktxn) points directly at
 * the process_* handlers in msg_headers.c / msg_blocks.c / msg_compact.c;
 * everything else (filter*, zmsg, zfile*, zgame, mempool, tx) is local.
 * Sentinel at the end. */

/* Shim adapting process_sendcmpct to the uniform (mp, node, s) dispatch
 * signature (the names differ only by this indirection). */
static bool mp_sendcmpct(struct msg_processor *mp, struct p2p_node *node,
                         struct byte_stream *s)
{
    return process_sendcmpct(mp, node, s);
}

static const struct msg_dispatch_entry g_msg_dispatch[] = {
    /* ── Bitcoin P2P ── */
    { "version",      mp_handle_version,      false, false, "p2p" },
    { "verack",       mp_handle_verack,       false, false, "p2p" },
    { "ping",         mp_handle_ping,         true,  false, "p2p" },
    { "pong",         mp_handle_pong,         true,  false, "p2p" },
    { "addr",         mp_handle_addr,         true,  false, "p2p" },
    { "inv",          mp_handle_inv,          true,  false, "sync" },
    { "getdata",      mp_handle_getdata,      true,  false, "sync" },
    { "getblocks",    process_getblocks,      true,  false, "sync" },
    { "getheaders",   process_getheaders,     true,  false, "sync" },
    { "block",        process_block_msg,      true,  false, "sync" },
    { "tx",           handle_tx_msg,          true,  false, "mempool" },
    { "headers",      process_headers,        true,  false, "sync" },
    { "getaddr",      mp_handle_getaddr,      true,  false, "p2p" },
    { "mempool",      handle_mempool,         true,  false, "mempool" },
    { "sendheaders",  mp_handle_sendheaders,  true,  false, "p2p" },
    { "reject",       mp_handle_reject,       true,  false, "p2p" },
    { "feefilter",    mp_handle_feefilter,    true,  false, "mempool" },
    { "notfound",     mp_handle_notfound,     true,  false, "sync" },
    /* ── BIP152 compact blocks ── */
    { "sendcmpct",   mp_sendcmpct,           true,  false, "compact" },
    { "cmpctblock",  process_cmpctblock,     true,  false, "compact" },
    { "getblocktxn", process_getblocktxn,    true,  false, "compact" },
    { "blocktxn",    process_blocktxn,       true,  false, "compact" },
    /* ── BIP37 bloom filters (gated by ZCL_ENABLE_BIP37) ── */
    { "filterload",   handle_filterload,     true,  false, "bloom" },
    { "filteradd",    handle_filteradd,      true,  false, "bloom" },
    { "filterclear",  handle_filterclear,    true,  false, "bloom" },
    /* ── ZCL23 File Service ── */
    { "zfileaddr",    handle_zfileaddr,      true,  true,  "filesvc" },
    /* ── ZCL Messaging ── */
    { "zmsg",         handle_zmsg,           true,  true,  "msg" },
    { "zmsgack",      handle_zmsgack,        true,  true,  "msg" },
    /* ── ZCL Market ── */
    { "zfilelist",    handle_zfilelist,      true,  true,  "market" },
    { "zfileoffer",   handle_zfileoffer,     true,  true,  "market" },
    { "zfilechal",    handle_zfilechal,      true,  true,  "market" },
    { "zfileproof",   handle_zfileproof,     true,  true,  "market" },
    { "zfilepay",     handle_zfilepay,       true,  true,  "market" },
    { "zswapquote",   handle_zswapquote,     true,  true,  "market" },
    { "zswapaccept",  handle_zswapaccept,    true,  true,  "market" },
    { "zswappartial", handle_zswappartial,   true,  true,  "market" },
    /* ── ZCL23 Game ── */
    { "zgame",        handle_game_msg,       true,  true,  "game" },
    /* ── ZCODE package swarm (slice 12; engine above net via hooks) ── */
    { "zpkgswm",      mp_handle_zcode_swarm, true,  true,  "zcode" },
    /* sentinel */
    { "",             NULL,                  false, false, NULL }
};

/* Snapshot/chunk/block/flyclient messages are dispatched separately
 * via mp_handle_zcl23_sync() because they share complex state.
 * Commands: zsnapshot, zsnapreq, zsnapdata, zsnapend,
 *           zfcchallenge, zfcproofs, zmanifest, zchunkreq, zchunkdata,
 *           zblkmanfst, zblkreq, zblkdata, zblkbitmap */

const struct msg_dispatch_entry *msg_get_dispatch_table(void)
{
    return g_msg_dispatch;
}

/* ── Lifecycle ────────────────────────────────────────────────── */

void msg_processor_init(struct msg_processor *mp,
                         struct main_state *ms,
                         struct tx_mempool *mempool,
                         struct coins_view_cache *coins_tip,
                         const struct chain_params *params,
                         const char *datadir,
                         struct net_manager *net_mgr,
                         const struct app_runtime_context *runtime)
{
    mp->main_state = ms;
    mp->mempool = mempool;
    mp->coins_tip = coins_tip;
    mp->params = params;
    /* Block bodies are served from <mp->datadir>/blocks/blkNNNNN.dat, but the
     * reducer persists them under the NET-SPECIFIC datadir, GetDataDir(true)
     * (=<base>/regtest on regtest; ==base on mainnet — see
     * reducer_ingest_service.c). Resolve net-specific here so the P2P serve
     * path opens the SAME directory the reducer wrote to. Passing the base
     * `datadir` made every getdata for a regtest-mined block answer
     * `notfound`, so a follower peer could never sync bodies (this is the
     * symmetric twin of the reducer write-path fix). On mainnet the two are
     * identical. The static buffer is process-lifetime (single node
     * instance) so the const char* mp->datadir stays valid for the run. */
    static char s_net_datadir[2048];
    GetDataDir(true, s_net_datadir, sizeof(s_net_datadir));
    mp->datadir = s_net_datadir[0] ? s_net_datadir : datadir;
    mp->net_mgr = net_mgr;
    mp->runtime = runtime;
    mp->block_submit = NULL;
    mp->block_submit_ctx = NULL;
    mp->compact_block_submit = NULL;
    mp->compact_block_submit_ctx = NULL;
    mp->peer_save = NULL;
    mp->peer_save_ctx = NULL;
    mp->zmsg_save = NULL;
    mp->zmsg_save_ctx = NULL;
    mp->file_offer_save = NULL;
    mp->file_offer_save_ctx = NULL;
    mp->file_payment_ingest = NULL;
    mp->file_payment_ingest_ctx = NULL;
    mp->file_service_save = NULL;
    mp->file_service_save_ctx = NULL;
    mp->snapshot_active = NULL;
    mp->snapshot_active_ctx = NULL;
    mp->snapshot_anchor_get = NULL;
    mp->snapshot_anchor_get_ctx = NULL;
    mp->snapshot_anchor_set = NULL;
    mp->snapshot_anchor_set_ctx = NULL;
    mp->activation_request = NULL;
    mp->activation_request_ctx = NULL;
    mp->activation_anchor_clear = NULL;
    mp->activation_anchor_clear_ctx = NULL;
    mp->post_activation_repair = NULL;
    mp->post_activation_repair_ctx = NULL;
    mp->block_file_scan = NULL;
    mp->block_file_scan_ctx = NULL;
    mp->block_index_heights_repaired = NULL;
    mp->block_index_heights_repaired_ctx = NULL;
    mp->header_tip_commit = NULL;
    mp->header_tip_commit_ctx = NULL;
    mp->snapshot_anchor_recommit = NULL;
    mp->snapshot_anchor_recommit_ctx = NULL;
    mp->wallet_tx_accepted = NULL;
    mp->wallet_tx_accepted_ctx = NULL;
    mp->block_connected = NULL;
    mp->block_connected_ctx = NULL;
    mp->peer_header_vote = NULL;
    mp->peer_header_vote_ctx = NULL;
    mp->flyclient_proof = NULL;
    mp->flyclient_proof_ctx = NULL;
    mp->block_hashes_range = NULL;
    mp->block_hashes_range_ctx = NULL;
    mp->utxo_sha3_compute = NULL;
    mp->utxo_sha3_compute_ctx = NULL;
    mp->block_intake = NULL;
    mp->zcode_swarm_frame = NULL;
    mp->zcode_swarm_tick = NULL;
    mp->zcode_swarm_ctx = NULL;

    /* Initialize download manager once (before threads start) */
    msg_get_download_mgr();

    /* tip-stall backpressure watchdog. Init seeds the stall
     * timer to "now" so we don't trip during startup; observers on
     * EV_BLOCK_CONNECTED + EV_TIP_UPDATED keep it warm thereafter. */
    tip_watchdog_init();
    {
        extern void msgprocessor_watchdog_tip_observer(
            enum event_type type, uint32_t peer_id,
            const void *payload, uint32_t payload_len, void *ctx);
        event_observe(EV_BLOCK_CONNECTED,
                      msgprocessor_watchdog_tip_observer, NULL);
        event_observe(EV_TIP_UPDATED,
                      msgprocessor_watchdog_tip_observer, NULL);
    }

    /* Initialize Dandelion++ tx propagation */
    if (!g_dandelion_init) {
        dandelion_init(&g_dandelion);
        g_dandelion_init = true;
    }

    /* Snapshot/fast-sync init: builds the initial block piece manifest
     * if we have a chain to publish. */
    mp_snapshot_init(mp);
}

void msg_processor_set_compact_block_submit(
    struct msg_processor *mp,
    msg_compact_block_submit_fn submit,
    void *ctx)
{
    if (!mp)
        return;
    mp->compact_block_submit = submit;
    mp->compact_block_submit_ctx = ctx;
}

void msg_processor_set_block_submit(struct msg_processor *mp,
                                    msg_block_submit_fn submit,
                                    void *ctx)
{
    if (!mp)
        return;
    mp->block_submit = submit;
    mp->block_submit_ctx = ctx;
}

void msg_processor_set_catchup_drain(struct msg_processor *mp,
                                     msg_catchup_drain_fn drain,
                                     void *ctx)
{
    if (!mp)
        return;
    mp->catchup_drain = drain;
    mp->catchup_drain_ctx = ctx;
}

void msg_processor_set_catchup_batch_scope(
    struct msg_processor *mp,
    msg_catchup_batch_scope_fn begin,
    msg_catchup_batch_scope_fn end,
    void *ctx)
{
    if (!mp)
        return;
    mp->catchup_batch_begin = begin;
    mp->catchup_batch_end = end;
    mp->catchup_batch_scope_ctx = ctx;
}

void msg_processor_set_peer_save(struct msg_processor *mp,
                                 msg_peer_save_fn save,
                                 void *ctx)
{
    if (!mp)
        return;
    mp->peer_save = save;
    mp->peer_save_ctx = ctx;
}

void msg_processor_set_zmsg_save(struct msg_processor *mp,
                                 msg_zmsg_save_fn save,
                                 void *ctx)
{
    if (!mp)
        return;
    mp->zmsg_save = save;
    mp->zmsg_save_ctx = ctx;
}

void msg_processor_set_file_offer_save(struct msg_processor *mp,
                                       msg_file_offer_save_fn save,
                                       void *ctx)
{
    if (!mp)
        return;
    mp->file_offer_save = save;
    mp->file_offer_save_ctx = ctx;
}

void msg_processor_set_file_payment_ingest(
    struct msg_processor *mp, msg_file_payment_ingest_fn ingest, void *ctx)
{
    if (!mp)
        return;
    mp->file_payment_ingest = ingest;
    mp->file_payment_ingest_ctx = ctx;
}

void msg_processor_set_file_service_save(struct msg_processor *mp,
                                         msg_file_service_save_fn save,
                                         void *ctx)
{
    if (!mp)
        return;
    mp->file_service_save = save;
    mp->file_service_save_ctx = ctx;
}

void msg_processor_set_zswap_ad_save(struct msg_processor *mp,
                                     msg_zswap_ad_save_fn save,
                                     void *ctx)
{
    if (!mp)
        return;
    mp->zswap_ad_save = save;
    mp->zswap_ad_save_ctx = ctx;
}

void msg_processor_set_zswap_ad_ingest(struct msg_processor *mp,
                                       msg_zswap_ad_ingest_fn ingest,
                                       void *ctx)
{
    if (!mp)
        return;
    mp->zswap_ad_ingest = ingest;
    mp->zswap_ad_ingest_ctx = ctx;
}

void msg_processor_set_zswap_accept_ingest(
    struct msg_processor *mp,
    msg_zswap_accept_ingest_fn ingest,
    void *ctx)
{
    if (!mp)
        return;
    mp->zswap_accept_ingest = ingest;
    mp->zswap_accept_ingest_ctx = ctx;
}

void msg_processor_set_zswap_partial_ingest(
    struct msg_processor *mp,
    msg_zswap_partial_ingest_fn ingest,
    void *ctx)
{
    if (!mp)
        return;
    mp->zswap_partial_ingest = ingest;
    mp->zswap_partial_ingest_ctx = ctx;
}

void msg_processor_set_snapshot_active(struct msg_processor *mp,
                                       msg_snapshot_active_fn active,
                                       void *ctx)
{
    if (!mp)
        return;
    mp->snapshot_active = active;
    mp->snapshot_active_ctx = ctx;
}

void msg_processor_set_snapshot_anchor_accessors(
    struct msg_processor *mp,
    msg_snapshot_anchor_get_fn get_anchor,
    void *get_ctx,
    msg_snapshot_anchor_set_fn set_anchor,
    void *set_ctx)
{
    if (!mp)
        return;
    mp->snapshot_anchor_get = get_anchor;
    mp->snapshot_anchor_get_ctx = get_ctx;
    mp->snapshot_anchor_set = set_anchor;
    mp->snapshot_anchor_set_ctx = set_ctx;
}

void msg_processor_set_activation_hooks(
    struct msg_processor *mp,
    msg_activation_request_fn request,
    void *request_ctx,
    msg_activation_anchor_clear_fn clear_anchor,
    void *clear_ctx,
    msg_post_activation_repair_fn repair,
    void *repair_ctx)
{
    if (!mp)
        return;
    mp->activation_request = request;
    mp->activation_request_ctx = request_ctx;
    mp->activation_anchor_clear = clear_anchor;
    mp->activation_anchor_clear_ctx = clear_ctx;
    mp->post_activation_repair = repair;
    mp->post_activation_repair_ctx = repair_ctx;
}

void msg_processor_set_header_index_hooks(
    struct msg_processor *mp,
    msg_block_file_scan_fn scan,
    void *scan_ctx,
    msg_block_index_heights_repaired_fn heights_repaired,
    void *heights_repaired_ctx)
{
    if (!mp)
        return;
    mp->block_file_scan = scan;
    mp->block_file_scan_ctx = scan_ctx;
    mp->block_index_heights_repaired = heights_repaired;
    mp->block_index_heights_repaired_ctx = heights_repaired_ctx;
}

void msg_processor_set_header_chainstate_hooks(
    struct msg_processor *mp,
    msg_header_tip_commit_fn commit_header_tip,
    void *commit_header_tip_ctx,
    msg_snapshot_anchor_recommit_fn recommit_anchor,
    void *recommit_anchor_ctx)
{
    if (!mp)
        return;
    mp->header_tip_commit = commit_header_tip;
    mp->header_tip_commit_ctx = commit_header_tip_ctx;
    mp->snapshot_anchor_recommit = recommit_anchor;
    mp->snapshot_anchor_recommit_ctx = recommit_anchor_ctx;
}

void msg_processor_set_wallet_tx_accepted(
    struct msg_processor *mp,
    msg_wallet_tx_accepted_fn accepted,
    void *ctx)
{
    if (!mp)
        return;
    mp->wallet_tx_accepted = accepted;
    mp->wallet_tx_accepted_ctx = ctx;
}

void msg_processor_set_block_connected(
    struct msg_processor *mp,
    msg_block_connected_fn connected,
    void *ctx)
{
    if (!mp)
        return;
    mp->block_connected = connected;
    mp->block_connected_ctx = ctx;
}

void msg_processor_set_peer_header_vote(
    struct msg_processor *mp,
    msg_peer_header_vote_fn vote,
    void *ctx)
{
    if (!mp)
        return;
    mp->peer_header_vote = vote;
    mp->peer_header_vote_ctx = ctx;
}

void msg_processor_set_flyclient_proof_builder(
    struct msg_processor *mp,
    msg_flyclient_proof_fn build,
    void *ctx)
{
    if (!mp)
        return;
    mp->flyclient_proof = build;
    mp->flyclient_proof_ctx = ctx;
}

void msg_processor_set_block_hashes_range(
    struct msg_processor *mp,
    msg_block_hashes_range_fn load,
    void *ctx)
{
    if (!mp)
        return;
    mp->block_hashes_range = load;
    mp->block_hashes_range_ctx = ctx;
}

void msg_processor_set_utxo_sha3_compute(
    struct msg_processor *mp,
    msg_utxo_sha3_compute_fn compute,
    void *ctx)
{
    if (!mp)
        return;
    mp->utxo_sha3_compute = compute;
    mp->utxo_sha3_compute_ctx = ctx;
}

bool msg_processor_snapshot_active(const struct msg_processor *mp)
{
    return mp && mp->snapshot_active &&
           mp->snapshot_active(mp->snapshot_active_ctx);
}

struct block_index *msg_processor_snapshot_anchor(const struct msg_processor *mp)
{
    if (!mp || !mp->snapshot_anchor_get)
        return NULL;
    return mp->snapshot_anchor_get(mp->snapshot_anchor_get_ctx);
}

void msg_processor_set_snapshot_anchor(const struct msg_processor *mp,
                                       struct block_index *anchor)
{
    if (mp && mp->snapshot_anchor_set)
        mp->snapshot_anchor_set(anchor, mp->snapshot_anchor_set_ctx);
}

void msg_processor_request_activation(const struct msg_processor *mp,
                                      enum msg_activation_request_source source)
{
    if (mp && mp->activation_request)
        mp->activation_request(source, mp->activation_request_ctx);
}

void msg_processor_clear_activation_anchor(const struct msg_processor *mp,
                                           const char *reason)
{
    if (mp && mp->activation_anchor_clear)
        mp->activation_anchor_clear(reason, mp->activation_anchor_clear_ctx);
}

void msg_processor_repair_post_activation_anchor(const struct msg_processor *mp)
{
    if (mp && mp->post_activation_repair)
        mp->post_activation_repair(mp->post_activation_repair_ctx);
}

int msg_processor_scan_block_files(const struct msg_processor *mp)
{
    if (!mp || !mp->block_file_scan)
        return 0;
    return mp->block_file_scan(mp->block_file_scan_ctx);
}

bool msg_processor_block_index_heights_repaired(const struct msg_processor *mp)
{
    return mp && mp->block_index_heights_repaired &&
           mp->block_index_heights_repaired(mp->block_index_heights_repaired_ctx);
}

bool msg_processor_commit_header_tip(const struct msg_processor *mp,
                                     struct block_index *header_tip)
{
    if (mp && mp->header_tip_commit)
        return mp->header_tip_commit(header_tip, mp->header_tip_commit_ctx);
#ifdef ZCL_TESTING
    if (mp && mp->main_state && header_tip) {
        mp->main_state->pindex_best_header = header_tip;
        return true;
    }
#endif
    return false;
}

bool msg_processor_recommit_snapshot_anchor(const struct msg_processor *mp,
                                            struct block_index *anchor,
                                            int from_height)
{
    if (mp && mp->snapshot_anchor_recommit)
        return mp->snapshot_anchor_recommit(
            anchor, from_height, mp->snapshot_anchor_recommit_ctx);
    return false;
}

void msg_processor_note_block_connected(const struct msg_processor *mp,
                                        int height)
{
    if (mp && mp->block_connected)
        mp->block_connected(height, mp->block_connected_ctx);
}

void msg_processor_record_peer_header_vote(const struct msg_processor *mp,
                                           uint32_t peer_id,
                                           int height,
                                           const char hash_hex[65])
{
    if (mp && mp->peer_header_vote)
        mp->peer_header_vote(peer_id, height, hash_hex,
                             mp->peer_header_vote_ctx);
}

void msg_processor_request_invalid_block_headers(struct msg_processor *mp,
                                                 struct p2p_node *node)
{
    struct sync_getheaders_action action = {0};

    syncsvc_plan_invalid_block_getheaders(&action, sync_get_state());
    exec_getheaders_action(mp, node, &action);
}

static int msg_processor_acceptance_peer_height(
    const struct msg_processor *mp,
    const struct p2p_node *node,
    int tip_height)
{
    int max_height = tip_height;

    if (mp && mp->main_state && mp->main_state->pindex_best_header &&
        mp->main_state->pindex_best_header->nHeight > max_height) {
        max_height = mp->main_state->pindex_best_header->nHeight;
    }
    if (node && node->starting_height > max_height)
        max_height = node->starting_height;
    return max_height;
}

void msg_processor_plan_valid_block_acceptance(
    struct msg_block_acceptance *out,
    const struct msg_processor *mp,
    const struct p2p_node *node,
    const struct block_index *new_tip)
{
    struct msg_block_acceptance empty = {0};
    struct sync_block_acceptance acceptance;

    if (!out)
        return;
    *out = empty;
    if (!mp || !mp->main_state || !node || !new_tip)
        return;

    int header_height = mp->main_state->pindex_best_header
        ? mp->main_state->pindex_best_header->nHeight
        : new_tip->nHeight;
    syncsvc_note_valid_block(&acceptance, node, sync_get_state(),
                             new_tip->nHeight, header_height, new_tip->nTime,
                             msg_processor_acceptance_peer_height(
                                 mp, node, new_tip->nHeight),
                             body_history_status_now());

    out->reached_peer_tip = acceptance.reached_peer_tip;
    out->should_emit_tip_updated = acceptance.should_emit_tip_updated;
    out->should_set_sync_state = acceptance.should_set_sync_state;
    out->next_sync_state = acceptance.next_sync_state;
    out->should_set_flush_policy = acceptance.should_set_flush_policy;
    out->should_update_peer_state = acceptance.should_update_peer_state;
    out->next_peer_state = acceptance.next_peer_state;
}

int msg_get_height(void *ctx)
{
    struct msg_processor *mp = (struct msg_processor *)ctx;
    return active_chain_height(&mp->main_state->chain_active);
}

/* ── msg_process_messages: dispatch loop ─────────────────────── */

bool msg_process_messages(void *ctx, struct p2p_node *node)
{
    struct msg_processor *mp = (struct msg_processor *)ctx;

    /* tip-stall watchdog state-machine tick. Cheap (a couple of
     * atomics + one stat read on the download manager). One tick per
     * peer per cycle is plenty — state transitions happen on second-
     * scale, not per-message scale. */
    tip_watchdog_tick();

    /* ZCODE package swarm (slice 12): peer-membership sync + scheduler
     * tick + outbound drain for THIS node, when the engine is wired. */
    if (mp->zcode_swarm_tick)
        mp->zcode_swarm_tick(mp, node, mp->zcode_swarm_ctx);

    size_t processed = 0;
    while (!node->disconnect &&
           processed < ZCL_MSG_PROCESS_MAX_PER_CYCLE) {
        zcl_mutex_lock(&node->cs_recv);
        if (node->recv_msg_count == 0 ||
            !net_message_complete(&node->recv_msgs[0])) {
            zcl_mutex_unlock(&node->cs_recv);
            break;
        }

        struct net_message msg = node->recv_msgs[0];
        memmove(&node->recv_msgs[0], &node->recv_msgs[1],
                (node->recv_msg_count - 1) * sizeof(struct net_message));
        node->recv_msg_count--;
        zcl_mutex_unlock(&node->cs_recv);
        processed++;

        /* Verify message checksum (first 4 bytes of double-SHA256) */
        struct uint256 msg_hash;
        hash256(msg.recv_data ? msg.recv_data : (const unsigned char *)"",
                msg.data_pos, msg_hash.data);
        unsigned int expected;
        memcpy(&expected, msg_hash.data, 4);
        if (expected != msg.hdr.nChecksum) {
            char ccmd[COMMAND_SIZE + 1];
            msg_header_get_command(&msg.hdr, ccmd, sizeof(ccmd));
            event_emitf(EV_MSG_CHECKSUM_FAIL, (uint32_t)node->id,
                        "%s size=%u exp=%08x got=%08x",
                        ccmd, msg.hdr.nMessageSize,
                        expected, msg.hdr.nChecksum);
            LOG_WARN("net", "peer %s: checksum mismatch on '%s' (size=%u exp=%08x got=%08x)",
                     node->addr_name, ccmd, msg.hdr.nMessageSize,
                     expected, msg.hdr.nChecksum);
            net_message_free(&msg);
            continue;
        }

        char cmd[COMMAND_SIZE + 1];
        msg_header_get_command(&msg.hdr, cmd, sizeof(cmd));

        /* Log every message received */
        event_emitf(EV_MSG_RECEIVED, (uint32_t)node->id,
                    "%s size=%u", cmd, msg.hdr.nMessageSize);

        if (net_partition_active_at((int64_t)platform_time_wall_time_t())) {
            event_emitf(EV_BACKPRESSURE_REJECT, (uint32_t)node->id,
                        "cmd=%s reason=partition", cmd);
            net_message_free(&msg);
            continue;
        }

        struct byte_stream s;
        stream_init_from_data(&s, msg.recv_data, msg.data_pos);

        /* post-parse pre-dispatch backpressure rejection.
         * When the watchdog is active we drop inv + block messages
         * without dispatching the handler — emits EV_BACKPRESSURE_REJECT
         * but does not bump ban-score. */
        if (tip_watchdog_should_reject((uint32_t)node->id, cmd)) {
            stream_free(&s);
            net_message_free(&msg);
            continue;
        }

        bool ok = true;

        /* ── Dispatch via table ──────────────────────────────── */
        bool dispatched = false;
        for (const struct msg_dispatch_entry *e = g_msg_dispatch;
             e->handler; e++) {
            if (strcmp(cmd, e->command) != 0)
                continue;

            if (e->requires_handshake && node->version == 0) {
                printf("Peer %s: received %s before version\n",
                       node->addr_name, cmd);
                (void)p2p_node_request_disconnect(
                    node, P2P_DISCONNECT_PROTOCOL_VIOLATION,
                    P2P_DISCONNECT_SOURCE_MESSAGE_HANDLER,
                    node->endpoint_generation);
                stream_free(&s);
                net_message_free(&msg);
                goto _msg_loop_exit;
            }
            if (e->zcl23_only && !peer_supports_fast_sync(node->services)) {
                event_emitf(EV_BACKPRESSURE_REJECT, (uint32_t)node->id,
                            "%s requires NODE_ZCL23", cmd);
                printf("Peer %s: ignoring ZCL23-only %s without NODE_ZCL23\n",
                       node->addr_name, cmd);
                ok = true;
                dispatched = true;
                break;
            }

            ok = e->handler(mp, node, &s);
            dispatched = true;
            break;
        }

        /* ZCL23 sync messages handled by a combined handler */
        if (!dispatched && cmd[0] == 'z') {
            if (node->version == 0) {
                printf("Peer %s: received %s before version\n",
                       node->addr_name, cmd);
                (void)p2p_node_request_disconnect(
                    node, P2P_DISCONNECT_PROTOCOL_VIOLATION,
                    P2P_DISCONNECT_SOURCE_MESSAGE_HANDLER,
                    node->endpoint_generation);
                stream_free(&s);
                net_message_free(&msg);
                goto _msg_loop_exit;
            }
            if (!peer_supports_fast_sync(node->services)) {
                event_emitf(EV_BACKPRESSURE_REJECT, (uint32_t)node->id,
                            "%s requires NODE_ZCL23", cmd);
                printf("Peer %s: ignoring ZCL23-only %s without NODE_ZCL23\n",
                       node->addr_name, cmd);
                dispatched = true;
                ok = true;
                stream_free(&s);
                net_message_free(&msg);
                continue;
            }
            if (strcmp(cmd, MSG_CHUNK_REQ) == 0)
                printf("Peer %s: dispatch %s size=%u\n",
                       node->addr_name, cmd, msg.hdr.nMessageSize);
            ok = mp_handle_zcl23_sync(mp, node, &s, cmd);
            dispatched = true;
        }

        /* Reject any pre-handshake message not in the table */
        if (!dispatched && node->version == 0) {
            printf("Peer %s: received %s before version\n",
                   node->addr_name, cmd);
            (void)p2p_node_request_disconnect(
                node, P2P_DISCONNECT_PROTOCOL_VIOLATION,
                P2P_DISCONNECT_SOURCE_MESSAGE_HANDLER,
                node->endpoint_generation);
            stream_free(&s);
            net_message_free(&msg);
            goto _msg_loop_exit;
        }

        stream_free(&s);
        net_message_free(&msg);

        if (!ok) {
            printf("Peer %s: error processing %s\n", node->addr_name, cmd);
        }
    }
    _msg_loop_exit:
    return true;
}

/* ── msg_send_messages: per-peer trickle ─────────────────────── */

bool msg_send_messages(void *ctx, struct p2p_node *node, bool send_trickle)
{
    struct msg_processor *mp = (struct msg_processor *)ctx;
    bool snapshot_active = mp_snapshot_is_active();

    /* Outbound nodes: send version to initiate handshake */
    if (node->state < PEER_HANDSHAKE_COMPLETE) {
        /* A Noise initiator has already sent its 32-byte msg1 before the
         * message loop sees the node, so send_bytes is not a handshake-state
         * predicate.  PEER_CONNECTING is: advance it exactly once after the
         * version has been queued (or buffered by the transport). */
        if (!node->inbound && node->state == PEER_CONNECTING) {
            push_version(mp, node);
            peer_set_state_checked((uint32_t)node->id, &node->state,
                                   PEER_VERSION_SENT, "outbound version sent");
        }
        return true;
    }

    /* Transition to ACTIVE if still at HANDSHAKE_COMPLETE */
    if (node->state == PEER_HANDSHAKE_COMPLETE) {
        peer_set_state_checked((uint32_t)node->id, &node->state,
                               PEER_ACTIVE, "ready for sync");
        peer_lifecycle_note_active(node);
    }

    /* Offer fast sync to ZCL23 peers that are behind us */
    mp_snapshot_maybe_offer(mp, node);

    /* Snapshot stall detection — if no chunk for 60s, reset and accept new peer */
    if (mp_snapshot_check_stall()) {
        printf("[sync] Snapshot stall detected — will accept new offer\n");
    }

    /* Initiate sync, and periodically re-request if behind. */
    {
        int our_height = msg_get_height(mp);
        int best_header_height = mp->main_state->pindex_best_header
            ? mp->main_state->pindex_best_header->nHeight
            : our_height;
        bool should_sync = syncsvc_begin_peer_sync(node, our_height,
                                                   best_header_height);
        struct sync_getheaders_action periodic = {0};

        bool in_ibd = syncsvc_is_initial_block_download(node, our_height);
        int64_t now_send = (int64_t)platform_time_wall_time_t();

        if (syncsvc_should_mark_peer_caught_up(node, our_height,
                                               best_header_height)) {
            peer_set_state_checked((uint32_t)node->id, &node->state,
                                   PEER_ACTIVE, "headers caught up");
        }

        /* ── Track pindex_best_header advance for stall detection ── */
        {
            int best_h = mp->main_state->pindex_best_header
                       ? mp->main_state->pindex_best_header->nHeight : 0;
            if (best_h > g_header_stall_last_height) {
                g_header_stall_last_height = best_h;
                g_header_stall_last_advance = now_send;
            }
            if (g_header_stall_last_advance == 0)
                g_header_stall_last_advance = now_send;
        }

        bool header_stall = syncsvc_is_header_sync_stalled(
            sync_get_state(), g_header_stall_last_height,
            g_header_stall_last_advance, now_send);

        /* ── Zero-outbound recovery ──────────────────────────────
         * If we have ONLY inbound peers and are behind, the normal
         * sync path never fires (syncsvc_begin_peer_sync rejects
         * inbound peers) and sync state never reaches
         * SYNC_HEADERS_DOWNLOAD, so stall detection never triggers.
         * Fix: when all peers are inbound and we're behind, force
         * the sync state transition and treat it as a stall so
         * inbound peers can serve headers. */
        if (!mp_swarm_is_active() &&
            !header_stall && node->inbound &&
            node->starting_height > our_height + 144) {
            bool have_outbound = false;
            zcl_mutex_lock(&mp->net_mgr->cs_nodes);
            for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
                if (!mp->net_mgr->nodes[pi]->inbound &&
                    !mp->net_mgr->nodes[pi]->disconnect &&
                    mp->net_mgr->nodes[pi]->state >= PEER_ACTIVE) {
                    have_outbound = true;
                    break;
                }
            }
            zcl_mutex_unlock(&mp->net_mgr->cs_nodes);

            if (!have_outbound) {
                enum sync_state ss = sync_get_state();
                if (ss == SYNC_IDLE || ss == SYNC_FINDING_PEERS) {
                    sync_set_state(SYNC_HEADERS_DOWNLOAD,
                                   "no outbound peers, using inbound");
                }
                header_stall = true;
            }
        }

        /* ── Stale-header disconnect rules A and B ─────────────────
         *
         * P3: trusted peers are exempt from BOTH rules — localhost is
         * unspoofable (the co-located zclassicd lifeline) and the
         * whitelist is explicit operator intent; same predicate as the
         * misbehavior ban exemption (is_trusted_peer, net.c). Remote
         * default peers keep full stall discipline.
         *
         * P2 (rule B below): skip eviction at frontier parity — when
         * our header frontier has reached the peer's claimed tip, no
         * peer can be "useful" by construction (new headers arrive at
         * ~150s block cadence), so evicting the worst peer is pure
         * churn. node->starting_height is handshake-static, so the
         * parity gate progressively relaxes stale-header discipline
         * for long-lived peers as the chain grows past their
         * connect-time claim — accepted consciously given IBD gating,
         * the loopback lifeline, rule B's per-stall-cycle rotation,
         * and the peer-floor conditions. */
        bool stall_peer_trusted = net_addr_is_local(&node->addr.svc.addr) ||
                                  node->whitelisted;
        bool header_frontier_at_peer_tip =
            node->starting_height > 0 &&
            best_header_height >= node->starting_height - 144;

        /* ── Rule A: per-peer stale header disconnect (IBD only) ── */
        if (!mp_swarm_is_active() && !stall_peer_trusted &&
            syncsvc_should_disconnect_stale_header_peer(node, our_height,
                                                        best_header_height,
                                                        now_send)) {
            int64_t last_useful = atomic_load_explicit(
                &node->last_useful_headers_time, memory_order_relaxed);
            printf("HEADER STALL: peer %s delivered 0 useful headers in "
                   "%llds (total_delivered=%llu), disconnecting\n",
                   node->addr_name,
                   (long long)(now_send - (last_useful
                       ? last_useful
                       : node->time_connected)),
                   (unsigned long long)node->total_headers_delivered);
            (void)p2p_node_request_disconnect(
                node, P2P_DISCONNECT_SYNC_STALL,
                P2P_DISCONNECT_SOURCE_SYNC, node->endpoint_generation);
            return true;
        }

        /* ── Rule B: header sync stall — disconnect worst outbound
         * peer. Skipped for trusted peers (P3) and at frontier parity
         * (P2) — see the comment block above rule A. */
        if (!mp_swarm_is_active() && !stall_peer_trusted &&
            !header_frontier_at_peer_tip &&
            header_stall && !node->inbound &&
            node->state >= PEER_SYNCING_HEADERS) {
            /* grace period for fresh peers.
             *
             * Without this, a header stall disconnects EVERY outbound
             * peer with total_delivered=0 on the same tick (the old
             * `<=` comparison plus a per-second reset of worst_delivered
             * meant the first 5 peers in the loop all matched
             * worst_delivered=0 and all got the disconnect flag). The
             * peers reconnect immediately and the cycle repeats —
             * net effect: outbound peers churn forever and never get
             * to deliver headers. Live evidence: 5 ESTAB sockets to
             * seed peers, all stuck at state=connecting after the
             * disconnect/reconnect loop.
             *
             * Fix: give every newly-connected outbound peer 60s
             * before they're eligible for stall-disconnect, and
             * disconnect at most ONE peer per stall cycle (strict
             * `<` + return after the first match). */
            const int64_t GRACE_SECS = 60;
            int64_t connected_for =
                now_send - (node->time_connected ? node->time_connected
                                                 : now_send);
            if (connected_for < GRACE_SECS)
                goto skip_stall_disconnect;

            /* Log stall once per detection cycle */
            static int64_t last_stall_log = 0;
            if (now_send - last_stall_log >= 30) {
                last_stall_log = now_send;
                printf("HEADER STALL: best_header stuck at %d for %llds, "
                       "disconnecting worst peer\n",
                       g_header_stall_last_height,
                       (long long)(now_send - g_header_stall_last_advance));
            }
            /* Find if this peer is the worst outbound by headers delivered.
             * Strict `<` so a single tick disconnects at most one peer
             * even when many tie at total_headers_delivered=0. */
            static uint64_t worst_delivered = UINT64_MAX;
            static int64_t worst_check_time = 0;
            if (now_send != worst_check_time) {
                worst_delivered = UINT64_MAX;
                worst_check_time = now_send;
            }
            if (node->total_headers_delivered < worst_delivered) {
                worst_delivered = node->total_headers_delivered;
                printf("HEADER STALL: disconnecting %s "
                       "(total_headers_delivered=%llu, connected_for=%llds)\n",
                       node->addr_name,
                       (unsigned long long)node->total_headers_delivered,
                       (long long)connected_for);
                (void)p2p_node_request_disconnect(
                    node, P2P_DISCONNECT_SYNC_STALL,
                    P2P_DISCONNECT_SOURCE_SYNC, node->endpoint_generation);
                return true;
            }
        }
        skip_stall_disconnect:;

        /* ── Rule C: body-download stall — disconnect a peer that serves
         * headers but never delivers block bodies. It passes rules A/B (it
         * keeps delivering headers, so total_headers_delivered climbs and
         * last_useful_headers_time refreshes) yet holds an outbound slot
         * forever while the body cursor never advances — the measured
         * "connected peer delivers no block data" wedge. Trusted/loopback
         * peers (the co-located zclassicd lifeline) and inbound peers are
         * exempt, exactly like rules A/B. Disconnecting lets connman fail
         * over to a peer that will serve bodies. Fires only after the peer
         * has had SYNC_BODY_STALL_MIN_TIMEOUTS block requests time out with
         * zero bodies delivered over a full stall window (predicate). */
        if (!mp_swarm_is_active() && !snapshot_active && !stall_peer_trusted &&
            !node->inbound && node->state >= PEER_SYNCING_HEADERS) {
            uint64_t body_recv = 0, body_timeout = 0;
            dl_peer_body_progress(get_download_mgr(), (uint32_t)node->id,
                                  NULL, &body_recv, &body_timeout);
            if (syncsvc_should_disconnect_body_stalled_peer(
                    node, our_height, body_recv, body_timeout, now_send)) {
                printf("BODY STALL: peer %s delivered 0 block bodies "
                       "(%llu getdata timed out) in %llds, disconnecting\n",
                       node->addr_name,
                       (unsigned long long)body_timeout,
                       (long long)(now_send - (node->time_connected
                           ? node->time_connected : now_send)));
                (void)p2p_node_request_disconnect(
                    node, P2P_DISCONNECT_SYNC_STALL,
                    P2P_DISCONNECT_SOURCE_SYNC, node->endpoint_generation);
                return true;
            }
        }

        /* ── Rule D: delivered-then-dark body stall — the complement of
         * Rule C. Rule C exempts any peer with body_received > 0, so a peer
         * that serves a few bodies and then goes silent holds its outbound
         * slot forever while the body cursor never advances again (and
         * DL_STALL_TIMEOUT_SECS, the download manager's own stall constant,
         * was defined-but-unenforced). This evicts it once its last body is
         * >= the stall window old AND it has accrued the same timed-out floor
         * Rule C uses, so connman fails over to a peer that keeps serving
         * bodies. The body_received > 0 (Rule D) vs == 0 (Rule C) split makes
         * the two mutually exclusive — no peer is double-evicted. Same
         * trusted/loopback/inbound exemptions as rules A/B/C. */
        if (!mp_swarm_is_active() && !snapshot_active && !stall_peer_trusted &&
            !node->inbound && node->state >= PEER_SYNCING_HEADERS) {
            uint64_t dark_recv = 0, dark_timeout = 0;
            int64_t dark_last_body = 0;
            dl_peer_body_staleness(get_download_mgr(), (uint32_t)node->id,
                                   &dark_recv, &dark_timeout, &dark_last_body);
            if (syncsvc_should_disconnect_body_dark_peer(
                    node, our_height, dark_recv, dark_timeout,
                    dark_last_body, now_send)) {
                printf("BODY DARK: peer %s delivered %llu block bodies then "
                       "went silent %llds (%llu getdata timed out), "
                       "disconnecting\n",
                       node->addr_name,
                       (unsigned long long)dark_recv,
                       (long long)(now_send - dark_last_body),
                       (unsigned long long)dark_timeout);
                (void)p2p_node_request_disconnect(
                    node, P2P_DISCONNECT_SYNC_STALL,
                    P2P_DISCONNECT_SOURCE_SYNC, node->endpoint_generation);
                return true;
            }
        }

        /* Re-request headers aggressively during IBD (10s), slower at tip (60s).
         * This is critical: legacy zclassicd sends at most 2000 headers per
         * getheaders response — for a 3M block chain, we need ~1500 rounds. */

        /* Use fallback (inbound peers) during header stall */
        if (header_stall) {
            bool ok = syncsvc_should_request_headers_with_fallback(
                node, our_height, now_send, true);
            if (ok && !snapshot_active) {
                should_sync = true;
                syncsvc_note_headers_requested(node, now_send);
            }
        }
        if (!snapshot_active) {
            syncsvc_plan_periodic_getheaders(&periodic, node, our_height,
                                             now_send);
            if (periodic.should_send) {
                should_sync = true;
                syncsvc_note_headers_requested(node, now_send);
            }
        }

        /* All-rejected (bad-prevblk) recovery probe continuation. The
         * receive-side probe (process_headers, msg_headers.c) fires once
         * per all-rejected batch, but when the announcement burst ends no
         * incoming message remains to trigger it and the peer's real tip is
         * never learned (rejected headers carry no height we accept). While
         * reject_probe_pending is armed, re-fire from this periodic per-peer
         * tick under the same per-peer rate limit until a batch connects
         * again (any accepted header disarms it). */
        if (!snapshot_active &&
            syncsvc_should_fire_reject_probe(node, now_send)) {
            atomic_store_explicit(&node->last_reject_probe_time, now_send,
                                  memory_order_relaxed);
            printf("Peer %s: reject-probe pending — re-probing with "
                   "getheaders from our best header h=%d\n",
                   node->addr_name, best_header_height);
            push_getheaders_from(mp, node,
                                 mp->main_state->pindex_best_header);
        }
        if (should_sync && !snapshot_active) {
            struct block_index *tip = active_chain_tip(
                &mp->main_state->chain_active);
            switch (syncsvc_header_log_mode(node, tip, in_ibd)) {
            case SYNC_HEADER_LOG_IBD:
                printf("IBD getheaders to %s (height=%d, peer=%d, "
                       "behind=%d)\n",
                       node->addr_name, tip->nHeight,
                       node->starting_height,
                       node->starting_height - tip->nHeight);
                break;
            case SYNC_HEADER_LOG_TIP:
                printf("Sending getheaders to %s (height=%d, peer=%d)\n",
                       node->addr_name, tip->nHeight,
                       node->starting_height);
                break;
            case SYNC_HEADER_LOG_NONE:
            default:
                break;
            }
            /* NET-3 range-parallel header acquisition: when >=2 fast-sync
             * peers are connected and the header gap exceeds one batch,
             * give this peer its own disjoint checkpoint-anchored span
             * instead of racing every peer for the same next batch. Returns
             * false (leaving the single-peer path below untouched) for a
             * single peer, a small gap, a legacy peer, or an open header
             * band — so existing behavior is a strict regression-safe
             * fallback. Validation and band closure are unchanged; this
             * only changes WHICH peer is asked for WHICH range. */
            if (!msg_try_range_parallel_getheaders(mp, node, our_height,
                                                   now_send))
                exec_getheaders_action(mp, node, &periodic);
        }

        /* Checkpoint-header-solution cure: when the app-layer repair condition
         * has armed a fetch (a staged checkpoint bundle needs the one missing
         * checkpoint-header Equihash solution), send ONE bounded getheaders span
         * to this peer so it returns exactly that header. Cheap no-op when not
         * armed; globally throttled so only one request goes out per interval. */
        if (!snapshot_active)
            checkpoint_header_fetch_maybe_send(mp, node, now_send);
    }

    /* ── Download manager: assign queued blocks to this peer ────── */
    {
        struct download_manager *dm = get_download_mgr();
        int64_t now_dl = (int64_t)platform_time_wall_time_t();
        bool block_swarm_active = mp_block_swarm_is_active();
        /* A swarm whose piece completions have gone silent would otherwise
         * hold body transfer forever: its only exit was full completion,
         * and legacy getdata stays paused while it is active. Reap it so
         * the height-sorted legacy queue (frontier at the front) resumes.
         * No-op at tip, where no swarm exists. */
        if (block_swarm_active && mp_block_swarm_reap_if_stalled(mp))
            block_swarm_active = false;

        /* During ZCL23 block-swarm catch-up, zblkreq/zblkdata owns body
         * transfer. Letting legacy getdata run at the same time fills the
         * peer window with duplicate requests and timeout churn, slowing the
         * fast path. Leave queued legacy work untouched; it resumes if the
         * swarm finishes or never starts. */
        if (!block_swarm_active) {
            size_t timed_out = dl_check_timeouts(dm, now_dl);
            if (timed_out > 0)
                event_emitf(EV_BLOCK_REQUESTED, 0,
                            "timeouts=%zu reassigned to queue", timed_out);
        }

        /* Snapshot receive owns catch-up while active. Normal block assignment,
         * stall recovery, and recovery getheaders only add churn until the
         * verified snapshot handoff is complete. */
        if (!snapshot_active && !block_swarm_active) {
            struct uint256 assign_hashes[DL_WINDOW_SIZE];
            struct sync_block_batch batch;
            /* our_height for the behind-peer gate (sibling scope; recompute
             * the same way as the sync block above, msgprocessor.c:1330). */
            int our_height = msg_get_height(mp);
            /* Request no more bodies than the intake ring can still absorb:
             * the surplus is received, destroyed, and re-requested on a 15 s
             * timeout. dl_inflight is read BEFORE assignment on purpose. */
            uint64_t inflight_now = 0;
            dl_get_stats(dm, NULL, NULL, NULL, &inflight_now, NULL);
            size_t assign_room = msg_processor_block_intake_request_room(
                mp, inflight_now, DL_WINDOW_SIZE);
            if (assign_room == 0) {
                memset(&batch, 0, sizeof(batch));
                msg_processor_log_block_intake_backpressure(node);
            } else {
                syncsvc_assign_peer_blocks(&batch, dm, node, assign_hashes,
                                           assign_room, our_height);
            }
            if (batch.assigned > 0) {
                struct byte_stream getdata_msg;
                stream_init(&getdata_msg, batch.assigned * 36 + 8);
                if (getdata_blocks_serialize(&getdata_msg, assign_hashes,
                                             batch.assigned)) {
                    p2p_node_begin_message(node, "getdata",
                                           mp->params->pchMessageStart);
                    p2p_node_write_message_data(node, getdata_msg.data,
                                                getdata_msg.size);
                    p2p_node_end_message(node);
                }
                stream_free(&getdata_msg);

                {
                    char hex[65];
                    uint256_get_hex(&assign_hashes[0], hex);
                    printf("getdata: %zu blocks to %s (first=%s)\n",
                           batch.assigned, node->addr_name, hex);
                }
                event_emitf(EV_BLOCK_REQUESTED, (uint32_t)node->id,
                            "assigned=%zu inflight=%zu",
                            batch.assigned,
                            batch.in_flight_before + batch.assigned);
            }

            /* Stall detection: if queue is empty, in-flight is zero,
             * and we're not at tip — find alternative blocks to download.
             * Scan block_map for blocks at tip+1 with header data but
             * no block data, that aren't failed. Queue them. */
            uint64_t dl_queued = 0, dl_inflight = 0;
            dl_get_stats(dm, NULL, NULL, NULL, &dl_inflight, &dl_queued);
            struct sync_stall_recovery recovery;
            if (syncsvc_build_stall_recovery(&recovery, mp->main_state, node,
                                             dl_queued, dl_inflight, now_dl)) {
                if (recovery.should_log) {
                    printf("STALL: h=%d entries_at_%d=%zu (data=%zu fail=%zu)\n",
                           recovery.chain_height, recovery.next_height,
                           recovery.entries_at_next, recovery.entries_with_data,
                           recovery.entries_failed);
                }
                {
                    int cleared = 0;
                    syncsvc_apply_stall_recovery(&recovery, mp->main_state,
                                                 dm, &cleared);
                    if (recovery.alt_count > 0) {
                        /* Clear re-queued blocks from the "recently seen"
                         * dedup buffer. Without this, blocks that were
                         * received but failed validation are permanently
                         * stuck: stall recovery re-downloads them, but
                         * block_already_seen silently drops them. */
                        for (size_t ri = 0; ri < recovery.alt_count; ri++)
                            block_clear_seen(&recovery.alt_hashes[ri]);
                        printf("Stall recovery: queued %zu alt blocks\n",
                               recovery.alt_count);
                    } else if (cleared > 0) {
                        printf("Stall recovery: reset %d blocks at h=%d for re-download\n",
                               cleared, recovery.next_height);
                    }
                }
                if (recovery.should_recover) {
                    struct block_index *tip = active_chain_tip(
                        &mp->main_state->chain_active);
                    struct sync_getheaders_action action = {0};
                    syncsvc_plan_recovery_getheaders(&action, &recovery, tip);
                    exec_getheaders_action(mp, node, &action);
                }
                syncsvc_free_stall_recovery(&recovery);
            }
        }
    }

    /* ── IBD progress log (every 30s, first outbound peer only) ── */
    {
        static int64_t last_progress_log = 0;
        int64_t now_prog = (int64_t)platform_time_wall_time_t();
        bool is_progress_peer = !node->inbound && node->id == 0;
        bool is_watchdog_peer = !node->inbound;

        if ((is_progress_peer || is_watchdog_peer) &&
            now_prog - last_progress_log >= 60) {
            if (is_progress_peer)
                last_progress_log = now_prog;
            struct download_manager *dm2 = get_download_mgr();
            int h = msg_get_height(mp);
            int header_tip = mp->main_state->pindex_best_header
                ? mp->main_state->pindex_best_header->nHeight : h;
            struct sync_progress_snapshot progress;
            syncsvc_collect_progress(&progress, dm2, sync_get_state(),
                                     h, header_tip, node->last_block_time,
                                     now_prog);
            if (is_progress_peer && progress.should_log_progress) {
                /* Compute blocks/sec and ETA */
                static int64_t ibd_speed_last_time = 0;
                static int     ibd_speed_last_height = 0;
                double blk_per_sec = 0;
                int remaining = progress.header_height - progress.chain_height;
                int eta_seconds = 0;
                if (ibd_speed_last_time > 0) {
                    int64_t dt = now_prog - ibd_speed_last_time;
                    int dh = progress.chain_height - ibd_speed_last_height;
                    if (dt > 0 && dh > 0)
                        blk_per_sec = (double)dh / (double)dt;
                    if (blk_per_sec > 0 && remaining > 0)
                        eta_seconds = (int)((double)remaining / blk_per_sec);
                }
                ibd_speed_last_time = now_prog;
                ibd_speed_last_height = progress.chain_height;

                printf("IBD: h=%d/%d  %.1f blk/s  ETA %dm%ds  "
                       "dl[flight=%llu queue=%llu timeout=%llu]  "
                       "%.2f GB @ %.1f MB/s\n",
                       progress.chain_height, progress.header_height,
                       blk_per_sec, eta_seconds / 60, eta_seconds % 60,
                       (unsigned long long)progress.in_flight,
                       (unsigned long long)progress.queued,
                       (unsigned long long)progress.timed_out,
                       progress.gib_received, progress.mbps_avg);
            }

            /* Tip-stale watchdog: if we're at the tip but haven't
             * received a new block in 10 minutes, re-request headers.
             * Runs on ALL outbound peers, not just id==0, so recovery
             * works even if the first peer disconnected. */
            {
                struct sync_getheaders_action stale = {0};
                syncsvc_plan_tip_stale_getheaders(&stale, &progress,
                                                  node, now_prog);
                if (stale.should_send) {
                    printf("Tip stale: no new block for %llds, "
                           "re-requesting headers from %s\n",
                           (long long)progress.tip_stale_seconds,
                           node->addr_name);
                    exec_getheaders_action(mp, node, &stale);
                }
            }

            /* Sync watchdog now runs on the lib/health periodic ring
             * (sync_watchdog_start in boot_services.c). The old
             * per-peer call here was gated on `node->id == 0`, which
             * is never true once peer ids rotate past zero — the bug
             * that left a node 22k blocks behind with checks_run=1. */
        }
    }

    /* Send a keepalive ping after 60 seconds without incoming traffic.  The
     * socket thread owns deadlines against these same monotonic stamps. */
    int64_t now_mono_us = platform_time_monotonic_us();
    struct peer_liveness_sample liveness = {
        .connected_us = atomic_load_explicit(
            &node->connected_monotonic_us, memory_order_relaxed),
        .last_activity_us = atomic_load_explicit(
            &node->last_activity_monotonic_us, memory_order_relaxed),
        .ping_sent_us = atomic_load_explicit(
            &node->keepalive_ping_sent_monotonic_us, memory_order_relaxed),
    };
    if (peer_liveness_decide(&liveness, now_mono_us) ==
        PEER_LIVENESS_SEND_PING) {
        uint64_t nonce = GetRand(UINT64_MAX);
        node->ping_nonce_sent = nonce;
        node->ping_usec_start = now_mono_us;
        atomic_store_explicit(&node->keepalive_ping_sent_monotonic_us,
                              now_mono_us, memory_order_relaxed);

        struct byte_stream ping;
        stream_init(&ping, 8);
        stream_write_u64_le(&ping, nonce);

        p2p_node_begin_message(node, "ping", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, ping.data, ping.size);
        p2p_node_end_message(node);
        stream_free(&ping);
    }

    /* Snapshot serving + swarm + block-swarm coordinators. */
    mp_snapshot_send_tick(mp, node);

    /* Dandelion++ embargo check: fluff any stemmed txs whose embargo expired.
     * Done once per trickle cycle (not per-peer) via a static timer guard. */
    if (send_trickle && g_dandelion_init && g_dandelion.stempool_count > 0) {
        struct uint256 expired[32];
        int nexp = dandelion_stempool_check_embargo(&g_dandelion, expired, 32);
        if (nexp > 0 && mp->net_mgr) {
            zcl_mutex_lock(&mp->net_mgr->cs_nodes);
            for (int ei = 0; ei < nexp; ei++) {
                struct inv_item einv;
                inv_item_init_typed(&einv, MSG_TX, &expired[ei]);
                for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
                    struct p2p_node *peer = mp->net_mgr->nodes[pi];
                    if (peer->state >= PEER_HANDSHAKE_COMPLETE &&
                        !peer->disconnect && peer->relay_txes)
                        p2p_node_push_inventory(peer, &einv);
                }
            }
            zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
        }
    }

    /* Send inventory on trickle */
    if (send_trickle) {
        zcl_mutex_lock(&node->cs_inventory);
        if (node->inventory_to_send_count > 0) {
            struct byte_stream inv_msg;
            stream_init(&inv_msg, 256);
            uint64_t count = 0;

            for (size_t i = 0; i < node->inventory_to_send_count; i++) {
                inv_item_serialize(&node->inventory_to_send[i], &inv_msg);
                count++;
            }

            if (count > 0) {
                struct byte_stream msg;
                stream_init(&msg, inv_msg.size + 8);
                stream_write_compact_size(&msg, count);
                stream_write(&msg, inv_msg.data, inv_msg.size);

                p2p_node_begin_message(node, "inv",
                                       mp->params->pchMessageStart);
                p2p_node_write_message_data(node, msg.data, msg.size);
                p2p_node_end_message(node);
                stream_free(&msg);
            }
            stream_free(&inv_msg);

            node->inventory_to_send_count = 0;
        }
        zcl_mutex_unlock(&node->cs_inventory);
    }

    /* Send addresses */
    if (node->addr_to_send_count > 0) {
        struct byte_stream addr_msg;
        stream_init(&addr_msg, 512);
        uint64_t count = node->addr_to_send_count;
        if (count > MAX_ADDR_TO_SEND)
            count = MAX_ADDR_TO_SEND;
        stream_write_compact_size(&addr_msg, count);

        for (size_t i = 0; i < count; i++)
            net_address_serialize(&node->addr_to_send[i], &addr_msg, true);

        p2p_node_begin_message(node, "addr", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, addr_msg.data, addr_msg.size);
        p2p_node_end_message(node);
        stream_free(&addr_msg);

        node->addr_to_send_count = 0;
    }

    return true;
}
