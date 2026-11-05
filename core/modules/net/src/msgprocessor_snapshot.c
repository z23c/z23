/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Snapshot/fast-sync requester and z-prefixed receiver dispatcher. Owns the
 * UTXO and block swarm coordinators plus the FlyClient challenge limiter.
 * Serve-side requests delegate to msgprocessor_snapshot_serve.c; shared
 * declarations live in msgprocessor_snapshot_internal.h. */

#include "platform/time_compat.h"
#include "msgprocessor_internal.h"
#include "msgprocessor_snapshot_internal.h"

#include "net/net_runtime_port.h"
#include "net/addrman.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "net/flyclient.h"
#include "net/peer_scoring.h"
#include "net/peer_lifecycle.h"
#include "net/file_service.h"
#include "net/sync_reduce_adapter.h"
#include "net/sync_shadow.h"
#include "storage/disk_block_io.h"
#include "coins/coins_view.h"
#include "jobs/reducer_frontier.h"  // lib-layer-ok:provable-tip-for-seed-floor-swarm-completion
#include "net/snapshot_sync_contract.h"
#include "validation/main_state.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "util/blocker.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "consensus/validation.h"
#include "core/uint256.h"
#include "core/random.h"
#include "crypto/sha3.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Global swarm coordinator — manages parallel UTXO chunk download.
 * Only active when we are syncing from multiple ZCL23 peers.
 * All access to g_swarm fields protected by g_swarm_mutex, which is
 * statically initialized like g_block_swarm_mutex below. The lazy
 * pthread_once it replaces had an abort() on its failure path, in a
 * network-reachable helper; a static initializer deletes that failure
 * rather than documenting it. Two things that gives up, both checked:
 * zcl_mutex_t is recursive on both platforms and this is not, which is
 * safe because the lock helpers are static to this file and no locked
 * region reaches another that locks; and the raw pthread type is
 * POSIX-only, which this file already is at g_block_swarm_mutex, so
 * porting core/modules/net to Windows has to handle both together rather than
 * one more site than before. */
static struct swarm_sync g_swarm __attribute__((used));
static _Atomic bool g_swarm_active = false;
static pthread_mutex_t g_swarm_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool swarm_mutex_lock(void)
{
    pthread_mutex_lock(&g_swarm_mutex);
    return true;
}

static void swarm_mutex_unlock(void)
{
    pthread_mutex_unlock(&g_swarm_mutex);
}

/* Snapshot sync service — global singleton in snapshot_sync_service.c */
static int64_t g_swarm_last_progress_time = 0;

/* Timeout for inflight chunk requests (30 seconds). */
#define SWARM_CHUNK_TIMEOUT_SECS 30

/* Progress display interval (5 seconds). */
#define SWARM_PROGRESS_INTERVAL_SECS 5
/* BLOCK_PIECE_MAX_BLOCK_BYTES lives in msgprocessor_snapshot_internal.h —
 * shared with msgprocessor_snapshot_serve.c's build_block_piece_payloads,
 * which must agree with this file's parse_block_piece_payload_refs on the
 * same per-block cap. */
#define BLOCK_PIECE_TIMEOUT_SECS 8
/* No piece completion for this long => the swarm is black-holing (peer
 * silently dropping zblkreq, serve-side gap, TCP backpressure): abandon it
 * so legacy getdata — paused while a swarm is active — resumes the fetch. */
#define BLOCK_SWARM_STALL_SECS 90
/* Minimum legacy-getdata ownership window before a reaped swarm may be
 * re-armed by a fresh manifest (anti-flap). */
#define BLOCK_SWARM_RESTART_COOLDOWN_SECS 300
/* Keep one full per-peer request pipeline contiguous: a bounded 16,384-block
 * ahead window. Every piece remains manifest-hash checked before any block
 * reaches the reducer. */
#define BLOCK_PIECE_CONTIGUOUS_WINDOW PIECE_PIPELINE_DEPTH

static void block_pipeline_clear_piece(struct p2p_node *node,
                                       uint32_t piece_index)
{
    if (!node)
        return;
    for (int pi = 0; pi < PIECE_PIPELINE_DEPTH; pi++) {
        if (node->blk_pipeline[pi].piece_index == (int32_t)piece_index) {
            node->blk_pipeline[pi].piece_index = -1;
            break;
        }
    }
}

/* The end height of the manifest this peer advertised and we anchored, or
 * -1 when none arrived: the reach its piece requests must stay within. */
static int32_t block_swarm_peer_manifest_end(const struct p2p_node *node)
{
    return node->blk_manifest_received ? node->blk_peer_height : -1;
}

static int32_t block_swarm_local_header_cap(const struct msg_processor *mp)
{
    int32_t cap = 0;
    if (!mp || !mp->main_state)
        return cap;

    int active_h = active_chain_height(&mp->main_state->chain_active);
    if (active_h > cap)
        cap = active_h;

    struct block_index *best_header = mp->main_state->pindex_best_header;
    if (best_header && best_header->nHeight > cap)
        cap = best_header->nHeight;

    return cap;
}

static int32_t block_swarm_contiguous_window_cap(
    struct block_swarm *bs,
    int32_t header_cap)
{
    if (!bs || !bs->piece_states || bs->manifest.num_pieces == 0)
        return header_cap;

    uint32_t first_open = block_swarm_first_incomplete_piece(bs);
    if (first_open >= bs->manifest.num_pieces)
        return header_cap;

    uint32_t window_cap = first_open + BLOCK_PIECE_CONTIGUOUS_WINDOW - 1;
    if (window_cap >= bs->manifest.num_pieces)
        window_cap = bs->manifest.num_pieces - 1;

    int64_t piece_end = (int64_t)bs->manifest.start_height +
        ((int64_t)window_cap + 1) * BLOCKS_PER_PIECE - 1;
    if (piece_end > bs->manifest.end_height)
        piece_end = bs->manifest.end_height;
    if (piece_end < header_cap)
        return (int32_t)piece_end;
    return header_cap;
}

struct snapshot_sync_service *msg_snapshot_sync(
    const struct msg_processor *mp)
{
    struct snapshot_sync_service *svc = net_runtime_snapshot_sync(mp ? mp->runtime : NULL);
    if (svc) return svc;
    if (snapsync_global_initialized())
        return snapsync_global();
    LOG_NULL("net", "no snapshot sync service available");
}

struct snapshot_sync_service *msg_snapshot_sync_ensure(
    const struct msg_processor *mp)
{
    struct snapshot_sync_service *svc = msg_snapshot_sync(mp);
    struct node_db *ndb;

    if (svc)
        return svc;
    ndb = msg_node_db(mp);
    if (!ndb)
        LOG_NULL("net", "node_db unavailable for snapshot sync init");
    snapsync_global_ensure_init(ndb);
    return snapsync_global();
}

/* ── Block swarm: parallel block download coordinator ───────── */
/* Manages BitTorrent-style block piece download across multiple
 * ZCL23 peers. Legacy peers contribute blocks via normal getdata/block
 * which the coordinator assembles into verified pieces. */
static struct block_swarm g_block_swarm __attribute__((used));
static _Atomic bool g_block_swarm_active = false;
static pthread_mutex_t g_block_swarm_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_block_swarm_last_progress = 0;
/* Wall-clock of the last stall-abandon. A reaped swarm may be re-armed by a
 * fresh manifest only after BLOCK_SWARM_RESTART_COOLDOWN_SECS, so a peer
 * whose piece service is silently black-holing cannot flap the body
 * transfer back out of legacy getdata's hands every few seconds. */
static _Atomic int64_t g_block_swarm_reaped_unix = 0;

/* The fc_rate_* per-peer FlyClient-challenge rate limiter (table, mutex,
 * fc_rate_acquire/fc_rate_should_score, and the msgprocessor_test_fc_rate_*
 * test surface) moved to msgprocessor_snapshot_fcrate.c — its only callers
 * are the two fc_rate_acquire/fc_rate_should_score calls in the
 * MSG_FC_CHALLENGE branch of mp_handle_zcl23_sync below. See
 * msgprocessor_snapshot_internal.h for the declarations that cross the
 * split. */

/* ── test hooks: g_swarm_active CAS drive ─────────────────
 * Expose the exact atomic primitive used by the zmanifest handler
 * so test_net.c can exercise the no-race / concurrent / reset-cycle
 * paths without a full peer-handshake setup. Body-for-body identical
 * to the production call sites around lines 2218 and 2398. */
bool msgprocessor_test_swarm_try_claim(void)
{
    bool expected = false;
    return atomic_compare_exchange_strong(&g_swarm_active,
                                          &expected, true);
}

void msgprocessor_test_swarm_release(void)
{
    atomic_store(&g_swarm_active, false);
}

bool msgprocessor_test_swarm_is_active(void)
{
    return atomic_load(&g_swarm_active);
}

/* Send a chunk request to a peer. */
static void push_chunk_request(struct msg_processor *mp,
                                struct p2p_node *node,
                                uint32_t chunk_index)
{
    struct byte_stream s;
    stream_init(&s, 4);
    stream_write_u32_le(&s, chunk_index);

    p2p_node_begin_message(node, MSG_CHUNK_REQ, mp->params->pchMessageStart);
    p2p_node_write_message_data(node, s.data, s.size);
    p2p_node_end_message(node);
    stream_free(&s);
}

/* Send a block piece request to a peer. */
static void push_block_piece_request(struct msg_processor *mp,
                                      struct p2p_node *node,
                                      uint32_t piece_index)
{
    struct byte_stream s;
    stream_init(&s, 4);
    stream_write_u32_le(&s, piece_index);

    p2p_node_begin_message(node, MSG_BLOCK_REQ,
                            mp->params->pchMessageStart);
    p2p_node_write_message_data(node, s.data, s.size);
    p2p_node_end_message(node);
    stream_free(&s);
}

static bool parse_block_piece_payload_refs(
    struct byte_stream *s,
    const uint8_t (*hashes)[32],
    uint32_t block_count,
    struct block_piece_payload_ref **out_refs)
{
    if (!s || !hashes || !out_refs)
        return false;
    *out_refs = NULL;
    if (stream_remaining(s) == 0)
        return true;

    struct block_piece_payload_ref *refs =
        zcl_calloc(block_count, sizeof(*refs), "block_piece_payload_refs");
    if (!refs)
        return false;

    for (uint32_t i = 0; i < block_count; i++) {
        uint64_t len64 = 0;
        if (!stream_read_compact_size(s, &len64) ||
            len64 == 0 ||
            len64 > BLOCK_PIECE_MAX_BLOCK_BYTES ||
            len64 > stream_remaining(s)) {
            free(refs);
            return false;
        }

        refs[i].data = s->data + s->read_pos;
        refs[i].len = (size_t)len64;

        struct byte_stream bs;
        stream_init_from_data(&bs, refs[i].data, refs[i].len);
        struct block blk;
        block_init(&blk);
        bool parsed = block_deserialize(&blk, &bs) &&
                      stream_remaining(&bs) == 0;
        if (parsed) {
            struct uint256 hash;
            block_get_hash(&blk, &hash);
            parsed = memcmp(hash.data, hashes[i], 32) == 0;
        }
        block_free(&blk);
        stream_free(&bs);
        if (!parsed) {
            free(refs);
            return false;
        }

        s->read_pos += refs[i].len;
    }

    if (stream_remaining(s) != 0) {
        free(refs);
        return false;
    }

    *out_refs = refs;
    return true;
}

bool mp_snapshot_is_active(void)
{
    return snapsync_is_active();
}

bool mp_swarm_is_active(void)
{
    return atomic_load(&g_swarm_active);
}

bool mp_block_swarm_is_active(void)
{
    return atomic_load(&g_block_swarm_active);
}
/* Stall watchdog. The legacy getdata assignment in msg_send_messages is
 * paused for as long as a block swarm is active (zblkreq/zblkdata owns body
 * transfer), but the swarm's only exit was full completion: a peer that
 * silently stops answering piece requests (serve-side gap, rate limit, TCP
 * backpressure) left the swarm re-requesting the same pieces every
 * BLOCK_PIECE_TIMEOUT_SECS forever — queue full, flight zero, frontier body
 * never fetched, permanent catch-up wedge. Reap a swarm with no piece
 * completion for BLOCK_SWARM_STALL_SECS so the height-sorted legacy queue
 * (frontier at the front) resumes. Also clears every peer's block-piece
 * pipeline slots so a later re-armed swarm does not inherit stale
 * CHUNK_INFLIGHT references from the dead one. Returns true when it reaped. */
bool mp_block_swarm_reap_if_stalled(struct msg_processor *mp)
{
    if (!atomic_load(&g_block_swarm_active))
        return false;

    int64_t now = (int64_t)platform_time_wall_time_t();
    struct block_swarm_abandonment abandoned = {0};
    pthread_mutex_lock(&g_block_swarm_mutex);
    struct block_swarm *bs = &g_block_swarm;
    bool stalled = bs->piece_states &&
                   bs->manifest.num_pieces > 0 &&
                   bs->pieces_complete < bs->manifest.num_pieces &&
                   bs->last_complete_unix > 0 &&
                   now - bs->last_complete_unix >= BLOCK_SWARM_STALL_SECS;
    if (stalled) {
        stalled = mp_block_swarm_abandon_locked(
            &g_block_swarm, &g_block_swarm_active,
            &g_block_swarm_reaped_unix, now, &abandoned);
    }
    pthread_mutex_unlock(&g_block_swarm_mutex);
    if (!stalled)
        return false;

    mp_block_swarm_finish_abandon(mp);

    LOG_WARN("net",
             "block swarm stalled at %u/%u pieces (no completion for %llds) "
             "— abandoning swarm; legacy getdata resumes body fetch",
             abandoned.complete, abandoned.total,
             (long long)(now - abandoned.last_complete_unix));
    event_emitf(EV_BLOCK_REQUESTED, 0,
                "block_swarm_stall_abandon complete=%u total=%u stall_s=%lld",
                abandoned.complete, abandoned.total,
                (long long)(now - abandoned.last_complete_unix));
    return true;
}

#ifdef ZCL_TESTING
/* Seed a minimal live swarm at a chosen completion age so stall-reap tests
 * need no wire dance. complete==0/total==0 tears the swarm down instead. */
void mp_block_swarm_test_seed_stall(uint32_t complete, uint32_t total,
                                    int64_t last_complete_unix)
{
    pthread_mutex_lock(&g_block_swarm_mutex);
    block_swarm_free(&g_block_swarm);
    atomic_store(&g_block_swarm_active, false);
    atomic_store(&g_block_swarm_reaped_unix, 0);
    if (total > 0) {
        struct block_piece_manifest pm;
        memset(&pm, 0, sizeof(pm));
        pm.start_height = 1;
        pm.end_height = (int32_t)total * BLOCKS_PER_PIECE;
        pm.num_pieces = total;
        if (block_swarm_init(&g_block_swarm, &pm, NULL)) {
            g_block_swarm.pieces_complete = complete;
            g_block_swarm.last_complete_unix = last_complete_unix;
            atomic_store(&g_block_swarm_active, true);
        }
    }
    pthread_mutex_unlock(&g_block_swarm_mutex);
}

int64_t mp_block_swarm_test_reaped_unix(void)
{
    return atomic_load(&g_block_swarm_reaped_unix);
}

bool mp_block_swarm_test_fail_integrity(struct msg_processor *mp,
                                        uint32_t piece_index)
{
    struct block_swarm_abandonment abandoned = {0};
    bool did_abandon = false;
    int64_t now = (int64_t)platform_time_wall_time_t();

    pthread_mutex_lock(&g_block_swarm_mutex);
    if (atomic_load(&g_block_swarm_active) &&
        g_block_swarm.piece_states &&
        piece_index < g_block_swarm.manifest.num_pieces) {
        block_swarm_fail_piece(&g_block_swarm, piece_index);
        did_abandon = mp_block_swarm_abandon_locked(
            &g_block_swarm, &g_block_swarm_active,
            &g_block_swarm_reaped_unix, now, &abandoned);
    }
    pthread_mutex_unlock(&g_block_swarm_mutex);
    if (did_abandon)
        mp_block_swarm_finish_abandon(mp);
    return did_abandon;
}
#endif

/* Event-driven block-swarm requeue on peer disconnect. connman's cleanup
 * sweep already calls dl_peer_disconnected() to reclaim the legacy download
 * manager's in-flight blocks; this reclaims the parallel block-swarm pieces
 * the same peer was assigned. A piece left CHUNK_INFLIGHT with its owning
 * peer gone is unassignable to anyone else until block_swarm_handle_timeouts()
 * expires it after BLOCK_PIECE_TIMEOUT_SECS (8 s); at the swarm's contiguous
 * assignment window that stalls forward progress for up to a full timeout per
 * dead peer. Resetting the peer's inflight pieces to CHUNK_NEEDED here lets the
 * next send tick hand them straight to a live peer. Returns pieces re-queued. */
size_t mp_block_swarm_peer_disconnected(uint32_t peer_id)
{
    if (!atomic_load(&g_block_swarm_active))
        return 0;

    size_t requeued = 0;
    pthread_mutex_lock(&g_block_swarm_mutex);
    struct block_swarm *bs = &g_block_swarm;
    if (bs->piece_states && bs->piece_peer) {
        for (uint32_t i = 0; i < bs->manifest.num_pieces; i++) {
            if (bs->piece_states[i] == CHUNK_INFLIGHT &&
                bs->piece_peer[i] == (int)peer_id) {
                if (block_swarm_requeue_piece(bs, i))
                    requeued++;
            }
        }
    }
    pthread_mutex_unlock(&g_block_swarm_mutex);

    if (requeued)
        LOG_INFO("net",
                 "block swarm: requeued %zu in-flight piece(s) from "
                 "disconnected peer %u (event-driven, pre-timeout)",
                 requeued, peer_id);
    return requeued;
}

bool mp_snapshot_check_stall(void)
{
    return snapsync_check_stall();
}

/* D1: aggregate SHA3 UTXO-snapshot verify for the swarm chunk-download
 * path. Was previously a silent-accept: FAILED printed, then fell
 * through into the same cleanup as PASSED (no offence, no blocker) —
 * invisible to the self-healing safety net. Advisory layer only
 * (background validation independently re-verifies block contents), so
 * the already-applied rows stay; a mismatch now scores the peer, names
 * a retry-forever DEPENDENCY blocker, and reports NOT complete. */
static bool msg_swarm_utxo_sha3_verify(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       const uint8_t local_root[32],
                                       const uint8_t expected_root[32],
                                       uint64_t local_count)
{
    if (memcmp(local_root, expected_root, 32) == 0) {
        printf("SHA3 UTXO verification: PASSED "
               "(%lu UTXOs)\n", (unsigned long)local_count);
        return true;
    }
    LOG_WARN("net",
             "Peer %s: swarm UTXO snapshot SHA3 mismatch (local_count=%"
             PRIu64 ") — data corrupted or manifest root inconsistent "
             "with its own chunk hashes; sync NOT complete",
             node->addr_name, (uint64_t)local_count);
    peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PROOF,
                        "swarm snapshot SHA3 verification failed");
    blocker_name_dependency(
        "snapshot_sync.utxo_sha3_mismatch", "msgprocessor_snapshot",
        "swarm UTXO snapshot aggregate SHA3 mismatch: applied chunk "
        "range is untrusted, sync did not complete");
    return false;
}

bool msgprocessor_test_swarm_utxo_sha3_verify(struct msg_processor *mp,
                                              struct p2p_node *node,
                                              const uint8_t local_root[32],
                                              const uint8_t expected_root[32],
                                              uint64_t local_count)
{
    return msg_swarm_utxo_sha3_verify(mp, node, local_root, expected_root,
                                      local_count);
}

/* ── ZCL23 Sync Message Handler ──────────────────────────────────
 * Handles all snapshot, chunk, block-piece, and FlyClient messages.
 * These share complex state (g_swarm, g_block_swarm). The dispatcher
 * mp_handle_zcl23_sync below routes each message kind to one small static
 * handler (mp_zs_on_*); every handler body is the former branch moved
 * unchanged, so bounds checks, peer-misbehaviour charges, log lines,
 * replies and swarm locking keep their order. */

/* 32-byte hash array element, used for heap-allocated hash lists. */
typedef uint8_t mp_zs_hash32[32];

/* ── Parallel chunk sync messages ────────────────────────────── */

/* Decoded zmanifest header fields. */
struct mp_zs_manifest {
    int32_t height;
    uint8_t block_hash[32];
    uint8_t merkle_root[32];
    uint8_t utxo_sha3[32];
    uint64_t num_utxos;
    uint32_t num_chunks;
    uint32_t chunk_size;
};

/* Read the fixed zmanifest header; false when the stream is truncated. */
static bool mp_zs_manifest_read_header(struct byte_stream *s,
                                       struct mp_zs_manifest *m)
{
    return stream_read_i32_le(s, &m->height) &&
           stream_read_bytes(s, m->block_hash, 32) &&
           stream_read_u64_le(s, &m->num_utxos) &&
           stream_read_u32_le(s, &m->num_chunks) &&
           stream_read_u32_le(s, &m->chunk_size) &&
           stream_read_bytes(s, m->merkle_root, 32);
}

/* Read the optional utxo root; false (already scored) when truncated. */
static bool mp_zs_manifest_read_utxo_root(struct msg_processor *mp,
                                          struct p2p_node *node,
                                          struct byte_stream *s,
                                          struct mp_zs_manifest *m)
{
    if (stream_remaining(s) >= ((size_t)m->num_chunks * 32 + 32)) {
        if (!stream_read_bytes(s, m->utxo_sha3, 32)) {
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                                "truncated zmanifest utxo root");
            return false;
        }
    }
    return true;
}

/* read num_chunks * 32 bytes of per-chunk SHA3 hashes
 * and reject the manifest if they don't Merkle-reconstruct
 * to the merkle_root the same peer advertised above. This
 * is the commitment the receiver checks each zchunkdata
 * response against before calling fast_sync_apply_chunk.
 * Returns the hash list, or NULL (already scored) when truncated. */
static mp_zs_hash32 *mp_zs_manifest_read_hashes(struct msg_processor *mp,
                                                struct p2p_node *node,
                                                struct byte_stream *s,
                                                uint32_t num_chunks)
{
    uint8_t (*hashes)[32] = zcl_calloc(num_chunks, 32,
                                        "peer_chunk_hashes");
    bool hashes_ok = hashes != NULL;
    for (uint32_t i = 0; i < num_chunks && hashes_ok; i++) {
        if (!stream_read_bytes(s, hashes[i], 32))
            hashes_ok = false;
    }
    if (!hashes_ok) {
        free(hashes);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "truncated zmanifest hashes");
        return NULL;
    }
    return hashes;
}

/* Claim the swarm slot and start the swarm from a verified manifest.
 * Returns false (hashes already freed) when the swarm mutex is unavailable. */
static bool mp_zs_manifest_start_swarm(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       const struct mp_zs_manifest *m,
                                       uint8_t (*hashes)[32])
{
    /* atomic compare-exchange on g_swarm_active
     * (false → true) closes the TOCTOU window between
     * the "is a swarm already running?" check and the
     * "claim the slot" write. Without it, two peers
     * racing on near-simultaneous manifests could both
     * observe false and both call swarm_sync_init, the
     * loser overwriting the winner's chunk index. The
     * CAS lets only one peer win the init; the loser
     * drops its message. */
    bool expected = false;
    if (!atomic_compare_exchange_strong(
            &g_swarm_active, &expected, true)) {
        /* Another peer raced us — drop silently
         * rather than risk state leak. */
        printf("Peer %s: swarm already active "
               "(peer raced), dropping manifest\n",
               node->addr_name);
    } else {
        struct sync_manifest peer_manifest = {
            .height = m->height,
            .num_utxos = m->num_utxos,
            .num_chunks = m->num_chunks,
            .chunk_size = m->chunk_size,
            .chunk_hashes = hashes
        };
        memcpy(peer_manifest.block_hash, m->block_hash, 32);
        memcpy(peer_manifest.merkle_root, m->merkle_root, 32);
        memcpy(peer_manifest.utxo_sha3, m->utxo_sha3, 32);

        int32_t first_chunk = -1;
        if (!swarm_mutex_lock()) {
            atomic_store(&g_swarm_active, false);
            free(hashes);
            LOG_FAIL("net", "rejecting snapshot manifest: "
                     "swarm mutex unavailable");
        }
        if (swarm_sync_init(&g_swarm, &peer_manifest,
                            mp->datadir)) {
            g_swarm_last_progress_time =
                (int64_t)platform_time_wall_time_t();
            printf("Swarm sync started: %u chunks "
                   "from h=%d\n", m->num_chunks, m->height);
            first_chunk = swarm_sync_assign_chunk(
                &g_swarm, node->id);
            if (first_chunk >= 0) {
                node->swarm_inflight_chunk =
                    first_chunk;
                node->swarm_chunk_req_time =
                    (int64_t)platform_time_wall_time_t();
            }
        } else {
            /* Init failed — release the claim so
             * another peer's manifest can retry. */
            atomic_store(&g_swarm_active, false);
        }
        swarm_mutex_unlock();
        if (first_chunk >= 0)
            push_chunk_request(mp, node,
                               (uint32_t)first_chunk);
    }
    return true;
}

/* Merkle-verified manifest: remember it and maybe start the swarm.
 * Takes ownership of `hashes`; false only when the swarm mutex failed. */
static bool mp_zs_manifest_accept(struct msg_processor *mp,
                                  struct p2p_node *node,
                                  const struct mp_zs_manifest *m,
                                  uint8_t (*hashes)[32])
{
    node->swarm_manifest_received = true;
    int our_h = active_chain_height(
        &mp->main_state->chain_active);
    printf("Peer %s: manifest h=%d chunks=%u "
           "(%llu UTXOs)\n",
           node->addr_name, m->height, m->num_chunks,
           (unsigned long long)m->num_utxos);

    /* If peer is significantly ahead and we have no
     * active swarm, initialize the swarm coordinator
     * from their (now-verified) manifest. */
    if (m->height > our_h + 100) {
        if (!mp_zs_manifest_start_swarm(mp, node, m, hashes))
            return false;
    }
    /* swarm_sync_init deep-copies the hash array, so
     * our peer copy is ours to free regardless. */
    free(hashes);
    return true;
}

/* Peer sends their manifest — describes available chunks. */
static bool mp_zs_on_manifest(struct msg_processor *mp,
                              struct p2p_node *node,
                              struct byte_stream *s)
{
    struct mp_zs_manifest m;
    memset(&m, 0, sizeof(m));

    if (!mp_zs_manifest_read_header(s, &m)) {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "truncated zmanifest header");
    } else if (m.num_chunks == 0 || m.num_chunks > MANIFEST_MAX_CHUNKS
               || m.chunk_size == 0) {
        fprintf(stderr, "Peer %s: manifest out of bounds "  // obs-ok:helper-context-logged
                "(num_chunks=%u cap=%u chunk_size=%u)\n",
                node->addr_name, m.num_chunks, MANIFEST_MAX_CHUNKS,
                m.chunk_size);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "manifest bounds");
    } else {
        if (!mp_zs_manifest_read_utxo_root(mp, node, s, &m))
            return true;

        uint8_t (*hashes)[32] =
            mp_zs_manifest_read_hashes(mp, node, s, m.num_chunks);
        if (hashes) {
            uint8_t computed_root[32];
            fast_sync_merkle_root(
                (const uint8_t (*)[32])hashes, m.num_chunks,
                computed_root);
            if (memcmp(computed_root, m.merkle_root, 32) != 0) {
                free(hashes);
                peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PROOF,
                                    "manifest merkle root mismatch");
            } else if (!mp_zs_manifest_accept(mp, node, &m, hashes)) {
                return false;
            }
        }
    }
    return true;
}

/* Parse one zchunkdata entry; false when truncated or oversized. */
static bool mp_zs_chunk_read_entry(struct byte_stream *s,
                                   struct utxo_chunk *chunk, uint32_t i)
{
    if (!stream_read_bytes(s, chunk->entries[i].txid, 32))
        return false;
    int32_t vout = 0;
    if (!stream_read_i32_le(s, &vout))
        return false;
    chunk->entries[i].vout = (uint32_t)vout;
    if (!stream_read_i64_le(s, &chunk->entries[i].value))
        return false;
    if (!stream_read_i32_le(s, &chunk->entries[i].height))
        return false;
    uint8_t is_coinbase = 0;
    if (!stream_read_u8(s, &is_coinbase))
        return false;
    chunk->entries[i].is_coinbase = is_coinbase != 0;
    uint16_t slen = 0;
    if (!stream_read_u16_le(s, &slen))
        return false;
    if (slen > sizeof(chunk->entries[i].script)) {
        /* Script too large for entry — reject chunk.
         * Don't silently truncate, that corrupts UTXOs. */
        return false;
    }
    chunk->entries[i].script_len = slen;
    if (slen > 0 &&
        !stream_read_bytes(s, chunk->entries[i].script, slen))
        return false;
    return true;
}

/* Swarm just completed: verify the SHA3 commitment, release the claim and
 * unlock the swarm mutex (held on entry). */
static void mp_zs_chunk_swarm_finish_locked(struct msg_processor *mp,
                                            struct p2p_node *node)
{
    printf("Swarm sync complete: %u/%u chunks\n",
           g_swarm.chunks_complete,
           g_swarm.manifest.num_chunks);

    /* Verify SHA3 UTXO commitment vs the
     * manifest root — see msg_swarm_utxo_sha3_verify
     * (D1) for the mismatch reaction. */
    if (mp->utxo_sha3_compute) {
        uint8_t local_root[32];
        uint64_t local_count = 0;

        if (mp->utxo_sha3_compute(
                local_root, &local_count,
                mp->utxo_sha3_compute_ctx)) {
            const uint8_t *expected_root =
                g_swarm.manifest.utxo_sha3;
            if (memcmp(expected_root,
                       (const uint8_t[32]){0}, 32) == 0)
                expected_root =
                    g_swarm.manifest.merkle_root;
            (void)msg_swarm_utxo_sha3_verify(
                mp, node, local_root, expected_root,
                local_count);
        }
    }

    /* Release the claim regardless of verify
     * outcome so a future manifest can retry —
     * not a declaration of trustworthiness. */
    swarm_sync_free(&g_swarm);
    /* explicit atomic_store for symmetry with
     * the CAS at the init site. Functionally
     * equivalent to `g_swarm_active = false` on
     * _Atomic bool, but documents the pairing. */
    atomic_store(&g_swarm_active, false);
    swarm_mutex_unlock();
}

/* Hand a fully parsed chunk to the swarm. Returns false (chunk already
 * freed) when the swarm mutex is unavailable. */
static bool mp_zs_chunk_deliver(struct msg_processor *mp,
                                struct p2p_node *node,
                                struct utxo_chunk *chunk,
                                uint32_t chunk_index)
{
    if (!swarm_mutex_lock()) {
        free(chunk);
        LOG_FAIL("net", "rejecting snapshot chunk: "
                         "swarm mutex unavailable");
    }
    bool verified = swarm_sync_receive_chunk(
        &g_swarm, chunk, node->id);
    node->swarm_inflight_chunk = -1;

    if (!verified) {
        swarm_mutex_unlock();
        fprintf(stderr, "Peer %s: chunk %u failed verification\n",  // obs-ok:helper-context-logged
               node->addr_name, chunk_index);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_CHUNK,
                            "bad chunk hash");
    } else if (swarm_sync_is_complete(&g_swarm)) {
        mp_zs_chunk_swarm_finish_locked(mp, node);
    } else {
        swarm_mutex_unlock();
    }
    return true;
}

/* Peer sends chunk data in response to our request. */
static bool mp_zs_on_chunk_data(struct msg_processor *mp,
                                struct p2p_node *node,
                                struct byte_stream *s)
{
    uint32_t chunk_index = 0, num_entries = 0;
    if (!stream_read_u32_le(s, &chunk_index) ||
        !stream_read_u32_le(s, &num_entries) ||
        num_entries > 1000) {
        printf("Peer %s: bad zchunkdata header\n", node->addr_name);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD, "bad zchunkdata");
    } else if (!g_swarm_active) {
        printf("Peer %s: zchunkdata but no swarm active\n",
               node->addr_name);
    } else {
        struct utxo_chunk *chunk = zcl_calloc(1, sizeof(struct utxo_chunk), "utxo_chunk");
        if (chunk) {
            chunk->chunk_index = chunk_index;
            chunk->num_entries = num_entries;
            bool parse_ok = true;

            for (uint32_t i = 0; i < num_entries && parse_ok; i++) {
                if (!mp_zs_chunk_read_entry(s, chunk, i))
                    parse_ok = false;
            }

            if (parse_ok) {
                if (!mp_zs_chunk_deliver(mp, node, chunk, chunk_index))
                    return false;
            } else {
                printf("Peer %s: truncated zchunkdata\n",
                       node->addr_name);
                peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                                    "truncated zchunkdata");
            }
            free(chunk);
        }
    }
    return true;
}

/* ── Block swarm messages (parallel block download) ──────────── */

/* Decoded zblkmanifest header fields. */
struct mp_zs_blkman {
    int32_t start_h;
    int32_t end_h;
    uint32_t num_pieces;
    uint8_t tip_hash[32];
    uint8_t merkle_root[32];
};

/* Read the piece hashes and compare their merkle root to the advertised
 * one. Returns the allocated list (NULL if nothing was allocated); `*valid`
 * says whether it can be trusted. The caller owns the list either way. */
static mp_zs_hash32 *mp_zs_blkman_read_piece_hashes(struct byte_stream *s,
                                                    const struct mp_zs_blkman *m,
                                                    bool *valid)
{
    uint8_t (*piece_hashes)[32] = NULL;
    *valid = false;
    size_t expected_hash_bytes = (size_t)m->num_pieces * 32;
    if (stream_remaining(s) >= expected_hash_bytes) {
        piece_hashes = zcl_calloc(m->num_pieces, 32,
                                   "peer_block_piece_hashes");
        if (piece_hashes) {
            bool hashes_read = true;
            for (uint32_t i = 0; i < m->num_pieces &&
                 hashes_read; i++) {
                hashes_read = stream_read_bytes(
                    s, piece_hashes[i], 32);
            }
            if (hashes_read) {
                uint8_t computed_root[32];
                fast_sync_merkle_root(
                    (const uint8_t (*)[32])piece_hashes,
                    m->num_pieces, computed_root);
                *valid =
                    memcmp(computed_root, m->merkle_root,
                           32) == 0;
            }
        }
    }
    return piece_hashes;
}

/* ANCHOR the manifest before trusting it. A
 * merkle root over attacker-chosen piece hashes
 * is self-consistent by construction, so the
 * only remaining trust step is against OUR OWN
 * validated header index: either tip_hash names
 * a block we admit at exactly the claimed end
 * height (full anchor), or our admitted header
 * tip reaches past start_height (an honestly
 * ahead peer whose later headers we simply
 * have not fetched yet — its body transfer
 * stays capped by local header admission).
 * Refuse and score otherwise: a range rooted
 * beyond anything we can bind offers bodies
 * that can never attach, so serving them is
 * pure resource burn. Returns whether this manifest anchored. The verdict
 * is per manifest: an earlier anchored manifest from this peer buys the next
 * one nothing. Honest publishers all start at height 1, so a republish passes
 * here by itself once any header is admitted. */
static bool mp_zs_blkman_anchor(struct msg_processor *mp,
                                struct p2p_node *node,
                                const struct mp_zs_blkman *m)
{
    struct uint256 tip_u;
    memcpy(tip_u.data, m->tip_hash, 32);
    bool anchored = false;
    if (mp->main_state) {
        struct block_index *tip_bi = block_map_find(
            &mp->main_state->map_block_index,
            &tip_u);
        if (tip_bi && tip_bi->nHeight == m->end_h)
            anchored = true;
    }
    if (!anchored && mp->main_state &&
        mp->main_state->pindex_best_header)
        anchored = m->start_h <=
            mp->main_state->pindex_best_header->nHeight;
    if (anchored) {
        node->blk_manifest_received = true;
        node->blk_peer_height = m->end_h;
    } else {
        fprintf(stderr,  // obs-ok:peer-scored
                "Peer %s: block manifest not "
                "anchored in local header index "
                "(start=%d end=%d)\n",
                node->addr_name, m->start_h, m->end_h);
        peer_scoring_record(
            mp->net_mgr, node,
            PEER_OFFENCE_INVALID_MESSAGE,
            "block manifest not header-anchored");
    }
    return anchored;
}

/* Validate a decoded block manifest. Returns the piece-hash list when the
 * manifest passed the checks and anchored, or NULL when it was refused
 * (already scored). A refused manifest changes nothing the peer anchored
 * before. */
static mp_zs_hash32 *mp_zs_blkman_validate(struct msg_processor *mp,
                                           struct p2p_node *node,
                                           struct byte_stream *s,
                                           const struct mp_zs_blkman *m)
{
    /* Sanity: heights must be positive and consistent */
    if (m->start_h < 0 || m->end_h < m->start_h || m->num_pieces == 0 ||
        m->num_pieces > BLOCK_SWARM_MAX_PIECES) {
        printf("Peer %s: invalid block manifest "
               "(start=%d end=%d pieces=%u)\n",
               node->addr_name, m->start_h, m->end_h, m->num_pieces);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "invalid block manifest params");
        return NULL;
    }
    /* Verify piece count is consistent with height range */
    uint32_t expected = (uint32_t)((m->end_h - m->start_h +
        BLOCKS_PER_PIECE) / BLOCKS_PER_PIECE);
    if (m->num_pieces != expected) {
        fprintf(stderr, "Peer %s: block manifest piece count mismatch "  // obs-ok:helper-context-logged
               "(got %u, expected %u for h=%d..%d)\n",
               node->addr_name, m->num_pieces, expected,
               m->start_h, m->end_h);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_MESSAGE,
                            "block manifest piece count wrong");
        return NULL;
    }
    bool piece_hashes_valid = false;
    uint8_t (*piece_hashes)[32] =
        mp_zs_blkman_read_piece_hashes(s, m, &piece_hashes_valid);

    if (!piece_hashes_valid) {
        fprintf(stderr,  // obs-ok:peer-scored
                "Peer %s: block manifest missing or bad "
                "piece hashes (h=%d..%d pieces=%u)\n",
                node->addr_name, m->start_h, m->end_h,
                m->num_pieces);
        peer_scoring_record(
            mp->net_mgr, node,
            PEER_OFFENCE_INVALID_MESSAGE,
            "block manifest piece hashes missing/bad");
        free(piece_hashes);
        return NULL;
    }
    if (!mp_zs_blkman_anchor(mp, node, m)) {
        free(piece_hashes);
        return NULL;
    }
    return piece_hashes;
}

/* If peer is ahead and no active block swarm, start one.
 * After a stall-abandon, hold off re-arming for
 * BLOCK_SWARM_RESTART_COOLDOWN_SECS so legacy getdata owns
 * body transfer long enough to push past the hole. */
static void mp_zs_blkman_maybe_start_swarm(struct msg_processor *mp,
                                           const struct mp_zs_blkman *m,
                                           uint8_t (*piece_hashes)[32],
                                           int our_h)
{
    struct block_piece_manifest pm = {
        .start_height = m->start_h,
        .end_height = m->end_h,
        .num_pieces = m->num_pieces,
        .piece_hashes = piece_hashes
    };
    memcpy(pm.tip_hash, m->tip_hash, 32);
    memcpy(pm.merkle_root, m->merkle_root, 32);
    pthread_mutex_lock(&g_block_swarm_mutex);
    if (block_swarm_init(&g_block_swarm, &pm, mp->datadir)) {
        g_block_swarm.last_complete_unix =
            (int64_t)platform_time_wall_time_t();
        mp_block_swarm_mark_complete_through_height(
            &g_block_swarm, our_h);
        g_block_swarm_active = true;
        g_block_swarm_last_progress = (int64_t)platform_time_wall_time_t();
        printf("Block swarm started: %u pieces, h=%d..%d "
               "(already_complete=%u at h=%d)\n",
               m->num_pieces, m->start_h, m->end_h,
               g_block_swarm.pieces_complete, our_h);
    }
    pthread_mutex_unlock(&g_block_swarm_mutex);
}

/* Peer sends their block piece manifest.
 * DEFENSIVE: validate all fields before trusting any data. */
static void mp_zs_on_block_manifest(struct msg_processor *mp,
                                    struct p2p_node *node,
                                    struct byte_stream *s)
{
    struct mp_zs_blkman m;
    memset(&m, 0, sizeof(m));
    uint8_t (*piece_hashes)[32] = NULL;

    if (stream_read_i32_le(s, &m.start_h) &&
        stream_read_i32_le(s, &m.end_h) &&
        stream_read_u32_le(s, &m.num_pieces) &&
        stream_read_bytes(s, m.tip_hash, 32) &&
        stream_read_bytes(s, m.merkle_root, 32)) {

        piece_hashes = mp_zs_blkman_validate(mp, node, s, &m);
        if (!piece_hashes)
            return;
        int our_h = active_chain_height(&mp->main_state->chain_active);
        /* Seed-floor raise: on a bundle/snapshot-seeded node the
         * install advances the reducer frontier (H*) past the
         * bundle height but never moves chainactive. Seeding the
         * swarm's completion from active_chain_height then marks
         * ~nothing complete, all ~50k pieces tie rarest-first to
         * the LOWEST indexes, the 256-deep per-peer pipeline fills
         * with h=1.. pieces whose bodies flood the 128-slot
         * intake ring, and the fold-needed range above H* never
         * enters the queue (FORWARD_PLAN backlog #10, observed
         * 2026-08-01: H* frozen at the seed, 256 pieces inflight,
         * zero completions). Floor the completion seed at H* so
         * the first open piece is the one containing the fold's
         * next-needed height. No-op on an unseeded node, where H*
         * tracks the active tip. */
        {
            int32_t hstar = reducer_frontier_provable_tip_cached();
            if (hstar > our_h)
                our_h = hstar;
        }
        printf("Peer %s: block manifest h=%d..%d (%u pieces)\n",
               node->addr_name, m.start_h, m.end_h, m.num_pieces);
        if (m.end_h > our_h + BLOCKS_PER_PIECE &&
            !g_block_swarm_active &&
            (int64_t)platform_time_wall_time_t() -
                atomic_load(&g_block_swarm_reaped_unix) >=
                    BLOCK_SWARM_RESTART_COOLDOWN_SECS) {
            mp_zs_blkman_maybe_start_swarm(mp, &m, piece_hashes, our_h);
        }
        free(piece_hashes);
    }
}

/* Submit the piece's block payloads with the swarm lock dropped. Called and
 * returns with g_block_swarm_mutex held. Returns whether the payloads were
 * accepted and the swarm is still the one the piece belongs to. */
static bool mp_zs_blkdata_submit_payloads_locked(
    struct msg_processor *mp, struct p2p_node *node,
    struct block_piece_payload_ref *block_refs, uint32_t block_count,
    uint32_t piece_index)
{
    /* Swarm identity before dropping the lock: payload
     * submit can block for seconds under reducer
     * backpressure, and the stall watchdog may reap (and
     * the net loop re-arm) the swarm meanwhile. */
    const int32_t swarm_start =
        g_block_swarm.manifest.start_height;
    const uint32_t swarm_pieces =
        g_block_swarm.manifest.num_pieces;
    pthread_mutex_unlock(&g_block_swarm_mutex);
    bool payloads_accepted = mp_block_payload_submit_all(
        mp, node, block_refs, block_count);
    pthread_mutex_lock(&g_block_swarm_mutex);
    if (!atomic_load(&g_block_swarm_active) ||
        !g_block_swarm.piece_states ||
        g_block_swarm.manifest.start_height !=
            swarm_start ||
        g_block_swarm.manifest.num_pieces !=
            swarm_pieces) {
        LOG_INFO("net",
                 "zblkdata piece %u: swarm reaped during "
                 "payload submit; dropping piece credit",
                 piece_index);
        payloads_accepted = false;
    }
    return payloads_accepted;
}

/* Credit a verified, accepted piece (g_block_swarm_mutex held). */
static void mp_zs_blkdata_credit_piece_locked(struct p2p_node *node,
                                              uint32_t piece_index)
{
    if (g_block_swarm.piece_states[piece_index] ==
        CHUNK_COMPLETE) {
        /* Duplicate delivery: a piece re-requested on
         * BLOCK_PIECE_TIMEOUT_SECS can be answered twice
         * (slow original + re-request). Crediting it again
         * inflates pieces_complete past the genuinely-
         * delivered count, letting the swarm "complete"
         * with pieces never fetched — fold holes behind a
         * complete swarm (the live tail wedge: 67 pieces
         * credited-but-never-delivered). Clear the stale
         * pipeline slot but never double-count. */
        block_pipeline_clear_piece(node, piece_index);
    } else {
        block_swarm_receive_piece(&g_block_swarm,
                                  piece_index, node->id);
        g_block_swarm.last_complete_unix =
            (int64_t)platform_time_wall_time_t();
        block_pipeline_clear_piece(node, piece_index);

        if (block_swarm_is_complete(&g_block_swarm)) {
            printf("Block swarm complete: %u/%u pieces\n",
                   g_block_swarm.pieces_complete,
                   g_block_swarm.manifest.num_pieces);
            block_swarm_free(&g_block_swarm);
            g_block_swarm_active = false;
        }
    }
}

/* Piece failed its manifest hash (g_block_swarm_mutex held). Returns whether
 * the swarm session was abandoned; details land in *integrity_abandoned. */
static bool mp_zs_blkdata_fail_piece_locked(
    struct msg_processor *mp, struct p2p_node *node, uint32_t piece_index,
    struct block_swarm_abandonment *integrity_abandoned)
{
    block_swarm_fail_piece(&g_block_swarm, piece_index);
    fprintf(stderr, "Peer %s: block piece %u failed verification\n",  // obs-ok:helper-context-logged
           node->addr_name, piece_index);
    peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_CHUNK,
                        "bad block piece hash");
    /* The manifest-bound piece hash is a cryptographic
     * identity check: this response is disproven, though a
     * different peer could still serve a valid response.
     * C3 measured 3,114 retries across 62 pieces followed
     * by the full 90 s silent-stall wait. Fail closed on
     * this swarm session and arm its anti-flap cooldown;
     * safe legacy getdata resumes and every block still
     * traverses the canonical reducer. */
    return mp_block_swarm_abandon_locked(
        &g_block_swarm, &g_block_swarm_active,
        &g_block_swarm_reaped_unix,
        (int64_t)platform_time_wall_time_t(),
        integrity_abandoned);
}

/* Verify and credit one fully-read zblkdata piece. The caller keeps
 * ownership of (and frees) blk_hashes. */
static void mp_zs_blkdata_apply_piece(struct msg_processor *mp,
                                      struct p2p_node *node,
                                      struct byte_stream *s,
                                      uint8_t (*blk_hashes)[32],
                                      uint32_t block_count,
                                      uint32_t piece_index)
{
    struct block_piece_payload_ref *block_refs = NULL;
    struct block_swarm_abandonment integrity_abandoned = {0};
    bool did_abandon_integrity = false;
    if (!parse_block_piece_payload_refs(
            s, (const uint8_t (*)[32])blk_hashes,
            block_count, &block_refs)) {
        printf("Peer %s: bad zblkdata block payloads\n",
               node->addr_name);
        peer_scoring_record(mp->net_mgr, node,
                            PEER_OFFENCE_INVALID_PAYLOAD,
                            "bad zblkdata block payloads");
        return;
    }

    /* DEFENSIVE: bounds check before touching swarm */
    pthread_mutex_lock(&g_block_swarm_mutex);
    if (piece_index >= g_block_swarm.manifest.num_pieces) {
        pthread_mutex_unlock(&g_block_swarm_mutex);
        printf("Peer %s: zblkdata piece %u out of range "
               "(max %u)\n", node->addr_name, piece_index,
               g_block_swarm.manifest.num_pieces);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "zblkdata piece out of range");
        free(block_refs);
        return;
    }

    /* Compute piece hash and verify against manifest.
     * SHA3-256 of (piece_index || count || block_hashes[]).
     * This is the core integrity check — if the hash doesn't
     * match the manifest, the peer sent bad data. */
    uint8_t computed_hash[32];
    block_piece_hash(
        (const uint8_t (*)[32])blk_hashes,
        block_count, piece_index, computed_hash);

    bool verified = false;
    if (g_block_swarm.manifest.piece_hashes) {
        verified = memcmp(computed_hash,
            g_block_swarm.manifest.piece_hashes[piece_index],
            32) == 0;
    }
    bool payloads_accepted = block_refs != NULL;
    if (verified && block_refs)
        payloads_accepted = mp_zs_blkdata_submit_payloads_locked(
            mp, node, block_refs, block_count, piece_index);

    if (verified && payloads_accepted) {
        mp_zs_blkdata_credit_piece_locked(node, piece_index);
    } else if (verified) {
        LOG_INFO("net",
                 "zblkdata piece %u waiting for timeout retry "
                 "after local payload intake backpressure",
                 piece_index);
    } else {
        did_abandon_integrity = mp_zs_blkdata_fail_piece_locked(
            mp, node, piece_index, &integrity_abandoned);
    }
    pthread_mutex_unlock(&g_block_swarm_mutex);
    if (did_abandon_integrity) {
        mp_block_swarm_report_integrity_abandon(
            mp, node, piece_index, &integrity_abandoned);
    }
    free(block_refs);
}

/* Peer sends block piece data (block hashes for a piece).
 * DEFENSIVE: validate piece_index, block_count, and hash. */
static void mp_zs_on_block_data(struct msg_processor *mp,
                                struct p2p_node *node,
                                struct byte_stream *s)
{
    uint32_t piece_index = 0, block_count = 0;
    if (!stream_read_u32_le(s, &piece_index) ||
        !stream_read_u32_le(s, &block_count) ||
        block_count == 0 || block_count > BLOCKS_PER_PIECE) {
        printf("Peer %s: bad zblkdata (piece=%u count=%u)\n",
               node->addr_name, piece_index, block_count);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "bad zblkdata header");
    } else if (!g_block_swarm_active) {
        printf("Peer %s: zblkdata piece=%u but no block swarm\n",
               node->addr_name, piece_index);
    } else {
        /* Read block hashes */
        uint8_t (*blk_hashes)[32] = zcl_calloc(block_count, 32, "blk_piece_hashes");
        bool parse_ok = true;
        if (blk_hashes) {
            for (uint32_t i = 0; i < block_count && parse_ok; i++) {
                if (!stream_read_bytes(s, blk_hashes[i], 32))
                    parse_ok = false;
            }
        }

        if (parse_ok && blk_hashes) {
            mp_zs_blkdata_apply_piece(mp, node, s, blk_hashes,
                                      block_count, piece_index);
        } else {
            printf("Peer %s: truncated zblkdata\n", node->addr_name);
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                                "truncated zblkdata");
        }
        free(blk_hashes);
    }
}

/* Peer sends their piece availability bitmap.
 * DEFENSIVE: validate length is reasonable. */
static void mp_zs_on_block_bitmap(struct p2p_node *node,
                                  struct byte_stream *s)
{
    uint32_t bitmap_len = 0;
    if (!stream_read_u32_le(s, &bitmap_len) ||
        bitmap_len == 0 || bitmap_len > 65536) {
        printf("Peer %s: bad zblkbitmap len=%u\n",
               node->addr_name, bitmap_len);
    } else {
        uint8_t *bitmap = zcl_calloc(bitmap_len, 1, "blk_bitmap");
        if (bitmap && stream_read_bytes(s, bitmap, bitmap_len)) {
            /* Store on peer for rarest-first selection */
            free(node->blk_bitmap);
            node->blk_bitmap = bitmap;
            node->blk_bitmap_len = bitmap_len;

            /* Update global availability counts */
            if (g_block_swarm_active) {
                pthread_mutex_lock(&g_block_swarm_mutex);
                block_swarm_update_availability(&g_block_swarm,
                                                 bitmap, bitmap_len);
                pthread_mutex_unlock(&g_block_swarm_mutex);
            }
        } else {
            free(bitmap);
            printf("Peer %s: truncated zblkbitmap\n",
                   node->addr_name);
        }
    }
}

/* Route one ZCL23 sync message to its handler. Returns false only when a
 * handler refused because the swarm mutex was unavailable. */
bool mp_handle_zcl23_sync(struct msg_processor *mp,
                          struct p2p_node *node,
                          struct byte_stream *s,
                          const char *cmd)
{
    if (strcmp(cmd, MSG_SNAPSHOT_OFFER) == 0) {
        mp_zs_on_snapshot_offer(mp, node, s);
    } else if (strcmp(cmd, MSG_SNAPSHOT_REQ) == 0) {
        mp_serve_snapshot_req(mp, node, s);
    } else if (strcmp(cmd, MSG_SNAPSHOT_DATA) == 0) {
        mp_zs_on_snapshot_data(mp, node, s);
    } else if (strcmp(cmd, MSG_SNAPSHOT_END) == 0) {
        mp_zs_on_snapshot_end(mp, node);
    } else if (strcmp(cmd, MSG_FC_CHALLENGE) == 0) {
        mp_zs_on_fc_challenge(mp, node, s);
    } else if (strcmp(cmd, MSG_FC_PROOFS) == 0) {
        mp_zs_on_fc_proofs(mp, node, s);
    } else if (strcmp(cmd, MSG_MANIFEST) == 0) {
        return mp_zs_on_manifest(mp, node, s);
    } else if (strcmp(cmd, MSG_CHUNK_REQ) == 0) {
        mp_serve_chunk_req(mp, node, s);
    } else if (strcmp(cmd, MSG_CHUNK_DATA) == 0) {
        return mp_zs_on_chunk_data(mp, node, s);
    } else if (strcmp(cmd, MSG_BLOCK_MANIFEST) == 0) {
        mp_zs_on_block_manifest(mp, node, s);
    } else if (strcmp(cmd, MSG_BLOCK_REQ) == 0) {
        mp_serve_block_req(mp, node, s);
    } else if (strcmp(cmd, MSG_BLOCK_DATA) == 0) {
        mp_zs_on_block_data(mp, node, s);
    } else if (strcmp(cmd, MSG_BLOCK_BITMAP) == 0) {
        mp_zs_on_block_bitmap(node, s);
    }
    return true;
}

/* True when the peer still needs (or has a stale copy of) our current
 * snapshot offer. */
static bool mp_snapshot_offer_is_stale(const struct p2p_node *node,
                                       const struct snapshot_offer *offer)
{
    uint64_t offer_version =
        msg_processor_offer_cache_version();
    uint64_t snapshot_version =
        fast_sync_snapshot_cache_version();
    return node->zsync_sent == 0 ||
        node->zsync_offered_height <= 0 ||
        node->zsync_offered_count == 0 ||
        node->zsync_offer_version != offer_version ||
        node->zsync_snapshot_version != snapshot_version ||
        node->zsync_offered_height != offer->height ||
        node->zsync_offered_count != offer->num_utxos ||
        memcmp(node->zsync_offered_root,
               offer->utxo_root, 32) != 0 ||
        memcmp(node->zsync_offered_block,
               offer->block_hash, 32) != 0;
}

/* Offer a snapshot to a ZCL23 peer if we're significantly ahead.
 * Called from the per-peer trickle in msg_send_messages. */
void mp_snapshot_maybe_offer(struct msg_processor *mp,
                              struct p2p_node *node)
{
    if (!peer_supports_fast_sync(node->services))
        return;
    if (node->state == PEER_SNAPSHOT_SERVING ||
        node->state == PEER_SNAPSHOT_RECEIVING)
        return;

    int our_h = msg_get_height(mp);
    if (our_h <= 100)
        return;
    if (node->starting_height >= 0 &&
        our_h <= node->starting_height + 100)
        return;

    struct snapshot_offer offer;
    if (!msg_processor_get_offer(&offer))
        return;

    bool stale_offer = mp_snapshot_offer_is_stale(node, &offer);

    if (stale_offer) {
        node->zsync_sent = UINT64_MAX; /* mark: offered */
        event_emitf(EV_SNAPSHOT_OFFER_SENT, (uint32_t)node->id,
                    "h=%d utxos=%llu", offer.height,
                    (unsigned long long)offer.num_utxos);
        printf("Peer %s: offering snapshot (us=%d, peer=%d)\n",
               node->addr_name, our_h, node->starting_height);
        send_snapshot_offer_msg(node, &offer,
                                mp->params->pchMessageStart);
    }
}

/* Requeue stale chunks and give this peer its next chunk request.
 * g_swarm_mutex is held by the caller. */
static void mp_snapshot_tick_chunk_assign_locked(struct msg_processor *mp,
                                                 struct p2p_node *node)
{
    /* Requeue globally stale inflight chunks. A peer can disconnect and
     * lose node->swarm_inflight_chunk while g_swarm still marks that
     * chunk inflight; without the global sweep the final chunk can sit
     * at 2679/2680 forever with no peer able to claim it. */
    swarm_sync_handle_timeouts(&g_swarm, SWARM_CHUNK_TIMEOUT_SECS);

    /* Handle timeout: if this peer's chunk is stale, re-queue it */
    if (node->swarm_inflight_chunk >= 0) {
        int64_t now_sw = (int64_t)platform_time_wall_time_t();
        if (now_sw - node->swarm_chunk_req_time > SWARM_CHUNK_TIMEOUT_SECS) {
            uint32_t ci = (uint32_t)node->swarm_inflight_chunk;
            if (ci < g_swarm.manifest.num_chunks &&
                g_swarm.chunk_states[ci] == CHUNK_INFLIGHT) {
                g_swarm.chunk_states[ci] = CHUNK_NEEDED;
                g_swarm.chunk_peer[ci] = -1;
                if (g_swarm.chunks_inflight > 0)
                    g_swarm.chunks_inflight--;
                printf("Peer %s: chunk %u timed out, re-queuing\n",
                       node->addr_name, ci);
            }
            node->swarm_inflight_chunk = -1;
        }
    }

    /* If peer has no inflight chunk, assign the next needed one */
    if (node->swarm_inflight_chunk < 0) {
        int32_t ci = swarm_sync_assign_chunk(&g_swarm, node->id);
        if (ci >= 0) {
            node->swarm_inflight_chunk = ci;
            node->swarm_chunk_req_time = (int64_t)platform_time_wall_time_t();
            push_chunk_request(mp, node, (uint32_t)ci);
        }
    }
}

/* Rate-limited chunk-swarm progress line. Called with g_swarm_mutex held;
 * releases it on every path. */
static void mp_snapshot_tick_chunk_progress_unlock(struct msg_processor *mp)
{
    /* Progress display (rate-limited to every 5 seconds) */
    int64_t now_prog = (int64_t)platform_time_wall_time_t();
    if (now_prog - g_swarm_last_progress_time >= SWARM_PROGRESS_INTERVAL_SECS) {
        g_swarm_last_progress_time = now_prog;

        int progress = swarm_sync_progress(&g_swarm);
        uint32_t complete = g_swarm.chunks_complete;
        uint32_t total = g_swarm.manifest.num_chunks;
        uint32_t inflight = g_swarm.chunks_inflight;
        swarm_mutex_unlock();

        /* Count serving peers — under cs_nodes: the socket-thread
         * disconnect sweep frees nodes at refcount 0. g_swarm_mutex
         * was released above, so no lock-order hazard. */
        int serving_peers = 0;
        if (mp->net_mgr) {
            zcl_mutex_lock(&mp->net_mgr->cs_nodes);
            for (size_t i = 0; i < mp->net_mgr->num_nodes; i++) {
                struct p2p_node *n = mp->net_mgr->nodes[i];
                if (n && n->swarm_manifest_received)
                    serving_peers++;
            }
            zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
        }

        printf("Sync: %d%% (%u/%u chunks, %u inflight, %d peers serving)\n",
               progress, complete, total, inflight, serving_peers);
    } else {
        swarm_mutex_unlock();
    }
}

/* Swarm parallel chunk sync coordinator. For each connected ZCL23 peer with
 * no inflight chunk, assign one and send a zchunkreq. Also handle timeouts on
 * stale requests. Returns false when the swarm mutex was unavailable (the
 * whole tick stops, as before). */
static bool mp_snapshot_tick_chunk_swarm(struct msg_processor *mp,
                                         struct p2p_node *node)
{
    if (g_swarm_active && node->swarm_manifest_received &&
        node->state >= PEER_HANDSHAKE_COMPLETE) {

        if (!swarm_mutex_lock()) {
            LOG_ERROR("net", "snapshot send tick refused: swarm mutex "
                      "unavailable peer=%s", node->addr_name);
            return false;
        }

        mp_snapshot_tick_chunk_assign_locked(mp, node);
        mp_snapshot_tick_chunk_progress_unlock(mp);
    }
    return true;
}

/* Expire stale pipeline slots of this peer and fill empty ones with new piece
 * assignments. g_block_swarm_mutex is held on entry and exit (it is dropped
 * around each request push). */
static void mp_snapshot_tick_block_pipeline_locked(struct msg_processor *mp,
                                                   struct p2p_node *node,
                                                   int64_t now_bs)
{
    /* Handle timeouts on this peer's pipeline */
    block_swarm_handle_timeouts(&g_block_swarm,
                                BLOCK_PIECE_TIMEOUT_SECS);
    for (int pi = 0; pi < PIECE_PIPELINE_DEPTH; pi++) {
        int32_t pidx = node->blk_pipeline[pi].piece_index;
        if (pidx >= 0 &&
            now_bs - node->blk_pipeline[pi].request_time >
                BLOCK_PIECE_TIMEOUT_SECS) {
            if ((uint32_t)pidx < g_block_swarm.manifest.num_pieces &&
                g_block_swarm.piece_states[pidx] == CHUNK_INFLIGHT) {
                (void)block_swarm_requeue_piece(
                    &g_block_swarm, (uint32_t)pidx);
            }
            node->blk_pipeline[pi].piece_index = -1;
        }
    }

    /* Fill empty pipeline slots with new piece assignments */
    for (int pi = 0; pi < PIECE_PIPELINE_DEPTH; pi++) {
        if (node->blk_pipeline[pi].piece_index >= 0)
            continue; /* slot occupied */

        int32_t header_cap = block_swarm_local_header_cap(mp);
        int32_t assignment_cap =
            block_swarm_contiguous_window_cap(&g_block_swarm, header_cap);
        int32_t pidx = block_swarm_assign_piece_for_peer(
            &g_block_swarm, node->id, node->blk_bitmap,
            node->blk_bitmap_len, assignment_cap,
            block_swarm_peer_manifest_end(node));
        if (pidx < 0)
            break; /* no more pieces to assign */

        node->blk_pipeline[pi].piece_index = pidx;
        node->blk_pipeline[pi].request_time = now_bs;

        pthread_mutex_unlock(&g_block_swarm_mutex);
        push_block_piece_request(mp, node, (uint32_t)pidx);
        pthread_mutex_lock(&g_block_swarm_mutex);
    }
}

/* Rate-limited block-swarm progress line. Called with g_block_swarm_mutex
 * held; releases it on every path. */
static void mp_snapshot_tick_block_progress_unlock(void)
{
    /* Progress display (rate-limited) */
    int64_t now_bp = (int64_t)platform_time_wall_time_t();
    if (now_bp - g_block_swarm_last_progress >=
        SWARM_PROGRESS_INTERVAL_SECS) {
        g_block_swarm_last_progress = now_bp;
        int bprog = block_swarm_progress(&g_block_swarm);
        uint32_t bcomplete = g_block_swarm.pieces_complete;
        uint32_t btotal = g_block_swarm.manifest.num_pieces;
        uint32_t binflight = g_block_swarm.pieces_inflight;
        bool endgame = g_block_swarm.endgame;
        pthread_mutex_unlock(&g_block_swarm_mutex);

        printf("BlockSync: %d%% (%u/%u pieces, %u inflight%s)\n",
               bprog, bcomplete, btotal, binflight,
               endgame ? " [endgame]" : "");
    } else {
        pthread_mutex_unlock(&g_block_swarm_mutex);
    }
}

/* Block swarm coordinator: parallel block piece download. Only for ZCL23
 * peers with completed handshake. Legacy peers contribute via normal
 * getdata/block (handled by download manager). */
static void mp_snapshot_tick_block_swarm(struct msg_processor *mp,
                                         struct p2p_node *node)
{
    if (g_block_swarm_active && peer_supports_fast_sync(node->services) &&
        node->blk_manifest_received &&
        node->state >= PEER_HANDSHAKE_COMPLETE) {

        pthread_mutex_lock(&g_block_swarm_mutex);

        int64_t now_bs = (int64_t)platform_time_wall_time_t();
        mp_snapshot_tick_block_pipeline_locked(mp, node, now_bs);
        mp_snapshot_tick_block_progress_unlock();
    }
}

/* Serve the snapshot stream and drive both swarm coordinators. */
void mp_snapshot_send_tick(struct msg_processor *mp,
                            struct p2p_node *node)
{
    /* Stream fast sync UTXO chunks if serving this peer.
     * Zero-copy from in-memory buffer — no file I/O, no SQL.
     * Snapshot pre-loaded into RAM at startup (~97 MB). */
    if (node->state == PEER_SNAPSHOT_SERVING) {
        if (mp_snapshot_send_tick_serve(mp, node))
            return;
    }

    push_block_manifest_if_ready(mp, node);
    if (!mp_snapshot_tick_chunk_swarm(mp, node))
        return;
    mp_snapshot_tick_block_swarm(mp, node);
}
