/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The snapshot/chunk/block-piece SERVE side: cached offer/manifest/
 * block-manifest publish + accessor APIs (populated by boot.c, read by
 * the handlers below), the client-puzzle PoW guard for zchunkreq/zblkreq,
 * the producers that advertise/serve our own state to peers
 * (send_snapshot_offer_msg, push_manifest, push_block_manifest,
 * build_block_piece_payloads), and the per-command serve handlers the
 * mp_handle_zcl23_sync dispatcher in msgprocessor_snapshot.c calls into
 * (mp_serve_snapshot_req, mp_serve_chunk_req, mp_serve_block_req) plus
 * the PEER_SNAPSHOT_SERVING chunk-streaming half of mp_snapshot_send_tick
 * (mp_snapshot_send_tick_serve).
 *
 * Split out of msgprocessor_snapshot.c (which owns the requester/client
 * side: mp_handle_zcl23_sync's dispatch table, push_chunk_request,
 * push_block_piece_request, parse_block_piece_payload_refs,
 * block_payload_submit_all, the swarm/block-swarm coordinators, and the
 * fc_rate_* FlyClient-challenge limiter) — pure code motion, no behavior
 * change. See msgprocessor_snapshot_internal.h for the shared
 * declarations this file promotes across the split. */

#include "platform/time_compat.h"
#include "msgprocessor_internal.h"
#include "msgprocessor_snapshot_internal.h"

#include "net/net_runtime_port.h"
#include "net/fast_sync.h"
#include "net/puzzle.h"
#include "net/peer_scoring.h"
#include "net/peer_lifecycle.h"
#include "net/snapshot_sync_contract.h"
#include "storage/disk_block_io.h"
#include "validation/main_state.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include "core/uint256.h"
#include "core/random.h"
#include "crypto/sha3.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Cached snapshot offer — pre-computed at startup, not in message handler.
 * Protected by g_offer_mutex to prevent struct tearing between the
 * background build thread (boot.c) and the P2P message handler. */
static struct snapshot_offer g_cached_offer;
static _Atomic bool g_cached_offer_valid = false;
static _Atomic uint64_t g_cached_offer_version = 0;
static pthread_mutex_t g_offer_mutex = PTHREAD_MUTEX_INITIALIZER;
struct fast_sync_rate_limiter g_rate_limiter = {0};
/* Separate limiter for block piece serving (zblkreq) — see
 * FAST_SYNC_MAX_BLOCK_PIECES_PER_HOUR in net/fast_sync.h. */
struct fast_sync_rate_limiter g_blk_rate_limiter = {0};

/* Cached manifest for parallel chunk sync (built in background at startup). */
struct sync_manifest g_cached_manifest;
_Atomic bool g_cached_manifest_valid = false;
static _Atomic uint64_t g_cached_manifest_version = 0;
static _Atomic uint32_t g_cached_manifest_num_chunks = 0;
static pthread_mutex_t g_manifest_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Cached block piece manifest (built in background).
 * Non-static: accessed from boot.c via extern. */
struct block_piece_manifest g_cached_block_manifest;
_Atomic bool g_cached_block_manifest_valid = false;
int32_t g_manifest_built_at_height = 0; /* height when manifest was last built */
static _Atomic uint64_t g_cached_block_manifest_version = 0;
static pthread_mutex_t g_block_manifest_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Rebuild manifest when chain grows this many blocks beyond the cached one.
 * This ensures new peers always get a reasonably fresh manifest. */
#define MANIFEST_REFRESH_BLOCKS 1000

/* ── Client-puzzle PoW guard for zchunkreq / zblkreq (PoW-DDoS posture) ──
 *
 * Cost of the two ops this guards (see the lane note for full numbers):
 *   - zchunkreq: one fast_sync_serve_chunk() DB read of up to
 *     SYNC_CHUNK_SIZE (500) UTXO rows (script up to 520 bytes each,
 *     ~571 B/row decoded) plus serialization — a single 4-byte request can
 *     pull ~285 KB out of storage.
 *   - zblkreq: up to BLOCKS_PER_PIECE (512) full block bodies read from
 *     disk and serialized, capped at MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB)
 *     per response — a single 4-byte request can force up to 2 MiB of
 *     disk reads. This is the "large range" expensive op in this file.
 *   - zsnapreq (legacy full-snapshot serve) already goes through
 *     snapsync_validate_serve_request()'s existing PoW gate — untouched,
 *     reused as-is.
 *
 * Design: a STATELESS puzzle, per the lane note. No per-peer server state,
 * no stored rotating seed table (unlike struct puzzle_gate, which this
 * deliberately does NOT reuse because that primitive keeps a mutex-guarded
 * seed + single-use ring; this guard only needs the pure, already-tested
 * digest/verify primitives it exposes):
 *
 *   challenge   = SHA3-256(domain[16] || request_kind[1] ||
 *                          request_index[4 LE] || time_bucket[8 LE])
 *                 where domain is the fixed lane tag below — it exists to
 *                 namespace the digest, not to hide anything. It must NOT
 *                 be process-random material: a requester that cannot
 *                 derive the challenge can never produce a valid nonce, so
 *                 arming a secret-bound variant would permanently deny
 *                 every external client (the in-process tests could not
 *                 catch that, since solver and verifier share the secret
 *                 there).
 *   solve       = nonce such that SHA3-256(challenge || 0^32 || 0 || nonce)
 *                 has D leading zero bits (reuses the hardened
 *                 puzzle_verify/puzzle_solve digest from
 *                 fast_sync.c, passing a zero peer_token/ts since peer
 *                 request binding and freshness are already carried by
 *                 `challenge` itself).
 *
 * The derivation is public by construction. Request kind and index are the
 * first fields of zchunkreq/zblkreq, and the time bucket is explicit LE.
 * The server-observed peer address is deliberately excluded: a requester
 * behind NAT cannot know which address the server observes. Per-address
 * abuse containment remains the existing fast_sync_rate_check() gate.
 * Arming is still deferred —
 * requesters do not attach nonces yet, so an armed gate today would deny
 * honest legacy peers outright (see msgprocessor.h for the constants and
 * the adaptive-difficulty ramp).
 *
 * Difficulty is 0 (mechanism present, gate open) until armed via
 * msg_snapshot_pow_set_armed(true) — see lane note point 3. When
 * disarmed, zchunkreq/zblkreq behave exactly as before (existing
 * msg_snapshot_serving_allowed / range / fast_sync_rate_check gates only).
 * When armed, a peer that omits or fails the puzzle simply doesn't get
 * this particular response — same as today's rate-limited path: no ban,
 * no peer_scoring penalty, so old peers that never learned to attach a
 * solution degrade to (existing-rate-limit-only) throttled service rather
 * than being dropped or scored.
 *
 * SNAP_POW_* difficulty/window constants live in net/msgprocessor.h (not
 * here) so the test suite can assert scaling bounds without duplicating
 * magic numbers. */

static _Atomic bool g_snap_pow_armed = false;

static pthread_mutex_t g_snap_pow_load_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_snap_pow_window_start = 0;
static uint32_t g_snap_pow_reqs_in_window = 0;

static void snap_pow_challenge(uint8_t request_kind, uint32_t request_index,
                               int64_t time_bucket, uint8_t out[32])
{
    static const uint8_t snap_pow_domain[16] = MSG_SNAP_POW_DOMAIN;
    uint8_t index_le[4];
    uint8_t bucket_le[8];
    uint64_t bucket_bits = (uint64_t)time_bucket;
    for (size_t i = 0; i < sizeof(index_le); i++)
        index_le[i] = (uint8_t)(request_index >> (8u * i));
    for (size_t i = 0; i < sizeof(bucket_le); i++)
        bucket_le[i] = (uint8_t)(bucket_bits >> (8u * i));
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, snap_pow_domain, sizeof(snap_pow_domain));
    sha3_256_write(&ctx, &request_kind, sizeof(request_kind));
    sha3_256_write(&ctx, index_le, sizeof(index_le));
    sha3_256_write(&ctx, bucket_le, sizeof(bucket_le));
    sha3_256_finalize(&ctx, out);
}

/* Recent-request-count load proxy → adaptive difficulty (caller-supplied
 * clock so tests are deterministic). Bumps the counter as a side effect,
 * matching the "note this request happened" contract every call site
 * needs (one call per admission decision). */
static int snap_pow_note_request_and_get_bits(int64_t now)
{
    pthread_mutex_lock(&g_snap_pow_load_mutex);
    if (now - g_snap_pow_window_start > SNAP_POW_WINDOW_SECS) {
        g_snap_pow_window_start = now;
        g_snap_pow_reqs_in_window = 0;
    }
    int bits = SNAP_POW_MIN_BITS;
    if (g_snap_pow_reqs_in_window > SNAP_POW_SOFT_RATE) {
        bits += (int)((g_snap_pow_reqs_in_window - SNAP_POW_SOFT_RATE) /
                      SNAP_POW_RATE_STEP);
    }
    if (bits > SNAP_POW_MAX_BITS) bits = SNAP_POW_MAX_BITS;
    if (g_snap_pow_reqs_in_window < UINT32_MAX)
        g_snap_pow_reqs_in_window++;
    pthread_mutex_unlock(&g_snap_pow_load_mutex);
    return bits;
}

static bool snap_pow_solve_at(uint8_t request_kind, uint32_t request_index,
                              int64_t at_time,
                              int difficulty_bits, uint64_t *nonce_out)
{
    int64_t bucket = at_time / SNAP_POW_BUCKET_SECS;
    uint8_t challenge[32];
    static const uint8_t zero32[32] = {0};
    snap_pow_challenge(request_kind, request_index, bucket, challenge);
    return puzzle_solve(challenge, zero32, 0, difficulty_bits,
                                  nonce_out);
}

/* Admit a zchunkreq/zblkreq at clock `now`. `nonce` is the peer-supplied
 * solution (NULL if the request carried none). Checks the current and
 * prior time bucket so a solve that started just before a rotation still
 * verifies (matches the +1 grace epoch struct puzzle_gate uses). */
static bool snap_pow_admit_at(uint8_t request_kind, uint32_t request_index,
                              int64_t now,
                              const uint64_t *nonce)
{
    int bits = snap_pow_note_request_and_get_bits(now);
    if (!atomic_load(&g_snap_pow_armed))
        return true;   /* difficulty-0 posture: mechanism wired, gate open */
    if (!nonce)
        return false;  /* no solution attached — no ban, just no serve */

    int64_t bucket = now / SNAP_POW_BUCKET_SECS;
    uint8_t challenge[32];
    static const uint8_t zero32[32] = {0};

    snap_pow_challenge(request_kind, request_index, bucket, challenge);
    if (puzzle_verify(challenge, zero32, 0, *nonce, bits))
        return true;
    snap_pow_challenge(request_kind, request_index, bucket - 1, challenge);
    return puzzle_verify(challenge, zero32, 0, *nonce, bits);
}

static bool snap_pow_admit(uint8_t request_kind, uint32_t request_index,
                           const uint64_t *nonce)
{
    return snap_pow_admit_at(request_kind, request_index,
                            (int64_t)platform_time_wall_time_t(), nonce);
}

void msg_snapshot_pow_set_armed(bool armed)
{
    atomic_store(&g_snap_pow_armed, armed);
}

bool msg_snapshot_pow_is_armed(void)
{
    return atomic_load(&g_snap_pow_armed);
}

bool msgprocessor_test_snap_pow_challenge(uint8_t request_kind,
                                          uint32_t request_index,
                                          int64_t at_time,
                                          uint8_t out[32])
{
    if (!out)
        return false;
    snap_pow_challenge(request_kind, request_index,
                       at_time / SNAP_POW_BUCKET_SECS, out);
    return true;
}

bool msgprocessor_test_snap_pow_solve(uint8_t request_kind,
                                      uint32_t request_index,
                                      int64_t at_time, int difficulty_bits,
                                      uint64_t *nonce_out)
{
    return snap_pow_solve_at(request_kind, request_index, at_time,
                             difficulty_bits, nonce_out);
}

bool msgprocessor_test_snap_pow_admit_at(uint8_t request_kind,
                                         uint32_t request_index,
                                         int64_t at_time,
                                         const uint64_t *nonce)
{
    return snap_pow_admit_at(request_kind, request_index, at_time, nonce);
}

int msgprocessor_test_snap_pow_bits_at(int64_t at_time)
{
    return snap_pow_note_request_and_get_bits(at_time);
}

void msgprocessor_test_snap_pow_reset(void)
{
    pthread_mutex_lock(&g_snap_pow_load_mutex);
    g_snap_pow_window_start = 0;
    g_snap_pow_reqs_in_window = 0;
    pthread_mutex_unlock(&g_snap_pow_load_mutex);
    atomic_store(&g_snap_pow_armed, false);
}

static size_t block_payload_compact_size_len(uint64_t n)
{
    if (n < 253u)
        return 1u;
    if (n <= 0xffffu)
        return 3u;
    if (n <= 0xffffffffu)
        return 5u;
    return 9u;
}

static void msg_manifest_reset(struct sync_manifest *manifest)
{
    if (!manifest)
        return;
    sync_manifest_free(manifest);
    memset(manifest, 0, sizeof(*manifest));
}

static void msg_block_manifest_reset(struct block_piece_manifest *manifest)
{
    if (!manifest)
        return;
    block_piece_manifest_free(manifest);
    memset(manifest, 0, sizeof(*manifest));
}

static bool msg_manifest_is_reasonable(const struct sync_manifest *manifest)
{
    if (!manifest)
        LOG_FAIL("net", "manifest is NULL");
    if (manifest->num_chunks == 0)
        LOG_FAIL("net", "manifest has zero chunks");
    if (manifest->chunk_size == 0)
        LOG_FAIL("net", "manifest has zero chunk_size");
    if (!manifest->chunk_hashes)
        LOG_FAIL("net", "manifest chunk_hashes is NULL");
    return true;
}

static bool msg_block_manifest_is_reasonable(
    const struct block_piece_manifest *manifest)
{
    if (!manifest)
        LOG_FAIL("net", "block manifest is NULL");
    if (manifest->num_pieces == 0)
        LOG_FAIL("net", "block manifest has zero pieces");
    if (manifest->start_height > manifest->end_height)
        LOG_FAIL("net", "block manifest start_height %d > end_height %d",
                 manifest->start_height, manifest->end_height);
    if (!manifest->piece_hashes)
        LOG_FAIL("net", "block manifest piece_hashes is NULL");
    return true;
}

static bool msg_snapshot_serving_allowed(void)
{
    return net_runtime_snapshot_state_is_sovereign(NULL, 0);
}

/* Thread-safe accessor: update cached snapshot offer from boot.c */
void msg_processor_update_offer(const struct snapshot_offer *offer)
{
    if (!offer)
        return;
    pthread_mutex_lock(&g_offer_mutex);
    g_cached_offer = *offer;
    atomic_store(&g_cached_offer_valid, true);
    g_cached_offer_version++;
    pthread_mutex_unlock(&g_offer_mutex);
}

bool msg_processor_get_offer(struct snapshot_offer *offer)
{
    if (!offer)
        LOG_FAIL("net", "offer output pointer is NULL");

    /* The cache is not authority.  A node can become assisted after an offer
     * was prepared (for example during recovery), so re-check the complete
     * state trust boundary before every advertisement or serving batch. */
    if (!msg_snapshot_serving_allowed()) {
        memset(offer, 0, sizeof(*offer));
        return false;
    }

    pthread_mutex_lock(&g_offer_mutex);
    bool ok = atomic_load(&g_cached_offer_valid);
    if (ok)
        *offer = g_cached_offer;
    else
        memset(offer, 0, sizeof(*offer));
    pthread_mutex_unlock(&g_offer_mutex);
    return ok;
}

void msg_processor_invalidate_offer(void)
{
    pthread_mutex_lock(&g_offer_mutex);
    memset(&g_cached_offer, 0, sizeof(g_cached_offer));
    atomic_store(&g_cached_offer_valid, false);
    g_cached_offer_version++;
    pthread_mutex_unlock(&g_offer_mutex);
}

uint64_t msg_processor_offer_cache_version(void)
{
    pthread_mutex_lock(&g_offer_mutex);
    uint64_t version = g_cached_offer_version;
    pthread_mutex_unlock(&g_offer_mutex);
    return version;
}

bool msg_processor_publish_manifest(struct sync_manifest *manifest)
{
    if (!msg_manifest_is_reasonable(manifest))
        LOG_FAIL("net", "cannot publish unreasonable manifest");

    pthread_mutex_lock(&g_manifest_mutex);
    if (atomic_load(&g_cached_manifest_valid))
        msg_manifest_reset(&g_cached_manifest);
    g_cached_manifest = *manifest;
    atomic_store(&g_cached_manifest_num_chunks, g_cached_manifest.num_chunks);
    memset(manifest, 0, sizeof(*manifest));
    atomic_store(&g_cached_manifest_valid, true);
    g_cached_manifest_version++;
    pthread_mutex_unlock(&g_manifest_mutex);
    return true;
}

void msg_processor_invalidate_manifest(void)
{
    pthread_mutex_lock(&g_manifest_mutex);
    if (atomic_load(&g_cached_manifest_valid))
        msg_manifest_reset(&g_cached_manifest);
    atomic_store(&g_cached_manifest_valid, false);
    atomic_store(&g_cached_manifest_num_chunks, 0);
    g_cached_manifest_version++;
    pthread_mutex_unlock(&g_manifest_mutex);
}

uint64_t msg_processor_manifest_cache_version(void)
{
    pthread_mutex_lock(&g_manifest_mutex);
    uint64_t version = g_cached_manifest_version;
    pthread_mutex_unlock(&g_manifest_mutex);
    return version;
}

bool msg_processor_get_manifest_header(struct sync_manifest *out)
{
    if (!out)
        LOG_FAIL("net", "manifest output pointer is NULL");
    if (!msg_snapshot_serving_allowed()) {
        memset(out, 0, sizeof(*out));
        return false;
    }

    pthread_mutex_lock(&g_manifest_mutex);
    bool ok = atomic_load(&g_cached_manifest_valid);
    if (ok) {
        *out = g_cached_manifest;
        out->chunk_hashes = NULL;
    } else {
        memset(out, 0, sizeof(*out));
    }
    pthread_mutex_unlock(&g_manifest_mutex);
    return ok;
}

bool msg_processor_copy_manifest_hashes(uint8_t (**out_hashes)[32],
                                        uint32_t *out_count)
{
    if (!out_hashes || !out_count)
        LOG_FAIL("net", "copy_manifest_hashes: NULL output");
    *out_hashes = NULL;
    *out_count = 0;
    if (!msg_snapshot_serving_allowed())
        return false;

    pthread_mutex_lock(&g_manifest_mutex);
    bool ok = atomic_load(&g_cached_manifest_valid)
              && g_cached_manifest.chunk_hashes
              && g_cached_manifest.num_chunks > 0
              && g_cached_manifest.num_chunks <= MANIFEST_MAX_CHUNKS;
    if (ok) {
        uint32_t n = g_cached_manifest.num_chunks;
        uint8_t (*copy)[32] = zcl_calloc(n, 32, "manifest_hashes_copy");
        if (copy) {
            memcpy(copy, g_cached_manifest.chunk_hashes, (size_t)n * 32);
            *out_hashes = copy;
            *out_count = n;
        } else {
            ok = false;
        }
    }
    pthread_mutex_unlock(&g_manifest_mutex);
    return ok;
}

bool msg_processor_publish_block_manifest(struct block_piece_manifest *manifest,
                                         int32_t built_at_height)
{
    if (!msg_block_manifest_is_reasonable(manifest))
        LOG_FAIL("net", "cannot publish unreasonable block manifest");

    pthread_mutex_lock(&g_block_manifest_mutex);
    if (atomic_load(&g_cached_block_manifest_valid))
        msg_block_manifest_reset(&g_cached_block_manifest);
    g_cached_block_manifest = *manifest;
    memset(manifest, 0, sizeof(*manifest));
    g_manifest_built_at_height = built_at_height;
    atomic_store(&g_cached_block_manifest_valid, true);
    g_cached_block_manifest_version++;
    pthread_mutex_unlock(&g_block_manifest_mutex);
    return true;
}

void msg_processor_invalidate_block_manifest(void)
{
    pthread_mutex_lock(&g_block_manifest_mutex);
    if (atomic_load(&g_cached_block_manifest_valid))
        msg_block_manifest_reset(&g_cached_block_manifest);
    g_manifest_built_at_height = 0;
    atomic_store(&g_cached_block_manifest_valid, false);
    g_cached_block_manifest_version++;
    pthread_mutex_unlock(&g_block_manifest_mutex);
}

uint64_t msg_processor_block_manifest_cache_version(void)
{
    pthread_mutex_lock(&g_block_manifest_mutex);
    uint64_t version = g_cached_block_manifest_version;
    pthread_mutex_unlock(&g_block_manifest_mutex);
    return version;
}

bool msg_processor_get_block_manifest_header(struct block_piece_manifest *out,
                                            int32_t *built_at_height)
{
    if (!out)
        LOG_FAIL("net", "block manifest output pointer is NULL");

    pthread_mutex_lock(&g_block_manifest_mutex);
    bool ok = atomic_load(&g_cached_block_manifest_valid);
    if (ok) {
        *out = g_cached_block_manifest;
        out->piece_hashes = NULL;
        if (built_at_height)
            *built_at_height = g_manifest_built_at_height;
    } else {
        memset(out, 0, sizeof(*out));
        if (built_at_height)
            *built_at_height = 0;
    }
    pthread_mutex_unlock(&g_block_manifest_mutex);
    return ok;
}

static bool msg_processor_copy_block_manifest(struct block_piece_manifest *out,
                                              int32_t *built_at_height)
{
    if (!out)
        LOG_FAIL("net", "block manifest copy output pointer is NULL");
    memset(out, 0, sizeof(*out));

    pthread_mutex_lock(&g_block_manifest_mutex);
    bool ok = atomic_load(&g_cached_block_manifest_valid) &&
              g_cached_block_manifest.piece_hashes &&
              g_cached_block_manifest.num_pieces > 0;
    if (ok) {
        uint32_t n = g_cached_block_manifest.num_pieces;
        uint8_t (*copy)[32] = zcl_calloc(n, 32, "block_manifest_hashes_copy");
        if (copy) {
            *out = g_cached_block_manifest;
            memcpy(copy, g_cached_block_manifest.piece_hashes, (size_t)n * 32);
            out->piece_hashes = copy;
            if (built_at_height)
                *built_at_height = g_manifest_built_at_height;
        } else {
            ok = false;
            if (built_at_height)
                *built_at_height = 0;
        }
    } else if (built_at_height) {
        *built_at_height = 0;
    }
    pthread_mutex_unlock(&g_block_manifest_mutex);
    return ok;
}

/* Serialize and send a snapshot offer to a peer.
 * Wire prefix: height(4) + block_hash(32) + utxo_root(32) + mmr_root(32) +
 *       num_utxos(8) + total_bytes(8) + mmb_root(32) = 148 bytes.
 * V2 appends protocol/schema/peer_tip/chainwork. Older ZCL23 nodes read
 * 116 or 148 bytes and ignore the trailing fields. */
void send_snapshot_offer_msg(struct p2p_node *node,
                             const struct snapshot_offer *offer,
                             const unsigned char *msg_start)
{
    uint64_t offer_version = msg_processor_offer_cache_version();
    uint64_t snapshot_version = fast_sync_snapshot_cache_version();

    p2p_node_begin_message(node, MSG_SNAPSHOT_OFFER, msg_start);
    struct byte_stream os;
    stream_init(&os, 192);
    stream_write_i32_le(&os, offer->height);
    stream_write_bytes(&os, offer->block_hash, 32);
    stream_write_bytes(&os, offer->utxo_root, 32);
    stream_write_bytes(&os, offer->mmr_root, 32);
    stream_write_u64_le(&os, offer->num_utxos);
    stream_write_u64_le(&os, offer->total_bytes);
    stream_write_bytes(&os, offer->mmb_root, 32); /* appended: backward compat */
    stream_write_u32_le(&os, offer->protocol_version);
    stream_write_u32_le(&os, offer->snapshot_schema_version);
    stream_write_i32_le(&os, offer->peer_tip_height);
    stream_write_bytes(&os, offer->chain_work, 32);
    p2p_node_write_message_data(node, os.data, os.size);
    p2p_node_end_message(node);
    stream_free(&os);

    memcpy(node->zsync_offered_root, offer->utxo_root, 32);
    memcpy(node->zsync_offered_mmr, offer->mmr_root, 32);
    memcpy(node->zsync_offered_block, offer->block_hash, 32);
    node->zsync_offered_height = offer->height;
    node->zsync_offered_count = offer->num_utxos;
    node->zsync_offer_version = offer_version;
    node->zsync_snapshot_version = snapshot_version;
}

/* Send our manifest to a ZCL23 peer. Called after version/verack handshake. */
void push_manifest(struct msg_processor *mp, struct p2p_node *node)
{
    struct sync_manifest m;
    uint8_t (*hashes)[32] = NULL;
    uint32_t hash_count = 0;

    if (node->swarm_manifest_sent ||
        !msg_processor_get_manifest_header(&m))
        return;
    if (m.num_chunks == 0 || m.num_chunks > MANIFEST_MAX_CHUNKS) {
        fprintf(stderr, "push_manifest: num_chunks %u out of [1,%u]\n",  // obs-ok:helper-context-logged
                m.num_chunks, MANIFEST_MAX_CHUNKS);
        return;
    }
    if (!msg_processor_copy_manifest_hashes(&hashes, &hash_count)
        || hash_count != m.num_chunks) {
        fprintf(stderr, "push_manifest: chunk_hashes unavailable "  // obs-ok:helper-context-logged
                "(count=%u vs num_chunks=%u)\n", hash_count, m.num_chunks);
        free(hashes);
        return;
    }

    struct byte_stream s;
    stream_init(&s, 116 + (size_t)m.num_chunks * 32);
    stream_write_i32_le(&s, m.height);
    stream_write_bytes(&s, m.block_hash, 32);
    stream_write_u64_le(&s, m.num_utxos);
    stream_write_u32_le(&s, m.num_chunks);
    stream_write_u32_le(&s, m.chunk_size);
    stream_write_bytes(&s, m.merkle_root, 32);
    stream_write_bytes(&s, m.utxo_sha3, 32);
    /* per-chunk SHA3-256 hashes so the receiver can reject a
     * corrupt or attacker-substituted chunk before it lands in the
     * utxos table. The receiver Merkle-reconstructs merkle_root from
     * these hashes and bans the peer on mismatch. */
    for (uint32_t i = 0; i < m.num_chunks; i++)
        stream_write_bytes(&s, hashes[i], 32);

    p2p_node_begin_message(node, MSG_MANIFEST, mp->params->pchMessageStart);
    p2p_node_write_message_data(node, s.data, s.size);
    p2p_node_end_message(node);
    stream_free(&s);
    free(hashes);

    node->swarm_manifest_sent = true;
    printf("Peer %s: sent manifest (h=%d, %u chunks)\n",
           node->addr_name, m.height, m.num_chunks);
}

/* Send our block piece manifest to a ZCL23 peer.
 * SAFETY: never call this for legacy peers — they will ignore it,
 * but we avoid sending unknown messages to be a good network citizen. */
void push_block_manifest(struct msg_processor *mp,
                                 struct p2p_node *node)
{
    struct block_piece_manifest m;

    if (node->blk_manifest_sent)
        return;
    if (!peer_supports_fast_sync(node->services))
        return; /* guard: only send to ZCL23 peers */

    if (!msg_processor_copy_block_manifest(&m, NULL))
        return;

    struct byte_stream s;
    size_t hashes_len = (size_t)m.num_pieces * 32;
    stream_init(&s, 4 + 4 + 4 + 32 + 32 + hashes_len);
    stream_write_i32_le(&s, m.start_height);
    stream_write_i32_le(&s, m.end_height);
    stream_write_u32_le(&s, m.num_pieces);
    stream_write_bytes(&s, m.tip_hash, 32);
    stream_write_bytes(&s, m.merkle_root, 32);
    for (uint32_t i = 0; i < m.num_pieces; i++)
        stream_write_bytes(&s, m.piece_hashes[i], 32);

    p2p_node_begin_message(node, MSG_BLOCK_MANIFEST,
                            mp->params->pchMessageStart);
    p2p_node_write_message_data(node, s.data, s.size);
    p2p_node_end_message(node);
    stream_free(&s);
    block_piece_manifest_free(&m);

    node->blk_manifest_sent = true;
    printf("Peer %s: sent block manifest (h=%d..%d, %u pieces)\n",
           node->addr_name, m.start_height, m.end_height, m.num_pieces);
}

static bool build_block_piece_payloads(struct msg_processor *mp,
                                       int32_t start_height,
                                       const uint8_t (*hashes)[32],
                                       uint32_t block_count,
                                       size_t max_payload_bytes,
                                       struct byte_stream *payloads)
{
    if (!mp || !mp->main_state || !hashes || !payloads || block_count == 0 ||
        max_payload_bytes == 0)
        return false;

    stream_init(payloads, (size_t)block_count * 4096);
    for (uint32_t i = 0; i < block_count; i++) {
        int32_t h = start_height + (int32_t)i;
        struct block_index *bi =
            active_chain_at(&mp->main_state->chain_active, h);
        if (!bi || !bi->phashBlock || !(bi->nStatus & BLOCK_HAVE_DATA)) {
            stream_free(payloads);
            return false;
        }

        struct block blk;
        block_init(&blk);
        if (!read_block_from_disk_index(&blk, bi, mp->datadir)) {
            block_free(&blk);
            stream_free(payloads);
            return false;
        }

        struct uint256 disk_hash;
        block_get_hash(&blk, &disk_hash);
        if (memcmp(disk_hash.data, hashes[i], 32) != 0) {
            block_free(&blk);
            stream_free(payloads);
            return false;
        }

        struct byte_stream raw;
        stream_init(&raw, 4096);
        bool ok = block_serialize(&blk, &raw) &&
                  raw.size <= BLOCK_PIECE_MAX_BLOCK_BYTES;
        if (ok) {
            size_t len_prefix = block_payload_compact_size_len(raw.size);
            if (payloads->size > max_payload_bytes ||
                len_prefix > max_payload_bytes - payloads->size ||
                raw.size > max_payload_bytes - payloads->size - len_prefix)
                ok = false;
        }
        ok = ok &&
                  stream_write_compact_size(payloads, raw.size) &&
                  stream_write_bytes(payloads, raw.data, raw.size);
        stream_free(&raw);
        block_free(&blk);
        if (!ok) {
            stream_free(payloads);
            return false;
        }
    }
    return true;
}

/* Serve a zsnapreq (peer asking for our full snapshot). Extracted from
 * mp_handle_zcl23_sync's MSG_SNAPSHOT_REQ branch — the original inline
 * `return true;` on a truncated request became `return;` here since
 * mp_handle_zcl23_sync unconditionally returns true at the end of its
 * dispatch chain regardless of which branch ran. */
void mp_serve_snapshot_req(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s)
{
    /* ── Route: zsnapreq → snapsync_validate_serve_request ─ */
    int32_t from_h = 0;
    if (!stream_read_i32_le(s, &from_h)) {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_MESSAGE, "truncated zsnapreq");
        return; /* skip — caller frees msg */
    }

    /* Pass remaining bytes (PoW data) to controller */
    size_t pow_len = s->size - s->read_pos;
    const uint8_t *pow_data = pow_len > 0 ? s->data + s->read_pos : NULL;
    enum snapsync_serve_result srv = snapsync_validate_serve_request(
        pow_data, pow_len, node->addr.svc.addr.ip);

    switch (srv) {
    case SNAPSYNC_SERVE_OK:
        {
            struct snapshot_offer offer;
            if (msg_processor_get_offer(&offer)) {
            uint64_t current_offer_version =
                msg_processor_offer_cache_version();
            uint64_t current_snapshot_version =
                fast_sync_snapshot_cache_version();
            bool stale_offer =
                node->zsync_offered_height <= 0 ||
                node->zsync_offered_count == 0 ||
                node->zsync_offer_version != current_offer_version ||
                node->zsync_snapshot_version != current_snapshot_version ||
                node->zsync_offered_height != offer.height ||
                node->zsync_offered_count != offer.num_utxos ||
                memcmp(node->zsync_offered_root, offer.utxo_root, 32) != 0 ||
                memcmp(node->zsync_offered_block, offer.block_hash, 32) != 0;
            if (stale_offer) {
                printf("Peer %s: stale snapshot request "
                       "(offered h=%d/%llu offer_v=%llu snap_v=%llu, "
                       "current h=%d/%llu offer_v=%llu snap_v=%llu); "
                       "re-offering latest snapshot\n",
                       node->addr_name,
                       node->zsync_offered_height,
                       (unsigned long long)node->zsync_offered_count,
                       (unsigned long long)node->zsync_offer_version,
                       (unsigned long long)node->zsync_snapshot_version,
                       offer.height,
                       (unsigned long long)offer.num_utxos,
                       (unsigned long long)current_offer_version,
                       (unsigned long long)current_snapshot_version);
                send_snapshot_offer_msg(node, &offer,
                                        mp->params->pchMessageStart);
                break;
            }
            struct snapsync_serve_start serve = {0};
            snapsync_build_serve_start(&serve, node->zsync_offered_count);
            if (serve.should_reset_progress) {
                node->zsync_offset = 0;
                node->zsync_sent = 0;
                node->zsync_file_offset = 0;
                node->zsync_file_size = 0;
            }
            if (serve.should_update_peer_state)
                peer_set_state_checked((uint32_t)node->id, &node->state,
                    serve.peer_state, "serving snapshot request");
            if (serve.should_reset_cursor) {
                node->zsync_cursor_valid = false;
                memset(node->zsync_cursor_txid, 0, 32);
                node->zsync_cursor_vout = 0;
            }
            node->zsync_total = node->zsync_offered_count;
            printf("Peer %s: serving snapshot (h=%d, %llu UTXOs)\n",
                   node->addr_name, node->zsync_offered_height,
                   (unsigned long long)node->zsync_offered_count);
            } else {
                printf("Peer %s: snapshot not ready yet\n",
                       node->addr_name);
            }
        }
        break;
    case SNAPSYNC_SERVE_BAD_POW:
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
            "zsnapreq without valid PoW");
        break;
    case SNAPSYNC_SERVE_RATE_LIMITED:
        printf("Peer %s: rate limited\n", node->addr_name);
        break;
    default:
        break;
    }
}

/* Serve a zchunkreq (peer asking for one UTXO chunk by index). Extracted
 * from mp_handle_zcl23_sync's MSG_CHUNK_REQ branch — no control-flow
 * change, the branch never returned early. */
void mp_serve_chunk_req(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s)
{
    /* Peer requests a specific chunk by index — serve it. An
     * optional 8-byte PoW nonce may follow the index (see the
     * client-puzzle guard note above); legacy peers that never
     * append one are unaffected while the guard is disarmed
     * (default), and degrade to the existing rate limiter (no
     * ban) once armed. */
    uint32_t chunk_index = 0;
    if (!stream_read_u32_le(s, &chunk_index)) {
        printf("Peer %s: bad zchunkreq\n", node->addr_name);
    } else {
        uint64_t pow_nonce = 0;
        bool have_pow_nonce = stream_remaining(s) >= 8 &&
                              stream_read_u64_le(s, &pow_nonce);
        printf("Peer %s: zchunkreq raw %u\n",
               node->addr_name, chunk_index);
        uint32_t num_chunks = atomic_load(&g_cached_manifest_num_chunks);
        if (!msg_snapshot_serving_allowed() ||
            !atomic_load(&g_cached_manifest_valid) ||
            num_chunks == 0) {
            printf("Peer %s: zchunkreq but no manifest ready\n",
                   node->addr_name);
        } else if (chunk_index >= num_chunks) {
            printf("Peer %s: zchunkreq index %u out of range (%u)\n",
                   node->addr_name, chunk_index,
                   num_chunks);
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_MESSAGE,
                                "zchunkreq out of range");
        } else if (!fast_sync_rate_check(&g_rate_limiter,
                                          node->addr.svc.addr.ip)) {
            printf("Peer %s: rate limited on chunk request\n",
                   node->addr_name);
        } else if (!snap_pow_admit(MSG_SNAP_POW_KIND_CHUNK, chunk_index,
                                   have_pow_nonce ? &pow_nonce : NULL)) {
            printf("Peer %s: zchunkreq missing/invalid client puzzle "
                   "(armed)\n", node->addr_name);
        } else {
            printf("Peer %s: zchunkreq %u\n",
                   node->addr_name, chunk_index);
            struct utxo_chunk *chunk = zcl_calloc(
                1, sizeof(struct utxo_chunk), "utxo_chunk");
            if (chunk &&
                fast_sync_serve_chunk(mp->datadir, chunk_index, chunk)) {
                /* Serialize chunk data into message. */
                struct byte_stream cs;
                stream_init(&cs, 65536);
                stream_write_u32_le(&cs, chunk->chunk_index);
                stream_write_u32_le(&cs, chunk->num_entries);
                for (uint32_t i = 0; i < chunk->num_entries; i++) {
                    stream_write_bytes(&cs, chunk->entries[i].txid, 32);
                    stream_write_i32_le(&cs,
                                        (int32_t)chunk->entries[i].vout);
                    stream_write_i64_le(&cs, chunk->entries[i].value);
                    stream_write_i32_le(&cs, chunk->entries[i].height);
                    stream_write_u8(&cs,
                                    chunk->entries[i].is_coinbase
                                        ? 1 : 0);
                    stream_write_u16_le(&cs,
                                        chunk->entries[i].script_len);
                    if (chunk->entries[i].script_len > 0)
                        stream_write_bytes(&cs,
                                           chunk->entries[i].script,
                                           chunk->entries[i].script_len);
                }

                if (msg_snapshot_serving_allowed()) {
                    p2p_node_begin_message(
                        node, MSG_CHUNK_DATA,
                        mp->params->pchMessageStart);
                    p2p_node_write_message_data(node, cs.data,
                                                cs.size);
                    p2p_node_end_message(node);
                    printf("Peer %s: served zchunk %u (%u entries, "
                           "%zu bytes)\n", node->addr_name,
                           chunk_index, chunk->num_entries, cs.size);
                } else {
                    printf("Peer %s: zchunk %u withheld after trust "
                           "state changed\n", node->addr_name,
                           chunk_index);
                }
                stream_free(&cs);
            } else {
                printf("Peer %s: failed to serve zchunk %u\n",
                       node->addr_name, chunk_index);
            }
            free(chunk);
        }
    }
}

/* Serve a zblkreq (peer asking for one block piece by index). Extracted
 * from mp_handle_zcl23_sync's MSG_BLOCK_REQ branch — no control-flow
 * change, the branch never returned early. */
void mp_serve_block_req(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s)
{
    /* Peer requests a specific block piece by index.
     * SAFETY: only serve if we have a valid manifest and the
     * piece index is in range. Rate-limited like chunk requests.
     * An optional 8-byte PoW nonce may follow the index (see the
     * client-puzzle guard note above); same graceful-degrade
     * contract as zchunkreq. */
    uint32_t piece_index = 0;
    struct block_piece_manifest bm;
    if (!stream_read_u32_le(s, &piece_index)) {
        printf("Peer %s: bad zblkreq\n", node->addr_name);
    } else {
    uint64_t pow_nonce = 0;
    bool have_pow_nonce = stream_remaining(s) >= 8 &&
                          stream_read_u64_le(s, &pow_nonce);
    if (!msg_processor_get_block_manifest_header(&bm, NULL)) {
        printf("Peer %s: zblkreq but no block manifest\n",
               node->addr_name);
    } else if (piece_index >= bm.num_pieces) {
        printf("Peer %s: zblkreq %u out of range (%u)\n",
               node->addr_name, piece_index,
               bm.num_pieces);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_MESSAGE,
                            "zblkreq out of range");
    } else if (!fast_sync_rate_check_n(&g_blk_rate_limiter,
                                       node->addr.svc.addr.ip,
                                       FAST_SYNC_MAX_BLOCK_PIECES_PER_HOUR,
                                       FAST_SYNC_MAX_GLOBAL_BLOCK_PIECES_PER_HOUR)) {
        printf("Peer %s: rate limited on block piece\n",
               node->addr_name);
    } else if (!snap_pow_admit(MSG_SNAP_POW_KIND_BLOCK, piece_index,
                               have_pow_nonce ? &pow_nonce : NULL)) {
        printf("Peer %s: zblkreq missing/invalid client puzzle "
               "(armed)\n", node->addr_name);
    } else {
        /* Serve the piece: send block hashes for this piece range.
         * The requester can then verify against their manifest. */
        int32_t piece_start = bm.start_height
            + (int32_t)(piece_index * BLOCKS_PER_PIECE);
        int32_t piece_end = piece_start + BLOCKS_PER_PIECE - 1;
        if (piece_end > bm.end_height)
            piece_end = bm.end_height;

        uint8_t piece_hashes[BLOCKS_PER_PIECE][32];
        int block_count = mp->block_hashes_range
            ? mp->block_hashes_range(piece_start, piece_end,
                                     piece_hashes, BLOCKS_PER_PIECE,
                                     mp->block_hashes_range_ctx)
            : 0;
        if (block_count > 0) {
            struct byte_stream payloads;
            size_t fixed_len = 4u + 4u + 32u * (size_t)block_count;
            size_t max_payload_bytes =
                fixed_len < MAX_PROTOCOL_MESSAGE_LENGTH
                    ? MAX_PROTOCOL_MESSAGE_LENGTH - fixed_len
                    : 0u;
            bool have_payloads =
                max_payload_bytes > 0 &&
                build_block_piece_payloads(
                    mp, piece_start,
                    (const uint8_t (*)[32])piece_hashes,
                    (uint32_t)block_count, max_payload_bytes,
                    &payloads);
            struct byte_stream bs_msg;
            stream_init(&bs_msg, fixed_len +
                        (have_payloads ? payloads.size : 0));
            stream_write_u32_le(&bs_msg, piece_index);
            stream_write_u32_le(&bs_msg, (uint32_t)block_count);
            for (int bi = 0; bi < block_count; bi++)
                stream_write_bytes(&bs_msg, piece_hashes[bi], 32);
            if (have_payloads)
                stream_write_bytes(&bs_msg, payloads.data,
                                   payloads.size);
            p2p_node_begin_message(node, MSG_BLOCK_DATA,
                                    mp->params->pchMessageStart);
            p2p_node_write_message_data(node, bs_msg.data, bs_msg.size);
            p2p_node_end_message(node);
            stream_free(&bs_msg);
            if (have_payloads)
                stream_free(&payloads);
        }
    }
    }
}

/* The PEER_SNAPSHOT_SERVING half of mp_snapshot_send_tick. Extracted as
 * bool-returning: the original inline code did `return;` out of the
 * WHOLE mp_snapshot_send_tick on a stale-offer reset, skipping the
 * swarm/block-swarm coordinator sections that follow it — this returns
 * true in that one case so the caller can replicate the same early
 * return, and false otherwise so the caller falls through normally. */
bool mp_snapshot_send_tick_serve(struct msg_processor *mp,
                                 struct p2p_node *node)
{
    struct snapshot_offer offer;
    int64_t buf_size = 0;
    const uint8_t *buf = fast_sync_get_snapshot_buf(&buf_size);
    if (buf && buf_size > 0 && msg_processor_get_offer(&offer)) {
        uint64_t current_offer_version = msg_processor_offer_cache_version();
        uint64_t current_snapshot_version =
            fast_sync_snapshot_cache_version();
        bool stale_offer =
            node->zsync_offered_height <= 0 ||
            node->zsync_offered_count == 0 ||
            node->zsync_offer_version != current_offer_version ||
            node->zsync_snapshot_version != current_snapshot_version ||
            node->zsync_offered_height != offer.height ||
            node->zsync_offered_count != offer.num_utxos ||
            memcmp(node->zsync_offered_root, offer.utxo_root, 32) != 0 ||
            memcmp(node->zsync_offered_block, offer.block_hash, 32) != 0;
        if (stale_offer) {
            printf("Peer %s: snapshot changed while serving; "
                   "resetting to re-offer latest snapshot\n",
                   node->addr_name);
            node->zsync_offset = 0;
            node->zsync_sent = 0;
            node->zsync_file_offset = 0;
            node->zsync_file_size = 0;
            peer_set_state_checked((uint32_t)node->id, &node->state,
                                   PEER_ACTIVE,
                                   "snapshot serve stale offer");
            return true;
        }
        /* Send chunks from memory, respecting TCP flow control.
         * Stop when send buffer exceeds 8MB to avoid unbounded
         * backlog that stalls the receiver.  The receiver's stall
         * detector fires at 120s — we must not queue more than
         * the receiver can process in that window. */
        for (int batch = 0; batch < 200; batch++) {
            if (node->send_size > 8 * 1024 * 1024)
                break;  /* backpressure: wait for drain */
            struct snapsync_serve_step step;
            if (!snapsync_prepare_serve_step(&step, node, buf, buf_size).ok)
                break;
            if (step.action == SNAPSYNC_SERVE_ACTION_NONE)
                break;
            if (step.action == SNAPSYNC_SERVE_ACTION_SEND_END) {
                /* EOF — all UTXOs sent */
                struct snapsync_serve_complete complete = {0};
                snapsync_build_serve_complete(&complete);
                p2p_node_begin_message(node, MSG_SNAPSHOT_END,
                                        mp->params->pchMessageStart);
                p2p_node_end_message(node);
                if (complete.should_update_peer_state) {
                    peer_set_state_checked((uint32_t)node->id, &node->state,
                                           complete.peer_state,
                                           "snapshot serve done");
                }
                printf("Peer %s: snapshot complete (%llu UTXOs, "
                       "%llu chunks sent)\n",
                       node->addr_name,
                       (unsigned long long)node->zsync_offset,
                       (unsigned long long)node->zsync_sent);
                break;
            }

            /* Send chunk directly from memory — true zero-copy */
            p2p_node_begin_message(node, MSG_SNAPSHOT_DATA,
                                    mp->params->pchMessageStart);
            p2p_node_write_message_data(node, buf + step.chunk_offset,
                                        step.chunk_len);
            p2p_node_end_message(node);

            if (node->zsync_sent % 100 == 0) {
                printf("Peer %s: sent %llu/%llu UTXOs (%.0f%%)\n",
                       node->addr_name,
                       (unsigned long long)node->zsync_offset,
                       (unsigned long long)node->zsync_total,
                       node->zsync_total > 0 ?
                           100.0 * (double)node->zsync_offset / (double)node->zsync_total : 0);
            }
        }
    } else {
        fprintf(stderr, "Peer %s: no snapshot in memory\n", node->addr_name);  // obs-ok:helper-context-logged
        peer_set_state_checked((uint32_t)node->id, &node->state,
                               PEER_ACTIVE, "no snapshot buffer");
    }
    return false;
}
