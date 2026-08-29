/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block swarm: BitTorrent-style parallel block download state machine.
 * Piece assignment, receipt, timeout handling and availability tracking
 * for a manifest already built by fast_sync.c (block_piece_manifest_build /
 * block_piece_manifest_build_active_chain). This half never touches a
 * sqlite3 handle or the chain state directly, only the in-memory
 * struct block_swarm the caller owns. */

#include "platform/time_compat.h"
#include "net/fast_sync.h"
#include <stdlib.h>
#include <string.h>
#include "util/safe_alloc.h"
#include "util/log_macros.h"

bool block_swarm_init(struct block_swarm *bs,
                      const struct block_piece_manifest *manifest,
                      const char *datadir)
{
    GUARD(bs && manifest && manifest->num_pieces > 0, "sync", "block_swarm_init: invalid args (bs=%p manifest=%p)", (void *)bs, (void *)manifest);
    memset(bs, 0, sizeof(*bs));

    uint32_t n = manifest->num_pieces;

    /* Deep-copy manifest */
    bs->manifest = *manifest;
    bs->manifest.piece_hashes = zcl_calloc(n, 32, "piece_hashes");
    GUARD(bs->manifest.piece_hashes, "sync", "block_swarm_init: alloc piece_hashes failed for %u pieces", n);
    if (manifest->piece_hashes)
        memcpy(bs->manifest.piece_hashes, manifest->piece_hashes,
               (size_t)n * 32);

    bs->piece_states = zcl_calloc(n, sizeof(enum chunk_state), "piece_states");
    bs->piece_peer = zcl_calloc(n, sizeof(int), "piece_peer");
    bs->piece_request_time = zcl_calloc(n, sizeof(int64_t), "piece_req_time");
    bs->piece_availability = zcl_calloc(n, sizeof(uint32_t), "piece_availability");

    if (!bs->piece_states || !bs->piece_peer ||
        !bs->piece_request_time || !bs->piece_availability) {
        block_swarm_free(bs);
        LOG_FAIL("sync", "block_swarm_init: alloc state arrays failed for %u pieces", n);
    }

    for (uint32_t i = 0; i < n; i++)
        bs->piece_peer[i] = -1;

    bs->datadir = datadir;
    return true;
}

void block_swarm_free(struct block_swarm *bs)
{
    if (!bs) return;
    free(bs->manifest.piece_hashes);
    bs->manifest.piece_hashes = NULL;
    free(bs->piece_states);
    bs->piece_states = NULL;
    free(bs->piece_peer);
    bs->piece_peer = NULL;
    free(bs->piece_request_time);
    bs->piece_request_time = NULL;
    free(bs->piece_availability);
    bs->piece_availability = NULL;
}

static int32_t block_swarm_assign_piece_capped(struct block_swarm *bs,
                                                int peer_id,
                                                const uint8_t *peer_bitmap,
                                                size_t peer_bitmap_bytes,
                                                uint32_t max_piece_index)
{
    if (!bs || !bs->piece_states)
        LOG_RETURN(-1, "sync", "assign_piece: bs or piece_states is NULL");

    if (bs->manifest.num_pieces == 0)
        return -1;
    if (max_piece_index >= bs->manifest.num_pieces)
        max_piece_index = bs->manifest.num_pieces - 1;

    /* Endgame mode: if few pieces remain, use broadcast strategy.
     * Caller should request all remaining from all peers. */
    uint32_t remaining = bs->manifest.num_pieces - bs->pieces_complete;
    if (remaining <= ENDGAME_THRESHOLD && remaining > 0)
        bs->endgame = true;

    int32_t best = -1;
    uint32_t best_avail = UINT32_MAX;

    for (uint32_t i = 0; i <= max_piece_index; i++) {
        if (bs->piece_states[i] != CHUNK_NEEDED &&
            bs->piece_states[i] != CHUNK_FAILED)
            continue;

        /* In endgame, also consider INFLIGHT pieces for duplicate requests */
        if (bs->endgame && bs->piece_states[i] == CHUNK_INFLIGHT) {
            /* Allow re-request in endgame, but not from same peer */
            if (bs->piece_peer[i] == peer_id) continue;
        } else if (bs->piece_states[i] == CHUNK_INFLIGHT) {
            continue;
        }

        /* Check peer bitmap if available. Bits past the buffer's span count
         * as NOT held, so a short bitmap can never be indexed out of bounds
         * (same bound as block_swarm_update_availability). */
        if (peer_bitmap && !(i / 8 < peer_bitmap_bytes &&
                             (peer_bitmap[i / 8] & (1 << (i % 8)))))
            continue;

        /* Rarest-first: prefer pieces fewer peers have */
        uint32_t avail = bs->piece_availability
            ? bs->piece_availability[i] : 1;
        if (avail < best_avail || (avail == best_avail && best < 0)) {
            best_avail = avail;
            best = (int32_t)i;
        }
    }

    if (best >= 0) {
        bs->piece_states[best] = CHUNK_INFLIGHT;
        bs->piece_peer[best] = peer_id;
        bs->piece_request_time[best] = (int64_t)platform_time_wall_time_t();
        bs->pieces_inflight++;
    }
    return best;
}

/* Rarest-first piece selection: pick the needed piece with the lowest
 * availability count. Ties broken by sequential order (lower index first).
 * If peer_bitmap is non-NULL, only consider pieces the peer has; bits at or
 * past peer_bitmap_bytes read as absent. */
int32_t block_swarm_assign_piece(struct block_swarm *bs, int peer_id,
                                  const uint8_t *peer_bitmap,
                                  size_t peer_bitmap_bytes)
{
    if (!bs || bs->manifest.num_pieces == 0)
        return -1;
    return block_swarm_assign_piece_capped(
        bs, peer_id, peer_bitmap, peer_bitmap_bytes,
        bs->manifest.num_pieces - 1);
}

int32_t block_swarm_assign_piece_through_height(struct block_swarm *bs,
                                                 int peer_id,
                                                 const uint8_t *peer_bitmap,
                                                 size_t peer_bitmap_bytes,
                                                 int32_t max_height)
{
    if (!bs || !bs->piece_states)
        LOG_RETURN(-1, "sync",
                   "assign_piece_through_height: invalid swarm");
    if (max_height < bs->manifest.start_height)
        return -1;

    uint32_t max_piece = 0;
    if (max_height >= bs->manifest.end_height) {
        max_piece = bs->manifest.num_pieces - 1;
    } else {
        int64_t complete_blocks =
            (int64_t)max_height - (int64_t)bs->manifest.start_height + 1;
        uint32_t complete_pieces =
            (uint32_t)(complete_blocks / BLOCKS_PER_PIECE);
        if (complete_pieces == 0)
            return -1;
        max_piece = complete_pieces - 1;
    }
    return block_swarm_assign_piece_capped(
        bs, peer_id, peer_bitmap, peer_bitmap_bytes, max_piece);
}

bool block_swarm_receive_piece(struct block_swarm *bs,
                                uint32_t piece_index, int peer_id)
{
    GUARD(bs && piece_index < bs->manifest.num_pieces, "sync", "receive_piece: invalid args (bs=%p piece=%u)", (void *)bs, piece_index);
    (void)peer_id;

    bs->piece_states[piece_index] = CHUNK_COMPLETE;
    if (bs->pieces_inflight > 0) bs->pieces_inflight--;
    bs->pieces_complete++;

    /* Check endgame exit */
    uint32_t remaining = bs->manifest.num_pieces - bs->pieces_complete;
    if (remaining == 0) bs->endgame = false;

    return true;
}

void block_swarm_fail_piece(struct block_swarm *bs, uint32_t piece_index)
{
    if (!bs || piece_index >= bs->manifest.num_pieces) return;
    bs->piece_states[piece_index] = CHUNK_NEEDED;
    bs->piece_peer[piece_index] = -1;
    if (bs->pieces_inflight > 0) bs->pieces_inflight--;
    bs->pieces_failed++;
}

bool block_swarm_is_complete(const struct block_swarm *bs)
{
    GUARD(bs, "sync", "block_swarm_is_complete: bs is NULL");
    return bs->pieces_complete == bs->manifest.num_pieces;
}

int block_swarm_progress(const struct block_swarm *bs)
{
    if (!bs || bs->manifest.num_pieces == 0) return 0;
    return (int)(bs->pieces_complete * 100 / bs->manifest.num_pieces);
}

void block_swarm_handle_timeouts(struct block_swarm *bs, int timeout_secs)
{
    if (!bs || !bs->piece_states) return;

    int64_t now = (int64_t)platform_time_wall_time_t();
    for (uint32_t i = 0; i < bs->manifest.num_pieces; i++) {
        if (bs->piece_states[i] == CHUNK_INFLIGHT &&
            now - bs->piece_request_time[i] > timeout_secs) {
            bs->piece_states[i] = CHUNK_NEEDED;
            bs->piece_peer[i] = -1;
            bs->piece_request_time[i] = 0;
            if (bs->pieces_inflight > 0)
                bs->pieces_inflight--;
        }
    }
}

void block_swarm_update_availability(struct block_swarm *bs,
                                      const uint8_t *bitmap,
                                      uint32_t bitmap_len)
{
    if (!bs || !bitmap || !bs->piece_availability) return;
    for (uint32_t i = 0; i < bs->manifest.num_pieces; i++) {
        if (i / 8 < bitmap_len && (bitmap[i / 8] & (1 << (i % 8))))
            bs->piece_availability[i]++;
    }
}

uint32_t block_swarm_endgame_pieces(const struct block_swarm *bs,
                                     uint32_t *out_indices, uint32_t max)
{
    if (!bs || !out_indices || !bs->endgame) return 0;

    uint32_t count = 0;
    for (uint32_t i = 0; i < bs->manifest.num_pieces && count < max; i++) {
        if (bs->piece_states[i] != CHUNK_COMPLETE)
            out_indices[count++] = i;
    }
    return count;
}

uint32_t block_swarm_serialize_bitmap(const struct block_swarm *bs,
                                       uint8_t *out, uint32_t max_len)
{
    if (!bs || !out) return 0;
    uint32_t bytes = (bs->manifest.num_pieces + 7) / 8;
    if (bytes > max_len) bytes = max_len;
    memset(out, 0, bytes);
    for (uint32_t i = 0; i < bs->manifest.num_pieces && i / 8 < bytes; i++) {
        if (bs->piece_states[i] == CHUNK_COMPLETE)
            out[i / 8] |= (uint8_t)(1 << (i % 8));
    }
    return bytes;
}
