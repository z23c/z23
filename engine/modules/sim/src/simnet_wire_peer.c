/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Deterministic adversarial byte generators for simnet_wire.
 */

#include "simnet_wire_internal.h"

#include "core/serialize.h"
#include "event/event.h"
#include "net/peer_scoring.h"
#include "net/version.h"
#include "platform/rng.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIMNET_WIRE_FLOOD_FRAMES_PER_TICK 256u
#define SIMNET_WIRE_FLOOD_MAX_TICKS 16u
#define SIMNET_WIRE_SLOWLORIS_PAYLOAD_LEN 10016u

static void wire_random_bytes(uint8_t *out, size_t len)
{
    if (!out && len > 0)
        return;
    size_t off = 0;
    while (off < len) {
        uint64_t r = rng_u64();
        size_t take = len - off;
        if (take > sizeof(r))
            take = sizeof(r);
        memcpy(out + off, &r, take);
        off += take;
    }
}

static bool wire_ping_payload(uint8_t out[8])
{
    if (!out)
        LOG_FAIL("simnet.wire.peer", "NULL ping payload");
    uint64_t nonce = rng_u64();
    memcpy(out, &nonce, sizeof(nonce));
    return true;
}

static bool wire_inv_payload(struct byte_stream *s)
{
    if (!s)
        LOG_FAIL("simnet.wire.peer", "NULL inv payload");
    struct uint256 hash;
    wire_random_bytes(hash.data, sizeof(hash.data));
    struct inv_item inv;
    inv_item_init_typed(&inv, MSG_TX, &hash);
    return stream_write_compact_size(s, 1) &&
           inv_item_serialize(&inv, s);
}

static bool wire_empty_count_payload(struct byte_stream *s)
{
    if (!s)
        LOG_FAIL("simnet.wire.peer", "NULL count payload");
    return stream_write_compact_size(s, 0);
}

static enum simnet_wire_malformed_case wire_select_malformed(
    const struct wire_peer *peer)
{
    if (!peer)
        return SIMNET_WIRE_MALFORMED_BAD_CHECKSUM;
    if (peer->malformed_case != SIMNET_WIRE_MALFORMED_RANDOM)
        return peer->malformed_case;
    switch (peer->child_seed % 3u) {
    case 0:
        return SIMNET_WIRE_MALFORMED_BAD_CHECKSUM;
    case 1:
        return SIMNET_WIRE_MALFORMED_OVERSIZED;
    default:
        return SIMNET_WIRE_MALFORMED_BAD_MAGIC;
    }
}

static enum simnet_wire_bad_handshake_case wire_select_bad_handshake(
    const struct wire_peer *peer)
{
    if (!peer)
        return SIMNET_WIRE_BAD_HANDSHAKE_DATA_BEFORE_VERSION;
    if (peer->bad_handshake_case != SIMNET_WIRE_BAD_HANDSHAKE_RANDOM)
        return peer->bad_handshake_case;
    switch (peer->child_seed % 3u) {
    case 0:
        return SIMNET_WIRE_BAD_HANDSHAKE_DATA_BEFORE_VERSION;
    case 1:
        return SIMNET_WIRE_BAD_HANDSHAKE_VERACK_FIRST;
    default:
        return SIMNET_WIRE_BAD_HANDSHAKE_GARBAGE_AFTER_VERACK;
    }
}

static bool wire_send_bad_checksum(struct simnet_wire *wire, size_t peer_id)
{
    uint8_t payload[8];
    if (!wire_ping_payload(payload))
        return false;

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (!simnet_wire_frame(wire, "ping", payload, sizeof(payload),
                           &frame, &frame_len))
        return false;

    size_t checksum_off = MESSAGE_START_SIZE + COMMAND_SIZE +
                          sizeof(unsigned int);
    size_t byte_off = checksum_off + (size_t)(rng_u64() % 4u);
    frame[byte_off] ^= (uint8_t)(1u << (rng_u64() % 8u));
    bool ok = simnet_wire_enqueue_raw(wire, peer_id, frame, frame_len);
    free(frame);
    peer_misbehaving(&wire->nm, wire->peers[peer_id].node, 10,
                     "simnet malformed frame: bad checksum");
    return ok;
}

static bool wire_send_oversized(struct simnet_wire *wire, size_t peer_id)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.peer", "invalid oversized peer=%zu", peer_id);
    size_t total = MSG_HEADER_SIZE + 1u;
    uint8_t *frame = zcl_malloc(total, "simnet_wire_oversized_frame");
    if (!frame)
        LOG_FAIL("simnet.wire.peer", "OOM oversized frame");

    struct msg_header hdr;
    msg_header_init_full(&hdr, wire->params->pchMessageStart, "ping",
                         MAX_PROTOCOL_MESSAGE_LENGTH + 1u);
    hdr.nChecksum ^= 0x01010101u;
    memcpy(frame, &hdr, MSG_HEADER_SIZE);
    frame[MSG_HEADER_SIZE] = (uint8_t)rng_u64();
    bool ok = simnet_wire_enqueue_raw(wire, peer_id, frame, total);
    free(frame);
    peer_misbehaving(&wire->nm, wire->peers[peer_id].node, 10,
                     "simnet malformed frame: oversized");
    return ok;
}

static bool wire_send_bad_magic(struct simnet_wire *wire, size_t peer_id)
{
    uint8_t payload[8];
    if (!wire_ping_payload(payload))
        return false;

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (!simnet_wire_frame(wire, "ping", payload, sizeof(payload),
                           &frame, &frame_len))
        return false;
    size_t byte_off = (size_t)(rng_u64() % MESSAGE_START_SIZE);
    frame[byte_off] ^= (uint8_t)(1u << (rng_u64() % 8u));
    bool ok = simnet_wire_enqueue_raw(wire, peer_id, frame, frame_len);
    free(frame);
    peer_misbehaving(&wire->nm, wire->peers[peer_id].node, 10,
                     "simnet malformed frame: bad magic");
    return ok;
}

static bool wire_start_malformed(struct simnet_wire *wire, size_t peer_id)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    enum simnet_wire_malformed_case c = wire_select_malformed(peer);
    peer->link.open = true;
    peer->adversary_started = true;
    peer->adversary_done = true;
    if (c == SIMNET_WIRE_MALFORMED_BAD_CHECKSUM)
        return wire_send_bad_checksum(wire, peer_id);
    if (c == SIMNET_WIRE_MALFORMED_OVERSIZED)
        return wire_send_oversized(wire, peer_id);
    return wire_send_bad_magic(wire, peer_id);
}

static bool wire_start_data_before_version(struct simnet_wire *wire,
                                           size_t peer_id)
{
    uint8_t payload[8];
    if (!wire_ping_payload(payload))
        return false;
    peer_misbehaving(&wire->nm, wire->peers[peer_id].node, 10,
                     "simnet bad handshake: data before version");
    return simnet_wire_enqueue_frame(wire, peer_id, "ping", payload,
                                     sizeof(payload));
}

static bool wire_start_verack_first(struct simnet_wire *wire, size_t peer_id)
{
    peer_misbehaving(&wire->nm, wire->peers[peer_id].node, 10,
                     "simnet bad handshake: verack first");
    return simnet_wire_enqueue_frame(wire, peer_id, "verack", NULL, 0);
}

static bool wire_start_garbage_after_verack(struct simnet_wire *wire,
                                            size_t peer_id)
{
    uint8_t garbage[4];
    wire_random_bytes(garbage, sizeof(garbage));
    peer_misbehaving(&wire->nm, wire->peers[peer_id].node, 10,
                     "simnet bad handshake: garbage after verack");
    return simnet_wire_enqueue_version(wire, peer_id) &&
           simnet_wire_enqueue_frame(wire, peer_id, "verack", NULL, 0) &&
           simnet_wire_enqueue_raw(wire, peer_id, garbage, sizeof(garbage));
}

static bool wire_start_bad_handshake(struct simnet_wire *wire, size_t peer_id)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    enum simnet_wire_bad_handshake_case c =
        wire_select_bad_handshake(peer);
    peer->link.open = true;
    peer->adversary_started = true;
    peer->adversary_done = true;
    if (c == SIMNET_WIRE_BAD_HANDSHAKE_DATA_BEFORE_VERSION)
        return wire_start_data_before_version(wire, peer_id);
    if (c == SIMNET_WIRE_BAD_HANDSHAKE_VERACK_FIRST)
        return wire_start_verack_first(wire, peer_id);
    return wire_start_garbage_after_verack(wire, peer_id);
}

static bool wire_start_stream_adversary(struct simnet_wire *wire,
                                        size_t peer_id,
                                        enum simnet_wire_peer_kind kind)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    peer->link.open = true;
    peer->adversary_started = true;
    if (kind == SIMNET_WIRE_PEER_FLOOD)
        peer->flood_active = true;
    /* D2: every stream adversary now completes its OWN version/verack
     * handshake against its OWN p2p_node (not just peer 0), so a flood /
     * slowloris / replay / reorder peer at any slot exercises the real
     * post-handshake dispatch path on an independently-tracked connection. */
    if (!peer->version_sent && !simnet_wire_peer_handshake_complete(wire, peer_id))
        return simnet_wire_enqueue_version(wire, peer_id);
    return true;
}

static enum simnet_byzantine_class wire_select_invalid_block_kind(
    const struct wire_peer *peer)
{
    static const enum simnet_byzantine_class kinds[] = {
        SIMNET_BYZ_BAD_MERKLE,
        SIMNET_BYZ_BAD_CB_AMOUNT,
        SIMNET_BYZ_BIP30_DUP_TXID,
        SIMNET_BYZ_MISSING_SPEND,
        SIMNET_BYZ_IMMATURE_SPEND,
        SIMNET_BYZ_NEGATIVE_OUTPUT,
        SIMNET_BYZ_OVERFLOW_OUTPUT,
        SIMNET_BYZ_OVERSIZE_VTX,
    };
    size_t idx = peer ? (size_t)(peer->child_seed %
                                 (sizeof(kinds) / sizeof(kinds[0]))) : 0;
    return kinds[idx];
}

static enum simnet_byzantine_class wire_select_invalid_header_kind(
    const struct wire_peer *peer)
{
    static const enum simnet_byzantine_class kinds[] = {
        SIMNET_BYZ_INVALID_POW,
        SIMNET_BYZ_BAD_BITS,
        SIMNET_BYZ_BAD_TIMESTAMP,
    };
    size_t idx = peer ? (size_t)(peer->child_seed %
                                 (sizeof(kinds) / sizeof(kinds[0]))) : 0;
    return kinds[idx];
}

static bool wire_mark_not_implemented(struct simnet_wire *wire,
                                      size_t peer_id,
                                      enum simnet_wire_peer_kind kind)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.peer", "invalid not-implemented peer=%zu",
                 peer_id);
    wire->peers[peer_id].kind = kind;
    wire->peers[peer_id].not_implemented = true;
    wire->not_implemented_peers++;
    return true;
}

bool simnet_wire_start_malformed_peer(
    struct simnet_wire *wire, size_t peer_id,
    enum simnet_wire_malformed_case malformed_case)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.peer", "invalid malformed peer=%zu", peer_id);
    wire->peers[peer_id].malformed_case = malformed_case;
    return simnet_wire_start_peer_kind(
        wire, peer_id, SIMNET_WIRE_PEER_MALFORMED_FRAME);
}

bool simnet_wire_start_bad_handshake_peer(
    struct simnet_wire *wire, size_t peer_id,
    enum simnet_wire_bad_handshake_case handshake_case)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.peer", "invalid bad-handshake peer=%zu",
                 peer_id);
    wire->peers[peer_id].bad_handshake_case = handshake_case;
    return simnet_wire_start_peer_kind(
        wire, peer_id, SIMNET_WIRE_PEER_BAD_HANDSHAKE);
}

bool simnet_wire_start_invalid_block_peer(
    struct simnet_wire *wire, size_t peer_id,
    enum simnet_byzantine_class kind)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.peer", "invalid byz block peer=%zu",
                 peer_id);
    wire->peers[peer_id].kind = SIMNET_WIRE_PEER_INVALID_BLOCK;
    return simnet_wire_byzantine_start(
        wire, peer_id, kind, SIMNET_BYZ_TIER_CONNECT_BLOCK);
}

bool simnet_wire_start_invalid_header_peer(
    struct simnet_wire *wire, size_t peer_id,
    enum simnet_byzantine_class kind)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.peer", "invalid byz header peer=%zu",
                 peer_id);
    wire->peers[peer_id].kind = SIMNET_WIRE_PEER_INVALID_HEADER;
    return simnet_wire_byzantine_start(
        wire, peer_id, kind, SIMNET_BYZ_TIER_HEADER_ADMISSION);
}

bool simnet_wire_start_peer_kind(struct simnet_wire *wire, size_t peer_id,
                                 enum simnet_wire_peer_kind kind)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.peer", "invalid peer kind start peer=%zu",
                 peer_id);
    struct wire_peer *peer = &wire->peers[peer_id];
    peer->kind = kind;
    if (kind == SIMNET_WIRE_PEER_HONEST)
        return simnet_wire_start_honest_peer(wire, peer_id);
    if (kind == SIMNET_WIRE_PEER_MALFORMED_FRAME)
        return wire_start_malformed(wire, peer_id);
    if (kind == SIMNET_WIRE_PEER_BAD_HANDSHAKE)
        return wire_start_bad_handshake(wire, peer_id);
    if (kind == SIMNET_WIRE_PEER_FLOOD ||
        kind == SIMNET_WIRE_PEER_SLOWLORIS ||
        kind == SIMNET_WIRE_PEER_REPLAY ||
        kind == SIMNET_WIRE_PEER_REORDER)
        return wire_start_stream_adversary(wire, peer_id, kind);
    if (kind == SIMNET_WIRE_PEER_INVALID_BLOCK)
        return simnet_wire_start_invalid_block_peer(
            wire, peer_id, wire_select_invalid_block_kind(peer));
    if (kind == SIMNET_WIRE_PEER_INVALID_HEADER)
        return simnet_wire_start_invalid_header_peer(
            wire, peer_id, wire_select_invalid_header_kind(peer));
    return wire_mark_not_implemented(wire, peer_id, kind);
}

static bool wire_make_flood_frame(struct simnet_wire *wire, uint64_t n,
                                  uint8_t **out, size_t *out_len)
{
    if (!wire || !out || !out_len)
        LOG_FAIL("simnet.wire.peer", "invalid flood frame request");
    struct byte_stream s;
    stream_init(&s, 64);
    const char *cmd = "inv";
    bool ok = true;
    if ((n % 3u) == 0) {
        cmd = "inv";
        ok = wire_inv_payload(&s);
    } else if ((n % 3u) == 1) {
        cmd = "addr";
        ok = wire_empty_count_payload(&s);
    } else {
        cmd = "getdata";
        ok = wire_empty_count_payload(&s);
    }
    if (ok)
        ok = simnet_wire_frame(wire, cmd, s.data, s.size, out, out_len);
    stream_free(&s);
    return ok;
}

static bool wire_tick_flood(struct simnet_wire *wire, size_t peer_id,
                            bool *progress)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    if (!peer->flood_active || peer->adversary_done)
        return true;
    if (!simnet_wire_peer_handshake_complete(wire, peer_id))
        return true;

    for (size_t i = 0; i < SIMNET_WIRE_FLOOD_FRAMES_PER_TICK; i++) {
        uint8_t *frame = NULL;
        size_t frame_len = 0;
        if (!wire_make_flood_frame(wire, peer->flood_ticks *
                                   SIMNET_WIRE_FLOOD_FRAMES_PER_TICK + i,
                                   &frame, &frame_len))
            return false;
        bool ok = simnet_wire_deliver_raw_now(wire, peer_id, frame,
                                              frame_len);
        free(frame);
        if (!ok)
            return false;
    }
    peer->flood_ticks++;
    *progress = true;
    if (peer->flood_ticks >= SIMNET_WIRE_FLOOD_MAX_TICKS) {
        peer->flood_active = false;
        peer->adversary_done = true;
    }
    return true;
}

static bool wire_build_slowloris(struct simnet_wire *wire, size_t peer_id)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    if (peer->slowloris_frame)
        return true;
    uint8_t *payload = zcl_malloc(SIMNET_WIRE_SLOWLORIS_PAYLOAD_LEN,
                                  "simnet_wire_slowloris_payload");
    if (!payload)
        LOG_FAIL("simnet.wire.peer", "OOM slowloris payload");
    wire_random_bytes(payload, SIMNET_WIRE_SLOWLORIS_PAYLOAD_LEN);
    if (!wire_ping_payload(payload)) {
        free(payload);
        return false;
    }

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    bool ok = simnet_wire_frame(wire, "ping", payload,
                                SIMNET_WIRE_SLOWLORIS_PAYLOAD_LEN,
                                &frame, &frame_len);
    free(payload);
    if (!ok)
        return false;
    peer->slowloris_frame = frame;
    peer->slowloris_len = frame_len;
    peer->slowloris_pos = 0;
    return true;
}

static bool wire_tick_slowloris(struct simnet_wire *wire, size_t peer_id,
                                bool *progress)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    if (peer->adversary_done)
        return true;
    if (!simnet_wire_peer_handshake_complete(wire, peer_id))
        return true;
    for (size_t i = 0; i < wire->peer_count; i++) {
        if (i != peer_id && wire->peers[i].kind == SIMNET_WIRE_PEER_FLOOD &&
            wire->peers[i].flood_active)
            return true;
    }
    if (!wire_build_slowloris(wire, peer_id))
        return false;
    if (peer->slowloris_pos >= peer->slowloris_len) {
        peer->adversary_done = true;
        return true;
    }

    const uint8_t *b = peer->slowloris_frame + peer->slowloris_pos;
    if (!simnet_wire_deliver_raw_now(wire, peer_id, b, 1))
        return false;
    peer->slowloris_pos++;
    *progress = true;
    if (peer->slowloris_pos >= peer->slowloris_len)
        peer->adversary_done = true;
    return true;
}

/* Build a one-item `inv` frame announcing (type, hash). Used by the REPLAY
 * and REORDER adversaries to emit real, well-formed block/tx announcements. */
static bool wire_build_single_inv(struct simnet_wire *wire, int type,
                                  const struct uint256 *hash,
                                  uint8_t **out, size_t *out_len)
{
    if (!wire || !hash || !out || !out_len)
        LOG_FAIL("simnet.wire.peer", "invalid single inv request");
    struct byte_stream s;
    stream_init(&s, 64);
    struct inv_item inv;
    inv_item_init_typed(&inv, type, hash);
    bool ok = stream_write_compact_size(&s, 1) &&
              inv_item_serialize(&inv, &s) &&
              simnet_wire_frame(wire, "inv", s.data, s.size, out, out_len);
    stream_free(&s);
    return ok;
}

/* Deterministic 32-byte hash for a labelled announcement height (no
 * wall-clock, no external entropy — derived purely from the peer's
 * child_seed so the same seed always produces the same reorder scenario
 * and fingerprint). */
static void wire_labelled_hash(uint64_t seed, uint64_t height,
                               struct uint256 *out)
{
    for (size_t i = 0; i < sizeof(out->data) / sizeof(uint64_t); i++) {
        uint64_t v = simnet_wire_splitmix64_value(
            seed ^ (height * 0x9E3779B97F4A7C15ULL) ^ (uint64_t)i);
        memcpy(out->data + i * sizeof(uint64_t), &v, sizeof(v));
    }
}

/* REPLAY: deliver one valid tx announcement, retain it, and re-deliver it
 * verbatim after replay_delay ticks. Proves the node handles a duplicated
 * announcement idempotently (no consensus change, no permanent blocker,
 * no disconnect) — the monitors enforce those invariants. */
static bool wire_tick_replay(struct simnet_wire *wire, size_t peer_id,
                             bool *progress)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    if (peer->replay_done)
        return true;
    if (!simnet_wire_peer_handshake_complete(wire, peer_id))
        return true;
    if (!peer->replay_sent) {
        struct uint256 hash;
        wire_random_bytes(hash.data, sizeof(hash.data));
        if (!wire_build_single_inv(wire, MSG_TX, &hash, &peer->replay_frame,
                                   &peer->replay_len))
            return false;
        if (!simnet_wire_deliver_raw_now(wire, peer_id, peer->replay_frame,
                                         peer->replay_len))
            return false;
        peer->replay_sent = true;
        peer->replay_first_tick = wire->ticks;
        peer->replay_delay = 2u + (peer->child_seed % 4u);
        *progress = true;
        return true;
    }
    if (wire->ticks >= peer->replay_first_tick + peer->replay_delay) {
        /* Re-send the EXACT same bytes — a verbatim replay. */
        if (!simnet_wire_deliver_raw_now(wire, peer_id, peer->replay_frame,
                                         peer->replay_len))
            return false;
        peer->replay_done = true;
        *progress = true;
    }
    return true;
}

/* REORDER: deliver two block announcements in reversed causal order — the
 * height N+1 inv strictly before the height N inv, on separate ticks. This
 * is an explicit, deterministic causal reversal, distinct from the
 * transport's latency-jitter reordering. The node must tolerate it with no
 * monitor violation. */
static bool wire_tick_reorder(struct simnet_wire *wire, size_t peer_id,
                              bool *progress)
{
    struct wire_peer *peer = &wire->peers[peer_id];
    if (peer->reorder_done)
        return true;
    if (!simnet_wire_peer_handshake_complete(wire, peer_id))
        return true;

    /* step 0 -> height N+1 (delivered FIRST); step 1 -> height N. */
    uint64_t height = peer->reorder_step == 0 ? 1u : 0u;
    struct uint256 hash;
    wire_labelled_hash(peer->child_seed, height, &hash);

    uint8_t *frame = NULL;
    size_t frame_len = 0;
    if (!wire_build_single_inv(wire, MSG_BLOCK, &hash, &frame, &frame_len))
        return false;
    bool ok = simnet_wire_deliver_raw_now(wire, peer_id, frame, frame_len);
    free(frame);
    if (!ok)
        return false;

    if (peer->reorder_step == 0)
        peer->reorder_step = 1;
    else
        peer->reorder_done = true;
    *progress = true;
    return true;
}

bool simnet_wire_peer_tick(struct simnet_wire *wire, size_t peer_id,
                           bool *progress)
{
    if (!wire || peer_id >= wire->peer_count || !progress)
        LOG_FAIL("simnet.wire.peer", "invalid peer tick peer=%zu", peer_id);
    struct wire_peer *peer = &wire->peers[peer_id];
    if (peer->kind == SIMNET_WIRE_PEER_FLOOD)
        return wire_tick_flood(wire, peer_id, progress);
    if (peer->kind == SIMNET_WIRE_PEER_SLOWLORIS)
        return wire_tick_slowloris(wire, peer_id, progress);
    if (peer->kind == SIMNET_WIRE_PEER_REPLAY)
        return wire_tick_replay(wire, peer_id, progress);
    if (peer->kind == SIMNET_WIRE_PEER_REORDER)
        return wire_tick_reorder(wire, peer_id, progress);
    if (peer->kind == SIMNET_WIRE_PEER_INVALID_BLOCK ||
        peer->kind == SIMNET_WIRE_PEER_INVALID_HEADER)
        return simnet_wire_byzantine_tick(wire, peer_id, progress);
    return true;
}

struct simnet_wire *simnet_wire_create_scenario(
    const struct wire_scenario *scenario)
{
    if (!scenario)
        LOG_NULL("simnet.wire.peer", "NULL scenario");
    size_t peer_count = scenario->honest_peer_count;
    for (size_t i = 0; i < scenario->peer_kind_count; i++)
        peer_count += scenario->peers[i].count;
    if (peer_count == 0)
        LOG_NULL("simnet.wire.peer", "scenario has no peers");

    struct simnet_wire *wire =
        simnet_wire_create(peer_count, scenario->master_seed);
    if (!wire)
        LOG_NULL("simnet.wire.peer", "scenario create failed");

    size_t peer_id = 0;
    for (size_t i = 0; i < scenario->honest_peer_count; i++) {
        if (!simnet_wire_start_honest_peer(wire, peer_id++)) {
            simnet_wire_free(wire);
            LOG_NULL("simnet.wire.peer", "scenario honest start failed");
        }
    }
    for (size_t i = 0; i < scenario->peer_kind_count; i++) {
        for (size_t n = 0; n < scenario->peers[i].count; n++) {
            if (!simnet_wire_start_peer_kind(
                    wire, peer_id++, scenario->peers[i].kind)) {
                simnet_wire_free(wire);
                LOG_NULL("simnet.wire.peer", "scenario peer start failed");
            }
        }
    }
    (void)scenario->duration_us;

    if (scenario->partition_count > 0) {
        if (!scenario->partitions) {
            simnet_wire_free(wire);
            LOG_NULL("simnet.wire.peer",
                     "scenario partition_count>0 with NULL partitions");
        }
        wire->partitions = zcl_calloc(scenario->partition_count,
                                      sizeof(*wire->partitions),
                                      "simnet_wire_scenario_partitions");
        if (!wire->partitions) {
            simnet_wire_free(wire);
            LOG_NULL("simnet.wire.peer", "OOM scenario partitions count=%zu",
                     scenario->partition_count);
        }
        for (size_t i = 0; i < scenario->partition_count; i++) {
            const struct wire_scenario_partition *src =
                &scenario->partitions[i];
            if (src->peer_id >= wire->peer_count) {
                simnet_wire_free(wire);
                LOG_NULL("simnet.wire.peer",
                         "scenario partition peer_id=%zu out of range "
                         "peer_count=%zu",
                         src->peer_id, wire->peer_count);
            }
            wire->partitions[i].peer_id = src->peer_id;
            wire->partitions[i].at_tick = src->at_tick;
            wire->partitions[i].duration_ticks = src->duration_ticks;
        }
        wire->partition_count = scenario->partition_count;
    }

    return wire;
}
