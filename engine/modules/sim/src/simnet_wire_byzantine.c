/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bridge simnet_byzantine catalogue artifacts onto simnet_wire frames.
 */

#include "simnet_wire_internal.h"

#include "coins/utxo_commitment.h"
#include "core/serialize.h"
#include "primitives/block.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "validation/connect_block.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIMNET_WIRE_BYZ_OWNER "simnet_wire_byz"
#define SIMNET_WIRE_BYZ_OVERSIZE_WIRE_LEN ((size_t)MAX_BLOCK_SIZE + 1u)

static bool byz_kind_is_tier(enum simnet_byzantine_class kind,
                             enum simnet_byzantine_tier tier)
{
    return simnet_byzantine_class_tier(kind) == tier;
}

static bool byz_build_connect_case(
    enum simnet_byzantine_class kind,
    struct simnet *sim,
    struct simnet_byzantine_block_case *out)
{
    switch (kind) {
    case SIMNET_BYZ_BAD_MERKLE:
        return simnet_byzantine_build_bad_merkle(sim, out);
    case SIMNET_BYZ_BAD_CB_AMOUNT:
        return simnet_byzantine_build_bad_cb_amount(sim, out);
    case SIMNET_BYZ_BIP30_DUP_TXID:
        return simnet_byzantine_build_bip30_duplicate_txid(sim, out);
    case SIMNET_BYZ_MISSING_SPEND:
        return simnet_byzantine_build_missing_spend(sim, out);
    case SIMNET_BYZ_IMMATURE_SPEND:
        return simnet_byzantine_build_immature_spend(sim, out);
    case SIMNET_BYZ_NEGATIVE_OUTPUT:
        return simnet_byzantine_build_negative_output(sim, out);
    case SIMNET_BYZ_OVERFLOW_OUTPUT:
        return simnet_byzantine_build_overflow_output(sim, out);
    case SIMNET_BYZ_OVERSIZE_VTX:
        return simnet_byzantine_build_oversize_vtx(sim, out);
    default:
        LOG_FAIL("simnet.wire.byz", "class %d is not tier1",
                 (int)kind);
    }
}

static bool byz_build_header_case(
    enum simnet_byzantine_class kind,
    const struct simnet *sim,
    struct simnet_byzantine_header_case *out)
{
    switch (kind) {
    case SIMNET_BYZ_INVALID_POW:
        return simnet_byzantine_build_invalid_pow_header(sim, out);
    case SIMNET_BYZ_BAD_BITS:
        return simnet_byzantine_build_bad_bits_header(sim, out);
    case SIMNET_BYZ_BAD_TIMESTAMP:
        return simnet_byzantine_build_bad_timestamp_header(sim, out);
    default:
        LOG_FAIL("simnet.wire.byz", "class %d is not tier2",
                 (int)kind);
    }
}

static bool byz_digest(struct simnet *sim, struct utxo_commitment *out)
{
    if (!sim || !sim->initialized || !out)
        LOG_FAIL("simnet.wire.byz", "invalid digest request");
    coins_view_cache_recompute_commitment(&sim->view, out);
    return true;
}

static bool byz_seed_wire_tip(struct simnet_wire *wire)
{
    if (!wire || !wire->byz_sim_ready)
        LOG_FAIL("simnet.wire.byz", "invalid tip seed request");

    /* Snapshot byz_sim's tip into wire-owned storage so subsequent byz_sim
     * mutations cannot alias into the node-under-test's chain. phashBlock
     * must be re-pointed at the COPY's own hash after the struct copy. */
    wire->byz_wire_tip = wire->byz_sim.tip;
    wire->byz_wire_tip.phashBlock = &wire->byz_wire_tip.hashBlock;
    wire->byz_wire_tip_ready = true;

    struct block_index *tip = &wire->byz_wire_tip;
    if (!block_map_find(&wire->ms.map_block_index, &tip->hashBlock) &&
        !block_map_insert(&wire->ms.map_block_index, &tip->hashBlock, tip))
        return false;
    if (!active_chain_install_tip_slot(&wire->ms.chain_active, tip))
        LOG_FAIL("simnet.wire.byz", "active chain tip seed failed");
    wire->ms.pindex_best_header = tip;
    coins_view_cache_set_best_block(&wire->coins_tip, &tip->hashBlock);
    return true;
}

static bool byz_set_sync_state(enum sync_state target)
{
    enum sync_state cur = sync_get_state();
    if (cur == target)
        return true;
    if (cur == SYNC_AT_TIP && target != SYNC_AT_TIP) {
        if (!sync_set_state(SYNC_IDLE, "simnet-wire byz restore"))
            return false;
        cur = SYNC_IDLE;
    }
    if (cur == SYNC_FAILED) {
        if (!sync_set_state(SYNC_IDLE, "simnet-wire byz recover failed"))
            return false;
        cur = SYNC_IDLE;
    }
    if (target == SYNC_IDLE)
        return sync_set_state(SYNC_IDLE, "simnet-wire byz restore");
    if (target == SYNC_FINDING_PEERS)
        return cur == SYNC_IDLE
            ? sync_set_state(SYNC_FINDING_PEERS,
                             "simnet-wire byz restore")
            : false;
    if (target == SYNC_HEADERS_DOWNLOAD) {
        if (cur == SYNC_IDLE)
            return sync_set_state(SYNC_HEADERS_DOWNLOAD,
                                  "simnet-wire byz restore");
        if (cur == SYNC_FINDING_PEERS)
            return sync_set_state(SYNC_HEADERS_DOWNLOAD,
                                  "simnet-wire byz restore");
        return false;
    }
    if (target == SYNC_BLOCKS_DOWNLOAD) {
        if (cur == SYNC_IDLE &&
            !sync_set_state(SYNC_HEADERS_DOWNLOAD,
                            "simnet-wire byz restore"))
            return false;
        return sync_set_state(SYNC_BLOCKS_DOWNLOAD,
                              "simnet-wire byz restore");
    }
    if (target == SYNC_CONNECTING_BLOCKS) {
        if (cur == SYNC_IDLE &&
            !sync_set_state(SYNC_HEADERS_DOWNLOAD,
                            "simnet-wire byz restore"))
            return false;
        if (sync_get_state() == SYNC_HEADERS_DOWNLOAD)
            return sync_set_state(SYNC_CONNECTING_BLOCKS,
                                  "simnet-wire byz restore");
        if (sync_get_state() == SYNC_BLOCKS_DOWNLOAD)
            return sync_set_state(SYNC_CONNECTING_BLOCKS,
                                  "simnet-wire byz restore");
        return false;
    }
    if (target == SYNC_AT_TIP) {
        if (cur == SYNC_IDLE &&
            !sync_set_state(SYNC_HEADERS_DOWNLOAD,
                            "simnet-wire byz at-tip"))
            return false;
        if (sync_get_state() == SYNC_FINDING_PEERS &&
            !sync_set_state(SYNC_HEADERS_DOWNLOAD,
                            "simnet-wire byz at-tip"))
            return false;
        if (sync_get_state() == SYNC_REORG)
            return sync_set_state(SYNC_AT_TIP,
                                  "simnet-wire byz at-tip");
        if (sync_get_state() == SYNC_SNAPSHOT_RECEIVE)
            return sync_set_state(SYNC_AT_TIP,
                                  "simnet-wire byz at-tip");
        return sync_set_state(SYNC_AT_TIP, "simnet-wire byz at-tip");
    }
    if (target == SYNC_SNAPSHOT_RECEIVE)
        return cur == SYNC_IDLE
            ? sync_set_state(SYNC_SNAPSHOT_RECEIVE,
                             "simnet-wire byz restore")
            : false;
    return true;
}

static bool byz_force_at_tip(struct simnet_wire *wire)
{
    if (!wire)
        LOG_FAIL("simnet.wire.byz", "NULL force-at-tip owner");
    if (!wire->byz_saved_sync_state_valid) {
        wire->byz_saved_sync_state = sync_get_state();
        wire->byz_saved_sync_state_valid = true;
    }
    return byz_set_sync_state(SYNC_AT_TIP);
}

static void byz_restore_sync_state(struct simnet_wire *wire)
{
    if (!wire || !wire->byz_saved_sync_state_valid)
        return;
    enum sync_state target = wire->byz_saved_sync_state;
    if (sync_get_state() != target)
        (void)byz_set_sync_state(target);
    wire->byz_saved_sync_state_valid = false;
}

static void byz_init_observation(struct simnet_wire *wire,
                                 enum simnet_byzantine_class kind,
                                 enum simnet_byzantine_tier tier)
{
    memset(&wire->byz_obs, 0, sizeof(wire->byz_obs));
    wire->byz_obs.kind = kind;
    wire->byz_obs.tier = tier;
    wire->byz_obs.expected_blocker_class =
        simnet_byzantine_expected_blocker_class(kind);
    wire->byz_obs.observed_blocker_class = BLOCKER_TRANSIENT;
    wire->byz_obs.tip_before = simnet_tip_height(&wire->byz_sim);
    wire->byz_obs.tip_after = wire->byz_obs.tip_before;
    wire->byz_obs.honest_tip_after = wire->byz_obs.tip_before;
    wire->byz_obs_ready = true;
    wire->byz_honest_after_attempted = false;
}

static bool byz_raise_blocker(struct simnet_wire *wire,
                              const char *reject_reason,
                              bool expected_reason)
{
    if (!wire || !wire->byz_obs_ready || !reject_reason ||
        reject_reason[0] == '\0')
        LOG_FAIL("simnet.wire.byz", "invalid blocker raise");

    enum simnet_byzantine_class kind = wire->byz_obs.kind;
    enum blocker_class cls = expected_reason
        ? simnet_byzantine_blocker_class_for_reason(reject_reason)
        : simnet_byzantine_expected_blocker_class(kind);
    char id[64];
    /* blocker-id: simnet_byz.* */
    snprintf(id, sizeof(id), "simnet_byz.%s",
             simnet_byzantine_class_name(kind));
    char reason[192];
    snprintf(reason, sizeof(reason), "reject_reason=%s", reject_reason);

    snprintf(wire->byz_obs.reject_reason, sizeof(wire->byz_obs.reject_reason),
             "%s", reject_reason);
    snprintf(wire->byz_obs.blocker_id, sizeof(wire->byz_obs.blocker_id),
             "%s", id);
    wire->byz_obs.observed_blocker_class = cls;
    wire->byz_obs.expected_reason_observed = expected_reason;
    wire->byz_obs.expected_reject_path_observed = !expected_reason;
    wire->byz_obs.expected_blocker_observed =
        cls == wire->byz_obs.expected_blocker_class;

    struct blocker_record rec;
    if (!blocker_init(&rec, id, SIMNET_WIRE_BYZ_OWNER, cls, reason))
        return false;
    int rc = blocker_set(&rec);
    if (rc < 0)
        LOG_FAIL("simnet.wire.byz", "blocker_set failed id=%s", id);
    return true;
}

static bool byz_record_unchanged(struct simnet_wire *wire)
{
    if (!wire || !wire->byz_obs_ready)
        LOG_FAIL("simnet.wire.byz", "invalid unchanged observation");
    struct uint256 tip_after;
    struct utxo_commitment coins_after;
    if (!simnet_tip_hash(&wire->byz_sim, &tip_after) ||
        !byz_digest(&wire->byz_sim, &coins_after))
        return false;
    wire->byz_obs.tip_after = simnet_tip_height(&wire->byz_sim);
    wire->byz_obs.tip_unchanged =
        uint256_eq(&tip_after, &wire->byz_baseline_tip);
    wire->byz_obs.coins_unchanged =
        utxo_commitment_equal(&coins_after, &wire->byz_baseline_coins);
    return true;
}

bool simnet_wire_byzantine_start(struct simnet_wire *wire, size_t peer_id,
                                 enum simnet_byzantine_class kind,
                                 enum simnet_byzantine_tier tier)
{
    if (!wire || peer_id >= wire->peer_count)
        LOG_FAIL("simnet.wire.byz", "invalid start peer=%zu", peer_id);
    if (!byz_kind_is_tier(kind, tier))
        LOG_FAIL("simnet.wire.byz", "class %d is not tier %d",
                 (int)kind, (int)tier);
    if (wire->byz_obs_ready)
        LOG_FAIL("simnet.wire.byz", "only one byzantine case per wire");
    if (!byz_force_at_tip(wire))
        LOG_FAIL("simnet.wire.byz", "failed to enter at-tip sync state");

    memset(&wire->byz_sim, 0, sizeof(wire->byz_sim));
    if (!simnet_init(&wire->byz_sim))
        return false;
    simnet_use_seed_tape(&wire->byz_sim, wire->tape);
    wire->byz_sim_ready = true;

    bool built = tier == SIMNET_BYZ_TIER_CONNECT_BLOCK
        ? byz_build_connect_case(kind, &wire->byz_sim, &wire->byz_block)
        : byz_build_header_case(kind, &wire->byz_sim, &wire->byz_header);
    if (!built)
        return false;
    wire->byz_block_ready = tier == SIMNET_BYZ_TIER_CONNECT_BLOCK;
    wire->byz_header_ready = tier == SIMNET_BYZ_TIER_HEADER_ADMISSION;

    if (!byz_seed_wire_tip(wire))
        return false;
    if (!simnet_wire_tip_hash(wire, &wire->monitor.baseline_tip) ||
        !simnet_wire_coins_digest(wire, &wire->monitor.baseline_coins))
        return false;

    byz_init_observation(wire, kind, tier);
    if (!simnet_tip_hash(&wire->byz_sim, &wire->byz_baseline_tip) ||
        !byz_digest(&wire->byz_sim, &wire->byz_baseline_coins))
        return false;

    struct wire_peer *peer = &wire->peers[peer_id];
    peer->byz_kind = kind;
    peer->byz_kind_set = true;
    peer->byz_injected = false;
    peer->adversary_started = true;
    peer->adversary_done = false;
    peer->link.open = true;
    if (tier == SIMNET_BYZ_TIER_CONNECT_BLOCK)
        peer->ban_expected = true;
    if (peer_id == 0 && !peer->version_sent)
        return simnet_wire_enqueue_version(wire, peer_id);
    return true;
}

static bool byz_enqueue_block(struct simnet_wire *wire, size_t peer_id)
{
    if (!wire || !wire->byz_block_ready)
        LOG_FAIL("simnet.wire.byz", "block artifact not ready");

    struct byte_stream s;
    stream_init(&s, 4096);
    bool ok = block_serialize(&wire->byz_block.block, &s);
    if (!ok) {
        stream_free(&s);
        LOG_FAIL("simnet.wire.byz", "block serialize failed");
    }

    size_t payload_len = s.size;
    if (wire->byz_obs.kind == SIMNET_BYZ_OVERSIZE_VTX &&
        payload_len > SIMNET_WIRE_BYZ_OVERSIZE_WIRE_LEN)
        payload_len = SIMNET_WIRE_BYZ_OVERSIZE_WIRE_LEN;
    if (payload_len > MAX_PROTOCOL_MESSAGE_LENGTH) {
        stream_free(&s);
        LOG_FAIL("simnet.wire.byz", "serialized block too large len=%zu",
                 payload_len);
    }
    ok = simnet_wire_enqueue_frame(wire, peer_id, "block", s.data,
                                   payload_len);
    stream_free(&s);
    return ok;
}

static bool byz_enqueue_header(struct simnet_wire *wire, size_t peer_id)
{
    if (!wire || !wire->byz_header_ready)
        LOG_FAIL("simnet.wire.byz", "header artifact not ready");
    struct byte_stream s;
    stream_init(&s, 256);
    bool ok = stream_write_compact_size(&s, 1) &&
              block_header_serialize(&wire->byz_header.header, &s) &&
              stream_write_compact_size(&s, 0) &&
              simnet_wire_enqueue_frame(wire, peer_id, "headers", s.data,
                                        s.size);
    stream_free(&s);
    return ok;
}

bool simnet_wire_byzantine_tick(struct simnet_wire *wire, size_t peer_id,
                                bool *progress)
{
    if (!wire || peer_id >= wire->peer_count || !progress)
        LOG_FAIL("simnet.wire.byz", "invalid tick peer=%zu", peer_id);
    struct wire_peer *peer = &wire->peers[peer_id];
    if (peer->byz_injected || peer->adversary_done)
        return true;
    if (!peer->byz_kind_set)
        LOG_FAIL("simnet.wire.byz", "byz tick without kind");
    if (!wire->nut || wire->nut->disconnect)
        return true;
    if (!simnet_wire_peer_handshake_complete(wire, 0))
        return true;

    bool ok = peer->kind == SIMNET_WIRE_PEER_INVALID_BLOCK
        ? byz_enqueue_block(wire, peer_id)
        : byz_enqueue_header(wire, peer_id);
    if (!ok)
        return false;
    peer->byz_injected = true;
    wire->byz_obs.injected = true;
    *progress = true;
    return true;
}

bool simnet_wire_byzantine_submit_block(struct block *block,
                                        struct validation_state *out,
                                        void *ctx)
{
    struct simnet_wire *wire = (struct simnet_wire *)ctx;
    if (!wire || !block || !out)
        LOG_FAIL("simnet.wire.byz", "invalid submit callback");
    if (!wire->byz_block_ready || !wire->byz_sim_ready)
        LOG_FAIL("simnet.wire.byz", "unexpected block submit");

    struct coins_view parent_view;
    coins_view_cache_as_view(&parent_view, &wire->byz_sim.view);
    struct coins_view_cache scratch;
    coins_view_cache_init(&scratch, &parent_view);

    struct uint256 block_hash;
    block_header_get_hash(&block->header, &block_hash);
    struct block_index idx;
    block_index_init(&idx);
    idx.hashBlock = block_hash;
    idx.phashBlock = &idx.hashBlock;
    idx.pprev = wire->byz_wire_tip_ready ? &wire->byz_wire_tip
                                         : &wire->byz_sim.tip;
    idx.nHeight = wire->byz_block.height;
    idx.nVersion = block->header.nVersion;
    idx.nTime = block->header.nTime;
    idx.nBits = block->header.nBits;
    idx.hashMerkleRoot = block->header.hashMerkleRoot;
    idx.has_chain_sprout_value = false;
    idx.has_chain_sapling_value = false;

    bool accepted = connect_block(block, out, &idx, &scratch,
                                  &wire->byz_sim.params, false);
    coins_view_cache_free(&scratch);
    if (accepted) {
        simnet_wire_mark_monitor_failed(wire,
                                        "byzantine block was accepted");
        LOG_FAIL("simnet.wire.byz", "byzantine block accepted kind=%d",
                 (int)wire->byz_obs.kind);
    }

    wire->byz_obs.rejected = true;
    const char *reason = out->reject_reason[0]
        ? out->reject_reason
        : simnet_byzantine_expected_reason(wire->byz_obs.kind);
    if (!byz_raise_blocker(wire, reason,
                           strcmp(reason, simnet_byzantine_expected_reason(
                                      wire->byz_obs.kind)) == 0) ||
        !byz_record_unchanged(wire))
        return false;
    return false;
}

void simnet_wire_byzantine_observe_event(struct simnet_wire *wire,
                                         enum event_type type,
                                         const void *payload,
                                         uint32_t payload_len)
{
    if (!wire || !wire->byz_obs_ready || !payload || payload_len == 0)
        return;
    char buf[EVENT_PAYLOAD_SIZE + 1];
    size_t n = payload_len < EVENT_PAYLOAD_SIZE
        ? payload_len
        : EVENT_PAYLOAD_SIZE;
    memcpy(buf, payload, n);
    buf[n] = '\0';

    if (type == EV_HEADERS_REJECTED &&
        wire->byz_obs.tier == SIMNET_BYZ_TIER_HEADER_ADMISSION &&
        strstr(buf, simnet_byzantine_expected_reason(wire->byz_obs.kind))) {
        if (!wire->byz_obs.rejected) {
            wire->byz_obs.rejected = true;
            (void)byz_raise_blocker(
                wire, simnet_byzantine_expected_reason(wire->byz_obs.kind),
                true);
            (void)byz_record_unchanged(wire);
            /* NOTE: no manual peer_scoring_record here. Production
             * process_headers() (core/modules/net/src/msg_headers.c, lane A2) now
             * scores an objectively-forged header page itself
             * (PEER_OFFENCE_INVALID_HEADER, dos>0), mirroring how
             * msg_blocks.c has always scored invalid blocks. This harness
             * observer only WATCHES the reject; it must not also score, or
             * the offence is double-counted (50+50=100) and the single
             * forged-header injection crosses the 100-point ban threshold —
             * a peer/ban state that leaks across test groups (event
             * observers + the score are global), which is why the group
             * passed standalone (one path counted) but failed in isolation
             * (both counted → banned). A single invalid header page is
             * weight 50: the peer is scored/misbehaved but NOT yet banned,
             * which is exactly what test_simnet_wire_peer_invalid_header
             * asserts (peer_misbehaved && !peer_banned). */
        }
    } else if (type == EV_PEER_MISBEHAVE &&
               wire->byz_obs.kind == SIMNET_BYZ_OVERSIZE_VTX &&
               strstr(buf, "oversized block msg")) {
        if (!wire->byz_obs.rejected) {
            wire->byz_obs.rejected = true;
            (void)byz_raise_blocker(wire, "oversized block msg", false);
            (void)byz_record_unchanged(wire);
        }
    }
}

bool simnet_wire_byzantine_expected_blocker(
    const struct simnet_wire *wire, const char *id, int cls)
{
    if (!wire || !wire->byz_obs_ready || !id)
        return false;
    return wire->byz_obs.expected_blocker_observed &&
           strcmp(wire->byz_obs.blocker_id, id) == 0 &&
           cls == (int)wire->byz_obs.expected_blocker_class;
}

void simnet_wire_byzantine_after_tick(struct simnet_wire *wire)
{
    if (!wire || !wire->byz_obs_ready || !wire->nut)
        return;
    if (wire->events.peer_misbehave > 0)
        wire->byz_obs.peer_misbehaved = true;
    wire->byz_obs.peer_banned =
        is_banned(&wire->nm, &wire->nut->addr.svc.addr);
    wire->byz_obs.peer_disconnected = wire->nut->disconnect;

    if (wire->byz_obs.peer_banned &&
        wire->byz_obs.peer_disconnected &&
        !wire->byz_honest_after_attempted &&
        wire->byz_sim_ready) {
        wire->byz_honest_after_attempted = true;
        wire->byz_obs.honest_after_accepted =
            simnet_mint_coinbase(&wire->byz_sim, NULL);
        wire->byz_obs.honest_tip_after = simnet_tip_height(&wire->byz_sim);
    }
}

void simnet_wire_byzantine_free(struct simnet_wire *wire)
{
    if (!wire)
        return;
    if (wire->byz_block_ready) {
        /* The p2p intake path marks a rejected block "seen" in a PROCESS-
         * global dedup ring (g_recent_blocks in msgprocessor.c). Two runs
         * with the same seed produce the byte-identical block, so leaving
         * the hash in the ring makes the second run's block get silently
         * dropped by block_already_seen() before it ever reaches
         * block_submit — breaking determinism. Clear it on teardown so
         * every fresh wire re-observes the reject from a clean slate. */
        struct uint256 seen_hash;
        block_get_hash(&wire->byz_block.block, &seen_hash);
        msg_processor_clear_seen_block(&seen_hash);
        simnet_byzantine_block_case_free(&wire->byz_block);
        wire->byz_block_ready = false;
    }
    if (wire->byz_sim_ready) {
        simnet_free(&wire->byz_sim);
        wire->byz_sim_ready = false;
    }
    byz_restore_sync_state(wire);
}

bool simnet_wire_byzantine_get_observation(
    const struct simnet_wire *wire,
    struct simnet_wire_byzantine_observation *out)
{
    if (!wire || !out)
        LOG_FAIL("simnet.wire.byz", "invalid observation request");
    if (!wire->byz_obs_ready)
        return false;
    *out = wire->byz_obs;
    return true;
}
