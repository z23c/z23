/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_blocks.c — Block message processing.
 * Split from msgprocessor.c for maintainability. */

#include "platform/time_compat.h"
#include "net/msg_internal.h"
#include "net/peer_scoring.h"
#include "net/compact_blocks.h"
#include "storage/disk_block_io.h"
#include "validation/process_block.h"
#include "validation/check_block.h"
#include "consensus/validation.h"
#include "core/arith_uint256.h"
#include "jobs/reducer_frontier.h"  // lib-layer-ok:provable-tip-for-self-suspicion-ban-gate
#include "net/download.h"
#include "net/https_server.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"
#include "util/sync.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

/* Rebuild manifest when chain grows this many blocks beyond the cached one. */
#define MANIFEST_REFRESH_BLOCKS 1000
#define MSG_BLOCK_RETRYABLE_LOG_KEEPALIVE_SECS 15

static struct log_throttle g_msg_block_retryable_log = LOG_THROTTLE_INIT;

bool process_getblocks(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s)
{
    struct block_locator locator;
    block_locator_init(&locator);
    if (!block_locator_deserialize(&locator, s)) {
        block_locator_free(&locator);
        LOG_FAIL("net", "failed to deserialize getblocks locator from %s",
                 node->addr_name);
    }

    struct uint256 hash_stop;
    if (!stream_read(s, hash_stop.data, 32)) {
        block_locator_free(&locator);
        LOG_FAIL("net", "failed to read getblocks hash_stop from %s",
                 node->addr_name);
    }

    struct block_index *pindex = NULL;
    struct active_chain *chain = &mp->main_state->chain_active;

    for (size_t i = 0; i < locator.num_hashes; i++) {
        struct block_index *found = block_map_find(
            &mp->main_state->map_block_index, &locator.vhave[i]);
        if (found && (active_chain_contains(chain, found) ||
                      (found->phashBlock &&
                       uint256_eq(found->phashBlock,
                                  &mp->params->consensus.hashGenesisBlock)))) {
            pindex = found;
            break;
        }
    }
    block_locator_free(&locator);

    if (!pindex)
        pindex = block_map_find(&mp->main_state->map_block_index,
                                &mp->params->consensus.hashGenesisBlock);
    if (!pindex)
        pindex = active_chain_at(chain, 0);

    int limit = 500;
    struct block_index *tip = active_chain_tip(chain);

    if (pindex)
        pindex = main_state_best_known_successor(mp->main_state, pindex);

    for (; pindex && limit > 0;
         pindex = main_state_best_known_successor(mp->main_state, pindex)) {
        if (!pindex || !pindex->phashBlock)
            break;

        struct inv_item inv;
        inv_item_init_typed(&inv, MSG_BLOCK, pindex->phashBlock);
        p2p_node_push_inventory(node, &inv);
        limit--;

        if (!uint256_is_null(&hash_stop) &&
            uint256_eq(pindex->phashBlock, &hash_stop))
            break;

        if (pindex == tip)
            break;
    }

    return true;
}

/* Flush up to 64 not-found items as one wire "notfound" message. Called
 * mid-loop (batch full) and once more at the end (remainder) from
 * process_getdata below — multiple notfound messages per getdata is valid
 * protocol, so batching here never has to drop anything. */
static void send_notfound_batch(struct msg_processor *mp, struct p2p_node *node,
                                struct inv_item *items, size_t count)
{
    if (count == 0)
        return;

    struct byte_stream nf;
    stream_init(&nf, count * 36 + 8);
    stream_write_compact_size(&nf, count);
    for (size_t i = 0; i < count; i++)
        inv_item_serialize(&items[i], &nf);

    p2p_node_begin_message(node, "notfound", mp->params->pchMessageStart);
    p2p_node_write_message_data(node, nf.data, nf.size);
    p2p_node_end_message(node);
    stream_free(&nf);
}

bool process_getdata(struct msg_processor *mp, struct p2p_node *node,
                     struct byte_stream *s)
{
    if (node->swarm_manifest_sent) {
        printf("Peer %s: deferring getdata while serving snapshot\n",
               node->addr_name);
        return true;
    }

    uint64_t count;
    if (!stream_read_compact_size(s, &count))
        LOG_FAIL("net", "failed to read getdata count from %s",
                 node->addr_name);

    if (count > MAX_INV_SZ) {
        /* Score this like every other oversized-count flood (inv, addr,
         * headers, notfound) so a peer that repeats this specific abuse
         * across reconnects still accrues toward the ban threshold —
         * without this, disconnect-only rejection let a hostile peer
         * repeat the flood forever with no persistent consequence. */
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                            "getdata count exceeds MAX_INV_SZ");
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_RESOURCE_LIMIT,
            P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR,
            node->endpoint_generation);
        LOG_FAIL("net", "getdata count %llu exceeds MAX_INV_SZ from %s",
                 (unsigned long long)count, node->addr_name);
    }

    struct inv_item not_found[64];
    size_t not_found_count = 0;

    for (uint64_t i = 0; i < count; i++) {
        /* Bound the send queue: a single getdata can request up to
         * MAX_INV_SZ (50000) blocks, and a slow-reader peer may never
         * drain its socket, so serving the whole batch could buffer
         * tens of GB of send_segments -> OOM. Once this peer (or the
         * process as a whole) is over the send budget, stop serving and
         * return — the peer is within protocol and will re-request the
         * remaining items later (Core's fPauseSend behaviour). Do NOT
         * disconnect. Whitelisted/trusted peers are exempt (checked
         * inside net_send_over_budget). Any not-found items already
         * accumulated are still flushed below. */
        if (net_send_over_budget(node))
            break;

        struct inv_item inv;
        if (!inv_item_deserialize(&inv, s))
            LOG_FAIL("net", "failed to deserialize getdata inv[%llu] from %s",
                     (unsigned long long)i, node->addr_name);

        bool sent = false;
        if (inv.type == MSG_BLOCK) {
            struct block_index *bi = block_map_find(
                &mp->main_state->map_block_index, &inv.hash);
            if (bi && (bi->nStatus & BLOCK_HAVE_DATA)) {
                struct block blk;
                block_init(&blk);

                if (read_block_from_disk_index(&blk, bi, mp->datadir)) {
                    /* Verify block hash before serving — never send
                     * corrupted data that would get us banned */
                    struct uint256 disk_hash;
                    block_get_hash(&blk, &disk_hash);
                    if (uint256_cmp(&disk_hash, &inv.hash) != 0) {
                        char exp[65], got[65];
                        uint256_get_hex(&inv.hash, exp);
                        uint256_get_hex(&disk_hash, got);
                        LOG_WARN("net", "SAFETY: refusing to serve block h=%d "
                                 "— hash mismatch (requested=%s disk=%s)",
                                 bi->nHeight, exp, got);
                        block_free(&blk);
                        goto skip_block_serve;
                    }

                    struct byte_stream blk_data;
                    stream_init(&blk_data, 1024 * 1024);
                    if (block_serialize(&blk, &blk_data)) {
                        p2p_node_begin_message(node, "block",
                                               mp->params->pchMessageStart);
                        p2p_node_write_message_data(node, blk_data.data,
                                                    blk_data.size);
                        p2p_node_end_message(node);
                        sent = true;
                    }
                    stream_free(&blk_data);
                }
                block_free(&blk);
            }
            skip_block_serve:
            (void)0;
        } else if (inv.type == MSG_TX) {
            struct transaction tx;
            transaction_init(&tx);
            if (tx_mempool_lookup(mp->mempool, &inv.hash, &tx)) {
                struct byte_stream tx_data;
                stream_init(&tx_data, 512);
                transaction_serialize(&tx, &tx_data);

                p2p_node_begin_message(node, "tx",
                                       mp->params->pchMessageStart);
                p2p_node_write_message_data(node, tx_data.data, tx_data.size);
                p2p_node_end_message(node);
                stream_free(&tx_data);
                sent = true;
            }
            transaction_free(&tx);
        }

        if (!sent) {
            /* A single getdata can legally request up to MAX_INV_SZ (50000)
             * items, and a contiguous unservable span (missing data below
             * a body floor, a corrupted local range, ...) can easily exceed
             * 64 of them. The old fixed-size array capped at 64 and simply
             * stopped recording once full — every item past the 64th got
             * no notfound reply at all. The requester's download manager
             * (net/download.h::dl_mark_notfound) only re-queues a block
             * promptly when notfound actually arrives; silently dropping
             * the reply forces it to sit out the full per-block timeout
             * instead, precisely when the unservable span is long enough
             * to matter. Flush a batch instead of dropping once one fills. */
            not_found[not_found_count++] = inv;
            if (not_found_count == 64) {
                send_notfound_batch(mp, node, not_found, not_found_count);
                not_found_count = 0;
            }
        }
    }

    send_notfound_batch(mp, node, not_found, not_found_count);
    return true;
}

bool msg_blocks_should_mark_seen(const struct active_chain *chain,
                                  const struct block_index *bi)
{
    if (!chain || !bi) return false;
    return active_chain_contains(chain, bi);
}

bool msg_blocks_should_echo_source_header(const struct p2p_node *peer,
                                          int source_peer_id)
{
    return peer && peer->id == source_peer_id && peer->prefer_headers &&
           peer->state >= PEER_HANDSHAKE_COMPLETE && !peer->disconnect;
}

bool msg_block_validation_is_retryable(const struct validation_state *state)
{
    if (!state || validation_state_is_valid(state))
        return false;
    static const char *const retryable_reasons[] = {
        "block-not-finalized-by-reducer",
        "p2p-block-queued-for-reducer",
        "p2p-block-staged-for-reducer",
        "p2p-block-header-missing",
        "header-admit-inbox-full",
        "reducer-body-header-missing",
        "reducer-body-runtime-unwired",
        "reducer-body-write-failed",
        "reducer-body-verify-failed",
        "p2p-block-intake-unavailable",
        "p2p-block-intake-stopped",
        "p2p-block-intake-full",
        "p2p-block-clone-failed",
    };
    for (size_t i = 0; i < sizeof(retryable_reasons) /
                           sizeof(retryable_reasons[0]); i++) {
        if (strcmp(state->reject_reason, retryable_reasons[i]) == 0)
            return true;
    }
    return false;
}

static bool msg_block_retryable_needs_redownload(
        const struct validation_state *state)
{
    if (!state)
        return false;
    return strcmp(state->reject_reason, "p2p-block-intake-unavailable") == 0 ||
           strcmp(state->reject_reason, "p2p-block-intake-stopped") == 0 ||
           strcmp(state->reject_reason, "p2p-block-intake-full") == 0 ||
           strcmp(state->reject_reason, "p2p-block-clone-failed") == 0;
}

static uint64_t msg_block_retryable_log_key(
        const struct validation_state *state)
{
    if (!state)
        return 0;
    if (strcmp(state->reject_reason, "p2p-block-intake-full") == 0)
        return 1;
    if (strcmp(state->reject_reason, "p2p-block-queued-for-reducer") == 0)
        return 2;
    return 3;
}

static void msg_block_log_retryable(const struct uint256 *hash,
                                    const struct validation_state *state)
{
    if (!hash || !state)
        return;
    uint64_t suppressed = 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint64_t key = msg_block_retryable_log_key(state);
    if (!log_throttle_should_emit(&g_msg_block_retryable_log, key, now,
                                  MSG_BLOCK_RETRYABLE_LOG_KEEPALIVE_SECS,
                                  &suppressed))
        return;

    char hex[65];
    uint256_get_hex(hash, hex);
    const char *detail = state->debug_message[0]
        ? state->debug_message
        : state->reject_reason;
    LOG_INFO("net",
             "block pending reducer/intake finalization "
             "(latest=%s detail=%s suppressed=%llu)",
             hex, detail[0] ? detail : "retryable",
             (unsigned long long)suppressed);
}

static void msg_block_requeue_after_intake_backpressure(
        struct msg_processor *mp,
        const struct uint256 *hash)
{
    if (!mp || !mp->main_state || !hash)
        return;
    struct block_index *bi = block_map_find(
        &mp->main_state->map_block_index, hash);
    int32_t height = bi ? bi->nHeight : -1;
    dl_queue_priority(get_download_mgr(), hash, height);
}

/* ── Self-suspicion gate for the block-reject ban path ──────────────────
 *
 * A dos>=100 block reject normally bans the serving peer (24h). But the
 * reject verdict produced by our own block-submit path mixes two very
 * different failure classes:
 *   - the block BODY is consensus-invalid (bad Equihash/PoW, bad merkle
 *     root, malformed tx, sigop overflow) — the peer is genuinely
 *     misbehaving and MUST be banned; OR
 *   - the block body is fine but OUR local state/context rejected it (a
 *     stale reducer verdict, a torn coins seed, a header-source mismatch).
 *     Here WE are wrong; banning every peer that serves the canonical block
 *     self-isolates the node from the honest majority.
 *
 * The old code exempted exactly ONE reject_reason string and otherwise
 * banned unconditionally — so any NEW local-state defect that we hadn't
 * spelled into that allowlist self-isolated the node silently.
 *
 * This gate re-derives the verdict from the block's OWN bytes via
 * check_block() — the same context-free consensus predicate zclassicd
 * applies (Equihash, PoW-vs-nBits, merkle root, structural/sigops). It is
 * armed ONLY for a block that the network's PoW says is a strictly-more-
 * work chain at/above our provable tip H* (i.e. the network disagrees with
 * us about the best chain), so it changes nothing for old forks or lower-
 * work side chains. When armed:
 *   - body INVALID  -> the block itself is condemned: ban normally (DoS
 *                      protection + consensus parity fully preserved).
 *   - body VALID    -> the fault is local: SUPPRESS the ban and leave the
 *                      block retryable so it reprocesses once our state
 *                      heals (never a silent dedup'd wedge).
 *
 * K distinct peers serving the SAME body-valid block we keep rejecting is
 * a NAMED, escalated blocker (event + WARN) — the otherwise-silent
 * ban-everyone loop now TERMINATES as a named self-isolation alarm. */
#define SELF_SUSPICION_SLOTS      64
#define SELF_SUSPICION_MAX_PEERS  32
#define SELF_SUSPICION_ESCALATE_K 2   /* distinct peers => named blocker */

struct self_suspicion_entry {
    struct uint256 hash;
    node_id_t peers[SELF_SUSPICION_MAX_PEERS];
    int n_peers;
    int64_t last_ms;
    bool used;
    bool escalated;
};

static struct self_suspicion_entry g_ss_table[SELF_SUSPICION_SLOTS];
static pthread_mutex_t g_ss_lock = PTHREAD_MUTEX_INITIALIZER;

/* Record that `peer_id` served the body-valid more-work block `hash` that
 * we locally rejected; return the count of DISTINCT peers seen for it
 * (>=1). Sets *escalated_now true exactly once, when the distinct count
 * first reaches SELF_SUSPICION_ESCALATE_K. Fixed-size table, LRU-evicted
 * by oldest last_ms. */
static int self_suspicion_record(const struct uint256 *hash,
                                 node_id_t peer_id, bool *escalated_now)
{
    if (escalated_now) *escalated_now = false;
    int64_t now = peer_scoring_now_ms();

    pthread_mutex_lock(&g_ss_lock);

    struct self_suspicion_entry *e = NULL;
    struct self_suspicion_entry *free_slot = NULL;
    struct self_suspicion_entry *oldest = &g_ss_table[0];
    for (int i = 0; i < SELF_SUSPICION_SLOTS; i++) {
        struct self_suspicion_entry *c = &g_ss_table[i];
        if (c->used && uint256_eq(&c->hash, hash)) { e = c; break; }
        if (!c->used && !free_slot) free_slot = c;
        if (c->last_ms < oldest->last_ms) oldest = c;
    }
    if (!e) {
        e = free_slot ? free_slot : oldest;
        memset(e, 0, sizeof(*e));
        e->hash = *hash;
        e->used = true;
    }

    bool known = false;
    for (int i = 0; i < e->n_peers; i++)
        if (e->peers[i] == peer_id) { known = true; break; }
    if (!known && e->n_peers < SELF_SUSPICION_MAX_PEERS)
        e->peers[e->n_peers++] = peer_id;
    e->last_ms = now;
    int distinct = e->n_peers;

    if (distinct >= SELF_SUSPICION_ESCALATE_K && !e->escalated) {
        e->escalated = true;
        if (escalated_now) *escalated_now = true;
    }

    pthread_mutex_unlock(&g_ss_lock);
    return distinct;
}

/* Decide whether a rejected block's fault is OURS (local state/context)
 * rather than the serving peer's. Returns true => the peer must NOT be
 * banned and the block must stay retryable; false => fall through to the
 * normal DoS/ban path (this includes the case where the block body is
 * itself consensus-invalid — a genuine offence). */
static bool msg_block_reject_self_suspected(struct msg_processor *mp,
                                            struct p2p_node *node,
                                            const struct block *blk,
                                            const struct uint256 *hash,
                                            const struct validation_state *state)
{
    /* We need our header index for this block to learn its height + work.
     * If we never accepted the header, we cannot establish a more-work
     * chain — fall back to the normal ban (conservative, DoS-preserving). */
    struct block_index *landed =
        block_map_find(&mp->main_state->map_block_index, hash);
    struct block_index *tip = active_chain_tip(&mp->main_state->chain_active);
    if (!landed || !tip)
        return false;

    int32_t hstar = reducer_frontier_provable_tip_cached();
    bool at_or_above_hstar = landed->nHeight >= hstar;
    bool strictly_more_work =
        arith_uint256_compare(&landed->nChainWork, &tip->nChainWork) > 0;

    /* Only suspect ourselves when the network's PoW says this is a BETTER
     * chain than ours AND it lives at/above the height we can prove. An old
     * fork or a lower-work side chain keeps the normal ban. */
    if (!at_or_above_hstar || !strictly_more_work)
        return false;

    /* Re-derive the verdict from the block's OWN bytes (context-free
     * consensus). This neither weakens nor strengthens any validity rule —
     * it is the identical predicate the connect path uses. */
    struct validation_state body_state;
    validation_state_init(&body_state);
    bool body_ok = check_block(blk, &body_state, mp->params,
                               /*check_pow=*/true,
                               /*check_merkle_root=*/true,
                               /*check_size_limits=*/true);

    char hex[65];
    uint256_get_hex(hash, hex);

    if (!body_ok) {
        /* The block body itself condemns the block — a genuine
         * consensus-invalid. Ban normally; parity + DoS preserved. */
        LOG_WARN("net",
                 "self-suspicion CLEARED: more-work block %s at h=%d is "
                 "body-invalid (%s) — banning %s as normal",
                 hex, landed->nHeight,
                 body_state.reject_reason[0] ? body_state.reject_reason
                                             : "invalid",
                 node->addr_name);
        return false;
    }

    /* Body is clean but we still rejected it: OUR state/context is the
     * suspect, not the peer. Count distinct peers; once K agree, raise a
     * NAMED blocker so this can never degrade into a silent ban-everyone
     * loop. */
    bool escalated_now = false;
    int distinct = self_suspicion_record(hash, node->id, &escalated_now);
    const char *lr = state->reject_reason[0] ? state->reject_reason
                                             : "unknown";
    if (escalated_now) {
        event_emitf(EV_BLOCK_REJECTED, (uint32_t)node->id,
                    "SELF_SUSPECT h=%d hash=%s peers=%d local_reason=%s",
                    landed->nHeight, hex, distinct, lr);
        LOG_WARN("net",
                 "SELF-SUSPICION BLOCKER: %d distinct peers serve body-valid "
                 "more-work block %s at h=%d (>=H*=%d) that we locally reject "
                 "(%s); NOT banning — local state/context is the suspect. "
                 "Block left retryable for reprocessing once state heals.",
                 distinct, hex, landed->nHeight, hstar, lr);
    } else {
        LOG_INFO("net",
                 "self-suspicion: not banning %s for body-valid more-work "
                 "block %s at h=%d we locally reject (%s); distinct_peers=%d",
                 node->addr_name, hex, landed->nHeight, lr, distinct);
    }
    return true;
}

bool process_block_msg(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s)
{
    /* Pre-check: reject oversized block messages before deserialization.
     * Prevents allocation DoS from crafted messages. */
    if (s->size > 2000000) {
        event_emitf(EV_PEER_MISBEHAVE, (uint32_t)node->id,
                    "oversized block msg %zu bytes", s->size);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_BLOCK,
                            "oversized block msg");
        LOG_FAIL("net", "oversized block msg %zu bytes from %s",
                 s->size, node->addr_name);
    }

    struct block blk;
    block_init(&blk);
    if (!block_deserialize(&blk, s)) {
        event_emitf(EV_MSG_DESERIALIZATION_FAIL, (uint32_t)node->id, "block");
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                            "malformed block");
        block_free(&blk);
        LOG_FAIL("net", "failed to deserialize block from %s",
                 node->addr_name);
    }

    struct uint256 hash;
    block_get_hash(&blk, &hash);

    /* Mark received in download manager (removes from in-flight) and
     * capture who (if anyone) we asked for it. A plain "block" message
     * is ONLY ever a getdata response in this protocol — the compact-
     * block fast-relay path (BIP152 "sendcmpct"/"cmpctblock") is the
     * one place a peer legitimately pushes block data unsolicited, and
     * that goes through process_cmpctblock() in msg_compact.c, never
     * here. So requester_id == 0 (no in-flight slot for this hash, from
     * ANY peer) is normally a provable unsolicited push.
     *
     * Two honest sources can produce the exact same "requester_id == 0"
     * signal though, so this is NOT simply "never in-flight == ban":
     * dl_drain_for_backpressure() (tip-stall backpressure) and
     * dl_check_timeouts() reassigning a slow peer's block to someone
     * else BOTH force-clear the in-flight slot without telling the
     * peer — a legitimately-requested body (the original peer was just
     * slow, or we were briefly overloaded) can still arrive afterward
     * with no trace it was ever asked for. We can't tell that apart
     * from a truly-unsolicited push by inspecting this hash alone, so
     * we withhold scoring for DL_STALL_TIMEOUT_SECS after either event
     * (ample time for an already-in-transit reply to land) rather than
     * risk banning an honest-but-slow peer. */
    struct download_manager *dm = get_download_mgr();
    uint32_t requester_id = dl_mark_received(dm, &hash);
    if (requester_id == 0) {
        int64_t now_s = (int64_t)platform_time_wall_time_t();
        int64_t last_settle = dl_last_forced_settle_time(dm);
        bool within_settle_grace =
            last_settle != 0 && (now_s - last_settle) < DL_STALL_TIMEOUT_SECS;
        if (!within_settle_grace) {
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_UNREQUESTED,
                                "block body we never requested");
        }
    }

    /* Track block bytes for MB/s throughput reporting */
    dl_add_bytes_received(dm, s->size);

    /* Defer block processing while snapshot sync is active (any state).
     * During NEGOTIATING: blocks fail at height 0, accumulate dos points.
     * During RECEIVING: starves P2P socket reads.
     * During VERIFYING: SHA3 computation needs uncontested SQLite. */
    if (msg_processor_snapshot_active(mp)) {
        block_free(&blk);
        return true;
    }

    if (block_already_seen(&hash)) {
        block_free(&blk);
        return true;
    }
    /* Do NOT mark seen here. A block received + indexed but that fails to
     * activate (e.g. ACTIVATION_SKIP_ALREADY_RUNNING from controller-mutex
     * contention under many concurrent peer arrivals) would be permanently
     * dedup'd and never retried. Mark seen only post-processing, once the
     * block has actually made it onto the active chain. */

    struct validation_state state;
    validation_state_init(&state);
    /* Block intake is owned by the app reducer/stage path injected at boot.
     * The verdict in `state` preserves the mark-seen + DoS/getheaders
     * contract below while keeping lib/net protocol handling app-agnostic. */
    if (!mp || !mp->block_submit) {
        block_free(&blk);
        LOG_FAIL("net", "block submit callback not configured");
    }
    if (!msg_processor_enqueue_p2p_block(mp, &blk, &hash,
                                         (uint32_t)node->id, &state)) {
        (void)mp->block_submit(&blk, &state, mp->block_submit_ctx);
    }

    /* Decide ONCE whether a non-retryable reject is OUR fault (a local
     * state/context defect against a body-valid, more-work block at/above
     * H*) rather than the peer's. Reused below to (a) leave the block
     * retryable instead of dedup'ing it away, and (b) suppress the peer
     * ban. Expensive (re-derives the body verdict via check_block) so it is
     * computed only on the invalid, non-retryable path and only fires the
     * body re-check for a strictly-more-work block at/above H*. */
    bool self_suspect = false;
    const bool reject_nonretryable =
        !validation_state_is_valid(&state) &&
        !msg_block_validation_is_retryable(&state);
    if (reject_nonretryable)
        self_suspect = msg_block_reject_self_suspected(mp, node, &blk, &hash,
                                                       &state);

    if (reject_nonretryable) {
        char hex[65];
        uint256_get_hex(&hash, hex);
        event_emitf(EV_BLOCK_REJECTED, (uint32_t)node->id,
                    "hash=%s reason=%s", hex,
                    state.reject_reason[0] ? state.reject_reason : "unknown");

        if (!self_suspect) {
            /* rejected blocks: mark seen so the dedup ring
             * short-circuits subsequent deliveries of the same bad block
             * from other peers. Only the "received but skipped connect"
             * case (SKIP_ALREADY_RUNNING, etc.) must stay UN-marked so
             * it can retry; that path is validation_state_is_valid ==
             * true but with no tip advance, handled below. */
            block_mark_seen(&hash);
        } else {
            /* Body-valid more-work block we reject on LOCAL state: do NOT
             * dedup it. Marking it seen would short-circuit every future
             * delivery (block_already_seen at intake) and silently wedge
             * the node below it forever. Leaving it out of the ring means
             * the next delivery reprocesses it once our state heals. */
            LOG_WARN("net",
                     "holding block %s retryable (self-suspected local "
                     "reject) — not dedup'ing so it reprocesses after heal",
                     hex);
        }

        /* When a block fails validation during IBD (likely a fork block),
         * re-request headers from this peer starting at our current tip.
         * This forces the peer to send us the correct chain of headers,
         * which will include the valid block at the failed height. */
        msg_processor_request_invalid_block_headers(mp, node);
    } else if (msg_block_validation_is_retryable(&state)) {
        if (msg_block_retryable_needs_redownload(&state))
            msg_block_requeue_after_intake_backpressure(mp, &hash);
        msg_block_log_retryable(&hash, &state);
    }

    if (validation_state_is_valid(&state)) {
        /* Block accepted — give the peer a decay tick. Peers that mostly
         * behave can work off earlier strikes; peers that only feed valid
         * blocks stay at score 0 forever. Safe on trusted peers. */
        peer_scoring_on_good_interaction(node, peer_scoring_now_ms());

        /* mark seen only after successful activation. If the
         * block is in block_index but NOT in active chain (e.g.
         * activation was skipped), leave it out of the dedup ring so
         * the next arrival retries and the controller has another
         * chance to pick it up once the mutex is free. */
        {
            struct block_index *landed = block_map_find(
                &mp->main_state->map_block_index, &hash);
            if (msg_blocks_should_mark_seen(&mp->main_state->chain_active,
                                             landed))
                block_mark_seen(&hash);
        }

        struct block_index *new_tip = active_chain_tip(
            &mp->main_state->chain_active);
        if (new_tip) {
            struct msg_block_acceptance acceptance;
            node->last_block_time = (int64_t)platform_time_wall_time_t();
            node->blocks_received++;
            msg_processor_plan_valid_block_acceptance(&acceptance, mp, node,
                                                      new_tip);
            event_emitf(EV_BLOCK_CONNECTED, (uint32_t)node->id,
                        "h=%d", new_tip->nHeight);
            /* Let the app runtime refresh its tip-advance observers without
             * making protocol handling depend on app-service ownership. */
            msg_processor_note_block_connected(mp, new_tip->nHeight);

            if (acceptance.reached_peer_tip) {
                if (acceptance.should_set_sync_state) {
                    sync_set_state(acceptance.next_sync_state,
                                   "caught up to peer");
                }
                if (acceptance.should_set_flush_policy)
                    set_flush_policy(3600, 500000, 100);
                if (acceptance.should_update_peer_state) {
                    peer_set_state_checked((uint32_t)node->id, &node->state,
                                           acceptance.next_peer_state,
                                           "chain caught up");
                }
                /* Start deferred HTTPS server now that it's safe */
                https_deferred_check();
                if (acceptance.should_emit_tip_updated)
                    event_emitf(EV_TIP_UPDATED, 0,
                                "AT_TIP height=%d",
                                new_tip->nHeight);
            }

            /* Progress logged by IBD progress timer (every 30s) */

            /* Refresh block manifest when chain grows beyond cached range.
             * Only at tip — during IBD, SQLite is still catching up and
             * manifest build can crash on partial data. We're a client
             * during IBD, not serving pieces to peers. */
            bool should_refresh_manifest = false;
            if (sync_get_state() == SYNC_AT_TIP && new_tip->nHeight > 1000) {
                struct block_piece_manifest header;
                int32_t built_at = 0;
                bool has_manifest =
                    msg_processor_get_block_manifest_header(&header,
                                                            &built_at);
                should_refresh_manifest =
                    !has_manifest ||
                    new_tip->nHeight - built_at >= MANIFEST_REFRESH_BLOCKS;
            }
            if (should_refresh_manifest) {
                /* Rebuild in a detached thread to avoid blocking message processing */
                static _Atomic bool g_manifest_rebuilding = false;
                if (!atomic_exchange(&g_manifest_rebuilding, true)) {
                    struct block_piece_manifest new_m;
                    memset(&new_m, 0, sizeof(new_m));
                    if (block_piece_manifest_build_active_chain(
                            &mp->main_state->chain_active, 1,
                            new_tip->nHeight, &new_m) ||
                        block_piece_manifest_build(mp->datadir, 1,
                            new_tip->nHeight, &new_m)) {
                        uint32_t num_pieces = new_m.num_pieces;
                        msg_processor_publish_block_manifest(
                            &new_m, new_tip->nHeight);
                        event_emitf(EV_SYNC_STATE_CHANGE, 0, "manifest refreshed to h=%d (%u pieces)",
                                    new_tip->nHeight, num_pieces);
                    }
                    atomic_store(&g_manifest_rebuilding, false);
                }
            }

            /* Relay accepted block to all connected peers (not during IBD).
             * At the tip, we act as a full relay node. During IBD, relaying
             * would flood peers with old blocks they already have.
             * BIP 130: peers that sent "sendheaders" get a direct headers
             * message (saves an inv→getheaders round-trip at the tip). */
            if (sync_get_state() == SYNC_AT_TIP && new_tip->phashBlock) {
                struct inv_item blk_inv;
                inv_item_init_typed(&blk_inv, MSG_BLOCK, new_tip->phashBlock);
                if (mp->net_mgr) {
                    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
                    for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
                        struct p2p_node *peer = mp->net_mgr->nodes[pi];
                        if (msg_blocks_should_echo_source_header(
                                peer, node->id)) {
                            /* Never echo the full/compact block to its source.
                             * Its accepted block is exactly what advanced our
                             * tip, so echo only the small verified header to
                             * refresh the receiver's expiring chain vote. */
                            if (!push_verified_header_announcement(
                                    mp, peer, new_tip)) {
                                LOG_WARN("headers",
                                         "source-peer tip proof failed "
                                         "h=%d peer=%s",
                                         new_tip->nHeight,
                                         peer->addr_name);
                            } else {
                                LOG_INFO("headers",
                                         "source-peer verified tip proof "
                                         "h=%d peer=%s",
                                         new_tip->nHeight,
                                         peer->addr_name);
                            }
                        } else if (peer->id != node->id &&
                            peer->state >= PEER_HANDSHAKE_COMPLETE &&
                            !peer->disconnect) {
                            if (peer->send_compact) {
                                /* BIP 152: send compact block directly */
                                struct block blk_cmp;
                                block_init(&blk_cmp);
                                if (read_block_from_disk_index(&blk_cmp, new_tip, mp->datadir)) {
                                    struct compact_block_msg cb;
                                    uint64_t nonce = (uint64_t)platform_time_wall_time_t() ^ (uint64_t)peer->id;
                                    if (compact_block_from_block(&cb, &blk_cmp, nonce)) {
                                        struct byte_stream cs;
                                        stream_init(&cs, 4096);
                                        if (compact_block_msg_serialize(&cb, &cs)) {
                                            p2p_node_begin_message(peer, "cmpctblock",
                                                                   mp->params->pchMessageStart);
                                            p2p_node_write_message_data(peer, cs.data, cs.size);
                                            p2p_node_end_message(peer);
                                        }
                                        stream_free(&cs);
                                        compact_block_msg_free(&cb);
                                    }
                                    block_free(&blk_cmp);
                                }
                            } else if (peer->prefer_headers) {
                                /* BIP 130: direct verified header. If local
                                 * bytes are unavailable, fall back to inv so
                                 * the peer still learns that a block exists. */
                                if (!push_verified_header_announcement(
                                        mp, peer, new_tip)) {
                                    LOG_WARN("headers",
                                             "new-tip header announcement "
                                             "failed h=%d peer=%s; using inv",
                                             new_tip->nHeight,
                                             peer->addr_name);
                                    p2p_node_push_inventory(peer, &blk_inv);
                                }
                            } else {
                                p2p_node_push_inventory(peer, &blk_inv);
                            }
                        }
                    }
                    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
                }
            }
        }
    } else {
        int dos = 0;
        if (validation_state_get_dos(&state, &dos) && dos > 0) {
            const char *rr = state.reject_reason[0] ? state.reject_reason
                                                    : "invalid block";
            if (self_suspect) {
                /* The fault is LOCAL, not the peer's: the block body is
                 * clean (re-derived via check_block) and on a strictly-
                 * more-work chain at/above H*. Banning would self-isolate
                 * from the honest majority, so we suppress ALL peer
                 * penalty here. The named self-isolation blocker is already
                 * emitted inside msg_block_reject_self_suspected(); this is
                 * the per-event suppression record. */
                event_emitf(EV_BLOCK_REJECTED, (uint32_t)node->id,
                            "dos=%d SUPPRESSED-self-suspect: %s", dos, rr);
                LOG_WARN("net",
                         "Peer %s: NOT penalizing (self-suspected local "
                         "reject, dos=%d): %s",
                         node->addr_name, dos, rr);
            } else {
                event_emitf(EV_BLOCK_REJECTED, (uint32_t)node->id,
                            "dos=%d %s", dos, state.reject_reason);
                printf("Peer %s: invalid block (dos=%d): %s\n",
                       node->addr_name, dos, state.reject_reason);
                /* DoS from validation is graded: treat the common [50, 100]
                 * range as the two typed categories so peer_offence_weight()
                 * drives the score increment. Anything else (graded 1..49)
                 * falls through to the raw peer_misbehaving() path so we
                 * still honour the validator's exact grade — a constant
                 * enum can't represent it. */
                if (dos >= 100) {
                    peer_scoring_record(mp->net_mgr, node,
                                        PEER_OFFENCE_INVALID_BLOCK, rr);
                } else if (dos >= 50) {
                    peer_scoring_record(mp->net_mgr, node,
                                        PEER_OFFENCE_INVALID_HEADER, rr);
                } else {
                    peer_misbehaving(mp->net_mgr, node, dos, rr);
                }
            }
        } else if (!validation_state_is_valid(&state)) {
            /* DoS=0 but invalid: orphan block or parent-failed.
             * Don't penalize peer — this is normal during sync. */
        }
    }

    block_free(&blk);
    return true;
}
