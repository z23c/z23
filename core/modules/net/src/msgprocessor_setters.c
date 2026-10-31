/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * msgprocessor_setters.c — the msg_processor_set_* hook installers and the
 * thin msg_processor_* accessors that forward to them. Split out of
 * msgprocessor.c so that file stays under its shrink-only file-size pin; the
 * functions below moved verbatim. */

#include "platform/time_compat.h"
#include "storage/body_history.h"
#include "msgprocessor_internal.h"
#include "net/addrman.h"
#include "net/checkpoint_header_fetch.h"
#include "net/header_serve_repair.h"
#include "net/dandelion.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "net/params_service.h"
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
/* core/modules/net still reaches the controller-owned manifest cache for P2P file
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
#include "encoding/utilstrencodings.h"
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

void msg_processor_set_offer_relay_allowed(
    struct msg_processor *mp, msg_offer_relay_allowed_fn allowed, void *ctx)
{
    if (!mp)
        return;
    mp->offer_relay_allowed = allowed;
    mp->offer_relay_allowed_ctx = ctx;
}

uint64_t msg_processor_offer_relay_hidden(const struct msg_processor *mp)
{
    if (!mp)
        return 0;
    return atomic_load_explicit(&mp->offer_relay_hidden_by_profile,
                                memory_order_relaxed);
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
