/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Receiver-side snapshot offer, zsnapdata, zsnapend and FlyClient message
 * handlers, split out of msgprocessor_snapshot.c as pure code motion. They
 * share no swarm state with the chunk/block coordinators left behind; the
 * mp_handle_zcl23_sync dispatcher there calls the mp_zs_on_* entry points
 * declared in msgprocessor_snapshot_internal.h. */

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

static bool msg_should_ignore_snapshot_offer(enum snapshot_sync_state snapsync_state,
                                             uint32_t serving_peer_id,
                                             enum peer_state peer_state,
                                             uint32_t peer_id,
                                             enum sync_state sync_state)
{
    (void)serving_peer_id;

    if (sync_state == SYNC_AT_TIP)
        return true;
    if (peer_state == PEER_SNAPSHOT_RECEIVING)
        return true;
    if (snapsync_state == SNAPSYNC_NEGOTIATING ||
        snapsync_state == SNAPSYNC_RECEIVING ||
        snapsync_state == SNAPSYNC_VERIFYING)
        return true;
    if (peer_id == 0)
        return false;
    return false;
}

bool msgprocessor_test_should_ignore_snapshot_offer(
    enum snapshot_sync_state snapsync_state,
    uint32_t serving_peer_id,
    enum peer_state peer_state,
    uint32_t peer_id,
    enum sync_state sync_state) {
    return msg_should_ignore_snapshot_offer(snapsync_state, serving_peer_id,
                                            peer_state, peer_id, sync_state);
}

/* Send zsnapreq for `our_height` to the peer. */
static void mp_zs_push_snapshot_request(struct msg_processor *mp,
                                        struct p2p_node *node,
                                        int32_t our_height)
{
    struct byte_stream rq;
    stream_init(&rq, 52);
    if (snapsync_write_snapshot_request(
            &rq, our_height,
            node->addr.svc.addr.ip).ok) {
        p2p_node_begin_message(node, MSG_SNAPSHOT_REQ,
            mp->params->pchMessageStart);
        p2p_node_write_message_data(node, rq.data, rq.size);
        p2p_node_end_message(node);
    }
    stream_free(&rq);
}

/* ── zsnapshot offer ───────────────────────────────────────────── */

/* SHADOW (WF1 lane 1D, sync/sync_reduce.h): the pure
 * kernel gets the SAME pre-offer status + the SAME
 * offer params the reference path above just used,
 * and its structural accept/reject call is compared
 * against the reference's. This has zero influence
 * on `result` or any branch below — the reference
 * service stays fully authoritative. A divergence is
 * expected for the reference's independent
 * range/schema/finality/work rejects when no session
 * is yet active (the kernel doesn't model offer
 * quality, only session identity + phase) and is
 * logged for visibility, not treated as a fault. */
static void mp_zs_offer_shadow_compare(const struct p2p_node *node,
                                       const struct snapsync_status *snap_status,
                                       const struct snapshot_offer_params *params,
                                       enum snapsync_offer_result result)
{
    struct sync_reduce_offer_shadow_result shadow =
        sync_reduce_offer_shadow_check(
            (uint64_t)snap_status->serving_peer_id,
            snap_status->state,
            (uint64_t)params->peer_id,
            params->height, params->utxo_root,
            result == SNAPSYNC_OFFER_ACCEPTED);
    if (!shadow.agrees) {
        LOG_ERROR("sync_reduce_adapter",
            "shadow kernel disagrees with reference "
            "offer decision: peer=%u "
            "state_before=%s(session=%u) "
            "event_session=%u reference_result=%d "
            "reference_accepts=%d kernel_next=%s "
            "kernel_accepts=%d",
            (uint32_t)node->id,
            snapsync_state_name(snap_status->state),
            snap_status->serving_peer_id,
            params->peer_id, (int)result,
            (int)shadow.reference_accepts,
            sync_phase_name(shadow.kernel_decision.next),
            (int)shadow.kernel_accepts);
    }
}

/* Send FlyClient challenge — verify chain before requesting snapshot data */
static void mp_zs_offer_send_fc_challenge(struct msg_processor *mp,
                                          struct p2p_node *node,
                                          struct snapshot_sync_service *svc)
{
    /* Serialise BEFORE opening the message, so a
     * failed encode cannot put a truncated
     * challenge on the wire. */
    struct byte_stream fc;
    stream_init(&fc, 72);
    struct zcl_result fcw =
        snapsync_write_fc_challenge(svc, &fc);
    if (!fcw.ok) {
        LOG_WARN("snapsync",
            "fc challenge encode failed for %s: code=%d %s",
            node->addr_name, fcw.code, fcw.message);
        stream_free(&fc);
    } else {
        p2p_node_begin_message(node, MSG_FC_CHALLENGE,
            mp->params->pchMessageStart);
        p2p_node_write_message_data(node, fc.data, fc.size);
        p2p_node_end_message(node);
        stream_free(&fc);
        printf("[snapsync] Sent FlyClient challenge to %s\n",
               node->addr_name);
    }
}

/* Offer accepted: record the offer on the peer, then send the follow-up. */
static void mp_zs_offer_accepted(struct msg_processor *mp,
                                 struct p2p_node *node,
                                 struct snapshot_sync_service *svc,
                                 const struct snapshot_offer_params *params)
{
    struct snapsync_offer_acceptance accepted = {0};
    snapsync_build_offer_acceptance(&accepted);
    if (accepted.should_store_offer_details) {
        memcpy(node->zsync_offered_root, params->utxo_root, 32);
        memcpy(node->zsync_offered_mmr, params->mmr_root, 32);
        memcpy(node->zsync_offered_block, params->block_hash, 32);
        node->zsync_offered_height = params->height;
    }
    if (accepted.should_reset_offset)
        node->zsync_offset = 0;
    if (accepted.should_update_peer_state)
        peer_set_state_checked((uint32_t)node->id, &node->state,
            accepted.peer_state, "accepted snapshot offer");
    event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, (uint32_t)node->id,
        "h=%d utxos=%llu", params->height,
        (unsigned long long)params->num_utxos);
    if (accepted.should_set_sync_state)
        sync_set_state(accepted.sync_state, "peer snapshot");

    struct snapsync_offer_followup followup = {0};
    snapsync_build_offer_followup(&followup, svc);
    if (followup.action ==
        SNAPSYNC_FOLLOWUP_SEND_FC_CHALLENGE) {
        mp_zs_offer_send_fc_challenge(mp, node, svc);
    } else if (followup.action ==
               SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ) {
        /* No MMB — send zsnapreq directly */
        mp_zs_push_snapshot_request(mp, node, params->our_height);
    }
}

/* React to the reference service's decision on an offer. */
static void mp_zs_offer_react(struct msg_processor *mp,
                              struct p2p_node *node,
                              struct snapshot_sync_service *svc,
                              const struct snapshot_offer_params *params,
                              enum snapsync_offer_result result)
{
    switch (result) {
    case SNAPSYNC_OFFER_ACCEPTED:
        mp_zs_offer_accepted(mp, node, svc, params);
        break;
    case SNAPSYNC_OFFER_REJECTED_RANGE:
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
            "snapshot offer out of range");
        break;
    case SNAPSYNC_OFFER_REJECTED_NO_MMR:
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_OFFER_REJECTED,
            "snapshot without MMR proof");
        break;
    case SNAPSYNC_OFFER_REJECTED_STALE_SCHEMA:
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
            "snapshot offer missing v2 schema");
        break;
    case SNAPSYNC_OFFER_REJECTED_UNFINAL:
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_OFFER_REJECTED,
            "snapshot offer non-final anchor");
        break;
    case SNAPSYNC_OFFER_REJECTED_WEAK_WORK:
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
            "snapshot offer weak chainwork");
        break;
    case SNAPSYNC_OFFER_REJECTED_BLACKLISTED:
        printf("[snapsync] Rejected offer from %s "
               "(peer %u): blacklisted after stall\n",
               node->addr_name, (uint32_t)node->id);
        break;
    case SNAPSYNC_OFFER_REJECTED_NOT_AHEAD:
    case SNAPSYNC_OFFER_REJECTED_BUSY:
        break; /* expected, no log needed */
    default:
        break;
    }
}

/* Route: zsnapshot → snapsync_handle_offer */
void mp_zs_on_snapshot_offer(struct msg_processor *mp,
                                    struct p2p_node *node,
                                    struct byte_stream *s)
{
    struct snapshot_offer_params params;
    if (snapsync_parse_offer_params(&params, s).ok) {
        struct snapsync_status snap_status = {0};
        params.peer_id = (uint32_t)node->id;
        params.our_height = active_chain_height(
            &mp->main_state->chain_active);

        {
            struct snapshot_sync_service *svc =
                msg_snapshot_sync_ensure(mp);
            if (svc)
                snapsync_get_status_snapshot(svc, &snap_status);
        }

        /* Additional gate: once snapshot sync already owns the
         * receiver lifecycle, duplicate offers should be ignored in
         * the router instead of trying to re-enter negotiation. */
        if (msg_should_ignore_snapshot_offer(
                snap_status.state,
                snap_status.serving_peer_id,
                node->state,
                (uint32_t)node->id,
                sync_get_state())) {
            /* silently ignore */
        } else {
            struct snapshot_sync_service *svc =
                msg_snapshot_sync_ensure(mp);
            if (svc) {
                enum snapsync_offer_result result =
                    snapsync_handle_offer(svc, &params);
                mp_zs_offer_shadow_compare(node, &snap_status, &params,
                                           result);
                mp_zs_offer_react(mp, node, svc, &params, result);
            }
        }
    } else {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
                            "truncated snapshot v2 offer");
    }
}

/* ── zsnapdata ─────────────────────────────────────────────────── */

/* Route: zsnapdata → snapsync_apply_chunk */
void mp_zs_on_snapshot_data(struct msg_processor *mp,
                                   struct p2p_node *node,
                                   struct byte_stream *s)
{
    struct snapshot_sync_service *svc = msg_snapshot_sync_ensure(mp);
    struct snapsync_status chunk_pre = {0};
    if (svc)
        snapsync_get_status_snapshot(svc, &chunk_pre);
    int applied = svc ? snapsync_apply_chunk(svc,
        s->data + s->read_pos, s->size - s->read_pos) : -1;
    if (applied < 0)
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_MESSAGE, "bad snapshot chunk");
    else
        node->zsync_offset += (uint64_t)applied;

    /* SHADOW (net/sync_shadow.h): fold the SAME chunk outcome through
     * the pure kernel and compare its phase change against the
     * reference's. Strictly AFTER the reference decision; nothing here
     * feeds back into any branch above. */
    if (svc) {
        struct snapsync_status chunk_post = {0};
        snapsync_get_status_snapshot(svc, &chunk_post);
        sync_shadow_observe(
            applied < 0 ? SYNC_SHADOW_CHUNK_REJECTED
                        : SYNC_SHADOW_CHUNK_ACCEPTED,
            (uint64_t)chunk_pre.serving_peer_id,
            chunk_pre.state, chunk_post.state,
            applied < 0 ? SYNC_EVENT_CHUNK_REJECTED
                        : SYNC_EVENT_CHUNK_RECEIVED,
            false);
    }
}

/* ── zsnapend ──────────────────────────────────────────────────── */

/* The verified-snapshot reaction of the zsnapend handler. */
static void mp_zs_end_apply_verified(struct msg_processor *mp,
                                     struct p2p_node *node,
                                     struct snapshot_sync_service *svc,
                                     const struct snapsync_end_result *end_result)
{
    if (end_result->should_update_peer_state) {
        peer_set_state_checked((uint32_t)node->id, &node->state,
            end_result->peer_state, "snapshot verified");
    }

    /* Set chain tip to snapshot height */
    if (end_result->should_activate_tip) {
        int activated_height = snapsync_activate_verified_tip(
            svc, mp->main_state);
        if (activated_height >= 0) {
            printf("[snapshot] Chain tip set to height %d\n",
                   activated_height);
            /* Update in-memory coins view to match snapshot.
             * snapsync_activate_verified_tip → csr_commit_tip
             * already set coins_best_block on the singleton's
             * coins_tip in production. This raw setter stays
             * as a defensive fallback for the test-harness
             * path (CSR_REJECTED_NOT_INITIALIZED — csr
             * singleton not wired), where snapsync's helper
             * only touches active_chain / pindex_best_header.
             * Low-level: bypasses csr on purpose. */
#ifdef ZCL_TESTING
            if (mp->coins_tip) {
                struct uint256 snap_hash;
                memcpy(snap_hash.data,
                       svc->offered_block_hash, 32);
                coins_view_cache_set_best_block(
                    mp->coins_tip, &snap_hash);
            }
#endif
        }
    }
    if (end_result->should_set_sync_state) {
        sync_set_state(end_result->sync_state,
            "snapshot verified, sync remaining headers");
    }
}

/* SHADOW (net/sync_shadow.h): the reference finalize has fully
 * run (RECEIVING→VERIFYING→outcome). Model the proof step in the
 * kernel's VERIFYING phase and compare its outcome against the
 * reference's. The activation-contained case is an ALLOWLISTED
 * gap (kernel stages, reference re-marks FAILED). Strictly after
 * the reference decision; no feedback. */
static void mp_zs_end_shadow_observe(struct snapshot_sync_service *svc,
                                     const struct snapsync_status *end_pre,
                                     const struct snapsync_end_result *end_result,
                                     const struct zcl_result *end_res)
{
    struct snapsync_status end_post = {0};
    snapsync_get_status_snapshot(svc, &end_post);
    enum sync_shadow_point pt;
    enum sync_event_kind kev;
    bool pok;
    if (end_result->verified) {
        pt = SYNC_SHADOW_PROOF_SUCCESS;
        kev = SYNC_EVENT_PROOF_VERIFIED; pok = true;
    } else if (end_res->code ==
               SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE) {
        pt = SYNC_SHADOW_CONTAINMENT;
        kev = SYNC_EVENT_PROOF_VERIFIED; pok = true;
    } else {
        pt = SYNC_SHADOW_PROOF_FAILURE;
        kev = SYNC_EVENT_PROOF_FAILED; pok = false;
    }
    sync_shadow_observe(pt,
        (uint64_t)end_pre->serving_peer_id,
        SNAPSYNC_VERIFYING, end_post.state, kev, pok);
}

/* Route: zsnapend → snapsync_handle_end */
void mp_zs_on_snapshot_end(struct msg_processor *mp,
                                  struct p2p_node *node)
{
    struct snapshot_sync_service *svc = msg_snapshot_sync(mp);
    if (!svc) {
        /* nothing to finalize */
        return;
    }
    struct snapsync_status end_pre = {0};
    snapsync_get_status_snapshot(svc, &end_pre);
    struct snapsync_end_result end_result = {0};
    struct zcl_result end_res = snapsync_handle_end(svc,
                                        (uint32_t)node->id);
    snapsync_build_end_result(&end_result, end_res.ok);
    if (end_result.verified) {
        mp_zs_end_apply_verified(mp, node, svc, &end_result);
    } else if (end_res.code == SNAPSYNC_ACTIVATION_CONTAINED_ERROR_CODE) {
        /* Honest transfer: SHA3 verification PASSED, but runtime
         * activation is deliberately fail-closed on OUR side until
         * a unified canonical installer exists (snapshot_apply.c's
         * snapsync_activation_contained: "continue_normal_p2p_sync
         * _or_upgrade"). This is not a peer fault — no offence, no
         * ban. Snapshot sync is simply unavailable this cycle; the
         * node falls back to ordinary P2P header/block sync. */
        LOG_INFO("net",
            "Peer %s: snapshot verified but activation contained "
            "(%s) — not a peer fault, continuing normal P2P sync",
            node->addr_name, end_res.message);
    } else {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PROOF,
            "snapshot SHA3 verification failed");
    }

    mp_zs_end_shadow_observe(svc, &end_pre, &end_result, &end_res);
}

/* ── FlyClient chain verification messages ────────────────────── */

/* Build and send zfcproofs for a parsed challenge. */
static void mp_zs_fc_challenge_respond(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       const struct fc_challenge *challenge)
{
    if (mp && mp->flyclient_proof) {
        struct fc_response resp;
        if (mp->flyclient_proof(
                &resp, challenge,
                &mp->main_state->chain_active,
                mp->flyclient_proof_ctx)) {
            /* Send zfcproofs — serialise first, so a failed
             * encode cannot put truncated proofs on the wire. */
            struct byte_stream fp;
            stream_init(&fp, 4 + resp.num_samples * 2048);
            struct zcl_result fpw =
                snapsync_write_fc_response(&fp, &resp);
            if (!fpw.ok) {
                LOG_WARN("snapsync",
                    "fc response encode failed for %s: code=%d %s",
                    node->addr_name, fpw.code, fpw.message);
                stream_free(&fp);
            } else {
                p2p_node_begin_message(node, MSG_FC_PROOFS,
                    mp->params->pchMessageStart);
                p2p_node_write_message_data(node, fp.data, fp.size);
                p2p_node_end_message(node);
                stream_free(&fp);
                printf("Peer %s: sent %u FlyClient proofs\n",
                       node->addr_name, resp.num_samples);
            }
        }
    } else {
        printf("Peer %s: FlyClient challenge but no MMB data\n",
               node->addr_name);
    }
}

/* Route: zfcchallenge → build and send proofs */
void mp_zs_on_fc_challenge(struct msg_processor *mp,
                                  struct p2p_node *node,
                                  struct byte_stream *s)
{
    /* token-bucket rate limit *before* parsing so even a
     * spray of cheap-to-read challenges can't saturate the MMB
     * proof builder. One bucket per peer; drops silently and
     * scores PEER_OFFENCE_FLOOD once per flood episode. */
    if (!fc_rate_acquire(node->id, peer_scoring_now_ms())) {
        uint32_t dropped = 0;
        if (fc_rate_should_score(node->id, &dropped)) {
            peer_scoring_record(mp->net_mgr, node,
                                PEER_OFFENCE_FLOOD,
                                "FlyClient challenge flood");
            fprintf(stderr,  // obs-ok:helper-context-logged
                    "Peer %s: FlyClient challenge flood "
                    "(dropped=%u)\n",
                    node->addr_name, dropped);
        }
        /* Silently drop this challenge. */
    } else {
        struct fc_challenge challenge;
        memset(&challenge, 0, sizeof(challenge));
        if (stream_read_bytes(s, challenge.seed, 32) &&
            stream_read_u64_le(s, &challenge.chain_length) &&
            stream_read_bytes(s, challenge.mmb_root, 32)) {
            mp_zs_fc_challenge_respond(mp, node, &challenge);
        }
    }
}

/* Route: zfcproofs → snapsync_verify_flyclient */
void mp_zs_on_fc_proofs(struct msg_processor *mp,
                               struct p2p_node *node,
                               struct byte_stream *s)
{
    struct fc_response resp;
    if (!snapsync_parse_fc_response(&resp, s).ok) {
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PAYLOAD,
            "truncated FlyClient proofs");
    } else {
        struct snapsync_verify_result verify_result = {0};
        struct snapshot_sync_service *svc = msg_snapshot_sync(mp);
        if (svc) {
            snapsync_build_verify_result(
                &verify_result,
                snapsync_verify_flyclient(svc, &resp).ok);
        }
        if (verify_result.should_send &&
            verify_result.action == SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ) {
            /* FlyClient passed — now send zsnapreq */
            int our_h = active_chain_height(
                &mp->main_state->chain_active);
            mp_zs_push_snapshot_request(mp, node, our_h);
        } else {
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_INVALID_PROOF,
                "FlyClient chain verification failed");
        }
    }
}

