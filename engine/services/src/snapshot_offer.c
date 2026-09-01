/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_offer.c — incoming snapshot offer evaluation.
 *
 * Validates the offer manifest (size, chunks, schema, finality,
 * chainwork) and transitions IDLE → NEGOTIATING. Also owns the
 * follow-up action helpers and the small wire-format helpers used
 * to parse/write the offer and FlyClient request envelopes. */

#include "net/snapshot_sync_contract.h"
#include "services/snapshot_manifest.h"
#include "services/block_source_policy.h"
#include "chain/mmb.h"
#include "chain/mmr.h"
#include "net/fast_sync.h"
#include "core/random.h"
#include "crypto/sha3.h"
#include "event/event.h"
#include "config/runtime.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "core/serialize.h"

#include "snapshot_sync_internal.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

static bool snapsync_bytes32_nonzero_internal(const uint8_t b[32])
{
    if (!b)
        return false;
    for (int i = 0; i < 32; i++) {
        if (b[i] != 0)
            return true;
    }
    return false;
}

static bool snapsync_read_i64_state_internal(struct node_db *ndb,
                                             const char *key,
                                             int64_t *out)
{
    uint8_t buf[8] = {0};
    size_t len = 0;

    if (!ndb || !key || !out)
        return false;
    if (!node_db_state_get(ndb, key, buf, sizeof(buf), &len) ||
        len == 0 || len > sizeof(buf))
        return false;
    memcpy(out, buf, len);
    return true;
}

static bool snapsync_load_state_mmr_root_internal(struct node_db *ndb,
                                                  uint8_t out[32])
{
    uint8_t buf[MMR_SERIALIZED_MAX];
    size_t len = 0;
    struct mmr m;

    if (!ndb || !out)
        return false;
    memset(buf, 0, sizeof(buf));
    if (!node_db_state_get(ndb, "mmr_state", buf, sizeof(buf), &len) ||
        len < 12 ||
        !mmr_deserialize(&m, buf, len) ||
        m.num_leaves == 0)
        return false;
    mmr_root(&m, out);
    return snapsync_bytes32_nonzero_internal(out);
}

static bool snapsync_load_state_mmb_root_internal(struct node_db *ndb,
                                                  uint8_t out[32])
{
    uint8_t buf[MMB_SERIALIZED_MAX];
    size_t len = 0;
    struct mmb m;

    if (!ndb || !out)
        return false;
    memset(buf, 0, sizeof(buf));
    if (!node_db_state_get(ndb, "mmb_state", buf, sizeof(buf), &len) ||
        len < 13 ||
        !mmb_deserialize(&m, buf, len) ||
        m.num_leaves == 0)
        return false;
    mmb_root(&m, out);
    return snapsync_bytes32_nonzero_internal(out);
}

static bool snapsync_read_tip_chainwork_internal(struct node_db *ndb,
                                                 const uint8_t hash[32],
                                                 uint8_t chain_work[32])
{
    struct snapshot_store_sqlite_ctx sctx;
    struct snapshot_store_port store = {0};

    if (!ndb || !ndb->open || !hash || !chain_work)
        return false;
    if (!snapsync_bind_store_internal(&sctx, ndb, &store).ok)
        return false;  // raw-return-ok:bind-only-fails-on-null-ctx/port-both-local-addresses
    return store.tip_chainwork(store.self, hash, chain_work);
}

enum snapsync_offer_result snapsync_offer_result_from_manifest_internal(
    enum snapshot_manifest_result result)
{
    switch (result) {
    case SNAPSHOT_MANIFEST_OK:
        return SNAPSYNC_OFFER_ACCEPTED;
    case SNAPSHOT_MANIFEST_RANGE:
        return SNAPSYNC_OFFER_REJECTED_RANGE;
    case SNAPSHOT_MANIFEST_STALE_SCHEMA:
        return SNAPSYNC_OFFER_REJECTED_STALE_SCHEMA;
    case SNAPSHOT_MANIFEST_UNFINAL:
        return SNAPSYNC_OFFER_REJECTED_UNFINAL;
    case SNAPSHOT_MANIFEST_WEAK_WORK:
        return SNAPSYNC_OFFER_REJECTED_WEAK_WORK;
    case SNAPSHOT_MANIFEST_NO_MMR:
    case SNAPSHOT_MANIFEST_NO_MMB:
        return SNAPSYNC_OFFER_REJECTED_NO_MMR;
    case SNAPSHOT_MANIFEST_NOT_AHEAD:
        return SNAPSYNC_OFFER_REJECTED_NOT_AHEAD;
    case SNAPSHOT_MANIFEST_NULL_ARG:
    case SNAPSHOT_MANIFEST_TRUNCATED:
    case SNAPSHOT_MANIFEST_TRAILING_BYTES:
    default:
        return SNAPSYNC_OFFER_REJECTED_PARSE;
    }
}

void snapsync_manifest_from_params_internal(struct snapshot_manifest *m,
                                            const struct snapshot_offer_params *p)
{
    memset(m, 0, sizeof(*m));
    m->height = p->height;
    memcpy(m->block_hash, p->block_hash, 32);
    memcpy(m->utxo_root, p->utxo_root, 32);
    memcpy(m->mmr_root, p->mmr_root, 32);
    memcpy(m->mmb_root, p->mmb_root, 32);
    memcpy(m->chain_work, p->chain_work, 32);
    m->num_utxos = p->num_utxos;
    m->total_bytes = p->total_bytes;
    m->protocol_version = p->protocol_version;
    m->snapshot_schema_version = p->snapshot_schema_version;
    m->peer_tip_height = p->peer_tip_height;
}

void snapsync_params_from_manifest_internal(struct snapshot_offer_params *p,
                                            const struct snapshot_manifest *m)
{
    p->height = m->height;
    memcpy(p->block_hash, m->block_hash, 32);
    memcpy(p->utxo_root, m->utxo_root, 32);
    memcpy(p->mmr_root, m->mmr_root, 32);
    memcpy(p->mmb_root, m->mmb_root, 32);
    memcpy(p->chain_work, m->chain_work, 32);
    p->num_utxos = m->num_utxos;
    p->total_bytes = m->total_bytes;
    p->protocol_version = m->protocol_version;
    p->snapshot_schema_version = m->snapshot_schema_version;
    p->peer_tip_height = m->peer_tip_height;
}

struct zcl_result snapsync_build_local_recovery_manifest(struct node_db *ndb,
                                            struct snapshot_offer_params *out,
                                            uint32_t peer_id)
{
    int64_t tip_height = 0;
    size_t hash_len = 0;
    uint64_t utxo_count = 0;

    if (!ndb || !ndb->open || !out)
        return ZCL_ERR(-1, "build_local_recovery_manifest: null/closed ndb or null out");

    memset(out, 0, sizeof(*out));
    if (!snapsync_read_i64_state_internal(ndb, "tip_height", &tip_height) ||
        tip_height <= 0 || tip_height > INT32_MAX)
        return ZCL_ERR(-2, "build_local_recovery_manifest: invalid tip_height=%lld",
                       (long long)tip_height);
    out->height = (int32_t)tip_height;
    out->peer_tip_height = out->height;
    out->our_height = out->height;
    out->peer_id = peer_id;
    out->protocol_version = FAST_SYNC_PROTOCOL_VERSION;
    out->snapshot_schema_version = FAST_SYNC_SNAPSHOT_SCHEMA_VERSION;

    if (!node_db_state_get(ndb, "tip_hash", out->block_hash, 32,
                           &hash_len) ||
        hash_len != 32 ||
        !snapsync_bytes32_nonzero_internal(out->block_hash))
        return ZCL_ERR(-3, "build_local_recovery_manifest: missing/invalid tip_hash");
    if (!snapsync_read_tip_chainwork_internal(ndb, out->block_hash,
                                              out->chain_work))
        return ZCL_ERR(-4, "build_local_recovery_manifest: missing tip chainwork");
    if (!snapsync_load_state_mmr_root_internal(ndb, out->mmr_root) ||
        !snapsync_load_state_mmb_root_internal(ndb, out->mmb_root))
        return ZCL_ERR(-5, "build_local_recovery_manifest: missing MMR/MMB root");

    /* SHA3 UTXO-root commitment math stays inline with the live handle —
     * it is the value the snapshot is pinned to, not storage access. */
    fast_sync_compute_utxo_root_db(ndb->db, out->utxo_root);
    if (!snapsync_bytes32_nonzero_internal(out->utxo_root))
        return ZCL_ERR(-6, "build_local_recovery_manifest: zero utxo root");

    {
        struct snapshot_store_sqlite_ctx sctx;
        struct snapshot_store_port store = {0};
        int64_t count = 0;
        struct zcl_result bind = snapsync_bind_store_internal(&sctx, ndb, &store);
        if (!bind.ok)
            return ZCL_ERR(-7, "build_local_recovery_manifest: %s", bind.message);
        if (!store.utxo_count(store.self, &count))
            return ZCL_ERR(-7, "build_local_recovery_manifest: prepare utxo count failed");
        utxo_count = (uint64_t)count;
    }
    if (utxo_count == 0)
        return ZCL_ERR(-8, "build_local_recovery_manifest: zero utxos");
    out->num_utxos = utxo_count;
    out->total_bytes = utxo_count * 80;
    return ZCL_OK;
}

/* ── Accept Offer ────────────────────────────────────────── */

static bool snapsync_accept_offer_internal(struct snapshot_sync_service *svc,
                                           int32_t height,
                                           uint64_t num_utxos,
                                           const uint8_t utxo_root[32],
                                           const uint8_t mmb_root[32],
                                           const uint8_t block_hash[32],
                                           uint32_t peer_id,
                                           bool allow_populated_utxos)
{
    snapsync_service_lock_internal();
    if (!svc || !utxo_root || !block_hash || svc->state != SNAPSYNC_IDLE
        || height <= 0 || num_utxos == 0 || num_utxos > 100000000ULL) {
        snapsync_service_unlock_internal();
        return false;
    }

    /* Skip P2P snapshot if we already have a real UTXO set.
     *
     * IMPORTANT: Do NOT skip just because coins_best_block is non-null.
     * A partial block connect from genesis (e.g. h=587) sets
     * coins_best_block but produces very few UTXOs — not a real set.
     * Only skip if the UTXO count indicates a genuine snapshot import
     * (100K+ UTXOs from file sync or a previous P2P snapshot). */
    if (svc->ndb && svc->ndb->open) {
        int64_t utxo_count = 0;
        struct snapshot_store_sqlite_ctx sctx;
        struct snapshot_store_port store = {0};
        if (snapsync_bind_store_internal(&sctx, svc->ndb, &store).ok)
            (void)store.utxo_count(store.self, &utxo_count);
        if (utxo_count > 100000 && !allow_populated_utxos) {
            printf("[snapsync] Skipping P2P snapshot — %lld UTXOs already "
                   "imported\n", (long long)utxo_count);
            snapsync_service_unlock_internal();
            return false;
        }
    }

    memcpy(svc->offered_utxo_root, utxo_root, 32);
    memcpy(svc->offered_block_hash, block_hash, 32);
    if (mmb_root) memcpy(svc->offered_mmb_root, mmb_root, 32);
    svc->offered_height = height;
    svc->offered_count = num_utxos;
    svc->serving_peer_id = peer_id;
    svc->start_time_us = snapsync_now_us_internal();

    svc->state = SNAPSYNC_NEGOTIATING;
    snapsync_set_state(SNAPSYNC_NEGOTIATING, "accepted offer");
    snapsync_service_unlock_internal();
    return true;
}

struct zcl_result snapsync_accept_offer(struct snapshot_sync_service *svc,
                           int32_t height, uint64_t num_utxos,
                           const uint8_t utxo_root[32],
                           const uint8_t mmb_root[32],
                           const uint8_t block_hash[32],
                           uint32_t peer_id)
{
    if (!snapsync_accept_offer_internal(svc, height, num_utxos, utxo_root,
                                        mmb_root, block_hash, peer_id,
                                        false))
        return ZCL_ERR(-1, "accept_offer: rejected (busy/invalid/populated) h=%d utxos=%llu peer=%u",
                       height, (unsigned long long)num_utxos, peer_id);
    return ZCL_OK;
}

enum snapsync_followup_action snapsync_offer_followup_action(
    const struct snapshot_sync_service *svc)
{
    enum snapsync_followup_action action = SNAPSYNC_FOLLOWUP_NONE;
    if (!svc)
        return SNAPSYNC_FOLLOWUP_NONE;

    snapsync_service_lock_internal();
    action = svc->fc_verified
        ? SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ
        : SNAPSYNC_FOLLOWUP_SEND_FC_CHALLENGE;
    snapsync_service_unlock_internal();
    return action;
}

enum snapsync_followup_action snapsync_verify_followup_action(bool verified)
{
    return verified ? SNAPSYNC_FOLLOWUP_SEND_SNAPSHOT_REQ
                    : SNAPSYNC_FOLLOWUP_NONE;
}

struct zcl_result snapsync_build_request_pow(const uint8_t peer_ip[16],
                                struct fast_sync_pow *pow)
{
    uint8_t peer_id[32];

    if (!peer_ip || !pow)
        return ZCL_ERR(-1, "build_request_pow: peer_ip=%p pow=%p", (const void*)peer_ip, (void*)pow);

    memset(pow, 0, sizeof(*pow));
    sha3_256(peer_ip, 16, peer_id);
    if (!fast_sync_solve_pow(peer_id, pow))
        return ZCL_ERR(-2, "build_request_pow: fast_sync_solve_pow failed");
    return ZCL_OK;
}

struct zcl_result snapsync_parse_offer_params(struct snapshot_offer_params *params,
                                 struct byte_stream *s)
{
    struct snapshot_manifest manifest;
    enum snapshot_manifest_result parse_result =
        SNAPSHOT_MANIFEST_OK;

    if (!params || !s)
        return ZCL_ERR(-1, "parse_offer_params: params=%p stream=%p", (void*)params, (void*)s);

    memset(params, 0, sizeof(*params));
    if (!snapshot_manifest_parse(&manifest, s, &parse_result).ok)
        return ZCL_ERR(-2,
                 "parse_offer_params: invalid v2 manifest reason=%s pos=%zu/%zu",
                 snapshot_manifest_result_name(parse_result),
                 s->read_pos, s->size);
    snapsync_params_from_manifest_internal(params, &manifest);
    return ZCL_OK;
}

struct zcl_result snapsync_write_snapshot_request(struct byte_stream *s,
                                     int32_t our_height,
                                     const uint8_t peer_ip[16])
{
    struct fast_sync_pow pow;

    if (!s || !peer_ip)
        return ZCL_ERR(-1, "write_snapshot_request: s=%p peer_ip=%p", (void*)s, (const void*)peer_ip);
    {
        struct zcl_result pr = snapsync_build_request_pow(peer_ip, &pow);
        if (!pr.ok)
            return ZCL_ERR(-2, "write_snapshot_request: build_request_pow failed: %s",
                           pr.message);
    }

    stream_write_i32_le(s, our_height);
    stream_write_bytes(s, pow.peer_id, 32);
    stream_write_i64_le(s, pow.timestamp);
    stream_write_u64_le(s, pow.nonce);
    return ZCL_OK;
}

void snapsync_build_offer_acceptance(struct snapsync_offer_acceptance *result)
{
    struct snapsync_offer_acceptance empty = {0};

    if (!result) return;
    *result = empty;

    result->should_begin_receive = true;
    result->should_store_offer_details = true;
    result->should_reset_offset = true;
    result->should_update_peer_state = true;
    result->peer_state = PEER_SNAPSHOT_RECEIVING;
    result->should_set_sync_state = true;
    result->sync_state = SYNC_SNAPSHOT_RECEIVE;
}

void snapsync_build_end_result(struct snapsync_end_result *result,
                               bool verified)
{
    struct snapsync_end_result empty = {0};

    if (!result) return;
    *result = empty;

    result->verified = verified;
    if (!verified)
        return;

    result->should_resume_header_sync = true;
    result->should_update_peer_state = true;
    result->peer_state = PEER_ACTIVE;
    result->should_activate_tip = true;
    result->should_set_sync_state = true;
    result->sync_state = SYNC_HEADERS_DOWNLOAD;
}

void snapsync_build_serve_start(struct snapsync_serve_start *result,
                                uint64_t total_utxos)
{
    struct snapsync_serve_start empty = {0};

    if (!result) return;
    *result = empty;

    result->should_begin_serving = true;
    result->should_reset_progress = true;
    result->should_reset_cursor = true;
    result->should_update_peer_state = true;
    result->peer_state = PEER_SNAPSHOT_SERVING;
    result->total_utxos = total_utxos;
}

void snapsync_build_offer_followup(struct snapsync_offer_followup *result,
                                   const struct snapshot_sync_service *svc)
{
    struct snapsync_offer_followup empty = {0};

    if (!result) return;
    *result = empty;
    if (!svc)
        return;

    result->action = snapsync_offer_followup_action(svc);
    result->should_send = (result->action != SNAPSYNC_FOLLOWUP_NONE);
}

void snapsync_build_verify_result(struct snapsync_verify_result *result,
                                  bool verified)
{
    struct snapsync_verify_result empty = {0};

    if (!result) return;
    *result = empty;

    result->verified = verified;
    result->action = snapsync_verify_followup_action(verified);
    result->should_send = (result->action != SNAPSYNC_FOLLOWUP_NONE);
}

void snapsync_build_serve_complete(struct snapsync_serve_complete *result)
{
    struct snapsync_serve_complete empty = {0};

    if (!result) return;
    *result = empty;

    result->should_finish_serving = true;
    result->should_update_peer_state = true;
    result->peer_state = PEER_ACTIVE;
}

/* ══════════════════════════════════════════════════════════════
 * Controller Actions — called from message router
 * ══════════════════════════════════════════════════════════════ */

/* Action: handle incoming snapshot offer.
 * Validates params, decides whether to accept, transitions state. */
enum snapsync_offer_result snapsync_handle_offer(
    struct snapshot_sync_service *svc,
    const struct snapshot_offer_params *params)
{
    struct snapshot_manifest manifest;
    enum snapshot_manifest_result manifest_result =
        SNAPSHOT_MANIFEST_OK;
    bool reconnect = false;
    enum snapshot_sync_state current_state = SNAPSYNC_IDLE;
    uint32_t prior_peer_id = 0;
    uint64_t prior_received = 0;

    if (!svc || !params)
        return SNAPSYNC_OFFER_REJECTED_PARSE;

    snapsync_manifest_from_params_internal(&manifest, params);
    manifest_result =
        snapshot_manifest_validate_offer(&manifest, params->our_height);
    if (manifest_result != SNAPSHOT_MANIFEST_OK) {
        (void)block_source_policy_snapshot_offer_allowed(
            params->our_height,
            params->height,
            params->peer_tip_height,
            false,
            snapshot_manifest_result_name(manifest_result),
            NULL);
        event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, params->peer_id,
                    "accepted=false reason=%s h=%d peer_tip=%d our_h=%d",
                    snapshot_manifest_result_name(manifest_result),
                    params->height, params->peer_tip_height,
                    params->our_height);
        return snapsync_offer_result_from_manifest_internal(manifest_result);
    }

    /* Reject peers that previously stalled during snapshot transfer */
    if (snapsync_is_peer_blacklisted(svc, params->peer_id)) {
        (void)block_source_policy_snapshot_offer_allowed(
            params->our_height,
            params->height,
            params->peer_tip_height,
            false,
            "blacklisted",
            NULL);
        event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, params->peer_id,
                    "accepted=false reason=blacklisted h=%d peer_tip=%d",
                    params->height, params->peer_tip_height);
        return SNAPSYNC_OFFER_REJECTED_BLACKLISTED;
    }

    /* If we're already receiving from a different peer (reconnect scenario),
     * reset and re-accept from the new peer. This handles the case where
     * the serving connection dropped and node2 reconnected. */
    snapsync_service_lock_internal();
    current_state = svc->state;
    if (current_state == SNAPSYNC_RECEIVING &&
        svc->serving_peer_id != params->peer_id) {
        reconnect = true;
        prior_peer_id = svc->serving_peer_id;
        prior_received = svc->received_utxos;
    }
    snapsync_service_unlock_internal();
    if (reconnect) {
        printf("[snapsync] Reconnect detected: resetting for new peer %u "
               "(was peer %u, had %llu UTXOs)\n",
               params->peer_id, prior_peer_id,
               (unsigned long long)prior_received);
        snapsync_reset(svc);
    } else if (current_state != SNAPSYNC_IDLE) {
        (void)block_source_policy_snapshot_offer_allowed(
            params->our_height,
            params->height,
            params->peer_tip_height,
            false,
            "busy",
            NULL);
        return SNAPSYNC_OFFER_REJECTED_BUSY;
    }

    /* Accept the offer via service */
    if (!snapsync_accept_offer(svc, params->height, params->num_utxos,
                               params->utxo_root, params->mmb_root,
                               params->block_hash, params->peer_id).ok) {
        (void)block_source_policy_snapshot_offer_allowed(
            params->our_height,
            params->height,
            params->peer_tip_height,
            false,
            "accept_failed",
            NULL);
        return SNAPSYNC_OFFER_REJECTED_BUSY;
    }
    if (!block_source_policy_snapshot_offer_allowed(
            params->our_height,
            params->height,
            params->peer_tip_height,
            true,
            "manifest_ok",
            NULL)) {
        snapsync_reset(svc);
        return SNAPSYNC_OFFER_REJECTED_BUSY;
    }
    snapsync_service_lock_internal();
    memcpy(svc->offered_chain_work, params->chain_work, 32);
    svc->offered_peer_tip_height = params->peer_tip_height;
    svc->offered_protocol_version = params->protocol_version;
    svc->offered_schema_version = params->snapshot_schema_version;
    snapsync_service_unlock_internal();

    printf("[snapsync] Accepted offer: h=%d, %llu UTXOs from peer %u\n",
           params->height, (unsigned long long)params->num_utxos,
           params->peer_id);
    event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, params->peer_id,
                "accepted=true h=%d peer_tip=%d utxos=%llu",
                params->height, params->peer_tip_height,
                (unsigned long long)params->num_utxos);

    /* Generate FlyClient challenge for MMB chain verification.
     * The router sends zfcchallenge to the peer, who must respond
     * with zfcproofs before we send zsnapreq. */
    uint8_t fc_seed[32];

    GetRandBytes(fc_seed, sizeof(fc_seed));
    snapsync_service_lock_internal();
    memcpy(svc->fc_challenge.seed, fc_seed, 32);
    svc->fc_challenge.chain_length = (uint64_t)params->height + 1;
    memcpy(svc->fc_challenge.mmb_root, params->mmb_root, 32);
    svc->fc_verified = false;
    snapsync_service_unlock_internal();
    printf("[snapsync] FlyClient challenge generated (%u samples, "
           "chain_length=%llu)\n", FC_NUM_SAMPLES,
           (unsigned long long)((uint64_t)params->height + 1));

    return SNAPSYNC_OFFER_ACCEPTED;
}

struct zcl_result snapsync_request_recovery(struct snapshot_sync_service *svc,
                               int32_t target_height,
                               const struct snapshot_offer_params *manifest)
{
    struct snapshot_manifest m;
    enum snapshot_manifest_result manifest_result =
        SNAPSHOT_MANIFEST_OK;
    enum snapshot_sync_state current_state = SNAPSYNC_IDLE;
    uint8_t fc_seed[32];

    if (!svc || !manifest)
        return ZCL_ERR(-1, "request_recovery: svc=%p manifest=%p",
                       (void*)svc, (const void*)manifest);

    snapsync_manifest_from_params_internal(&m, manifest);
    manifest_result = snapshot_manifest_validate_recovery(&m, target_height);
    if (manifest_result != SNAPSHOT_MANIFEST_OK) {
        event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, manifest->peer_id,
                    "accepted=false recovery=true reason=%s h=%d target=%d",
                    snapshot_manifest_result_name(manifest_result),
                    manifest->height, target_height);
        return ZCL_ERR(-2, "request_recovery: manifest invalid reason=%s h=%d target=%d",
                       snapshot_manifest_result_name(manifest_result),
                       manifest->height, target_height);
    }

    snapsync_service_lock_internal();
    current_state = svc->state;
    snapsync_service_unlock_internal();
    if (current_state != SNAPSYNC_IDLE) {
        event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, manifest->peer_id,
                    "accepted=false recovery=true reason=busy h=%d target=%d",
                    manifest->height, target_height);
        return ZCL_ERR(-3, "request_recovery: busy (state != IDLE) h=%d target=%d",
                       manifest->height, target_height);
    }

    if (!snapsync_accept_offer_internal(svc, manifest->height,
                                        manifest->num_utxos,
                                        manifest->utxo_root,
                                        manifest->mmb_root,
                                        manifest->block_hash,
                                        manifest->peer_id,
                                        true)) {
        event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, manifest->peer_id,
                    "accepted=false recovery=true reason=accept_failed "
                    "h=%d target=%d",
                    manifest->height, target_height);
        return ZCL_ERR(-4, "request_recovery: accept_offer failed h=%d target=%d",
                       manifest->height, target_height);
    }

    GetRandBytes(fc_seed, sizeof(fc_seed));
    snapsync_service_lock_internal();
    memcpy(svc->offered_chain_work, manifest->chain_work, 32);
    svc->offered_peer_tip_height = manifest->peer_tip_height;
    svc->offered_protocol_version = manifest->protocol_version;
    svc->offered_schema_version = manifest->snapshot_schema_version;
    memcpy(svc->fc_challenge.seed, fc_seed, 32);
    svc->fc_challenge.chain_length = (uint64_t)manifest->height + 1;
    memcpy(svc->fc_challenge.mmb_root, manifest->mmb_root, 32);
    svc->fc_verified = false;
    snapsync_service_unlock_internal();

    event_emitf(EV_SNAPSHOT_OFFER_RECEIVED, manifest->peer_id,
                "accepted=true recovery=true h=%d target=%d utxos=%llu",
                manifest->height, target_height,
                (unsigned long long)manifest->num_utxos);
    return ZCL_OK;
}
