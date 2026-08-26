/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Message-processor / connman / observer callback unit.
 *
 * Verbatim extraction of the msg-callback functions registered with the
 * msg_processor, block generator, and observers in app_init_services. Each
 * callback takes the threaded boot svc handle (struct boot_svc_ctx *) as its
 * void *ctx and reaches only external subsystem APIs plus svc-> fields — it is
 * S-accessor-free, so it relocates out of boot_services.c without touching any
 * boot-state static. */

#include "config/boot_msg_callbacks.h"
#include "config/boot_file_market_delivery.h"
#include "config/boot_internal.h"
#include "config/db_service.h"
#include "services/chain_activation_service.h"
#include "services/reducer_ingest_service.h"
#include "services/block_index_integrity.h"
#include "services/chain_state_service.h"
#include "services/chain_tip.h"
#include "services/quorum_oracle_service.h"
#include "services/network_monitor.h"
#include "services/sync_monitor.h"
#include "services/file_market_payment_service.h"
#include "services/market_moderation_service.h"
#include "controllers/sync_controller.h"
#include "controllers/yardsale_controller.h"
#include "models/peer.h"
#include "models/zmsg.h"
#include "models/file_offer.h"
#include "models/file_service.h"
#include "models/zswap_ad.h"
#include "net/msgprocessor.h"
#include "net/snapshot_sync_contract.h"
#include "net/peer_lifecycle.h"
#include "net/fast_sync.h"
#include "net/download.h"
#include "storage/peers_projection.h"
#include "sync/sync_state.h"
#include "validation/process_block.h"
#include "wallet/wallet.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>

bool boot_submit_mined_block(struct block *block, void *ctx)
{
    (void)ctx;
    struct validation_state state;
    validation_state_init(&state);
    return reducer_ingest_block(boot_activation_controller(), block,
                                REDUCER_SRC_MINED, true, &state);
}

bool boot_submit_p2p_block(struct block *block,
                                  struct validation_state *state,
                                  void *ctx)
{
    (void)ctx;
    if (!block || !state)
        LOG_FAIL("boot", "p2p block submit missing block=%p state=%p",
                 (void *)block, (void *)state);
    if (sync_get_state() != SYNC_AT_TIP)
        return reducer_stage_p2p_block_for_catchup(
            boot_activation_controller(), block, state);
    return reducer_ingest_block(boot_activation_controller(), block,
                                REDUCER_SRC_P2P, false, state);
}

bool boot_submit_compact_block(struct block *block,
                                      struct validation_state *state,
                                      void *ctx)
{
    (void)ctx;
    if (!block || !state)
        LOG_FAIL("boot", "compact block submit missing block=%p state=%p",
                 (void *)block, (void *)state);
    return reducer_ingest_block(boot_activation_controller(), block,
                                REDUCER_SRC_COMPACT, false, state);
}

int boot_drain_catchup_reducer(void *ctx)
{
    (void)ctx;
    /* Network catch-up is a latency-sensitive runtime path, not the dedicated
     * -mint-anchor bulk fold. The unbudgeted kick holds progress_store_tx_lock
     * for batches of 1000 steps; header event durability can therefore pin
     * operator RPC behind thousands of fsyncs. The ordinary kick preserves the
     * exact reducer checks and cursor transactions while yielding on its
     * bounded runtime cadence. */
    return reducer_kick(boot_activation_controller());
}

void boot_begin_catchup_batch(void *ctx)
{
    (void)ctx;
    reducer_enter_batched_body_sync();
}

void boot_end_catchup_batch(void *ctx)
{
    (void)ctx;
    reducer_exit_batched_body_sync();
}

bool boot_snapshot_active(void *ctx)
{
    (void)ctx;
    return snapsync_is_active();
}

struct block_index *boot_snapshot_anchor_get(void *ctx)
{
    (void)ctx;
    return snapsync_get_anchor();
}

void boot_snapshot_anchor_set(struct block_index *anchor, void *ctx)
{
    (void)ctx;
    snapsync_set_anchor(anchor);
}

void boot_request_header_activation(
    enum msg_activation_request_source source,
    void *ctx)
{
    enum activation_request_source activation_source;
    struct activation_exec_outcome outcome;

    (void)ctx;
    switch (source) {
    case MSG_ACTIVATE_BLOCK_FILE_SCAN:
        activation_source = ACTIVATION_SRC_BLOCK_FILE_SCAN;
        break;
    case MSG_ACTIVATE_HEADERS_ALL_DATA:
    default:
        activation_source = ACTIVATION_SRC_HEADERS_ALL_DATA;
        break;
    }
    activation_request_connect(boot_activation_controller(),
                               activation_source, NULL, &outcome);
}

void boot_clear_header_activation_anchor(const char *reason, void *ctx)
{
    (void)ctx;
    activation_clear_anchor(boot_activation_controller(), reason);
}

void boot_repair_header_post_activation_anchor(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    struct bii_post_activation_result result;

    if (!svc)
        return;
    (void)bii_repair_post_activation_anchor(svc->state, svc->coins_tip,
                                            svc->datadir, &result);
}

int boot_scan_header_block_files(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;

    if (!svc)
        return 0;
    return scan_block_files_mark_data(svc->state, svc->datadir, svc->params);
}

bool boot_header_block_index_heights_repaired(void *ctx)
{
    (void)ctx;
    return block_index_heights_repaired();
}

bool boot_commit_header_tip(struct block_index *header_tip, void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    bool promoted = false;
    enum csr_result rc = csr_promote_header_tip(
        csr_instance(), svc && svc->state ? &svc->state->chain_active : NULL,
        svc && svc->state ? &svc->state->pindex_best_header : NULL,
        header_tip, "msg_headers.best_header", &promoted);

#ifdef ZCL_TESTING
    if (rc == CSR_REJECTED_NOT_INITIALIZED && svc && svc->state && header_tip) {
        svc->state->pindex_best_header = header_tip;
        return true;
    }
#else
    (void)svc;
#endif
    if (rc != CSR_OK) {
        LOG_WARN("sync", "csr rejected best-header promotion (%s) h=%d",
                 csr_result_name(rc), header_tip ? header_tip->nHeight : -1);
        return false;
    }
    (void)promoted;
    return true;
}

bool boot_recommit_snapshot_anchor(struct block_index *anchor,
                                          int from_height,
                                          void *ctx)
{
    struct boot_svc_ctx *svc = ctx;

    if (!anchor || !anchor->phashBlock)
        return false;

    struct chain_state_rollback_authorization rollback_auth = {
        .source = CSR_ROLLBACK_SOURCE_HEADER_SYNC,
        .decision = POLICY_ALLOW,
        .from_height = from_height,
        .to_height = anchor->nHeight,
        .max_depth = INT64_MAX,
        .evidence_class = "header_chain_extends_snapshot_anchor",
        .reason = "msgprocessor.headers_past_anchor",
    };
    struct chain_state_commit commit = {
        .new_tip = anchor,
        .new_coins_best = *anchor->phashBlock,
        .expected_utxo_count = 0,
        .update_header_tip = false,
        .rollback_auth = &rollback_auth,
        .wallet_scan_height = -1,
        .reason = "msgprocessor.headers_past_anchor",
    };
    enum csr_result rc = csr_commit_tip(csr_instance(), &commit);

#ifdef ZCL_TESTING
    if (rc == CSR_REJECTED_NOT_INITIALIZED && svc && svc->state) {
        struct zcl_result tr = chain_set_active_tip(
            svc->state, anchor, TIP_FROM_P2P_REPAIR,
            "anchor_recommit_csr_uninit");
        return tr.ok;
    }
#else
    (void)svc;
#endif
    if (rc != CSR_OK) {
        LOG_WARN("sync", "csr rejected anchor re-commit (%s) h=%d",
                 csr_result_name(rc), anchor->nHeight);
        return false;
    }
    return true;
}

void boot_block_connected_observer(int height, void *ctx)
{
    (void)ctx;
    sync_monitor_on_block_connected(height);
}

void boot_record_peer_header_vote(uint32_t peer_id,
                                         int height,
                                         const char hash_hex[65],
                                         void *ctx)
{
    (void)ctx;
    quorum_oracle_record_peer_header_vote(peer_id, height, hash_hex);
    /* Fan out the same already-flowing accepted-header (peer_id, height, hash)
     * to the network monitor for per-peer tip-hash / fork intelligence. No new
     * wire message: this taps the existing header-vote callback. */
    network_monitor_note_peer_header(peer_id, height, hash_hex);
}

void boot_wallet_tx_accepted(const struct transaction *tx, void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !tx || !svc->wallet)
        return;

    wallet_sync_transaction(svc->wallet, tx, NULL);
    if (svc->node_db)
        (void)node_db_sync_wallet_tx(svc->node_db, tx, svc->wallet, 0);
}

struct boot_peer_save_ctx {
    struct db_peer peer;
    int64_t peer_id;
    char addr[256];
};

static void boot_build_peer_record(const struct p2p_node *node,
                                   struct db_peer *peer)
{
    memset(peer, 0, sizeof(*peer));
    memcpy(peer->ip, node->addr.svc.addr.ip, 16);
    peer->port = node->addr.svc.port;
    peer->services = node->services;
    peer->last_seen = (int64_t)platform_time_wall_time_t();
    peer->is_zcl23 = peer_supports_fast_sync(node->services);
}

static bool boot_peer_save_write(struct node_db *ndb, void *ctx)
{
    struct boot_peer_save_ctx *save = ctx;
    if (!ndb || !save)
        LOG_FAIL("boot", "peer save missing ndb=%p ctx=%p",
                 (void *)ndb, ctx);
    bool ok = db_peer_save_advisory(ndb, &save->peer);
    if (!ok)
        peer_lifecycle_note_cache_skipped_addr(save->addr, save->peer_id,
                                               "save_advisory");
    return ok;
}

static void boot_peer_save_free(void *ctx)
{
    free(ctx);
}

void boot_save_peer_advisory(const struct p2p_node *node, void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    struct db_peer peer;
    struct db_service *dbsvc = svc ? svc->db_service : NULL;
    struct node_db *ndb = svc ? svc->node_db : NULL;

    if (!svc || !node)
        return;
    boot_build_peer_record(node, &peer);

    /* NET-2 feed-read: seed this peer's initial download window from its banked
     * reputation so a proven-fast peer starts at its historical throughput
     * instead of the per-peer minimum. Fail-open — no reputation ⇒ no-op. */
    {
        struct peer_reputation rep;
        if (peers_projection_get_reputation_global(node->addr.svc.addr.ip,
                                                   node->addr.svc.port, &rep) &&
            rep.bandwidth_score > 0)
            dl_peer_seed_bandwidth_score(msg_get_download_mgr(),
                                         (uint32_t)node->id,
                                         rep.bandwidth_score);
    }

    if (dbsvc && db_service_is_started(dbsvc)) {
        struct boot_peer_save_ctx *save =
            zcl_malloc(sizeof(*save), "boot.peer_save_ctx");
        if (!save)
            return;
        save->peer = peer;
        save->peer_id = node->id;
        snprintf(save->addr, sizeof(save->addr), "%s", node->addr_name);
        if (db_service_enqueue_write(dbsvc, boot_peer_save_write,
                                     save, boot_peer_save_free))
            return;
        peer_lifecycle_note_cache_skipped(node, "enqueue_queue_full");
        boot_peer_save_free(save);
        return;
    }

    if (ndb && ndb->open && !db_peer_save_advisory(ndb, &peer))
        peer_lifecycle_note_cache_skipped(node, "save_advisory");
}

bool boot_save_zmsg(const struct zmsg_message *msg, void *ctx)
{
    struct boot_svc_ctx *svc = ctx;

    if (!svc || !svc->node_db || !svc->node_db->open || !msg) {
        LOG_WARN("boot", "zmsg save missing svc=%p ndb=%p msg=%p",
                 (void *)svc, svc ? (void *)svc->node_db : NULL,
                 (const void *)msg);
        return false;
    }

    return db_zmsg_save(svc->node_db, msg);
}

bool boot_save_file_offer(const struct file_offer *offer, void *ctx)
{
    struct boot_svc_ctx *svc = ctx;

    if (!svc || !svc->node_db || !svc->node_db->open || !offer) {
        LOG_WARN("boot", "file offer save missing svc=%p ndb=%p offer=%p",
                 (void *)svc, svc ? (void *)svc->node_db : NULL,
                 (const void *)offer);
        return false;
    }

    return db_file_offer_save(svc->node_db, offer);
}

int boot_ingest_file_payment(const struct file_payment *payment,
                             int64_t peer_id, int64_t now_unix, void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    (void)peer_id;
    if (!svc || !svc->node_db || !svc->state || !payment)
        return FILE_PAYMENT_INGEST_REJECTED;
    int wallet_projection_height = -1;
    if (svc->wallet) {
        zcl_mutex_lock(&svc->wallet->cs);
        wallet_projection_height = svc->wallet->best_block_height;
        zcl_mutex_unlock(&svc->wallet->cs);
    }
    struct market_payment_claim_record record;
    struct zcl_result result = market_payment_claim_ingest(
        svc->node_db, svc->state, sync_get_state() == SYNC_AT_TIP,
        wallet_projection_height, payment, now_unix, &record);
    if (!result.ok) {
        LOG_WARN("market", "payment claim ingress failed: code=%d %s",
                 result.code, result.message);
        return FILE_PAYMENT_INGEST_REJECTED;
    }
    if (strcmp(record.status, "CONFIRMED") == 0)
        return FILE_PAYMENT_INGEST_CONFIRMED;
    if (strcmp(record.status, "PENDING") == 0)
        return FILE_PAYMENT_INGEST_PENDING;
    if (strcmp(record.status, "UNKNOWN") == 0)
        return FILE_PAYMENT_INGEST_UNKNOWN;
    if (strcmp(record.status, "CONFLICTED") == 0)
        return FILE_PAYMENT_INGEST_CONFLICTED;
    return FILE_PAYMENT_INGEST_REJECTED;
}

/* Relay gate adapter: the node's own listing-visibility profile decides
 * whether a third party's offer is rebroadcast from here. The offer row is
 * keyed by root_hash in the review store, which is the id the free
 * (zfilelist) carrier also has, so the root is the key both callers share.
 * market_moderation_may_serve_root() is fail-closed for every failure
 * class, so this adapter adds no policy of its own. */
static bool boot_offer_relay_allowed(const struct file_offer *offer,
                                     void *ctx)
{
    (void)ctx;
    if (!offer)
        return false;
    return market_moderation_may_serve_root(offer->root_hash);
}

void boot_wire_file_market(struct msg_processor *mp,
                           struct boot_svc_ctx *svc)
{
    msg_processor_set_file_offer_save(mp, boot_save_file_offer, svc);
    msg_processor_set_file_payment_ingest(mp, boot_ingest_file_payment, svc);
    msg_processor_set_offer_relay_allowed(mp, boot_offer_relay_allowed, svc);
    boot_wire_file_market_delivery(svc);
}

bool boot_save_zswap_ad(const struct zswap_yardsale_ad *ad, void *ctx)
{
    struct boot_svc_ctx *svc = ctx;

    if (!svc || !svc->node_db || !svc->node_db->open || !ad) {
        LOG_WARN("boot", "zswap ad save missing svc=%p ndb=%p ad=%p",
                 (void *)svc, svc ? (void *)svc->node_db : NULL,
                 (const void *)ad);
        return false;
    }

    return db_zswap_ad_save(svc->node_db, ad);
}

int boot_zswap_ad_ingest(const uint8_t *wire, size_t wire_len,
                         const uint8_t expected_network_genesis[32],
                         int64_t peer_id, int64_t now_unix,
                         struct zswap_yardsale_ad *out_ad, void *ctx)
{
    (void)ctx;
    return (int)zswap_yardsale_ingest_wire(wire, wire_len,
                                           expected_network_genesis,
                                           peer_id, now_unix, out_ad);
}

void boot_wire_zswap_yardsale(struct msg_processor *mp,
                              struct boot_svc_ctx *svc)
{
    msg_processor_set_zswap_ad_ingest(mp, boot_zswap_ad_ingest, svc);
    msg_processor_set_zswap_ad_save(mp, boot_save_zswap_ad, svc);
    /* The ceremony ports ride the same one-call wiring so boot_services.c
     * stays flat against its file-size baseline. */
    boot_wire_zswap_ceremony(mp, svc);
}

/* The msgprocessor ceremony ports take a trailing void *ctx the yardsale
 * controller does not need (its state is its own statics); these two
 * adapters drop it, exactly like boot_zswap_ad_ingest above. */
static int boot_zswap_accept_ingest(const uint8_t *wire, size_t wire_len,
                                    int64_t peer_id, int64_t now_unix,
                                    uint8_t *respond, size_t respond_cap,
                                    size_t *respond_len, void *ctx)
{
    (void)ctx;
    return yardsale_ceremony_accept_ingest(wire, wire_len, peer_id,
                                           now_unix, respond, respond_cap,
                                           respond_len);
}

static int boot_zswap_partial_ingest(const uint8_t *wire, size_t wire_len,
                                     int64_t peer_id, int64_t now_unix,
                                     void *ctx)
{
    (void)ctx;
    return yardsale_ceremony_partial_ingest(wire, wire_len, peer_id,
                                            now_unix);
}

/* The buyer's outbound gossip port, adapted onto the msg_processor's
 * flood (ctx is the msg_processor itself). */
static void boot_zswap_ceremony_flood(const char *command,
                                      const uint8_t *wire, size_t wire_len,
                                      void *ctx)
{
    msg_processor_flood_message((struct msg_processor *)ctx, command,
                                wire, wire_len);
}

void boot_wire_zswap_ceremony(struct msg_processor *mp,
                              struct boot_svc_ctx *svc)
{
    (void)svc;
    msg_processor_set_zswap_accept_ingest(mp, boot_zswap_accept_ingest,
                                          NULL);
    msg_processor_set_zswap_partial_ingest(mp, boot_zswap_partial_ingest,
                                           NULL);
    yardsale_ceremony_set_flood(boot_zswap_ceremony_flood, mp);
}

bool boot_save_file_service(const uint8_t ip[16],
                                   uint16_t port,
                                   uint16_t p2p_port,
                                   int64_t last_seen,
                                   bool is_zcl23,
                                   void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    struct db_file_service fs;

    if (!svc || !svc->node_db || !svc->node_db->open || !ip || port == 0) {
        LOG_WARN("boot",
                 "file service save missing svc=%p ndb=%p ip=%p port=%u",
                 (void *)svc, svc ? (void *)svc->node_db : NULL,
                 (const void *)ip, (unsigned)port);
        return false;
    }

    memset(&fs, 0, sizeof(fs));
    memcpy(fs.ip, ip, sizeof(fs.ip));
    fs.port = port;
    fs.p2p_port = p2p_port;
    fs.last_seen = last_seen;
    fs.is_zcl23 = is_zcl23;
    return db_file_service_save(svc->node_db, &fs);
}
