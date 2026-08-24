/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot snapshot-offer worker — the fast-sync snapshot offer + manifest
 * builder, lifted out of boot_background_workers.c so that file stays under
 * the E1 800-line ceiling. PURE relocation: the worker body is byte-identical
 * to its prior home; only its surrounding TU changed.
 *
 * UTXO snapshot export stays opt-in (ZCL_PUBLISH_FASTSYNC_ON_BOOT) because
 * it takes live DB read locks. Block-piece swarm publishing is default-on
 * once bodies are within BOOT_BLOCK_SWARM_MAX_HEADER_LAG of the header tip,
 * so caught-up zclassic23 peers can feed IBD without a RAM snapshot cache.
 * It is a supervised background worker
 * (Shape 5 — MONITOR): it shares the
 * worker_on_stall handler + boot_register_worker_supervisor helper exposed by
 * boot_background_workers.h and implemented in boot_worker_supervisor.c
 * (single source, not duplicated here), reaches the boot context through the
 * boot_services.c accessors declared in boot_internal.h (boot_node_db /
 * boot_profile_has_file_service / boot_serialize_utxo_snapshot), and reaches
 * the single MMB leaf store declared by boot_flyclient.h through
 * boot_internal.h.
 *
 * The start/join pair is called from its existing sites in app_init_services /
 * app_shutdown_svc (boot_services.c), boot order preserved.
 */

#include "config/boot_internal.h"
#include "config/boot_background_workers.h"
#include "config/boot_snapshot_offer.h"
#include "services/consensus_snapshot_export_service.h"
#include "models/mmb_leaf_store.h"
#include "chain/mmb.h"
#include "controllers/blockchain_controller.h"
#include "controllers/file_controller.h"
#include "jobs/reducer_frontier.h"
#include "net/file_service.h"
#include "net/fast_sync.h"
#include "services/sync_trust_policy.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "supervisors/domains.h"
#include "util/ar_step_readonly.h"
#include "util/supervisor.h"
#include "validation/chainstate.h"
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* ── Supervisor liveness (Model A — MONITOR; disk_monitor.c exemplar) ─
 *
 * The snapshot-offer worker keeps its own pthread and gains an observe-only
 * liveness_contract registered ONCE at boot_start_offer_service. The
 * supervisor never owns or tears down the thread (period_secs == 0); it only
 * watches the heartbeat the worker emits at each phase checkpoint and fires
 * worker_on_stall (log + EV_RECOVERY_ACTION) when the deadline lapses. */
#define SNAPSHOT_OFFER_SUPERVISOR_DEADLINE_SEC      1800

static struct liveness_contract g_offer_contract;
static _Atomic supervisor_child_id g_offer_sup_id = SUPERVISOR_INVALID_ID;

static void *build_snapshot_offer_thread(void *arg);

/* The supervisor register helper (boot_register_worker_supervisor), the
 * observe-only stall handler (worker_on_stall), and the generic thread
 * start/named-join plumbing (boot_start_thread_service /
 * boot_join_thread_service_named) are shared via boot_background_workers.h,
 * so this TU spawns no raw worker thread of its own. */

bool boot_start_offer_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return false;
    boot_register_worker_supervisor(&g_offer_sup_id, &g_offer_contract,
                                    &g_op_sup, "op.build_snapshot_offer",
                                    SNAPSHOT_OFFER_SUPERVISOR_DEADLINE_SEC, 0);
    return boot_start_thread_service(&svc->offer_thread,
                                     &svc->offer_thread_started,
                                     build_snapshot_offer_thread, svc);
}

void boot_join_offer_service(struct boot_svc_ctx *svc)
{
    if (!svc)
        return;
    boot_join_thread_service_named(&svc->offer_thread,
                                   &svc->offer_thread_started,
                                   "snapshot_offer", 5);
}

/* One-shot-checkpointed heartbeat for the snapshot-offer worker. It has no
 * polling loop, so it ticks + advances its progress marker at each phase
 * boundary (export, offer build, chunk manifest, block manifest) — enough
 * forward signal for the supervisor to distinguish "working" from "wedged"
 * across the worker's slow I/O phases. */
static void offer_checkpoint(int64_t *checkpoint)
{
    supervisor_child_id sup_id = atomic_load(&g_offer_sup_id);
    if (sup_id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(sup_id);
    supervisor_progress(sup_id, ++(*checkpoint));
}

static bool env_flag_enabled(const char *name)
{
    const char *value = getenv(name);
    if (!value)
        return false;
    return strcmp(value, "1") == 0 ||
           strcmp(value, "true") == 0 ||
           strcmp(value, "yes") == 0 ||
           strcmp(value, "on") == 0;
}

bool boot_publish_block_swarm(int32_t body_height, int32_t header_height,
                              int32_t blocks_per_piece)
{
    int32_t lag;

    if (blocks_per_piece <= 0)
        return false;
    if (body_height <= blocks_per_piece)
        return false;
    if (header_height < body_height)
        return false;
    lag = header_height - body_height;
    if (lag > BOOT_BLOCK_SWARM_MAX_HEADER_LAG)
        return false;
    return true;
}

static void boot_try_publish_block_swarm(struct boot_svc_ctx *svc,
                                         const char *datadir)
{
    int32_t body_h = 0;
    int32_t header_h = 0;
    struct block_piece_manifest block_manifest;

    if (svc && svc->state) {
        body_h = active_chain_height(&svc->state->chain_active);
        if (svc->state->pindex_best_header)
            header_h = svc->state->pindex_best_header->nHeight;
    }
    if (header_h < body_h)
        header_h = body_h;
    if (!boot_publish_block_swarm(body_h, header_h, BLOCKS_PER_PIECE))
        return;
    if (!datadir || datadir[0] == '\0')
        return;

    printf("Building block piece manifest...\n");
    memset(&block_manifest, 0, sizeof(block_manifest));
    if ((svc && svc->state &&
         block_piece_manifest_build_active_chain(&svc->state->chain_active, 1,
                                                 body_h, &block_manifest)) ||
        block_piece_manifest_build(datadir, 1, body_h, &block_manifest)) {
        int32_t start_height = block_manifest.start_height;
        int32_t end_height = block_manifest.end_height;
        uint32_t num_pieces = block_manifest.num_pieces;
        msg_processor_publish_block_manifest(&block_manifest, body_h);
        printf("Block manifest ready: h=%d..%d, %u pieces\n",
               start_height, end_height, num_pieces);
    } else {
        printf("Block manifest: build failed\n");
    }
}

bool boot_snapshot_offer_trust_policy(
    bool hstar_known, bool transparent_self_derived,
    bool sprout_cursor_found, int64_t sprout_cursor,
    bool sapling_cursor_found, int64_t sapling_cursor,
    bool nullifier_cursor_found, int64_t nullifier_cursor)
{
    return hstar_known && transparent_self_derived && sprout_cursor_found &&
           sprout_cursor == 0 && sapling_cursor_found &&
           sapling_cursor == 0 && nullifier_cursor_found &&
           nullifier_cursor == 0;
}

#ifdef ZCL_TESTING
static _Atomic int g_snapshot_offer_trust_override = -1;
static _Atomic int g_snapshot_offer_publication_override = -1;

void boot_snapshot_offer_test_set_trust_override(int value)
{
    int normalized = value < 0 ? -1 : value != 0 ? 1 : 0;
    atomic_store(&g_snapshot_offer_trust_override, normalized);
    atomic_store(&g_snapshot_offer_publication_override, normalized);
}

void boot_snapshot_offer_test_set_publication_override(int value)
{
    atomic_store(&g_snapshot_offer_publication_override,
                 value < 0 ? -1 : value != 0 ? 1 : 0);
}
#endif

/* Phase-0 containment. The serving codecs still read node.db.utxos, while the
 * live sovereignty proof is over coins_kv. Until export streams from coins_kv
 * and binds its root/count/supply plus the exact active H* hash, no payload is
 * eligible even when the node's consensus state itself is sovereign. */
static bool snapshot_offer_payload_authority_is_bound(char *reason,
                                                       size_t reason_size)
{
#ifdef ZCL_TESTING
    int override = atomic_load(&g_snapshot_offer_publication_override);
    if (override >= 0) {
        if (!override && reason && reason_size)
            (void)snprintf(reason, reason_size,
                           "test_override_payload_unbound");
        return override != 0;
    }
#endif
    if (reason && reason_size)
        (void)snprintf(reason, reason_size,
                       "snapshot_payload_authority_binding_incomplete");
    return false;
}

static bool snapshot_offer_state_is_sovereign_at(int32_t *out_hstar,
                                                  char *reason,
                                                  size_t reason_size)
{
#ifdef ZCL_TESTING
    int override = atomic_load(&g_snapshot_offer_trust_override);
    if (override >= 0) {
        if (!override) {
            if (out_hstar)
                *out_hstar = -1;
            if (reason && reason_size)
                (void)snprintf(reason, reason_size,
                               "test_override_not_sovereign");
            return false;
        }
        if (!snapshot_offer_payload_authority_is_bound(reason, reason_size)) {
            if (out_hstar)
                *out_hstar = -1;
            return false;
        }
        if (out_hstar)
            *out_hstar = INT32_MAX;
        return true;
    }
#endif
    sqlite3 *db = progress_store_db();
    if (!db) {
        if (reason && reason_size)
            (void)snprintf(reason, reason_size, "progress_store_unavailable");
        return false;
    }

    int32_t hstar = -1;
    int32_t served_floor = -1;
    int64_t sprout_cursor = -1;
    int64_t sapling_cursor = -1;
    int64_t nullifier_cursor = -1;
    bool sprout_found = false;
    bool sapling_found = false;
    bool nullifier_found = false;
    char transparent_reason[96] = {0};

    progress_store_tx_lock();
    bool hstar_known = reducer_frontier_compute_hstar(
        db, &hstar, &served_floor);
    /* Offer-advertisement trust bit: centralized through
     * services/sync_trust_policy.h rather than reading the raw
     * self-derived predicate directly. S = self_derived is unchanged;
     * X = proven_authority && refold_marker mirrors bx_qualified's
     * reading (config/src/bundle_exporter.c). By construction,
     * SYNC_CAP_SEED_BUNDLE is granted iff S holds (ARTIFACT_VERIFIED
     * and SOVEREIGN both carry it, no other state does), so this is
     * behavior-preserving: the resulting bit equals the raw S value in
     * every case, just resolved through the single policy table. */
    bool transparent_self_derived_raw = hstar_known &&
        coins_kv_tip_is_self_derived(db, hstar, transparent_reason,
                                     sizeof(transparent_reason));
    bool offer_proven = coins_kv_is_proven_authority(db, NULL);
    bool offer_refold =
        offer_proven && coins_kv_contains_refold_marker(db);
    enum sync_trust_state offer_trust_state = sync_trust_derive(
        offer_proven, offer_refold, transparent_self_derived_raw);
    bool transparent_self_derived = sync_trust_cap_allowed(
        offer_trust_state, SYNC_CAP_SEED_BUNDLE);
    bool cursors_read =
        anchor_kv_activation_cursor(db, ANCHOR_POOL_SPROUT,
                                    &sprout_cursor, &sprout_found) &&
        anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING,
                                    &sapling_cursor, &sapling_found) &&
        nullifier_kv_activation_cursor(db, &nullifier_cursor,
                                       &nullifier_found);
    progress_store_tx_unlock();

    bool allowed = cursors_read && boot_snapshot_offer_trust_policy(
        hstar_known, transparent_self_derived,
        sprout_found, sprout_cursor, sapling_found, sapling_cursor,
        nullifier_found, nullifier_cursor);
    if (allowed && !snapshot_offer_payload_authority_is_bound(reason,
                                                               reason_size))
        allowed = false;
    else if (!allowed && reason && reason_size) {
        if (!hstar_known)
            (void)snprintf(reason, reason_size, "hstar_unavailable");
        else if (!transparent_self_derived)
            (void)snprintf(reason, reason_size, "transparent_%s",
                           transparent_reason[0] ? transparent_reason
                                                 : "not_self_derived");
        else if (!cursors_read || !sprout_found || !sapling_found ||
                 !nullifier_found)
            (void)snprintf(reason, reason_size,
                           "shielded_history_provenance_unknown");
        else
            (void)snprintf(reason, reason_size,
                           "shielded_history_incomplete");
    }
    (void)served_floor;
    if (out_hstar)
        *out_hstar = allowed ? hstar : -1;
    return allowed;
}

bool boot_snapshot_offer_state_is_sovereign(char *reason,
                                             size_t reason_size)
{
    return snapshot_offer_state_is_sovereign_at(NULL, reason, reason_size);
}

bool boot_snapshot_offer_artifact_is_eligible(const char *datadir,
                                               char *reason,
                                               size_t reason_size)
{
    int32_t hstar = -1;
    if (!snapshot_offer_state_is_sovereign_at(&hstar, reason, reason_size))
        return false;
    struct zcl_result result = consensus_snapshot_export_artifact_check(
        datadir, hstar);
    if (!result.ok && reason && reason_size)
        (void)snprintf(reason, reason_size, "%s", result.message);
    return result.ok;
}

static bool snapshot_offer_read_block_hash(const char *datadir,
                                           int32_t height,
                                           uint8_t out_hash[32])
{
    char path[576];
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    bool ok = false;
    if (!datadir || height < 0 || !out_hash)
        return false;
    int n = snprintf(path, sizeof(path), "%s/node.db", datadir);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK ||
        !db)
        goto done;
    if (sqlite3_prepare_v2(db,
            "SELECT hash FROM blocks WHERE height=? AND status>=3 AND "
            "length(hash)=32 LIMIT 1", -1, &stmt, NULL) != SQLITE_OK || !stmt)
        goto done;
    if (sqlite3_bind_int(stmt, 1, height) != SQLITE_OK ||
        AR_STEP_ROW_READONLY(stmt) != SQLITE_ROW ||
        sqlite3_column_bytes(stmt, 0) != 32)
        goto done;
    memcpy(out_hash, sqlite3_column_blob(stmt, 0), 32);
    ok = true;
done:
    if (stmt)
        sqlite3_finalize(stmt);
    if (db)
        sqlite3_close(db);
    return ok;
}

static void *build_snapshot_offer_thread(void *arg)
{
    struct boot_svc_ctx *svc = arg;
    const char *datadir = svc ? svc->datadir : NULL;
    int64_t checkpoint = 0;

    if (!datadir || datadir[0] == '\0')
        goto done;

    offer_checkpoint(&checkpoint);

    bool file_service_enabled =
        svc && boot_profile_has_file_service(svc->app_ctx);

    /* Fast-sync publishing is peer service work, not node liveness work.
     * The exporter, offer builder, pre-serialized snapshot, and manifests all
     * walk large live tables. During boot that competes with chain-evidence,
     * UTXO-mirror, and wallet durability writes, so the daily-driver default is
     * to skip it. Operators that intentionally run a snapshot supplier can opt
     * in after they are willing to spend those DB read locks on peer service. */
    if (!env_flag_enabled("ZCL_PUBLISH_FASTSYNC_ON_BOOT")) {
        printf("Fast sync snapshot publish skipped on boot "
               "(set ZCL_PUBLISH_FASTSYNC_ON_BOOT=1 to build offers)\n");
        (void)file_service_enabled;
        boot_try_publish_block_swarm(svc, datadir);
        goto done;
    }

    char trust_reason[128] = {0};
    int32_t sovereign_height = -1;
    if (!snapshot_offer_state_is_sovereign_at(&sovereign_height, trust_reason,
                                               sizeof(trust_reason))) {
        printf("Fast sync snapshot publish withheld: node trust state is "
               "not sovereign (%s)\n",
               trust_reason[0] ? trust_reason : "unknown");
        boot_try_publish_block_swarm(svc, datadir);
        goto done;
    }

    /* Sticky/global-sync (Lane F #9c): when enabled, any SOVEREIGN at-tip
     * zclassic23 node may build and offer a snapshot, not only file-service
     * profile nodes. Assisted nodes were rejected above before export or
     * manifest construction. The
     * offer is still only PUBLISHED once a disk-backed serving buffer is ready
     * (see snapshot_serving_ready below), so this only widens who BUILDS,
     * never who falsely advertises.
     *
     * Cost: SQLite vacuum allocates transiently -- typically a few GB on
     * archival nodes, sub-second to a few seconds on healthy hosts. Operators
     * running a supplier can still opt out of the export phase by setting
     * ZCL_EXPORT_CONSENSUS_SNAPSHOT_ON_BOOT=0. */
    const char *export_snapshot =
        getenv("ZCL_EXPORT_CONSENSUS_SNAPSHOT_ON_BOOT");
    bool export_opt_out = export_snapshot &&
                          strcmp(export_snapshot, "0") == 0;
    /* Build on any profile unless explicitly opted out. */
    if (!export_opt_out) {
        printf("Exporting consensus snapshot (no wallet data)...\n");
        uint8_t sovereign_hash[32] = {0};
        struct zcl_result export_result = ZCL_ERR(
            -1, "sovereign block hash unavailable at h=%d",
            sovereign_height);
        if (snapshot_offer_read_block_hash(datadir, sovereign_height,
                                           sovereign_hash)) {
            export_result = consensus_snapshot_export_service_run_bound(
                datadir, sovereign_height, sovereign_hash);
        }
        if (export_result.ok) {
            file_controller_refresh_manifest();
            fs_server_refresh_manifest();
            printf("Consensus snapshot ready for file service\n");
        } else {
            printf("Consensus snapshot export skipped/failed (%s)\n",
                   export_result.message);
        }
    } else {
        printf("Consensus snapshot export skipped on boot "
               "(ZCL_EXPORT_CONSENSUS_SNAPSHOT_ON_BOOT=0 — opt-out)\n");
    }
    (void)file_service_enabled;

    offer_checkpoint(&checkpoint);

    printf("Building fast sync snapshot offer...\n");

    /* Zero-init: on the no-snapshot-yet path fast_sync_build_offer() returns
     * false WITHOUT filling offer, but offer.height is still read below to
     * gate the block-piece manifest. Uninitialized, that fed a garbage
     * end-height into the manifest builder on every at-tip node. With {0},
     * height==0 fails the `tip_h > BLOCKS_PER_PIECE` guard and we skip it. */
    struct snapshot_offer offer = {0};
    if (fast_sync_build_offer(datadir, &offer)) {
        /* Embed the peer-advertised header MMR root.  It proves membership in
         * that advertised header history, but ZClassic headers do not commit
         * the UTXO payload; never call this a consensus state binding. */
        uint64_t mmr_leaves = 0;
        if (!rpc_blockchain_mmr_snapshot(offer.mmr_root, &mmr_leaves, NULL) ||
            mmr_leaves == 0) {
            memset(offer.mmr_root, 0, 32);
        }

        /* Embed MMB root — replayed from leaf hash store via
         * mmb_append_hash(), guaranteeing identical merge logic
         * as mmb_prove() uses internally. */
        if (g_mmb_leaf_store.open && g_mmb_leaf_store.num_leaves > 0) {
            const uint8_t (*lh)[32] = mmb_leaf_store_all(&g_mmb_leaf_store);
            /* Replay through the snapshot anchor.  Heights are zero-based,
             * so a snapshot at height H needs H+1 MMB leaves and a
             * FlyClient chain_length of H+1. */
            uint64_t replay_count = (uint64_t)offer.height + 1;
            if (g_mmb_leaf_store.num_leaves < replay_count) {
                printf("Fast sync: MMB leaf store short (%llu/%llu); "
                       "snapshot offer unavailable\n",
                       (unsigned long long)g_mmb_leaf_store.num_leaves,
                       (unsigned long long)replay_count);
                memset(offer.mmb_root, 0, 32);
            } else if (lh && replay_count > 0) {
                struct mmb replay;
                mmb_init(&replay);
                for (uint64_t i = 0; i < replay_count; i++)
                    mmb_append_hash(&replay, lh[i]);
                mmb_root(&replay, offer.mmb_root);
                printf("Fast sync: MMB root at h=%d (%llu/%llu leaves, "
                       "%u peaks)\n", offer.height,
                       (unsigned long long)replay.num_leaves,
                       (unsigned long long)g_mmb_leaf_store.num_leaves,
                       replay.num_mountains);
            } else {
                memset(offer.mmb_root, 0, 32);
            }
        } else {
            memset(offer.mmb_root, 0, 32);
            printf("Fast sync: WARNING — no MMB leaf store\n");
        }
        /* Pre-serialize snapshot file and publish its SHA3 metadata.
         * The legacy zsnapshot offer is only advertised when an explicit
         * bounded RAM serving cache exists; otherwise peers should use the
         * chunk/file manifests below. */
        bool snapshot_serving_ready = false;
        struct node_db *ndb = boot_node_db(svc);
        if (ndb && ndb->open) {
            int64_t snap_count = fast_sync_prebuild_snapshot(
                datadir, boot_serialize_utxo_snapshot, ndb);
            if (snap_count > 0) {
                /* Use the SHA3 computed during serialization */
                uint8_t snap_sha3[32];
                uint64_t snap_n = 0;
                if (fast_sync_get_snapshot_sha3(snap_sha3, &snap_n)) {
                    memcpy(offer.utxo_root, snap_sha3, 32);
                    offer.num_utxos = snap_n;
                    printf("Snapshot: %llu UTXOs, SHA3 from file\n",
                           (unsigned long long)snap_n);
                }
                int64_t snap_buf_size = 0;
                snapshot_serving_ready =
                    fast_sync_get_snapshot_buf(&snap_buf_size) != NULL &&
                    snap_buf_size > 0;
            }
        }

        bool have_mmb_root = false;
        for (size_t i = 0; i < sizeof(offer.mmb_root); i++) {
            if (offer.mmb_root[i] != 0) {
                have_mmb_root = true;
                break;
            }
        }
        if (have_mmb_root && snapshot_serving_ready) {
            msg_processor_update_offer(&offer);
            printf("Fast sync ready: h=%d, %llu UTXOs, MMB+MMR secured\n",
                   offer.height, (unsigned long long)offer.num_utxos);
        } else if (have_mmb_root) {
            printf("Fast sync: snapshot offer withheld "
                   "(disk-backed snapshot serving not enabled)\n");
        } else {
            printf("Fast sync: snapshot offer withheld (MMB root unavailable)\n");
        }
    } else {
        printf("Fast sync: no snapshot available yet\n");
    }

    offer_checkpoint(&checkpoint);

    if (file_service_enabled) {
        printf("Building chunk sync manifest...\n");
        struct sync_manifest chunk_manifest;
        memset(&chunk_manifest, 0, sizeof(chunk_manifest));
        if (fast_sync_build_manifest(datadir, &chunk_manifest)) {
            int32_t manifest_height = chunk_manifest.height;
            uint32_t num_chunks = chunk_manifest.num_chunks;
            uint64_t num_utxos = chunk_manifest.num_utxos;
            msg_processor_publish_manifest(&chunk_manifest);
            printf("Chunk manifest ready: h=%d, %u chunks (%llu UTXOs)\n",
                   manifest_height, num_chunks,
                   (unsigned long long)num_utxos);
        } else {
            printf("Chunk manifest: not available yet\n");
        }
    }

    offer_checkpoint(&checkpoint);
    boot_try_publish_block_swarm(svc, datadir);
    offer_checkpoint(&checkpoint);
done:
    boot_complete_worker_supervisor(&g_offer_sup_id);
    return NULL;
}
