/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
/* Node / diagnostics route handlers for the REST API controller.
 *
 * These functions own node, diagnostics, and explorer factoid
 * response helpers for the route table in api_controller.c. They read
 * g_api_ctx, lock-free atomics, and node state, then write directly into the
 * caller's response buffer. */
#include "platform/time_compat.h"
#include "controllers/api_controller.h"
#include "controllers/agent_security_posture.h"
#include "controllers/block_intake_json.h"
#include "controllers/blockchain_controller.h"
#include "controllers/download_stats_json.h"
#include "controllers/file_controller.h"
#include "controllers/network_controller.h"
#include "api_controller_internal.h"
#include "config/boot.h"
#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "sync/sync_state.h"
#include "keys/key_io.h"
#include "models/database.h"
#include "models/block.h"
#include "models/file_service.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "sapling/incremental_merkle_tree.h"
#include "services/node_health_service.h"
#include "net/snapshot_sync_contract.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "views/explorer_factoids_view.h"
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "util/log_macros.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"

static struct snapshot_sync_service *api_snapshot_sync(bool *initialized)
{
    struct snapshot_sync_service *svc = app_runtime_snapshot_sync();
    if (svc) {
        if (initialized)
            *initialized = true;
        return svc;
    }
    if (initialized)
        *initialized = snapsync_global_initialized();
    return snapsync_global_initialized() ? snapsync_global() : NULL;
}
static void api_json_push_kv_nullable_str(struct json_value *obj,
                                          const char *key,
                                          const char *value)
{
    struct json_value v;
    json_init(&v);
    if (value && value[0])
        json_set_str(&v, value);
    else
        json_set_null(&v);
    json_push_kv(obj, key, &v);
    json_free(&v);
}

static void api_json_push_recent_errors(struct json_value *obj,
                                        const char *key,
                                        struct error_ring *er)
{
    char errors_json[2048];
    struct json_value recent;
    size_t elen = er ? error_ring_dump_json(er, errors_json,
                                            sizeof(errors_json)) : 0;

    json_init(&recent);
    if (elen == 0 || elen >= sizeof(errors_json) ||
        !json_read(&recent, errors_json, elen)) {
        json_set_array(&recent);
    }
    json_push_kv(obj, key, &recent);
    json_free(&recent);
}
/* Sync state — minimal monitoring endpoint */
size_t api_serve_syncstate(uint8_t *response, size_t response_max)
{
    struct json_value body;

    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.syncstate.v1");
    api_json_add_freshness(&body, "sync_projection", -1);
    json_push_kv_str(&body, "sync_state", sync_state_name(sync_get_state()));
    json_push_kv_bool(&body, "utxo_replay_active",
                      atomic_load(&g_utxo_replay_active));
    json_push_kv_int(&body, "utxo_replay_height",
                     atomic_load(&g_utxo_replay_height));
    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}
/* Download stats — IBD progress monitoring */
size_t api_serve_downloadstats(uint8_t *response, size_t response_max)
{
    struct download_stats_snapshot dl_snap;
    download_stats_snapshot_collect(&dl_snap, true);

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.downloadstats.v1");
    api_json_add_freshness(&body, "download_manager", -1);
    json_push_kv_str(&body, "sync_state", sync_state_name(sync_get_state()));
    download_stats_push_json(&body, &dl_snap, true);
    controller_json_push_block_intake_stats(&body);
    json_push_kv_int(&body, "defer_proof_validation_below_height",
                     g_deferred_proof_validation_below_height);
    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}
/* Health check — lightweight, machine-readable */
size_t api_serve_health(uint8_t *response, size_t response_max)
{
    struct node_health_snapshot health = {0};
    struct node_db *ndb = g_api_ctx.node_db ? g_api_ctx.node_db
                                            : app_runtime_node_db();
    node_health_collect(&health, ndb, g_api_ctx.main_state);
    struct agent_security_posture posture;
    agent_security_posture_collect(&posture, ndb);
    struct blocker_snapshot blockers[BLOCKER_CAP];
    int blocker_count = blocker_snapshot_all(blockers, BLOCKER_CAP);
    const struct blocker_snapshot *dominant =
        blocker_select_dominant(blockers, blocker_count);
    const struct blocker_snapshot *authority_blocker =
        api_blocker_hard_gates_public_serving(dominant) ? dominant : NULL;
    const struct blocker_snapshot *warning_blocker =
        dominant && !authority_blocker ? dominant : NULL;
    size_t public_warning_count = health.warning_count +
        (warning_blocker ? 1u : 0u);
    char public_warning_reasons[sizeof(health.warning_reasons) +
                                BLOCKER_ID_MAX + 2] = {0};
    snprintf(public_warning_reasons, sizeof(public_warning_reasons),
             "%s%s%s", health.warning_reasons,
             health.warning_reasons[0] && warning_blocker ? "," : "",
             warning_blocker ? warning_blocker->id : "");
    bool public_serving = health.serving && !authority_blocker &&
        agent_security_posture_allows_public_serving(&posture);
    bool public_healthy = health.healthy && public_serving;

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.health.v1");
    api_json_add_freshness(&body, "served_tip", -1);
    json_push_kv_bool(&body, "healthy", public_healthy);
    json_push_kv_bool(&body, "serving", public_serving);
    json_push_kv_int(&body, "warning_count",
                     (int64_t)public_warning_count);
    json_push_kv_str(&body, "sync_state", sync_state_name(health.sync_state));

    struct json_value chain;
    json_init(&chain);
    json_set_object(&chain);
    json_push_kv_int(&chain, "tip_height", health.tip_height);
    json_push_kv_int(&chain, "header_height", health.header_height);
    json_push_kv_int(&chain, "peer_best_height", health.peer_best_height);
    json_push_kv_int(&chain, "tip_lag", health.tip_lag);
    json_push_kv(&body, "chain", &chain);
    json_free(&chain);

    struct json_value database;
    json_init(&database);
    json_set_object(&database);
    json_push_kv_int(&database, "wal_size_bytes", health.wal_size_bytes);
    json_push_kv_int(&database, "utxo_count", health.utxo_count);
    json_push_kv(&body, "database", &database);
    json_free(&database);

    struct json_value network;
    json_init(&network);
    json_set_object(&network);
    json_push_kv_int(&network, "peer_count", (int64_t)health.peer_count);
    json_push_kv_bool(&network, "has_peers", health.has_peers);
    json_push_kv_bool(&network, "tip_stale", health.tip_stale);
    json_push_kv_int(&network, "tip_stale_seconds",
                     health.tip_stale_seconds);
    json_push_kv_int(&network, "magicbean_peer_count",
                     (int64_t)health.magicbean_peer_count);
    json_push_kv_int(&network, "zclassic23_peer_count",
                     (int64_t)health.zclassic_c23_peer_count);
    json_push_kv_int(&network, "zclassic_c23_peer_count",
                     (int64_t)health.zclassic_c23_peer_count);
    json_push_kv(&body, "network", &network);
    json_free(&network);

    struct json_value services;
    json_init(&services);
    json_set_object(&services);
    json_push_kv_bool(&services, "tor_enabled", health.tor_enabled);
    json_push_kv_bool(&services, "tor_ready", health.tor_ready);
    json_push_kv_bool(&services, "onion_service_ready",
                      health.onion_service_ready);
    api_json_push_kv_nullable_str(&services, "onion_address",
                                  health.onion_address);
    json_push_kv(&body, "services", &services);
    json_free(&services);

    struct json_value download;
    json_init(&download);
    json_set_object(&download);
    struct download_stats_snapshot dl_snap;
    download_stats_snapshot_from_health(&dl_snap, &health);
    download_stats_push_json(&download, &dl_snap, false);
    json_push_kv_bool(&download, "queue_backed_up",
                      health.queue_backed_up);
    json_push_kv(&body, "download", &download);
    json_free(&download);

    struct json_value boot;
    json_init(&boot);
    json_set_object(&boot);
    json_push_kv_int(&boot, "uptime_seconds", health.uptime_seconds);
    json_push_kv(&body, "boot", &boot);
    json_free(&boot);

    struct json_value errors;
    json_init(&errors);
    json_set_object(&errors);
    json_push_kv_int(&errors, "total", health.error_total);
    api_json_push_kv_nullable_str(&errors, "last", health.last_error);
    api_json_push_kv_nullable_str(&errors, "last_type",
                                  health.last_error_type);
    json_push_kv_int(&errors, "last_age_seconds",
                     health.last_error_age_seconds);
    json_push_kv_bool(&errors, "last_recent", health.last_error_recent);
    json_push_kv(&body, "errors", &errors);
    json_free(&errors);

    struct json_value watchdog;
    json_init(&watchdog);
    json_set_object(&watchdog);
    json_push_kv_int(&watchdog, "checks_run", health.wd_checks_run);
    json_push_kv_int(&watchdog, "recoveries", health.wd_recoveries);
    json_push_kv_real(&watchdog, "blocks_per_sec",
                      health.wd_blocks_per_sec);
    json_push_kv_int(&watchdog, "escalation_level",
                     health.wd_escalation_level);
    api_json_push_kv_nullable_str(&watchdog, "last_recovery",
                                  health.wd_last_recovery_name);
    json_push_kv_int(&watchdog, "last_recovery_ago_secs",
        health.wd_last_recovery_time > 0
            ? (int64_t)platform_time_wall_time_t() -
                health.wd_last_recovery_time
            : 0);
    json_push_kv_int(&watchdog, "last_recovery_target_height",
                     health.wd_last_recovery_target_height);
    json_push_kv_int(&watchdog, "last_recovery_manifest_height",
                     health.wd_last_recovery_manifest_height);
    api_json_push_kv_nullable_str(&watchdog, "last_recovery_trigger",
                                  health.wd_last_recovery_trigger);
    api_json_push_kv_nullable_str(&watchdog, "last_recovery_reason",
                                  health.wd_last_recovery_reason);
    json_push_kv(&body, "watchdog", &watchdog);
    json_free(&watchdog);

    struct json_value status;
    json_init(&status);
    json_set_object(&status);
    json_push_kv_bool(&status, "serving", public_serving);
    json_push_kv_bool(&status, "operator_latch_recovered",
                      health.operator_latch_recovered);
    api_json_push_kv_nullable_str(
        &status, "blocking_reason",
        authority_blocker ? authority_blocker->id :
        posture.review_required ? posture.status : health.blocking_reason);
    json_push_kv_bool(&status, "warning", public_warning_count > 0);
    json_push_kv_int(&status, "warning_count",
                     (int64_t)public_warning_count);
    api_json_push_kv_nullable_str(&status, "warning_reasons",
                                  public_warning_reasons);
    api_json_push_kv_nullable_str(&status, "typed_blocker_warning",
                                  warning_blocker
                                      ? warning_blocker->id : "");
    api_json_push_kv_nullable_str(&status, "degraded_reason",
                                  health.degraded_reason);
    json_push_kv(&body, "status", &status);
    json_free(&status);

    agent_push_security_posture_json(&body, "security_posture", ndb);

    size_t n = api_json_status(response, response_max,
        public_healthy ? "200 OK" : "503 Service Unavailable", &body);
    json_free(&body);
    return n;
}

/* Route: /api/node/snapshot — snapshot sync service status */
size_t api_serve_node_snapshot(uint8_t *response, size_t response_max)
{
    bool init = false;
    struct snapshot_sync_service *svc = api_snapshot_sync(&init);
    struct snapsync_status snap_status = {0};
    snap_status.state = SNAPSYNC_IDLE;
    uint64_t received = 0, total = 0;
    double rate = 0;
    if (init) snapsync_get_status_snapshot(svc, &snap_status);
    if (init) snapsync_get_progress(svc, &received, &total, &rate);
    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.node_snapshot.v1");
    api_json_add_freshness(&body, "snapshot_sync_service", -1);
    json_push_kv_str(&body, "state",
                     init ? snapsync_state_name(snap_status.state)
                          : "not_initialized");
    json_push_kv_int(&body, "received", (int64_t)received);
    json_push_kv_int(&body, "total", (int64_t)total);
    json_push_kv_real(&body, "rate_per_sec", rate);
    json_push_kv_real(&body, "percent",
                      total > 0 ? 100.0 * (double)received / (double)total
                                : 0.0);
    json_push_kv_int(&body, "serving_peer",
                     init ? snap_status.serving_peer_id : 0);
    json_push_kv_int(&body, "offered_height",
                     init ? snap_status.offered_height : 0);
    json_push_kv_bool(&body, "turbo_active",
                      init && snap_status.turbo_active);

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}

/* Route: /api/node/mmb — Merkle Mountain Belt status */
size_t api_serve_node_mmb(uint8_t *response, size_t response_max)
{
    uint8_t root[32] = {0};
    uint64_t leaves = 0;
    uint32_t peaks = 0;
    rpc_blockchain_mmb_snapshot(root, &leaves, &peaks);
    char hex[65];
    HexStr(root, 32, false, hex, sizeof(hex));
    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.node_mmb.v1");
    api_json_add_freshness(&body, "mmb_projection", -1);
    json_push_kv_str(&body, "mmb_root", hex);
    json_push_kv_int(&body, "num_leaves", (int64_t)leaves);
    json_push_kv_int(&body, "num_peaks", peaks);

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}

/* Route: /api/node/status — comprehensive one-stop diagnostics */
size_t api_serve_node_status(uint8_t *response, size_t response_max)
{
    enum sync_state ss = sync_get_state();
    bool snap_init = false;
    struct snapshot_sync_service *svc = api_snapshot_sync(&snap_init);
    struct snapsync_status snap_status = {0};
    snap_status.state = SNAPSYNC_IDLE;
    uint64_t mmb_leaves = 0;
    uint32_t mmb_peaks = 0;
    rpc_blockchain_mmb_snapshot(NULL, &mmb_leaves, &mmb_peaks);
    struct error_ring *er = error_ring_global();
    uint64_t snap_received = 0, snap_total = 0;
    double snap_rate = 0;
    if (snap_init) snapsync_get_status_snapshot(svc, &snap_status);
    if (snap_init) snapsync_get_progress(svc, &snap_received, &snap_total, &snap_rate);

    /* Collect health for peer/network data */
    struct node_health_snapshot health = {0};
    node_health_collect(&health, g_api_ctx.node_db ?
        g_api_ctx.node_db : app_runtime_node_db(),
        g_api_ctx.main_state);

    /* Chain tip info */
    char tip_hash_hex[65] = "null";
    char sapling_root_hex[65] = "null";
    char best_header_hex[65] = "null";
    int tip_height = -1;
    int header_height = -1;
    int64_t tip_time = 0;
    size_t sapling_tree_size = 0;

    struct main_state *ms = g_api_ctx.main_state;
    if (ms) {
        tip_height = reducer_frontier_provable_tip_cached();
        const struct block_index *tip =
            active_chain_at(&ms->chain_active, tip_height);
        if (tip) {
            tip_time = (int64_t)tip->nTime;
            if (tip->phashBlock) {
                uint256_get_hex(tip->phashBlock, tip_hash_hex);
            }
            uint256_get_hex(&tip->hashFinalSaplingRoot, sapling_root_hex);
        }
        if (ms->pindex_best_header) {
            header_height = ms->pindex_best_header->nHeight;
            if (ms->pindex_best_header->phashBlock)
                uint256_get_hex(ms->pindex_best_header->phashBlock,
                                best_header_hex);
        }
    }
    /* Read current sapling tree from node_state (authoritative source,
     * updated by sync_controller on every block connection). */
    char sapling_tree_root_hex[65] = "null";
    {
        struct node_db *ndb = g_api_ctx.node_db ?
            g_api_ctx.node_db : app_runtime_node_db();
        if (ndb && ndb->db) {
            uint8_t tree_buf[8192];
            size_t tree_len = 0;
            if (node_db_state_get(ndb, "sapling_tree",
                    tree_buf, sizeof(tree_buf), &tree_len)
                && tree_len > 0) {
                struct incremental_merkle_tree api_tree;
                sapling_tree_init(&api_tree);
                struct byte_stream tbs;
                stream_init_from_data(&tbs, tree_buf, tree_len);
                if (incremental_tree_deserialize(&api_tree, &tbs)) {
                    sapling_tree_size = incremental_tree_size(&api_tree);
                    if (sapling_tree_size > 0) {
                        struct uint256 tree_root;
                        incremental_tree_root(&api_tree, &tree_root);
                        uint256_get_hex(&tree_root,
                                        sapling_tree_root_hex);
                    }
                }
            }
        }
    }

    /* Download stats — read off the health snapshot already collected
     * above instead of re-fetching from the download manager. */
    struct download_stats_snapshot dl_snap;
    download_stats_snapshot_from_health(&dl_snap, &health);

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.node_status.v1");
    api_json_add_freshness(&body, "served_tip", tip_height);

    struct json_value sync;
    json_init(&sync);
    json_set_object(&sync);
    json_push_kv_str(&sync, "state", sync_state_name(ss));
    json_push_kv_bool(&sync, "replay_active",
                      atomic_load(&g_utxo_replay_active));
    json_push_kv_int(&sync, "replay_height",
                     atomic_load(&g_utxo_replay_height));
    json_push_kv(&body, "sync", &sync);
    json_free(&sync);

    struct json_value chain;
    json_init(&chain);
    json_set_object(&chain);
    json_push_kv_int(&chain, "tip_height", tip_height);
    api_json_push_kv_nullable_str(&chain, "tip_hash",
                                  strcmp(tip_hash_hex, "null") == 0
                                      ? NULL : tip_hash_hex);
    json_push_kv_int(&chain, "tip_time", tip_time);
    json_push_kv_int(&chain, "header_height", header_height);
    api_json_push_kv_nullable_str(&chain, "best_header_hash",
                                  strcmp(best_header_hex, "null") == 0
                                      ? NULL : best_header_hex);
    json_push_kv_int(&chain, "peer_best_height", health.peer_best_height);
    json_push_kv_int(&chain, "tip_lag", health.tip_lag);
    json_push_kv_int(&chain, "blocks_behind",
        health.peer_best_height > tip_height ?
            health.peer_best_height - tip_height : 0);
    json_push_kv(&body, "chain", &chain);
    json_free(&chain);

    struct json_value sapling;
    json_init(&sapling);
    json_set_object(&sapling);
    json_push_kv_int(&sapling, "tree_size", (int64_t)sapling_tree_size);
    api_json_push_kv_nullable_str(&sapling, "tree_root",
                                  strcmp(sapling_tree_root_hex, "null") == 0
                                      ? NULL : sapling_tree_root_hex);
    api_json_push_kv_nullable_str(&sapling, "header_root",
                                  strcmp(sapling_root_hex, "null") == 0
                                      ? NULL : sapling_root_hex);
    json_push_kv_bool(&sapling, "roots_match",
                      sapling_tree_size > 0 &&
                      strcmp(sapling_tree_root_hex, sapling_root_hex) == 0);
    json_push_kv(&body, "sapling", &sapling);
    json_free(&sapling);

    struct json_value network;
    json_init(&network);
    json_set_object(&network);
    json_push_kv_int(&network, "peer_count", (int64_t)health.peer_count);
    json_push_kv_bool(&network, "tip_stale", health.tip_stale);
    json_push_kv_int(&network, "tip_stale_seconds",
                     health.tip_stale_seconds);
    json_push_kv(&body, "network", &network);
    json_free(&network);

    struct json_value download;
    json_init(&download);
    json_set_object(&download);
    download_stats_push_json(&download, &dl_snap, false);
    json_push_kv(&body, "download", &download);
    json_free(&download);

    struct json_value snapshot;
    json_init(&snapshot);
    json_set_object(&snapshot);
    json_push_kv_str(&snapshot, "state",
                     snap_init ? snapsync_state_name(snap_status.state)
                               : "not_initialized");
    json_push_kv_int(&snapshot, "received",
                     (int64_t)(snap_init ? snap_received : 0));
    json_push_kv_int(&snapshot, "total",
                     (int64_t)(snap_init ? snap_total : 0));
    json_push_kv_real(&snapshot, "rate", snap_rate);
    json_push_kv(&body, "snapshot", &snapshot);
    json_free(&snapshot);

    struct json_value mmb;
    json_init(&mmb);
    json_set_object(&mmb);
    json_push_kv_int(&mmb, "leaves", (int64_t)mmb_leaves);
    json_push_kv_int(&mmb, "peaks", mmb_peaks);
    json_push_kv(&body, "mmb", &mmb);
    json_free(&mmb);

    struct json_value database;
    json_init(&database);
    json_set_object(&database);
    json_push_kv_int(&database, "wal_size_bytes", health.wal_size_bytes);
    json_push_kv_int(&database, "utxo_count", health.utxo_count);
    json_push_kv(&body, "database", &database);
    json_free(&database);

    struct json_value errors;
    json_init(&errors);
    json_set_object(&errors);
    json_push_kv_int(&errors, "total", error_ring_total(er));
    api_json_push_kv_nullable_str(&errors, "last_type",
                                  health.last_error_type);
    json_push_kv_int(&errors, "last_age_seconds",
                     health.last_error_age_seconds);
    json_push_kv_bool(&errors, "last_recent", health.last_error_recent);
    api_json_push_recent_errors(&errors, "recent", er);
    json_push_kv(&body, "errors", &errors);
    json_free(&errors);

    json_push_kv_int(&body, "defer_proof_validation_below_height",
                     g_deferred_proof_validation_below_height);
    json_push_kv_int(&body, "uptime_seconds", health.uptime_seconds);
    agent_push_security_posture_json(
        &body, "security_posture",
        g_api_ctx.node_db ? g_api_ctx.node_db : app_runtime_node_db());

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}

/* Wallet data — balance, address, activity */
size_t api_serve_wallet(uint8_t *response, size_t response_max)
{
    struct node_db *ndb = g_api_ctx.node_db ?
        g_api_ctx.node_db : app_runtime_node_db();
    if (!ndb || !ndb->db) {
        return api_json_error(response, response_max, JSON_500_HEADERS,
                          "No database");
    }

    /* Balance — use wallet_utxos (correct spent tracking). Spendable balance
     * EXCLUDES immature coinbase (matches listunspent + the coin selector). */
    int64_t transparent = db_wallet_utxo_spendable_balance(ndb, NULL);
    int64_t shielded = db_sapling_note_balance(ndb);

    /* Address — encode the first wallet key's pubkey hash */
    char address[128] = "";
    uint8_t pkh[20];
    if (db_wallet_key_first_pubkey_hash(ndb, pkh)) {
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memcpy(dest.id.key.id.data, pkh, 20);
        const unsigned char pk[] = {0x1C, 0xB8};
        const unsigned char sc[] = {0x1C, 0xBD};
        encode_destination(&dest, pk, 2, sc, 2,
                           address, sizeof(address));
    }

    /* Chain height + latest block time */
    int64_t height = 0, block_time = 0;
    db_block_tip_height_and_time(ndb, &height, &block_time);

    /* Activity — last 20 wallet UTXOs with timestamps */
    struct db_wallet_activity activity[20];
    int activity_count = db_wallet_utxo_recent_activity(ndb, activity, 20);

    struct json_value body;
    struct json_value events;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.wallet_status.v1");
    api_json_add_freshness(&body, "wallet_projection", height);
    json_push_kv_int(&body, "transparent", transparent);
    json_push_kv_int(&body, "shielded", shielded);
    json_push_kv_str(&body, "address", address);
    json_push_kv_int(&body, "height", height);
    json_push_kv_int(&body, "block_time", block_time);
    json_push_kv_int(&body, "now", (int64_t)platform_time_wall_time_t());

    json_init(&events);
    json_set_array(&events);
    for (int i = 0; i < activity_count; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_int(&item, "value", activity[i].value);
        json_push_kv_int(&item, "height", activity[i].height);
        json_push_kv_int(&item, "time", activity[i].time);
        json_push_back(&events, &item);
        json_free(&item);
    }
    json_push_kv(&body, "activity", &events);
    json_free(&events);

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}

/* GET /api/files/manifest — JSON manifest of all chunks */
size_t api_serve_files_manifest(uint8_t *response, size_t response_max)
{
    struct file_manifest manifest;
    if (!file_controller_get_manifest_copy(&manifest)) {
        /* Try building on demand */
        extern void file_controller_init(const char *);
        if (g_api_ctx.datadir) {
            file_controller_init(g_api_ctx.datadir);
            file_controller_refresh_manifest();
        }
    }
    if (!file_controller_get_manifest_copy(&manifest))
        return api_json_error(response, response_max, JSON_500_HEADERS,
                          "No block files for manifest");

    char root_hex[65];
    char mmr_hex[65];
    HexStr(manifest.root_hash, 32, false, root_hex, sizeof(root_hex));
    HexStr(manifest.mmr_root, 32, false, mmr_hex, sizeof(mmr_hex));

    struct json_value body;
    struct json_value chunks;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_str(&body, "schema", "zcl.files_manifest.v1");
    api_json_add_freshness(&body, "file_manifest", manifest.chain_height);
    json_push_kv_str(&body, "root_hash", root_hex);
    json_push_kv_str(&body, "mmr_root", mmr_hex);
    json_push_kv_int(&body, "chain_height", manifest.chain_height);
    json_push_kv_int(&body, "num_chunks", manifest.num_chunks);
    json_push_kv_int(&body, "total_bytes", (int64_t)manifest.total_bytes);

    json_init(&chunks);
    json_set_array(&chunks);
    for (uint32_t i = 0; i < manifest.num_chunks; i++) {
        char hex[65];
        struct json_value item;
        HexStr(manifest.chunks[i].sha3, 32, false, hex, sizeof(hex));
        json_init(&item);
        json_set_object(&item);
        json_push_kv_str(&item, "sha3", hex);
        json_push_kv_int(&item, "size", manifest.chunks[i].size);
        json_push_kv_int(&item, "file", manifest.chunks[i].file_index);
        json_push_kv_int(&item, "offset",
                         (int64_t)manifest.chunks[i].offset);
        json_push_back(&chunks, &item);
        json_free(&item);
    }
    json_push_kv(&body, "chunks", &chunks);
    json_free(&chunks);

    size_t n = api_json_ok(response, response_max, &body);
    json_free(&body);
    return n;
}

/* GET /api/files/:sha3hash — raw chunk bytes by SHA3 hash */
size_t api_serve_file_chunk(const char *hex, uint8_t *response,
                            size_t response_max)
{
    struct file_manifest manifest;
    uint8_t sha3[32];
    if (ParseHex(hex, sha3, 32) != 32)
        return api_json_error(response, response_max,
            JSON_404_HEADERS, "Invalid SHA3 hash");
    if (!file_controller_get_manifest_copy(&manifest))
        return api_json_error(response, response_max,
            JSON_404_HEADERS, "No manifest");
    const struct file_chunk *chunk = file_manifest_find(&manifest, sha3);
    if (!chunk)
        return api_json_error(response, response_max,
            JSON_404_HEADERS, "Chunk not found");
    uint8_t *data = NULL;
    uint32_t data_size = 0;
    if (!file_chunk_read(chunk, g_api_ctx.datadir, &data, &data_size))
        return api_json_error(response, response_max,
            JSON_500_HEADERS, "Failed to read chunk");

    size_t off = (size_t)snprintf((char *)response, response_max,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: engine/application/octet-stream\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: public, max-age=31536000, immutable\r\n"
        "X-SHA3-256: %s\r\n"
        "Connection: close\r\n"
        "Content-Length: %u\r\n\r\n", hex, data_size);
    if (off + data_size <= response_max)
        memcpy(response + off, data, data_size);
    free(data);
    return off + data_size < response_max ? off + data_size : response_max;
}
