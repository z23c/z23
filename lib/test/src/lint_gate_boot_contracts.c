/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot-ordering and persistence-ownership contracts. The load-bearing order in
 * config/src/boot_services.c (core liveness registers before the frontend,
 * shutdown persists in a fixed order, genesis init preserves restored
 * authority) is pinned here, as is the rule that lib/ owns no runtime handle
 * it did not receive: gauges, peer saves, wallet sync, block submit, flyclient
 * proof building, header peer votes and process_block's node-db access are all
 * callback-injected rather than reaching for a global.
 *
 * These assert on the TEXT of the boot and lib sources, so moving that
 * sequence or re-introducing a direct handle fails here. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; native
 * Windows has no fork/exec/waitpid, so on _WIN32 every check compiles out and
 * the registered group entry points (test_make_lint_gates.c) report a loud
 * skip instead. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

int t_boot_chain_advance_diagnostics_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("boot wiring initializes chain advance before diagnostics") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *init = strstr(buf, "block_source_policy_init(");
        char *diag_state = strstr(buf, "diagnostics_controller_set_state(");
        char *diag_register = strstr(buf, "register_diagnostics_rpc_commands(");
        ASSERT(init != NULL);
        ASSERT(diag_state != NULL);
        ASSERT(diag_register != NULL);
        ASSERT(init < diag_state);
        ASSERT(init < diag_register);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_boot_core_liveness_precedes_frontend_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("boot starts reducer liveness before optional frontend services") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *helper = strstr(buf, "static void boot_register_core_liveness_and_reducer(");
        char *helper_end = helper
            ? strstr(helper, "bool app_init_services(struct app_context *ctx,")
            : NULL;
        char *helper_stage = helper
            ? strstr(helper, "staged_sync_supervisor_register(svc->state);")
            : NULL;
        char *call = strstr(buf, "boot_register_core_liveness_and_reducer(svc, params);");
        char *frontend = strstr(buf, "boot_register_frontend_services(svc)");
        char *runtime = strstr(buf, "boot_register_runtime_services(svc)");
        ASSERT(helper != NULL);
        ASSERT(helper_end != NULL);
        ASSERT(helper_stage != NULL);
        ASSERT(call != NULL);
        ASSERT(frontend != NULL);
        ASSERT(runtime != NULL);
        ASSERT(helper_stage < helper_end);
        ASSERT(helper_stage < frontend);
        ASSERT(helper_stage < runtime);
        ASSERT(call < frontend);
        ASSERT(call < runtime);
        ASSERT(count_occurrences(buf, "staged_sync_supervisor_register(svc->state);") == 1);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_boot_addrman_persistence_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("boot uses one sidecar-protected addrman persistence path") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "connman_load_addrman(") != NULL);
        ASSERT(strstr(buf, "addr_db_read(") == NULL);
        ASSERT(strstr(buf, "addr_db_write(") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_lib_runtime_gauges_are_callback_injected(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("lib runtime gauges and peer preference are callback injected") {
        char path[PATH_MAX];
        /* The external-gauge injection moved with app_start_metrics into
         * config/src/boot_node_utilities.c (boot composition-root unit). */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_node_utilities.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_metrics_external_gauges") != NULL);
        ASSERT(strstr(buf, "svc->metrics->external_gauges =") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "connman_set_known_zcl23_peer_source") != NULL);
        ASSERT(strstr(buf, "db_peer_fast_zcl23") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "lib/metrics/src/metrics.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "ctx->external_gauges") != NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "services/sync_monitor.h") == NULL);
        ASSERT(strstr(buf, "services/legacy_mirror_sync_service.h") == NULL);
        ASSERT(strstr(buf, "services/node_health_service.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "lib/net/src/connman.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "known_zcl23_peers") != NULL);
        ASSERT(strstr(buf, "models/peer.h") == NULL);
        ASSERT(strstr(buf, "config/runtime.h") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_boot_shutdown_persistence_order_contract(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("shutdown writes clean marker before the block-index flat save") {
        /* Durability-first ordering: node.db is WAL-checkpointed + closed, then
         * the verified-clean marker is written, and ONLY THEN the best-effort
         * block-index flat save runs. A kill during the slow flat save must not
         * be able to strand the marker, so the marker write must precede the
         * flat-save call. (This replaces the older "fast < connman_join"
         * contract, which required the flat save before the checkpoint.)
         * The shutdown pipeline lives in boot_services_shutdown.c. */
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_services_shutdown.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        char *network_stop = strstr(buf, "zcl_service_kernel_stop_all(&svc->network_kernel);");
        char *health_stop = strstr(buf, "health_stop();");
        char *supervisor_stop = strstr(buf, "supervisor_stop();");
        char *stages_stop = strstr(buf,
            "staged_sync_supervisor_shutdown_stages();");
        char *service_stop = strstr(
            buf, "zcl_service_kernel_stop_all(&svc->service_kernel);");
        char *wal_checkpoint = strstr(
            buf, "db_service_wal_checkpoint(svc->db_service)");
        char *consumer_join = strstr(
            buf, "thread_registry_join_all_except(\n"
                 "        2, db_threads, db_thread_count)");
        char *thread_join = strstr(buf, "thread_registry_join_all(2)");
        char *marker = strstr(
            buf, "boot_shutdown_marker_write_clean(svc->datadir)");
        char *fast = strstr(buf, "shutdown_persist_fast_restart_state(svc);");
        ASSERT(network_stop != NULL);
        ASSERT(health_stop != NULL);
        ASSERT(supervisor_stop != NULL);
        ASSERT(stages_stop != NULL);
        ASSERT(service_stop != NULL);
        ASSERT(wal_checkpoint != NULL);
        ASSERT(consumer_join != NULL);
        ASSERT(thread_join != NULL);
        ASSERT(marker != NULL);
        ASSERT(fast != NULL);
        /* Periodic health callbacks can read node.db. Their sweeper must be
         * joined before the DB checkpoint/close begins. */
        ASSERT(health_stop < wal_checkpoint);
        ASSERT(count_occurrences(buf, "health_stop();") == 1);
        /* Stage-owned pools must receive their stop signal before the generic
         * registry join, after their supervisor callback users are joined,
         * and while persistence dependencies are still live. */
        ASSERT(supervisor_stop < stages_stop);
        ASSERT(stages_stop < wal_checkpoint);
        ASSERT(stages_stop < consumer_join);
        ASSERT(service_stop < consumer_join);
        ASSERT(consumer_join < wal_checkpoint);
        /* The DB provider is stopped only after the WAL barrier, then the
         * final registry audit proves no thread survives to the marker. */
        ASSERT(wal_checkpoint < thread_join);
        ASSERT(thread_join < marker);
        ASSERT(count_occurrences(buf,
                   "staged_sync_supervisor_shutdown_stages();") == 1);
        ASSERT(count_occurrences(buf,
                   "zcl_service_kernel_stop_all(&svc->service_kernel);") == 1);
        /* checkpoint precedes the marker (marker binds a checkpointed DB) */
        ASSERT(wal_checkpoint < marker);
        /* marker precedes the slow flat save (durability before optimization) */
        ASSERT(marker < fast);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_hodl_history_uses_runtime_db_service(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("HODL history worker uses runtime DB service") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_background_workers.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "hodl_history_fill_pending_write") != NULL);
        ASSERT(strstr(buf, "db_service_run_write(\n"
                           "                        dbsvc, "
                           "hodl_history_fill_pending_write") != NULL);
        ASSERT(strstr(buf, "node_db_open(&hdb") == NULL);
        ASSERT(strstr(buf, "private node.db open") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_db_service_query_handle_is_canonical(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("DB service query handle aliases canonical node DB") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/db_service.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "svc->query_db = svc->node_db->db") != NULL);
        ASSERT(strstr(buf, "sqlite3_open_v2(db_path, &svc->query_db") == NULL);
        ASSERT(strstr(buf, "SQLITE_OPEN_READONLY") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_txindex_releases_node_db_between_batches(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("txindex releases node.db between batches") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "app/controllers/src/snapshot_controller_txindex.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "#define TX_INDEX_BATCH_TXS 1000") != NULL);
        ASSERT(strstr(buf, "#define TX_INDEX_BATCH_YIELD_MS 100") != NULL);
        ASSERT(strstr(buf, "if (complete >= 3)") != NULL);
        ASSERT(strstr(buf, "existing > 100000") == NULL);
        ASSERT(strstr(buf, "platform_sleep_ms(TX_INDEX_BATCH_YIELD_MS)") != NULL);
        char *fail_begin = strstr(buf, "tx_index begin bulk load transaction");
        char *finalize = fail_begin ? strstr(fail_begin, "sqlite3_finalize(query)") : NULL;
        char *close_read = fail_begin ? strstr(fail_begin, "sqlite3_close(read_db)") : NULL;
        char *close_ndb = fail_begin ? strstr(fail_begin, "node_db_close(&ndb)") : NULL;
        ASSERT(fail_begin != NULL);
        ASSERT(finalize != NULL);
        ASSERT(close_read != NULL);
        ASSERT(close_ndb != NULL);
        ASSERT(finalize < close_read);
        ASSERT(close_read < close_ndb);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_peer_save_busy_reports_db_error(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("peer save lock exhaustion is reported as DB error") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "app/models/src/peer.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "event_emitf(EV_DB_ERROR") != NULL);
        ASSERT(strstr(buf, "sqlite3_errstr(rc)") != NULL);
        ASSERT(strstr(buf, "model=peer op=%s rc=%d attempts=%d msg=%s")
               != NULL);
        ASSERT(strstr(buf, "peer %s skipped") != NULL);
        ASSERT(strstr(buf, "event_emitf(EV_MODEL_VALIDATION_FAILED, 0,\n"
                           "                    \"model=peer op=save") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_handshake_peer_save_is_async(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("handshake peer persistence is advisory async write") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "msg_processor_set_peer_save") != NULL);
        ASSERT(strstr(buf, "EV_DB_ERROR") == NULL);
        free(buf);
        buf = NULL;
        /* The advisory peer-save callback body (its async-write impl detail)
         * lives in boot_msg_callbacks.c. */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_msg_callbacks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "db_service_enqueue_write(dbsvc") != NULL);
        ASSERT(strstr(buf, "db_peer_save_advisory") != NULL);
        ASSERT(strstr(buf, "boot.peer_save_ctx") != NULL);
        ASSERT(strstr(buf, "enqueue_queue_full") != NULL);
        ASSERT(strstr(buf, "peer_lifecycle_note_cache_skipped") != NULL);
        ASSERT(strstr(buf, "peer_lifecycle_note_cache_skipped_addr") != NULL);
        ASSERT(strstr(buf, "EV_DB_ERROR") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msg_version.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "mp->peer_save") != NULL);
        ASSERT(strstr(buf, "models/peer.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/peer_lifecycle.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "EV_PEER_CACHE_SKIPPED") != NULL);
        ASSERT(strstr(buf, "\"cache_skipped\"") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_p2p_app_persistence_is_callback_injected(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("p2p app persistence is injected into net") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_save_zmsg") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_zmsg_save") != NULL);
        ASSERT(strstr(buf, "boot_wire_file_market") != NULL);
        ASSERT(strstr(buf, "boot_save_file_service") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_file_service_save") != NULL);
        free(buf);
        buf = NULL;
        /* Callback bodies (the DB-write impl detail) live in boot_msg_callbacks.c. */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_msg_callbacks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "db_zmsg_save") != NULL);
        ASSERT(strstr(buf, "db_file_offer_save") != NULL);
        ASSERT(strstr(buf, "boot_ingest_file_payment") != NULL);
        ASSERT(strstr(buf, "market_payment_claim_ingest") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_file_offer_save") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_file_payment_ingest") != NULL);
        ASSERT(strstr(buf, "db_file_service_save") != NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msgprocessor.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "mp->zmsg_save") != NULL);
        ASSERT(strstr(buf, "mp->file_offer_save") != NULL);
        ASSERT(strstr(buf, "mp->file_payment_ingest") != NULL);
        ASSERT(strstr(buf, "mp->file_service_save") != NULL);
        ASSERT(strstr(buf, "db_zmsg_save") == NULL);
        ASSERT(strstr(buf, "db_file_offer_save") == NULL);
        ASSERT(strstr(buf, "db_file_service_save") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "models/file_service.h") == NULL);
        ASSERT(strstr(buf, "sync/sync_planner.h") != NULL);
        ASSERT(strstr(buf, "services/" "block_sync_" "service.h") == NULL);
        ASSERT(strstr(buf, "services/" "header_sync_" "service.h") == NULL);
        ASSERT(strstr(buf, "net/snapshot_sync_contract.h") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_tx_wallet_sync_is_callback_injected(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("tx wallet persistence and snapshot state are injected into net") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_wallet_tx_accepted") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_snapshot_active") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_snapshot_anchor_accessors") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_wallet_tx_accepted") != NULL);
        free(buf);
        buf = NULL;
        /* Callback bodies (the wallet-sync impl detail) live in boot_msg_callbacks.c. */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_msg_callbacks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "wallet_sync_transaction") != NULL);
        ASSERT(strstr(buf, "node_db_sync_wallet_tx") != NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msg_tx.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "mp->wallet_tx_accepted") != NULL);
        ASSERT(strstr(buf, "msg_processor_snapshot_active") != NULL);
        ASSERT(strstr(buf, "wallet_sync_transaction") == NULL);
        ASSERT(strstr(buf, "node_db_sync_wallet_tx") == NULL);
        ASSERT(strstr(buf, "controllers/sync_controller.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "services/" "header_sync_" "service.h") == NULL);
        ASSERT(strstr(buf, "net/snapshot_sync_contract.h") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_p2p_block_submit_is_callback_injected(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("p2p block submission is injected into net") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_submit_p2p_block") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_block_submit") != NULL);
        ASSERT(strstr(buf, "boot_block_connected_observer") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_block_connected") != NULL);
        free(buf);
        buf = NULL;
        /* Callback bodies (block-submit + observer impl detail) live in
         * boot_msg_callbacks.c. */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_msg_callbacks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "REDUCER_SRC_P2P") != NULL);
        ASSERT(strstr(buf, "sync_monitor_on_block_connected") != NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msg_blocks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "mp->block_submit") != NULL);
        ASSERT(strstr(buf, "msg_processor_snapshot_active") != NULL);
        ASSERT(strstr(buf, "msg_processor_note_block_connected") != NULL);
        ASSERT(strstr(buf, "msg_processor_request_invalid_block_headers") != NULL);
        ASSERT(strstr(buf, "msg_processor_plan_valid_block_acceptance") != NULL);
        ASSERT(strstr(buf, "reducer_ingest_block") == NULL);
        ASSERT(strstr(buf, "boot_activation_controller") == NULL);
        ASSERT(strstr(buf, "controllers/sync_controller.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "services/" "block_sync_" "service.h") == NULL);
        ASSERT(strstr(buf, "services/chain_activation_service.h") == NULL);
        ASSERT(strstr(buf, "services/" "header_sync_" "service.h") == NULL);
        ASSERT(strstr(buf, "net/snapshot_sync_contract.h") == NULL);
        ASSERT(strstr(buf, "services/sync_monitor.h") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_flyclient_proof_builder_is_callback_injected(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("FlyClient proof builder is injected into net snapshot handler") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_build_flyclient_proof") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_flyclient_proof_builder") != NULL);
        ASSERT(strstr(buf, "boot_load_block_hashes_range") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_block_hashes_range") != NULL);
        ASSERT(strstr(buf, "boot_compute_utxo_sha3") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_utxo_sha3_compute") != NULL);
        ASSERT(strstr(buf, "snapsync_build_fc_response") == NULL);
        ASSERT(strstr(buf, "db_block_hashes_in_range") == NULL);
        ASSERT(strstr(buf, "utxo_commitment_sha3_compute") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_flyclient.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_build_flyclient_proof") != NULL);
        ASSERT(strstr(buf, "snapsync_build_fc_response") != NULL);
        ASSERT(strstr(buf, "boot_load_block_hashes_range") != NULL);
        ASSERT(strstr(buf, "db_block_hashes_in_range") != NULL);
        ASSERT(strstr(buf, "boot_compute_utxo_sha3") != NULL);
        ASSERT(strstr(buf, "utxo_commitment_sha3_compute") != NULL);
        ASSERT(strstr(buf, "boot_prepare_mmb_leaf_store") != NULL);
        ASSERT(strstr(buf, "mmb_leaf_store_rebuild") != NULL);
        ASSERT(strstr(buf, "legacy_chain_rpc_") == NULL);
        ASSERT(strstr(buf, "legacy_chain_oracle") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path),
                         "lib/net/src/msgprocessor_snapshot.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "mp->flyclient_proof") != NULL);
        ASSERT(strstr(buf, "net/snapshot_sync_contract.h") != NULL);
        ASSERT(strstr(buf, "msg_snapshot_sync(") != NULL);
        ASSERT(strstr(buf, "msg_snapshot_sync_ensure") != NULL);
        ASSERT(strstr(buf, "mp->utxo_sha3_compute") != NULL);
        ASSERT(strstr(buf, "db_block_hashes_in_range") == NULL);
        ASSERT(strstr(buf, "utxo_commitment_sha3_compute") == NULL);
        ASSERT(strstr(buf, "rpc_blockchain_get_mmb") == NULL);
        ASSERT(strstr(buf, "g_mmb_leaf_store") == NULL);
        ASSERT(strstr(buf, "controllers/blockchain_controller.h") == NULL);
        ASSERT(strstr(buf, "models/mmb_leaf_store.h") == NULL);
        ASSERT(strstr(buf, "models/block.h") == NULL);
        ASSERT(strstr(buf, "coins/utxo_commitment.h") == NULL);
        ASSERT(strstr(buf, "controllers/sync_controller.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        ASSERT(strstr(buf, "services/" "snapshot_sync_" "service.h") == NULL);
        free(buf);
        buf = NULL;
        /* mp->block_hashes_range's only caller (the zblkreq SERVE handler,
         * mp_serve_block_req) lives in msgprocessor_snapshot_serve.c since
         * the lib/net/src/msgprocessor_snapshot.c SERVE-side split — see
         * msgprocessor_snapshot_internal.h. Same injected-callback
         * boundary applies there: it must call mp->block_hashes_range,
         * never reach into boot/db/model internals directly. */
        ASSERT(repo_path(path, sizeof(path),
                         "lib/net/src/msgprocessor_snapshot_serve.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "mp->block_hashes_range") != NULL);
        ASSERT(strstr(buf, "db_block_hashes_in_range") == NULL);
        ASSERT(strstr(buf, "utxo_commitment_sha3_compute") == NULL);
        ASSERT(strstr(buf, "rpc_blockchain_get_mmb") == NULL);
        ASSERT(strstr(buf, "g_mmb_leaf_store") == NULL);
        ASSERT(strstr(buf, "controllers/blockchain_controller.h") == NULL);
        ASSERT(strstr(buf, "models/mmb_leaf_store.h") == NULL);
        ASSERT(strstr(buf, "models/block.h") == NULL);
        ASSERT(strstr(buf, "coins/utxo_commitment.h") == NULL);
        ASSERT(strstr(buf, "controllers/sync_controller.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        ASSERT(strstr(buf, "services/" "snapshot_sync_" "service.h") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_fast_sync_uses_lib_sqlite_helpers(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("fast sync avoids direct AR, DB, and UTXO model includes") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/fast_sync.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "util/ar_step_readonly.h") != NULL);
        ASSERT(strstr(buf, "AR_STEP_WRITE") != NULL);
        ASSERT(strstr(buf, "models/activerecord.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "models/utxo.h") == NULL);
        ASSERT(strstr(buf, "db_utxo_serialize_snapshot") == NULL);
        ASSERT(strstr(buf, "AR_BIND_") == NULL);
        ASSERT(strstr(buf, "AR_STEP_DONE") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/net/include/net/fast_sync.h") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "fast_sync_snapshot_serialize_fn") != NULL);
        ASSERT(strstr(buf, "struct node_db") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_flyclient.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_serialize_utxo_snapshot") != NULL);
        ASSERT(strstr(buf, "db_utxo_serialize_snapshot") != NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_snapshot_offer.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "ZCL_PUBLISH_FASTSYNC_ON_BOOT") != NULL);
        ASSERT(strstr(buf, "Fast sync snapshot publish skipped on boot") != NULL);
        ASSERT(strstr(buf, "boot_serialize_utxo_snapshot") != NULL);
        ASSERT(strstr(buf, "fast_sync_prebuild_snapshot") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_framework_reexport_headers_stay_deleted(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("framework primitive re-export headers stay deleted") {
        char path[PATH_MAX];
        struct stat st;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/framework/include/framework/mailbox.h") == 0);
        errno = 0;
        ASSERT(stat(path, &st) != 0 && errno == ENOENT);

        ASSERT(repo_path(path, sizeof(path),
                         "lib/framework/include/framework/projection.h") == 0);
        errno = 0;
        ASSERT(stat(path, &st) != 0 && errno == ENOENT);

        ASSERT(repo_path(path, sizeof(path),
                         "app/services/include/services/header_admit_inbox.h") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "util/mailbox.h") != NULL);
        ASSERT(strstr(buf, "framework/mailbox.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "app/controllers/src/chain_projection.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "util/projection.h") != NULL);
        ASSERT(strstr(buf, "framework/projection.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "lib/framework/README.md") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "only purpose is to re-export") != NULL);
        ASSERT(strstr(buf, "include/framework/mailbox.h") == NULL);
        ASSERT(strstr(buf, "include/framework/projection.h") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_utxo_reimport_flag_is_storage_owned(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("utxo reimport flag is storage owned") {
        char path[PATH_MAX];

        ASSERT(repo_path(path, sizeof(path),
                         "app/services/include/services/utxo_recovery_service.h")
               == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "storage/utxo_reimport_flag.h") == NULL);
        ASSERT(strstr(buf, "re-export") == NULL);
        ASSERT(strstr(buf, "re-exports") == NULL);
        ASSERT(strstr(buf, "utxo_reimport_flag_check_and_clear") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "config/src/boot.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "storage/utxo_reimport_flag.h") != NULL);
        ASSERT(strstr(buf, "utxo_reimport_flag_check_and_clear") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/"
                         "process_block_self_heal_hot_loop.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "storage/utxo_reimport_flag.h") != NULL);
        ASSERT(strstr(buf, "utxo_reimport_flag_set") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_net_sync_planners_are_lib_owned(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("net sync planners use lib-owned contract") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msg_headers.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "sync/sync_planner.h") != NULL);
        ASSERT(strstr(buf, "msg_processor_snapshot_active") != NULL);
        ASSERT(strstr(buf, "msg_processor_snapshot_anchor") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_snapshot_anchor") != NULL);
        ASSERT(strstr(buf, "msg_processor_request_activation") != NULL);
        ASSERT(strstr(buf, "msg_processor_clear_activation_anchor") != NULL);
        ASSERT(strstr(buf, "msg_processor_repair_post_activation_anchor") != NULL);
        ASSERT(strstr(buf, "msg_processor_scan_block_files") != NULL);
        ASSERT(strstr(buf, "msg_processor_block_index_heights_repaired") != NULL);
        ASSERT(strstr(buf, "msg_processor_commit_header_tip") != NULL);
        ASSERT(strstr(buf, "msg_processor_recommit_snapshot_anchor") != NULL);
        ASSERT(strstr(buf, "services/" "block_sync_" "service.h") == NULL);
        ASSERT(strstr(buf, "services/block_index_integrity.h") == NULL);
        ASSERT(strstr(buf, "services/chain_activation_service.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        ASSERT(strstr(buf, "services/chain_tip.h") == NULL);
        ASSERT(strstr(buf, "services/" "header_sync_" "service.h") == NULL);
        ASSERT(strstr(buf, "net/snapshot_sync_contract.h") == NULL);
        ASSERT(strstr(buf, "config/boot_internal.h") == NULL);
        ASSERT(strstr(buf, "boot_activation_controller") == NULL);
        ASSERT(strstr(buf, "activation_request_connect") == NULL);
        ASSERT(strstr(buf, "activation_clear_anchor") == NULL);
        ASSERT(strstr(buf, "bii_repair_post_activation_anchor") == NULL);
        ASSERT(strstr(buf, "csr_commit_tip") == NULL);
        ASSERT(strstr(buf, "csr_commit_header_tip") == NULL);
        ASSERT(strstr(buf, "csr_instance") == NULL);
        ASSERT(strstr(buf, "chain_state_commit") == NULL);
        ASSERT(strstr(buf, "scan_block_files_mark_data") == NULL);
        ASSERT(strstr(buf, "block_index_heights_repaired()") == NULL);
        ASSERT(strstr(buf, "snapsync_is_active") == NULL);
        ASSERT(strstr(buf, "snapsync_get_anchor") == NULL);
        ASSERT(strstr(buf, "snapsync_set_anchor") == NULL);
        ASSERT(strstr(buf, "TIP_FROM_P2P_REPAIR") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_request_header_activation") != NULL);
        ASSERT(strstr(buf, "boot_clear_header_activation_anchor") != NULL);
        ASSERT(strstr(buf, "boot_repair_header_post_activation_anchor") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_activation_hooks") != NULL);
        ASSERT(strstr(buf, "boot_scan_header_block_files") != NULL);
        ASSERT(strstr(buf, "scan_block_files_mark_data") != NULL);
        ASSERT(strstr(buf, "boot_header_block_index_heights_repaired") != NULL);
        ASSERT(strstr(buf, "block_index_heights_repaired") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_header_index_hooks") != NULL);
        ASSERT(strstr(buf, "boot_commit_header_tip") != NULL);
        ASSERT(strstr(buf, "boot_recommit_snapshot_anchor") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_header_chainstate_hooks") != NULL);
        free(buf);
        buf = NULL;
        /* The background_utxo_replay worker drives the post-snapshot activation
         * connect + chainstate commit. It lives in its own boot unit
         * (boot_utxo_replay.c, split out of boot_background_workers.c for the
         * file-size ratchet), so its activation_request_connect /
         * csr_commit_tip call sites live there — still boot-owned
         * (config/src), never in lib/net. */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_utxo_replay.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "activation_request_connect") != NULL);
        ASSERT(strstr(buf, "csr_commit_tip") != NULL);
        free(buf);
        buf = NULL;
        /* Callback bodies (the activation/index/chainstate impl detail) live in
         * boot_msg_callbacks.c. */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_msg_callbacks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "activation_clear_anchor") != NULL);
        ASSERT(strstr(buf, "bii_repair_post_activation_anchor") != NULL);
        /* Header-tip mutation routes through the chain-state repository's
         * validated promote (operator-snapshot refactor). */
        ASSERT(strstr(buf, "csr_promote_header_tip") != NULL);
        ASSERT(strstr(buf, "chain_set_active_tip") != NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path),
                         "lib/sync/include/sync/sync_planner.h") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "struct sync_header_processing_plan") != NULL);
        ASSERT(strstr(buf, "struct sync_stall_recovery") != NULL);
        ASSERT(strstr(buf, "syncsvc_plan_periodic_getheaders") != NULL);
        ASSERT(strstr(buf, "syncsvc_assign_peer_blocks") != NULL);
        ASSERT(strstr(buf, "services/") == NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/event/include/event/event.h") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "EV_SYNC_STATE_CHANGE") != NULL);
        ASSERT(strstr(buf, "#include \"sync/sync_state.h\"") == NULL);
        ASSERT(strstr(buf, "enum sync_state") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_header_peer_votes_are_callback_injected(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("header peer votes are injected into net") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_record_peer_header_vote") != NULL);
        ASSERT(strstr(buf, "msg_processor_set_peer_header_vote") != NULL);
        free(buf);
        buf = NULL;
        /* Callback body (the quorum-oracle impl detail) lives in
         * boot_msg_callbacks.c. */
        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_msg_callbacks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "quorum_oracle_record_peer_header_vote") != NULL);
        free(buf);
        buf = NULL;
        ASSERT(repo_path(path, sizeof(path), "lib/net/src/msg_headers.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "msg_processor_record_peer_header_vote") != NULL);
        ASSERT(strstr(buf, "quorum_oracle_record_peer_header_vote") == NULL);
        ASSERT(strstr(buf, "services/quorum_oracle_service.h") == NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

int t_process_block_node_db_access_is_runtime_owned(void)
{
    int failures = 0;
    char *buf = NULL;
    TEST("process block node_db access is runtime owned") {
        char path[PATH_MAX];
        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        /* The accessors live behind storage/node_db_runtime.h, a lib/-owned
         * port config/ registers into. Naming config/ from lib/ would make
         * the composition root and the foundation mutually dependent, so the
         * negative guard below is joined by check-lib-layering (gate #15). */
        ASSERT(strstr(buf, "node_db_runtime_handle_open") != NULL);
        ASSERT(strstr(buf, "config/runtime.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_flush_policy.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "node_db_runtime_handle_open") != NULL);
        ASSERT(strstr(buf, "node_db_runtime_state_set") != NULL);
        /* sync_flush_if_needed + wal_checkpoint positive-assertions removed:
         * their only use site here (flush_coins_if_needed, the dead
         * forward-writer) was deleted in the dead-code removal — process_block
         * no longer flushes coins to the node.db mirror (the staged pipeline
         * owns coin writes; the mirror is rebuilt one-way by
         * utxo_mirror_sync_service). The runtime-owned invariant stays enforced
         * by the accessors present (handle_open, state_set) + the negative
         * models/database.h guard. */
        ASSERT(strstr(buf, "models/database.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_self_heal.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "node_db_runtime_utxo_max_height") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_tx_index_find") == NULL);
        ASSERT(strstr(buf, "db_tx_find_native_or_reversed") == NULL);
        ASSERT(strstr(buf, "sqlite3_prepare_v2") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "models/tx_index.h") == NULL);
        ASSERT(strstr(buf, "rpc/legacy_rpc_client.h") == NULL);
        ASSERT(strstr(buf, "process_block_json_string") == NULL);
        ASSERT(strstr(buf, "process_block_legacy_rpc_body") == NULL);
        ASSERT(strstr(buf,
                      "process_block_recover_missing_utxo_from_sqlite_tx_index(")
               == NULL);
        ASSERT(strstr(buf, "read_block_from_disk_index") == NULL);
        ASSERT(strstr(buf, "process_block_recover_missing_utxo_from_chain_scan(")
               == NULL);
        ASSERT(strstr(buf, "block_tree_db_write_tx_index") == NULL);
        ASSERT(strstr(buf, "process_block_self_heal_scan_depth_limit") == NULL);
        ASSERT(strstr(buf, "process_block_self_heal_stats_snapshot") == NULL);
        ASSERT(strstr(buf, "g_self_heal_scan_hits") == NULL);
        ASSERT(strstr(buf, "utxo_reimport_flag_set") == NULL);
        ASSERT(strstr(buf, "FATAL_HOT_LOOP") == NULL);
        ASSERT(strstr(buf, "last_reimport_attempted") == NULL);
        ASSERT(strstr(buf, "process_block_inject_missing_utxo(") == NULL);
        ASSERT(strstr(buf, "coins_from_transaction") == NULL);
        ASSERT(strstr(buf, "coins_view_cache_modify_new") == NULL);
        ASSERT(strstr(buf, "COINS_CACHE_DIRTY") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/"
                         "process_block_self_heal_hot_loop.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_maybe_write_needs_reimport_flag")
               != NULL);
        ASSERT(strstr(buf, "process_block_maybe_trigger_hot_loop_exit")
               != NULL);
        ASSERT(strstr(buf, "process_block_get_utxo_activation_paused_height")
               != NULL);
        ASSERT(strstr(buf, "process_block_clear_utxo_activation_pause_range")
               != NULL);
        ASSERT(strstr(buf, "utxo_reimport_flag_set") != NULL);
        ASSERT(strstr(buf, "FATAL_HOT_LOOP") != NULL);
        ASSERT(strstr(buf, "last_reimport_attempted") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_tx_index_find") == NULL);
        ASSERT(strstr(buf, "read_block_from_disk_index") == NULL);
        ASSERT(strstr(buf, "block_tree_db_write_tx_index") == NULL);
        ASSERT(strstr(buf, "rpc/legacy_rpc_client.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/"
                         "process_block_self_heal_scan_state.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_self_heal_scan_depth_limit") != NULL);
        ASSERT(strstr(buf, "process_block_self_heal_scan_enabled") != NULL);
        ASSERT(strstr(buf, "process_block_self_heal_stats_snapshot") != NULL);
        ASSERT(strstr(buf, "g_self_heal_scan_hits") != NULL);
        ASSERT(strstr(buf, "ZCL_SELF_HEAL_SCAN_DEPTH") != NULL);
        ASSERT(strstr(buf, "ZCL_SELF_HEAL_SCAN_ENABLE") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_tx_index_find") == NULL);
        ASSERT(strstr(buf, "utxo_reimport_flag_set") == NULL);
        ASSERT(strstr(buf, "read_block_from_disk_index") == NULL);
        ASSERT(strstr(buf, "block_tree_db_write_tx_index") == NULL);
        ASSERT(strstr(buf, "rpc/legacy_rpc_client.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_core.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "controllers/blockchain_controller.h") == NULL);
        ASSERT(strstr(buf, "controllers/sync_controller.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "models/tx_index.h") == NULL);
        ASSERT(strstr(buf, "services/chain_activation_service.h") == NULL);
        ASSERT(strstr(buf, "services/chain_evidence_authority_service.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        ASSERT(strstr(buf, "services/chain_tip.h") == NULL);
        ASSERT(strstr(buf, "services/gap_fill_service.h") == NULL);
        ASSERT(strstr(buf, "net/snapshot_sync_contract.h") == NULL);
        ASSERT(strstr(buf, "process_block_set_gap_fill_kick") == NULL);
        ASSERT(strstr(buf, "process_block_set_tip_publication_hooks") == NULL);
        ASSERT(strstr(buf, "process_block_propagate_failed_child(") == NULL);
        ASSERT(strstr(buf, "block_index_hydrate_from_disk(") == NULL);
        ASSERT(strstr(buf, "find_block_pos(") == NULL);
        ASSERT(strstr(buf, "block_index_refresh_header(") == NULL);
        ASSERT(strstr(buf, "process_block_commit_tip(") == NULL);
        ASSERT(strstr(buf, "process_block_publish_tip(") == NULL);
        ASSERT(strstr(buf, "process_block_clear_tip(") == NULL);
        ASSERT(strstr(buf, "process_block_tip_is_best_work(") == NULL);
        ASSERT(strstr(buf, "process_block_verify_active_tip_child_on_disk(")
               == NULL);
        ASSERT(strstr(buf, "find_best_active_tip_child(") == NULL);
        ASSERT(strstr(buf, "find_verified_unlinked_active_tip_child(") == NULL);
        ASSERT(strstr(buf, "process_block_should_skip_contextual_header(")
               == NULL);
        ASSERT(strstr(buf, "process_block_pow_window_complete(") == NULL);
        ASSERT(strstr(buf, "consensus/params.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_contextual_header.c")
               == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_should_skip_contextual_header")
               != NULL);
        ASSERT(strstr(buf, "process_block_pow_window_complete") != NULL);
        ASSERT(strstr(buf, "find_most_work_chain") == NULL);
        ASSERT(strstr(buf, "process_block_kick_gap_fill") == NULL);
        ASSERT(strstr(buf, "services/gap_fill_service.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_tip_child.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_verify_active_tip_child_on_disk")
               != NULL);
        ASSERT(strstr(buf, "find_best_active_tip_child") != NULL);
        ASSERT(strstr(buf, "find_verified_unlinked_active_tip_child") != NULL);
        ASSERT(strstr(buf, "controllers/blockchain_controller.h") == NULL);
        ASSERT(strstr(buf, "controllers/sync_controller.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_tip_publish.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_commit_tip") != NULL);
        ASSERT(strstr(buf, "update_tip") != NULL);
        ASSERT(strstr(buf, "process_block_tip_is_best_work") != NULL);
        ASSERT(strstr(buf, "process_block_publish_tip") != NULL);
        ASSERT(strstr(buf, "controllers/blockchain_controller.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_index.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "find_block_pos") != NULL);
        ASSERT(strstr(buf, "block_index_refresh_header") != NULL);
        ASSERT(strstr(buf, "block_index_hydrate_from_disk") != NULL);
        ASSERT(strstr(buf, "block_index_snapshot_for_persist") != NULL);
        ASSERT(strstr(buf, "disk_block_index_init") != NULL);
        ASSERT(strstr(buf, "controllers/blockchain_controller.h") == NULL);
        ASSERT(strstr(buf, "models/database.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_invalidate.c")
               == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "block_index_emit_header_event") != NULL);
        ASSERT(strstr(buf, "block_index_snapshot_for_persist") == NULL);
        ASSERT(strstr(buf, "disk_block_index_init") == NULL);
        ASSERT(strstr(buf, "nCachedBranchId") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_revalidate.c")
               == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "block_index_emit_header_event") != NULL);
        ASSERT(strstr(buf, "block_index_snapshot_for_persist") == NULL);
        ASSERT(strstr(buf, "disk_block_index_init") == NULL);
        ASSERT(strstr(buf, "nCachedBranchId") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_runtime_hooks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_set_gap_fill_kick") != NULL);
        ASSERT(strstr(buf, "process_block_kick_gap_fill") != NULL);
        ASSERT(strstr(buf, "process_block_set_tip_publication_hooks") != NULL);
        ASSERT(strstr(buf, "process_block_publish_tip") != NULL);
        ASSERT(strstr(buf, "process_block_clear_tip") != NULL);
        ASSERT(strstr(buf, "controllers/blockchain_controller.h") == NULL);
        ASSERT(strstr(buf, "services/chain_state_service.h") == NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "lib/validation/src/process_block_failed_child.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_propagate_failed_child") != NULL);
        ASSERT(strstr(buf, "PROPAGATE_FAILED_CHILD_SKIP_RATE_LIMITED") != NULL);
        ASSERT(strstr(buf, "zcl_malloc") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "config/src/runtime.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "app_runtime_node_db_handle_open") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_state_set") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_sync_flush_if_needed") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_wal_checkpoint") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_utxo_max_height") != NULL);
        ASSERT(strstr(buf, "app_runtime_node_db_tx_index_find") != NULL);
        ASSERT(strstr(buf, "db_tx_find_native_or_reversed") != NULL);
        ASSERT(strstr(buf, "SELECT MAX(height) FROM utxos") != NULL);
        ASSERT(strstr(buf, "node_db_state_set") != NULL);
        ASSERT(strstr(buf, "node_db_sync_flush") != NULL);
        ASSERT(strstr(buf, "ndb->open") != NULL);
        free(buf);
        buf = NULL;

        /* The process-block hooks were extracted to boot_tip_hooks.c
         * (behavior-neutral, Wave D). boot_services.c wires them via the seam
         * call; the inline NULL teardown moved with the shutdown pipeline to
         * boot_services_shutdown.c. The hook bodies + the non-NULL
         * registration live in boot_tip_hooks.c. node_db is still reached via
         * svc (runtime-owned) in all three. */
        ASSERT(repo_path(path, sizeof(path), "config/src/boot_services.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_register_process_block_hooks(svc)") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path),
                         "config/src/boot_services_shutdown.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "process_block_set_gap_fill_kick(NULL, NULL)") != NULL);
        ASSERT(strstr(buf, "process_block_set_tip_publication_hooks(NULL, NULL, NULL)") != NULL);
        free(buf);
        buf = NULL;

        ASSERT(repo_path(path, sizeof(path), "config/src/boot_tip_hooks.c") == 0);
        ASSERT(read_entire_file(path, &buf) == 0);
        ASSERT(strstr(buf, "boot_gap_fill_kick") != NULL);
        ASSERT(strstr(buf, "gap_fill_kick") != NULL);
        ASSERT(strstr(buf, "boot_process_block_commit_tip") != NULL);
        ASSERT(strstr(buf, "boot_process_block_clear_tip") != NULL);
        ASSERT(strstr(buf, "process_block_set_gap_fill_kick(boot_gap_fill_kick, svc)") != NULL);
        ASSERT(strstr(buf, "process_block_set_tip_publication_hooks(boot_process_block_commit_tip") != NULL);
        PASS();
    } _test_next:;
    free(buf);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_boot_unit;

#endif /* ZCL_TESTING */
