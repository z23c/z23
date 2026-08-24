/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Test-suite core: assertion macros, temp-directory helpers, and the group
 * entry-point declarations. Includes NO node header, so editing a node header
 * never invalidates a test translation unit that only needs this file.
 *
 * Node-typed shared fixtures live in the facets beside it:
 *   test/block_fixtures.h      — test_block_copy (needs struct block)
 *   test/wallet_view_fixture.h — DEFINE_WALLET_VIEW_CLIENT
 * test/test_helpers.h remains the umbrella over this file, both facets, and
 * the node headers the unconverted test files still rely on transitively. */

#ifndef TEST_CORE_H
#define TEST_CORE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include <dirent.h>
#include <unistd.h>

/* Only ever used through a pointer here — the definition stays in
 * consensus/params.h for the callers that fill one in. */
struct consensus_params;

/* Remove a test temp directory and any files inside it.
 * Handles the common case where SQLite leaves node.db, -wal, -shm behind. */
static inline void test_cleanup_tmpdir(const char *path)
{
    if (!path) return;
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *ent;
    char fpath[512];
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        snprintf(fpath, sizeof(fpath), "%s/%s", path, ent->d_name);
        unlink(fpath);
    }
    closedir(d);
    rmdir(path);
}

/* Build "./test-tmp/<prefix>_<pid>_<tag>" into buf (snprintf-only, no
 * directory creation). Shared by the per-stage *_tmpdir helpers. */
static inline void test_fmt_tmpdir(char *buf, size_t n,
                                   const char *prefix, const char *tag)
{
    snprintf(buf, n, "./test-tmp/%s_%d_%s", prefix, (int)getpid(), tag);
}

/* Shared helper functions */
int check_hex(const unsigned char *data, size_t len, const char *expected);
void test_hex_to_bytes(const char *hex, uint8_t *out, int len);
void test_hex_to_bytes_rev(const char *hex, uint8_t *out, int len);

/* Recursively delete a directory tree via system("rm -rf ..."). No-op
 * for NULL/empty input. */
void test_rm_rf(const char *dir);

/* Recursively delete a directory tree in pure C (opendir/unlink/rmdir).
 * Returns the rmdir/unlink result of the top-level path. */
int test_rm_rf_recursive(const char *path);

/* Build "./test-tmp/<prefix>_<pid>_<tag>" into buf, clean any stale
 * directory at that path, then mkdir test-tmp and the dir itself. */
void test_make_tmpdir(char *buf, size_t n, const char *prefix,
                      const char *tag);

/* Build the smallest exact bounded replay fixture (genesis only) and publish
 * shielded completeness through the production atomic completion API. */
bool test_complete_genesis_shielded_replay(sqlite3 *db);

/* Zero a consensus_params and set powLimit to all-ones (trivially-easy
 * target) for deterministic PoW in tests. */
void test_make_easy_consensus_params(struct consensus_params *p);

/* Build "<dir>/event_log.dat" and "<dir>/<name>_projection.db". */
void test_projection_paths(const char *dir, const char *name,
                           char *elog, size_t elog_n,
                           char *proj, size_t proj_n);

/* Reset process-global singletons that leak across groups in the
 * single-process monolith (test_zcl). Call at the TOP of any group whose
 * assertions read shared global state. See test_helpers.c for the rationale. */
void test_reset_shared_globals(void);

/* Test group functions — each returns failure count */
int test_crypto(void);
int test_crypto_registry(void);
int test_encoding(void);
int test_sapling(void);
int test_script(void);
int test_chain(void);
int test_sqlite(void);
int test_keys(void);
int test_mempool(void);
int test_accept_to_mempool(void);
int test_rpc(void);
int test_transaction(void);
int test_net(void);
int test_netbase_split_host_port(void);
int test_activerecord(void);
int test_sapling_crypto(void);
int test_groth16_msm_parity(void);
int test_groth16_r1cs_oracle(void);
int test_native_spend_proof(void);
int test_sapling_tree(void);
int test_sapling_ckpt_persist(void);
int test_shutdown_marker(void);
int test_bn254(void);
int test_merkle_tree(void);
int test_merkle_malleability(void);
int test_slp(void);
int test_models(void);
int test_core(void);
int test_json(void);
int test_validation(void);
int test_wallet(void);
int test_primitives(void);
int test_bloom(void);
int test_compact_blocks(void);
int test_dandelion(void);
int test_addrman_rebalance(void);
int test_addrman_eclipse(void);
int test_coins(void);
int test_chainstate_legacy_reader(void);
int test_importblockindex_roundtrip(void);
int test_importblockindex_cli_dispatch(void);
int test_chainstate_sapling_anchor(void);
int test_utxo_import_pipeline(void);
int test_ccoins_decoder_kat(void);
int test_coins_record_codec(void);
int test_storage_coins_utxo(void);
int test_blob_read_bounds(void);
int test_boot_snapshot_drop_bodiless(void);
int test_tor(void);
int test_game(void);
int test_store(void);
int test_store_listing(void);
int test_store_buyer(void);
int test_store_transparent_pay(void);
int test_blog(void);
int test_robustness(void);
int test_api(void);
int test_explorer(void);
int test_explorer_rpc_call(void);
int test_explorer_index(void);
int test_mining(void);
int test_utxo_commitment(void);
int test_mmr(void);
int test_mmb(void);
int test_flyclient(void);
int test_scan_util(void);
int test_event(void);
int test_download(void);
int test_consensus(void);
int test_connman_addnode_fallback(void);
int test_peer_eviction(void);
int test_net_bootstrap(void);
int test_policy(void);
int test_wallet_view(void);
int test_fast_sync(void);
int test_block_scan(void);
int test_node_health_service(void);
int test_chain_state_repo(void);
int test_chain_evidence_controller(void);
int test_chain_evidence_live_advance(void);
int test_long_op(void);
int test_agent_copy_prove(void);
int test_agent_test(void);
int test_recovery_policy(void);
int test_oracle_policy(void);
int test_quorum_oracle(void);
int test_db_txn(void);
int test_sync_service(void);
int test_node_db_catchup_service(void);
int test_catchup_lifecycle_service(void);
int test_sync_state_fsm(void);
int test_heartbeat(void);
int test_block_source_policy(void);
int test_block_source_policy_status_json(void);
int test_snapshot_sync_service(void);
int test_snapshot_serve_loopback(void);
int test_block_swarm_loopback(void);
int test_file_controller(void);
int test_file_ops(void);
int test_integrity(void);
int test_rolling_anchor_service(void);
int test_protocols(void);
int test_chain_restore_planner(void);
int test_chain_restore_service(void);
int test_chain_activation_controller(void);
int test_hotswap_loader(void);
int test_hotswap_simnet(void);
int test_hotswap_module(void);
int test_hotswap_module_v2(void);
int test_hotswap_service_registry(void);
int test_dev_platform(void);
int test_command_registry_catalog(void);
int test_command_registry_latency(void);
int test_metaverse_agent_broker(void);
int test_metaverse_broker_authority(void);
int test_metaverse_broker_idempotency(void);
int test_status_readiness_truth(void);
int test_native_api_contract(void);
int test_metric_alerts(void);
int test_db_validators(void);
int test_peer_scoring(void);
int test_peer_bandwidth(void);
int test_peer_lifecycle(void);
int test_peer_identity_hostkey(void);
int test_secrets_hygiene(void);
int test_block_index_integrity(void);
int test_block_map_grow_phashblock(void);
int test_block_successor(void);
int test_key_hostile_wif(void);
/* Subsection 5/6 finish-drive: defensive + consensus unit-test gaps. */
int test_block_locator_bounds(void);
int test_block_map_grow_collision(void);
int test_connect_node_locked(void);
int test_stream_read_no_overflow(void);
int test_transaction_deserialize_count_amplification(void);
int test_block_deserialize_txcount_amplification(void);
int test_fast_sync_serve_chunk_db_clamps(void);
int test_connman_node_count_locked(void);
int test_fees_oom(void);
int test_fees_oom_inject(void);
int test_multisig_consensus_branches(void);
int test_parse_script_oversize_hex(void);
int test_script_num_minimal_encoding(void);
/* Subsection 3 finish-drive: crypto KAT + consensus regression-seal tests. */
int test_domain_consensus_pow_seal_matrix(void);
int test_domain_consensus_pow_seal_powlimit_floor(void);
int test_domain_consensus_pow_seal_malformed_paths(void);
int test_domain_consensus_pow_seal_deterministic(void);
int test_checkpoints_progress_boundary_crossover(void);
int test_checkpoints_progress_zero_defenses(void);
int test_checkpoints_progress_sigcheck_factor(void);
int test_checkpoints_progress_regression_seal(void);
int test_equihash_null_guards(void);
int test_equihash_solution_size_demux(void);
int test_equihash_blake2b_state_seal(void);
int test_equihash_serialization_matches_independent_rebuild(void);
int test_equihash_legacy_wrapper_regression_seal(void);
int test_coins_amount_codec_roundtrip(void);
int test_coins_amount_codec_boundary_exponents(void);
int test_coins_amount_codec_digit_preservation(void);
int test_coins_amount_codec_regression_seal(void);
int test_hkdf_sha256_rfc5869(void);
int test_x25519_safe(void);
int test_noise_nk_handshake(void);
int test_noise_xx_handshake(void);
int test_session_transport(void);
int test_v2_transport_parity(void);
int test_hmac_sha512_kat_rfc4231_jefe(void);
int test_hmac_sha512_kat_oversized_key(void);
int test_hmac_sha512_empty_message(void);
int test_hmac_sha512_multiblock_stateful_write(void);
int test_hmac_sha512_key_len_128_boundary(void);
int test_pbkdf2_sha512_rfc_vector(void);
int test_pbkdf2_sha512_multiblock(void);
int test_pbkdf2_sha512_high_iterations(void);
int test_pbkdf2_sha512_empty_inputs(void);
int test_pbkdf2_sha512_one_byte_output(void);
/* Drive 4 finish-drive: sapling/script/wallet pedantic regression tests. */
int test_sapling_address_hash_fields(void);
int test_sprout_address_hash_fields(void);
int test_sapling_sprout_hash_idempotence_and_distinct(void);
int test_sprout_spending_key_viewing_key(void);
int test_note_encryption_kdf_domain_separation(void);
int test_note_encryption_prf_ock_known_answer(void);
int test_note_encryption_sapling_kdf_arg_order_distinct(void);
int test_note_encryption_sapling_kdf_avalanche(void);
int test_note_encryption_sapling_kdf_known_answer(void);
int test_note_encryption_sprout_kdf_avalanche(void);
int test_note_encryption_sprout_kdf_known_answer(void);
int test_note_encryption_sprout_kdf_nonce_sweep(void);
int test_zip32_default_diversifier_deterministic(void);
int test_zip32_default_diversifier_is_ff1_of_settled_index(void);
int test_zip32_diversifier_advances_index_in_place(void);
int test_zip32_diversifier_distinct_keys_distinct_output(void);
int test_zip32_diversifier_index_boundaries(void);
int test_zip32_diversifier_skips_invalid_indices(void);
int test_zip32_ff1_radix2_deterministic(void);
int test_script_interp_altstack_conditional(void);
int test_script_interp_op2rot_order(void);
int test_script_interp_oppick_bounds(void);
int test_script_interp_oproll_semantics(void);
int test_script_interp_optuck_insert(void);
int test_script_interp_overflow_boundary(void);
int test_wallet_backup(void);
int test_wallet_restore(void);
int test_wallet_destruction_drill(void);
int test_log_json(void);
int test_http_middleware(void);
int test_rpc_timeout(void);
int test_wallet_keystore(void);
int test_wallet_sqlite_enc(void);
int test_disk_monitor(void);
int test_binary_staleness(void);
int test_binary_ab_fallback(void);
int test_db_maintenance(void);
int test_mempool_limits(void);
int test_addrman_integrity(void);
int test_anchor_peers(void);
int test_zdir_selection(void);
int test_ibd_throttle(void);
int test_consensus_reject_events(void);
int test_consensus_reject_index(void);
int test_blocker_history(void);
int test_chain_rollback(void);
int test_alerts(void);
int test_ws_events(void);
int test_trace(void);
int test_phgr13_fix(void);
int test_sprout_phgr13_kat(void);
int test_sprout_groth16_kat(void);
int test_transaction_wire_evidence(void);
int test_rescanwitnesses_diverge_guard(void);
int test_gap_fill_frontier_window(void);
int test_snark_kat(void);
int test_bls12_381_adversarial(void);
int test_verify_bench_selftest(void);
int test_crypto_perf_selftest(void);
int test_unclean_shutdown_advance(void);
int test_cookie_rotation(void);
int test_reorg_safety(void);
int test_invalidateblock(void);
int test_most_work_selector(void);
int test_reorg_parity(void);
int test_stage_reorg_unwind_parity(void);
int test_coins_wipe_rebuild_reorg(void);
int test_coins_applied_frontier(void);
int test_utxo_apply_value_balance(void);
int test_utxo_apply_unspendable(void);
int test_reducer_ingest_e2e(void);
int test_reducer_step_drain_harness(void);
int test_reducer_ondemand_genesis_seed(void);
int test_mint_fold_livelock(void);
int test_mint_anchor_fresh_datadir(void);
int test_boot_matrix(void);
int test_reducer_drain_spin_contract(void);
int test_stage_reducer_unwedge(void);
int test_stage_repair_coin_backfill(void);
int test_reducer_frontier_reconcile_light(void);
int test_connect_block_self_write(void);
int test_simnet(void);
int test_simnet_cluster(void);
int test_simnet_cluster_reorg(void);
int test_simnet_wire(void);
int test_simnet_wire_ibd(void);
int test_simnet_wire_peer_malformed_frame(void);
int test_simnet_wire_peer_bad_handshake(void);
int test_simnet_wire_garbage_after_verack(void);
int test_simnet_wire_peer_flood(void);
int test_simnet_wire_peer_slowloris(void);
int test_simnet_wire_mixed_scenario(void);
int test_simnet_wire_bandwidth_cap(void);
int test_simnet_wire_peer_replay(void);
int test_simnet_wire_peer_reorder(void);
int test_simnet_wire_peer_invalid_block(void);
int test_simnet_wire_peer_invalid_header(void);
int test_simnet_wire_eclipse(void);
int test_simnet_txkit(void);
int test_simnet_contract(void);
int test_simnet_doublespend(void);
int test_simnet_chained_tx(void);
int test_simnet_mempool_adv(void);
int test_simnet_block_sigops(void);
int test_simnet_duplicate_input(void);
int test_simnet_value_inflation(void);
int test_simnet_fee_range(void);
int test_simnet_empty_vin_vout(void);
int test_simnet_input_value_range(void);
int test_simnet_sapling_activation(void);
int test_simnet_sapling_shielded_send(void);
int test_simnet_wallet_import_backup(void);
int test_simnet_zmsg_onchain(void);
int test_coinbase_subsidy_adversarial(void);
int test_connect_block_sapling_root(void);
int test_connect_block_checkdatasig_sigops(void);
int test_utxo_apply_coinbase_maturity(void);
int test_pow_diffadj_precedence(void);
int test_difficulty_adjustment_adversarial(void);
int test_bip34_coinbase_height_parity(void);
int test_key_scrub(void);
int test_block_index_loader(void);
int test_chain_state_validator(void);
int test_utxo_recovery_service(void);
int test_utxo_reimport_flag(void);
int test_connect_tip_hot_loop_exit(void);
int test_self_heal_scan_fallback(void);
int test_utxo_audit(void);
int test_utxo_parity_service(void);
int test_rpc_error_envelope(void);
int test_tx_property(void);
int test_znam(void);
int test_zid(void);
int test_zid_identity(void);
int test_zid_seniority(void);
int test_zid_seniority_binding(void);
int test_zdir(void);
int test_zdir_write_path(void);
int test_zendp_records(void);
int test_identity_command(void);
int test_proof_chain(void);
int test_htlc(void);
int test_swap_settlement(void);
int test_file_market(void);
int test_file_market_moderation(void);
int file_market_payment_tests(void);
int file_market_delivery_tests(void);
int file_market_content_tests(void);
int file_market_purchase_tests(void);
int file_market_offer_tests(void);
int test_strong_params(void);
int test_workpool(void);
int test_app_context(void);
int test_service_kernel(void);
int test_service_manifest(void);
int test_app_checkpoint_manifest(void);
int test_bip113_bip65(void);
int test_block_timestamp_adversarial(void);
int test_mempool_orphan(void);
int test_fee_estimation(void);
int test_header_sync(void);
int test_header_sync_stall(void);
int test_header_range_sched(void);
int test_hd_keychain(void);
int test_mnemonic(void);
int test_bip44(void);
int test_block_pruning(void);
int test_schema_migration(void);
int test_db_migration_idempotent(void);
int test_coins_view_atomicity(void);
int test_coins_anchor_reconcile_all(void);
int test_coins_best_derivation(void);
int test_chain_stall_repro(void);
/* The make_lint_gates family — see lib/test/src/test_make_lint_gates.c for the
 * lane split. test_make_lint_gates() is the exclusive lane; the shards and the
 * realroot lane are pool-eligible; the partition group proves every check is
 * owned by exactly one of them. */
int test_make_lint_gates(void);
int test_make_lint_gates_shard_01(void);
int test_make_lint_gates_shard_02(void);
int test_make_lint_gates_shard_03(void);
int test_make_lint_gates_shard_04(void);
int test_make_lint_gates_shard_05(void);
int test_make_lint_gates_shard_06(void);
int test_make_lint_gates_shard_07(void);
int test_make_lint_gates_shard_08(void);
int test_make_lint_gates_realroot(void);
int test_make_lint_gates_heavy_01(void);
int test_make_lint_gates_heavy_02(void);
int test_make_lint_gates_partition(void);

/* Scheduler policy owned by test_make_lint_gates.c: true only for the group
 * name whose checks plant into the live worktree and therefore must run
 * alone. test_parallel.c's group_requires_exclusive_repo() delegates here. */
bool lint_gates_group_is_exclusive(const char *group_name);
/* True for the eight private-sandbox scan shards that share one bounded
 * parallel quiet phase before unrelated suite workers. */
bool lint_gates_group_requires_quiet_pool(const char *group_name);

int test_multisig(void);
int test_rpc_auth_hardening(void);
int test_disk_block_io(void);
int test_msg_handlers(void);
int test_process_headers_adversarial(void);
int test_getheaders_serve_fallback(void);
int test_getheaders_serve_pow_dedup(void);
int test_net_msg_dos(void);
int test_net_handshake_adversarial(void);
int test_net_ban_persistence(void);
int test_net_census(void);
int test_zclassicd_oracle(void);
int test_header_probe(void);
int test_header_probe_p2p_fallback(void);
int test_syncdiag_rpc(void);
int test_rpc_safety(void);
int test_rpc_service_restart(void);
int test_failed_child_cap(void);
int test_power_node_contract_spec(void);
int test_boot_phase(void);
int test_boot_status(void);
int test_boot_odelta_scan(void);
int test_boot_datadir_lock(void);
int test_boot_shutdown_marker(void);
int test_boot_stale_locks(void);
int test_boot_blocktree_cleanup(void);
int test_boot_legacy_blocks(void);
int test_boot_flyclient(void);
int test_boot_memory_guard(void);
int test_path_check(void);
int test_parse_num(void);
int test_boot_progress(void);
int test_supervisor(void);
int test_supervisor_domains(void);
int test_supervisor_backstop(void);
int test_sd_notify(void);
int test_self_heal_supervisor(void);
int test_condition_engine(void);
int test_utxo_activation_paused(void);
int test_sync_watchdog_conditions(void);
int test_peer_snapshot_conditions(void);
int test_snapshot_receive_stalled_condition(void);
int test_snapshot_negotiation_stalled_condition(void);
int test_snapshot_failed_reset_condition(void);
int test_snapshot_complete_resume_condition(void);
int test_chain_integrity_failed_condition(void);
int test_body_fetch_missing_have_data_condition(void);
int test_stale_validate_headers_repair_condition(void);
int test_reducer_drive_watchdog(void);
int test_orphan_utxo_above_tip(void);
int test_tip_fork_stale(void);
int test_tip_stall_oracle_rebuild_condition(void);
int test_active_chain_extend(void);
int test_rebuild_recent(void);
int test_torn_index_blocks_tip(void);
int test_have_data_unreadable(void);
int test_chain_tip_watchdog_bounded_restart(void);
int test_blocker(void);
int test_blocker_handoff(void);
int test_cpu_topology(void);
int test_hw_profile(void);
int test_hw_bench(void);
int test_log_level(void);
int test_operator_ux(void);
int test_cli_render(void);
int test_service_state(void);
int test_service_state_driver(void);
int test_clock(void);
int test_time_authority(void);
int test_rng(void);
int test_seed_tape(void);
int test_postmortem(void);
int test_postmortem_to_scenario(void);
int test_simnet_byzantine(void);
int test_simnet_fuzz(void);
int test_util_signal_handler(void);
int test_chaos_harness(void);
int test_simnet_trace(void);
int test_stage(void);
int test_stage_anchor(void);
int test_mailbox(void);
int test_mailbox_adoption(void);
int test_projection(void);
int test_projection_adoption(void);
int test_projection_consumer(void);
int test_progress_store(void);
int test_event_log(void);
int test_event_log_kill9(void);
int test_event_log_benchmark(void);
int test_mempool_projection(void);
int test_peers_projection(void);
int test_znam_projection(void);
int test_wallet_projection(void);
int test_small_projections(void);
int test_block_index_projection(void);
int test_block_index_rebuild(void);
int test_block_index_topup(void);
int test_block_index_node_db_topup(void);
int test_projection_replay_invariant(void);
int test_block_status_event_restart_proof(void);
int test_header_admit_stage(void);
int test_header_probe_poll(void);
int test_validate_headers_stage(void);
int test_body_fetch_stage(void);
int test_body_persist_stage(void);
int test_created_outputs_index(void);
int test_coins_kv(void);
int test_coins_ram(void);
int test_seal_kv(void);
int test_sha3_sidecar_io(void);
int test_seal_ratify(void);
int test_seal_rewind(void);
int test_nullifier_kv(void);
int test_nullifier_backfill_service(void);
int test_body_crosscheck(void);
int test_shielded_history_promote(void);
int test_shielded_import_cured_tip_anchor(void);
int test_utxo_recovery_shielded_backfill(void);
int test_reducer_drive_guard(void);
int test_sapling_nullifier_adversarial(void);
int test_stage_repair(void);
int test_script_validate_stage(void);
int test_script_validate_contextual_gate(void);
int test_proof_validate_stage(void);
int test_validate_parallel_determinism(void);
int test_mint_skip_crypto(void);
int test_mint_anchor_preflight(void);
int test_utxo_apply_stage(void);
int test_utxo_apply_crash_replay(void);
int test_tip_finalize_stage(void);
int test_tip_finalize_post_step(void);
int test_reducer_frontier(void);
int test_always_sync_chaos(void);
int test_waitforheight_provable(void);
int test_refold_progress_floor(void);
int test_refold_cadence(void);
int test_validate_headers_tuning(void);
int test_catchup_cadence(void);
int test_refold_premature_clear(void);
int test_chain_linkage_check(void);
int test_invariant_sentinel(void);
int test_seed_integrity_gate(void);
int test_seed_torn_import_gate(void);
int test_mirror_divergence_locator(void);
int test_log_throttle(void);
int test_reducer_stage_fuzz(void);
int test_process_block_revalidate(void);
int test_domain_consensus_verify(void);
int test_domain_consensus_subsidy(void);
int test_domain_consensus_pow(void);
int test_domain_consensus_sigops(void);
int test_domain_consensus_script_standard(void);
int test_domain_consensus_tx_structural(void);
int test_domain_consensus_sapling_structural(void);
int test_domain_consensus_sighash(void);
int test_sighash_malleability(void);
int test_domain_consensus_check_block(void);
int test_domain_consensus_equihash(void);
int test_regtest_generate(void);
int test_domain_consensus_script_interp(void);
int test_domain_consensus_coins_math(void);
int test_domain_consensus_checkpoints(void);
int test_domain_consensus_locktime(void);
int test_tx_expiry_locktime_adversarial(void);
int test_domain_consensus_upgrades(void);
int test_domain_consensus_coinbase(void);
int test_domain_consensus_header_accept(void);
int test_domain_wallet_key_derivation(void);
int test_domain_wallet_mnemonic(void);
int test_domain_encoding_base58(void);
int test_domain_encoding_bech32(void);
int test_block_log_file(void);
int test_block_log_legacy(void);
int test_replay_verify(void);
int test_utxo_snapshot_inmem(void);
int test_snapshot_apply_coins_kv(void);
int test_consensus_state_snapshot_install(void);
int test_checkpoint_rom_authority(void);
int test_consensus_state_install_runtime(void);
int test_boot_bundle_fetch(void);
int test_boot_header_seed_import(void);
int test_bundle_publish_serve(void);
int test_consensus_state_snapshot_export(void);
int test_consensus_state_producer_receipt(void);
int test_consensus_state_chain_binding(void);
int test_consensus_state_publication_cas(void);
int test_file_tree_ops(void);
int test_spawn(void);
int test_hodl_history_port(void);
int test_node_health_store_port(void);
int test_db_maintenance_port(void);
int test_wallet_backup_port(void);
int test_snapshot_store_port(void);
int test_block_index_sidecar_port(void);
int test_wallet_view_port(void);
int test_bg_hash_verify_store_port(void);
int test_bg_validation_store_port(void);
int test_bg_validation_reverify(void);
int test_zslp_store_port(void);
int test_atomic_commit_ordering(void);
int test_shielded_spend_slice(void);
int test_coldimport_restart_fragility(void);

/* Spec-based user story tests (one per feature area) */
int spec_wallet_dashboard(void);
int spec_wallet_send(void);
int spec_wallet_receive(void);
int spec_wallet_shield(void);
int spec_wallet_node(void);
int spec_wallet_history(void);
int spec_wallet_coins(void);
int spec_wallet_pulse(void);
int spec_wallet_tx_detail(void);
int spec_wallet_navigation(void);
int spec_wallet_errors(void);
int spec_wallet_privacy(void);
int spec_wallet_sovereignty(void);
int spec_wallet_celebration(void);
int spec_wallet_empowerment(void);
int spec_wallet_flow(void);
int spec_wallet_accessibility(void);
int spec_data_hooks(void);
int spec_event_observers(void);
int spec_state_machine(void);
int spec_ux_sierra(void);
int spec_html_quality(void);
int spec_user_journeys(void);
int spec_e2e_wallet(void);
int spec_render_audit(void);
int spec_smoke(void);
int spec_100_stories(void);
int spec_consensus_compat(void);

/* ── DRY test macros ─────────────────────────────────────── */

/* Run a named test. Usage:
 *   TEST("my test name") {
 *       bool ok = (1 + 1 == 2);
 *       ASSERT(ok);
 *   }
 * Automatically prints name, OK/FAIL, tracks failure count.
 * Requires `int failures = 0;` in scope. */

#define TEST(name) \
    for (int _t_once = (printf("%s... ", name), 1); _t_once; _t_once = 0)

#define ASSERT(cond) do { \
    if (!(cond)) { printf("FAIL (%s)\n", #cond); failures++; goto _test_next; } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { printf("FAIL (%s != %s)\n", #a, #b); failures++; goto _test_next; } \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { printf("FAIL (\"%s\" != \"%s\")\n", (a), (b)); failures++; goto _test_next; } \
} while(0)

#define PASS() do { printf("OK\n"); } while(0)

/* Block-scoped test with automatic PASS at end and goto label.
 * Usage:
 *   TEST_CASE("name") {
 *       ASSERT(condition);
 *       // if we reach here, test passed
 *   } TEST_END */
#define TEST_CASE(name) \
    printf("%s... ", name); \
    {

#define TEST_END \
        printf("OK\n"); \
    } \
    if (0) { _test_next: ; }

/* SQLite fixture helpers for tests.
 * Keep setup code focused on the data being created rather than
 * repeating prepare/step/finalize boilerplate. */
#define TEST_DB_EXEC(db, sql) \
    sqlite3_exec((db), (sql), NULL, NULL, NULL)

#define TEST_DB_BEGIN(db) \
    TEST_DB_EXEC((db), "BEGIN")

#define TEST_DB_BEGIN_TXN(db) \
    TEST_DB_EXEC((db), "BEGIN TRANSACTION")

#define TEST_DB_COMMIT(db) \
    TEST_DB_EXEC((db), "COMMIT")

#define TEST_DB_RUN(db, stmt, sql, bind_code) do { \
    (stmt) = NULL; \
    if (sqlite3_prepare_v2((db), (sql), -1, &(stmt), NULL) == SQLITE_OK && \
        (stmt) != NULL) { \
        do { bind_code; } while (0); \
        sqlite3_step(stmt); \
    } \
    sqlite3_finalize(stmt); \
    (stmt) = NULL; \
} while (0)

#endif /* TEST_CORE_H */
