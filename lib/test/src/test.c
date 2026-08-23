/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Main test runner for ZClassic C23 test suite. */

#include "test/test_core.h"
#include "keys/key.h"
#include "chain/chainparams.h"
#include <signal.h>

/* Required by process_block.c (normally in main.c) */
volatile sig_atomic_t g_shutdown_requested = 0;

/* The lint-gate self-tests are split across several parallel groups (see
 * lib/test/src/test_make_lint_gates.c). test_make_lint_gates() alone is now
 * just the exclusive lane — two checks — so this serial runner would silently
 * cover 2 of ~116 if it kept calling it directly. Run the whole family. */
static int test_make_lint_gates_family(void)
{
    int failures = 0;
    failures += test_make_lint_gates();
    failures += test_make_lint_gates_realroot();
    failures += test_make_lint_gates_heavy_01();
    failures += test_make_lint_gates_heavy_02();
    failures += test_make_lint_gates_shard_01();
    failures += test_make_lint_gates_shard_02();
    failures += test_make_lint_gates_shard_03();
    failures += test_make_lint_gates_shard_04();
    failures += test_make_lint_gates_shard_05();
    failures += test_make_lint_gates_shard_06();
    failures += test_make_lint_gates_shard_07();
    failures += test_make_lint_gates_shard_08();
    failures += test_make_lint_gates_partition();
    return failures;
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL); /* Unbuffered for test progress visibility */
    int failures = 0;

    /* Global init required by many test groups */
    chain_params_select(CHAIN_MAIN);
    ecc_start();
    ecc_verify_init();

    if (argc > 1) {
        bool simnet_wire_args = true;
        bool saw_simnet_wire_group = false;
        for (int i = 1; i < argc; i++) {
            const char *name = argv[i];
            if (strncmp(name, "test_", 5) == 0)
                name += 5;
            if (strcmp(name, "simnet_wire") == 0) {
                saw_simnet_wire_group = true;
                continue;
            }
            if (strcmp(name, "simnet_wire_peer_malformed_frame") == 0 ||
                strcmp(name, "simnet_wire_peer_bad_handshake") == 0 ||
                strcmp(name, "simnet_wire_garbage_after_verack") == 0 ||
                strcmp(name, "simnet_wire_peer_flood") == 0 ||
                strcmp(name, "simnet_wire_peer_slowloris") == 0 ||
                strcmp(name, "simnet_wire_mixed_scenario") == 0 ||
                strcmp(name, "simnet_wire_bandwidth_cap") == 0 ||
                strcmp(name, "simnet_wire_peer_replay") == 0 ||
                strcmp(name, "simnet_wire_peer_reorder") == 0 ||
                strcmp(name, "simnet_wire_peer_invalid_block") == 0 ||
                strcmp(name, "simnet_wire_peer_invalid_header") == 0 ||
                strcmp(name, "simnet_wire_partition_recovery") == 0 ||
                strcmp(name, "simnet_wire_partition_survivor") == 0 ||
                strcmp(name, "simnet_wire_eclipse") == 0) {
                continue;
            }
            simnet_wire_args = false;
            break;
        }
        if (simnet_wire_args) {
            if (saw_simnet_wire_group) {
                printf("[test] argv simnet_wire suite — running simnet wire only\n");
                failures += test_simnet_wire();
            } else {
                for (int i = 1; i < argc; i++) {
                    const char *name = argv[i];
                    if (strncmp(name, "test_", 5) == 0)
                        name += 5;
                    if (strcmp(name, "simnet_wire_peer_malformed_frame") == 0) {
                        extern int test_simnet_wire_peer_malformed_frame(void);
                        failures += test_simnet_wire_peer_malformed_frame();
                    } else if (strcmp(name, "simnet_wire_peer_bad_handshake") == 0) {
                        extern int test_simnet_wire_peer_bad_handshake(void);
                        failures += test_simnet_wire_peer_bad_handshake();
                    } else if (strcmp(name, "simnet_wire_garbage_after_verack") == 0) {
                        extern int test_simnet_wire_garbage_after_verack(void);
                        failures += test_simnet_wire_garbage_after_verack();
                    } else if (strcmp(name, "simnet_wire_peer_flood") == 0) {
                        extern int test_simnet_wire_peer_flood(void);
                        failures += test_simnet_wire_peer_flood();
                    } else if (strcmp(name, "simnet_wire_peer_slowloris") == 0) {
                        extern int test_simnet_wire_peer_slowloris(void);
                        failures += test_simnet_wire_peer_slowloris();
                    } else if (strcmp(name, "simnet_wire_mixed_scenario") == 0) {
                        extern int test_simnet_wire_mixed_scenario(void);
                        failures += test_simnet_wire_mixed_scenario();
                    } else if (strcmp(name, "simnet_wire_bandwidth_cap") == 0) {
                        extern int test_simnet_wire_bandwidth_cap(void);
                        failures += test_simnet_wire_bandwidth_cap();
                    } else if (strcmp(name, "simnet_wire_peer_replay") == 0) {
                        extern int test_simnet_wire_peer_replay(void);
                        failures += test_simnet_wire_peer_replay();
                    } else if (strcmp(name, "simnet_wire_peer_reorder") == 0) {
                        extern int test_simnet_wire_peer_reorder(void);
                        failures += test_simnet_wire_peer_reorder();
                    } else if (strcmp(name, "simnet_wire_peer_invalid_block") == 0) {
                        extern int test_simnet_wire_peer_invalid_block(void);
                        failures += test_simnet_wire_peer_invalid_block();
                    } else if (strcmp(name, "simnet_wire_peer_invalid_header") == 0) {
                        extern int test_simnet_wire_peer_invalid_header(void);
                        failures += test_simnet_wire_peer_invalid_header();
                    } else if (strcmp(name, "simnet_wire_partition_recovery") == 0) {
                        extern int test_simnet_wire_partition_recovery(void);
                        failures += test_simnet_wire_partition_recovery();
                    } else if (strcmp(name, "simnet_wire_partition_survivor") == 0) {
                        extern int test_simnet_wire_partition_survivor(void);
                        failures += test_simnet_wire_partition_survivor();
                    } else if (strcmp(name, "simnet_wire_eclipse") == 0) {
                        extern int test_simnet_wire_eclipse(void);
                        failures += test_simnet_wire_eclipse();
                    }
                }
            }
            printf("\n=== simnet_wire argv subset complete: %d failure(s) ===\n",
                   failures);
            return failures ? 1 : 0;
        }
    }

    /* Developer-only fast loop: ZCL_TEST_ONLY=persistence runs only the
     * persistence-layer regression tests (agent-2 scope) so an iteration
     * doesn't have to wait for the entire 1500-test suite.  Unset or
     * unknown value runs the full suite unchanged. */
    const char *only = getenv("ZCL_TEST_ONLY");
    if ((!only || !*only) && argc > 1) {
        only = argv[1];
        if (strncmp(only, "test_", 5) == 0)
            only += 5;
    }
    if (only && strcmp(only, "lcc") == 0) {
        printf("[test] ZCL_TEST_ONLY=lcc — running Log-Cursor Contiguity write rules only\n");
        { extern int test_lcc_write_rules(void);
          failures += test_lcc_write_rules(); }
        printf("\n=== LCC write-rules subset complete: %d failure(s) ===\n", failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "onion") == 0) {
        printf("[test] ZCL_TEST_ONLY=onion — running onion bootstrap only\n");
        { extern int test_onion_bootstrap(void);
          failures += test_onion_bootstrap(); }
        printf("\n=== Onion subset complete: %d failure(s) ===\n", failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "cold_start") == 0) {
        printf("[test] ZCL_TEST_ONLY=cold_start — running cold-start sync only\n");
        { extern int test_cold_start_sync(void);
          failures += test_cold_start_sync(); }
        printf("\n=== Cold-start subset complete: %d failure(s) ===\n", failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "kill9") == 0) {
        printf("[test] ZCL_TEST_ONLY=kill9 — running kill -9 recovery only\n");
        { extern int test_kill9_recovery(void);
          failures += test_kill9_recovery(); }
        printf("\n=== kill9 subset complete: %d failure(s) ===\n", failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "destruction_drill") == 0) {
        printf("[test] ZCL_TEST_ONLY=destruction_drill — running the wallet "
               "destruction-and-restore drill only\n");
        { extern int test_wallet_destruction_drill(void);
          failures += test_wallet_destruction_drill(); }
        printf("\n=== destruction_drill subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_advance_atomicity") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_advance_atomicity — running Move 2 / A5 only\n");
        { extern int test_chain_advance_atomicity(void);
          failures += test_chain_advance_atomicity(); }
        printf("\n=== chain_advance_atomicity subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_stall_repro") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_stall_repro — running chain-stall regressions only\n");
        { extern int test_chain_stall_repro(void);
          failures += test_chain_stall_repro(); }
        printf("\n=== chain_stall_repro subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "snark_kat") == 0) {
        printf("[test] ZCL_TEST_ONLY=snark_kat — running SNARK KAT only\n");
        failures += test_snark_kat();
        printf("\n=== snark_kat subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "groth16_selfverify") == 0) {
        extern int test_groth16_selfverify(void);
        printf("[test] ZCL_TEST_ONLY=groth16_selfverify — running self-verify only\n");
        failures += test_groth16_selfverify();
        printf("\n=== groth16_selfverify subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "groth16_r1cs_oracle") == 0) {
        printf("[test] ZCL_TEST_ONLY=groth16_r1cs_oracle — running the "
               "canonical R1CS transcript oracle only\n");
        failures += test_groth16_r1cs_oracle();
        printf("\n=== groth16_r1cs_oracle subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "block_source_policy") == 0) {
        printf("[test] ZCL_TEST_ONLY=block_source_policy — running source policy only\n");
        failures += test_block_source_policy();
        printf("\n=== block_source_policy subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "block_index_node_db_topup") == 0) {
        printf("[test] ZCL_TEST_ONLY=block_index_node_db_topup — running node.db top-up only\n");
        failures += test_block_index_node_db_topup();
        printf("\n=== block_index_node_db_topup subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "connman_addnode") == 0) {
        printf("[test] ZCL_TEST_ONLY=connman_addnode — running addnode fallback only\n");
        failures += test_connman_addnode_fallback();
        printf("\n=== connman_addnode subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "node_health") == 0) {
        printf("[test] ZCL_TEST_ONLY=node_health — running node health only\n");
        failures += test_node_health_service();
        printf("\n=== node_health subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "node_health_syncdiag") == 0) {
        printf("[test] ZCL_TEST_ONLY=node_health_syncdiag — running node health then sync RPC diagnostics\n");
        failures += test_node_health_service();
        failures += test_syncdiag_rpc();
        printf("\n=== node_health_syncdiag subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "shielded_payment") == 0) {
        printf("[test] ZCL_TEST_ONLY=shielded_payment — running shielded-payment gate only\n");
        { extern int test_shielded_payment_gate(void);
          failures += test_shielded_payment_gate(); }
        printf("\n=== shielded-payment subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "reducer_ingest") == 0) {
        printf("[test] ZCL_TEST_ONLY=reducer_ingest — running the MVP it-works gate only\n");
        { extern int test_reducer_block_ingest_gate(void);
          failures += test_reducer_block_ingest_gate(); }
        printf("\n=== reducer-ingest subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "seal_rewind") == 0) {
        printf("[test] ZCL_TEST_ONLY=seal_rewind — running the seal-ring rewind consumer only\n");
        { extern int test_seal_rewind(void); failures += test_seal_rewind(); }
        printf("\n=== seal_rewind subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "onion_slice") == 0) {
        printf("[test] ZCL_TEST_ONLY=onion_slice — running the MVP #2 hermetic onion slice only\n");
        { extern int test_onion_bootstrap_slice(void);
          failures += test_onion_bootstrap_slice(); }
        printf("\n=== onion_bootstrap_slice subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "shielded_receive") == 0) {
        printf("[test] ZCL_TEST_ONLY=shielded_receive — running the shielded-receive slice gate only\n");
        { extern int test_shielded_receive_slice(void);
          failures += test_shielded_receive_slice(); }
        printf("\n=== shielded_receive subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "shielded_receive_persist") == 0) {
        printf("[test] ZCL_TEST_ONLY=shielded_receive_persist — "
               "running the durable-receive gate only\n");
        { extern int test_shielded_receive_persist(void);
          failures += test_shielded_receive_persist(); }
        printf("\n=== shielded_receive_persist subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "reducer_forward") == 0) {
        printf("[test] ZCL_TEST_ONLY=reducer_forward — running the forward-progress gate only\n");
        { extern int test_reducer_forward_progress_gate(void);
          failures += test_reducer_forward_progress_gate(); }
        printf("\n=== reducer-forward subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "parity_slice") == 0) {
        printf("[test] ZCL_TEST_ONLY=parity_slice — running the MVP C8 hermetic parity slice only\n");
        { extern int test_parity_slice(void);
          failures += test_parity_slice(); }
        printf("\n=== parity_slice subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "store_e2e") == 0) {
        printf("[test] ZCL_TEST_ONLY=store_e2e — running store e2e gate only\n");
        { extern int test_store_e2e_gate(void);
          failures += test_store_e2e_gate(); }
        printf("\n=== store e2e subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "store_e2e_shielded") == 0) {
        printf("[test] ZCL_TEST_ONLY=store_e2e_shielded — "
               "running store e2e SHIELDED gate only\n");
        { extern int test_store_e2e_shielded(void);
          failures += test_store_e2e_shielded(); }
        printf("\n=== store e2e shielded subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "parity_diff") == 0) {
        printf("[test] ZCL_TEST_ONLY=parity_diff — running parity-diff gate only\n");
        failures += test_reorg_parity();
        failures += test_projection_replay_invariant();
        printf("\n=== parity_diff subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "event") == 0) {
        printf("[test] ZCL_TEST_ONLY=event — running event subset\n");
        failures += test_event();
        printf("\n=== event subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "event_log") == 0) {
        printf("[test] ZCL_TEST_ONLY=event_log — running event-log subset\n");
        failures += test_event_log();
        printf("\n=== event_log subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "persistence") == 0) {
        printf("[test] ZCL_TEST_ONLY=persistence — running persistence subset\n");
        failures += test_schema_migration();
        failures += test_db_migration_idempotent();
        failures += test_coins_view_atomicity();
        failures += test_coins_anchor_reconcile_all();
        failures += test_coins_best_derivation();
        { extern int test_boot_coins_anchor_dual_store_recovery(void);
          failures += test_boot_coins_anchor_dual_store_recovery(); }
        failures += test_make_lint_gates_family();
        failures += test_wallet_sqlite_enc();
        failures += test_wallet_keystore();
        { extern int test_wallet_persistence_cycle(void);
          failures += test_wallet_persistence_cycle(); }
        { extern int test_wallet_flush_rollback(void);
          failures += test_wallet_flush_rollback(); }
        { extern int test_wallet_sqlite_open_errors(void);
          failures += test_wallet_sqlite_open_errors(); }
        { extern int test_watch_only(void); failures += test_watch_only(); }
        { extern int test_wallet_canary(void); failures += test_wallet_canary(); }
        failures += test_unclean_shutdown_advance();
        printf("\n=== Persistence subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "sqlite") == 0) {
        printf("[test] ZCL_TEST_ONLY=sqlite — running SQLite model subset\n");
        failures += test_sqlite();
        printf("\n=== sqlite subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "wallet_funds_safety") == 0) {
        printf("[test] ZCL_TEST_ONLY=wallet_funds_safety — running wallet funds-safety only\n");
        { extern int test_wallet_funds_safety(void);
          failures += test_wallet_funds_safety(); }
        printf("\n=== wallet_funds_safety subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "waitforheight_provable") == 0) {
        printf("[test] ZCL_TEST_ONLY=waitforheight_provable — running waitforheight provable only\n");
        failures += test_waitforheight_provable();
        printf("\n=== waitforheight_provable subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "peers_projection") == 0) {
        printf("[test] ZCL_TEST_ONLY=peers_projection — running peers projection only\n");
        failures += test_peers_projection();
        printf("\n=== peers_projection subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "mempool_projection") == 0) {
        printf("[test] ZCL_TEST_ONLY=mempool_projection — running mempool projection only\n");
        failures += test_mempool_projection();
        printf("\n=== mempool_projection subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "znam_projection") == 0) {
        printf("[test] ZCL_TEST_ONLY=znam_projection — running znam projection only\n");
        failures += test_znam_projection();
        printf("\n=== znam_projection subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "wallet_projection") == 0) {
        printf("[test] ZCL_TEST_ONLY=wallet_projection — running wallet projection only\n");
        failures += test_wallet_projection();
        printf("\n=== wallet_projection subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "small_projections") == 0) {
        printf("[test] ZCL_TEST_ONLY=small_projections — running small projections only\n");
        failures += test_small_projections();
        printf("\n=== small_projections subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "script_validate") == 0) {
        printf("[test] ZCL_TEST_ONLY=script_validate — running script_validate stage only\n");
        failures += test_script_validate_stage();
        printf("\n=== script_validate subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only &&
        (strcmp(only, "header_admit") == 0 ||
         strcmp(only, "header_admit_stage") == 0)) {
        printf("[test] ZCL_TEST_ONLY=header_admit — running header_admit stage only\n");
        failures += test_header_admit_stage();
        printf("\n=== header_admit subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only &&
        (strcmp(only, "validate_headers") == 0 ||
         strcmp(only, "validate_headers_stage") == 0)) {
        printf("[test] ZCL_TEST_ONLY=validate_headers — running validate_headers stage only\n");
        failures += test_validate_headers_stage();
        printf("\n=== validate_headers subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only &&
        (strcmp(only, "header_validate_sequence") == 0 ||
         strcmp(only, "header_admit_validate_headers") == 0)) {
        printf("[test] ZCL_TEST_ONLY=header_validate_sequence — running header_admit then validate_headers\n");
        failures += test_header_admit_stage();
        failures += test_validate_headers_stage();
        printf("\n=== header_validate_sequence subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "proof_validate") == 0) {
        printf("[test] ZCL_TEST_ONLY=proof_validate — running proof_validate stage only\n");
        failures += test_proof_validate_stage();
        printf("\n=== proof_validate subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "utxo_apply") == 0) {
        printf("[test] ZCL_TEST_ONLY=utxo_apply — running utxo_apply stage only\n");
        failures += test_utxo_apply_stage();
        printf("\n=== utxo_apply subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "tip_finalize") == 0) {
        printf("[test] ZCL_TEST_ONLY=tip_finalize — running tip_finalize stage only\n");
        failures += test_tip_finalize_stage();
        printf("\n=== tip_finalize subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "crypto_registry") == 0) {
        printf("[test] ZCL_TEST_ONLY=crypto_registry — running crypto registry only\n");
        failures += test_crypto_registry();
        printf("\n=== crypto_registry subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "postmortem") == 0) {
        printf("[test] ZCL_TEST_ONLY=postmortem — running postmortem only\n");
        failures += test_postmortem();
        printf("\n=== postmortem subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "seed_tape") == 0) {
        printf("[test] ZCL_TEST_ONLY=seed_tape — running seed tape only\n");
        failures += test_seed_tape();
        printf("\n=== seed_tape subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "simnet_wire") == 0) {
        printf("[test] ZCL_TEST_ONLY=simnet_wire — running simnet wire only\n");
        failures += test_simnet_wire();
        printf("\n=== simnet_wire subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "seed_torn_import") == 0) {
        printf("[test] ZCL_TEST_ONLY=seed_torn_import — running torn-import gate only\n");
        failures += test_seed_torn_import_gate();
        printf("\n=== seed_torn_import subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "coin_backfill") == 0) {
        printf("[test] ZCL_TEST_ONLY=coin_backfill — running coin_backfill + torn-import gate only\n");
        failures += test_stage_repair_coin_backfill();
        failures += test_seed_torn_import_gate();
        printf("\n=== coin_backfill subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chaos_harness") == 0) {
        printf("[test] ZCL_TEST_ONLY=chaos_harness — running chaos harness only\n");
        failures += test_chaos_harness();
        printf("\n=== chaos_harness subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "rpc_safety") == 0) {
        printf("[test] ZCL_TEST_ONLY=rpc_safety — running RPC safety subset\n");
        failures += test_rpc_safety();
        failures += test_make_lint_gates_family();
        printf("\n=== RPC safety subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "power_node_contract") == 0) {
        printf("[test] ZCL_TEST_ONLY=power_node_contract — running doc contract only\n");
        failures += test_power_node_contract_spec();
        printf("\n=== power_node_contract subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "self_heal_scan") == 0) {
        printf("[test] ZCL_TEST_ONLY=self_heal_scan — running only\n");
        failures += test_self_heal_scan_fallback();
        printf("\n=== self_heal_scan subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "hot_loop_exit") == 0) {
        printf("[test] ZCL_TEST_ONLY=hot_loop_exit — running UTXO hot-loop exit only\n");
        failures += test_connect_tip_hot_loop_exit();
        printf("\n=== hot_loop_exit subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_restore") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_restore — running chain restore only\n");
        failures += test_chain_restore_service();
        printf("\n=== chain_restore subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_restore_planner") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_restore_planner — running chain restore planner only\n");
        failures += test_chain_restore_planner();
        printf("\n=== chain_restore_planner subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "block_index_loader") == 0) {
        printf("[test] ZCL_TEST_ONLY=block_index_loader — running block index loader only\n");
        failures += test_block_index_loader();
        printf("\n=== block_index_loader subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "utxo_recovery") == 0) {
        printf("[test] ZCL_TEST_ONLY=utxo_recovery — running UTXO recovery only\n");
        failures += test_utxo_recovery_service();
        printf("\n=== utxo_recovery subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_evidence_controller") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_evidence_controller — running chain evidence controller only\n");
        failures += test_chain_evidence_controller();
        printf("\n=== chain_evidence_controller subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_evidence_live_advance") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_evidence_live_advance — running chain evidence live advance only\n");
        failures += test_chain_evidence_live_advance();
        printf("\n=== chain_evidence_live_advance subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_evidence_controller_live") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_evidence_controller_live — running chain evidence controller then live advance\n");
        failures += test_chain_evidence_controller();
        failures += test_chain_evidence_live_advance();
        printf("\n=== chain_evidence_controller_live subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_state_repo") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_state_repo — running chain state repository only\n");
        failures += test_chain_state_repo();
        printf("\n=== chain_state_repo subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "sync_service") == 0) {
        printf("[test] ZCL_TEST_ONLY=sync_service — running sync service only\n");
        failures += test_sync_service();
        printf("\n=== sync_service subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "utxo_audit") == 0) {
        printf("[test] ZCL_TEST_ONLY=utxo_audit — running only\n");
        failures += test_utxo_audit();
        printf("\n=== utxo_audit subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "utxo_mirror_sync") == 0) {
        printf("[test] ZCL_TEST_ONLY=utxo_mirror_sync — running only\n");
        { extern int test_utxo_mirror_sync(void);
          failures += test_utxo_mirror_sync(); }
        printf("\n=== utxo_mirror_sync subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "utxo_parity") == 0) {
        printf("[test] ZCL_TEST_ONLY=utxo_parity — running only\n");
        failures += test_utxo_parity_service();
        printf("\n=== utxo_parity subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "make_lint_gates") == 0) {
        printf("[test] ZCL_TEST_ONLY=make_lint_gates — running lint gate subset\n");
        failures += test_make_lint_gates_family();
        printf("\n=== make_lint_gates subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "mailbox_adoption") == 0) {
        printf("[test] ZCL_TEST_ONLY=mailbox_adoption — running only\n");
        failures += test_mailbox_adoption();
        printf("\n=== mailbox_adoption subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "projection_adoption") == 0) {
        printf("[test] ZCL_TEST_ONLY=projection_adoption — running only\n");
        failures += test_projection_adoption();
        printf("\n=== projection_adoption subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "projection_consumer") == 0) {
        printf("[test] ZCL_TEST_ONLY=projection_consumer — running only\n");
        failures += test_projection_consumer();
        printf("\n=== projection_consumer subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "utxo_activation_paused") == 0) {
        printf("[test] ZCL_TEST_ONLY=utxo_activation_paused — running only\n");
        failures += test_utxo_activation_paused();
        printf("\n=== utxo_activation_paused subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "condition_engine") == 0) {
        printf("[test] ZCL_TEST_ONLY=condition_engine - running only\n");
        failures += test_condition_engine();
        printf("\n=== condition_engine subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "sync_watchdog_conditions") == 0) {
        printf("[test] ZCL_TEST_ONLY=sync_watchdog_conditions - running only\n");
        failures += test_sync_watchdog_conditions();
        printf("\n=== sync_watchdog_conditions subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_tip_watchdog_bounded_restart") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_tip_watchdog_bounded_restart — running only\n");
        failures += test_chain_tip_watchdog_bounded_restart();
        printf("\n=== chain_tip_watchdog_bounded_restart subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "peer_snapshot_conditions") == 0) {
        printf("[test] ZCL_TEST_ONLY=peer_snapshot_conditions - running only\n");
        failures += test_peer_snapshot_conditions();
        printf("\n=== peer_snapshot_conditions subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "snapshot_receive_stalled_condition") == 0) {
        printf("[test] ZCL_TEST_ONLY=snapshot_receive_stalled_condition — running only\n");
        failures += test_snapshot_receive_stalled_condition();
        printf("\n=== snapshot_receive_stalled_condition subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "snapshot_negotiation_stalled_condition") == 0) {
        printf("[test] ZCL_TEST_ONLY=snapshot_negotiation_stalled_condition — running only\n");
        failures += test_snapshot_negotiation_stalled_condition();
        printf("\n=== snapshot_negotiation_stalled_condition subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "snapshot_failed_reset_condition") == 0) {
        printf("[test] ZCL_TEST_ONLY=snapshot_failed_reset_condition — running only\n");
        failures += test_snapshot_failed_reset_condition();
        printf("\n=== snapshot_failed_reset_condition subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "snapshot_complete_resume_condition") == 0) {
        printf("[test] ZCL_TEST_ONLY=snapshot_complete_resume_condition — running only\n");
        failures += test_snapshot_complete_resume_condition();
        printf("\n=== snapshot_complete_resume_condition subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "chain_integrity_failed_condition") == 0) {
        printf("[test] ZCL_TEST_ONLY=chain_integrity_failed_condition — running only\n");
        failures += test_chain_integrity_failed_condition();
        printf("\n=== chain_integrity_failed_condition subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "body_fetch_missing_have_data_condition") == 0) {
        printf("[test] ZCL_TEST_ONLY=body_fetch_missing_have_data_condition — running only\n");
        failures += test_body_fetch_missing_have_data_condition();
        printf("\n=== body_fetch_missing_have_data_condition subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "stale_validate_headers_repair_condition") == 0) {
        printf("[test] ZCL_TEST_ONLY=stale_validate_headers_repair_condition — running only\n");
        failures += test_stale_validate_headers_repair_condition();
        printf("\n=== stale_validate_headers_repair_condition subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "zclassicd_oracle") == 0) {
        printf("[test] ZCL_TEST_ONLY=zclassicd_oracle — running oracle subset\n");
        failures += test_zclassicd_oracle();
        printf("\n=== zclassicd_oracle subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "syncdiag_rpc") == 0) {
        printf("[test] ZCL_TEST_ONLY=syncdiag_rpc — running sync RPC diagnostics subset\n");
        failures += test_syncdiag_rpc();
        printf("\n=== syncdiag_rpc subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "api") == 0) {
        printf("[test] ZCL_TEST_ONLY=api — running REST/API contract subset\n");
        failures += test_api();
        printf("\n=== api subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "service_kernel") == 0) {
        printf("[test] ZCL_TEST_ONLY=service_kernel - running service kernel subset\n");
        failures += test_service_kernel();
        printf("\n=== service_kernel subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "app_context") == 0) {
        printf("[test] ZCL_TEST_ONLY=app_context - running only\n");
        failures += test_app_context();
        printf("\n=== app_context subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "tor") == 0) {
        printf("[test] ZCL_TEST_ONLY=tor - running Tor integration subset\n");
        failures += test_tor();
        printf("\n=== tor subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "onion_persistence") == 0) {
        printf("[test] ZCL_TEST_ONLY=onion_persistence - running persistent "
               "onion identity subset\n");
        { extern int test_onion_persistence(void);
          failures += test_onion_persistence(); }
        printf("\n=== onion_persistence subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "shop") == 0) {
        printf("[test] ZCL_TEST_ONLY=shop - running shop command subset\n");
        { extern int test_shop(void);
          failures += test_shop(); }
        printf("\n=== shop subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "shop_reputation") == 0) {
        printf("[test] ZCL_TEST_ONLY=shop_reputation - running shop "
               "reputation readout subset\n");
        { extern int test_shop_reputation(void);
          failures += test_shop_reputation(); }
        printf("\n=== shop_reputation subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "shop_want") == 0) {
        printf("[test] ZCL_TEST_ONLY=shop_want - running shop want board "
               "subset\n");
        { extern int test_shop_want(void);
          failures += test_shop_want(); }
        printf("\n=== shop_want subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "shop_fulfill") == 0) {
        printf("[test] ZCL_TEST_ONLY=shop_fulfill - running shop "
               "fulfillment subset\n");
        { extern int test_shop_fulfill(void);
          failures += test_shop_fulfill(); }
        printf("\n=== shop_fulfill subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "fast_sync") == 0) {
        printf("[test] ZCL_TEST_ONLY=fast_sync — running fast sync subset\n");
        failures += test_fast_sync();
        printf("\n=== fast_sync subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_snapshot_failure_memory") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_snapshot_failure_memory - running only\n");
        { extern int test_boot_snapshot_failure_memory(void);
          failures += test_boot_snapshot_failure_memory(); }
        printf("\n=== boot_snapshot_failure_memory subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_datadir_lock") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_datadir_lock - running only\n");
        failures += test_boot_datadir_lock();
        printf("\n=== boot_datadir_lock subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_shutdown_marker") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_shutdown_marker - running only\n");
        failures += test_boot_shutdown_marker();
        printf("\n=== boot_shutdown_marker subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_stale_locks") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_stale_locks - running only\n");
        failures += test_boot_stale_locks();
        printf("\n=== boot_stale_locks subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_blocktree_cleanup") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_blocktree_cleanup - running only\n");
        failures += test_boot_blocktree_cleanup();
        printf("\n=== boot_blocktree_cleanup subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_legacy_blocks") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_legacy_blocks - running only\n");
        failures += test_boot_legacy_blocks();
        printf("\n=== boot_legacy_blocks subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_flyclient") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_flyclient - running only\n");
        failures += test_boot_flyclient();
        printf("\n=== boot_flyclient subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "boot_memory_guard") == 0) {
        printf("[test] ZCL_TEST_ONLY=boot_memory_guard - running only\n");
        failures += test_boot_memory_guard();
        printf("\n=== boot_memory_guard subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "explorer") == 0) {
        printf("[test] ZCL_TEST_ONLY=explorer — running explorer subset\n");
        failures += test_explorer();
        failures += test_explorer_rpc_call();
        failures += test_explorer_index();
        printf("\n=== explorer subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "mmb") == 0) {
        printf("[test] ZCL_TEST_ONLY=mmb - running MMB subset\n");
        failures += test_mmb();
        { extern int test_keystone_utxo_binding(void);
          failures += test_keystone_utxo_binding(); }
        printf("\n=== mmb subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "addrman") == 0) {
        printf("[test] ZCL_TEST_ONLY=addrman — running addrman subset\n");
        failures += test_addrman_rebalance();
        printf("\n=== addrman subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "integrity") == 0) {
        printf("[test] ZCL_TEST_ONLY=integrity — running integrity subset\n");
        failures += test_integrity();
        printf("\n=== integrity subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "rolling_anchor") == 0) {
        printf("[test] ZCL_TEST_ONLY=rolling_anchor — running rolling anchor subset\n");
        failures += test_rolling_anchor_service();
        printf("\n=== rolling_anchor subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "net") == 0) {
        printf("[test] ZCL_TEST_ONLY=net — running net subset\n");
        failures += test_net();
        failures += test_peer_lifecycle();
        printf("\n=== net subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "peer_lifecycle") == 0) {
        printf("[test] ZCL_TEST_ONLY=peer_lifecycle — running peer lifecycle subset\n");
        failures += test_peer_lifecycle();
        printf("\n=== peer_lifecycle subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "header_sync") == 0) {
        printf("[test] ZCL_TEST_ONLY=header_sync — running header sync subset\n");
        failures += test_header_sync();
        failures += test_header_sync_stall();
        printf("\n=== header_sync subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "header_probe") == 0) {
        printf("[test] ZCL_TEST_ONLY=header_probe — running header probe service only\n");
        failures += test_header_probe();
        printf("\n=== header_probe subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "header_probe_p2p_fallback") == 0) {
        printf("[test] ZCL_TEST_ONLY=header_probe_p2p_fallback — running "
               "Detective A2 P2P header-repair fallback only\n");
        failures += test_header_probe_p2p_fallback();
        printf("\n=== header_probe_p2p_fallback subset complete: %d "
               "failure(s) ===\n", failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "header_probe_poll") == 0) {
        printf("[test] ZCL_TEST_ONLY=header_probe_poll — running header probe poll only\n");
        failures += test_header_probe_poll();
        printf("\n=== header_probe_poll subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "rpc") == 0) {
        printf("[test] ZCL_TEST_ONLY=rpc — running rpc only\n");
        failures += test_rpc();
        printf("\n=== rpc subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "peer_scoring") == 0) {
        printf("[test] ZCL_TEST_ONLY=peer_scoring — running peer scoring only\n");
        failures += test_peer_scoring();
        printf("\n=== peer_scoring subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "snapshot_sync") == 0) {
        printf("[test] ZCL_TEST_ONLY=snapshot_sync - running snapshot sync subset\n");
        failures += test_snapshot_sync_service();
        printf("\n=== snapshot_sync subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    if (only && strcmp(only, "hotswap_service_registry") == 0) {
        printf("[test] ZCL_TEST_ONLY=hotswap_service_registry — running pure service registry only\n");
        failures += test_hotswap_service_registry();
        printf("\n=== hotswap_service_registry subset complete: %d failure(s) ===\n",
               failures);
        return failures ? 1 : 0;
    }
    { extern int test_base_foundation(void);
      failures += test_base_foundation(); }
    { extern int test_codec_cursor(void); failures += test_codec_cursor(); }
    { extern int test_zcode_creation_attribution(void);
      failures += test_zcode_creation_attribution(); }
    { extern int test_zcode_shadow_policy(void);
      failures += test_zcode_shadow_policy(); }
    { extern int test_zcode_score_receipt(void);
      failures += test_zcode_score_receipt(); }
    { extern int test_zcode_score_receipt_packages(void);
      failures += test_zcode_score_receipt_packages(); }
    { extern int test_zcode_score_receipt_rejections(void);
      failures += test_zcode_score_receipt_rejections(); }
    { extern int test_zcode_score_receipt_creation(void);
      failures += test_zcode_score_receipt_creation(); }
    { extern int test_zcode_score_receipt_patronage(void);
      failures += test_zcode_score_receipt_patronage(); }
    { extern int test_zcode_score_receipt_reproduction(void);
      failures += test_zcode_score_receipt_reproduction(); }
    { extern int test_zcode_score_receipt_shadow(void);
      failures += test_zcode_score_receipt_shadow(); }
    { extern int test_zcode_package_registry(void);
      failures += test_zcode_package_registry(); }
    failures += test_game();
    failures += test_crypto();
    failures += test_crypto_registry();
    failures += test_encoding();
    { extern int test_test_str_money_codecs(void);
      failures += test_test_str_money_codecs(); }
    failures += test_chain();
    { extern int test_pprev_walk(void); failures += test_pprev_walk(); }
    { extern int test_chain_tip(void); failures += test_chain_tip(); }
    { extern int test_checkpoint(void); failures += test_checkpoint(); }
    { extern int test_anchor_finality(void);
      failures += test_anchor_finality(); }
    failures += test_keys();
    { extern int test_test_key_io_codec(void);
      failures += test_test_key_io_codec(); }
    { extern int test_test_png_writer(void);
      failures += test_test_png_writer(); }
    { extern int test_qr(void); failures += test_qr(); }
    { extern int test_shared_validators_zcl_address(void);
      failures += test_shared_validators_zcl_address(); }
    failures += test_script();
    failures += test_net();
    failures += test_netbase_split_host_port();
    failures += test_connman_addnode_fallback();
    failures += test_transaction();
    failures += test_mempool();
    failures += test_accept_to_mempool();
    failures += test_rpc();
    failures += test_sqlite();
    failures += test_activerecord();
    failures += test_validation();
    { extern int test_consensus_parity(void); failures += test_consensus_parity(); }
    { extern int test_rom_state_checkpoint(void); failures += test_rom_state_checkpoint(); }
    { extern int test_sapling_lazy_init(void);
      failures += test_sapling_lazy_init(); }
    failures += test_sapling();
    failures += test_sapling_crypto();
    failures += test_groth16_msm_parity();
    failures += test_groth16_r1cs_oracle();
    failures += test_sapling_tree();
    failures += test_bn254();
    failures += test_merkle_tree();
    { extern int test_merkle_malleability(void); failures += test_merkle_malleability(); }
    failures += test_slp();
    failures += test_models();
    failures += test_core();
    failures += test_znam();
    failures += test_zid();
    { extern int test_epoch(void); failures += test_epoch(); }
    { extern int test_zcode_release(void); failures += test_zcode_release(); }
    failures += test_zid_identity();
    failures += test_zid_seniority();
    failures += test_zid_seniority_binding();
    failures += test_zdir();
    failures += test_zdir_write_path();
    failures += test_identity_command();
    { extern int test_zdesc(void); failures += test_zdesc(); }
    { extern int test_zendp(void); failures += test_zendp(); }
    failures += test_zendp_records();
    { extern int test_zendp_revocation(void);
      failures += test_zendp_revocation(); }
    { extern int test_zendp_window(void); failures += test_zendp_window(); }
    failures += test_proof_chain();
    { extern int test_znam_site(void); failures += test_znam_site(); }
    failures += test_htlc();
    failures += test_swap_settlement();
    failures += test_file_market();
    failures += test_file_market_moderation();
    failures += test_strong_params();
    { extern int test_wallet_funds_safety(void);
      failures += test_wallet_funds_safety(); }
    failures += test_json();
    failures += test_robustness();
    failures += test_wallet();
    failures += test_primitives();
    failures += test_bloom();
    failures += test_coins();
    failures += test_chainstate_legacy_reader();
    failures += test_chainstate_sapling_anchor();
    failures += test_utxo_import_pipeline();
    failures += test_ccoins_decoder_kat();
    failures += test_coins_record_codec();
    failures += test_blob_read_bounds();
    { extern int test_ldb_snapshot(void);
      failures += test_ldb_snapshot(); }
    { extern int test_ldb_reader(void);
      failures += test_ldb_reader(); }
    { extern int test_utxo_snapshot_loader(void);
      failures += test_utxo_snapshot_loader(); }
    failures += test_snapshot_apply_coins_kv();
    failures += test_consensus_state_snapshot_install();
    failures += test_checkpoint_rom_authority();
    failures += test_consensus_state_install_runtime();
    failures += test_consensus_state_snapshot_export();
    { extern int test_ratify_mint_anchor(void);
      failures += test_ratify_mint_anchor(); }
    { extern int test_sovereign_promotion(void);
      failures += test_sovereign_promotion(); }
    failures += test_consensus_state_producer_receipt();
    { extern int test_authority_receipt(void);
      failures += test_authority_receipt(); }
    failures += test_consensus_state_chain_binding();
    failures += test_consensus_state_publication_cas();
    { extern int test_snapshot_shielded(void);
      failures += test_snapshot_shielded(); }
    { extern int test_load_verify_boot(void);
      failures += test_load_verify_boot(); }
    { extern int test_boot_snapshot_failure_memory(void);
      failures += test_boot_snapshot_failure_memory(); }
    failures += test_boot_snapshot_drop_bodiless();
    failures += test_boot_datadir_lock();
    failures += test_boot_shutdown_marker();
    failures += test_boot_stale_locks();
    failures += test_boot_blocktree_cleanup();
    failures += test_boot_legacy_blocks();
    failures += test_boot_flyclient();
    failures += test_boot_memory_guard();
    failures += test_store();
    failures += test_store_listing();
    failures += test_store_buyer();
    failures += test_store_transparent_pay();
    { extern int test_shop(void);
      failures += test_shop(); }
    { extern int test_shop_reputation(void);
      failures += test_shop_reputation(); }
    { extern int test_shop_want(void);
      failures += test_shop_want(); }
    { extern int test_shop_fulfill(void);
      failures += test_shop_fulfill(); }
    failures += test_blog();
    failures += test_api();
    failures += test_explorer();
    failures += test_explorer_rpc_call();
    failures += test_explorer_index();
    { extern int test_format_helpers_codec(void);
      failures += test_format_helpers_codec(); }
    failures += test_mining();
    failures += test_regtest_generate();
    failures += test_utxo_commitment();
    failures += test_mmr();
    failures += test_mmb();
    { extern int test_keystone_utxo_binding(void);
      failures += test_keystone_utxo_binding(); }
    { extern int test_self_folded_anchor(void);
      failures += test_self_folded_anchor(); }
    { extern int test_sha3_windows(void);
      failures += test_sha3_windows(); }
    { extern int test_sha3_stream(void);
      failures += test_sha3_stream(); }
    { extern int test_utxo_root_ladder(void);
      failures += test_utxo_root_ladder(); }
    { extern int test_utxo_root_ladder_tripwire(void);
      failures += test_utxo_root_ladder_tripwire(); }
    { extern int test_golden_staleness_canary(void);
      failures += test_golden_staleness_canary(); }
    failures += test_flyclient();
    { extern int test_flyclient_chainwork_floor(void);
      failures += test_flyclient_chainwork_floor(); }
    { extern int test_test_zmsg_memo_codec(void);
      failures += test_test_zmsg_memo_codec(); }
    { extern int test_zpay(void);
      failures += test_zpay(); }
    { extern int test_zses(void);
      failures += test_zses(); }
    { extern int test_wallet_metadata_encryption(void);
      failures += test_wallet_metadata_encryption(); }
    { extern int test_transaction_intent(void);
      failures += test_transaction_intent(); }
    failures += test_scan_util();
    failures += test_tor();
    { extern int test_onion_bootstrap(void);
      failures += test_onion_bootstrap(); }
    { extern int test_onion_directory(void);
      failures += test_onion_directory(); }
    { extern int test_onion_persistence(void);
      failures += test_onion_persistence(); }
    { extern int test_onion_stream(void);
      failures += test_onion_stream(); }
    { extern int test_onion_bridge(void);
      failures += test_onion_bridge(); }
    { extern int test_cold_start_sync(void);
      failures += test_cold_start_sync(); }
    { extern int test_kill9_recovery(void);
      failures += test_kill9_recovery(); }
    { extern int test_shielded_payment_gate(void);
      failures += test_shielded_payment_gate(); }
    { extern int test_store_e2e_gate(void);
      failures += test_store_e2e_gate(); }
    { extern int test_store_e2e_shielded(void);
      failures += test_store_e2e_shielded(); }
    { extern int test_soak_harness(void);
      failures += test_soak_harness(); }
    /* Consensus edge-case coverage (boundary / overflow / known-CVE patterns) */
    { extern int test_script_interp_edge(void);  failures += test_script_interp_edge(); }
    { extern int test_script_interp_edges(void); failures += test_script_interp_edges(); }
    { extern int test_sighash_edge(void);         failures += test_sighash_edge(); }
    { extern int test_sighash_malleability(void); failures += test_sighash_malleability(); }
    { extern int test_sigops_edge(void);          failures += test_sigops_edge(); }
    { extern int test_check_tx_edge(void);        failures += test_check_tx_edge(); }
    { extern int test_check_block_edge(void);     failures += test_check_block_edge(); }
    { extern int test_amount_subsidy_edge(void);  failures += test_amount_subsidy_edge(); }
    { extern int test_clientversion_format(void); failures += test_clientversion_format(); }
    { extern int test_locktime_edge(void);        failures += test_locktime_edge(); }
    /* Consensus-parity round-3 lock-in pins (assert CURRENT zcl23-vs-zclassicd
     * behavior so a future tightening flips a test deliberately). */
    { extern int test_pow_diffadj_precedence(void);       failures += test_pow_diffadj_precedence(); }
    { extern int test_difficulty_adjustment_adversarial(void); failures += test_difficulty_adjustment_adversarial(); }
    { extern int test_bip34_coinbase_height_parity(void); failures += test_bip34_coinbase_height_parity(); }
    /* MVP "it works" gate: one mined block through the reducer front door */
    { extern int test_reducer_block_ingest_gate(void); failures += test_reducer_block_ingest_gate(); }
    /* MVP C2/C4 hermetic slices (self-skip without ZCL_STRESS_TESTS) */
    { extern int test_onion_bootstrap_slice(void);  failures += test_onion_bootstrap_slice(); }
    { extern int test_shielded_receive_slice(void); failures += test_shielded_receive_slice(); }
    { extern int test_shielded_receive_persist(void); failures += test_shielded_receive_persist(); }
    { extern int test_reducer_forward_progress_gate(void); failures += test_reducer_forward_progress_gate(); }
    { extern int test_parity_slice(void);           failures += test_parity_slice(); }
    failures += test_event();
    failures += test_download();
    failures += test_consensus();
    failures += test_policy();
    failures += test_wallet_view();
    failures += test_fast_sync();
    failures += test_block_scan();
    failures += test_node_health_service();
    failures += test_syncdiag_rpc();
    failures += test_rpc_safety();
    failures += test_rpc_service_restart();
    failures += test_chain_state_repo();
    failures += test_chain_evidence_controller();
    failures += test_chain_evidence_live_advance();
    failures += test_long_op();
    failures += test_agent_copy_prove();
    failures += test_agent_test();
    failures += test_recovery_policy();
    failures += test_oracle_policy();
    failures += test_db_txn();
    failures += test_sync_service();
    failures += test_node_db_catchup_service();
    failures += test_catchup_lifecycle_service();
    failures += test_sync_state_fsm();
    failures += test_heartbeat();
    failures += test_block_source_policy();
    { extern int test_chain_advance_atomicity(void);
      failures += test_chain_advance_atomicity(); }
    failures += test_block_source_policy_status_json();
    failures += test_snapshot_sync_service();
    failures += test_snapshot_serve_loopback();
    failures += test_block_swarm_loopback();
    failures += test_file_controller();
    failures += test_file_ops();
    failures += test_file_tree_ops();
    failures += test_spawn();
    failures += test_integrity();
    failures += test_rolling_anchor_service();
    failures += test_protocols();
    failures += test_chain_restore_planner();
    failures += test_chain_restore_service();
    failures += test_chain_activation_controller();
    failures += test_hotswap_loader();
    failures += test_hotswap_simnet();
    failures += test_hotswap_module();
    failures += test_hotswap_module_v2();
    failures += test_hotswap_service_registry();
    failures += test_dev_platform();
    failures += test_command_registry_catalog();
    failures += test_command_registry_latency();
    failures += test_native_api_contract();
    failures += test_metric_alerts();
    failures += test_db_validators();
    failures += test_peer_scoring();
    failures += test_peer_bandwidth();
    failures += test_peer_lifecycle();
    failures += test_peer_identity_hostkey();
    failures += test_secrets_hygiene();
    failures += test_block_index_integrity();
    failures += test_block_map_grow_phashblock();
    failures += test_block_successor();
    failures += test_key_hostile_wif();
    /* Subsection 5/6 finish-drive: defensive + consensus unit-test gaps. */
    failures += test_block_locator_bounds();
    failures += test_block_map_grow_collision();
    failures += test_connect_node_locked();
    failures += test_stream_read_no_overflow();
    failures += test_transaction_deserialize_count_amplification();
    failures += test_block_deserialize_txcount_amplification();
    failures += test_fast_sync_serve_chunk_db_clamps();
    failures += test_connman_node_count_locked();
    failures += test_fees_oom();
    failures += test_fees_oom_inject();
    failures += test_multisig_consensus_branches();
    failures += test_parse_script_oversize_hex();
    failures += test_script_num_minimal_encoding();
    /* Subsection 3 finish-drive: crypto KAT + consensus regression-seal tests. */
    failures += test_domain_consensus_pow_seal_matrix();
    failures += test_domain_consensus_pow_seal_powlimit_floor();
    failures += test_domain_consensus_pow_seal_malformed_paths();
    failures += test_domain_consensus_pow_seal_deterministic();
    failures += test_checkpoints_progress_boundary_crossover();
    failures += test_checkpoints_progress_zero_defenses();
    failures += test_checkpoints_progress_sigcheck_factor();
    failures += test_checkpoints_progress_regression_seal();
    failures += test_equihash_null_guards();
    failures += test_equihash_solution_size_demux();
    failures += test_equihash_blake2b_state_seal();
    failures += test_equihash_serialization_matches_independent_rebuild();
    failures += test_equihash_legacy_wrapper_regression_seal();
    failures += test_coins_amount_codec_roundtrip();
    failures += test_coins_amount_codec_boundary_exponents();
    failures += test_coins_amount_codec_digit_preservation();
    failures += test_coins_amount_codec_regression_seal();
    failures += test_hkdf_sha256_rfc5869();
    failures += test_x25519_safe();
    failures += test_noise_nk_handshake();
    failures += test_noise_xx_handshake();
    failures += test_session_transport();
    failures += test_v2_transport_parity();
    failures += test_hmac_sha512_kat_rfc4231_jefe();
    failures += test_hmac_sha512_kat_oversized_key();
    failures += test_hmac_sha512_empty_message();
    failures += test_hmac_sha512_multiblock_stateful_write();
    failures += test_hmac_sha512_key_len_128_boundary();
    failures += test_pbkdf2_sha512_rfc_vector();
    failures += test_pbkdf2_sha512_multiblock();
    failures += test_pbkdf2_sha512_high_iterations();
    failures += test_pbkdf2_sha512_empty_inputs();
    failures += test_pbkdf2_sha512_one_byte_output();
    /* Drive 4 finish-drive: sapling/script/wallet pedantic regression tests. */
    failures += test_sapling_address_hash_fields();
    failures += test_sprout_address_hash_fields();
    failures += test_sapling_sprout_hash_idempotence_and_distinct();
    failures += test_sprout_spending_key_viewing_key();
    failures += test_note_encryption_kdf_domain_separation();
    failures += test_note_encryption_prf_ock_known_answer();
    failures += test_note_encryption_sapling_kdf_arg_order_distinct();
    failures += test_note_encryption_sapling_kdf_avalanche();
    failures += test_note_encryption_sapling_kdf_known_answer();
    failures += test_note_encryption_sprout_kdf_avalanche();
    failures += test_note_encryption_sprout_kdf_known_answer();
    failures += test_note_encryption_sprout_kdf_nonce_sweep();
    failures += test_zip32_default_diversifier_deterministic();
    failures += test_zip32_default_diversifier_is_ff1_of_settled_index();
    failures += test_zip32_diversifier_advances_index_in_place();
    failures += test_zip32_diversifier_distinct_keys_distinct_output();
    failures += test_zip32_diversifier_index_boundaries();
    failures += test_zip32_diversifier_skips_invalid_indices();
    failures += test_zip32_ff1_radix2_deterministic();
    failures += test_script_interp_altstack_conditional();
    failures += test_script_interp_op2rot_order();
    failures += test_script_interp_oppick_bounds();
    failures += test_script_interp_oproll_semantics();
    failures += test_script_interp_optuck_insert();
    failures += test_script_interp_overflow_boundary();
    failures += test_wallet_backup();
    { extern int test_wallet_canary(void); failures += test_wallet_canary(); }
    { extern int test_wallet_persistence_cycle(void);
      failures += test_wallet_persistence_cycle(); }
    { extern int test_wallet_flush_rollback(void);
      failures += test_wallet_flush_rollback(); }
    { extern int test_dbquery_secret_denylist(void);
      failures += test_dbquery_secret_denylist(); }
    failures += test_log_json();
    failures += test_http_middleware();
    failures += test_rpc_timeout();
    failures += test_wallet_keystore();
    failures += test_wallet_sqlite_enc();
    { extern int test_zcl_result(void); failures += test_zcl_result(); }
    { extern int test_netaddr_classify(void);
      failures += test_netaddr_classify(); }
    { extern int test_wallet_sqlite_open_errors(void);
      failures += test_wallet_sqlite_open_errors(); }
    { extern int test_watch_only(void); failures += test_watch_only(); }
    { extern int test_coin_selection(void); failures += test_coin_selection(); }
    failures += test_disk_monitor();
    failures += test_binary_staleness();
    failures += test_binary_ab_fallback();
    { extern int test_network_monitor(void); failures += test_network_monitor(); }
    { extern int test_netsplit_detector(void); failures += test_netsplit_detector(); }
    { extern int test_directory_influence_policy(void); failures += test_directory_influence_policy(); }
    { extern int test_network_crawler(void); failures += test_network_crawler(); }
    failures += test_db_maintenance();
    failures += test_mempool_limits();
    failures += test_addrman_integrity();
    failures += test_zdir_selection();
    failures += test_ibd_throttle();
    failures += test_consensus_reject_events();
    failures += test_consensus_reject_index();
    failures += test_blocker_history();
    failures += test_chain_rollback();
    failures += test_alerts();
    failures += test_ws_events();
    failures += test_trace();
    failures += test_phgr13_fix();
    failures += test_sprout_phgr13_kat();
    failures += test_sprout_groth16_kat();
    failures += test_transaction_wire_evidence();
    failures += test_rescanwitnesses_diverge_guard();
    failures += test_gap_fill_frontier_window();
    failures += test_snark_kat();
    { extern int test_sapling_prover_rng_determinism(void);
      failures += test_sapling_prover_rng_determinism(); }
    failures += test_unclean_shutdown_advance();
    { extern int test_no_hardcoded_home(void);
      failures += test_no_hardcoded_home(); }
    failures += test_cookie_rotation();
    failures += test_reorg_safety();
    failures += test_invalidateblock();
    failures += test_most_work_selector();
    failures += test_reorg_parity();
    failures += test_stage_reorg_unwind_parity();
    failures += test_coins_wipe_rebuild_reorg();
    failures += test_utxo_apply_value_balance();
    failures += test_utxo_apply_unspendable();
    failures += test_coins_applied_frontier();
    failures += test_reducer_ingest_e2e();
    failures += test_reducer_step_drain_harness();
    failures += test_reducer_ondemand_genesis_seed();
    failures += test_mint_fold_livelock();
    failures += test_reducer_drain_spin_contract();
    failures += test_connect_block_self_write();
    failures += test_simnet_doublespend();
    failures += test_simnet_chained_tx();
    failures += test_simnet_block_sigops();
    failures += test_simnet_duplicate_input();
    failures += test_simnet_value_inflation();
    failures += test_simnet_fee_range();
    failures += test_simnet_empty_vin_vout();
    failures += test_simnet_input_value_range();
    failures += test_simnet_sapling_activation();
    failures += test_simnet_sapling_shielded_send();
    failures += test_simnet_wallet_import_backup();
    failures += test_simnet_zmsg_onchain();
    failures += test_coinbase_subsidy_adversarial();
    failures += test_simnet_fuzz();
    failures += test_connect_block_sapling_root();
    failures += test_connect_block_checkdatasig_sigops();
    failures += test_utxo_apply_coinbase_maturity();
    failures += test_key_scrub();
    failures += test_block_index_loader();
    failures += test_chain_state_validator();
    failures += test_utxo_recovery_service();
    failures += test_utxo_reimport_flag();
    failures += test_connect_tip_hot_loop_exit();
    failures += test_self_heal_scan_fallback();
    failures += test_utxo_audit();
    failures += test_utxo_parity_service();
    failures += test_rpc_error_envelope();
    failures += test_tx_property();
    failures += test_workpool();
    failures += test_app_context();
    failures += test_service_kernel();
    failures += test_service_manifest();
    failures += test_app_checkpoint_manifest();
    { extern int test_thread_registry(void);
      failures += test_thread_registry(); }
    { extern int test_thread_qos(void);
      failures += test_thread_qos(); }
    failures += test_bip113_bip65();
    failures += test_block_timestamp_adversarial();
    failures += test_mempool_orphan();
    failures += test_fee_estimation();
    failures += test_header_sync();
    failures += test_header_sync_stall();
    failures += test_header_range_sched();
    failures += test_hd_keychain();
    failures += test_mnemonic();
    failures += test_bip44();
    failures += test_compact_blocks();
    failures += test_dandelion();
    failures += test_addrman_rebalance();
    failures += test_block_pruning();
    failures += test_schema_migration();
    failures += test_db_migration_idempotent();
    failures += test_coins_view_atomicity();
    failures += test_coins_anchor_reconcile_all();
    failures += test_coins_best_derivation();
    { extern int test_boot_coins_anchor_dual_store_recovery(void);
      failures += test_boot_coins_anchor_dual_store_recovery(); }
    failures += test_chain_stall_repro();
    failures += test_failed_child_cap();
    failures += test_power_node_contract_spec();
    failures += test_boot_phase();
    failures += test_boot_status();
    failures += test_boot_odelta_scan();
    failures += test_path_check();
    failures += test_parse_num();
    failures += test_boot_progress();
    failures += test_supervisor();
    failures += test_supervisor_domains();
    failures += test_supervisor_backstop();
    failures += test_sd_notify();
    failures += test_self_heal_supervisor();
    failures += test_condition_engine();
    failures += test_utxo_activation_paused();
    failures += test_sync_watchdog_conditions();
    { extern int test_sticky_conditions(void);
      failures += test_sticky_conditions(); }
    { extern int test_mem_pressure(void);
      failures += test_mem_pressure(); }
    { extern int test_validation_pack_conditions(void);
      failures += test_validation_pack_conditions(); }
    { extern int test_sticky_escalator(void);
      failures += test_sticky_escalator(); }
    { extern int test_stall_totality_matrix(void);
      failures += test_stall_totality_matrix(); }
    failures += test_peer_snapshot_conditions();
    failures += test_snapshot_receive_stalled_condition();
    failures += test_snapshot_negotiation_stalled_condition();
    failures += test_snapshot_failed_reset_condition();
    failures += test_snapshot_complete_resume_condition();
    failures += test_chain_integrity_failed_condition();
    failures += test_body_fetch_missing_have_data_condition();
    failures += test_stale_validate_headers_repair_condition();
    failures += test_orphan_utxo_above_tip();
    failures += test_tip_fork_stale();
    failures += test_tip_stall_oracle_rebuild_condition();
    failures += test_active_chain_extend();
    failures += test_rebuild_recent();
    failures += test_torn_index_blocks_tip();
    failures += test_have_data_unreadable();
    failures += test_chain_tip_watchdog_bounded_restart();
    failures += test_blocker();
    failures += test_cpu_topology();
    failures += test_hw_profile();
    failures += test_hw_bench();
    failures += test_log_level();
    failures += test_operator_ux();
    failures += test_cli_render();
    failures += test_service_state();
    failures += test_service_state_driver();
    failures += test_clock();
    failures += test_time_authority();
    failures += test_rng();
    { extern int test_os_proc(void);
      failures += test_os_proc(); }
    failures += test_seed_tape();
    failures += test_postmortem();
    failures += test_chaos_harness();
    failures += test_stage();
    failures += test_stage_anchor();
    failures += test_mailbox();
    failures += test_mailbox_adoption();
    failures += test_projection();
    failures += test_projection_adoption();
    failures += test_projection_consumer();
    failures += test_progress_store();
    failures += test_event_log();
    failures += test_event_log_kill9();
    failures += test_event_log_benchmark();
    failures += test_mempool_projection();
    failures += test_peers_projection();
    { extern int test_topology_store(void);
      failures += test_topology_store(); }
    failures += test_wallet_projection();
    failures += test_small_projections();
    { extern int test_coins_view_kv(void);
      failures += test_coins_view_kv(); }
    failures += test_block_index_projection();
    failures += test_block_index_rebuild();
    failures += test_block_index_topup();
    failures += test_block_index_node_db_topup();
    failures += test_projection_replay_invariant();
    failures += test_block_status_event_restart_proof();
    failures += test_header_admit_stage();
    failures += test_header_probe_poll();
    failures += test_validate_headers_stage();
    failures += test_body_fetch_stage();
    failures += test_body_persist_stage();
    failures += test_created_outputs_index();
    failures += test_coins_kv();
    { extern int test_coins_kv_reset_for_reseed(void);
      failures += test_coins_kv_reset_for_reseed(); }
    { extern int test_utxo_mirror_sync(void);
      failures += test_utxo_mirror_sync(); }
    failures += test_seal_kv();
    failures += test_sha3_sidecar_io();
    failures += test_seal_ratify();
    { extern int test_seal_rewind(void); failures += test_seal_rewind(); }
    { extern int test_vcs_core(void); failures += test_vcs_core(); }
    { extern int test_vcs_release(void); failures += test_vcs_release(); }
    { extern int test_vcs_accept(void); failures += test_vcs_accept(); }
    { extern int test_zcode_store(void); failures += test_zcode_store(); }
    { extern int test_zcode_publish(void); failures += test_zcode_publish(); }
    { extern int test_zcode_package_dev(void); failures += test_zcode_package_dev(); }
    { extern int test_zcode_dev_product(void); failures += test_zcode_dev_product(); }
    { extern int test_zcode_recipe(void); failures += test_zcode_recipe(); }
    { extern int test_zcode_contributor(void); failures += test_zcode_contributor(); }
    { extern int test_zcode_verify(void); failures += test_zcode_verify(); }
    { extern int test_zcode_score(void); failures += test_zcode_score(); }
    { extern int test_zcode_reward(void); failures += test_zcode_reward(); }
    { extern int test_zcode_rank(void); failures += test_zcode_rank(); }
    { extern int test_zcode_discovery_rank(void);
      failures += test_zcode_discovery_rank(); }
    { extern int test_zcode_seed_election(void);
      failures += test_zcode_seed_election(); }
    { extern int test_zcode_dht(void); failures += test_zcode_dht(); }
    { extern int test_zcode_dht_delegation(void);
      failures += test_zcode_dht_delegation(); }
    { extern int test_zcode_dht_msgs(void); failures += test_zcode_dht_msgs(); }
    { extern int test_zcode_dht_record(void);
      failures += test_zcode_dht_record(); }
    { extern int test_zcode_sovereignty_policy(void);
      failures += test_zcode_sovereignty_policy(); }
    { extern int test_zcode_dht_service(void);
      failures += test_zcode_dht_service(); }
    { extern int test_zcode_dht_lookup(void);
      failures += test_zcode_dht_lookup(); }
    { extern int test_zcode_dht_model(void);
      failures += test_zcode_dht_model(); }
    { extern int test_zcode_badge(void); failures += test_zcode_badge(); }
    { extern int test_zcode_policy(void); failures += test_zcode_policy(); }
    { extern int test_zcode_public_shape(void);
      failures += test_zcode_public_shape(); }
    { extern int test_zcode_swarm(void); failures += test_zcode_swarm(); }
    { extern int test_zcode_swarm_net(void); failures += test_zcode_swarm_net(); }
    { extern int test_zcode_swarm_complete(void);
      failures += test_zcode_swarm_complete(); }
    { extern int test_zcode_fetch(void); failures += test_zcode_fetch(); }
    { extern int test_zcode_site(void); failures += test_zcode_site(); }
    { extern int test_zcode_add(void); failures += test_zcode_add(); }
    { extern int test_zcode_science(void); failures += test_zcode_science(); }
    { extern int test_zcode_science_store(void);
      failures += test_zcode_science_store(); }
    { extern int test_zcode_benchmark_exec(void);
      failures += test_zcode_benchmark_exec(); }
    { extern int test_zcode_discovery_projection(void);
      failures += test_zcode_discovery_projection(); }
    { extern int test_metaverse_catalog(void); failures += test_metaverse_catalog(); }
    { extern int test_site_routes(void); failures += test_site_routes(); }
    { extern int test_space(void); failures += test_space(); }
    { extern int test_space_scout(void); failures += test_space_scout(); }
    { extern int test_vcs_devloop(void); failures += test_vcs_devloop(); }
    { extern int test_testcache(void); failures += test_testcache(); }
    failures += test_nullifier_kv();
    failures += test_sapling_nullifier_adversarial();
    failures += test_stage_repair();
    { extern int test_always_sync_selfheal(void);
      failures += test_always_sync_selfheal(); }
    failures += test_script_validate_stage();
    failures += test_script_validate_contextual_gate();
    failures += test_proof_validate_stage();
    failures += test_mint_skip_crypto();
    failures += test_mint_anchor_preflight();
    failures += test_utxo_apply_stage();
    failures += test_utxo_apply_crash_replay();
    failures += test_tip_finalize_stage();
    failures += test_tip_finalize_post_step();
    failures += test_reducer_frontier();
    { extern int test_offline_datadir_query(void);
      failures += test_offline_datadir_query(); }
    { extern int test_read_leaf_no_datadir_write(void);
      failures += test_read_leaf_no_datadir_write(); }
    { extern int test_wallet_phrase_never_logged(void);
      failures += test_wallet_phrase_never_logged(); }
    { extern int test_wallet_recovery_safety(void);
      failures += test_wallet_recovery_safety(); }
    { extern int test_hstar_integrity(void);
      failures += test_hstar_integrity(); }
    { extern int test_install_verb_warm(void);
      failures += test_install_verb_warm(); }
    failures += test_always_sync_chaos();
    { extern int test_always_sync_lifecycle(void);
      failures += test_always_sync_lifecycle(); }
    { extern int test_reindex_sparse_bodies(void);
      failures += test_reindex_sparse_bodies(); }
    failures += test_waitforheight_provable();
    failures += test_refold_progress_floor();
    failures += test_refold_cadence();
    failures += test_catchup_cadence();
    { extern int test_stage_dump_trylock(void);
      failures += test_stage_dump_trylock(); }
    { extern int test_agent_posture_trylock(void);
      failures += test_agent_posture_trylock(); }
    { extern int test_operator_needed_policy(void);
      failures += test_operator_needed_policy(); }
    { extern int test_subsystem_snapshot(void);
      failures += test_subsystem_snapshot(); }
    { extern int test_rom_compile_status(void);
      failures += test_rom_compile_status(); }
    { extern int test_rom_watch_loop(void);
      failures += test_rom_watch_loop(); }
    { extern int test_reindex_epilogue(void);
      failures += test_reindex_epilogue(); }
    { extern int test_snapshot_boot_seed(void);
      failures += test_snapshot_boot_seed(); }
    failures += test_chain_linkage_check();
    failures += test_invariant_sentinel();
    failures += test_seed_integrity_gate();
    failures += test_seed_torn_import_gate();
    failures += test_mirror_divergence_locator();
    failures += test_log_throttle();
    failures += test_reducer_frontier_reconcile_light();
    failures += test_reducer_stage_fuzz();
    failures += test_reducer_ingest_e2e();
    failures += test_reducer_step_drain_harness();
    failures += test_reducer_ondemand_genesis_seed();
    failures += test_mint_fold_livelock();
    failures += test_reducer_drain_spin_contract();
    failures += test_stage_reducer_unwedge();
    { extern int test_repair_marker(void);
      failures += test_repair_marker(); }
    failures += test_stage_repair_coin_backfill();
    { extern int test_stage_anchor_frontier_cap(void);
      failures += test_stage_anchor_frontier_cap(); }
    { extern int test_sapling_anchor_frontier_condition(void);
      failures += test_sapling_anchor_frontier_condition(); }
    { extern int test_shielded_sync_strength(void);
      failures += test_shielded_sync_strength(); }
    { extern int test_stage_repair_script_refill(void);
      failures += test_stage_repair_script_refill(); }
    { extern int test_stage_repair_tipfin_backfill(void);
      failures += test_stage_repair_tipfin_backfill(); }
    { extern int test_reorg_residue_tipfin_replace(void);
      failures += test_reorg_residue_tipfin_replace(); }
    { extern int test_stage_rederive_range(void);
      failures += test_stage_rederive_range(); }
    { extern int test_utxo_apply_upstream_hole(void);
      failures += test_utxo_apply_upstream_hole(); }
    { extern int test_lcc_write_rules(void);
      failures += test_lcc_write_rules(); }
    { extern int test_reducer_reconcile_witness(void);
      failures += test_reducer_reconcile_witness(); }
    { extern int test_recovery_no_worse(void);
      failures += test_recovery_no_worse(); }
    failures += test_process_block_revalidate();
    failures += test_domain_consensus_verify();
    failures += test_domain_consensus_subsidy();
    failures += test_domain_consensus_pow();
    failures += test_domain_consensus_sigops();
    failures += test_domain_consensus_script_standard();
    failures += test_domain_consensus_tx_structural();
    failures += test_domain_consensus_sapling_structural();
    failures += test_domain_consensus_sighash();
    failures += test_domain_consensus_check_block();
    failures += test_domain_consensus_equihash();
    failures += test_domain_consensus_script_interp();
    failures += test_domain_consensus_coins_math();
    failures += test_domain_consensus_checkpoints();
    failures += test_domain_consensus_locktime();
    failures += test_tx_expiry_locktime_adversarial();
    failures += test_domain_consensus_upgrades();
    failures += test_domain_consensus_coinbase();
    failures += test_domain_consensus_header_accept();
    failures += test_domain_wallet_key_derivation();
    failures += test_domain_wallet_mnemonic();
    failures += test_domain_encoding_base58();
    failures += test_domain_encoding_bech32();
    failures += test_block_log_file();
    failures += test_block_log_legacy();
    failures += test_replay_verify();
    failures += test_utxo_snapshot_inmem();
    failures += test_hodl_history_port();
    failures += test_node_health_store_port();
    failures += test_db_maintenance_port();
    failures += test_wallet_backup_port();
    failures += test_snapshot_store_port();
    failures += test_block_index_sidecar_port();
    failures += test_wallet_view_port();
    failures += test_bg_hash_verify_store_port();
    failures += test_bg_validation_store_port();
    failures += test_zslp_store_port();
    { extern int test_zswap_quote(void); failures += test_zswap_quote(); }
    { extern int test_zswap_yardsale(void); failures += test_zswap_yardsale(); }
    { extern int test_zswap_ceremony(void); failures += test_zswap_ceremony(); }
    { extern int test_yardsale_app(void); failures += test_yardsale_app(); }
    { extern int test_yardsale_wallet(void); failures += test_yardsale_wallet(); }
    failures += test_make_lint_gates_family();
    failures += test_multisig();
    failures += test_rpc_auth_hardening();
    failures += test_disk_block_io();
    failures += test_msg_handlers();
    failures += test_process_headers_adversarial();
    failures += test_getheaders_serve_fallback();
    failures += test_net_handshake_adversarial();
    failures += test_net_ban_persistence();
    failures += test_net_census();
    failures += test_zclassicd_oracle();
    failures += test_header_probe();
    failures += test_header_probe_p2p_fallback();
    { extern int test_lag_slo(void); failures += test_lag_slo(); }
    { extern int test_soak_attestation(void); failures += test_soak_attestation(); }
    { extern int test_replay_canary_verdict(void); failures += test_replay_canary_verdict(); }
    { extern int test_canary_sentinel_watch(void); failures += test_canary_sentinel_watch(); }
    failures += test_shielded_spend_slice();
    failures += test_atomic_commit_ordering();
    failures += test_coldimport_restart_fragility();

    /* Step-0 contracts commit — agent-oriented sync architecture (tidy-fog). */
    { extern int test_sync_reduce(void); failures += test_sync_reduce(); }
    { extern int test_sync_reduce_invariants(void); failures += test_sync_reduce_invariants(); }
    { extern int test_sync_reduce_fuzz(void); failures += test_sync_reduce_fuzz(); }
    { extern int test_sync_reduce_adapter(void); failures += test_sync_reduce_adapter(); }
    { extern int test_sync_shadow(void); failures += test_sync_shadow(); }
    { extern int test_zcl_ids(void); failures += test_zcl_ids(); }
    { extern int test_rom_manifest(void); failures += test_rom_manifest(); }
    { extern int test_rom_journal_resume(void); failures += test_rom_journal_resume(); }
    { extern int test_sync_trust_policy(void); failures += test_sync_trust_policy(); }
    { extern int test_code_capsule(void); failures += test_code_capsule(); }
    { extern int test_code_impact(void); failures += test_code_impact(); }
    { extern int test_code_merkle(void); failures += test_code_merkle(); }
    { extern int test_code_emitter(void); failures += test_code_emitter(); }
    { extern int test_fact_writers(void); failures += test_fact_writers(); }

    /* Spec-based user story tests */
    failures += spec_wallet_dashboard();
    failures += spec_wallet_send();
    failures += spec_wallet_receive();
    failures += spec_wallet_shield();
    failures += spec_wallet_node();
    failures += spec_wallet_history();
    failures += spec_wallet_coins();
    failures += spec_wallet_pulse();
    failures += spec_wallet_tx_detail();
    failures += spec_wallet_navigation();
    failures += spec_wallet_errors();
    failures += spec_wallet_privacy();
    failures += spec_wallet_sovereignty();
    failures += spec_wallet_celebration();
    failures += spec_wallet_empowerment();
    failures += spec_wallet_flow();
    failures += spec_wallet_accessibility();
    failures += spec_data_hooks();
    failures += spec_event_observers();
    failures += spec_state_machine();
    failures += spec_ux_sierra();
    failures += spec_html_quality();
    failures += spec_user_journeys();
    failures += spec_e2e_wallet();
    failures += spec_render_audit();
    failures += spec_smoke();
    failures += spec_100_stories();
    failures += spec_consensus_compat();

    ecc_verify_destroy();
    ecc_stop();

    printf("\n%s (%d failures)\n",
           failures ? "SOME TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
