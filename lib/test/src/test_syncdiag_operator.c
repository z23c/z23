/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * operator-surface cases: milestone bars, UTXO anchor rebuild readiness, the proof bundle, zclassicd warmup scoping, mirror-override safety context, the network and connman/addrman dumpstate rollups, and the MVP scoreboard classifier.
 */

#include "test/syncdiag_rpc_fixture.h"

int syncdiag_cases_operator(void)
{
    int failures = 0;

    printf("dumpstate chain_evidence health_reason is bounded... ");
    {
        struct json_value result = {0};
        bool ok = diag_chain_evidence_dump_state_json(
            &result, "health_reason");
        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get(&result, "health_reason") != NULL;
        ok = ok && json_get(&result, "contradiction_reason") != NULL;
        ok = ok && json_get(&result, "active_tip_hash_mismatch") != NULL;
        ok = ok && json_get(&result, "explorer_index_state") == NULL;
        ok = ok && json_get(&result, "block_index_evidence_state") == NULL;
        printf("%s\n", ok ? "OK" : "FAIL");
        if (!ok)
            failures++;
        json_free(&result);
    }

    printf("api: native RPC returns milestone ASCII bars... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "milestone",
                                          &params, &result);
        const struct json_value *ascii = json_get(&result, "ascii");
        const struct json_value *bars = json_get(&result, "bars");
        const struct json_value *criteria = json_get(&result, "criteria");
        const struct json_value *operator_proofs =
            json_get(&result, "operator_proofs");
        const struct json_value *proof_items =
            operator_proofs ? json_get(operator_proofs, "items") : NULL;
        const struct json_value *cold_start =
            find_object_with_str(proof_items, "key", "cold_start_sync");
        const struct json_value *soak =
            find_object_with_str(proof_items, "key", "seven_day_soak");
        const struct json_value *live = json_get(&result, "live");
        const char *live_source = json_get_str(json_get(live, "source"));
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.milestone_status.v2") == 0;
        ok = ok && json_get_int(json_get(&result,
                          "mvp_readiness_score")) == 4;
        ok = ok && ascii && strstr(json_get_str(json_get(ascii, "goals")),
                                   "goals [#####-----] 4/8") != NULL;
        ok = ok && bars && strcmp(json_get_str(json_get(json_get(bars,
                          "subgoals"), "bar")), "[########--]") == 0;
        ok = ok && criteria && json_size(criteria) == 8;
        ok = ok && operator_proofs &&
            strcmp(json_get_str(json_get(operator_proofs, "schema")),
                   "zcl.mvp_operator_proofs.v1") == 0;
        ok = ok && json_get_int(json_get(operator_proofs,
                                         "accepted_count")) == 4;
        ok = ok && json_get_int(json_get(operator_proofs,
                                         "pending_count")) == 4;
        ok = ok && json_get_int(json_get(operator_proofs,
                                         "target_count")) == 8;
        ok = ok && strcmp(json_get_str(json_get(operator_proofs,
                                                "next_command")),
                          "make mvp-verify") == 0;
        ok = ok && proof_items && json_size(proof_items) == 8;
        ok = ok && cold_start &&
            strcmp(json_get_str(json_get(cold_start, "proof_command")),
                   "make mvp-coldstart-to-tip-local") == 0;
        ok = ok && cold_start &&
            strcmp(json_get_str(json_get(cold_start, "primary_blocker")),
                   "full_zclassic23_to_zclassic23_sync_to_tip_not_run_passed")
                == 0;
        ok = ok && soak &&
            strcmp(json_get_str(json_get(soak, "proof_scope")),
                   "live_window") == 0;
        ok = ok && soak &&
            strcmp(json_get_str(json_get(soak, "proof_command")),
                   "make soak-evidence-report") == 0;
        ok = ok && soak &&
            strcmp(json_get_str(json_get(soak, "primary_blocker")),
                   "clean_168h_soak_window_pending") == 0;
        ok = ok && soak &&
            json_get_bool(json_get(soak, "local_dependency_required"));
        bool live_full_agent = live_source &&
            strcmp(live_source, "agent_cached_summary") == 0;
        bool live_agent_fallback = live_source &&
            strcmp(live_source,
                   "agent_cached_summary_with_fallbacks") == 0;
        ok = ok && live && (live_full_agent || live_agent_fallback);
        ok = ok && strcmp(json_get_str(json_get(live, "source_schema")),
                          "zcl.public_status.v3") == 0;
        ok = ok && json_get_bool(json_get(live,
                                          "agent_summary_available"));
        ok = ok && json_get_bool(json_get(live, "agent_fields_complete")) ==
            live_full_agent;
        if (live_full_agent)
            ok = ok && strcmp(json_get_str(json_get(live,
                                                    "fallback_source")),
                              "none") == 0;
        if (live_agent_fallback)
            ok = ok && strcmp(json_get_str(json_get(live,
                                                    "fallback_source")),
                              "none") != 0;
        ok = ok && json_get(live, "agent_status") != NULL;
        ok = ok && json_get(live, "readiness_status") != NULL;
        ok = ok && json_get(live, "height_contract_status") != NULL;

        struct json_value agent;
        json_init(&agent);
        bool agent_executed = rpc_table_execute(&tbl, "agent",
                                                &params, &agent);
        int64_t agent_served =
            json_get_int(json_get(&agent, "served_height"));
        if (ok && agent_executed && agent.type == JSON_OBJ &&
            live_full_agent && agent_served > 0) {
            const struct json_value *agent_peers =
                json_get(&agent, "peers");
            const struct json_value *agent_services =
                json_get(&agent, "services");
            bool agent_onion =
                json_get_bool(json_get(agent_services, "tor_enabled")) &&
                json_get_bool(json_get(agent_services, "tor_ready")) &&
                json_get_bool(json_get(agent_services,
                                       "onion_service_ready"));

            ok = ok && json_get_int(json_get(live, "served_height")) ==
                json_get_int(json_get(&agent, "served_height"));
            ok = ok && json_get_int(json_get(live, "indexed_height")) ==
                json_get_int(json_get(&agent, "indexed_height"));
            ok = ok && json_get_int(json_get(live, "header_height")) ==
                json_get_int(json_get(&agent, "header_height"));
            ok = ok && json_get_int(json_get(live, "peer_best_height")) ==
                json_get_int(json_get(&agent, "peer_best_height"));
            ok = ok && json_get_int(json_get(live, "target_height")) ==
                json_get_int(json_get(&agent, "target_height"));
            ok = ok && json_get_int(json_get(live, "gap")) ==
                json_get_int(json_get(&agent, "gap"));
            ok = ok && json_get_int(json_get(live, "peers")) ==
                json_get_int(json_get(agent_peers, "total"));
            ok = ok && json_get_bool(json_get(live, "tor_enabled")) ==
                json_get_bool(json_get(agent_services, "tor_enabled"));
            ok = ok && json_get_bool(json_get(live, "onion_ready")) ==
                agent_onion;
            ok = ok && strcmp(json_get_str(json_get(live, "sync_state")),
                              json_get_str(json_get(&agent,
                                                    "sync_state"))) == 0;
        }

        struct json_value alias;
        json_init(&alias);
        bool alias_executed = rpc_table_execute(&tbl, "mvpstatus",
                                                &params, &alias);
        ok = ok && alias_executed && alias.type == JSON_OBJ &&
            strcmp(json_get_str(json_get(&alias, "schema")),
                   "zcl.milestone_status.v2") == 0;

        json_free(&alias);
        json_free(&agent);
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC returns UTXO anchor rebuild readiness... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "refold",
                                          &params, &result);
        const struct json_value *snap = json_get(&result, "anchor_snapshot");
        const struct json_value *commands = json_get(&result, "commands");
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.refold_status.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "api_version")),
                          "v1") == 0;
        ok = ok && strstr(json_get_str(json_get(&result, "purpose")),
                          "UTXO anchor rebuild") != NULL;
        ok = ok && strstr(json_get_str(json_get(&result, "plain_english")),
                          "borrowed snapshot seed") != NULL;
        ok = ok && strcmp(json_get_str(json_get(&result,
                                                "internal_mechanism")),
                          "-refold-from-anchor") == 0;
        ok = ok && !json_get_bool(json_get(&result, "ready_for_refold"));
        ok = ok && snap && json_get(snap, "verification") != NULL;
        ok = ok && commands &&
            strcmp(json_get_str(json_get(commands, "native")),
                   "z23 refold") == 0;

        struct json_value alias;
        json_init(&alias);
        bool alias_executed = rpc_table_execute(&tbl, "refoldstatus",
                                                &params, &alias);
        ok = ok && alias_executed && alias.type == JSON_OBJ &&
            strcmp(json_get_str(json_get(&alias, "schema")),
                   "zcl.refold_status.v2") == 0;

        json_free(&alias);
        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("api: native RPC returns operator proof bundle... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value anchor_dir;
        json_init(&anchor_dir);
        json_set_str(&anchor_dir, "/tmp");
        json_push_back(&params, &anchor_dir);
        json_free(&anchor_dir);

        bool env_ok = set_dev_status_cmd_json(
            "{\"schema\":\"zcl.agent_dev_status.v2\","
            "\"worker_lane\":{\"name\":\"dev\",\"role\":\"worker\","
            "\"mutation_policy\":\"noncanonical_dev_only\","
            "\"canonical_guard\":\"never_touches_live_or_soak\"},"
            "\"next_action\":\"unit-test\","
            "\"service\":{\"active_state\":\"active\"},"
            "\"rpc\":{\"status\":\"ok\"}}");

        struct json_value result;
        json_init(&result);

        bool executed = rpc_table_execute(&tbl, "proofbundle",
                                          &params, &result);
        unsetenv("ZCL_AGENT_DEV_STATUS_CMD");
        const struct json_value *commands = json_get(&result, "commands");
        const struct json_value *agent = json_get(&result, "agent");
        const struct json_value *milestone = json_get(&result, "milestone");
        const struct json_value *refold = json_get(&result, "refold");
        const struct json_value *anchor = json_get(&result, "anchor_status");
        const struct json_value *lanes = json_get(&result, "lanes");
        const struct json_value *dev = json_get(&result, "dev_status");
        bool ok = env_ok && executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.operator_proof_bundle.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result, "anchor_datadir")),
                          "/tmp") == 0;
        ok = ok && commands && commands->type == JSON_OBJ;
        ok = ok && commands &&
            strcmp(json_get_str(json_get(commands, "native")),
                   "z23 proofbundle [anchor_datadir]") == 0;
        ok = ok && agent &&
            strcmp(json_get_str(json_get(agent, "schema")),
                   "zcl.public_status.v3") == 0;
        ok = ok && milestone &&
            strcmp(json_get_str(json_get(milestone, "schema")),
                   "zcl.milestone_status.v2") == 0;
        ok = ok && refold &&
            strcmp(json_get_str(json_get(refold, "schema")),
                   "zcl.refold_status.v2") == 0;
        ok = ok && anchor &&
            strcmp(json_get_str(json_get(anchor, "schema")),
                   "zcl.anchor_mint_status.v1") == 0;
        ok = ok && lanes &&
            strcmp(json_get_str(json_get(lanes, "schema")),
                   "zcl.agent_lanes.v2") == 0;
        ok = ok && dev &&
            strcmp(json_get_str(json_get(dev, "schema")),
                   "zcl.agent_dev_status.v2") == 0;
        ok = ok && strcmp(json_get_str(json_get(dev, "next_action")),
                          "unit-test") == 0;

        json_free(&params);
        json_free(&result);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("healthcheck: scopes zclassicd warmup as advisory when P2P "
           "is active (RED)... ");
    {
        struct connman cm;
        struct node_signals sigs;
        struct main_state ms;
        struct block_index tip;
        struct block_index best_header;
        struct rpc_table tbl;
        struct json_value params;
        struct json_value result;
        struct legacy_mirror_sync_stats stats;

        chain_params_select(CHAIN_MAIN);
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        memset(&ms, 0, sizeof(ms));
        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(&stats, 0, sizeof(stats));

        bool ok = connman_init(&cm, chain_params_get(), &sigs);
        main_state_init(&ms);
        tip.nHeight = 3117074;
        best_header.nHeight = 3117074;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);
        ms.pindex_best_header = &best_header;
        ok = ok && syncdiag_add_peer(&cm, 21, false,
                                     PEER_HANDSHAKE_COMPLETE) != NULL;
        ok = ok && syncdiag_add_peer(&cm, 22, false,
                                     PEER_HANDSHAKE_COMPLETE) != NULL;
        ok = ok && syncdiag_add_peer(&cm, 23, false,
                                     PEER_HANDSHAKE_COMPLETE) != NULL;

        block_source_policy_reset_for_test();
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        block_source_policy_init(&cm, &ms, NULL);

        stats.enabled = true;
        stats.running = true;
        stats.reachable = false;
        stats.legacy_height = 0;
        stats.local_height = 3117074;
        stats.best_header_height = 3117074;
        stats.target_height = 3117074;
        stats.rpc_errors = 940;
        stats.last_attempt = 123456;
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "rpc-unreachable");
        snprintf(stats.last_error, sizeof(stats.last_error),
                 "%s",
                 "rpc error -28: Activating best chain... height 0 (1%)");
        legacy_mirror_sync_test_set_stats(&stats, &ms);

        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();
        json_init(&params);
        json_set_object(&params);
        json_push_kv_bool(&params, "full", true);
        json_init(&result);
        ok = ok && rpc_table_execute(&tbl, "healthcheck", &params, &result);

        const struct json_value *checks = json_get(&result, "checks");
        const struct json_value *ca =
            checks ? json_get(checks, "chain_advance") : NULL;
        ok = ok && result.type == JSON_OBJ;
        ok = ok && ca && ca->type == JSON_OBJ;
        ok = ok && json_get(ca, "selected_source") != NULL &&
            strcmp(json_get_str(json_get(ca, "selected_source")),
                   "p2p") == 0;
        ok = ok && json_get(ca, "selected_source_trust") != NULL &&
            strcmp(json_get_str(json_get(ca, "selected_source_trust")),
                   "native_peer_validated") == 0;
        ok = ok && json_get(&result, "active_source") != NULL &&
            strcmp(json_get_str(json_get(&result, "active_source")),
                   "p2p") == 0;
        ok = ok && json_get(&result, "active_source_trust") != NULL &&
            strcmp(json_get_str(json_get(&result, "active_source_trust")),
                   "native_peer_validated") == 0;
        ok = ok && json_get(&result, "active_blocker") != NULL &&
            strcmp(json_get_str(json_get(&result, "active_blocker")),
                   "") == 0;
        ok = ok && json_get(&result, "candidate_source") != NULL &&
            strcmp(json_get_str(json_get(&result, "candidate_source")),
                   "legacy_advisory") == 0;
        ok = ok && json_get(&result, "candidate_blocker") != NULL &&
            strcmp(json_get_str(json_get(&result, "candidate_blocker")),
                   "") == 0;
        ok = ok && json_get(&result, "candidate_blocker_scope") != NULL &&
            strcmp(json_get_str(json_get(
                       &result, "candidate_blocker_scope")),
                   "advisory_only") == 0;
        ok = ok && json_get(&result, "legacy_advisory_blocker") != NULL &&
            strcmp(json_get_str(json_get(
                       &result, "legacy_advisory_blocker")),
                   "rpc-unreachable") == 0;
        ok = ok && json_get(&result, "mirror_monitor_running") != NULL &&
            json_get_bool(json_get(&result, "mirror_monitor_running"));
        ok = ok && json_get(&result,
                            "zclassicd_rpc_transport_reachable") != NULL &&
            json_get_bool(json_get(&result,
                                   "zclassicd_rpc_transport_reachable"));
        ok = ok && json_get(&result, "legacy_oracle_usable") != NULL &&
            !json_get_bool(json_get(&result, "legacy_oracle_usable"));
        ok = ok && json_get(&result, "zclassicd_rpc_error_code") != NULL &&
            json_get_int(json_get(&result,
                                  "zclassicd_rpc_error_code")) == -28;
        ok = ok && json_get(&result,
                            "zclassicd_rpc_error_message") != NULL &&
            strstr(json_get_str(json_get(
                       &result, "zclassicd_rpc_error_message")),
                   "Activating best chain") != NULL;
        ok = ok && json_get(&result, "mirror_rpc_errors") != NULL &&
            json_get_int(json_get(&result, "mirror_rpc_errors")) == 940;
        ok = ok && json_get(&result, "mirror_last_attempt") != NULL &&
            json_get_int(json_get(&result, "mirror_last_attempt")) == 123456;
        ok = ok && json_get(&result, "mirror_active_error_code") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "mirror_active_error_code")),
                   "rpc-unreachable") == 0;
        ok = ok && json_get(&result, "mirror_active_error_detail") != NULL &&
            strstr(json_get_str(json_get(
                       &result, "mirror_active_error_detail")),
                   "Activating best chain") != NULL;

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
        json_free(&params);
        json_free(&result);
        rpc_net_set_connman(NULL);
        block_source_policy_reset_for_test();
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        main_state_free(&ms);
        connman_free(&cm);
    }

    printf("getsyncdetail: exposes mirror override safety context "
           "(RED)... ");
    {
        struct json_value result;
        json_init(&result);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        mirror_consensus_set_enabled(true);
        mirror_consensus_record_override(300, "body-hash-mismatch");
        mirror_consensus_record_blocker("body-hash-mismatch");

        bool ok = api_getsyncdetail(&result);
        ok = ok && result.type == JSON_OBJ;
        ok = ok && json_get(&result, "mirror_unsafe_overrides_total") != NULL &&
            json_get_int(json_get(&result,
                                  "mirror_unsafe_overrides_total")) == 1;
        ok = ok && json_get(&result, "mirror_last_override_safe") != NULL &&
            !json_get_bool(json_get(&result, "mirror_last_override_safe"));
        ok = ok && json_get(&result, "mirror_last_override_reason") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "mirror_last_override_reason")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(&result, "mirror_last_override_scope") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "mirror_last_override_scope")),
                   "unsafe_no_authorized_scope") == 0;

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
        json_free(&result);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
    }

    printf("dumpstate network: rolls up connman/peer_floor/chain_view/"
           "census/peer_lifecycle on a minimal fixture... ");
    {
        struct json_value result = {0};

        /* ── Part 1: nothing wired (the true minimal state — no connman,
         * no network_monitor sample, no crawler round). The rollup must
         * still return a well-formed object, never crash or fail. */
        rpc_net_set_connman(NULL);
        bool ok = network_dump_state_json(&result, NULL);
        ok = ok && result.type == JSON_OBJ;

        const struct json_value *connman_j = json_get(&result, "connman");
        ok = ok && connman_j && connman_j->type == JSON_OBJ;
        ok = ok && json_get(connman_j, "wired") &&
            !json_get_bool(json_get(connman_j, "wired"));
        ok = ok && json_get(connman_j, "connected_peers") &&
            json_get_int(json_get(connman_j, "connected_peers")) == -1;
        ok = ok && json_get(connman_j, "addrman_size") &&
            json_get_int(json_get(connman_j, "addrman_size")) == -1;

        const struct json_value *addnode_j0 = json_get(&result, "addnode");
        ok = ok && addnode_j0 && addnode_j0->type == JSON_OBJ;
        ok = ok && json_get(addnode_j0, "count") &&
            json_get_int(json_get(addnode_j0, "count")) == -1;

        const struct json_value *messaging_j =
            json_get(&result, "messaging");
        ok = ok && messaging_j && messaging_j->type == JSON_OBJ;
        ok = ok && json_get(messaging_j, "transport_telemetry_wired") &&
            !json_get_bool(json_get(messaging_j,
                                    "transport_telemetry_wired"));
        ok = ok && json_get(messaging_j, "frames_received") &&
            json_get_int(json_get(messaging_j, "frames_received")) == 0;
        ok = ok && json_get(messaging_j, "acknowledgements_received") &&
            json_get_int(json_get(messaging_j,
                                  "acknowledgements_received")) == 0;

        const struct json_value *peer_floor_j = json_get(&result, "peer_floor");
        ok = ok && peer_floor_j && peer_floor_j->type == JSON_OBJ;
        ok = ok && json_get(peer_floor_j, "registered") != NULL;
        ok = ok && json_get(peer_floor_j, "healthy_outbound") != NULL;

        const struct json_value *chain_view_j = json_get(&result, "chain_view");
        ok = ok && chain_view_j && chain_view_j->type == JSON_OBJ;
        ok = ok && json_get(chain_view_j, "ready") != NULL;

        const struct json_value *census_j = json_get(&result, "census");
        ok = ok && census_j && census_j->type == JSON_OBJ;
        ok = ok && json_get(census_j, "started") != NULL;

        const struct json_value *tip_cmp_j = json_get(&result, "tip_comparison");
        ok = ok && tip_cmp_j && tip_cmp_j->type == JSON_OBJ;
        ok = ok && json_get(tip_cmp_j, "our_height") &&
            json_get_int(json_get(tip_cmp_j, "our_height")) == -1;

        const struct json_value *pl_j = json_get(&result, "peer_lifecycle");
        ok = ok && pl_j && pl_j->type == JSON_OBJ;
        ok = ok && json_get(pl_j, "summary") != NULL;

        json_free(&result);

        /* ── Part 2: a freshly-initialized connman with zero peers and an
         * empty addrman wired in. connman.wired flips true and the two
         * bare counters read back 0 (not -1), everything else unchanged. */
        struct connman cm;
        struct node_signals sigs;
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        chain_params_select(CHAIN_MAIN);
        ok = ok && connman_init(&cm, chain_params_get(), &sigs);
        rpc_net_set_connman(&cm);

        struct json_value result2 = {0};
        ok = ok && network_dump_state_json(&result2, NULL);
        const struct json_value *cm2 = json_get(&result2, "connman");
        ok = ok && cm2 && json_get(cm2, "wired") &&
            json_get_bool(json_get(cm2, "wired"));
        ok = ok && json_get(cm2, "connected_peers") &&
            json_get_int(json_get(cm2, "connected_peers")) == 0;
        ok = ok && json_get(cm2, "outbound_healthy") &&
            json_get_int(json_get(cm2, "outbound_healthy")) == 0;
        ok = ok && json_get(cm2, "addrman_size") &&
            json_get_int(json_get(cm2, "addrman_size")) == 0;

        /* addnode self-healing (RETIRE + HARVEST — net/connman.h) rollup:
         * a fresh connman has no addnodes, so count/retired_count/
         * retirements_total all read back 0. */
        const struct json_value *addnode_j = json_get(&result2, "addnode");
        ok = ok && addnode_j && addnode_j->type == JSON_OBJ;
        ok = ok && json_get(addnode_j, "count") &&
            json_get_int(json_get(addnode_j, "count")) == 0;
        ok = ok && json_get(addnode_j, "retired_count") &&
            json_get_int(json_get(addnode_j, "retired_count")) == 0;
        ok = ok && json_get(addnode_j, "retirements_total") &&
            json_get_int(json_get(addnode_j, "retirements_total")) == 0;

        json_free(&result2);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
        rpc_net_set_connman(NULL);
        connman_free(&cm);
    }

    printf("dumpstate connman/addrman: previously \"unknown subsystem\", "
           "now direct P2P plumbing visibility on a minimal fixture... ");
    {
        /* ── Part 1: nothing wired — must still be a well-formed object,
         * never crash, and every counter that depends on a live connman
         * reads back as absent/zero rather than fabricated. */
        rpc_net_set_connman(NULL);

        struct json_value cm_result = {0};
        bool ok = connman_diag_dump_state_json(&cm_result, NULL);
        ok = ok && cm_result.type == JSON_OBJ;
        ok = ok && json_get(&cm_result, "wired") &&
            !json_get_bool(json_get(&cm_result, "wired"));
        ok = ok && json_get(&cm_result, "outbound") == NULL;
        json_free(&cm_result);

        struct json_value am_result = {0};
        ok = ok && addrman_diag_dump_state_json(&am_result, NULL);
        ok = ok && am_result.type == JSON_OBJ;
        ok = ok && json_get(&am_result, "wired") &&
            !json_get_bool(json_get(&am_result, "wired"));
        ok = ok && json_get(&am_result, "size") == NULL;
        json_free(&am_result);

        /* ── Part 2: a freshly-initialized connman with zero peers and an
         * empty addrman wired in — "connman"/"addrman" flip wired=true and
         * report real (zero) counts, not sentinels. */
        struct connman cm;
        struct node_signals sigs;
        memset(&cm, 0, sizeof(cm));
        memset(&sigs, 0, sizeof(sigs));
        chain_params_select(CHAIN_MAIN);
        ok = ok && connman_init(&cm, chain_params_get(), &sigs);
        rpc_net_set_connman(&cm);

        struct json_value cm_result2 = {0};
        ok = ok && connman_diag_dump_state_json(&cm_result2, NULL);
        ok = ok && json_get(&cm_result2, "wired") &&
            json_get_bool(json_get(&cm_result2, "wired"));

        const struct json_value *ob = json_get(&cm_result2, "outbound");
        ok = ok && ob && ob->type == JSON_OBJ &&
            json_get(ob, "total") && json_get_int(json_get(ob, "total")) == 0;

        const struct json_value *ib = json_get(&cm_result2, "inbound");
        ok = ok && ib && ib->type == JSON_OBJ &&
            json_get(ib, "total") && json_get_int(json_get(ib, "total")) == 0;

        /* addnode ledger: a fresh connman has no addnodes, and the
         * per-index "entries" array is present but empty. */
        const struct json_value *an = json_get(&cm_result2, "addnode");
        ok = ok && an && an->type == JSON_OBJ &&
            json_get(an, "count") && json_get_int(json_get(an, "count")) == 0 &&
            json_get(an, "retirements_total") &&
            json_get_int(json_get(an, "retirements_total")) == 0;
        const struct json_value *an_entries = an ? json_get(an, "entries")
                                                  : NULL;
        ok = ok && an_entries && an_entries->type == JSON_ARR &&
            json_size(an_entries) == 0;

        /* reactor + message_cycle + floor + addrman_summary + dial_outcomes
         * sections are all present (rollups of existing owners — never
         * absent just because the node is idle). The discovered-peer section
         * must explicitly name the shared scheduler and handshake gate. */
        ok = ok && json_get(&cm_result2, "reactor") != NULL;
        ok = ok && json_get(&cm_result2, "message_cycle") != NULL;
        ok = ok && json_get(&cm_result2, "floor") != NULL;
        const struct json_value *am_sum = json_get(&cm_result2,
                                                    "addrman_summary");
        ok = ok && am_sum && json_get(am_sum, "size") &&
            json_get_int(json_get(am_sum, "size")) == 0;
        ok = ok && json_get(&cm_result2, "dial_outcomes") != NULL;
        const struct json_value *zdb = json_get(&cm_result2, "zcl23_db");
        ok = ok && zdb && zdb->type == JSON_OBJ &&
            strcmp(json_get_str(json_get(zdb, "owner")),
                   "persistent_dial_scheduler") == 0 &&
            strcmp(json_get_str(json_get(zdb, "success_gate")),
                   "protocol_handshake") == 0 &&
            json_get(zdb, "dials_scheduled") &&
            json_get_int(json_get(zdb, "dials_scheduled")) == 0 &&
            json_get(zdb, "backoff_skips") &&
            json_get_int(json_get(zdb, "backoff_skips")) == 0;
        json_free(&cm_result2);

        struct json_value am_result2 = {0};
        ok = ok && addrman_diag_dump_state_json(&am_result2, NULL);
        ok = ok && json_get(&am_result2, "wired") &&
            json_get_bool(json_get(&am_result2, "wired"));
        ok = ok && json_get(&am_result2, "size") &&
            json_get_int(json_get(&am_result2, "size")) == 0;
        ok = ok && json_get(&am_result2, "new_count") &&
            json_get_int(json_get(&am_result2, "new_count")) == 0;
        ok = ok && json_get(&am_result2, "tried_count") &&
            json_get_int(json_get(&am_result2, "tried_count")) == 0;
        ok = ok && json_get(&am_result2, "buckets") != NULL;
        ok = ok && json_get(&am_result2, "address_index") != NULL;
        const struct json_value *cand = json_get(&am_result2, "candidates");
        ok = ok && cand && json_get(cand, "live") &&
            json_get_int(json_get(cand, "live")) == 0 &&
            json_get(cand, "dead") &&
            json_get_int(json_get(cand, "dead")) == 0;
        json_free(&am_result2);

        /* Seed the hardcoded fixed seeds (offline, no network I/O) so
         * addrman's real fields flip off zero and the two subsystems agree
         * with each other on the resulting size. */
        connman_kick_seed_discovery(&cm);
        size_t seeded = addrman_size(&cm.manager.addrman);
        ok = ok && seeded > 0;

        struct json_value cm_result3 = {0};
        ok = ok && connman_diag_dump_state_json(&cm_result3, NULL);
        const struct json_value *am_sum3 = json_get(&cm_result3,
                                                     "addrman_summary");
        ok = ok && am_sum3 && json_get(am_sum3, "size") &&
            (size_t)json_get_int(json_get(am_sum3, "size")) == seeded;
        json_free(&cm_result3);

        struct json_value am_result3 = {0};
        ok = ok && addrman_diag_dump_state_json(&am_result3, NULL);
        ok = ok && json_get(&am_result3, "size") &&
            (size_t)json_get_int(json_get(&am_result3, "size")) == seeded;
        json_free(&am_result3);

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
        rpc_net_set_connman(NULL);
        connman_free(&cm);
    }

    /* ── mvp scoreboard (schema zcl.mvp_status.v1) ──────────────────────
     * The reporter's classifier is a PURE function over struct mvp_evidence,
     * so seed known evidence and assert the eight criteria classify as
     * expected (incl. an "unknown" for a missing source) and the met_count
     * math. It must flip nothing true on its own: with all-absent evidence
     * every criterion is unknown and met_count is 0. */
    printf("mvp scoreboard classifier (zcl.mvp_status.v1)... ");
    {
        bool ok = true;
        #define MVP_FIND(arr_, id_) mvp_find_criterion((arr_), (id_))

        /* (1) All-absent evidence → 8x unknown, met_count 0, not ready. */
        {
            struct mvp_evidence ev;
            memset(&ev, 0, sizeof(ev));
            ev.c3_cold_sync_secs = -1;
            ev.c6_soak_window_hours = -1;
            ev.c6_slo_success_rate = -1.0;
            ev.c7_recovery_secs = -1;
            ev.c8_parity_mismatches = -1;

            struct json_value out = {0};
            ok = ok && mvp_build_status_json(&ev, &out);
            ok = ok && strcmp(json_get_str(json_get(&out, "schema")),
                              "zcl.mvp_status.v1") == 0;
            ok = ok && json_get_bool(json_get(&out, "reporter_only"));
            ok = ok && json_get_int(json_get(&out, "total")) == 8;
            ok = ok && json_get_int(json_get(&out, "met_count")) == 0;
            ok = ok && json_get_bool(json_get(&out, "ready_for_v1")) == false;

            const struct json_value *arr = json_get(&out, "criteria");
            ok = ok && arr && arr->type == JSON_ARR && json_size(arr) == 8;

            const char *ids[8] = {"C1","C2","C3","C4","C5","C6","C7","C8"};
            for (size_t i = 0; i < 8 && ok; i++) {
                const struct json_value *c = MVP_FIND(arr, ids[i]);
                ok = ok && c != NULL;
                /* met tri-state: unknown encodes as JSON null. */
                ok = ok && json_is_null(json_get(c, "met"));
                ok = ok && strcmp(json_get_str(json_get(c, "met_state")),
                                  "unknown") == 0;
                /* every unknown carries a named (non-empty) reason. */
                ok = ok && json_get_str(json_get(c, "reason"))[0] != '\0';
                /* evidence object with a named source is always present. */
                const struct json_value *e = json_get(c, "evidence");
                ok = ok && e && e->type == JSON_OBJ;
                ok = ok && json_get_str(json_get(e, "evidence_source"))[0]
                           != '\0';
            }
            /* C6 unknown reason must name the missing soak source. */
            {
                const struct json_value *c6 = MVP_FIND(arr, "C6");
                ok = ok && c6 &&
                     strstr(json_get_str(json_get(c6, "reason")),
                            "soak attestation service not initialized") != NULL;
            }
            json_free(&out);
        }

        /* (2) The four runtime-derivable criteria all MET; the four offline
         * operator-proof criteria stay unknown → met_count == 4. */
        {
            struct mvp_evidence ev;
            memset(&ev, 0, sizeof(ev));
            /* C3: a passing cold-start receipt within budget. */
            ev.c3_health_present = true;
            ev.c3_sync_state = SYNC_AT_TIP;
            ev.c3_log_head_gap = 0;
            ev.c3_sync_benchmark_receipt_present = true;
            ev.c3_cold_sync_secs = 120;
            /* C6: 168h+ clean healthy eligible window, no SLO probe. */
            ev.c6_soak_present = true;
            ev.c6_soak_last_healthy = true;
            ev.c6_soak_window_eligible = true;
            ev.c6_soak_window_hours = 200;
            ev.c6_slo_probe_present = false;
            ev.c6_slo_success_rate = -1.0;
            /* C7: a recovery drill within the 2min budget. */
            ev.c7_recovery_drill_present = true;
            ev.c7_recovery_secs = 30;
            /* C8: standing oracle at 0 mismatches, canary present not failing. */
            ev.c8_parity_present = true;
            ev.c8_parity_mismatches = 0;
            ev.c8_canary_present = true;
            ev.c8_canary_fail_active = false;

            struct json_value out = {0};
            ok = ok && mvp_build_status_json(&ev, &out);
            ok = ok && json_get_int(json_get(&out, "met_count")) == 4;
            ok = ok && json_get_bool(json_get(&out, "ready_for_v1")) == false;

            const struct json_value *arr = json_get(&out, "criteria");
            const char *met_ids[4] = {"C3","C6","C7","C8"};
            for (size_t i = 0; i < 4 && ok; i++) {
                const struct json_value *c = MVP_FIND(arr, met_ids[i]);
                ok = ok && c != NULL;
                /* met encodes as JSON true. */
                ok = ok && !json_is_null(json_get(c, "met")) &&
                     json_get_bool(json_get(c, "met")) == true;
                ok = ok && strcmp(json_get_str(json_get(c, "met_state")),
                                  "met") == 0;
                ok = ok && json_is_null(json_get(c, "blocker"));
            }
            /* The offline-proof criteria remain unknown (never silently met). */
            const char *unk_ids[4] = {"C1","C2","C4","C5"};
            for (size_t i = 0; i < 4 && ok; i++) {
                const struct json_value *c = MVP_FIND(arr, unk_ids[i]);
                ok = ok && c != NULL && json_is_null(json_get(c, "met")) &&
                     strcmp(json_get_str(json_get(c, "met_state")),
                            "unknown") == 0;
            }
            json_free(&out);
        }

        /* (3) Unmet-with-blocker branches: incomplete soak window, slow
         * recovery, latched canary FAIL. Each is met=false + named blocker. */
        {
            struct mvp_evidence ev;
            memset(&ev, 0, sizeof(ev));
            ev.c3_cold_sync_secs = -1;
            /* C6: healthy+eligible but only a 10h window → incomplete. */
            ev.c6_soak_present = true;
            ev.c6_soak_last_healthy = true;
            ev.c6_soak_window_eligible = true;
            ev.c6_soak_window_hours = 10;
            ev.c6_slo_success_rate = -1.0;
            /* C7: a recovery drill over the 2min budget. */
            ev.c7_recovery_drill_present = true;
            ev.c7_recovery_secs = 200;
            /* C8: canary latched FAIL. */
            ev.c8_parity_present = true;
            ev.c8_parity_mismatches = 0;
            ev.c8_canary_present = true;
            ev.c8_canary_fail_active = true;

            struct json_value out = {0};
            ok = ok && mvp_build_status_json(&ev, &out);
            ok = ok && json_get_int(json_get(&out, "met_count")) == 0;
            const struct json_value *arr = json_get(&out, "criteria");

            const struct json_value *c6 = MVP_FIND(arr, "C6");
            ok = ok && c6 && !json_is_null(json_get(c6, "met")) &&
                 json_get_bool(json_get(c6, "met")) == false;
            ok = ok && c6 && strcmp(json_get_str(json_get(c6, "met_state")),
                                    "unmet") == 0;
            ok = ok && c6 && strcmp(json_get_str(json_get(c6, "blocker")),
                                    "soak.window_incomplete") == 0;

            const struct json_value *c7 = MVP_FIND(arr, "C7");
            ok = ok && c7 && json_get_bool(json_get(c7, "met")) == false &&
                 strcmp(json_get_str(json_get(c7, "blocker")),
                        "recovery.too_slow") == 0;

            const struct json_value *c8 = MVP_FIND(arr, "C8");
            ok = ok && c8 && json_get_bool(json_get(c8, "met")) == false &&
                 strcmp(json_get_str(json_get(c8, "blocker")),
                        "consensus.replay_canary_failed") == 0;
            json_free(&out);
        }

        /* (4) NULL evidence is treated as all-absent (no crash, 8x unknown). */
        {
            struct json_value out = {0};
            ok = ok && mvp_build_status_json(NULL, &out);
            ok = ok && json_get_int(json_get(&out, "met_count")) == 0;
            ok = ok && json_size(json_get(&out, "criteria")) == 8;
            json_free(&out);
        }

        /* (5) The live dumper runs NULL-safe on an uninitialized node and
         * yields a well-formed schema object. */
        {
            struct json_value out = {0};
            ok = ok && mvp_dump_state_json(&out, NULL);
            ok = ok && strcmp(json_get_str(json_get(&out, "schema")),
                              "zcl.mvp_status.v1") == 0;
            ok = ok && json_size(json_get(&out, "criteria")) == 8;
            json_free(&out);
        }

        #undef MVP_FIND
        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    return failures;
}
