/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getservicehealth / healthcheck cases: chain-advance coordinator state, canonical mirror trust, and the bounded first-call health document.
 */

#include "test/syncdiag_rpc_fixture.h"

#include "services/bg_validation_service.h"

/* Sibling-private tally seam in bg_validation_verify_block.c — the block
 * verifier's one call per block. Driving it here plants the same
 * undo_missing_blocks value a real undo-less walk would. */
bool bg_validation_note_undo_skips(int64_t skips, bool verified_with_undo,
                                   uint64_t *blocks_out, uint64_t *txs_out);

/* One `validationstatus` call through the registered RPC table. */
static bool vs_call(struct rpc_table *tbl, struct json_value *out)
{
    struct json_value params;
    json_init(&params);
    json_set_object(&params);
    bool ok = rpc_table_execute(tbl, "validationstatus", &params, out);
    json_free(&params);
    return ok;
}

/* With no service at all the coverage fields must still be present and
 * fail-closed: a missing key can never be read as "verified". */
static bool vs_uninitialized_is_fail_closed(struct rpc_table *tbl)
{
    struct json_value r;
    json_init(&r);
    bool ok = vs_call(tbl, &r);
    ok = ok && strcmp(json_get_str(json_get(&r, "state")),
                      "not_initialized") == 0;
    ok = ok && json_get_int(json_get(&r, "script_verif_skipped_no_undo")) == 0;
    ok = ok && json_get_int(json_get(&r, "undo_missing_blocks")) == 0;
    ok = ok && json_get_bool(json_get(&r, "verification_incomplete"));
    json_free(&r);
    return ok;
}

/* A walk sitting at tip and reading COMPLETE, with 7 txs left unverified
 * across 2 blocks for want of undo: the undo term alone must make it
 * incomplete, and both counts must be reported. */
static bool vs_undo_gap_is_incomplete(struct rpc_table *tbl)
{
    struct json_value r;
    json_init(&r);
    bool ok = vs_call(tbl, &r);
    ok = ok && json_get_int(json_get(&r, "verified_height")) == 100;
    ok = ok && json_get_int(json_get(&r, "script_verif_skipped_no_undo")) == 7;
    ok = ok && json_get_int(json_get(&r, "undo_missing_blocks")) == 2;
    ok = ok && json_get_bool(json_get(&r, "verification_incomplete"));
    json_free(&r);
    return ok;
}

/* The verification_incomplete verdict for whatever progress is installed;
 * `called` reports that the RPC itself succeeded. */
static bool vs_reports_incomplete(struct rpc_table *tbl, bool *called)
{
    struct json_value r;
    json_init(&r);
    *called = vs_call(tbl, &r);
    bool incomplete = json_get_bool(json_get(&r, "verification_incomplete"));
    json_free(&r);
    return incomplete;
}

/* `validationstatus` is the RPC operators and the native fleet status call.
 * It reported verified_height 669755 with sigs_verified 0 on an index that
 * had no undo data at all, and nothing in the reply said the transparent
 * scripts had never been checked. Pin the coverage fields. */
static int syncdiag_case_validationstatus_coverage(void)
{
    int failures = 0;
    static struct bg_validation_service svc;
    struct bg_validation_service *saved = g_bg_validation;

    printf("validationstatus: names incomplete script coverage... ");
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_event_rpc_commands(&tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
    bg_validation_reset_undo_skip_stats();

    g_bg_validation = NULL;
    bool ok = vs_uninitialized_is_fail_closed(&tbl);

    memset(&svc, 0, sizeof(svc));
    atomic_store(&svc.progress.verified_height, 100);
    atomic_store(&svc.progress.chain_height, 100);
    atomic_store(&svc.progress.script_verif_skipped_no_undo, 7);
    atomic_store(&svc.progress.state, BG_VALIDATION_COMPLETE);
    g_bg_validation = &svc;
    uint64_t b = 0, t = 0;
    bg_validation_note_undo_skips(4, false, &b, &t);
    bg_validation_note_undo_skips(3, false, &b, &t);
    ok = ok && vs_undo_gap_is_incomplete(&tbl);

    /* A short walk with zero skips is incomplete for the other reason —
     * the predicate's height term, not the undo term. Clear the process
     * tally first, so the undo term cannot be what is carrying the verdict. */
    atomic_store(&svc.progress.script_verif_skipped_no_undo, 0);
    atomic_store(&svc.progress.verified_height, 99);
    bg_validation_reset_undo_skip_stats();
    bool called = false;
    ok = ok && vs_reports_incomplete(&tbl, &called) && called;

    /* And the undo term ALONE: a full walk reading COMPLETE with the
     * per-service skip counter at 0 — which is what a restart or a
     * bg_validation_reset() leaves — is still incomplete when this process
     * has watched a block advance with unverified scripts. */
    atomic_store(&svc.progress.verified_height, 100);
    uint64_t sb = 0, st = 0;
    bg_validation_note_undo_skips(1, false, &sb, &st);
    ok = ok && vs_reports_incomplete(&tbl, &called) && called;

    /* Full walk, no skips, COMPLETE, AND no undo-missing block tallied by
     * this process: only then is nothing this status can see missing. */
    bg_validation_reset_undo_skip_stats();
    ok = ok && !vs_reports_incomplete(&tbl, &called) && called;

    g_bg_validation = saved;
    bg_validation_reset_undo_skip_stats();
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

/* The invariant EVERY getsyncdetail reply must satisfy, whatever progress is
 * installed: a nonzero undo-missing tally and verification_incomplete=false
 * can never appear in the same object. Checked on every reply this case
 * reads, not only on the ones whose verdict is under test. */
static bool gsd_object_is_consistent(const struct json_value *bgv)
{
    if (json_get_int(json_get(bgv, "undo_missing_blocks")) > 0)
        return json_get_bool(json_get(bgv, "verification_incomplete"));
    return true;
}

/* getsyncdetail's bg_validation.verification_incomplete verdict for whatever
 * progress is installed. `called` reports that the RPC succeeded, that both
 * fields under test are present, and that the reply satisfies the invariant
 * above — so a false verdict is read off a real, self-consistent reply and
 * never off a missing section. */
static bool gsd_reports_incomplete(bool *called)
{
    struct json_value r;
    json_init(&r);
    bool ok = api_getsyncdetail(&r);
    const struct json_value *bgv = json_get(&r, "bg_validation");
    *called = ok && bgv != NULL &&
        json_get(bgv, "undo_missing_blocks") != NULL &&
        json_get(bgv, "verification_incomplete") != NULL &&
        gsd_object_is_consistent(bgv);
    bool incomplete = json_get_bool(json_get(bgv, "verification_incomplete"));
    json_free(&r);
    return incomplete;
}

/* `getsyncdetail` publishes undo_missing_blocks and verification_incomplete
 * into the SAME object. The two must never disagree: a reply naming a
 * nonzero undo-missing tally while calling verification complete says the
 * scripts were checked when this process watched them go unchecked. Same
 * fail-closed rule validationstatus carries, pinned on the sibling RPC. */
static int syncdiag_case_getsyncdetail_coverage(void)
{
    int failures = 0;
    static struct bg_validation_service svc;

    printf("getsyncdetail: undo gap alone fails coverage closed... ");
    memset(&svc, 0, sizeof(svc));
    atomic_store(&svc.progress.verified_height, 100);
    atomic_store(&svc.progress.chain_height, 100);
    atomic_store(&svc.progress.script_verif_skipped_no_undo, 0);
    atomic_store(&svc.progress.state, BG_VALIDATION_COMPLETE);
    rpc_health_set_state(NULL, &svc, NULL, NULL);
    bg_validation_reset_undo_skip_stats();

    /* The undo term ALONE: the per-service skip counter reads 0 — what a
     * restart or bg_validation_reset() leaves — while this process has
     * already watched a block advance without undo. */
    bool called = false;
    uint64_t b = 0, t = 0;
    bg_validation_note_undo_skips(3, false, &b, &t);
    bool ok = gsd_reports_incomplete(&called) && called;

    /* And the per-service counter alone, with the process tally clear. */
    bg_validation_reset_undo_skip_stats();
    atomic_store(&svc.progress.script_verif_skipped_no_undo, 7);
    ok = ok && gsd_reports_incomplete(&called) && called;

    /* A RUNNING walk mid-chain with neither term set: zero script skips,
     * zero undo-missing blocks, verified_height short of chain_height. It
     * is still incomplete — the heights term carries the verdict, because a
     * walk that has not reached the tip has verified nothing about the
     * blocks it has not reached. This is the case the old
     * `script_verif_skipped_no_undo > 0` verdict got wrong, and the reason
     * this RPC now shares validationstatus's predicate. */
    atomic_store(&svc.progress.script_verif_skipped_no_undo, 0);
    atomic_store(&svc.progress.verified_height, 42);
    atomic_store(&svc.progress.state, BG_VALIDATION_RUNNING);
    ok = ok && gsd_reports_incomplete(&called) && called;

    /* Neither term, walk at tip, state COMPLETE: only then may the reply
     * call coverage complete. */
    atomic_store(&svc.progress.verified_height, 100);
    atomic_store(&svc.progress.state, BG_VALIDATION_COMPLETE);
    ok = ok && !gsd_reports_incomplete(&called) && called;

    rpc_health_set_state(NULL, NULL, NULL, NULL);
    bg_validation_reset_undo_skip_stats();
    if (ok) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }
    return failures;
}

int syncdiag_cases_health(void)
{
    int failures = 0;

    printf("getservicehealth: exposes chain advance coordinator "
           "(RED)... ");
    {
        struct json_value result;
        json_init(&result);
        block_source_policy_reset_for_test();
        condition_engine_reset_for_testing();
        mirror_consensus_reset_for_test();
        mirror_consensus_set_enabled(true);
        mirror_consensus_record_blocker("body-hash-mismatch");
        bool seeded = block_source_policy_snapshot_offer_allowed(
            100, 10000, 10100, true, "manifest_ok", NULL);
        bool ok = seeded && api_getservicehealth(&result);
        const struct json_value *svc =
            find_service(&result, "chain_advance_coordinator");
        ok = ok && result.type == JSON_ARR && svc != NULL;
        ok = ok && json_get(svc, "authority") != NULL;
        ok = ok && json_get(svc, "decision") != NULL;
        ok = ok && json_get(svc, "selected_source") != NULL;
        ok = ok && json_get(svc, "selected_source_trust") != NULL;
        ok = ok && json_get(svc, "mirror_fallback_allowed") != NULL;
        ok = ok && json_get(svc, "activation_allowed") != NULL;
        ok = ok && json_get(svc, "best_header_height") != NULL;
        ok = ok && json_get(svc, "projection_height") != NULL;
        ok = ok && json_get(svc, "projection_lag") != NULL;
        ok = ok && json_get(svc, "projection_deferred") != NULL;
        ok = ok && json_get(svc, "projection_state") != NULL;
        ok = ok && json_get(svc, "projection_deferred_total") != NULL;
        ok = ok && json_get(svc, "last_projection_deferred_height") != NULL;
        ok = ok && json_get(svc, "last_projection_deferred_time") != NULL;
        ok = ok && json_get(svc, "last_projection_deferred_reason") != NULL;
        ok = ok && json_get(svc, "reason") != NULL;
        ok = ok && json_get(svc, "initialized") != NULL;
        ok = ok && json_get(svc, "has_connman") != NULL;
        ok = ok && json_get(svc, "has_main_state") != NULL;
        ok = ok && json_get(svc, "has_node_db") != NULL;
        const struct json_value *sources =
            svc ? json_get(svc, "sources") : NULL;
        const struct json_value *current_snapshot =
            find_source_json(sources, "snapshot");
        ok = ok && sources && sources->type == JSON_ARR;
        ok = ok && current_snapshot && current_snapshot->type == JSON_OBJ;
        ok = ok && json_get(current_snapshot, "selectable") != NULL;
        ok = ok && json_get(current_snapshot, "selection_blocker") != NULL;
        ok = ok && json_get(current_snapshot,
                            "score_target_lag_penalty") != NULL;
        ok = ok && json_get(current_snapshot,
                            "score_failure_penalty") != NULL;
        const struct json_value *has_last =
            svc ? json_get(svc, "has_last_decision") : NULL;
        const struct json_value *last =
            svc ? json_get(svc, "last_decision") : NULL;
        ok = ok && has_last && json_get_bool(has_last);
        ok = ok && last && last->type == JSON_OBJ;
        ok = ok && json_get(last, "op") != NULL &&
            strcmp(json_get_str(json_get(last, "op")),
                   "snapshot_offer") == 0;
        ok = ok && json_get(last, "selected_source_reason") != NULL &&
            strcmp(json_get_str(json_get(last, "selected_source_reason")),
                   "manifest_ok") == 0;
        ok = ok && json_get(last, "selected_source_selectable") != NULL;
        ok = ok && json_get_bool(json_get(
            last, "selected_source_selectable"));
        ok = ok && json_get(last,
                            "selected_source_selection_blocker") != NULL;
        ok = ok && strcmp(json_get_str(json_get(
            last, "selected_source_selection_blocker")), "") == 0;
        ok = ok && json_get(last, "selected_source_score_base") != NULL;
        ok = ok && json_get_int(json_get(
            last, "selected_source_score_base")) == 85;
        ok = ok && json_get(last,
                            "selected_source_score_target_lag_penalty")
                 != NULL;
        ok = ok && json_get_int(json_get(
            last, "selected_source_score_target_lag_penalty")) == 25;
        ok = ok && json_get(last,
                            "selected_source_score_failure_penalty") != NULL;
        ok = ok && json_get_int(json_get(
            last, "selected_source_score_failure_penalty")) == 0;
        const struct json_value *last_sources = json_get(last, "sources");
        const struct json_value *snapshot =
            find_source_json(last_sources, "snapshot");
        ok = ok && last_sources && last_sources->type == JSON_ARR;
        ok = ok && snapshot && snapshot->type == JSON_OBJ;
        ok = ok && json_get(snapshot, "trust") != NULL &&
            strcmp(json_get_str(json_get(snapshot, "trust")),
                   "native_snapshot_proof_validated") == 0;
        ok = ok && json_get(snapshot, "reason") != NULL &&
            strcmp(json_get_str(json_get(snapshot, "reason")),
                   "manifest_ok") == 0;

        json_free(&result);
        block_source_policy_reset_for_test();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("getservicehealth: exposes canonical mirror trust "
           "(RED)... ");
    {
        struct legacy_mirror_sync_stats stats;
        struct json_value result;

        sync_monitor_init();
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        mirror_consensus_set_enabled(true);
        mirror_consensus_record_override(200, "body-hash-mismatch");
        mirror_consensus_record_blocker("body-hash-mismatch");

        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.legacy_height = 200;
        stats.local_height = 199;
        stats.target_height = 200;
        stats.stalls_total = 3;
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "body-hash-mismatch");
        legacy_mirror_sync_test_set_stats(&stats, NULL);

        json_init(&result);
        bool ok = api_getservicehealth(&result);
        const struct json_value *svc = find_service(&result, "legacy_mirror");
        ok = ok && result.type == JSON_ARR && svc != NULL;
        ok = ok && json_get(svc, "state") != NULL &&
            strcmp(json_get_str(json_get(svc, "state")), "blocked") == 0;
        ok = ok && json_get(svc, "consensus_authority") != NULL &&
            strcmp(json_get_str(json_get(svc, "consensus_authority")),
                   "local_consensus_validation") == 0;
        ok = ok && json_get(svc, "candidate_source") != NULL &&
            strcmp(json_get_str(json_get(svc, "candidate_source")),
                   "legacy_advisory") == 0;
        ok = ok && json_get(svc, "mirror_authorization_enabled") == NULL;
        ok = ok && json_get(svc, "mirror_source_trust") == NULL;
        ok = ok && json_get(svc, "candidate_trust") != NULL &&
            strcmp(json_get_str(json_get(svc, "candidate_trust")),
                   "bounded_advisory_fallback") == 0;
        ok = ok && json_get(svc, "candidate_lag_observed") != NULL &&
            json_is_null(json_get(svc, "candidate_lag_observed"));
        ok = ok && json_get(svc, "candidate_lag") != NULL &&
            json_get_int(json_get(svc, "candidate_lag")) == 0;
        ok = ok && json_get(svc, "tip_hashes_agree") != NULL &&
            !json_get_bool(json_get(svc, "tip_hashes_agree"));
        ok = ok && json_get(svc, "blocker_recovered_by_tip_agreement") !=
                 NULL &&
            !json_get_bool(json_get(
                svc, "blocker_recovered_by_tip_agreement"));
        ok = ok && json_get(svc, "mirror_monitor_running") != NULL &&
            json_get_bool(json_get(svc, "mirror_monitor_running"));
        ok = ok && json_get(svc, "zclassicd_rpc_transport_reachable") != NULL &&
            json_get_bool(json_get(svc, "zclassicd_rpc_transport_reachable"));
        ok = ok && json_get(svc, "legacy_oracle_usable") != NULL &&
            !json_get_bool(json_get(svc, "legacy_oracle_usable"));
        ok = ok && json_get(svc, "zclassicd_rpc_error_code") != NULL &&
            json_get_int(json_get(svc, "zclassicd_rpc_error_code")) == 0;
        ok = ok && json_get(svc, "zclassicd_rpc_error_message") != NULL &&
            strcmp(json_get_str(json_get(svc,
                                         "zclassicd_rpc_error_message")),
                   "") == 0;
        ok = ok && json_get(svc, "candidate_blocker") != NULL &&
            strcmp(json_get_str(json_get(svc, "candidate_blocker")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(svc, "candidate_blocker_scope") != NULL &&
            strcmp(json_get_str(json_get(svc, "candidate_blocker_scope")),
                   "advisory_source") == 0;
        ok = ok && json_get(svc, "activation_blocker") != NULL &&
            strcmp(json_get_str(json_get(svc, "activation_blocker")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(svc, "last_blocker_code") != NULL &&
            strcmp(json_get_str(json_get(svc, "last_blocker_code")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(svc,
                             "legacy_advisory_gated_by_native_retries") != NULL;
        ok = ok && json_get(svc,
                             "mirror_repair_gated_by_local_retries") != NULL;
        ok = ok && json_get(svc, "local_retries_exhausted") != NULL;
        ok = ok && json_get(svc, "overrides_total") != NULL;
        ok = ok && json_get(svc, "unsafe_overrides_total") != NULL &&
            json_get_int(json_get(svc, "unsafe_overrides_total")) == 1;
        ok = ok && json_get(svc, "last_override_safe") != NULL &&
            !json_get_bool(json_get(svc, "last_override_safe"));
        ok = ok && json_get(svc, "last_override_reason") != NULL &&
            strcmp(json_get_str(json_get(svc, "last_override_reason")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(svc, "last_override_scope") != NULL &&
            strcmp(json_get_str(json_get(svc, "last_override_scope")),
                   "unsafe_no_authorized_scope") == 0;
        ok = ok && json_get(svc, "blockers_total") != NULL &&
            json_get_int(json_get(svc, "blockers_total")) == 1;
        ok = ok && json_get(svc, "stalls_total") != NULL &&
            json_get_int(json_get(svc, "stalls_total")) == 3;
        ok = ok && json_get(svc, "lag_observed") != NULL &&
            json_is_null(json_get(svc, "lag_observed"));
        ok = ok && json_get(svc, "lag") != NULL &&
            json_get_int(json_get(svc, "lag")) == 0;

        json_free(&result);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
    }

    printf("healthcheck: exposes chain advance decision "
           "(RED)... ");
    {
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        register_event_rpc_commands(&tbl);
        if (rpc_is_in_warmup(NULL, 0))
            set_rpc_warmup_finished();

        struct json_value params;
        json_init(&params);
        json_set_object(&params);
        json_push_kv_bool(&params, "full", true);

        struct json_value result;
        json_init(&result);

        block_source_policy_reset_for_test();
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        struct legacy_mirror_sync_stats stats;
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = false;
        stats.legacy_height = 0;
        stats.local_height = 3157703;
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "rpc-unreachable");
        snprintf(stats.last_error, sizeof(stats.last_error),
                 "%s", "connect failed");
        legacy_mirror_sync_test_set_stats(&stats, NULL);
        mirror_consensus_set_enabled(true);
        mirror_consensus_record_override(100, "body-hash-mismatch");
        mirror_consensus_record_blocker("body-hash-mismatch");
        bool seeded = block_source_policy_snapshot_offer_allowed(
            100, 10000, 10100, true, "manifest_ok", NULL);
        bool executed = rpc_table_execute(&tbl, "healthcheck",
                                          &params, &result);

        const struct json_value *checks = json_get(&result, "checks");
        const struct json_value *ca =
            checks ? json_get(checks, "chain_advance") : NULL;
        const struct json_value *ce =
            checks ? json_get(checks, "chain_evidence") : NULL;
        const struct json_value *condition_engine =
            checks ? json_get(checks, "condition_engine") : NULL;
        bool ok = seeded && executed && result.type == JSON_OBJ;
        ok = ok && json_get(&result, "build_commit") != NULL &&
            strcmp(json_get_str(json_get(&result, "build_commit")),
                   zcl_build_commit()) == 0;
        ok = ok && checks && checks->type == JSON_OBJ;
        ok = ok && json_get(checks, "error_total") != NULL;
        ok = ok && json_get(checks, "last_error_age_seconds") != NULL;
        ok = ok && json_get(checks, "last_error_recent") != NULL;
        ok = ok && json_get(&result, "candidate_lag_known") != NULL &&
            !json_get_bool(json_get(&result, "candidate_lag_known"));
        ok = ok && json_get(&result, "candidate_lag_valid") != NULL &&
            !json_get_bool(json_get(&result, "candidate_lag_valid"));
        ok = ok && json_get(&result, "mirror_tip_hashes_agree") != NULL &&
            !json_get_bool(json_get(&result, "mirror_tip_hashes_agree"));
        ok = ok && json_get(&result,
                            "mirror_blocker_recovered_by_tip_agreement")
                 != NULL &&
            !json_get_bool(json_get(
                &result, "mirror_blocker_recovered_by_tip_agreement"));
        ok = ok && json_get(&result, "candidate_lag") != NULL &&
            json_get_int(json_get(&result, "candidate_lag")) == 0;
        ok = ok && json_get(&result, "candidate_lag_observed") != NULL &&
            json_is_null(json_get(&result, "candidate_lag_observed"));
        ok = ok && json_get(&result, "mirror_lag") != NULL &&
            json_get_int(json_get(&result, "mirror_lag")) == 0;
        ok = ok && json_get(&result, "mirror_lag_observed") != NULL &&
            json_is_null(json_get(&result, "mirror_lag_observed"));
        ok = ok && json_get(&result, "mirror_monitor_running") != NULL &&
            json_get_bool(json_get(&result, "mirror_monitor_running"));
        ok = ok && json_get(&result,
                            "zclassicd_rpc_transport_reachable") != NULL &&
            !json_get_bool(json_get(&result,
                                    "zclassicd_rpc_transport_reachable"));
        ok = ok && json_get(&result, "legacy_oracle_usable") != NULL &&
            !json_get_bool(json_get(&result, "legacy_oracle_usable"));
        ok = ok && json_get(&result, "zclassicd_rpc_error_code") != NULL &&
            json_get_int(json_get(&result, "zclassicd_rpc_error_code")) == 0;
        ok = ok && json_get(&result,
                            "zclassicd_rpc_error_message") != NULL &&
            strcmp(json_get_str(json_get(
                       &result, "zclassicd_rpc_error_message")),
                   "connect failed") == 0;
        ok = ok && json_get(&result, "mirror_rpc_errors") != NULL &&
            json_get_int(json_get(&result, "mirror_rpc_errors")) == 0;
        ok = ok && json_get(&result, "mirror_active_error_code") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "mirror_active_error_code")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(&result, "mirror_active_error_detail") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "mirror_active_error_detail")),
                   "connect failed") == 0;
        ok = ok && json_get(&result, "candidate_blocker") != NULL &&
            strcmp(json_get_str(json_get(&result, "candidate_blocker")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(&result, "candidate_blocker_scope") != NULL &&
            strcmp(json_get_str(json_get(
                       &result, "candidate_blocker_scope")),
                   "active_or_safety") == 0;
        ok = ok && json_get(&result, "legacy_advisory_blocker") != NULL &&
            strcmp(json_get_str(json_get(
                       &result, "legacy_advisory_blocker")),
                   "body-hash-mismatch") == 0;
        ok = ok && json_get(&result, "mirror_blockers_total") != NULL &&
            json_get_int(json_get(&result, "mirror_blockers_total")) == 1;
        ok = ok && json_get(&result, "mirror_stalls_total") != NULL &&
            json_get_int(json_get(&result, "mirror_stalls_total")) == 0;
        ok = ok && json_get(&result,
                            "mirror_unsafe_overrides_total") != NULL &&
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
        ok = ok && json_get(&result, "mirror_activation_blocker") != NULL &&
            strcmp(json_get_str(json_get(&result,
                                         "mirror_activation_blocker")),
                   "body-hash-mismatch") == 0;
        ok = ok && condition_engine && condition_engine->type == JSON_OBJ;
        ok = ok && json_get(condition_engine, "registered_count") != NULL;
        ok = ok && json_get(condition_engine, "active_count") != NULL;
        ok = ok && json_get(condition_engine, "unresolved_count") != NULL;
        ok = ok && json_get(condition_engine, "conditions") != NULL;
        ok = ok && ce && ce->type == JSON_OBJ;
        ok = ok && json_get(ce, "state") != NULL;
        ok = ok && json_get(ce, "publish_state") != NULL;
        ok = ok && json_get(ce, "active_tip_source_class") != NULL;
        ok = ok && json_get(ce, "active_tip") != NULL;
        ok = ok && json_get(ce, "header_tip") != NULL;
        ok = ok && json_get(ce, "persisted_active_tip") != NULL;
        ok = ok && json_get(ce, "utxo_max_height") != NULL;
        ok = ok && json_get(ce, "coins_best_block_height") != NULL;
        ok = ok && json_get(ce, "csr_sqlite_max_height") != NULL;
        ok = ok && json_get(ce, "missing_active_tip_evidence") != NULL;
        ok = ok && json_get(ce, "publish_state_not_local") != NULL;
        ok = ok && json_get(ce, "active_tip_hash_mismatch") != NULL;
        ok = ok && json_get(ce, "csr_cursor_mismatch") != NULL;
        ok = ok && ca && ca->type == JSON_OBJ;
        ok = ok && json_get(ca, "authority") != NULL;
        ok = ok && json_get(ca, "decision") != NULL;
        ok = ok && json_get(ca, "selected_source") != NULL;
        ok = ok && json_get(ca, "selected_source_trust") != NULL;
        ok = ok && json_get(ca, "mirror_fallback_allowed") != NULL;
        ok = ok && json_get(ca, "activation_allowed") != NULL;
        ok = ok && json_get(ca, "best_header_height") != NULL;
        ok = ok && json_get(ca, "projection_height") != NULL;
        ok = ok && json_get(ca, "projection_lag") != NULL;
        ok = ok && json_get(ca, "projection_deferred") != NULL;
        ok = ok && json_get(ca, "projection_state") != NULL;
        ok = ok && json_get(ca, "projection_deferred_total") != NULL;
        ok = ok && json_get(ca, "last_projection_deferred_height") != NULL;
        ok = ok && json_get(ca, "last_projection_deferred_time") != NULL;
        ok = ok && json_get(ca, "last_projection_deferred_reason") != NULL;
        ok = ok && json_get(ca, "reason") != NULL;
        ok = ok && json_get(ca, "initialized") != NULL;
        ok = ok && json_get(ca, "has_connman") != NULL;
        ok = ok && json_get(ca, "has_main_state") != NULL;
        ok = ok && json_get(ca, "has_node_db") != NULL;
        const struct json_value *sources =
            ca ? json_get(ca, "sources") : NULL;
        const struct json_value *current_snapshot =
            find_source_json(sources, "snapshot");
        ok = ok && sources && sources->type == JSON_ARR;
        ok = ok && current_snapshot && current_snapshot->type == JSON_OBJ;
        ok = ok && json_get(current_snapshot, "selectable") != NULL;
        ok = ok && json_get(current_snapshot, "selection_blocker") != NULL;
        ok = ok && json_get(current_snapshot,
                            "score_target_lag_penalty") != NULL;
        ok = ok && json_get(current_snapshot,
                            "score_failure_penalty") != NULL;
        const struct json_value *has_last = json_get(ca, "has_last_decision");
        const struct json_value *last = json_get(ca, "last_decision");
        ok = ok && has_last && json_get_bool(has_last);
        ok = ok && last && last->type == JSON_OBJ;
        ok = ok && json_get(last, "op") != NULL &&
            strcmp(json_get_str(json_get(last, "op")),
                   "snapshot_offer") == 0;
        ok = ok && json_get(last, "selected_source_reason") != NULL &&
            strcmp(json_get_str(json_get(last, "selected_source_reason")),
                   "manifest_ok") == 0;
        ok = ok && json_get(last, "selected_source_selectable") != NULL;
        ok = ok && json_get_bool(json_get(
            last, "selected_source_selectable"));
        ok = ok && json_get(last,
                            "selected_source_selection_blocker") != NULL;
        ok = ok && strcmp(json_get_str(json_get(
            last, "selected_source_selection_blocker")), "") == 0;
        ok = ok && json_get(last, "selected_source_score_base") != NULL;
        ok = ok && json_get_int(json_get(
            last, "selected_source_score_base")) == 85;
        ok = ok && json_get(last,
                            "selected_source_score_target_lag_penalty")
                 != NULL;
        ok = ok && json_get_int(json_get(
            last, "selected_source_score_target_lag_penalty")) == 25;
        ok = ok && json_get(last,
                            "selected_source_score_failure_penalty") != NULL;
        ok = ok && json_get_int(json_get(
            last, "selected_source_score_failure_penalty")) == 0;
        const struct json_value *last_sources = json_get(last, "sources");
        const struct json_value *snapshot =
            find_source_json(last_sources, "snapshot");
        ok = ok && last_sources && last_sources->type == JSON_ARR;
        ok = ok && snapshot && snapshot->type == JSON_OBJ;
        ok = ok && json_get(snapshot, "trust") != NULL &&
            strcmp(json_get_str(json_get(snapshot, "trust")),
                   "native_snapshot_proof_validated") == 0;
        ok = ok && json_get(snapshot, "reason") != NULL &&
            strcmp(json_get_str(json_get(snapshot, "reason")),
                   "manifest_ok") == 0;

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
        json_free(&params);
        json_free(&result);
        block_source_policy_reset_for_test();
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
    }

    printf("healthcheck: default is bounded first-call JSON... ");
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

        bool executed = rpc_table_execute(&tbl, "healthcheck",
                                          &params, &result);
        const struct json_value *checks = json_get(&result, "checks");
        const struct json_value *agent = json_get(&result, "agent");
        const struct json_value *ca =
            checks ? json_get(checks, "chain_advance") : NULL;
        bool ok = executed && result.type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(&result, "schema")),
                          "zcl.healthcheck.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                          "consensus_authority")),
                          "local_consensus_validation") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                          "candidate_source")),
                          "agent_cached_summary") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                          "candidate_trust")),
                          "bounded_cached_status") == 0;
        ok = ok && strcmp(json_get_str(json_get(&result,
                          "result_completeness")), "bounded") == 0;
        ok = ok && json_get_bool(json_get(&result, "partial_result"));
        const struct json_value *first_call =
            json_get(&result, "first_call");
        ok = ok && first_call && first_call->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(first_call, "schema")),
                          "zcl.first_call_contract.v1") == 0;
        ok = ok && strcmp(json_get_str(json_get(first_call, "api")),
                          "healthcheck") == 0;
        ok = ok && strcmp(json_get_str(json_get(first_call,
                          "result_completeness")), "bounded") == 0;
        ok = ok && strcmp(json_get_str(json_get(first_call, "source")),
                          "agent_cached_summary") == 0;
        ok = ok && json_get_bool(json_get(first_call, "partial_result"));
        ok = ok && json_get_int(json_get(first_call, "budget_ms")) == 500;
        ok = ok && json_get(first_call, "elapsed_ms") != NULL;
        ok = ok && json_get(first_call, "budget_exceeded") != NULL;
        ok = ok && json_get(&result, "full_mode_command") != NULL;
        ok = ok && json_get(&result, "healthy") != NULL;
        ok = ok && json_get(&result, "serving") != NULL;
        ok = ok && json_get(&result, "readiness_status") != NULL;
        ok = ok && json_get(&result, "chain_serving_ready") != NULL;
        ok = ok && json_get(&result, "height_contract_status") != NULL;
        ok = ok && json_get(&result, "normal_lookahead") != NULL;
        ok = ok && json_get(&result, "sync_fsm_at_tip") != NULL;
        ok = ok && checks && checks->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(checks, "bounded"));
        ok = ok && json_get_bool(json_get(checks, "partial_result"));
        ok = ok && json_get(checks, "height_contract_status") != NULL;
        ok = ok && json_get(checks, "normal_lookahead") != NULL;
        ok = ok && json_get(checks, "sync_fsm_at_tip") != NULL;
        ok = ok && json_get(checks, "chain_serving_ready") != NULL;
        ok = ok && json_get(checks, "serving_ready") != NULL;
        ok = ok && json_get(checks, "index_projection_ready") != NULL;
        ok = ok && json_get(checks, "agent_work_ready") != NULL;
        ok = ok && json_get(checks, "peer_count") != NULL;
        ok = ok && json_get(checks, "log_head") != NULL;
        ok = ok && json_get(checks, "chain_evidence") == NULL;
        ok = ok && ca && ca->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(ca, "source")),
                          "cached_first_call") == 0;
        ok = ok && json_get(ca, "block_source_status_cached") != NULL;
        ok = ok && agent && agent->type == JSON_OBJ;
        ok = ok && strcmp(json_get_str(json_get(agent, "schema")),
                          "zcl.public_status.v3") == 0;

        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
        json_free(&params);
        json_free(&result);
    }

    failures += syncdiag_case_validationstatus_coverage();
    failures += syncdiag_case_getsyncdetail_coverage();

    return failures;
}
