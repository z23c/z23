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

/* One field expectation, walked in source order. A miss stops the walk,
 * matching `ok = ok && ...`. STR, INT, BOOL and IS_NULL look the key up
 * again for the value compare, as each original check did. */
enum {
    SYNC_HEALTH_PRESENT = 1,
    SYNC_HEALTH_ABSENT,
    SYNC_HEALTH_STR,
    SYNC_HEALTH_INT,
    SYNC_HEALTH_BOOL,
    SYNC_HEALTH_IS_NULL
};

struct sync_health_expect {
    const char *key;
    int kind;
    bool want_bool;
    int64_t want_int;
    const char *want_str;
};

static bool sync_health_expect_holds(const struct json_value *obj,
                                    const struct sync_health_expect *e)
{
    const struct json_value *v = json_get(obj, e->key);
    if (e->kind == SYNC_HEALTH_PRESENT)
        return v != NULL;
    if (e->kind == SYNC_HEALTH_ABSENT)
        return v == NULL;
    if (v == NULL)
        return false;
    if (e->kind == SYNC_HEALTH_STR)
        return strcmp(json_get_str(json_get(obj, e->key)), e->want_str) == 0;
    if (e->kind == SYNC_HEALTH_INT)
        return json_get_int(json_get(obj, e->key)) == e->want_int;
    if (e->kind == SYNC_HEALTH_BOOL)
        return json_get_bool(json_get(obj, e->key)) == e->want_bool;
    if (e->kind == SYNC_HEALTH_IS_NULL)
        return json_is_null(json_get(obj, e->key));
    return false;
}

static bool sync_health_expects_hold(const struct json_value *obj,
                                    const struct sync_health_expect *rows,
                                    size_t n)
{
    bool ok = true;
    for (size_t i = 0; i < n && ok; i++)
        ok = sync_health_expect_holds(obj, &rows[i]);
    return ok;
}

static bool sync_health_is_type(const struct json_value *v, enum json_type t)
{
    return v && v->type == t;
}

static bool sync_health_bool_is(const struct json_value *v, bool want)
{
    return v && json_get_bool(v) == want;
}

static bool sync_health_coordinator_keys(const struct json_value *svc)
{
    static const struct sync_health_expect keys[] = {
        { "authority", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "decision", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "selected_source", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "selected_source_trust", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "mirror_fallback_allowed", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "activation_allowed", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "best_header_height", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "projection_height", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "projection_lag", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "projection_deferred", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "projection_state", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "projection_deferred_total", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "last_projection_deferred_height", SYNC_HEALTH_PRESENT, false, 0,
          NULL },
        { "last_projection_deferred_time", SYNC_HEALTH_PRESENT, false, 0,
          NULL },
        { "last_projection_deferred_reason", SYNC_HEALTH_PRESENT, false, 0,
          NULL },
        { "reason", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "initialized", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "has_connman", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "has_main_state", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "has_node_db", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    return sync_health_expects_hold(svc, keys, sizeof(keys) / sizeof(keys[0]));
}

static bool sync_health_current_sources(bool ok, const struct json_value *svc)
{
    static const struct sync_health_expect rows[] = {
        { "selectable", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "selection_blocker", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "score_target_lag_penalty", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "score_failure_penalty", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    const struct json_value *sources =
        svc ? json_get(svc, "sources") : NULL;
    const struct json_value *current_snapshot =
        find_source_json(sources, "snapshot");
    ok = ok && sync_health_is_type(sources, JSON_ARR);
    ok = ok && sync_health_is_type(current_snapshot, JSON_OBJ);
    ok = ok && sync_health_expects_hold(current_snapshot, rows,
                                        sizeof(rows) / sizeof(rows[0]));
    return ok;
}

static bool sync_health_last_decision(bool ok,
                                     const struct json_value *has_last,
                                     const struct json_value *last)
{
    static const struct sync_health_expect last_rows[] = {
        { "op", SYNC_HEALTH_STR, false, 0, "snapshot_offer" },
        { "selected_source_reason", SYNC_HEALTH_STR, false, 0, "manifest_ok" },
        { "selected_source_selectable", SYNC_HEALTH_BOOL, true, 0, NULL },
        { "selected_source_selection_blocker", SYNC_HEALTH_STR, false, 0, "" },
        { "selected_source_score_base", SYNC_HEALTH_INT, false, 85, NULL },
        { "selected_source_score_target_lag_penalty", SYNC_HEALTH_INT, false,
          25, NULL },
        { "selected_source_score_failure_penalty", SYNC_HEALTH_INT, false, 0,
          NULL },
    };
    static const struct sync_health_expect snap_rows[] = {
        { "trust", SYNC_HEALTH_STR, false, 0,
          "native_snapshot_proof_validated" },
        { "reason", SYNC_HEALTH_STR, false, 0, "manifest_ok" },
    };
    ok = ok && sync_health_bool_is(has_last, true);
    ok = ok && sync_health_is_type(last, JSON_OBJ);
    ok = ok && sync_health_expects_hold(last, last_rows,
                                        sizeof(last_rows) / sizeof(last_rows[0]));
    const struct json_value *last_sources = json_get(last, "sources");
    const struct json_value *snapshot =
        find_source_json(last_sources, "snapshot");
    ok = ok && sync_health_is_type(last_sources, JSON_ARR);
    ok = ok && sync_health_is_type(snapshot, JSON_OBJ);
    ok = ok && sync_health_expects_hold(snapshot, snap_rows,
                                        sizeof(snap_rows) / sizeof(snap_rows[0]));
    return ok;
}

static bool gsh_chain_advance_coordinator_ok(void)
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
    ok = ok && sync_health_coordinator_keys(svc);
    ok = sync_health_current_sources(ok, svc);
    const struct json_value *has_last =
        svc ? json_get(svc, "has_last_decision") : NULL;
    const struct json_value *last =
        svc ? json_get(svc, "last_decision") : NULL;
    ok = sync_health_last_decision(ok, has_last, last);

    json_free(&result);
    block_source_policy_reset_for_test();
    return ok;
}

static bool gsh_canonical_mirror_trust_ok(void)
{
    static const struct sync_health_expect rows[] = {
        { "state", SYNC_HEALTH_STR, false, 0, "blocked" },
        { "consensus_authority", SYNC_HEALTH_STR, false, 0,
          "local_consensus_validation" },
        { "candidate_source", SYNC_HEALTH_STR, false, 0, "legacy_advisory" },
        { "mirror_authorization_enabled", SYNC_HEALTH_ABSENT, false, 0, NULL },
        { "mirror_source_trust", SYNC_HEALTH_ABSENT, false, 0, NULL },
        { "candidate_trust", SYNC_HEALTH_STR, false, 0,
          "bounded_advisory_fallback" },
        { "candidate_lag_observed", SYNC_HEALTH_IS_NULL, false, 0, NULL },
        { "candidate_lag", SYNC_HEALTH_INT, false, 0, NULL },
        { "tip_hashes_agree", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "blocker_recovered_by_tip_agreement", SYNC_HEALTH_BOOL, false, 0,
          NULL },
        { "mirror_monitor_running", SYNC_HEALTH_BOOL, true, 0, NULL },
        { "zclassicd_rpc_transport_reachable", SYNC_HEALTH_BOOL, true, 0,
          NULL },
        { "legacy_oracle_usable", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "zclassicd_rpc_error_code", SYNC_HEALTH_INT, false, 0, NULL },
        { "zclassicd_rpc_error_message", SYNC_HEALTH_STR, false, 0, "" },
        { "candidate_blocker", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "candidate_blocker_scope", SYNC_HEALTH_STR, false, 0,
          "advisory_source" },
        { "activation_blocker", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "last_blocker_code", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "legacy_advisory_gated_by_native_retries", SYNC_HEALTH_PRESENT,
          false, 0, NULL },
        { "mirror_repair_gated_by_local_retries", SYNC_HEALTH_PRESENT, false,
          0, NULL },
        { "local_retries_exhausted", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "overrides_total", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "unsafe_overrides_total", SYNC_HEALTH_INT, false, 1, NULL },
        { "last_override_safe", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "last_override_reason", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "last_override_scope", SYNC_HEALTH_STR, false, 0,
          "unsafe_no_authorized_scope" },
        { "blockers_total", SYNC_HEALTH_INT, false, 1, NULL },
        { "stalls_total", SYNC_HEALTH_INT, false, 3, NULL },
        { "lag_observed", SYNC_HEALTH_IS_NULL, false, 0, NULL },
        { "lag", SYNC_HEALTH_INT, false, 0, NULL },
    };
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
    ok = ok && sync_health_expects_hold(svc, rows,
                                        sizeof(rows) / sizeof(rows[0]));

    json_free(&result);
    legacy_mirror_sync_reset_for_test();
    mirror_consensus_reset_for_test();
    return ok;
}

static bool hc_build_and_check_fields(bool ok, const struct json_value *result,
                                     const struct json_value *checks)
{
    static const struct sync_health_expect check_rows[] = {
        { "error_total", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "last_error_age_seconds", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "last_error_recent", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    static const struct sync_health_expect result_rows[] = {
        { "candidate_lag_known", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "candidate_lag_valid", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "mirror_tip_hashes_agree", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "mirror_blocker_recovered_by_tip_agreement", SYNC_HEALTH_BOOL,
          false, 0, NULL },
        { "candidate_lag", SYNC_HEALTH_INT, false, 0, NULL },
        { "candidate_lag_observed", SYNC_HEALTH_IS_NULL, false, 0, NULL },
        { "mirror_lag", SYNC_HEALTH_INT, false, 0, NULL },
        { "mirror_lag_observed", SYNC_HEALTH_IS_NULL, false, 0, NULL },
        { "mirror_monitor_running", SYNC_HEALTH_BOOL, true, 0, NULL },
        { "zclassicd_rpc_transport_reachable", SYNC_HEALTH_BOOL, false, 0,
          NULL },
        { "legacy_oracle_usable", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "zclassicd_rpc_error_code", SYNC_HEALTH_INT, false, 0, NULL },
        { "zclassicd_rpc_error_message", SYNC_HEALTH_STR, false, 0,
          "connect failed" },
        { "mirror_rpc_errors", SYNC_HEALTH_INT, false, 0, NULL },
        { "mirror_active_error_code", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "mirror_active_error_detail", SYNC_HEALTH_STR, false, 0,
          "connect failed" },
        { "candidate_blocker", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "candidate_blocker_scope", SYNC_HEALTH_STR, false, 0,
          "active_or_safety" },
        { "legacy_advisory_blocker", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "mirror_blockers_total", SYNC_HEALTH_INT, false, 1, NULL },
        { "mirror_stalls_total", SYNC_HEALTH_INT, false, 0, NULL },
        { "mirror_unsafe_overrides_total", SYNC_HEALTH_INT, false, 1, NULL },
        { "mirror_last_override_safe", SYNC_HEALTH_BOOL, false, 0, NULL },
        { "mirror_last_override_reason", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
        { "mirror_last_override_scope", SYNC_HEALTH_STR, false, 0,
          "unsafe_no_authorized_scope" },
        { "mirror_activation_blocker", SYNC_HEALTH_STR, false, 0,
          "body-hash-mismatch" },
    };
    ok = ok && json_get(result, "build_commit") != NULL &&
        strcmp(json_get_str(json_get(result, "build_commit")),
               zcl_build_commit()) == 0;
    ok = ok && sync_health_is_type(checks, JSON_OBJ);
    ok = ok && sync_health_expects_hold(checks, check_rows,
                                        sizeof(check_rows) / sizeof(check_rows[0]));
    ok = ok && sync_health_expects_hold(result, result_rows,
                                        sizeof(result_rows) / sizeof(result_rows[0]));
    return ok;
}

static bool hc_engine_and_evidence(bool ok,
                                  const struct json_value *condition_engine,
                                  const struct json_value *ce)
{
    static const struct sync_health_expect engine_rows[] = {
        { "registered_count", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "active_count", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "unresolved_count", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "conditions", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    static const struct sync_health_expect ce_rows[] = {
        { "state", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "publish_state", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "active_tip_source_class", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "active_tip", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "header_tip", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "persisted_active_tip", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "utxo_max_height", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "coins_best_block_height", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "csr_sqlite_max_height", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "missing_active_tip_evidence", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "publish_state_not_local", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "active_tip_hash_mismatch", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "csr_cursor_mismatch", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    ok = ok && sync_health_is_type(condition_engine, JSON_OBJ);
    ok = ok && sync_health_expects_hold(condition_engine, engine_rows,
                                        sizeof(engine_rows) / sizeof(engine_rows[0]));
    ok = ok && sync_health_is_type(ce, JSON_OBJ);
    ok = ok && sync_health_expects_hold(ce, ce_rows,
                                        sizeof(ce_rows) / sizeof(ce_rows[0]));
    return ok;
}

static bool hc_advance_object(bool ok, const struct json_value *ca)
{
    ok = ok && sync_health_is_type(ca, JSON_OBJ);
    ok = ok && sync_health_coordinator_keys(ca);
    ok = sync_health_current_sources(ok, ca);
    const struct json_value *has_last = json_get(ca, "has_last_decision");
    const struct json_value *last = json_get(ca, "last_decision");
    return sync_health_last_decision(ok, has_last, last);
}

static bool hc_chain_advance_decision_ok(struct json_value *params,
                                        struct json_value *result)
{
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_event_rpc_commands(&tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    json_init(params);
    json_set_object(params);
    json_push_kv_bool(params, "full", true);

    json_init(result);

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
                                      params, result);

    const struct json_value *checks = json_get(result, "checks");
    const struct json_value *ca =
        checks ? json_get(checks, "chain_advance") : NULL;
    const struct json_value *ce =
        checks ? json_get(checks, "chain_evidence") : NULL;
    const struct json_value *condition_engine =
        checks ? json_get(checks, "condition_engine") : NULL;
    bool ok = seeded && executed && result->type == JSON_OBJ;
    ok = hc_build_and_check_fields(ok, result, checks);
    ok = hc_engine_and_evidence(ok, condition_engine, ce);
    ok = hc_advance_object(ok, ca);
    return ok;
}

static bool hc_bounded_result_identity(bool ok, const struct json_value *result)
{
    static const struct sync_health_expect rows[] = {
        { "schema", SYNC_HEALTH_STR, false, 0, "zcl.healthcheck.v1" },
        { "consensus_authority", SYNC_HEALTH_STR, false, 0,
          "local_consensus_validation" },
        { "candidate_source", SYNC_HEALTH_STR, false, 0,
          "agent_cached_summary" },
        { "candidate_trust", SYNC_HEALTH_STR, false, 0,
          "bounded_cached_status" },
        { "result_completeness", SYNC_HEALTH_STR, false, 0, "bounded" },
        { "partial_result", SYNC_HEALTH_BOOL, true, 0, NULL },
    };
    return ok && sync_health_expects_hold(result, rows,
                                          sizeof(rows) / sizeof(rows[0]));
}

static bool hc_bounded_first_call_block(bool ok,
                                       const struct json_value *result)
{
    static const struct sync_health_expect call_rows[] = {
        { "schema", SYNC_HEALTH_STR, false, 0, "zcl.first_call_contract.v1" },
        { "api", SYNC_HEALTH_STR, false, 0, "healthcheck" },
        { "result_completeness", SYNC_HEALTH_STR, false, 0, "bounded" },
        { "source", SYNC_HEALTH_STR, false, 0, "agent_cached_summary" },
        { "partial_result", SYNC_HEALTH_BOOL, true, 0, NULL },
        { "budget_ms", SYNC_HEALTH_INT, false, 500, NULL },
        { "elapsed_ms", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "budget_exceeded", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    static const struct sync_health_expect top_rows[] = {
        { "full_mode_command", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "healthy", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "serving", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "readiness_status", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "chain_serving_ready", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "height_contract_status", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "normal_lookahead", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "sync_fsm_at_tip", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    const struct json_value *first_call = json_get(result, "first_call");
    ok = ok && sync_health_is_type(first_call, JSON_OBJ);
    ok = ok && sync_health_expects_hold(first_call, call_rows,
                                        sizeof(call_rows) / sizeof(call_rows[0]));
    ok = ok && sync_health_expects_hold(result, top_rows,
                                        sizeof(top_rows) / sizeof(top_rows[0]));
    return ok;
}

static bool hc_bounded_tail(bool ok, const struct json_value *checks,
                           const struct json_value *ca,
                           const struct json_value *agent)
{
    static const struct sync_health_expect check_rows[] = {
        { "bounded", SYNC_HEALTH_BOOL, true, 0, NULL },
        { "partial_result", SYNC_HEALTH_BOOL, true, 0, NULL },
        { "height_contract_status", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "normal_lookahead", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "sync_fsm_at_tip", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "chain_serving_ready", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "serving_ready", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "index_projection_ready", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "agent_work_ready", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "peer_count", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "log_head", SYNC_HEALTH_PRESENT, false, 0, NULL },
        { "chain_evidence", SYNC_HEALTH_ABSENT, false, 0, NULL },
    };
    static const struct sync_health_expect ca_rows[] = {
        { "source", SYNC_HEALTH_STR, false, 0, "cached_first_call" },
        { "block_source_status_cached", SYNC_HEALTH_PRESENT, false, 0, NULL },
    };
    static const struct sync_health_expect agent_rows[] = {
        { "schema", SYNC_HEALTH_STR, false, 0, "zcl.public_status.v3" },
    };
    ok = ok && sync_health_is_type(checks, JSON_OBJ);
    ok = ok && sync_health_expects_hold(checks, check_rows,
                                        sizeof(check_rows) / sizeof(check_rows[0]));
    ok = ok && sync_health_is_type(ca, JSON_OBJ);
    ok = ok && sync_health_expects_hold(ca, ca_rows,
                                        sizeof(ca_rows) / sizeof(ca_rows[0]));
    ok = ok && sync_health_is_type(agent, JSON_OBJ);
    ok = ok && sync_health_expects_hold(agent, agent_rows,
                                        sizeof(agent_rows) / sizeof(agent_rows[0]));
    return ok;
}

static bool hc_bounded_first_call_ok(struct json_value *params,
                                    struct json_value *result)
{
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_event_rpc_commands(&tbl);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    json_init(params);
    json_set_array(params);

    json_init(result);

    bool executed = rpc_table_execute(&tbl, "healthcheck",
                                      params, result);
    const struct json_value *checks = json_get(result, "checks");
    const struct json_value *agent = json_get(result, "agent");
    const struct json_value *ca =
        checks ? json_get(checks, "chain_advance") : NULL;
    bool ok = executed && result->type == JSON_OBJ;
    ok = hc_bounded_result_identity(ok, result);
    ok = hc_bounded_first_call_block(ok, result);
    ok = hc_bounded_tail(ok, checks, ca, agent);
    return ok;
}

int syncdiag_cases_health(void)
{
    int failures = 0;

    printf("getservicehealth: exposes chain advance coordinator "
           "(RED)... ");
    if (gsh_chain_advance_coordinator_ok()) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }

    printf("getservicehealth: exposes canonical mirror trust "
           "(RED)... ");
    if (gsh_canonical_mirror_trust_ok()) printf("OK\n");
    else    { printf("FAIL\n"); failures++; }

    printf("healthcheck: exposes chain advance decision "
           "(RED)... ");
    {
        struct json_value params;
        struct json_value result;
        bool ok = hc_chain_advance_decision_ok(&params, &result);
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
        struct json_value params;
        struct json_value result;
        bool ok = hc_bounded_first_call_ok(&params, &result);
        if (ok) printf("OK\n");
        else    { printf("FAIL\n"); failures++; }
        json_free(&params);
        json_free(&result);
    }

    failures += syncdiag_case_validationstatus_coverage();
    failures += syncdiag_case_getsyncdetail_coverage();

    return failures;
}
