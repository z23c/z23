/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.land (tools/command/native_dev_land.c).
 *
 * Queue cases use isolated state and real git rigs, with the exact proof
 * replaced by ZCL_LAND_PROOF_STUB. Rebase, push, rows and locks use the
 * production paths. Watcher-admission cases separately use inert scheduler
 * fixtures to exercise structured arguments, refusal and a bounded timeout;
 * they cannot establish real watcher or proof readiness.
 *
 * The handler is called DIRECTLY, which is exactly what the CLI does after
 * input validation — and the input is additionally validated through the
 * real registry first, so a key the .def never declared is caught here
 * rather than passing in-process and failing from a shell.
 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"


#if !defined(_WIN32)
struct dlx_scope_case {
    struct dlx_rig rig;
    char queue[16384], origin[64], wt[1400];
    size_t queue_len;
};

static bool dlx_scope_state_matches(void)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    if (!g_dlx_state[0]) return false;
    if (xdg && xdg[0]) return strcmp(xdg, g_dlx_state) == 0;
    const char *home = getenv("HOME");
    char base[4096];
    if (!home || !home[0]) return false;
    int n = snprintf(base, sizeof(base), "%s/.local/state", home);
    return n > 0 && (size_t)n < sizeof(base) && strcmp(base, g_dlx_state) == 0;
}

static bool dlx_scope_fence_prepare(struct dlx_rig *rig, const char *tag,
                                    char base[64], char wt[1400], char tip[64])
{
    return dlx_scope_state_matches() && dlx_fence_prepare(rig, tag, base, wt, tip);
}

static int dlx_scope_isolation_guard(void)
{
    int failures = 0;
    char saved[1024] = "", other[512], path[1400], base[64], wt[1400], tip[64];
    struct dlx_rig rig = {0};
    struct stat info;
    TEST("land: scope preparation refuses absent or mismatched isolated state") {
        dlx_isolate("drive_seq_scope_guard");
        (void)snprintf(saved, sizeof(saved), "%s", g_dlx_state);
        test_make_tmpdir(other, sizeof(other), "dev_land", "scope_guard_other");
        ASSERT(setenv("XDG_STATE_HOME", other, 1) == 0);
        ASSERT(!dlx_scope_fence_prepare(&rig, "scope_guard_mismatch", base, wt, tip));
        (void)snprintf(path, sizeof(path), "%s/z23/dev/land/queue.jsonl", other);
        ASSERT(lstat(path, &info) != 0 && errno == ENOENT);
        ASSERT(setenv("XDG_STATE_HOME", saved, 1) == 0);
        g_dlx_state[0] = '\0';
        ASSERT(!dlx_scope_fence_prepare(&rig, "scope_guard_absent", base, wt, tip));
        (void)snprintf(path, sizeof(path), "%s/z23/dev/land/queue.jsonl", saved);
        ASSERT(lstat(path, &info) != 0 && errno == ENOENT);
        PASS();
    }
_test_next:;
    if (saved[0]) (void)snprintf(g_dlx_state, sizeof(g_dlx_state), "%s", saved);
    dlx_restore();
    return failures;
}

static bool dlx_scope_submit(const struct dlx_rig *rig, const char *tip)
{
    if (!dlx_scope_state_matches()) return false;
    struct dlx_call c;
    dlx_submit(&c, rig, tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

static bool dlx_scope_number(const char *old, const char *replacement,
                              const char *old_priority, const char *priority)
{
    return dlx_queue_field_once(old, old, replacement) &&
           dlx_queue_field_once(replacement, old_priority, priority);
}

static bool dlx_scope_terminal(struct dlx_scope_case *t, const char *state,
                                const char *base, const char *later)
{
    struct dlx_call c;
    dlx_begin(&c, "cancel");
    (void)json_push_kv_int(&c.input, "seq", 685);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok || strcmp(state, "cancelled") == 0) return ok;
    char land[1200], path[1400], row[4096], wire[4200];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    if (!dlx_chain_row(row, sizeof(row), 685, t->rig.clone, later, base,
                        state, 0, NULL, NULL)) return false;
    int n = snprintf(wire, sizeof(wire), "%s\n", row);
    return n > 0 && (size_t)n < sizeof(wire) && dlx_write(path, wire);
}

static bool dlx_scope_prepare(struct dlx_scope_case *t, const char *tag,
                               const char *terminal)
{
    char base[64], later[64];
    dlx_isolate(tag);
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    if (!dlx_rig_make(&t->rig, tag) || !dlx_origin_main(&t->rig, base) ||
        !dlx_scope_submit(&t->rig, t->rig.tip) ||
        !dlx_commit(t->rig.clone, "later.txt", "later\n", later) ||
        !dlx_scope_submit(&t->rig, later) ||
        !dlx_scope_number("\"seq\":1,", "\"seq\":674,",
                           "\"priority_seq\":1,", "\"priority_seq\":674,") ||
        !dlx_scope_number("\"seq\":2,", "\"seq\":685,",
                           "\"priority_seq\":2,", "\"priority_seq\":685,") ||
        (terminal && !dlx_scope_terminal(t, terminal, base, later)))
        return false;
    dlx_land_wt(t->wt, sizeof(t->wt));
    return dlx_queue_bytes(t->queue, sizeof(t->queue), &t->queue_len) &&
           dlx_origin_main(&t->rig, t->origin);
}


static bool dlx_scope_unchanged(const struct dlx_scope_case *t)
{
    char queue[16384], origin[64];
    size_t len = 0;
    struct stat info;
    return dlx_queue_bytes(queue, sizeof(queue), &len) && len == t->queue_len &&
           memcmp(queue, t->queue, len) == 0 &&
           dlx_origin_main(&t->rig, origin) && strcmp(origin, t->origin) == 0 &&
           lstat(t->wt, &info) != 0 && errno == ENOENT;
}

static int dlx_scope_refusal_case(int seq, const char *terminal,
                                  const char *reason)
{
    int failures = 0;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    TEST("land: named drive leaves another eligible row and its origin untouched") {
        ASSERT(dlx_scope_prepare(&t, "drive_seq_scope", terminal));
        opened = true;
        ASSERT(dlx_drive_seq(&c, seq));
        ASSERT(dlx_scope_unchanged(&t));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_REFUSED");
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_str(&c, "reason"), reason) != NULL);
        ASSERT_EQ(dlx_int(&c, "seq"), seq);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_scope_landed_target(void)
{
    int failures = 0;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    TEST("land: an already landed named target does not drive the live head") {
        ASSERT(dlx_scope_prepare(&t, "drive_seq_landed_scope", "landed"));
        opened = true;
        ASSERT(dlx_drive_seq(&c, 685) && dlx_ok(&c));
        ASSERT(dlx_scope_unchanged(&t));
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
        ASSERT_EQ(dlx_int(&c, "seq"), 685);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static bool dlx_scope_later_unchanged(const struct dlx_scope_case *t)
{
    char queue[16384];
    size_t len = 0;
    if (!dlx_queue_bytes(queue, sizeof(queue), &len)) return false;
    const char *before = strstr(t->queue, "{\"seq\":685,");
    const char *after = strstr(queue, "{\"seq\":685,");
    if (!before || !after) return false;
    const char *a = strchr(before, '\n'), *b = strchr(after, '\n');
    return a && b && a - before == b - after &&
           memcmp(before, after, (size_t)(a - before)) == 0;
}

static int dlx_scope_requested_head(void)
{
    int failures = 0;
    struct dlx_scope_case t = {0};
    struct dlx_call c;
    bool opened = false;
    TEST("land: named queue head still starts its own bounded proof") {
        ASSERT(dlx_scope_prepare(&t, "drive_seq_head_scope", NULL));
        opened = true;
        ASSERT(dlx_drive_seq(&c, 674));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_STOPPED");
        ASSERT_EQ(dlx_int(&c, "seq"), 674);
        ASSERT_EQ(dlx_int(&c, "rounds"), 6);
        ASSERT(dlx_scope_later_unchanged(&t));
        dlx_end(&c); opened = false;
        dlx_begin(&c, "status"); opened = true;
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *active = json_get(&c.reply.data, "in_flight");
        ASSERT(active && json_get_int(json_get(active, "seq")) == 674);
        const struct json_value *queued = dlx_arr(&c, "queued");
        ASSERT(queued && queued->num_children == 1);
        ASSERT_EQ(json_get_int(json_get(&queued->children[0], "seq")), 685);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&c);
    dlx_restore();
    return failures;
}

static int dlx_scope_shared_fence(void)
{
    int failures = 0;
    struct dlx_fence_case t = {0};
    char path[1400], before[32768], after[32768], old_head[64], head[64];
    size_t before_len = 0, after_len = 0;
    bool opened = false;
    TEST("land: named drive refuses a publication fence spanning another row") {
        dlx_isolate("drive_seq_fence_scope");
        ASSERT(dlx_scope_fence_prepare(&t.rig, "drive_seq_fence_scope", t.base, t.wt, t.successor));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor); opened = true;
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c));
        dlx_end(&t.c); opened = false;
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_landdir(t.land, sizeof(t.land));
        (void)snprintf(path, sizeof(path), "%s/fence.jsonl", t.land);
        ASSERT(dlx_slurp(path, before, sizeof(before), &before_len));
        ASSERT(dlx_origin_main(&t.rig, t.remote));
        const char *rev[] = { "rev-parse", "HEAD", NULL };
        ASSERT(dlx_git_out(t.wt, rev, old_head, sizeof(old_head)) == 0);
        opened = true;
        ASSERT(dlx_drive_seq(&t.c, 1));
        ASSERT_STR_EQ(dlx_err_code(&t.c), "DRIVE_REFUSED");
        ASSERT(strstr(dlx_str(&t.c, "reason"), "requested_seq=1 blocking_seq=2") != NULL);
        ASSERT(!t.c.reply.error.mutated);
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
        ASSERT(before_len == after_len && memcmp(before, after, before_len) == 0);
        ASSERT(dlx_origin_main(&t.rig, head));
        ASSERT_STR_EQ(head, t.remote);
        ASSERT(dlx_git_out(t.wt, rev, head, sizeof(head)) == 0);
        ASSERT_STR_EQ(head, old_head);
        PASS();
    }
_test_next:;
    if (opened) dlx_end(&t.c);
    dlx_restore();
    return failures;
}

static int test_dev_land_drive_seq_scope(void)
{
    return dlx_scope_refusal_case(685, NULL, "requested_seq=685 blocking_seq=674") +
           dlx_scope_refusal_case(999, "cancelled", "unknown_seq_999") +
           dlx_scope_refusal_case(685, "cancelled", "row_cancelled") +
           dlx_scope_landed_target() + dlx_scope_requested_head() +
           dlx_scope_shared_fence() + dlx_scope_isolation_guard();
}
#endif

/* The historical dispatcher's ordered invocation list. Each row remains an
 * indivisible scenario; shard processes own all environment, cwd and native
 * test-hook mutation. Portable rows 2–4 keep every shard nonempty on Windows.
 * The umbrella walks this list in its original order. */
#define DLX_SHARD_COUNT 4u
#define DLX_ALL_SHARDS DLX_SHARD_COUNT
#define DLX_UMBRELLA "test_dev_land"

#if !defined(_WIN32)
static int dlx_shard_row_071(void)
{
    return test_dev_land_competing_publish("step", "step", true);
}
static int dlx_shard_row_072(void)
{
    return test_dev_land_competing_publish("step", "drive", true);
}
static int dlx_shard_row_073(void)
{
    return test_dev_land_competing_publish("drive", "step", true);
}
static int dlx_shard_row_074(void)
{
    return test_dev_land_competing_publish("step", "drive", false);
}
static int dlx_shard_row_075(void)
{
    return test_dev_land_competing_publish("drive", "step", false);
}
static int dlx_shard_row_120(void)
{
    return test_dev_land_postpush_observation_missing(false);
}
static int dlx_shard_row_121(void)
{
    return test_dev_land_postpush_observation_missing(true);
}
static int dlx_shard_row_158(void)
{
    return test_dev_land_integrated_merge(false);
}
static int dlx_shard_row_159(void)
{
    return test_dev_land_integrated_merge(true);
}
#endif /* !defined(_WIN32) */

struct dlx_shard_case {
    const char *name;
    int (*run)(void);
    unsigned owner;
};

static const struct dlx_shard_case g_dlx_shard_cases[] = {
    {"dlx_publication_hold_cases()",
     dlx_publication_hold_cases, 0u},
    {"dlx_hold_legacy_case()",
     dlx_hold_legacy_case, 1u},
    {"dlx_guarded_priority_case()",
     dlx_guarded_priority_case, 2u},
    {"dlx_guarded_hold_mismatch_case()",
     dlx_guarded_hold_mismatch_case, 3u},
    {"dlx_hold_pushed_case()",
     dlx_hold_pushed_case, 0u},
    {"dlx_hold_malformed_case()",
     dlx_hold_malformed_case, 0u},
    {"dlx_hold_sealed_case()",
     dlx_hold_sealed_case, 0u},
    {"dlx_hold_lock_case()",
     dlx_hold_lock_case, 0u},
    {"dlx_hold_admissible_during_step()",
     dlx_hold_admissible_during_step, 0u},
    {"dlx_hold_survives_step_rewrite()",
     dlx_hold_survives_step_rewrite, 0u},
    {"dlx_launcher_join_cases()",
     dlx_launcher_join_cases, 0u},
    {"dlx_origin_config_cases()",
     dlx_origin_config_cases, 0u},
    {"dlx_attest_only_cases()",
     dlx_attest_only_cases, 0u},
    {"dlx_attest_bounded_wire_cases()",
     dlx_attest_bounded_wire_cases, 0u},
    {"dlx_attest_refusal_cases()",
     dlx_attest_refusal_cases, 0u},
    {"test_dev_land_signed_intent()",
     test_dev_land_signed_intent, 0u},
#if !defined(_WIN32)
    {"dlx_fence_cases()",
     dlx_fence_cases, 1u},
    {"dlx_fence_concurrent()",
     dlx_fence_concurrent, 0u},
    {"dlx_fence_negative_cases()",
     dlx_fence_negative_cases, 3u},
    {"test_dev_land_status_observation()",
     test_dev_land_status_observation, 0u},
#endif
    {"test_dev_land_signed_tamper()",
     test_dev_land_signed_tamper, 0u},
    {"test_dev_land_receipt_adversarial()",
     test_dev_land_receipt_adversarial, 0u},
    {"test_dev_land_signer_takeover()",
     test_dev_land_signer_takeover, 0u},
    {"test_dev_land_signed_stale()",
     test_dev_land_signed_stale, 0u},
    {"test_dev_land_signed_recovery()",
     test_dev_land_signed_recovery, 0u},
    {"test_dev_land_new_source_precheck()",
     test_dev_land_new_source_precheck, 0u},
    {"test_dev_land_drive_producer_reproof()",
     test_dev_land_drive_producer_reproof, 0u},
    {"test_dev_land_step_producer_recovery()",
     test_dev_land_step_producer_recovery, 0u},
#if !defined(_WIN32)
    {"test_dev_land_phase_mail_quiet()",
     test_dev_land_phase_mail_quiet, 0u},
#endif
    {"test_dev_land_phase_digest()",
     test_dev_land_phase_digest, 0u},
    {"test_dev_land_signed_lost_ack()",
     test_dev_land_signed_lost_ack, 0u},
    {"test_dev_land_signed_lost_race()",
     test_dev_land_signed_lost_race, 0u},
    {"test_dev_land_signed_lost_ack_resend()",
     test_dev_land_signed_lost_ack_resend, 0u},
    {"test_dev_land_signed_push_lost_race()",
     test_dev_land_signed_push_lost_race, 0u},
    {"test_dev_land_cancel_push_refused()",
     test_dev_land_cancel_push_refused, 0u},
    {"test_dev_land_push_declined()",
     test_dev_land_push_declined, 0u},
    {"test_dev_land_signed_publisher_death()",
     test_dev_land_signed_publisher_death, 0u},
#if !defined(_WIN32)
    {"test_dev_land_signed_crash_before_push()",
     test_dev_land_signed_crash_before_push, 0u},
    {"test_dev_land_signed_third_party_before_push()",
     test_dev_land_signed_third_party_before_push, 0u},
    {"test_dev_land_signed_unknown_not_retried_blind()",
     test_dev_land_signed_unknown_not_retried_blind, 0u},
    {"test_dev_land_two_candidates_same_base()",
     test_dev_land_two_candidates_same_base, 0u},
#endif
    {"test_dev_land_watcher_admission()",
     test_dev_land_watcher_admission, 0u},
    {"test_dev_land_long_proof_root()",
     test_dev_land_long_proof_root, 0u},
    {"test_dev_land_malformed_queue_refusal()",
     test_dev_land_malformed_queue_refusal, 0u},
    {"test_dev_land_chain_codec()",
     test_dev_land_chain_codec, 0u},
    {"test_dev_land_chain_relation()",
     test_dev_land_chain_relation, 0u},
    {"test_dev_land_malformed_priority_refusal()",
     test_dev_land_malformed_priority_refusal, 0u},
    {"test_dev_land_malformed_outcome_refusal()",
     test_dev_land_malformed_outcome_refusal, 0u},
    {"test_dev_land_exact_tree()",
     test_dev_land_exact_tree, 0u},
    {"test_dev_land_source_binding()",
     test_dev_land_source_binding, 0u},
#if !defined(_WIN32)
    {"test_dev_land_tree_types()",
     test_dev_land_tree_types, 0u},
    {"test_dev_land_tree_malformed()",
     test_dev_land_tree_malformed, 0u},
    {"test_dev_land_tree_replacements()",
     test_dev_land_tree_replacements, 0u},
    {"test_dev_land_tree_missing()",
     test_dev_land_tree_missing, 0u},
    {"test_dev_land_proof_evidence_test()",
     test_dev_land_proof_evidence_test, 0u},
    {"test_dev_land_resubmit_failed_pair()",
     test_dev_land_resubmit_failed_pair, 0u},
    {"test_dev_land_refusal_names_next_step()",
     test_dev_land_refusal_names_next_step, 0u},
    {"test_dev_land_proof_evidence_compile()",
     test_dev_land_proof_evidence_compile, 0u},
#endif
    {"dlx_case_registration()",
     dlx_case_registration, 1u},
    {"dlx_case_unknown_action()",
     dlx_case_unknown_action, 1u},
#if !defined(_WIN32)
    {"dlx_case_unsigned_tip()",
     dlx_case_unsigned_tip, 1u},
    {"dlx_case_checkout_location()",
     dlx_case_checkout_location, 1u},
    {"dlx_case_submit_status()",
     dlx_case_submit_status, 1u},
    {"dlx_case_duplicate_submit()",
     dlx_case_duplicate_submit, 1u},
    {"dlx_case_precheck()",
     dlx_case_precheck, 1u},
    {"dlx_case_empty_step()",
     dlx_case_empty_step, 1u},
    {"dlx_case_step_lock()",
     dlx_case_step_lock, 1u},
    {"dlx_case_starts_proof()",
     dlx_case_starts_proof, 1u},
    {"dlx_case_absent_watcher()",
     dlx_case_absent_watcher, 1u},
    {"dlx_case_unarmed_proof()",
     dlx_case_unarmed_proof, 1u},
    {"test_dev_land_missing_worker()",
     test_dev_land_missing_worker, 1u},
    {"test_dev_land_interrupted_proof()",
     test_dev_land_interrupted_proof, 1u},
#if !defined(_WIN32)
    {"test_dev_land_drive_base_watch()",
     test_dev_land_drive_base_watch, 1u},
#endif
    {"test_dev_land_competing_publish(\"step\", \"step\", true)",
     dlx_shard_row_071, 1u},
    {"test_dev_land_competing_publish(\"step\", \"drive\", true)",
     dlx_shard_row_072, 1u},
    {"test_dev_land_competing_publish(\"drive\", \"step\", true)",
     dlx_shard_row_073, 1u},
    {"test_dev_land_competing_publish(\"step\", \"drive\", false)",
     dlx_shard_row_074, 1u},
    {"test_dev_land_competing_publish(\"drive\", \"step\", false)",
     dlx_shard_row_075, 1u},
    {"test_dev_land_bounded_drive()",
     test_dev_land_bounded_drive, 1u},
    {"test_dev_land_drive_seq_lands()",
     test_dev_land_drive_seq_lands, 1u},
    {"test_dev_land_drive_seq_scope()",
     test_dev_land_drive_seq_scope, 1u},
    {"test_dev_land_drive_seq_refusals()",
     test_dev_land_drive_seq_refusals, 1u},
    {"test_dev_land_drive_seq_proof_failed()",
     test_dev_land_drive_seq_proof_failed, 1u},
    {"test_dev_land_drive_seq_stops()",
     test_dev_land_drive_seq_stops, 1u},
    {"test_dev_land_prove_drive1()",
     test_dev_land_prove_drive1, 1u},
    {"test_dev_land_prove_drive2()",
     test_dev_land_prove_drive2, 1u},
    {"test_dev_land_prove_drive3()",
     test_dev_land_prove_drive3, 1u},
    {"test_dev_land_prove_drive4()",
     test_dev_land_prove_drive4, 1u},
    {"test_dev_land_prove_drive5()",
     test_dev_land_prove_drive5, 1u},
    {"test_dev_land_prove_drive6()",
     test_dev_land_prove_drive6, 1u},
    {"test_dev_land_qualify_make_caps()",
     test_dev_land_qualify_make_caps, 1u},
    {"test_dev_land_qualify_canonical_aliases()",
     test_dev_land_qualify_canonical_aliases, 1u},
    {"test_dev_land_qualify_unregistered_group()",
     test_dev_land_qualify_unregistered_group, 1u},
    {"test_dev_land_qualify_passes()",
     test_dev_land_qualify_passes, 1u},
    {"test_dev_land_qualify_job_caps()",
     test_dev_land_qualify_job_caps, 1u},
    {"test_dev_land_qualify_complexity()",
     test_dev_land_qualify_complexity, 1u},
    {"test_dev_land_qualify_verdict_rule()",
     test_dev_land_qualify_verdict_rule, 1u},
    {"test_dev_land_qualify_refusals()",
     test_dev_land_qualify_refusals, 1u},
    {"test_dev_land_qualify_dirty_tree()",
     test_dev_land_qualify_dirty_tree, 1u},
    {"test_dev_land_qualify_stale_doc_refused()",
     test_dev_land_qualify_stale_doc_refused, 1u},
    {"test_dev_land_qualify_group_verdicts()",
     test_dev_land_qualify_group_verdicts, 1u},
    {"test_dev_land_qualify_groups_reported()",
     test_dev_land_qualify_groups_reported, 1u},
    {"test_dev_land_qualify_selection_refusals()",
     test_dev_land_qualify_selection_refusals, 1u},
    {"test_dev_land_qualify_origin_moves()",
     test_dev_land_qualify_origin_moves, 1u},
    {"test_dev_land_qualify_rebase_and_fetch_failures()",
     test_dev_land_qualify_rebase_and_fetch_failures, 1u},
    {"test_dev_land_drive_seq_landed_reply_stands_alone()",
     test_dev_land_drive_seq_landed_reply_stands_alone, 1u},
    {"test_dev_land_stubs_are_test_build_only()",
     test_dev_land_stubs_are_test_build_only, 1u},
    {"dlx_case_stub_detail()",
     dlx_case_stub_detail, 2u},
    {"dlx_case_lands_proof()",
     dlx_case_lands_proof, 2u},
    {"dlx_case_hook_refusal()",
     dlx_case_hook_refusal, 2u},
    {"dlx_case_proof_failure()",
     dlx_case_proof_failure, 2u},
    {"dlx_case_timing_detail()",
     dlx_case_timing_detail, 2u},
    {"dlx_case_moved_base()",
     dlx_case_moved_base, 2u},
    {"test_dev_land_explicit_main()",
     test_dev_land_explicit_main, 2u},
    {"test_dev_land_stale_file_retests()",
     test_dev_land_stale_file_retests, 2u},
    {"test_dev_land_missing_main()",
     test_dev_land_missing_main, 2u},
    {"test_dev_land_initial_remote_missing()",
     test_dev_land_initial_remote_missing, 2u},
    {"test_dev_land_final_observation_missing()",
     test_dev_land_final_observation_missing, 2u},
    {"dlx_case_cancel_request()",
     dlx_case_cancel_request, 2u},
    {"dlx_case_concurrent_submit()",
     dlx_case_concurrent_submit, 2u},
    {"dlx_case_dense_detail()",
     dlx_case_dense_detail, 2u},
    {"test_dev_land_publisher_death()",
     test_dev_land_publisher_death, 2u},
    {"test_dev_land_drain_adoption()",
     test_dev_land_drain_adoption, 2u},
    {"test_dev_land_postpush_observation_missing(false)",
     dlx_shard_row_120, 2u},
    {"test_dev_land_postpush_observation_missing(true)",
     dlx_shard_row_121, 2u},
    {"test_dev_land_prepush_checkpoint()",
     test_dev_land_prepush_checkpoint, 2u},
    {"test_dev_land_prepush_persist_refusal()",
     test_dev_land_prepush_persist_refusal, 2u},
    {"test_dev_land_prepush_sync_refusal()",
     test_dev_land_prepush_sync_refusal, 2u},
    {"test_dev_land_missing_publication_intent()",
     test_dev_land_missing_publication_intent, 2u},
    {"test_dev_land_attach_target_cases()",
     test_dev_land_attach_target_cases, 2u},
    {"test_dev_land_postpush_result_unconfirmed()",
     test_dev_land_postpush_result_unconfirmed, 2u},
    {"test_dev_land_expected_base_race()",
     test_dev_land_expected_base_race, 2u},
    {"test_dev_land_recovery_ignores_replace_refs()",
     test_dev_land_recovery_ignores_replace_refs, 2u},
    {"test_dev_land_nonfastforward_client_guard()",
     test_dev_land_nonfastforward_client_guard, 2u},
    {"test_dev_land_lost_persistence()",
     test_dev_land_lost_persistence, 2u},
    {"test_dev_land_after_proof_restart()",
     test_dev_land_after_proof_restart, 2u},
    {"test_dev_land_objectives_snapshot()",
     test_dev_land_objectives_snapshot, 2u},
    {"test_dev_land_objectives_append_blocked()",
     test_dev_land_objectives_append_blocked, 2u},
    {"test_dev_land_objectives_failed_outcome()",
     test_dev_land_objectives_failed_outcome, 2u},
    {"test_dev_land_terminal_replay()",
     test_dev_land_terminal_replay, 2u},
    {"test_dev_land_outcome_visible_in_mail()",
     test_dev_land_outcome_visible_in_mail, 2u},
    {"dlx_case_missing_hook()",
     dlx_case_missing_hook, 2u},
    {"dlx_case_cancel_race()",
     dlx_case_cancel_race, 2u},
    {"dlx_case_aged_successor()",
     dlx_case_aged_successor, 2u},
    {"test_dev_land_main_moves_converge()",
     test_dev_land_main_moves_converge, 2u},
    {"dlx_case_option_path()",
     dlx_case_option_path, 2u},
    {"test_dev_land_vendor_dependencies()",
     test_dev_land_vendor_dependencies, 2u},
    {"dlx_case_dependency_links()",
     dlx_case_dependency_links, 2u},
    {"dlx_case_missing_dependency()",
     dlx_case_missing_dependency, 2u},
    {"test_dev_land_missing_tor_makefile()",
     test_dev_land_missing_tor_makefile, 2u},
    {"dlx_case_tor_gitlink()",
     dlx_case_tor_gitlink, 2u},
    {"dlx_case_tor_head()",
     dlx_case_tor_head, 2u},
    {"dlx_case_hook_drift()",
     dlx_case_hook_drift, 2u},
    {"dlx_case_idle_proof()",
     dlx_case_idle_proof, 2u},
    {"dlx_case_unclaimed_proof()",
     dlx_case_unclaimed_proof, 2u},
    {"dlx_case_missing_hook_binary()",
     dlx_case_missing_hook_binary, 2u},
    {"dlx_case_quiet_hooks()",
     dlx_case_quiet_hooks, 2u},
    {"dlx_case_uninitialised_tor()",
     dlx_case_uninitialised_tor, 2u},
    {"dlx_case_current_tor()",
     dlx_case_current_tor, 2u},
    {"dlx_case_generated_conflict()",
     dlx_case_generated_conflict, 2u},
    {"dlx_case_rerere_conflict()",
     dlx_case_rerere_conflict, 2u},
    {"dlx_case_retired_generated_conflict()",
     dlx_case_retired_generated_conflict, 2u},
    {"dlx_case_mixed_conflict()",
     dlx_case_mixed_conflict, 2u},
    {"test_dev_land_integrated_merge(false)",
     dlx_shard_row_158, 3u},
    {"test_dev_land_integrated_merge(true)",
     dlx_shard_row_159, 3u},
    {"test_dev_land_proof_tools_preparation()",
     test_dev_land_proof_tools_preparation, 3u},
    {"test_dev_land_final_plan_preparation()",
     test_dev_land_final_plan_preparation, 3u},
    {"test_dev_land_rebase_count_conflicts()",
     test_dev_land_rebase_count_conflicts, 3u},
    {"test_dev_land_queued_precheck_cases()",
     test_dev_land_queued_precheck_cases, 3u},
    {"test_dev_land_train_cases()",
     test_dev_land_train_cases, 2u},
    {"test_dev_land_test_hatches_testing_only()",
     test_dev_land_test_hatches_testing_only, 3u},
    {"dlx_outcome_escape_cases()",
     dlx_outcome_escape_cases, 3u},
    {"dlx_optional_string_refusal_cases()",
     dlx_optional_string_refusal_cases, 3u},
    {"dlx_string_compatibility_cases()",
     dlx_string_compatibility_cases, 3u},
    {"test_dev_land_window_defer()",
     test_dev_land_window_defer, 3u},
    {"test_dev_land_window_replay()",
     test_dev_land_window_replay, 3u},
#endif /* !defined(_WIN32) */
};
#define DLX_CASE_COUNT \
    (sizeof(g_dlx_shard_cases) / sizeof(g_dlx_shard_cases[0]))

/* Independently retained from the original dispatcher, including call
 * arguments and platform guards: dropping, duplicating or reordering a row
 * in the ownership table must fail before any scenario runs. */
static const char *const g_dlx_original_calls[] = {
    "dlx_publication_hold_cases()",
    "dlx_hold_legacy_case()",
    "dlx_guarded_priority_case()",
    "dlx_guarded_hold_mismatch_case()",
    "dlx_hold_pushed_case()",
    "dlx_hold_malformed_case()",
    "dlx_hold_sealed_case()",
    "dlx_hold_lock_case()",
    "dlx_hold_admissible_during_step()",
    "dlx_hold_survives_step_rewrite()",
    "dlx_launcher_join_cases()",
    "dlx_origin_config_cases()",
    "dlx_attest_only_cases()",
    "dlx_attest_bounded_wire_cases()",
    "dlx_attest_refusal_cases()",
    "test_dev_land_signed_intent()",
#if !defined(_WIN32)
    "dlx_fence_cases()",
    "dlx_fence_concurrent()",
    "dlx_fence_negative_cases()",
    "test_dev_land_status_observation()",
#endif
    "test_dev_land_signed_tamper()",
    "test_dev_land_receipt_adversarial()",
    "test_dev_land_signer_takeover()",
    "test_dev_land_signed_stale()",
    "test_dev_land_signed_recovery()",
    "test_dev_land_new_source_precheck()",
    "test_dev_land_drive_producer_reproof()",
    "test_dev_land_step_producer_recovery()",
#if !defined(_WIN32)
    "test_dev_land_phase_mail_quiet()",
#endif
    "test_dev_land_phase_digest()",
    "test_dev_land_signed_lost_ack()",
    "test_dev_land_signed_lost_race()",
    "test_dev_land_signed_lost_ack_resend()",
    "test_dev_land_signed_push_lost_race()",
    "test_dev_land_cancel_push_refused()",
    "test_dev_land_push_declined()",
    "test_dev_land_signed_publisher_death()",
#if !defined(_WIN32)
    "test_dev_land_signed_crash_before_push()",
    "test_dev_land_signed_third_party_before_push()",
    "test_dev_land_signed_unknown_not_retried_blind()",
    "test_dev_land_two_candidates_same_base()",
#endif
    "test_dev_land_watcher_admission()",
    "test_dev_land_long_proof_root()",
    "test_dev_land_malformed_queue_refusal()",
    "test_dev_land_chain_codec()",
    "test_dev_land_chain_relation()",
    "test_dev_land_malformed_priority_refusal()",
    "test_dev_land_malformed_outcome_refusal()",
    "test_dev_land_exact_tree()",
    "test_dev_land_source_binding()",
#if !defined(_WIN32)
    "test_dev_land_tree_types()",
    "test_dev_land_tree_malformed()",
    "test_dev_land_tree_replacements()",
    "test_dev_land_tree_missing()",
    "test_dev_land_proof_evidence_test()",
    "test_dev_land_resubmit_failed_pair()",
    "test_dev_land_refusal_names_next_step()",
    "test_dev_land_proof_evidence_compile()",
#endif
    "dlx_case_registration()",
    "dlx_case_unknown_action()",
#if !defined(_WIN32)
    "dlx_case_unsigned_tip()",
    "dlx_case_checkout_location()",
    "dlx_case_submit_status()",
    "dlx_case_duplicate_submit()",
    "dlx_case_precheck()",
    "dlx_case_empty_step()",
    "dlx_case_step_lock()",
    "dlx_case_starts_proof()",
    "dlx_case_absent_watcher()",
    "dlx_case_unarmed_proof()",
    "test_dev_land_missing_worker()",
    "test_dev_land_interrupted_proof()",
#if !defined(_WIN32)
    "test_dev_land_drive_base_watch()",
#endif
    "test_dev_land_competing_publish(\"step\", \"step\", true)",
    "test_dev_land_competing_publish(\"step\", \"drive\", true)",
    "test_dev_land_competing_publish(\"drive\", \"step\", true)",
    "test_dev_land_competing_publish(\"step\", \"drive\", false)",
    "test_dev_land_competing_publish(\"drive\", \"step\", false)",
    "test_dev_land_bounded_drive()",
    "test_dev_land_drive_seq_lands()",
    "test_dev_land_drive_seq_scope()",
    "test_dev_land_drive_seq_refusals()",
    "test_dev_land_drive_seq_proof_failed()",
    "test_dev_land_drive_seq_stops()",
    "test_dev_land_prove_drive1()",
    "test_dev_land_prove_drive2()",
    "test_dev_land_prove_drive3()",
    "test_dev_land_prove_drive4()",
    "test_dev_land_prove_drive5()",
    "test_dev_land_prove_drive6()",
    "test_dev_land_qualify_make_caps()",
    "test_dev_land_qualify_canonical_aliases()",
    "test_dev_land_qualify_unregistered_group()",
    "test_dev_land_qualify_passes()",
    "test_dev_land_qualify_job_caps()",
    "test_dev_land_qualify_complexity()",
    "test_dev_land_qualify_verdict_rule()",
    "test_dev_land_qualify_refusals()",
    "test_dev_land_qualify_dirty_tree()",
    "test_dev_land_qualify_stale_doc_refused()",
    "test_dev_land_qualify_group_verdicts()",
    "test_dev_land_qualify_groups_reported()",
    "test_dev_land_qualify_selection_refusals()",
    "test_dev_land_qualify_origin_moves()",
    "test_dev_land_qualify_rebase_and_fetch_failures()",
    "test_dev_land_drive_seq_landed_reply_stands_alone()",
    "test_dev_land_stubs_are_test_build_only()",
    "dlx_case_stub_detail()",
    "dlx_case_lands_proof()",
    "dlx_case_hook_refusal()",
    "dlx_case_proof_failure()",
    "dlx_case_timing_detail()",
    "dlx_case_moved_base()",
    "test_dev_land_explicit_main()",
    "test_dev_land_stale_file_retests()",
    "test_dev_land_missing_main()",
    "test_dev_land_initial_remote_missing()",
    "test_dev_land_final_observation_missing()",
    "dlx_case_cancel_request()",
    "dlx_case_concurrent_submit()",
    "dlx_case_dense_detail()",
    "test_dev_land_publisher_death()",
    "test_dev_land_drain_adoption()",
    "test_dev_land_postpush_observation_missing(false)",
    "test_dev_land_postpush_observation_missing(true)",
    "test_dev_land_prepush_checkpoint()",
    "test_dev_land_prepush_persist_refusal()",
    "test_dev_land_prepush_sync_refusal()",
    "test_dev_land_missing_publication_intent()",
    "test_dev_land_attach_target_cases()",
    "test_dev_land_postpush_result_unconfirmed()",
    "test_dev_land_expected_base_race()",
    "test_dev_land_recovery_ignores_replace_refs()",
    "test_dev_land_nonfastforward_client_guard()",
    "test_dev_land_lost_persistence()",
    "test_dev_land_after_proof_restart()",
    "test_dev_land_objectives_snapshot()",
    "test_dev_land_objectives_append_blocked()",
    "test_dev_land_objectives_failed_outcome()",
    "test_dev_land_terminal_replay()",
    "test_dev_land_outcome_visible_in_mail()",
    "dlx_case_missing_hook()",
    "dlx_case_cancel_race()",
    "dlx_case_aged_successor()",
    "test_dev_land_main_moves_converge()",
    "dlx_case_option_path()",
    "test_dev_land_vendor_dependencies()",
    "dlx_case_dependency_links()",
    "dlx_case_missing_dependency()",
    "test_dev_land_missing_tor_makefile()",
    "dlx_case_tor_gitlink()",
    "dlx_case_tor_head()",
    "dlx_case_hook_drift()",
    "dlx_case_idle_proof()",
    "dlx_case_unclaimed_proof()",
    "dlx_case_missing_hook_binary()",
    "dlx_case_quiet_hooks()",
    "dlx_case_uninitialised_tor()",
    "dlx_case_current_tor()",
    "dlx_case_generated_conflict()",
    "dlx_case_rerere_conflict()",
    "dlx_case_retired_generated_conflict()",
    "dlx_case_mixed_conflict()",
    "test_dev_land_integrated_merge(false)",
    "test_dev_land_integrated_merge(true)",
    "test_dev_land_proof_tools_preparation()",
    "test_dev_land_final_plan_preparation()",
    "test_dev_land_rebase_count_conflicts()",
    "test_dev_land_queued_precheck_cases()",
    "test_dev_land_train_cases()",
    "test_dev_land_test_hatches_testing_only()",
    "dlx_outcome_escape_cases()",
    "dlx_optional_string_refusal_cases()",
    "dlx_string_compatibility_cases()",
    "test_dev_land_window_defer()",
    "test_dev_land_window_replay()",
#endif /* !defined(_WIN32) */
};
#define DLX_ORIGINAL_COUNT \
    (sizeof(g_dlx_original_calls) / sizeof(g_dlx_original_calls[0]))

static bool dlx_shard_partition_valid(void)
{
    unsigned owned[DLX_SHARD_COUNT] = {0};
    if (DLX_CASE_COUNT != DLX_ORIGINAL_COUNT ||
        !zcl_test_group_is_umbrella(DLX_UMBRELLA) ||
        zcl_test_group_umbrella_shard_count(DLX_UMBRELLA) != DLX_SHARD_COUNT)
        return false;
    for (size_t i = 0; i < DLX_CASE_COUNT; i++) {
        const struct dlx_shard_case *row = &g_dlx_shard_cases[i];
        if (!row->run || row->owner >= DLX_SHARD_COUNT ||
            strcmp(row->name, g_dlx_original_calls[i]) != 0)
            return false;
        owned[row->owner]++;
        for (size_t j = 0; j < i; j++)
            if (strcmp(row->name, g_dlx_shard_cases[j].name) == 0)
                return false;
    }
    for (unsigned s = 0; s < DLX_SHARD_COUNT; s++) {
        char id[ZCL_TEST_GROUP_FULL_MAX];
        (void)snprintf(id, sizeof(id), DLX_UMBRELLA "_shard_%02u", s + 1u);
        if (!owned[s] || !zcl_test_group_is_umbrella_shard(DLX_UMBRELLA, id))
            return false;
    }
    return true;
}

static int dlx_run_shard(unsigned shard)
{
    /* A malformed partition never starts a scenario, even for the umbrella. */
    if (shard > DLX_ALL_SHARDS || !dlx_shard_partition_valid()) {
        printf("test_dev_land: invalid shard partition\n");
        return 1;
    }
    /* The landing snapshot reads the node rows from these instead of asking
     * a live node: no scenario here may reach one. */
    (void)setenv("ZCL_LAND_OBJECTIVES_BRIEF", "/nonexistent/z23-dl/brief.json", 1);
    (void)setenv("ZCL_LAND_OBJECTIVES_DATADIR", "/nonexistent/z23-dl/datadir", 1);
    int failures = 0;
    size_t ran = 0;
    for (size_t i = 0; i < DLX_CASE_COUNT; i++) {
        const struct dlx_shard_case *row = &g_dlx_shard_cases[i];
        if (shard != DLX_ALL_SHARDS && row->owner != shard)
            continue;
        int64_t dlx_row_started = platform_time_monotonic_us();
        int added = row->run();
        int64_t dlx_row_elapsed =
            platform_time_monotonic_us() - dlx_row_started;
        failures += added;
        ran++;
        printf("[dev-land-case] shard=%u name=%s us=%lld failures=%d\n",
               row->owner + 1u, row->name, (long long)dlx_row_elapsed, added);
    }
    dlx_restore();
    printf("test_dev_land: ran %zu of %zu scenarios (%s), %d failed\n",
           ran, DLX_CASE_COUNT,
           shard == DLX_ALL_SHARDS ? "umbrella" : "one shard", failures);
    if (failures == 0)
        printf("test_dev_land: all passed\n");
    else
        printf("test_dev_land: %d FAILED\n", failures);
    return failures;
}

int test_dev_land(void)
{
    return dlx_run_shard(DLX_ALL_SHARDS);
}

int test_dev_land_shard_01(void)
{
    return dlx_run_shard(0u);
}

int test_dev_land_shard_02(void)
{
    return dlx_run_shard(1u);
}

int test_dev_land_shard_03(void)
{
    return dlx_run_shard(2u);
}

int test_dev_land_shard_04(void)
{
    return dlx_run_shard(3u);
}
