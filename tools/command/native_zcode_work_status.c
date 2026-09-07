/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `zcode work status` — one honest human answer about one exact
 * task: what changed, what the evidence says, what still stands between it
 * and acceptance, and the one safe next command. Split out of
 * native_zcode_work_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_priv.h. Status is a projection: it re-reads canonical
 * bytes and writes nothing back. */

#include "command/native_command.h"
#include "native_zcode_work_priv.h"

#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_patch.h"
#include "vcs/zcode_task_index.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Every canonical object one status answer re-reads, owned together. */
struct zwork_status_load {
    struct vcs_zcode_task_index *index;
    const struct vcs_zcode_task_index_entry *entry;
    const struct vcs_zcode_task_context_entry *agent_context;
    bool context_ambiguous;
    char *goal;
    struct zwork_patch_summary summary;
    struct vcs_zcode_proof_policy_v1 policy;
};

/* One reading of the lifecycle, derived once and then only consulted. */
struct zwork_status_facts {
    const char *state;
    bool expired;
    bool accepted;
    bool repair_needed;
    bool admitted;
    bool proof_in_flight;
    bool admitted_stalled;
    bool no_candidate;
    bool confirmation_ready;
    bool compile_required;
    bool test_required;
    bool fuzz_required;
    bool review_required;
    bool clean_shadow_required;
    bool standard_evidence;
    bool sanitizer_satisfied;
    bool review_pending;
    size_t sanitizer_receipts;
};

/* The short human phrases the reply reports, all chosen from the facts. */
struct zwork_status_summaries {
    const char *stage;
    const char *build;
    const char *test;
    const char *sanitizer;
    const char *fuzz;
    const char *reproduction;
    const char *review;
    const char *next_action;
    const char *next_safe_command;
};

/* Which continuation this exact work can still offer. */
struct zwork_status_resume {
    bool candidate;
    bool confirmation;
    bool publication;
};

/* One lifecycle fact, one human interpretation — shared with
 * zcode.work.run.  An admitted candidate whose latest action has an
 * outstanding async proof chain in a supervised (named or resident)
 * datadir is really waiting for independent reproduction.  An admitted
 * candidate whose reachable ledger shows no outstanding chain is an
 * incomplete execution: nothing is arriving, and run refuses it as
 * CANDIDATE_EXECUTION_INCOMPLETE.  With no reachable ledger the reader
 * is blind, not stalled. */
static void zwork_status_lifecycle_facts(
    const struct vcs_zcode_task_index_entry *entry,
    const struct zwork_proof_snapshot *proof, bool confirmation_ready,
    struct zwork_status_facts *facts)
{
    facts->state = entry->expired ? "BLOCKED" : entry->state;
    facts->expired = entry->expired;
    facts->confirmation_ready = confirmation_ready;
    facts->repair_needed =
        strcmp(facts->state, VCS_ZCODE_TASK_STATE_REPAIR_NEEDED) == 0;
    facts->accepted =
        strcmp(facts->state, VCS_ZCODE_TASK_STATE_PROVEN) == 0;
    facts->admitted =
        strcmp(facts->state, VCS_ZCODE_TASK_STATE_CANDIDATE_ADMITTED) == 0;
    facts->proof_in_flight = facts->admitted && proof->ledger_supervised &&
                             proof->async_proof_outstanding;
    facts->admitted_stalled = facts->admitted && !facts->proof_in_flight &&
        (proof->available || proof->async_proof_state[0]);
    /* latest_action_root_hex is receipt-derived, so it stays empty for an
     * admitted candidate until the first receipt arrives; "no candidate yet"
     * must key on the state, not on that proxy. */
    facts->no_candidate =
        !facts->admitted && !entry->latest_action_root_hex[0];
}

static void zwork_status_policy_facts(
    const struct vcs_zcode_proof_policy_v1 *policy,
    const struct zwork_proof_snapshot *proof,
    struct zwork_status_facts *facts)
{
    facts->compile_required = zwork_proof_required(
        policy, VCS_ZCODE_PROOF_COMPILE,
        policy->minimum_compile_receipts > policy->minimum_matching_receipts
            ? policy->minimum_compile_receipts
            : policy->minimum_matching_receipts);
    facts->test_required = zwork_proof_required(
        policy, VCS_ZCODE_PROOF_TEST, policy->minimum_test_receipts);
    facts->fuzz_required = zwork_proof_required(
        policy, VCS_ZCODE_PROOF_FUZZ, policy->minimum_fuzz_receipts);
    facts->review_required = zwork_proof_required(
        policy, VCS_ZCODE_PROOF_REVIEW, policy->minimum_reviews);
    facts->clean_shadow_required =
        (policy->required_proofs & VCS_ZCODE_PROOF_LOCAL_REPRODUCTION) != 0;
    facts->standard_evidence = policy->minimum_compile_receipts >= 2u ||
                               policy->minimum_test_receipts >= 2u;
    facts->sanitizer_receipts = facts->standard_evidence && proof->available
        ? proof->facts.compile_receipts : 0;
    facts->sanitizer_satisfied = facts->standard_evidence &&
        proof->available && proof->facts.compile_satisfied;
    facts->review_pending = proof->available && facts->review_required &&
        proof->facts.compile_satisfied && proof->facts.test_satisfied &&
        proof->facts.fuzz_satisfied && !proof->facts.review_satisfied;
}

static const char *zwork_status_stage(const struct zwork_status_facts *facts)
{
    return facts->expired ? "Understanding request" :
        facts->accepted ? "Accepted" :
        facts->repair_needed || facts->no_candidate
            ? "Creating missing code" :
        facts->confirmation_ready ? "Ready for your decision" :
        facts->admitted_stalled ? "Needs attention" :
        "Waiting for independent reproduction";
}

static const char *zwork_status_build_summary(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    return facts->repair_needed ? "failed" :
        facts->no_candidate ? "not_started" :
        !proof->available
            ? facts->proof_in_flight ? "background_pending" : "unknown" :
        proof->facts.compile_satisfied ? "passed" :
        proof->facts.compile_receipts > 0 ? "pending_policy" :
        facts->proof_in_flight ? "background_pending" : "not_started";
}

static const char *zwork_status_test_summary(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    return facts->repair_needed ? "failed_or_not_reached" :
        !facts->test_required ? "not_required" :
        !proof->available
            ? facts->proof_in_flight ? "background_pending" : "unknown" :
        proof->facts.test_satisfied ? "passed_declared_tests" :
        proof->facts.test_receipts > 0 ? "pending_policy" :
        facts->proof_in_flight ? "background_pending" : "not_started";
}

static const char *zwork_status_fuzz_summary(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    return !facts->fuzz_required ? "not_required" :
        !proof->available
            ? facts->proof_in_flight ? "background_pending" : "unknown" :
        proof->facts.fuzz_satisfied ? "passed_declared_fuzz" :
        proof->facts.fuzz_receipts > 0 ? "pending_policy" :
        facts->proof_in_flight ? "background_pending" : "not_started";
}

static const char *zwork_status_sanitizer_summary(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    return !facts->standard_evidence ? "not_required" :
        facts->repair_needed ? "failed_or_unavailable" :
        facts->no_candidate ? "not_started" :
        !proof->available
            ? facts->proof_in_flight ? "background_pending" : "unknown" :
        facts->sanitizer_satisfied ? "passed_asan_ubsan" :
        facts->sanitizer_receipts > 0 ? "pending_policy" :
        facts->proof_in_flight ? "background_pending" : "not_started";
}

static const char *zwork_status_reproduction_grade(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    return facts->no_candidate
        ? "none" : !proof->available ? "unknown" :
        proof->facts.local_reproduced ? "clean_shadow_matched" :
        proof->facts.quorum_satisfied ? "approved_signer_threshold" :
        proof->facts.valid_receipts > 0 ? "pending" : "none";
}

static const char *zwork_status_next_safe_command(
    const struct zwork_status_facts *facts,
    const struct vcs_zcode_task_index_entry *entry)
{
    return facts->expired ? "zcode work start" :
        facts->accepted ? "zcode work accept" :
        facts->repair_needed && entry->candidate_count >= 3u
            ? "zcode work start" :
        facts->repair_needed || facts->no_candidate
            ? "zcode work run" :
        facts->confirmation_ready ? "ask user to confirm exact candidate" :
        facts->review_pending ? "zcode work review" : "zcode work status";
}

static const char *zwork_status_next_action(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    return facts->expired ? "Start a fresh bounded task." :
        facts->accepted ? "Continue publishing this accepted version." :
        facts->repair_needed ? "Repair the named candidate failure." :
        facts->no_candidate ? "Produce one bounded candidate." :
        facts->confirmation_ready
            ? "Ask the user to confirm or cancel this exact candidate." :
        facts->admitted_stalled
            ? "Preserve the captured candidate and diagnose the package prerequisite before another attempt." :
        facts->admitted && !facts->proof_in_flight
            ? "No proof ledger reachable here shows this candidate's proof; pass the admitting node's datadir." :
        facts->review_pending ? "Review the exact candidate evidence." :
        facts->proof_in_flight &&
            strcmp(proof->async_proof_state, "REQUESTED") == 0
            ? "Run zcode work toolchain here and on the proving node; independent compile evidence needs the same capsule_root." :
              "Keep thinking while the missing proof arrives.";
}

/* Where the task stands in its own life, before any evidence is weighed. */
static const char *zwork_status_lifecycle_risk(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    if (facts->expired) return "task expired";
    if (facts->repair_needed)
        return "latest candidate failed confined package build or tests";
    if (facts->accepted) return "accepted version is not fully published";
    if (facts->no_candidate) return "candidate not admitted";
    if (facts->admitted_stalled)
        return "candidate execution produced no signed work receipt and no outstanding supervised proof";
    if (!proof->available)
        return "canonical proof ledger is unavailable; no proof result inferred";
    return NULL;
}

/* The first policy requirement the canonical evidence has not met. */
static const char *zwork_status_evidence_risk(
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof)
{
    if (facts->compile_required && !proof->facts.compile_satisfied)
        return strcmp(proof->async_proof_state, "REQUESTED") == 0
            ? "independent compile evidence is still REQUESTED; run zcode work toolchain on this node and the proving node so capsule_root matches"
            : "required compile or matching-build evidence is pending";
    if (facts->test_required && !proof->facts.test_satisfied)
        return "required candidate behavior evidence is pending";
    if (facts->fuzz_required && !proof->facts.fuzz_satisfied)
        return "required deterministic fuzz evidence is pending";
    if (facts->review_required && !proof->facts.review_satisfied)
        return "required independent review is pending";
    if (facts->clean_shadow_required && !proof->facts.local_reproduced)
        return "required clean-shadow observation is pending";
    if (!proof->facts.release_identity_satisfied)
        return "release byte-identity evidence is not satisfied";
    return proof->facts.policy_satisfied
        ? "human acceptance, secure release qualification, and publication remain separate"
        : "proof policy remains unsatisfied by canonical evidence";
}

static void zwork_status_risks(const struct zwork_status_facts *facts,
                               const struct zwork_proof_snapshot *proof,
                               char *out, size_t cap)
{
    const char *risk = zwork_status_lifecycle_risk(facts, proof);
    if (!risk) risk = zwork_status_evidence_risk(facts, proof);
    (void)snprintf(out, cap, "%s", risk);
}

static void zwork_status_api_summary(const struct zwork_patch_summary *summary,
                                     char *out, size_t cap)
{
    if (summary->public_api_changes == 0)
        (void)snprintf(out, cap, "none");
    else
        (void)snprintf(out, cap, "%zu public header file%s changed",
                       summary->public_api_changes,
                       summary->public_api_changes == 1 ? "" : "s");
}

static const char *zwork_status_review_summary(
    const struct vcs_zcode_task_index_entry *entry)
{
    return entry->latest_review_verdict ==
            VCS_ZCODE_REVIEW_APPROVE ? "approve" :
        entry->latest_review_verdict == VCS_ZCODE_REVIEW_REQUEST_CHANGES
            ? "request_changes" :
        entry->latest_review_verdict == VCS_ZCODE_REVIEW_REJECT
            ? "reject" : "not_started";
}

static void zwork_status_summaries_fill(
    struct zwork_status_summaries *out,
    const struct zwork_status_facts *facts,
    const struct zwork_proof_snapshot *proof,
    const struct vcs_zcode_task_index_entry *entry)
{
    out->stage = zwork_status_stage(facts);
    out->build = zwork_status_build_summary(facts, proof);
    out->test = zwork_status_test_summary(facts, proof);
    out->sanitizer = zwork_status_sanitizer_summary(facts, proof);
    out->fuzz = zwork_status_fuzz_summary(facts, proof);
    out->reproduction = zwork_status_reproduction_grade(facts, proof);
    out->review = zwork_status_review_summary(entry);
    out->next_action = zwork_status_next_action(facts, proof);
    out->next_safe_command = zwork_status_next_safe_command(facts, entry);
}

static bool zwork_status_changed_paths(
    const struct zwork_patch_summary *summary, struct json_value *out)
{
    bool ok = true;
    for (size_t i = 0; ok && i < summary->patch.count; i++) {
        struct json_value path;
        json_init(&path); json_set_str(&path, summary->patch.changes[i].path);
        ok = json_push_back(out, &path);
        json_free(&path);
    }
    return ok;
}

static bool zwork_status_proof_counts_json(
    struct json_value *proof_json, const struct zwork_proof_snapshot *proof,
    const struct zwork_status_facts *facts)
{
    return json_push_kv_bool(proof_json, "facts_available",
                             proof->available) &&
        json_push_kv_int(proof_json, "valid_receipts",
                         (int64_t)proof->facts.valid_receipts) &&
        json_push_kv_int(proof_json, "compile_receipts",
                         (int64_t)proof->facts.compile_receipts) &&
        json_push_kv_int(proof_json, "test_receipts",
                         (int64_t)proof->facts.test_receipts) &&
        json_push_kv_int(proof_json, "sanitizer_receipts",
                         (int64_t)facts->sanitizer_receipts) &&
        json_push_kv_int(proof_json, "fuzz_receipts",
                         (int64_t)proof->facts.fuzz_receipts) &&
        json_push_kv_int(proof_json, "review_receipts",
                         (int64_t)proof->facts.review_receipts) &&
        json_push_kv_int(proof_json, "approved_distinct_signers",
                         (int64_t)proof->facts.approved_distinct_signers);
}

static bool zwork_status_proof_flags_json(
    struct json_value *proof_json, const struct zwork_proof_snapshot *proof,
    const struct zwork_status_facts *facts,
    struct json_value *receipt_roots, bool receipt_roots_available)
{
    return json_push_kv_bool(proof_json, "clean_shadow_observed",
                             proof->facts.local_reproduced) &&
        json_push_kv_bool(proof_json, "signer_threshold_satisfied",
                          proof->facts.quorum_satisfied) &&
        json_push_kv_bool(proof_json, "compile_satisfied",
                          proof->facts.compile_satisfied) &&
        json_push_kv_bool(proof_json, "test_satisfied",
                          proof->facts.test_satisfied) &&
        json_push_kv_bool(proof_json, "sanitizer_satisfied",
                          facts->sanitizer_satisfied) &&
        json_push_kv_bool(proof_json, "fuzz_satisfied",
                          proof->facts.fuzz_satisfied) &&
        json_push_kv_bool(proof_json, "review_satisfied",
                          proof->facts.review_satisfied) &&
        json_push_kv_bool(proof_json, "policy_satisfied",
                          proof->facts.policy_satisfied) &&
        json_push_kv_bool(proof_json, "receipt_roots_available",
                          receipt_roots_available) &&
        json_push_kv(proof_json, "receipt_roots", receipt_roots) &&
        json_push_kv_str(proof_json, "authority",
                         "canonical_readonly_receipt_evaluation");
}

/* The exact members of the proof set are shown only on request; without
 * them the document still reports that they were not projected. */
static bool zwork_status_proof_json(
    struct json_value *proof_json, const struct zwork_proof_snapshot *proof,
    const struct zwork_status_facts *facts, const char *workspace,
    const char *proof_set_root, bool details)
{
    struct json_value receipt_roots;
    json_init(&receipt_roots); json_set_array(&receipt_roots);
    bool receipt_roots_available = false;
    bool ok = (!details || zwork_proof_receipt_roots(
                   workspace, proof_set_root, &receipt_roots,
                   &receipt_roots_available)) &&
        zwork_status_proof_counts_json(proof_json, proof, facts) &&
        zwork_status_proof_flags_json(proof_json, proof, facts,
                                      &receipt_roots,
                                      receipt_roots_available);
    json_free(&receipt_roots);
    return ok;
}

static bool zwork_status_expert_task_json(
    struct json_value *expert,
    const struct vcs_zcode_task_index_entry *entry,
    const struct vcs_zcode_task_context_entry *agent_context,
    bool context_ambiguous)
{
    return json_push_kv_str(expert, "task_root", entry->task_root_hex) &&
        json_push_kv_str(expert, "source_root", entry->source_root_hex) &&
        json_push_kv_str(expert, "goal_root", entry->goal_root_hex) &&
        json_push_kv_str(expert, "agent_context_root",
                         agent_context ? agent_context->context_root_hex : "") &&
        json_push_kv_bool(expert, "agent_context_ambiguous",
                          context_ambiguous) &&
        json_push_kv_str(expert, "proof_policy_root",
                         entry->proof_policy_root_hex) &&
        json_push_kv_str(expert, "toolchain_capsule_root",
                         entry->toolchain_capsule_root_hex);
}

static bool zwork_status_expert_candidate_json(
    struct json_value *expert,
    const struct vcs_zcode_task_index_entry *entry,
    const struct zwork_proof_snapshot *proof)
{
    return json_push_kv_str(expert, "action_id",
                            entry->latest_action_root_hex[0]
                                ? entry->latest_action_root_hex
                                : proof->action_root) &&
        json_push_kv_str(expert, "candidate_root",
                         entry->latest_candidate_root_hex) &&
        json_push_kv_str(expert, "candidate_source_root",
                         entry->latest_candidate_source_root_hex) &&
        json_push_kv_str(expert, "patch_root",
                         entry->latest_patch_root_hex) &&
        json_push_kv_str(expert, "work_receipt_root",
                         entry->latest_work_receipt_hex) &&
        json_push_kv_str(expert, "output_root",
                         entry->latest_receipt_output_root_hex) &&
        json_push_kv_str(expert, "proof_action_root",
                         proof->action_root) &&
        json_push_kv_str(expert, "build_output_root",
                         proof->available
                             ? proof->facts.output_root_sha3 : "");
}

static bool zwork_status_expert_app_run_json(
    struct json_value *expert,
    const struct vcs_zcode_task_index_entry *entry)
{
    return json_push_kv_int(expert, "app_run_receipt_count",
                            (int64_t)entry->app_run_receipt_count) &&
        json_push_kv_int(expert, "valid_app_run_receipt_count",
                         (int64_t)entry->valid_app_run_receipt_count) &&
        json_push_kv_str(expert, "app_run_receipt_root",
                         entry->latest_app_run_receipt_hex) &&
        json_push_kv_str(expert, "app_run_observation_root",
                         entry->latest_app_run_observation_hex) &&
        json_push_kv_str(expert, "app_run_artifact_root",
                         entry->latest_app_run_artifact_root_hex) &&
        json_push_kv_str(expert, "app_run_invocation_root",
                         entry->latest_app_run_invocation_root_hex) &&
        json_push_kv_str(expert, "app_run_action_root",
                         entry->latest_app_run_action_root_hex) &&
        json_push_kv_int(expert, "app_run_flags",
                         (int64_t)entry->latest_app_run_flags) &&
        json_push_kv_int(expert, "app_run_status",
                         (int64_t)entry->latest_app_run_status) &&
        json_push_kv_int(expert, "app_run_exit_status",
                         (int64_t)entry->latest_app_run_exit_status) &&
        json_push_kv_int(expert, "app_run_finished_unix",
                         entry->latest_app_run_finished_unix);
}

static bool zwork_status_expert_lane_json(
    struct json_value *expert,
    const struct vcs_zcode_task_index_entry *entry,
    const struct zwork_status_facts *facts, const char *proof_set_root)
{
    return json_push_kv_str(expert, "lane_receipt_root",
                            entry->latest_lane_receipt_hex) &&
        json_push_kv_str(expert, "accepted_work_root",
                         facts->accepted ? entry->latest_lane_receipt_hex : "") &&
        json_push_kv_int(expert, "lane_created_unix",
                         entry->latest_lane_created_unix) &&
        json_push_kv_str(expert, "proof_set_root",
                         proof_set_root) &&
        json_push_kv_str(expert, "review_root",
                         entry->latest_review_root_hex);
}

static bool zwork_status_expert_json(
    struct json_value *expert,
    const struct vcs_zcode_task_index_entry *entry,
    const struct zwork_proof_snapshot *proof,
    const struct zwork_status_facts *facts,
    const struct vcs_zcode_task_context_entry *agent_context,
    bool context_ambiguous, const char *proof_set_root)
{
    return zwork_status_expert_task_json(expert, entry, agent_context,
                                         context_ambiguous) &&
        zwork_status_expert_candidate_json(expert, entry, proof) &&
        zwork_status_expert_app_run_json(expert, entry) &&
        zwork_status_expert_lane_json(expert, entry, facts, proof_set_root);
}

static bool zwork_status_change_json(
    struct zcl_command_reply *reply, const char *work_id, const char *goal,
    const struct zwork_status_facts *facts,
    const struct zwork_status_summaries *summaries,
    const struct zwork_patch_summary *summary,
    struct json_value *changed_paths, const char *api_summary)
{
    return json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "goal", goal) &&
        json_push_kv_str(&reply->data, "state", facts->state) &&
        json_push_kv_str(&reply->data, "stage", summaries->stage) &&
        json_push_kv_int(&reply->data, "changed_files",
                         (int64_t)summary->patch.count) &&
        json_push_kv(&reply->data, "changed_paths", changed_paths) &&
        json_push_kv_int(&reply->data, "added_lines",
                         (int64_t)summary->added_lines) &&
        json_push_kv_int(&reply->data, "deleted_lines",
                         (int64_t)summary->deleted_lines) &&
        json_push_kv_bool(&reply->data, "line_counts_complete",
                          summary->line_counts_exact) &&
        json_push_kv_str(&reply->data, "public_api_changes", api_summary);
}

static bool zwork_status_result_json(
    struct zcl_command_reply *reply,
    const struct zwork_status_summaries *summaries,
    const struct zwork_proof_snapshot *proof, const char *remaining_risks)
{
    return json_push_kv_str(&reply->data, "build_result",
                            summaries->build) &&
        json_push_kv_str(&reply->data, "test_result",
                         summaries->test) &&
        json_push_kv_str(&reply->data, "sanitizer_result",
                         summaries->sanitizer) &&
        json_push_kv_str(&reply->data, "fuzz_result", summaries->fuzz) &&
        json_push_kv_str(&reply->data, "reproduction_grade",
                         summaries->reproduction) &&
        (proof->async_proof_state[0] == '\0' ||
         json_push_kv_str(&reply->data, "async_proof_state",
                          proof->async_proof_state)) &&
        json_push_kv_str(&reply->data, "review_verdict",
                         summaries->review) &&
        json_push_kv_str(&reply->data, "remaining_risks",
                         remaining_risks);
}

static bool zwork_status_decision_json(
    struct zcl_command_reply *reply, const struct zwork_status_facts *facts,
    const char *confirmation_identity, bool details,
    const struct zwork_status_summaries *summaries,
    struct json_value *proof_json, struct json_value *expert)
{
    bool confirm = !facts->accepted && facts->confirmation_ready;
    return json_push_kv_bool(&reply->data, "confirmation_ready", confirm) &&
        (!details || json_push_kv_str(
            &reply->data, "confirmation_identity", confirmation_identity)) &&
        json_push_kv_str(&reply->data, "confirmation_effect",
                         confirm
                           ? "advance exact candidate to PROVEN; do not apply, sign, or publish"
                           : "none") &&
        json_push_kv_int(&reply->data, "scope_violations", 0) &&
        json_push_kv_str(&reply->data, "next_action",
                         summaries->next_action) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         summaries->next_safe_command) &&
        json_push_kv_bool(&reply->data, "details_available", true) &&
        (!details || (json_push_kv(&reply->data, "proof", proof_json) &&
                      json_push_kv(&reply->data, "expert", expert)));
}

static struct zwork_status_resume zwork_status_resume_from(
    const struct zwork_status_facts *facts)
{
    struct zwork_status_resume resume;
    resume.candidate = !facts->expired && !facts->accepted &&
        (facts->repair_needed || facts->no_candidate);
    resume.confirmation = !facts->expired && !facts->accepted &&
        facts->confirmation_ready;
    resume.publication = !facts->expired && facts->accepted;
    return resume;
}

static const char *zwork_status_resume_command(
    const struct zwork_status_resume *resume)
{
    return resume->candidate
        ? "zcode.work.run"
        : resume->publication
        ? "zcode.work.accept"
        : "app.presentation.release-confirm";
}

static const char *zwork_status_resume_reason(
    const struct zwork_status_resume *resume, bool repair_needed)
{
    return resume->publication
        ? "resume this exact accepted work and recover its existing publication continuation"
        : resume->confirmation
        ? "show the real result and ask for one exact human decision"
        : repair_needed
        ? "repair the bounded candidate and admit this exact work again"
        : "create only the behavior still missing from this exact work";
}

/* A continuation may only name paths that exist right now. */
static bool zwork_status_continuation_paths(
    const char *workspace, const char *proof_datadir,
    char continuation_workspace[ZWORK_PATH_MAX],
    char continuation_datadir[ZWORK_PATH_MAX])
{
    return platform_directory_canonical_real(
               workspace, continuation_workspace, ZWORK_PATH_MAX) &&
        (!proof_datadir || !proof_datadir[0] ||
         platform_directory_canonical_real(
             proof_datadir, continuation_datadir, ZWORK_PATH_MAX));
}

static bool zwork_status_continuation(
    struct zcl_command_reply *reply, const struct zwork_status_facts *facts,
    const struct zwork_status_resume *resume, const char *work_id,
    const char *workspace, const char *proof_datadir)
{
    if (!resume->candidate && !resume->confirmation && !resume->publication)
        return true;
    char continuation_workspace[ZWORK_PATH_MAX] = {0};
    char continuation_datadir[ZWORK_PATH_MAX] = {0};
    if (!zwork_status_continuation_paths(workspace, proof_datadir,
                                         continuation_workspace,
                                         continuation_datadir))
        return false;
    struct json_value next_input;
    json_init(&next_input); json_set_object(&next_input);
    bool ok = json_push_kv_str(&next_input, "workspace",
                               continuation_workspace) &&
        json_push_kv_str(&next_input, "work", work_id) &&
        (!proof_datadir || !proof_datadir[0] ||
         json_push_kv_str(&next_input, "datadir",
                          continuation_datadir)) &&
        zwork_add_next(reply, zwork_status_resume_command(resume),
                       &next_input,
                       zwork_status_resume_reason(resume,
                                                  facts->repair_needed));
    json_free(&next_input);
    return ok;
}

static void zwork_status_load_close(struct zwork_status_load *load)
{
    vcs_zcode_patch_free(&load->summary.patch);
    free(load->goal);
    vcs_zcode_task_index_free(load->index);
}

/* Rebuild the canonical projection, resolve the one work alias it names, and
 * re-verify every object status will report. Any gap is a refusal, never a
 * partial answer. */
static bool zwork_status_load_open(const char *workspace, const char *work,
                                   int64_t now,
                                   struct zwork_status_load *load,
                                   struct zcl_command_reply *reply)
{
    memset(load, 0, sizeof(*load));
    vcs_zcode_patch_init(&load->summary.patch);
    load->index = vcs_zcode_task_index_build(workspace, now);
    if (!load->index) {
        zwork_fail(reply, "WORK_INDEX_FAILED", "rebuild",
                   "canonical task projection could not be rebuilt", true,
                   false);
        return false;
    }
    bool ambiguous = false;
    load->entry = zwork_resolve(load->index, work, &ambiguous);
    load->goal = load->entry
        ? zwork_load_goal(workspace, load->entry->goal_root_hex) : NULL;
    if (!load->entry || !load->goal) {
        zwork_fail(reply, ambiguous ? "AMBIGUOUS_WORK" : "WORK_NOT_FOUND",
                   "resolve", ambiguous
                     ? "work prefix resolves to more than one canonical task"
                     : "no verified canonical task matches this work alias",
                   false, false);
        zwork_status_load_close(load);
        return false;
    }
    load->agent_context = vcs_zcode_task_index_context_for_task(
        load->index, load->entry->task_root_hex, &load->context_ambiguous);
    if (!zwork_patch_summary_load(workspace, load->entry, &load->summary) ||
        !zwork_policy_load(workspace, load->entry->proof_policy_root_hex,
                           &load->policy)) {
        zwork_fail(reply, "PATCH_SUMMARY_FAILED", "rebuild",
                   "latest canonical patch or its source blobs could not be reverified",
                   false, false);
        zwork_status_load_close(load);
        return false;
    }
    return true;
}

/* A later independently signed display receipt may name a proof set the
 * ledger cannot re-evaluate; the index row then still names the last one. */
static const char *zwork_status_proof_set_root(
    const struct zwork_proof_snapshot *proof,
    const struct vcs_zcode_task_index_entry *entry)
{
    return proof->available && proof->facts.proof_set_root_sha3[0]
        ? proof->facts.proof_set_root_sha3
        : entry->latest_proof_set_root_hex;
}

static void zwork_status_render(struct zcl_command_reply *reply,
                                struct zwork_status_load *load,
                                const char *workspace,
                                const char *proof_datadir, bool details,
                                int64_t now)
{
    const struct vcs_zcode_task_index_entry *entry = load->entry;
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    struct zwork_proof_snapshot proof;
    zwork_proof_snapshot_read(workspace, entry->task_root_hex,
                              entry->latest_action_root_hex,
                              entry->latest_candidate_root_hex,
                              proof_datadir, now,
                              &proof);
    char confirmation_identity[65];
    bool confirmation_ready = zwork_confirmation_identity(
        entry, &proof, confirmation_identity);
    struct zwork_status_facts facts;
    zwork_status_lifecycle_facts(entry, &proof, confirmation_ready, &facts);
    zwork_status_policy_facts(&load->policy, &proof, &facts);
    struct zwork_status_summaries summaries;
    zwork_status_summaries_fill(&summaries, &facts, &proof, entry);
    char remaining_risks[256];
    zwork_status_risks(&facts, &proof, remaining_risks,
                       sizeof(remaining_risks));
    char api_summary[96];
    zwork_status_api_summary(&load->summary, api_summary,
                             sizeof(api_summary));
    const char *proof_set_root = zwork_status_proof_set_root(&proof, entry);
    struct json_value expert, changed_paths, proof_json;
    json_init(&expert); json_set_object(&expert);
    json_init(&changed_paths); json_set_array(&changed_paths);
    json_init(&proof_json); json_set_object(&proof_json);
    struct zwork_status_resume resume = zwork_status_resume_from(&facts);
    bool ok = zwork_status_changed_paths(&load->summary, &changed_paths) &&
        zwork_status_proof_json(&proof_json, &proof, &facts, workspace,
                                proof_set_root, details) &&
        zwork_status_expert_json(&expert, entry, &proof, &facts,
                                 load->agent_context,
                                 load->context_ambiguous, proof_set_root) &&
        zwork_status_change_json(reply, work_id, load->goal, &facts,
                                 &summaries, &load->summary, &changed_paths,
                                 api_summary) &&
        zwork_status_result_json(reply, &summaries, &proof,
                                 remaining_risks) &&
        zwork_status_decision_json(reply, &facts, confirmation_identity,
                                   details, &summaries, &proof_json,
                                   &expert) &&
        zwork_status_continuation(reply, &facts, &resume, work_id, workspace,
                                  proof_datadir);
    json_free(&changed_paths);
    json_free(&proof_json); json_free(&expert);
    if (!ok)
        zwork_fail(reply, "WORK_STATUS_OUTPUT", "render",
                   "human work status could not be rendered", false, false);
}

void zcl_native_handle_zcode_work_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = zwork_str(request->input, "workspace");
    const char *work = zwork_str(request->input, "work");
    const char *proof_datadir = zwork_str(request->input, "datadir");
    bool details = zwork_bool(request->input, "details");
    if (zcl_native_forward_live_command(
            request, proof_datadir, "zcode_work_status",
            "LIVE_WORK_STATUS_FAILED", "status", "zcode.work.status",
            reply))
        return;
    if (!workspace || !workspace[0]) workspace = ".";
    int64_t now = platform_time_wall_unix();
    struct zwork_status_load load;
    if (!zwork_status_load_open(workspace, work, now, &load, reply))
        return;
    zwork_status_render(reply, &load, workspace, proof_datadir, details, now);
    zwork_status_load_close(&load);
}
