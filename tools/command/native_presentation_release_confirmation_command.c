/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: inert native decision over one exact proven ZCODE candidate. */

#include "command/native_command.h"

#include "base/hex.h"
#include "config/runtime.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "presentation/model.h"
#include "services/build_fabric_service.h"
#include "util/log_macros.h"
#include "vcs/zcode_dev.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define NPRC_LEAF "app.presentation.release-confirm"
#define NPRC_PATH_MAX 4400

static const struct json_value *nprc_object(
    const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_OBJ ? value : NULL;
}

static const char *nprc_str(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool nprc_bool(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static int64_t nprc_int(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : -1;
}

static bool nprc_root(const char *hex, uint8_t out[32])
{
    return hex && zcl_hex_decode_lower(hex, out, 32);
}

static bool nprc_value_fits(const char *value)
{
    return value && strlen(value) <= ZCL_PRESENT_MODEL_VALUE_MAX;
}

static void nprc_item(struct zcl_present_model_v1 *model, const char *id,
                      const char *label, const char *value, uint16_t status)
{
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = ZCL_PRESENT_ITEM_KEY_VALUE;
    item->status = status;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    item->flags = ZCL_PRESENT_ITEM_READ_ONLY;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label), "%s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
}

static bool nprc_state_is_release_ready(const char *state)
{
    return state && (strcmp(state, "EVIDENCE_READY") == 0 ||
                     strcmp(state, "CANDIDATE_PROOFS_READY") == 0);
}

static bool nprc_decode_fact_roots(const char *task, const char *candidate,
                                   const char *policy, const char *proof,
                                   uint8_t task_root[32],
                                   uint8_t candidate_root[32],
                                   uint8_t policy_root[32],
                                   uint8_t proof_root[32])
{
    return nprc_root(task, task_root) &&
        nprc_root(candidate, candidate_root) &&
        nprc_root(policy, policy_root) && nprc_root(proof, proof_root);
}

static bool nprc_evidence_gates_satisfied(const char *authority,
                                          int64_t compile, int64_t tests,
                                          int64_t signers,
                                          const struct json_value *evidence)
{
    return authority && authority[0] && compile >= 0 && tests >= 0 &&
        signers >= 0 && nprc_bool(evidence, "policy_satisfied") &&
        nprc_bool(evidence, "compile_satisfied") &&
        nprc_bool(evidence, "test_satisfied");
}

static const char *nprc_plural_suffix(int64_t count)
{
    return count == 1 ? "" : "s";
}

bool zcl_native_presentation_release_confirm_model_from_facts(
    const struct json_value *status, const struct json_value *evidence,
    struct zcl_present_model_v1 *model, char identity[65],
    char *why, size_t why_cap)
{
    const struct json_value *expert = nprc_object(status, "expert");
    const char *state = nprc_str(status, "state");
    const char *goal = nprc_str(status, "goal");
    const char *task = nprc_str(expert, "task_root");
    const char *candidate = nprc_str(expert, "candidate_root");
    const char *policy = nprc_str(expert, "proof_policy_root");
    const char *proof = nprc_str(evidence, "proof_set_root");
    const char *authority = nprc_str(evidence, "authority");
    int64_t compile = nprc_int(evidence, "compile_receipts");
    int64_t tests = nprc_int(evidence, "test_receipts");
    int64_t signers = nprc_int(evidence, "approved_distinct_signers");
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    uint8_t proof_root[32], plan_root[32];
    if (!model || !identity || !nprc_state_is_release_ready(state) ||
        !nprc_value_fits(goal) ||
        !nprc_decode_fact_roots(task, candidate, policy, proof, task_root,
                                candidate_root, policy_root, proof_root) ||
        !nprc_evidence_gates_satisfied(authority, compile, tests, signers,
                                       evidence) ||
        vcs_zcode_acceptance_plan_root(task_root, candidate_root, policy_root,
                                       proof_root, plan_root) !=
            VCS_ZCODE_DEV_OK) {
        (void)snprintf(why, why_cap,
                       "candidate is not ready for one exact human decision");
        return false;
    }
    zcl_hex_encode(plan_root, 32, identity);
    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_CONFIRMATION);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "release-%.12s", identity);
    (void)snprintf(model->title, sizeof(model->title),
                   "Accept this exact candidate for release?");
    (void)snprintf(model->summary, sizeof(model->summary),
                   "HUMAN DECISION - proof policy is GREEN; this screen cannot accept, apply, sign or publish.");
    (void)snprintf(model->exact_root, sizeof(model->exact_root), "%s",
                   identity);
    nprc_item(model, "effect", "EXACT EFFECT",
              "Advance this candidate to PROVEN; source and network stay unchanged",
              ZCL_PRESENT_STATUS_YELLOW);
    nprc_item(model, "goal", "REQUESTED BEHAVIOR", goal,
              ZCL_PRESENT_STATUS_INFO);
    nprc_item(model, "candidate", "CANDIDATE ROOT", candidate,
              ZCL_PRESENT_STATUS_INFO);
    nprc_item(model, "proof-set", "VERIFIED PROOF SET", proof,
              ZCL_PRESENT_STATUS_GREEN);
    nprc_item(model, "authority", "PROOF AUTHORITY", authority,
              ZCL_PRESENT_STATUS_GREEN);
    char count[96];
    (void)snprintf(count, sizeof(count), "%lld matching compile receipt%s",
                   (long long)compile, nprc_plural_suffix(compile));
    nprc_item(model, "compile", "COMPILE EVIDENCE", count,
              ZCL_PRESENT_STATUS_GREEN);
    (void)snprintf(count, sizeof(count), "%lld passing test receipt%s",
                   (long long)tests, nprc_plural_suffix(tests));
    nprc_item(model, "tests", "BEHAVIOR EVIDENCE", count,
              ZCL_PRESENT_STATUS_GREEN);
    (void)snprintf(count, sizeof(count), "%lld approved distinct signer%s",
                   (long long)signers, nprc_plural_suffix(signers));
    nprc_item(model, "signers", "INDEPENDENT EVIDENCE", count,
              nprc_bool(evidence, "quorum_satisfied")
                  ? ZCL_PRESENT_STATUS_GREEN : ZCL_PRESENT_STATUS_INFO);
    nprc_item(model, "recheck", "AUTHORITY BOUNDARY",
              "Separate zcode work accept rechecks this identity and all evidence",
              ZCL_PRESENT_STATUS_GREEN);
    nprc_item(model, "publication", "PUBLICATION",
              "Not performed; signing and P2P publication remain separate",
              ZCL_PRESENT_STATUS_NEUTRAL);
    model->action_count = 2;
    model->actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(model->actions[0].id, sizeof(model->actions[0].id),
                   "cancel");
    (void)snprintf(model->actions[0].label,
                   sizeof(model->actions[0].label), "Cancel - make no change");
    model->actions[1].kind = ZCL_PRESENT_ACTION_CONFIRM;
    (void)snprintf(model->actions[1].id, sizeof(model->actions[1].id),
                   "confirm");
    (void)snprintf(model->actions[1].label,
                   sizeof(model->actions[1].label), "Confirm exact candidate");
    return zcl_present_model_validate_v1(model, why, why_cap);
}

static void nprc_fail(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence)
{
    LOG_ERROR("native.presentation.release_confirmation", "%s: %s",
              code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "confirm", false, false, message,
        evidence ? evidence : NPRC_LEAF);
}

static bool nprc_evidence_datadir(const char *requested, const char *task,
                                  char out[NPRC_PATH_MAX])
{
    char candidate[NPRC_PATH_MAX], canonical[NPRC_PATH_MAX];
    if (requested && requested[0]) {
        if (!platform_directory_canonical_real(requested, canonical,
                                               sizeof(canonical)))
            return false;
    } else {
#if defined(_WIN32)
        char private_root[NPRC_PATH_MAX];
        int n = platform_state_root(private_root, sizeof(private_root))
            ? snprintf(candidate, sizeof(candidate),
                       "%s/zcode-workspaces/%.64s/zbuild", private_root, task)
            : -1;
        if (n <= 0 || (size_t)n >= sizeof(candidate) ||
            !platform_directory_canonical_real(candidate, canonical,
                                               sizeof(canonical)))
            return false;
#else
        int n = snprintf(candidate, sizeof(candidate),
                         "/tmp/zclassic23-zcode-workspaces/%lu/%.64s/zbuild",
                         (unsigned long)getuid(), task);
        if (n <= 0 || (size_t)n >= sizeof(candidate) ||
            !platform_directory_canonical_real(candidate, canonical,
                                               sizeof(canonical)))
            return false;
#endif
    }
#if defined(_WIN32)
    uintptr_t directory = 0;
    if (!platform_private_directory_open_validated(canonical, &directory))
        return false;
    platform_private_directory_close(directory);
#endif
    int copied = snprintf(out, NPRC_PATH_MAX, "%s", canonical);
    return copied > 0 && copied < NPRC_PATH_MAX;
}

static int nprc_evidence_db_path(const char *proof_datadir, const char *task,
                                 char db_path[NPRC_PATH_MAX])
{
    char datadir[NPRC_PATH_MAX];
    int dn = nprc_evidence_datadir(proof_datadir, task, datadir)
        ? (int)strlen(datadir) : -1;
    return dn > 0 && (size_t)dn < sizeof(datadir)
        ? snprintf(db_path, NPRC_PATH_MAX, "%s/node.db", datadir) : -1;
}

static bool nprc_evidence_ledger_open(int bn, char db_path[NPRC_PATH_MAX],
                                      struct node_db *local_ndb,
                                      struct node_db **ndb, bool *owned)
{
    *ndb = app_runtime_node_db();
    *owned = bn > 0 && (size_t)bn < NPRC_PATH_MAX &&
        app_runtime_node_db_handle_open(*ndb) &&
        strcmp(db_path, (*ndb)->path) == 0;
    if (!*owned) *ndb = local_ndb;
    return bn > 0 && (size_t)bn < NPRC_PATH_MAX &&
        (*owned || node_db_open_existing_runtime(
             *ndb, db_path, "presentation.release-confirm"));
}

static const char *nprc_proof_authority_name(
    const struct build_fabric_proof_evaluation *facts)
{
    return facts->local_reproduced
        ? "LOCAL_CLEAN_SHADOW" : facts->quorum_satisfied
            ? "APPROVED_SIGNER_QUORUM" : "UNTRUSTED";
}

static bool nprc_evidence_facts_push(
    struct json_value *evidence,
    const struct build_fabric_proof_evaluation *facts)
{
    const char *authority = nprc_proof_authority_name(facts);
    return json_push_kv_int(evidence, "compile_receipts",
                            (int64_t)facts->compile_receipts) &&
        json_push_kv_int(evidence, "test_receipts",
                         (int64_t)facts->test_receipts) &&
        json_push_kv_int(evidence, "approved_distinct_signers",
                         (int64_t)facts->approved_distinct_signers) &&
        json_push_kv_bool(evidence, "local_reproduced",
                          facts->local_reproduced) &&
        json_push_kv_bool(evidence, "quorum_satisfied",
                          facts->quorum_satisfied) &&
        json_push_kv_bool(evidence, "compile_satisfied",
                          facts->compile_satisfied) &&
        json_push_kv_bool(evidence, "test_satisfied",
                          facts->test_satisfied) &&
        json_push_kv_bool(evidence, "policy_satisfied",
                          facts->policy_satisfied) &&
        json_push_kv_str(evidence, "proof_set_root",
                         facts->proof_set_root_sha3) &&
        json_push_kv_str(evidence, "authority", authority);
}

static bool nprc_evidence_read(const char *workspace,
                               const struct json_value *status,
                               const char *proof_datadir,
                               struct json_value *evidence,
                               char *why, size_t why_cap)
{
    const struct json_value *expert = nprc_object(status, "expert");
    const char *task = nprc_str(expert, "task_root");
    const char *action = nprc_str(expert, "action_id");
    uint8_t root[32];
    if (!nprc_root(task, root) || !nprc_root(action, root)) {
        (void)snprintf(why, why_cap, "work status omitted exact proof roots");
        return false;
    }
    char db_path[NPRC_PATH_MAX];
    int bn = nprc_evidence_db_path(proof_datadir, task, db_path);
    struct node_db local_ndb = {0};
    struct node_db *ndb = NULL;
    bool owned = false;
    if (!nprc_evidence_ledger_open(bn, db_path, &local_ndb, &ndb, &owned)) {
        (void)snprintf(why, why_cap,
                       "candidate proof ledger is unavailable");
        return false;
    }
    struct build_fabric_proof_evaluation facts;
    struct zcl_result result = build_fabric_proof_evaluate_readonly(
        ndb, workspace, action, (int64_t)platform_time_wall_unix(), &facts);
    if (!owned) node_db_close(ndb);
    if (!result.ok) {
        (void)snprintf(why, why_cap, "%s", result.message);
        return false;
    }
    json_set_object(evidence);
    return nprc_evidence_facts_push(evidence, &facts);
}

static bool nprc_arguments_missing(const struct zcl_command_request *request,
                                   const struct zcl_command_reply *reply)
{
    return !request || !reply || !request->input;
}

static const char *nprc_workspace_argument(const char *workspace_arg)
{
    return workspace_arg && workspace_arg[0] ? workspace_arg : ".";
}

static bool nprc_work_status_fetch(struct zcl_command_reply *status,
                                   const char *workspace, const char *work,
                                   const char *proof_datadir, bool *input_ok)
{
    struct json_value status_input;
    json_init(&status_input); json_set_object(&status_input);
    static const char status_details_key[] = "details";
    *input_ok = json_push_kv_str(&status_input, "workspace", workspace) &&
        json_push_kv_bool(&status_input, status_details_key, true) &&
        (!work || json_push_kv_str(&status_input, "work", work)) &&
        (!proof_datadir || json_push_kv_str(
            &status_input, "datadir", proof_datadir));
    struct zcl_command_request status_request = { .input = &status_input };
    zcl_command_reply_init(status, "zcl.zcode_work_status.v1");
    if (*input_ok)
        zcl_native_handle_zcode_work_status(&status_request, status);
    json_free(&status_input);
    return *input_ok && status->exit_code == ZCL_COMMAND_EXIT_OK;
}

static void nprc_work_status_unavailable_message(
    char *message, size_t message_cap, bool input_ok,
    const struct zcl_command_reply *status)
{
    (void)snprintf(message, message_cap, "%s",
                   input_ok && status->error.message[0]
                       ? status->error.message
                       : "canonical work status is unavailable");
}

static bool nprc_confirmation_model_build(
    bool evidence_ok, const struct json_value *status_data,
    struct json_value *evidence, struct zcl_present_model_v1 *model,
    char identity[65], char *why, size_t why_cap, char *work_id,
    size_t work_id_cap)
{
    const char *canonical_work = nprc_str(status_data, "work_id");
    bool built = evidence_ok &&
        zcl_native_presentation_release_confirm_model_from_facts(
            status_data, evidence, model, identity, why, why_cap) &&
        canonical_work && strlen(canonical_work) < work_id_cap;
    if (built)
        (void)snprintf(work_id, work_id_cap, "%s", canonical_work);
    return built;
}

static bool nprc_decision_summary_push(struct zcl_command_reply *reply,
                                       const char *identity, bool *confirmed)
{
    const char *action = nprc_str(&reply->data, "action_id");
    bool observed = action &&
        (strcmp(action, "confirm") == 0 || strcmp(action, "cancel") == 0);
    *confirmed = action && strcmp(action, "confirm") == 0;
    if (observed)
        (void)json_push_kv_str(&reply->data, "human_decision",
                              *confirmed ? "CONFIRM" : "CANCEL");
    (void)json_push_kv_str(&reply->data, "confirmation_identity", identity);
    (void)json_push_kv_bool(&reply->data, "human_confirmation_observed",
                           observed);
    (void)json_push_kv_bool(&reply->data, "human_confirmed", *confirmed);
    (void)json_push_kv_bool(&reply->data, "candidate_accepted", false);
    (void)json_push_kv_bool(&reply->data, "source_applied", false);
    (void)json_push_kv_bool(&reply->data, "publication_performed", false);
    (void)json_push_kv_str(&reply->data, "effect_boundary",
                          "separate_zcode_work_accept_rechecks_everything");
    return observed;
}

static bool nprc_accept_handoff_append(struct zcl_command_reply *reply,
                                       const char *workspace,
                                       const char *work_id,
                                       const char *identity)
{
    struct json_value next_input;
    json_init(&next_input); json_set_object(&next_input);
    bool next_ok = json_push_kv_str(&next_input, "workspace", workspace) &&
        json_push_kv_str(&next_input, "work", work_id) &&
        json_push_kv_str(&next_input, "confirmation_identity", identity);
    char wire[sizeof(reply->next[0].input_json)];
    size_t wire_len = next_ok
        ? json_write(&next_input, wire, sizeof(wire)) : 0;
    next_ok = wire_len > 0 && wire_len < sizeof(wire) &&
        zcl_command_reply_add_next(
            reply, "zcode.work.accept", wire,
            "after reviewing the consequence, accept this exact version");
    json_free(&next_input);
    return next_ok;
}

void zcl_native_handle_presentation_release_confirm(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (nprc_arguments_missing(request, reply)) return;
    const char *workspace_arg = nprc_str(request->input, "workspace");
    const char *work = nprc_str(request->input, "work");
    const char *proof_datadir = nprc_str(request->input, "datadir");
    if (zcl_native_forward_live_command(
            request, proof_datadir, "zcode_work_release_confirm",
            "LIVE_RELEASE_CONFIRM_FAILED", "present",
            "app.presentation.release-confirm", reply))
        return;
    workspace_arg = nprc_workspace_argument(workspace_arg);
    char workspace[NPRC_PATH_MAX];
    if (!platform_directory_canonical_real(workspace_arg, workspace,
                                           sizeof(workspace))) {
        nprc_fail(reply, "BAD_WORKSPACE",
                  "workspace must resolve to an existing directory",
                  workspace_arg);
        return;
    }
    struct zcl_command_reply status;
    bool input_ok = false;
    if (!nprc_work_status_fetch(&status, workspace, work, proof_datadir,
                                &input_ok)) {
        char message[192];
        nprc_work_status_unavailable_message(message, sizeof(message),
                                             input_ok, &status);
        zcl_command_reply_free(&status);
        nprc_fail(reply, "WORK_STATUS_UNAVAILABLE", message, NPRC_LEAF);
        return;
    }
    struct json_value evidence;
    json_init(&evidence);
    char why[192];
    bool evidence_ok = nprc_evidence_read(
        workspace, &status.data, proof_datadir, &evidence, why, sizeof(why));
    struct zcl_present_model_v1 model;
    char identity[65] = {0};
    char work_id[32] = {0};
    bool built = nprc_confirmation_model_build(
        evidence_ok, &status.data, &evidence, &model, identity, why,
        sizeof(why), work_id, sizeof(work_id));
    json_free(&evidence);
    zcl_command_reply_free(&status);
    if (!built) {
        nprc_fail(reply, "RELEASE_CONFIRMATION_NOT_READY", why,
                  "wait for the exact proof policy to become GREEN");
        return;
    }
    zcl_native_present_model(&model, NPRC_LEAF, request->input, reply);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) return;
    bool confirmed = false;
    bool observed = nprc_decision_summary_push(reply, identity, &confirmed);
    if (!observed || confirmed) {
        if (!nprc_accept_handoff_append(reply, workspace, work_id, identity))
            nprc_fail(reply, "ACCEPT_HANDOFF_FAILED",
                      "exact acceptance input could not be rendered",
                      NPRC_LEAF);
    }
}
