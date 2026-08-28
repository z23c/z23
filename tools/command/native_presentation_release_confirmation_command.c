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
    bool state_ready = state &&
        (strcmp(state, "EVIDENCE_READY") == 0 ||
         strcmp(state, "CANDIDATE_PROOFS_READY") == 0);
    if (!model || !identity || !state_ready || !nprc_value_fits(goal) ||
        !nprc_root(task, task_root) || !nprc_root(candidate, candidate_root) ||
        !nprc_root(policy, policy_root) || !nprc_root(proof, proof_root) ||
        !authority || !authority[0] || compile < 0 || tests < 0 ||
        signers < 0 || !nprc_bool(evidence, "policy_satisfied") ||
        !nprc_bool(evidence, "compile_satisfied") ||
        !nprc_bool(evidence, "test_satisfied") ||
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
                   (long long)compile, compile == 1 ? "" : "s");
    nprc_item(model, "compile", "COMPILE EVIDENCE", count,
              ZCL_PRESENT_STATUS_GREEN);
    (void)snprintf(count, sizeof(count), "%lld passing test receipt%s",
                   (long long)tests, tests == 1 ? "" : "s");
    nprc_item(model, "tests", "BEHAVIOR EVIDENCE", count,
              ZCL_PRESENT_STATUS_GREEN);
    (void)snprintf(count, sizeof(count), "%lld approved distinct signer%s",
                   (long long)signers, signers == 1 ? "" : "s");
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
    char datadir[NPRC_PATH_MAX], db_path[NPRC_PATH_MAX];
    int dn = nprc_evidence_datadir(proof_datadir, task, datadir)
        ? (int)strlen(datadir) : -1;
    int bn = dn > 0 && (size_t)dn < sizeof(datadir)
        ? snprintf(db_path, sizeof(db_path), "%s/node.db", datadir) : -1;
    struct node_db local_ndb = {0};
    struct node_db *ndb = app_runtime_node_db();
    bool owned = bn > 0 && (size_t)bn < sizeof(db_path) &&
        app_runtime_node_db_handle_open(ndb) &&
        strcmp(db_path, ndb->path) == 0;
    if (!owned) ndb = &local_ndb;
    if (bn <= 0 || (size_t)bn >= sizeof(db_path) ||
        (!owned && !node_db_open_existing_runtime(
            ndb, db_path, "presentation.release-confirm"))) {
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
    const char *authority = facts.local_reproduced
        ? "LOCAL_CLEAN_SHADOW" : facts.quorum_satisfied
            ? "APPROVED_SIGNER_QUORUM" : "UNTRUSTED";
    return json_push_kv_int(evidence, "compile_receipts",
                            (int64_t)facts.compile_receipts) &&
        json_push_kv_int(evidence, "test_receipts",
                         (int64_t)facts.test_receipts) &&
        json_push_kv_int(evidence, "approved_distinct_signers",
                         (int64_t)facts.approved_distinct_signers) &&
        json_push_kv_bool(evidence, "local_reproduced",
                          facts.local_reproduced) &&
        json_push_kv_bool(evidence, "quorum_satisfied",
                          facts.quorum_satisfied) &&
        json_push_kv_bool(evidence, "compile_satisfied",
                          facts.compile_satisfied) &&
        json_push_kv_bool(evidence, "test_satisfied",
                          facts.test_satisfied) &&
        json_push_kv_bool(evidence, "policy_satisfied",
                          facts.policy_satisfied) &&
        json_push_kv_str(evidence, "proof_set_root",
                         facts.proof_set_root_sha3) &&
        json_push_kv_str(evidence, "authority", authority);
}

void zcl_native_handle_presentation_release_confirm(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply || !request->input) return;
    const char *workspace_arg = nprc_str(request->input, "workspace");
    const char *work = nprc_str(request->input, "work");
    const char *proof_datadir = nprc_str(request->input, "datadir");
    if (zcl_native_forward_live_command(
            request, proof_datadir, "zcode_work_release_confirm",
            "LIVE_RELEASE_CONFIRM_FAILED", "present",
            "app.presentation.release-confirm", reply))
        return;
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    char workspace[NPRC_PATH_MAX];
    if (!platform_directory_canonical_real(workspace_arg, workspace,
                                           sizeof(workspace))) {
        nprc_fail(reply, "BAD_WORKSPACE",
                  "workspace must resolve to an existing directory",
                  workspace_arg);
        return;
    }
    struct json_value status_input;
    json_init(&status_input); json_set_object(&status_input);
    static const char status_details_key[] = "details";
    bool input_ok = json_push_kv_str(&status_input, "workspace", workspace) &&
        json_push_kv_bool(&status_input, status_details_key, true) &&
        (!work || json_push_kv_str(&status_input, "work", work)) &&
        (!proof_datadir || json_push_kv_str(
            &status_input, "datadir", proof_datadir));
    struct zcl_command_request status_request = { .input = &status_input };
    struct zcl_command_reply status;
    zcl_command_reply_init(&status, "zcl.zcode_work_status.v1");
    if (input_ok)
        zcl_native_handle_zcode_work_status(&status_request, &status);
    json_free(&status_input);
    if (!input_ok || status.exit_code != ZCL_COMMAND_EXIT_OK) {
        char message[192];
        (void)snprintf(message, sizeof(message), "%s",
                       input_ok && status.error.message[0]
                           ? status.error.message
                           : "canonical work status is unavailable");
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
    const char *canonical_work = nprc_str(&status.data, "work_id");
    bool built = evidence_ok &&
        zcl_native_presentation_release_confirm_model_from_facts(
            &status.data, &evidence, &model, identity, why, sizeof(why)) &&
        canonical_work && strlen(canonical_work) < sizeof(work_id);
    if (built)
        (void)snprintf(work_id, sizeof(work_id), "%s", canonical_work);
    json_free(&evidence);
    zcl_command_reply_free(&status);
    if (!built) {
        nprc_fail(reply, "RELEASE_CONFIRMATION_NOT_READY", why,
                  "wait for the exact proof policy to become GREEN");
        return;
    }
    zcl_native_present_model(&model, NPRC_LEAF, request->input, reply);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) return;
    const char *action = nprc_str(&reply->data, "action_id");
    bool observed = action &&
        (strcmp(action, "confirm") == 0 || strcmp(action, "cancel") == 0);
    bool confirmed = action && strcmp(action, "confirm") == 0;
    if (observed)
        (void)json_push_kv_str(&reply->data, "human_decision",
                              confirmed ? "CONFIRM" : "CANCEL");
    (void)json_push_kv_str(&reply->data, "confirmation_identity", identity);
    (void)json_push_kv_bool(&reply->data, "human_confirmation_observed",
                           observed);
    (void)json_push_kv_bool(&reply->data, "human_confirmed", confirmed);
    (void)json_push_kv_bool(&reply->data, "candidate_accepted", false);
    (void)json_push_kv_bool(&reply->data, "source_applied", false);
    (void)json_push_kv_bool(&reply->data, "publication_performed", false);
    (void)json_push_kv_str(&reply->data, "effect_boundary",
                          "separate_zcode_work_accept_rechecks_everything");
    if (!observed || confirmed) {
        struct json_value next_input;
        json_init(&next_input); json_set_object(&next_input);
        bool next_ok = json_push_kv_str(
                           &next_input, "workspace", workspace) &&
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
        if (!next_ok)
            nprc_fail(reply, "ACCEPT_HANDOFF_FAILED",
                      "exact acceptance input could not be rendered",
                      NPRC_LEAF);
    }
}
