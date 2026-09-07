/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `zcode work accept` — the one human decision that advances an
 * exact proven candidate, signed by this node's own operator identity, and
 * binds the accepted work to the publication job that follows it. Split out
 * of native_zcode_work_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_priv.h. Acceptance never applies, signs or publishes the
 * source: it only moves the lane. */

#include "command/native_command.h"
#include "native_zcode_work_priv.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "services/zcode_lane_service.h"
#include "vcs/vcs_devloop.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_index.h"

#include <stdio.h>
#include <string.h>

/* The four publication roots the accepted lane binding produced. */
struct zwork_accept_publication_hex {
    char job[65];
    char progress[65];
    char commit[65];
    char proof[65];
};

/* The accepted lane receipt names the exact candidate whose retained
 * workspace enters publication; both identities must decode first. */
static bool zwork_accepted_roots(
    const struct zcl_command_reply *accepted_reply,
    const struct vcs_zcode_task_index_entry *entry,
    uint8_t accepted_root[32], uint8_t source_root[32])
{
    const struct json_value *accepted_value = accepted_reply
        ? json_get(&accepted_reply->data, "lane_receipt_root") : NULL;
    const char *accepted_hex = accepted_value &&
            accepted_value->type == JSON_STR
        ? json_get_str(accepted_value) : NULL;
    return accepted_hex && entry &&
        entry->latest_candidate_sequence != 0 &&
        entry->latest_candidate_sequence <= UINT32_MAX &&
        zcl_hex_decode_lower(accepted_hex, accepted_root, 32) &&
        zcl_hex_decode_lower(entry->latest_candidate_source_root_hex,
                             source_root, 32);
}

static bool zwork_bind_accepted_publication(
    const char *workspace, const struct vcs_zcode_task_index_entry *entry,
    const struct zcl_command_reply *accepted_reply,
    char candidate_workspace[ZWORK_PATH_MAX],
    struct vcs_devloop_accepted_candidate_result *publication)
{
    if (!candidate_workspace || !publication) return false;
    candidate_workspace[0] = '\0';
    memset(publication, 0, sizeof(*publication));
    uint8_t accepted_root[32], source_root[32];
    if (!workspace || !zwork_accepted_roots(accepted_reply, entry,
                                            accepted_root, source_root))
        return false;
    char candidate_path[ZWORK_PATH_MAX];
    char suffix[48];
    int n = snprintf(suffix, sizeof(suffix), "/attempt-%u",
                     (uint32_t)entry->latest_candidate_sequence);
    if (n <= 0 || (size_t)n >= sizeof(suffix) ||
        !zwork_task_path(candidate_path, entry->task_root_hex, suffix) ||
        !platform_directory_canonical_real(
            candidate_path, candidate_workspace, ZWORK_PATH_MAX))
        return false;
    vcs_devloop_publication_bind_accepted_candidate(
        workspace, candidate_workspace, accepted_root, source_root,
        platform_time_wall_unix(), publication);
    return publication->ok;
}

static int zwork_accept_lane_target(const char *lane)
{
    return lane && strcmp(lane, "CANDIDATE") == 0
        ? VCS_ZCODE_LANE_CANDIDATE
        : lane && strcmp(lane, "PROVEN") == 0
            ? VCS_ZCODE_LANE_PROVEN : 0;
}

/* The resident node's own handle when this is its datadir, otherwise the
 * task-local acceptance ledger, which acceptance never creates. */
static struct node_db *zwork_accept_open(const char *datadir, int target,
                                         struct node_db *local,
                                         bool *owned_out)
{
    char db_path[ZWORK_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    struct node_db *ndb = n > 0 && (size_t)n < sizeof(db_path)
        ? zwork_runtime_ledger(db_path) : NULL;
    *owned_out = ndb != NULL;
    if (target == 0 || n <= 0 || (size_t)n >= sizeof(db_path)) return NULL;
    return ndb ? ndb
        : (zwork_open_build_ledger(local, db_path, "zcode.work.accept",
                                   false) ? local : NULL);
}

static void zwork_accept_status_json(struct zcl_command_reply *reply,
                                     const struct zcode_lane_status *status)
{
    (void)json_push_kv_str(&reply->data, "lane", status->lane_name);
    (void)json_push_kv_str(&reply->data, "source_root",
                           status->source_root_sha3);
    (void)json_push_kv_str(&reply->data, "task_root",
                           status->task_root_sha3);
    (void)json_push_kv_str(&reply->data, "candidate_root",
                           status->candidate_root_sha3);
    (void)json_push_kv_str(&reply->data, "proof_policy_root",
                           status->proof_policy_root_sha3);
    (void)json_push_kv_str(&reply->data, "proof_set_root",
                           status->proof_set_root_sha3);
    (void)json_push_kv_str(&reply->data, "lane_receipt_root",
                           status->receipt_root_sha3);
    (void)json_push_kv_str(&reply->data, "prior_lane_receipt_root",
                           status->prior_receipt_root_sha3);
    (void)json_push_kv_str(&reply->data, "signer_pubkey",
                           status->signer_pubkey);
}

static void zwork_accept_inner(const char *workspace, const char *datadir,
                               const char *action_id, const char *lane,
                               struct zcl_command_reply *reply)
{
    int target = zwork_accept_lane_target(lane);
    struct node_db local_ndb = {0};
    bool owned = false;
    struct node_db *ndb = zwork_accept_open(datadir, target, &local_ndb,
                                            &owned);
    struct db_build_worker signer;
    uint8_t secret[32] = {0}, pubkey[32] = {0};
    struct zcode_lane_status status;
    int64_t now = (int64_t)platform_time_wall_unix();
    struct zcl_result result = ndb
        ? build_fabric_worker_identity_load(
              datadir, &signer, secret, pubkey)
        : ZCL_ERR(-1, "human acceptance ledger could not be opened");
    /* Acceptance is signed by this node's own operator identity, which lives
     * in this datadir. A requester node runs no build worker on purpose — it
     * must not be able to prove its own work — so nothing else ever enrolls
     * that key here, and without this the last human step of the journey
     * refuses every candidate with an unapproved signer. Enrollment is
     * first-use only: an identity the operator revoked or let expire keeps
     * refusing. */
    if (result.ok) {
        signer.last_seen_at = now;
        result = build_fabric_worker_enroll_local(ndb, &signer, now);
    }
    if (result.ok)
        result = zcode_lane_advance(
            ndb, workspace, action_id, target, now, secret, pubkey, &status);
    memory_cleanse(secret, sizeof(secret));
    if (ndb && !owned) node_db_close(ndb);
    if (!result.ok) {
        zwork_fail(reply, "LANE_PROMOTION_REFUSED", "accept",
                   result.message, false, false);
        return;
    }
    zwork_accept_status_json(reply, &status);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void zwork_lane_inner(const char *workspace, const char *datadir,
                             const char *source_root,
                             struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "datadir", datadir) &&
        json_push_kv_str(&input, "source_root", source_root);
    if (ok) {
        struct zcl_command_request request = { .input = &input };
        zcl_native_handle_zcode_lane(&request, reply);
    }
    json_free(&input);
    if (!ok)
        zwork_fail(reply, "LANE_INPUT_FAILED", "compose",
                   "existing lane lookup input could not be composed",
                   false, false);
}

static void zwork_evidence_inner(const char *workspace, const char *datadir,
                                 const char *action_id,
                                 struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "workspace", workspace) &&
        json_push_kv_str(&input, "datadir", datadir) &&
        json_push_kv_str(&input, "action_id", action_id);
    if (ok) {
        struct zcl_command_request request = { .input = &input };
        zcl_native_handle_zcode_evidence(&request, reply);
    }
    json_free(&input);
    if (!ok)
        zwork_fail(reply, "EVIDENCE_INPUT_FAILED", "compose",
                   "existing evidence evaluation input could not be composed",
                   false, false);
}

/* A read-only reopen of the acceptance ledger, closed again by the caller
 * unless the resident node owns the handle. */
static struct node_db *zwork_accept_read_ledger(const char *datadir,
                                                const char *reason,
                                                struct node_db *local,
                                                bool *owned_out)
{
    char db_path[ZWORK_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(db_path)) return NULL;
    struct node_db *ndb = zwork_runtime_ledger(db_path);
    *owned_out = ndb != NULL;
    if (ndb) return ndb;
    return node_db_open_existing_runtime(local, db_path, reason)
        ? local : NULL;
}

static bool zwork_accept_action_better(struct node_db *ndb,
                                       const char *workspace,
                                       const char *action_id, int64_t now,
                                       const char *out)
{
    struct build_fabric_proof_evaluation facts = {0};
    return build_fabric_proof_evaluate_readonly(
               ndb, workspace, action_id, now, &facts).ok &&
        facts.policy_satisfied &&
        (!out[0] || strcmp(action_id, out) < 0);
}

/* The workspace index deliberately projects every valid signed receipt, but
 * acceptance authority lives in the task-local build ledger. Resolve the
 * action whose independently re-evaluated proof policy is satisfied; an
 * unrelated later display receipt must never redirect acceptance. */
static bool zwork_accept_action_resolve(
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_index_entry *entry,
    char out[BUILD_FABRIC_ID_HEX + 1])
{
    if (!workspace || !datadir || !entry || !out) return false;
    out[0] = '\0';
    struct node_db local = {0};
    bool owned = false;
    struct node_db *ndb = zwork_accept_read_ledger(
        datadir, "zcode.work.accept.action", &local, &owned);
    struct db_build_action actions[64];
    int count = ndb ? db_build_candidate_actions(
        ndb, entry->task_root_hex, entry->latest_candidate_root_hex,
        entry->proof_policy_root_hex, actions,
        sizeof(actions) / sizeof(actions[0])) : 0;
    int64_t now = (int64_t)platform_time_wall_unix();
    for (int i = 0; i < count; i++)
        if (zwork_accept_action_better(ndb, workspace, actions[i].action_id,
                                       now, out))
            (void)snprintf(out, BUILD_FABRIC_ID_HEX + 1, "%s",
                           actions[i].action_id);
    if (ndb && !owned) node_db_close(ndb);
    return out[0] != '\0';
}

/* A native confirmation names the exact acceptance plan the operator saw;
 * any drift in the proof set invalidates it. */
static bool zwork_accept_confirmation(
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_index_entry *entry, const char *action,
    const char *confirmed_identity, char acceptance_hex[65])
{
    struct node_db local_identity_db = {0};
    bool identity_owned = false;
    struct node_db *identity_db = zwork_accept_read_ledger(
        datadir, "zcode.work.accept.confirmation", &local_identity_db,
        &identity_owned);
    struct build_fabric_proof_evaluation identity_facts;
    bool identity_ready = identity_db != NULL;
    if (identity_ready) {
        identity_ready = build_fabric_proof_evaluate_readonly(
            identity_db, workspace, action,
            (int64_t)platform_time_wall_unix(), &identity_facts).ok;
        if (!identity_owned) node_db_close(identity_db);
    }
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    uint8_t proof_root[32], acceptance_root[32], supplied_root[32];
    identity_ready = identity_ready &&
        zcl_hex_decode_lower(entry->task_root_hex, task_root, 32) &&
        zcl_hex_decode_lower(entry->latest_candidate_root_hex,
                             candidate_root, 32) &&
        zcl_hex_decode_lower(entry->proof_policy_root_hex,
                             policy_root, 32) &&
        zcl_hex_decode_lower(identity_facts.proof_set_root_sha3,
                             proof_root, 32) &&
        vcs_zcode_acceptance_plan_root(
            task_root, candidate_root, policy_root, proof_root,
            acceptance_root) == VCS_ZCODE_DEV_OK;
    if (identity_ready)
        zcl_hex_encode(acceptance_root, 32, acceptance_hex);
    return identity_ready &&
        zcl_hex_decode_lower(confirmed_identity, supplied_root, 32) &&
        memcmp(supplied_root, acceptance_root, 32) == 0;
}

static bool zwork_accept_resolve(
    const char *workspace, const char *work,
    struct vcs_zcode_task_index **index_out,
    const struct vcs_zcode_task_index_entry **entry_out,
    struct zcl_command_reply *reply)
{
    struct vcs_zcode_task_index *index = vcs_zcode_task_index_build(
        workspace, platform_time_wall_unix());
    bool ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? zwork_resolve(index, work, &ambiguous) : NULL;
    bool ready = entry && !entry->expired &&
        (strcmp(entry->state, VCS_ZCODE_TASK_STATE_EVIDENCE_READY) == 0 ||
         strcmp(entry->state,
                VCS_ZCODE_TASK_STATE_CANDIDATE_PROOFS_READY) == 0 ||
         strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) == 0);
    if (!ready || !entry->latest_action_root_hex[0] ||
        !entry->latest_candidate_source_root_hex[0]) {
        zwork_fail(reply, ambiguous ? "AMBIGUOUS_WORK" :
                     "WORK_NOT_READY_FOR_ACCEPTANCE", "accept",
                   entry && entry->expired ? "task expired" :
                   "the latest candidate lacks verified passing evidence",
                   false, false);
        vcs_zcode_task_index_free(index);
        return false;
    }
    *index_out = index;
    *entry_out = entry;
    return true;
}

static bool zwork_accept_datadir(
    const char *proof_datadir,
    const struct vcs_zcode_task_index_entry *entry,
    char datadir[ZWORK_PATH_MAX], struct zcl_command_reply *reply)
{
    int n = proof_datadir && proof_datadir[0]
        ? (platform_directory_canonical_real(
               proof_datadir, datadir, ZWORK_PATH_MAX)
            ? (int)strlen(datadir) : -1)
        : (zwork_task_path(datadir, entry->task_root_hex, "/zbuild")
            ? (int)strlen(datadir) : -1);
    if (n > 0 && n < ZWORK_PATH_MAX) return true;
    zwork_fail(reply, "ACCEPT_PATH_FAILED", "resolve",
               proof_datadir && proof_datadir[0]
                 ? "explicit proof datadir must resolve to an existing directory"
                 : "task-local ZBuild path is too long", false, false);
    return false;
}

static void zwork_accept_publication_hex(
    const struct vcs_devloop_accepted_candidate_result *publication,
    struct zwork_accept_publication_hex *hex)
{
    zcl_hex_encode(publication->publication_job_root, 32, hex->job);
    zcl_hex_encode(publication->publication_progress_root, 32,
                   hex->progress);
    zcl_hex_encode(publication->vcs_commit_root, 32, hex->commit);
    zcl_hex_encode(publication->proof_receipt_root, 32, hex->proof);
}

static bool zwork_accept_summary_json(
    struct zcl_command_reply *reply, const char *work_id,
    const char *acceptance_hex, const char *confirmed_identity,
    bool already_proven, bool details)
{
    return json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "goal_decision", "accepted") &&
        json_push_kv_str(&reply->data, "state", "PROVEN") &&
        json_push_kv_str(&reply->data, "stage", "Accepted") &&
        (!details || !confirmed_identity ||
         json_push_kv_str(&reply->data, "confirmation_identity",
                          acceptance_hex)) &&
        json_push_kv_bool(&reply->data, "confirmation_identity_checked",
                          confirmed_identity != NULL) &&
        json_push_kv_bool(&reply->data, "idempotent", already_proven);
}

static bool zwork_accept_status_fields_json(
    struct zcl_command_reply *reply,
    const struct vcs_devloop_accepted_candidate_result *publication)
{
    return json_push_kv_str(&reply->data, "authoritative_workspace",
                            "unchanged") &&
        json_push_kv_str(&reply->data, "publication_status",
                         "ACCEPTED_LANE_BOUND") &&
        json_push_kv_bool(&reply->data, "publication_reused",
                          publication->reused) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode work publish") &&
        json_push_kv_bool(&reply->data, "details_available", true);
}

static bool zwork_accept_details_json(
    struct zcl_command_reply *reply, const char *workspace,
    const char *retained_candidate_workspace,
    const struct zwork_accept_publication_hex *hex,
    struct json_value *expert, bool details)
{
    return !details || (
        json_push_kv_str(&reply->data, "publication_workspace",
                         workspace) &&
        json_push_kv_str(&reply->data, "candidate_workspace",
                         retained_candidate_workspace) &&
        json_push_kv_str(&reply->data, "publication_job_root",
                         hex->job) &&
        json_push_kv_str(&reply->data, "publication_progress_root",
                         hex->progress) &&
        json_push_kv_str(&reply->data, "publication_commit_root",
                         hex->commit) &&
        json_push_kv_str(
            &reply->data, "publication_proof_receipt_root",
            hex->proof) &&
        json_push_kv(&reply->data, "expert", expert));
}

static bool zwork_accept_next_json(struct zcl_command_reply *reply,
                                   const char *workspace,
                                   const char *datadir, const char *work_id,
                                   const char *job_hex)
{
    struct json_value next_input;
    json_init(&next_input); json_set_object(&next_input);
    bool ok = json_push_kv_str(&next_input, "workspace", workspace) &&
        json_push_kv_str(&next_input, "work", work_id) &&
        json_push_kv_str(&next_input, "datadir", datadir) &&
        json_push_kv_str(&next_input, "job_root", job_hex) &&
        zwork_add_next(
            reply, "zcode.work.publish", &next_input,
            "advance the accepted exact source through its existing publication job");
    json_free(&next_input);
    return ok;
}

/* Acceptance is only finished once the retained candidate and the accepted
 * work identity have entered the publication continuation. */
static void zwork_accept_accepted(
    struct zcl_command_reply *reply, const char *workspace,
    const char *datadir, const struct vcs_zcode_task_index_entry *entry,
    const struct zcl_command_reply *final_reply, const char *acceptance_hex,
    const char *confirmed_identity, bool already_proven, bool details)
{
    char retained_candidate_workspace[ZWORK_PATH_MAX] = {0};
    struct vcs_devloop_accepted_candidate_result publication;
    if (!zwork_bind_accepted_publication(
            workspace, entry, final_reply, retained_candidate_workspace,
            &publication)) {
        zwork_fail(reply, "ACCEPTED_PUBLICATION_BIND_FAILED", "publish",
                   publication.error[0] ? publication.error :
                   "the retained candidate or accepted-work identity could not enter dev.publication",
                   true, true);
        return;
    }
    struct json_value expert;
    json_init(&expert); json_copy(&expert, &final_reply->data);
    const struct json_value *accepted_root_value =
        json_get(&final_reply->data, "lane_receipt_root");
    const char *accepted_work_root = accepted_root_value &&
            accepted_root_value->type == JSON_STR
        ? json_get_str(accepted_root_value) : NULL;
    struct zwork_accept_publication_hex hex;
    zwork_accept_publication_hex(&publication, &hex);
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    bool ok = accepted_work_root &&
        json_push_kv_str(&expert, "accepted_work_root",
                         accepted_work_root) &&
        zwork_accept_summary_json(reply, work_id, acceptance_hex,
                                  confirmed_identity, already_proven,
                                  details) &&
        zwork_accept_status_fields_json(reply, &publication) &&
        zwork_accept_details_json(reply, workspace,
                                  retained_candidate_workspace, &hex,
                                  &expert, details) &&
        zwork_accept_next_json(reply, workspace, datadir, work_id, hex.job);
    json_free(&expert);
    if (!ok)
        zwork_fail(reply, "ACCEPT_OUTPUT_FAILED", "render",
                   "human acceptance summary could not be rendered",
                   false, !already_proven);
}

/* The exact proof profile must be satisfied again here, and a candidate on
 * the frontier is promoted one lane at a time. */
static bool zwork_accept_promote(struct zcl_command_reply *reply,
                                 const char *workspace, const char *datadir,
                                 const char *action, const char *lane,
                                 struct zcl_command_reply *final_reply)
{
    struct zcl_command_reply evidence;
    zcl_command_reply_init(&evidence, "zcl.zcode_evidence.v1");
    zwork_evidence_inner(workspace, datadir, action, &evidence);
    const struct json_value *satisfied = evidence.status ==
            ZCL_COMMAND_STATUS_PASSED
        ? json_get(&evidence.data, "policy_satisfied") : NULL;
    if (!satisfied || !json_get_bool(satisfied)) {
        zwork_fail(reply, "PROOF_PROFILE_INCOMPLETE", "evidence",
                   evidence.status == ZCL_COMMAND_STATUS_PASSED
                     ? "the exact proof profile is not yet satisfied; preserved evidence remains inspectable"
                     : evidence.error.message,
                   true, false);
        zcl_command_reply_free(&evidence);
        return false;
    }
    zcl_command_reply_free(&evidence);
    if (strcmp(lane, "FRONTIER") == 0) {
        struct zcl_command_reply candidate;
        zcl_command_reply_init(&candidate, "zcl.zcode_accept.v1");
        zwork_accept_inner(workspace, datadir, action, "CANDIDATE",
                           &candidate);
        if (candidate.status != ZCL_COMMAND_STATUS_PASSED) {
            zwork_fail(reply, "CANDIDATE_ACCEPTANCE_REFUSED", "accept",
                       candidate.error.message, false, false);
            zcl_command_reply_free(&candidate);
            return false;
        }
        zcl_command_reply_free(&candidate);
    }
    zwork_accept_inner(workspace, datadir, action, "PROVEN", final_reply);
    return true;
}

static void zwork_accept_lane(
    struct zcl_command_reply *reply, const char *workspace,
    const char *datadir, const struct vcs_zcode_task_index_entry *entry,
    const char *action, const char *acceptance_hex,
    const char *confirmed_identity, bool details)
{
    struct zcl_command_reply lane_reply;
    zcl_command_reply_init(&lane_reply, "zcl.zcode_lane.v1");
    zwork_lane_inner(workspace, datadir,
                     entry->latest_candidate_source_root_hex, &lane_reply);
    const struct json_value *lane_value = lane_reply.status ==
            ZCL_COMMAND_STATUS_PASSED
        ? json_get(&lane_reply.data, "lane") : NULL;
    const char *lane = lane_value && lane_value->type == JSON_STR
        ? json_get_str(lane_value) : NULL;
    if (!lane) {
        zwork_fail(reply, "LANE_STATE_MISSING", "accept",
                   lane_reply.error.message[0] ? lane_reply.error.message :
                   "the signed FRONTIER lane could not be reloaded",
                   true, false);
        zcl_command_reply_free(&lane_reply);
        return;
    }
    bool already_proven = strcmp(lane, "PROVEN") == 0;
    struct zcl_command_reply final_reply;
    zcl_command_reply_init(&final_reply, "zcl.zcode_accept.v1");
    if (already_proven) {
        json_copy(&final_reply.data, &lane_reply.data);
        final_reply.status = ZCL_COMMAND_STATUS_PASSED;
    } else if (!zwork_accept_promote(reply, workspace, datadir, action, lane,
                                     &final_reply)) {
        zcl_command_reply_free(&final_reply);
        zcl_command_reply_free(&lane_reply);
        return;
    }
    if (final_reply.status != ZCL_COMMAND_STATUS_PASSED)
        zwork_fail(reply, "PROVEN_ACCEPTANCE_REFUSED", "accept",
                   final_reply.error.message, false, true);
    else
        zwork_accept_accepted(reply, workspace, datadir, entry, &final_reply,
                              acceptance_hex, confirmed_identity,
                              already_proven, details);
    zcl_command_reply_free(&final_reply);
    zcl_command_reply_free(&lane_reply);
}

static void zwork_accept_run(struct zcl_command_reply *reply,
                             const char *workspace,
                             const struct vcs_zcode_task_index_entry *entry,
                             const char *confirmed_identity,
                             const char *proof_datadir, bool details)
{
    char datadir[ZWORK_PATH_MAX];
    if (!zwork_accept_datadir(proof_datadir, entry, datadir, reply)) return;
    char acceptance_action[BUILD_FABRIC_ID_HEX + 1];
    if (!zwork_accept_action_resolve(workspace, datadir, entry,
                                     acceptance_action)) {
        zwork_fail(reply, "PROOF_PROFILE_INCOMPLETE", "evidence",
                   "no canonical action currently satisfies the exact proof profile",
                   true, false);
        return;
    }
    char acceptance_hex[65] = {0};
    if (confirmed_identity &&
        !zwork_accept_confirmation(workspace, datadir, entry,
                                   acceptance_action, confirmed_identity,
                                   acceptance_hex)) {
        zwork_fail(reply, "CONFIRMATION_IDENTITY_STALE", "accept",
                   "the confirmed native decision no longer matches the exact candidate proof set",
                   false, false);
        return;
    }
    zwork_accept_lane(reply, workspace, datadir, entry, acceptance_action,
                      acceptance_hex, confirmed_identity, details);
}

void zcl_native_handle_zcode_work_accept(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zwork_str(request->input, "workspace");
    const char *work = zwork_str(request->input, "work");
    const char *confirmed_identity =
        zwork_str(request->input, "confirmation_identity");
    const char *proof_datadir = zwork_str(request->input, "datadir");
    bool details = zwork_bool(request->input, "details");
    if (zcl_native_forward_live_command(
            request, proof_datadir, "zcode_work_accept",
            "LIVE_WORK_ACCEPT_FAILED", "accept", "zcode.work.accept",
            reply))
        return;
    if (!workspace_arg || !workspace_arg[0]) workspace_arg = ".";
    char workspace[ZWORK_PATH_MAX];
    if (!platform_directory_canonical_real(
            workspace_arg, workspace, sizeof(workspace))) {
        zwork_fail(reply, "BAD_WORKSPACE", "resolve",
                   "workspace must resolve to an existing directory",
                   false, false);
        return;
    }
    struct vcs_zcode_task_index *index = NULL;
    const struct vcs_zcode_task_index_entry *entry = NULL;
    if (!zwork_accept_resolve(workspace, work, &index, &entry, reply))
        return;
    zwork_accept_run(reply, workspace, entry, confirmed_identity,
                     proof_datadir, details);
    vcs_zcode_task_index_free(index);
}
