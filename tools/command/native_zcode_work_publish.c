/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `zcode work publish` — advance one already-accepted exact work
 * through the publication job that acceptance queued for it. Split out of
 * native_zcode_work_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_priv.h. A job locator never grants acceptance: the
 * queued job must bind the currently accepted work before anything runs. */

#include "command/native_command.h"
#include "native_zcode_work_priv.h"

#include "base/hex.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/time_compat.h"
#include "services/zcode_lane_service.h"
#include "vcs/vcs_devloop.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_index.h"

#include <stdio.h>
#include <string.h>

/* The oldest link of the chain: the receipt that bound this accepted work,
 * which must itself descend from a job that was only waiting for it. */
static bool zwork_publication_origin(
    const char *workspace, const uint8_t job_root[32],
    const struct vcs_zcode_accepted_work_v1 *accepted,
    struct vcs_devloop_publication_receipt *progress)
{
    if (memcmp(progress->artifact_root,
               accepted->accepted_work_root, 32) != 0 ||
        !vcs_devloop_publication_receipt_load(
            workspace, progress->predecessor_receipt_root, progress))
        return false;
    const uint8_t zero[32] = {0};
    return progress->phase ==
            VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE &&
        memcmp(progress->job_root, job_root, 32) == 0 &&
        memcmp(progress->predecessor_receipt_root, zero, 32) == 0;
}

/* A job locator never grants acceptance. Follow its existing, root-checked
 * progress chain back to the exact accepted lane before invoking its owner. */
static bool zwork_publication_bound(
    const char *workspace, const uint8_t job_root[32],
    const struct vcs_zcode_accepted_work_v1 *accepted,
    enum vcs_devloop_publication_phase *phase)
{
    struct vcs_devloop_publication_job job;
    struct vcs_devloop_publication_receipt progress;
    uint8_t progress_root[32];
    if (!vcs_devloop_publication_job_load(workspace, job_root, &job) ||
        !vcs_devloop_publication_job_is_queued(workspace, job_root) ||
        memcmp(job.source_tree_root,
               accepted->candidate.candidate_source_root, 32) != 0 ||
        !vcs_devloop_publication_progress_load(
            workspace, job_root, &progress, progress_root))
        return false;
    *phase = progress.phase;
    for (unsigned i = 0; i < VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED;
         i++) {
        if (memcmp(progress.job_root, job_root, 32) != 0) return false;
        if (progress.phase == VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND)
            return zwork_publication_origin(workspace, job_root, accepted,
                                            &progress);
        if (progress.phase <= VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND ||
            progress.phase > VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)
            return false;
        enum vcs_devloop_publication_phase prior_phase = progress.phase;
        if (!vcs_devloop_publication_receipt_load(
                workspace, progress.predecessor_receipt_root, &progress) ||
            progress.phase != prior_phase - 1)
            return false;
    }
    return false;
}

static struct node_db *zwork_publish_open_ledger(const char *datadir,
                                                 struct node_db *local,
                                                 bool *owned_out)
{
    char db_path[ZWORK_PATH_MAX];
    int n = snprintf(db_path, sizeof(db_path), "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= sizeof(db_path)) return NULL;
    struct node_db *ndb = zwork_runtime_ledger(db_path);
    *owned_out = ndb != NULL;
    if (ndb) return ndb;
    return node_db_open_existing_runtime(local, db_path,
                                         "zcode.work.publish")
        ? local : NULL;
}

/* The accepted work this ledger knows must be the exact task, candidate and
 * policy the index row names, and the queued job must bind it. */
static bool zwork_publish_verify(
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_index_entry *entry,
    const uint8_t job_root[32],
    enum vcs_devloop_publication_phase *phase)
{
    struct node_db local = {0};
    bool owned = false;
    struct node_db *ndb = zwork_publish_open_ledger(datadir, &local, &owned);
    struct zcode_accepted_work_status accepted;
    uint8_t task_root[32], candidate_root[32], policy_root[32];
    bool verified = ndb && zcode_accepted_work_find(
        ndb, workspace, entry->latest_candidate_source_root_hex,
        (int64_t)platform_time_wall_unix(), false, &accepted).ok &&
        zcl_hex_decode_lower(entry->task_root_hex, task_root, 32) &&
        zcl_hex_decode_lower(entry->latest_candidate_root_hex, candidate_root, 32) &&
        zcl_hex_decode_lower(entry->proof_policy_root_hex, policy_root, 32) &&
        memcmp(task_root, accepted.accepted.task_root, 32) == 0 &&
        memcmp(candidate_root, accepted.accepted.candidate_root, 32) == 0 &&
        memcmp(policy_root, accepted.accepted.proof_policy_root, 32) == 0;
    if (ndb && !owned) node_db_close(ndb);
    return verified && zwork_publication_bound(workspace, job_root,
                                               &accepted.accepted, phase);
}

static bool zwork_publish_resolve(
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
    if (!entry || entry->expired ||
        strcmp(entry->state, VCS_ZCODE_TASK_STATE_PROVEN) != 0) {
        zwork_fail(reply, ambiguous ? "AMBIGUOUS_WORK" : "WORK_NOT_ACCEPTED",
                   "verify", "the current exact work must already be accepted",
                   false, false);
        vcs_zcode_task_index_free(index);
        return false;
    }
    *index_out = index;
    *entry_out = entry;
    return true;
}

/* Only these four publisher steps have their own typed input schema; every
 * other continuation returns the reader to work status. */
static const char *zwork_publish_schema(const char *next_safe)
{
    if (!next_safe) return NULL;
    if (strcmp(next_safe, "zcode package dev publish plan") == 0)
        return "zcode.package.dev.publish.plan";
    if (strcmp(next_safe, "zcode passport plan") == 0)
        return "zcode.passport.plan";
    if (strcmp(next_safe, "zcode workspace manifest plan") == 0)
        return "zcode.workspace.manifest.plan";
    if (strcmp(next_safe, "zcode network publish") == 0)
        return "zcode.network.publish";
    return NULL;
}

static bool zwork_publish_reply_json(
    struct zcl_command_reply *reply, const char *work_id, const char *status,
    const char *next_action, const char *next_safe, const char *schema)
{
    return status &&
        json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "status", status) &&
        json_push_kv_str(&reply->data, "stage", "Publishing") &&
        json_push_kv_str(&reply->data, "next_action", next_action ? next_action :
            strcmp(status, "SOURCE_REPRODUCED") == 0
                ? "Keep this accepted package available to other nodes."
                : "Continue collecting independent storage and source reproduction evidence.") &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         schema ? next_safe : "zcode work status") &&
        json_push_kv_bool(&reply->data, "acceptance_reverified", true) &&
        json_push_kv_bool(&reply->data, "details_available", true);
}

/* The publisher's own counters pass through unchanged when it reported
 * them; a missing counter is simply not reported. */
static bool zwork_publish_fields(struct zcl_command_reply *reply,
                                 const struct zcl_command_reply *inner)
{
    const char *fields[] = {"receipt_reused", "receipt_written", "network_called",
        "wallet_called", "package_written", "mapping_cache_written", "storage_acks",
        "reproduced", "physical_independence_attested"};
    bool rendered = true;
    for (size_t i = 0; rendered && i < sizeof(fields) / sizeof(fields[0]); i++) {
        const struct json_value *value = json_get(&inner->data, fields[i]);
        if (value) rendered = json_push_kv(&reply->data, fields[i], value);
    }
    return rendered;
}

static bool zwork_publish_next(struct zcl_command_reply *reply,
                               const char *schema, const char *workspace,
                               const char *datadir, const char *work_id)
{
    struct json_value next_input;
    json_init(&next_input); json_set_object(&next_input);
    bool rendered;
    if (schema) {
        rendered = json_push_kv_str(&next_input, "path", schema) &&
            zwork_add_next(reply, "discover.schema", &next_input,
                           "inspect the publisher inputs required by the existing next step");
    } else {
        rendered =
            json_push_kv_str(&next_input, "workspace", workspace) &&
            json_push_kv_str(&next_input, "datadir", datadir) &&
            json_push_kv_str(&next_input, "work", work_id) &&
            zwork_add_next(reply, "zcode.work.status", &next_input,
                           "inspect this accepted work and its current publication continuation");
    }
    json_free(&next_input);
    return rendered;
}

/* Two phases only collect independent evidence; every other phase advances
 * the chain and must reverify the acceptance it claims to publish. */
static void zwork_publish_run(struct zcl_command_reply *reply,
                              const char *workspace, const char *datadir,
                              const char *job_hex, const char *work_id,
                              enum vcs_devloop_publication_phase phase,
                              bool details)
{
    struct zcl_dev_publication_input publication = {
        .source_root = workspace,
        .workspace = workspace,
        .datadir = datadir,
        .job_root = job_hex,
        .details = details,
    };
    struct zcl_command_reply inner;
    zcl_command_reply_init(&inner, "zcl.zcode_work_publish.v1");
    bool collect = phase == VCS_DEVLOOP_PUBLICATION_PHASE_PROVIDER_ANNOUNCED ||
                   phase == VCS_DEVLOOP_PUBLICATION_PHASE_STORAGE_ACKNOWLEDGED;
    if (collect) zcl_dev_publication_collect(&publication, &inner);
    else zcl_dev_publication_advance(&publication, &inner);
    if (inner.status != ZCL_COMMAND_STATUS_PASSED) {
        reply->status = inner.status;
        reply->exit_code = inner.exit_code;
        reply->error = inner.error;
        zcl_command_reply_free(&inner);
        return;
    }
    if (!collect && !zwork_bool(&inner.data, "acceptance_reverified")) {
        zcl_command_reply_free(&inner);
        zwork_fail(reply, "WORK_PUBLICATION_MISMATCH", "verify",
                   "publication could not reverify the current accepted work",
                   true, false);
        return;
    }
    const char *next_safe = zwork_str(&inner.data, "next_safe_command");
    const char *schema = NULL;
    if (!collect && phase != VCS_DEVLOOP_PUBLICATION_PHASE_SOURCE_REPRODUCED)
        schema = zwork_publish_schema(next_safe);
    bool rendered = zwork_publish_reply_json(
            reply, work_id, zwork_str(&inner.data, "status"),
            zwork_str(&inner.data, "next_action"), next_safe, schema) &&
        zwork_publish_fields(reply, &inner) &&
        (!details || (
            json_push_kv_str(&reply->data, "publication_job_root", job_hex) &&
            json_push_kv(&reply->data, "expert", &inner.data))) &&
        zwork_publish_next(reply, schema, workspace, datadir, work_id);
    zcl_command_reply_free(&inner);
    if (!rendered)
        zwork_fail(reply, "PUBLICATION_OUTPUT_FAILED", "render",
                   "the publication continuation exceeded its output bound", false, true);
}

void zcl_native_handle_zcode_work_publish(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace_arg = zwork_str(request->input, "workspace");
    const char *work = zwork_str(request->input, "work");
    const char *proof_datadir = zwork_str(request->input, "datadir");
    const char *job_hex = zwork_str(request->input, "job_root");
    bool details = zwork_bool(request->input, "details");
    if (zcl_native_forward_live_command(
            request, proof_datadir, "zcode_work_publish",
            "LIVE_WORK_PUBLISH_FAILED", "publish", "zcode.work.publish",
            reply))
        return;
    char workspace[ZWORK_PATH_MAX], datadir[ZWORK_PATH_MAX];
    uint8_t job_root[32];
    if (!platform_directory_canonical_real(
            workspace_arg && workspace_arg[0] ? workspace_arg : ".",
            workspace, sizeof(workspace)) ||
        !job_hex || !zcl_hex_decode_lower(job_hex, job_root, 32)) {
        zwork_fail(reply, "BAD_PUBLICATION_INPUT", "resolve",
                   "use the exact publication continuation returned by work accept",
                   false, false);
        return;
    }
    struct vcs_zcode_task_index *index = NULL;
    const struct vcs_zcode_task_index_entry *entry = NULL;
    if (!zwork_publish_resolve(workspace, work, &index, &entry, reply))
        return;
    bool path_ok = proof_datadir && proof_datadir[0]
        ? platform_directory_canonical_real(proof_datadir, datadir, sizeof(datadir))
        : zwork_task_path(datadir, entry->task_root_hex, "/zbuild");
    enum vcs_devloop_publication_phase phase = 0;
    if (!path_ok || !zwork_publish_verify(workspace, datadir, entry,
                                          job_root, &phase)) {
        zwork_fail(reply, "WORK_PUBLICATION_MISMATCH", "verify",
                   "the queued publication must bind this exact currently accepted work",
                   false, false);
        vcs_zcode_task_index_free(index);
        return;
    }
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s", entry->task_root_hex);
    vcs_zcode_task_index_free(index);
    zwork_publish_run(reply, workspace, datadir, job_hex, work_id, phase,
                      details);
}
