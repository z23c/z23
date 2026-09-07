/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `zcode work review` — one independent human review recorded as a
 * signed canonical receipt against one exact candidate. Split out of
 * native_zcode_work_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_priv.h. The whole recording is one fail-closed
 * transaction: it names the stage it stopped at and preserves every prior
 * piece of canonical evidence. */

#include "command/native_command.h"
#include "native_zcode_work_priv.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/database.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/time_compat.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "vcs/build_action.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_index.h"
#include "vcs/zcode_work_swarm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The bounded manual-review request, already defaulted and closed. */
struct zwork_review_input {
    const char *workspace_arg;
    const char *work;
    const char *adapter;
    const char *verdict_text;
    const char *findings;
    uint8_t verdict;
};

/* One review transaction: its scratch ledger, the base action it reviews,
 * the reviewer identity, and the stage it last reached. */
struct zwork_review_session {
    struct node_db ndb;
    bool opened;
    char datadir[ZWORK_PATH_MAX];
    char reviewer_dir[ZWORK_PATH_MAX];
    struct db_build_action base_action;
    struct db_build_action review_action;
    struct db_build_job base_job;
    struct build_fabric_proof_evaluation before;
    struct build_fabric_proof_evaluation after;
    struct db_build_worker reviewer;
    uint8_t secret[32];
    uint8_t pubkey[32];
    uint8_t review_root[32];
    char receipt_root[65];
    const char *failed_stage;
};

static bool zwork_review_load_objects(
    const char *workspace, const struct vcs_zcode_task_index_entry *entry,
    struct vcs_zcode_task_v1 *task,
    struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t root[32], *wire = NULL;
    size_t wire_len = 0;
    bool ok = zcl_hex_decode_lower(entry->task_root_hex, root, 32) &&
        vcs_object_load_raw(workspace, root, &wire, &wire_len) == 0 &&
        vcs_zcode_task_parse(wire, wire_len, task) == VCS_ZCODE_DEV_OK;
    free(wire); wire = NULL; wire_len = 0;
    if (!ok || !zcl_hex_decode_lower(entry->latest_candidate_root_hex,
                                     root, 32) ||
        vcs_object_load_raw(workspace, root, &wire, &wire_len) != 0 ||
        vcs_zcode_candidate_parse(wire, wire_len, candidate) !=
            VCS_ZCODE_DEV_OK) {
        free(wire);
        return false;
    }
    free(wire);
    return vcs_zcode_candidate_validate_for_task(
               task, candidate, platform_time_wall_unix()) ==
           VCS_ZCODE_DEV_OK;
}

static bool zwork_review_action(
    struct node_db *ndb, const struct db_build_action *base,
    const struct db_build_job *base_job, int64_t now,
    struct db_build_action *review)
{
    memset(review, 0, sizeof(*review));
    review->sequence = base->sequence + 1;
    (void)snprintf(review->kind, sizeof(review->kind), "%s",
                   VCS_BUILD_ACTION_KIND_REVIEW_V1);
    (void)snprintf(review->state, sizeof(review->state), "SNAPSHOTTED");
    (void)snprintf(review->input_root_sha3,
                   sizeof(review->input_root_sha3), "%s",
                   base->candidate_root_sha3);
    (void)snprintf(review->task_root_sha3,
                   sizeof(review->task_root_sha3), "%s",
                   base->task_root_sha3);
    (void)snprintf(review->candidate_root_sha3,
                   sizeof(review->candidate_root_sha3), "%s",
                   base->candidate_root_sha3);
    (void)snprintf(review->proof_policy_root_sha3,
                   sizeof(review->proof_policy_root_sha3), "%s",
                   base->proof_policy_root_sha3);
    (void)snprintf(review->target, sizeof(review->target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t flags[32], environment[32];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(
            review->kind, flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            review->kind, environment))
        return false;
    zcl_hex_encode(flags, 32, review->flags_sha3);
    zcl_hex_encode(environment, 32, review->environment_sha3);
    (void)snprintf(review->virtual_workdir,
                   sizeof(review->virtual_workdir), "%s",
                   VCS_BUILD_REVIEW_VIRTUAL_ROOT_V1);
    (void)snprintf(review->declared_outputs,
                   sizeof(review->declared_outputs), "%s",
                   VCS_BUILD_REVIEW_OUTPUT_V1);
    (void)snprintf(review->resource_policy,
                   sizeof(review->resource_policy), "%s",
                   VCS_BUILD_REVIEW_RESOURCE_POLICY_V1);
    review->created_at = review->updated_at = now;
    struct db_build_job job = *base_job;
    job.job_id[0] = '\0';
    (void)snprintf(job.state, sizeof(job.state), "PLANNED");
    job.outcome[0] = '\0';
    job.created_at = job.updated_at = now;
    if (!build_fabric_action_id(&job, review, review->action_id).ok ||
        !build_fabric_job_id(&job, review->action_id, job.job_id).ok)
        return false;
    (void)snprintf(review->job_id, sizeof(review->job_id), "%s", job.job_id);
    return db_build_job_save(ndb, &job) && db_build_action_save(ndb, review);
}

static bool zwork_review_receipt(
    struct node_db *ndb, const char *workspace,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const struct db_build_action *action, const uint8_t proof_set_root[32],
    const uint8_t review_root[32], const uint8_t secret[32],
    const uint8_t pubkey[32], int64_t now, char receipt_root[65])
{
    struct vcs_zcode_work_request_v1 request = {
        .request_id = (uint64_t)now,
        .work_kind = VCS_ZCODE_WORK_REVIEW,
        .target = VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3,
        .max_cpu_seconds = task->max_cpu_seconds,
        .max_memory_bytes = task->max_memory_bytes,
        .max_output_bytes = task->max_output_bytes,
        .deadline_unix = task->expires_unix - 1,
    };
    uint8_t task_root[32], candidate_root[32], action_root[32];
    if (vcs_zcode_task_root(task, task_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        !zcl_hex_decode_lower(action->action_id, action_root, 32))
        return false;
    memcpy(request.task_root, task_root, 32);
    memcpy(request.candidate_root, candidate_root, 32);
    memcpy(request.action_root, action_root, 32);
    memcpy(request.input_root, candidate_root, 32);
    memcpy(request.context_root, proof_set_root, 32);
    memcpy(request.proof_policy_root, task->proof_policy_root, 32);
    memcpy(request.toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    if (!vcs_zcode_work_request_seal(&request, secret, pubkey))
        return false;
    struct vcs_zcode_work_result_v1 result = {0};
    result.request_id = request.request_id;
    memcpy(result.task_root, task_root, 32);
    memcpy(result.candidate_root, candidate_root, 32);
    memcpy(result.action_root, action_root, 32);
    memcpy(result.output_root, review_root, 32);
    struct vcs_zcode_work_receipt_v1 *receipt = &result.receipt;
    receipt->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(receipt->task_root, task_root, 32);
    memcpy(receipt->candidate_root, candidate_root, 32);
    memcpy(receipt->action_root, action_root, 32);
    memcpy(receipt->input_root, candidate_root, 32);
    memcpy(receipt->output_root, review_root, 32);
    memcpy(receipt->proof_policy_root, task->proof_policy_root, 32);
    memcpy(receipt->toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    static const char lease_domain[] = "zcl.zcode.review.manual.lease.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)lease_domain,
                   sizeof(lease_domain));
    sha3_256_write(&sha, review_root, 32);
    sha3_256_finalize(&sha, receipt->lease_id);
    memcpy(receipt->evidence_root, proof_set_root, 32);
    static const char confinement[] =
        "zcode-review:manual;candidate=read-only;accept=0;publish=0";
    sha3_256((const uint8_t *)confinement, sizeof(confinement),
             receipt->confinement_root);
    receipt->work_kind = VCS_ZCODE_WORK_REVIEW;
    receipt->status = VCS_ZCODE_WORK_PASS;
    receipt->started_unix = now > 0 ? now - 1 : 0;
    receipt->finished_unix = now;
    if (vcs_zcode_work_receipt_seal(receipt, secret, pubkey) !=
        VCS_ZCODE_DEV_OK)
        return false;
    return build_fabric_receipt_observe_remote(
               ndb, workspace, &request, &result, now, receipt_root).ok;
}

static uint8_t zwork_review_verdict(const char *text)
{
    return text && strcmp(text, "approve") == 0
        ? VCS_ZCODE_REVIEW_APPROVE
        : text && strcmp(text, "request_changes") == 0
        ? VCS_ZCODE_REVIEW_REQUEST_CHANGES
        : text && strcmp(text, "reject") == 0
        ? VCS_ZCODE_REVIEW_REJECT : 0;
}

static bool zwork_review_validate(const struct zcl_command_request *request,
                                  struct zwork_review_input *in,
                                  struct zcl_command_reply *reply)
{
    in->workspace_arg = zwork_str(request->input, "workspace");
    in->work = zwork_str(request->input, "work");
    in->adapter = zwork_str(request->input, "adapter");
    in->verdict_text = zwork_str(request->input, "verdict");
    in->findings = zwork_str(request->input, "findings");
    if (!in->workspace_arg || !in->workspace_arg[0]) in->workspace_arg = ".";
    if (!in->adapter || !in->adapter[0]) in->adapter = "manual";
    in->verdict = zwork_review_verdict(in->verdict_text);
    if (strcmp(in->adapter, "manual") != 0 || in->verdict == 0 ||
        !in->findings || in->findings[0] == '\0' ||
        strlen(in->findings) > 4096u) {
        zwork_fail(reply, strcmp(in->adapter, "manual") != 0
                         ? "REVIEW_ADAPTER_UNAVAILABLE" : "BAD_REVIEW_INPUT",
                   "review", "manual review requires a closed verdict and 1..4096 bytes of findings",
                   false, false);
        return false;
    }
    return true;
}

/* The review runs against the task-local scratch ledger, which it may
 * create: a review never touches the operator's node datadir. */
static bool zwork_review_open(struct zwork_review_session *s,
                              const struct vcs_zcode_task_index_entry *entry)
{
    char db_path[ZWORK_PATH_MAX];
    int dn = zwork_task_path(s->datadir, entry->task_root_hex, "/zbuild")
        ? (int)strlen(s->datadir) : -1;
    int rn = snprintf(s->reviewer_dir, sizeof(s->reviewer_dir),
                      "%s/reviewer", s->datadir);
    int bn = snprintf(db_path, sizeof(db_path), "%s/node.db", s->datadir);
    s->opened = dn > 0 && (size_t)dn < sizeof(s->datadir) && rn > 0 &&
        (size_t)rn < sizeof(s->reviewer_dir) && bn > 0 &&
        (size_t)bn < sizeof(db_path) && zwork_open_build_ledger(
            &s->ndb, db_path, "zcode.work.review", true);
    s->failed_stage = s->opened ? "base_action" : "scratch_ledger";
    return s->opened;
}

/* Only a candidate that already carries signed non-review evidence, and no
 * review yet, can be reviewed. */
static bool zwork_review_base(struct zwork_review_session *s,
                              const char *workspace,
                              const struct vcs_zcode_task_index_entry *entry,
                              int64_t now)
{
    bool ready = db_build_action_find(
        &s->ndb, entry->latest_action_root_hex, &s->base_action);
    if (ready) s->failed_stage = "base_job";
    ready = ready && db_build_job_find(&s->ndb, s->base_action.job_id,
                                       &s->base_job);
    if (ready) s->failed_stage = "non_review_proof_set";
    return ready && build_fabric_proof_evaluate(
        &s->ndb, workspace, entry->latest_action_root_hex, now,
        &s->before).ok &&
        s->before.valid_receipts > 0 && s->before.review_receipts == 0;
}

/* The reviewer is a separate approved identity in its own private
 * directory; a candidate may never review itself. */
static bool zwork_review_reviewer(
    struct zwork_review_session *s,
    const struct vcs_zcode_candidate_v1 *candidate, int64_t now)
{
    s->failed_stage = "reviewer_directory";
#if defined(_WIN32)
    bool ready = platform_private_directory_ensure(s->reviewer_dir);
#else
    bool ready = zcl_mkdir_p(s->reviewer_dir, 0700).ok;
#endif
    if (ready) s->failed_stage = "reviewer_identity";
    ready = ready && build_fabric_worker_identity_load(
        s->reviewer_dir, &s->reviewer, s->secret, s->pubkey).ok;
    if (ready) s->failed_stage = "reviewer_independence";
    ready = ready && memcmp(s->pubkey, candidate->author_pubkey, 32) != 0;
    if (ready) s->failed_stage = "reviewer_approval";
    return ready && build_fabric_worker_approve(&s->ndb, &s->reviewer,
                                                now).ok;
}

static bool zwork_review_store(struct zwork_review_session *s,
                               const char *workspace,
                               const struct vcs_zcode_review_v1 *review,
                               const uint8_t findings_root[32],
                               const char *findings)
{
    s->failed_stage = "findings_store";
    uint8_t review_wire[VCS_ZCODE_REVIEW_WIRE_BYTES];
    bool ready = vcs_object_put_addressed(
        workspace, findings_root, (const uint8_t *)findings,
        strlen(findings));
    if (ready) s->failed_stage = "review_wire";
    ready = ready && vcs_zcode_review_serialize(
        review, review_wire) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_review_root(review, s->review_root) == VCS_ZCODE_DEV_OK;
    if (ready) s->failed_stage = "review_store";
    return ready && vcs_object_put_addressed(
        workspace, s->review_root, review_wire, sizeof(review_wire));
}

/* The findings, the review object, its action and its signed receipt are
 * one ordered chain; each step names itself before it is attempted. */
static bool zwork_review_compose(
    struct zwork_review_session *s, const char *workspace,
    const char *action_id, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, const char *findings,
    uint8_t verdict, int64_t now)
{
    uint8_t proof_set_root[32], findings_root[32];
    struct vcs_zcode_review_v1 review = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .verdict = verdict,
        .sequence = 1,
        .created_unix = now,
    };
    s->failed_stage = "proof_set_root";
    if (!zcl_hex_decode_lower(s->before.proof_set_root_sha3,
                              proof_set_root, 32))
        return false;
    (void)vcs_zcode_task_root(task, review.task_root);
    (void)vcs_zcode_candidate_root(candidate, review.candidate_root);
    memcpy(review.proof_policy_root, task->proof_policy_root, 32);
    memcpy(review.proof_set_root, proof_set_root, 32);
    sha3_256((const uint8_t *)findings, strlen(findings), findings_root);
    memcpy(review.findings_root, findings_root, 32);
    memcpy(review.reviewer_pubkey, s->pubkey, 32);
    if (!zwork_review_store(s, workspace, &review, findings_root, findings))
        return false;
    s->failed_stage = "review_action";
    if (!zwork_review_action(&s->ndb, &s->base_action, &s->base_job, now,
                             &s->review_action))
        return false;
    s->failed_stage = "review_receipt";
    if (!zwork_review_receipt(&s->ndb, workspace, task, candidate,
                              &s->review_action, proof_set_root,
                              s->review_root, s->secret, s->pubkey, now,
                              s->receipt_root))
        return false;
    s->failed_stage = "proof_re_evaluation";
    return build_fabric_proof_evaluate(&s->ndb, workspace, action_id, now,
                                       &s->after).ok;
}

static void zwork_review_refused(struct zcl_command_reply *reply,
                                 const struct zwork_review_session *s)
{
    char detail[256];
    (void)snprintf(detail, sizeof(detail),
                   "review stopped at %s; prior canonical evidence is preserved",
                   s->failed_stage);
    zwork_fail(reply, s->before.review_receipts > 0
                 ? "REVIEW_ALREADY_PRESENT" : "REVIEW_EXECUTION_FAILED",
               s->failed_stage,
               s->before.review_receipts > 0
                 ? "the candidate already has a trusted review; conflicting-review support is not yet complete"
                 : detail,
               true, s->opened);
}

static bool zwork_review_reply_json(
    struct zcl_command_reply *reply,
    const struct vcs_zcode_task_index_entry *entry, const char *verdict_text,
    const struct zwork_review_session *s)
{
    char review_hex[65], reviewer_hex[65];
    zcl_hex_encode(s->review_root, 32, review_hex);
    zcl_hex_encode(s->pubkey, 32, reviewer_hex);
    char work_id[32];
    (void)snprintf(work_id, sizeof(work_id), "work-%.12s",
                   entry->task_root_hex);
    return json_push_kv_str(&reply->data, "work_id", work_id) &&
        json_push_kv_str(&reply->data, "adapter", "manual") &&
        json_push_kv_str(&reply->data, "verdict", verdict_text) &&
        json_push_kv_bool(&reply->data, "independent_reviewer", true) &&
        json_push_kv_int(&reply->data, "review_receipts",
                         (int64_t)s->after.review_receipts) &&
        json_push_kv_bool(&reply->data, "review_satisfied",
                          s->after.review_satisfied) &&
        json_push_kv_bool(&reply->data, "policy_satisfied",
                          s->after.policy_satisfied) &&
        json_push_kv_str(&reply->data, "review_root", review_hex) &&
        json_push_kv_str(&reply->data, "work_receipt_root",
                         s->receipt_root) &&
        json_push_kv_str(&reply->data, "reviewer_pubkey", reviewer_hex) &&
        json_push_kv_str(&reply->data, "proof_set_reviewed",
                         s->before.proof_set_root_sha3) &&
        json_push_kv_str(&reply->data, "next_safe_command",
                         "zcode work status");
}

/* Object, action, receipt and evidence evaluation are one fail-closed
 * operation over one candidate: any stage that refuses leaves the prior
 * canonical evidence exactly as it was. */
static void zwork_review_transaction(
    struct zcl_command_reply *reply, const struct zwork_review_input *in,
    const char *workspace,
    const struct vcs_zcode_task_index_entry *entry,
    const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate, int64_t now)
{
    struct zwork_review_session s = {0};
    bool ready = zwork_review_open(&s, entry) &&
        zwork_review_base(&s, workspace, entry, now) &&
        zwork_review_reviewer(&s, candidate, now) &&
        zwork_review_compose(&s, workspace, entry->latest_action_root_hex,
                             task, candidate, in->findings, in->verdict, now);
    memory_cleanse(s.secret, sizeof(s.secret));
    if (s.opened) node_db_close(&s.ndb);
    if (!ready) {
        zwork_review_refused(reply, &s);
        return;
    }
    if (!zwork_review_reply_json(reply, entry, in->verdict_text, &s))
        zwork_fail(reply, "REVIEW_OUTPUT_FAILED", "render",
                   "review result could not be rendered", false, true);
}

void zcl_native_handle_zcode_work_review(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    struct zwork_review_input in;
    if (!zwork_review_validate(request, &in, reply)) return;
    char workspace[ZWORK_PATH_MAX];
    if (!platform_directory_canonical_real(
            in.workspace_arg, workspace, sizeof(workspace))) {
        zwork_fail(reply, "BAD_WORKSPACE", "resolve",
                   "workspace must resolve to an existing directory",
                   false, false);
        return;
    }
    int64_t now = platform_time_wall_unix();
    struct vcs_zcode_task_index *index =
        vcs_zcode_task_index_build(workspace, now);
    bool ambiguous = false;
    const struct vcs_zcode_task_index_entry *entry = index
        ? zwork_resolve(index, in.work, &ambiguous) : NULL;
    struct vcs_zcode_task_v1 task;
    struct vcs_zcode_candidate_v1 candidate;
    if (!entry || entry->expired || !entry->latest_action_root_hex[0] ||
        !zwork_review_load_objects(workspace, entry, &task, &candidate)) {
        zwork_fail(reply, ambiguous ? "AMBIGUOUS_WORK" : "WORK_NOT_REVIEWABLE",
                   "review", "a current candidate with signed non-review evidence is required",
                   false, false);
        vcs_zcode_task_index_free(index);
        return;
    }
    zwork_review_transaction(reply, &in, workspace, entry, &task, &candidate,
                             now);
    vcs_zcode_task_index_free(index);
}
