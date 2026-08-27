/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Requester-local build lifecycle, trust, and receipt verification. */

#include "services/build_fabric_service.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include "vcs/build_action.h"

#include <stdio.h>
#include <string.h>

enum { BUILD_FABRIC_ACTION_LIMIT = 256 };

/* BUILD_FABRIC_ACTION_LIMIT * sizeof(struct db_build_action) is ~516 KiB.
 * That buffer must never live in an automatic: the callers run on ordinary
 * worker threads (the supervisor tick-runner among them) whose platform
 * default stack is 512 KiB on macOS, so one frame this large drives the stack
 * pointer past the guard page on entry. The kernel then cannot deliver the
 * resulting fault — a worker thread has no sigaltstack — and falls back to
 * its "process has trashed its stack" remedy: force SIGILL to SIG_DFL and
 * kill the process. The node dies with signal 4 / exit 132, no handler runs,
 * and the crash report blames whatever thread the signal happened to land on.
 * Always allocate this array on the heap. */
static struct db_build_action *bf_actions_scratch(const char *label)
{
    return zcl_malloc(BUILD_FABRIC_ACTION_LIMIT *
                      sizeof(struct db_build_action), label);
}

static void bf_sha_text(struct sha3_256_ctx *sha, const char *text)
{
    uint64_t len = text ? strlen(text) : 0;
    unsigned char le[8];
    for (unsigned i = 0; i < sizeof(le); i++)
        le[i] = (unsigned char)((len >> (i * 8U)) & 0xffU);
    sha3_256_write(sha, le, sizeof(le));
    if (len) sha3_256_write(sha, (const unsigned char *)text, (size_t)len);
}

static void bf_sha_i64(struct sha3_256_ctx *sha, int64_t value)
{
    uint64_t raw = (uint64_t)value;
    unsigned char le[8];
    for (unsigned i = 0; i < sizeof(le); i++)
        le[i] = (unsigned char)((raw >> (i * 8U)) & 0xffU);
    sha3_256_write(sha, le, sizeof(le));
}

static void bf_sha_finish(struct sha3_256_ctx *sha,
                          char out_hex[BUILD_FABRIC_ID_HEX + 1])
{
    uint8_t digest[32];
    sha3_256_finalize(sha, digest);
    zcl_hex_encode(digest, sizeof(digest), out_hex);
}

struct zcl_result build_fabric_action_id(
    const struct db_build_job *job, const struct db_build_action *action,
    char out_hex[BUILD_FABRIC_ID_HEX + 1])
{
    if (!job || !action || !out_hex)
        return ZCL_ERR(-1, "action id requires a job, action, and output");
    struct vcs_build_action_v1 canonical = {0};
    if (!zcl_hex_decode_lower(job->source_sha256, canonical.source_sha256, 32) ||
        !zcl_hex_decode_lower(job->source_cas_sha3,
                              canonical.source_cas_sha3, 32) ||
        !zcl_hex_decode_lower(action->input_root_sha3,
                              canonical.input_root_sha3, 32) ||
        !zcl_hex_decode_lower(job->toolchain_sha3,
                              canonical.toolchain_capsule_sha3, 32) ||
        !zcl_hex_decode_lower(action->flags_sha3, canonical.flags_sha3, 32) ||
        !zcl_hex_decode_lower(action->environment_sha3,
                              canonical.environment_sha3, 32))
        return ZCL_ERR(-1, "build action digests must be lowercase 64-hex");
    (void)snprintf(canonical.target, sizeof(canonical.target), "%s",
                   action->target);
    (void)snprintf(canonical.profile, sizeof(canonical.profile), "%s",
                   job->profile);
    (void)snprintf(canonical.virtual_workdir,
                   sizeof(canonical.virtual_workdir), "%s",
                   action->virtual_workdir);
    (void)snprintf(canonical.declared_outputs,
                   sizeof(canonical.declared_outputs), "%s",
                   action->declared_outputs);
    (void)snprintf(canonical.resource_policy,
                   sizeof(canonical.resource_policy), "%s",
                   action->resource_policy);
    canonical.sequence = (uint64_t)action->sequence;
    uint8_t digest[32];
    if (action->sequence < 0 ||
        !vcs_build_action_v1_root_for_kind(
            action->kind, &canonical, digest))
        return ZCL_ERR(-1, "build action violates the fixed V1 execution policy");
    zcl_hex_encode(digest, sizeof(digest), out_hex);
    return ZCL_OK;
}

struct zcl_result build_fabric_job_id(
    const struct db_build_job *job, const char *action_id,
    char out_hex[BUILD_FABRIC_ID_HEX + 1])
{
    if (!job || !action_id || strlen(action_id) != BUILD_FABRIC_ID_HEX ||
        !out_hex)
        return ZCL_ERR(-1, "job id requires immutable job inputs and action id");
    static const char domain[] = "zcl.build_job.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    bf_sha_text(&sha, job->source_sha256);
    bf_sha_text(&sha, job->source_cas_sha3);
    bf_sha_text(&sha, job->toolchain_sha3);
    bf_sha_text(&sha, job->profile);
    bf_sha_text(&sha, action_id);
    bf_sha_finish(&sha, out_hex);
    return ZCL_OK;
}

struct zcl_result build_fabric_receipt_id(
    const struct db_build_receipt *receipt,
    char out_hex[BUILD_FABRIC_ID_HEX + 1])
{
    if (!receipt || !out_hex)
        return ZCL_ERR(-1, "receipt id requires a receipt and output buffer");
    static const char domain_v2[] = "zcl.build_receipt.v2";
    static const char domain_v3[] = "zcl.build_receipt.v3";
    const char *domain = receipt->observation_sha3[0] ? domain_v3 : domain_v2;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const unsigned char *)domain,
                   strlen(domain) + 1u);
    bf_sha_text(&sha, receipt->action_id);
    bf_sha_text(&sha, receipt->job_id);
    bf_sha_text(&sha, receipt->worker_id);
    bf_sha_text(&sha, receipt->lease_id);
    bf_sha_text(&sha, receipt->action_sha3);
    bf_sha_text(&sha, receipt->output_sha3);
    if (receipt->observation_sha3[0])
        bf_sha_text(&sha, receipt->observation_sha3);
    bf_sha_text(&sha, receipt->work_receipt_sha3);
    bf_sha_text(&sha, receipt->confinement);
    bf_sha_i64(&sha, receipt->exit_status);
    bf_sha_i64(&sha, receipt->created_at);
    bf_sha_finish(&sha, out_hex);
    return ZCL_OK;
}

static bool bf_job_same_plan(const struct db_build_job *a,
                             const struct db_build_job *b)
{
    return strcmp(a->source_sha256, b->source_sha256) == 0 &&
           strcmp(a->source_cas_sha3, b->source_cas_sha3) == 0 &&
           strcmp(a->toolchain_sha3, b->toolchain_sha3) == 0 &&
           strcmp(a->profile, b->profile) == 0;
}

static bool bf_action_same_plan(const struct db_build_action *a,
                                const struct db_build_action *b)
{
    /* context_root_sha3 is a request-scoped content.v2 carrier, not part of
     * the already-frozen build_action.v1 identity. The same immutable action
     * may be transported by a freshly repacked equivalent context. */
    return strcmp(a->job_id, b->job_id) == 0 &&
           a->sequence == b->sequence && strcmp(a->kind, b->kind) == 0 &&
           strcmp(a->input_root_sha3, b->input_root_sha3) == 0 &&
           strcmp(a->task_root_sha3, b->task_root_sha3) == 0 &&
           strcmp(a->candidate_root_sha3, b->candidate_root_sha3) == 0 &&
           strcmp(a->proof_policy_root_sha3,
                  b->proof_policy_root_sha3) == 0 &&
           strcmp(a->target, b->target) == 0 &&
           strcmp(a->flags_sha3, b->flags_sha3) == 0 &&
           strcmp(a->environment_sha3, b->environment_sha3) == 0 &&
           strcmp(a->virtual_workdir, b->virtual_workdir) == 0 &&
           strcmp(a->declared_outputs, b->declared_outputs) == 0 &&
           strcmp(a->resource_policy, b->resource_policy) == 0;
}

static bool bf_lower_hex_id(const char *value)
{
    if (!value || strlen(value) != BUILD_FABRIC_ID_HEX)
        return false;
    for (size_t i = 0; i < BUILD_FABRIC_ID_HEX; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static bool bf_capability_has(const char *capabilities, const char *wanted)
{
    if (!capabilities || !wanted || !wanted[0])
        return false;
    size_t wanted_len = strlen(wanted);
    const char *at = capabilities;
    while (*at) {
        while (*at == ',' || *at == ' ' || *at == '\t') at++;
        const char *end = at;
        while (*end && *end != ',') end++;
        const char *trim = end;
        while (trim > at && (trim[-1] == ' ' || trim[-1] == '\t')) trim--;
        if ((size_t)(trim - at) == wanted_len &&
            memcmp(at, wanted, wanted_len) == 0)
            return true;
        at = *end ? end + 1 : end;
    }
    return false;
}

static bool bf_action_identity_current(const struct db_build_job *job,
                                       const struct db_build_action *action)
{
    char expected[BUILD_FABRIC_ID_HEX + 1];
    return build_fabric_action_id(job, action, expected).ok &&
           strcmp(expected, action->action_id) == 0;
}

struct zcl_result build_fabric_plan(struct node_db *ndb,
                                    const struct db_build_job *job,
                                    const struct db_build_action *action)
{
    if (!ndb || !ndb->open || !job || !action)
        return ZCL_ERR(-1, "build plan requires an open db, job, and action");
    if (strcmp(job->state, "PLANNED") != 0 ||
        strcmp(action->state, "SNAPSHOTTED") != 0 ||
        strcmp(job->job_id, action->job_id) != 0)
        return ZCL_ERR(-1, "build plan lifecycle or ownership is invalid");
    uint8_t fixed_flags[32], fixed_environment[32];
    char fixed_flags_hex[65], fixed_environment_hex[65];
    if (!vcs_build_action_v1_fixed_flags_root_for_kind(
            action->kind, fixed_flags) ||
        !vcs_build_action_v1_fixed_environment_root_for_kind(
            action->kind, fixed_environment))
        return ZCL_ERR(-1, "build plan action kind is not executable");
    zcl_hex_encode(fixed_flags, 32, fixed_flags_hex);
    zcl_hex_encode(fixed_environment, 32, fixed_environment_hex);
    if (strcmp(action->flags_sha3, fixed_flags_hex) != 0 ||
        strcmp(action->environment_sha3, fixed_environment_hex) != 0)
        return ZCL_ERR(-1, "supervisor fixed flags or environment mismatch");
    char expected_action[BUILD_FABRIC_ID_HEX + 1];
    char expected_job[BUILD_FABRIC_ID_HEX + 1];
    if (!build_fabric_action_id(job, action, expected_action).ok ||
        strcmp(expected_action, action->action_id) != 0 ||
        !build_fabric_job_id(job, action->action_id, expected_job).ok ||
        strcmp(expected_job, job->job_id) != 0)
        return ZCL_ERR(-1, "build plan ids do not match immutable inputs");
    struct db_build_job prior_job;
    bool have_job = db_build_job_find(ndb, job->job_id, &prior_job);
    if (have_job && !bf_job_same_plan(&prior_job, job))
        return ZCL_ERR(-1, "job id collides with a different immutable plan");
    struct db_build_action prior_action;
    bool have_action = db_build_action_find(ndb, action->action_id,
                                             &prior_action);
    if (have_action && !bf_action_same_plan(&prior_action, action))
        return ZCL_ERR(-1, "action id collides with different immutable inputs");
    /* An idempotent plan replay proves identity only.  In particular, it must
     * never rewind an already-queued or completed durable record. */
    if (have_job && have_action)
        return ZCL_OK;
    if (!node_db_begin(ndb))
        return ZCL_ERR(-1, "cannot begin build plan transaction");
    bool ok = (have_job || db_build_job_save(ndb, job)) &&
              (have_action || db_build_action_save(ndb, action)) &&
              node_db_commit(ndb);
    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "plan save and rollback both failed");
        return ZCL_ERR(-1, "cannot persist build plan atomically");
    }
    return ZCL_OK;
}

struct zcl_result build_fabric_plan_reproduction(
    struct node_db *ndb, const char *primary_action_id,
    const char *reproduction_profile, int64_t now,
    char out_action_id[BUILD_FABRIC_ID_HEX + 1],
    char out_job_id[BUILD_FABRIC_ID_HEX + 1])
{
    if (out_action_id) out_action_id[0] = '\0';
    if (out_job_id) out_job_id[0] = '\0';
    if (!ndb || !ndb->open || !bf_lower_hex_id(primary_action_id) ||
        !reproduction_profile || !reproduction_profile[0] ||
        strlen(reproduction_profile) > BUILD_FABRIC_PROFILE_MAX ||
        now <= 0 || !out_action_id || !out_job_id)
        return ZCL_ERR(-1, "reproduction plan requires exact inputs");
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, primary_action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job) ||
        !bf_action_identity_current(&job, &action))
        return ZCL_ERR(-1, "primary action is absent or noncanonical");
    if (strcmp(job.profile, reproduction_profile) == 0)
        return ZCL_ERR(-1, "reproduction profile must be distinct");

    (void)snprintf(job.profile, sizeof(job.profile), "%s",
                   reproduction_profile);
    job.job_id[0] = '\0';
    (void)snprintf(job.state, sizeof(job.state), "PLANNED");
    job.outcome[0] = '\0';
    job.cancel_requested = 0;
    job.created_at = job.updated_at = now;
    action.action_id[0] = '\0';
    action.job_id[0] = '\0';
    (void)snprintf(action.state, sizeof(action.state), "SNAPSHOTTED");
    action.outcome[0] = '\0';
    action.output_root_sha3[0] = '\0';
    action.worker_id[0] = '\0';
    action.lease_id[0] = '\0';
    action.last_error[0] = '\0';
    action.lease_expires_at = action.lease_heartbeat_at = 0;
    action.attempt_count = action.claimed_at = action.started_at = 0;
    action.finished_at = 0;
    action.created_at = action.updated_at = now;
    ZCL_CHECK(build_fabric_action_id(&job, &action, action.action_id));
    ZCL_CHECK(build_fabric_job_id(&job, action.action_id, job.job_id));
    (void)snprintf(action.job_id, sizeof(action.job_id), "%s", job.job_id);
    ZCL_CHECK(build_fabric_plan(ndb, &job, &action));
    (void)snprintf(out_action_id, BUILD_FABRIC_ID_HEX + 1u, "%s",
                   action.action_id);
    (void)snprintf(out_job_id, BUILD_FABRIC_ID_HEX + 1u, "%s", job.job_id);
    return ZCL_OK;
}

static bool bf_terminal(const char *state)
{
    return state && (strcmp(state, "ACCEPTED") == 0 ||
                     strcmp(state, "CACHE_HIT") == 0 ||
                     strcmp(state, "CANCELLED") == 0 ||
                     strcmp(state, "FAILED") == 0 ||
                     strcmp(state, "DISPUTED") == 0);
}

struct zcl_result build_fabric_submit(struct node_db *ndb,
                                      const char *job_id, int64_t now)
{
    struct db_build_job job;
    if (!ndb || !ndb->open || !job_id || !db_build_job_find(ndb, job_id, &job))
        return ZCL_ERR(-1, "build job not found");
    if (strcmp(job.state, "QUEUED") == 0)
        return ZCL_OK;
    if (strcmp(job.state, "PLANNED") != 0 &&
        strcmp(job.state, "SNAPSHOTTED") != 0)
        return ZCL_ERR(-1, "job state %s cannot transition to QUEUED", job.state);
    struct db_build_action *actions = bf_actions_scratch("build.submit.actions");
    if (!actions)
        return ZCL_ERR(-1, "cannot allocate build action scan buffer");
    int count = db_build_job_actions(ndb, job_id, actions,
                                     BUILD_FABRIC_ACTION_LIMIT);
    if (count <= 0) {
        free(actions);
        return ZCL_ERR(-1, "build job has no actions");
    }
    if (!node_db_begin(ndb)) {
        free(actions);
        return ZCL_ERR(-1, "cannot begin build submit transaction");
    }
    bool ok = true;
    for (int i = 0; i < count && ok; i++) {
        if (bf_terminal(actions[i].state)) {
            ok = false;
            break;
        }
        (void)snprintf(actions[i].state, sizeof(actions[i].state), "QUEUED");
        actions[i].updated_at = now;
        ok = db_build_action_save(ndb, &actions[i]);
    }
    (void)snprintf(job.state, sizeof(job.state), "QUEUED");
    job.updated_at = now;
    ok = ok && db_build_job_save(ndb, &job) && node_db_commit(ndb);
    free(actions);
    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "submit and rollback both failed");
        return ZCL_ERR(-1, "cannot queue build job atomically");
    }
    return ZCL_OK;
}

struct zcl_result build_fabric_claim(
    struct node_db *ndb, const char *worker_id, const char *lease_id,
    int64_t now, int64_t lease_seconds, struct db_build_action *out,
    bool *claimed)
{
    if (claimed) *claimed = false;
    if (!ndb || !ndb->open || !bf_lower_hex_id(worker_id) ||
        !bf_lower_hex_id(lease_id) || now < 0 ||
        lease_seconds < BUILD_FABRIC_LEASE_SECONDS_MIN ||
        lease_seconds > BUILD_FABRIC_LEASE_SECONDS_MAX || !out || !claimed)
        return ZCL_ERR(-1, "claim requires valid worker, lease, time, and bounds");
    struct db_build_worker worker;
    if (!db_build_worker_find(ndb, worker_id, &worker) || !worker.approved ||
        worker.revoked || (worker.expires_at && now >= worker.expires_at))
        return ZCL_ERR(-1, "worker is unapproved, expired, or revoked");
    struct db_build_action *queued = bf_actions_scratch("build.claim.queued");
    if (!queued)
        return ZCL_ERR(-1, "cannot allocate build action scan buffer");
    int count = db_build_actions_queued(ndb, queued,
                                        BUILD_FABRIC_ACTION_LIMIT);
    for (int i = 0; i < count; i++) {
        if (!bf_capability_has(worker.capabilities, queued[i].kind))
            continue;
        struct db_build_job job;
        if (!db_build_job_find(ndb, queued[i].job_id, &job) ||
            job.cancel_requested || strcmp(job.state, "QUEUED") != 0 ||
            !bf_action_identity_current(&job, &queued[i]))
            continue;
        struct db_build_action next = queued[i];
        (void)snprintf(next.state, sizeof(next.state), "CLAIMED");
        (void)snprintf(next.worker_id, sizeof(next.worker_id), "%s", worker_id);
        (void)snprintf(next.lease_id, sizeof(next.lease_id), "%s", lease_id);
        next.lease_expires_at = now + lease_seconds;
        next.lease_heartbeat_at = now;
        next.attempt_count++;
        next.claimed_at = now;
        next.started_at = 0;
        next.finished_at = 0;
        next.updated_at = now;
        if (!node_db_begin(ndb)) {
            free(queued);
            return ZCL_ERR(-1, "cannot begin build claim transaction");
        }
        bool ok = db_build_action_claim_queued(ndb, &next);
        if (ok) {
            (void)snprintf(job.state, sizeof(job.state), "CLAIMED");
            job.updated_at = now;
            ok = db_build_job_save(ndb, &job) && node_db_commit(ndb);
        }
        if (!ok) {
            if (!node_db_rollback(ndb))
                LOG_ERROR("build_fabric", "claim and rollback both failed");
            continue; /* another owner won this candidate */
        }
        *out = next;
        *claimed = true;
        free(queued);
        return ZCL_OK;
    }
    free(queued);
    return ZCL_OK;
}

static struct zcl_result bf_leased_transition(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    const char *expected_state, const char *next_state, int64_t now)
{
    if (!ndb || !ndb->open || !bf_lower_hex_id(action_id) ||
        !bf_lower_hex_id(lease_id) || now < 0)
        return ZCL_ERR(-1, "leased transition requires valid ids and time");
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job))
        return ZCL_ERR(-1, "leased action or job not found");
    if (strcmp(action.state, expected_state) != 0 ||
        strcmp(action.lease_id, lease_id) != 0)
        return ZCL_ERR(-1, "lease or expected action state is stale");
    if (job.cancel_requested || strcmp(job.state, "CANCELLED") == 0)
        return ZCL_ERR(-1, "build job is cancelled");
    if (action.lease_expires_at == 0 || now >= action.lease_expires_at)
        return ZCL_ERR(-1, "build action lease has expired");
    if (!bf_action_identity_current(&job, &action))
        return ZCL_ERR(-1, "build action immutable identity is stale");
    struct db_build_action next = action;
    (void)snprintf(next.state, sizeof(next.state), "%s", next_state);
    if (strcmp(next_state, "RUNNING") == 0 && next.started_at == 0)
        next.started_at = now;
    next.lease_heartbeat_at = now;
    next.updated_at = now;
    if (!node_db_begin(ndb))
        return ZCL_ERR(-1, "cannot begin leased transition");
    bool ok = db_build_action_save_leased(ndb, &next, expected_state,
                                          lease_id);
    if (ok) {
        (void)snprintf(job.state, sizeof(job.state), "%s", next_state);
        job.updated_at = now;
        ok = db_build_job_save(ndb, &job) && node_db_commit(ndb);
    }
    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "leased transition rollback failed");
        return ZCL_ERR(-1, "leased transition lost ownership");
    }
    return ZCL_OK;
}

struct zcl_result build_fabric_start(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    int64_t now)
{
    return bf_leased_transition(ndb, action_id, lease_id, "CLAIMED",
                                "RUNNING", now);
}

struct zcl_result build_fabric_begin_verify(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    int64_t now)
{
    return bf_leased_transition(ndb, action_id, lease_id, "RUNNING",
                                "VERIFYING", now);
}

struct zcl_result build_fabric_heartbeat(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    int64_t now, int64_t lease_seconds)
{
    if (!ndb || !ndb->open || !bf_lower_hex_id(action_id) ||
        !bf_lower_hex_id(lease_id) || now < 0 ||
        lease_seconds < BUILD_FABRIC_LEASE_SECONDS_MIN ||
        lease_seconds > BUILD_FABRIC_LEASE_SECONDS_MAX)
        return ZCL_ERR(-1, "heartbeat requires valid ids, time, and bounds");
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job))
        return ZCL_ERR(-1, "heartbeat action or job not found");
    if ((strcmp(action.state, "CLAIMED") != 0 &&
         strcmp(action.state, "RUNNING") != 0 &&
         strcmp(action.state, "VERIFYING") != 0) ||
        strcmp(action.lease_id, lease_id) != 0 || job.cancel_requested ||
        action.lease_expires_at == 0 || now >= action.lease_expires_at ||
        !bf_action_identity_current(&job, &action))
        return ZCL_ERR(-1, "heartbeat lease, authority, or identity is stale");
    char prior[BUILD_FABRIC_STATE_MAX + 1];
    (void)snprintf(prior, sizeof(prior), "%s", action.state);
    action.lease_heartbeat_at = now;
    action.lease_expires_at = now + lease_seconds;
    action.updated_at = now;
    if (!db_build_action_save_leased(ndb, &action, prior, lease_id))
        return ZCL_ERR(-1, "heartbeat lost lease ownership");
    return ZCL_OK;
}

struct zcl_result build_fabric_recover_expired(
    struct node_db *ndb, int64_t now, size_t *requeued)
{
    if (requeued) *requeued = 0;
    if (!ndb || !ndb->open || now < 0 || !requeued)
        return ZCL_ERR(-1, "lease recovery requires an open db and time");
    struct db_build_action *expired = bf_actions_scratch("build.recover.expired");
    if (!expired) {
        if (requeued) *requeued = 0;
        return ZCL_ERR(-1, "cannot allocate build action scan buffer");
    }
    int count = db_build_actions_expired(ndb, now, expired,
                                         BUILD_FABRIC_ACTION_LIMIT);
    for (int i = 0; i < count; i++) {
        struct db_build_job job;
        if (!db_build_job_find(ndb, expired[i].job_id, &job))
            continue;
        char prior_state[BUILD_FABRIC_STATE_MAX + 1];
        char prior_lease[BUILD_FABRIC_ID_HEX + 1];
        (void)snprintf(prior_state, sizeof(prior_state), "%s",
                       expired[i].state);
        (void)snprintf(prior_lease, sizeof(prior_lease), "%s",
                       expired[i].lease_id);
        struct db_build_action next = expired[i];
        (void)snprintf(next.state, sizeof(next.state), "QUEUED");
        next.outcome[0] = '\0';
        next.worker_id[0] = '\0';
        next.lease_id[0] = '\0';
        next.lease_expires_at = 0;
        next.lease_heartbeat_at = 0;
        (void)snprintf(next.last_error, sizeof(next.last_error),
                       "lease-expired-requeued");
        next.updated_at = now;
        if (!node_db_begin(ndb)) {
            free(expired);
            return ZCL_ERR(-1, "cannot begin expired-lease recovery");
        }
        bool ok = db_build_action_save_leased(ndb, &next, prior_state,
                                              prior_lease);
        if (ok) {
            (void)snprintf(job.state, sizeof(job.state), "QUEUED");
            job.updated_at = now;
            ok = db_build_job_save(ndb, &job) && node_db_commit(ndb);
        }
        if (!ok) {
            if (!node_db_rollback(ndb))
                LOG_ERROR("build_fabric", "recovery rollback failed");
            continue;
        }
        (*requeued)++;
    }
    free(expired);
    return ZCL_OK;
}

struct zcl_result build_fabric_finish_leased(
    struct node_db *ndb, const char *action_id, const char *lease_id,
    const char *outcome, const char *detail, int64_t now)
{
    if (!ndb || !ndb->open || !bf_lower_hex_id(action_id) ||
        !bf_lower_hex_id(lease_id) || !outcome || !detail || now < 0 ||
        (strcmp(outcome, "FAILED") != 0 &&
         strcmp(outcome, "LOCAL_FALLBACK") != 0 &&
         strcmp(outcome, "CANCELLED") != 0))
        return ZCL_ERR(-1, "leased finish requires a named terminal outcome");
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job))
        return ZCL_ERR(-1, "leased finish action or job not found");
    if ((strcmp(action.state, "CLAIMED") != 0 &&
         strcmp(action.state, "RUNNING") != 0 &&
         strcmp(action.state, "VERIFYING") != 0) ||
        strcmp(action.lease_id, lease_id) != 0)
        return ZCL_ERR(-1, "leased finish owner or state is stale");
    char prior[BUILD_FABRIC_STATE_MAX + 1];
    (void)snprintf(prior, sizeof(prior), "%s", action.state);
    (void)snprintf(action.state, sizeof(action.state), "%s", outcome);
    (void)snprintf(action.outcome, sizeof(action.outcome), "%s", outcome);
    (void)snprintf(action.last_error, sizeof(action.last_error), "%s", detail);
    action.finished_at = now;
    action.updated_at = now;
    if (!node_db_begin(ndb))
        return ZCL_ERR(-1, "cannot begin leased terminal transition");
    bool ok = db_build_action_save_leased(ndb, &action, prior, lease_id);
    if (ok) {
        (void)snprintf(job.state, sizeof(job.state), "%s", outcome);
        (void)snprintf(job.outcome, sizeof(job.outcome), "%s", outcome);
        if (strcmp(outcome, "CANCELLED") == 0) job.cancel_requested = 1;
        job.updated_at = now;
        ok = db_build_job_save(ndb, &job) && node_db_commit(ndb);
    }
    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "leased finish rollback failed");
        return ZCL_ERR(-1, "leased terminal transition lost ownership");
    }
    return ZCL_OK;
}

struct zcl_result build_fabric_cancel(struct node_db *ndb,
                                      const char *job_id, int64_t now)
{
    struct db_build_job job;
    if (!ndb || !ndb->open || !job_id || !db_build_job_find(ndb, job_id, &job))
        return ZCL_ERR(-1, "build job not found");
    if (strcmp(job.state, "CANCELLED") == 0)
        return ZCL_OK;
    if (strcmp(job.state, "ACCEPTED") == 0 || strcmp(job.state, "CACHE_HIT") == 0)
        return ZCL_ERR(-1, "completed build job cannot be cancelled");
    struct db_build_action *actions = bf_actions_scratch("build.cancel.actions");
    if (!actions)
        return ZCL_ERR(-1, "cannot allocate build action scan buffer");
    int count = db_build_job_actions(ndb, job_id, actions,
                                     BUILD_FABRIC_ACTION_LIMIT);
    if (!node_db_begin(ndb)) {
        free(actions);
        return ZCL_ERR(-1, "cannot begin cancellation transaction");
    }
    bool ok = true;
    for (int i = 0; i < count && ok; i++) {
        if (!bf_terminal(actions[i].state)) {
            (void)snprintf(actions[i].state, sizeof(actions[i].state),
                           "CANCELLED");
            (void)snprintf(actions[i].outcome, sizeof(actions[i].outcome),
                           "CANCELLED");
            actions[i].updated_at = now;
            ok = db_build_action_save(ndb, &actions[i]);
        }
    }
    (void)snprintf(job.state, sizeof(job.state), "CANCELLED");
    (void)snprintf(job.outcome, sizeof(job.outcome), "CANCELLED");
    job.cancel_requested = 1;
    job.updated_at = now;
    ok = ok && db_build_job_save(ndb, &job) && node_db_commit(ndb);
    free(actions);
    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "cancel and rollback both failed");
        return ZCL_ERR(-1, "cannot cancel build job atomically");
    }
    return ZCL_OK;
}

struct zcl_result build_fabric_worker_approve(
    struct node_db *ndb, const struct db_build_worker *worker, int64_t now)
{
    if (!ndb || !ndb->open || !worker)
        return ZCL_ERR(-1, "worker approval requires an open db and worker");
    struct db_build_worker next = *worker;
    next.approved = 1;
    next.revoked = 0;
    if (next.approved_at == 0) next.approved_at = now;
    if (!db_build_worker_save(ndb, &next))
        return ZCL_ERR(-1, "worker approval could not be persisted");
    return ZCL_OK;
}

struct zcl_result build_fabric_worker_enroll_local(
    struct node_db *ndb, const struct db_build_worker *worker, int64_t now)
{
    if (!ndb || !ndb->open || !worker || !worker->worker_id[0])
        return ZCL_ERR(-1, "local enrollment requires an open db and worker");
    struct db_build_worker existing;
    if (db_build_worker_find(ndb, worker->worker_id, &existing))
        return ZCL_OK;
    return build_fabric_worker_approve(ndb, worker, now);
}

struct zcl_result build_fabric_worker_revoke(
    struct node_db *ndb, const char *worker_id, int64_t now)
{
    (void)now;
    struct db_build_worker worker;
    if (!ndb || !ndb->open || !worker_id ||
        !db_build_worker_find(ndb, worker_id, &worker))
        return ZCL_ERR(-1, "build worker not found");
    if (worker.revoked)
        return ZCL_OK;
    worker.revoked = 1;
    if (!db_build_worker_save(ndb, &worker))
        return ZCL_ERR(-1, "worker revocation could not be persisted");
    return ZCL_OK;
}

struct zcl_result build_fabric_receipt_accept(
    struct node_db *ndb, const struct db_build_receipt *receipt, int64_t now)
{
    if (!ndb || !ndb->open || !receipt)
        return ZCL_ERR(-1, "receipt acceptance requires an open db and receipt");
    if (strcmp(receipt->trust_state, "LOCAL_ACCEPTED") != 0)
        return ZCL_ERR(-1, "only a local accepted receipt may advance an action");
    struct db_build_worker worker;
    if (!db_build_worker_find(ndb, receipt->worker_id, &worker) ||
        !worker.approved || worker.revoked ||
        (worker.expires_at != 0 && now >= worker.expires_at))
        return ZCL_ERR(-1, "receipt signer is unapproved, expired, or revoked");
    struct db_build_action action;
    if (!db_build_action_find(ndb, receipt->action_id, &action) ||
        strcmp(action.job_id, receipt->job_id) != 0 ||
        strcmp(receipt->action_sha3, action.action_id) != 0 ||
        strcmp(receipt->worker_id, action.worker_id) != 0 ||
        strcmp(receipt->lease_id, action.lease_id) != 0)
        return ZCL_ERR(-1, "receipt is not bound to the named action and job");
    if (strcmp(action.state, "ACCEPTED") == 0 ||
        strcmp(action.state, "FAILED") == 0) {
        struct db_build_receipt prior;
        if (db_build_receipt_find(ndb, receipt->receipt_id, &prior))
            return ZCL_OK;
    }
    if (strcmp(action.state, "VERIFYING") != 0)
        return ZCL_ERR(-1, "action state %s cannot accept a receipt",
                       action.state);
    if (action.lease_expires_at == 0 || now >= action.lease_expires_at)
        return ZCL_ERR(-1, "receipt action lease is expired");
    char expected_id[65];
    if (!build_fabric_receipt_id(receipt, expected_id).ok ||
        strcmp(expected_id, receipt->receipt_id) != 0)
        return ZCL_ERR(-1, "receipt id does not match its canonical preimage");
    uint8_t id[32], sig[64], pubkey[32];
    if (!zcl_hex_decode_lower(receipt->receipt_id, id, sizeof(id)) ||
        !zcl_hex_decode_lower(receipt->signature, sig, sizeof(sig)) ||
        !zcl_hex_decode_lower(worker.signer_pubkey, pubkey, sizeof(pubkey)) ||
        !ed25519_verify(sig, id, sizeof(id), pubkey))
        return ZCL_ERR(-1, "receipt Ed25519 signature is invalid");
    const bool passed = receipt->exit_status == 0;
    (void)snprintf(action.state, sizeof(action.state), "%s",
                   passed ? "ACCEPTED" : "FAILED");
    (void)snprintf(action.outcome, sizeof(action.outcome), "%s",
                   passed ? "ACCEPTED" : "FAILED");
    if (!passed)
        (void)snprintf(action.last_error, sizeof(action.last_error),
                       "fixed-action-reported-failure");
    (void)snprintf(action.output_root_sha3, sizeof(action.output_root_sha3),
                   "%s", receipt->output_sha3);
    (void)snprintf(action.worker_id, sizeof(action.worker_id), "%s",
                   receipt->worker_id);
    action.finished_at = now;
    action.updated_at = now;
    if (!node_db_begin(ndb))
        return ZCL_ERR(-1, "cannot begin receipt acceptance transaction");
    bool ok = db_build_receipt_save(ndb, receipt) &&
              db_build_action_save_leased(ndb, &action, "VERIFYING",
                                           receipt->lease_id);
    struct db_build_action *actions = bf_actions_scratch("build.receipt.actions");
    int count = 0;
    if (!actions) {
        ok = false;
    } else {
        count = db_build_job_actions(ndb, receipt->job_id, actions,
                                     BUILD_FABRIC_ACTION_LIMIT);
    }
    bool all_accepted = passed && count > 0;
    for (int i = 0; i < count; i++)
        if (strcmp(actions[i].state, "ACCEPTED") != 0 &&
            strcmp(actions[i].state, "CACHE_HIT") != 0)
            all_accepted = false;
    if (ok && all_accepted) {
        struct db_build_job job;
        ok = db_build_job_find(ndb, receipt->job_id, &job);
        if (ok) {
            (void)snprintf(job.state, sizeof(job.state), "ACCEPTED");
            (void)snprintf(job.outcome, sizeof(job.outcome), "ACCEPTED");
            job.updated_at = now;
            ok = db_build_job_save(ndb, &job);
        }
    } else if (ok && !passed) {
        struct db_build_job job;
        ok = db_build_job_find(ndb, receipt->job_id, &job);
        if (ok) {
            (void)snprintf(job.state, sizeof(job.state), "FAILED");
            (void)snprintf(job.outcome, sizeof(job.outcome), "FAILED");
            job.updated_at = now;
            ok = db_build_job_save(ndb, &job);
        }
    }
    ok = ok && node_db_commit(ndb);
    free(actions);
    if (!ok) {
        if (!node_db_rollback(ndb))
            LOG_ERROR("build_fabric", "receipt accept and rollback both failed");
        return ZCL_ERR(-1, "verified receipt could not be accepted atomically");
    }
    return ZCL_OK;
}
