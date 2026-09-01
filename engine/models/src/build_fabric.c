/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ActiveRecord persistence for build jobs/actions/workers/receipts. */

#include "models/build_fabric.h"

#include "models/model_text.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <string.h>

DEFINE_MODEL_CALLBACKS(build_job)
DEFINE_MODEL_CALLBACKS(build_action)
DEFINE_MODEL_CALLBACKS(build_worker)
DEFINE_MODEL_CALLBACKS(build_receipt)

static bool build_state_valid(const char *state)
{
    static const char *const states[] = {
        "PLANNED", "SNAPSHOTTED", "QUEUED", "CLAIMED", "RUNNING",
        "VERIFYING", "ACCEPTED", "CACHE_HIT", "LOCAL_FALLBACK",
        "DISPUTED", "CANCELLED", "FAILED",
    };
    if (!state)
        return false;
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
        if (strcmp(state, states[i]) == 0)
            return true;
    return false;
}

static bool build_outcome_valid(const char *outcome)
{
    return !outcome || !outcome[0] || strcmp(outcome, "CACHE_HIT") == 0 ||
           strcmp(outcome, "LOCAL_FALLBACK") == 0 ||
           strcmp(outcome, "DISPUTED") == 0 ||
           strcmp(outcome, "CANCELLED") == 0 ||
           strcmp(outcome, "FAILED") == 0 ||
           strcmp(outcome, "ACCEPTED") == 0;
}

static bool build_lower_hex(const char *value, size_t length)
{
    if (!value || strlen(value) != length)
        return false;
    for (size_t i = 0; i < length; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f')))
            return false;
    return true;
}

static bool build_hex_id(const char *value)
{
    return build_lower_hex(value, BUILD_FABRIC_ID_HEX);
}

static bool build_job_before_validate(void *record, void *ctx)
{
    struct db_build_job *row = record;
    (void)ctx;
    if (!row)
        return false;
    model_trim_ascii(row->profile);
    model_trim_ascii(row->state);
    model_trim_ascii(row->outcome);
    int64_t now = (int64_t)platform_time_wall_unix();
    if (row->created_at == 0) row->created_at = now;
    if (row->updated_at == 0) row->updated_at = now;
    return true;
}

static bool build_action_before_validate(void *record, void *ctx)
{
    struct db_build_action *row = record;
    (void)ctx;
    if (!row)
        return false;
    model_trim_ascii(row->kind);
    model_trim_ascii(row->state);
    model_trim_ascii(row->outcome);
    model_trim_ascii(row->target);
    model_trim_ascii(row->virtual_workdir);
    model_trim_ascii(row->declared_outputs);
    model_trim_ascii(row->resource_policy);
    model_trim_ascii(row->last_error);
    int64_t now = (int64_t)platform_time_wall_unix();
    if (row->created_at == 0) row->created_at = now;
    if (row->updated_at == 0) row->updated_at = now;
    return true;
}

static bool build_worker_before_validate(void *record, void *ctx)
{
    struct db_build_worker *row = record;
    (void)ctx;
    if (!row)
        return false;
    model_trim_ascii(row->capabilities);
    return true;
}

static bool build_receipt_before_validate(void *record, void *ctx)
{
    struct db_build_receipt *row = record;
    (void)ctx;
    if (!row)
        return false;
    model_trim_ascii(row->confinement);
    if (row->created_at == 0)
        row->created_at = (int64_t)platform_time_wall_unix();
    return true;
}

DEFINE_MODEL_BEFORE_VALIDATE_READY(build_job, build_job_before_validate)
DEFINE_MODEL_BEFORE_VALIDATE_READY(build_action, build_action_before_validate)
DEFINE_MODEL_BEFORE_VALIDATE_READY(build_worker, build_worker_before_validate)
DEFINE_MODEL_BEFORE_VALIDATE_READY(build_receipt, build_receipt_before_validate)

bool db_build_job_validate(const struct db_build_job *row,
                           struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, build_hex_id(row->job_id), "job_id",
                     "must be 64 lowercase hex characters");
    validates_custom(errors, build_hex_id(row->source_sha256),
                     "source_sha256", "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->source_cas_sha3),
                     "source_cas_sha3", "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->toolchain_sha3),
                     "toolchain_sha3", "must be a 64-byte hex digest");
    validates_string_present(errors, row->profile, "profile");
    validates_custom(errors, build_state_valid(row->state), "state",
                     "is not a build lifecycle state");
    validates_custom(errors, build_outcome_valid(row->outcome), "outcome",
                     "is not a named build outcome");
    validates_custom(errors,
                     row->cancel_requested == 0 || row->cancel_requested == 1,
                     "cancel_requested", "must be 0 or 1");
    validates_non_negative(errors, row, created_at);
    validates_non_negative(errors, row, updated_at);
    return !ar_errors_any(errors);
}

bool db_build_action_validate(const struct db_build_action *row,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, build_hex_id(row->action_id), "action_id",
                     "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->job_id), "job_id",
                     "must be a 64-byte hex digest");
    validates_non_negative(errors, row, sequence);
    validates_string_present(errors, row->kind, "kind");
    validates_custom(errors, build_state_valid(row->state), "state",
                     "is not a build lifecycle state");
    validates_custom(errors, build_outcome_valid(row->outcome), "outcome",
                     "is not a named build outcome");
    validates_custom(errors, build_hex_id(row->input_root_sha3),
                     "input_root_sha3", "must be a 64-byte hex digest");
    bool no_zcode = !row->task_root_sha3[0] &&
                    !row->candidate_root_sha3[0] &&
                    !row->proof_policy_root_sha3[0];
    bool full_zcode = build_hex_id(row->task_root_sha3) &&
                      build_hex_id(row->candidate_root_sha3) &&
                      build_hex_id(row->proof_policy_root_sha3);
    validates_custom(errors, no_zcode || full_zcode, "zcode_roots",
                     "must be all empty or canonical task/candidate/policy roots");
    validates_custom(errors,
                     !row->context_root_sha3[0] ||
                         build_hex_id(row->context_root_sha3),
                     "context_root_sha3", "must be empty or a hex digest");
    validates_string_present(errors, row->target, "target");
    validates_custom(errors, build_hex_id(row->flags_sha3), "flags_sha3",
                     "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->environment_sha3),
                     "environment_sha3", "must be a 64-byte hex digest");
    validates_string_present(errors, row->virtual_workdir, "virtual_workdir");
    validates_string_present(errors, row->declared_outputs,
                             "declared_outputs");
    validates_string_present(errors, row->resource_policy, "resource_policy");
    validates_custom(errors,
                     !row->output_root_sha3[0] ||
                         build_hex_id(row->output_root_sha3),
                     "output_root_sha3", "must be empty or a hex digest");
    validates_custom(errors,
                     !row->worker_id[0] || build_hex_id(row->worker_id),
                     "worker_id", "must be empty or a hex id");
    validates_custom(errors,
                     !row->lease_id[0] || build_hex_id(row->lease_id),
                     "lease_id", "must be empty or a hex id");
    validates_non_negative(errors, row, lease_expires_at);
    validates_non_negative(errors, row, lease_heartbeat_at);
    validates_non_negative(errors, row, attempt_count);
    validates_non_negative(errors, row, claimed_at);
    validates_non_negative(errors, row, started_at);
    validates_non_negative(errors, row, finished_at);
    validates_non_negative(errors, row, created_at);
    validates_non_negative(errors, row, updated_at);
    return !ar_errors_any(errors);
}

bool db_build_worker_validate(const struct db_build_worker *row,
                              struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, build_hex_id(row->worker_id), "worker_id",
                     "must be a 64-byte hex id");
    validates_custom(errors, build_hex_id(row->signer_pubkey),
                     "signer_pubkey", "must be a 32-byte Ed25519 key");
    validates_custom(errors, row->approved == 0 || row->approved == 1,
                     "approved", "must be 0 or 1");
    validates_custom(errors, row->revoked == 0 || row->revoked == 1,
                     "revoked", "must be 0 or 1");
    validates_non_negative(errors, row, approved_at);
    validates_non_negative(errors, row, expires_at);
    validates_non_negative(errors, row, last_seen_at);
    return !ar_errors_any(errors);
}

bool db_build_receipt_validate(const struct db_build_receipt *row,
                               struct ar_errors *errors)
{
    ar_errors_clear(errors);
    if (!row) {
        validates_custom(errors, false, "record", "is null");
        return false;
    }
    validates_custom(errors, build_hex_id(row->receipt_id), "receipt_id",
                     "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->action_id), "action_id",
                     "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->job_id), "job_id",
                     "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->worker_id), "worker_id",
                     "must be a 64-byte hex id");
    validates_custom(errors, build_hex_id(row->lease_id), "lease_id",
                     "must be a 64-byte hex id");
    validates_custom(errors, build_hex_id(row->action_sha3), "action_sha3",
                     "must be a 64-byte hex digest");
    validates_custom(errors, build_hex_id(row->output_sha3), "output_sha3",
                     "must be a 64-byte hex digest");
    validates_custom(errors,
                     !row->observation_sha3[0] ||
                         build_hex_id(row->observation_sha3),
                     "observation_sha3", "must be empty or a hex digest");
    validates_custom(errors,
                     !row->work_receipt_sha3[0] ||
                         build_hex_id(row->work_receipt_sha3),
                     "work_receipt_sha3", "must be empty or a hex digest");
    validates_custom(errors,
                     build_lower_hex(row->signature,
                                     BUILD_FABRIC_SIGNATURE_HEX),
                     "signature", "must be a 64-byte signature in hex");
    validates_string_present(errors, row->confinement, "confinement");
    validates_custom(errors,
                     strcmp(row->trust_state, "LOCAL_ACCEPTED") == 0 ||
                         strcmp(row->trust_state, "REMOTE_OBSERVED") == 0 ||
                         strcmp(row->trust_state, "LOCAL_REPRODUCED") == 0 ||
                         strcmp(row->trust_state, "QUORUM_MATCHED") == 0 ||
                         strcmp(row->trust_state, "REJECTED") == 0,
                     "trust_state", "must name a receipt trust state");
    validates_custom(errors, row->exit_status >= 0 && row->exit_status <= 255,
                     "exit_status", "must be between 0 and 255");
    validates_non_negative(errors, row, created_at);
    return !ar_errors_any(errors);
}

bool db_build_job_save(struct node_db *ndb, const struct db_build_job *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_build_job_save: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO build_jobs "
        "(job_id,source_sha256,source_cas_sha3,toolchain_sha3,profile,state,"
        "outcome,cancel_requested,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(job_id) DO UPDATE SET source_sha256=excluded.source_sha256,"
        "source_cas_sha3=excluded.source_cas_sha3,"
        "toolchain_sha3=excluded.toolchain_sha3,profile=excluded.profile,"
        "state=excluded.state,outcome=excluded.outcome,"
        "cancel_requested=excluded.cancel_requested,updated_at=excluded.updated_at",
        build_job_callbacks_ready(), "build_job", row, db_build_job_validate,
        AR_BIND_TEXT(st, 1, row->job_id);
        AR_BIND_TEXT(st, 2, row->source_sha256);
        AR_BIND_TEXT(st, 3, row->source_cas_sha3);
        AR_BIND_TEXT(st, 4, row->toolchain_sha3);
        AR_BIND_TEXT(st, 5, row->profile);
        AR_BIND_TEXT(st, 6, row->state);
        AR_BIND_TEXT(st, 7, row->outcome);
        AR_BIND_INT(st, 8, row->cancel_requested);
        AR_BIND_INT(st, 9, row->created_at);
        AR_BIND_INT(st, 10, row->updated_at));
}

bool db_build_action_save(struct node_db *ndb,
                          const struct db_build_action *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_build_action_save: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO build_actions "
        "(action_id,job_id,sequence,kind,state,outcome,input_root_sha3,"
        "target,flags_sha3,environment_sha3,virtual_workdir,declared_outputs,"
        "resource_policy,output_root_sha3,worker_id,lease_id,last_error,"
        "lease_expires_at,lease_heartbeat_at,attempt_count,claimed_at,"
        "started_at,finished_at,created_at,updated_at,task_root_sha3,"
        "candidate_root_sha3,proof_policy_root_sha3,context_root_sha3) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(action_id) DO UPDATE SET "
        "state=excluded.state,outcome=excluded.outcome,"
        "output_root_sha3=excluded.output_root_sha3,worker_id=excluded.worker_id,"
        "lease_id=excluded.lease_id,last_error=excluded.last_error,"
        "lease_expires_at=excluded.lease_expires_at,"
        "lease_heartbeat_at=excluded.lease_heartbeat_at,"
        "attempt_count=excluded.attempt_count,claimed_at=excluded.claimed_at,"
        "started_at=excluded.started_at,finished_at=excluded.finished_at,"
        "updated_at=excluded.updated_at",
        build_action_callbacks_ready(), "build_action", row,
        db_build_action_validate,
        AR_BIND_TEXT(st, 1, row->action_id);
        AR_BIND_TEXT(st, 2, row->job_id);
        AR_BIND_INT(st, 3, row->sequence);
        AR_BIND_TEXT(st, 4, row->kind);
        AR_BIND_TEXT(st, 5, row->state);
        AR_BIND_TEXT(st, 6, row->outcome);
        AR_BIND_TEXT(st, 7, row->input_root_sha3);
        AR_BIND_TEXT(st, 8, row->target);
        AR_BIND_TEXT(st, 9, row->flags_sha3);
        AR_BIND_TEXT(st, 10, row->environment_sha3);
        AR_BIND_TEXT(st, 11, row->virtual_workdir);
        AR_BIND_TEXT(st, 12, row->declared_outputs);
        AR_BIND_TEXT(st, 13, row->resource_policy);
        AR_BIND_TEXT(st, 14, row->output_root_sha3);
        AR_BIND_TEXT(st, 15, row->worker_id);
        AR_BIND_TEXT(st, 16, row->lease_id);
        AR_BIND_TEXT(st, 17, row->last_error);
        AR_BIND_INT(st, 18, row->lease_expires_at);
        AR_BIND_INT(st, 19, row->lease_heartbeat_at);
        AR_BIND_INT(st, 20, row->attempt_count);
        AR_BIND_INT(st, 21, row->claimed_at);
        AR_BIND_INT(st, 22, row->started_at);
        AR_BIND_INT(st, 23, row->finished_at);
        AR_BIND_INT(st, 24, row->created_at);
        AR_BIND_INT(st, 25, row->updated_at);
        AR_BIND_TEXT(st, 26, row->task_root_sha3);
        AR_BIND_TEXT(st, 27, row->candidate_root_sha3);
        AR_BIND_TEXT(st, 28, row->proof_policy_root_sha3);
        AR_BIND_TEXT(st, 29, row->context_root_sha3));
}

bool db_build_worker_save(struct node_db *ndb,
                          const struct db_build_worker *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_build_worker_save: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT INTO build_workers "
        "(worker_id,signer_pubkey,capabilities,approved,revoked,approved_at,"
        "expires_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(worker_id) DO UPDATE SET signer_pubkey=excluded.signer_pubkey,"
        "capabilities=excluded.capabilities,approved=excluded.approved,"
        "revoked=excluded.revoked,approved_at=excluded.approved_at,"
        "expires_at=excluded.expires_at,last_seen_at=excluded.last_seen_at",
        build_worker_callbacks_ready(), "build_worker", row,
        db_build_worker_validate,
        AR_BIND_TEXT(st, 1, row->worker_id);
        AR_BIND_TEXT(st, 2, row->signer_pubkey);
        AR_BIND_TEXT(st, 3, row->capabilities);
        AR_BIND_INT(st, 4, row->approved);
        AR_BIND_INT(st, 5, row->revoked);
        AR_BIND_INT(st, 6, row->approved_at);
        AR_BIND_INT(st, 7, row->expires_at);
        AR_BIND_INT(st, 8, row->last_seen_at));
}

bool db_build_receipt_save(struct node_db *ndb,
                           const struct db_build_receipt *row)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !row)
        LOG_FAIL("model", "db_build_receipt_save: bad args");
    AR_ADHOC_SAVE(ndb, st,
        "INSERT OR REPLACE INTO build_receipts "
        "(receipt_id,action_id,job_id,worker_id,lease_id,action_sha3,output_sha3,"
        "signature,confinement,exit_status,created_at,work_receipt_sha3,"
        "trust_state,observation_sha3) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        build_receipt_callbacks_ready(), "build_receipt", row,
        db_build_receipt_validate,
        AR_BIND_TEXT(st, 1, row->receipt_id);
        AR_BIND_TEXT(st, 2, row->action_id);
        AR_BIND_TEXT(st, 3, row->job_id);
        AR_BIND_TEXT(st, 4, row->worker_id);
        AR_BIND_TEXT(st, 5, row->lease_id);
        AR_BIND_TEXT(st, 6, row->action_sha3);
        AR_BIND_TEXT(st, 7, row->output_sha3);
        AR_BIND_TEXT(st, 8, row->signature);
        AR_BIND_TEXT(st, 9, row->confinement);
        AR_BIND_INT(st, 10, row->exit_status);
        AR_BIND_INT(st, 11, row->created_at);
        AR_BIND_TEXT(st, 12, row->work_receipt_sha3);
        AR_BIND_TEXT(st, 13, row->trust_state);
        AR_BIND_TEXT(st, 14, row->observation_sha3));
}

static void build_job_read(struct db_build_job *out, sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->job_id, sizeof(out->job_id));
    AR_READ_STR(st, 1, out->source_sha256, sizeof(out->source_sha256));
    AR_READ_STR(st, 2, out->source_cas_sha3, sizeof(out->source_cas_sha3));
    AR_READ_STR(st, 3, out->toolchain_sha3, sizeof(out->toolchain_sha3));
    AR_READ_STR(st, 4, out->profile, sizeof(out->profile));
    AR_READ_STR(st, 5, out->state, sizeof(out->state));
    AR_READ_STR(st, 6, out->outcome, sizeof(out->outcome));
    out->cancel_requested = (int)AR_COL_INT(st, 7);
    out->created_at = AR_COL_INT(st, 8);
    out->updated_at = AR_COL_INT(st, 9);
}

static void build_action_read(struct db_build_action *out, sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->action_id, sizeof(out->action_id));
    AR_READ_STR(st, 1, out->job_id, sizeof(out->job_id));
    out->sequence = AR_COL_INT(st, 2);
    AR_READ_STR(st, 3, out->kind, sizeof(out->kind));
    AR_READ_STR(st, 4, out->state, sizeof(out->state));
    AR_READ_STR(st, 5, out->outcome, sizeof(out->outcome));
    AR_READ_STR(st, 6, out->input_root_sha3, sizeof(out->input_root_sha3));
    AR_READ_STR(st, 7, out->target, sizeof(out->target));
    AR_READ_STR(st, 8, out->flags_sha3, sizeof(out->flags_sha3));
    AR_READ_STR(st, 9, out->environment_sha3, sizeof(out->environment_sha3));
    AR_READ_STR(st, 10, out->virtual_workdir, sizeof(out->virtual_workdir));
    AR_READ_STR(st, 11, out->declared_outputs, sizeof(out->declared_outputs));
    AR_READ_STR(st, 12, out->resource_policy, sizeof(out->resource_policy));
    AR_READ_STR(st, 13, out->output_root_sha3, sizeof(out->output_root_sha3));
    AR_READ_STR(st, 14, out->worker_id, sizeof(out->worker_id));
    AR_READ_STR(st, 15, out->lease_id, sizeof(out->lease_id));
    AR_READ_STR(st, 16, out->last_error, sizeof(out->last_error));
    out->lease_expires_at = AR_COL_INT(st, 17);
    out->lease_heartbeat_at = AR_COL_INT(st, 18);
    out->attempt_count = AR_COL_INT(st, 19);
    out->claimed_at = AR_COL_INT(st, 20);
    out->started_at = AR_COL_INT(st, 21);
    out->finished_at = AR_COL_INT(st, 22);
    out->created_at = AR_COL_INT(st, 23);
    out->updated_at = AR_COL_INT(st, 24);
    AR_READ_STR(st, 25, out->task_root_sha3, sizeof(out->task_root_sha3));
    AR_READ_STR(st, 26, out->candidate_root_sha3,
                sizeof(out->candidate_root_sha3));
    AR_READ_STR(st, 27, out->proof_policy_root_sha3,
                sizeof(out->proof_policy_root_sha3));
    AR_READ_STR(st, 28, out->context_root_sha3,
                sizeof(out->context_root_sha3));
}

static void build_worker_read(struct db_build_worker *out, sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->worker_id, sizeof(out->worker_id));
    AR_READ_STR(st, 1, out->signer_pubkey, sizeof(out->signer_pubkey));
    AR_READ_STR(st, 2, out->capabilities, sizeof(out->capabilities));
    out->approved = (int)AR_COL_INT(st, 3);
    out->revoked = (int)AR_COL_INT(st, 4);
    out->approved_at = AR_COL_INT(st, 5);
    out->expires_at = AR_COL_INT(st, 6);
    out->last_seen_at = AR_COL_INT(st, 7);
}

static void build_receipt_read(struct db_build_receipt *out, sqlite3_stmt *st)
{
    AR_READ_STR(st, 0, out->receipt_id, sizeof(out->receipt_id));
    AR_READ_STR(st, 1, out->action_id, sizeof(out->action_id));
    AR_READ_STR(st, 2, out->job_id, sizeof(out->job_id));
    AR_READ_STR(st, 3, out->worker_id, sizeof(out->worker_id));
    AR_READ_STR(st, 4, out->lease_id, sizeof(out->lease_id));
    AR_READ_STR(st, 5, out->action_sha3, sizeof(out->action_sha3));
    AR_READ_STR(st, 6, out->output_sha3, sizeof(out->output_sha3));
    AR_READ_STR(st, 7, out->signature, sizeof(out->signature));
    AR_READ_STR(st, 8, out->confinement, sizeof(out->confinement));
    out->exit_status = (int)AR_COL_INT(st, 9);
    out->created_at = AR_COL_INT(st, 10);
    AR_READ_STR(st, 11, out->work_receipt_sha3,
                sizeof(out->work_receipt_sha3));
    AR_READ_STR(st, 12, out->trust_state, sizeof(out->trust_state));
    AR_READ_STR(st, 13, out->observation_sha3,
                sizeof(out->observation_sha3));
}

#define BUILD_JOB_COLS "job_id,source_sha256,source_cas_sha3,toolchain_sha3," \
    "profile,state,outcome,cancel_requested,created_at,updated_at"
#define BUILD_ACTION_COLS "action_id,job_id,sequence,kind,state,outcome," \
    "input_root_sha3,target,flags_sha3,environment_sha3,virtual_workdir," \
    "declared_outputs,resource_policy,output_root_sha3,worker_id,lease_id," \
    "last_error,lease_expires_at,lease_heartbeat_at,attempt_count,claimed_at," \
    "started_at,finished_at,created_at,updated_at,task_root_sha3," \
    "candidate_root_sha3,proof_policy_root_sha3,context_root_sha3"
#define BUILD_WORKER_COLS "worker_id,signer_pubkey,capabilities,approved," \
    "revoked,approved_at,expires_at,last_seen_at"
#define BUILD_RECEIPT_COLS "receipt_id,action_id,job_id,worker_id,lease_id," \
    "action_sha3,output_sha3,signature,confinement,exit_status,created_at," \
    "work_receipt_sha3,trust_state,observation_sha3"

bool db_build_job_find(struct node_db *ndb, const char *job_id,
                       struct db_build_job *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !job_id || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " BUILD_JOB_COLS " FROM build_jobs WHERE job_id=?",
        AR_BIND_TEXT(st, 1, job_id), build_job_read(out, st));
}

bool db_build_action_find(struct node_db *ndb, const char *action_id,
                          struct db_build_action *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !action_id || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " BUILD_ACTION_COLS " FROM build_actions WHERE action_id=?",
        AR_BIND_TEXT(st, 1, action_id), build_action_read(out, st));
}

bool db_build_action_bind_context(struct node_db *ndb, const char *action_id,
                                  const char *context_root_sha3)
{
    if (!ndb || !ndb->open || !action_id || !context_root_sha3)
        LOG_FAIL("model", "db_build_action_bind_context: bad args");
    struct db_build_action row;
    if (!db_build_action_find(ndb, action_id, &row)) return false;
    if (row.context_root_sha3[0])
        return strcmp(row.context_root_sha3, context_root_sha3) == 0;
    (void)snprintf(row.context_root_sha3, sizeof(row.context_root_sha3),
                   "%s", context_root_sha3);
    sqlite3_stmt *st = NULL;
    AR_BEGIN_SAVE(build_action_callbacks_ready(), "build_action", &row,
                  db_build_action_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE build_actions SET context_root_sha3=?,updated_at=? "
        "WHERE action_id=? AND context_root_sha3='' RETURNING action_id");
    AR_BIND_TEXT(st, 1, row.context_root_sha3);
    AR_BIND_INT(st, 2, row.updated_at);
    AR_BIND_TEXT(st, 3, row.action_id);
    bool ok = AR_STEP_ROW(st);
    AR_FINALIZE(st);
    AR_FINISH_SAVE(build_action_callbacks_ready(), &row, ok);
}

bool db_build_worker_find(struct node_db *ndb, const char *worker_id,
                          struct db_build_worker *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !worker_id || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " BUILD_WORKER_COLS " FROM build_workers WHERE worker_id=?",
        AR_BIND_TEXT(st, 1, worker_id), build_worker_read(out, st));
}

bool db_build_receipt_find(struct node_db *ndb, const char *receipt_id,
                           struct db_build_receipt *out)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !receipt_id || !out)
        return false;
    AR_QUERY_ONE_BOOL(ndb, st,
        "SELECT " BUILD_RECEIPT_COLS " FROM build_receipts WHERE receipt_id=?",
        AR_BIND_TEXT(st, 1, receipt_id), build_receipt_read(out, st));
}

int db_build_jobs_recent(struct node_db *ndb, struct db_build_job *out,
                         size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_JOB_COLS " FROM build_jobs "
        "ORDER BY created_at DESC,job_id LIMIT ?", out, max,
        AR_BIND_INT(st, 1, (int64_t)max), build_job_read(&out[count], st));
}

int db_build_job_actions(struct node_db *ndb, const char *job_id,
                         struct db_build_action *out, size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !job_id || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_ACTION_COLS " FROM build_actions WHERE job_id=? "
        "ORDER BY sequence,action_id LIMIT ?", out, max,
        AR_BIND_TEXT(st, 1, job_id); AR_BIND_INT(st, 2, (int64_t)max),
        build_action_read(&out[count], st));
}

int db_build_workers_list(struct node_db *ndb, struct db_build_worker *out,
                          size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_WORKER_COLS " FROM build_workers "
        "ORDER BY approved DESC,revoked,worker_id LIMIT ?", out, max,
        AR_BIND_INT(st, 1, (int64_t)max), build_worker_read(&out[count], st));
}

int db_build_job_receipts(struct node_db *ndb, const char *job_id,
                          struct db_build_receipt *out, size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !job_id || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_RECEIPT_COLS " FROM build_receipts WHERE job_id=? "
        "ORDER BY created_at,receipt_id LIMIT ?", out, max,
        AR_BIND_TEXT(st, 1, job_id); AR_BIND_INT(st, 2, (int64_t)max),
        build_receipt_read(&out[count], st));
}

int db_build_candidate_receipts(
    struct node_db *ndb, const char *task_root_sha3,
    const char *candidate_root_sha3, const char *proof_policy_root_sha3,
    struct db_build_receipt *out, size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !task_root_sha3 || !candidate_root_sha3 ||
        !proof_policy_root_sha3 || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_RECEIPT_COLS " FROM build_receipts "
        "WHERE action_id IN (SELECT action_id FROM build_actions "
        "WHERE task_root_sha3=? AND candidate_root_sha3=? "
        "AND proof_policy_root_sha3=?) "
        "ORDER BY created_at,receipt_id LIMIT ?", out, max,
        AR_BIND_TEXT(st, 1, task_root_sha3);
        AR_BIND_TEXT(st, 2, candidate_root_sha3);
        AR_BIND_TEXT(st, 3, proof_policy_root_sha3);
        AR_BIND_INT(st, 4, (int64_t)max),
        build_receipt_read(&out[count], st));
}

int db_build_candidate_actions(
    struct node_db *ndb, const char *task_root_sha3,
    const char *candidate_root_sha3, const char *proof_policy_root_sha3,
    struct db_build_action *out, size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !task_root_sha3 || !candidate_root_sha3 ||
        !proof_policy_root_sha3 || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_ACTION_COLS " FROM build_actions "
        "WHERE task_root_sha3=? AND candidate_root_sha3=? "
        "AND proof_policy_root_sha3=? ORDER BY action_id LIMIT ?", out, max,
        AR_BIND_TEXT(st, 1, task_root_sha3);
        AR_BIND_TEXT(st, 2, candidate_root_sha3);
        AR_BIND_TEXT(st, 3, proof_policy_root_sha3);
        AR_BIND_INT(st, 4, (int64_t)max),
        build_action_read(&out[count], st));
}

int db_build_actions_queued(struct node_db *ndb,
                            struct db_build_action *out, size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_ACTION_COLS " FROM build_actions "
        "WHERE state='QUEUED' AND lease_id='' "
        "ORDER BY updated_at,job_id,sequence LIMIT ?", out, max,
        AR_BIND_INT(st, 1, (int64_t)max),
        build_action_read(&out[count], st));
}

int db_build_actions_expired(struct node_db *ndb, int64_t now,
                             struct db_build_action *out, size_t max)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || now < 0 || !out || max == 0)
        return 0;
    AR_QUERY_LIST(ndb, st,
        "SELECT " BUILD_ACTION_COLS " FROM build_actions "
        "WHERE state IN ('CLAIMED','RUNNING','VERIFYING') "
        "AND lease_id<>'' AND lease_expires_at>0 AND lease_expires_at<=? "
        "ORDER BY lease_expires_at,updated_at,action_id LIMIT ?", out, max,
        AR_BIND_INT(st, 1, now); AR_BIND_INT(st, 2, (int64_t)max),
        build_action_read(&out[count], st));
}

bool db_build_action_claim_queued(struct node_db *ndb,
                                  const struct db_build_action *next)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !next)
        LOG_FAIL("model", "db_build_action_claim_queued: bad args");
    AR_BEGIN_SAVE(build_action_callbacks_ready(), "build_action", next,
                  db_build_action_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE build_actions SET state=?,outcome=?,output_root_sha3=?,"
        "worker_id=?,lease_id=?,last_error=?,lease_expires_at=?,"
        "lease_heartbeat_at=?,attempt_count=?,claimed_at=?,started_at=?,"
        "finished_at=?,updated_at=? WHERE action_id=? AND state='QUEUED' "
        "AND lease_id='' AND EXISTS (SELECT 1 FROM build_jobs j "
        "WHERE j.job_id=build_actions.job_id AND j.cancel_requested=0 "
        "AND j.state='QUEUED')");
    AR_BIND_TEXT(st, 1, next->state);
    AR_BIND_TEXT(st, 2, next->outcome);
    AR_BIND_TEXT(st, 3, next->output_root_sha3);
    AR_BIND_TEXT(st, 4, next->worker_id);
    AR_BIND_TEXT(st, 5, next->lease_id);
    AR_BIND_TEXT(st, 6, next->last_error);
    AR_BIND_INT(st, 7, next->lease_expires_at);
    AR_BIND_INT(st, 8, next->lease_heartbeat_at);
    AR_BIND_INT(st, 9, next->attempt_count);
    AR_BIND_INT(st, 10, next->claimed_at);
    AR_BIND_INT(st, 11, next->started_at);
    AR_BIND_INT(st, 12, next->finished_at);
    AR_BIND_INT(st, 13, next->updated_at);
    AR_BIND_TEXT(st, 14, next->action_id);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(st, ok);
    ok = ok && sqlite3_changes(ndb->db) == 1;
    AR_FINISH_SAVE(build_action_callbacks_ready(), next, ok);
}

bool db_build_action_save_leased(struct node_db *ndb,
                                 const struct db_build_action *next,
                                 const char *expected_state,
                                 const char *expected_lease_id)
{
    sqlite3_stmt *st = NULL;
    if (!ndb || !ndb->open || !next || !expected_state ||
        !expected_lease_id)
        LOG_FAIL("model", "db_build_action_save_leased: bad args");
    AR_BEGIN_SAVE(build_action_callbacks_ready(), "build_action", next,
                  db_build_action_validate);
    AR_PREPARE_BOOL(ndb, st,
        "UPDATE build_actions SET state=?,outcome=?,output_root_sha3=?,"
        "worker_id=?,lease_id=?,last_error=?,lease_expires_at=?,"
        "lease_heartbeat_at=?,attempt_count=?,claimed_at=?,started_at=?,"
        "finished_at=?,updated_at=? WHERE action_id=? AND state=? "
        "AND lease_id=? AND EXISTS (SELECT 1 FROM build_jobs j "
        "WHERE j.job_id=build_actions.job_id AND j.cancel_requested=0 "
        "AND j.state<>'CANCELLED')");
    AR_BIND_TEXT(st, 1, next->state);
    AR_BIND_TEXT(st, 2, next->outcome);
    AR_BIND_TEXT(st, 3, next->output_root_sha3);
    AR_BIND_TEXT(st, 4, next->worker_id);
    AR_BIND_TEXT(st, 5, next->lease_id);
    AR_BIND_TEXT(st, 6, next->last_error);
    AR_BIND_INT(st, 7, next->lease_expires_at);
    AR_BIND_INT(st, 8, next->lease_heartbeat_at);
    AR_BIND_INT(st, 9, next->attempt_count);
    AR_BIND_INT(st, 10, next->claimed_at);
    AR_BIND_INT(st, 11, next->started_at);
    AR_BIND_INT(st, 12, next->finished_at);
    AR_BIND_INT(st, 13, next->updated_at);
    AR_BIND_TEXT(st, 14, next->action_id);
    AR_BIND_TEXT(st, 15, expected_state);
    AR_BIND_TEXT(st, 16, expected_lease_id);
    bool ok = false;
    AR_FINALIZE_STEP_DONE(st, ok);
    ok = ok && sqlite3_changes(ndb->db) == 1;
    AR_FINISH_SAVE(build_action_callbacks_ready(), next, ok);
}
