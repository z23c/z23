/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Build-fabric application records. These tables are each full node's durable
 * requester/executor ledger; compiler outputs remain content-addressed CAS objects. They are
 * operator/development state and are never consulted by consensus. */

#ifndef ZCL_DB_MODEL_BUILD_FABRIC_H
#define ZCL_DB_MODEL_BUILD_FABRIC_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    BUILD_FABRIC_ID_HEX = 64,
    BUILD_FABRIC_KIND_MAX = 63,
    BUILD_FABRIC_TARGET_MAX = 63,
    BUILD_FABRIC_PROFILE_MAX = 31,
    BUILD_FABRIC_STATE_MAX = 23,
    BUILD_FABRIC_OUTCOME_MAX = 23,
    BUILD_FABRIC_ERROR_MAX = 255,
    BUILD_FABRIC_CAPS_MAX = 1023,
    BUILD_FABRIC_CONFINEMENT_MAX = 255,
    BUILD_FABRIC_DESCRIPTOR_MAX = 255,
    BUILD_FABRIC_SIGNATURE_HEX = 128,
    BUILD_FABRIC_TRUST_STATE_MAX = 23,
};

struct db_build_job {
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    char source_sha256[BUILD_FABRIC_ID_HEX + 1];
    char source_cas_sha3[BUILD_FABRIC_ID_HEX + 1];
    char toolchain_sha3[BUILD_FABRIC_ID_HEX + 1];
    char profile[BUILD_FABRIC_PROFILE_MAX + 1];
    char state[BUILD_FABRIC_STATE_MAX + 1];
    char outcome[BUILD_FABRIC_OUTCOME_MAX + 1];
    int cancel_requested;
    int64_t created_at;
    int64_t updated_at;
};

struct db_build_action {
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    int64_t sequence;
    char kind[BUILD_FABRIC_KIND_MAX + 1];
    char state[BUILD_FABRIC_STATE_MAX + 1];
    char outcome[BUILD_FABRIC_OUTCOME_MAX + 1];
    char input_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char task_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char candidate_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char proof_policy_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char context_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char target[BUILD_FABRIC_TARGET_MAX + 1];
    char flags_sha3[BUILD_FABRIC_ID_HEX + 1];
    char environment_sha3[BUILD_FABRIC_ID_HEX + 1];
    char virtual_workdir[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char declared_outputs[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char resource_policy[BUILD_FABRIC_DESCRIPTOR_MAX + 1];
    char output_root_sha3[BUILD_FABRIC_ID_HEX + 1];
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char lease_id[BUILD_FABRIC_ID_HEX + 1];
    char last_error[BUILD_FABRIC_ERROR_MAX + 1];
    int64_t lease_expires_at;
    int64_t lease_heartbeat_at;
    int64_t attempt_count;
    int64_t claimed_at;
    int64_t started_at;
    int64_t finished_at;
    int64_t created_at;
    int64_t updated_at;
};

struct db_build_worker {
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char signer_pubkey[BUILD_FABRIC_ID_HEX + 1];
    char capabilities[BUILD_FABRIC_CAPS_MAX + 1];
    int approved;
    int revoked;
    int64_t approved_at;
    int64_t expires_at;
    int64_t last_seen_at;
};

struct db_build_receipt {
    char receipt_id[BUILD_FABRIC_ID_HEX + 1];
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    char worker_id[BUILD_FABRIC_ID_HEX + 1];
    char lease_id[BUILD_FABRIC_ID_HEX + 1];
    char action_sha3[BUILD_FABRIC_ID_HEX + 1];
    char output_sha3[BUILD_FABRIC_ID_HEX + 1];
    char observation_sha3[BUILD_FABRIC_ID_HEX + 1];
    char work_receipt_sha3[BUILD_FABRIC_ID_HEX + 1];
    char signature[BUILD_FABRIC_SIGNATURE_HEX + 1];
    char confinement[BUILD_FABRIC_CONFINEMENT_MAX + 1];
    char trust_state[BUILD_FABRIC_TRUST_STATE_MAX + 1];
    int exit_status;
    int64_t created_at;
};

struct ar_callbacks *db_build_job_callbacks(void);
struct ar_callbacks *db_build_action_callbacks(void);
struct ar_callbacks *db_build_worker_callbacks(void);
struct ar_callbacks *db_build_receipt_callbacks(void);

bool db_build_job_validate(const struct db_build_job *row,
                           struct ar_errors *errors);
bool db_build_action_validate(const struct db_build_action *row,
                              struct ar_errors *errors);
bool db_build_worker_validate(const struct db_build_worker *row,
                              struct ar_errors *errors);
bool db_build_receipt_validate(const struct db_build_receipt *row,
                               struct ar_errors *errors);

bool db_build_job_save(struct node_db *ndb, const struct db_build_job *row);
bool db_build_action_save(struct node_db *ndb,
                          const struct db_build_action *row);
bool db_build_worker_save(struct node_db *ndb,
                          const struct db_build_worker *row);
bool db_build_receipt_save(struct node_db *ndb,
                           const struct db_build_receipt *row);

bool db_build_job_find(struct node_db *ndb, const char *job_id,
                       struct db_build_job *out);
bool db_build_action_find(struct node_db *ndb, const char *action_id,
                          struct db_build_action *out);
bool db_build_worker_find(struct node_db *ndb, const char *worker_id,
                          struct db_build_worker *out);
bool db_build_receipt_find(struct node_db *ndb, const char *receipt_id,
                           struct db_build_receipt *out);

int db_build_jobs_recent(struct node_db *ndb, struct db_build_job *out,
                         size_t max);
int db_build_job_actions(struct node_db *ndb, const char *job_id,
                         struct db_build_action *out, size_t max);
int db_build_workers_list(struct node_db *ndb, struct db_build_worker *out,
                          size_t max);
int db_build_job_receipts(struct node_db *ndb, const char *job_id,
                          struct db_build_receipt *out, size_t max);
int db_build_candidate_receipts(
    struct node_db *ndb, const char *task_root_sha3,
    const char *candidate_root_sha3, const char *proof_policy_root_sha3,
    struct db_build_receipt *out, size_t max);
int db_build_candidate_actions(
    struct node_db *ndb, const char *task_root_sha3,
    const char *candidate_root_sha3, const char *proof_policy_root_sha3,
    struct db_build_action *out, size_t max);

/* Lease writes are compare-and-swap operations. A queued action can be
 * claimed once; every later mutation must present the exact lease id and
 * expected state. Expired reads are bounded and ordered for crash recovery. */
int db_build_actions_queued(struct node_db *ndb,
                            struct db_build_action *out, size_t max);
int db_build_actions_expired(struct node_db *ndb, int64_t now,
                             struct db_build_action *out, size_t max);
bool db_build_action_claim_queued(struct node_db *ndb,
                                  const struct db_build_action *next);
bool db_build_action_save_leased(struct node_db *ndb,
                                 const struct db_build_action *next,
                                 const char *expected_state,
                                 const char *expected_lease_id);
/* Bind the request-scoped content carrier after foreground admission. The
 * immutable action identity excludes this root; a nonempty different root is
 * never overwritten while an action is active. */
bool db_build_action_bind_context(struct node_db *ndb, const char *action_id,
                                  const char *context_root_sha3);

#endif /* ZCL_DB_MODEL_BUILD_FABRIC_H */
