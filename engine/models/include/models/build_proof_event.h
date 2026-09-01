/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Root-bound async proof events in the existing build ledger. */

#ifndef ZCL_DB_MODEL_BUILD_PROOF_EVENT_H
#define ZCL_DB_MODEL_BUILD_PROOF_EVENT_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    BUILD_PROOF_EVENT_ROOT_HEX = 64,
    BUILD_PROOF_EVENT_STATE_MAX = 23,
    BUILD_PROOF_EVENT_WORKSPACE_MAX = 4095,
};

struct db_build_proof_event {
    char event_root[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char prior_event_root[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char action_id[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char source_root_sha3[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char task_root_sha3[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char candidate_root_sha3[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char proof_policy_root_sha3[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char context_root_sha3[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char receipt_root_sha3[BUILD_PROOF_EVENT_ROOT_HEX + 1];
    char workspace[BUILD_PROOF_EVENT_WORKSPACE_MAX + 1];
    char state[BUILD_PROOF_EVENT_STATE_MAX + 1];
    uint64_t peer_id;
    uint64_t request_id;
    int64_t deadline_at;
    int64_t elapsed_us;
    int64_t created_at;
};

struct ar_callbacks *db_build_proof_event_callbacks(void);
bool db_build_proof_event_root(
    const struct db_build_proof_event *row,
    char out_hex[BUILD_PROOF_EVENT_ROOT_HEX + 1]);
bool db_build_proof_event_validate(
    const struct db_build_proof_event *row, struct ar_errors *errors);
bool db_build_proof_event_save(
    struct node_db *ndb, const struct db_build_proof_event *row);
bool db_build_proof_event_latest(
    struct node_db *ndb, const char *action_id,
    struct db_build_proof_event *out);
bool db_build_proof_event_requested(
    struct node_db *ndb, const char *action_id, uint64_t request_id,
    struct db_build_proof_event *out);
int db_build_proof_events_pending(
    struct node_db *ndb, struct db_build_proof_event *out, size_t max);
int db_build_proof_events_for_task(
    struct node_db *ndb, const char *task_root,
    struct db_build_proof_event *out, size_t max);
int db_build_proof_events_for_action(
    struct node_db *ndb, const char *action_id,
    struct db_build_proof_event *out, size_t max);

#endif /* ZCL_DB_MODEL_BUILD_PROOF_EVENT_H */
