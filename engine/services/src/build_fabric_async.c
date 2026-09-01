/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Requester-local durable state for asynchronous peer proof. */

#include "services/build_fabric_async.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "models/build_fabric.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>

uint64_t build_fabric_proof_request_id(const char *action_id)
{
    uint8_t action_root[32], digest[32];
    if (!action_id || !zcl_hex_decode_lower(action_id, action_root, 32))
        return 0;
    static const char domain[] = "zcl.build_proof_request_id.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, action_root, sizeof(action_root));
    sha3_256_finalize(&sha, digest);
    uint64_t request_id = zcl_read_u64_le(digest) & (uint64_t)INT64_MAX;
    return request_id == 0 ? 1 : request_id;
}

static bool proof_transition_allowed(const char *from, const char *to)
{
    if (!from || !to) return false;
    if (strcmp(to, "SUPERSEDED") == 0)
        return strcmp(from, "SUPERSEDED") != 0;
    if (strcmp(from, "REQUESTED") == 0)
        return strcmp(to, "PEER_DISCOVERED") == 0;
    if (strcmp(from, "PEER_DISCOVERED") == 0)
        return strcmp(to, "CONTEXT_READY") == 0 ||
               strcmp(to, "PEER_DISCOVERED") == 0;
    if (strcmp(from, "CONTEXT_READY") == 0)
        return strcmp(to, "RUNNING") == 0 ||
               strcmp(to, "PEER_DISCOVERED") == 0;
    if (strcmp(from, "RUNNING") == 0)
        return strcmp(to, "REMOTE_GREEN") == 0 ||
               strcmp(to, "REMOTE_RED") == 0 ||
               strcmp(to, "PEER_DISCOVERED") == 0;
    if (strcmp(from, "REMOTE_GREEN") == 0)
        return strcmp(to, "RECEIPT_VERIFIED") == 0 ||
               strcmp(to, "REMOTE_RED") == 0;
    if (strcmp(from, "REMOTE_RED") == 0)
        return strcmp(to, "PEER_DISCOVERED") == 0 ||
               strcmp(to, "RECEIPT_VERIFIED") == 0;
    if (strcmp(from, "RECEIPT_VERIFIED") == 0)
        return strcmp(to, "REPRODUCED") == 0;
    if (strcmp(from, "REPRODUCED") == 0)
        return strcmp(to, "READY_FOR_ACCEPTANCE") == 0;
    return false;
}

static bool proof_state_needs_peer(const char *state)
{
    return strcmp(state, "PEER_DISCOVERED") == 0 ||
           strcmp(state, "CONTEXT_READY") == 0 ||
           strcmp(state, "RUNNING") == 0 ||
           strcmp(state, "REMOTE_GREEN") == 0 ||
           strcmp(state, "REMOTE_RED") == 0 ||
           strcmp(state, "RECEIPT_VERIFIED") == 0;
}

static bool proof_state_needs_context(const char *state)
{
    return proof_state_needs_peer(state) ||
           strcmp(state, "REPRODUCED") == 0 ||
           strcmp(state, "READY_FOR_ACCEPTANCE") == 0;
}

static bool proof_state_needs_receipt(const char *state)
{
    return strcmp(state, "REMOTE_GREEN") == 0 ||
           strcmp(state, "REMOTE_RED") == 0 ||
           strcmp(state, "RECEIPT_VERIFIED") == 0 ||
           strcmp(state, "REPRODUCED") == 0 ||
           strcmp(state, "READY_FOR_ACCEPTANCE") == 0;
}

static struct zcl_result proof_event_store(
    struct node_db *ndb, struct db_build_proof_event *event)
{
    if (!db_build_proof_event_root(event, event->event_root))
        return ZCL_ERR(-1, "async proof event root derivation failed");
    if (!db_build_proof_event_save(ndb, event))
        return ZCL_ERR(-1, "async proof event persistence failed");
    return ZCL_OK;
}

struct zcl_result build_fabric_proof_transition(
    struct node_db *ndb, const char *action_id, const char *state,
    uint64_t peer_id, uint64_t request_id, const char *context_root,
    const char *receipt_root, int64_t deadline_at, int64_t elapsed_us,
    int64_t now,
    struct db_build_proof_event *out)
{
    if (!ndb || !ndb->open || !action_id || !state || !out ||
        request_id == 0 || deadline_at < 0 || elapsed_us < 0 || now <= 0)
        return ZCL_ERR(-1, "async proof transition requires exact inputs");
    struct db_build_proof_event prior;
    if (!db_build_proof_event_latest(ndb, action_id, &prior))
        return ZCL_ERR(-1, "async proof transition has no REQUESTED event");
    if (prior.request_id != request_id)
        return ZCL_ERR(-1, "async proof request identity changed");
    if (!proof_transition_allowed(prior.state, state))
        return ZCL_ERR(-1, "async proof transition %s -> %s is refused",
                       prior.state, state);
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->prior_event_root, sizeof(out->prior_event_root),
                   "%s", prior.event_root);
    (void)snprintf(out->action_id, sizeof(out->action_id), "%s", action_id);
    (void)snprintf(out->source_root_sha3, sizeof(out->source_root_sha3),
                   "%s", prior.source_root_sha3);
    if (!out->source_root_sha3[0]) {
        struct db_build_action action;
        struct db_build_job job;
        if (!db_build_action_find(ndb, action_id, &action) ||
            !db_build_job_find(ndb, action.job_id, &job) ||
            !job.source_cas_sha3[0])
            return ZCL_ERR(-1, "async proof transition lost source binding");
        (void)snprintf(out->source_root_sha3,
                       sizeof(out->source_root_sha3), "%s",
                       job.source_cas_sha3);
    }
    (void)snprintf(out->task_root_sha3, sizeof(out->task_root_sha3), "%s",
                   prior.task_root_sha3);
    (void)snprintf(out->candidate_root_sha3,
                   sizeof(out->candidate_root_sha3), "%s",
                   prior.candidate_root_sha3);
    (void)snprintf(out->proof_policy_root_sha3,
                   sizeof(out->proof_policy_root_sha3), "%s",
                   prior.proof_policy_root_sha3);
    (void)snprintf(out->context_root_sha3, sizeof(out->context_root_sha3),
                   "%s", context_root && context_root[0]
                       ? context_root : prior.context_root_sha3);
    (void)snprintf(out->receipt_root_sha3, sizeof(out->receipt_root_sha3),
                   "%s", receipt_root && receipt_root[0]
                       ? receipt_root : prior.receipt_root_sha3);
    (void)snprintf(out->workspace, sizeof(out->workspace), "%s",
                   prior.workspace);
    (void)snprintf(out->state, sizeof(out->state), "%s", state);
    out->peer_id = peer_id ? peer_id : prior.peer_id;
    out->request_id = request_id;
    out->deadline_at = deadline_at ? deadline_at : prior.deadline_at;
    out->elapsed_us = elapsed_us;
    out->created_at = now;
    if (proof_state_needs_peer(state) && out->peer_id == 0)
        return ZCL_ERR(-1, "%s requires a selected peer", state);
    if (proof_state_needs_context(state) && !out->context_root_sha3[0])
        return ZCL_ERR(-1, "%s requires the exact context root", state);
    if (proof_state_needs_receipt(state) && !out->receipt_root_sha3[0])
        return ZCL_ERR(-1, "%s requires a signed receipt root", state);
    return proof_event_store(ndb, out);
}

static struct zcl_result proof_supersede_older(
    struct node_db *ndb, const struct db_build_action *action,
    uint64_t request_id, int64_t now)
{
    struct db_build_proof_event current[64];
    int count = db_build_proof_events_for_task(
        ndb, action->task_root_sha3, current, 64);
    for (int i = 0; i < count; i++) {
        if (strcmp(current[i].action_id, action->action_id) == 0 ||
            strcmp(current[i].candidate_root_sha3,
                   action->candidate_root_sha3) == 0 ||
            strcmp(current[i].state, "SUPERSEDED") == 0)
            continue;
        struct db_build_proof_event superseded;
        ZCL_CHECK(build_fabric_proof_transition(
            ndb, current[i].action_id, "SUPERSEDED", current[i].peer_id,
            current[i].request_id, NULL, NULL, current[i].deadline_at,
            current[i].elapsed_us, now, &superseded));
    }
    (void)request_id;
    return ZCL_OK;
}

struct zcl_result build_fabric_proof_request(
    struct node_db *ndb, const char *action_id, const char *workspace,
    uint64_t peer_hint, int64_t local_submit_us,
    int64_t now, struct db_build_proof_event *out, bool *created)
{
    if (!ndb || !ndb->open || !action_id || !workspace ||
        workspace[0] != '/' || !out || !created || local_submit_us < 0 ||
        now <= 0)
        return ZCL_ERR(-1, "async proof request requires exact inputs");
    uint64_t request_id = build_fabric_proof_request_id(action_id);
    if (request_id == 0)
        return ZCL_ERR(-1, "async proof action id is not canonical");
    if (db_build_proof_event_requested(ndb, action_id, request_id, out)) {
        *created = false;
        return ZCL_OK;
    }
    struct db_build_action action;
    struct db_build_job job;
    if (!db_build_action_find(ndb, action_id, &action) ||
        !db_build_job_find(ndb, action.job_id, &job) ||
        !job.source_cas_sha3[0] ||
        !action.task_root_sha3[0] || !action.candidate_root_sha3[0] ||
        !action.proof_policy_root_sha3[0])
        return ZCL_ERR(-1, "async proof action is absent or not ZCODE-bound");
    ZCL_CHECK(proof_supersede_older(ndb, &action, request_id, now));
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->action_id, sizeof(out->action_id), "%s", action_id);
    (void)snprintf(out->source_root_sha3, sizeof(out->source_root_sha3),
                   "%s", job.source_cas_sha3);
    (void)snprintf(out->task_root_sha3, sizeof(out->task_root_sha3), "%s",
                   action.task_root_sha3);
    (void)snprintf(out->candidate_root_sha3,
                   sizeof(out->candidate_root_sha3), "%s",
                   action.candidate_root_sha3);
    (void)snprintf(out->proof_policy_root_sha3,
                   sizeof(out->proof_policy_root_sha3), "%s",
                   action.proof_policy_root_sha3);
    (void)snprintf(out->workspace, sizeof(out->workspace), "%s", workspace);
    (void)snprintf(out->state, sizeof(out->state), "REQUESTED");
    out->peer_id = peer_hint;
    out->request_id = request_id;
    out->elapsed_us = local_submit_us;
    out->created_at = now;
    ZCL_CHECK(proof_event_store(ndb, out));
    *created = true;
    return ZCL_OK;
}

struct zcl_result build_fabric_proof_timings(
    struct node_db *ndb, const char *action_id,
    struct build_fabric_proof_timings *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!ndb || !ndb->open || !action_id || !out)
        return ZCL_ERR(-1, "async proof timings require exact inputs");
    struct db_build_proof_event events[64];
    int count = db_build_proof_events_for_action(
        ndb, action_id, events, sizeof(events) / sizeof(events[0]));
    if (count <= 0)
        return ZCL_ERR(-1, "async proof timing chain is absent or invalid");
    for (int i = 0; i < count; i++) {
        const char *state = events[i].state;
        if (strcmp(state, "REQUESTED") == 0 && out->local_submit_us == 0)
            out->local_submit_us = events[i].elapsed_us;
        else if (strcmp(state, "PEER_DISCOVERED") == 0 &&
                 out->peer_discovery_us == 0)
            out->peer_discovery_us = events[i].elapsed_us;
        else if (strcmp(state, "CONTEXT_READY") == 0 &&
                 out->transfer_us == 0)
            out->transfer_us = events[i].elapsed_us;
        else if (strcmp(state, "RUNNING") == 0 &&
                 out->remote_queue_us == 0)
            out->remote_queue_us = events[i].elapsed_us;
        else if ((strcmp(state, "REMOTE_GREEN") == 0 ||
                  strcmp(state, "REMOTE_RED") == 0) &&
                 out->remote_execution_us == 0)
            out->remote_execution_us = events[i].elapsed_us;
        else if (strcmp(state, "RECEIPT_VERIFIED") == 0 &&
                 out->receipt_verification_us == 0)
            out->receipt_verification_us = events[i].elapsed_us;
        else if (strcmp(state, "READY_FOR_ACCEPTANCE") == 0 &&
                 out->total_background_proof_us == 0)
            out->total_background_proof_us = events[i].elapsed_us;
    }
    return ZCL_OK;
}
