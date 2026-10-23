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

struct proof_transition_edge {
    const char *from;
    const char *to;
};

/* Every legal move except SUPERSEDED, which any non-SUPERSEDED state may take. */
static const struct proof_transition_edge proof_transition_edges[] = {
    { "REQUESTED", "PEER_DISCOVERED" },
    { "PEER_DISCOVERED", "CONTEXT_READY" },
    { "PEER_DISCOVERED", "PEER_DISCOVERED" },
    { "CONTEXT_READY", "RUNNING" },
    { "CONTEXT_READY", "PEER_DISCOVERED" },
    { "RUNNING", "REMOTE_GREEN" },
    { "RUNNING", "REMOTE_RED" },
    { "RUNNING", "PEER_DISCOVERED" },
    { "REMOTE_GREEN", "RECEIPT_VERIFIED" },
    { "REMOTE_GREEN", "REMOTE_RED" },
    { "REMOTE_RED", "PEER_DISCOVERED" },
    { "REMOTE_RED", "RECEIPT_VERIFIED" },
    { "RECEIPT_VERIFIED", "REPRODUCED" },
    { "REPRODUCED", "READY_FOR_ACCEPTANCE" },
};

static bool proof_transition_allowed(const char *from, const char *to)
{
    if (!from || !to) return false;
    if (strcmp(to, "SUPERSEDED") == 0)
        return strcmp(from, "SUPERSEDED") != 0;
    for (size_t i = 0;
         i < sizeof(proof_transition_edges) / sizeof(proof_transition_edges[0]);
         i++)
        if (strcmp(from, proof_transition_edges[i].from) == 0 &&
            strcmp(to, proof_transition_edges[i].to) == 0)
            return true;
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

/* True when the action, its job and the job's source CAS root all exist. */
static bool proof_action_job_find(
    struct node_db *ndb, const char *action_id,
    struct db_build_action *action, struct db_build_job *job)
{
    return db_build_action_find(ndb, action_id, action) &&
           db_build_job_find(ndb, action->job_id, job) &&
           job->source_cas_sha3[0];
}

static bool proof_transition_inputs_invalid(
    struct node_db *ndb, const char *action_id, const char *state,
    struct db_build_proof_event *out, uint64_t request_id,
    int64_t deadline_at, int64_t elapsed_us, int64_t now)
{
    return !ndb || !ndb->open || !action_id || !state || !out ||
        request_id == 0 || deadline_at < 0 || elapsed_us < 0 || now <= 0;
}

static struct zcl_result proof_transition_bind_source(
    struct node_db *ndb, const char *action_id,
    struct db_build_proof_event *out)
{
    if (out->source_root_sha3[0]) return ZCL_OK;
    struct db_build_action action;
    struct db_build_job job;
    if (!proof_action_job_find(ndb, action_id, &action, &job))
        return ZCL_ERR(-1, "async proof transition lost source binding");
    (void)snprintf(out->source_root_sha3,
                   sizeof(out->source_root_sha3), "%s",
                   job.source_cas_sha3);
    return ZCL_OK;
}

static struct zcl_result proof_transition_state_complete(
    const struct db_build_proof_event *out, const char *state)
{
    if (proof_state_needs_peer(state) && out->peer_id == 0)
        return ZCL_ERR(-1, "%s requires a selected peer", state);
    if (proof_state_needs_context(state) && !out->context_root_sha3[0])
        return ZCL_ERR(-1, "%s requires the exact context root", state);
    if (proof_state_needs_receipt(state) && !out->receipt_root_sha3[0])
        return ZCL_ERR(-1, "%s requires a signed receipt root", state);
    return ZCL_OK;
}

struct zcl_result build_fabric_proof_transition(
    struct node_db *ndb, const char *action_id, const char *state,
    uint64_t peer_id, uint64_t request_id, const char *context_root,
    const char *receipt_root, int64_t deadline_at, int64_t elapsed_us,
    int64_t now,
    struct db_build_proof_event *out)
{
    if (proof_transition_inputs_invalid(ndb, action_id, state, out,
                                        request_id, deadline_at, elapsed_us,
                                        now))
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
    struct zcl_result bound = proof_transition_bind_source(ndb, action_id, out);
    if (!bound.ok) return bound;
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
    struct zcl_result complete = proof_transition_state_complete(out, state);
    if (!complete.ok) return complete;
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

static bool proof_request_inputs_invalid(
    struct node_db *ndb, const char *action_id, const char *workspace,
    int64_t local_submit_us, int64_t now,
    struct db_build_proof_event *out, bool *created)
{
    return !ndb || !ndb->open || !action_id || !workspace ||
        workspace[0] != '/' || !out || !created || local_submit_us < 0 ||
        now <= 0;
}

struct zcl_result build_fabric_proof_request(
    struct node_db *ndb, const char *action_id, const char *workspace,
    uint64_t peer_hint, int64_t local_submit_us,
    int64_t now, struct db_build_proof_event *out, bool *created)
{
    if (proof_request_inputs_invalid(ndb, action_id, workspace,
                                     local_submit_us, now, out, created))
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
    if (!proof_action_job_find(ndb, action_id, &action, &job) ||
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

/* Tallies each event into the metric sample rows it belongs to, in event
 * order. A REMOTE_RED event also counts as a remote-execution sample. */
static void proof_timing_collect(
    const struct db_build_proof_event *events, int count,
    struct build_fabric_proof_timings *out,
    int64_t samples[7][64], size_t sample_count[7])
{
    int64_t *values[7] = { &out->local_submit_us, &out->peer_discovery_us,
        &out->transfer_us, &out->remote_queue_us, &out->remote_execution_us,
        &out->receipt_verification_us, &out->total_background_proof_us };
    const char *states[7] = {"REQUESTED", "PEER_DISCOVERED", "CONTEXT_READY",
        "RUNNING", "REMOTE_GREEN", "RECEIPT_VERIFIED",
        "READY_FOR_ACCEPTANCE"};
    for (int i = 0; i < count; i++) {
        const char *state = events[i].state;
        if (strcmp(state, "REMOTE_RED") == 0) out->failure_events++;
        for (size_t j = 0; j < 7; j++) {
            if (strcmp(state, states[j]) != 0 &&
                !(j == 4 && strcmp(state, "REMOTE_RED") == 0)) continue;
            if (sample_count[j] == 0) *values[j] = events[i].elapsed_us;
            samples[j][sample_count[j]++] = events[i].elapsed_us;
            break;
        }
    }
}

/* Sums the samples with overflow checks and records min and max. */
static struct zcl_result proof_timing_accumulate(
    const int64_t *samples, size_t count,
    struct build_fabric_timing_metric *m, int64_t *sum_out)
{
    int64_t sum = 0;
    for (size_t a = 0; a < count; a++) {
        if ((samples[a] > 0 && sum > INT64_MAX - samples[a]) ||
            (samples[a] < 0 && sum < INT64_MIN - samples[a]))
            return ZCL_ERR(-1, "async proof timing sum overflow");
        sum += samples[a];
        if (a == 0 || samples[a] < m->min_us) m->min_us = samples[a];
        if (a == 0 || samples[a] > m->max_us) m->max_us = samples[a];
    }
    *sum_out = sum;
    return ZCL_OK;
}

static struct zcl_result proof_timing_metric_fill(
    int64_t *samples, size_t count, struct build_fabric_timing_metric *m)
{
    int64_t sum = 0;
    struct zcl_result acc = proof_timing_accumulate(samples, count, m, &sum);
    if (!acc.ok) return acc;
    for (size_t a = 1; a < count; a++) {
        int64_t value = samples[a];
        size_t b = a;
        while (b > 0 && samples[b - 1] > value) {
            samples[b] = samples[b - 1];
            b--;
        }
        samples[b] = value;
    }
    m->mean_us = sum / (int64_t)count;
    m->p50_us = samples[(count-1u)/2u];
    m->p95_us = samples[(count*95u-1u)/100u];
    return ZCL_OK;
}

struct zcl_result build_fabric_proof_timings(
    struct node_db *ndb, const char *action_id,
    struct build_fabric_proof_timings *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!ndb || !ndb->open || !action_id || !out)
        return ZCL_ERR(-1, "async proof timings require exact inputs");
    struct db_build_proof_event events[65];
    int count = db_build_proof_events_for_action(
        ndb, action_id, events, sizeof(events) / sizeof(events[0]));
    if (count <= 0)
        return ZCL_ERR(-1, "async proof timing chain is absent or invalid");
    if (count > 64)
        return ZCL_ERR(-1, "async proof timing chain exceeds bounded capacity");
    int64_t samples[7][64];
    size_t sample_count[7] = {0};
    struct build_fabric_timing_metric *metrics[7] = {
        &out->metric_local_submit, &out->metric_peer_discovery,
        &out->metric_transfer, &out->metric_remote_queue,
        &out->metric_remote_execution, &out->metric_receipt_verification,
        &out->metric_total_background_proof };
    out->total_events = (uint64_t)count;
    proof_timing_collect(events, count, out, samples, sample_count);
    for (size_t j = 0; j < 7; j++) {
        struct build_fabric_timing_metric *m = metrics[j];
        m->measured_count = sample_count[j];
        m->missing_count = sample_count[j] == 0 ? 1 : 0;
        if (!sample_count[j]) continue;
        struct zcl_result fill =
            proof_timing_metric_fill(samples[j], sample_count[j], m);
        if (!fill.ok) return fill;
    }
    out->retry_events = sample_count[1] > 1 ? sample_count[1] - 1u : 0;
    return ZCL_OK;
}
