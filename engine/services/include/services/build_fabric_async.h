/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Requester-local durable state for asynchronous peer proof. */

#ifndef ZCL_SERVICES_BUILD_FABRIC_ASYNC_H
#define ZCL_SERVICES_BUILD_FABRIC_ASYNC_H

#include "base/result.h"
#include "models/build_proof_event.h"

#include <stdbool.h>
#include <stdint.h>

uint64_t build_fabric_proof_request_id(const char *action_id);

/* Exact immutable actions deduplicate to one REQUESTED event. Requesting a
 * newer candidate for the same task appends SUPERSEDED to older active
 * candidates; their receipts remain in the existing receipt ledger. */
struct zcl_result build_fabric_proof_request(
    struct node_db *ndb, const char *action_id, const char *workspace,
    uint64_t peer_hint, int64_t local_submit_us,
    int64_t now, struct db_build_proof_event *out, bool *created);

/* Append one closed transition. Roots not supplied inherit from the prior
 * event; the model recomputes and verifies the deterministic event root. */
struct zcl_result build_fabric_proof_transition(
    struct node_db *ndb, const char *action_id, const char *state,
    uint64_t peer_id, uint64_t request_id, const char *context_root,
    const char *receipt_root, int64_t deadline_at, int64_t elapsed_us,
    int64_t now,
    struct db_build_proof_event *out);

struct build_fabric_timing_metric {
    uint64_t measured_count;
    uint64_t missing_count;
    int64_t min_us;
    int64_t max_us;
    int64_t mean_us;
    int64_t p50_us;
    int64_t p95_us;
};

struct build_fabric_proof_timings {
    int64_t local_submit_us;
    int64_t peer_discovery_us;
    int64_t transfer_us;
    int64_t remote_queue_us;
    int64_t remote_execution_us;
    int64_t receipt_verification_us;
    int64_t total_background_proof_us;
    struct build_fabric_timing_metric metric_local_submit,
      metric_peer_discovery, metric_transfer,
      metric_remote_queue, metric_remote_execution,
      metric_receipt_verification, metric_total_background_proof;
    uint64_t total_events;
    uint64_t failure_events;
    uint64_t retry_events;
};

/* Derive named latency categories from the complete append-only event chain.
 * Legacy scalars preserve the first measurement, including zero. Aggregates
 * include every matching event (both REMOTE_GREEN and REMOTE_RED executions).
 * missing_count is one when the category has no event, otherwise zero; it is
 * not an estimate of unobserved worker attempts. Means truncate toward zero;
 * percentiles use nearest rank. retry_events counts PEER_DISCOVERED events
 * after the first; failure_events counts REMOTE_RED observations, not process
 * crashes. Chains over 64 events and sum overflow refuse without claiming a
 * complete report. No timing can alter proof acceptance or local feedback. */
struct zcl_result build_fabric_proof_timings(
    struct node_db *ndb, const char *action_id,
    struct build_fabric_proof_timings *out);

#endif /* ZCL_SERVICES_BUILD_FABRIC_ASYNC_H */
