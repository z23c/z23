/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_OPERATOR_SNAPSHOT_SERVICE_H
#define ZCL_SERVICES_OPERATOR_SNAPSHOT_SERVICE_H

#include "framework/condition.h"
#include "services/chain_frontier_snapshot_service.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/operator_peer_snapshot_service.h"
#include "services/runtime_identity_service.h"
#include "sync/sync_state.h"
#include "util/alerts.h"
#include "util/blocker.h"

#include <stdbool.h>
#include <stdint.h>

struct operator_capture {
    struct runtime_identity_snapshot identity;
    uint64_t sequence;
    int attempts;
    int64_t started_wall_us;
    int64_t completed_wall_us;
    int64_t started_mono_us;
    int64_t duration_us;
    bool critical_frontier_stable;
    struct chain_frontier_snapshot chain;
    struct agent_peer_snapshot peers;
    bool download_known;
    uint64_t download_requested;
    uint64_t download_received;
    uint64_t download_timed_out;
    uint64_t download_in_flight;
    uint64_t download_queued;
    enum sync_state sync_state;
    bool sync_state_known;
    struct blocker_snapshot blockers[BLOCKER_CAP];
    int blocker_count;
    int blocker_class_count[4];
    uint64_t blocker_generation;
    int blocker_escape_dispatched;
    int blocker_rate_limit_ms;
    struct condition_engine_summary conditions;
    bool operator_latch_active;
    int64_t operator_latch_since_unix;
    char operator_latch_detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
    bool security_review_required;
    char security_posture_status[48];
    char security_posture_next_action[96];
    struct legacy_mirror_sync_stats mirror;
};

struct operator_verdict {
    const char *status;
    const char *primary;
    const char *next_action;
    const char *next_command;
    const char *next_command2;
    bool complete;
    bool healthy;
    bool serving;
    bool operator_needed;
    bool chain_values_known;
    bool frontier_order_ok;
    bool chain_consistent;
    bool gap_known;
    int64_t gap;
    int64_t index_gap;
};

void operator_snapshot_collect(struct operator_capture *capture);
struct operator_verdict operator_snapshot_classify(
    const struct operator_capture *capture);
bool operator_snapshot_chain_bindings_known(
    const struct operator_capture *capture);
const struct blocker_snapshot *operator_snapshot_dominant_blocker(
    const struct operator_capture *capture);

#endif
