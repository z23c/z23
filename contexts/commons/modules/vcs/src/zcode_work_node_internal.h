/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private bounded work-node state shared by execution and diagnostic views. */
#ifndef ZCODE_WORK_NODE_INTERNAL_H
#define ZCODE_WORK_NODE_INTERNAL_H

#include "vcs/zcode_work_node.h"
#include <pthread.h>
struct work_peer {
    bool used;
    uint64_t id;
    bool has_capability;
    bool busy_observed;
    struct vcs_zcode_work_capability_v1 capability;
};

struct work_track {
    bool used;
    bool inbound;
    bool finished;
    bool cancelled;
    bool expired;
    bool receiver_admitted;
    bool admission_sent;
    uint64_t peer;
    uint8_t worker_signer[32];
    uint8_t progress_stage;
    uint8_t admission_disposition;
    uint16_t worker_slot;
    uint64_t lease_generation;
    int64_t worker_capability_expires;
    int64_t result_last_queued;
    bool has_result;
    struct vcs_zcode_work_request_v1 request;
    struct vcs_zcode_work_result_v1 result;
};

struct work_slot {
    bool used;
    bool action_ready;
    uint64_t generation;
    uint64_t context_bytes;
    int64_t deadline_unix;
    struct vcs_zcode_work_request_v1 binding;
};
struct work_frame {
    uint64_t peer;
    size_t len;
    uint8_t bytes[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
};
struct work_request_event {
    uint64_t peer;
    struct vcs_zcode_work_request_v1 request;
};
struct work_cancel_event {
    uint64_t peer;
    struct vcs_zcode_work_cancel_v1 cancel;
};
struct work_result_event {
    uint64_t peer;
    struct vcs_zcode_work_result_v1 result;
};
struct work_progress_event {
    uint64_t peer;
    struct vcs_zcode_work_progress_v1 progress;
};
struct work_admission_event {
    uint64_t peer;
    struct vcs_zcode_work_admission_v1 admission;
};

struct vcs_zcode_work_node {
    pthread_mutex_t lock;
    struct work_peer peers[VCS_ZCODE_WORK_NODE_MAX_PEERS];
    struct work_track tracks[VCS_ZCODE_WORK_NODE_MAX_REQUESTS * 2u];
    bool has_local_capability;
    struct vcs_zcode_work_capability_v1 local_capability;
    bool has_local_signer;
    uint8_t local_signer_secret[32];
    uint8_t local_signer_pubkey[32];
    uint64_t next_lease_generation;
    struct work_slot slots[64];
    struct work_frame outbound[VCS_ZCODE_WORK_NODE_MAX_OUTBOUND];
    size_t outbound_pos, outbound_count;
    struct work_request_event requests[VCS_ZCODE_WORK_NODE_MAX_REQUESTS];
    size_t request_pos, request_count;
    struct work_cancel_event cancels[VCS_ZCODE_WORK_NODE_MAX_REQUESTS];
    size_t cancel_pos, cancel_count;
    struct work_result_event results[VCS_ZCODE_WORK_NODE_MAX_RESULTS];
    size_t result_pos, result_count;
    struct work_progress_event progresses[VCS_ZCODE_WORK_NODE_MAX_RESULTS];
    size_t progress_pos, progress_count;
    struct work_admission_event admissions[VCS_ZCODE_WORK_NODE_MAX_RESULTS];
    size_t admission_pos, admission_count;
};

struct vcs_zcode_work_capability_v1
zcode_work_node_effective_capability_internal(
    const struct vcs_zcode_work_node *node, int peer_at);

#endif
