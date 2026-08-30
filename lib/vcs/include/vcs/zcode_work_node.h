/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded requester-owned ZCODE work state over package peers. */

#ifndef ZCL_VCS_ZCODE_WORK_NODE_H
#define ZCL_VCS_ZCODE_WORK_NODE_H

#include "vcs/zcode_work_swarm.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_WORK_NODE_MAX_PEERS 64u
#define VCS_ZCODE_WORK_NODE_MAX_REQUESTS 32u
#define VCS_ZCODE_WORK_NODE_MAX_RESULTS 64u
#define VCS_ZCODE_WORK_NODE_MAX_OUTBOUND 128u
#define VCS_ZCODE_WORK_NODE_NO_SLOT UINT16_MAX

struct vcs_zcode_work_node;

enum vcs_zcode_work_node_result {
    VCS_ZCODE_WORK_NODE_OK = 0,
    VCS_ZCODE_WORK_NODE_MALFORMED,
    VCS_ZCODE_WORK_NODE_UNKNOWN_PEER,
    VCS_ZCODE_WORK_NODE_CAPABILITY_STALE,
    VCS_ZCODE_WORK_NODE_LEASE_EXPIRED,
    VCS_ZCODE_WORK_NODE_CAPABILITY_MISMATCH,
    VCS_ZCODE_WORK_NODE_REPLAY,
    VCS_ZCODE_WORK_NODE_UNREQUESTED,
    VCS_ZCODE_WORK_NODE_BINDING,
    VCS_ZCODE_WORK_NODE_FULL,
    VCS_ZCODE_WORK_NODE_NOT_LOCAL_WORKER,
};

const char *vcs_zcode_work_node_result_string(
    enum vcs_zcode_work_node_result result);

struct vcs_zcode_work_node *vcs_zcode_work_node_create(void);
void vcs_zcode_work_node_free(struct vcs_zcode_work_node *node);
void vcs_zcode_work_node_set_global(struct vcs_zcode_work_node *node);
struct vcs_zcode_work_node *vcs_zcode_work_node_global(void);

/* Reentrant diagnostic snapshot for the native agent status instrument.
 * Reports bounded counts, enablement, and fresh signature-verified worker
 * capability projections. Public signers are domain-separated fingerprints;
 * no request, signature, key material, or action root leaves this boundary. */
struct json_value;
bool vcs_zcode_work_node_dump_state_json(struct json_value *out,
                                         const char *key);

bool vcs_zcode_work_node_peer_add(struct vcs_zcode_work_node *node,
                                  uint64_t peer);
void vcs_zcode_work_node_peer_drop(struct vcs_zcode_work_node *node,
                                   uint64_t peer);
/* Expire unfinished signed requests and release their bounded headroom.
 * Their immutable binding remains as a bounded tombstone until a late local
 * result is explicitly refused as WORK_LEASE_EXPIRED (or the peer drops). */
void vcs_zcode_work_node_tick(struct vcs_zcode_work_node *node, int64_t now);

/* The caller seals this capability before installation. Setting it queues an
 * advertisement to every current peer; peer_add queues it for the new peer. */
bool vcs_zcode_work_node_set_local_capability(
    struct vcs_zcode_work_node *node,
    const struct vcs_zcode_work_capability_v1 *capability);
/* Installs the worker-local signing identity used only for signed admission
 * control messages. The key must match every installed local capability. */
bool vcs_zcode_work_node_set_local_signer(
    struct vcs_zcode_work_node *node, const uint8_t secret[32],
    const uint8_t pubkey[32]);

bool vcs_zcode_work_node_peer_capability(
    struct vcs_zcode_work_node *node, uint64_t peer, int64_t now,
    struct vcs_zcode_work_capability_v1 *out);
size_t vcs_zcode_work_node_capable_peers(
    struct vcs_zcode_work_node *node, int64_t now, uint64_t *peers,
    struct vcs_zcode_work_capability_v1 *capabilities, size_t max);

/* Requester coordination. No automatic peer selection exists: the requester
 * chooses one advertised peer and owns its deadline, cancellation, and quorum. */
enum vcs_zcode_work_node_result vcs_zcode_work_node_submit(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request, int64_t now);
enum vcs_zcode_work_node_result vcs_zcode_work_node_cancel(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_cancel_v1 *cancel);

/* Worker response for a request previously drained from next_request. */
enum vcs_zcode_work_node_result vcs_zcode_work_node_publish_result(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_result_v1 *result);
/* RESULT has no transport acknowledgement. Retain the exact verified frame
 * and requeue it at a bounded interval until the request's signed deadline;
 * the requester accepts an exact duplicate idempotently. */
size_t vcs_zcode_work_node_requeue_results(
    struct vcs_zcode_work_node *node, int64_t now);
enum vcs_zcode_work_node_result vcs_zcode_work_node_publish_progress(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_progress_v1 *progress);

/* Deliver one authenticated ZCWS frame from an existing package-swarm peer. */
enum vcs_zcode_work_node_result vcs_zcode_work_node_handle_frame(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const uint8_t *wire, size_t wire_len, int64_t now);

/* Transport and application drains. All are bounded FIFO operations. */
bool vcs_zcode_work_node_next_outbound(
    struct vcs_zcode_work_node *node, uint64_t peer_filter,
    uint64_t *peer_out, uint8_t out[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES],
    size_t *out_len);
bool vcs_zcode_work_node_next_request(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_request_v1 *out);
/* Inspect the FIFO head without consuming it, so the transport glue can wait
 * for its content.v2 context to become complete. */
bool vcs_zcode_work_node_peek_request(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_request_v1 *out);
/* Snapshot unfinished inbound tracks. The request remains tracked after its
 * admission event is drained, allowing a durable ZBuild result to be returned. */
size_t vcs_zcode_work_node_inbound_requests(
    struct vcs_zcode_work_node *node, uint64_t *peers,
    struct vcs_zcode_work_request_v1 *requests, size_t max);
bool vcs_zcode_work_node_inbound_request(
    struct vcs_zcode_work_node *node, uint64_t peer, uint64_t request_id,
    struct vcs_zcode_work_request_v1 *out, bool *cancelled);
bool vcs_zcode_work_node_outbound_request(
    struct vcs_zcode_work_node *node, uint64_t peer, uint64_t request_id,
    struct vcs_zcode_work_request_v1 *out);
bool vcs_zcode_work_node_next_cancel(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_cancel_v1 *out);
bool vcs_zcode_work_node_next_result(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_result_v1 *out);
bool vcs_zcode_work_node_next_admission(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_admission_v1 *out);
bool vcs_zcode_work_node_peek_result(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_result_v1 *out);
bool vcs_zcode_work_node_next_progress(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_progress_v1 *out);
bool vcs_zcode_work_node_peek_progress(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_progress_v1 *out);

#endif /* ZCL_VCS_ZCODE_WORK_NODE_H */
