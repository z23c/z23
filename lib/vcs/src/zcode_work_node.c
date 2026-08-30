/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded requester-owned ZCODE work state over package peers. */

#include "vcs/zcode_work_node.h"

#include "base/hex.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

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
    uint64_t generation;
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

static struct vcs_zcode_work_node *g_work_node;

#define ZCODE_WORK_PROJECTED_WORKERS_MAX 8u

static struct vcs_zcode_work_capability_v1 work_effective_capability(
    const struct vcs_zcode_work_node *node, int peer_at);

const char *vcs_zcode_work_node_result_string(
    enum vcs_zcode_work_node_result r)
{
    switch (r) {
    case VCS_ZCODE_WORK_NODE_OK: return "ok";
    case VCS_ZCODE_WORK_NODE_MALFORMED: return "malformed-frame";
    case VCS_ZCODE_WORK_NODE_UNKNOWN_PEER: return "unknown-peer";
    case VCS_ZCODE_WORK_NODE_CAPABILITY_STALE: return "capability-stale";
    case VCS_ZCODE_WORK_NODE_LEASE_EXPIRED: return "work-lease-expired";
    case VCS_ZCODE_WORK_NODE_CAPABILITY_MISMATCH: return "capability-mismatch";
    case VCS_ZCODE_WORK_NODE_REPLAY: return "replayed-work-frame";
    case VCS_ZCODE_WORK_NODE_UNREQUESTED: return "unrequested-result";
    case VCS_ZCODE_WORK_NODE_BINDING: return "request-result-binding";
    case VCS_ZCODE_WORK_NODE_FULL: return "bounded-queue-full";
    case VCS_ZCODE_WORK_NODE_NOT_LOCAL_WORKER: return "local-worker-disabled";
    }
    return "unknown";
}

struct vcs_zcode_work_node *vcs_zcode_work_node_create(void)
{
    struct vcs_zcode_work_node *node =
        zcl_malloc(sizeof(*node), "zcode.work_node");
    if (!node) return NULL;
    memset(node, 0, sizeof(*node));
    if (pthread_mutex_init(&node->lock, NULL) != 0) {
        free(node);
        LOG_NULL("vcs.work_node", "mutex initialization failed");
    }
    return node;
}

void vcs_zcode_work_node_free(struct vcs_zcode_work_node *node)
{
    if (!node) return;
    memset(node->local_signer_secret, 0, sizeof(node->local_signer_secret));
    pthread_mutex_destroy(&node->lock);
    free(node);
}

bool vcs_zcode_work_node_set_local_signer(
    struct vcs_zcode_work_node *node, const uint8_t secret[32],
    const uint8_t pubkey[32])
{
    if (!node || !secret || !pubkey) return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= pubkey[i];
    if (any == 0) return false;
    pthread_mutex_lock(&node->lock);
    bool compatible = !node->has_local_capability ||
        memcmp(node->local_capability.signer_pubkey, pubkey, 32) == 0;
    if (compatible) {
        memcpy(node->local_signer_secret, secret, 32);
        memcpy(node->local_signer_pubkey, pubkey, 32);
        node->has_local_signer = true;
    }
    pthread_mutex_unlock(&node->lock);
    return compatible;
}

void vcs_zcode_work_node_set_global(struct vcs_zcode_work_node *node)
{
    g_work_node = node;
}

struct vcs_zcode_work_node *vcs_zcode_work_node_global(void)
{
    return g_work_node;
}

static void work_signer_fingerprint(const uint8_t signer[32], char out[65])
{
    static const char domain[] = "zcl.zcode.work.signer.fingerprint.v1";
    struct sha3_256_ctx hash;
    uint8_t digest[32];
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain) - 1u);
    sha3_256_write(&hash, signer, 32);
    sha3_256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
}

static const char *work_target_name(uint32_t target)
{
    return target == VCS_ZCODE_WORK_TARGET_LINUX_X86_64_V3
        ? "linux-x86_64-v3" : "unknown";
}

static void work_push_kind_names(struct json_value *row, uint32_t mask)
{
    static const struct {
        uint8_t kind;
        const char *name;
    } kinds[] = {
        { VCS_ZCODE_WORK_PROPOSE, "propose" },
        { VCS_ZCODE_WORK_BUILD, "build" },
        { VCS_ZCODE_WORK_TEST, "test" },
        { VCS_ZCODE_WORK_FUZZ, "fuzz" },
        { VCS_ZCODE_WORK_REVIEW, "review" },
        { VCS_ZCODE_WORK_REPRODUCE, "reproduce" },
        { VCS_ZCODE_WORK_DIAGNOSE, "diagnose" },
    };
    struct json_value names = {0};
    json_set_array(&names);
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        if ((mask & (UINT32_C(1) << kinds[i].kind)) == 0) continue;
        struct json_value name = {0};
        json_set_str(&name, kinds[i].name);
        json_push_back(&names, &name);
        json_free(&name);
    }
    json_push_kv(row, "work_kinds", &names);
    json_free(&names);
}

static void work_push_confinement_names(struct json_value *row, uint32_t mask)
{
    static const struct {
        uint32_t bit;
        const char *name;
    } facts[] = {
        { VCS_ZCODE_WORK_CONFINEMENT_LANDLOCK, "landlock" },
        { VCS_ZCODE_WORK_CONFINEMENT_SECCOMP, "seccomp" },
        { VCS_ZCODE_WORK_CONFINEMENT_RLIMITS, "rlimits" },
        { VCS_ZCODE_WORK_CONFINEMENT_NO_NETWORK, "no_network" },
    };
    struct json_value names = {0};
    json_set_array(&names);
    for (size_t i = 0; i < sizeof(facts) / sizeof(facts[0]); i++) {
        if ((mask & facts[i].bit) == 0) continue;
        struct json_value name = {0};
        json_set_str(&name, facts[i].name);
        json_push_back(&names, &name);
        json_free(&name);
    }
    json_push_kv(row, "confinement", &names);
    json_free(&names);
}

static void work_push_worker(struct json_value *workers, uint64_t peer_id,
                             const struct vcs_zcode_work_capability_v1 *cap)
{
    char signer[65], toolchain[65];
    work_signer_fingerprint(cap->signer_pubkey, signer);
    zcl_hex_encode(cap->toolchain_capsule_root, 32, toolchain);
    struct json_value row = {0};
    json_set_object(&row);
    json_push_kv_int(&row, "peer_id", (int64_t)peer_id);
    json_push_kv_str(&row, "signer_fingerprint_sha3", signer);
    json_push_kv_str(&row, "toolchain_capsule_root", toolchain);
    json_push_kv_str(&row, "target", work_target_name(cap->target));
    json_push_kv_int(&row, "work_kinds_mask", (int64_t)cap->work_kinds);
    work_push_kind_names(&row, cap->work_kinds);
    json_push_kv_int(&row, "confinement_mask", (int64_t)cap->confinement);
    work_push_confinement_names(&row, cap->confinement);
    json_push_kv_int(&row, "max_cpu_seconds", cap->max_cpu_seconds);
    json_push_kv_int(&row, "max_memory_bytes", (int64_t)cap->max_memory_bytes);
    json_push_kv_int(&row, "max_output_bytes", (int64_t)cap->max_output_bytes);
    json_push_kv_int(&row, "max_lease_seconds", cap->max_lease_seconds);
    json_push_kv_int(&row, "slots", cap->slots);
    json_push_kv_int(&row, "queue_headroom", cap->queue_headroom);
    json_push_kv_int(&row, "expires_unix", cap->expires_unix);
    json_push_kv_str(&row, "freshness", "fresh");
    json_push_back(workers, &row);
    json_free(&row);
}

bool vcs_zcode_work_node_dump_state_json(struct json_value *out,
                                         const char *key)
{
    (void)key;
    if (!out) {
        LOG_FAIL("zcode_work", "dump_state_json: out is NULL");
    }
    json_set_object(out);
    struct vcs_zcode_work_node *node = g_work_node;
    if (!node) {
        json_push_kv_bool(out, "enabled", false);
        json_push_kv_int(out, "worker_capacity", 0);
        json_push_kv_int(out, "worker_active", 0);
        json_push_kv_int(out, "worker_available", 0);
        json_push_kv_int(out, "capable_peers", 0);
        json_push_kv_int(out, "total", 0);
        json_push_kv_int(out, "returned", 0);
        json_push_kv_bool(out, "truncated", false);
        struct json_value workers = {0};
        json_set_array(&workers);
        json_push_kv(out, "workers", &workers);
        json_free(&workers);
        json_push_kv_str(out, "next_action", "z23 join");
        return true;
    }
    int64_t now = platform_time_wall_unix();
    pthread_mutex_lock(&node->lock);
    size_t capacity = node->has_local_capability
        ? node->local_capability.slots : 0;
    if (capacity > sizeof(node->slots) / sizeof(node->slots[0]))
        capacity = sizeof(node->slots) / sizeof(node->slots[0]);
    size_t active = 0;
    for (size_t i = 0; i < capacity; i++)
        active += node->slots[i].used ? 1u : 0u;
    size_t total = 0, returned = 0;
    struct json_value workers = {0};
    json_set_array(&workers);
    for (size_t i = 0; i < VCS_ZCODE_WORK_NODE_MAX_PEERS; i++) {
        if (!node->peers[i].used || !node->peers[i].has_capability ||
            now <= 0 || now >= node->peers[i].capability.expires_unix)
            continue;
        total++;
        if (returned >= ZCODE_WORK_PROJECTED_WORKERS_MAX) continue;
        struct vcs_zcode_work_capability_v1 effective =
            work_effective_capability(node, (int)i);
        work_push_worker(&workers, node->peers[i].id, &effective);
        returned++;
    }
    json_push_kv_bool(out, "enabled", node->has_local_capability);
    json_push_kv_int(out, "worker_capacity", (int64_t)capacity);
    json_push_kv_int(out, "worker_active", (int64_t)active);
    json_push_kv_int(out, "worker_available", (int64_t)(capacity - active));
    json_push_kv_int(out, "capable_peers", (int64_t)total);
    json_push_kv_int(out, "total", (int64_t)total);
    json_push_kv_int(out, "returned", (int64_t)returned);
    json_push_kv_bool(out, "truncated", returned < total);
    json_push_kv(out, "workers", &workers);
    json_free(&workers);
    json_push_kv_str(out, "next_action",
        node->has_local_capability
            ? "zcode work toolchain"
            : "z23 join");
    pthread_mutex_unlock(&node->lock);
    return true;
}

static int work_peer_slot(const struct vcs_zcode_work_node *node,
                          uint64_t peer)
{
    for (size_t i = 0; i < VCS_ZCODE_WORK_NODE_MAX_PEERS; i++)
        if (node->peers[i].used && node->peers[i].id == peer) return (int)i;
    return -1;
}

/* Transport sessions are not worker identities.  A full node can have more
 * than one authenticated connection to the same worker signer, and each
 * session may carry the same signed slot advertisement.  Count requester-
 * owned outstanding leases by signer so duplicate sessions cannot multiply
 * one physical worker's capacity.  The signed queue_headroom remains an
 * upper bound; this local projection only subtracts leases this requester
 * already owns.  Caller holds node->lock. */
static struct vcs_zcode_work_capability_v1 work_effective_capability(
    const struct vcs_zcode_work_node *node, int peer_at)
{
    struct vcs_zcode_work_capability_v1 effective =
        node->peers[peer_at].capability;
    if (node->peers[peer_at].busy_observed)
        effective.queue_headroom = 0;
    uint16_t active = 0;
    for (size_t i = 0; i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++) {
        const struct work_track *track = &node->tracks[i];
        if (!track->used || track->inbound || track->finished ||
            track->cancelled || track->expired)
            continue;
        if (memcmp(track->worker_signer, effective.signer_pubkey, 32) == 0 &&
            active < UINT16_MAX)
            active++;
    }
    uint16_t local_headroom = active < effective.slots
        ? (uint16_t)(effective.slots - active) : 0;
    if (effective.queue_headroom > local_headroom)
        effective.queue_headroom = local_headroom;
    return effective;
}

static bool work_queue_frame(struct vcs_zcode_work_node *node, uint64_t peer,
                             const struct vcs_zcode_work_swarm_message *message)
{
    if (node->outbound_count >= VCS_ZCODE_WORK_NODE_MAX_OUTBOUND) return false;
    size_t slot = (node->outbound_pos + node->outbound_count) %
                  VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
    struct work_frame *frame = &node->outbound[slot];
    if (!vcs_zcode_work_swarm_serialize(message, frame->bytes,
                                         sizeof(frame->bytes), &frame->len))
        return false;
    frame->peer = peer;
    node->outbound_count++;
    return true;
}

static bool work_advertise_locked(struct vcs_zcode_work_node *node,
                                  uint64_t peer)
{
    if (!node->has_local_capability) return true;
    struct vcs_zcode_work_swarm_message message = {
        .type = VCS_ZCODE_WORK_SWARM_CAPABILITY,
    };
    message.body.capability = node->local_capability;
    return work_queue_frame(node, peer, &message);
}

bool vcs_zcode_work_node_peer_add(struct vcs_zcode_work_node *node,
                                  uint64_t peer)
{
    if (!node || peer == 0) LOG_FAIL("vcs.work_node", "invalid peer add");
    pthread_mutex_lock(&node->lock);
    int existing = work_peer_slot(node, peer);
    if (existing >= 0) { pthread_mutex_unlock(&node->lock); return true; }
    bool ok = false;
    for (size_t i = 0; i < VCS_ZCODE_WORK_NODE_MAX_PEERS; i++) {
        if (node->peers[i].used) continue;
        node->peers[i].used = true;
        node->peers[i].id = peer;
        ok = work_advertise_locked(node, peer);
        if (!ok) memset(&node->peers[i], 0, sizeof(node->peers[i]));
        break;
    }
    pthread_mutex_unlock(&node->lock);
    return ok;
}

void vcs_zcode_work_node_peer_drop(struct vcs_zcode_work_node *node,
                                   uint64_t peer)
{
    if (!node || peer == 0) return;
    pthread_mutex_lock(&node->lock);
    int slot = work_peer_slot(node, peer);
    if (slot >= 0) memset(&node->peers[slot], 0, sizeof(node->peers[slot]));
    /* A transport session does not own a worker slot. Inbound tracks survive
     * disconnect until their signed lease expires, is cancelled, or finishes. */
    size_t kept = 0;
    for (size_t i = 0; i < node->outbound_count; i++) {
        size_t src = (node->outbound_pos + i) %
                     VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
        if (node->outbound[src].peer == peer) continue;
        size_t dst = (node->outbound_pos + kept) %
                     VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
        if (dst != src) node->outbound[dst] = node->outbound[src];
        kept++;
    }
    node->outbound_count = kept;
    pthread_mutex_unlock(&node->lock);
}

void vcs_zcode_work_node_tick(struct vcs_zcode_work_node *node, int64_t now)
{
    if (!node || now < 0) return;
    pthread_mutex_lock(&node->lock);
    for (size_t i = 0; i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++) {
        struct work_track *track = &node->tracks[i];
        if (!track->used || track->finished || track->cancelled ||
            track->expired ||
            now < track->request.deadline_unix)
            continue;
        /* Keep the immutable request binding after its lease expires.  A
         * worker may still finish an already-running child; retaining this
         * bounded tombstone lets publish_result name WORK_LEASE_EXPIRED
         * instead of silently losing the result as "unrequested". */
        track->expired = true;
    }
    for (size_t i = 0; i < sizeof(node->slots) / sizeof(node->slots[0]); i++) {
        struct work_slot *slot = &node->slots[i];
        if (!slot->used || now < slot->deadline_unix) continue;
        for (size_t j = 0;
             j < sizeof(node->tracks) / sizeof(node->tracks[0]); j++) {
            struct work_track *track = &node->tracks[j];
            if (track->used && track->inbound && track->worker_slot == i &&
                !track->finished && !track->cancelled)
                track->expired = true;
        }
        memset(slot, 0, sizeof(*slot));
    }
    size_t kept = 0;
    for (size_t i = 0; i < node->request_count; i++) {
        size_t src = (node->request_pos + i) %
                     VCS_ZCODE_WORK_NODE_MAX_REQUESTS;
        if (node->requests[src].request.deadline_unix <= now) continue;
        size_t dst = (node->request_pos + kept) %
                     VCS_ZCODE_WORK_NODE_MAX_REQUESTS;
        if (dst != src) node->requests[dst] = node->requests[src];
        kept++;
    }
    node->request_count = kept;
    kept = 0;
    for (size_t i = 0; i < node->outbound_count; i++) {
        size_t src = (node->outbound_pos + i) %
                     VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
        struct vcs_zcode_work_swarm_message message;
        bool expired = vcs_zcode_work_swarm_parse(
                node->outbound[src].bytes, node->outbound[src].len,
                &message) &&
            message.type == VCS_ZCODE_WORK_SWARM_REQUEST &&
            message.body.request.deadline_unix <= now;
        if (expired) continue;
        size_t dst = (node->outbound_pos + kept) %
                     VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
        if (dst != src) node->outbound[dst] = node->outbound[src];
        kept++;
    }
    node->outbound_count = kept;
    pthread_mutex_unlock(&node->lock);
}

bool vcs_zcode_work_node_set_local_capability(
    struct vcs_zcode_work_node *node,
    const struct vcs_zcode_work_capability_v1 *capability)
{
    if (!node || !capability || !vcs_zcode_work_capability_verify(capability))
        return false;
    pthread_mutex_lock(&node->lock);
    if (node->has_local_signer &&
        memcmp(node->local_signer_pubkey, capability->signer_pubkey, 32) != 0) {
        pthread_mutex_unlock(&node->lock);
        return false;
    }
    node->local_capability = *capability;
    node->has_local_capability = true;
    bool ok = true;
    for (size_t i = 0; i < VCS_ZCODE_WORK_NODE_MAX_PEERS; i++)
        if (node->peers[i].used &&
            !work_advertise_locked(node, node->peers[i].id)) ok = false;
    pthread_mutex_unlock(&node->lock);
    return ok;
}

bool vcs_zcode_work_node_peer_capability(
    struct vcs_zcode_work_node *node, uint64_t peer, int64_t now,
    struct vcs_zcode_work_capability_v1 *out)
{
    if (!node || !out) return false;
    pthread_mutex_lock(&node->lock);
    int slot = work_peer_slot(node, peer);
    bool ok = slot >= 0 && node->peers[slot].has_capability &&
              now < node->peers[slot].capability.expires_unix;
    if (ok) *out = work_effective_capability(node, slot);
    pthread_mutex_unlock(&node->lock);
    return ok;
}

size_t vcs_zcode_work_node_capable_peers(
    struct vcs_zcode_work_node *node, int64_t now, uint64_t *peers,
    struct vcs_zcode_work_capability_v1 *capabilities, size_t max)
{
    if (!node || !peers || !capabilities || max == 0 || now < 0) return 0;
    pthread_mutex_lock(&node->lock);
    size_t count = 0;
    for (size_t i = 0; i < VCS_ZCODE_WORK_NODE_MAX_PEERS && count < max; i++) {
        if (!node->peers[i].used || !node->peers[i].has_capability ||
            now >= node->peers[i].capability.expires_unix)
            continue;
        peers[count] = node->peers[i].id;
        capabilities[count] = work_effective_capability(node, (int)i);
        count++;
    }
    pthread_mutex_unlock(&node->lock);
    return count;
}

static bool work_capability_allows(
    const struct vcs_zcode_work_capability_v1 *cap,
    const struct vcs_zcode_work_request_v1 *request, int64_t now)
{
    return cap && request && now < cap->expires_unix &&
           request->deadline_unix > now && cap->queue_headroom > 0 &&
           request->deadline_unix - now <= cap->max_lease_seconds &&
           (cap->work_kinds & (UINT32_C(1) << request->work_kind)) != 0 &&
           (cap->confinement & VCS_ZCODE_WORK_CONFINEMENT_V1_MASK) ==
               VCS_ZCODE_WORK_CONFINEMENT_V1_MASK &&
           cap->target == request->target &&
           memcmp(cap->toolchain_capsule_root,
                  request->toolchain_capsule_root, 32) == 0 &&
           request->max_cpu_seconds <= cap->max_cpu_seconds &&
           request->max_memory_bytes <= cap->max_memory_bytes &&
           request->max_output_bytes <= cap->max_output_bytes;
}

static bool work_capability_matches(
    const struct vcs_zcode_work_capability_v1 *cap,
    const struct vcs_zcode_work_request_v1 *request, int64_t now)
{
    if (!cap) return false;
    struct vcs_zcode_work_capability_v1 available = *cap;
    available.queue_headroom = available.slots;
    return work_capability_allows(&available, request, now);
}

static bool work_same_action_binding(
    const struct vcs_zcode_work_request_v1 *a,
    const struct vcs_zcode_work_request_v1 *b)
{
    return memcmp(a->task_root, b->task_root, 32) == 0 &&
        memcmp(a->candidate_root, b->candidate_root, 32) == 0 &&
        memcmp(a->action_root, b->action_root, 32) == 0 &&
        memcmp(a->input_root, b->input_root, 32) == 0 &&
        memcmp(a->context_root, b->context_root, 32) == 0 &&
        memcmp(a->proof_policy_root, b->proof_policy_root, 32) == 0 &&
        memcmp(a->toolchain_capsule_root,
               b->toolchain_capsule_root, 32) == 0 &&
        a->work_kind == b->work_kind && a->target == b->target &&
        a->max_cpu_seconds == b->max_cpu_seconds &&
        a->max_memory_bytes == b->max_memory_bytes &&
        a->max_output_bytes == b->max_output_bytes;
}

static int work_find_action_slot(const struct vcs_zcode_work_node *node,
                                 const uint8_t action_root[32])
{
    for (size_t i = 0; i < sizeof(node->slots) / sizeof(node->slots[0]); i++)
        if (node->slots[i].used &&
            memcmp(node->slots[i].binding.action_root, action_root, 32) == 0)
            return (int)i;
    return -1;
}

static int work_find_free_slot(const struct vcs_zcode_work_node *node)
{
    size_t limit = node->local_capability.slots;
    if (limit > sizeof(node->slots) / sizeof(node->slots[0]))
        limit = sizeof(node->slots) / sizeof(node->slots[0]);
    for (size_t i = 0; i < limit; i++)
        if (!node->slots[i].used) return (int)i;
    return -1;
}

static bool work_slot_has_active_track(const struct vcs_zcode_work_node *node,
                                       uint16_t slot)
{
    for (size_t i = 0; i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++) {
        const struct work_track *track = &node->tracks[i];
        if (track->used && track->inbound && track->worker_slot == slot &&
            !track->finished && !track->cancelled && !track->expired)
            return true;
    }
    return false;
}

static bool work_queue_admission(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request, uint8_t disposition,
    uint8_t reason, uint16_t slot, uint64_t generation, int64_t deadline)
{
    if (!node->has_local_signer) return false;
    struct vcs_zcode_work_swarm_message message = {
        .type = VCS_ZCODE_WORK_SWARM_ADMISSION,
    };
    struct vcs_zcode_work_admission_v1 *admission = &message.body.admission;
    admission->request_id = request->request_id;
    memcpy(admission->requester_pubkey, request->requester_pubkey, 32);
    memcpy(admission->action_root, request->action_root, 32);
    admission->lease_generation = generation;
    admission->deadline_unix = deadline;
    admission->slot = slot;
    admission->disposition = disposition;
    admission->reason = reason;
    if (!vcs_zcode_work_admission_seal(
            admission, node->local_signer_secret,
            node->local_signer_pubkey))
        return false;
    return work_queue_frame(node, peer, &message);
}

static struct work_track *work_find_track(struct vcs_zcode_work_node *node,
                                          uint64_t peer, uint64_t request_id,
                                          bool inbound)
{
    for (size_t i = 0; i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++)
        if (node->tracks[i].used && node->tracks[i].peer == peer &&
            node->tracks[i].inbound == inbound &&
            node->tracks[i].request.request_id == request_id)
            return &node->tracks[i];
    return NULL;
}

static struct work_track *work_add_track(struct vcs_zcode_work_node *node)
{
    for (size_t i = 0; i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++)
        if (!node->tracks[i].used) return &node->tracks[i];
    return NULL;
}

static bool work_same_result(const struct vcs_zcode_work_result_v1 *a,
                             const struct vcs_zcode_work_result_v1 *b)
{
    struct vcs_zcode_work_swarm_message ma = {
        .type = VCS_ZCODE_WORK_SWARM_RESULT, .body.result = *a,
    };
    struct vcs_zcode_work_swarm_message mb = {
        .type = VCS_ZCODE_WORK_SWARM_RESULT, .body.result = *b,
    };
    uint8_t wa[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    uint8_t wb[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES];
    size_t la = 0, lb = 0;
    return vcs_zcode_work_swarm_serialize(&ma, wa, sizeof(wa), &la) &&
        vcs_zcode_work_swarm_serialize(&mb, wb, sizeof(wb), &lb) &&
        la == lb && memcmp(wa, wb, la) == 0;
}

static bool work_has_expired_outbound_binding(
    const struct vcs_zcode_work_node *node,
    const struct vcs_zcode_work_request_v1 *request)
{
    for (size_t i = 0; i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++) {
        const struct work_track *track = &node->tracks[i];
        if (track->used && !track->inbound && track->expired &&
            !track->cancelled &&
            track->request.request_id == request->request_id &&
            work_same_action_binding(&track->request, request))
            return true;
    }
    return false;
}

static void work_remove_queued_action(struct vcs_zcode_work_node *node,
                                      const uint8_t action_root[32])
{
    size_t kept = 0;
    for (size_t i = 0; i < node->request_count; i++) {
        size_t src = (node->request_pos + i) %
                     VCS_ZCODE_WORK_NODE_MAX_REQUESTS;
        if (memcmp(node->requests[src].request.action_root,
                   action_root, 32) == 0)
            continue;
        size_t dst = (node->request_pos + kept) %
                     VCS_ZCODE_WORK_NODE_MAX_REQUESTS;
        if (dst != src) node->requests[dst] = node->requests[src];
        kept++;
    }
    node->request_count = kept;
}

enum vcs_zcode_work_node_result vcs_zcode_work_node_submit(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request, int64_t now)
{
    if (!node || !request || !vcs_zcode_work_request_verify(request))
        return VCS_ZCODE_WORK_NODE_MALFORMED;
    pthread_mutex_lock(&node->lock);
    int peer_at = work_peer_slot(node, peer);
    enum vcs_zcode_work_node_result result = VCS_ZCODE_WORK_NODE_OK;
    if (peer_at < 0) result = VCS_ZCODE_WORK_NODE_UNKNOWN_PEER;
    else if (!node->peers[peer_at].has_capability ||
             now >= node->peers[peer_at].capability.expires_unix)
        result = VCS_ZCODE_WORK_NODE_CAPABILITY_STALE;
    struct work_track *existing = peer_at >= 0
        ? work_find_track(node, peer, request->request_id, false) : NULL;
    bool capacity_retry = existing && existing->finished &&
        existing->admission_disposition == VCS_ZCODE_WORK_ADMISSION_BUSY &&
        node->peers[peer_at].capability.expires_unix >
            existing->worker_capability_expires;
    bool expired_cross_peer_retry = !existing && peer_at >= 0 &&
        work_has_expired_outbound_binding(node, request);
    if (result == VCS_ZCODE_WORK_NODE_OK && !existing) {
        bool allowed;
        if (expired_cross_peer_retry) {
            /* The old peer's signed lease is over.  A different peer still
             * enforces its own live capacity on receipt, so stale signed
             * zero headroom must not prevent sending this exact immutable
             * retry forever.  All other signed limits remain mandatory. */
            allowed = work_capability_matches(
                &node->peers[peer_at].capability, request, now);
        } else {
            struct vcs_zcode_work_capability_v1 effective =
                work_effective_capability(node, peer_at);
            allowed = work_capability_allows(&effective, request, now);
        }
        if (!allowed)
            result = VCS_ZCODE_WORK_NODE_CAPABILITY_MISMATCH;
    }
    else if (result == VCS_ZCODE_WORK_NODE_OK && capacity_retry) {
        struct vcs_zcode_work_capability_v1 effective =
            work_effective_capability(node, peer_at);
        if (!work_capability_allows(&effective, request, now))
            result = VCS_ZCODE_WORK_NODE_CAPABILITY_MISMATCH;
    }
    else if (result == VCS_ZCODE_WORK_NODE_OK)
        result = VCS_ZCODE_WORK_NODE_REPLAY;
    struct work_track *track = result == VCS_ZCODE_WORK_NODE_OK
        ? (capacity_retry ? existing : work_add_track(node)) : NULL;
    if (result == VCS_ZCODE_WORK_NODE_OK && !track)
        result = VCS_ZCODE_WORK_NODE_FULL;
    if (result == VCS_ZCODE_WORK_NODE_OK) {
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_REQUEST, .body.request = *request,
        };
        if (!work_queue_frame(node, peer, &message))
            result = VCS_ZCODE_WORK_NODE_FULL;
        else {
            memset(track, 0, sizeof(*track));
            track->used = true; track->peer = peer; track->request = *request;
            memcpy(track->worker_signer,
                   node->peers[peer_at].capability.signer_pubkey, 32);
            track->worker_capability_expires =
                node->peers[peer_at].capability.expires_unix;
        }
    }
    pthread_mutex_unlock(&node->lock);
    return result;
}

enum vcs_zcode_work_node_result vcs_zcode_work_node_cancel(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_cancel_v1 *cancel)
{
    if (!node || !cancel || !vcs_zcode_work_cancel_verify(cancel))
        return VCS_ZCODE_WORK_NODE_MALFORMED;
    pthread_mutex_lock(&node->lock);
    struct work_track *track = work_find_track(node, peer, cancel->request_id,
                                                false);
    enum vcs_zcode_work_node_result result = VCS_ZCODE_WORK_NODE_OK;
    if (!track) result = VCS_ZCODE_WORK_NODE_UNREQUESTED;
    else if (track->cancelled || track->finished)
        result = VCS_ZCODE_WORK_NODE_REPLAY;
    else if (memcmp(track->request.task_root, cancel->task_root, 32) != 0 ||
             memcmp(track->request.requester_pubkey,
                    cancel->requester_pubkey, 32) != 0)
        result = VCS_ZCODE_WORK_NODE_BINDING;
    if (result == VCS_ZCODE_WORK_NODE_OK) {
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_CANCEL, .body.cancel = *cancel,
        };
        if (!work_queue_frame(node, peer, &message))
            result = VCS_ZCODE_WORK_NODE_FULL;
        else {
            track->cancelled = true;
        }
    }
    pthread_mutex_unlock(&node->lock);
    return result;
}

enum vcs_zcode_work_node_result vcs_zcode_work_node_publish_result(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_result_v1 *result_row)
{
    if (!node || !result_row) return VCS_ZCODE_WORK_NODE_MALFORMED;
    pthread_mutex_lock(&node->lock);
    struct work_track *track = work_find_track(
        node, peer, result_row->request_id, true);
    enum vcs_zcode_work_node_result result = VCS_ZCODE_WORK_NODE_OK;
    if (!node->has_local_capability)
        result = VCS_ZCODE_WORK_NODE_NOT_LOCAL_WORKER;
    else if (!track) result = VCS_ZCODE_WORK_NODE_UNREQUESTED;
    else if (track->expired)
        result = VCS_ZCODE_WORK_NODE_LEASE_EXPIRED;
    else if (track->finished)
        result = VCS_ZCODE_WORK_NODE_REPLAY;
    else if (track->worker_slot >=
                 sizeof(node->slots) / sizeof(node->slots[0]) ||
             !node->slots[track->worker_slot].used ||
             node->slots[track->worker_slot].generation !=
                 track->lease_generation)
        result = VCS_ZCODE_WORK_NODE_LEASE_EXPIRED;
    else if (!vcs_zcode_work_result_verify(
                 &track->request, result_row,
                 node->local_capability.signer_pubkey))
        result = VCS_ZCODE_WORK_NODE_BINDING;
    if (result == VCS_ZCODE_WORK_NODE_OK) {
        size_t recipients = 0;
        for (size_t i = 0;
             i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++) {
            const struct work_track *candidate = &node->tracks[i];
            if (candidate->used && candidate->inbound &&
                candidate->worker_slot == track->worker_slot &&
                !candidate->finished && !candidate->cancelled &&
                !candidate->expired)
                recipients++;
        }
        if (recipients == 0)
            result = VCS_ZCODE_WORK_NODE_REPLAY;
        else if (node->outbound_count + recipients >
                 VCS_ZCODE_WORK_NODE_MAX_OUTBOUND)
            result = VCS_ZCODE_WORK_NODE_FULL;
        else for (size_t i = 0;
                  i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++) {
            struct work_track *recipient = &node->tracks[i];
            if (!recipient->used || !recipient->inbound ||
                recipient->worker_slot != track->worker_slot ||
                recipient->finished || recipient->cancelled ||
                recipient->expired)
                continue;
            struct vcs_zcode_work_swarm_message message = {
                .type = VCS_ZCODE_WORK_SWARM_RESULT,
                .body.result = *result_row,
            };
            message.body.result.request_id = recipient->request.request_id;
            if (!vcs_zcode_work_result_verify(
                    &recipient->request, &message.body.result,
                    node->local_capability.signer_pubkey) ||
                !work_queue_frame(node, recipient->peer, &message)) {
                result = VCS_ZCODE_WORK_NODE_BINDING;
                break;
            }
            recipient->finished = true;
            recipient->has_result = true;
            recipient->result = message.body.result;
            recipient->result_last_queued = 0;
        }
        if (result == VCS_ZCODE_WORK_NODE_OK)
            memset(&node->slots[track->worker_slot], 0,
                   sizeof(node->slots[track->worker_slot]));
    }
    pthread_mutex_unlock(&node->lock);
    return result;
}

size_t vcs_zcode_work_node_requeue_results(
    struct vcs_zcode_work_node *node, int64_t now)
{
    if (!node || now < 0) return 0;
    pthread_mutex_lock(&node->lock);
    size_t queued = 0;
    for (size_t i = 0;
         i < sizeof(node->tracks) / sizeof(node->tracks[0]); i++) {
        struct work_track *track = &node->tracks[i];
        if (!track->used || !track->inbound || !track->finished ||
            !track->has_result || track->cancelled ||
            now >= track->request.deadline_unix)
            continue;
        /* The initial publish already queued one frame. Stamp it without
         * creating an immediate duplicate, then retry every five seconds.
         * A missing session does not consume the retry interval. */
        if (track->result_last_queued == 0) {
            track->result_last_queued = now;
            continue;
        }
        if (now - track->result_last_queued < 5 ||
            work_peer_slot(node, track->peer) < 0)
            continue;
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_RESULT,
            .body.result = track->result,
        };
        if (!work_queue_frame(node, track->peer, &message)) continue;
        track->result_last_queued = now;
        queued++;
    }
    pthread_mutex_unlock(&node->lock);
    return queued;
}

enum vcs_zcode_work_node_result vcs_zcode_work_node_publish_progress(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_progress_v1 *progress)
{
    if (!node || !progress) return VCS_ZCODE_WORK_NODE_MALFORMED;
    pthread_mutex_lock(&node->lock);
    struct work_track *track = work_find_track(
        node, peer, progress->request_id, true);
    enum vcs_zcode_work_node_result result = VCS_ZCODE_WORK_NODE_OK;
    if (!node->has_local_capability)
        result = VCS_ZCODE_WORK_NODE_NOT_LOCAL_WORKER;
    else if (!track) result = VCS_ZCODE_WORK_NODE_UNREQUESTED;
    else if (track->expired)
        result = VCS_ZCODE_WORK_NODE_LEASE_EXPIRED;
    else if (track->finished || track->cancelled)
        result = VCS_ZCODE_WORK_NODE_REPLAY;
    else if (!vcs_zcode_work_progress_verify_for_request(
                 &track->request, progress,
                 node->local_capability.signer_pubkey))
        result = VCS_ZCODE_WORK_NODE_BINDING;
    else if (progress->stage <= track->progress_stage)
        result = VCS_ZCODE_WORK_NODE_REPLAY;
    else if (progress->stage != track->progress_stage + 1u)
        result = VCS_ZCODE_WORK_NODE_BINDING;
    if (result == VCS_ZCODE_WORK_NODE_OK) {
        struct vcs_zcode_work_swarm_message message = {
            .type = VCS_ZCODE_WORK_SWARM_PROGRESS,
            .body.progress = *progress,
        };
        if (!work_queue_frame(node, peer, &message))
            result = VCS_ZCODE_WORK_NODE_FULL;
        else
            track->progress_stage = progress->stage;
    }
    pthread_mutex_unlock(&node->lock);
    return result;
}

static enum vcs_zcode_work_node_result work_handle_capability(
    struct vcs_zcode_work_node *node, int peer_at,
    const struct vcs_zcode_work_capability_v1 *capability, int64_t now)
{
    if (capability->expires_unix <= now)
        return VCS_ZCODE_WORK_NODE_CAPABILITY_STALE;
    bool newer = !node->peers[peer_at].has_capability ||
        capability->expires_unix >
            node->peers[peer_at].capability.expires_unix;
    node->peers[peer_at].capability = *capability;
    node->peers[peer_at].has_capability = true;
    /* Only a strictly newer signed capability supersedes an earlier signed
     * BUSY fact.  Replaying the pre-BUSY advertisement after reconnect must
     * not make the same occupied worker eligible again.  Keep the canonical
     * advertisement unchanged; busy_observed is requester-local projection. */
    if (newer) node->peers[peer_at].busy_observed = false;
    return VCS_ZCODE_WORK_NODE_OK;
}

static enum vcs_zcode_work_node_result work_handle_request(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_request_v1 *request, int64_t now)
{
    if (!node->has_local_capability || !node->has_local_signer)
        return VCS_ZCODE_WORK_NODE_NOT_LOCAL_WORKER;
    if (!work_capability_matches(&node->local_capability, request, now) ||
        (node->local_capability.confinement &
         VCS_ZCODE_WORK_CONFINEMENT_V1_MASK) !=
            VCS_ZCODE_WORK_CONFINEMENT_V1_MASK) {
        return work_queue_admission(
            node, peer, request, VCS_ZCODE_WORK_ADMISSION_REFUSED,
            VCS_ZCODE_WORK_ADMISSION_REASON_POLICY, UINT16_MAX, 0, 0)
                ? VCS_ZCODE_WORK_NODE_OK : VCS_ZCODE_WORK_NODE_FULL;
    }

    struct work_track *existing = work_find_track(
        node, peer, request->request_id, true);
    if (existing) {
        uint8_t disposition = existing->expired
            ? VCS_ZCODE_WORK_ADMISSION_REFUSED
            : existing->admission_disposition;
        uint8_t reason = existing->expired
            ? VCS_ZCODE_WORK_ADMISSION_REASON_CAPACITY
            : VCS_ZCODE_WORK_ADMISSION_REASON_NONE;
        uint16_t slot = existing->expired ? UINT16_MAX
                                           : existing->worker_slot;
        uint64_t generation = existing->expired ? 0
                                                 : existing->lease_generation;
        int64_t deadline = existing->expired ? 0
            : node->slots[existing->worker_slot].deadline_unix;
        return work_queue_admission(node, peer, request, disposition, reason,
                                    slot, generation, deadline)
                ? VCS_ZCODE_WORK_NODE_OK : VCS_ZCODE_WORK_NODE_FULL;
    }

    int action_slot = work_find_action_slot(node, request->action_root);
    if (action_slot >= 0 &&
        !work_same_action_binding(&node->slots[action_slot].binding, request)) {
        return work_queue_admission(
            node, peer, request, VCS_ZCODE_WORK_ADMISSION_REFUSED,
            VCS_ZCODE_WORK_ADMISSION_REASON_BINDING, UINT16_MAX, 0, 0)
                ? VCS_ZCODE_WORK_NODE_OK : VCS_ZCODE_WORK_NODE_FULL;
    }

    bool attached = action_slot >= 0;
    if (!attached) action_slot = work_find_free_slot(node);
    if (action_slot < 0) {
        return work_queue_admission(
            node, peer, request, VCS_ZCODE_WORK_ADMISSION_BUSY,
            VCS_ZCODE_WORK_ADMISSION_REASON_NO_SLOT, UINT16_MAX, 0, 0)
                ? VCS_ZCODE_WORK_NODE_OK : VCS_ZCODE_WORK_NODE_FULL;
    }
    if (node->request_count >= VCS_ZCODE_WORK_NODE_MAX_REQUESTS)
        return work_queue_admission(
            node, peer, request, VCS_ZCODE_WORK_ADMISSION_REFUSED,
            VCS_ZCODE_WORK_ADMISSION_REASON_CAPACITY, UINT16_MAX, 0, 0)
                ? VCS_ZCODE_WORK_NODE_OK : VCS_ZCODE_WORK_NODE_FULL;

    struct work_track *track = work_add_track(node);
    if (!track)
        return work_queue_admission(
            node, peer, request, VCS_ZCODE_WORK_ADMISSION_REFUSED,
            VCS_ZCODE_WORK_ADMISSION_REASON_CAPACITY, UINT16_MAX, 0, 0)
                ? VCS_ZCODE_WORK_NODE_OK : VCS_ZCODE_WORK_NODE_FULL;
    struct work_slot *slot = &node->slots[action_slot];
    if (!attached) {
        node->next_lease_generation++;
        if (node->next_lease_generation == 0) node->next_lease_generation++;
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        slot->generation = node->next_lease_generation;
        slot->deadline_unix = request->deadline_unix;
        slot->binding = *request;
    }
    uint8_t disposition = attached ? VCS_ZCODE_WORK_ADMISSION_ATTACHED
                                   : VCS_ZCODE_WORK_ADMISSION_GRANTED;
    if (!work_queue_admission(node, peer, request, disposition,
                              VCS_ZCODE_WORK_ADMISSION_REASON_NONE,
                              (uint16_t)action_slot, slot->generation,
                              slot->deadline_unix)) {
        if (!attached) memset(slot, 0, sizeof(*slot));
        return VCS_ZCODE_WORK_NODE_FULL;
    }
    memset(track, 0, sizeof(*track));
    track->used = true;
    track->inbound = true;
    track->peer = peer;
    track->request = *request;
    track->worker_slot = (uint16_t)action_slot;
    track->lease_generation = slot->generation;
    track->admission_disposition = disposition;
    /* Every requester receives its own canonical context/running projection.
     * The downstream build_fabric_plan/submit boundary is idempotent on the
     * exact action root, so ATTACHED creates no second physical execution. */
    size_t event = (node->request_pos + node->request_count) %
                   VCS_ZCODE_WORK_NODE_MAX_REQUESTS;
    node->requests[event].peer = peer;
    node->requests[event].request = *request;
    node->request_count++;
    return VCS_ZCODE_WORK_NODE_OK;
}

static enum vcs_zcode_work_node_result work_handle_cancel(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const struct vcs_zcode_work_cancel_v1 *cancel)
{
    struct work_track *track = work_find_track(node, peer, cancel->request_id,
                                                true);
    if (!track) return VCS_ZCODE_WORK_NODE_UNREQUESTED;
    if (track->cancelled || track->finished)
        return VCS_ZCODE_WORK_NODE_REPLAY;
    if (memcmp(track->request.task_root, cancel->task_root, 32) != 0 ||
        memcmp(track->request.requester_pubkey,
               cancel->requester_pubkey, 32) != 0)
        return VCS_ZCODE_WORK_NODE_BINDING;
    track->cancelled = true;
    uint16_t worker_slot = track->worker_slot;
    if (!work_slot_has_active_track(node, worker_slot)) {
        if (node->cancel_count >= VCS_ZCODE_WORK_NODE_MAX_REQUESTS) {
            track->cancelled = false;
            return VCS_ZCODE_WORK_NODE_FULL;
        }
        size_t event = (node->cancel_pos + node->cancel_count) %
                       VCS_ZCODE_WORK_NODE_MAX_REQUESTS;
        node->cancels[event].peer = peer;
        node->cancels[event].cancel = *cancel;
        node->cancel_count++;
        work_remove_queued_action(node, track->request.action_root);
        if (worker_slot < sizeof(node->slots) / sizeof(node->slots[0]))
            memset(&node->slots[worker_slot], 0,
                   sizeof(node->slots[worker_slot]));
    }
    return VCS_ZCODE_WORK_NODE_OK;
}

static enum vcs_zcode_work_node_result work_handle_result(
    struct vcs_zcode_work_node *node, int peer_at, uint64_t peer,
    const struct vcs_zcode_work_result_v1 *result_row, int64_t now)
{
    struct work_track *track = work_find_track(
        node, peer, result_row->request_id, false);
    if (!track) return VCS_ZCODE_WORK_NODE_UNREQUESTED;
    if (track->expired || now >= track->request.deadline_unix)
        return VCS_ZCODE_WORK_NODE_LEASE_EXPIRED;
    if (track->finished || track->cancelled) {
        if (track->finished && !track->cancelled && track->has_result &&
            vcs_zcode_work_result_verify(
                &track->request, result_row,
                node->peers[peer_at].capability.signer_pubkey) &&
            work_same_result(&track->result, result_row))
            return VCS_ZCODE_WORK_NODE_OK;
        return VCS_ZCODE_WORK_NODE_REPLAY;
    }
    if (!node->peers[peer_at].has_capability ||
        now >= node->peers[peer_at].capability.expires_unix)
        return VCS_ZCODE_WORK_NODE_CAPABILITY_STALE;
    if (!vcs_zcode_work_result_verify(
            &track->request, result_row,
            node->peers[peer_at].capability.signer_pubkey))
        return VCS_ZCODE_WORK_NODE_BINDING;
    if (node->result_count >= VCS_ZCODE_WORK_NODE_MAX_RESULTS)
        return VCS_ZCODE_WORK_NODE_FULL;
    size_t slot = (node->result_pos + node->result_count) %
                  VCS_ZCODE_WORK_NODE_MAX_RESULTS;
    node->results[slot].peer = peer;
    node->results[slot].result = *result_row;
    node->result_count++;
    track->finished = true;
    track->has_result = true;
    track->result = *result_row;
    return VCS_ZCODE_WORK_NODE_OK;
}

static enum vcs_zcode_work_node_result work_handle_admission(
    struct vcs_zcode_work_node *node, int peer_at, uint64_t peer,
    const struct vcs_zcode_work_admission_v1 *admission)
{
    struct work_track *track = work_find_track(
        node, peer, admission->request_id, false);
    if (!track) return VCS_ZCODE_WORK_NODE_UNREQUESTED;
    if (!node->peers[peer_at].has_capability)
        return VCS_ZCODE_WORK_NODE_CAPABILITY_STALE;
    if (!vcs_zcode_work_admission_verify_for_request(
            &track->request, admission,
            node->peers[peer_at].capability.signer_pubkey))
        return VCS_ZCODE_WORK_NODE_BINDING;
    if (track->admission_disposition != 0) {
        return track->admission_disposition == admission->disposition &&
               track->worker_slot == admission->slot &&
               track->lease_generation == admission->lease_generation
            ? VCS_ZCODE_WORK_NODE_OK : VCS_ZCODE_WORK_NODE_BINDING;
    }
    if (node->admission_count >= VCS_ZCODE_WORK_NODE_MAX_RESULTS)
        return VCS_ZCODE_WORK_NODE_FULL;
    size_t event = (node->admission_pos + node->admission_count) %
                   VCS_ZCODE_WORK_NODE_MAX_RESULTS;
    node->admissions[event].peer = peer;
    node->admissions[event].admission = *admission;
    node->admission_count++;
    track->admission_disposition = admission->disposition;
    track->worker_slot = admission->slot;
    track->lease_generation = admission->lease_generation;
    if (admission->disposition == VCS_ZCODE_WORK_ADMISSION_BUSY)
        node->peers[peer_at].busy_observed = true;
    if (admission->disposition == VCS_ZCODE_WORK_ADMISSION_BUSY ||
        admission->disposition == VCS_ZCODE_WORK_ADMISSION_REFUSED)
        track->finished = true;
    return VCS_ZCODE_WORK_NODE_OK;
}

static enum vcs_zcode_work_node_result work_handle_progress(
    struct vcs_zcode_work_node *node, int peer_at, uint64_t peer,
    const struct vcs_zcode_work_progress_v1 *progress, int64_t now)
{
    struct work_track *track = work_find_track(
        node, peer, progress->request_id, false);
    if (!track) return VCS_ZCODE_WORK_NODE_UNREQUESTED;
    if (now >= track->request.deadline_unix)
        return VCS_ZCODE_WORK_NODE_LEASE_EXPIRED;
    if (track->finished || track->cancelled)
        return VCS_ZCODE_WORK_NODE_REPLAY;
    if (!node->peers[peer_at].has_capability ||
        now >= node->peers[peer_at].capability.expires_unix)
        return VCS_ZCODE_WORK_NODE_CAPABILITY_STALE;
    if (!vcs_zcode_work_progress_verify_for_request(
            &track->request, progress,
            node->peers[peer_at].capability.signer_pubkey))
        return VCS_ZCODE_WORK_NODE_BINDING;
    if (progress->stage <= track->progress_stage)
        return VCS_ZCODE_WORK_NODE_REPLAY;
    if (progress->stage != track->progress_stage + 1u)
        return VCS_ZCODE_WORK_NODE_BINDING;
    if (node->progress_count >= VCS_ZCODE_WORK_NODE_MAX_RESULTS)
        return VCS_ZCODE_WORK_NODE_FULL;
    size_t slot = (node->progress_pos + node->progress_count) %
                  VCS_ZCODE_WORK_NODE_MAX_RESULTS;
    node->progresses[slot].peer = peer;
    node->progresses[slot].progress = *progress;
    node->progress_count++;
    track->progress_stage = progress->stage;
    return VCS_ZCODE_WORK_NODE_OK;
}

enum vcs_zcode_work_node_result vcs_zcode_work_node_handle_frame(
    struct vcs_zcode_work_node *node, uint64_t peer,
    const uint8_t *wire, size_t wire_len, int64_t now)
{
    if (!node || !wire || peer == 0 || now < 0)
        return VCS_ZCODE_WORK_NODE_MALFORMED;
    struct vcs_zcode_work_swarm_message message;
    if (!vcs_zcode_work_swarm_parse(wire, wire_len, &message))
        return VCS_ZCODE_WORK_NODE_MALFORMED;
    pthread_mutex_lock(&node->lock);
    int peer_at = work_peer_slot(node, peer);
    enum vcs_zcode_work_node_result result = VCS_ZCODE_WORK_NODE_OK;
    if (peer_at < 0) {
        result = VCS_ZCODE_WORK_NODE_UNKNOWN_PEER;
    } else if (message.type == VCS_ZCODE_WORK_SWARM_CAPABILITY) {
        result = work_handle_capability(node, peer_at,
                                        &message.body.capability, now);
    } else if (message.type == VCS_ZCODE_WORK_SWARM_REQUEST) {
        result = work_handle_request(node, peer, &message.body.request, now);
    } else if (message.type == VCS_ZCODE_WORK_SWARM_CANCEL) {
        result = work_handle_cancel(node, peer, &message.body.cancel);
    } else if (message.type == VCS_ZCODE_WORK_SWARM_RESULT) {
        result = work_handle_result(node, peer_at, peer,
                                    &message.body.result, now);
    } else if (message.type == VCS_ZCODE_WORK_SWARM_PROGRESS) {
        result = work_handle_progress(node, peer_at, peer,
                                      &message.body.progress, now);
    } else if (message.type == VCS_ZCODE_WORK_SWARM_ADMISSION) {
        result = work_handle_admission(node, peer_at, peer,
                                       &message.body.admission);
    } else {
        result = VCS_ZCODE_WORK_NODE_MALFORMED;
    }
    pthread_mutex_unlock(&node->lock);
    return result;
}

bool vcs_zcode_work_node_next_outbound(
    struct vcs_zcode_work_node *node, uint64_t peer_filter,
    uint64_t *peer_out, uint8_t out[VCS_ZCODE_WORK_SWARM_MAX_WIRE_BYTES],
    size_t *out_len)
{
    if (!node || !peer_out || !out || !out_len) return false;
    *peer_out = 0; *out_len = 0;
    pthread_mutex_lock(&node->lock);
    size_t found = node->outbound_count;
    for (size_t i = 0; i < node->outbound_count; i++) {
        size_t at = (node->outbound_pos + i) % VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
        if (!peer_filter || node->outbound[at].peer == peer_filter) {
            found = i; break;
        }
    }
    if (found == node->outbound_count) {
        pthread_mutex_unlock(&node->lock); return false;
    }
    size_t at = (node->outbound_pos + found) % VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
    struct work_frame selected = node->outbound[at];
    for (size_t i = found; i + 1u < node->outbound_count; i++) {
        size_t dst = (node->outbound_pos + i) % VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
        size_t src = (node->outbound_pos + i + 1u) % VCS_ZCODE_WORK_NODE_MAX_OUTBOUND;
        node->outbound[dst] = node->outbound[src];
    }
    node->outbound_count--;
    memcpy(out, selected.bytes, selected.len);
    *peer_out = selected.peer; *out_len = selected.len;
    pthread_mutex_unlock(&node->lock);
    return true;
}

#define WORK_DRAIN(name, field, type, max_count) \
bool name(struct vcs_zcode_work_node *node, uint64_t *peer_out, type *out) \
{ \
    if (!node || !peer_out || !out) return false; \
    pthread_mutex_lock(&node->lock); \
    if (node->field##_count == 0) { \
        pthread_mutex_unlock(&node->lock); return false; \
    } \
    *peer_out = node->field##s[node->field##_pos].peer; \
    *out = node->field##s[node->field##_pos].field; \
    node->field##_pos = (node->field##_pos + 1u) % (max_count); \
    node->field##_count--; \
    pthread_mutex_unlock(&node->lock); \
    return true; \
}

WORK_DRAIN(vcs_zcode_work_node_next_request, request,
           struct vcs_zcode_work_request_v1, VCS_ZCODE_WORK_NODE_MAX_REQUESTS)
WORK_DRAIN(vcs_zcode_work_node_next_cancel, cancel,
           struct vcs_zcode_work_cancel_v1, VCS_ZCODE_WORK_NODE_MAX_REQUESTS)
WORK_DRAIN(vcs_zcode_work_node_next_result, result,
           struct vcs_zcode_work_result_v1, VCS_ZCODE_WORK_NODE_MAX_RESULTS)
WORK_DRAIN(vcs_zcode_work_node_next_admission, admission,
           struct vcs_zcode_work_admission_v1,
           VCS_ZCODE_WORK_NODE_MAX_RESULTS)
bool vcs_zcode_work_node_next_progress(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_progress_v1 *out)
{
    if (!node || !peer_out || !out) return false;
    pthread_mutex_lock(&node->lock);
    if (node->progress_count == 0) {
        pthread_mutex_unlock(&node->lock);
        return false;
    }
    *peer_out = node->progresses[node->progress_pos].peer;
    *out = node->progresses[node->progress_pos].progress;
    node->progress_pos = (node->progress_pos + 1u) %
                         VCS_ZCODE_WORK_NODE_MAX_RESULTS;
    node->progress_count--;
    pthread_mutex_unlock(&node->lock);
    return true;
}

bool vcs_zcode_work_node_peek_request(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_request_v1 *out)
{
    if (!node || !peer_out || !out) return false;
    pthread_mutex_lock(&node->lock);
    bool present = node->request_count > 0;
    if (present) {
        *peer_out = node->requests[node->request_pos].peer;
        *out = node->requests[node->request_pos].request;
    }
    pthread_mutex_unlock(&node->lock);
    return present;
}

size_t vcs_zcode_work_node_inbound_requests(
    struct vcs_zcode_work_node *node, uint64_t *peers,
    struct vcs_zcode_work_request_v1 *requests, size_t max)
{
    if (!node || !peers || !requests || max == 0) return 0;
    pthread_mutex_lock(&node->lock);
    size_t count = 0;
    for (size_t i = 0;
         i < sizeof(node->tracks) / sizeof(node->tracks[0]) && count < max;
         i++) {
        const struct work_track *track = &node->tracks[i];
        if (!track->used || !track->inbound || track->finished ||
            track->cancelled)
            continue;
        peers[count] = track->peer;
        requests[count] = track->request;
        count++;
    }
    pthread_mutex_unlock(&node->lock);
    return count;
}

bool vcs_zcode_work_node_inbound_request(
    struct vcs_zcode_work_node *node, uint64_t peer, uint64_t request_id,
    struct vcs_zcode_work_request_v1 *out, bool *cancelled)
{
    if (!node || !out || peer == 0 || request_id == 0) return false;
    pthread_mutex_lock(&node->lock);
    struct work_track *track = work_find_track(node, peer, request_id, true);
    bool present = track != NULL;
    if (present) {
        *out = track->request;
        if (cancelled) *cancelled = track->cancelled;
    }
    pthread_mutex_unlock(&node->lock);
    return present;
}

bool vcs_zcode_work_node_outbound_request(
    struct vcs_zcode_work_node *node, uint64_t peer, uint64_t request_id,
    struct vcs_zcode_work_request_v1 *out)
{
    if (!node || !out || peer == 0 || request_id == 0) return false;
    pthread_mutex_lock(&node->lock);
    struct work_track *track = work_find_track(node, peer, request_id, false);
    bool present = track != NULL;
    if (present) *out = track->request;
    pthread_mutex_unlock(&node->lock);
    return present;
}

bool vcs_zcode_work_node_peek_result(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_result_v1 *out)
{
    if (!node || !peer_out || !out) return false;
    pthread_mutex_lock(&node->lock);
    bool present = node->result_count > 0;
    if (present) {
        *peer_out = node->results[node->result_pos].peer;
        *out = node->results[node->result_pos].result;
    }
    pthread_mutex_unlock(&node->lock);
    return present;
}

bool vcs_zcode_work_node_peek_progress(
    struct vcs_zcode_work_node *node, uint64_t *peer_out,
    struct vcs_zcode_work_progress_v1 *out)
{
    if (!node || !peer_out || !out) return false;
    pthread_mutex_lock(&node->lock);
    bool present = node->progress_count > 0;
    if (present) {
        *peer_out = node->progresses[node->progress_pos].peer;
        *out = node->progresses[node->progress_pos].progress;
    }
    pthread_mutex_unlock(&node->lock);
    return present;
}
