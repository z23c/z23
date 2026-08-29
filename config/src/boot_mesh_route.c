/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Bounded direct route acquisition without endpoint trust. */

#include "config/boot_mesh_route.h"

#include "config/boot_internal.h"
#include "config/boot_zcode_dht_reachability.h"
#include "config/db_service.h"
#include "models/mesh_pairing.h"
#include "net/connman.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "services/subordinate_work_admission.h"
#include "util/log_macros.h"
#include "util/sync.h"

#include <stdatomic.h>
#include <string.h>

#define ROUTE_BACKOFF_BASE_MS UINT64_C(1000)

struct mesh_route_slot {
    bool used;
    bool terminal;
    enum boot_mesh_route_result terminal_result;
    char pairing_id[65];
    struct net_address endpoint;
    uint64_t deadline_ms;
    uint64_t next_attempt_ms;
    uint8_t attempts;
};

static zcl_mutex_t g_route_lock;
static _Atomic int g_route_lock_state;
static struct mesh_route_slot g_routes[BOOT_MESH_ROUTE_MAX];

static void route_lock(void)
{
    if (atomic_load_explicit(&g_route_lock_state, memory_order_acquire) != 2) {
        int expected = 0;
        if (atomic_compare_exchange_strong_explicit(
                &g_route_lock_state, &expected, 1, memory_order_acq_rel,
                memory_order_acquire)) {
            zcl_mutex_init(&g_route_lock);
            atomic_store_explicit(&g_route_lock_state, 2,
                                  memory_order_release);
        } else {
            while (atomic_load_explicit(&g_route_lock_state,
                                        memory_order_acquire) != 2)
                ;
        }
    }
    zcl_mutex_lock(&g_route_lock);
}

const char *boot_mesh_route_result_string(enum boot_mesh_route_result result)
{
    switch (result) {
    case BOOT_MESH_ROUTE_ACQUIRED: return "acquired";
    case BOOT_MESH_ROUTE_PENDING: return "pending";
    case BOOT_MESH_ROUTE_RESOURCE_DEFERRED: return "resource_deferred";
    case BOOT_MESH_ROUTE_NO_ENDPOINT: return "no_endpoint";
    case BOOT_MESH_ROUTE_AMBIGUOUS_ENDPOINT: return "ambiguous_endpoint";
    case BOOT_MESH_ROUTE_BUSY: return "busy";
    case BOOT_MESH_ROUTE_IDENTITY_MISMATCH: return "identity_mismatch";
    case BOOT_MESH_ROUTE_DOWNGRADE: return "plaintext_downgrade";
    case BOOT_MESH_ROUTE_EXHAUSTED: return "exhausted";
    case BOOT_MESH_ROUTE_UNAVAILABLE: return "unavailable";
    }
    return "unavailable";
}

static struct mesh_route_slot *route_slot(const char *pairing_id,
                                          const struct net_address *endpoint,
                                          uint64_t now_ms)
{
    struct mesh_route_slot *free_slot = NULL;
    for (size_t i = 0; i < BOOT_MESH_ROUTE_MAX; i++) {
        struct mesh_route_slot *slot = &g_routes[i];
        if (slot->used && strcmp(slot->pairing_id, pairing_id) == 0) {
            if (slot->terminal && now_ms >= slot->deadline_ms) {
                memset(slot, 0, sizeof(*slot));
                free_slot = slot;
                break;
            }
            if (!net_service_eq(&slot->endpoint.svc, &endpoint->svc)) {
                memset(slot, 0, sizeof(*slot));
                free_slot = slot;
                break;
            }
            return slot;
        }
        if (slot->used && now_ms >= slot->deadline_ms) {
            memset(slot, 0, sizeof(*slot));
            if (!free_slot)
                free_slot = slot;
            continue;
        }
        if (!slot->used && !free_slot)
            free_slot = slot;
    }
    if (!free_slot)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->used = true;
    memcpy(free_slot->pairing_id, pairing_id, 65);
    free_slot->endpoint = *endpoint;
    free_slot->deadline_ms = now_ms + BOOT_MESH_ROUTE_LIFETIME_MS;
    return free_slot;
}

static enum boot_mesh_route_result route_step_locked(
    struct mesh_route_slot *slot, enum boot_mesh_route_observation observation,
    bool resource_admitted, uint64_t now_ms, struct connman *connman)
{
    if (!slot || !connman)
        return BOOT_MESH_ROUTE_UNAVAILABLE;
    if (slot->terminal)
        return slot->terminal_result;
    if (observation == BOOT_MESH_ROUTE_OBS_MATCHED_NOISE) {
        memset(slot, 0, sizeof(*slot));
        return BOOT_MESH_ROUTE_ACQUIRED;
    }
    if (observation == BOOT_MESH_ROUTE_OBS_WRONG_NOISE ||
        observation == BOOT_MESH_ROUTE_OBS_PLAINTEXT) {
        slot->terminal = true;
        slot->terminal_result =
            observation == BOOT_MESH_ROUTE_OBS_WRONG_NOISE
                ? BOOT_MESH_ROUTE_IDENTITY_MISMATCH
                : BOOT_MESH_ROUTE_DOWNGRADE;
        slot->deadline_ms = now_ms + BOOT_MESH_ROUTE_TERMINAL_RETENTION_MS;
        return slot->terminal_result;
    }
    if (observation == BOOT_MESH_ROUTE_OBS_CONNECTING)
        return BOOT_MESH_ROUTE_PENDING;
    if (now_ms >= slot->deadline_ms) {
        slot->terminal = true;
        slot->terminal_result = BOOT_MESH_ROUTE_EXHAUSTED;
        slot->deadline_ms = now_ms + BOOT_MESH_ROUTE_TERMINAL_RETENTION_MS;
        return slot->terminal_result;
    }
    if (slot->attempts >= BOOT_MESH_ROUTE_MAX_ATTEMPTS)
        return BOOT_MESH_ROUTE_PENDING;
    if (now_ms < slot->next_attempt_ms)
        return BOOT_MESH_ROUTE_PENDING;
    if (!resource_admitted)
        return BOOT_MESH_ROUTE_RESOURCE_DEFERRED;

    struct net_address endpoint = slot->endpoint;
    endpoint.nServices |= NODE_NOISE_TRANSPORT;
    if (!connman_queue_dht_hint(connman, &endpoint))
        return BOOT_MESH_ROUTE_RESOURCE_DEFERRED;
    slot->attempts++;
    uint64_t delay = ROUTE_BACKOFF_BASE_MS << (slot->attempts - 1u);
    slot->next_attempt_ms = now_ms + delay;
    return BOOT_MESH_ROUTE_PENDING;
}

static enum boot_mesh_route_observation route_observe_peer(
    struct net_manager *manager, const struct net_address *endpoint,
    const uint8_t expected_static[32], struct p2p_node **matched_out,
    struct noise_transport_snapshot *session_out)
{
    struct p2p_node *peers[CONNMAN_DHT_HINT_MAX];
    size_t count = 0;
    zcl_mutex_lock(&manager->cs_nodes);
    for (size_t i = 0; i < manager->num_nodes && count < CONNMAN_DHT_HINT_MAX;
         i++) {
        struct p2p_node *peer = manager->nodes[i];
        if (!peer || peer->inbound || peer->disconnect ||
            !net_service_eq(&peer->addr.svc, &endpoint->svc))
            continue;
        peers[count++] = peer;
        p2p_node_add_ref(peer);
    }
    zcl_mutex_unlock(&manager->cs_nodes);

    enum boot_mesh_route_observation observed = BOOT_MESH_ROUTE_OBS_NONE;
    struct p2p_node *matched = NULL;
    for (size_t i = 0; i < count; i++) {
        struct p2p_node *peer = peers[i];
        struct noise_transport_snapshot snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        if (peer->transport &&
            noise_transport_snapshot(peer->transport, &snapshot) &&
            snapshot.established) {
            if (memcmp(snapshot.remote_static, expected_static, 32) == 0 &&
                !matched) {
                matched = peer;
                *session_out = snapshot;
                observed = BOOT_MESH_ROUTE_OBS_MATCHED_NOISE;
                continue;
            }
            if (!matched)
                observed = BOOT_MESH_ROUTE_OBS_WRONG_NOISE;
            (void)p2p_node_request_disconnect(
                peer, P2P_DISCONNECT_APPLICATION,
                P2P_DISCONNECT_SOURCE_APPLICATION,
                peer->endpoint_generation);
        } else if (atomic_load_explicit(&peer->state, memory_order_acquire) >=
                       PEER_HANDSHAKE_COMPLETE) {
            if (!matched)
                observed = BOOT_MESH_ROUTE_OBS_PLAINTEXT;
            (void)p2p_node_request_disconnect(
                peer, P2P_DISCONNECT_APPLICATION,
                P2P_DISCONNECT_SOURCE_APPLICATION, peer->endpoint_generation);
        } else if (observed == BOOT_MESH_ROUTE_OBS_NONE) {
            observed = BOOT_MESH_ROUTE_OBS_CONNECTING;
        }
    }
    for (size_t i = 0; i < count; i++)
        if (peers[i] != matched)
            p2p_node_release(peers[i]);
    *matched_out = matched;
    return observed;
}

static bool route_resources_admit(struct boot_svc_ctx *svc)
{
    struct node_db *ndb = boot_node_db(svc);
    struct db_service *dbsvc = boot_db_service(svc);
    if (!ndb || !dbsvc)
        return false;
    struct subordinate_work_facts facts;
    struct zcl_result observed = subordinate_work_admission_observe(
        boot_running(svc), db_service_is_started(dbsvc), ndb, &facts);
    return observed.ok && subordinate_work_admission_decide(&facts) ==
                              SUBORDINATE_WORK_ADMIT;
}

enum boot_mesh_route_result boot_mesh_route_acquire(
    struct boot_svc_ctx *svc, const struct db_mesh_pairing *pairing,
    uint64_t wall_unix, uint64_t monotonic_ms, struct p2p_node **peer_out,
    struct noise_transport_snapshot *session_out)
{
    if (peer_out)
        *peer_out = NULL;
    if (!svc || !svc->connman || !svc->msg_processor ||
        !svc->msg_processor->net_mgr || !pairing || !peer_out || !session_out ||
        wall_unix == 0 || monotonic_ms == 0)
        return BOOT_MESH_ROUTE_UNAVAILABLE;

    struct net_address endpoint;
    struct vcs_zcode_dht_time now = {
        .wall_unix = wall_unix,
        .monotonic_s = monotonic_ms / 1000u,
    };
    if (!boot_zcode_dht_reachability_refresh(pairing->network_genesis, now))
        return BOOT_MESH_ROUTE_UNAVAILABLE;
    enum boot_zcode_dht_direct_lookup lookup =
        boot_zcode_dht_reachability_direct_for_master(
            pairing->peer_master_pubkey, &endpoint);
    if (lookup == BOOT_ZCODE_DHT_DIRECT_MISSING)
        return BOOT_MESH_ROUTE_NO_ENDPOINT;
    if (lookup == BOOT_ZCODE_DHT_DIRECT_AMBIGUOUS)
        return BOOT_MESH_ROUTE_AMBIGUOUS_ENDPOINT;

    struct p2p_node *matched = NULL;
    enum boot_mesh_route_observation observation = route_observe_peer(
        svc->msg_processor->net_mgr, &endpoint, pairing->peer_noise_pubkey,
        &matched, session_out);
    bool resources_admitted = observation != BOOT_MESH_ROUTE_OBS_NONE ||
                              route_resources_admit(svc);

    route_lock();
    struct mesh_route_slot *slot = route_slot(pairing->pairing_id, &endpoint,
                                               monotonic_ms);
    enum boot_mesh_route_result result = slot
        ? route_step_locked(slot, observation, resources_admitted,
                            monotonic_ms, svc->connman)
        : BOOT_MESH_ROUTE_BUSY;
    zcl_mutex_unlock(&g_route_lock);
    if (result == BOOT_MESH_ROUTE_ACQUIRED) {
        *peer_out = matched;
    } else if (matched) {
        p2p_node_release(matched);
    }
    return result;
}

void boot_mesh_route_reset(void)
{
    route_lock();
    memset(g_routes, 0, sizeof(g_routes));
    zcl_mutex_unlock(&g_route_lock);
}

#ifdef ZCL_TESTING
enum boot_mesh_route_result boot_mesh_route_test_step(
    const char pairing_id[65], const struct net_address *endpoint,
    enum boot_mesh_route_observation observation, bool resource_admitted,
    uint64_t monotonic_ms, struct connman *connman, uint8_t *attempts_out)
{
    if (!pairing_id || strlen(pairing_id) != 64 || !endpoint || !connman ||
        !attempts_out || monotonic_ms == 0)
        return BOOT_MESH_ROUTE_UNAVAILABLE;
    route_lock();
    struct mesh_route_slot *slot = route_slot(pairing_id, endpoint,
                                               monotonic_ms);
    enum boot_mesh_route_result result = slot
        ? route_step_locked(slot, observation, resource_admitted, monotonic_ms,
                            connman)
        : BOOT_MESH_ROUTE_BUSY;
    *attempts_out = slot && slot->used ? slot->attempts : 0;
    zcl_mutex_unlock(&g_route_lock);
    return result;
}
#endif
