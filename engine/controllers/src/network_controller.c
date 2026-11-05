/* Copyright 2026 Rhett Creighton - Apache License 2.0. Distributed under the
 * MIT software license; see COPYING or opensource.org/license/mit. */

#include "platform/time_compat.h"
#include "platform/socket_compat.h"
#include "config/state_offer_service.h"
#include "config/state_offer_store.h"
#include "controllers/agent_controller.h"
#include "controllers/agent_security_posture.h"
#include "controllers/fleet_status_controller.h"
#include "controllers/network_controller.h"
#include "controllers/node_binary_identity_json.h"
#include "util/log_macros.h"
#include "controllers/strong_params.h"
#include "core/utiltime.h"
#include "event/event.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "base/cleanse.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "net/connman.h"
#include "net/noise_transport.h"
#include "net/v2_identity.h"
#include "net/fast_sync.h"
#include "net/netbase.h"
#include "net/peer_identity.h"
#include "net/peer_lifecycle.h"
#include "net/protocol.h"
#include "net/tor_integration.h"
#include "net/version.h"
#include "services/beta6_bootstrap.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct network_context {
    _Atomic(struct connman *) connman;
    struct msg_processor *msg_processor;
    const char *datadir;
    const char *load_snapshot_at_own_height;
};

#define BOOTSTRAP_STATUS_SCHEMA "zcl.bootstrap_status.v1"
#define BOOTSTRAP_STATUS_SCHEMA_VERSION 1
#define ZCLASSICD_BETA6_LABEL "zclassicd v2.1.2-beta6"

struct network_counts {
    size_t connections;
    int inbound;
    int outbound;
    int handshaked;
    int inbound_handshaked;
    int outbound_handshaked;
    int legacy_compatible;
    int zcl23;
    int zcl23_connections;
    int zcl23_duplicate_connections;
    int zcl23_self_connections;
    size_t listen_socket_count;
    uint64_t local_services;
    size_t addrman_entries;
    struct addrman_bucket_stats addrman_stats;
};

static struct network_context g_network_ctx = {0};

static struct network_context *network_ctx(void)
{
    return &g_network_ctx;
}

void rpc_net_set_connman(struct connman *cm)
{
    atomic_store_explicit(&network_ctx()->connman, cm, memory_order_release);
}

struct connman *rpc_net_get_connman(void)
{
    return atomic_load_explicit(&network_ctx()->connman,
                                memory_order_acquire);
}

void rpc_net_set_msg_processor(struct msg_processor *mp)
{
    network_ctx()->msg_processor = mp;
}

struct msg_processor *rpc_net_get_msg_processor(void)
{
    return network_ctx()->msg_processor;
}

void rpc_net_set_boot_context(const char *datadir,
                              const char *load_snapshot_at_own_height)
{
    struct network_context *ctx = network_ctx();
    ctx->datadir = datadir;
    ctx->load_snapshot_at_own_height = load_snapshot_at_own_height;
}

static void network_counts_collect(struct connman *cm,
                                   struct network_counts *out)
{
    struct zcl_peer_host_set zcl23_hosts;

    memset(out, 0, sizeof(*out));
    if (!cm)
        return;
    zcl_peer_host_set_init(&zcl23_hosts);

    out->connections = connman_get_node_count(cm);
    out->listen_socket_count = cm->manager.num_listen_sockets;
    out->local_services = cm->manager.local_services;

    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        struct p2p_node *node = cm->manager.nodes[i];
        if (!node || node->disconnect)
            continue;
        if (node->inbound)
            out->inbound++;
        else
            out->outbound++;
        if (node->state >= PEER_HANDSHAKE_COMPLETE) {
            bool is_legacy = false, is_z23 = false;
            out->handshaked++;
            if (node->inbound)
                out->inbound_handshaked++;
            else
                out->outbound_handshaked++;
            msg_version_classify_peer(node->sub_ver, node->services,
                                      &is_legacy, &is_z23);
            if (is_legacy)
                out->legacy_compatible++;
            if (is_z23) {
                if (msg_version_peer_uses_external_host(node))
                    out->zcl23_self_connections++;
                else {
                    out->zcl23_connections++;
                    if (zcl_peer_host_set_add_peer(&zcl23_hosts, node))
                        out->zcl23++;
                    else
                        out->zcl23_duplicate_connections++;
                }
            }
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);

    zcl_mutex_lock(&cm->manager.addrman.cs);
    out->addrman_entries = addrman_size(&cm->manager.addrman);
    addrman_get_bucket_stats(&cm->manager.addrman,
                             &out->addrman_stats);
    zcl_mutex_unlock(&cm->manager.addrman.cs);
}

static void json_push_str_array(struct json_value *obj, const char *key,
                                const char *const *items, size_t count)
{
    struct json_value arr = {0};
    json_set_array(&arr);
    for (size_t i = 0; i < count; i++) {
        struct json_value item = {0};
        json_set_str(&item, items[i]);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(obj, key, &arr);
    json_free(&arr);
}

static void json_push_localaddresses(struct json_value *obj,
                                     const char *key,
                                     const char *ext_ip,
                                     uint16_t ext_port)
{
    struct json_value localaddrs = {0};
    json_set_array(&localaddrs);
    if (ext_ip && ext_ip[0] != '\0' && ext_port != 0) {
        struct json_value entry = {0};
        json_set_object(&entry);
        json_push_kv_str(&entry, "address", ext_ip);
        json_push_kv_int(&entry, "port", ext_port);
        json_push_kv_int(&entry, "score", 1);
        json_push_back(&localaddrs, &entry);
        json_free(&entry);
    }
    json_push_kv(obj, key, &localaddrs);
    json_free(&localaddrs);
}

static void json_push_string_item(struct json_value *arr, const char *value)
{
    struct json_value item = {0};
    json_set_str(&item, value);
    json_push_back(arr, &item);
    json_free(&item);
}

static bool addnode_is_connected(struct connman *cm, int addnode_index)
{
    bool connected = false;

    if (!cm || addnode_index < 0 || addnode_index >= cm->num_addnodes)
        return false;

    zcl_mutex_lock(&cm->manager.cs_nodes);
    for (size_t i = 0; i < cm->manager.num_nodes; i++) {
        const struct p2p_node *node = cm->manager.nodes[i];
        if (!node || node->disconnect)
            continue;
        if (net_addr_eq(&node->addr.svc.addr,
                        &cm->addnodes[addnode_index].svc.addr) &&
            node->addr.svc.port == cm->addnodes[addnode_index].svc.port) {
            connected = true;
            break;
        }
    }
    zcl_mutex_unlock(&cm->manager.cs_nodes);

    return connected;
}

static void push_addnode_status(struct json_value *result,
                                struct connman *cm)
{
    struct json_value arr = {0};
    int64_t now = (int64_t)platform_time_wall_time_t();

    json_set_array(&arr);
    if (cm) {
        for (int i = 0; i < cm->num_addnodes; i++) {
            struct json_value entry = {0};
            char addr[NET_SERVICE_STR_MAX + 1];
            int64_t last = cm->addnode_last_attempt[i];
            int64_t elapsed = last > 0 && now >= last ? now - last : -1;
            int64_t remaining = 0;

            if (cm->addnode_backoff_sec[i] > 0 && elapsed >= 0 &&
                elapsed < cm->addnode_backoff_sec[i])
                remaining = cm->addnode_backoff_sec[i] - elapsed;

            net_service_to_string(&cm->addnodes[i].svc, addr, sizeof(addr));
            json_set_object(&entry);
            json_push_kv_int(&entry, "index", i);
            json_push_kv_str(&entry, "address", addr);
            json_push_kv_bool(&entry, "connected",
                              addnode_is_connected(cm, i));
            json_push_kv_int(&entry, "last_attempt", last);
            json_push_kv_int(&entry, "seconds_since_attempt", elapsed);
            json_push_kv_int(&entry, "backoff_seconds",
                             cm->addnode_backoff_sec[i]);
            json_push_kv_int(&entry, "backoff_remaining_seconds",
                             remaining);
            json_push_kv_int(&entry, "tcp_failures",
                             cm->addnode_tcp_failures[i]);
            json_push_kv_int(&entry, "protocol_failures",
                             cm->addnode_protocol_failures[i]);
            /* Retired addnodes remain recorded but undialed until a manual
             * success or operator re-add revives them. */
            json_push_kv_bool(&entry, "retired", cm->addnode_retired[i]);
            json_push_kv_int(&entry, "retired_at",
                             cm->addnode_retired_at[i]);
            json_push_back(&arr, &entry);
            json_free(&entry);
        }
    }

    json_push_kv(result, "addnode_status", &arr);
    json_free(&arr);
}

static bool rpc_getnetworkinfo(const struct json_value *params, bool help,
                                 struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getnetworkinfo\n"
        "Returns an object containing various state info "
        "regarding P2P networking.");

    json_set_object(result);
    node_binary_identity_push_json(result, NULL, true);

    struct network_context *ctx = network_ctx();
    struct network_counts counts;
    network_counts_collect(ctx->connman, &counts);
    bool local_zcl23 = (counts.local_services & NODE_ZCL23) != 0;
    int64_t zcl23_nodes_seen = counts.zcl23 + (local_zcl23 ? 1 : 0);
    json_push_kv_int(result, "connections", (int64_t)counts.connections);
    json_push_kv_int(result, "localservices",
                     (int64_t)counts.local_services);
    json_push_kv_int(result, "advertised_services",
                     (int64_t)counts.local_services);

    struct json_value networks = {0};
    json_set_array(&networks);
    json_push_kv(result, "networks", &networks);
    json_free(&networks);

    json_push_kv_real(result, "relayfee", 0.00000100);

    char ext_ip[PLATFORM_IPV4_ADDRESS_TEXT_SIZE] = {0};
    uint16_t ext_port = 0;
    msg_version_get_external_ip(ext_ip, sizeof(ext_ip), &ext_port);
    json_push_localaddresses(result, "localaddresses", ext_ip, ext_port);

    json_push_kv_int(result, "inbound_connections", counts.inbound);
    json_push_kv_int(result, "outbound_connections", counts.outbound);
    json_push_kv_int(result, "handshaked_connections", counts.handshaked);
    json_push_kv_int(result, "inbound_handshaked_connections",
                     counts.inbound_handshaked);
    json_push_kv_int(result, "outbound_handshaked_connections",
                     counts.outbound_handshaked);
    json_push_kv_int(result, "legacy_compatible_peers",
                     counts.legacy_compatible);
    json_push_kv_int(result, "legacy_magicbean_peers",
                     counts.legacy_compatible);
    json_push_kv_int(result, "magicbean_peers", counts.legacy_compatible);
    json_push_kv_int(result, "zclassic23_peers", counts.zcl23);
    json_push_kv_int(result, "zclassic_c23_peers", counts.zcl23);
    json_push_kv_int(result, "zclassic23_peer_connections",
                     counts.zcl23_connections);
    json_push_kv_int(result,
                     "zclassic23_duplicate_connections_excluded",
                     counts.zcl23_duplicate_connections);
    json_push_kv_int(result, "zclassic23_self_connections_excluded",
                     counts.zcl23_self_connections);
    json_push_kv_bool(result, "local_zclassic23_node_included", local_zcl23);
    json_push_kv_int(result, "zclassic23_nodes_seen", zcl23_nodes_seen);
    json_push_kv_bool(result, "zclassic23_two_node_floor_met",
                      zcl23_nodes_seen >= 2);
    json_push_kv_int(result, "listen_socket_count",
                     (int64_t)counts.listen_socket_count);
    json_push_kv_bool(result, "listening", counts.listen_socket_count > 0);
    json_push_kv_bool(result, "externalip_configured", ext_port != 0);
    json_push_kv_bool(result, "inbound_handshake_seen",
                      counts.inbound_handshaked > 0);
    json_push_kv_bool(result, "remote_handshake_seen",
                      counts.handshaked > 0);
    push_addnode_status(result, ctx->connman);

    struct json_value life = {0};
    peer_lifecycle_summary_json(&life);
    json_push_kv(result, "peer_lifecycle", &life);
    json_free(&life);

    return true;
}

/* The two facts a cold-start question turns on: can a stranger find a state source THROUGH this node
 * (are we appending a state offer to our handshakes), and has this node been
 * offered one (how many peers are advertising state to us, and how new).
 *
 * Deliberately separate from `beta6_snapshot_bootstrap`: NODE_BOOTSTRAP is
 * zclassicd beta6's service bit, advertised only when the opt-in beta6
 * snapshot server is armed, and it carries no port a stranger could dial for z23
 * state. The z23 state source is advertised by the zfileaddr message instead,
 * because a service bit carries no file-service port (net/protocol.h). */
static void network_push_state_source(struct json_value *result)
{
    struct state_offer_store_status st;
    state_offer_store_status_get(&st);

    struct json_value src = {0};
    json_set_object(&src);
    json_push_kv_str(&src, "schema", "zcl.bootstrap.state_source.v1");
    json_push_kv_str(&src, "advertised_by", "zfileaddr_state_offer");
    json_push_kv_bool(&src, "advertising_consensus_state_bundle",
                      state_offer_service_advertising());
    json_push_kv_int(&src, "candidate_source_peers",
                     (int64_t)st.peers_offering);
    json_push_kv_int(&src, "offers_seen", (int64_t)st.offers_seen);
    json_push_kv_int(&src, "newest_offered_height",
                     (int64_t)st.newest_height_seen);
    json_push_kv(result, "state_source", &src);
    json_free(&src);
}

/* NODE_BOOTSTRAP as a beta6 client sees it. Two independent ways this node can
 * be advertising it: the in-band seam, which puts the bit into the ORDINARY
 * P2P `version` (engine/services/src/beta6_bootstrap_inband.c — the production
 * path, because that is the only port a stock client dials), or the optional
 * side listener, whose own version message carries it
 * (engine/services/src/beta6_bootstrap_listen.c). */
static bool beta6_advertises_node_bootstrap(uint64_t local_services, bool in_band,
                                            bool listening)
{
    return (local_services & NODE_BOOTSTRAP) != 0 || in_band || listening;
}

/* Is this node actually answering beta6 clients? Either wire counts — in-band
 * on the ordinary P2P port (the production path) or the optional side listener
 * — and both still respect the security posture, which is what gates public
 * serving at all. The beta6 wire answers from an already-hashed snapshot, so
 * unlike the z23 paths it does not additionally require being at tip. */
static bool beta6_is_serving(bool in_band, bool listening, bool security_posture_ok)
{
    return (in_band || listening) && security_posture_ok;
}

/* The single named fact keeping this node from serving beta6 clients, in the
 * order an operator has to fix them; empty while it is serving.
 * `posture_blocker` is NULL when the security posture allows public serving. */
static const char *beta6_current_blocker(bool serving, const char *posture_blocker)
{
    if (serving)
        return "";
    if (posture_blocker)
        return posture_blocker;
    if (!beta6_bs_status().ok)
        return "beta6_bootstrap_source_not_configured";
    /* Armed, but nothing is answering: the in-band seam did not install and
     * no side listener was configured either. */
    return "beta6_bootstrap_serving_not_installed";
}

/* What this node would actually hand a beta6 client: which directory is armed
 * and what the cached manifest says it covers. Present (with an empty source
 * and -1 height) even when dormant, so an operator can tell "not configured"
 * from "configured and empty" without a second call. */
static void network_push_beta6_source(struct json_value *beta6)
{
    const struct beta6_bs_manifest *manifest = beta6_bs_manifest();
    /* Which wire is actually answering. `in_band` is the production path (the
     * node's own P2P port); `listen_port` is the optional side socket, 0 when
     * none was configured. */
    json_push_kv_bool(beta6, "in_band", beta6_bs_inband_status().ok);
    json_push_kv_int(beta6, "listen_port", (int64_t)beta6_bs_listen_port());
    json_push_kv_int(beta6, "manifest_version",
                     manifest ? (int64_t)manifest->version : 0);
    json_push_kv_int(beta6, "manifest_height",
                     manifest ? (int64_t)manifest->height : -1);
    json_push_kv_int(beta6, "manifest_files",
                     manifest ? (int64_t)manifest->file_count : 0);
    json_push_kv_int(beta6, "manifest_bytes",
                     manifest ? (int64_t)manifest->snapshot_bytes : 0);
}

/* The top-level readiness `blockers[]` array: every named fact currently
 * keeping this node from full P2P/beta6 readiness, in the order an operator
 * has to fix them. Split out of rpc_bootstrapstatus() so that function's own
 * branch count stays under its complexity pin as this list grows. */
static void network_push_bootstrap_blockers(struct json_value *result,
                                             bool has_connman, bool listening,
                                             bool node_network, bool protocol_ok,
                                             bool has_tip, bool security_posture_ok,
                                             const char *security_posture_status,
                                             bool node_bootstrap,
                                             bool beta6_params_served)
{
    struct json_value blockers = {0};
    json_set_array(&blockers);
    if (!has_connman)
        json_push_string_item(&blockers, "p2p_not_initialized");
    if (has_connman && !listening)
        json_push_string_item(&blockers, "not_listening");
    if (!node_network)
        json_push_string_item(&blockers, "NODE_NETWORK_not_advertised");
    if (!protocol_ok)
        json_push_string_item(&blockers, "protocol_below_min_peer_version");
    if (!has_tip)
        json_push_string_item(&blockers, "provable_tip_not_published");
    if (!security_posture_ok)
        json_push_string_item(&blockers,
                              security_posture_status && security_posture_status[0]
                                  ? security_posture_status
                                  : "security_posture_review_required");
    if (!node_bootstrap)
        json_push_string_item(&blockers, "beta6_NODE_BOOTSTRAP_not_advertised");
    if (!beta6_params_served)
        json_push_string_item(&blockers, "beta6_params_dir_not_configured");
    json_push_kv(result, "blockers", &blockers);
    json_free(&blockers);
}

/* The transport half of ordinary P2P bootstrap: a connman, a listen socket,
 * NODE_NETWORK, a new-enough protocol, and a published provable tip. */
static bool bootstrap_transport_ready(bool has_connman, bool listening,
                                      bool node_network, bool protocol_ok,
                                      bool has_tip)
{
    return has_connman && listening && node_network && protocol_ok && has_tip;
}

/* Ordinary P2P bootstrap is served only when the transport is ready and the
 * security posture allows public serving. */
static bool bootstrap_p2p_serving(bool transport_ready,
                                  bool security_posture_ok)
{
    return transport_ready && security_posture_ok;
}

/* zclassic23 fast sync is ordinary P2P serving with NODE_ZCL23 advertised. */
static bool bootstrap_zcl23_fast(bool p2p_serving, bool node_zcl23)
{
    return p2p_serving && node_zcl23;
}

/* bootstrapstatus `peers`, including the zclassic23 node-floor counts.
 * Split out of rpc_bootstrapstatus() so that function's own branch count
 * stays under its complexity pin. */
static void network_push_bootstrap_peers(struct json_value *result,
                                         const struct network_counts *counts,
                                         struct connman *cm,
                                         bool p2p_serving, bool node_zcl23)
{
    struct json_value peers = {0};
    json_set_object(&peers);
    json_push_kv_int(&peers, "connections", (int64_t)counts->connections);
    json_push_kv_int(&peers, "inbound_connections", counts->inbound);
    json_push_kv_int(&peers, "outbound_connections", counts->outbound);
    json_push_kv_int(&peers, "handshaked_connections", counts->handshaked);
    json_push_kv_int(&peers, "inbound_handshaked_connections",
                     counts->inbound_handshaked);
    json_push_kv_int(&peers, "outbound_handshaked_connections",
                     counts->outbound_handshaked);
    json_push_kv_int(&peers, "legacy_compatible_peers",
                     counts->legacy_compatible);
    json_push_kv_int(&peers, "zclassic23_peers", counts->zcl23);
    json_push_kv_int(&peers, "zclassic23_peer_connections",
                     counts->zcl23_connections);
    json_push_kv_int(&peers,
                     "zclassic23_duplicate_connections_excluded",
                     counts->zcl23_duplicate_connections);
    json_push_kv_int(&peers, "zclassic23_self_connections_excluded",
                     counts->zcl23_self_connections);
    network_push_verified_zclassic23_bootstrap_peers(&peers, cm);
    int64_t verified_zcl23_peers = json_get_int(json_get(&peers,
        "verified_zclassic23_bootstrap_peer_count"));
    bool local_verified_zcl23_bootstrap =
        bootstrap_zcl23_fast(p2p_serving, node_zcl23);
    json_push_kv_bool(&peers, "local_zclassic23_node_included", node_zcl23);
    json_push_kv_int(&peers, "zclassic23_nodes_seen",
                     counts->zcl23 + (node_zcl23 ? 1 : 0));
    json_push_kv_bool(&peers, "zclassic23_two_node_floor_met",
                      counts->zcl23 + (node_zcl23 ? 1 : 0) >= 2);
    json_push_kv_bool(&peers, "local_zclassic23_bootstrap_node_verified",
                      local_verified_zcl23_bootstrap);
    json_push_kv_int(&peers, "verified_zclassic23_bootstrap_nodes_seen",
                     verified_zcl23_peers +
                         (local_verified_zcl23_bootstrap ? 1 : 0));
    json_push_kv_bool(&peers, "verified_zclassic23_two_node_floor_met",
                      verified_zcl23_peers +
                          (local_verified_zcl23_bootstrap ? 1 : 0) >= 2);
    json_push_kv(result, "peers", &peers);
    json_free(&peers);
}

/* bootstrapstatus `warnings`: facts that do not block serving. Split out
 * of rpc_bootstrapstatus() so that function's own branch count stays under
 * its complexity pin. */
static void network_push_bootstrap_warnings(struct json_value *result,
                                            bool has_external_ip,
                                            uint16_t ext_port,
                                            bool addr_relay_ready)
{
    struct json_value warnings = {0};
    json_set_array(&warnings);
    if (!has_external_ip || ext_port == 0)
        json_push_string_item(&warnings, "externalip_not_configured");
    if (!addr_relay_ready)
        json_push_string_item(&warnings, "addrman_empty");
    json_push_kv(result, "warnings", &warnings);
    json_free(&warnings);
}

static bool rpc_bootstrapstatus(const struct json_value *params, bool help,
                                struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "bootstrapstatus\n"
        "Returns a versioned bootstrap-service contract: ordinary P2P "
        "bootstrap readiness plus zclassicd beta6 snapshot-bootstrap "
        "compatibility.");

    struct network_context *ctx = network_ctx();
    struct network_counts counts;
    network_counts_collect(ctx->connman, &counts);

    char ext_ip[PLATFORM_IPV4_ADDRESS_TEXT_SIZE] = {0};
    uint16_t ext_port = 0;
    bool has_external_ip =
        msg_version_get_external_ip(ext_ip, sizeof(ext_ip), &ext_port);
    int32_t advertised_height = reducer_frontier_external_tip_height();
    bool has_connman = ctx->connman != NULL;
    bool node_network = (counts.local_services & NODE_NETWORK) != 0;
    bool node_zcl23 = (counts.local_services & NODE_ZCL23) != 0;
    bool beta6_listening = beta6_bs_listen_status().ok;
    bool beta6_in_band = beta6_bs_inband_status().ok;
    bool node_bootstrap = beta6_advertises_node_bootstrap(counts.local_services,
                                                          beta6_in_band,
                                                          beta6_listening);
    bool protocol_ok = PROTOCOL_VERSION >= MIN_PEER_PROTO_VERSION;
    bool listening = counts.listen_socket_count > 0;
    bool has_tip = advertised_height > 0;
    bool transport_ready =
        bootstrap_transport_ready(has_connman, listening, node_network,
                                  protocol_ok, has_tip);
    struct agent_security_posture security_posture;
    agent_security_posture_collect(&security_posture, NULL);
    bool security_posture_ok =
        agent_security_posture_allows_public_serving(&security_posture);
    bool p2p_serving = bootstrap_p2p_serving(transport_ready,
                                             security_posture_ok);
    bool addr_relay_ready = counts.addrman_entries > 0;
    bool beta6_fast =
        beta6_is_serving(beta6_in_band, beta6_listening, security_posture_ok);
    bool zcl23_fast = bootstrap_zcl23_fast(p2p_serving, node_zcl23);

    json_set_object(result);
    json_push_kv_str(result, "schema", BOOTSTRAP_STATUS_SCHEMA);
    json_push_kv_int(result, "schema_version",
                     BOOTSTRAP_STATUS_SCHEMA_VERSION);
    json_push_kv_bool(result, "ok", p2p_serving);
    json_push_kv_bool(result, "transport_ready", transport_ready);
    json_push_kv_bool(result, "security_review_required",
                      security_posture.review_required);
    json_push_kv_bool(result, "security_posture_ok", security_posture_ok);
    json_push_kv_str(result, "security_posture_status",
                     security_posture.status);
    json_push_kv_str(result, "readiness",
                     network_bootstrap_readiness_label(p2p_serving,
                                                       addr_relay_ready));
    json_push_kv_str(result, "fresh_node_next_action",
                     network_bootstrap_next_action(p2p_serving, node_zcl23,
                                                   addr_relay_ready));
    json_push_kv_bool(result, "serving_p2p_bootstrap", p2p_serving);
    json_push_kv_bool(result, "serving_addr_bootstrap",
                      p2p_serving && addr_relay_ready);
    json_push_kv_bool(result, "serving_snapshot_bootstrap", beta6_fast);
    json_push_kv_bool(result, "zclassic23_fast_sync_compatible",
                      zcl23_fast);
    json_push_kv_bool(result, "zclassicd_beta6_p2p_compatible",
                      node_network && protocol_ok);
    json_push_kv_bool(result,
                      "zclassicd_beta6_fast_bootstrap_compatible",
                      beta6_fast);

    node_binary_identity_push_json(result, "binary", false);

    struct json_value p2p = {0};
    json_set_object(&p2p);
    json_push_kv_int(&p2p, "protocolversion", PROTOCOL_VERSION);
    json_push_kv_int(&p2p, "minimum_peer_protocol",
                     MIN_PEER_PROTO_VERSION);
    json_push_kv_int(&p2p, "advertised_services",
                     (int64_t)counts.local_services);
    json_push_kv_bool(&p2p, "node_network", node_network);
    json_push_kv_bool(&p2p, "node_zclassic23", node_zcl23);
    json_push_kv_bool(&p2p, "node_bootstrap", node_bootstrap);
    json_push_kv_bool(&p2p, "listening", listening);
    json_push_kv_int(&p2p, "listen_socket_count",
                     (int64_t)counts.listen_socket_count);
    json_push_kv_int(&p2p, "advertised_start_height",
                     advertised_height);
    json_push_kv_bool(&p2p, "externalip_configured",
                      has_external_ip && ext_port != 0);
    json_push_localaddresses(&p2p, "localaddresses", ext_ip, ext_port);
    json_push_kv(result, "p2p", &p2p);
    json_free(&p2p);

    network_push_bootstrap_peers(result, &counts, ctx->connman, p2p_serving,
                                 node_zcl23);

    struct json_value addrman = {0};
    json_set_object(&addrman);
    json_push_kv_int(&addrman, "entries",
                     (int64_t)counts.addrman_entries);
    json_push_kv_int(&addrman, "getaddr_max", MAX_ADDR_TO_SEND);
    json_push_kv_int(&addrman, "new_occupied",
                     counts.addrman_stats.new_occupied);
    json_push_kv_int(&addrman, "tried_occupied",
                     counts.addrman_stats.tried_occupied);
    json_push_kv_int(&addrman, "new_buckets_nonempty",
                     counts.addrman_stats.new_buckets_nonempty);
    json_push_kv_int(&addrman, "tried_buckets_nonempty",
                     counts.addrman_stats.tried_buckets_nonempty);
    json_push_kv_bool(&addrman, "addr_relay_ready", addr_relay_ready);
    json_push_kv(result, "addrman", &addrman);
    json_free(&addrman);

    network_push_zclassic23_bootstrap_contract(result, p2p_serving,
                                               addr_relay_ready, node_zcl23,
                                               ext_ip, ext_port);
    network_push_state_source(result);
    network_push_snapshot_loader_status(result, ctx ? ctx->datadir : "",
                                        ctx ? ctx->load_snapshot_at_own_height
                                            : "");

    static const char *const legacy_msgs[] = {
        "version", "verack", "sendheaders", "getheaders", "headers",
        "getblocks", "inv", "getdata", "block", "getaddr", "addr",
        "ping", "pong"
    };
    static const char *const beta6_msgs[] = {
        "getbsman", "bsman", "getbschk", "bschk",
        "getbspman", "bspman", "getbspchk", "bspchk"
    };

    struct json_value legacy = {0};
    json_set_object(&legacy);
    json_push_kv_str(&legacy, "schema", "zcl.bootstrap.p2p.v1");
    json_push_kv_str(&legacy, "target_client", ZCLASSICD_BETA6_LABEL);
    json_push_kv_str(&legacy, "required_service_bit", "NODE_NETWORK");
    json_push_kv_int(&legacy, "required_service_bit_value", NODE_NETWORK);
    json_push_kv_bool(&legacy, "serving", p2p_serving);
    json_push_kv_bool(&legacy, "addr_relay_ready",
                      p2p_serving && addr_relay_ready);
    json_push_str_array(&legacy, "messages", legacy_msgs,
                        sizeof(legacy_msgs) / sizeof(legacy_msgs[0]));
    json_push_kv(result, "legacy_p2p_bootstrap", &legacy);
    json_free(&legacy);

    struct json_value beta6 = {0};
    json_set_object(&beta6);
    json_push_kv_str(&beta6, "schema",
                     "zclassicd.bootstrap.snapshot.v3");
    json_push_kv_str(&beta6, "target_client", ZCLASSICD_BETA6_LABEL);
    json_push_kv_str(&beta6, "required_service_bit", "NODE_BOOTSTRAP");
    json_push_kv_int(&beta6, "required_service_bit_value",
                     NODE_BOOTSTRAP);
    json_push_kv_bool(&beta6, "advertised", node_bootstrap);
    json_push_kv_bool(&beta6, "serving", beta6_fast);
    json_push_kv_int(&beta6, "chunk_size_bytes", BETA6_BS_CHUNK_SIZE);
    bool beta6_params_served = beta6_bs_inband_params_status().ok;
    json_push_kv_bool(&beta6, "params_served", beta6_params_served);
    network_push_beta6_source(&beta6);
    json_push_kv_str(&beta6, "current_blocker",
                     beta6_current_blocker(beta6_fast,
                                           security_posture_ok
                                               ? NULL
                                               : security_posture.status));
    json_push_str_array(&beta6, "messages", beta6_msgs,
                        sizeof(beta6_msgs) / sizeof(beta6_msgs[0]));
    json_push_kv(result, "beta6_snapshot_bootstrap", &beta6);
    json_free(&beta6);

    network_push_bootstrap_blockers(result, has_connman, listening, node_network,
                                    protocol_ok, has_tip, security_posture_ok,
                                    security_posture.status, node_bootstrap,
                                    beta6_params_served);

    network_push_bootstrap_warnings(result, has_external_ip, ext_port,
                                    addr_relay_ready);

    return true;
}

bool network_bootstrap_status_json(struct json_value *out)
{
    if (!out)
        LOG_FAIL("network", "bootstrap status output is NULL");
    return rpc_bootstrapstatus(NULL, false, out);
}

const char *network_peer_transport_name(enum peer_transport_class cls)
{
    switch (cls) {
    case PEER_TRANSPORT_NOISE_XXHFS: return "noise_xxhfs";
    case PEER_TRANSPORT_HANDSHAKING: return "handshaking";
    case PEER_TRANSPORT_PLAINTEXT:   break;
    }
    return "plaintext";
}

/* Established means the hybrid suite: noise_transport.c drives only the
 * XXhfs pattern (driver_pattern() -> noise_pattern_xxhfs()), so there is no
 * classical-XX state to mislabel. An established transport whose locked
 * snapshot disagrees is reported as handshaking, never as secure. */
void network_peer_transport_inspect(struct p2p_node *node,
                                    struct peer_transport_info *info,
                                    struct json_value *dump)
{
    memset(info, 0, sizeof(*info));
    zcl_mutex_lock(&node->cs_recv);
    const struct noise_transport *t = node->transport;
    if (!t) {
        info->cls = PEER_TRANSPORT_PLAINTEXT;
    } else {
        info->cls = PEER_TRANSPORT_HANDSHAKING;
        struct noise_transport_snapshot snap = {0};
        uint8_t fp[32] = {0};
        if (t->state == NOISE_ESTABLISHED &&
            noise_transport_snapshot(t, &snap) && snap.established &&
            v2_identity_public_fingerprint(snap.remote_static, fp)) {
            info->cls = PEER_TRANSPORT_NOISE_XXHFS;
            zcl_hex_encode(fp, sizeof(fp), info->fingerprint_hex);
        }
        memory_cleanse(&snap, sizeof(snap));
        memory_cleanse(fp, sizeof(fp));
    }
    if (dump)
        noise_transport_dump_peer(dump, t);
    zcl_mutex_unlock(&node->cs_recv);
}

void network_peer_transport_push_json(struct json_value *obj,
                                      const struct peer_transport_info *info)
{
    json_push_kv_str(obj, "transport", network_peer_transport_name(info->cls));
    if (info->cls != PEER_TRANSPORT_NOISE_XXHFS)
        return;
    json_push_kv_str(obj, "noise_key_agreement", "x25519+mlkem768");
    /* The static identity key is classical X25519; only the session key
     * agreement is hybrid. Say so rather than imply a PQ identity. */
    json_push_kv_str(obj, "noise_peer_identity", "x25519");
    json_push_kv_str(obj, "noise_peer_fingerprint_sha3", info->fingerprint_hex);
}

static bool rpc_getpeerinfo(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getpeerinfo\n"
        "Returns data about each connected network node.");

    json_set_array(result);
    struct network_context *ctx = network_ctx();
    if (!ctx->connman) return true;

    struct tor_onion_port_map port_map;
    tor_integration_port_map_snapshot(&port_map);

    zcl_mutex_lock(&ctx->connman->manager.cs_nodes);
    for (size_t i = 0; i < ctx->connman->manager.num_nodes; i++) {
        struct p2p_node *node = ctx->connman->manager.nodes[i];
        struct json_value entry = {0};
        json_set_object(&entry);

        json_push_kv_int(&entry, "id", (int64_t)node->id);
        json_push_kv_str(&entry, "addr", node->addr_name);
        json_push_kv_str(&entry, "subver", node->clean_sub_ver);
        json_push_kv_int(&entry, "version", (int64_t)node->version);
        json_push_kv_bool(&entry, "inbound", node->inbound);
        json_push_kv_int(&entry, "startingheight",
                          (int64_t)node->starting_height);
        json_push_kv_int(&entry, "best_height",
                          (int64_t)atomic_load(&node->best_height));
        json_push_kv_int(&entry, "conntime", node->time_connected);
        json_push_kv_int(&entry, "lastsend", node->last_send);
        json_push_kv_int(&entry, "lastrecv", node->last_recv);
        json_push_kv_int(&entry, "bytessent", (int64_t)node->send_bytes);
        json_push_kv_int(&entry, "bytesrecv", (int64_t)node->recv_bytes);
        bool source_is_loopback = node->inbound && net_addr_is_operator_local(
            &node->addr.svc.addr);
        bool onion_ingress_candidate = source_is_loopback &&
            port_map.p2p_route_installed &&
            node->accepted_local_port == port_map.p2p_target_port;
        json_push_kv_int(&entry, "accepted_local_port", node->accepted_local_port);
        json_push_kv_bool(&entry, "source_is_loopback", source_is_loopback);
        json_push_kv_bool(&entry, "onion_ingress_candidate", onion_ingress_candidate);

        double ping_ms = (double)node->ping_usec_time / 1000000.0;
        json_push_kv_real(&entry, "pingtime", ping_ms);

        json_push_kv_str(&entry, "state",
                          peer_state_name(node->state));
        json_push_kv_int(&entry, "state_id", (int64_t)node->state);
        json_push_kv_int(&entry, "misbehavior",
                          (int64_t)node->misbehavior);
        json_push_kv_int(&entry, "blocks_received",
                          (int64_t)node->blocks_received);
        if (node->avg_latency_us > 0)
            json_push_kv_real(&entry, "avg_latency_ms",
                               (double)node->avg_latency_us / 1000.0);

        /* Read only what this peer published. Current peers expose a compact
         * source prefix; legacy peers may expose the full identity. Never
         * promote a prefix into source_id_sha256. Absence is a normal answer:
         * it is reported and never scored, gated, or acted on. */
        {
            char peer_source_id[ZCL_BUILD_IDENTITY_BUFSIZE];
            char peer_source_prefix[ZCL_BUILD_IDENTITY_PREFIX_BUFSIZE];
            bool source_id_known = msg_version_parse_build_identity(
                node->clean_sub_ver, peer_source_id, sizeof(peer_source_id));
            bool source_prefix_known = msg_version_parse_build_identity_prefix(
                node->clean_sub_ver, peer_source_prefix,
                sizeof(peer_source_prefix));
            json_push_kv_str(&entry, "source_id_sha256",
                             source_id_known ? peer_source_id : "unknown");
            json_push_kv_bool(&entry, "source_id_known", source_id_known);
            json_push_kv_str(&entry, "source_id_prefix",
                             source_prefix_known ? peer_source_prefix :
                                                   "unknown");
            json_push_kv_bool(&entry, "source_id_prefix_known",
                              source_prefix_known);
        }

        /* Keep classification here; full lifecycle stays in its dumpstate so
         * this bounded response can represent the whole peer list. */
        {
            bool is_mb = false, is_z23 = false;
            msg_version_classify_peer(node->sub_ver, node->services,
                                      &is_mb, &is_z23);
            json_push_kv_bool(&entry, "magicbean", is_mb);
            json_push_kv_bool(&entry, "zclassic23", is_z23);
            json_push_kv_bool(&entry, "zclassic_c23", is_z23);
        }

        {
            struct peer_transport_info tinfo;
            network_peer_transport_inspect(node, &tinfo, NULL);
            network_peer_transport_push_json(&entry, &tinfo);
        }

        json_push_back(result, &entry);
        json_free(&entry);
    }
    zcl_mutex_unlock(&ctx->connman->manager.cs_nodes);

    return true;
}

static bool rpc_getconnectioncount(const struct json_value *params, bool help,
                                     struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "getconnectioncount\n"
        "Returns the number of connections to other nodes.");

    struct network_context *ctx = network_ctx();
    size_t conns = ctx->connman ? connman_get_node_count(ctx->connman) : 0;
    json_set_int(result, (int64_t)conns);
    return true;
}

static bool rpc_peerincidents(const struct json_value *params, bool help,
                              struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "peerincidents\n"
        "Returns a bounded peer lifecycle incident view grouped by host.");

    if (!peer_lifecycle_incidents_json(result)) {
        json_set_str(result, "peer lifecycle incident view unavailable");
        return false;
    }
    agent_push_contract_identity_fields_json(result, "peerincidents");
    return true;
}

static bool rpc_ping_rpc(const struct json_value *params, bool help,
                           struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "ping\n"
        "Requests that a ping be sent to all other nodes.");

    struct network_context *ctx = network_ctx();
    if (ctx->connman) {
        zcl_mutex_lock(&ctx->connman->manager.cs_nodes);
        for (size_t i = 0; i < ctx->connman->manager.num_nodes; i++)
            ctx->connman->manager.nodes[i]->ping_queued = true;
        zcl_mutex_unlock(&ctx->connman->manager.cs_nodes);
    }

    json_set_null(result);
    return true;
}

/* ── Operator ban table: listbanned, setban, clearbanned ─────────────
 * Authority is addnode's: the RPC table grants no more and no less. Every
 * mutation goes through core's own ban functions, which write
 * <datadir>/banlist.dat at once whenever the manager has a datadir
 * (core/modules/net/src/net.c: ban_addr_ex, unban_addr, clear_banned). */

static struct net_manager *network_ban_manager(void)
{
    struct connman *cm = rpc_net_get_connman();
    return cm ? &cm->manager : NULL;
}

/* A ban is keyed by IP. Onion and DNS names are refused, never resolved. */
static bool network_ban_parse_ip(const struct net_manager *nm,
                                 const char *text, struct net_addr *out,
                                 struct json_value *result)
{
    if (net_name_is_onion(text)) {
        json_set_str(result, "setban requires a numeric IP address "
                             "(onion peers are not banned by address)");
        LOG_WARN("net", "setban: refused onion address (not banned by address)");
        return false;
    }
    struct net_service svc;
    if (!lookup_numeric(text, &svc, nm->default_port)) {
        LOG_WARN("net", "setban: refused a non-numeric address (DNS not resolved)");
        json_set_str(result, "setban requires a numeric IP address "
                             "(DNS names are not resolved)");
        return false;
    }
    *out = svc.addr;
    return true;
}

static void network_ban_push_entry(struct json_value *result,
                                   const struct ban_entry *ban)
{
    char address[NET_ADDR_STR_MAX + 1];
    net_addr_to_string(&ban->addr, address, sizeof(address));
    struct json_value entry = {0};
    json_set_object(&entry);
    json_push_kv_str(&entry, "address", address);
    json_push_kv_int(&entry, "banned_until", ban->ban_until);
    json_push_kv_str(&entry, "ban_reason", ban->reason);
    json_push_back(result, &entry);
    json_free(&entry);
}

/* Longest bantime setban accepts: ten years, in seconds. */
#define NETWORK_BAN_MAX_SECS (10LL * 365 * 24 * 3600)

/* Strict digits-only parse: no sign, no spaces, no trailing text. A value that
 * is not a whole number is refused rather than read as 0 (which would mean the
 * 24h default). The digit loop stops at the cap, so it cannot overflow. */
static bool network_ban_bantime_from_string(const char *text, int64_t *out,
                                            struct json_value *result)
{
    if (text[0] == '-') {
        LOG_WARN("net", "setban: refused a negative bantime");
        json_set_str(result, "setban bantime must not be negative");
        return false;
    }
    if (text[0] == '\0') {
        LOG_WARN("net", "setban: refused an empty bantime");
        json_set_str(result, "setban bantime must be a whole number of seconds");
        return false;
    }
    int64_t value = 0;
    for (const char *c = text; *c; c++) {
        if (*c < '0' || *c > '9') {
            LOG_WARN("net", "setban: refused a non-numeric bantime");
            json_set_str(result, "setban bantime must be a whole number of seconds");
            return false;
        }
        if (value > NETWORK_BAN_MAX_SECS / 10) {
            LOG_WARN("net", "setban: refused a bantime past the cap");
            json_set_str(result, "setban bantime is too large (at most 10 years)");
            return false;
        }
        value = value * 10 + (*c - '0');
    }
    *out = value;
    return true;
}

/* Reads the optional bantime (params[2]). A JSON integer is taken as is; the
 * range checks run afterwards in network_ban_check_bantime(). */
static bool network_ban_bantime_from_param(const struct json_value *params,
                                           int64_t *out,
                                           struct json_value *result)
{
    *out = 0;
    if (json_size(params) < 3)
        return true;
    const struct json_value *v = json_at(params, 2);
    if (v->type == JSON_NULL)
        return true;
    if (v->type == JSON_INT) {
        *out = json_get_int(v);
        return true;
    }
    if (v->type == JSON_STR)
        return network_ban_bantime_from_string(json_get_str(v), out, result);
    LOG_WARN("net", "setban: refused a bantime that is not a whole number");
    json_set_str(result, "setban bantime must be a whole number of seconds");
    return false;
}

/* Range: not negative, at most ten years, and not past the largest value that
 * GetTime() + offset can hold. */
static bool network_ban_check_bantime(int64_t bantime, struct json_value *result)
{
    if (bantime < 0) {
        LOG_WARN("net", "setban: refused a negative bantime");
        json_set_str(result, "setban bantime must not be negative");
        return false;
    }
    if (bantime > NETWORK_BAN_MAX_SECS) {
        LOG_WARN("net", "setban: refused a bantime past the cap");
        json_set_str(result, "setban bantime is too large (at most 10 years)");
        return false;
    }
    if (bantime > INT64_MAX - GetTime()) {
        LOG_WARN("net", "setban: refused a bantime that would overflow the clock");
        json_set_str(result, "setban bantime would overflow the clock");
        return false;
    }
    return true;
}

/* The same bytes core's is_banned() exempts (net.c, localhost is never banned),
 * so an add here would report success and ban nothing. */
static bool network_ban_is_loopback(const struct net_addr *a)
{
    static const uint8_t lo_prefix[13] = {
        0,0,0,0,0,0,0,0,0,0,0xff,0xff,127
    };
    return memcmp(a->ip, lo_prefix, sizeof lo_prefix) == 0;
}

/* ban_addr() may only mark the table dirty for a debounced write, and
 * unban_addr() ignores a failed write, so neither says whether banlist.dat
 * holds the change. Force one write here and report a failure: the change is
 * live in memory but would be lost on restart. A manager with no datadir
 * keeps bans in memory by design and has nothing to save. */
static bool network_ban_saved(struct net_manager *nm, const char *what,
                              const char *reply,
                              struct json_value *result)
{
    if (!nm->datadir || ban_db_write(nm, nm->datadir))
        return true;
    LOG_WARN("net", "setban: %s applied in memory but banlist.dat was not saved",
             what);
    json_set_str(result, reply);
    return false;
}

static bool network_ban_add(struct net_manager *nm, const struct net_addr *addr,
                            int64_t bantime, struct json_value *result)
{
    if (network_ban_is_loopback(addr)) {
        LOG_WARN("net", "setban: refused a loopback address (localhost is never banned)");
        json_set_str(result, "setban refuses a loopback address (localhost is never banned)");
        return false;
    }
    ban_addr(nm, addr, bantime, false);
    /* ban_addr() returns nothing; a refused insert (table full of manual
     * entries, or a failed grow) leaves the address unbanned, so check. */
    if (is_banned(nm, addr))
        return network_ban_saved(nm, "ban",
            "setban: the ban is active but not saved (banlist.dat could not be "
            "written), so it will not survive a restart", result);
    LOG_WARN("net", "setban: ban table is full of manual entries, add refused");
    json_set_str(result, "setban refused: the ban table is full of manual entries");
    return false;
}

static bool network_ban_remove(struct net_manager *nm, const struct net_addr *addr,
                               struct json_value *result)
{
    if (unban_addr(nm, addr))
        return network_ban_saved(nm, "unban",
            "setban: the ban is lifted but not saved (banlist.dat could not be "
            "written), so it will return after a restart", result);
    LOG_WARN("net", "setban: remove found no ban entry for the address");
    json_set_str(result, "setban entry not found");
    return false;
}

static bool rpc_listbanned(const struct json_value *params, bool help,
                           struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "listbanned\n"
        "Returns the IP addresses currently banned, with expiry and reason.");

    json_set_array(result);
    struct net_manager *nm = network_ban_manager();
    if (!nm) {
        LOG_WARN("net", "listbanned: P2P not initialized, reporting an empty list");
        return true;
    }

    /* Copy the rows under cs_banned, then release it before any JSON is built:
     * allocation and JSON work never run while peers wait on the ban lock. */
    struct ban_entry *rows = zcl_malloc(NET_BAN_TABLE_MAX * sizeof(*rows),
                                        "listbanned_rows");
    if (!rows) {
        LOG_WARN("net", "listbanned: could not allocate the ban copy");
        json_set_str(result, "listbanned: out of memory");
        return false;
    }
    zcl_mutex_lock(&nm->cs_banned);
    size_t n = nm->num_banned < NET_BAN_TABLE_MAX ? nm->num_banned
                                                  : NET_BAN_TABLE_MAX;
    if (n > 0)
        memcpy(rows, nm->banned, n * sizeof(*rows));
    zcl_mutex_unlock(&nm->cs_banned);

    int64_t now = GetTime();
    for (size_t i = 0; i < n; i++) {
        /* An expired row stays until the next lazy prune; it is not a live
         * ban (is_banned() ignores it too), so it is not reported. */
        if (now >= rows[i].ban_until)
            continue;
        network_ban_push_entry(result, &rows[i]);
    }
    free(rows);
    return true;
}

static bool rpc_setban(const struct json_value *params, bool help,
                       struct json_value *result)
{
    RPC_HELP(help, result,
        "setban \"ip\" \"add|remove\" ( bantime )\n"
        "Adds an IP address to the ban list, or lifts its ban. bantime is "
        "whole seconds from now (default 24h, at most 10 years) and applies "
        "to add only. add does not disconnect a peer that is already "
        "connected.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 2, 3);
    const char *ip = rpc_require_str(&p, 0, "ip");
    const char *cmd = rpc_require_str(&p, 1, "command");
    if (rpc_params_invalid(&p)) {
        LOG_WARN("net", "setban: refused a bad argument count or type");
        rpc_params_error(&p, result);
        return false;
    }

    struct net_manager *nm = network_ban_manager();
    if (!nm) {
        LOG_WARN("net", "setban: refused, P2P is not initialized");
        json_set_str(result, "P2P not initialized");
        return false;
    }
    bool is_add = strcmp(cmd, "add") == 0;
    if (!is_add && strcmp(cmd, "remove") != 0) {
        LOG_WARN("net", "setban: refused an unknown command");
        json_set_str(result, "setban command must be add or remove");
        return false;
    }
    int64_t bantime = 0;
    if (!network_ban_bantime_from_param(params, &bantime, result)) {
        LOG_WARN("net", "setban: refused the request (bantime)");
        return false;
    }
    if (!network_ban_check_bantime(bantime, result)) {
        LOG_WARN("net", "setban: refused the request (bantime range)");
        return false;
    }
    struct net_addr addr;
    if (!network_ban_parse_ip(nm, ip, &addr, result)) {
        LOG_WARN("net", "setban: refused the request (target)");
        return false;
    }

    bool done = is_add ? network_ban_add(nm, &addr, bantime, result)
                       : network_ban_remove(nm, &addr, result);
    if (!done)
        return false;
    json_set_null(result);
    return true;
}

static bool rpc_clearbanned(const struct json_value *params, bool help,
                            struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "clearbanned\n"
        "Clears every IP address from the ban list.");

    struct net_manager *nm = network_ban_manager();
    if (!nm) {
        LOG_WARN("net", "clearbanned: refused, P2P not initialized");
        json_set_str(result, "P2P not initialized");
        return false;
    }
    clear_banned(nm);
    json_set_null(result);
    return true;
}

void register_net_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "network", "getnetworkinfo",    rpc_getnetworkinfo,    true },
        { "network", "bootstrapstatus",   rpc_bootstrapstatus,   true },
        { "network", "onionstatus",       network_onion_status_rpc, true },
        { "network", "onionremotestatus", network_onion_remote_status_rpc, true },
        { "network", "fleetstatus",       fleet_status_rpc,      true },
        { "network", "getpeerinfo",       rpc_getpeerinfo,       true },
        { "network", "getconnectioncount", rpc_getconnectioncount, true },
        { "network", "peerincidents",     rpc_peerincidents,     true },
        { "network", "ping",              rpc_ping_rpc,          true },
        { "network", "addnode",           network_addnode_rpc,   true },
        { "network", "listbanned",        rpc_listbanned,        true },
        { "network", "setban",            rpc_setban,            true },
        { "network", "clearbanned",       rpc_clearbanned,       true },
    };

    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
