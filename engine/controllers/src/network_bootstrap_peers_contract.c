/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Live Z23 peer evidence for bootstrapstatus. This stays separate from
 * the generic network RPC controller so the first-call bootstrap contract can
 * grow without turning network_controller.c into a peer-reporting dump. */

#include "controllers/network_controller.h"

#include "json/json.h"
#include "net/connman.h"
#include "net/fast_sync.h"
#include "net/net.h"
#include "net/peer_identity.h"
#include "net/peer_lifecycle.h"
#include "net/protocol.h"
#include "net/version.h"
#include <string.h>

#define BOOTSTRAP_ZCL23_PEER_QUORUM_TARGET 2
#define BOOTSTRAP_ZCL23_PEER_LIST_LIMIT 8

static const char *bootstrap_zcl23_quorum_status(int64_t peers)
{
    if (peers >= BOOTSTRAP_ZCL23_PEER_QUORUM_TARGET)
        return "redundant";
    if (peers > 0)
        return "single_peer";
    return "missing";
}

static const char *node_bootstrap_readiness(const struct p2p_node *node)
{
    if (!node || node->disconnect)
        return "not_connected";
    if (node->state < PEER_HANDSHAKE_COMPLETE)
        return "handshake_incomplete";
    if ((node->services & NODE_NETWORK) == 0)
        return "missing_NODE_NETWORK";
    if (node->starting_height <= 0)
        return "missing_advertised_height";
    return "useful";
}

static bool node_is_zclassic23(const struct p2p_node *node)
{
    bool is_legacy = false, is_z23 = false;

    if (!node)
        return false;
    msg_version_classify_peer(node->sub_ver, node->services,
                              &is_legacy, &is_z23);
    return is_z23;
}

static bool node_is_verified_zclassic23_bootstrap(
    const struct p2p_node *node)
{
    return node_is_zclassic23(node) &&
           strcmp(node_bootstrap_readiness(node), "useful") == 0;
}

static bool bootstrap_peer_preferred(const struct p2p_node *candidate,
                                     const struct p2p_node *current)
{
    if (!candidate)
        return false;
    if (!current)
        return true;
    if (!candidate->inbound && current->inbound)
        return true;
    if (candidate->inbound != current->inbound)
        return false;
    return candidate->addr.svc.port == 8033 && current->addr.svc.port != 8033;
}

struct verified_zclassic23_bootstrap_scan {
    struct zcl_peer_host_set *verified_hosts;
    const struct p2p_node **representatives;
    bool *representative_fast_sync;
    int64_t *verified_count;
    int64_t *verified_connection_count;
    int64_t *duplicate_connections;
    int64_t *fast_sync_count;
    int64_t *fast_sync_connection_count;
    int64_t *self_excluded;
};

static void bootstrap_store_new_verified_zclassic23_host(
    struct verified_zclassic23_bootstrap_scan *scan,
    const struct p2p_node *node, const char *host,
    bool fast_sync_useful)
{
    if (zcl_peer_host_set_add_host(scan->verified_hosts, host)) {
        (*scan->verified_count)++;
        if (fast_sync_useful)
            (*scan->fast_sync_count)++;
        if (scan->verified_hosts->count > 0 &&
            scan->verified_hosts->count <= ZCL_PEER_HOST_SET_MAX) {
            size_t stored = scan->verified_hosts->count - 1;

            scan->representatives[stored] = node;
            scan->representative_fast_sync[stored] = fast_sync_useful;
        }
    }
}

static void bootstrap_update_duplicate_verified_zclassic23_host(
    struct verified_zclassic23_bootstrap_scan *scan,
    const struct p2p_node *node, int host_index,
    bool fast_sync_useful)
{
    (*scan->duplicate_connections)++;
    if (fast_sync_useful &&
        !scan->representative_fast_sync[host_index]) {
        scan->representative_fast_sync[host_index] = true;
        (*scan->fast_sync_count)++;
    }
    if (bootstrap_peer_preferred(node,
                                 scan->representatives[host_index]))
        scan->representatives[host_index] = node;
}

static void bootstrap_consider_verified_zclassic23_node(
    struct p2p_node *node,
    struct verified_zclassic23_bootstrap_scan *scan)
{
    bool fast_sync_useful;
    char host[ZCL_PEER_HOST_KEY_MAX];
    int host_index;

    if (node_is_zclassic23(node) &&
        msg_version_peer_uses_external_host(node)) {
        (*scan->self_excluded)++;
        return;
    }

    if (!node_is_verified_zclassic23_bootstrap(node))
        return;

    fast_sync_useful = peer_supports_fast_sync(node->services);
    (*scan->verified_connection_count)++;
    if (fast_sync_useful)
        (*scan->fast_sync_connection_count)++;

    if (!zcl_peer_host_key(node, host, sizeof(host)))
        return;

    host_index = zcl_peer_host_set_find_host(scan->verified_hosts, host);
    if (host_index < 0) {
        bootstrap_store_new_verified_zclassic23_host(scan, node, host,
                                                     fast_sync_useful);
        return;
    }

    bootstrap_update_duplicate_verified_zclassic23_host(
        scan, node, host_index, fast_sync_useful);
}

void network_push_verified_zclassic23_bootstrap_peers(
    struct json_value *peers, struct connman *cm)
{
    struct json_value arr = {0};
    struct zcl_peer_host_set verified_hosts;
    const struct p2p_node *representatives[ZCL_PEER_HOST_SET_MAX];
    bool representative_fast_sync[ZCL_PEER_HOST_SET_MAX];
    int64_t verified_count = 0;
    int64_t verified_connection_count = 0;
    int64_t duplicate_connections = 0;
    int64_t fast_sync_count = 0;
    int64_t fast_sync_connection_count = 0;
    int64_t self_excluded = 0;
    int64_t included = 0;

    zcl_peer_host_set_init(&verified_hosts);
    memset(representatives, 0, sizeof(representatives));
    memset(representative_fast_sync, 0, sizeof(representative_fast_sync));
    json_set_array(&arr);
    if (cm) {
        struct verified_zclassic23_bootstrap_scan scan = {
            .verified_hosts = &verified_hosts,
            .representatives = representatives,
            .representative_fast_sync = representative_fast_sync,
            .verified_count = &verified_count,
            .verified_connection_count = &verified_connection_count,
            .duplicate_connections = &duplicate_connections,
            .fast_sync_count = &fast_sync_count,
            .fast_sync_connection_count = &fast_sync_connection_count,
            .self_excluded = &self_excluded,
        };

        zcl_mutex_lock(&cm->manager.cs_nodes);
        for (size_t i = 0; i < cm->manager.num_nodes; i++) {
            bootstrap_consider_verified_zclassic23_node(
                cm->manager.nodes[i], &scan);
        }

        for (size_t i = 0; i < verified_hosts.count &&
             included < BOOTSTRAP_ZCL23_PEER_LIST_LIMIT; i++) {
            const struct p2p_node *node = representatives[i];
            struct json_value item = {0};
            struct json_value lifecycle = {0};
            const char *source = "";
            int64_t handshake_age = -1;
            bool fast_sync_useful;

            if (!node)
                continue;
            fast_sync_useful = peer_supports_fast_sync(node->services);
            json_set_object(&item);
            json_push_kv_str(&item, "addr", node->addr_name);
            json_push_kv_bool(&item, "inbound", node->inbound);
            json_push_kv_str(&item, "subver",
                             node->clean_sub_ver[0]
                                 ? node->clean_sub_ver
                                 : node->sub_ver);
            json_push_kv_int(&item, "services",
                             (int64_t)node->services);
            json_push_kv_bool(&item, "node_network", true);
            json_push_kv_bool(&item, "node_zclassic23", true);
            json_push_kv_bool(&item,
                              "fast_sync_service_bit_advertised",
                              peer_supports_fast_sync(node->services));
            json_push_kv_int(&item, "advertised_height",
                             node->starting_height);
            json_push_kv_str(&item, "verified_by", "live_handshake");
            json_push_kv_str(&item, "bootstrap_readiness", "useful");
            json_push_kv_bool(&item, "bootstrap_useful", true);
            json_push_kv_bool(&item, "fast_sync_useful",
                              fast_sync_useful);

            if (peer_lifecycle_peer_json(node, &lifecycle)) {
                source = json_get_str(json_get(&lifecycle, "source"));
                handshake_age =
                    json_get_int(json_get(&lifecycle,
                                           "handshake_age_secs"));
            }
            json_push_kv_str(&item, "source", source ? source : "");
            json_push_kv_int(&item, "handshake_age_secs",
                             handshake_age);
            json_free(&lifecycle);

            json_push_back(&arr, &item);
            json_free(&item);
            included++;
        }
        zcl_mutex_unlock(&cm->manager.cs_nodes);
    }

    json_push_kv_int(peers, "verified_zclassic23_bootstrap_peer_count",
                     verified_count);
    json_push_kv_int(peers,
                     "verified_zclassic23_bootstrap_connection_count",
                     verified_connection_count);
    json_push_kv_int(peers, "fast_sync_useful_zclassic23_peer_count",
                     fast_sync_count);
    json_push_kv_int(peers,
                     "fast_sync_useful_zclassic23_connection_count",
                     fast_sync_connection_count);
    json_push_kv_int(peers,
                     "verified_zclassic23_duplicate_connections_excluded",
                     duplicate_connections);
    json_push_kv_int(peers, "verified_zclassic23_self_connections_excluded",
                     self_excluded);
    json_push_kv_int(peers, "zclassic23_bootstrap_quorum_target",
                     BOOTSTRAP_ZCL23_PEER_QUORUM_TARGET);
    json_push_kv_str(peers, "zclassic23_bootstrap_quorum_status",
                     bootstrap_zcl23_quorum_status(verified_count));
    json_push_kv_bool(peers, "zclassic23_bootstrap_quorum_met",
                      verified_count >=
                          BOOTSTRAP_ZCL23_PEER_QUORUM_TARGET);
    json_push_kv_bool(peers, "zclassic23_fast_sync_quorum_met",
                      fast_sync_count >=
                          BOOTSTRAP_ZCL23_PEER_QUORUM_TARGET);
    json_push_kv_int(peers, "verified_zclassic23_bootstrap_peer_list_limit",
                     BOOTSTRAP_ZCL23_PEER_LIST_LIMIT);
    json_push_kv_bool(peers, "verified_zclassic23_bootstrap_peers_truncated",
                      verified_count > BOOTSTRAP_ZCL23_PEER_LIST_LIMIT);
    json_push_kv(peers, "verified_zclassic23_bootstrap_peers", &arr);
    json_free(&arr);
}
