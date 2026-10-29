/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_RPC_NET_H
#define ZCL_RPC_NET_H

#include "rpc/server.h"
#include <stdbool.h>
#include <stdint.h>

struct connman;
struct msg_processor;
struct onion_stream_stages;
struct peer_lifecycle_summary;

void rpc_net_set_connman(struct connman *cm);
struct connman *rpc_net_get_connman(void);
void rpc_net_set_msg_processor(struct msg_processor *mp);
struct msg_processor *rpc_net_get_msg_processor(void);
void rpc_net_set_boot_context(const char *datadir,
                              const char *load_snapshot_at_own_height);
void register_net_rpc_commands(struct rpc_table *t);

struct json_value;

/* Backing RPC for the typed core.network.onion.status contract. */
bool network_onion_status_rpc(const struct json_value *params, bool help,
                              struct json_value *result);
/* Operator-only: fetch another onion's /status through the embedded Tor. */
bool network_onion_remote_status_rpc(const struct json_value *params,
                                     bool help, struct json_value *result);
bool network_addnode_rpc(const struct json_value *params, bool help,
                         struct json_value *result);
const char *network_onion_first_incomplete_stage(
    bool tor_enabled, bool tor_requested, bool dial_ready,
    const struct onion_stream_stages *stream,
    const struct peer_lifecycle_summary *peer);

/* Shared bootstrap-service readiness contract for RPC, REST, and native. */
bool network_bootstrap_status_json(struct json_value *out);
const char *network_bootstrap_readiness_label(bool p2p_serving,
                                              bool addr_relay_ready);
const char *network_bootstrap_next_action(bool p2p_serving,
                                          bool node_zcl23,
                                          bool addr_relay_ready);
void network_push_zclassic23_bootstrap_contract(struct json_value *result,
                                                bool p2p_serving,
                                                bool addr_relay_ready,
                                                bool node_zcl23,
                                                const char *ext_ip,
                                                uint16_t ext_port);
void network_push_verified_zclassic23_bootstrap_peers(
    struct json_value *peers, struct connman *cm);
void network_push_snapshot_loader_status(struct json_value *result,
                                         const char *datadir,
                                         const char *load_snapshot_at_own_height);

/* One peer's transport posture, classified once for getpeerinfo and the
 * dumpstate transport dump so the two cannot disagree. The inspector reads
 * node->transport under node->cs_recv, the lock the socket thread holds while
 * it feeds or frees the transport (lock order cs_nodes -> cs_recv, as in
 * connman.c); callers hold cs_nodes. fingerprint_hex is set only for
 * PEER_TRANSPORT_NOISE_XXHFS. When `dump` is non-NULL it receives the
 * noise_transport_dump_peer object, captured under the same lock. */
enum peer_transport_class {
    PEER_TRANSPORT_PLAINTEXT = 0,
    PEER_TRANSPORT_HANDSHAKING,
    PEER_TRANSPORT_NOISE_XXHFS,
};
struct peer_transport_info {
    enum peer_transport_class cls;
    char fingerprint_hex[65];
};
struct p2p_node;
void network_peer_transport_inspect(struct p2p_node *node,
                                    struct peer_transport_info *info,
                                    struct json_value *dump);
const char *network_peer_transport_name(enum peer_transport_class cls);
/* Adds "transport" and, when established, the three noise_* fields. */
void network_peer_transport_push_json(struct json_value *obj,
                                      const struct peer_transport_info *info);

/* Normalize `dumpstate peer_lifecycle incidents` into the standalone
 * `peerincidents` contract. This is used only as a compatibility fallback
 * when a running target predates the direct peerincidents RPC method. */
bool peer_incidents_from_dumpstate_result_json(const struct json_value *result,
                                               struct json_value *out,
                                               const char *reason);

#endif
