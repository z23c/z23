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

/* Normalize `dumpstate peer_lifecycle incidents` into the standalone
 * `peerincidents` contract. This is used only as a compatibility fallback
 * when a running target predates the direct peerincidents RPC method. */
bool peer_incidents_from_dumpstate_result_json(const struct json_value *result,
                                               struct json_value *out,
                                               const char *reason);

#endif
