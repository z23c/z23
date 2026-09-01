/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_NET_PEER_LIFECYCLE_H
#define ZCL_NET_PEER_LIFECYCLE_H

#include "net/net.h"
#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum peer_lifecycle_source {
    PEER_LIFECYCLE_SOURCE_UNKNOWN = 0,
    PEER_LIFECYCLE_SOURCE_INBOUND,
    PEER_LIFECYCLE_SOURCE_ADDNODE,
    PEER_LIFECYCLE_SOURCE_ADDRMAN,
    PEER_LIFECYCLE_SOURCE_ZCL23_DB,
    PEER_LIFECYCLE_SOURCE_MANUAL,
    PEER_LIFECYCLE_SOURCE_ANCHOR,   /* dialed from persisted anchors.dat (boot-first) */
};

struct peer_lifecycle_summary {
    int64_t attempted;
    int64_t connected;
    int64_t version_sent;
    int64_t version_received;
    int64_t verack_received;
    int64_t handshake_complete;
    int64_t active;
    int64_t disconnected;
    int64_t timeout;
    int64_t rejected;
    int64_t cache_skipped;
    int64_t magicbean_handshakes;
    int64_t legacy_compatible_handshakes;
    int64_t zcl23_handshakes;
    int64_t pre_handshake_disconnects;
    int64_t disconnect_reason_counts[P2P_DISCONNECT_REASON_COUNT];
    int64_t disconnect_source_counts[P2P_DISCONNECT_SOURCE_COUNT];
    uint64_t max_endpoint_generation;
};

const char *peer_lifecycle_source_name(enum peer_lifecycle_source source);

void peer_lifecycle_note_attempt(const struct net_address *addr,
                                 enum peer_lifecycle_source source);
void peer_lifecycle_note_connected(const struct p2p_node *node,
                                   enum peer_lifecycle_source source);
void peer_lifecycle_note_version_sent(const struct p2p_node *node,
                                      uint64_t services,
                                      int start_height,
                                      const char *subver);
void peer_lifecycle_note_version_received(const struct p2p_node *node,
                                          uint64_t services,
                                          int start_height,
                                          const char *subver);
void peer_lifecycle_note_verack_received(const struct p2p_node *node);
void peer_lifecycle_note_handshake_complete(const struct p2p_node *node);
void peer_lifecycle_note_active(const struct p2p_node *node);
void peer_lifecycle_note_timeout(const struct p2p_node *node,
                                 const char *reason);
void peer_lifecycle_note_reject(const struct p2p_node *node,
                                const char *reason);
void peer_lifecycle_note_disconnected(const struct p2p_node *node,
                                      const char *reason);
void peer_lifecycle_note_cache_skipped(const struct p2p_node *node,
                                       const char *reason);
void peer_lifecycle_note_cache_skipped_addr(const char *addr,
                                            int64_t peer_id,
                                            const char *reason);

bool peer_lifecycle_peer_json(const struct p2p_node *node,
                              struct json_value *out);
bool peer_lifecycle_addr_json(const char *addr, struct json_value *out);
bool peer_lifecycle_summary_json(struct json_value *out);
bool peer_lifecycle_incidents_json(struct json_value *out);
bool peer_lifecycle_dump_state_json(struct json_value *out,
                                    const char *key);
void peer_lifecycle_get_summary(struct peer_lifecycle_summary *out);
void peer_lifecycle_reset_for_test(void);

#endif /* ZCL_NET_PEER_LIFECYCLE_H */
