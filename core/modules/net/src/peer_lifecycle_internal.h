/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Internal peer_lifecycle record and scoring types shared by its
 * implementation units. */

#ifndef ZCL_NET_PEER_LIFECYCLE_INTERNAL_H
#define ZCL_NET_PEER_LIFECYCLE_INTERNAL_H

#include "net/peer_lifecycle.h"

#define PEER_LIFECYCLE_MAX 1024
#define PEER_LIFECYCLE_INCIDENT_LIMIT 16
#define PEER_LIFECYCLE_GROUP_LIMIT 64
#define PEER_LIFECYCLE_HOST_INCIDENT_LIMIT 8

struct peer_lifecycle_entry {
    bool used;
    int64_t peer_id;
    char addr[256];
    enum peer_lifecycle_source source;
    int64_t first_seen;
    int64_t last_seen;
    int64_t connected_at;
    int64_t last_reconnect_at;
    int64_t last_reconnect_interval_secs;
    uint64_t connected_seq;
    int64_t version_sent_at;
    int64_t version_received_at;
    int64_t verack_received_at;
    int64_t handshake_complete_at;
    uint64_t handshake_complete_seq;
    int64_t active_at;
    int64_t disconnected_at;
    int64_t timeout_at;
    int64_t rejected_at;
    uint64_t terminal_seq;
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
    int64_t pre_handshake_disconnects;
    uint64_t services;
    int start_height;
    char subver[MAX_SUBVERSION_LENGTH];
    char last_reason[128];
};

struct peer_lifecycle_host_group {
    bool used;
    char host[256];
    int64_t entries;
    int64_t inbound_entries;
    int64_t outbound_entries;
    int64_t unknown_entries;
    int64_t open_connections;
    int64_t open_inbound_connections;
    int64_t open_outbound_connections;
    int64_t open_unknown_connections;
    int64_t handshaked_open_connections;
    int64_t handshaked_inbound_connections;
    int64_t handshaked_outbound_connections;
    int64_t handshaked_unknown_connections;
    int64_t handshaked_network_connections;
    int64_t handshaked_advertised_height_connections;
    int64_t handshaked_trusted_advertised_height_connections;
    int64_t handshaked_untrusted_advertised_height_connections;
    int64_t handshaked_zclassic23_connections;
    int64_t bootstrap_useful_connections;
    int64_t fast_sync_useful_connections;
    int64_t connected;
    int64_t handshake_complete;
    int64_t active;
    int64_t disconnected;
    int64_t timeout;
    int64_t rejected;
    int64_t reconnects;
    int64_t pre_handshake_disconnects;
    int64_t last_reconnect_at;
    int64_t last_reconnect_interval_secs;
    int64_t min_reconnect_interval_secs;
    int64_t max_reconnect_interval_secs;
    int64_t last_seen;
    int64_t max_advertised_height;
    uint64_t services_or;
    bool bootstrap_useful;
    bool fast_sync_useful;
    char last_reason[128];
};

struct peer_lifecycle_incident_pick {
    const struct peer_lifecycle_entry *entry;
    int64_t score;
    int64_t duplicate_host_entries;
    char host[256];
};

struct peer_lifecycle_host_pick {
    const struct peer_lifecycle_host_group *group;
    int64_t score;
};

/* Below: the bounded top-N incident scoring/selection API implemented in
 * peer_lifecycle_incident_score.c. These operate only on already-populated
 * entry/host-group snapshots — never on g_pl — which is what lets them live
 * in a sibling translation unit. peer_lifecycle.c calls them while holding
 * g_pl.lock and building the incidents JSON view. */
int64_t duplicate_entries_for_host(
                                 const struct peer_lifecycle_host_group *groups,
                                 const char *host);
int64_t host_group_incident_score(const struct peer_lifecycle_host_group *g);
const char *host_group_issue_class(const struct peer_lifecycle_host_group *g);
const char *host_group_next_action(const struct peer_lifecycle_host_group *g);
void host_pick_consider(struct peer_lifecycle_host_pick *picks,
                        size_t *count,
                        const struct peer_lifecycle_host_group *g);
void incident_pick_consider(struct peer_lifecycle_incident_pick *picks,
                            size_t *count,
                            const struct peer_lifecycle_entry *e,
                            int64_t score, int64_t duplicate_host_entries,
                            const char *host);

/* Entry predicates and renderers split across peer_lifecycle.c (entry state,
 * g_pl) and peer_lifecycle_incident_json.c (incidents JSON rendering). The
 * first group is defined in peer_lifecycle.c and used by the renderers; the
 * second group is defined in peer_lifecycle_incident_json.c and called while
 * peer_lifecycle.c holds g_pl.lock. */
const char *entry_direction(const struct peer_lifecycle_entry *e);
bool entry_connection_open(const struct peer_lifecycle_entry *e);
bool entry_current_connection_handshaked(
    const struct peer_lifecycle_entry *e);
int64_t entry_handshake_age_secs(const struct peer_lifecycle_entry *e,
                                 int64_t now);
int64_t entry_reconnects(const struct peer_lifecycle_entry *e);
void services_summary(uint64_t services, char *out, size_t out_sz);
bool entry_advertised_height_trusted(const struct peer_lifecycle_entry *e);
bool entry_bootstrap_useful(const struct peer_lifecycle_entry *e);
const char *entry_advertised_height_trust(
    const struct peer_lifecycle_entry *e);
const char *entry_bootstrap_readiness(const struct peer_lifecycle_entry *e);
bool entry_fast_sync_useful(const struct peer_lifecycle_entry *e);

void append_incident_peer_json(
    const struct peer_lifecycle_incident_pick *pick, int64_t now,
    struct json_value *arr);
void append_host_group_json(const struct peer_lifecycle_host_group *g,
                            int64_t score, struct json_value *arr);
void append_primary_host_issue_json(
    const struct peer_lifecycle_host_pick *pick, struct json_value *out);
const char *peer_incidents_bootstrap_readiness(
    int64_t open_connections, int64_t handshaked_connections,
    int64_t bootstrap_useful_connections);
const char *peer_incidents_fast_sync_readiness(
    int64_t bootstrap_useful_connections, int64_t fast_sync_useful_connections,
    const char *bootstrap_readiness);
const char *peer_incidents_severity(
    int64_t incident_count, int64_t host_incident_count,
    int64_t duplicate_group_count);
const char *peer_incidents_next_action(
    size_t host_pick_count, int64_t incident_count,
    bool bootstrap_blocked, bool fast_sync_blocked);

#endif /* ZCL_NET_PEER_LIFECYCLE_INTERNAL_H */
