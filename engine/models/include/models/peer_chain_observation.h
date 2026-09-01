/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * peer_chain_observation — retained history of per-peer chain intelligence.
 * One row per sampled peer per network-monitor tick: the peer's advertised
 * best height, learnable tip hash, protocol version + user-agent, ping
 * latency, and first/last-seen times. The network monitor
 * (engine/services/src/network_monitor.c) folds the most-recent observations
 * into a consensus view (modal tip, max height, fork clusters, our delta)
 * so the node can always SEE the chain it is trying to be on. Purely
 * observational: never consulted by consensus / chain selection. Bounded
 * retention — pruned to the newest N rows. */

#ifndef ZCL_DB_MODEL_PEER_CHAIN_OBSERVATION_H
#define ZCL_DB_MODEL_PEER_CHAIN_OBSERVATION_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    PEER_OBS_ADDR_MAX = 127,      /* "ip:port" display string */
    PEER_OBS_UA_MAX = 95,         /* sanitized user-agent (clean_sub_ver) */
    PEER_OBS_TIP_HEX = 64         /* 32-byte block hash as hex (+NUL) */
};

/* One retained per-peer chain observation. tip_hash is the empty string
 * when no tip hash was learnable for the peer at sample time. */
struct db_peer_chain_observation {
    int64_t peer_id;
    char addr[PEER_OBS_ADDR_MAX + 1];
    char user_agent[PEER_OBS_UA_MAX + 1];
    int version;
    int64_t best_height;                  /* advertised best height (-1 unknown) */
    char tip_hash[PEER_OBS_TIP_HEX + 1];  /* hex, or "" when unknown */
    int64_t latency_us;                   /* rolling avg ping RTT, microseconds */
    int inbound;                          /* 0 = outbound, 1 = inbound */
    int64_t first_seen;                   /* peer connect time (unix secs) */
    int64_t last_seen;                    /* last activity (unix secs) */
    int64_t observed_at;                  /* when this sample was taken */
};

/* Lazily-initialized before/after-save callback registry for the model. */
struct ar_callbacks *db_peer_chain_observation_callbacks(void);

/* Populate errors with any validation failures. Returns true iff valid. */
bool db_peer_chain_observation_validate(const struct db_peer_chain_observation *o,
                                        struct ar_errors *errors);

/* Insert one observation row. Runs the AR lifecycle (validate + hooks).
 * Stamps observed_at if unset. Returns false on bad args / veto / DB error. */
bool db_peer_chain_observation_save(struct node_db *ndb,
                                    const struct db_peer_chain_observation *o);

/* Bounded retention: delete all but the newest keep_rows rows (by id).
 * Returns true on success (including nothing-to-delete). */
bool db_peer_chain_observation_prune(struct node_db *ndb, int keep_rows);

/* Total retained rows. Returns 0 on bad args / empty. */
int db_peer_chain_observation_count(struct node_db *ndb);

/* Load up to max most-recent observations (newest first) into out.
 * Returns the number of rows written, or 0 on bad args / empty. */
int db_peer_chain_observation_recent(struct node_db *ndb,
                                     struct db_peer_chain_observation *out,
                                     size_t max);

#endif /* ZCL_DB_MODEL_PEER_CHAIN_OBSERVATION_H */
