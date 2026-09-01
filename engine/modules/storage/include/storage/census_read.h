/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * census_read — READ-ONLY operator surface over the network census + topology
 * stores banked by the crawler/indexer lanes. This module NEVER writes those
 * stores (except the ZCL_TESTING fixture helpers below) and NEVER touches
 * consensus: it opens each store with SQLITE_OPEN_READONLY and folds bounded,
 * pedantically length-checked rows for the `net census|node|versions|graph`
 * commands and the explorer `/network` page.
 *
 * Canonical schema — the reader is designed to the EXISTING writer schemas, it
 * does not invent its own. There are TWO stores, each its own file:
 *
 *   <datadir>/peers_projection.db  (engine/modules/storage/src/peers_projection.c)
 *     node_census(ip BLOB, port, user_agent, ua_overflow, protocol_version,
 *                 services, last_reported_height, first_seen, last_seen,
 *                 last_success, dial_success_count, dial_fail_count, source,
 *                 PRIMARY KEY(ip,port))
 *     census_observations(seq PK, ip BLOB, port, observed_unix, user_agent,
 *                 ua_overflow, protocol_version, services, reported_height,
 *                 source)
 *   <datadir>/topology.db          (engine/modules/storage/src/topology_store.c)
 *     topology_edges(id PK, observer_ip TEXT, observer_port, advertised_ip TEXT,
 *                 advertised_port, first_advertised, last_advertised, times_seen)
 *     topology_sweeps(sweep_id PK, started_unix, finished_unix, nodes_contacted,
 *                 nodes_reachable, edges_seen, new_nodes)
 *
 * Note the type split: node_census/census_observations key on a 16-byte `ip`
 * BLOB (the raw IPv4-mapped-or-v6 address); topology_edges stores the rendered
 * dotted/colon TEXT form. The reader renders the blob to the same TEXT form via
 * an `ip_to_str()` SQL function so the two stores can be related. There is NO
 * `reachable` column and NO `height` column anywhere — reachability is DERIVED
 * from dial_success_count/last_success and node height is `last_reported_height`.
 *
 * The reader opens peers_projection.db as the primary connection and ATTACHes
 * topology.db read-only; both absences degrade gracefully (a missing primary is
 * CENSUS_READ_DB_ABSENT, a present file missing node_census is
 * CENSUS_READ_TABLES_ABSENT, a missing topology.db just zeroes the graph/edge
 * surfaces). Everything the reader returns is bounded by construction.
 */
#ifndef ZCL_STORAGE_CENSUS_READ_H
#define ZCL_STORAGE_CENSUS_READ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Store file basenames inside the datadir (the real writer-owned files). */
#define CENSUS_PEERS_DB_BASENAME    "peers_projection.db"
#define CENSUS_TOPOLOGY_DB_BASENAME "topology.db"

/* Read-surface bounds. A user_agent taken from the wire (or a store fed from
 * the wire) is length-checked into this fixed buffer; anything longer is stored
 * truncated WITH a flag, never silently trusted at full length. */
#define CENSUS_UA_MAX               96   /* incl. NUL */
#define CENSUS_IP_MAX               64   /* incl. NUL; holds v4/v6 host */
#define CENSUS_ENDPOINT_MAX         80   /* "ip:port" endpoint string, incl. NUL */
#define CENSUS_LIST_HARD_CAP        40   /* max node rows one list call returns */
#define CENSUS_LIST_DEFAULT_LIMIT   25
#define CENSUS_MAX_OBSERVATIONS     40   /* bounded per-node observation history */
#define CENSUS_MAX_EDGES            40   /* bounded per-node edge fan-out */
#define CENSUS_MAX_VERSION_BUCKETS  40
#define CENSUS_MAX_TOP_ADVERTISED   10

enum census_read_status {
    CENSUS_READ_OK = 0,        /* peers_projection.db open, node_census present */
    CENSUS_READ_DB_ABSENT,     /* no peers_projection.db / could not open read-only */
    CENSUS_READ_TABLES_ABSENT, /* file present but node_census table missing */
};

typedef struct census_reader census_reader;

struct census_node {
    char    ip[CENSUS_IP_MAX];  /* rendered from the 16-byte ip BLOB */
    int     port;
    char    user_agent[CENSUS_UA_MAX];
    bool    ua_truncated;       /* reader clipped UA into CENSUS_UA_MAX-1 bytes */
    bool    ua_overflow;        /* stored ua_overflow flag (writer over-length) */
    int64_t protocol_version;
    int64_t services;
    int64_t reported_height;    /* node_census.last_reported_height (-1 = unknown) */
    int64_t first_seen;
    int64_t last_seen;
    int64_t last_success;       /* unix of last successful dial (0 = never) */
    int64_t dial_success_count;
    int64_t dial_fail_count;
    bool    reachable;          /* DERIVED: dial_success_count > 0 */
};

struct census_filter {
    const char *ua_contains;   /* NULL/"" = no user-agent substring filter */
    int64_t     min_height;    /* < 0 = no minimum-height filter (last_reported_height) */
    int64_t     seen_within_secs; /* < 0 = no recency filter (on last_seen) */
    int64_t     now_unix;      /* reference clock for seen_within_secs */
};

struct census_observation {
    int64_t observed_unix;
    int64_t reported_height;   /* census_observations.reported_height */
    int64_t protocol_version;
    int64_t services;
    char    user_agent[CENSUS_UA_MAX];
    bool    ua_truncated;
    bool    ua_overflow;
};

struct census_edge {
    char    observer[CENSUS_ENDPOINT_MAX];   /* "observer_ip:observer_port" */
    char    advertised[CENSUS_ENDPOINT_MAX]; /* "advertised_ip:advertised_port" */
    int64_t times_seen;
    int64_t last_advertised;
};

struct census_version_bucket {
    char    user_agent[CENSUS_UA_MAX];
    bool    ua_truncated;
    int64_t count;
    int64_t max_reported_height; /* MAX(last_reported_height) in the bucket */
};

struct census_top_advertised {
    char    advertised[CENSUS_ENDPOINT_MAX];
    int64_t times_seen;         /* summed times_seen across observers */
    int64_t distinct_observers; /* how many observers advertised this endpoint */
};

struct census_graph_stats {
    int64_t node_count;
    int64_t edge_count;
    int64_t observation_count;
    int64_t advertised_in_census; /* DISTINCT advertised endpoints present in census */
    int64_t sweeps_total;         /* rows in topology_sweeps */
    int64_t last_sweep_finished_unix; /* MAX(finished_unix); 0 = no finished sweep */
    struct census_top_advertised top[CENSUS_MAX_TOP_ADVERTISED];
    int     top_count;
};

/* Open the census stores for read-only queries. `datadir` may be NULL/"" — the
 * reader falls back to the default node datadir. On success (*out set,
 * CENSUS_READ_OK) the caller MUST census_read_close(). On any non-OK status
 * *out is NULL; the operator surface should print the "census empty: indexer
 * not yet populated" degradation message. Never fails hard. */
enum census_read_status census_read_open(const char *datadir, census_reader **out);
void census_read_close(census_reader *r);

/* Resolved primary (peers_projection.db) path — for degradation messages /
 * SQL-fallback hints. Always writes a NUL-terminated string; returns false only
 * on bad args. */
bool census_read_db_path(const char *datadir, char *out, size_t out_cap);

/* Total nodes in node_census (0 on any absence). */
int64_t census_read_node_total(census_reader *r);

/* List up to min(limit, cap, CENSUS_LIST_HARD_CAP) node rows matching `filter`,
 * newest-last_seen first, skipping `offset` rows. Writes rows[0..return) and,
 * when non-NULL, *matched_total (total rows matching the filter, pre-paging).
 * Returns the number of rows written (0 on absence or past-end offset). A NULL
 * filter means "no filters". */
int census_read_list(census_reader *r, const struct census_filter *filter,
                     int64_t offset, int limit,
                     struct census_node *rows, int cap, int64_t *matched_total);

/* Everything known about one node. Returns true and fills *node (+ bounded
 * observation history and bounded edges referencing ip:port) when the node is
 * in the census; false when absent. obs/edges/out-counts may be NULL. */
bool census_read_node(census_reader *r, const char *ip, int port,
                      struct census_node *node,
                      struct census_observation *obs, int obs_cap, int *obs_n,
                      struct census_edge *edges, int edge_cap, int *edge_n);

/* User-agent / version distribution, descending by count. Fills
 * buckets[0..return) (bounded by cap and CENSUS_MAX_VERSION_BUCKETS). */
int census_read_versions(census_reader *r,
                         struct census_version_bucket *buckets, int cap);

/* Topology / graph statistics: node/edge/observation counts, distinct
 * advertised endpoints that are themselves in the census, the last sweep's
 * finished_unix, and the top-10 most-advertised endpoints. Returns true on OK,
 * false on absence (leaves *out zeroed). */
bool census_read_graph(census_reader *r, struct census_graph_stats *out);

#ifdef ZCL_TESTING
/* Fixture helpers (test-only): create the canonical writer schema (VERBATIM
 * copies of the peers_projection.c / topology_store.c CREATE TABLE text) and
 * seed rows in the two writable store files under `datadir`. Return false on
 * any error. `ip` strings are dotted-IPv4 or the 8-group hex IPv6 form
 * net_addr_to_string emits; they are converted to the 16-byte blob on insert. */
bool census_read_test_create_schema(const char *datadir);
bool census_read_test_insert_node(const char *datadir,
                                  const struct census_node *n);
bool census_read_test_insert_edge(const char *datadir,
                                  const char *observer_ip, int observer_port,
                                  const char *advertised_ip, int advertised_port,
                                  int64_t times_seen, int64_t last_advertised);
bool census_read_test_insert_observation(const char *datadir, const char *ip,
                                         int port, int64_t observed_unix,
                                         int64_t reported_height, const char *ua,
                                         int64_t protocol_version,
                                         int64_t services);
bool census_read_test_insert_sweep(const char *datadir, int64_t started_unix,
                                   int64_t finished_unix, int nodes_contacted,
                                   int nodes_reachable, int edges_seen,
                                   int new_nodes);
#endif

#endif /* ZCL_STORAGE_CENSUS_READ_H */
