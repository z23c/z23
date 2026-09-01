/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * topology_store — the network GRAPH: who advertises whom.
 *
 * addr/addrv2 gossip (core/modules/net/src/msgprocessor_inv.c::process_addr) and the
 * whole-network crawler (engine/services/src/network_crawler.c) both learn
 * "node X told us about address Y" — that is one directed edge in the
 * ZClassic P2P topology graph. Nothing previously recorded it; this module
 * banks it durably in its own dedicated sqlite file (topology.db), owned
 * directly by this TU (no event log, no projection_consumer — a plain
 * bounded upsert table, opened once at boot like progress_store).
 *
 * Two edge sources feed the same table:
 *   - topology_store_record_edge()      — real graph edges: observer_addr
 *     (the already-connected peer or crawl target) advertised
 *     advertised_addr in an addr/addrv2 message.
 *   - topology_store_record_self_edge() — crawler-result edges: our own
 *     crawler directly reached advertised_addr this round. observer is the
 *     fixed literal "self" (not a wire address, so it skips the observer
 *     routability check — only the advertised address is wire-controlled
 *     untrusted data).
 *
 * PEDANTIC: every advertised address is validated routable
 * (net_addr_is_routable — the same IsRoutable-class helper addrman_add()
 * uses) before storage; non-routable / malformed input is rejected and
 * counted, never stored. Bounded upsert: total rows capped at
 * TOPOLOGY_EDGES_CAP, oldest-by-last_advertised evicted past the cap.
 *
 * Observational only — never consulted by consensus / chain selection /
 * peer scoring. A missing/unopened store makes every call here a safe
 * no-op (fail-open), so callers never gate network processing on this
 * module being available.
 */

#ifndef ZCL_STORAGE_TOPOLOGY_STORE_H
#define ZCL_STORAGE_TOPOLOGY_STORE_H

#include "net/netaddr.h"

#include <stdbool.h>
#include <stdint.h>

struct json_value;

enum {
    /* Bounded upsert cap on total topology_edges rows; oldest
     * last_advertised evicted past this. */
    TOPOLOGY_EDGES_CAP_DEFAULT = 200000,
    /* Rendered "ip" identity string cap (onion identity is 6 + 64 hex
     * chars = 70; ipv6 is at most 39; both comfortably fit). */
    TOPOLOGY_ADDR_STR_MAX = 96,
    /* Bounded retention on the append-only topology_sweeps ledger. */
    TOPOLOGY_SWEEPS_CAP = 20000,
};

/* Open (idempotent) the dedicated topology.db under datadir. Safe to skip —
 * every record_edge/record_sweep/dump call below no-ops (fail-open) while
 * unopened. */
bool topology_store_open(const char *datadir);
void topology_store_close(void);

/* Record (bounded upsert) one observed edge: observer told us about
 * advertised. Both endpoints are validated via net_addr_is_routable() before
 * storage; a non-routable/invalid endpoint is rejected (counted, not
 * stored) and this returns false. now_unix <= 0 stamps wall-clock now.
 * out_new_advertised_node (nullable) is set true iff `advertised` had never
 * been seen as an advertised endpoint by ANY observer before this call —
 * pass NULL to skip that extra lookup on a hot ingestion path. */
bool topology_store_record_edge(const struct net_addr *observer_addr,
                                uint16_t observer_port,
                                const struct net_addr *advertised_addr,
                                uint16_t advertised_port,
                                int64_t now_unix,
                                bool *out_new_advertised_node);

/* Same contract as topology_store_record_edge(), but the observer is the
 * fixed literal "self" (our own node reached `advertised` directly during a
 * crawl round) — only `advertised` is validated/rendered. */
bool topology_store_record_self_edge(const struct net_addr *advertised_addr,
                                     uint16_t advertised_port,
                                     int64_t now_unix,
                                     bool *out_new_advertised_node);

/* Append one per-sweep summary row (best-effort; false on not-open/bad
 * args). Bounded retention (TOPOLOGY_SWEEPS_CAP, oldest evicted). */
bool topology_store_record_sweep(int64_t started_unix, int64_t finished_unix,
                                 int32_t nodes_contacted,
                                 int32_t nodes_reachable,
                                 int32_t edges_seen, int32_t new_nodes);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * Surfaces: open, edge_count/cap, distinct_observers,
 * distinct_advertised_nodes, top_advertised (in-degree top-10), and
 * last_sweep (most recent topology_sweeps row). */
bool topology_store_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
/* Wipe both tables on the open store (no-op if unopened). */
void topology_store_test_reset(void);
int64_t topology_store_test_edge_count(void);
int64_t topology_store_test_sweep_count(void);
/* Lower the bounded-upsert cap so eviction is provable without inserting
 * TOPOLOGY_EDGES_CAP_DEFAULT rows. 0 restores the default. */
void topology_store_test_set_cap(int64_t cap);
#endif

#endif /* ZCL_STORAGE_TOPOLOGY_STORE_H */
