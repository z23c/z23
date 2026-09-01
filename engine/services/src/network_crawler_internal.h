/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * network_crawler internals shared between the service TU
 * (network_crawler.c — config, pure fold, census table, worker, dumper) and
 * the DIAL TU (network_crawler_dial.c — the two-phase, separately-bounded
 * probe waves). Not a public surface: services/network_crawler.h is.
 */

#ifndef ZCL_SERVICES_NETWORK_CRAWLER_INTERNAL_H
#define ZCL_SERVICES_NETWORK_CRAWLER_INTERNAL_H

#include "services/network_crawler.h"

/* Insert-or-update one result in the bounded census, taking the crawler lock.
 * Owned by network_crawler.c; called by the dial TU per recordable result. */
void ncrawl_census_ingest(const struct ncrawl_probe_result *pr);

/* Every bound one round obeys. Clearnet and onion are budgeted SEPARATELY so
 * a slow circuit can never eat the clearnet batch or the crawler tick. */
struct ncrawl_round_limits {
    int concurrent;            /* clearnet in-flight cap */
    int connect_timeout_ms;
    int handshake_timeout_ms;
    int onion_per_round;       /* onion dials attempted per round */
    int onion_concurrent;      /* onion in-flight cap (much smaller) */
    int onion_timeout_ms;      /* per-onion-dial ceiling */
    int onion_round_budget_ms; /* wall-clock ceiling on the onion phase */
};

/* What one round did. */
struct ncrawl_round_stats {
    int recorded;    /* recordable results banked (measured + not-probed) */
    int reachable;
    int not_probed;
    int edges_seen;
    int new_nodes;
};

/* Dial addrs[0..n) under `lim`, banking every recordable result into the
 * bounded census AND the durable ledger. Returns stats->recorded. */
int ncrawl_run_round(const struct net_address *addrs, int n,
                     ncrawl_probe_fn fn,
                     const struct ncrawl_round_limits *lim,
                     struct ncrawl_round_stats *stats);

#endif /* ZCL_SERVICES_NETWORK_CRAWLER_INTERNAL_H */
