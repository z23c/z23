/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer dashboard view — the /explorer landing page (block height +
 * difficulty + mempool stat row, followed by the "Latest Blocks" table).
 * Two render modes mirror the two data sources the controller fetches
 * from: the RPC-proxy mode and the native-chain mode. The controller
 * parses the request, fetches the data (via RPC or the in-process chain
 * accessors), packs it into the structs below, and delegates the entire
 * HTML/HTTP assembly here. */

#ifndef ZCL_VIEWS_EXPLORER_DASHBOARD_VIEW_H
#define ZCL_VIEWS_EXPLORER_DASHBOARD_VIEW_H

#include <stdint.h>
#include <stddef.h>

/* Compact live network summary shown on the landing dashboard. These values
 * are runtime handshake evidence, not persisted peer-projection guesses. */
struct explorer_dashboard_network_view {
    size_t peer_count;
    size_t zclassic23_peers;
    size_t zclassic23_nodes_seen;
    size_t magicbean_peers;
};

/* ── RPC-proxy mode ───────────────────────────────────────── */

/* One "Latest Blocks" row, RPC-proxy mode. The controller pre-formats
 * the display strings exactly as the original emit expected. */
struct explorer_dashboard_rpc_row {
    int    height;
    char   hash[65];
    char   short_hash[18];
    char   ago[32];
    char   ts[32];
    int    tx_count;
    double difficulty;
};

/* RPC-proxy dashboard payload: the four-stat header row plus up to
 * `row_count` latest-block rows (already filtered + formatted by the
 * controller). */
struct explorer_dashboard_rpc_view {
    int     tip;
    double  difficulty;
    int64_t mempool_count;
    int64_t mempool_bytes;
    int64_t tip_time;            /* tip block unix time (0 if unknown) */
    double  recent_avg_interval; /* avg interval over shown blocks (s, 0 if n/a) */
    struct explorer_dashboard_network_view network;
    const struct explorer_dashboard_rpc_row *rows;
    int     row_count;
};

/* Render the RPC-proxy dashboard into r. Returns bytes written. */
size_t explorer_dashboard_view_rpc(uint8_t *r, size_t max,
                                   const struct explorer_dashboard_rpc_view *v);

/* ── Native-chain mode ────────────────────────────────────── */

/* One "Latest Blocks" row, native-chain mode. */
struct explorer_dashboard_native_row {
    int      height;
    char     h_fmt[32];   /* height formatted with thousands separators */
    char     hash[65];
    char     short_hash[18];
    char     ts[32];
    uint32_t ntx;
    double   difficulty;
    char     sapling[32];  /* formatted shielded value, "" if zero */
};

/* Native-chain dashboard payload: header stat row, latest-block rows,
 * and pagination state. */
struct explorer_dashboard_native_view {
    int      tip;
    double   difficulty;
    size_t   mempool_count;
    uint64_t mempool_bytes;
    int64_t  tip_time;            /* tip block unix time (0 if unknown) */
    double   recent_avg_interval; /* avg interval over shown blocks (s, 0 if n/a) */
    struct explorer_dashboard_network_view network;
    const struct explorer_dashboard_native_row *rows;
    int      row_count;
    int      page;          /* current page (>= 0) */
    int      end_height;    /* lowest height shown on this page */
};

/* Render the native-chain dashboard into r. Returns bytes written. */
size_t explorer_dashboard_view_native(uint8_t *r, size_t max,
                                      const struct explorer_dashboard_native_view *v);

#endif
