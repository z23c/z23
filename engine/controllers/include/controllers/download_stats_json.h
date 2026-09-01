/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */
#ifndef ZCLASSIC23_CONTROLLERS_DOWNLOAD_STATS_JSON_H
#define ZCLASSIC23_CONTROLLERS_DOWNLOAD_STATS_JSON_H

/* Single collector + single serializer for the download-manager counters
 * that used to be re-fetched and hand-serialized independently at five
 * call sites (rpc_downloadstats, api_serve_downloadstats,
 * api_serve_node_status, api_serve_node_summary, api_serve_health),
 * with real field drift between them (some had the throughput fields,
 * some didn't). See CLAUDE.md "Adding state introspection" for the
 * general collector convention this follows. */

#include <stdbool.h>
#include <stdint.h>

#include "net/connman.h"
#include "net/download.h"
#include "services/gap_fill_service.h"

struct json_value;
struct node_health_snapshot;

struct download_stats_snapshot {
    uint64_t requested;
    uint64_t received;
    uint64_t timed_out;
    uint64_t in_flight;
    uint64_t queued;
    uint64_t bytes_downloaded;
    double   mbps_avg;
    /* Only populated when download_stats_snapshot_collect() is called
     * with full=true; zeroed otherwise. */
    struct dl_diagnostics diag;
    struct gap_fill_stats gf_stats;
    struct connman_message_cycle_stats msg_stats;
};

/* Collects the shared download-manager counters + throughput once.
 * full=true additionally collects the extended diagnostics (dl_diagnostics,
 * gap-fill pass counters, connman message-cycle counters) used by the two
 * verbose endpoints; full=false skips that extra work — it's meant for
 * the abbreviated dashboard callers, which only need the counts. */
void download_stats_snapshot_collect(struct download_stats_snapshot *out,
                                     bool full);

/* Fills a snapshot from an already-collected node_health_snapshot instead
 * of re-fetching from the download manager. Use this when a health
 * snapshot is already in scope (node_health_collect() already called
 * dl_get_stats()/dl_get_throughput() for it) to avoid a redundant fetch.
 * Always produces a full=false-shaped snapshot (diag/gf_stats/msg_stats
 * left zeroed — the health snapshot does not carry them). */
void download_stats_snapshot_from_health(
    struct download_stats_snapshot *out,
    const struct node_health_snapshot *health);

/* Pushes the snapshot's fields directly into obj (no implicit nesting —
 * callers that want a "download": {...} sub-object create it themselves
 * and pass that sub-object in, same as the existing hand-rolled call
 * sites). Both full=true and full=false push the core counts
 * (requested/received/timed_out/in_flight/queued) and the throughput
 * fields (bytes_downloaded/mbps_avg/gb_downloaded). full=true additionally
 * pushes the extended diagnostics from a snapshot collected with
 * full=true. */
void download_stats_push_json(struct json_value *obj,
                              const struct download_stats_snapshot *s,
                              bool full);

#endif /* ZCLASSIC23_CONTROLLERS_DOWNLOAD_STATS_JSON_H */
