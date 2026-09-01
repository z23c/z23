/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_trace — opt-in, append-only NDJSON state trace for a `mode simnet`
 * chaos cluster (docs/CHAOS_HARNESS.md "Recording a full-state trace").
 *
 * Why this exists: a chaos scenario today only reports a small, fixed set of
 * hand-picked counters (docs/CHAOS_HARNESS.md's `expect METRIC` list). When a
 * scenario fails or behaves surprisingly there is no way to ask "what did
 * node 3's chain/coins state actually look like right before it diverged" —
 * only whatever counter someone thought to track ahead of time. This module
 * closes that gap by snapshotting every simulated node's chain/coins facts
 * at each meaningful cluster event and appending them to a trace file.
 *
 * Why this is NOT "call the live diagnostics dumpers": every registered
 * `<name>_dump_state_json()` in engine/controllers/include/controllers/
 * diagnostics_dumpers.def reads ONE live process's global singleton state
 * (validation/main_state, chainman, a service's module-level statics, or a
 * SQLite table on the live node.db) — none of them take an explicit state
 * instance as a parameter. `simnet_cluster` is a pure in-memory, N-instance
 * simulator (engine/modules/sim/include/sim/simnet_cluster.h): each node owns its own
 * `struct coins_view_cache` and retained block set and NEVER touches the
 * live process's globals. There is therefore no existing per-instance
 * dumper to call for a simnet node — reusing the registry's functions
 * verbatim would either not compile (wrong shape) or silently report the
 * live host process's state for every "node", which is not what this trace
 * is for. What IS reused, byte-for-byte, is: the public simnet_cluster
 * accessors (tip hash/height, coins digest, delivery fingerprint,
 * byzantine-reject count) already exposed for exactly this kind of
 * inspection, the platform/modules/json library the diagnostics registry itself uses to
 * serialize, and the single canonical hex codec (platform/modules/base/include/base/
 * hex.h). No new fault injection, no new consensus surface, and nothing
 * reachable from a live node.
 *
 * Format: one JSON object per line (NDJSON). One line per (node, event): a
 * single recorded cluster event (a mint, a delivery drain, a partition, a
 * heal) snapshots every node in the cluster, so an N-node cluster writes N
 * lines for that one event. Every line carries "seq" (the caller's
 * monotonically increasing event sequence number — shared by all N lines
 * from the same event), "event" (the short command name that triggered the
 * snapshot), and "node_id", plus nested "chain" (tip_height, tip_hash),
 * "coins" (commitment_hex, utxo_count), and "cluster" (delivery_fingerprint,
 * byzantine_rejected — cluster-wide, so identical across a given event's N
 * lines, included for context).
 */

#ifndef ZCL_SIM_SIMNET_TRACE_H
#define ZCL_SIM_SIMNET_TRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct simnet_cluster;

struct simnet_trace_writer {
    FILE *fp;
    char path[512];
};

/* Opens `path` for appending (created if absent; the parent directory must
 * already exist). Leaves *w zeroed/closed and returns false on any I/O
 * failure or a path >= sizeof(w->path). Safe to call at most once per
 * writer; open an already-open writer is refused. */
bool simnet_trace_writer_open(struct simnet_trace_writer *w,
                              const char *path);

bool simnet_trace_writer_is_open(const struct simnet_trace_writer *w);

/* Snapshot every node in [0, node_count) of `cluster` and append one NDJSON
 * line per node to `w` (flushed before returning). `event` is a short label
 * (e.g. "simnet_mint", "simnet_deliver", "simnet_partition", "simnet_heal");
 * `seq` is the caller's own monotonically increasing counter, carried
 * verbatim into every line this call writes. Returns false on a NULL
 * argument, a closed writer, or any accessor/I/O failure; some lines may
 * already have been appended when this happens (best-effort, matching the
 * rest of the chaos harness's non-transactional artifact writers). */
bool simnet_trace_write_event(struct simnet_trace_writer *w,
                              struct simnet_cluster *cluster,
                              size_t node_count, uint64_t seq,
                              const char *event);

void simnet_trace_writer_close(struct simnet_trace_writer *w);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_TRACE_H */
