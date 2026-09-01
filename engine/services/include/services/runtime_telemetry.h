/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `runtime` telemetry domain's provider: supervisor tree, supervisor
 * threads, CPU topology and memory posture, collected into the typed snapshot
 * that util/telemetry_render.h renders.
 *
 * WHERE THE VALUES COME FROM, and why it is not a direct in-process read.
 * A native command handler runs in the CLI process, not in the node. Calling
 * supervisor_child_count_total() here would return 0 — a true statement about
 * the wrong process, and exactly the plausible-looking empty answer this layer
 * exists to make impossible. So the collector asks the RUNNING node, over the
 * same `dumpstate` JSON-RPC surface `ops state` uses, and fills the snapshot
 * from the reply. Four subsystems are read: supervisor, cpu_topology,
 * mem_pressure, hw_profile.
 *
 * Reading four dumps on every call is deliberate even though each command
 * shows one group: `completeness` in the rendered document is a property of
 * the whole snapshot, so a collector that filled only the caller's group would
 * report every other leaf as a provider defect.
 *
 * WHAT IT NEVER DOES. It writes no JSON (the render layer owns that and a lint
 * gate proves it), decides no health (the field table's rules do), and takes no
 * lock — the only blocking it can do is the bounded RPC round trip, which lands
 * on the node's RPC thread where the dumpers are already proven non-blocking.
 *
 * Layering: an app-side collector over the diagnostics surface. Touches no
 * consensus state and no database.
 */
#ifndef ZCL_SERVICES_RUNTIME_TELEMETRY_H
#define ZCL_SERVICES_RUNTIME_TELEMETRY_H

#include <stdbool.h>

struct runtime_snapshot; /* util/telemetry_snapshots.h */

/* Fill `snap` — which the CALLER must have zero-initialized, so that any leaf
 * this function forgets renders as a counted provider defect rather than a
 * plausible zero.
 *
 * Returns false ONLY when the node could not be reached at all; `*why` then
 * receives a static reason token ("node_unreachable", "snapshot_null"). The
 * caller fails the command closed in that case rather than returning a
 * document in which every leaf is unavailable — a total loss is a transport
 * failure, not telemetry.
 *
 * Returns true for a partial read: a subsystem whose dump was missing or
 * malformed leaves ITS leaves at presence UNAVAILABLE with a static reason,
 * and `completeness` in the rendered document states the totals.
 *
 * Reentrant. Allocates only transiently for the RPC replies. */
bool runtime_dump_state_fill(struct runtime_snapshot *snap, const char **why);

#endif /* ZCL_SERVICES_RUNTIME_TELEMETRY_H */
