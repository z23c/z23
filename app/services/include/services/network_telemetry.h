/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `network` telemetry domain's PROVIDER (docs/TELEMETRY_CONTRACT.md).
 *
 * It fills a typed `struct network_snapshot` and does nothing else: it writes
 * no JSON, decides no health, and names no field in prose. The field names,
 * units, tiers, health rules and meanings all live in exactly one place —
 * util/telemetry/network_fields.def — and the snapshot struct is generated
 * from that table, so a member here cannot drift from the JSON key or the
 * ontology path the renderer will use.
 *
 * WHAT IT COVERS. The aggregate connection posture (connman + peer_lifecycle),
 * the embedded onion service, and what the wire actually negotiated for the
 * Noise transport. It deliberately does NOT enumerate peers: the peer set
 * is unbounded and a fixed-offset table has nowhere to put a list, so per-peer
 * detail stays on `ops state --subsystem=connman` / `--subsystem=transport`.
 *
 * NEVER BLOCKS. The one lock it reaches for — the connection manager's node
 * array — is taken with a TRYlock; on contention the leaves behind it are
 * recorded UNAVAILABLE with a static reason token rather than left at their
 * zero value or omitted. No database is opened and no unbounded scan runs.
 *
 * CONTEXT SENSITIVITY, stated because it changes how the reply reads: this is
 * an IN-PROCESS collector. Run inside the node it reports live values. Run in
 * a one-shot CLI process there is no connection manager and no Tor thread, so
 * every live leaf is UNAVAILABLE with the reason `node_not_in_process`. That
 * is a truthful "we could not read it here", which the render layer folds to
 * health `unknown` — never a plausible zero and never a claim that the node
 * is down.
 */
#ifndef ZCL_SERVICES_NETWORK_TELEMETRY_H
#define ZCL_SERVICES_NETWORK_TELEMETRY_H

#include "util/telemetry_snapshots.h"

#include <stdbool.h>

/* Fill every leaf of `snap`. The caller owns the snapshot and MUST
 * zero-initialise it (`struct network_snapshot s = {0};`) so any leaf this
 * provider forgot renders as a counted provider_defect rather than a zero.
 *
 * Returns false only on a NULL argument: an unreadable subsystem is reported
 * per-leaf, not as a failed call — a provider that failed wholesale would tell
 * the reader nothing about WHICH part of the network stack was unreadable.
 * Reentrant; safe before boot and from any thread. */
bool network_dump_state_fill(struct network_snapshot *snap);

#endif /* ZCL_SERVICES_NETWORK_TELEMETRY_H */
