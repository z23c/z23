/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * metaverse_telemetry — the collector behind the `metaverse` telemetry domain.
 *
 * WHAT IT COLLECTS, AND WHAT IT DELIBERATELY DOES NOT. Sovereign digital
 * property is directory-scoped and node-free: the catalog is a projection
 * rebuilt at call time over a directory the CALLER names, and the confined
 * agent broker is a separate process whose state lives in a broker directory.
 * There is therefore no ambient node state to sample here, and this collector
 * TAKES NO PATH — not an argument, and emphatically not a default. A read
 * surface that defaults a datadir reads (and, in this repository's history,
 * writes) the operator's live node; the only safe answer to "which directory"
 * is the one the caller supplied on the command that wants an inventory.
 *
 * What is left after that exclusion is real and is the part an operator needs
 * first: the compiled-in property-kind vocabulary and which of its kinds have
 * a read adapter wired. That is what makes an empty inventory readable — an
 * unwired kind and a kind that owns nothing produce the same empty page, and
 * only this answer separates them.
 *
 * COST AND CONCURRENCY. Every value comes from static const data in
 * contexts/commons/modules/metaverse/src/adapter_registry.c through the public accessors. No lock,
 * no allocation, no syscall, no I/O, bounded by METAVERSE_KIND_COUNT. Safe on
 * any thread, at any time, including before boot.
 */

#ifndef ZCL_SERVICES_METAVERSE_TELEMETRY_H
#define ZCL_SERVICES_METAVERSE_TELEMETRY_H

#include <stdbool.h>

struct metaverse_snapshot;

/* Fill every leaf of a zero-initialized `struct metaverse_snapshot`.
 *
 * The caller owns `snap` and MUST zero it first (`= {0}`): every leaf then
 * starts at TELEMETRY_UNSET, so a field this collector forgot renders as a
 * counted provider defect rather than a plausible zero.
 *
 * Returns false only on a NULL `snap`. Every other outcome is expressed in
 * the snapshot itself — a value that could not be established is set
 * UNAVAILABLE with a static reason token, never omitted and never zeroed. */
bool metaverse_dump_state_fill(struct metaverse_snapshot *snap);

#endif /* ZCL_SERVICES_METAVERSE_TELEMETRY_H */
