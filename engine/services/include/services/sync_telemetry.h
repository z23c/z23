/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_telemetry — the `sync` domain's typed snapshot PROVIDER.
 *
 * One job, and only one: fill a `struct sync_snapshot` from the reducer
 * frontier and the stage ladder. It writes no JSON, names no JSON key and
 * decides no health. Every field name in the domain is spelled once, as a
 * TL_LEAF row in platform/modules/util/include/util/telemetry/sync_fields.def; the struct
 * member, the JSON key, the ontology path and the leaf id are all expansions
 * of that one token. See docs/TELEMETRY_CONTRACT.md for the four layers.
 *
 * THE COLLECTOR NEVER BLOCKS. It runs on whatever native/RPC thread asked for
 * the reply, while the reducer fold may own progress_store_tx_lock around a
 * bulk batch. A blocking acquire here would queue the operator surface behind
 * the fold and make `ops telemetry sync` disappear exactly when the node is
 * busiest — the "RPC-dark under load" defect class. Every read is therefore a
 * lock-free atomic, and the single durable read goes through
 * progress_store_tx_trylock(); losing that race reports the affected leaves
 * UNAVAILABLE with the static reason `progress_store_busy`, never a stale or
 * zero value. Enforced by tools/scripts/check_dumper_never_blocks.sh, which
 * scans `*_dump_state_fill` bodies exactly as it scans `*_dump_state_json`.
 *
 * Reentrant. Allocates nothing. Callable before boot and during shutdown: it
 * dereferences no node object, only published scalars.
 */
#ifndef ZCL_SERVICES_SYNC_TELEMETRY_H
#define ZCL_SERVICES_SYNC_TELEMETRY_H

#include <stdbool.h>

struct sync_snapshot;

/* Fill every leaf of `snap`. The caller owns the storage and MUST
 * zero-initialize it (`struct sync_snapshot s = {0};`) so any leaf this
 * provider forgot starts at TELEMETRY_UNSET and renders as a counted
 * provider defect rather than a plausible 0.
 *
 * Postcondition on success: NO leaf is left UNSET. A value that could not be
 * read is written as UNAVAILABLE (or NOT_APPLICABLE, where the value is
 * meaningless rather than unread) with a static reason token — never omitted
 * and never left at its zero value.
 *
 * Returns false only on a NULL `snap`. There is no partial-failure return:
 * every per-leaf failure is expressed as that leaf's presence, which is the
 * whole point of the typed snapshot. */
bool sync_dump_state_fill(struct sync_snapshot *snap);

#endif /* ZCL_SERVICES_SYNC_TELEMETRY_H */
