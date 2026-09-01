/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `storage` telemetry domain's collector — the provider half of the
 * table-driven telemetry layer (util/telemetry_render.h) for on-disk state:
 * the SQLite stores, the block index, and disk headroom.
 *
 * Division of labour. This file's job is to FILL a typed snapshot. It writes
 * no JSON and decides no health: the field table
 * (util/telemetry/storage_fields.def) owns every field name, unit, tier and
 * health rule, and platform/modules/util/src/telemetry_render.c owns the document and the
 * verdict. A collector that hand-writes a telemetry key fails
 * check-telemetry-ontology, which is the precise regression that gate exists
 * for.
 *
 * COST CONTRACT, and it is the whole reason this collector looks the way it
 * does. It runs on the RPC/native thread, and the one moment an operator asks
 * a storage question is the moment the node is busiest. So:
 *
 *   - no SQL. Not one statement. Every value is either an O(1) published
 *     counter, an atomic, or a struct copy under a lock held for microseconds.
 *   - no COUNT(*), not even an "it's only a few rows" one. `SELECT COUNT(*)
 *     FROM block_index` is several million rows on a node at tip, which is
 *     exactly why block_index_projection's dumper is NOT one of the sources
 *     read here.
 *   - no blocking acquire of a lock a long operation can hold. The
 *     db_maintenance state is read through that service's own trylocking
 *     dumper, because a VACUUM owns its mutex for minutes; a lost race is
 *     reported as UNAVAILABLE with a static reason, never as a zero.
 *
 * A field that could not be read this cycle is never left at its zero value
 * and never omitted — it is marked unavailable with a greppable reason token,
 * which the render layer turns into a JSON null judged `unknown`.
 *
 * Layering: reads other subsystems' published snapshots. Opens nothing, and
 * in particular opens no database of its own — a read-only open in this tree
 * has previously leaked write-ahead-log sidecars and served an immutable
 * stale snapshot with no error, so every handle used here belongs to the
 * model that owns it.
 */
#ifndef ZCL_SERVICES_STORAGE_TELEMETRY_H
#define ZCL_SERVICES_STORAGE_TELEMETRY_H

#include "util/telemetry_snapshots.h"

#include <stdbool.h>

/* Fill `snap` from the storage subsystems' published state.
 *
 * `snap` MUST be zero-initialized by the caller (`= {0}`): that is what starts
 * every leaf at TELEMETRY_UNSET, which is the provider-defect signal the
 * render layer counts. This function sets a presence for every leaf in the
 * table on every path, so a surviving UNSET is a bug in this file and the
 * owning test asserts there are none.
 *
 * Returns false only on a NULL argument. A subsystem that could not be read is
 * a successful fill with unavailable leaves, not a failure — the whole point
 * of the presence plane is that partial truth still gets reported. */
bool storage_dump_state_fill(struct storage_snapshot *snap);

/* `z23 ops state --subsystem=storage_telemetry` and the RPC behind
 * `ops.telemetry.storage.*`: fill, then render at the view `key` names.
 *
 * `key` is passed to telemetry_view_parse: NULL/"" (normal), "summary",
 * "normal", "full", or a group name for that group at full detail. An
 * unrecognized key renders normal and says so rather than guessing.
 *
 * See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool storage_telemetry_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_STORAGE_TELEMETRY_H */
