/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_telemetry — THE provider for the `zcode` telemetry domain.
 *
 * One collector fills one typed snapshot; it writes no JSON and decides no
 * health. The field names, units, tiers, health rules and meanings all live
 * in platform/modules/util/include/util/telemetry/zcode_fields.def and are written there
 * exactly once; util/telemetry_render.c turns the filled snapshot into the
 * document. See docs/TELEMETRY_CONTRACT.md for the four-layer split.
 *
 * NEVER BLOCKS, and that is a contract not an aspiration. This runs on the
 * native/RPC thread. The package store's own lock is held across CAS file
 * writes and its global lock across the whole crash-recovery open, so the
 * collector reaches the store only through vcs_package_store_try_totals(),
 * which trylocks once and gives up. A lost race renders those leaves
 * unavailable with a static reason token — never a zero, never an omission.
 */
#ifndef ZCL_SERVICES_ZCODE_TELEMETRY_H
#define ZCL_SERVICES_ZCODE_TELEMETRY_H

#include "util/telemetry_snapshots.h"

#include <stdbool.h>

/* Fill `snap` from live node state. The caller owns the snapshot and MUST
 * zero-initialise it (`struct zcode_snapshot s = {0};`) so any leaf this
 * function fails to touch renders as a counted provider defect rather than
 * a plausible zero.
 *
 * Returns false only when `snap` is NULL. Every other outcome — hosting off,
 * store closed, lock contention — is expressed IN the snapshot as a presence
 * plus a static reason, because "the store was busy" is an answer and a
 * failed call is not. */
bool zcode_dump_state_fill(struct zcode_snapshot *snap);

#endif /* ZCL_SERVICES_ZCODE_TELEMETRY_H */
