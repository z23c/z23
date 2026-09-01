/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_compile_offline — compose a zcl.rom_compile.v1-shaped `state` body for a
 * FOREIGN producer datadir, entirely READ-ONLY and WITHOUT a running node. It
 * mirrors the shape engine/jobs/src/rom_compile_status.c produces on a live node,
 * so the same pure renderer (rom_compile_render_ascii) draws it, but sources its
 * fields from on-disk artifacts of an offline `-mint-anchor` producer:
 *
 *   fold height/target/rate/eta  — consensus_state_producer_status_read()
 *                                  (READONLY kernel store — consensus.db, or
 *                                  the legacy progress.kv on a pre-flip
 *                                  datadir; ENOENT = idle, not an error) +
 *                                  the compiled SHA3 checkpoint height.
 *   sealed_history layer          — chain_segment_store_stat(<datadir>/segments).
 *   the eight stage EWMAs + the   — tail-parsed from <datadir>/mint-progress.log
 *   bottleneck + commit EWMA        ('stages=[ha:.. vh:.. ...]' EWMAs). A
 *                                   missing/malformed log yields zeroed EWMAs,
 *                                   never an error.
 *
 * Node-only layers (state-seal ring, delta frontier, tip ring, bundle export)
 * are reported absent with a note — they have no on-disk projection a foreign
 * reader can trust without the running reducer. NEVER writes to `datadir`. */

#ifndef ZCL_TOOLS_ROM_COMPILE_OFFLINE_H
#define ZCL_TOOLS_ROM_COMPILE_OFFLINE_H

#include <stdbool.h>
#include <stddef.h>

struct json_value;

/* Fill `out` (json_init'd by the caller) with a zcl.rom_compile.v1 `state`
 * object for `datadir`. Returns false and writes a bounded reason into `err`
 * only on a hard failure (null out, empty/oversized datadir, or an
 * unreadable-but-present kernel store). Absent artifacts (no kernel store, no
 * segments, no progress log) are honest "idle/absent" fields, not errors. */
bool rom_compile_offline_compose(const char *datadir, struct json_value *out,
                                 char *err, size_t errlen);

#endif /* ZCL_TOOLS_ROM_COMPILE_OFFLINE_H */
