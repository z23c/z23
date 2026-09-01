/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared one-shot repair_marker helpers for reducer-frontier helpers. Each
 * one-shot marker is keyed (kind, height, block_hash) in the repair_marker
 * table; the kind is a per-repair constant
 * (REPAIR_MARKER_KIND_RF_PROOF_REPLAY / _RF_TIPFIN_BACKFILL). */

#include "stage_repair_reducer_frontier_internal.h"

#include "core/uint256.h"
#include "storage/repair_marker.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdbool.h>

bool stage_reducer_frontier_repair_marker_seen(
    sqlite3 *db,
    const char *kind,
    int height,
    const struct uint256 *block_hash,
    const char *label,
    bool *seen)
{
    if (!db || !kind || !block_hash || !seen)
        LOG_FAIL("stage_repair",
                 "[stage_repair] repair marker read NULL input label=%s kind=%s",
                 label ? label : "(null)", kind ? kind : "(null)");

    *seen = false;
    if (!repair_marker_have(db, kind, height, block_hash->data, seen,
                            NULL, 0, NULL))
        LOG_FAIL("stage_repair",
                 "[stage_repair] %s marker read failed kind=%s h=%d",
                 label ? label : "repair", kind, height);
    return true;
}

bool stage_reducer_frontier_repair_marker_record_in_tx(
    sqlite3 *db,
    const char *kind,
    int height,
    const struct uint256 *block_hash,
    const char *label)
{
    if (!db || !kind || !block_hash)
        LOG_FAIL("stage_repair",
                 "[stage_repair] repair marker write NULL input label=%s kind=%s",
                 label ? label : "(null)", kind ? kind : "(null)");

    /* Presence marker: a 1-byte {1} payload preserves the legacy progress_meta
     * value so migrated and freshly-written markers are byte-identical. */
    static const uint8_t present = 1;
    if (!repair_marker_note_in_tx(db, kind, height, block_hash->data,
                                  &present, sizeof(present)))
        LOG_FAIL("stage_repair",
                 "[stage_repair] %s marker write failed kind=%s h=%d",
                 label ? label : "repair", kind, height);
    return true;
}
