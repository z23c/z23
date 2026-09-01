/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_finalize_anchor_internal — src-private seam between
 * tip_finalize_stage.c (stage lifecycle + step body) and
 * tip_finalize_anchor.c (trusted anchor/seed cursor alignment), extracted
 * to keep tip_finalize_stage.c under the framework file-size ceiling (E1).
 * engine/jobs/src only — nothing here is public API. */

#ifndef ZCL_JOBS_TIP_FINALIZE_ANCHOR_INTERNAL_H
#define ZCL_JOBS_TIP_FINALIZE_ANCHOR_INTERNAL_H

#include "util/stage.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

/* Owned by tip_finalize_stage.c — the live stage handle (NULL before init /
 * after shutdown). Anchor writes must re-read it at call time, never cache
 * it across calls. */
stage_t *tip_finalize_stage_handle(void);

/* Owned by tip_finalize_stage.c — publish the served authoritative tip
 * (last-advance height + hash) immediately, not only after the next boot. */
void tip_finalize_publish_last_advance(int height, const uint8_t hash[32]);

/* Owned by tip_finalize_anchor.c — align the tip_finalize cursor (and,
 * when anchor_upstream, every upstream stage cursor) to a trusted
 * authority tip at height/hash, writing the durable own-hash anchor row
 * first. require_prior_progress makes the call a no-op on a completely
 * fresh stage (cursor 0, empty log) so init never invents authority.
 *
 * FIX-3 (jump site 2): the cursor write is capped at the tip_finalize_log
 * frontier — a held/rowless span (the 3,135,516 class, manufactured by
 * init_existing_tip / trusted_tip when the restored tip cache is ahead of
 * the cursor) caps the jump and the stage re-finalizes forward instead.
 * The seed exemption is the PRE-INSERT row count (read before the anchor
 * row is written; see stage_anchor.h). Healthy restarts are unchanged:
 * the scan over [cursor, height+1) is covered by the just-ensured anchor
 * row at `height`. */
bool tip_finalize_anchor_cursor_to_authority(sqlite3 *db, int height,
                                             const uint8_t hash[32],
                                             bool anchor_upstream,
                                             bool require_prior_progress,
                                             const char *reason);

#endif /* ZCL_JOBS_TIP_FINALIZE_ANCHOR_INTERNAL_H */
