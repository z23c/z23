/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * segment_corruption condition — public registration + directory-scoped pure
 * helpers for the sealed-ROM-segment integrity healer (detect a corrupt sealed
 * segment via a bounded round-robin SHA3 spot-verify, unlink + rebuild the
 * manifest so reads fall back to blk*.dat, witness that the range is clean). */

#ifndef ZCL_CONDITIONS_SEGMENT_CORRUPTION_H
#define ZCL_CONDITIONS_SEGMENT_CORRUPTION_H

#include "storage/chain_segment.h"

#include <stddef.h>
#include <stdint.h>

/* SYMPTOM: a sealed ROM segment under <datadir>/segments fails its SHA3 digest
 *   verification (whole-segment digest on open, or a per-block digest). A
 *   corrupt segment can never serve wrong bytes — block_parse_cache re-checks
 *   the per-block SHA3 and falls back to blk*.dat — so this is an integrity
 *   healer, not a consensus halt: the symptom is "the fold lost its fast IO
 *   substrate for a range and is silently paying the blk*.dat path".
 * DETECT: a bounded round-robin spot-verify — ONE segment per poll — via
 *   chain_segment_store_verify_index (re-opens + re-hashes it from disk).
 * REMEDY: unlink the corrupt seg-<first>-<count>.dat and rebuild the manifest
 *   so the store drops it (read-correctness restored immediately via the
 *   blk*.dat fallback); the segment sealer re-seals the range from disk. If the
 *   authoritative blk*.dat body is ALSO unreadable, the height-agnostic body
 *   refetch primitive (clear HAVE_DATA → re-emit → dl_queue_priority, wrapped by
 *   sync_monitor_queue_active_frontier_body) re-downloads it.
 * WITNESSED: no sealed segment covering the corrupt range verifies-corrupt (it
 *   is gone or has been re-sealed clean).
 * COND_WARN; poll_secs 30 (bounded sweep), backoff 60s, max_attempts 3. */
void register_segment_corruption(void);

/* ── Pure helpers (directory-scoped; no node state) ──────────────────────
 * Exposed so the detect/remedy flow can be exercised on a fixture segments dir
 * without a running node (the network-refetch seam is the only node-coupled
 * part, and it is skipped when there is no main_state). */

/* Verify the segment at round-robin index (*cursor mod segment_count) in `dir`,
 * advancing *cursor. Fills first/count with the probed segment's covered
 * range. Returns that segment's verify status: CSEG_OK when it is clean, a
 * digest/format/io error when it is corrupt, or CSEG_ERR_NOT_FOUND when the
 * store is empty. */
enum cseg_status segment_corruption_scan_one(const char *dir, uint32_t *cursor,
                                             uint32_t *first, uint32_t *count,
                                             char *err, size_t errlen);

/* Repair a corrupt sealed segment: unlink seg-<first>-<count>.dat and rebuild
 * the manifest from the survivors. Returns CSEG_OK when the file is gone. */
enum cseg_status segment_corruption_repair(const char *dir, uint32_t first,
                                           uint32_t count,
                                           char *err, size_t errlen);

#endif /* ZCL_CONDITIONS_SEGMENT_CORRUPTION_H */
