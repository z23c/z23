/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_auto_refold — durable, bounded "refold-from-anchor" request. The sibling
 * of boot_auto_reindex for the sticky escalator's DEEPEST rung
 * (STICKY_RUNG_REFOLD_FROM_ANCHOR, fail-safe-architecture.md §1 rung 3 / §4
 * item 5): when the shallower rungs fail-forward on a wedged-but-alive node, the
 * refold rung ARMS this request and triggers a supervised self-respawn; the NEXT
 * boot consumes it to run boot_refold_from_anchor_reset() (LOAD+VERIFY the
 * SHA3-checkpoint-bound anchor UTXO set into coins_kv, then fold ONLY the
 * anchor->tip delta over on-disk bodies). This keeps ONE write path (Law 2): the
 * refold logic stays in boot_refold_from_anchor_reset; this primitive only arms
 * a one-shot flag the boot consumes, so the armed deep rung actually executes
 * without a human step (the §0/§4a defect the reindex rung had — armed for the
 * next boot but nothing ever restarted a deterministic stall).
 *
 * Bounded per anchor-height episode so a genuinely broken/absent anchor artifact
 * PAGES the operator instead of FATAL-crash-looping (boot_refold_from_anchor_
 * reset _exit()s on a mismatch), and fsync-durable so the budget survives a
 * crash mid-refold. The attempt count increments at CONSUME (boot) time — not at
 * arm time — precisely because a FATAL-exit never runs the rung again, so the
 * boots-that-attempt-the-refold are what must be counted. File:
 * <datadir>/auto_refold_request — a top-level sentinel, NEVER part of any
 * derived-state wipe set.
 */

#ifndef ZCL_STORAGE_BOOT_AUTO_REFOLD_H
#define ZCL_STORAGE_BOOT_AUTO_REFOLD_H

#include <stdbool.h>
#include <stdint.h>

/* Max refold-from-anchor attempts per anchor episode before pausing for the
 * operator (a genuinely broken anchor artifact must page, not loop). */
#define BOOT_AUTO_REFOLD_MAX 3

/* Terminal-marker attempt count: the budget is EXHAUSTED at a stable anchor; the
 * operator was paged. The request stays on disk (NOT deleted) so the next boot
 * reads the terminal marker and does NOT re-arm a fresh attempt. */
#define BOOT_AUTO_REFOLD_TERMINAL (-1)

/* Arm a refold-from-anchor request keyed on `anchor` (the checkpoint height the
 * refold will re-seed to). Idempotent while pending: an already-armed request at
 * the SAME anchor is left untouched (attempts are only ever bumped at consume
 * time). A TERMINAL marker is a no-op that returns BOOT_AUTO_REFOLD_TERMINAL so
 * the rung does NOT re-arm the exhausted budget. fsync-durable. Returns 1 when
 * (freshly) armed, the current attempt count when already pending,
 * BOOT_AUTO_REFOLD_TERMINAL if terminal, or 0 on a write error. */
int boot_auto_refold_request(const char *datadir, int32_t anchor);

/* True iff a refold request is on disk AND it is not the terminal marker — the
 * escalator rung HOLDS (does not re-arm) while pending, and the next boot
 * consumes it. A terminal marker is present-but-not-pending: budget spent. */
bool boot_auto_refold_pending(const char *datadir);

/* Boot-time consume: read the marker, and if a refold should run THIS boot,
 * increment the attempt count (fsync-durable) and return true. Returns false —
 * and rewrites the marker as TERMINAL — when the bounded budget is already spent
 * (attempts >= BOOT_AUTO_REFOLD_MAX), so a persistently-failing anchor stops
 * FATAL-looping and the node boots normally (the escalator then pages). Absent
 * marker / terminal marker → false with no refold. */
bool boot_auto_refold_consume(const char *datadir);

/* Read the durable marker for diagnostics/guards. Returns true iff well-formed.
 * `count == BOOT_AUTO_REFOLD_TERMINAL` means exhausted; count >= 0 means armed
 * (0 = armed-not-yet-attempted); no/absent marker returns false. */
bool boot_auto_refold_status(const char *datadir, int32_t *anchor, int *count);

/* True iff the on-disk request is the TERMINAL marker: the budget was exhausted
 * at a stable anchor and the operator was paged; the rung must go deeper / cycle
 * rather than re-arm. */
bool boot_auto_refold_is_terminal(const char *datadir);

/* Clear the request once a boot has consumed it and the refold reset committed
 * (the destructive coins re-seed + verify succeeded). Budget exhaustion does NOT
 * clear — boot_auto_refold_consume rewrites the terminal marker so the next boot
 * does not re-arm. Idempotent. */
void boot_auto_refold_clear(const char *datadir);

#endif /* ZCL_STORAGE_BOOT_AUTO_REFOLD_H */
