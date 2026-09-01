/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_auto_reindex — durable, bounded "self-rebuild" request for crash-only
 * recovery. When boot's post-restore integrity gate detects the
 * reindex-recoverable shape (a derived tip ABOVE the on-disk validated index
 * extent: zero_nbits==0, holes only above the index, no structural nBits
 * corruption), it records a request that the NEXT boot consumes to set
 * -reindex-chainstate — which rewinds to the consistent reindex target and
 * rebuilds the UTXO set from blocks/. This is the crash-only primitive: the
 * node throws away inconsistent derived state and re-derives it, instead of
 * FATAL-ing or surgically repairing.
 *
 * The request is bounded per anchor-height episode so a genuinely corrupt
 * blocks/ pages the operator instead of looping, and is fsync-durable so the
 * budget survives a crash mid-rebuild. File: <datadir>/auto_reindex_request —
 * a top-level sentinel that is NEVER part of any derived-state wipe set.
 */

#ifndef ZCL_STORAGE_BOOT_AUTO_REINDEX_H
#define ZCL_STORAGE_BOOT_AUTO_REINDEX_H

#include <stdbool.h>
#include <stdint.h>

/* Max reindex attempts per anchor-height episode before pausing for the
 * operator (a genuinely corrupt blocks/ must page, not loop). */
#define BOOT_AUTO_REINDEX_MAX 3

/* Terminal-marker count: a sentinel rewritten in place of the attempt count
 * once the budget is EXHAUSTED at a stable anchor. It means "the operator was
 * paged; do NOT request another reindex on this datadir" — the request stays on
 * disk (it is NOT deleted) so the next boot reads the terminal marker and
 * refuses to re-arm a fresh count=1 (which is what produced the unbounded
 * crash-loop the chain_tip_watchdog model avoids by persisting exhaustion). */
#define BOOT_AUTO_REINDEX_TERMINAL (-1)

/* Record a self-rebuild request keyed on `anchor` (the wedged tip height).
 * If the on-disk request already names this anchor its count is incremented;
 * a DIFFERENT, LOWER anchor (a partial replay leaves a different tip each boot)
 * does NOT reset the count — the budget keys on the MINIMUM anchor seen this
 * episode so a moving tip cannot re-arm the cap. A first request at a strictly
 * HIGHER anchor (a genuinely new wedge after the old one cleared) starts fresh.
 * If the on-disk request is the TERMINAL marker, the budget is already
 * exhausted: this is a no-op that returns BOOT_AUTO_REINDEX_TERMINAL so the
 * caller does NOT re-arm. fsync-durable. Returns the new attempt count (>=1),
 * BOOT_AUTO_REINDEX_TERMINAL if already terminal, or 0 on a write error. */
int boot_auto_reindex_request(const char *datadir, int32_t anchor);

/* True iff a self-rebuild request is on disk AND it is not the terminal marker
 * — boot consumes it to set -reindex-chainstate before the coins-integrity gate
 * runs. A terminal marker is present-but-not-pending: the budget is spent. */
bool boot_auto_reindex_pending(const char *datadir);

/* Read the durable marker for diagnostics/guards. Returns true iff the marker
 * is well-formed. `count == BOOT_AUTO_REINDEX_TERMINAL` means exhausted; a
 * positive count means pending; zero/no marker returns false. */
bool boot_auto_reindex_status(const char *datadir, int32_t *anchor,
                              int *count);

/* True iff the on-disk request is the TERMINAL marker (count == -1): the budget
 * was exhausted at a stable anchor, the operator was paged, and no further
 * reindex must be requested. */
bool boot_auto_reindex_is_terminal(const char *datadir);

/* Rewrite the on-disk request as the TERMINAL marker for `anchor` (count = -1),
 * fsync-durable. Called when the bounded budget is exhausted: it PERSISTS the
 * exhausted state (rather than deleting the sentinel, which would let the next
 * boot re-arm a fresh count=1 and loop forever). Returns true on success. */
bool boot_auto_reindex_mark_terminal(const char *datadir, int32_t anchor);

/* Clear the request once the node boots to a clean post-restore integrity
 * state (the rebuild converged). NOTE: budget exhaustion no longer clears —
 * it rewrites the terminal marker via boot_auto_reindex_mark_terminal() so the
 * next boot does not re-arm. */
void boot_auto_reindex_clear(const char *datadir);

#endif /* ZCL_STORAGE_BOOT_AUTO_REINDEX_H */
