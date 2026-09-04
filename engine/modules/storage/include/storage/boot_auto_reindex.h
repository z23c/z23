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

/* Why the request was armed. The class is RECORDED IN THE REQUEST FILE because
 * the boot that later decides whether the request is still warranted is a
 * DIFFERENT boot with a different view of the datadir, and without the reason
 * it can only guess. The live failure this exists to stop: boot arms a request
 * because the block index failed its post-restore integrity check (mismatched
 * pprev/height links far below the tip), and the next boot discards that same
 * request because derived coins-best covers the anchor — a judgement about
 * TRANSPARENT COINS that says nothing about block-index links. The request
 * never survives to be consumed, the attempt count never climbs, and the node
 * crash-loops at "attempt 1/3" forever.
 *
 * The class is monotonic: escalating from UNSPECIFIED to INDEX_INTEGRITY
 * sticks for the episode, and a later UNSPECIFIED arming never demotes it. */
enum boot_auto_reindex_reason {
    /* No recorded class: a legacy 2-field request file written before the
     * class existed, the boot-storage episode, or a coins-shaped wedge (a
     * derived tip installed above the validated on-disk index extent with no
     * structural link damage). Coins-best coverage DOES retire these — a
     * hash-verified coins-best at the anchor proves the transparent set is
     * intact and a from-genesis replay would only wipe it. */
    BOOT_AUTO_REINDEX_REASON_UNSPECIFIED = 0,
    /* The block index itself failed its integrity check: active_chain
     * height/pprev MISMATCHES (not merely holes above the extent). Coins-best
     * coverage must NOT retire this — coins-best is derived transparent state
     * and cannot witness a broken link at h=2004318 under a tip at h=3172671.
     * Only an actual reindex (or the bounded budget running out) retires it. */
    BOOT_AUTO_REINDEX_REASON_INDEX_INTEGRITY = 1,
};

/* Human/agent-greppable name for a recorded reason class. Never NULL. */
const char *boot_auto_reindex_reason_name(int reason);

/* Record a self-rebuild request keyed on `anchor` (the wedged tip height).
 * If the on-disk request already names this anchor its count is incremented;
 * a DIFFERENT, LOWER anchor (a partial replay leaves a different tip each boot)
 * does NOT reset the count — the budget keys on the MINIMUM anchor seen this
 * episode so a moving tip cannot re-arm the cap. A first request at a strictly
 * HIGHER anchor (a genuinely new wedge after the old one cleared) starts fresh.
 * If the on-disk request is the TERMINAL marker, the budget is already
 * exhausted: this is a no-op that returns BOOT_AUTO_REINDEX_TERMINAL so the
 * caller does NOT re-arm. fsync-durable. Returns the new attempt count (>=1),
 * BOOT_AUTO_REINDEX_TERMINAL if already terminal, or 0 on a write error.
 *
 * `reason` is an enum boot_auto_reindex_reason recorded alongside the count and
 * folded MONOTONICALLY into the on-disk class (max), so one integrity-class
 * arming in an episode keeps the whole episode protected from the coins-best
 * stale-clear even if a later boot arms it with UNSPECIFIED. */
int boot_auto_reindex_request(const char *datadir, int32_t anchor, int reason);

/* True iff a self-rebuild request is on disk AND it is not the terminal marker
 * — boot consumes it to set -reindex-chainstate before the coins-integrity gate
 * runs. A terminal marker is present-but-not-pending: the budget is spent. */
bool boot_auto_reindex_pending(const char *datadir);

/* Read the durable marker for diagnostics/guards. Returns true iff the marker
 * is well-formed. `count == BOOT_AUTO_REINDEX_TERMINAL` means exhausted; a
 * positive count means pending; zero/no marker returns false. */
bool boot_auto_reindex_status(const char *datadir, int32_t *anchor,
                              int *count);

/* The recorded reason class of the on-disk request, or
 * BOOT_AUTO_REINDEX_REASON_UNSPECIFIED when there is no request, the file is
 * malformed, or it is a legacy 2-field request written before the class
 * existed. Reading a legacy file as UNSPECIFIED is the safe default: it keeps
 * the pre-existing coins-best stale-clear behaviour for requests whose class
 * genuinely is not known. */
int boot_auto_reindex_reason_of(const char *datadir);

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
