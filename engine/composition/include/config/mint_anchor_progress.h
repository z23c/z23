/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONFIG_MINT_ANCHOR_PROGRESS_H
#define ZCL_CONFIG_MINT_ANCHOR_PROGRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

struct sha3_utxo_checkpoint;

/* Durable checkpoint-bound marker for the offline -mint-anchor producer. */
#define MINT_ANCHOR_IN_PROGRESS_KEY "mint_anchor_in_progress_v1"
#define MINT_ANCHOR_PRODUCER_LANE_KEY "mint_anchor_producer_lane_v1"

/* Permanently bind a datadir to one offline producer profile. The binding is
 * never cleared when an artifact completes; producer state must cross into a
 * serving datadir only through the verified installer. Pre-lane durable state
 * has no trustworthy mode witness: it may bind only to checkpoint_fold, never
 * be promoted to full. */
bool mint_anchor_producer_lane_bind(sqlite3 *db, bool checkpoint_fold);

/* Refuse a normal serving boot when this is a producer lane or contains an
 * exact non-full success row. `reason` receives an actionable diagnosis. */
bool mint_anchor_normal_boot_allowed(sqlite3 *db, char *reason,
                                     size_t reason_size);

/* Mark that this progress.kv is in the middle of minting the compiled anchor.
 * The blob binds the resume permission to the checkpoint height/count/SHA3, so
 * a future binary with a different checkpoint resets instead of inheriting an
 * unrelated fold. */
bool mint_anchor_progress_mark(sqlite3 *db,
                               const struct sha3_utxo_checkpoint *cp);

/* Clear the marker after the snapshot has been written and hard-verified. */
bool mint_anchor_progress_clear(sqlite3 *db);

/* True iff a valid durable producer lane is already bound and -mint-anchor may
 * resume without resetting to genesis. A current marker must match `cp`; older
 * interrupted mints that predate the marker may be adopted only when
 * refold_in_progress is set and coins_applied_height is a sane genesis..anchor
 * frontier. The lane binder has already forced such legacy state into the
 * checkpoint_fold posture. `applied_through_out` receives
 * coins_applied_height - 1 when known. */
bool mint_anchor_progress_can_resume(sqlite3 *db,
                                     const struct sha3_utxo_checkpoint *cp,
                                     int32_t *applied_through_out,
                                     bool *legacy_adopted_out);

#endif /* ZCL_CONFIG_MINT_ANCHOR_PROGRESS_H */
