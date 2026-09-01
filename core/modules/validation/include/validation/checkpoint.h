/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint — hard reorg-depth invariant.
 *
 * ZCL_FINALITY_DEPTH (=10) is the sync trust boundary. Blocks at or
 * below tip - 10 are immutable for steady-state reorg refusal,
 * snapshot activation, and rolling-anchor policy. COINBASE_MATURITY is
 * an economic spend rule and must not drive sync finality decisions.
 *
 * checkpoint enforces the invariant at every fork-point walk, not just
 * the extending-reorg branch — a single call site leaves the other
 * fork-point walks free to walk past tip - 10 before any cycle guard
 * would catch it.
 *
 * `reorg_is_allowed` remains the compatibility wrapper for callers
 * that predate validation/sync_evidence_policy.h. */

#ifndef ZCL_VALIDATION_CHECKPOINT_H
#define ZCL_VALIDATION_CHECKPOINT_H

#include <stdbool.h>

/* Return true iff a reorg from `tip_h` whose deepest disconnected
 * block is at `target_fork_h` is permitted. `target_fork_h` is the
 * HEIGHT of the fork point — the highest block both chains share.
 * The disconnected depth is therefore `tip_h - target_fork_h`.
 *
 * If false, `*reason_out` (if non-NULL) is set to a static string
 * describing why. The pointer is owned by this module and must not
 * be freed by the caller.
 *
 * Semantics:
 *   tip_h - target_fork_h <= ZCL_FINALITY_DEPTH → allowed
 *   tip_h - target_fork_h >  ZCL_FINALITY_DEPTH → refused
 *
 * The function does not log — callers decide whether to emit a
 * stderr line or an event when refusing. */
bool reorg_is_allowed(int tip_h, int target_fork_h,
                      const char **reason_out);

/* Convenience: returns true iff `h` is at or below the immutable
 * height, tip_h - ZCL_FINALITY_DEPTH. */
bool height_is_immutable(int tip_h, int h);

#endif /* ZCL_VALIDATION_CHECKPOINT_H */
