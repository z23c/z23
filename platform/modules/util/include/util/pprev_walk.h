/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * pprev_walk_safe — canonical cycle-detecting walk over a pprev chain.
 *
 * The block_index pprev linked list is the most-walked data structure
 * in the node. There are 16+ places in the codebase that traverse it,
 * each with its own (or no) protection against the failure mode
 * "pprev forms a ring after a partial chain restore". A 14-minute
 * silent boot stall in reducer activation came from exactly this — an
 * unbounded walk over a non-monotonic pprev sequence.
 *
 * pprev_walk_safe is the single helper everyone should use. It
 * enforces three invariants on every step:
 *
 *   1. monotonic height — `prev->nHeight < cur->nHeight`. A walk that
 *      sees a non-decreasing height has either hit a cycle or
 *      collided with structurally broken data.
 *   2. hard step cap — `max_steps`, supplied by the caller. Even if
 *      heights are monotonic, a finite cap means we never block the
 *      thread for unbounded time on a single walk.
 *   3. caller-supplied stop predicate — `keep_going(cur, user)`. Walk
 *      continues while this returns true and the above invariants
 *      hold.
 *
 * On invariant violation the helper:
 *   - emits a single `[pprev-walk]` line on stderr naming `call_site`
 *     and the offending height
 *   - increments the static counter exposed by `pprev_walk_violations()`
 *     so tests and observability hooks can assert no violations
 *   - returns NULL, leaving the caller to bail (the standard pattern)
 *
 * Returns: the final node reached when the walk stops normally
 * (the predicate returned false, or pprev hit NULL), or NULL if
 * a cycle/step-cap violation was detected. */

#ifndef ZCL_PPREV_WALK_H
#define ZCL_PPREV_WALK_H

#include <stdbool.h>
#include <stdint.h>

struct block_index;

/* Predicate: return true to keep walking pprev, false to stop here.
 * Called with each block_index encountered, starting at `start`. */
typedef bool (*pprev_walk_pred)(const struct block_index *bi, void *user);

/* Walk pprev from `start` while the predicate returns true.
 * `max_steps` is the hard step cap (must be > 0).
 * `call_site` is a short stable string for diagnostic logging
 * (e.g. "reducer_activation.fork_point"). */
struct block_index *pprev_walk_safe(struct block_index *start,
                                    pprev_walk_pred keep_going,
                                    void *user,
                                    int max_steps,
                                    const char *call_site);

/* Walk pprev until height drops to `stop_height` (exclusive) or
 * pprev becomes NULL. Convenience for the common "walk down to
 * height H" pattern. */
struct block_index *pprev_walk_until_height(struct block_index *start,
                                            int stop_height_exclusive,
                                            int max_steps,
                                            const char *call_site);

/* Walk pprev until the target block_index pointer is reached or
 * pprev becomes NULL. Returns target if found, NULL if not. Used
 * for fork-point detection. */
struct block_index *pprev_walk_until_target(struct block_index *start,
                                            const struct block_index *target,
                                            int max_steps,
                                            const char *call_site);

/* Walk pprev all the way to a node with no pprev (genesis) while
 * counting steps. Returns the depth (number of pprev edges traversed)
 * or -1 if a cycle/step-cap violation was detected. The final node
 * is optionally returned via `out_root` (NULL on violation). */
int pprev_walk_depth(struct block_index *start,
                     int max_steps,
                     const char *call_site,
                     struct block_index **out_root);

/* Number of cycle/cap violations observed since process start.
 * Monotonic counter. Useful for tests + RPC diagnostics. */
uint64_t pprev_walk_violations(void);

#endif /* ZCL_PPREV_WALK_H */
