/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * header_corroboration — LOCAL-POLICY multi-peer corroboration for best-header
 * SWITCH adoption (eclipse resistance).
 *
 * This is NOT a consensus validity rule (it never changes what constitutes a
 * valid chain, header, or block — E13 parity is untouched). It governs only
 * whether WE locally adopt a *reorg of the header tree* — a switch to a
 * different branch than our current best-header tip, deeper than
 * HEADER_CORROBORATION_MIN_SWITCH_DEPTH blocks — before at least two peers from
 * distinct address groups have announced/served the new branch. Plain tip
 * EXTENSION of the current chain (the normal-sync case) is never gated. Forks
 * at or below a compiled checkpoint are exempt: the checkpoint already binds
 * that history with something stronger than corroboration.
 *
 * Threat closed: a single fast-feeding peer (or an eclipse set sharing one
 * address group) steering our best-header selection onto a fake most-work
 * branch during sync. An un-corroborated switch is HELD (not adopted, peer NOT
 * banned, candidate stays in the header tree) and surfaced as the transient
 * blocker chain.reorg_uncorroborated; it auto-clears the instant a second
 * distinct group corroborates the branch, or the branch is abandoned.
 */

#ifndef ZCL_NET_HEADER_CORROBORATION_H
#define ZCL_NET_HEADER_CORROBORATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/arith_uint256.h"

struct uint256;
struct block_index;

/* Reorg depth (blocks below the current best-header tip that the fork point
 * sits) beyond which a SWITCH requires corroboration. Shallow competing tips
 * near the tip are normal and are never gated. */
#define HEADER_CORROBORATION_MIN_SWITCH_DEPTH 6

/* Runtime enable. Default ON; -nocorroborate flips it OFF for single-peer lab
 * setups. */
void header_corroboration_set_enabled(bool enabled);
bool header_corroboration_enabled(void);

/* Record that a peer in address-group `group` (`group_len` bytes, as produced
 * by net_addr_get_group) announced/served header `hash`. Thread-safe; the
 * backing store is a bounded direct-mapped cache, so the same hash from two
 * peers always accumulates into the same slot. Onion and clearnet peers carry
 * distinct group keys and therefore count as distinct groups. */
void header_corroboration_note(const struct uint256 *hash,
                               const unsigned char *group, size_t group_len);

/* Distinct address groups that have vouched for `hash` (>= 2 == corroborated).
 * Returns 0 for an unknown or NULL hash. */
int header_corroboration_groups(const struct uint256 *hash);

enum header_corroboration_gate {
    HEADER_CORROBORATION_ALLOW = 0, /* adopt `candidate` as best header */
    HEADER_CORROBORATION_HOLD  = 1, /* deep un-corroborated switch — hold */
};

/* Decide whether adopting `candidate` as the new best header is permitted.
 *
 *   ALLOW  — plain extension, a shallow (<= MIN_SWITCH_DEPTH) switch, a
 *            checkpoint-covered fork, a corroborated switch, a candidate that
 *            is not strictly better than `current`, or corroboration disabled.
 *   HOLD   — a strictly-better switch deeper than MIN_SWITCH_DEPTH, above the
 *            checkpoint, that no second distinct group has yet corroborated.
 *
 * `current` is the current best-header tip (may be NULL — then always ALLOW).
 * `checkpoint_last_height` exempts forks whose fork point is at/below it.
 * `peer_group`/`peer_name` identify the peer offering the candidate (recorded
 * in the hold facts for the condition surface; may be NULL).
 *
 * Side effects: on HOLD, refreshes the single transient hold record (fork
 * height, work delta, peer). On ALLOW that resolves or moots the current hold,
 * clears it. Never bans, never mutates the block index. */
enum header_corroboration_gate header_corroboration_gate_switch(
    const struct block_index *current,
    const struct block_index *candidate,
    int checkpoint_last_height,
    const unsigned char *peer_group, size_t peer_group_len,
    const char *peer_name);

/* Snapshot of the currently-held un-corroborated switch (for the condition +
 * diagnostics). Returns false (and zeroes `out`) when nothing is held. */
struct header_corroboration_hold {
    bool     active;
    int      fork_height;
    int      candidate_height;
    int      current_height;
    int      switch_depth;
    char     work_delta_hex[65];
    char     candidate_tip_hex[65];
    char     peer_name[64];
    int64_t  raised_unix;
};
bool header_corroboration_hold_get(struct header_corroboration_hold *out);

/* True iff a switch is currently held (cheap; no copy). */
bool header_corroboration_hold_active(void);

#ifdef ZCL_TESTING
/* Full reset of the corroboration store + hold state + enable flag (ON). */
void header_corroboration_test_reset(void);
#endif

#endif /* ZCL_NET_HEADER_CORROBORATION_H */
