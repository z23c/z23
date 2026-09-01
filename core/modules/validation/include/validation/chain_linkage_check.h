/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_linkage_check — fail-loud validation pack: the HOLD latch and the
 * O(1) per-connect linkage checks (pack checks 1 + 2).
 *
 * Why this exists: a header SPLICE can poison the
 * nHeight labels of millions of block-index entries, caught only dozens of
 * blocks later by the contextual coinbase-height check inside script_validate.
 * nHeight is derived from the parent at the cause side; this
 * module is the DETECTOR-side complement: catch any future label
 * divergence at the EARLIEST detectable moment — the very first tip move
 * that touches a mislabeled block — and refuse forward progress LOUDLY.
 *
 * CRASH-ONLY RULE: a firing check NEVER kills the process. It latches a
 * HOLD (this module), registers a typed blocker (util/blocker.h), emits
 * EV_OPERATOR_NEEDED once (dedup via blocker_set rc), and surfaces in
 * `z23 dumpstate validation_pack` and health. FATAL stays reserved for
 * boot integrity.
 *
 * The HOLD latch
 * ---------------
 * One process-wide latch with a small fixed set of holder slots (one per
 * check id). While ANY slot is held, active_chain_move_window_tip refuses
 * tip moves to heights >= the minimum refuse_from height across holders.
 * Moves BELOW the divergence always pass — rewinds, reorg unwinds and
 * operator/window_rebuild repair must be able to run UNDER the hold.
 *
 * WINDOW_REBUILD TRIGGER SEAM (wave 3, designed): the latch + blocker
 * reason carry refuse_from_h (the first refused height). window_rebuild
 * consumes it, rebuilds [refuse_from_h, tip], then calls
 * chain_linkage_hold_clear(check_id) ON WITNESSED success only. Until
 * then: HOLD + PAGE, the operator owns the repair.
 *
 * Hot-path cost: one relaxed atomic load + <=3 integer compares per tip
 * move; zero allocations. The violation path is cold. */

#ifndef ZCL_VALIDATION_CHAIN_LINKAGE_CHECK_H
#define ZCL_VALIDATION_CHAIN_LINKAGE_CHECK_H

#include <stdbool.h>
#include <stdint.h>

struct active_chain;
struct block_index;
struct json_value;

#define CHAIN_HOLD_CHECK_ID_MAX   32
#define CHAIN_HOLD_REASON_MAX    160
#define CHAIN_HOLD_SLOTS           4

/* Latch a HOLD: refuse tip moves to heights >= refuse_from_h until
 * chain_linkage_hold_clear(check_id). Re-latching the same check_id
 * updates the slot (keeps the LOWER refuse_from). check_id is one of a
 * small set of stable names ("linkage", "coinbase_label", "window_sweep",
 * "mirror_divergence"). Does NOT register a blocker or emit an event —
 * callers that want the full crash-only action use
 * chain_linkage_hold_raise(). */
void chain_linkage_hold_set(const char *check_id, int refuse_from_h,
                            const char *reason);

/* Full crash-only action in one call: HOLD latch + typed blocker
 * (PERMANENT, owner "validation_pack") + EV_OPERATOR_NEEDED on a fresh
 * blocker write (blocker_set rc==0 — the dedup discipline). `reason` goes
 * into both the blocker reason and the event payload. */
void chain_linkage_hold_raise(const char *check_id, const char *blocker_id,
                              int refuse_from_h, const char *reason);

/* Release one holder slot (and its blocker when raised via _raise). No-op
 * if not held. */
void chain_linkage_hold_clear(const char *check_id);

bool chain_linkage_hold_active(void);

/* Minimum refuse_from height across active holders, or -1 when no hold. */
int chain_linkage_hold_refuse_from(void);

/* Pack check 1 — parent linkage at connect. Called by
 * active_chain_move_window_tip BEFORE the window fill. Returns true =
 * proceed with the move; false = REFUSED (violation latched, or an active
 * hold covers bi->nHeight). O(1), zero allocations on the pass path.
 *
 * Predicate (E13-neutral: an internal label-consistency check on OUR
 * index, never a block-validity rule):
 *   (a) REFUSES: bi->pprev != NULL => bi->pprev->nHeight == bi->nHeight-1
 *       (a label splice surfaces here the first time the spliced
 *        boundary block reaches a tip move — block 1, not block 28);
 *   (b) DIAGNOSTIC: a strict +1 advance whose pprev is not the current
 *       window tip object is COUNTED, not refused — it is either a
 *       legitimate single-move fork switch (active_chain_fill_window
 *       absorbs it by rewriting the window from the pprev walk) or a
 *       splice already refused by (a) at its boundary block; refusing
 *       would false-HOLD routine 1-block reorgs.
 * Rewinds (nHeight <= window height), jumps (> +1: boot seed / catch-up)
 * and genesis installs are covered by csr Steps 4/5, Invariant A and the
 * post-seed linkage gate (check 7). */
bool chain_linkage_check_advance(const struct active_chain *c,
                                 const struct block_index *bi);

/* Counters for the validation_pack state dump. */
uint64_t chain_linkage_violations_total(void);
uint64_t chain_linkage_hold_refusals_total(void);
uint64_t chain_linkage_offtip_switches_total(void);

/* Snapshot of the latch for dumpers (any may be NULL). */
void chain_linkage_hold_snapshot(bool *active, int *refuse_from,
                                 char *check_ids, int check_ids_cap,
                                 char *reason, int reason_cap);

#ifdef ZCL_TESTING
void chain_linkage_reset_for_testing(void);
#endif

#endif /* ZCL_VALIDATION_CHAIN_LINKAGE_CHECK_H */
