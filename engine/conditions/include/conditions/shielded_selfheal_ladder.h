/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_selfheal_ladder — the sovereign, auto-executing 3-rung self-heal
 * ladder for the NAMED-REMEDY shielded-history gap (a genuine below-cursor
 * historical anchor gap and/or a standalone nullifier gap), factored out of the
 * sapling_anchor_frontier_unavailable condition so the ladder stays a small,
 * self-contained TU.  Every rung RE-DERIVES proven state (Rung A) or
 * CHECKPOINT-verifies (Rung B) or NAMES the exact need (Rung C); none forges,
 * borrows-unverified, or relaxes a consensus check.
 *
 * STRUCTURAL SEPARATION: this TU NEVER includes shielded_history_import_service.h
 * and NEVER references -import-complete-shielded, so the sovereign auto path
 * physically cannot run the BORROWED import — that verb keeps its own owner-gate
 * (shielded_gap_remedy_eval_containment / auto_execute), untouched.  The public
 * rung-selection, sovereign-authorization, and named-need helpers are declared
 * in conditions/sapling_anchor_frontier_unavailable.h (shared with the condition
 * + its hermetic tests); this header is the condition<->ladder driver seam. */
#ifndef ZCL_CONDITIONS_SHIELDED_SELFHEAL_LADDER_H
#define ZCL_CONDITIONS_SHIELDED_SELFHEAL_LADDER_H

#include "framework/condition.h" /* enum condition_remedy_result */

#include <stdbool.h>
#include <stdint.h>

/* Run the ladder for the NAMED-REMEDY class (Rungs A/B/C).  Returns
 * COND_REMEDY_OK when a rung acted/armed (the condition's witness — blocker
 * cleared + H* climbed — confirms the real clear; while a multi-round heal is in
 * flight the .progressing hook keeps the attempt budget alive), COND_REMEDY_
 * FAILED when it could only name the need (Rung C) so the bounded page fires, or
 * COND_REMEDY_SKIP when the store/state is not wired this tick. */
enum condition_remedy_result shielded_selfheal_run_named_remedy(void);

/* .progressing hook body.  named_episode gates it to the NAMED-REMEDY class (the
 * birth-defect tiers clear purely on the H* witness).  Returns true — resetting
 * the attempt budget WITHOUT clearing — only while the durable heal cursor
 * advances, re-snapshotting the baseline; a frozen cursor returns false so the
 * budget still exhausts and pages in bounded time. */
bool shielded_selfheal_progressing(bool named_episode);

/* The exact first-missing body/artifact height Rung C last named (-1 = none). */
int64_t shielded_selfheal_last_named_height(void);

/* Reset the ladder's per-episode state (progress baseline + named height).
 * Called at each named-remedy rising edge and by the test reset. */
void shielded_selfheal_reset_episode(void);

#endif /* ZCL_CONDITIONS_SHIELDED_SELFHEAL_LADDER_H */
