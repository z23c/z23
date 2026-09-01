/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Condition `body_history_unproven` — the node cannot prove it holds the
 * block bodies for its own history.
 *
 * It fires on BOTH disqualifying states, and the distinction is carried in
 * the blocker text rather than collapsed:
 *
 *   BODY_HISTORY_INCOMPLETE  the census probed heights below the tip and
 *                            found bodies missing (count + lowest height
 *                            are reported)
 *   BODY_HISTORY_UNKNOWN     the census has not established coverage — it
 *                            has not run, could not read the block index,
 *                            or has not yet reached part of the window
 *
 * Firing on UNKNOWN is the point. The bug this whole slice exists to remove
 * is a node that could not tell "I looked and found nothing missing" apart
 * from "I could not look", and a condition that stayed silent on the second
 * one would rebuild that bug at the reporting layer.
 *
 * There is no automatic remedy that would be honest here: the fill is the
 * gap-fill service's bounded background backfill, which is already running
 * and rate-limited on purpose. The condition's job is to make the state
 * SAYABLE and to keep the node from calling itself at tip.
 */

#ifndef ZCL_CONDITIONS_BODY_HISTORY_UNPROVEN_H
#define ZCL_CONDITIONS_BODY_HISTORY_UNPROVEN_H

void register_body_history_unproven(void);

#ifdef ZCL_TESTING
void body_history_unproven_test_reset(void);
/* True when detect() would currently fire. */
bool body_history_unproven_test_detect(void);
#endif

#endif /* ZCL_CONDITIONS_BODY_HISTORY_UNPROVEN_H */
