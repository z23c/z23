/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private header_admit helpers for the forward-fork replay guard. */

#ifndef ZCL_JOBS_HEADER_ADMIT_FORWARD_REWIND_H
#define ZCL_JOBS_HEADER_ADMIT_FORWARD_REWIND_H

#include "validation/chainstate.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>

struct main_state;

/* Rewind results below 0: nothing to rewind, or a target at/below a trusted
 * anchor the cursor has passed (logged); on REFUSED the caller ends the pass. */
#define HEADER_ADMIT_REWIND_NONE (-1)
#define HEADER_ADMIT_REWIND_REFUSED (-2)

/* True when a present active tip is malformed or its height disagrees with
 * its parent link (logged, throttled). The caller ends the pass: no rewind,
 * admission or cursor move. */
bool header_admit_tip_refused(sqlite3 *db, struct active_chain *chain);

/* *out_target: the rewind height, HEADER_ADMIT_REWIND_NONE or
 * HEADER_ADMIT_REWIND_REFUSED. */
bool header_admit_forward_rewind_target(sqlite3 *db,
                                        struct active_chain *chain,
                                        uint64_t cursor,
                                        int *out_target,
                                        const char **out_reason);

bool header_admit_forward_rewind_clamp_downstream(sqlite3 *db, int target);

/* Shared anchor rule for every header_admit rewind: returns target,
 * HEADER_ADMIT_REWIND_NONE when it is not below the cursor, or
 * HEADER_ADMIT_REWIND_REFUSED at/below the trusted anchor once the cursor
 * has passed it (logged). */
int header_admit_rewind_target_above_anchor(int target, uint64_t cursor);

bool header_admit_forward_replay_parent_ok(sqlite3 *db,
                                           struct main_state *ms,
                                           const struct block_index *bi,
                                           int height);

#endif /* ZCL_JOBS_HEADER_ADMIT_FORWARD_REWIND_H */
