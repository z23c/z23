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

bool header_admit_forward_rewind_target(sqlite3 *db,
                                        struct active_chain *chain,
                                        uint64_t cursor,
                                        int *out_target,
                                        const char **out_reason);

bool header_admit_forward_rewind_clamp_downstream(sqlite3 *db, int target);

bool header_admit_forward_replay_parent_ok(sqlite3 *db,
                                           struct main_state *ms,
                                           const struct block_index *bi,
                                           int height);

#endif /* ZCL_JOBS_HEADER_ADMIT_FORWARD_REWIND_H */
