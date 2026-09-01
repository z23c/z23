/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * tip_finalize drain batching: defer cache-window collapse to the existing
 * transaction boundary. Internal to engine/jobs/src. */

#ifndef ZCL_TIP_FINALIZE_BATCH_DRAIN_H
#define ZCL_TIP_FINALIZE_BATCH_DRAIN_H

#include <stdbool.h>

struct block_index;
struct main_state;

/* Move immediately outside a drain batch; inside one, remember the latest
 * body-bearing finalized tip for one collapse before the outer COMMIT. */
bool tip_finalize_batch_window_move(struct main_state *ms,
                                    struct block_index *tip);

#endif /* ZCL_TIP_FINALIZE_BATCH_DRAIN_H */
