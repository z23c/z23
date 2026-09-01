/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Domain projections over node.db for chain-facing controller reads. */

#ifndef ZCL_CONTROLLERS_CHAIN_PROJECTION_H
#define ZCL_CONTROLLERS_CHAIN_PROJECTION_H

#include <stdint.h>

/* Return -1 on projection open/query failure. Callers decide whether to
 * fall back to the live RPC path. */
int64_t chain_projection_best_block_height(void);
int64_t chain_projection_best_header_height(void);

#endif /* ZCL_CONTROLLERS_CHAIN_PROJECTION_H */
