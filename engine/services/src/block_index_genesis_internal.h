/* purpose: Share foreign-genesis identity checks between block index loaders. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_BLOCK_INDEX_GENESIS_INTERNAL_H
#define ZCL_BLOCK_INDEX_GENESIS_INTERNAL_H
#include <stdbool.h>
#include <stdint.h>
struct main_state;
struct chain_params;
bool block_index_has_foreign_genesis(struct main_state *state, const struct chain_params *params);
bool block_index_foreign_genesis_row(int height, const uint8_t hash[32], const struct chain_params *params);
#endif
