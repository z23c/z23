/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Declare the private history-archive header-ancestry walk. */
#ifndef ZCL_BLOCK_INDEX_HISTORY_ANCESTRY_H
#define ZCL_BLOCK_INDEX_HISTORY_ANCESTRY_H
#include <stdint.h>
#include "util/result.h"

struct main_state;
struct blocks_mmap;
struct block_index;
struct block_header;
struct uint256;

/* Walk `tip` back to height 0 in `reader` and prove each row holds the
 * header its index entry names and links to its parent, with the height-0
 * row matching `genesis`. The newest ISLAND_ANCHOR_WINDOW rows also gain
 * their header extensions. `top_window`, when non-NULL, receives those
 * headers newest first. Codes are the archive opener's: -5 when shutdown was
 * requested, -3 for any invalid or missing row. */
struct zcl_result block_index_history_ancestry_verify(struct main_state *state,
    struct blocks_mmap *reader, struct block_index *tip, int32_t height,
    const struct uint256 *genesis, struct block_header *top_window);

/* The archive opener's cancellation refusal between its slow steps: -5 once
 * shutdown is requested, OK while it may continue. */
struct zcl_result block_index_history_cancel_refusal(int32_t height);
#endif
