/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Chain restore planner — pure planning slice for chain tip restoration. */

#ifndef ZCL_CHAIN_RESTORE_PLANNER_H
#define ZCL_CHAIN_RESTORE_PLANNER_H

#include "core/uint256.h"
#include <stdbool.h>

enum chain_restore_state {
    CHAIN_RESTORE_UNRESOLVED = 0,   /* coins_best_block not evaluated */
    CHAIN_RESTORE_FOUND_IN_INDEX,   /* hash found in block_map */
    CHAIN_RESTORE_ANCHOR_CREATED,   /* placeholder anchor inserted */
    CHAIN_RESTORE_RESOLVED,         /* chain tip set, ready for sync */
    CHAIN_RESTORE_FAILED,           /* unrecoverable: no hash/height */
};

enum chain_restore_source {
    CHAIN_RESTORE_SRC_NORMAL_BOOT = 0,
    CHAIN_RESTORE_SRC_LDB_IMPORT,
    CHAIN_RESTORE_SRC_SNAPSHOT,
};

struct chain_restore_input {
    struct uint256 coins_best_hash;     /* from LDB or coins_view_cache */
    int            utxo_max_height;     /* SELECT MAX(height) FROM utxos */
    bool           hash_found_in_map;   /* block_map_find returned non-NULL */
    int            found_height;        /* height of found block (if any) */
    bool           found_has_pprev;     /* found->pprev != NULL */
    enum chain_restore_source source;
};

struct chain_restore_plan {
    enum chain_restore_state next_state;
    bool should_create_anchor;
    bool should_set_chain_tip;
    bool should_set_best_header;
    bool should_set_snapshot_anchor;
    bool should_skip_activate;
    int  anchor_height;
    struct uint256 anchor_hash;
    char reason[128];
};

void chain_restore_plan(struct chain_restore_plan *out,
                        const struct chain_restore_input *in);

#endif /* ZCL_CHAIN_RESTORE_PLANNER_H */
