/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* purpose: Declare private verified block-index top-up prefix operations. */
#ifndef ZCL_BLOCK_INDEX_TOPUP_CLEAN_H
#define ZCL_BLOCK_INDEX_TOPUP_CLEAN_H
#include <stdbool.h>
#include <stdint.h>
struct main_state;
struct node_db;
int topup_clean_resume(struct main_state *ms, struct node_db *ndb,
                       const uint8_t anchor[32], int lo, int coins_best,
                       bool *verified);
void topup_clean_record(struct main_state *ms, struct node_db *ndb,
                        const uint8_t anchor[32], int lo, int coins_best,
                        bool fold_was_noop, bool verified);
#endif
