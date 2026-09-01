/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BlockData model — validates and copies block data files (blk*.dat, rev*.dat).
 *
 * ActiveRecord pattern:
 *   struct block_data bd = { .src_dir = "/path/blocks", .dst_dir = "/path/blocks" };
 *   struct ar_errors errors;
 *   ar_errors_clear(&errors);
 *   if (block_data_validate(&bd, &errors))
 *       block_data_save(&bd);
 */

#ifndef ZCL_MODELS_BLOCK_DATA_H
#define ZCL_MODELS_BLOCK_DATA_H

#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

struct block_data {
    const char *src_dir;    /* Source blocks/ directory */
    const char *dst_dir;    /* Destination blocks/ directory */

    /* Populated by validate */
    int num_blk_files;      /* Count of blk*.dat files */
    int num_rev_files;      /* Count of rev*.dat files */
    int64_t blk_bytes;      /* Total bytes in blk*.dat */
    int64_t rev_bytes;      /* Total bytes in rev*.dat */

    /* Populated by save */
    bool copy_blk_ok;
    bool copy_rev_ok;
};

/* validates_presence_of :src_dir, :dst_dir
 * validates :num_blk_files, numericality: { greater_than: 0 } */
bool block_data_validate(struct block_data *bd, struct ar_errors *errors);

/* save: cp -au blk*.dat and rev*.dat (append-only, update-only) */
bool block_data_save(struct block_data *bd);

#endif
