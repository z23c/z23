/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * LevelDB store model — validates and copies a LevelDB directory.
 * Used for both block_index and chainstate stores.
 *
 * ActiveRecord pattern:
 *   struct leveldb_store store = { .src_dir = "...", .dst_dir = "...",
 *                                  .label = "block_index" };
 *   struct ar_errors errors;
 *   if (leveldb_store_validate(&store, &errors))
 *       leveldb_store_save(&store);
 */

#ifndef ZCL_MODELS_LEVELDB_STORE_H
#define ZCL_MODELS_LEVELDB_STORE_H

#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

struct leveldb_store {
    const char *src_dir;
    const char *dst_dir;
    const char *label;      /* "block_index" or "chainstate" for logging */

    /* Populated by validate */
    int num_sst_files;
    int64_t total_bytes;
    bool has_manifest;
    bool has_current;

    /* Populated by save */
    bool copy_ok;
};

bool leveldb_store_validate(struct leveldb_store *store,
                             struct ar_errors *errors);

bool leveldb_store_save(struct leveldb_store *store);

#endif
