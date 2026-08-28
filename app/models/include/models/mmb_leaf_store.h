/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ActiveRecord-style model: MMB Leaf Store
 *
 * Persists MMB leaf hashes to a flat file for FlyClient proof building.
 * Memory-mapped for O(1) access to any leaf hash.
 *
 * File format: leaf_hash[32] × num_leaves (append-only)
 * ~96 MB for 3M blocks. mmap'd read-only after initial build.
 *
 * validates :num_leaves matches MMB num_leaves
 * validates :file_size == num_leaves * 32
 */

#ifndef ZCL_DB_MODEL_MMB_LEAF_STORE_H
#define ZCL_DB_MODEL_MMB_LEAF_STORE_H

#include "chain/mmb.h"
#include "models/activerecord.h"
#include <stdint.h>
#include <stdbool.h>

struct mmb_leaf_store {
    char     path[256];
    int      fd;
    uint8_t *map;          /* mmap'd leaf hashes, 32 bytes each */
    uint64_t num_leaves;
    uint64_t capacity;     /* file size / 32 */
    bool     open;
};

/* Validate the store record — path must be present and file size
 * (if any) must be a clean multiple of 32 bytes. Used at open time
 * and exposed so the AR-style model contract is satisfied. */
bool mmb_leaf_store_validate(struct mmb_leaf_store *store,
                             struct ar_errors *errors);

/* Open or create the leaf store at the given path.
 * If file exists, validates size and mmap's it.
 * Returns true on success. */
bool mmb_leaf_store_open(struct mmb_leaf_store *store, const char *path);

/* Close and unmap the store. */
void mmb_leaf_store_close(struct mmb_leaf_store *store);

/* Append a leaf hash. Extends the file by 32 bytes.
 * Must be called in order (leaf 0, 1, 2, ...). */
bool mmb_leaf_store_append(struct mmb_leaf_store *store,
                           const uint8_t hash[32]);

/* Refresh mmap after appends have extended the backing file. */
bool mmb_leaf_store_remap(struct mmb_leaf_store *store);

/* Get pointer to leaf hash at index (O(1) via mmap). */
const uint8_t *mmb_leaf_store_get(const struct mmb_leaf_store *store,
                                  uint64_t index);

/* Get the full leaf hash array for mmb_prove().
 * Returns pointer to contiguous 32-byte hashes. */
const uint8_t (*mmb_leaf_store_all(const struct mmb_leaf_store *store))[32];

/* Rebuild from block index: iterate all blocks, compute leaf hashes,
 * write to file. Called at startup if file is missing or short.
 * Returns number of leaves written. */
uint64_t mmb_leaf_store_rebuild(struct mmb_leaf_store *store,
                                const void *chain_active);

#endif
