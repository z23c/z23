/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private block-index flat wire shape shared by its reader and writer. */

#ifndef ZCL_SERVICES_BLOCK_INDEX_FLAT_INTERNAL_H
#define ZCL_SERVICES_BLOCK_INDEX_FLAT_INTERNAL_H

#include "services/block_index_loader.h"

/* Final on-disk row format: height-sorted, packed, and covered by the
 * surrounding embedded SHA3 envelope. A single definition prevents reader /
 * writer layout drift; sizeof(struct block_index_flat) remains the canonical
 * payload-size term. */
struct __attribute__((packed)) block_index_flat {
    uint8_t hash[32];
    uint8_t prev_hash[32];
    int32_t height;
    uint32_t n_bits;
    uint32_t n_time;
    int32_t n_version;
    uint32_t n_status;
    int32_t n_file;
    uint32_t n_data_pos;
    uint32_t n_undo_pos;
    uint32_t n_tx;
    uint32_t n_chain_tx;
    uint8_t chain_work[32];
    uint32_t n_cached_branch_id;
    uint8_t sapling_root[32];
};

void block_index_flat_identity_remember(
    const char *datadir, const struct block_index_flat_identity *identity);
void block_index_flat_identity_forget(void);
struct zcl_result block_index_flat_write_identity(
    const char *datadir, struct main_state *ms,
    struct block_index_flat_identity *out);

#endif /* ZCL_SERVICES_BLOCK_INDEX_FLAT_INTERNAL_H */
