/* purpose: Verify a legacy block-index row before snapshot import. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCLASSIC23_SNAPSHOT_IMPORT_ROW_VERIFY_H
#define ZCLASSIC23_SNAPSHOT_IMPORT_ROW_VERIFY_H

#include "storage/block_index_db.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct chain_params;

bool snapshot_import_row_verify(const struct disk_block_index *dbi,
                                const uint8_t block_hash[32],
                                const struct chain_params *cp,
                                int64_t rom_checkpoint_height,
                                char *out_reason, size_t out_reason_size);

#endif
