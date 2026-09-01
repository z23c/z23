/* purpose: Select one continuous legacy header chain for snapshot import. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCLASSIC23_SNAPSHOT_IMPORT_CHAIN_SELECT_H
#define ZCLASSIC23_SNAPSHOT_IMPORT_CHAIN_SELECT_H

#include "storage/blocks_index_legacy_reader.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct snapshot_selected_chain {
    struct legacy_block_loc *entries;
    size_t count;
    bool ready;
};

void snapshot_selected_chain_load(const char *index_path,
                                  struct snapshot_selected_chain *out);
bool snapshot_selected_chain_contains(const struct snapshot_selected_chain *chain,
                                      int height, const uint8_t hash[32]);
void snapshot_selected_chain_free(struct snapshot_selected_chain *chain);

#endif
