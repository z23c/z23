/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Resolve the selected legacy hashPrev chain before bulk header import. */

#include "snapshot_import_chain_select.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>

void snapshot_selected_chain_load(const char *index_path,
                                  struct snapshot_selected_chain *out)
{
    memset(out, 0, sizeof(*out));

    struct bilr *reader = NULL;
    out->ready = bilr_open(index_path, &reader) &&
        bilr_load_height_map(reader, &out->entries, &out->count);
    if (reader)
        bilr_close(reader);

    if (out->ready) {
        printf("T1: selected header chain resolved: %zu rows\n", out->count);
        fflush(stdout);
        return;
    }

    bilr_free_height_map(out->entries);
    out->entries = NULL;
    out->count = 0;
    LOG_WARN("importblockindex",
             "selected-chain prepass unavailable; importing verified rows "
             "and requiring duplicate-height fallback proof");
}

bool snapshot_selected_chain_contains(const struct snapshot_selected_chain *chain,
                                      int height, const uint8_t hash[32])
{
    if (!chain->ready)
        return true;
    return height >= 0 && (size_t)height < chain->count &&
        chain->entries[height].height == height &&
        memcmp(chain->entries[height].hash.data, hash, 32) == 0;
}

void snapshot_selected_chain_free(struct snapshot_selected_chain *chain)
{
    bilr_free_height_map(chain->entries);
    memset(chain, 0, sizeof(*chain));
}
