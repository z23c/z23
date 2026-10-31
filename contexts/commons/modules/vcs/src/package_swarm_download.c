/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_download — per-download map lifecycle for the slice-12 swarm
 * engine: release, reset, and build of the manifest-derived coordinate maps
 * (file_of, chunk_of, have, peer_failed, chunk_attempts). Moved verbatim
 * out of package_swarm_node.c. */

#include "package_swarm_priv.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define SWARM_LOG "vcs.swarm"

void dl_free_maps(struct swarm_download *dl)
{
    if (dl->manifest_loaded)
        vcs_package_manifest_free(&dl->manifest);
    dl->manifest_loaded = false;
    free(dl->file_of);
    free(dl->chunk_of);
    free(dl->have);
    free(dl->peer_failed);
    free(dl->chunk_attempts);
    dl->file_of = NULL;
    dl->chunk_of = NULL;
    dl->have = NULL;
    dl->peer_failed = NULL;
    dl->chunk_attempts = NULL;
    dl->total_chunks = 0;
    dl->have_count = 0;
}

void dl_reset(struct swarm_download *dl)
{
    dl_free_maps(dl);
    memset(dl, 0, sizeof(*dl));
}

/* Per-chunk map slots: at least one, even for an empty manifest. */
static size_t dl_map_slots(const struct swarm_download *dl)
{
    return dl->total_chunks ? dl->total_chunks : 1;
}

/* Build the flattened coordinate maps after dl->manifest was loaded.
 * False (logged) on allocation failure. */
bool dl_build_maps(struct swarm_download *dl)
{
    uint64_t total = 0;
    for (size_t i = 0; i < dl->manifest.count; i++)
        total += dl->manifest.files[i].chunk_count;
    if (total > VCS_PACKAGE_MAX_TOTAL_CHUNKS)
        LOG_FAIL(SWARM_LOG, "manifest chunk count over the wire bound");
    dl->total_chunks = (uint32_t)total;
    size_t bitmap_bytes = ((size_t)dl->total_chunks + 7u) / 8u;
    dl->file_of = zcl_malloc(dl_map_slots(dl) * sizeof(uint32_t),
                             "vcs_swarm_file_of");
    dl->chunk_of = zcl_malloc(dl_map_slots(dl) * sizeof(uint32_t),
                              "vcs_swarm_chunk_of");
    dl->have = zcl_malloc(bitmap_bytes ? bitmap_bytes : 1u,
                          "vcs_swarm_have");
    dl->peer_failed = zcl_malloc(dl_map_slots(dl) * sizeof(uint64_t),
                                 "vcs_swarm_peer_failed");
    dl->chunk_attempts = zcl_malloc(dl_map_slots(dl) * sizeof(uint32_t),
                                    "vcs_swarm_chunk_attempts");
    if (!dl->file_of || !dl->chunk_of || !dl->have || !dl->peer_failed ||
        !dl->chunk_attempts)
        LOG_FAIL(SWARM_LOG, "download map allocation failed");
    memset(dl->have, 0, bitmap_bytes ? bitmap_bytes : 1u);
    memset(dl->peer_failed, 0, dl_map_slots(dl) * sizeof(uint64_t));
    memset(dl->chunk_attempts, 0, dl_map_slots(dl) * sizeof(uint32_t));
    uint32_t g = 0;
    for (size_t i = 0; i < dl->manifest.count; i++)
        for (uint32_t c = 0; c < dl->manifest.files[i].chunk_count; c++) {
            dl->file_of[g] = (uint32_t)i;
            dl->chunk_of[g] = c;
            g++;
        }
    return true;
}
