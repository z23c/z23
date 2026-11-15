/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_download — per-download map lifecycle for the slice-12 swarm
 * engine: request timeout lifecycle, lookup, and manifest-derived coordinate maps
 * (file_of, chunk_of, have, peer_failed, chunk_attempts). Moved verbatim
 * out of package_swarm_node.c. */

#include "package_swarm_priv.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define SWARM_LOG "vcs.swarm"

void vcs_swarm_log_failure(const struct swarm_download *dl, const char *rule)
{
    if (!strcmp(rule, "chunk-attempts-exhausted"))
        LOG_WARN(SWARM_LOG, "download %.16s failed: %s timeouts=%llu invalid=%llu chunk_known=%u chunk=%u attempts=%u",
                 dl->root_hex, rule, (unsigned long long)dl->chunk_timeouts, (unsigned long long)dl->chunk_invalid,
                 dl->exhausted_chunk_known ? 1u : 0u, dl->exhausted_chunk, dl->exhausted_attempts);
    else
        LOG_WARN(SWARM_LOG, "download %.16s failed: %s", dl->root_hex, rule);
}

void vcs_swarm_invalid_chunk(struct swarm_download *dl, uint32_t chunk)
{
    if (dl->chunk_invalid != UINT64_MAX) ++dl->chunk_invalid;
    if (dl->chunk_attempts[chunk] >= VCS_SWARM_MAX_CHUNK_ATTEMPTS) {
        dl->exhausted_chunk_known = true;
        dl->exhausted_chunk = chunk;
        dl->exhausted_attempts = dl->chunk_attempts[chunk];
    }
}

void vcs_swarm_exhaustion_status(const struct swarm_download *dl, struct vcs_swarm_download_status *out)
{
    out->chunk_timeouts = dl->chunk_timeouts;
    out->chunk_invalid = dl->chunk_invalid;
    out->exhausted_chunk_known = dl->exhausted_chunk_known;
    out->exhausted_chunk = dl->exhausted_chunk;
    out->exhausted_attempts = dl->exhausted_attempts;
}

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

/* Request lifetime and timeout grace; caller holds the engine lock. */
void vcs_swarm_timeout_grace_clear(struct swarm_download *dl, uint64_t peer)
{
    for (size_t i = 0; i < dl->tomb_count; i++)
        if (peer == 0 || dl->tombs[i].expired.peer == peer)
            dl->tombs[i].expired.used = false;
}

struct swarm_tombstone *vcs_swarm_find_tombstone(struct swarm_download *dl,
                                                 uint64_t id)
{
    for (size_t i = 0; i < dl->tomb_count; i++)
        if (dl->tombs[i].id == id) return &dl->tombs[i];
    return NULL;
}

void vcs_swarm_timeouts_locked(struct vcs_swarm_engine *engine, uint64_t now)
{
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++) {
        struct swarm_download *dl = &engine->dls[i];
        if (!dl->used ||
            (dl->state != VCS_SWARM_DL_WANT_MANIFEST &&
             dl->state != VCS_SWARM_DL_CHUNKS))
            continue;
        for (size_t r = 0; r < SWARM_DL_INFLIGHT_MAX; r++) {
            struct swarm_req *req = &dl->reqs[r];
            if (!req->used || now < req->deadline)
                continue;
            uint32_t g = req->global_chunk;
            struct swarm_req expired = *req;
            vcs_swarm_req_finish(engine, dl, req, true, false);
            if (g == UINT32_MAX)
                dl->manifest_attempts++;
            else {
                struct swarm_tombstone *t = vcs_swarm_find_tombstone(dl, expired.want.request_id);
                if (t) t->expired = expired;
                dl->chunk_attempts[g]++;
                if (dl->chunk_timeouts != UINT64_MAX) ++dl->chunk_timeouts;
            }
        }
    }
}

static struct swarm_req *find_outstanding(struct swarm_download *dl,
                                          uint64_t peer, uint64_t id)
{
    for (size_t i = 0; i < SWARM_DL_INFLIGHT_MAX; i++)
        if (dl->reqs[i].used && dl->reqs[i].peer == peer &&
            dl->reqs[i].want.request_id == id)
            return &dl->reqs[i];
    return NULL;
}

/* Retain exact authorization for one retry interval, never revive a
 * canceled session, terminal download, manifest, or already stored chunk. */
static bool timeout_chunk_request(struct swarm_download *dl, uint64_t peer,
    uint64_t id, uint64_t now, struct swarm_req *out)
{
    if (dl->state != VCS_SWARM_DL_CHUNKS || !dl->manifest_loaded ||
        !vcs_swarm_provider_allowed(dl->provider_restricted, dl->provider_peers,
                                    dl->provider_count, peer)) return false;
    struct swarm_tombstone *t = vcs_swarm_find_tombstone(dl, id);
    if (!t || t->fulfilled || !t->expired.used || t->expired.peer != peer)
        return false;
    const struct swarm_req *r = &t->expired;
    if (now < r->deadline || now - r->deadline >= VCS_SWARM_REQUEST_TIMEOUT_TICKS ||
        r->global_chunk >= dl->total_chunks || vcs_swarm_bitmap_get(dl->have, r->global_chunk))
        return false;
    *out = *r;
    /* The timeout already released its slot and in-flight count. */
    out->used = false;
    t->expired.used = false;
    return true;
}

struct swarm_req *vcs_swarm_data_request(struct swarm_download *dl,
    uint64_t peer, uint64_t id, uint64_t now, struct swarm_req *late)
{
    if (!dl) return NULL;
    struct swarm_req *req = find_outstanding(dl, peer, id);
    if (req) return req;
    return timeout_chunk_request(dl, peer, id, now, late) ? late : NULL;
}
