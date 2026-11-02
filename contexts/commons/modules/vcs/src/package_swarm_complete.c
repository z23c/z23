/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_complete — COMPLETE a swarm download and immediately
 * ANNOUNCE that exact root to every currently known peer. Completing a
 * fetch does not pin; ANNOUNCE stays gated by public_serveable(). Also
 * the restricted-fetch precheck, which may answer a providerless fetch
 * only from a complete, possession-proven local copy. */

#include "package_swarm_priv.h"

#include "vcs/package_swarm.h"

#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

#define SWARM_COMPLETE_LOG "vcs.swarm.complete"

void vcs_swarm_bitmap_set(uint8_t *map, uint32_t bit);

/* Resume only exact verified bytes; a CAS filename is not possession.
 * Caller holds the engine lock and supplies a fresh have bitmap. */
bool vcs_swarm_rebuild_have(struct vcs_swarm_engine *engine,
                            struct swarm_download *dl)
{
    dl->have_count = 0;
    for (uint32_t g = 0; g < dl->total_chunks; g++) {
        if (!vcs_package_store_chunk_present(engine->store, dl->root,
                                             dl->file_of[g], dl->chunk_of[g]))
            continue;
        uint8_t *bytes = NULL;
        size_t len = 0;
        enum vcs_package_store_result result = vcs_package_store_get_chunk_at(
            engine->store, dl->root, dl->file_of[g], dl->chunk_of[g],
            &bytes, &len);
        free(bytes);
        if (result == VCS_PACKAGE_STORE_ERR_CHUNK_HASH ||
            result == VCS_PACKAGE_STORE_ERR_CHUNK_MISSING)
            continue;
        if (result != VCS_PACKAGE_STORE_OK) {
            LOG_WARN(SWARM_COMPLETE_LOG, "resume %.16s chunk %u: %s",
                     dl->root_hex, g, vcs_package_store_result_string(result));
            return false;
        }
        vcs_swarm_bitmap_set(dl->have, g);
        dl->have_count++;
    }
    return true;
}

/* Queue ANNOUNCE of `root` to every known peer that has not already
 * received it. Caller holds engine->lock. Silent when the root is not
 * public-serveable or is not a complete tracked package. */
static void announce_completed_root(struct vcs_swarm_engine *engine,
                                    const uint8_t root[32])
{
    if (!engine->store)
        return;
    if (!vcs_swarm_public_serveable(engine, root, NULL))
        return;

    struct vcs_package_store_summary summaries[VCS_SWARM_MAX_LOCAL_ANNOUNCES];
    size_t n = vcs_package_store_list_summaries(
        engine->store, true, summaries, VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    const struct vcs_package_store_summary *sum = NULL;
    for (size_t i = 0; i < n; i++) {
        if (memcmp(summaries[i].root, root, 32) == 0) {
            sum = &summaries[i];
            break;
        }
    }

    struct vcs_package_swarm_announce body;
    memset(&body, 0, sizeof(body));
    memcpy(body.package_root, root, 32);
    if (sum) {
        body.manifest_bytes = sum->manifest_bytes;
        body.file_count = sum->file_count;
        body.total_bytes = sum->total_bytes;
        body.total_chunks = sum->total_chunks;
    } else {
        /* The bounded list_summaries prefix can miss a 65th complete
         * root; still advertise THIS package from the store. */
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        if (vcs_package_store_get_manifest_wire(engine->store, root, &wire,
                                                &wire_len) !=
            VCS_PACKAGE_STORE_OK) {
            free(wire);
            LOG_WARN(SWARM_COMPLETE_LOG,
                     "complete announce skipped: manifest unreadable");
            return;
        }
        struct vcs_package_manifest parsed;
        bool ok = vcs_package_manifest_parse(wire, wire_len, &parsed);
        if (!ok) {
            free(wire);
            LOG_WARN(SWARM_COMPLETE_LOG,
                     "complete announce skipped: manifest unparseable");
            return;
        }
        body.manifest_bytes = (uint32_t)wire_len;
        body.file_count = (uint32_t)parsed.count;
        for (size_t i = 0; i < parsed.count; i++) {
            body.total_bytes += parsed.files[i].size;
            body.total_chunks += parsed.files[i].chunk_count;
        }
        vcs_package_manifest_free(&parsed);
        free(wire);
    }

    struct vcs_package_swarm_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = VCS_PACKAGE_SWARM_ANNOUNCE;
    msg.body.announce = body;
    /* Same per-session cap and hourly accounting as announce_to: an ANNOUNCE
     * past the receiver's budget is an unremembered root and gets us banned. */
    struct vcs_package_store_summary shelf[VCS_SWARM_MAX_LOCAL_ANNOUNCES];
    size_t shelf_n = vcs_package_store_list_announce_summaries(
        engine->store, shelf, VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++) {
        struct swarm_peer *peer = &engine->peers[i];
        if (!peer->used)
            continue;
        if (vcs_swarm_peer_was_announced(peer, root))
            continue;
        int keep = vcs_swarm_announce_plan(engine, peer, root, shelf,
                                           shelf_n);
        if (keep < 0)
            continue;
        if (!vcs_swarm_queue_frame(engine, peer->id, &msg))
            break;
        vcs_swarm_announce_commit(peer, keep, root);
    }
}

void vcs_swarm_complete_download(struct vcs_swarm_engine *engine,
                                 struct swarm_download *dl)
{
    vcs_swarm_cancel_outstanding(engine, dl);
    dl->state = VCS_SWARM_DL_COMPLETE;
    vcs_swarm_record_delete_dl(engine, dl);
    announce_completed_root(engine, dl->root);
}

static enum vcs_swarm_fetch_result provider_input_result(
    const uint64_t *provider_peers, size_t provider_count)
{
    if ((!provider_peers && provider_count) ||
        provider_count > VCS_SWARM_PROVIDER_MAX)
        return VCS_SWARM_FETCH_BAD_INPUT;
    for (size_t i = 0; i < provider_count; i++)
        if (provider_peers[i] != 0)
            return VCS_SWARM_FETCH_OK;
    return VCS_SWARM_FETCH_NO_PROVIDER;
}

/* A restricted fetch that names no authenticated provider can still be
 * answered from this node's own store: it needs no remote bytes. The
 * store's `complete` bit is a presence index (every committed coordinate
 * has a CAS object, each hash-checked when it was admitted), not a fresh
 * read of the bytes on disk, so success here also requires a full
 * possession proof: the manifest re-parsed and bound to this exact root,
 * every chunk re-read and re-hashed. Partial, untracked, corrupt, or
 * foreign-root bytes keep the original no-provider refusal. Runs with or
 * without the engine lock held; engine->store is fixed at create. */
enum vcs_swarm_fetch_result vcs_swarm_local_complete_result(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    uint64_t maximum_package_bytes)
{
    struct vcs_package_store_status st;
    memset(&st, 0, sizeof(st));
    if (!engine->store ||
        !vcs_package_store_package_status(engine->store, package_root,
                                          &st) ||
        !st.tracked || !st.complete)
        return VCS_SWARM_FETCH_NO_PROVIDER;
    enum vcs_swarm_fetch_result cached =
        vcs_swarm_cached_fetch_result(&st, maximum_package_bytes);
    if (cached != VCS_SWARM_FETCH_ALREADY_COMPLETE)
        return cached;
    return vcs_package_store_verify_possession(engine->store, package_root,
                                               false)
        ? VCS_SWARM_FETCH_ALREADY_COMPLETE
        : VCS_SWARM_FETCH_NO_PROVIDER;
}

enum vcs_swarm_fetch_result vcs_swarm_restricted_precheck(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    const uint64_t *provider_peers, size_t provider_count,
    uint64_t maximum_package_bytes)
{
    enum vcs_swarm_fetch_result input =
        provider_input_result(provider_peers, provider_count);
    return input == VCS_SWARM_FETCH_NO_PROVIDER
        ? vcs_swarm_local_complete_result(engine, package_root,
                                      maximum_package_bytes)
        : input;
}
