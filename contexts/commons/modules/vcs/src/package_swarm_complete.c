/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_complete — COMPLETE a swarm download and immediately
 * ANNOUNCE that exact root to every currently known peer. Completing a
 * fetch does not pin; ANNOUNCE stays gated by public_serveable(). */

#include "package_swarm_priv.h"

#include "vcs/package_swarm.h"

#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

#define SWARM_COMPLETE_LOG "vcs.swarm.complete"

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
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++) {
        struct swarm_peer *peer = &engine->peers[i];
        if (!peer->used)
            continue;
        if (vcs_swarm_peer_was_announced(peer, root))
            continue;
        if (!vcs_swarm_queue_frame(engine, peer->id, &msg))
            break;
        if (peer->announced_count < VCS_SWARM_MAX_LOCAL_ANNOUNCES)
            memcpy(peer->announced[peer->announced_count++], root, 32);
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
