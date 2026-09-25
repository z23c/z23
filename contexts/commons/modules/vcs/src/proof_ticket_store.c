/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: CAS placement of proof tickets, checkpoints and key preimages,
 *          and the receiver rebuilt as a projection over those blobs. */

#include "proof_reuse_priv.h"

#include "vcs/blob_store.h"
#include "vcs/package_store.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define PTS_LOG "vcs.proof_ticket_store"
#define PTS_REBUILD_BATCH 4096u
#define PTS_BLOB_MAX VCS_CPK_WIRE_BYTES

bool vcs_proof_ticket_store_put(struct vcs_package_store *store,
                                const uint8_t *wire, size_t len,
                                uint8_t blob_root[VCS_PROOF_ROOT_BYTES])
{
    if (!store || !wire || !blob_root)
        LOG_RETURN(false, PTS_LOG, "store put: null argument");
    enum vcs_blob_result r = vcs_blob_put_to(store, wire, len, blob_root);
    if (r != VCS_BLOB_OK)
        LOG_RETURN(false, PTS_LOG, "store put (%zu bytes): %s", len,
                   vcs_blob_result_string(r));
    return true;
}

bool vcs_component_proof_key_load(struct vcs_package_store *store,
                                  const uint8_t preimage_root[32],
                                  struct vcs_component_proof_key_v1 *out)
{
    if (!store || !preimage_root || !out)
        LOG_RETURN(false, PTS_LOG, "preimage load: null argument");
    uint8_t wire[VCS_CPK_WIRE_BYTES + 1u];
    size_t len = 0;
    enum vcs_blob_result r =
        vcs_blob_get_from(store, preimage_root, wire, sizeof(wire), &len);
    if (r != VCS_BLOB_OK)
        LOG_RETURN(false, PTS_LOG, "preimage load: %s",
                   vcs_blob_result_string(r));
    if (!vcs_component_proof_key_decode(wire, len, out))
        LOG_RETURN(false, PTS_LOG, "preimage load: blob is not a key preimage");
    uint8_t again[VCS_PROOF_ROOT_BYTES];
    if (!vcs_component_proof_key_preimage_root(out, again) ||
        memcmp(again, preimage_root, VCS_PROOF_ROOT_BYTES) != 0)
        LOG_RETURN(false, PTS_LOG, "preimage load: root does not re-derive");
    return true;
}

/* ── Rebuild ────────────────────────────────────────────────────────── */

struct pts_cps {
    uint8_t (*wires)[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    struct vcs_proof_checkpoint_v1 *decoded;
    size_t count;
};

struct pts_counts {
    size_t tickets;
    size_t checkpoints;
    size_t skipped;
};

static void pts_take(struct vcs_proof_receiver *r, struct pts_cps *cps,
                     const uint8_t *blob, size_t len, struct pts_counts *n)
{
    bool added = false;
    if (len == VCS_PROOF_TICKET_WIRE_BYTES &&
        memcmp(blob, "Z23PTK1\0", 8) == 0 &&
        vcs_proof_ticket_decode(blob, len, &(struct vcs_proof_ticket_v1){0})) {
        if (vcs_proof_receiver_add_ticket(r, blob, len, &added) && added)
            n->tickets++;
        return;
    }
    if (len == VCS_PROOF_CHECKPOINT_WIRE_BYTES &&
        memcmp(blob, "Z23PCK1\0", 8) == 0 &&
        vcs_proof_checkpoint_decode(blob, len, &cps->decoded[cps->count])) {
        memcpy(cps->wires[cps->count++], blob, len);
        return;
    }
    n->skipped++;
}

/* Tickets of `issuer` at seq [from, to), first retained entry per seq. */
static bool pts_delta(const struct vcs_proof_receiver *r,
                      const uint8_t issuer[32], uint64_t from, uint64_t to,
                      const uint8_t **wires, size_t *lens)
{
    for (uint64_t seq = from; seq < to; seq++) {
        const uint8_t *hit = NULL;
        for (size_t i = 0; i < r->count && !hit; i++)
            if (r->entries[i].issuer_seq == seq &&
                memcmp(r->entries[i].producer, issuer, 32) == 0)
                hit = r->entries[i].wire;
        if (!hit) return false;
        wires[seq - from] = hit;
        lens[seq - from] = VCS_PROOF_TICKET_WIRE_BYTES;
    }
    return true;
}

static bool pts_replay_one(struct vcs_proof_receiver *r,
                           const struct pts_cps *cps, size_t k,
                           struct pts_counts *n)
{
    const struct vcs_proof_checkpoint_v1 *c = &cps->decoded[k];
    uint64_t from = vcs_proof_receiver_issuer_leaves(r, c->issuer_pubkey);
    size_t count = c->leaf_count > from ? (size_t)(c->leaf_count - from) : 0;
    const uint8_t **wires = count ? zcl_calloc(count, sizeof(*wires),
                                               "proof_rebuild_delta") : NULL;
    size_t *lens = count ? zcl_calloc(count, sizeof(*lens),
                                      "proof_rebuild_lens") : NULL;
    bool ok = count == 0 || (wires && lens);
    struct vcs_proof_sync_report rep;
    if (ok && pts_delta(r, c->issuer_pubkey, from, from + count, wires, lens) &&
        vcs_proof_receiver_sync(r, cps->wires[k],
                                VCS_PROOF_CHECKPOINT_WIRE_BYTES,
                                (const uint8_t *const *)wires, lens, count,
                                &rep) &&
        (rep.outcome == VCS_PROOF_SYNC_ADVANCED ||
         rep.outcome == VCS_PROOF_SYNC_CURRENT))
        n->checkpoints++;
    else
        n->skipped++;
    free(wires);
    free(lens);
    return ok;
}

/* Replay in ascending leaf_count so each issuer's prefix grows in order. */
static bool pts_replay(struct vcs_proof_receiver *r, const struct pts_cps *cps,
                       struct pts_counts *n)
{
    bool *done = cps->count ? zcl_calloc(cps->count, sizeof(*done),
                                         "proof_rebuild_done") : NULL;
    if (cps->count && !done)
        LOG_RETURN(false, PTS_LOG, "rebuild: out of memory");
    bool ok = true;
    for (size_t round = 0; round < cps->count && ok; round++) {
        size_t best = SIZE_MAX;
        for (size_t k = 0; k < cps->count; k++)
            if (!done[k] && (best == SIZE_MAX ||
                             cps->decoded[k].leaf_count <
                                 cps->decoded[best].leaf_count))
                best = k;
        done[best] = true;
        ok = pts_replay_one(r, cps, best, n);
    }
    free(done);
    return ok;
}

static bool pts_scan(struct vcs_proof_receiver *r,
                     struct vcs_package_store *store, struct pts_cps *cps,
                     struct pts_counts *n)
{
    struct vcs_package_store_summary *rows =
        zcl_calloc(PTS_REBUILD_BATCH, sizeof(*rows), "proof_rebuild_rows");
    if (!rows) LOG_RETURN(false, PTS_LOG, "rebuild: out of memory");
    size_t count = vcs_package_store_list_summaries(store, true, rows,
                                                    PTS_REBUILD_BATCH);
    bool ok = count < PTS_REBUILD_BATCH;
    cps->wires = zcl_calloc(count + 1u, sizeof(*cps->wires), "proof_cps");
    cps->decoded = zcl_calloc(count + 1u, sizeof(*cps->decoded), "proof_cps");
    ok = ok && cps->wires && cps->decoded;
    for (size_t i = 0; ok && i < count; i++) {
        uint8_t blob[PTS_BLOB_MAX + 1u];
        size_t len = 0;
        if (vcs_blob_get_from(store, rows[i].root, blob, sizeof(blob), &len) ==
            VCS_BLOB_OK)
            pts_take(r, cps, blob, len, n);
        else
            n->skipped++;
    }
    free(rows);
    if (!ok)
        LOG_RETURN(false, PTS_LOG,
                   "rebuild: store lists %zu+ packages or out of memory; "
                   "refusing a partial projection", count);
    return true;
}

bool vcs_proof_receiver_rebuild(struct vcs_proof_receiver *r,
                                struct vcs_package_store *store,
                                size_t *tickets, size_t *checkpoints,
                                size_t *skipped)
{
    if (!r || !store)
        LOG_RETURN(false, PTS_LOG, "rebuild: null argument");
    struct pts_cps cps = {0};
    struct pts_counts n = {0};
    bool ok = pts_scan(r, store, &cps, &n) && pts_replay(r, &cps, &n);
    free(cps.wires);
    free(cps.decoded);
    if (tickets) *tickets = n.tickets;
    if (checkpoints) *checkpoints = n.checkpoints;
    if (skipped) *skipped = n.skipped;
    return ok;
}
