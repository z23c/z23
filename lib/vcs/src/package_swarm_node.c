/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_node — the slice-12 swarm engine: scheduler, serving
 * decisions, and slice-11 accounting over the content.v2 swarm codec.
 * Pure: no sockets, no wall clock, no threads. See the public header for
 * the full contract (chunk binding, credit discipline, policy
 * consumption, scheduler shape, resume, threading). */

#include "vcs/package_swarm_node.h"

#include "vcs/package_manifest.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"

#include "package_store_priv.h" /* store_atomic_write/mkdir/rm_rf */
#include "package_swarm_priv.h"
#include "package_swarm_record.h"
#include "vcs_priv.h"

#include "base/hex.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SWARM_LOG "vcs.swarm"
#define SWARM_MANIFEST_CHUNK UINT32_MAX

static uint64_t nonce_bump(struct vcs_swarm_engine *engine);
bool vcs_swarm_bitmap_get(const uint8_t *map, uint32_t bit);
void vcs_swarm_bitmap_set(uint8_t *map, uint32_t bit);
void vcs_swarm_derive_request_id32(const uint8_t key[33], uint64_t request_id,
                                   const uint8_t root[32], uint8_t out[32]);
bool vcs_swarm_provider_allowed(bool restricted, const uint64_t *allowed,
                                size_t count, uint64_t peer);
size_t vcs_swarm_provider_set(uint64_t *out, size_t capacity,
                              const uint64_t *peers, size_t count);
#define bitmap_get vcs_swarm_bitmap_get
#define bitmap_set vcs_swarm_bitmap_set
#define derive_request_id32 vcs_swarm_derive_request_id32
#define dl_peer_allowed(d, p) vcs_swarm_provider_allowed(                 \
    (d)->provider_restricted, (d)->provider_peers, (d)->provider_count, (p))
#define dl_set_providers(d, p, n) ((d)->provider_count =                  \
    vcs_swarm_provider_set((d)->provider_peers, VCS_SWARM_PROVIDER_MAX, p, n))

/* ── small helpers ──────────────────────────────────────────────────── */

static int peer_slot(const struct vcs_swarm_engine *engine, uint64_t peer)
{
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
        if (engine->peers[i].used && engine->peers[i].id == peer)
            return (int)i;
    return -1;
}

/* Shared with package_swarm_stalled.c (declared in package_swarm_priv.h). */
static int peer_ad_index(const struct swarm_peer *peer,
                         const uint8_t root[32])
{
    for (size_t i = 0; i < peer->ad_count; i++)
        if (memcmp(peer->ads[i], root, 32) == 0)
            return (int)i;
    return -1;
}

bool peer_advertises(const struct swarm_peer *peer,
                     const uint8_t root[32])
{
    return peer_ad_index(peer, root) >= 0;
}

static void peer_prune_expired_offers(struct swarm_peer *peer, uint64_t now)
{
    size_t write = 0;
    for (size_t read = 0; read < peer->ad_count; read++) {
        uint64_t expiry = peer->ad_expires_at[read];
        if (expiry != 0 && expiry <= now)
            continue;
        if (write != read) {
            memcpy(peer->ads[write], peer->ads[read], 32);
            peer->ad_expires_at[write] = expiry;
        }
        write++;
    }
    peer->ad_count = write;
}

/* A provider-directed fetch is already bound to explicit authenticated
 * transport handles by its caller.  Requiring those same handles to win the
 * unrelated broadcast ANNOUNCE rate limit makes the restriction unusable:
 * a newly published immutable root can sit forever behind older announces.
 * Ordinary discovery still requires an advertisement. */
static bool peer_offers_download(const struct swarm_download *dl,
                                 const struct swarm_peer *peer)
{
    return peer->used && dl_peer_allowed(dl, peer->id) &&
           (dl->provider_restricted || peer_advertises(peer, dl->root));
}

uint32_t advertisers_of(const struct vcs_swarm_engine *engine,
                        const struct swarm_download *dl)
{
    uint32_t n = 0;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
        if (peer_offers_download(dl, &engine->peers[i]))
            n++;
    return n;
}

static uint32_t dl_inflight(const struct swarm_download *dl)
{
    uint32_t n = 0;
    for (size_t i = 0; i < SWARM_DL_INFLIGHT_MAX; i++)
        if (dl->reqs[i].used)
            n++;
    return n;
}

static uint32_t global_inflight(const struct vcs_swarm_engine *engine)
{
    uint32_t n = 0;
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++)
        if (engine->dls[i].used)
            n += dl_inflight(&engine->dls[i]);
    return n;
}

static struct swarm_download *dl_find(struct vcs_swarm_engine *engine,
                                      const uint8_t root[32])
{
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++)
        if (engine->dls[i].used &&
            memcmp(engine->dls[i].root, root, 32) == 0)
            return &engine->dls[i];
    return NULL;
}

/* ── slice-11 accounting (book NULL = accounting skipped) ───────────── */

static void book_no_credit(struct vcs_swarm_engine *engine,
                           const struct swarm_peer *peer,
                           enum vcs_policy_no_credit kind, uint64_t bytes,
                           int64_t day)
{
    if (!engine->book)
        return;
    if (vcs_service_record_no_credit(engine->book, peer->key, kind, bytes,
                                     day) == VCS_SERVICE_RECORD_IO)
        LOG_WARN(SWARM_LOG, "no-credit record I/O failed (kind=%s)",
                 vcs_policy_no_credit_string(kind));
}

/* Returns the key's offence total after recording (0 without a book). */
static uint32_t book_offence(struct vcs_swarm_engine *engine,
                             const struct swarm_peer *peer,
                             enum vcs_policy_offence kind, int64_t day)
{
    if (!engine->book)
        return 0;
    if (vcs_service_record_offence(engine->book, peer->key, kind, day) ==
        VCS_SERVICE_RECORD_IO)
        LOG_WARN(SWARM_LOG, "offence record I/O failed (kind=%s)",
                 vcs_policy_offence_string(kind));
    struct vcs_service_key_totals totals;
    if (!vcs_service_key_totals(engine->book, peer->key, -1, &totals))
        return 0;
    return totals.offence_total;
}

static void xfer_note(struct swarm_peer *peer, const uint8_t root[32],
                      uint64_t bytes, bool upload)
{
    if (!peer || !root || bytes == 0)
        return;
    if ((peer->xfer_served + peer->xfer_fetched) == 0 ||
        memcmp(peer->xfer_root, root, 32) == 0) {
        memcpy(peer->xfer_root, root, 32);
        if (upload)
            peer->xfer_served += bytes;
        else
            peer->xfer_fetched += bytes;
    }
}

static void book_credit_download(struct vcs_swarm_engine *engine,
                                 struct swarm_peer *peer, uint64_t request_id,
                                 const uint8_t root[32], uint64_t bytes,
                                 int64_t day)
{
    xfer_note(peer, root, bytes, false);
    if (!engine->book)
        return;
    uint8_t id32[32];
    derive_request_id32(peer->key, request_id, root, id32);
    enum vcs_service_credit_result r = vcs_service_credit_download(
        engine->book, peer->key, id32, bytes, day);
    if (r != VCS_SERVICE_CREDIT_OK && r != VCS_SERVICE_CREDIT_DUPLICATE)
        LOG_WARN(SWARM_LOG, "download credit refused: %s",
                 vcs_service_credit_result_string(r));
}

static void book_credit_upload(struct vcs_swarm_engine *engine,
                               struct swarm_peer *peer, uint64_t request_id,
                               const uint8_t root[32], uint64_t bytes,
                               int64_t day)
{
    xfer_note(peer, root, bytes, true);
    if (!engine->book)
        return;
    uint8_t id32[32];
    derive_request_id32(peer->key, request_id, root, id32);
    enum vcs_service_credit_result r = vcs_service_credit_upload(
        engine->book, peer->key, id32, bytes, day);
    if (r != VCS_SERVICE_CREDIT_OK && r != VCS_SERVICE_CREDIT_DUPLICATE)
        LOG_WARN(SWARM_LOG, "upload credit refused: %s",
                 vcs_service_credit_result_string(r));
}

static enum vcs_policy_tier peer_tier_locked(
    const struct vcs_swarm_engine *engine, const struct swarm_peer *peer)
{
    uint64_t earned = engine->score_fn
                          ? engine->score_fn(peer->key, engine->score_ctx)
                          : 0;
    uint64_t up = 0, down = 0;
    if (engine->book) {
        struct vcs_service_key_totals totals;
        if (vcs_service_key_totals(engine->book, peer->key, -1, &totals)) {
            up = totals.verified_bytes_uploaded;
            down = totals.verified_bytes_downloaded;
        }
    }
    return vcs_policy_tier_for(earned, up, down);
}

/* ── outbound queue ─────────────────────────────────────────────────── */

bool vcs_swarm_queue_frame(struct vcs_swarm_engine *engine, uint64_t peer,
                           const struct vcs_package_swarm_message *message)
{
    uint8_t buf[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t len = 0;
    if (!vcs_package_swarm_serialize(message, buf, sizeof(buf), &len) ||
        len > VCS_SWARM_OUTBOUND_FRAME_MAX)
        LOG_FAIL(SWARM_LOG, "swarm frame does not fit the outbound queue");
    if (engine->outq_count >= VCS_SWARM_OUTBOUND_MAX) {
        /* Drop the OLDEST frame: scheduler work is re-issuable and the
         * tombstone tables absorb a lost CANCEL. */
        engine->outq_pos = (engine->outq_pos + 1) % VCS_SWARM_OUTBOUND_MAX;
        engine->outq_count--;
        LOG_WARN(SWARM_LOG, "outbound queue full: dropped oldest frame");
    }
    size_t slot = (engine->outq_pos + engine->outq_count) %
                  VCS_SWARM_OUTBOUND_MAX;
    engine->outq[slot].peer = peer;
    engine->outq[slot].len = (uint8_t)len;
    memcpy(engine->outq[slot].bytes, buf, len);
    engine->outq_count++;
    return true;
}

/* ── download lifecycle ─────────────────────────────────────────────── */

static void dl_free_maps(struct swarm_download *dl)
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

static void dl_reset(struct swarm_download *dl)
{
    dl_free_maps(dl);
    memset(dl, 0, sizeof(*dl));
}

/* Build the flattened coordinate maps after dl->manifest was loaded.
 * False (logged) on allocation failure. */
static bool dl_build_maps(struct swarm_download *dl)
{
    uint64_t total = 0;
    for (size_t i = 0; i < dl->manifest.count; i++)
        total += dl->manifest.files[i].chunk_count;
    if (total > VCS_PACKAGE_MAX_TOTAL_CHUNKS)
        LOG_FAIL(SWARM_LOG, "manifest chunk count over the wire bound");
    dl->total_chunks = (uint32_t)total;
    size_t bitmap_bytes = ((size_t)dl->total_chunks + 7u) / 8u;
    dl->file_of = zcl_malloc((size_t)(dl->total_chunks ? dl->total_chunks
                                                      : 1) *
                                 sizeof(uint32_t),
                             "vcs_swarm_file_of");
    dl->chunk_of = zcl_malloc((size_t)(dl->total_chunks ? dl->total_chunks
                                                       : 1) *
                                  sizeof(uint32_t),
                              "vcs_swarm_chunk_of");
    dl->have = zcl_malloc(bitmap_bytes ? bitmap_bytes : 1u,
                          "vcs_swarm_have");
    dl->peer_failed = zcl_malloc(
        (size_t)(dl->total_chunks ? dl->total_chunks : 1) * sizeof(uint64_t),
        "vcs_swarm_peer_failed");
    dl->chunk_attempts = zcl_malloc(
        (size_t)(dl->total_chunks ? dl->total_chunks : 1) * sizeof(uint32_t),
        "vcs_swarm_chunk_attempts");
    if (!dl->file_of || !dl->chunk_of || !dl->have || !dl->peer_failed ||
        !dl->chunk_attempts)
        LOG_FAIL(SWARM_LOG, "download map allocation failed");
    memset(dl->have, 0, bitmap_bytes ? bitmap_bytes : 1u);
    memset(dl->peer_failed, 0,
           (size_t)(dl->total_chunks ? dl->total_chunks : 1) *
               sizeof(uint64_t));
    memset(dl->chunk_attempts, 0,
           (size_t)(dl->total_chunks ? dl->total_chunks : 1) *
               sizeof(uint32_t));
    uint32_t g = 0;
    for (size_t i = 0; i < dl->manifest.count; i++)
        for (uint32_t c = 0; c < dl->manifest.files[i].chunk_count; c++) {
            dl->file_of[g] = (uint32_t)i;
            dl->chunk_of[g] = c;
            g++;
        }
    return true;
}

static bool record_persist(struct vcs_swarm_engine *engine,
                           const struct swarm_download *dl)
{
    if (!engine->persist)
        return true;
    struct vcs_swarm_record record;
    memcpy(record.root, dl->root, 32);
    record.created_day = dl->created_day;
    record.provider_restricted = dl->provider_restricted;
    record.maximum_package_bytes = dl->maximum_package_bytes;
    return vcs_swarm_record_persist(engine->zcode_dir, dl->root_hex, &record);
}

void vcs_swarm_record_delete_dl(struct vcs_swarm_engine *engine,
                                const struct swarm_download *dl)
{
    if (!engine->persist)
        return;
    vcs_swarm_record_delete(engine->zcode_dir, dl->root_hex);
}

static void req_finish(struct vcs_swarm_engine *engine,
                       struct swarm_download *dl, struct swarm_req *req,
                       bool tombstone, bool fulfilled);
static uint64_t chunk_len_of(const struct swarm_download *dl, uint32_t g);

static void dl_fail(struct vcs_swarm_engine *engine,
                    struct swarm_download *dl, const char *rule)
{
    LOG_WARN(SWARM_LOG, "download %.16s failed: %s", dl->root_hex, rule);
    dl->state = VCS_SWARM_DL_FAILED;
    dl->rule = rule;
    /* Tombstone every outstanding request as cancelled: data still in
     * flight for a failed download is an honest race, not an offence. */
    for (size_t i = 0; i < SWARM_DL_INFLIGHT_MAX; i++)
        if (dl->reqs[i].used)
            req_finish(engine, dl, &dl->reqs[i], true, false);
    vcs_swarm_record_delete_dl(engine, dl);
}

/* Rebuild the have-bitmap from pure CAS presence probes (resume). */
static void dl_rebuild_have(struct vcs_swarm_engine *engine,
                            struct swarm_download *dl)
{
    dl->have_count = 0;
    for (uint32_t g = 0; g < dl->total_chunks; g++) {
        if (vcs_package_store_chunk_present(engine->store, dl->root,
                                            dl->file_of[g],
                                            dl->chunk_of[g])) {
            bitmap_set(dl->have, g);
            dl->have_count++;
        }
    }
}

/* Load the tracked (staged or committed) manifest wire from the store
 * into the download. False when untracked or on parse/alloc failure. */
static bool dl_load_manifest_from_store(struct vcs_swarm_engine *engine,
                                        struct swarm_download *dl)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(engine->store, dl->root, &wire,
                                            &wire_len) !=
        VCS_PACKAGE_STORE_OK)
        return false;
    bool ok = vcs_package_manifest_parse(wire, wire_len, &dl->manifest);
    free(wire);
    if (!ok)
        LOG_FAIL(SWARM_LOG, "stored manifest re-parse failed for %.16s",
                 dl->root_hex);
    dl->manifest_loaded = true;
    if (!vcs_swarm_manifest_within_bound(
            &dl->manifest, dl->maximum_package_bytes)) {
        dl_free_maps(dl);
        return false;
    }
    if (!dl_build_maps(dl)) {
        dl_free_maps(dl);
        return false;
    }
    dl_rebuild_have(engine, dl);
    /* A persisted/staged manifest is a resume boundary.  Report the exact
     * verified CAS objects this engine incarnation inherited so callers can
     * distinguish resuming the graph from starting it over. */
    dl->reused_objects = dl->have_count;
    dl->reused_bytes = 0;
    for (uint32_t g = 0; g < dl->total_chunks; g++)
        if (bitmap_get(dl->have, g))
            dl->reused_bytes += chunk_len_of(dl, g);
    return true;
}

/* ── request issue ──────────────────────────────────────────────────── */

static uint64_t next_request_id(struct vcs_swarm_engine *engine)
{
    engine->next_request_id++;
    if ((engine->next_request_id & UINT64_C(0xffffffff)) == 0) {
        /* Low-32 wrap: re-anchor on a fresh boot nonce. */
        engine->next_request_id = nonce_bump(engine) << 32;
        engine->next_request_id++;
    }
    return engine->next_request_id;
}

static struct swarm_req *req_alloc(struct swarm_download *dl)
{
    for (size_t i = 0; i < SWARM_DL_INFLIGHT_MAX; i++)
        if (!dl->reqs[i].used)
            return &dl->reqs[i];
    return NULL;
}

/* Issue one WANT to `peer`. The request records the exact outstanding
 * object the eventual DATA must reproduce. */
static bool issue_want(struct vcs_swarm_engine *engine,
                       struct swarm_download *dl, struct swarm_peer *peer,
                       uint32_t global_chunk, uint64_t now)
{
    struct swarm_req *req = req_alloc(dl);
    if (!req)
        return false;
    struct vcs_package_swarm_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = VCS_PACKAGE_SWARM_WANT;
    struct vcs_package_swarm_object *want = &msg.body.want;
    memset(want, 0, sizeof(*want));
    want->request_id = next_request_id(engine);
    memcpy(want->package_root, dl->root, 32);
    if (global_chunk == SWARM_MANIFEST_CHUNK) {
        want->object_kind = VCS_PACKAGE_SWARM_OBJECT_MANIFEST;
        want->file_index = UINT32_MAX;
        want->chunk_index = UINT32_MAX;
    } else {
        want->object_kind = VCS_PACKAGE_SWARM_OBJECT_CHUNK;
        want->file_index = dl->file_of[global_chunk];
        want->chunk_index = dl->chunk_of[global_chunk];
        const struct vcs_package_file *file =
            &dl->manifest.files[want->file_index];
        memcpy(want->expected_hash,
               file->chunk_hashes + (size_t)want->chunk_index * 32u, 32);
    }
    if (!vcs_swarm_queue_frame(engine, peer->id, &msg))
        return false;
    dl->requested_objects++;
    if (global_chunk != SWARM_MANIFEST_CHUNK)
        dl->requested_bytes += chunk_len_of(dl, global_chunk);
    req->used = true;
    req->global_chunk = global_chunk;
    req->peer = peer->id;
    req->deadline = now + VCS_SWARM_REQUEST_TIMEOUT_TICKS;
    req->want = *want;
    peer->inflight++;
    return true;
}

static void req_finish(struct vcs_swarm_engine *engine,
                       struct swarm_download *dl, struct swarm_req *req,
                       bool tombstone, bool fulfilled)
{
    int slot = peer_slot(engine, req->peer);
    if (slot >= 0 && engine->peers[slot].inflight > 0)
        engine->peers[slot].inflight--;
    if (tombstone) {
        dl->tombs[dl->tomb_pos].id = req->want.request_id;
        dl->tombs[dl->tomb_pos].fulfilled = fulfilled;
        dl->tomb_pos = (dl->tomb_pos + 1) % VCS_SWARM_TOMBSTONES_PER_DL;
        if (dl->tomb_count < VCS_SWARM_TOMBSTONES_PER_DL)
            dl->tomb_count++;
    }
    req->used = false;
}

/* 0 = no tombstone, 1 = fulfilled (replay offence), 2 = cancelled. */
static int tombstone_kind(const struct swarm_download *dl, uint64_t id)
{
    for (size_t i = 0; i < dl->tomb_count; i++)
        if (dl->tombs[i].id == id)
            return dl->tombs[i].fulfilled ? 1 : 2;
    return 0;
}

/* ── scheduler ──────────────────────────────────────────────────────── */

/* The exact byte length of chunk g (the final chunk of a file may be
 * short). */
static uint64_t chunk_len_of(const struct swarm_download *dl, uint32_t g)
{
    const struct vcs_package_file *file = &dl->manifest.files[dl->file_of[g]];
    uint64_t done = (uint64_t)dl->chunk_of[g] * VCS_PACKAGE_CHUNK_BYTES;
    uint64_t rest = file->size - done;
    return rest < VCS_PACKAGE_CHUNK_BYTES ? rest
                                          : VCS_PACKAGE_CHUNK_BYTES;
}

/* The peer's weekly download allowance gates how much THIS node pulls
 * from it: the free allowance is honored for every tier; a denial is a
 * per-window rate limit (cached per ISO week), never an offence. */
static bool allowance_denied(struct vcs_swarm_engine *engine,
                             struct swarm_peer *peer, uint64_t bytes,
                             int64_t day)
{
    int64_t week = vcs_policy_week_start(day);
    if (peer->allowance_week != week) {
        peer->allowance_week = week;
        peer->allowance_exhausted = false;
    }
    if (peer->allowance_exhausted)
        return true;
    uint64_t downloaded = 0;
    if (engine->book) {
        struct vcs_service_key_totals totals;
        if (vcs_service_key_totals(engine->book, peer->key, day, &totals))
            downloaded = totals.downloaded_this_week;
    }
    struct vcs_policy_decision d =
        vcs_policy_check_download(peer->tier, downloaded, bytes);
    if (!d.allow) {
        peer->allowance_exhausted = true;
        return true;
    }
    return false;
}

/* Least-in-flight advertising peer for this chunk, skipping failed and
 * allowance-exhausted slots. -1 when none qualifies. */
static int pick_peer(const struct vcs_swarm_engine *engine,
                     const struct swarm_download *dl, uint32_t g)
{
    int best = -1;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++) {
        const struct swarm_peer *peer = &engine->peers[i];
        if (!peer_offers_download(dl, peer) ||
            peer->inflight >= VCS_SWARM_PEER_INFLIGHT_MAX ||
            peer->allowance_exhausted)
            continue;
        if (g == SWARM_MANIFEST_CHUNK) {
            if (dl->manifest_failed_mask & (UINT64_C(1) << i))
                continue;
        } else if (dl->peer_failed[g] & (UINT64_C(1) << i)) {
            continue;
        }
        if (best < 0 || peer->inflight < engine->peers[best].inflight)
            best = (int)i;
    }
    return best;
}

/* Issue new WANTs. Caller holds the lock. Rarest-first ACROSS downloads
 * (fewest advertisers first — the wire carries package-level ads only);
 * ascending chunks, least-in-flight peers within a download. */
static void schedule_locked(struct vcs_swarm_engine *engine, int64_t day,
                            uint64_t now)
{
    size_t order[VCS_SWARM_MAX_DOWNLOADS];
    uint32_t ad_counts[VCS_SWARM_MAX_DOWNLOADS];
    size_t active = 0;
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++) {
        if (!engine->dls[i].used ||
            (engine->dls[i].state != VCS_SWARM_DL_WANT_MANIFEST &&
             engine->dls[i].state != VCS_SWARM_DL_CHUNKS))
            continue;
        ad_counts[active] = advertisers_of(engine, &engine->dls[i]);
        order[active++] = i;
    }
    /* Insertion sort by advertiser count ascending (stable). */
    for (size_t i = 1; i < active; i++) {
        size_t k = order[i];
        uint32_t c = ad_counts[i];
        size_t j = i;
        while (j > 0 && ad_counts[j - 1] > c) {
            order[j] = order[j - 1];
            ad_counts[j] = ad_counts[j - 1];
            j--;
        }
        order[j] = k;
        ad_counts[j] = c;
    }

    for (size_t oi = 0; oi < active; oi++) {
        struct swarm_download *dl = &engine->dls[order[oi]];
        if (dl->state == VCS_SWARM_DL_WANT_MANIFEST) {
            if (dl->manifest_attempts >= VCS_SWARM_MAX_CHUNK_ATTEMPTS) {
                dl_fail(engine, dl, "manifest-attempts-exhausted");
                continue;
            }
            bool outstanding = false;
            for (size_t r = 0; r < SWARM_DL_INFLIGHT_MAX; r++)
                if (dl->reqs[r].used &&
                    dl->reqs[r].global_chunk == SWARM_MANIFEST_CHUNK)
                    outstanding = true;
            if (!outstanding) {
                /* Terminal check BEFORE scheduling: every advertiser has
                 * already served a bad manifest (manifest_failed_mask),
                 * so no assignment can ever succeed. Zero advertisers is
                 * NOT a failure — a fresh fetch honestly waits for the
                 * first ANNOUNCE. */
                if (advertisers_of(engine, dl) > 0) {
                    bool eligible = false;
                    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
                        if (peer_offers_download(dl, &engine->peers[i]) &&
                            !(dl->manifest_failed_mask &
                              (UINT64_C(1) << i)))
                            eligible = true;
                    if (!eligible) {
                        dl_fail(engine, dl, "no-serving-peer");
                        continue;
                    }
                }
                int slot = pick_peer(engine, dl, SWARM_MANIFEST_CHUNK);
                if (slot >= 0) {
                    issue_want(engine, dl, &engine->peers[slot],
                               SWARM_MANIFEST_CHUNK, now);
                    dl->manifest_attempts++;
                }
            }
            continue;
        }
        /* CHUNKS terminal checks. Attempts are consumed by invalid DATA
         * AND by timeout retries (timeouts_locked); peer_failed masks
         * exclude a chunk's bad advertisers permanently. A download is
         * terminally stuck — and must SAY so — when every unfinished
         * chunk exhausted its bounded attempts ("chunk-attempts-
         * exhausted"), or when no unfinished chunk has any eligible
         * advertiser left while at least one peer still advertises the
         * root ("no-serving-peer": a peer that served bad data is a
         * named failure; ZERO advertisers is not — a fetch honestly
         * waits for the first ANNOUNCE, and an allowance-exhausted peer
         * still counts as eligible because the weekly allowance is a
         * rate limit, never a failure). A complete download never
         * reaches this: the all-have sweep moves it to COMPLETE first. */
        uint32_t unfinished = 0, exhausted = 0, assignable = 0;
        for (uint32_t g = 0; g < dl->total_chunks; g++) {
            if (bitmap_get(dl->have, g))
                continue;
            unfinished++;
            if (dl->chunk_attempts[g] >= VCS_SWARM_MAX_CHUNK_ATTEMPTS) {
                exhausted++;
                continue;
            }
            for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
                if (peer_offers_download(dl, &engine->peers[i]) &&
                    !(dl->peer_failed[g] & (UINT64_C(1) << i))) {
                    assignable++;
                    break;
                }
        }
        if (unfinished > 0 && exhausted == unfinished) {
            dl_fail(engine, dl, "chunk-attempts-exhausted");
            continue;
        }
        if (unfinished > 0 && assignable == 0 && dl_inflight(dl) == 0 &&
            advertisers_of(engine, dl) > 0) {
            dl_fail(engine, dl, "no-serving-peer");
            continue;
        }
        for (uint32_t g = 0; g < dl->total_chunks; g++) {
            if (dl_inflight(dl) >= SWARM_DL_INFLIGHT_MAX ||
                global_inflight(engine) >= VCS_SWARM_GLOBAL_INFLIGHT_MAX)
                break;
            if (bitmap_get(dl->have, g) ||
                dl->chunk_attempts[g] >= VCS_SWARM_MAX_CHUNK_ATTEMPTS)
                continue;
            bool outstanding = false;
            for (size_t r = 0; r < SWARM_DL_INFLIGHT_MAX; r++)
                if (dl->reqs[r].used && dl->reqs[r].global_chunk == g)
                    outstanding = true;
            if (outstanding)
                continue;
            for (;;) {
                int slot = pick_peer(engine, dl, g);
                if (slot < 0)
                    break;
                if (allowance_denied(engine, &engine->peers[slot],
                                     chunk_len_of(dl, g), day))
                    continue;
                if (issue_want(engine, dl, &engine->peers[slot], g, now))
                    dl->chunk_attempts[g]++;
                break;
            }
        }
    }
}

static void timeouts_locked(struct vcs_swarm_engine *engine, uint64_t now)
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
            req_finish(engine, dl, req, true, false);
            if (g == SWARM_MANIFEST_CHUNK)
                dl->manifest_attempts++;
            else
                dl->chunk_attempts[g]++;
        }
    }
}

/* ── inbound frame handlers (lock held) ─────────────────────────────── */

static void handle_announce(struct vcs_swarm_engine *engine,
                            struct swarm_peer *peer,
                            const struct vcs_package_swarm_announce *a,
                            size_t frame_len, int64_t day, uint64_t now,
                            struct vcs_swarm_frame_result *res)
{
    /* Announcements NEVER earn credit — recorded on every announce. */
    book_no_credit(engine, peer, VCS_POLICY_NO_CREDIT_ANNOUNCEMENT,
                   frame_len, day);
    if (peer->announce_count == 0 || now >= peer->announce_start +
                                      VCS_SWARM_ANNOUNCE_WINDOW_TICKS) {
        peer->announce_start = now;
        peer->announce_count = 0;
    }
    /* Keep-alive of a root already in peer->ads[] is accepted and does
     * not consume the unique-root inventory quota or raise ANNOUNCE_FLOOD. */
    int existing = peer_ad_index(peer, a->package_root);
    if (existing >= 0) {
        /* A live authenticated ANNOUNCE supersedes finite DHT evidence for
         * this transport session. Disconnect still clears the whole table. */
        peer->ad_expires_at[existing] = 0;
        return;
    }
    struct vcs_policy_decision d =
        vcs_policy_check_announce(peer->tier, peer->announce_count);
    if (!d.allow) {
        uint32_t total = book_offence(engine, peer,
                                      VCS_POLICY_OFFENCE_ANNOUNCE_FLOOD,
                                      day);
        res->penalty = VCS_SWARM_PENALTY_ANNOUNCE_FLOOD;
        res->rule = d.rule;
        res->disconnect_peer =
            total >= VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD;
        return;
    }
    peer->announce_count++;
    if (peer->ad_count < VCS_SWARM_MAX_PEER_ADS) {
        memcpy(peer->ads[peer->ad_count], a->package_root, 32);
        peer->ad_expires_at[peer->ad_count++] = 0;
    }
}

/* Public-hosting admission for one root.
 *
 * Every byte this node offers a stranger passes through here: the ANNOUNCE
 * that advertises a root and the WANT that asks for its manifest or its
 * chunks. Completeness is not enough. The root must match one of the
 * closed shapes in vcs/package_public_shape.h, and the shapes that carry
 * source for other people to build must re-derive their whole signed,
 * permissively licensed closure — dependency graph included — out of the
 * bytes we hold. Anything else is refused by name.
 *
 * Caching. A self-contained verdict is only invalidated by this package
 * changing, so it keys on the package's own generation. A verdict that
 * rested on the dependency graph can be falsified by a SIBLING package
 * being evicted or mutated, which that generation cannot see, so it keys
 * on the store-wide epoch as well. Getting this wrong would keep serving a
 * package whose dependencies this node can no longer hand over.
 *
 * Called with engine->lock held; takes the store lock beneath it, which is
 * the order the serve path already uses. */
bool vcs_swarm_public_serveable(struct vcs_swarm_engine *engine,
                                const uint8_t root[32], const char **rule_out)
{
    struct vcs_package_possession_receipt receipt;
    memset(&receipt, 0, sizeof(receipt));
    if (!vcs_package_store_possession_snapshot(engine->store, root,
                                               &receipt)) {
        if (rule_out) *rule_out = "not-tracked";
        return false;
    }
    uint64_t epoch = vcs_package_store_mutation_epoch(engine->store);
    struct swarm_public_entry *slot =
        &engine->public_cache[root[0] % VCS_SWARM_PUBLIC_CACHE_SLOTS];
    bool stale = !slot->used || memcmp(slot->root, root, 32) != 0 ||
                 slot->generation != receipt.mutation_generation ||
                 (slot->dep_scoped && slot->epoch != epoch);
    if (stale) {
        struct vcs_package_public_verdict verdict;
        vcs_package_public_shape_classify(engine->store, root, &verdict);
        memcpy(slot->root, root, 32);
        slot->generation = receipt.mutation_generation;
        slot->epoch = epoch;
        slot->shape = verdict.shape;
        slot->rule = verdict.rule;
        slot->dep_scoped = verdict.dep_scoped;
        slot->used = true;
    }
    if (rule_out)
        *rule_out = slot->rule;
    return slot->shape != VCS_PACKAGE_PUBLIC_REFUSED;
}

static void serve_manifest_want(struct vcs_swarm_engine *engine,
                                struct swarm_peer *peer,
                                const struct vcs_package_swarm_object *want,
                                int64_t day, struct vcs_swarm_frame_result *res)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(engine->store,
                                            want->package_root, &wire,
                                            &wire_len) !=
        VCS_PACKAGE_STORE_OK) {
        free(wire);
        return; /* not tracked here: silent, no offence */
    }
    struct vcs_package_swarm_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = VCS_PACKAGE_SWARM_DATA;
    msg.body.data.object = *want;
    msg.body.data.bytes = wire;
    msg.body.data.bytes_len = (uint32_t)wire_len;
    size_t need = vcs_package_swarm_wire_size(&msg);
    uint8_t *reply = zcl_malloc(need, "vcs_swarm_manifest_reply");
    if (!reply) {
        free(wire);
        LOG_WARN(SWARM_LOG, "manifest reply allocation failed");
        return;
    }
    size_t reply_len = 0;
    bool ok = vcs_package_swarm_serialize(&msg, reply, need, &reply_len);
    free(wire);
    if (!ok) {
        free(reply);
        LOG_WARN(SWARM_LOG, "manifest reply serialization failed");
        return;
    }
    book_credit_upload(engine, peer, want->request_id, want->package_root,
                       wire_len, day);
    peer->verified_served += wire_len;
    res->reply = reply;
    res->reply_len = reply_len;
}

/* Load the serve-cache manifest for a root. False when untracked. */
static bool serve_cache_load(struct vcs_swarm_engine *engine,
                             const uint8_t root[32])
{
    if (engine->serve_loaded &&
        memcmp(engine->serve_root, root, 32) == 0)
        return true;
    if (engine->serve_loaded) {
        vcs_package_manifest_free(&engine->serve_manifest);
        engine->serve_loaded = false;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_store_get_manifest_wire(engine->store, root, &wire,
                                            &wire_len) !=
        VCS_PACKAGE_STORE_OK) {
        free(wire);
        return false;
    }
    bool ok =
        vcs_package_manifest_parse(wire, wire_len, &engine->serve_manifest);
    free(wire);
    if (!ok)
        LOG_FAIL(SWARM_LOG, "serve manifest parse failed");
    memcpy(engine->serve_root, root, 32);
    engine->serve_loaded = true;
    return true;
}

static void serve_chunk_want(struct vcs_swarm_engine *engine,
                             struct swarm_peer *peer,
                             const struct vcs_package_swarm_object *want,
                             int64_t day, struct vcs_swarm_frame_result *res)
{
    if (!serve_cache_load(engine, want->package_root))
        return; /* untracked: silent */
    const struct vcs_package_manifest *m = &engine->serve_manifest;
    if (want->file_index >= m->count)
        return;
    const struct vcs_package_file *file = &m->files[want->file_index];
    if (want->chunk_index >= file->chunk_count)
        return;
    /* The WANT's expected hash must equal the manifest's commitment at
     * those coordinates — otherwise the requester is fishing for bytes
     * under a root it does not actually hold. Silent no-serve. */
    if (memcmp(file->chunk_hashes + (size_t)want->chunk_index * 32u,
               want->expected_hash, 32) != 0)
        return;
    uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    if (vcs_package_store_get_chunk_at(engine->store, want->package_root,
                                       want->file_index, want->chunk_index,
                                       &chunk, &chunk_len) !=
        VCS_PACKAGE_STORE_OK)
        return; /* we do not hold this chunk: silent */
    struct vcs_package_swarm_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = VCS_PACKAGE_SWARM_DATA;
    msg.body.data.object = *want;
    msg.body.data.bytes = chunk;
    msg.body.data.bytes_len = (uint32_t)chunk_len;
    size_t need = vcs_package_swarm_wire_size(&msg);
    uint8_t *reply = zcl_malloc(need, "vcs_swarm_chunk_reply");
    if (!reply) {
        free(chunk);
        LOG_WARN(SWARM_LOG, "chunk reply allocation failed");
        return;
    }
    size_t reply_len = 0;
    bool ok = vcs_package_swarm_serialize(&msg, reply, need, &reply_len);
    free(chunk);
    if (!ok) {
        free(reply);
        LOG_WARN(SWARM_LOG, "chunk reply serialization failed");
        return;
    }
    book_credit_upload(engine, peer, want->request_id, want->package_root,
                       chunk_len, day);
    peer->verified_served += chunk_len;
    res->reply = reply;
    res->reply_len = reply_len;
}

static void handle_want(struct vcs_swarm_engine *engine,
                        struct swarm_peer *peer,
                        const struct vcs_package_swarm_object *want,
                        size_t frame_len, int64_t day, uint64_t now,
                        struct vcs_swarm_frame_result *res)
{
    /* Replay window: a repeated request id is always a replay (retries
     * use fresh ids). No service, no credit, named offence. */
    for (size_t i = 0; i < peer->seen_count; i++) {
        if (peer->seen[i] == want->request_id) {
            LOG_WARN(SWARM_LOG, "duplicate want %llu refused",
                     (unsigned long long)want->request_id);
            book_offence(engine, peer,
                         VCS_POLICY_OFFENCE_DUPLICATE_REQUEST, day);
            book_no_credit(engine, peer,
                           VCS_POLICY_NO_CREDIT_DUPLICATE_REQUEST,
                           frame_len, day);
            res->penalty = VCS_SWARM_PENALTY_REPLAYED_REQUEST;
            res->rule = "duplicate-request";
            return;
        }
    }
    if (peer->burst_count == 0 ||
        now >= peer->burst_start + VCS_SWARM_BURST_WINDOW_TICKS) {
        peer->burst_start = now;
        peer->burst_count = 0;
    }
    struct vcs_policy_decision d =
        vcs_policy_check_request_burst(peer->tier, peer->burst_count);
    if (!d.allow) {
        LOG_WARN(SWARM_LOG, "want refused: %s (burst window hot)",
                 d.rule);
        uint32_t total = book_offence(engine, peer,
                                      VCS_POLICY_OFFENCE_REQUEST_FLOOD,
                                      day);
        res->penalty = VCS_SWARM_PENALTY_REQUEST_FLOOD;
        res->rule = d.rule;
        res->disconnect_peer =
            total >= VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD;
        return;
    }
    peer->burst_count++;
    peer->seen[peer->seen_pos] = want->request_id;
    peer->seen_pos = (peer->seen_pos + 1) % VCS_SWARM_SEEN_IDS_PER_PEER;
    if (peer->seen_count < VCS_SWARM_SEEN_IDS_PER_PEER)
        peer->seen_count++;
    if (!engine->store)
        return;
    /* Public-hosting admission. Refusing is not an offence: the requester
     * has no way to know what this node will host, so it costs them
     * nothing but gets a named rule instead of silence. The rule is also
     * the operator's only clue when a fetch stalls against this node, so
     * it reaches the log too — the wire stays silent, the log does not. */
    const char *rule = NULL;
    if (!vcs_swarm_public_serveable(engine, want->package_root, &rule)) {
        char root_hex[65];
        zcl_hex_encode(want->package_root, 32, root_hex);
        LOG_WARN(SWARM_LOG, "refused want for %.16s: %s", root_hex, rule);
        res->rule = rule;
        return;
    }
    if (want->object_kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST)
        serve_manifest_want(engine, peer, want, day, res);
    else
        serve_chunk_want(engine, peer, want, day, res);
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

/* Cancel every outstanding request of a download (completion/cancel
 * path): queue CANCEL frames and tombstone the ids as cancelled. */
void vcs_swarm_cancel_outstanding(struct vcs_swarm_engine *engine,
                                  struct swarm_download *dl)
{
    for (size_t i = 0; i < SWARM_DL_INFLIGHT_MAX; i++) {
        struct swarm_req *req = &dl->reqs[i];
        if (!req->used)
            continue;
        struct vcs_package_swarm_message msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = VCS_PACKAGE_SWARM_CANCEL;
        msg.body.cancel.request_id = req->want.request_id;
        memcpy(msg.body.cancel.package_root, dl->root, 32);
        uint64_t peer = req->peer;
        req_finish(engine, dl, req, true, false);
        vcs_swarm_queue_frame(engine, peer, &msg);
    }
}

static void handle_data_manifest(struct vcs_swarm_engine *engine,
                                 struct swarm_peer *peer,
                                 struct swarm_download *dl,
                                 struct swarm_req *req,
                                 const struct vcs_package_swarm_data *data,
                                 int64_t day, struct vcs_swarm_frame_result *res)
{
    if (!vcs_package_swarm_verify_data(NULL, &req->want, data)) {
        book_offence(engine, peer, VCS_POLICY_OFFENCE_INVALID_CHUNK, day);
        book_no_credit(engine, peer, VCS_POLICY_NO_CREDIT_UNVERIFIED,
                       data->bytes_len, day);
        dl->manifest_failed_mask |=
            UINT64_C(1) << (size_t)peer_slot(engine, peer->id);
        req_finish(engine, dl, req, false, false);
        res->penalty = VCS_SWARM_PENALTY_INVALID_DATA;
        res->rule = "invalid-chunk";
        return;
    }
    /* Verified against the announced root and parsed against the persistent
     * caller byte ceiling BEFORE the store sees it or any chunk is wanted. */
    struct vcs_package_manifest parsed;
    if (!vcs_package_manifest_parse(data->bytes, data->bytes_len, &parsed)) {
        req_finish(engine, dl, req, true, false);
        dl_fail(engine, dl, "manifest-reparse-failed");
        res->rule = dl->rule;
        return;
    }
    dl->manifest = parsed;
    dl->manifest_loaded = true;
    if (!vcs_swarm_manifest_within_bound(
            &dl->manifest, dl->maximum_package_bytes)) {
        req_finish(engine, dl, req, true, false);
        dl_fail(engine, dl, "maximum-package-bytes-exceeded");
        res->rule = dl->rule;
        return;
    }
    enum vcs_package_store_result sr = vcs_package_store_put_manifest(
        engine->store, data->bytes, data->bytes_len, NULL);
    if (sr != VCS_PACKAGE_STORE_OK) {
        req_finish(engine, dl, req, true, false);
        dl_fail(engine, dl, vcs_package_store_result_string(sr));
        res->rule = dl->rule;
        return;
    }
    if (!dl_build_maps(dl)) {
        req_finish(engine, dl, req, true, false);
        dl_fail(engine, dl, "allocation-failed");
        res->rule = dl->rule;
        return;
    }
    dl_rebuild_have(engine, dl); /* dedup: chunks already in the CAS */
    dl->reused_objects = dl->have_count;
    for (uint32_t g = 0; g < dl->total_chunks; g++)
        if (bitmap_get(dl->have, g))
            dl->reused_bytes += chunk_len_of(dl, g);
    book_credit_download(engine, peer, req->want.request_id, dl->root,
                         data->bytes_len, day);
    peer->verified_from += data->bytes_len;
    /* A manifest's exact byte length is learned only from the verified DATA;
     * chunk lengths are committed by the manifest and counted at WANT time. */
    dl->requested_bytes += data->bytes_len;
    dl->transferred_bytes += data->bytes_len;
    dl->transferred_objects++;
    dl->fetched_bytes += data->bytes_len;
    req_finish(engine, dl, req, true, true);
    if (dl->total_chunks == 0 || dl->have_count == dl->total_chunks) {
        vcs_swarm_complete_download(engine, dl);
        return;
    }
    dl->state = VCS_SWARM_DL_CHUNKS;
    record_persist(engine, dl);
}

static void handle_data_chunk(struct vcs_swarm_engine *engine,
                              struct swarm_peer *peer,
                              struct swarm_download *dl,
                              struct swarm_req *req,
                              const struct vcs_package_swarm_data *data,
                              int64_t day, struct vcs_swarm_frame_result *res)
{
    uint32_t g = req->global_chunk;
    if (!vcs_package_swarm_verify_data(&dl->manifest, &req->want, data)) {
        book_offence(engine, peer, VCS_POLICY_OFFENCE_INVALID_CHUNK, day);
        book_no_credit(engine, peer, VCS_POLICY_NO_CREDIT_INVALID_CHUNK,
                       data->bytes_len, day);
        int slot = peer_slot(engine, peer->id);
        if (slot >= 0)
            dl->peer_failed[g] |= UINT64_C(1) << (size_t)slot;
        dl->chunk_attempts[g]++;
        req_finish(engine, dl, req, false, false);
        if (dl->chunk_attempts[g] >= VCS_SWARM_MAX_CHUNK_ATTEMPTS)
            dl_fail(engine, dl, "chunk-attempts-exhausted");
        res->penalty = VCS_SWARM_PENALTY_INVALID_DATA;
        res->rule = "invalid-chunk";
        return;
    }
    const char *path = dl->manifest.files[dl->file_of[g]].path;
    enum vcs_package_store_result sr = vcs_package_store_put_chunk(
        engine->store, dl->root, path, dl->chunk_of[g], data->bytes,
        data->bytes_len);
    if (sr != VCS_PACKAGE_STORE_OK) {
        req_finish(engine, dl, req, true, false);
        dl_fail(engine, dl, vcs_package_store_result_string(sr));
        res->rule = dl->rule;
        return;
    }
    if (!bitmap_get(dl->have, g)) {
        bitmap_set(dl->have, g);
        dl->have_count++;
    }
    book_credit_download(engine, peer, req->want.request_id, dl->root,
                         data->bytes_len, day);
    peer->verified_from += data->bytes_len;
    dl->transferred_bytes += data->bytes_len;
    dl->transferred_objects++;
    dl->fetched_bytes += data->bytes_len;
    req_finish(engine, dl, req, true, true);
    if (dl->have_count == dl->total_chunks)
        vcs_swarm_complete_download(engine, dl);
}

static void handle_data(struct vcs_swarm_engine *engine,
                        struct swarm_peer *peer,
                        const struct vcs_package_swarm_data *data,
                        int64_t day, struct vcs_swarm_frame_result *res)
{
    struct swarm_download *dl = dl_find(engine, data->object.package_root);
    struct swarm_req *req =
        dl ? find_outstanding(dl, peer->id, data->object.request_id) : NULL;
    if (!req) {
        /* Nothing outstanding: fulfilled-id replay, cancelled-id late
         * arrival (honest race — no offence), or never requested. */
        int kind = dl ? tombstone_kind(dl, data->object.request_id) : 0;
        if (kind == 1) {
            book_offence(engine, peer,
                         VCS_POLICY_OFFENCE_DUPLICATE_REQUEST, day);
            book_no_credit(engine, peer,
                           VCS_POLICY_NO_CREDIT_DUPLICATE_REQUEST,
                           data->bytes_len, day);
            res->penalty = VCS_SWARM_PENALTY_REPLAYED_DATA;
            res->rule = "duplicate-request";
        } else if (kind == 2) {
            book_no_credit(engine, peer, VCS_POLICY_NO_CREDIT_UNREQUESTED,
                           data->bytes_len, day);
        } else {
            uint32_t total = book_offence(
                engine, peer, VCS_POLICY_OFFENCE_UNREQUESTED_BYTES, day);
            book_no_credit(engine, peer, VCS_POLICY_NO_CREDIT_UNREQUESTED,
                           data->bytes_len, day);
            res->penalty = VCS_SWARM_PENALTY_UNREQUESTED_DATA;
            res->rule = "unrequested-bytes";
            res->disconnect_peer =
                total >= VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD;
        }
        return;
    }
    if (dl->state == VCS_SWARM_DL_WANT_MANIFEST &&
        data->object.object_kind == VCS_PACKAGE_SWARM_OBJECT_MANIFEST) {
        handle_data_manifest(engine, peer, dl, req, data, day, res);
        return;
    }
    if (dl->state == VCS_SWARM_DL_CHUNKS &&
        data->object.object_kind == VCS_PACKAGE_SWARM_OBJECT_CHUNK &&
        dl->manifest_loaded) {
        handle_data_chunk(engine, peer, dl, req, data, day, res);
        return;
    }
    /* Outstanding id but the WRONG object kind/state — the DATA does not
     * reproduce the WANT. Named invalid, no credit. */
    book_offence(engine, peer, VCS_POLICY_OFFENCE_INVALID_CHUNK, day);
    book_no_credit(engine, peer, VCS_POLICY_NO_CREDIT_INVALID_CHUNK,
                   data->bytes_len, day);
    req_finish(engine, dl, req, false, false);
    res->penalty = VCS_SWARM_PENALTY_INVALID_DATA;
    res->rule = "invalid-chunk";
}

/* ── public API ─────────────────────────────────────────────────────── */

static void resume_downloads(struct vcs_swarm_engine *engine)
{
    char dir[STORE_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/downloads", engine->zcode_dir);
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!store_name_is_hex64(ent->d_name))
            continue;
        char path[STORE_PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        struct vcs_swarm_record record;
        if (!vcs_swarm_record_load(path, &record)) {
            LOG_WARN(SWARM_LOG, "discarding corrupt download record %s",
                     ent->d_name);
            unlink(path);
            continue;
        }
        struct swarm_download *dl = NULL;
        for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++)
            if (!engine->dls[i].used) {
                dl = &engine->dls[i];
                break;
            }
        if (!dl) {
            LOG_WARN(SWARM_LOG, "download table full at resume: %s",
                     ent->d_name);
            continue;
        }
        dl_reset(dl);
        dl->used = true;
        memcpy(dl->root, record.root, 32);
        zcl_hex_encode(dl->root, 32, dl->root_hex);
        dl->created_day = record.created_day;
        dl->provider_restricted = record.provider_restricted;
        dl->maximum_package_bytes = record.maximum_package_bytes;
        dl->state = VCS_SWARM_DL_WANT_MANIFEST;
        if (engine->store) {
            struct vcs_package_store_status st;
            memset(&st, 0, sizeof(st));
            bool tracked = vcs_package_store_package_status(
                engine->store, dl->root, &st) && st.tracked;
            if (tracked && st.complete) {
                /* Done while we were down: drop the record. */
                dl_reset(dl);
                unlink(path);
                continue;
            }
            if (tracked && dl_load_manifest_from_store(engine, dl))
                dl->state = dl->have_count == dl->total_chunks
                                ? VCS_SWARM_DL_COMPLETE
                                : VCS_SWARM_DL_CHUNKS;
        }
    }
    closedir(d);
}

/* Load-and-bump the persisted boot nonce: request ids are
 * (nonce << 32) | counter, unique across engine restarts so the
 * slice-11 replayed-request dedup never swallows credit for reissued
 * work. Without persistence the nonce is a fixed 1 (single-lifetime
 * engines, e.g. tests without a zcode_dir). */
static uint64_t nonce_bump(struct vcs_swarm_engine *engine)
{
    if (!engine->persist)
        return 1;
    char path[STORE_PATH_MAX];
    snprintf(path, sizeof(path), "%s/swarm_nonce", engine->zcode_dir);
    uint64_t nonce = 0;
    FILE *f = fopen(path, "rb");
    if (f) {
        uint8_t buf[8];
        if (fread(buf, 1, sizeof(buf), f) == sizeof(buf))
            nonce = vcs_rd_u64le(buf);
        fclose(f);
    }
    nonce++;
    if (nonce >= (UINT64_C(1) << 32))
        nonce = 1;
    uint8_t buf[8];
    vcs_wr_u64le(buf, nonce);
    if (!store_atomic_write(path, buf, sizeof(buf)))
        LOG_WARN(SWARM_LOG, "swarm nonce persist failed (ids may repeat "
                            "across restarts on this datadir)");
    return nonce;
}

struct vcs_swarm_engine *vcs_swarm_engine_create(
    struct vcs_package_store *store, struct vcs_service_book *book,
    const char *zcode_dir, vcs_swarm_score_fn score_fn, void *score_ctx)
{
    struct vcs_swarm_engine *engine =
        zcl_malloc(sizeof(*engine), "vcs_swarm_engine");
    if (!engine)
        LOG_NULL(SWARM_LOG, "swarm engine allocation failed");
    memset(engine, 0, sizeof(*engine));
    pthread_mutex_init(&engine->lock, NULL);
    engine->store = store;
    engine->book = book;
    engine->persist = false;
    if (zcode_dir && strlen(zcode_dir) < STORE_PATH_MAX - 80u) {
        snprintf(engine->zcode_dir, sizeof(engine->zcode_dir), "%s",
                 zcode_dir);
        engine->persist = true;
    }
    engine->score_fn = score_fn;
    engine->score_ctx = score_ctx;
    uint64_t nonce = nonce_bump(engine);
    engine->next_request_id = nonce << 32;
    pthread_mutex_lock(&engine->lock);
    if (engine->persist)
        resume_downloads(engine);
    pthread_mutex_unlock(&engine->lock);
    return engine;
}

enum vcs_package_transport_result vcs_swarm_engine_import_transport(
    struct vcs_swarm_engine *engine, const uint8_t transport_root[32],
    struct vcs_package_transport_import *receipt)
{
    if (!engine || !transport_root || !receipt)
        return VCS_PACKAGE_TRANSPORT_ERR_NULL;
    pthread_mutex_lock(&engine->lock);
    enum vcs_package_transport_result result = engine->store
        ? vcs_package_transport_import(engine->store, transport_root, receipt)
        : VCS_PACKAGE_TRANSPORT_ERR_STORE;
    pthread_mutex_unlock(&engine->lock);
    return result;
}

void vcs_swarm_engine_free(struct vcs_swarm_engine *engine)
{
    if (!engine)
        return;
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++)
        if (engine->dls[i].used)
            dl_free_maps(&engine->dls[i]);
    if (engine->serve_loaded)
        vcs_package_manifest_free(&engine->serve_manifest);
    pthread_mutex_destroy(&engine->lock);
    free(engine);
}

bool vcs_swarm_engine_peer_add(struct vcs_swarm_engine *engine,
                               uint64_t peer, const uint8_t key[33])
{
    if (!engine || !key || peer == 0)
        LOG_FAIL(SWARM_LOG, "null engine/key or zero peer id");
    pthread_mutex_lock(&engine->lock);
    if (peer_slot(engine, peer) >= 0) {
        pthread_mutex_unlock(&engine->lock);
        return true;
    }
    int slot = -1;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
        if (!engine->peers[i].used) {
            slot = (int)i;
            break;
        }
    if (slot < 0) {
        pthread_mutex_unlock(&engine->lock);
        LOG_FAIL(SWARM_LOG, "swarm peer table full");
    }
    struct swarm_peer *p = &engine->peers[slot];
    memset(p, 0, sizeof(*p));
    p->used = true;
    p->id = peer;
    memcpy(p->key, key, 33);
    p->allowance_week = -1;
    p->tier = peer_tier_locked(engine, p);
    /* A fresh session in a recycled slot inherits no chunk failures. */
    uint64_t bit = UINT64_C(1) << (size_t)slot;
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++) {
        struct swarm_download *dl = &engine->dls[i];
        if (!dl->used)
            continue;
        dl->manifest_failed_mask &= ~bit;
        if (dl->peer_failed)
            for (uint32_t g = 0; g < dl->total_chunks; g++)
                dl->peer_failed[g] &= ~bit;
    }
    pthread_mutex_unlock(&engine->lock);
    return true;
}

void vcs_swarm_engine_peer_drop(struct vcs_swarm_engine *engine,
                                uint64_t peer)
{
    if (!engine)
        return;
    pthread_mutex_lock(&engine->lock);
    int slot = peer_slot(engine, peer);
    if (slot < 0) {
        pthread_mutex_unlock(&engine->lock);
        return;
    }
    /* Disconnect requeue: in-flight work returns to the scheduler, which
     * reassigns it with fresh request ids. No attempts are consumed —
     * a disconnect is not a failure. */
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++) {
        struct swarm_download *dl = &engine->dls[i];
        if (!dl->used)
            continue;
        for (size_t r = 0; r < SWARM_DL_INFLIGHT_MAX; r++)
            if (dl->reqs[r].used && dl->reqs[r].peer == peer)
                dl->reqs[r].used = false;
    }
    engine->peers[slot].used = false;
    pthread_mutex_unlock(&engine->lock);
}

bool vcs_swarm_engine_peer_offer(struct vcs_swarm_engine *engine,
                                 uint64_t peer, const uint8_t root[32],
                                 uint64_t expires_at, uint64_t now)
{
    if (!engine || !root || peer == 0)
        LOG_FAIL(SWARM_LOG, "peer_offer: null engine/root or zero id");
    if (expires_at <= now)
        return false;
    pthread_mutex_lock(&engine->lock);
    int slot = peer_slot(engine, peer);
    if (slot < 0) {
        pthread_mutex_unlock(&engine->lock);
        return false;
    }
    struct swarm_peer *p = &engine->peers[slot];
    peer_prune_expired_offers(p, now);
    /* Locally authenticated evidence, not a wire frame: announce quota
     * and flood scoring stay out of this path entirely. */
    int existing = peer_ad_index(p, root);
    if (existing >= 0) {
        /* A session ANNOUNCE (expiry zero) is stronger and stays scoped to
         * the connection. Otherwise retain the latest verified window. */
        if (p->ad_expires_at[existing] != 0 &&
            expires_at > p->ad_expires_at[existing])
            p->ad_expires_at[existing] = expires_at;
        pthread_mutex_unlock(&engine->lock);
        return true;
    }
    if (p->ad_count >= VCS_SWARM_MAX_PEER_ADS) {
        pthread_mutex_unlock(&engine->lock);
        LOG_WARN(SWARM_LOG, "peer %llu ad table full; offer unapplied",
                 (unsigned long long)peer);
        return false;
    }
    memcpy(p->ads[p->ad_count], root, 32);
    p->ad_expires_at[p->ad_count++] = expires_at;
    pthread_mutex_unlock(&engine->lock);
    return true;
}

bool vcs_swarm_engine_peer_known(const struct vcs_swarm_engine *engine,
                                 uint64_t peer)
{
    if (!engine)
        return false;
    /* Read-only probe; the caller holds no lock, so take it briefly. */
    struct vcs_swarm_engine *mut = (struct vcs_swarm_engine *)engine;
    pthread_mutex_lock(&mut->lock);
    bool known = peer_slot(engine, peer) >= 0;
    pthread_mutex_unlock(&mut->lock);
    return known;
}

size_t vcs_swarm_engine_peer_ids(struct vcs_swarm_engine *engine,
                                 uint64_t *out, size_t max)
{
    if (!engine || (!out && max > 0))
        return 0;
    size_t n = 0;
    pthread_mutex_lock(&engine->lock);
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS && n < max; i++)
        if (engine->peers[i].used)
            out[n++] = engine->peers[i].id;
    pthread_mutex_unlock(&engine->lock);
    return n;
}

size_t vcs_swarm_engine_announce_to(struct vcs_swarm_engine *engine,
                                    uint64_t peer)
{
    if (!engine || !engine->store || peer == 0)
        return 0;
    struct vcs_package_store_summary summaries[VCS_SWARM_MAX_LOCAL_ANNOUNCES];
    size_t n = vcs_package_store_list_summaries(
        engine->store, true, summaries, VCS_SWARM_MAX_LOCAL_ANNOUNCES);
    pthread_mutex_lock(&engine->lock);
    int slot = peer_slot(engine, peer);
    if (slot < 0) {
        pthread_mutex_unlock(&engine->lock);
        return 0;
    }
    struct swarm_peer *p = &engine->peers[slot];
    size_t queued = 0;
    for (size_t i = 0; i < n; i++) {
        if (vcs_swarm_peer_was_announced(p, summaries[i].root))
            continue;
        /* Advertise only what this node would actually serve. Announcing a
         * root we would then refuse is worse than not announcing it: it
         * spends the peer's request budget on an answer that cannot come. */
        if (!vcs_swarm_public_serveable(engine, summaries[i].root, NULL))
            continue;
        struct vcs_package_swarm_message msg;
        memset(&msg, 0, sizeof(msg));
        msg.type = VCS_PACKAGE_SWARM_ANNOUNCE;
        memcpy(msg.body.announce.package_root, summaries[i].root, 32);
        msg.body.announce.manifest_bytes = summaries[i].manifest_bytes;
        msg.body.announce.file_count = summaries[i].file_count;
        msg.body.announce.total_bytes = summaries[i].total_bytes;
        msg.body.announce.total_chunks = summaries[i].total_chunks;
        if (!vcs_swarm_queue_frame(engine, peer, &msg))
            break;
        if (p->announced_count < VCS_SWARM_MAX_LOCAL_ANNOUNCES)
            memcpy(p->announced[p->announced_count++], summaries[i].root,
                   32);
        queued++;
    }
    pthread_mutex_unlock(&engine->lock);
    return queued;
}

bool vcs_swarm_engine_transfer_snapshot(
    struct vcs_swarm_engine *engine, uint64_t peer,
    struct vcs_swarm_transfer *out)
{
    if (!engine || !out || peer == 0)
        return false;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&engine->lock);
    int slot = peer_slot(engine, peer);
    if (slot < 0) {
        pthread_mutex_unlock(&engine->lock);
        return false;
    }
    const struct swarm_peer *p = &engine->peers[slot];
    if (p->xfer_served == 0 && p->xfer_fetched == 0) {
        pthread_mutex_unlock(&engine->lock);
        return false;
    }
    memcpy(out->package_root, p->xfer_root, 32);
    out->served = p->xfer_served;
    out->fetched = p->xfer_fetched;
    pthread_mutex_unlock(&engine->lock);
    return true;
}

struct vcs_swarm_frame_result vcs_swarm_engine_handle_frame(
    struct vcs_swarm_engine *engine, uint64_t peer, const uint8_t *frame,
    size_t frame_len, int64_t day, uint64_t now)
{
    struct vcs_swarm_frame_result res;
    memset(&res, 0, sizeof(res));
    if (!engine || !frame || peer == 0) {
        res.penalty = VCS_SWARM_PENALTY_MALFORMED;
        res.rule = "bad-input";
        return res;
    }
    pthread_mutex_lock(&engine->lock);
    int slot = peer_slot(engine, peer);
    if (slot < 0) {
        pthread_mutex_unlock(&engine->lock);
        LOG_WARN(SWARM_LOG, "dropped frame from unregistered peer %llu",
                 (unsigned long long)peer);
        res.rule = "unknown-peer";
        return res;
    }
    struct swarm_peer *p = &engine->peers[slot];
    struct vcs_package_swarm_message msg;
    if (!vcs_package_swarm_parse(frame, frame_len, &msg)) {
        pthread_mutex_unlock(&engine->lock);
        res.penalty = VCS_SWARM_PENALTY_MALFORMED;
        res.rule = "malformed-frame";
        return res;
    }
    switch (msg.type) {
    case VCS_PACKAGE_SWARM_ANNOUNCE:
        handle_announce(engine, p, &msg.body.announce, frame_len, day, now,
                        &res);
        break;
    case VCS_PACKAGE_SWARM_WANT:
        handle_want(engine, p, &msg.body.want, frame_len, day, now, &res);
        break;
    case VCS_PACKAGE_SWARM_DATA:
        handle_data(engine, p, &msg.body.data, day, &res);
        break;
    case VCS_PACKAGE_SWARM_CANCEL:
        /* A peer cancelling its own WANT: serving is synchronous, so
         * there is nothing to undo and nothing to credit. */
        break;
    default:
        res.penalty = VCS_SWARM_PENALTY_MALFORMED;
        res.rule = "malformed-frame";
        break;
    }
    pthread_mutex_unlock(&engine->lock);
    return res;
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

static enum vcs_swarm_fetch_result swarm_fetch(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    int64_t day, uint64_t now, const uint64_t *provider_peers,
    size_t provider_count, bool restricted, uint64_t maximum_package_bytes)
{
    (void)now; /* the tick owns scheduling; fetch only registers intent */
    if (!engine || !package_root)
        return VCS_SWARM_FETCH_BAD_INPUT;
    static const uint8_t zero[32] = {0};
    if (memcmp(package_root, zero, 32) == 0)
        return VCS_SWARM_FETCH_BAD_INPUT;
    if (restricted) {
        enum vcs_swarm_fetch_result input =
            provider_input_result(provider_peers, provider_count);
        if (input != VCS_SWARM_FETCH_OK)
            return input;
    }
    pthread_mutex_lock(&engine->lock);
    if (!engine->store) {
        pthread_mutex_unlock(&engine->lock);
        return VCS_SWARM_FETCH_NO_STORE;
    }
    struct swarm_download *dl = dl_find(engine, package_root);
    if (dl && dl->state == VCS_SWARM_DL_COMPLETE) {
        struct vcs_package_store_status complete_status;
        memset(&complete_status, 0, sizeof(complete_status));
        if (vcs_package_store_package_status(
                engine->store, package_root, &complete_status) &&
            complete_status.complete) {
            pthread_mutex_unlock(&engine->lock);
            return VCS_SWARM_FETCH_ALREADY_COMPLETE;
        }
        /* COMPLETE is a possession cache, never authority. A verified read
         * may have quarantined a corrupt CAS object since this slot last ran;
         * discard the stale scheduler state so the tracked manifest can
         * rebuild its have-bitmap and fetch the missing coordinate. */
        dl_reset(dl);
        dl = NULL;
    }
    if (dl && dl->state == VCS_SWARM_DL_FAILED) {
        /* Operator retry after a named failure: start clean. */
        dl_reset(dl);
        dl = NULL;
    }
    if (dl) {
        /* Never tighten shared work; ordinary demand lifts a scout bound. */
        if (maximum_package_bytes > 0 &&
            (dl->maximum_package_bytes == 0 ||
             maximum_package_bytes < dl->maximum_package_bytes)) {
            pthread_mutex_unlock(&engine->lock);
            return VCS_SWARM_FETCH_BOUND_NOT_OWNED;
        }
        if (maximum_package_bytes == 0 && dl->maximum_package_bytes > 0) {
            dl->maximum_package_bytes = 0;
            (void)record_persist(engine, dl);
        }
        if (restricted) {
            dl->provider_restricted = true;
            dl_set_providers(dl, provider_peers, provider_count);
            (void)record_persist(engine, dl);
        }
        pthread_mutex_unlock(&engine->lock);
        return VCS_SWARM_FETCH_OK;
    }
    struct vcs_package_store_status st;
    memset(&st, 0, sizeof(st));
    bool already_tracked =
        vcs_package_store_package_status(engine->store, package_root,
                                         &st) && st.tracked;
    if (already_tracked && st.complete) {
        pthread_mutex_unlock(&engine->lock);
        return VCS_SWARM_FETCH_ALREADY_COMPLETE;
    }
    /* Prefer a free, then durable-complete, then failed slot. */
    int slot = -1, complete_slot = -1, failed_slot = -1;
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++) {
        if (!engine->dls[i].used) {
            slot = (int)i;
            break;
        }
        if (engine->dls[i].state == VCS_SWARM_DL_COMPLETE &&
            complete_slot < 0)
            complete_slot = (int)i;
        if (engine->dls[i].state == VCS_SWARM_DL_FAILED && failed_slot < 0)
            failed_slot = (int)i;
    }
    if (slot < 0)
        slot = complete_slot >= 0 ? complete_slot : failed_slot;
    if (slot < 0) {
        pthread_mutex_unlock(&engine->lock);
        return VCS_SWARM_FETCH_FULL;
    }
    dl = &engine->dls[slot];
    dl_reset(dl);
    dl->used = true;
    memcpy(dl->root, package_root, 32);
    zcl_hex_encode(dl->root, 32, dl->root_hex);
    dl->state = VCS_SWARM_DL_WANT_MANIFEST;
    dl->created_day = day;
    dl->provider_restricted = restricted;
    dl->maximum_package_bytes = maximum_package_bytes;
    dl_set_providers(dl, provider_peers, provider_count);
    /* The resumable record lands FIRST — a crash after this point
     * resumes the fetch. */
    if (engine->persist && !record_persist(engine, dl)) {
        dl_reset(dl);
        pthread_mutex_unlock(&engine->lock);
        return VCS_SWARM_FETCH_RECORD_IO;
    }
    /* A tracked-but-incomplete package (staged manifest from an earlier
     * publish/fetch) resumes directly in CHUNKS. */
    if (already_tracked && dl_load_manifest_from_store(engine, dl)) {
        dl->state = dl->have_count == dl->total_chunks
                        ? VCS_SWARM_DL_COMPLETE
                        : VCS_SWARM_DL_CHUNKS;
        if (dl->state == VCS_SWARM_DL_COMPLETE)
            vcs_swarm_record_delete_dl(engine, dl);
    }
    /* No scheduling here: the tick owns assignment order (deterministic
     * rarest-first across downloads). */
    pthread_mutex_unlock(&engine->lock);
    return VCS_SWARM_FETCH_OK;
}

enum vcs_swarm_fetch_result vcs_swarm_engine_fetch(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    int64_t day, uint64_t now)
{
  return swarm_fetch(engine, package_root, day, now, NULL, 0, false, 0);
}

enum vcs_swarm_fetch_result vcs_swarm_engine_fetch_from(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    int64_t day, uint64_t now, const uint64_t *provider_peers,
    size_t provider_count)
{
    return swarm_fetch(engine, package_root, day, now, provider_peers,
                       provider_count, true, 0);
}
enum vcs_swarm_fetch_result vcs_swarm_engine_fetch_from_bounded(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    int64_t day, uint64_t now, const uint64_t *provider_peers,
    size_t provider_count, uint64_t maximum_package_bytes)
{
    if (maximum_package_bytes == 0)
        return VCS_SWARM_FETCH_BAD_INPUT;
    return swarm_fetch(engine, package_root, day, now, provider_peers,
                       provider_count, true, maximum_package_bytes);
}

/* Cancel an active download: queues CANCEL per outstanding request,
 * tombstones the ids, deletes the record. The slot is kept as a named
 * FAILED("operator-cancelled") record so late DATA for a tombstoned id
 * stays the honest race (no credit, no offence); a fresh fetch reuses
 * the slot. False when not active. */
bool vcs_swarm_engine_cancel(struct vcs_swarm_engine *engine,
                             const uint8_t package_root[32], uint64_t now)
{
    if (!engine || !package_root)
        return false;
    pthread_mutex_lock(&engine->lock);
    struct swarm_download *dl = dl_find(engine, package_root);
    if (!dl || dl->state == VCS_SWARM_DL_COMPLETE ||
        dl->state == VCS_SWARM_DL_FAILED) {
        pthread_mutex_unlock(&engine->lock);
        return false;
    }
    (void)now;
    vcs_swarm_cancel_outstanding(engine, dl);
    vcs_swarm_record_delete_dl(engine, dl);
    dl->state = VCS_SWARM_DL_FAILED;
    dl->rule = "operator-cancelled";
    pthread_mutex_unlock(&engine->lock);
    return true;
}

void vcs_swarm_engine_tick(struct vcs_swarm_engine *engine, int64_t day,
                           uint64_t now)
{
    if (!engine)
        return;
    pthread_mutex_lock(&engine->lock);
    if (engine->ticked && engine->last_tick == now) {
        pthread_mutex_unlock(&engine->lock);
        return;
    }
    engine->ticked = true;
    engine->last_tick = now;
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
        if (engine->peers[i].used) {
            peer_prune_expired_offers(&engine->peers[i], now);
            engine->peers[i].tier = peer_tier_locked(engine,
                                                     &engine->peers[i]);
        }
    timeouts_locked(engine, now);
    if (engine->store)
        schedule_locked(engine, day, now);
    pthread_mutex_unlock(&engine->lock);
}

void vcs_swarm_engine_schedule_ready(struct vcs_swarm_engine *engine,
                                     int64_t day, uint64_t now)
{
    if (!engine)
        return;
    pthread_mutex_lock(&engine->lock);
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS; i++)
        if (engine->peers[i].used)
            peer_prune_expired_offers(&engine->peers[i], now);
    if (engine->store)
        schedule_locked(engine, day, now);
    pthread_mutex_unlock(&engine->lock);
}

bool vcs_swarm_engine_next_outbound(struct vcs_swarm_engine *engine,
                                    uint64_t peer_filter, uint64_t *peer_out,
                                    uint8_t *out, size_t *out_len)
{
    if (!engine || !peer_out || !out || !out_len)
        return false;
    pthread_mutex_lock(&engine->lock);
    for (size_t scanned = 0; scanned < engine->outq_count; scanned++) {
        size_t slot =
            (engine->outq_pos + scanned) % VCS_SWARM_OUTBOUND_MAX;
        if (peer_filter != 0 && engine->outq[slot].peer != peer_filter)
            continue;
        *peer_out = engine->outq[slot].peer;
        *out_len = engine->outq[slot].len;
        memcpy(out, engine->outq[slot].bytes, *out_len);
        /* Compact: move every later queued frame one slot back. */
        for (size_t j = scanned; j + 1 < engine->outq_count; j++) {
            size_t from = (engine->outq_pos + j + 1) % VCS_SWARM_OUTBOUND_MAX;
            size_t to = (engine->outq_pos + j) % VCS_SWARM_OUTBOUND_MAX;
            engine->outq[to] = engine->outq[from];
        }
        engine->outq_count--;
        pthread_mutex_unlock(&engine->lock);
        return true;
    }
    pthread_mutex_unlock(&engine->lock);
    return false;
}

size_t vcs_swarm_engine_active_downloads(struct vcs_swarm_engine *engine)
{
    if (!engine)
        return 0;
    pthread_mutex_lock(&engine->lock);
    size_t n = 0;
    for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++)
        if (engine->dls[i].state == VCS_SWARM_DL_WANT_MANIFEST ||
            engine->dls[i].state == VCS_SWARM_DL_CHUNKS)
            n++;
    pthread_mutex_unlock(&engine->lock);
    return n;
}

bool vcs_swarm_engine_download_status(struct vcs_swarm_engine *engine,
                                      const uint8_t package_root[32],
                                      struct vcs_swarm_download_status *out)
{
    if (!engine || !package_root || !out)
        return false;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&engine->lock);
    struct swarm_download *dl = dl_find(engine, package_root);
    if (dl) {
        out->state = dl->state;
        out->rule = dl->rule;
        out->advertisers = advertisers_of(engine, dl);
        out->inflight = dl_inflight(dl);
        out->fetched_bytes = dl->fetched_bytes;
        out->requested_bytes = dl->requested_bytes;
        out->transferred_bytes = dl->transferred_bytes;
        out->reused_bytes = dl->reused_bytes;
        out->requested_objects = dl->requested_objects;
        out->transferred_objects = dl->transferred_objects;
        out->reused_objects = dl->reused_objects;
        out->maximum_package_bytes = dl->maximum_package_bytes;
        if (dl->manifest_loaded) {
            out->total_chunks = dl->total_chunks;
            out->present_chunks = dl->have_count;
            uint64_t present = 0, total = 0;
            for (uint32_t g = 0; g < dl->total_chunks; g++) {
                uint64_t len = chunk_len_of(dl, g);
                total += len;
                if (bitmap_get(dl->have, g))
                    present += len;
            }
            out->present_bytes = present;
            out->total_bytes = total;
        }
        pthread_mutex_unlock(&engine->lock);
        return true;
    }
    pthread_mutex_unlock(&engine->lock);
    /* No engine record: fall back to store state so a package the node
     * already hosts reports honestly. */
    out->state = VCS_SWARM_DL_INACTIVE;
    if (engine->store) {
        struct vcs_package_store_status st;
        if (vcs_package_store_package_status(engine->store, package_root,
                                             &st) &&
            st.tracked) {
            out->state = st.complete ? VCS_SWARM_DL_COMPLETE
                                     : VCS_SWARM_DL_INACTIVE;
            out->present_chunks = st.present_chunks;
            out->total_chunks = st.total_chunks;
            out->present_bytes = st.present_bytes;
            out->total_bytes = st.total_bytes;
        }
    }
    return true;
}

size_t vcs_swarm_engine_peers_for(struct vcs_swarm_engine *engine,
                                  const uint8_t package_root[32],
                                  struct vcs_swarm_peer_info *out,
                                  size_t out_max)
{
    if (!engine || !package_root || (!out && out_max > 0))
        return 0;
    size_t n = 0;
    pthread_mutex_lock(&engine->lock);
    for (size_t i = 0; i < VCS_SWARM_MAX_PEERS && n < out_max; i++) {
        struct swarm_peer *peer = &engine->peers[i];
        if (!peer->used || !peer_advertises(peer, package_root))
            continue;
        struct vcs_swarm_peer_info *info = &out[n++];
        memset(info, 0, sizeof(*info));
        info->peer = peer->id;
        memcpy(info->key, peer->key, 33);
        info->tier = peer->tier;
        info->inflight = peer->inflight;
        info->verified_served = peer->verified_served;
        info->verified_from = peer->verified_from;
        info->allowance_exhausted = peer->allowance_exhausted;
        if (engine->book) {
            struct vcs_service_key_totals totals;
            if (vcs_service_key_totals(engine->book, peer->key, -1,
                                       &totals))
                info->offence_total = totals.offence_total;
        }
    }
    pthread_mutex_unlock(&engine->lock);
    return n;
}
