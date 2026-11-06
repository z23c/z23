/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bounded state-offer peer frames and registered bundle serving. */
// supervisor-ok:bounded-object-read — one-shot worker per serve slot, joined before reuse and shutdown; no resident service
#include "config/state_offer_link.h"
#include "base/serialize_le.h"
#include "base/safe_alloc.h"
#include "util/thread_registry.h"
#include "net/rom_seed.h"
#include "net/state_offer.h"
#include "platform/time_compat.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static bool valid_request(const struct state_offer_link_frame *f, uint32_t limit)
{
    return f->total && f->offset < limit && f->total <= limit - f->offset && !f->size;
}
static bool valid_part(const struct state_offer_link_frame *f, uint32_t limit)
{
    return f->total && f->total <= limit && f->size && f->offset <= f->total &&
        f->size <= f->total - f->offset;
}
static bool valid_empty(const struct state_offer_link_frame *f)
{
    return !f->index && !f->offset && !f->total && !f->size;
}
static bool valid_offer_reply(const struct state_offer_link_frame *f)
{
    return !f->index && !f->offset && f->size && f->size == f->total &&
        f->size <= STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES;
}
static bool valid_kind(const struct state_offer_link_frame *f)
{
    switch (f->kind) {
    case STATE_OFFER_LINK_MANIFEST_REQUEST:
        return !f->index && valid_request(f, ROM_SEED_MANIFEST_BLOB_MAX);
    case STATE_OFFER_LINK_CHUNK_REQUEST:
        return f->index < ROM_SEED_MAX_CHUNKS && valid_request(f, ROM_SEED_CHUNK_SIZE);
    case STATE_OFFER_LINK_MANIFEST_PART:
        return !f->index && valid_part(f, ROM_SEED_MANIFEST_BLOB_MAX);
    case STATE_OFFER_LINK_CHUNK_PART:
        return f->index < ROM_SEED_MAX_CHUNKS && valid_part(f, ROM_SEED_CHUNK_SIZE);
    case STATE_OFFER_LINK_OFFER_REQUEST:
    case STATE_OFFER_LINK_REFUSAL:
        return valid_empty(f);
    case STATE_OFFER_LINK_OFFER_REPLY:
        return valid_offer_reply(f);
    }
    return false;
}
static bool valid(const struct state_offer_link_frame *f)
{
    if (!f || f->kind < STATE_OFFER_LINK_MANIFEST_REQUEST || f->kind > STATE_OFFER_LINK_OFFER_REPLY || !f->nonce ||
        f->size > STATE_OFFER_LINK_PAYLOAD_MAX || (f->size && !f->data)) return false;
    return valid_kind(f);
}

bool state_offer_link_encode(const struct state_offer_link_frame *f, uint8_t *out, size_t cap, size_t *used)
{
    if (used) *used = 0;
    if (!used || !out || !valid(f) || cap < STATE_OFFER_LINK_HEADER + f->size) return false;
    memcpy(out, "ZBND", 4);
    out[4] = 1; out[5] = (uint8_t)f->kind; out[6] = out[7] = 0;
    zcl_write_u64_le(out + 8, f->nonce);
    memcpy(out + 16, f->digest, 32);
    zcl_write_u32_le(out + 48, f->index);
    zcl_write_u32_le(out + 52, f->offset);
    zcl_write_u32_le(out + 56, f->total);
    zcl_write_u32_le(out + 60, f->size);
    if (f->size) memcpy(out + STATE_OFFER_LINK_HEADER, f->data, f->size);
    *used = STATE_OFFER_LINK_HEADER + f->size;
    return true;
}

bool state_offer_link_decode(const uint8_t *wire, size_t len, struct state_offer_link_frame *out)
{
    if (!wire || !out || len < STATE_OFFER_LINK_HEADER || len > STATE_OFFER_LINK_FRAME_MAX ||
        memcmp(wire, "ZBND", 4) || wire[4] != 1 || wire[6] || wire[7]) return false;
    struct state_offer_link_frame f = {0};
    f.kind = (enum state_offer_link_kind)wire[5];
    f.nonce = zcl_read_u64_le(wire + 8);
    memcpy(f.digest, wire + 16, 32);
    f.index = zcl_read_u32_le(wire + 48);
    f.offset = zcl_read_u32_le(wire + 52);
    f.total = zcl_read_u32_le(wire + 56);
    f.size = zcl_read_u32_le(wire + 60);
    f.data = wire + STATE_OFFER_LINK_HEADER;
    if (f.size != len - STATE_OFFER_LINK_HEADER || !valid(&f)) return false;
    *out = f;
    return true;
}

static bool registered_bundle(const uint8_t root[32], enum state_offer_link_kind kind,
                              uint32_t index, struct rom_artifact *artifact)
{
    uint32_t checked_index = kind == STATE_OFFER_LINK_MANIFEST_REQUEST ? 0 : index;
    return !(kind == STATE_OFFER_LINK_MANIFEST_REQUEST && index) &&
        rom_seed_serve_lookup(root, checked_index, artifact) == ROM_SERVE_FREE_OK &&
        artifact->kind == ROM_ARTIFACT_CONSENSUS_BUNDLE;
}

bool state_offer_link_read_registered(const char *datadir, enum state_offer_link_kind kind,
                                      const uint8_t root[32], uint32_t index,
                                      uint8_t *scratch, uint32_t cap, uint32_t *size)
{
    if (size) *size = 0;
    if (!datadir || !root || !scratch || !size ||
        (kind != STATE_OFFER_LINK_MANIFEST_REQUEST && kind != STATE_OFFER_LINK_CHUNK_REQUEST)) return false;
    struct rom_artifact artifact;
    if (!registered_bundle(root, kind, index, &artifact)) return false;
    if (kind == STATE_OFFER_LINK_CHUNK_REQUEST)
        return rom_seed_read_chunk(&artifact, datadir, index, scratch, cap, size);
    size_t n = rom_seed_manifest_blob(&artifact, scratch, cap);
    if (!n || n > UINT32_MAX) return false;
    *size = (uint32_t)n;
    return true;
}

/* Each serve slot streams one object to one connection. Its disk read runs in
 * a one-shot worker, so the message thread only
 * copies a bounded request and the peer tick takes a bounded number of ready
 * frames per connection. A slot is free when it is neither working nor ready;
 * clearing a working slot bumps its generation so the late result is dropped.
 * The client abandons an object after SOL_INACTIVITY_SECONDS (30 s) without a
 * part; a slot idle 15 s longer than that has no reader left. */
#define SOL_SERVER_IDLE_MS INT64_C(45000)
struct sol_slot {
    pthread_t thread;
    bool working, ready, thread_started;
    uint64_t generation, peer;
    struct state_offer_link_frame request;
    uint8_t *data;
    uint32_t object_size, cursor, end;
    int64_t last_ms;
};
static struct {
    pthread_mutex_t mutex;
    char datadir[1024];
    bool started, stop;
    void (*wake)(void);
    struct sol_slot slots[STATE_OFFER_LINK_SERVER_SLOTS];
} server = {.mutex = PTHREAD_MUTEX_INITIALIZER};

static void sol_slot_clear_locked(struct sol_slot *s)
{
    free(s->data);
    s->data = NULL;
    s->ready = false;
    s->peer = 0;
    ++s->generation;
}

struct sol_job {
    struct state_offer_link_frame request;
    uint8_t ip[16];
    uint64_t generation;
    size_t slot;
    char datadir[sizeof(server.datadir)];
};

/* Admission, registered read and byte-rate charge for one object. */
static bool sol_server_read(const struct sol_job *job, uint8_t *bytes, uint32_t *size)
{
    bool acquired = bytes && rom_seed_peer_acquire(job->ip);
    bool ok = acquired && state_offer_link_read_registered(job->datadir, job->request.kind, job->request.digest,
                                                            job->request.index, bytes, ROM_SEED_CHUNK_SIZE, size) &&
        rom_seed_rate_charge(job->ip, *size, (int64_t)platform_time_wall_time_t());
    if (acquired) rom_seed_peer_release(job->ip);
    return ok && job->request.offset < *size;
}

/* Publish the object (or a refusal when size is 0) unless the slot moved on. */
static void sol_server_publish(const struct sol_job *job, uint8_t *bytes, uint32_t size)
{
    const struct state_offer_link_frame *r = &job->request;
    pthread_mutex_lock(&server.mutex);
    struct sol_slot *s = &server.slots[job->slot];
    void (*wake)(void) = NULL;
    if (!server.stop && job->generation == s->generation) {
        s->data = size ? bytes : NULL;
        s->object_size = size;
        s->cursor = size ? r->offset : 0;
        s->end = size && r->total < size - r->offset ? r->offset + r->total : size;
        s->ready = true;
        s->last_ms = platform_time_monotonic_ms();
        if (size) bytes = NULL;
        wake = server.wake;
    }
    free(bytes);
    s->working = false;
    pthread_mutex_unlock(&server.mutex);
    if (wake) wake();
}

static void *sol_server_worker(void *arg)
{
    struct sol_job *job = arg;
    uint8_t *bytes = zcl_malloc(ROM_SEED_CHUNK_SIZE, "state_offer_link_chunk");
    uint32_t size = 0;
    if (!sol_server_read(job, bytes, &size)) size = 0;
    sol_server_publish(job, bytes, size);
    free(job);
    return NULL;
}

bool state_offer_link_server_start(const char *datadir, void (*wake)(void))
{
    if (!datadir || !*datadir || strlen(datadir) >= sizeof(server.datadir)) return false;
    pthread_mutex_lock(&server.mutex);
    if (server.started) { pthread_mutex_unlock(&server.mutex); return false; }
    memcpy(server.datadir, datadir, strlen(datadir) + 1);
    server.stop = false;
    server.wake = wake;
    server.started = true;
    pthread_mutex_unlock(&server.mutex);
    return true;
}

/* One stream per connection; otherwise the first free slot. */
static struct sol_slot *sol_server_admit_locked(uint64_t peer)
{
    struct sol_slot *free_slot = NULL;
    if (!server.started || server.stop) return NULL;
    for (size_t i = 0; i < STATE_OFFER_LINK_SERVER_SLOTS; ++i) {
        struct sol_slot *s = &server.slots[i];
        if (s->peer == peer) return NULL;
        if (!free_slot && !s->working && !s->ready) free_slot = s;
    }
    return free_slot;
}

/* The previous worker of a free slot has already published; join it before reuse. */
static bool sol_server_spawn_locked(struct sol_slot *s, uint64_t peer, struct sol_job *job)
{
    if (s->thread_started) {
        (void)pthread_join(s->thread, NULL);
        s->thread_started = false;
    }
    s->peer = peer;
    s->request = job->request;
    s->last_ms = platform_time_monotonic_ms();
    job->slot = (size_t)(s - server.slots);
    job->generation = s->generation;
    memcpy(job->datadir, server.datadir, sizeof(job->datadir));
    s->working = true;
    // thread-supervision-ok: one bounded object read per slot, joined before reuse and shutdown
    s->thread_started = thread_registry_spawn("zcl_state_offer", sol_server_worker, job, &s->thread) == 0;
    if (!s->thread_started) { s->working = false; s->peer = 0; }
    return s->thread_started;
}

bool state_offer_link_server_request(uint64_t peer, const uint8_t ip[16], const struct state_offer_link_frame *request)
{
    if (!peer || !ip || !valid(request) ||
        (request->kind != STATE_OFFER_LINK_MANIFEST_REQUEST && request->kind != STATE_OFFER_LINK_CHUNK_REQUEST)) return false;
    struct sol_job *job = zcl_malloc(sizeof(*job), "state_offer_link_job");
    if (!job) return false;
    job->request = *request;
    job->request.data = NULL;
    memcpy(job->ip, ip, sizeof(job->ip));
    pthread_mutex_lock(&server.mutex);
    struct sol_slot *s = sol_server_admit_locked(peer);
    bool ok = s && sol_server_spawn_locked(s, peer, job);
    pthread_mutex_unlock(&server.mutex);
    if (!ok) free(job);
    return ok;
}

static struct sol_slot *sol_server_ready_locked(uint64_t peer)
{
    for (size_t i = 0; peer && i < STATE_OFFER_LINK_SERVER_SLOTS; ++i)
        if (server.slots[i].peer == peer && server.slots[i].ready) return &server.slots[i];
    return NULL;
}

bool state_offer_link_server_next(uint64_t peer, uint8_t *wire, size_t cap, size_t *size)
{
    if (size) *size = 0;
    if (!wire || !size) return false;
    pthread_mutex_lock(&server.mutex);
    struct sol_slot *s = sol_server_ready_locked(peer);
    if (!s) { pthread_mutex_unlock(&server.mutex); return false; }
    struct state_offer_link_frame f = s->request;
    f.kind = s->object_size ? (f.kind == STATE_OFFER_LINK_CHUNK_REQUEST ? STATE_OFFER_LINK_CHUNK_PART :
                               STATE_OFFER_LINK_MANIFEST_PART) : STATE_OFFER_LINK_REFUSAL;
    if (s->object_size) {
        f.offset = s->cursor;
        f.total = s->object_size;
        f.size = s->end - s->cursor;
        if (f.size > STATE_OFFER_LINK_PAYLOAD_MAX) f.size = STATE_OFFER_LINK_PAYLOAD_MAX;
        f.data = s->data + s->cursor;
    } else { f.index = f.offset = f.total = f.size = 0; f.data = NULL; }
    bool ok = state_offer_link_encode(&f, wire, cap, size);
    if (ok) {
        s->cursor += f.size;
        s->last_ms = platform_time_monotonic_ms();
        if (!s->object_size || s->cursor == s->end) sol_slot_clear_locked(s);
    }
    pthread_mutex_unlock(&server.mutex);
    return ok;
}

void state_offer_link_server_drop(uint64_t peer)
{
    pthread_mutex_lock(&server.mutex);
    for (size_t i = 0; peer && i < STATE_OFFER_LINK_SERVER_SLOTS; ++i)
        if (server.slots[i].peer == peer) sol_slot_clear_locked(&server.slots[i]);
    pthread_mutex_unlock(&server.mutex);
}

size_t state_offer_link_server_peers(uint64_t *out, size_t cap)
{
    size_t n = 0;
    pthread_mutex_lock(&server.mutex);
    for (size_t i = 0; out && i < STATE_OFFER_LINK_SERVER_SLOTS && n < cap; ++i)
        if (server.slots[i].peer) out[n++] = server.slots[i].peer;
    pthread_mutex_unlock(&server.mutex);
    return n;
}

void state_offer_link_server_tick(void)
{
    pthread_mutex_lock(&server.mutex);
    int64_t now = platform_time_monotonic_ms();
    for (size_t i = 0; i < STATE_OFFER_LINK_SERVER_SLOTS; ++i) {
        struct sol_slot *s = &server.slots[i];
        if (s->peer && now >= s->last_ms && now - s->last_ms >= SOL_SERVER_IDLE_MS) sol_slot_clear_locked(s);
    }
    pthread_mutex_unlock(&server.mutex);
}

void state_offer_link_server_shutdown(void)
{
    pthread_t joins[STATE_OFFER_LINK_SERVER_SLOTS];
    size_t n = 0;
    pthread_mutex_lock(&server.mutex);
    server.stop = true;
    for (size_t i = 0; i < STATE_OFFER_LINK_SERVER_SLOTS; ++i) {
        struct sol_slot *s = &server.slots[i];
        sol_slot_clear_locked(s);
        if (s->thread_started) joins[n++] = s->thread;
        s->thread_started = false;
    }
    pthread_mutex_unlock(&server.mutex);
    for (size_t i = 0; i < n; ++i) (void)pthread_join(joins[i], NULL);
    pthread_mutex_lock(&server.mutex);
    server.started = false;
    pthread_mutex_unlock(&server.mutex);
}
