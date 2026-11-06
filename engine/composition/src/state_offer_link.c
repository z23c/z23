/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bounded state-offer peer frames and registered bundle serving. */
// supervisor-ok:bounded-object-read — one-shot worker joined before reuse and shutdown; no resident service
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

/* Server disk work is serialized in a worker. The message thread only copies a
 * bounded request; the peer tick takes a bounded number of ready frames. */
#define SOL_SERVER_IDLE_MS INT64_C(120000)
struct sol_server {
    pthread_mutex_t mutex;
    pthread_t thread;
    char datadir[1024];
    bool started, stop, working, ready, thread_started;
    void (*wake)(void);
    uint64_t generation, peer;
    uint8_t ip[16];
    struct state_offer_link_frame request;
    uint8_t *data;
    uint32_t object_size, cursor, end;
    int64_t last_ms;
};
static struct sol_server server = {.mutex = PTHREAD_MUTEX_INITIALIZER};

static void sol_server_clear_locked(void)
{
    free(server.data);
    server.data = NULL;
    server.ready = false;
    ++server.generation;
}

struct sol_job {
    struct state_offer_link_frame request;
    uint8_t ip[16];
    uint64_t generation;
};

static void *sol_server_worker(void *arg)
{
    struct sol_job *job = arg;
    struct state_offer_link_frame request = job->request;
    uint8_t ip[16]; memcpy(ip, job->ip, sizeof(ip));
    uint64_t generation = job->generation;
    free(job);
    uint8_t *bytes = zcl_malloc(ROM_SEED_CHUNK_SIZE, "state_offer_link_chunk");
    uint32_t size = 0;
    bool acquired = bytes && rom_seed_peer_acquire(ip);
    bool ok = acquired && state_offer_link_read_registered(server.datadir, request.kind, request.digest, request.index,
                                                            bytes, ROM_SEED_CHUNK_SIZE, &size) &&
        rom_seed_rate_charge(ip, size, (int64_t)platform_time_wall_time_t());
    if (acquired) rom_seed_peer_release(ip);
    if (ok && request.offset >= size) ok = false;
    pthread_mutex_lock(&server.mutex);
    bool notify = false;
    if (!server.stop && generation == server.generation) {
        server.data = bytes;
        server.object_size = ok ? size : 0;
        server.cursor = ok ? request.offset : 0;
        server.end = ok && request.total < size - request.offset ? request.offset + request.total : size;
        server.ready = true;
        server.last_ms = platform_time_monotonic_ms();
        bytes = NULL;
        notify = server.wake != NULL;
    }
    free(bytes);
    void (*wake)(void) = notify ? server.wake : NULL;
    server.working = false;
    pthread_mutex_unlock(&server.mutex);
    if (wake) wake();
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

bool state_offer_link_server_request(uint64_t peer, const uint8_t ip[16], const struct state_offer_link_frame *request)
{
    if (!peer || !ip || !valid(request) ||
        (request->kind != STATE_OFFER_LINK_MANIFEST_REQUEST && request->kind != STATE_OFFER_LINK_CHUNK_REQUEST)) return false;
    pthread_mutex_lock(&server.mutex);
    bool ok = server.started && !server.stop && !server.working && !server.ready;
    if (ok && server.thread_started) {
        (void)pthread_join(server.thread, NULL);
        server.thread_started = false;
    }
    if (ok) {
        server.peer = peer;
        memcpy(server.ip, ip, 16);
        server.request = *request;
        server.request.data = NULL;
        server.last_ms = platform_time_monotonic_ms();
        struct sol_job *job = zcl_malloc(sizeof(*job), "state_offer_link_job");
        if (job) {
            job->request = server.request;
            memcpy(job->ip, server.ip, sizeof(job->ip));
            job->generation = server.generation;
            server.working = true;
            // thread-supervision-ok: one bounded object read, joined before reuse and shutdown
            ok = thread_registry_spawn("zcl_state_offer", sol_server_worker, job, &server.thread) == 0;
            server.thread_started = ok;
            if (!ok) { server.working = false; free(job); }
        } else ok = false;
    }
    pthread_mutex_unlock(&server.mutex);
    return ok;
}

bool state_offer_link_server_next(uint64_t peer, uint8_t *wire, size_t cap, size_t *size)
{
    if (size) *size = 0;
    if (!wire || !size) return false;
    pthread_mutex_lock(&server.mutex);
    if (!server.ready || server.peer != peer) { pthread_mutex_unlock(&server.mutex); return false; }
    struct state_offer_link_frame f = server.request;
    f.kind = server.object_size ? (f.kind == STATE_OFFER_LINK_CHUNK_REQUEST ? STATE_OFFER_LINK_CHUNK_PART :
                                   STATE_OFFER_LINK_MANIFEST_PART) : STATE_OFFER_LINK_REFUSAL;
    if (server.object_size) {
        f.offset = server.cursor;
        f.total = server.object_size;
        f.size = server.end - server.cursor;
        if (f.size > STATE_OFFER_LINK_PAYLOAD_MAX) f.size = STATE_OFFER_LINK_PAYLOAD_MAX;
        f.data = server.data + server.cursor;
    } else { f.index = f.offset = f.total = f.size = 0; f.data = NULL; }
    bool ok = state_offer_link_encode(&f, wire, cap, size);
    if (ok) {
        server.cursor += f.size;
        server.last_ms = platform_time_monotonic_ms();
        if (!server.object_size || server.cursor == server.end) sol_server_clear_locked();
    }
    pthread_mutex_unlock(&server.mutex);
    return ok;
}

void state_offer_link_server_drop(uint64_t peer)
{
    pthread_mutex_lock(&server.mutex);
    if (server.peer == peer) sol_server_clear_locked();
    pthread_mutex_unlock(&server.mutex);
}

uint64_t state_offer_link_server_peer(void)
{
    pthread_mutex_lock(&server.mutex);
    uint64_t peer = (server.working || server.ready) ? server.peer : 0;
    pthread_mutex_unlock(&server.mutex);
    return peer;
}

void state_offer_link_server_tick(void)
{
    pthread_mutex_lock(&server.mutex);
    int64_t now = platform_time_monotonic_ms();
    if ((server.working || server.ready) && now >= server.last_ms &&
        now - server.last_ms >= SOL_SERVER_IDLE_MS) sol_server_clear_locked();
    pthread_mutex_unlock(&server.mutex);
}

void state_offer_link_server_shutdown(void)
{
    pthread_mutex_lock(&server.mutex);
    bool join = server.thread_started;
    server.stop = true;
    sol_server_clear_locked();
    pthread_mutex_unlock(&server.mutex);
    if (join) (void)pthread_join(server.thread, NULL);
    pthread_mutex_lock(&server.mutex);
    server.started = false;
    server.thread_started = false;
    pthread_mutex_unlock(&server.mutex);
}
