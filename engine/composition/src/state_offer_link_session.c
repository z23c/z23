/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Bounded synchronous object reads over a live peer link. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "config/state_offer_link_session.h"
#include "net/rom_seed.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#define SOL_INACTIVITY_SECONDS 30
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed;
static bool initialized;
static uint64_t next_nonce;
static struct {
    bool active, busy, pending, done;
    uint64_t peer;
    void (*wake)(void *);
    void *wake_ctx;
    struct state_offer_link_frame request;
    uint8_t *buffer;
    uint32_t cap, received, total;
    enum sol_read_result result;
    struct timespec deadline;
} s;

static void init(void)
{
    pthread_condattr_t attr;
    if (!rng_host_fill((uint8_t *)&next_nonce, sizeof(next_nonce)) ||
        !next_nonce || pthread_condattr_init(&attr)) return;
#if defined(__APPLE__)
    if (!pthread_cond_init(&changed, &attr)) initialized = true;
#else
    if (!pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) &&
        !pthread_cond_init(&changed, &attr)) initialized = true;
#endif
    pthread_condattr_destroy(&attr);
}
static bool ready(void)
{
    return !pthread_once(&once, init) && initialized;
}
static bool deadline(void)
{
    if (platform_time_monotonic_timespec(&s.deadline)) return false;
    s.deadline.tv_sec += SOL_INACTIVITY_SECONDS;
    return true;
}
static int wait_until_deadline(void)
{
#if defined(__APPLE__)
    struct timespec now, remaining;
    if (platform_time_monotonic_timespec(&now)) return EINVAL;
    if (now.tv_sec > s.deadline.tv_sec ||
        (now.tv_sec == s.deadline.tv_sec && now.tv_nsec >= s.deadline.tv_nsec)) return ETIMEDOUT;
    remaining.tv_sec = s.deadline.tv_sec - now.tv_sec;
    remaining.tv_nsec = s.deadline.tv_nsec - now.tv_nsec;
    if (remaining.tv_nsec < 0) { --remaining.tv_sec; remaining.tv_nsec += 1000000000L; }
    return pthread_cond_timedwait_relative_np(&changed, &lock, &remaining);
#else
    return pthread_cond_timedwait(&changed, &lock, &s.deadline);
#endif
}
static void finish(enum sol_read_result result)
{
    s.pending = false;
    s.done = true;
    s.result = result;
    pthread_cond_broadcast(&changed);
}
bool sol_client_start(uint64_t peer, void (*wake)(void *), void *wake_ctx)
{
    if (!peer || !wake || !ready()) return false;
    pthread_mutex_lock(&lock);
    bool ok = !s.active && !s.busy;
    if (ok) { s.active = true; s.peer = peer; s.wake = wake; s.wake_ctx = wake_ctx; }
    pthread_mutex_unlock(&lock);
    return ok;
}
void sol_client_shutdown(void)
{
    if (!ready()) return;
    pthread_mutex_lock(&lock);
    s.active = false;
    if (s.busy && !s.done) finish(SOL_READ_CANCELLED);
    pthread_mutex_unlock(&lock);
}
void sol_client_drop(uint64_t peer)
{
    if (!ready()) return;
    pthread_mutex_lock(&lock);
    if (s.active && s.peer == peer) {
        s.active = false;
        if (s.busy && !s.done) finish(SOL_READ_CANCELLED);
    }
    pthread_mutex_unlock(&lock);
}
/* Validate caller-owned storage before publishing a single object request. */
static bool read_args_valid(void *peer, enum sol_object_kind kind, const uint8_t *root,
                            uint32_t index, uint8_t *buf, uint32_t cap, uint32_t *len)
{
    return peer && root && buf && len && cap && cap <= ROM_SEED_CHUNK_SIZE &&
        (kind == SOL_OBJECT_MANIFEST || kind == SOL_OBJECT_CHUNK) &&
        (kind != SOL_OBJECT_MANIFEST || (!index && cap <= ROM_SEED_MANIFEST_BLOB_MAX)) &&
        (kind != SOL_OBJECT_CHUNK || index < ROM_SEED_MAX_CHUNKS);
}
/* The worker holds the mutex while publishing the request and buffer. */
static void prepare_read(enum sol_object_kind kind, const uint8_t root[32],
                         uint32_t index, uint8_t *buf, uint32_t cap)
{
    s.busy = s.pending = true;
    s.done = false;
    s.buffer = buf; s.cap = cap; s.received = s.total = 0;
    s.request = (struct state_offer_link_frame){
        .kind = kind == SOL_OBJECT_MANIFEST ? STATE_OFFER_LINK_MANIFEST_REQUEST : STATE_OFFER_LINK_CHUNK_REQUEST,
        .nonce = next_nonce++, .index = index,
        .total = kind == SOL_OBJECT_MANIFEST ? ROM_SEED_MANIFEST_BLOB_MAX : ROM_SEED_CHUNK_SIZE
    };
    memcpy(s.request.digest, root, 32);
}
/* Progress may extend the deadline while a timed wait is reacquiring the mutex. */
static bool timeout_expired(void)
{
    struct timespec now;
    return platform_time_monotonic_timespec(&now) || now.tv_sec > s.deadline.tv_sec ||
        (now.tv_sec == s.deadline.tv_sec && now.tv_nsec >= s.deadline.tv_nsec);
}
/* Wait for completion, cancellation, or a full inactivity interval. */
static void wait_for_read(void)
{
    while (!s.done) {
        int rc = wait_until_deadline();
        if (rc == ETIMEDOUT && !s.done && timeout_expired()) finish(SOL_READ_UNAVAILABLE);
        else if (rc && rc != ETIMEDOUT && !s.done) finish(SOL_READ_UNAVAILABLE);
    }
}
enum sol_read_result sol_client_read(void *peer_id, enum sol_object_kind kind,
    const uint8_t root[32], uint32_t index, uint8_t *buf, uint32_t cap, uint32_t *len)
{
    if (len) *len = 0;
    if (!read_args_valid(peer_id, kind, root, index, buf, cap, len) || !ready()) return SOL_READ_BAD_DATA;
    uint64_t peer = *(const uint64_t *)peer_id;
    pthread_mutex_lock(&lock);
    if (!s.active || s.peer != peer || s.busy || !next_nonce || !deadline()) {
        pthread_mutex_unlock(&lock);
        return SOL_READ_UNAVAILABLE;
    }
    prepare_read(kind, root, index, buf, cap);
    void (*wake)(void *) = s.wake;
    void *wake_ctx = s.wake_ctx;
    pthread_mutex_unlock(&lock);
    wake(wake_ctx);
    pthread_mutex_lock(&lock);
    wait_for_read();
    enum sol_read_result result = s.result;
    if (result == SOL_READ_OK) *len = s.received;
    s.buffer = NULL; s.busy = s.pending = false;
    pthread_mutex_unlock(&lock);
    return result;
}
bool sol_client_poll(uint64_t peer, struct state_offer_link_frame *out)
{
    if (!out || !ready()) return false;
    pthread_mutex_lock(&lock);
    bool ok = s.active && s.peer == peer && s.busy && s.pending && !s.done;
    if (ok) { *out = s.request; s.pending = false; }
    pthread_mutex_unlock(&lock);
    return ok;
}
/* A part must describe one contiguous span within the caller's buffer. */
static bool part_valid(const struct state_offer_link_frame *f)
{
    enum state_offer_link_kind expected = s.request.kind == STATE_OFFER_LINK_MANIFEST_REQUEST ?
        STATE_OFFER_LINK_MANIFEST_PART : STATE_OFFER_LINK_CHUNK_PART;
    return f->kind == expected && f->index == s.request.index && f->data && f->size &&
        f->size <= STATE_OFFER_LINK_PAYLOAD_MAX && f->offset == s.received &&
        f->total && f->total <= s.cap && (!s.total || f->total == s.total) &&
        f->offset <= f->total && f->size <= f->total - f->offset;
}
/* Copy data before releasing the message owner's frame. */
static void accept_part(const struct state_offer_link_frame *f)
{
    memcpy(s.buffer + s.received, f->data, f->size);
    s.total = f->total; s.received += f->size;
    if (s.received == s.total) finish(SOL_READ_OK);
    else if (!deadline()) finish(SOL_READ_UNAVAILABLE);
    else pthread_cond_signal(&changed);
}
bool sol_client_consume(uint64_t peer, const struct state_offer_link_frame *f)
{
    if (!f || !ready()) return false;
    pthread_mutex_lock(&lock);
    bool match = s.active && s.peer == peer && s.busy && !s.pending && !s.done &&
        f->nonce == s.request.nonce && !memcmp(f->digest, s.request.digest, 32);
    if (!match) { pthread_mutex_unlock(&lock); return false; }
    if (f->kind == STATE_OFFER_LINK_REFUSAL) finish(SOL_READ_UNAVAILABLE);
    else if (!part_valid(f)) finish(SOL_READ_BAD_DATA);
    else accept_part(f);
    pthread_mutex_unlock(&lock);
    return true;
}
