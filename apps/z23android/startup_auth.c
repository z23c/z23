/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "startup_auth.h"
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "platform/wallet_startup_auth_protocol.h"
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct zapp_startup_auth {
    pthread_mutex_t lock;
    unsigned refs;
    int fd;
    bool active, cancelled, refused;
    zapp_startup_auth_cancel_fn cancel_fn;
    void *cancel_ctx;
    char files[1024];
};
static pthread_mutex_t provider_lock = PTHREAD_MUTEX_INITIALIZER;
static zapp_startup_auth_unwrap provider;
void zapp_startup_auth_provider(zapp_startup_auth_unwrap unwrap)
{
    pthread_mutex_lock(&provider_lock); provider = unwrap; pthread_mutex_unlock(&provider_lock);
}
struct zapp_startup_auth *zapp_startup_auth_new(void)
{
    struct zapp_startup_auth *a = zcl_calloc(1, sizeof(*a), "android startup auth");
    if (!a) return NULL;
    if (pthread_mutex_init(&a->lock, NULL)) { free(a); return NULL; }
    a->refs = 1; a->fd = -1;
    return a;
}
static void auth_release(struct zapp_startup_auth *a)
{
    pthread_mutex_lock(&a->lock);
    bool last = --a->refs == 0;
    pthread_mutex_unlock(&a->lock);
    if (last) { pthread_mutex_destroy(&a->lock); free(a); }
}
void zapp_startup_auth_cancel(struct zapp_startup_auth *a)
{
    if (!a) return;
    pthread_mutex_lock(&a->lock);
    a->cancelled = true;
    if (a->fd >= 0) (void)shutdown(a->fd, SHUT_RDWR);
    if (a->cancel_fn) a->cancel_fn(a->cancel_ctx);
    pthread_mutex_unlock(&a->lock);
}
bool zapp_startup_auth_register_cancel(struct zapp_startup_auth *a, zapp_startup_auth_cancel_fn fn, void *ctx)
{
    if (!a || !fn) return false;
    pthread_mutex_lock(&a->lock);
    bool ok = !a->cancelled;
    if (ok) { a->cancel_fn = fn; a->cancel_ctx = ctx; }
    else fn(ctx);
    pthread_mutex_unlock(&a->lock);
    return ok;
}
void zapp_startup_auth_unregister_cancel(struct zapp_startup_auth *a)
{
    if (!a) return;
    pthread_mutex_lock(&a->lock); a->cancel_fn = NULL; a->cancel_ctx = NULL; pthread_mutex_unlock(&a->lock);
}
void zapp_startup_auth_reset(struct zapp_startup_auth *a)
{
    if (!a) return;
    pthread_mutex_lock(&a->lock); if (!a->active) a->refused = false; pthread_mutex_unlock(&a->lock);
}
bool zapp_startup_auth_ready(struct zapp_startup_auth *a)
{
    if (!a) return false;
    pthread_mutex_lock(&a->lock); bool ready = !a->active; pthread_mutex_unlock(&a->lock);
    return ready;
}
bool zapp_startup_auth_refused(struct zapp_startup_auth *a)
{
    if (!a) return false;
    pthread_mutex_lock(&a->lock); bool refused = a->refused; pthread_mutex_unlock(&a->lock);
    return refused;
}
void zapp_startup_auth_free(struct zapp_startup_auth *a)
{
    if (!a) return;
    zapp_startup_auth_cancel(a); auth_release(a);
}
static bool auth_read_header(int fd, uint8_t header[Z23_WALLET_AUTH_HEADER_SIZE], size_t *received)
{
    size_t have = 0;
    while (have < Z23_WALLET_AUTH_HEADER_SIZE) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int rc = poll(&p, 1, have ? 120000 : -1);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) { *received = have; return false; }
        ssize_t n = recv(fd, header + have, Z23_WALLET_AUTH_HEADER_SIZE - have, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { *received = have; return false; }
        have += (size_t)n;
    }
    *received = have; return true;
}
static bool auth_send_locked(struct zapp_startup_auth *a, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len && !a->cancelled) {
        ssize_t n = send(a->fd, buf + sent, len - sent, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return sent == len && !a->cancelled;
}
static void auth_answer(struct zapp_startup_auth *a)
{
    uint8_t secret[32] = {0}, wire[72] = {'Z','W','A','1', Z23_WALLET_AUTH_CANCEL, 0, 0, 0};
    pthread_mutex_lock(&provider_lock); zapp_startup_auth_unwrap unwrap = provider; pthread_mutex_unlock(&provider_lock);
    bool ok = unwrap && unwrap(a, a->files, secret);
    if (ok) {
        static const char hex[] = "0123456789abcdef";
        wire[4] = Z23_WALLET_AUTH_SECRET; wire[6] = 64;
        for (size_t i = 0; i < sizeof(secret); i++) {
            wire[8 + 2 * i] = (uint8_t)hex[secret[i] >> 4];
            wire[9 + 2 * i] = (uint8_t)hex[secret[i] & 15];
        }
    }
    memory_cleanse(secret, sizeof(secret));
    pthread_mutex_lock(&a->lock);
    bool sent = !a->cancelled && auth_send_locked(a, wire, ok ? sizeof(wire) : 8);
    if (!a->cancelled && (!ok || !sent)) a->refused = true;
    pthread_mutex_unlock(&a->lock);
    memory_cleanse(wire, sizeof(wire));
}
static void *auth_worker(void *opaque)
{
    struct zapp_startup_auth *a = opaque;
    uint8_t h[Z23_WALLET_AUTH_HEADER_SIZE];
    size_t received = 0;
    bool complete = auth_read_header(a->fd, h, &received);
    bool valid = complete && memcmp(h, "ZWA1", 4) == 0 && h[4] == Z23_WALLET_AUTH_REQUEST && !h[5] && !h[6] && !h[7];
    if (valid) auth_answer(a);
    else if (received) { pthread_mutex_lock(&a->lock); if (!a->cancelled) a->refused = true; pthread_mutex_unlock(&a->lock); }
    pthread_mutex_lock(&a->lock);
    if (a->fd >= 0) close(a->fd);
    a->fd = -1; a->active = false;
    pthread_mutex_unlock(&a->lock);
    auth_release(a);
    return NULL;
}
bool zapp_startup_auth_start(struct zapp_startup_auth *a, int fd, const char *files)
{
    if (!a || fd < 0 || !files || strlen(files) >= sizeof(a->files)) return false;
    pthread_mutex_lock(&a->lock);
    if (a->active) { pthread_mutex_unlock(&a->lock); return false; }
    memcpy(a->files, files, strlen(files) + 1);
    a->fd = fd; a->active = true; a->cancelled = false; a->refs++;
    pthread_t thread;
    if (pthread_create(&thread, NULL, auth_worker, a)) {
        a->fd = -1; a->active = false; a->refs--; pthread_mutex_unlock(&a->lock); return false;
    }
    (void)pthread_detach(thread);
    pthread_mutex_unlock(&a->lock);
    return true;
}
