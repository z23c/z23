/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "startup_auth.h"
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sched.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static bool entered, released, cancelled, decline, before_register, proceed, late_response;
static void wait_signal(void)
{
    struct timespec until; assert(clock_gettime(CLOCK_REALTIME, &until) == 0); until.tv_sec += 5;
    assert(pthread_cond_timedwait(&cond, &lock, &until) == 0);
}
static void wait_ready(struct zapp_startup_auth *auth)
{
    struct timespec start, now; assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    while (!zapp_startup_auth_ready(auth)) {
        sched_yield(); assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0); assert(now.tv_sec - start.tv_sec < 5);
    }
}
static ssize_t bounded_read(int fd, void *buf, size_t n)
{
    struct pollfd p = {.fd = fd, .events = POLLIN}; assert(poll(&p, 1, 5000) > 0);
    return read(fd, buf, n);
}
static void cancel_prompt(void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&lock); cancelled = true; if (!late_response) released = true; pthread_cond_broadcast(&cond); pthread_mutex_unlock(&lock);
}
static bool unwrap(struct zapp_startup_auth *auth, const char *files, uint8_t secret[32])
{
    (void)files;
    pthread_mutex_lock(&lock);
    if (before_register) {
        entered = true; pthread_cond_broadcast(&cond);
        while (!proceed) wait_signal();
    }
    pthread_mutex_unlock(&lock);
    bool registered = zapp_startup_auth_register_cancel(auth, cancel_prompt, NULL);
    pthread_mutex_lock(&lock); entered = true; pthread_cond_broadcast(&cond);
    while (!released) wait_signal();
    bool ok = registered && !decline && (!cancelled || late_response);
    pthread_mutex_unlock(&lock);
    if (registered) zapp_startup_auth_unregister_cancel(auth);
    if (ok) memset(secret, 0x5a, 32);
    return ok;
}
static void read_exact(int fd, uint8_t *buf, size_t n)
{
    while (n) { ssize_t got = bounded_read(fd, buf, n); assert(got > 0); buf += got; n -= (size_t)got; }
}
static void run(bool stop, bool reject)
{
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct zapp_startup_auth *auth = zapp_startup_auth_new(); assert(auth);
    pthread_mutex_lock(&lock); entered = released = cancelled = before_register = proceed = late_response = false; decline = reject; pthread_mutex_unlock(&lock);
    assert(zapp_startup_auth_start(auth, pair[0], "/fixture"));
    const uint8_t request[8] = {'Z','W','A','1',1,0,0,0};
    assert(write(pair[1], request, 3) == 3); assert(write(pair[1], request + 3, 5) == 5);
    pthread_mutex_lock(&lock); while (!entered) wait_signal(); pthread_mutex_unlock(&lock);
    if (stop) zapp_startup_auth_cancel(auth);
    else { pthread_mutex_lock(&lock); released = true; pthread_cond_broadcast(&cond); pthread_mutex_unlock(&lock); }
    uint8_t header[8];
    if (stop) { assert(bounded_read(pair[1], header, sizeof(header)) == 0); }
    else {
        read_exact(pair[1], header, sizeof(header));
        assert(memcmp(header, "ZWA1", 4) == 0 && header[4] == (reject ? 3 : 2));
        assert(header[5] == 0 && header[6] == (reject ? 0 : 64) && header[7] == 0);
        if (!reject) { uint8_t hex[64]; read_exact(pair[1], hex, sizeof(hex)); for (size_t i = 0; i < sizeof(hex); i += 2) assert(hex[i] == '5' && hex[i + 1] == 'a'); }
    }
    close(pair[1]); wait_ready(auth);
    if (reject) { assert(zapp_startup_auth_refused(auth)); zapp_startup_auth_reset(auth); assert(!zapp_startup_auth_refused(auth)); }
    zapp_startup_auth_free(auth);
}
static void cancel_before_registration(void)
{
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct zapp_startup_auth *auth = zapp_startup_auth_new(); assert(auth);
    pthread_mutex_lock(&lock); entered = released = cancelled = proceed = late_response = false; before_register = true; pthread_mutex_unlock(&lock);
    assert(zapp_startup_auth_start(auth, pair[0], "/fixture"));
    const uint8_t request[8] = {'Z','W','A','1',1,0,0,0}; assert(write(pair[1], request, sizeof(request)) == sizeof(request));
    pthread_mutex_lock(&lock); while (!entered) wait_signal(); pthread_mutex_unlock(&lock);
    zapp_startup_auth_cancel(auth);
    pthread_mutex_lock(&lock); proceed = true; pthread_cond_broadcast(&cond); pthread_mutex_unlock(&lock);
    uint8_t byte; assert(bounded_read(pair[1], &byte, 1) == 0);
    close(pair[1]); wait_ready(auth); zapp_startup_auth_free(auth);
}
static void late_reply_cannot_use_recycled_fd(void)
{
    int pair[2], other[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct zapp_startup_auth *auth = zapp_startup_auth_new(); assert(auth);
    pthread_mutex_lock(&lock); entered = released = cancelled = decline = before_register = false; late_response = true; pthread_mutex_unlock(&lock);
    assert(zapp_startup_auth_start(auth, pair[0], "/fixture"));
    const uint8_t request[8] = {'Z','W','A','1',1,0,0,0}; assert(write(pair[1], request, sizeof(request)) == sizeof(request));
    pthread_mutex_lock(&lock); while (!entered) wait_signal(); pthread_mutex_unlock(&lock);
    zapp_startup_auth_cancel(auth); assert(!zapp_startup_auth_ready(auth));
    assert(fcntl(pair[0], F_GETFD) >= 0); assert(socketpair(AF_UNIX, SOCK_STREAM, 0, other) == 0);
    assert(other[0] != pair[0] && other[1] != pair[0]);
    pthread_mutex_lock(&lock); released = true; pthread_cond_broadcast(&cond); pthread_mutex_unlock(&lock);
    uint8_t byte; assert(bounded_read(pair[1], &byte, 1) == 0); wait_ready(auth);
    struct pollfd probe = {.fd = other[1], .events = POLLIN}; assert(poll(&probe, 1, 100) == 0);
    close(other[0]); close(other[1]); close(pair[1]); zapp_startup_auth_free(auth);
}
static void reject_bad_frame(void)
{
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct zapp_startup_auth *auth = zapp_startup_auth_new(); assert(auth);
    pthread_mutex_lock(&lock); entered = false; pthread_mutex_unlock(&lock);
    assert(zapp_startup_auth_start(auth, pair[0], "/fixture"));
    const uint8_t request[8] = {'Z','W','A','1',1,0,1,0}; assert(write(pair[1], request, sizeof(request)) == sizeof(request));
    uint8_t byte; assert(bounded_read(pair[1], &byte, 1) == 0);
    wait_ready(auth);
    pthread_mutex_lock(&lock); assert(!entered); pthread_mutex_unlock(&lock);
    assert(zapp_startup_auth_refused(auth)); close(pair[1]); zapp_startup_auth_free(auth);
}
static void no_request_no_prompt(void)
{
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct zapp_startup_auth *auth = zapp_startup_auth_new(); assert(auth);
    pthread_mutex_lock(&lock); entered = false; pthread_mutex_unlock(&lock);
    assert(zapp_startup_auth_start(auth, pair[0], "/fixture"));
    struct pollfd probe = {.fd = pair[1], .events = POLLIN}; assert(poll(&probe, 1, 100) == 0);
    zapp_startup_auth_cancel(auth); wait_ready(auth);
    pthread_mutex_lock(&lock); assert(!entered); pthread_mutex_unlock(&lock);
    close(pair[1]); zapp_startup_auth_free(auth);
}
int main(void)
{
    zapp_startup_auth_provider(unwrap); no_request_no_prompt(); run(false, false); run(false, true); run(true, false); cancel_before_registration(); late_reply_cannot_use_recycled_fd(); reject_bad_frame(); return 0;
}
