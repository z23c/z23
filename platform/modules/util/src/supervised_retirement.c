/* purpose: Retain optional supervised cleanup under the existing thread registry lifecycle. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "util/supervised_retirement.h"
#include "util/thread_registry.h"
#include "platform/clock.h"
#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <unistd.h>
enum { RETIREMENT_SLOTS = ZCL_SUPERVISED_RETIREMENT_SLOTS };
enum retirement_state { RETIREMENT_FREE, RETIREMENT_RESERVED, RETIREMENT_OWNED };
struct retirement_slot {
    enum retirement_state state;
    uint64_t token;
    struct platform_supervised_process *owner;
    struct platform_supervised_process process;
};
static struct retirement_slot retirement_slots[RETIREMENT_SLOTS];
static pthread_mutex_t retirement_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t retirement_once = PTHREAD_ONCE_INIT;
static atomic_int retirement_pid;
static int retirement_wake[2] = {-1, -1};
static bool retirement_ready;
static enum zcl_supervised_retirement_phase retirement_phase = ZCL_RETIREMENT_STOPPED;
static bool retirement_started;
static uint64_t retirement_next = 1;
#ifdef ZCL_TESTING
static _Thread_local bool retirement_refused, retirement_wake_error_once;
static _Thread_local int reservation_notify = -1, reservation_resume = -1;
static atomic_uint retirement_reaps;
#endif

/* Owner PID is claimed before pthread_once: a post-fork child never touches
 * inherited once/mutex state or clears its parent's outstanding reservations. */
static bool retirement_owner(void)
{
    return ATOMIC_INT_LOCK_FREE == 2 &&
        atomic_load_explicit(&retirement_pid, memory_order_acquire) == getpid();
}

static void retirement_release(struct platform_supervised_process *process)
{
    if (!process || !retirement_owner()) return;
    pthread_mutex_lock(&retirement_mutex);
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i) {
        struct retirement_slot *slot = &retirement_slots[i];
        if (slot->state == RETIREMENT_RESERVED && slot->owner == process) {
            *slot = (struct retirement_slot){0};
            break;
        }
    }
    pthread_mutex_unlock(&retirement_mutex);
}

static size_t retirement_collect(struct pollfd ready[RETIREMENT_SLOTS + 1],
    size_t indices[RETIREMENT_SLOTS])
{
    size_t count = 0;
    ready[0] = (struct pollfd){.fd = retirement_wake[0], .events = POLLIN};
    pthread_mutex_lock(&retirement_mutex);
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i) {
        if (retirement_slots[i].state != RETIREMENT_OWNED) continue;
        indices[count] = i;
        ready[++count] = (struct pollfd){.fd = retirement_slots[i].process.control_fd, .events = POLLIN};
    }
    pthread_mutex_unlock(&retirement_mutex);
    return count;
}

static void retirement_progress(size_t index)
{
    struct retirement_slot *slot = &retirement_slots[index];
    (void)platform_supervised_poll(&slot->process);
    if (slot->process.supervisor_pid >= 0) return;
#ifdef ZCL_TESTING
    if (slot->process.observation.no_children)
        atomic_fetch_add_explicit(&retirement_reaps, 1, memory_order_relaxed);
#endif
    if (!slot->process.observation.no_children)
        fprintf(stderr, "supervised retirement: observation failed; descendant teardown unconfirmed\n");
    pthread_mutex_lock(&retirement_mutex);
    *slot = (struct retirement_slot){0};
    pthread_mutex_unlock(&retirement_mutex);
}

static bool retirement_finished(void)
{
    bool empty = true;
    pthread_mutex_lock(&retirement_mutex);
    if (thread_registry_shutdown_requested()) retirement_phase = ZCL_RETIREMENT_DRAINING;
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i)
        if (retirement_slots[i].state != RETIREMENT_FREE) empty = false;
    bool done = empty && retirement_phase == ZCL_RETIREMENT_DRAINING;
    if (done) retirement_phase = ZCL_RETIREMENT_STOPPED;
    pthread_mutex_unlock(&retirement_mutex);
    return done;
}

static void *retirement_worker(void *unused)
{
    (void)unused;
    while (!retirement_finished()) {
        struct pollfd ready[RETIREMENT_SLOTS + 1];
        size_t indices[RETIREMENT_SLOTS];
        size_t count = retirement_collect(ready, indices);
        /* Bounded idle observation of atomic registry shutdown; no signal
         * handler callback, inherited jobserver FD, or shutdown setter lock. */
        (void)poll(ready, count + 1, 20);
        if (ready[0].revents) {
            uint8_t bytes[RETIREMENT_SLOTS];
            ssize_t drained = read(retirement_wake[0], bytes, sizeof(bytes));
            (void)drained;
        }
        for (size_t i = 0; i < count; ++i) retirement_progress(indices[i]);
    }
    return NULL;
}

static void retirement_initialize(void)
{
    if (pipe2(retirement_wake, O_CLOEXEC | O_NONBLOCK) < 0) return;
    // thread-supervision-ok:registry-owned join; stop closes admission, existing custody drains; pending remains owned under caller shutdown policy
    int error = thread_registry_spawn("supervised-retire", retirement_worker, NULL, NULL);
    retirement_ready = error == 0;
    if (!retirement_ready) {
        close(retirement_wake[0]); close(retirement_wake[1]);
        retirement_wake[0] = retirement_wake[1] = -1;
    }
}

static bool retirement_reserve(struct platform_supervised_process *process)
{
    if (!retirement_owner()) { errno = ENOTSUP; return false; }
#ifdef ZCL_TESTING
    if (retirement_refused) { errno = EAGAIN; return false; }
#endif
    pthread_mutex_lock(&retirement_mutex);
    if (!retirement_ready || retirement_phase != ZCL_RETIREMENT_RUNNING ||
        thread_registry_shutdown_requested()) {
        pthread_mutex_unlock(&retirement_mutex);
        errno = EAGAIN;
        return false;
    }
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i) {
        if (retirement_slots[i].state != RETIREMENT_FREE && retirement_slots[i].owner == process) {
            pthread_mutex_unlock(&retirement_mutex);
            errno = EINVAL;
            return false;
        }
    }
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i) {
        if (retirement_slots[i].state != RETIREMENT_FREE || retirement_next == UINT64_MAX) continue;
        uint64_t token = retirement_next++;
        retirement_slots[i] = (struct retirement_slot){.state = RETIREMENT_RESERVED,
            .token = token, .owner = process};
        pthread_mutex_unlock(&retirement_mutex);
        return true;
    }
    pthread_mutex_unlock(&retirement_mutex);
    errno = EAGAIN;
    return false;
}

/* Called under the ownership mutex: the reaper cannot miss publication after
 * consuming this wake. EAGAIN means an unread notification already exists.
 * In particular EINTR refuses without an unbounded retry or lost handle. */
static bool retirement_notify(void)
{
#ifdef ZCL_TESTING
    if (retirement_wake_error_once) {
        retirement_wake_error_once = false;
        errno = EINTR;
        return false;
    }
#endif
    uint8_t wake = 1;
    ssize_t n = write(retirement_wake[1], &wake, sizeof(wake));
    return n == (ssize_t)sizeof(wake) || (n < 0 && errno == EAGAIN);
}

#endif /* __linux__ */

bool zcl_supervised_retirement_begin(void)
{
#if defined(__linux__)
    if (ATOMIC_INT_LOCK_FREE != 2) return false;
    int expected = 0;
    (void)atomic_compare_exchange_strong_explicit(&retirement_pid, &expected, getpid(),
        memory_order_acq_rel, memory_order_acquire);
    if (!retirement_owner()) return false;
    pthread_mutex_lock(&retirement_mutex);
    if (!retirement_started && !thread_registry_shutdown_requested()) {
        retirement_started = true;
        retirement_phase = ZCL_RETIREMENT_RUNNING;
        (void)pthread_once(&retirement_once, retirement_initialize);
        if (!retirement_ready) retirement_phase = ZCL_RETIREMENT_STOPPED;
    }
    bool ready = retirement_ready && retirement_phase == ZCL_RETIREMENT_RUNNING &&
        !thread_registry_shutdown_requested();
    pthread_mutex_unlock(&retirement_mutex);
    return ready;
#else
    return false;
#endif
}

enum zcl_supervised_retirement_phase zcl_supervised_retirement_phase(void)
{
#if defined(__linux__)
    if (!retirement_owner()) return ZCL_RETIREMENT_STOPPED;
    pthread_mutex_lock(&retirement_mutex);
    enum zcl_supervised_retirement_phase phase = retirement_phase;
    pthread_mutex_unlock(&retirement_mutex);
    return phase;
#else
    return ZCL_RETIREMENT_STOPPED;
#endif
}

void zcl_supervised_retirement_request_stop(void)
{
#if defined(__linux__)
    if (!retirement_owner()) return;
    pthread_mutex_lock(&retirement_mutex);
    if (retirement_phase == ZCL_RETIREMENT_RUNNING) retirement_phase = ZCL_RETIREMENT_DRAINING;
    pthread_mutex_unlock(&retirement_mutex);
#else

#endif
}

bool zcl_supervised_retirement_drain(int64_t deadline_ns)
{
#if defined(__linux__)
    if (!retirement_owner()) return false;
    zcl_supervised_retirement_request_stop();
    for (;;) {
        if (zcl_supervised_retirement_phase() == ZCL_RETIREMENT_STOPPED) return true;
        int64_t now = clock_now_monotonic_ns();
        if (now >= deadline_ns) return false;
        int64_t left = (deadline_ns - now) / 1000000;
        (void)poll(NULL, 0, left < 20 ? (int)left : 20);
    }
#else
    (void)deadline_ns; return false;
#endif
}

enum platform_supervised_state zcl_supervised_retirement_start(
    struct platform_supervised_process *process, const struct platform_supervised_spec *spec)
{
#if defined(__linux__)
    if (!process || process->supervisor_pid >= 0) return PLATFORM_SUPERVISED_INVALID;
    if (!retirement_reserve(process))
        return errno == ENOTSUP ? PLATFORM_SUPERVISED_UNSUPPORTED : PLATFORM_SUPERVISED_LAUNCH_FAILED;
#ifdef ZCL_TESTING
    if (reservation_notify >= 0) {
        uint8_t byte = 1;
        ssize_t sent = write(reservation_notify, &byte, 1);
        ssize_t received = read(reservation_resume, &byte, 1);
        if (sent != 1 || received != 1) {
            retirement_release(process);
            return PLATFORM_SUPERVISED_LAUNCH_FAILED;
        }
    }
#endif
    enum platform_supervised_state result = platform_supervised_start(process, spec);
    if (process->supervisor_pid < 0) retirement_release(process);
    return result;
#else
    (void)process; (void)spec; return PLATFORM_SUPERVISED_UNSUPPORTED;
#endif
}

enum platform_supervised_state zcl_supervised_retirement_poll(struct platform_supervised_process *process)
{
#if defined(__linux__)
    enum platform_supervised_state result = platform_supervised_poll(process);
    if (process && process->supervisor_pid < 0) retirement_release(process);
    return result;
#else
    return platform_supervised_poll(process);
#endif
}

enum platform_supervised_state zcl_supervised_retirement_stop(
    struct platform_supervised_process *process, int64_t deadline_ns)
{
#if defined(__linux__)
    enum platform_supervised_state result = platform_supervised_stop(process, deadline_ns);
    if (process && process->supervisor_pid < 0) retirement_release(process);
    return result;
#else
    return platform_supervised_stop(process, deadline_ns);
#endif
}

enum zcl_supervised_retirement_result zcl_supervised_retirement_transfer(
    struct platform_supervised_process *process)
{
#if defined(__linux__)
    if (!process || process->supervisor_pid < 0 || process->control_fd < 0 ||
        !retirement_owner()) return ZCL_RETIREMENT_REFUSED;
    pthread_mutex_lock(&retirement_mutex);
    enum zcl_supervised_retirement_result result = ZCL_RETIREMENT_REFUSED;
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i) {
        struct retirement_slot *slot = &retirement_slots[i];
        if (slot->state != RETIREMENT_RESERVED || slot->owner != process) continue;
        if (shutdown(process->control_fd, SHUT_WR) < 0 && errno != ENOTCONN) break;
        if (!retirement_notify()) break;
        slot->process = *process;
        slot->owner = NULL;
        slot->state = RETIREMENT_OWNED;
        platform_supervised_init(process);
        result = ZCL_RETIREMENT_TRANSFERRED;
        break;
    }
    pthread_mutex_unlock(&retirement_mutex);
    return result;
#else
    (void)process; return ZCL_RETIREMENT_REFUSED;
#endif
}

#ifdef ZCL_TESTING
void zcl_supervised_retirement_fixture_reservation_gate(int notify_fd, int resume_fd)
{
#if defined(__linux__)
    reservation_notify = notify_fd; reservation_resume = resume_fd;
#else
    (void)notify_fd; (void)resume_fd;
#endif
}

void zcl_supervised_retirement_fixture_refuse(bool refuse)
{
#if defined(__linux__)
    retirement_refused = refuse;
#else
    (void)refuse;
#endif
}

void zcl_supervised_retirement_fixture_wake_error_once(void)
{
#if defined(__linux__)
    retirement_wake_error_once = true;
#else

#endif
}

unsigned zcl_supervised_retirement_fixture_pending(void)
{
#if defined(__linux__)
    if (!retirement_owner()) return 0;
    unsigned count = 0;
    pthread_mutex_lock(&retirement_mutex);
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i)
        count += retirement_slots[i].state != RETIREMENT_FREE;
    pthread_mutex_unlock(&retirement_mutex);
    return count;
#else
    return 0;
#endif
}

unsigned zcl_supervised_retirement_fixture_reaps(void)
{
#if defined(__linux__)
    return atomic_load_explicit(&retirement_reaps, memory_order_relaxed);
#else
    return 0;
#endif
}

uint64_t zcl_supervised_retirement_fixture_token(const struct platform_supervised_process *process)
{
#if defined(__linux__)
    if (!retirement_owner()) return 0;
    uint64_t token = 0;
    pthread_mutex_lock(&retirement_mutex);
    for (size_t i = 0; i < RETIREMENT_SLOTS; ++i)
        if (retirement_slots[i].state == RETIREMENT_RESERVED && retirement_slots[i].owner == process)
            token = retirement_slots[i].token;
    pthread_mutex_unlock(&retirement_mutex);
    return token;
#else
    (void)process; return 0;
#endif
}

#endif /* ZCL_TESTING */
