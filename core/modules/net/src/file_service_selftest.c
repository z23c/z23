/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL_TESTING self-tests for the file-service client half: the resolved
 * connect deadline lifecycle and the range-worker socket ownership helpers.
 * Split out of file_service.c. */

#if !defined(_WIN32) && defined(ZCL_TESTING)

#include "platform/barrier.h"
#include "file_service_priv.h"
#include "file_service_worker_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct fs_test_connect_state {
    int now_calls;
    int poll_calls;
    int timeout_ms;
    int connected_fd;
    int64_t finished_ms;
    bool poll_ready;
    bool check_success;
};

static int64_t fs_test_connect_now(void *opaque)
{
    struct fs_test_connect_state *state = opaque;
    state->now_calls++;
    return state->now_calls < 3 ? 1000 : state->finished_ms;
}

static int fs_test_connect_pending(void *opaque, int fd,
                                   const struct sockaddr *address,
                                   socklen_t address_len)
{
    struct fs_test_connect_state *state = opaque;
    (void)address;
    (void)address_len;
    state->connected_fd = fd;
    errno = EINPROGRESS;
    return -1;
}

static int fs_test_connect_poll_timeout(void *opaque, struct pollfd *pfd,
                                        int timeout_ms)
{
    struct fs_test_connect_state *state = opaque;
    (void)pfd;
    state->poll_calls++;
    state->timeout_ms = timeout_ms;
    if (state->poll_ready) {
        pfd->revents = POLLOUT;
        return 1;
    }
    return 0;
}

static bool fs_test_connect_check(void *opaque, int fd)
{
    const struct fs_test_connect_state *state = opaque;
    (void)fd;
    return state->check_success;
}

static void fs_test_close_fd(int fd)
{
    if (fd >= 0)
        close(fd);
}

static bool fs_test_connect_real(struct sockaddr_storage *resolved)
{
    int listen_fd = -1;
    int connected_fd = -1;
    int accepted_fd = -1;
    bool ok = true;
    struct sockaddr_in listener = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t listener_len = sizeof(listener);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    ok = listen_fd >= 0 &&
         bind(listen_fd, (struct sockaddr *)&listener, sizeof(listener)) == 0 &&
         listen(listen_fd, 1) == 0 &&
         getsockname(listen_fd, (struct sockaddr *)&listener,
                     &listener_len) == 0;
    memset(resolved, 0, sizeof(*resolved));
    memcpy(resolved, &listener, sizeof(listener));
    if (ok)
        connected_fd = fs_connect_resolved_until(
            resolved, sizeof(listener), SOCK_STREAM, 0, 1000, NULL);
    int connected_flags = connected_fd >= 0
        ? fcntl(connected_fd, F_GETFL, 0) : -1;
    struct pollfd accept_ready = {.fd = listen_fd, .events = POLLIN};
    int accept_poll = connected_fd >= 0 ? poll(&accept_ready, 1, 250) : -1;
    if (accept_poll > 0 && (accept_ready.revents & POLLIN) != 0)
        accepted_fd = accept(listen_fd, NULL, NULL);
    ok = ok && connected_fd >= 0 && accepted_fd >= 0 &&
         connected_flags >= 0 && (connected_flags & O_NONBLOCK) == 0;

    fs_test_close_fd(accepted_fd);
    fs_test_close_fd(connected_fd);
    fs_test_close_fd(listen_fd);
    return ok;
}

static bool fs_test_connect_fake(const struct sockaddr_storage *resolved,
                                 socklen_t resolved_len, bool ok)
{
    struct fs_test_connect_state state = {
        .connected_fd = -1,
        .finished_ms = 1138,
    };
    struct fs_connect_ops fake = {
        .now_ms = fs_test_connect_now,
        .connect_fd = fs_test_connect_pending,
        .poll_fd = fs_test_connect_poll_timeout,
        .check_fd = fs_test_connect_check,
        .opaque = &state,
    };
    int timed_fd = fs_connect_resolved_until(
        resolved, resolved_len, SOCK_STREAM, 0, 137, &fake);
    errno = 0;
    int closed_probe = state.connected_fd >= 0
        ? fcntl(state.connected_fd, F_GETFD) : 0;
    ok = ok && timed_fd < 0 && state.now_calls == 3 &&
         state.poll_calls == 1 && state.timeout_ms == 137 &&
         closed_probe < 0 && errno == EBADF;

    struct fs_test_connect_state edge = {
        .connected_fd = -1,
        .finished_ms = 1137,
        .poll_ready = true,
        .check_success = true,
    };
    fake.opaque = &edge;
    int edge_fd = fs_connect_resolved_until(
        resolved, resolved_len, SOCK_STREAM, 0, 137, &fake);
    errno = 0;
    int edge_closed = edge.connected_fd >= 0
        ? fcntl(edge.connected_fd, F_GETFD) : 0;
    ok = ok && edge_fd < 0 && edge.now_calls == 3 &&
         edge.poll_calls == 1 && edge.timeout_ms == 137 &&
         edge_closed < 0 && errno == EBADF;
    return ok;
}

bool fs_test_resolved_connect_lifecycle(void)
{
    struct sockaddr_storage resolved;
    bool ok = fs_test_connect_real(&resolved);
    ok = fs_test_connect_fake(&resolved, sizeof(struct sockaddr_in), ok);

    const struct fs_connect_ops bad_ops = {0};
    int bad_fd = fs_connect_resolved_until(
        &resolved, sizeof(struct sockaddr_in), SOCK_STREAM, 0, 137, &bad_ops);
    ok = ok && bad_fd < 0;
    return ok;

}

struct fs_test_range_close_race {
    struct range_worker *worker;
    zcl_barrier_t *barrier;
    int fd;
};

static void *fs_test_range_close_race_fn(void *opaque)
{
    struct fs_test_range_close_race *race = opaque;
    (void)zcl_barrier_wait(race->barrier);
    range_worker_socket_close(race->worker, race->fd);
    return NULL;
}

static bool fs_test_range_reuse_phase(struct range_worker *wp, bool ok)
{
    int old_pair[2] = {-1, -1};
    int replacement[2] = {-1, -1};
    int old_number = -1;
    int live_fd = -1;
    int peer_fd = -1;
    uint8_t byte = 0x5a;
    uint8_t received = 0;
    ok = ok && socketpair(AF_UNIX, SOCK_STREAM, 0, old_pair) == 0;
    if (ok) {
        old_number = old_pair[0];
        ok = range_worker_socket_publish(wp, old_pair[0]);
    }
    if (ok) {
        range_worker_socket_close(wp, old_pair[0]);
        old_pair[0] = -1;
        ok = socketpair(AF_UNIX, SOCK_STREAM, 0, replacement) == 0;
    }
    if (ok) {
        if (replacement[0] == old_number) {
            live_fd = replacement[0];
            peer_fd = replacement[1];
            replacement[0] = replacement[1] = -1;
        } else if (replacement[1] == old_number) {
            live_fd = replacement[1];
            peer_fd = replacement[0];
            replacement[0] = replacement[1] = -1;
        } else if (dup2(replacement[0], old_number) == old_number) {
            live_fd = old_number;
            peer_fd = replacement[1];
            close(replacement[0]);
            replacement[0] = replacement[1] = -1;
        } else {
            ok = false;
        }
    }
    if (ok) {
        range_worker_cancel(wp);
        ok = send(peer_fd, &byte, 1, MSG_NOSIGNAL) == 1 &&
             recv(live_fd, &received, 1, 0) == 1 && received == byte;
    }
    fs_test_close_fd(live_fd);
    fs_test_close_fd(peer_fd);
    fs_test_close_fd(old_pair[0]);
    fs_test_close_fd(old_pair[1]);
    fs_test_close_fd(replacement[0]);
    fs_test_close_fd(replacement[1]);
    return ok;
}

static bool fs_test_range_early_phase(struct range_worker *wp, bool ok)
{
    int early_pair[2] = {-1, -1};
    uint8_t received = 0;

    atomic_store(&wp->cancel, false);
    wp->fd = -1;
    range_worker_cancel(wp);
    ok = ok && socketpair(AF_UNIX, SOCK_STREAM, 0, early_pair) == 0;
    if (early_pair[0] >= 0) {
        bool published = range_worker_socket_publish(wp, early_pair[0]);
        ssize_t n = recv(early_pair[0], &received, 1, MSG_DONTWAIT);
        ok = ok && !published && n == 0;
        range_worker_socket_close(wp, early_pair[0]);
        early_pair[0] = -1;
    }
    if (early_pair[0] >= 0)
        close(early_pair[0]);
    if (early_pair[1] >= 0)
        close(early_pair[1]);
    return ok;
}

static bool fs_test_range_race_phase(struct range_worker *wp, bool ok)
{
    int race_pair[2] = {-1, -1};
    atomic_store(&wp->cancel, false);
    wp->fd = -1;
    ok = ok && socketpair(AF_UNIX, SOCK_STREAM, 0, race_pair) == 0;
    zcl_barrier_t barrier;
    bool barrier_initialized = ok && zcl_barrier_init(&barrier, 2) == 0;
    pthread_t closer;
    bool closer_started = false;
    struct fs_test_range_close_race race = {
        .worker = wp,
        .barrier = &barrier,
        .fd = race_pair[0],
    };
    if (barrier_initialized)
        ok = range_worker_socket_publish(wp, race_pair[0]);
    if (ok) {
        /* raw-pthread-ok: deterministic joined ownership-race regression */
        closer_started = pthread_create(&closer, NULL,
                                         fs_test_range_close_race_fn,
                                         &race) == 0;
        ok = closer_started;
    }
    if (closer_started) {
        (void)zcl_barrier_wait(&barrier);
        range_worker_cancel(wp);
        pthread_join(closer, NULL);
        race_pair[0] = -1;
        ok = ok && wp->fd == -1;
    } else if (race_pair[0] >= 0) {
        range_worker_socket_close(wp, race_pair[0]);
        race_pair[0] = -1;
    }
    if (barrier_initialized)
        zcl_barrier_destroy(&barrier);
    if (race_pair[0] >= 0)
        close(race_pair[0]);
    if (race_pair[1] >= 0)
        close(race_pair[1]);
    return ok;
}

bool fs_test_range_worker_socket_lifecycle(void)
{
    pthread_mutex_t fd_mutex;
    struct range_worker w;
    if (pthread_mutex_init(&fd_mutex, NULL) != 0)
        return false;
    bool ok = true;

    memset(&w, 0, sizeof(w));
    w.fd_mutex = &fd_mutex;
    w.fd = -1;
    atomic_init(&w.cancel, false);


    ok = fs_test_range_reuse_phase(&w, ok);
    ok = fs_test_range_early_phase(&w, ok);
    ok = fs_test_range_race_phase(&w, ok);
    pthread_mutex_destroy(&fd_mutex);
    return ok;
}

#else
typedef int file_service_selftest_nonempty_translation_unit;
#endif
