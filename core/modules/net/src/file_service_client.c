/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast File Service client half: resolved-endpoint connect, the parallel
 * range-download workers and fs_client_sync(). Split out of file_service.c. */

#if !defined(_WIN32)
#define _GNU_SOURCE  /* pthread_timedjoin_np */
#endif

#if !defined(_WIN32)

#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "platform/file_sync.h"
#include "net/file_manifest.h"
#include "net/file_service.h"
#include "net/netbase.h"
#include "file_service_priv.h"
#include "rom_fetch_transport.h"
#include "crypto/sha3.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include "util/safe_alloc.h"
#include "base/serialize_le.h"
#include "util/log_macros.h"
#define FS_WORKER_CONNECT_BUDGET_MS 10000LL
#define FS_WORKER_CONNECT_POLL_MS 100

static int64_t fs_connect_now_ms(const struct fs_connect_ops *ops)
{
    return ops ? ops->now_ms(ops->opaque) : platform_time_monotonic_ms();
}

static bool fs_connect_args_invalid(const struct sockaddr_storage *address,
                                    socklen_t address_len, int64_t budget_ms,
                                    const struct fs_connect_ops *ops)
{
    return !address || address_len == 0 || address_len > sizeof(*address) ||
        budget_ms <= 0 ||
        (ops && (!ops->now_ms || !ops->connect_fd || !ops->poll_fd ||
                 !ops->check_fd));
}

static const char *fs_connect_open_nonblocking(
    const struct sockaddr_storage *address, int socktype, int protocol,
    int *fd, int *flags)
{
    *fd = socket(address->ss_family, socktype, protocol);
    if (*fd < 0)
        return "socket creation failed";
    *flags = fcntl(*fd, F_GETFL, 0);
    if (*flags < 0 || fcntl(*fd, F_SETFL, *flags | O_NONBLOCK) < 0)
        return "nonblocking setup failed";
    return NULL;
}

static int fs_connect_start(int fd, const struct sockaddr_storage *address,
                            socklen_t address_len,
                            const struct fs_connect_ops *ops)
{
    return ops
        ? ops->connect_fd(ops->opaque, fd,
                          (const struct sockaddr *)address, address_len)
        : netbase_connect_guarded(fd, (const struct sockaddr *)address, address_len);
}

static const char *fs_connect_poll_ready(const struct pollfd *pfd, int fd,
                                         const struct fs_connect_ops *ops)
{
    bool connected = ops ? ops->check_fd(ops->opaque, fd)
                         : connect_socket_check(fd);
    if ((pfd->revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
        (pfd->revents & POLLOUT) == 0 || !connected)
        return "asynchronous connect failed";
    return NULL;
}

static const char *fs_connect_wait(int fd, const struct fs_connect_ops *ops,
                                   int64_t start_ms, int64_t deadline_ms)
{
    for (;;) {
        int64_t now_ms = fs_connect_now_ms(ops);
        if (now_ms < start_ms || now_ms >= deadline_ms)
            return "connect deadline expired or clock reversed";
        int64_t remaining_ms = deadline_ms - now_ms;
        int timeout_ms = remaining_ms > INT_MAX ? INT_MAX
                                                : (int)remaining_ms;
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int poll_rc = ops ? ops->poll_fd(ops->opaque, &pfd, timeout_ms)
                          : poll(&pfd, 1, timeout_ms);
        if (poll_rc < 0 && errno == EINTR)
            continue;
        if (poll_rc < 0)
            return "connect poll failed";
        if (poll_rc == 0)
            continue;
        return fs_connect_poll_ready(&pfd, fd, ops);
    }
}



/* Connect an already-resolved endpoint with one absolute monotonic budget.
 * The returned descriptor is restored to blocking mode; every failure closes
 * it.  Tests inject only the timing/syscall edge while production calls the
 * real nonblocking connect/poll/SO_ERROR path. */
int fs_connect_resolved_until(const struct sockaddr_storage *address,
                              socklen_t address_len,
                              int socktype, int protocol,
                              int64_t budget_ms,
                              const struct fs_connect_ops *ops)
{
    const char *failure = NULL;
    int fd = -1;
    int flags = -1;
    int64_t start_ms = 0;

    if (fs_connect_args_invalid(address, address_len, budget_ms, ops)) {
        failure = "invalid resolved endpoint or budget";
        goto failed;
    }
    start_ms = fs_connect_now_ms(ops);
    if (start_ms <= 0 || start_ms > INT64_MAX - budget_ms) {
        failure = "monotonic connect deadline unavailable";
        goto failed;
    }
    int64_t deadline_ms = start_ms + budget_ms;

    failure = fs_connect_open_nonblocking(address, socktype, protocol,
                                          &fd, &flags);
    if (failure)
        goto failed;

    int rc = fs_connect_start(fd, address, address_len, ops);
    if (rc < 0 && errno != EINPROGRESS && errno != EWOULDBLOCK) {
        failure = "connect failed";
        goto failed;
    }
    if (rc < 0) {
        failure = fs_connect_wait(fd, ops, start_ms, deadline_ms);
        if (failure)
            goto failed;
    }

    int64_t completed_ms = fs_connect_now_ms(ops);
    if (completed_ms < start_ms || completed_ms >= deadline_ms) {
        failure = "connect completed outside its absolute deadline";
        goto failed;
    }
    if (fcntl(fd, F_SETFL, flags) < 0) {
        failure = "blocking-mode restore failed";
        goto failed;
    }
    return fd;

failed:
    if (fd >= 0)
        close(fd);
    LOG_ERR("filesvc", "resolved connect: %s", failure ? failure : "failed");
}

/* `fd_mutex` protects the descriptor number through shutdown/close.  Clearing
 * it before close while still holding the mutex prevents the manager from
 * applying cancellation to an unrelated socket that later reuses the number.
 * The atomic cancellation flag closes the cancel-before-publish window. */
bool range_worker_socket_publish(struct range_worker *w, int fd)
{
    bool cancelled;

    pthread_mutex_lock(w->fd_mutex);
    w->fd = fd;
    cancelled = atomic_load_explicit(&w->cancel, memory_order_acquire) ||
        (w->operation && atomic_load_explicit(&w->operation->cancelled, memory_order_acquire));
    if (!cancelled && w->operation) w->operation->fds[w->operation_slot] = fd;
    if (cancelled)
        (void)shutdown(fd, SHUT_RDWR);
    pthread_mutex_unlock(w->fd_mutex);
    return !cancelled;
}

void range_worker_cancel(struct range_worker *w)
{
    atomic_store_explicit(&w->cancel, true, memory_order_release);
    pthread_mutex_lock(w->fd_mutex);
    if (w->fd >= 0)
        (void)shutdown(w->fd, SHUT_RDWR);
    pthread_mutex_unlock(w->fd_mutex);
}

void range_worker_socket_close(struct range_worker *w, int fd)
{
    if (fd < 0)
        return;

    pthread_mutex_lock(w->fd_mutex);
    if (w->fd == fd) w->fd = -1;
    if (w->operation && w->operation->fds[w->operation_slot] == fd)
        w->operation->fds[w->operation_slot] = -1;
    (void)close(fd);
    pthread_mutex_unlock(w->fd_mutex);
}

/* Client side: fetch a PoW challenge from the server, solve it, and fill a
 * 48-byte solution bound to this session's handshake nonce. Honest peers must
 * present this before the server will commit to a large range/ALL stream. */
static bool fs_client_solve_challenge(struct fs_session *s,
                                      uint8_t solution[FS_POW_SOLUTION_SIZE],
                                      struct range_worker *worker)
{
    if (!fs_send_frame(s, FS_CHALLENGE, NULL, 0))
        return false;
    uint8_t type;
    const uint8_t *payload;
    uint32_t plen;
    if (!fs_recv_frame(s, &type, &payload, &plen))
        return false;
    if (type != FS_CHALLENGE || plen < FS_CHALLENGE_PAYLOAD_SIZE)
        return false;

    uint8_t seed[32];
    memcpy(seed, payload, 32);
    int bits = payload[32];
    int64_t ts = (int64_t)platform_time_wall_time_t();
    uint64_t nonce = 0;
    if (!fs_solve_challenge_nonce(s, worker, seed, bits, ts, &nonce)) return false;

    memcpy(solution, s->our_nonce, 32);
    memcpy(solution + 32, &ts, 8);
    memcpy(solution + 40, &nonce, 8);
    return true;
}

static bool range_worker_set_nonblocking(int fd, int *flags)
{
    *flags = fcntl(fd, F_GETFL, 0);
    return !(*flags < 0 || fcntl(fd, F_SETFL, *flags | O_NONBLOCK) < 0);
}

static bool range_worker_set_timeouts(int fd)
{
    /* The record layer has tighter absolute deadlines; socket timeouts remain
     * a final kernel-level backstop for handshake and challenge traffic. */
    struct timeval tv = {.tv_sec = 120, .tv_usec = 0};
    return !(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
             setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0);
}

static void range_worker_build_request(const struct range_worker *w,
                                       const uint8_t solution[FS_POW_SOLUTION_SIZE],
                                       uint8_t rng[FS_POW_SOLUTION_SIZE + 8])
{
    memcpy(rng, solution, FS_POW_SOLUTION_SIZE);
    rng[FS_POW_SOLUTION_SIZE + 0] = 'R';
    rng[FS_POW_SOLUTION_SIZE + 1] = 'N';
    rng[FS_POW_SOLUTION_SIZE + 2] = 'G';
    zcl_write_u16_le(&rng[FS_POW_SOLUTION_SIZE + 3], (uint16_t)w->start);
    zcl_write_u16_le(&rng[FS_POW_SOLUTION_SIZE + 5], (uint16_t)w->end);
    rng[FS_POW_SOLUTION_SIZE + 7] = 0;
}

/* Validate peer-provided extents before any output is opened. */
bool fs_manifest_extents_ok(const struct file_chunk *chunks, uint32_t count,
                                   uint64_t lengths[255])
{
    if (!chunks || !lengths || !count || count > FILE_MAX_CHUNKS) return false;
    memset(lengths, 0, 255 * sizeof(*lengths));
    for (uint32_t i = 0; i < count; i++) {
        const struct file_chunk *c = &chunks[i];
        if (c->file_index >= 255 || !c->size || c->size > 60u * 1024u * 1024u ||
            c->offset != lengths[c->file_index] ||
            c->offset > (uint64_t)INT64_MAX - c->size) return false;
        lengths[c->file_index] = c->offset + c->size;
    }
    return true;
}

/* Open each directory component without following links. */
int fs_open_directory(const char *path)
{
    if (!path || !path[0] || strlen(path) >= 4096) { errno = EINVAL; return -1; }
    char copy[4096];
    memcpy(copy, path, strlen(path) + 1);
    int fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    char *save = NULL;
    for (char *part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (strcmp(part, ".") == 0) continue;
        if (strcmp(part, "..") == 0) { close(fd); errno = EINVAL; return -1; }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int saved_errno = errno;
        close(fd);
        if (next < 0) { errno = saved_errno; return -1; }
        fd = next;
    }
    return fd;
}

/* Refuse links at every directory component and output file. */
int fs_chunk_open(const char *dir, uint8_t index, int flags)
{
    int root = fs_open_directory(dir);
    if (root < 0) return -1;
    int parent = root;
    char name[32];
    if (index < 253) {
        parent = openat(root, "blocks", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (parent < 0) { close(root); return -1; }
        (void)snprintf(name, sizeof(name), "blk%05u.dat", (unsigned)index);
    } else if (index == 253) {
        (void)snprintf(name, sizeof(name), "block_index.bin");
    } else if (index == 254) {
        (void)snprintf(name, sizeof(name), "consensus_snapshot.db");
    } else { close(root); return -1; }
    int fd = openat(parent, name, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0644);
    int saved_errno = errno;
    if (parent != root) close(parent);
    close(root);
    errno = saved_errno;
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); errno = EINVAL; return -1; }
    }
    return fd;
}

static bool fs_ensure_blocks(const char *dir)
{
    int root = fs_open_directory(dir);
    if (root < 0) return false;
    if (mkdirat(root, "blocks", 0755) != 0 && errno != EEXIST) { close(root); return false; }
    int blocks = openat(root, "blocks", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(root);
    if (blocks < 0) return false;
    return close(blocks) == 0;
}

static bool fs_output_preflight(const char *dir, const uint64_t lengths[255])
{
    for (unsigned i = 0; i < 255; i++) {
        if (!lengths[i]) continue;
        int fd = fs_chunk_open(dir, (uint8_t)i, O_RDONLY);
        if (fd < 0) { if (errno == ENOENT) continue; return false; }
        struct stat st;
        bool ok = fstat(fd, &st) == 0 && st.st_size >= 0 &&
                  (uint64_t)st.st_size <= lengths[i];
        if (close(fd) != 0 || !ok) return false;
    }
    return true;
}


#ifdef ZCL_TESTING
bool fs_test_output_size(const char *, uint8_t, uint64_t, bool);
bool fs_test_chunk_open(const char *, uint8_t);
bool fs_test_manifest_extents(const struct file_chunk *, uint32_t);
bool fs_test_output_size(const char *dir, uint8_t index, uint64_t size, bool final)
{
    uint64_t lengths[255] = {0};
    if (index == 255 || size == 0) return false;
    lengths[index] = size;
    return final ? fs_output_lengths_ok(dir, lengths) : fs_output_preflight(dir, lengths);
}

bool fs_test_chunk_open(const char *dir, uint8_t index)
{
    int fd = fs_chunk_open(dir, index, O_RDONLY);
    if (fd < 0) return false;
    return close(fd) == 0;
}

bool fs_test_manifest_extents(const struct file_chunk *chunks, uint32_t count)
{
    uint64_t lengths[255];
    return fs_manifest_extents_ok(chunks, count, lengths);
}
#endif

static void range_worker_chunk_path(const struct range_worker *w, uint32_t i,
                                    char blk_path[600])
{
    /* Write to the correct file at the correct offset.
     * file_index 0-252: block files (blk%05d.dat)
     * file_index 253: block_index.bin
     * file_index 254: node.db (SQLite UTXO set)
     * Uses pwrite() for atomic positioned write. */
    if (w->chunks[i].file_index == 254)
        snprintf(blk_path, 600, "%s/consensus_snapshot.db", w->datadir);
    else if (w->chunks[i].file_index == 253)
        snprintf(blk_path, 600, "%s/block_index.bin", w->datadir);
    else
        snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                 w->datadir, w->chunks[i].file_index);
}

/* Writes one received chunk and frees buf. False means the positioned write
 * failed and the chunk must not count as progress. */
static bool range_worker_store_chunk(struct range_worker *w, uint32_t i,
                                      uint8_t *buf, uint32_t sz)
{
    char blk_path[600];
    range_worker_chunk_path(w, i, blk_path);
    int bfd = fs_chunk_open(w->datadir, w->chunks[i].file_index, O_WRONLY | O_CREAT);
    if (bfd >= 0) {
        ssize_t written = pwrite(bfd, buf, sz, (off_t)w->chunks[i].offset);
        if (written != (ssize_t)sz) {
            fprintf(stderr,  // obs-ok:file-transfer-disk-failure
                    "worker %d: pwrite %s offset=%llu "
                    "sz=%u wrote=%zd errno=%d\n",
                    w->id, blk_path,
                    (unsigned long long)w->chunks[i].offset,
                    sz, written, errno);
            close(bfd);
            free(buf);
            atomic_fetch_add(&w->chunks_fail, 1);
            return false;
        }
        /* Sync to disk so crash can't lose this chunk */
        int sync_rc = platform_data_sync(bfd);
        int close_rc = close(bfd);
        if (sync_rc != 0 || close_rc != 0) {
            free(buf);
            atomic_fetch_add(&w->chunks_fail, 1);
            return false;
        }
        atomic_fetch_add(&w->chunks_ok, 1);
    } else {
        fprintf(stderr,  // obs-ok:file-transfer-disk-failure
                "worker %d: open %s failed: %s\n",
                w->id, blk_path, strerror(errno));
        atomic_fetch_add(&w->chunks_fail, 1);
        free(buf);
        return false;
    }
    free(buf);
    return true;
}

/* Open the worker socket, set it nonblocking, and publish it. */
static int range_worker_open_published(struct range_worker *w, int *wfd,
                                       int *flags)
{
    *wfd = -1;
    *flags = -1;
    *wfd = socket(w->peer_sockaddr.ss_family, w->peer_socktype,
                  w->peer_protocol);
    if (*wfd < 0) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: socket() failed: %s",
                  w->id, strerror(errno));
        return -1;
    }
    if (!range_worker_set_nonblocking(*wfd, flags)) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: nonblocking setup failed: %s",
                  w->id, strerror(errno));
        return -1;
    }
    if (!range_worker_socket_publish(w, *wfd)) {
        LOG_WARN_IN("range_worker_fn", "filesvc", "worker %d: cancelled before connect", w->id);
        return -1;
    }
    return 0;
}

/* Poll one in-progress connect. 1 connected, 0 retry, -1 poll error, -2 failed. */
static int range_worker_poll_connect_once(int wfd, int wait_ms)
{
    struct pollfd pfd = {.fd = wfd, .events = POLLOUT, .revents = 0};
    int poll_rc = poll(&pfd, 1, wait_ms);
    if (poll_rc < 0 && errno == EINTR)
        return 0;
    if (poll_rc < 0)
        return -1;
    if (poll_rc == 0)
        return 0;
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
        !connect_socket_check(wfd))
        return -2;
    return 1;
}

/* Finish a connect that returned EINPROGRESS or EWOULDBLOCK. */
static int range_worker_finish_connect(struct range_worker *w, int wfd)
{
    int64_t connect_start = platform_time_monotonic_ms();
    if (connect_start <= 0 ||
        connect_start > INT64_MAX - FS_WORKER_CONNECT_BUDGET_MS) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: invalid connect clock start=%lld",
                      w->id, (long long)connect_start);
        return -1;
    }
    int64_t connect_deadline = connect_start + FS_WORKER_CONNECT_BUDGET_MS;
    for (;;) {
        if (atomic_load_explicit(&w->cancel, memory_order_acquire)) {
            LOG_WARN_IN("range_worker_fn", "filesvc", "worker %d: cancelled during connect",
                         w->id);
            return -1;
        }
        int64_t connect_now = platform_time_monotonic_ms();
        if (connect_now < connect_start) {
            LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: connect clock reversed",
                          w->id);
            return -1;
        }
        int64_t remaining = connect_deadline - connect_now;
        if (remaining <= 0) {
            LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: connect timed out after %lldms",
                          w->id, (long long)FS_WORKER_CONNECT_BUDGET_MS);
            return -1;
        }
        int wait_ms = remaining < FS_WORKER_CONNECT_POLL_MS
            ? (int)remaining : FS_WORKER_CONNECT_POLL_MS;
        int step = range_worker_poll_connect_once(wfd, wait_ms);
        if (step == 0)
            continue;
        if (step < 0) {
            if (step == -1)
                LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: connect poll failed: %s",
                          w->id, strerror(errno));
            else
                LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: asynchronous connect failed",
                          w->id);
            return -1;
        }
        break;
    }
    return 0;
}

/* Restore blocking mode and apply the socket timeouts. */
static int range_worker_arm_socket(struct range_worker *w, int wfd,
                                   int socket_flags)
{
    if (atomic_load_explicit(&w->cancel, memory_order_acquire)) {
        LOG_WARN_IN("range_worker_fn", "filesvc", "worker %d: cancelled after connect", w->id);
        return -1;
    }
    if (fcntl(wfd, F_SETFL, socket_flags) < 0) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: blocking restore failed: %s",
                  w->id, strerror(errno));
        return -1;
    }
    if (!range_worker_set_timeouts(wfd)) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: socket timeout setup failed: %s",
                  w->id, strerror(errno));
        return -1;
    }
    return 0;
}

/* Handshake, solve the PoW challenge, and send the gated range request. */
static int range_worker_handshake_request(struct range_worker *w,
                                          struct fs_session *ws)
{
    if (!fs_handshake(ws, w->utxo_root, true)) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: handshake failed", w->id);
        return -1;
    }

    /* Solve the server's PoW challenge before requesting the range. */
    uint8_t solution[FS_POW_SOLUTION_SIZE];
    if (!fs_client_solve_challenge(ws, solution, w)) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: PoW challenge/solve failed", w->id);
        return -1;
    }

    /* Send the gated range request: [48-byte solution]["RNG"][start][end]. */
    uint8_t rng[FS_POW_SOLUTION_SIZE + 8];
    range_worker_build_request(w, solution, rng);
    if (!fs_send_frame(ws, FS_REQUEST, rng, sizeof(rng))) {
        LOG_ERROR_IN("range_worker_fn", "filesvc", "worker %d: range request send failed", w->id);
        return -1;
    }
    return 0;
}

/* Read the worker's chunk range and return the updated next-chunk index. */
static uint32_t range_worker_recv_range(struct range_worker *w,
                                        struct fs_session *ws,
                                        uint32_t next_chunk)
{
    for (uint32_t i = w->start; i < w->end; i++) {
        if (atomic_load_explicit(&w->cancel, memory_order_acquire) ||
            fs_receive_cancelled(w->operation)) {
            if (atomic_load(&w->chunks_fail) == 0)
                atomic_store(&w->stopped_at_boundary, true);
            LOG_WARN_IN("range_worker_fn", "filesvc", "worker %d: cancelled", w->id);
            return next_chunk;
        }
        uint8_t *buf = NULL;
        uint32_t sz = 0;
        if (!fs_recv_chunk_fast(ws, &buf, &sz, w->chunks[i].sha3)) {
            fprintf(stderr,  // obs-ok:file-transfer-peer-failure
                    "worker %d: chunk %u/%u recv failed\n",
                    w->id, i, w->end);
            /* A partial raw record desynchronizes this byte stream.  Cleanup
             * counts the unreceived tail; retry opens a fresh connection. */
            return next_chunk;
        }

        if (sz != w->chunks[i].size) {
            free(buf);
            atomic_fetch_add(&w->chunks_fail, 1);
            next_chunk = i + 1;
            continue;
        }
        if (!range_worker_store_chunk(w, i, buf, sz)) {
            next_chunk = i + 1;
            continue; /* skip — don't count failed write as progress */
        }
        atomic_fetch_add(&w->bytes, sz);
        next_chunk = i + 1;
    }
    return next_chunk;
}

static int fs_onion_dial_cancelable(const char *peer, uint16_t port, struct fs_receive_op *op)
{
    if (!op || !op->strict) return rf_connect(peer, port);
    return (int)rf_connect_onion_cancelable(peer, port, fs_receive_cancelled, op);
}

static int fs_onion_manifest_dial(const char *peer, uint16_t port)
{ return rf_connect(peer, port); }
static int fs_onion_worker_dial(const char *peer, uint16_t port)
{ return rf_connect(peer, port); }
static int fs_onion_retry_dial(const char *peer, uint16_t port)
{ return rf_connect(peer, port); }
#ifdef ZCL_TESTING
int fs_test_onion_dial(unsigned, const char *, uint16_t);
int fs_test_onion_dial(unsigned site, const char *peer, uint16_t port)
{
    switch (site) {
    case 0: return fs_onion_manifest_dial(peer, port);
    case 1: return fs_onion_worker_dial(peer, port);
    case 2: return fs_onion_retry_dial(peer, port);
    default: return -1;
    }
}
#endif

static bool range_worker_connect(struct range_worker *w, int *wfd, int *socket_flags)
{
    if (w->onion_peer) {
        *wfd = w->operation ? fs_onion_dial_cancelable(w->onion_peer, w->onion_port, w->operation) :
            fs_onion_worker_dial(w->onion_peer, w->onion_port);
        if (*wfd < 0 || !range_worker_socket_publish(w, *wfd)) return false;
    } else {
        if (range_worker_open_published(w, wfd, socket_flags) != 0)
            return false;

        int connect_rc = netbase_connect_guarded(
            *wfd, (struct sockaddr *)&w->peer_sockaddr, w->peer_sockaddr_len);
        if (connect_rc < 0 && errno != EINPROGRESS && errno != EWOULDBLOCK) {
            LOG_ERROR("filesvc", "worker %d: connect failed: %s",
                      w->id, strerror(errno));
            return false;
        }
        if (connect_rc < 0 && range_worker_finish_connect(w, *wfd) != 0)
            return false;
        if (range_worker_arm_socket(w, *wfd, *socket_flags) != 0)
            return false;
    }
    return true;
}

static void *range_worker_fn(void *arg)
{
    struct range_worker *w = (struct range_worker *)arg;
    int wfd = -1;
    int socket_flags = -1;
    bool session_initialized = false;
    uint32_t next_chunk = w->start;
    struct fs_session ws;

    if (w->start >= w->end)
        goto done;
    if (!range_worker_connect(w, &wfd, &socket_flags)) goto done;

    fs_session_init(&ws, wfd);
    session_initialized = true;
    if (range_worker_handshake_request(w, &ws) != 0)
        goto done;

    next_chunk = range_worker_recv_range(w, &ws, next_chunk);

done:
    if (next_chunk < w->end)
        atomic_fetch_add(&w->chunks_fail, w->end - next_chunk);
    if (session_initialized)
        fs_session_cleanup(&ws);
    range_worker_socket_close(w, wfd);
    atomic_store_explicit(&w->done, true, memory_order_release);
    return NULL;
}


static void fs_sync_check_stalls(struct range_worker *workers, int nworkers,
                                 uint64_t *prev_done_bytes, int *stall_counts)
{
        /* The transport itself bounds a maximum public record to 271s.
         * Keep this coarser recovery guard above that honest wire budget. */
        {
            for (int w = 0; w < nworkers; w++) {
                uint64_t wb = atomic_load(&workers[w].bytes);
                if (!atomic_load(&workers[w].done) && wb == prev_done_bytes[w]) {
                    stall_counts[w]++;
                    if (stall_counts[w] >= 60) { /* 60*5s = 300s stall */
                        fprintf(stderr,  // obs-ok:file-transfer-stall-recovery
                                "file_service: worker %d stalled "
                                "at %llu bytes, cancelling\n",
                                w, (unsigned long long)wb);
                        range_worker_cancel(&workers[w]);
                        stall_counts[w] = 0;
                    }
                } else {
                    stall_counts[w] = 0;
                    prev_done_bytes[w] = wb;
                }
            }
        }
}

static bool fs_sync_workers_expired(struct range_worker *workers, int nworkers,
                                    int64_t elapsed, int64_t max_wait)
{
    if (elapsed <= max_wait) return false;
    printf("file_service: timeout after %llds, cancelling stuck workers\n", (long long)elapsed);
    for (int w = 0; w < nworkers; w++)
        if (!atomic_load(&workers[w].done)) range_worker_cancel(&workers[w]);
    return true;
}

static bool fs_sync_monitor_workers(struct range_worker *workers,
                                    int nworkers, uint64_t total_bytes,
                                    int64_t dl_start, struct fs_receive_op *op)
{
    /* Monitor progress — give up after 30 min total */
    int64_t max_wait = 1800;
    uint64_t prev_done_bytes[FS_NWORKERS];
    int stall_counts[FS_NWORKERS];
    memset(prev_done_bytes, 0, sizeof(prev_done_bytes));
    /* Start at -4 so workers have 20s grace period to connect+handshake
     * before stall detection kicks in. Prevents false cancellation. */
    for (int w = 0; w < FS_NWORKERS; w++) stall_counts[w] = -4;
    while (true) {
        for (int tick = 0; tick < 5; ++tick) {
            if (fs_receive_cancelled(op)) {
                for (int w = 0; w < nworkers; ++w) range_worker_cancel(&workers[w]);
                return true;
            }
            sleep(1);
        }
        uint64_t done = 0;
        bool all_done = true;
        for (int w = 0; w < nworkers; w++) {
            done += atomic_load(&workers[w].bytes);
            if (!atomic_load(&workers[w].done)) all_done = false;
        }
        int64_t el = (int64_t)platform_time_wall_time_t() - dl_start;
        if (fs_sync_workers_expired(workers, nworkers, el, max_wait)) break;
        fs_sync_check_stalls(workers, nworkers, prev_done_bytes, stall_counts);
        double pct = total_bytes > 0 ? 100.0 * (double)done / (double)total_bytes : 0;
        int64_t elapsed = (int64_t)platform_time_wall_time_t() - dl_start;
        double mbps = elapsed > 0 ? (double)done / (1048576.0 * (double)elapsed) : 0;
        int eta = (done > 0 && elapsed > 0) ?
            (int)((double)(total_bytes - done) / ((double)done / (double)elapsed)) : 0;
        printf("file_service: [%3.0f%%] %.1f/%.1f GB  %.1f MB/s  "
               "(%d connections)  ETA %dm%02ds\n",
               pct, (double)done / (1024.0*1024.0*1024.0),
               (double)total_bytes / (1024.0*1024.0*1024.0),
               mbps, nworkers, eta / 60, eta % 60);
        fflush(stdout);
        if (all_done || done >= total_bytes) break;
    }
    return false;
}

static void fs_sync_worker_init(struct range_worker *wk, int w,
                                const struct sockaddr_storage *peer,
                                socklen_t peer_len, int peer_socktype,
                                int peer_protocol, const uint8_t utxo_root[32],
                                struct file_chunk *chunks, uint32_t ws,
                                uint32_t we, const char *datadir,
                                pthread_mutex_t *fd_mutex)
{
    wk->onion_peer = NULL;
    wk->onion_port = 0;
    wk->peer_sockaddr = *peer;
    wk->peer_sockaddr_len = peer_len;
    wk->peer_socktype = peer_socktype;
    wk->peer_protocol = peer_protocol;
    memcpy(wk->utxo_root, utxo_root, 32);
    wk->chunks = chunks;
    wk->start = ws;
    wk->end = we;
    wk->datadir = datadir;
    wk->id = w;
    wk->fd_mutex = fd_mutex;
    wk->fd = -1;
    atomic_store(&wk->done, false);
    atomic_store(&wk->cancel, false);
    atomic_store(&wk->stopped_at_boundary, false);
    atomic_store(&wk->bytes, 0);
    atomic_store(&wk->chunks_ok, 0);
    atomic_store(&wk->chunks_fail, 0);
}

static uint32_t fs_sync_collect_retry(const struct file_chunk *chunks,
                                      uint32_t skip_chunks,
                                      uint32_t num_chunks, const char *datadir,
                                      uint32_t total_fail,
                                      uint32_t *retry_idx, struct fs_receive_op *op)
{
        uint32_t nretry = 0;
        for (uint32_t c = skip_chunks; c < num_chunks && nretry < total_fail; c++) {
            if (fs_receive_cancelled(op)) break;
            enum fs_resume_cause cause;
            if (fs_sync_resume_scan(datadir, &chunks[c], 1, op, &cause) != 1)
                retry_idx[nretry++] = c;
        }
    return nretry;
}

static uint32_t fs_sync_retry_fetch(struct fs_session *rs,
                                    const struct file_chunk *chunks,
                                    const char *datadir,
                                    const uint32_t *retry_idx,
                                    uint32_t nretry, int retry)
{
    uint32_t recovered = 0;
        for (uint32_t r = 0; r < nretry; r++) {
            uint32_t ci = retry_idx[r];
            /* Request individual chunk by hash. A send failure means the
             * retry connection is dead — stop and let the post-loop cleanup
             * close rfd and free retry_idx. */
            if (!fs_send_frame(rs, FS_REQUEST, chunks[ci].sha3, 32))
                break;

            uint8_t *buf = NULL;
            uint32_t sz = 0;
            if (!fs_recv_chunk_fast(rs, &buf, &sz, chunks[ci].sha3)) {
                printf("[file] retrying chunk %u attempt %d failed\n",
                       ci, retry + 1);
                break;
            }

            if (sz != chunks[ci].size) { free(buf); continue; }
            int bfd = fs_chunk_open(datadir, chunks[ci].file_index, O_WRONLY | O_CREAT);
            if (bfd >= 0) {
                ssize_t written = pwrite(bfd, buf, sz,
                                         (off_t)chunks[ci].offset);
                int sync_rc = platform_data_sync(bfd);
                int close_rc = close(bfd);
                if (written == (ssize_t)sz && sync_rc == 0 && close_rc == 0) {
                    recovered++;
                    printf("[file] retrying chunk %u attempt %d succeeded\n",
                           ci, retry + 1);
                }
            }
            free(buf);
        }
    return recovered;
}

enum {
    FS_SYNC_OK = 0,
    FS_SYNC_CONNECT_FAIL = 1,
    FS_SYNC_RESOLVE = 2,
    FS_SYNC_ADDR = 3,
    FS_SYNC_HANDSHAKE = 4,
    FS_SYNC_TIMEOUT = 5,
    FS_SYNC_SEND = 6,
    FS_SYNC_BAD_SIZE = 7,
    FS_SYNC_BAD_INDEX = 8,
    FS_SYNC_EMPTY = 9,
    FS_SYNC_CEILING = 10,
    FS_SYNC_MUTEX = 11,
    FS_SYNC_THREAD = 12,
    FS_SYNC_FAIL_CHUNKS = 13,
    FS_SYNC_INCOMPLETE = 14,
    FS_SYNC_EXPECTED_MISMATCH = 15,
    FS_SYNC_PREFIX_CHANGED = 16
};

/* Manifest connection plus the parallel range workers it launches. */
struct fs_sync_state {
    const char *datadir;
    const char *onion_peer;
    uint16_t onion_port;
    const uint8_t *utxo_root;
    const struct file_manifest *expected;
    struct fs_receive_op *operation;
    bool stopped;
    bool stopped_at_boundary;
    int rc;
    bool complete;
    struct sockaddr_storage resolved_peer;
    socklen_t resolved_peer_len;
    int resolved_peer_socktype;
    int resolved_peer_protocol;
    int fd;
    struct fs_session session;
    bool session_initialized;
    struct file_chunk chunks[FILE_MAX_CHUNKS];
    struct file_chunk *bad_chunk;
    uint32_t num_chunks;
    bool manifest_done;
    uint64_t lengths[255];
    uint64_t total_bytes;
    int64_t dl_start;
    uint32_t skip_chunks;
    uint32_t remaining;
    uint32_t per;
    struct range_worker workers[FS_NWORKERS];
    pthread_t wthreads[FS_NWORKERS];
    int nworkers;
    pthread_mutex_t worker_fd_mutex;
    int worker_mutex_rc;
    int w;
    uint64_t bytes_done;
    uint32_t total_ok;
    uint32_t total_fail;
};

/* Close the manifest session and record rc. */
static void fs_sync_drop_session(struct fs_sync_state *st, int rc)
{
    if (st->session_initialized) fs_session_cleanup(&st->session);
    st->session_initialized = false;
    fs_receive_close(st->operation, FS_NWORKERS, st->fd);
    st->fd = -1;
    st->rc = rc;
}

/* Resolve peer_addr and open the bounded manifest connection. */
static void fs_sync_resolve_connect(struct fs_sync_state *st,
                                    const char *peer_addr, uint16_t port)
{
    if (net_name_is_onion(peer_addr)) {
        st->onion_peer = peer_addr;
        st->onion_port = port;
        st->fd = st->operation ? fs_onion_dial_cancelable(peer_addr, port, st->operation) :
            fs_onion_manifest_dial(peer_addr, port);
        if (st->fd >= 0 && !fs_receive_adopt(st->operation, FS_NWORKERS, st->fd)) {
            close(st->fd); st->fd = -1;
        }
        if (st->fd < 0) st->rc = FS_SYNC_CONNECT_FAIL;
        return;
    }
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (st->operation && st->operation->strict) hints.ai_flags = AI_NUMERICHOST;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (netbase_getaddrinfo_guarded(peer_addr, port_str, &hints, &res) != 0) {
        st->rc = FS_SYNC_RESOLVE;
        return;
    }

    if (res->ai_addrlen > sizeof(st->resolved_peer)) {
        freeaddrinfo(res);
        st->rc = FS_SYNC_ADDR;
        return;
    }
    memset(&st->resolved_peer, 0, sizeof(st->resolved_peer));
    memcpy(&st->resolved_peer, res->ai_addr, res->ai_addrlen);
    st->resolved_peer_len = res->ai_addrlen;
    st->resolved_peer_socktype = res->ai_socktype;
    st->resolved_peer_protocol = res->ai_protocol;

    st->fd = fs_connect_with_operation(
        &st->resolved_peer, st->resolved_peer_len, st->resolved_peer_socktype,
        st->resolved_peer_protocol, FS_WORKER_CONNECT_BUDGET_MS, st->operation);
    freeaddrinfo(res);
    if (st->fd >= 0 && !fs_receive_adopt(st->operation, FS_NWORKERS, st->fd)) {
        close(st->fd); st->fd = -1;
    }
    if (st->fd < 0) {
        /* Optional fast-sync seed not reachable — routine on a fresh node;
         * P2P snapshot sync remains the fallback. */
        LOG_WARN_IN("fs_client_sync", "filesvc", "client_sync: bounded connect to %s:%d failed "
                 "(optional seed; falling back to P2P)", peer_addr, port);
        st->rc = FS_SYNC_CONNECT_FAIL;
    }
}

/* Handshake, then request the manifest on the open connection. */
static void fs_sync_handshake_manifest(struct fs_sync_state *st)
{
    if (st->rc != 0)
        return;
    fs_session_init(&st->session, st->fd);
    st->session_initialized = true;

    if (!fs_handshake(&st->session, st->utxo_root, true)) {
        fs_sync_drop_session(st, FS_SYNC_HANDSHAKE);
        return;
    }

    printf("file_service: connected, requesting manifest...\n");

    /* Set timeout for manifest reception — don't block forever */
    struct timeval mtv;
    mtv.tv_sec = 60; /* 60s to receive full manifest */
    mtv.tv_usec = 0;
    if (setsockopt(st->fd, SOL_SOCKET, SO_RCVTIMEO, &mtv, sizeof(mtv)) < 0) {
        fs_sync_drop_session(st, FS_SYNC_TIMEOUT);
        return;
    }

    if (!fs_send_frame(&st->session, FS_MANIFEST, NULL, 0))
        fs_sync_drop_session(st, FS_SYNC_SEND);
}


/* Read manifest frames into st->chunks. Stops on a rejected entry. */
static void fs_sync_read_chunks(struct fs_sync_state *st)
{
    if (st->rc != 0)
        return;
    for (;;) {
        uint8_t type;
        const uint8_t *payload;
        uint32_t plen;

        if (!fs_recv_frame(&st->session, &type, &payload, &plen))
            break;

        int frame = fs_manifest_frame(type, plen, st->num_chunks, st->operation && st->operation->strict);
        if (frame == 0) { st->manifest_done = true; break; }
        if (frame < 0) { fs_sync_drop_session(st, FS_SYNC_BAD_SIZE); return; }
        {
            struct file_chunk *c = &st->chunks[st->num_chunks];
            memset(c, 0, sizeof(*c));   /* short form leaves file_index/offset
                                         * unset — zero them, not stack garbage */
            memcpy(c->sha3, payload, 32);
            c->size = zcl_read_u32_le(payload + 32);
            /* Extended manifest: file_index + offset */
            if (plen >= 45) {
                c->file_index = payload[36];
                memcpy(&c->offset, payload + 37, 8);
            }
            /* SECURITY: every manifest field is peer-supplied. Bound the chunk
             * size here at parse time (the recv path caps at 60MB on the wire,
             * but the resume-verify malloc at line ~1137 trusted this size and a
             * size=0xFFFFFFFF entry would attempt a ~4GB alloc → OOM/DoS on a
             * fresh node). Reject the whole manifest on any out-of-range entry.
             * file_index must address a real sink (0-252 block files, 253
             * block_index.bin, 254 consensus_snapshot.db); 255 is invalid. */
            if (c->size == 0 || c->size > 60 * 1024 * 1024) {
                st->bad_chunk = c;
                fs_sync_drop_session(st, FS_SYNC_BAD_SIZE);
                return;
            }
            if (c->file_index > 254) {
                st->bad_chunk = c;
                fs_sync_drop_session(st, FS_SYNC_BAD_INDEX);
                return;
            }
            st->num_chunks++;
        }
    }
}

enum fs_receive_result fs_receive_probe(struct fs_receive_op *op, const char *peer_addr,
    uint16_t port, const uint8_t utxo_root[32], struct file_manifest *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !op || !op->strict || op->has_expected || !peer_addr || !utxo_root ||
        atomic_exchange(&op->used, true)) return FS_RECEIVE_ERROR;
    if (fs_receive_cancelled(op)) return FS_RECEIVE_STOPPED;
    struct fs_sync_state st = {0};
    st.operation = op; st.utxo_root = utxo_root; st.fd = -1; st.bad_chunk = st.chunks;
    fs_sync_resolve_connect(&st, peer_addr, port);
    fs_sync_handshake_manifest(&st);
    fs_sync_read_chunks(&st);
    bool valid = st.rc == FS_SYNC_OK && fs_probe_validate(st.chunks, st.num_chunks, st.manifest_done, st.lengths, out);
    if (st.fd >= 0) fs_sync_drop_session(&st, st.rc);
    if (!valid) { memset(out, 0, sizeof(*out)); return FS_RECEIVE_ERROR; }
    if (fs_receive_cancelled(op)) { memset(out, 0, sizeof(*out)); return FS_RECEIVE_STOPPED; }
    return FS_RECEIVE_COMPLETE;
}

/* Check the manifest, resume from disk, and close the manifest connection. */
static void fs_sync_finish_manifest(struct fs_sync_state *st)
{
    if (st->rc != 0)
        return;
    if (!st->manifest_done || !fs_manifest_extents_ok(st->chunks, st->num_chunks, st->lengths)) {
        fs_sync_drop_session(st, FS_SYNC_EMPTY);
        return;
    }
    if (st->num_chunks == 0) {
        fs_sync_drop_session(st, FS_SYNC_EMPTY);
        return;
    }

    /* Compute total download size for progress reporting. Each chunk is already
     * bounded at <=60MB and num_chunks at FILE_MAX_CHUNKS (1024), so the sum
     * cannot overflow uint64; cap the cumulative total at the documented
     * ~50GB ceiling so a maximal-but-individually-valid manifest can't request
     * an absurd download. */
    st->total_bytes = 0;
    for (uint32_t j = 0; j < st->num_chunks; j++)
        st->total_bytes += st->chunks[j].size;
    if (st->total_bytes > (uint64_t)FILE_MAX_CHUNKS * FILE_CHUNK_SIZE) {
        fs_sync_drop_session(st, FS_SYNC_CEILING);
        return;
    }
    if (!fs_manifest_expected(st->chunks, st->num_chunks, st->total_bytes, st->lengths, st->expected)) {
        fs_sync_drop_session(st, FS_SYNC_EXPECTED_MISMATCH);
        return;
    }
    printf("file_service: manifest has %u chunks (%.1f GB), downloading...\n",
           st->num_chunks, (double)st->total_bytes / (1024.0 * 1024.0 * 1024.0));

    /* Create blocks directory */
    if (!fs_ensure_blocks(st->datadir)) {
        fs_sync_drop_session(st, FS_SYNC_EMPTY);
        return;
    }

    if (!fs_output_preflight(st->datadir, st->lengths)) {
        fs_sync_drop_session(st, FS_SYNC_INCOMPLETE);
        return;
    }
    st->dl_start = (int64_t)platform_time_wall_time_t();

    /* Check if previous partial download exists — verify and resume.
     * We spot-check existing chunks with SHA3 to detect corruption. */
    enum fs_resume_cause cause;
    st->skip_chunks = fs_sync_resume_scan(st->datadir, st->chunks, st->num_chunks,
                                          st->operation, &cause);

    /* Close manifest connection before opening range sessions. */
    fs_sync_drop_session(st, FS_SYNC_OK);
    enum fs_prefix_decision decision = fs_prefix_decide(cause, st->skip_chunks,
        st->operation ? st->operation->min_verified_chunks : 0, fs_receive_cancelled(st->operation));
    if (decision == FS_PREFIX_ERROR) {
        st->rc = FS_SYNC_PREFIX_CHANGED;
        return;
    }
    if (decision == FS_PREFIX_STOPPED) { st->stopped = st->stopped_at_boundary = true; return; }

    st->remaining = st->num_chunks - st->skip_chunks;
    if (st->remaining == 0) {
        printf("file_service: all %u chunks already verified on disk\n",
               st->num_chunks);
        st->complete = true;
    }
}

/* Launch the parallel range workers for the chunks still missing. */
static void fs_sync_launch(struct fs_sync_state *st)
{
    if (st->rc != 0 || st->complete || st->stopped)
        return;
    /* Launch 8 parallel workers, each downloads a range of chunks */
    st->per = (st->remaining + FS_NWORKERS - 1) / FS_NWORKERS;
    st->nworkers = 0;
    st->worker_mutex_rc = st->operation ? 0 : pthread_mutex_init(&st->worker_fd_mutex, NULL);
    if (st->worker_mutex_rc != 0) {
        st->rc = FS_SYNC_MUTEX;
        return;
    }

    for (st->w = 0; st->w < FS_NWORKERS; st->w++) {
        uint32_t ws = st->skip_chunks + (uint32_t)st->w * st->per;
        uint32_t we = ws + st->per;
        if (we > st->num_chunks) we = st->num_chunks;
        if (ws >= st->num_chunks) break;

        fs_sync_worker_init(&st->workers[st->nworkers], st->w, &st->resolved_peer,
                            st->resolved_peer_len, st->resolved_peer_socktype,
                            st->resolved_peer_protocol, st->utxo_root, st->chunks,
                            ws, we, st->datadir, st->operation ? &st->operation->mutex : &st->worker_fd_mutex);
        st->workers[st->nworkers].operation = st->operation;
        st->workers[st->nworkers].operation_slot = (size_t)st->nworkers;
        st->workers[st->nworkers].onion_peer = st->onion_peer;
        st->workers[st->nworkers].onion_port = st->onion_port;
        /* raw-pthread-ok: short-burst-joined-immediately (per-download workers) */
        if (pthread_create(&st->wthreads[st->nworkers], NULL,
                           range_worker_fn, &st->workers[st->nworkers]) != 0) {
            for (int j = 0; j < st->nworkers; j++) {
                range_worker_cancel(&st->workers[j]);
            }
            for (int j = 0; j < st->nworkers; j++)
                pthread_join(st->wthreads[j], NULL);
            if (!st->operation) pthread_mutex_destroy(&st->worker_fd_mutex);
            st->rc = FS_SYNC_THREAD;
            return;
        }
        st->nworkers++;
    }

    printf("file_service: %d parallel connections downloading...\n", st->nworkers);
}

/* Wait for the workers, then tally bytes and chunk counts. */
static void fs_sync_finish_workers(struct fs_sync_state *st)
{
    if (st->rc != 0 || st->complete || st->stopped)
        return;
    st->stopped = fs_sync_monitor_workers(st->workers, st->nworkers, st->total_bytes,
                            st->dl_start, st->operation);

    for (int w = 0; w < st->nworkers; w++)
        pthread_join(st->wthreads[w], NULL);
    if (!st->operation) pthread_mutex_destroy(&st->worker_fd_mutex);

    st->bytes_done = 0;
    st->total_ok = 0;
    st->total_fail = 0;
    st->stopped_at_boundary = fs_workers_clean_stop(st->workers, st->nworkers, st->stopped);
    for (int w = 0; w < st->nworkers; w++) {
        st->bytes_done += atomic_load(&st->workers[w].bytes);
        st->total_ok += atomic_load(&st->workers[w].chunks_ok);
        st->total_fail += atomic_load(&st->workers[w].chunks_fail);
    }

    int64_t dl_elapsed = (int64_t)platform_time_wall_time_t() - st->dl_start;
    printf("=== File sync: %.1f GB in %llds (%.1f MB/s avg) "
           "chunks: %u ok, %u failed out of %u ===\n",
           (double)st->bytes_done / (1024.0 * 1024.0 * 1024.0),
           (long long)dl_elapsed,
           dl_elapsed > 0 ? (double)st->bytes_done / (1024.0 * 1024.0) / (double)dl_elapsed : 0,
           st->total_ok, st->total_fail, st->remaining);
}

/* Retry chunks the workers failed, up to three fresh connections. */
static int fs_retry_connect(struct fs_sync_state *st)
{
    int fd = st->onion_peer ? (st->operation ?
        fs_onion_dial_cancelable(st->onion_peer, st->onion_port, st->operation) :
        fs_onion_retry_dial(st->onion_peer, st->onion_port)) :
        fs_connect_with_operation(&st->resolved_peer, st->resolved_peer_len,
            st->resolved_peer_socktype, st->resolved_peer_protocol,
            FS_WORKER_CONNECT_BUDGET_MS, st->operation);
    if (fd >= 0 && !fs_receive_adopt(st->operation, FS_NWORKERS + 1, fd)) {
        close(fd); return -1;
    }
    return fd;
}

static bool fs_retry_handshake(struct fs_sync_state *st, int fd, int retry,
                               struct fs_session *session)
{
    struct timeval timeout = {.tv_sec = 120, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        LOG_ERROR_IN("fs_client_sync", "filesvc", "retry %d: socket timeout setup failed: %s",
                     retry + 1, strerror(errno));
        return false;
    }
    fs_session_init(session, fd);
    if (fs_handshake(session, st->utxo_root, true)) return true;
    fs_session_cleanup(session);
    return false;
}

static void fs_sync_retry_failed(struct fs_sync_state *st)
{
    if (st->rc != 0 || st->complete || st->stopped)
        return;
    /* Retry failed chunks — up to 3 attempts with fresh connections */
    for (int retry = 0; retry < 3 && st->total_fail > 0; retry++) {
        if (fs_receive_cancelled(st->operation)) { st->stopped = true; break; }
        printf("[file] retrying %u failed chunks, attempt %d/3\n",
               st->total_fail, retry + 1);

        /* Collect indices of chunks that aren't on disk yet */
        uint32_t *retry_idx = zcl_calloc(st->total_fail, sizeof(uint32_t),
                                         "retry_indices");
        if (!retry_idx) break;
        uint32_t nretry = fs_sync_collect_retry(st->chunks, st->skip_chunks,
                                                st->num_chunks, st->datadir,
                                                st->total_fail, retry_idx, st->operation);
        if (fs_receive_cancelled(st->operation)) { free(retry_idx); st->stopped = true; break; }

        if (nretry == 0) { free(retry_idx); break; }

        /* Reuse the address that completed the manifest connection.  Retry
         * never re-enters DNS and every dial has the same absolute 10s cap. */
        int rfd = fs_retry_connect(st);
        if (rfd < 0) {
            free(retry_idx);
            if (fs_receive_cancelled(st->operation)) { st->rc = FS_SYNC_CONNECT_FAIL; break; }
            continue;
        }

        struct fs_session rs;
        if (!fs_retry_handshake(st, rfd, retry, &rs)) {
            fs_receive_close(st->operation, FS_NWORKERS + 1, rfd);
            free(retry_idx);
            continue;
        }

        uint32_t recovered = fs_sync_retry_fetch(&rs, st->chunks, st->datadir,
                                                 retry_idx, nretry, retry);

        fs_session_cleanup(&rs);
        fs_receive_close(st->operation, FS_NWORKERS + 1, rfd);
        free(retry_idx);
        st->total_fail = (recovered >= st->total_fail) ? 0 : st->total_fail - recovered;
        st->total_ok += recovered;
        printf("[file] retry attempt %d: recovered %u chunks, %u still failed\n",
               retry + 1, recovered, st->total_fail);
    }
}

/* Record a chunk-count failure after retries. */
static void fs_sync_verdict(struct fs_sync_state *st)
{
    if (st->rc != 0 || st->complete || st->stopped_at_boundary)
        return;
    if (st->total_fail > 0)
        st->rc = FS_SYNC_FAIL_CHUNKS;
    else if (st->total_ok < st->remaining)
        st->rc = FS_SYNC_INCOMPLETE;
}

/* ── Client ────────────────────────────────────────────────────── */

static bool fs_sync_report(struct fs_sync_state *st, const char *peer_addr, uint16_t port);

static void fs_sync_complete_outputs(struct fs_sync_state *st)
{
    if (st->rc != FS_SYNC_OK) return;
    if (!fs_output_lengths_ok(st->datadir, st->lengths)) {
        st->rc = FS_SYNC_INCOMPLETE;
        return;
    }
    if (st->operation && st->operation->has_expected &&
        (!fs_output_inventory(st->datadir, st->lengths) ||
         !fs_output_durable(st->datadir, st->lengths))) st->rc = FS_SYNC_INCOMPLETE;
}

static bool fs_client_sync_impl(const char *peer_addr, uint16_t port,
                                const char *datadir, const uint8_t utxo_root[32],
                                struct fs_receive_op *operation, bool *stopped)
{
    printf("file_service: connecting to %s:%d...\n", peer_addr, port);

    struct fs_sync_state st;
    memset(&st, 0, sizeof(st));
    st.datadir = datadir;
    st.utxo_root = utxo_root;
    st.operation = operation;
    st.expected = operation && operation->has_expected ? &operation->expected : NULL;
    st.fd = -1;
    st.bad_chunk = &st.chunks[0];

    if (fs_receive_cancelled(operation)) { *stopped = true; return false; }
    fs_sync_resolve_connect(&st, peer_addr, port);
    fs_sync_handshake_manifest(&st);
    fs_sync_read_chunks(&st);
    fs_sync_finish_manifest(&st);
    fs_sync_launch(&st);
    fs_sync_finish_workers(&st);
    fs_sync_retry_failed(&st);
    fs_sync_verdict(&st);
    if (st.rc == FS_SYNC_OK && fs_receive_cancelled(operation)) st.stopped = true;
    if (st.stopped && st.rc == FS_SYNC_OK) { *stopped = true; return false; }
    fs_sync_complete_outputs(&st);
    if (st.rc == FS_SYNC_OK && fs_receive_cancelled(operation)) { *stopped = true; return false; }

    return fs_sync_report(&st, peer_addr, port);
}


static bool fs_sync_manifest_report(const struct fs_sync_state *st)
{
    uint32_t num_chunks = st->num_chunks;
    uint64_t total_bytes = st->total_bytes;
    struct file_chunk *c = st->bad_chunk;
    switch (st->rc) {
    case FS_SYNC_BAD_SIZE:
        LOG_FAIL("filesvc", "client_sync: manifest chunk %u has invalid "
                 "size=%u (peer-supplied) — rejecting manifest", num_chunks, c->size);
    case FS_SYNC_BAD_INDEX:
        LOG_FAIL("filesvc", "client_sync: manifest chunk %u has invalid "
                 "file_index=%u — rejecting manifest", num_chunks, (unsigned)c->file_index);
    case FS_SYNC_EMPTY:
        LOG_FAIL("filesvc", "client_sync: manifest empty (server still building)");
    case FS_SYNC_CEILING:
        LOG_FAIL("filesvc", "client_sync: manifest total %llu bytes exceeds "
                 "ceiling — rejecting manifest", (unsigned long long)total_bytes);
    case FS_SYNC_EXPECTED_MISMATCH:
        LOG_FAIL("filesvc", "client_sync: received manifest differs from expected history");
    case FS_SYNC_PREFIX_CHANGED:
        LOG_FAIL("filesvc", "client_sync: verified history prefix became unavailable");
    default:
        return st->rc == FS_SYNC_OK;
    }
}

static bool fs_sync_report(struct fs_sync_state *st, const char *peer_addr, uint16_t port)
{
    int worker_mutex_rc = st->worker_mutex_rc;
    int w = st->w;
    uint32_t total_fail = st->total_fail;
    uint32_t total_ok = st->total_ok;
    uint32_t remaining = st->remaining;
    switch (st->rc) {
    case FS_SYNC_RESOLVE:
        LOG_FAIL("filesvc", "client_sync: resolve failed for %s", peer_addr);
    case FS_SYNC_ADDR:
        LOG_FAIL("filesvc", "client_sync: resolved address is too large");
    case FS_SYNC_HANDSHAKE:
        LOG_FAIL("filesvc", "client_sync: handshake failed with %s:%d", peer_addr, port);
    case FS_SYNC_TIMEOUT:
        LOG_FAIL("filesvc", "client_sync: manifest timeout setup failed: %s",
                 strerror(errno));
    case FS_SYNC_SEND:
        LOG_FAIL("filesvc", "client_sync: manifest request send failed to %s:%d", peer_addr, port);
    case FS_SYNC_MUTEX:
        LOG_FAIL("filesvc", "client_sync: worker fd mutex init failed: %s",
                 strerror(worker_mutex_rc));
    case FS_SYNC_THREAD:
        LOG_FAIL("filesvc", "client_sync: failed to start download worker %d", w);
    case FS_SYNC_FAIL_CHUNKS:
        LOG_FAIL("filesvc", "client_sync: %u/%u chunks failed after retries — download incomplete", total_fail, remaining);
    case FS_SYNC_INCOMPLETE:
        LOG_FAIL("filesvc", "client_sync: only %u/%u chunks received — incomplete", total_ok, remaining);
    default:
        return fs_sync_manifest_report(st);
    }
}

enum fs_receive_result fs_receive_run(struct fs_receive_op *op, const char *peer_addr,
    uint16_t port, const char *datadir, const uint8_t utxo_root[32])
{
    if (!op || !op->has_expected || !peer_addr || !datadir || !utxo_root || atomic_exchange(&op->used, true))
        return FS_RECEIVE_ERROR;
    bool stopped = false;
    bool ok = fs_client_sync_impl(peer_addr, port, datadir, utxo_root, op, &stopped);
    return stopped ? FS_RECEIVE_STOPPED : ok ? FS_RECEIVE_COMPLETE : FS_RECEIVE_ERROR;
}

bool fs_client_sync(const char *peer_addr, uint16_t port,
                    const char *datadir, const uint8_t utxo_root[32])
{
    struct fs_receive_op *op = fs_receive_create_internal(NULL);
    if (!op) return false;
    bool stopped = false;
    bool ok = fs_client_sync_impl(peer_addr, port, datadir, utxo_root, op, &stopped);
    fs_receive_destroy(op);
    return ok;
}

#endif /* !_WIN32 */
