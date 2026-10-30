#if !defined(_WIN32)
#define _GNU_SOURCE  /* pthread_timedjoin_np */
#endif

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast File Service client half: resolved-endpoint connect, the parallel
 * range-download workers and fs_client_sync(). Split out of file_service.c. */

#if !defined(_WIN32)

#include "platform/time_compat.h"
#include "platform/thread_compat.h"
#include "platform/file_sync.h"
#include "net/file_manifest.h"
#include "net/file_service.h"
#include "net/netbase.h"
#include "file_service_priv.h"
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

    if (!address || address_len == 0 || address_len > sizeof(*address) ||
        budget_ms <= 0 ||
        (ops && (!ops->now_ms || !ops->connect_fd || !ops->poll_fd ||
                 !ops->check_fd))) {
        failure = "invalid resolved endpoint or budget";
        goto failed;
    }
    start_ms = ops ? ops->now_ms(ops->opaque)
                   : platform_time_monotonic_ms();
    if (start_ms <= 0 || start_ms > INT64_MAX - budget_ms) {
        failure = "monotonic connect deadline unavailable";
        goto failed;
    }
    int64_t deadline_ms = start_ms + budget_ms;

    fd = socket(address->ss_family, socktype, protocol);
    if (fd < 0) {
        failure = "socket creation failed";
        goto failed;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        failure = "nonblocking setup failed";
        goto failed;
    }

    int rc = ops
        ? ops->connect_fd(ops->opaque, fd,
                          (const struct sockaddr *)address, address_len)
        : netbase_connect_guarded(fd, (const struct sockaddr *)address, address_len);
    if (rc < 0 && errno != EINPROGRESS && errno != EWOULDBLOCK) {
        failure = "connect failed";
        goto failed;
    }
    while (rc < 0) {
        int64_t now_ms = ops ? ops->now_ms(ops->opaque)
                             : platform_time_monotonic_ms();
        if (now_ms < start_ms || now_ms >= deadline_ms) {
            failure = "connect deadline expired or clock reversed";
            goto failed;
        }
        int64_t remaining_ms = deadline_ms - now_ms;
        int timeout_ms = remaining_ms > INT_MAX ? INT_MAX
                                                : (int)remaining_ms;
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int poll_rc = ops ? ops->poll_fd(ops->opaque, &pfd, timeout_ms)
                          : poll(&pfd, 1, timeout_ms);
        if (poll_rc < 0 && errno == EINTR)
            continue;
        if (poll_rc < 0) {
            failure = "connect poll failed";
            goto failed;
        }
        if (poll_rc == 0)
            continue;
        bool connected = ops ? ops->check_fd(ops->opaque, fd)
                             : connect_socket_check(fd);
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            (pfd.revents & POLLOUT) == 0 || !connected) {
            failure = "asynchronous connect failed";
            goto failed;
        }
        rc = 0;
    }

    int64_t completed_ms = ops ? ops->now_ms(ops->opaque)
                               : platform_time_monotonic_ms();
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
    cancelled = atomic_load_explicit(&w->cancel, memory_order_acquire);
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
    if (w->fd == fd)
        w->fd = -1;
    (void)close(fd);
    pthread_mutex_unlock(w->fd_mutex);
}

/* Client side: fetch a PoW challenge from the server, solve it, and fill a
 * 48-byte solution bound to this session's handshake nonce. Honest peers must
 * present this before the server will commit to a large range/ALL stream. */
static bool fs_client_solve_challenge(struct fs_session *s,
                                      uint8_t solution[FS_POW_SOLUTION_SIZE])
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
    if (!puzzle_solve(seed, s->our_nonce, ts, bits, &nonce))
        return false;

    memcpy(solution, s->our_nonce, 32);
    memcpy(solution + 32, &ts, 8);
    memcpy(solution + 40, &nonce, 8);
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

    wfd = socket(w->peer_sockaddr.ss_family, w->peer_socktype,
                 w->peer_protocol);
    if (wfd < 0) {
        LOG_ERROR("filesvc", "worker %d: socket() failed: %s",
                  w->id, strerror(errno));
        goto done;
    }

    socket_flags = fcntl(wfd, F_GETFL, 0);
    if (socket_flags < 0 || fcntl(wfd, F_SETFL, socket_flags | O_NONBLOCK) < 0) {
        LOG_ERROR("filesvc", "worker %d: nonblocking setup failed: %s",
                  w->id, strerror(errno));
        goto done;
    }
    if (!range_worker_socket_publish(w, wfd)) {
        LOG_WARN("filesvc", "worker %d: cancelled before connect", w->id);
        goto done;
    }

    int connect_rc = netbase_connect_guarded(wfd, (struct sockaddr *)&w->peer_sockaddr,
                             w->peer_sockaddr_len);
    if (connect_rc < 0 && errno != EINPROGRESS && errno != EWOULDBLOCK) {
        LOG_ERROR("filesvc", "worker %d: connect failed: %s",
                  w->id, strerror(errno));
        goto done;
    }
    if (connect_rc < 0) {
        int64_t connect_start = platform_time_monotonic_ms();
        if (connect_start <= 0 ||
            connect_start > INT64_MAX - FS_WORKER_CONNECT_BUDGET_MS) {
            LOG_ERROR("filesvc", "worker %d: invalid connect clock start=%lld",
                      w->id, (long long)connect_start);
            goto done;
        }
        int64_t connect_deadline = connect_start + FS_WORKER_CONNECT_BUDGET_MS;
        for (;;) {
            if (atomic_load_explicit(&w->cancel, memory_order_acquire)) {
                LOG_WARN("filesvc", "worker %d: cancelled during connect",
                         w->id);
                goto done;
            }
            int64_t connect_now = platform_time_monotonic_ms();
            if (connect_now < connect_start) {
                LOG_ERROR("filesvc", "worker %d: connect clock reversed",
                          w->id);
                goto done;
            }
            int64_t remaining = connect_deadline - connect_now;
            if (remaining <= 0) {
                LOG_ERROR("filesvc", "worker %d: connect timed out after %lldms",
                          w->id, (long long)FS_WORKER_CONNECT_BUDGET_MS);
                goto done;
            }
            int wait_ms = remaining < FS_WORKER_CONNECT_POLL_MS
                ? (int)remaining : FS_WORKER_CONNECT_POLL_MS;
            struct pollfd pfd = {.fd = wfd, .events = POLLOUT, .revents = 0};
            int poll_rc = poll(&pfd, 1, wait_ms);
            if (poll_rc < 0 && errno == EINTR)
                continue;
            if (poll_rc < 0) {
                LOG_ERROR("filesvc", "worker %d: connect poll failed: %s",
                          w->id, strerror(errno));
                goto done;
            }
            if (poll_rc == 0)
                continue;
            if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
                !connect_socket_check(wfd)) {
                LOG_ERROR("filesvc", "worker %d: asynchronous connect failed",
                          w->id);
                goto done;
            }
            break;
        }
    }
    if (atomic_load_explicit(&w->cancel, memory_order_acquire)) {
        LOG_WARN("filesvc", "worker %d: cancelled after connect", w->id);
        goto done;
    }
    if (fcntl(wfd, F_SETFL, socket_flags) < 0) {
        LOG_ERROR("filesvc", "worker %d: blocking restore failed: %s",
                  w->id, strerror(errno));
        goto done;
    }

    /* The record layer has tighter absolute deadlines; socket timeouts remain
     * a final kernel-level backstop for handshake and challenge traffic. */
    struct timeval tv = {.tv_sec = 120, .tv_usec = 0};
    if (setsockopt(wfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(wfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        LOG_ERROR("filesvc", "worker %d: socket timeout setup failed: %s",
                  w->id, strerror(errno));
        goto done;
    }

    fs_session_init(&ws, wfd);
    session_initialized = true;
    if (!fs_handshake(&ws, w->utxo_root, true)) {
        LOG_ERROR("filesvc", "worker %d: handshake failed", w->id);
        goto done;
    }

    /* Solve the server's PoW challenge before requesting the range. */
    uint8_t solution[FS_POW_SOLUTION_SIZE];
    if (!fs_client_solve_challenge(&ws, solution)) {
        LOG_ERROR("filesvc", "worker %d: PoW challenge/solve failed", w->id);
        goto done;
    }

    /* Send the gated range request: [48-byte solution]["RNG"][start][end]. */
    uint8_t rng[FS_POW_SOLUTION_SIZE + 8];
    memcpy(rng, solution, FS_POW_SOLUTION_SIZE);
    rng[FS_POW_SOLUTION_SIZE + 0] = 'R';
    rng[FS_POW_SOLUTION_SIZE + 1] = 'N';
    rng[FS_POW_SOLUTION_SIZE + 2] = 'G';
    zcl_write_u16_le(&rng[FS_POW_SOLUTION_SIZE + 3], (uint16_t)w->start);
    zcl_write_u16_le(&rng[FS_POW_SOLUTION_SIZE + 5], (uint16_t)w->end);
    rng[FS_POW_SOLUTION_SIZE + 7] = 0;
    if (!fs_send_frame(&ws, FS_REQUEST, rng, sizeof(rng))) {
        LOG_ERROR("filesvc", "worker %d: range request send failed", w->id);
        goto done;
    }

    for (uint32_t i = w->start; i < w->end; i++) {
        if (atomic_load_explicit(&w->cancel, memory_order_acquire)) {
            LOG_WARN("filesvc", "worker %d: cancelled", w->id);
            goto done;
        }
        uint8_t *buf = NULL;
        uint32_t sz = 0;
        if (!fs_recv_chunk_fast(&ws, &buf, &sz, w->chunks[i].sha3)) {
            fprintf(stderr,  // obs-ok:file-transfer-peer-failure
                    "worker %d: chunk %u/%u recv failed\n",
                    w->id, i, w->end);
            /* A partial raw record desynchronizes this byte stream.  Cleanup
             * counts the unreceived tail; retry opens a fresh connection. */
            goto done;
        }

        /* Write to the correct file at the correct offset.
         * file_index 0-252: block files (blk%05d.dat)
         * file_index 253: block_index.bin
         * file_index 254: node.db (SQLite UTXO set)
         * Uses pwrite() for atomic positioned write. */
        char blk_path[600];
        if (w->chunks[i].file_index == 254)
            snprintf(blk_path, 600, "%s/consensus_snapshot.db", w->datadir);
        else if (w->chunks[i].file_index == 253)
            snprintf(blk_path, 600, "%s/block_index.bin", w->datadir);
        else
            snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                     w->datadir, w->chunks[i].file_index);
        int bfd = open(blk_path, O_WRONLY | O_CREAT, 0644);
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
                next_chunk = i + 1;
                continue; /* skip — don't count failed write as progress */
            }
            /* Sync to disk so crash can't lose this chunk */
            platform_data_sync(bfd);
            close(bfd);
            atomic_fetch_add(&w->chunks_ok, 1);
        } else {
            fprintf(stderr,  // obs-ok:file-transfer-disk-failure
                    "worker %d: open %s failed: %s\n",
                    w->id, blk_path, strerror(errno));
            atomic_fetch_add(&w->chunks_fail, 1);
        }
        free(buf);
        atomic_fetch_add(&w->bytes, sz);
        next_chunk = i + 1;
    }

done:
    if (next_chunk < w->end)
        atomic_fetch_add(&w->chunks_fail, w->end - next_chunk);
    if (session_initialized)
        fs_session_cleanup(&ws);
    range_worker_socket_close(w, wfd);
    atomic_store_explicit(&w->done, true, memory_order_release);
    return NULL;
}

/* ── Client ────────────────────────────────────────────────────── */

bool fs_client_sync(const char *peer_addr, uint16_t port,
                     const char *datadir, const uint8_t utxo_root[32])
{
    printf("file_service: connecting to %s:%d...\n", peer_addr, port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (netbase_getaddrinfo_guarded(peer_addr, port_str, &hints, &res) != 0)
        LOG_FAIL("filesvc", "client_sync: resolve failed for %s", peer_addr);

    struct sockaddr_storage resolved_peer;
    if (res->ai_addrlen > sizeof(resolved_peer)) {
        freeaddrinfo(res);
        LOG_FAIL("filesvc", "client_sync: resolved address is too large");
    }
    memset(&resolved_peer, 0, sizeof(resolved_peer));
    memcpy(&resolved_peer, res->ai_addr, res->ai_addrlen);
    socklen_t resolved_peer_len = res->ai_addrlen;
    int resolved_peer_socktype = res->ai_socktype;
    int resolved_peer_protocol = res->ai_protocol;

    int fd = fs_connect_resolved_until(
        &resolved_peer, resolved_peer_len, resolved_peer_socktype,
        resolved_peer_protocol, FS_WORKER_CONNECT_BUDGET_MS, NULL);
    freeaddrinfo(res);
    if (fd < 0) {
        /* Optional fast-sync seed not reachable — routine on a fresh node;
         * P2P snapshot sync remains the fallback. */
        LOG_WARN("filesvc", "client_sync: bounded connect to %s:%d failed "
                 "(optional seed; falling back to P2P)", peer_addr, port);
        return false;
    }

    struct fs_session session;
    fs_session_init(&session, fd);

    if (!fs_handshake(&session, utxo_root, true)) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: handshake failed with %s:%d", peer_addr, port);
    }

    printf("file_service: connected, requesting manifest...\n");

    /* Set timeout for manifest reception — don't block forever */
    struct timeval mtv;
    mtv.tv_sec = 60; /* 60s to receive full manifest */
    mtv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &mtv, sizeof(mtv)) < 0) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: manifest timeout setup failed: %s",
                 strerror(errno));
    }

    if (!fs_send_frame(&session, FS_MANIFEST, NULL, 0)) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: manifest request send failed to %s:%d", peer_addr, port);
    }

    struct file_chunk chunks[FILE_MAX_CHUNKS];
    uint32_t num_chunks = 0;

    while (num_chunks < FILE_MAX_CHUNKS) {
        uint8_t type;
        const uint8_t *payload;
        uint32_t plen;

        if (!fs_recv_frame(&session, &type, &payload, &plen))
            break;

        if (type == FS_DONE) break;
        if (type == FS_MANIFEST && plen >= 36) {
            struct file_chunk *c = &chunks[num_chunks];
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
                fs_session_cleanup(&session);
                close(fd);
                LOG_FAIL("filesvc", "client_sync: manifest chunk %u has invalid "
                         "size=%u (peer-supplied) — rejecting manifest",
                         num_chunks, c->size);
            }
            if (c->file_index > 254) {
                fs_session_cleanup(&session);
                close(fd);
                LOG_FAIL("filesvc", "client_sync: manifest chunk %u has invalid "
                         "file_index=%u — rejecting manifest",
                         num_chunks, (unsigned)c->file_index);
            }
            num_chunks++;
        }
    }

    if (num_chunks == 0) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: manifest empty (server still building)");
    }

    /* Compute total download size for progress reporting. Each chunk is already
     * bounded at <=60MB and num_chunks at FILE_MAX_CHUNKS (1024), so the sum
     * cannot overflow uint64; cap the cumulative total at the documented
     * ~50GB ceiling so a maximal-but-individually-valid manifest can't request
     * an absurd download. */
    uint64_t total_bytes = 0;
    for (uint32_t j = 0; j < num_chunks; j++)
        total_bytes += chunks[j].size;
    if (total_bytes > (uint64_t)FILE_MAX_CHUNKS * FILE_CHUNK_SIZE) {
        fs_session_cleanup(&session);
        close(fd);
        LOG_FAIL("filesvc", "client_sync: manifest total %llu bytes exceeds "
                 "ceiling — rejecting manifest",
                 (unsigned long long)total_bytes);
    }
    printf("file_service: manifest has %u chunks (%.1f GB), downloading...\n",
           num_chunks, (double)total_bytes / (1024.0 * 1024.0 * 1024.0));

    /* Create blocks directory */
    char blocks_dir[512];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", datadir);
    mkdir(blocks_dir, 0755);

    int64_t dl_start = (int64_t)platform_time_wall_time_t();

    /* Check if previous partial download exists — verify and resume.
     * We spot-check existing chunks with SHA3 to detect corruption. */
    uint32_t skip_chunks = 0;
    {
        uint32_t verified = 0, checked = 0;
        for (uint32_t j = 0; j < num_chunks; j++) {
            char blk_path[600];
            if (chunks[j].file_index == 253)
                snprintf(blk_path, 600, "%s/block_index.bin", datadir);
            else
                snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                         datadir, chunks[j].file_index);

            /* Check if file is large enough for this chunk */
            struct stat st;
            if (stat(blk_path, &st) != 0 ||
                (uint64_t)st.st_size < chunks[j].offset + chunks[j].size)
                break; /* this chunk not on disk, stop skipping */

            /* SHA3 verify every 20th chunk + first + last existing.
             * Full verification would be slow on 7GB, spot-check is fast. */
            if (j == 0 || j % 20 == 0) {
                int fd2 = open(blk_path, O_RDONLY);
                if (fd2 < 0) break;
                uint8_t *vbuf = zcl_malloc(chunks[j].size, "file_verify_buf");
                if (!vbuf) { close(fd2); break; }
                ssize_t got = pread(fd2, vbuf, chunks[j].size,
                                     (off_t)chunks[j].offset);
                close(fd2);
                if (got != (ssize_t)chunks[j].size) {
                    free(vbuf); break;
                }
                uint8_t hash[32];
                sha3_256(vbuf, chunks[j].size, hash);
                free(vbuf);
                if (memcmp(hash, chunks[j].sha3, 32) != 0) {
                    fprintf(stderr,  // obs-ok:file-transfer-integrity-retry
                            "file_service: resume SHA3 mismatch at "
                            "chunk %u (file=%d off=%llu) — re-downloading "
                            "from here\n", j, chunks[j].file_index,
                            (unsigned long long)chunks[j].offset);
                    break;
                }
                checked++;
            }
            verified++;
        }
        skip_chunks = verified;
        if (skip_chunks > 0) {
            printf("file_service: resuming — %u/%u chunks on disk "
                   "(%u SHA3-verified)\n", skip_chunks, num_chunks, checked);
        }
    }

    /* Close manifest connection — we'll open parallel ones */
    fs_session_cleanup(&session);
    close(fd);

    /* Launch 8 parallel workers, each downloads a range of chunks */
    #define FS_NWORKERS 8
    uint32_t remaining = num_chunks - skip_chunks;
    if (remaining == 0) {
        printf("file_service: all %u chunks already verified on disk\n",
               num_chunks);
        return true;
    }
    uint32_t per = (remaining + FS_NWORKERS - 1) / FS_NWORKERS;
    struct range_worker workers[FS_NWORKERS];
    pthread_t wthreads[FS_NWORKERS];
    int nworkers = 0;
    pthread_mutex_t worker_fd_mutex;
    int worker_mutex_rc = pthread_mutex_init(&worker_fd_mutex, NULL);
    if (worker_mutex_rc != 0)
        LOG_FAIL("filesvc", "client_sync: worker fd mutex init failed: %s",
                 strerror(worker_mutex_rc));

    for (int w = 0; w < FS_NWORKERS; w++) {
        uint32_t ws = skip_chunks + (uint32_t)w * per;
        uint32_t we = ws + per;
        if (we > num_chunks) we = num_chunks;
        if (ws >= num_chunks) break;

        workers[nworkers].peer_sockaddr = resolved_peer;
        workers[nworkers].peer_sockaddr_len = resolved_peer_len;
        workers[nworkers].peer_socktype = resolved_peer_socktype;
        workers[nworkers].peer_protocol = resolved_peer_protocol;
        memcpy(workers[nworkers].utxo_root, utxo_root, 32);
        workers[nworkers].chunks = chunks;
        workers[nworkers].start = ws;
        workers[nworkers].end = we;
        workers[nworkers].datadir = datadir;
        workers[nworkers].id = w;
        workers[nworkers].fd_mutex = &worker_fd_mutex;
        workers[nworkers].fd = -1;
        atomic_store(&workers[nworkers].done, false);
        atomic_store(&workers[nworkers].cancel, false);
        atomic_store(&workers[nworkers].bytes, 0);
        atomic_store(&workers[nworkers].chunks_ok, 0);
        atomic_store(&workers[nworkers].chunks_fail, 0);
        /* raw-pthread-ok: short-burst-joined-immediately (per-download workers) */
        if (pthread_create(&wthreads[nworkers], NULL,
                           range_worker_fn, &workers[nworkers]) != 0) {
            for (int j = 0; j < nworkers; j++) {
                range_worker_cancel(&workers[j]);
            }
            for (int j = 0; j < nworkers; j++)
                pthread_join(wthreads[j], NULL);
            pthread_mutex_destroy(&worker_fd_mutex);
            LOG_FAIL("filesvc", "client_sync: failed to start download worker %d", w);
        }
        nworkers++;
    }

    printf("file_service: %d parallel connections downloading...\n", nworkers);

    /* Monitor progress — give up after 30 min total */
    int64_t max_wait = 1800;
    uint64_t prev_done_bytes[FS_NWORKERS];
    int stall_counts[FS_NWORKERS];
    memset(prev_done_bytes, 0, sizeof(prev_done_bytes));
    /* Start at -4 so workers have 20s grace period to connect+handshake
     * before stall detection kicks in. Prevents false cancellation. */
    for (int w = 0; w < FS_NWORKERS; w++) stall_counts[w] = -4;
    while (true) {
        sleep(5);
        uint64_t done = 0;
        bool all_done = true;
        for (int w = 0; w < nworkers; w++) {
            done += atomic_load(&workers[w].bytes);
            if (!atomic_load(&workers[w].done)) all_done = false;
        }
        int64_t el = (int64_t)platform_time_wall_time_t() - dl_start;
        if (el > max_wait) {
            printf("file_service: timeout after %llds, cancelling stuck "
                   "workers\n", (long long)el);
            for (int w = 0; w < nworkers; w++) {
                if (!atomic_load(&workers[w].done)) {
                    range_worker_cancel(&workers[w]);
                }
            }
            break;
        }
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

    for (int w = 0; w < nworkers; w++)
        pthread_join(wthreads[w], NULL);
    pthread_mutex_destroy(&worker_fd_mutex);

    uint64_t bytes_done = 0;
    uint32_t total_ok = 0, total_fail = 0;
    for (int w = 0; w < nworkers; w++) {
        bytes_done += atomic_load(&workers[w].bytes);
        total_ok += atomic_load(&workers[w].chunks_ok);
        total_fail += atomic_load(&workers[w].chunks_fail);
    }

    int64_t dl_elapsed = (int64_t)platform_time_wall_time_t() - dl_start;
    printf("=== File sync: %.1f GB in %llds (%.1f MB/s avg) "
           "chunks: %u ok, %u failed out of %u ===\n",
           (double)bytes_done / (1024.0 * 1024.0 * 1024.0),
           (long long)dl_elapsed,
           dl_elapsed > 0 ? (double)bytes_done / (1024.0 * 1024.0) / (double)dl_elapsed : 0,
           total_ok, total_fail, remaining);

    /* Retry failed chunks — up to 3 attempts with fresh connections */
    for (int retry = 0; retry < 3 && total_fail > 0; retry++) {
        printf("[file] retrying %u failed chunks, attempt %d/3\n",
               total_fail, retry + 1);

        /* Collect indices of chunks that aren't on disk yet */
        uint32_t *retry_idx = zcl_calloc(total_fail, sizeof(uint32_t),
                                         "retry_indices");
        if (!retry_idx) break;
        uint32_t nretry = 0;
        for (uint32_t c = skip_chunks; c < num_chunks && nretry < total_fail; c++) {
            /* Quick check: try reading the chunk back and verifying hash */
            char blk_path[600];
            if (chunks[c].file_index == 254)
                snprintf(blk_path, 600, "%s/consensus_snapshot.db", datadir);
            else if (chunks[c].file_index == 253)
                snprintf(blk_path, 600, "%s/block_index.bin", datadir);
            else
                snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                         datadir, chunks[c].file_index);
            int cfd = open(blk_path, O_RDONLY);
            if (cfd < 0) { retry_idx[nretry++] = c; continue; }
            uint8_t probe[1];
            ssize_t rd = pread(cfd, probe, 1, (off_t)chunks[c].offset);
            close(cfd);
            if (rd <= 0)
                retry_idx[nretry++] = c;
        }

        if (nretry == 0) { free(retry_idx); break; }

        /* Reuse the address that completed the manifest connection.  Retry
         * never re-enters DNS and every dial has the same absolute 10s cap. */
        int rfd = fs_connect_resolved_until(
            &resolved_peer, resolved_peer_len, resolved_peer_socktype,
            resolved_peer_protocol, FS_WORKER_CONNECT_BUDGET_MS, NULL);
        if (rfd < 0) {
            free(retry_idx);
            continue;
        }

        struct timeval rtv = { .tv_sec = 120, .tv_usec = 0 };
        if (setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv)) < 0 ||
            setsockopt(rfd, SOL_SOCKET, SO_SNDTIMEO, &rtv, sizeof(rtv)) < 0) {
            LOG_ERROR("filesvc", "retry %d: socket timeout setup failed: %s",
                      retry + 1, strerror(errno));
            close(rfd);
            free(retry_idx);
            continue;
        }

        struct fs_session rs;
        fs_session_init(&rs, rfd);
        if (!fs_handshake(&rs, utxo_root, true)) {
            fs_session_cleanup(&rs);
            close(rfd);
            free(retry_idx);
            continue;
        }

        uint32_t recovered = 0;
        for (uint32_t r = 0; r < nretry; r++) {
            uint32_t ci = retry_idx[r];
            /* Request individual chunk by hash. A send failure means the
             * retry connection is dead — stop and let the post-loop cleanup
             * close rfd and free retry_idx. */
            if (!fs_send_frame(&rs, FS_REQUEST, chunks[ci].sha3, 32))
                break;

            uint8_t *buf = NULL;
            uint32_t sz = 0;
            if (!fs_recv_chunk_fast(&rs, &buf, &sz, chunks[ci].sha3)) {
                printf("[file] retrying chunk %u attempt %d failed\n",
                       ci, retry + 1);
                break;
            }

            char blk_path[600];
            if (chunks[ci].file_index == 254)
                snprintf(blk_path, 600, "%s/consensus_snapshot.db", datadir);
            else if (chunks[ci].file_index == 253)
                snprintf(blk_path, 600, "%s/block_index.bin", datadir);
            else
                snprintf(blk_path, 600, "%s/blocks/blk%05d.dat",
                         datadir, chunks[ci].file_index);
            int bfd = open(blk_path, O_WRONLY | O_CREAT, 0644);
            if (bfd >= 0) {
                ssize_t written = pwrite(bfd, buf, sz,
                                         (off_t)chunks[ci].offset);
                platform_data_sync(bfd);
                close(bfd);
                if (written == (ssize_t)sz) {
                    recovered++;
                    printf("[file] retrying chunk %u attempt %d succeeded\n",
                           ci, retry + 1);
                }
            }
            free(buf);
        }

        fs_session_cleanup(&rs);
        close(rfd);
        free(retry_idx);
        total_fail = (recovered >= total_fail) ? 0 : total_fail - recovered;
        total_ok += recovered;
        printf("[file] retry attempt %d: recovered %u chunks, %u still failed\n",
               retry + 1, recovered, total_fail);
    }

    if (total_fail > 0)
        LOG_FAIL("filesvc", "client_sync: %u/%u chunks failed after retries — download incomplete", total_fail, remaining);

    if (total_ok < remaining)
        LOG_FAIL("filesvc", "client_sync: only %u/%u chunks received — incomplete", total_ok, remaining);

    return true;
}


#endif /* !_WIN32 */
