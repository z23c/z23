/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private cross-file declarations shared by file_service.c's client half
 * (file_service_client.c) and its ZCL_TESTING self-tests
 * (file_service_selftest.c). Not part of the public API. */

#ifndef ZCL_FILE_SERVICE_PRIV_H
#define ZCL_FILE_SERVICE_PRIV_H

#if !defined(_WIN32)

#include "net/file_manifest.h"

#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

struct fs_connect_ops {
    int64_t (*now_ms)(void *opaque);
    int (*connect_fd)(void *opaque, int fd, const struct sockaddr *addr,
                      socklen_t addr_len);
    int (*poll_fd)(void *opaque, struct pollfd *pfd, int timeout_ms);
    bool (*check_fd)(void *opaque, int fd);
    void *opaque;
};

int fs_connect_resolved_until(const struct sockaddr_storage *address,
                              socklen_t address_len,
                              int socktype, int protocol,
                              int64_t budget_ms,
                              const struct fs_connect_ops *ops);

struct range_worker {
    struct sockaddr_storage peer_sockaddr;
    socklen_t peer_sockaddr_len;
    int peer_socktype;
    int peer_protocol;
    uint8_t utxo_root[32];
    struct file_chunk *chunks;
    uint32_t start, end;
    const char *datadir;
    int id;
    pthread_mutex_t *fd_mutex;
    int fd;                /* guarded by fd_mutex; worker alone closes it */
    _Atomic bool done;
    _Atomic bool cancel;   /* set by main thread to abort stuck worker */
    _Atomic uint64_t bytes;
    _Atomic uint32_t chunks_ok;    /* successfully written chunks */
    _Atomic uint32_t chunks_fail;  /* failed recv or write */
};

bool range_worker_socket_publish(struct range_worker *w, int fd);
void range_worker_cancel(struct range_worker *w);
void range_worker_socket_close(struct range_worker *w, int fd);

#endif /* !_WIN32 */

#endif
