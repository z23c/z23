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

#define FS_NWORKERS 8
#define FS_RECEIVE_SLOTS (FS_NWORKERS + 2)
struct fs_receive_op {
    pthread_mutex_t mutex;
    _Atomic bool cancelled;
    _Atomic bool used;
    struct file_manifest expected;
    uint32_t min_verified_chunks;
    bool has_expected;
    bool strict;
    int fds[FS_RECEIVE_SLOTS];
};
struct fs_receive_op *fs_receive_create_internal(const struct file_manifest *expected);
bool fs_receive_cancelled(void *context);
bool fs_receive_adopt(struct fs_receive_op *op, size_t slot, int fd);
void fs_receive_close(struct fs_receive_op *op, size_t slot, int fd);
int fs_open_directory(const char *path);
int fs_chunk_open(const char *dir, uint8_t index, int flags);
bool fs_manifest_extents_ok(const struct file_chunk *chunks, uint32_t count, uint64_t lengths[255]);
int fs_manifest_frame(uint8_t type, uint32_t size, uint32_t count, bool strict);
bool fs_probe_validate(const struct file_chunk *chunks, uint32_t count, bool done,
                       uint64_t lengths[255], struct file_manifest *out);
bool fs_manifest_expected(const struct file_chunk *chunks, uint32_t count, uint64_t total,
                          const uint64_t lengths[255], const struct file_manifest *expected);
bool fs_output_durable(const char *dir, const uint64_t lengths[255]);
bool fs_output_inventory(const char *dir, const uint64_t lengths[255]);
bool fs_output_lengths_ok(const char *dir, const uint64_t lengths[255]);
enum fs_chunk_check { FS_CHUNK_VALID, FS_CHUNK_FAILED, FS_CHUNK_STOPPED };
enum fs_chunk_check fs_verify_local_chunk(int fd, const struct file_chunk *chunk,
                                         struct fs_receive_op *op);
enum fs_resume_cause { FS_RESUME_SCANNED, FS_RESUME_FAILED, FS_RESUME_STOPPED };
enum fs_prefix_decision { FS_PREFIX_READY, FS_PREFIX_ERROR, FS_PREFIX_STOPPED };
enum fs_prefix_decision fs_prefix_decide(enum fs_resume_cause cause, uint32_t verified,
    uint32_t minimum, bool cancelled);
uint32_t fs_sync_resume_scan(const char *datadir, const struct file_chunk *chunks,
    uint32_t num_chunks, struct fs_receive_op *op, enum fs_resume_cause *cause);
int fs_connect_with_operation(const struct sockaddr_storage *address, socklen_t length,
    int type, int protocol, int64_t budget, struct fs_receive_op *op);

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

struct fs_session;
struct range_worker;
bool fs_solve_challenge_nonce(struct fs_session *session, struct range_worker *worker,
                              const uint8_t seed[32], int bits, int64_t timestamp,
                              uint64_t *nonce);
bool fs_workers_clean_stop(const struct range_worker *workers, int count, bool stopped);

struct range_worker {
    const char *onion_peer;
    uint16_t onion_port;
    struct sockaddr_storage peer_sockaddr;
    socklen_t peer_sockaddr_len;
    int peer_socktype;
    int peer_protocol;
    uint8_t utxo_root[32];
    struct file_chunk *chunks;
    uint32_t start, end;
    const char *datadir;
    int id;
    struct fs_receive_op *operation;
    size_t operation_slot;
    pthread_mutex_t *fd_mutex;
    int fd;                /* guarded by fd_mutex; worker alone closes it */
    _Atomic bool done;
    _Atomic bool cancel;   /* set by main thread to abort stuck worker */
    _Atomic bool stopped_at_boundary;
    _Atomic uint64_t bytes;
    _Atomic uint32_t chunks_ok;    /* successfully written chunks */
    _Atomic uint32_t chunks_fail;  /* failed recv or write */
};

bool range_worker_socket_publish(struct range_worker *w, int fd);
void range_worker_cancel(struct range_worker *w);
void range_worker_socket_close(struct range_worker *w, int fd);

struct fs_ip_stat {
    uint8_t ip[16];
    bool used;
    uint32_t concurrent;
    int64_t hour_start;
    uint64_t bytes_this_hour;
    int64_t last_seen;
};
extern struct fs_ip_stat g_fs_ip[];
extern pthread_mutex_t g_fs_ip_mutex;
bool fs_client_budget_check(const struct fs_session *session);
void fs_gate_log_throttled(const char *event, int detail);
void fs_stream_range(struct fs_session *session, const struct file_manifest *manifest,
    uint32_t start, uint32_t end, const uint8_t client_ip[16], bool snapshot_allowed);
bool fs_client_recv_checked(struct fs_session *session, uint8_t *type,
    const uint8_t **payload, uint32_t *plen, int64_t deadline_ms);
bool fs_conn_deadline_ms(const struct fs_session *session, int64_t *deadline_ms);
bool fs_client_serve_challenge(struct fs_session *session);
bool fs_client_serve_gated(struct fs_session *session, const struct file_manifest *manifest,
    const uint8_t client_ip[16], bool snapshot_allowed, const uint8_t *puzzle,
    bool is_rng, uint16_t rng_start, uint16_t rng_end);
bool fs_client_serve_manifest(struct fs_session *session, const struct file_manifest *manifest,
    bool snapshot_allowed);

#endif /* !_WIN32 */

#endif
