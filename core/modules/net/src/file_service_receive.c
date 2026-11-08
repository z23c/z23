/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Per-operation ownership and verified history receiver helpers. */
// supervisor-ok:caller-joined-receive-operations — each operation is bounded by its caller, canceled before destruction, and has no resident service loop.
#if !defined(_WIN32)
#define _GNU_SOURCE
#include "file_service_priv.h"
#include "net/file_service.h"
#include "net/netbase.h"
#include "crypto/sha3.h"
#include "platform/time_compat.h"
#include "util/safe_alloc.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef ZCL_TESTING
bool fs_test_boundary_aggregation(void);
bool fs_test_receive_challenge_difficulty(int bits);
void fs_test_set_fail_fsync(bool fail);
bool fs_test_manifest_frame_compat(void);
bool fs_test_expected_manifest(const struct file_chunk *, uint32_t, uint64_t,
                               const struct file_manifest *);
bool fs_test_inventory_complete(const char *dir, const uint64_t lengths[255]);
bool fs_test_receive_cancel_fd(void);
#endif

struct fs_receive_op *fs_receive_create_internal(const struct file_manifest *expected)
{
    if (expected && (!expected->num_chunks || expected->num_chunks > FILE_MAX_CHUNKS)) return NULL;
    struct fs_receive_op *op = zcl_calloc(1, sizeof(*op), "file receive operation");
    if (!op) return NULL;
    if (pthread_mutex_init(&op->mutex, NULL) != 0) { free(op); return NULL; }
    if (expected) { op->expected = *expected; op->has_expected = true; op->strict = true; }
    for (size_t i = 0; i < FS_RECEIVE_SLOTS; ++i) op->fds[i] = -1;
    return op;
}

struct fs_receive_op *fs_receive_create(const struct file_manifest *expected)
{
    struct fs_receive_op *op = fs_receive_create_internal(expected);
    if (op) op->strict = true;
    return op;
}

struct fs_receive_op *fs_receive_create_with_prefix(const struct file_manifest *expected,
                                                     uint32_t min_verified_chunks)
{
    if (!expected || !expected->num_chunks || expected->num_chunks > FILE_MAX_CHUNKS ||
        min_verified_chunks > expected->num_chunks) return NULL;
    struct fs_receive_op *op = fs_receive_create(expected);
    if (op) op->min_verified_chunks = min_verified_chunks;
    return op;
}

void fs_receive_cancel(struct fs_receive_op *op)
{
    if (!op) return;
    pthread_mutex_lock(&op->mutex);
    atomic_store_explicit(&op->cancelled, true, memory_order_release);
    for (size_t i = 0; i < FS_RECEIVE_SLOTS; ++i)
        if (op->fds[i] >= 0) (void)shutdown(op->fds[i], SHUT_RDWR);
    pthread_mutex_unlock(&op->mutex);
}

void fs_receive_destroy(struct fs_receive_op *op)
{
    if (!op) return;
    pthread_mutex_destroy(&op->mutex);
    free(op);
}

bool fs_receive_cancelled(void *context)
{
    struct fs_receive_op *op = context;
    return op && atomic_load_explicit(&op->cancelled, memory_order_acquire);
}

bool fs_receive_adopt(struct fs_receive_op *op, size_t slot, int fd)
{
    if (!op) return true;
    pthread_mutex_lock(&op->mutex);
    bool ok = slot < FS_RECEIVE_SLOTS && op->fds[slot] < 0 &&
        !atomic_load_explicit(&op->cancelled, memory_order_acquire);
    if (ok) op->fds[slot] = fd;
    pthread_mutex_unlock(&op->mutex);
    return ok;
}

void fs_receive_close(struct fs_receive_op *op, size_t slot, int fd)
{
    if (fd < 0) return;
    if (!op) { close(fd); return; }
    pthread_mutex_lock(&op->mutex);
    if (slot < FS_RECEIVE_SLOTS && op->fds[slot] == fd) op->fds[slot] = -1;
    close(fd);
    pthread_mutex_unlock(&op->mutex);
}

static int64_t fs_op_now(void *context)
{
    (void)context;
    return platform_time_monotonic_ms();
}
static int fs_op_connect(void *context, int fd, const struct sockaddr *addr, socklen_t len)
{
    if (fs_receive_cancelled(context)) { errno = ECANCELED; return -1; }
    return netbase_connect_guarded(fd, addr, len);
}
static int fs_op_poll(void *context, struct pollfd *pfd, int timeout_ms)
{
    if (fs_receive_cancelled(context)) { errno = ECANCELED; return -1; }
    return poll(pfd, 1, timeout_ms < 100 ? timeout_ms : 100);
}
static bool fs_op_connected(void *context, int fd)
{
    return !fs_receive_cancelled(context) && connect_socket_check(fd);
}
int fs_connect_with_operation(const struct sockaddr_storage *address,
    socklen_t length, int type, int protocol, int64_t budget, struct fs_receive_op *op)
{
    if (!op || !op->strict)
        return fs_connect_resolved_until(address, length, type, protocol, budget, NULL);
    struct fs_connect_ops ops = {.now_ms = fs_op_now, .connect_fd = fs_op_connect,
        .poll_fd = fs_op_poll, .check_fd = fs_op_connected, .opaque = op};
    return fs_connect_resolved_until(address, length, type, protocol, budget, &ops);
}

bool fs_workers_clean_stop(const struct range_worker *workers, int count, bool stopped)
{
    if (!stopped) return false;
    for (int i = 0; i < count; ++i)
        if (atomic_load(&workers[i].chunks_fail) &&
            !atomic_load(&workers[i].stopped_at_boundary)) return false;
    return true;
}

#ifdef ZCL_TESTING
bool fs_test_boundary_aggregation(void)
{
    struct range_worker workers[2] = {0};
    atomic_store(&workers[0].chunks_fail, 2);
    atomic_store(&workers[0].stopped_at_boundary, true);
    bool ok = fs_workers_clean_stop(workers, 2, true) &&
        !fs_workers_clean_stop(workers, 2, false);
    atomic_store(&workers[1].chunks_fail, 1);
    ok = ok && !fs_workers_clean_stop(workers, 2, true);
    return ok;
}
#endif

static bool fs_receive_challenge_difficulty(int bits)
{
    return bits >= PUZZLE_MIN_BITS && bits <= PUZZLE_MAX_BITS;
}
#ifdef ZCL_TESTING
bool fs_test_receive_challenge_difficulty(int bits)
{
    return fs_receive_challenge_difficulty(bits);
}
#endif

bool fs_solve_challenge_nonce(struct fs_session *s, struct range_worker *worker,
                                     const uint8_t seed[32], int bits, int64_t ts,
                                     uint64_t *nonce)
{
    if (!worker->operation || !worker->operation->has_expected)
        return puzzle_solve(seed, s->our_nonce, ts, bits, nonce);
    if (!fs_receive_challenge_difficulty(bits)) return false;
    for (;;) {
        if ((*nonce & 255u) == 0 &&
            (fs_receive_cancelled(worker->operation) || atomic_load(&worker->cancel))) return false;
        if (puzzle_verify(seed, s->our_nonce, ts, *nonce, bits)) return true;
        if (*nonce == UINT64_MAX) return false;
        ++*nonce;
    }
}

static bool fs_inventory_name(const char *name, const uint64_t lengths[255])
{
    if (!strcmp(name, ".") || !strcmp(name, "..")) return true;
    unsigned index;
    char extra, canonical[16];
    if (sscanf(name, "blk%5u.dat%c", &index, &extra) != 1 || index >= 253 || !lengths[index])
        return false;
    return snprintf(canonical, sizeof(canonical), "blk%05u.dat", index) == 12 &&
        !strcmp(name, canonical);
}

static bool fs_inventory_entries(int fd, bool blocks, const uint64_t lengths[255])
{
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return false; }
    bool ok = true;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if (blocks ? !fs_inventory_name(name, lengths) :
            strcmp(name, ".") && strcmp(name, "..") && strcmp(name, "blocks") &&
            strcmp(name, "block_index.bin")) { ok = false; break; }
        errno = 0;
    }
    if (errno != 0) ok = false;
    if (closedir(dir) != 0) ok = false;
    return ok;
}

bool fs_output_inventory(const char *path, const uint64_t lengths[255])
{
    int root = fs_open_directory(path);
    if (root < 0) return false;
    int blocks = openat(root, "blocks", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (blocks < 0) { close(root); return false; }
    bool ok = fs_inventory_entries(blocks, true, lengths);
    return fs_inventory_entries(root, false, lengths) && ok;
}

#ifdef ZCL_TESTING
static _Atomic bool fs_test_fail_fsync;
void fs_test_set_fail_fsync(bool fail) { atomic_store(&fs_test_fail_fsync, fail); }
#endif

static int fs_sync_fd(int fd)
{
#ifdef ZCL_TESTING
    if (atomic_load(&fs_test_fail_fsync)) { errno = EIO; return -1; }
#endif
    return fsync(fd);
}

bool fs_output_lengths_ok(const char *dir, const uint64_t lengths[255])
{
    for (unsigned i = 0; i < 255; i++) {
        if (!lengths[i]) continue;
        int fd = fs_chunk_open(dir, (uint8_t)i, O_RDONLY);
        if (fd < 0) return false;
        struct stat st;
        bool ok = fstat(fd, &st) == 0 && st.st_size >= 0 &&
                  (uint64_t)st.st_size == lengths[i];
        if (close(fd) != 0 || !ok) return false;
    }
    return true;
}

/* Complete is not reported until files and their directory entries are durable. */
bool fs_output_durable(const char *dir, const uint64_t lengths[255])
{
    for (unsigned i = 0; i < 255; ++i) {
        if (!lengths[i]) continue;
        int fd = fs_chunk_open(dir, (uint8_t)i, O_RDONLY);
        if (fd < 0) return false;
        bool ok = fs_sync_fd(fd) == 0;
        if (close(fd) != 0) ok = false;
        if (!ok) return false;
    }
    int root = fs_open_directory(dir);
    if (root < 0) return false;
    int blocks = openat(root, "blocks", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool ok = blocks >= 0 && fs_sync_fd(blocks) == 0;
    if (blocks >= 0 && close(blocks) != 0) ok = false;
    if (fs_sync_fd(root) != 0) ok = false;
    if (close(root) != 0) ok = false;
    return ok;
}

enum fs_chunk_check fs_verify_local_chunk(int fd, const struct file_chunk *chunk,
                                         struct fs_receive_op *op)
{
    uint8_t bytes[65536], digest[32];
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint32_t done = 0;
    while (done < chunk->size) {
        if (fs_receive_cancelled(op)) return FS_CHUNK_STOPPED;
        size_t want = chunk->size - done;
        if (want > sizeof(bytes)) want = sizeof(bytes);
        ssize_t n = pread(fd, bytes, want, (off_t)(chunk->offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return FS_CHUNK_FAILED;
        sha3_256_write(&hash, bytes, (size_t)n);
        done += (uint32_t)n;
    }
    sha3_256_finalize(&hash, digest);
    return memcmp(digest, chunk->sha3, sizeof(digest)) == 0 ? FS_CHUNK_VALID : FS_CHUNK_FAILED;
}

/* Classify a frame before indexing the bounded manifest array. */
int fs_manifest_frame(uint8_t type, uint32_t size, uint32_t count, bool strict)
{
    if (type == FS_DONE) return size == 0 ? 0 : -1;
    if (type != FS_MANIFEST || size < 45 || (strict && size != 45) || count >= FILE_MAX_CHUNKS) return -1;
    return 1;
}
#ifdef ZCL_TESTING
bool fs_test_manifest_frame_compat(void)
{
    return fs_manifest_frame(FS_MANIFEST, 46, 0, false) == 1 &&
        fs_manifest_frame(FS_MANIFEST, 46, 0, true) == -1;
}
bool fs_test_manifest_sequence(uint32_t entries, bool done);
bool fs_test_manifest_sequence(uint32_t entries, bool done)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < entries; i++) {
        if (fs_manifest_frame(FS_MANIFEST, 45, count, true) != 1) return false;
        count++;
    }
    return done && fs_manifest_frame(FS_DONE, 0, count, true) == 0;
}
#endif

bool fs_probe_validate(const struct file_chunk *chunks, uint32_t count, bool done,
                       uint64_t lengths[255], struct file_manifest *out)
{
    if (!done || !count || !fs_manifest_extents_ok(chunks, count, lengths)) return false;
    uint64_t total = 0;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    for (uint32_t i = 0; i < count; ++i) {
        total += chunks[i].size;
        sha3_256_write(&hash, chunks[i].sha3, 32);
    }
    if (total > (uint64_t)FILE_MAX_CHUNKS * FILE_CHUNK_SIZE) return false;
    out->num_chunks = count;
    out->total_bytes = total;
    out->chain_height = -1;
    memcpy(out->chunks, chunks, count * sizeof(chunks[0]));
    sha3_256_finalize(&hash, out->root_hash);
    return fs_manifest_expected(chunks, count, total, lengths, out);
}

static bool fs_history_layout(const uint64_t lengths[255])
{
    if (!lengths[0] || !lengths[253] || lengths[254]) return false;
    bool missing = false;
    for (unsigned i = 0; i < 253; ++i) {
        if (!lengths[i]) missing = true;
        else if (missing) return false;
    }
    return true;
}

/* Compare the complete ordered wire manifest before creating output files. */
bool fs_manifest_expected(const struct file_chunk *chunks, uint32_t count, uint64_t total,
                          const uint64_t lengths[255], const struct file_manifest *expected)
{
    if (!expected) return true;
    if (!expected->num_chunks || expected->num_chunks != count ||
        expected->total_bytes != total || !fs_history_layout(lengths)) return false;
    struct sha3_256_ctx hash;
    uint8_t root[32];
    sha3_256_init(&hash);
    for (uint32_t i = 0; i < count; ++i) {
        const struct file_chunk *a = &chunks[i];
        const struct file_chunk *b = &expected->chunks[i];
        if (a->file_index != b->file_index || a->offset != b->offset ||
            a->size != b->size || memcmp(a->sha3, b->sha3, 32)) return false;
        sha3_256_write(&hash, a->sha3, 32);
    }
    sha3_256_finalize(&hash, root);
    return memcmp(root, expected->root_hash, 32) == 0;
}

#ifdef ZCL_TESTING
bool fs_test_expected_manifest(const struct file_chunk *chunks, uint32_t count,
                               uint64_t total, const struct file_manifest *expected)
{
    if (count > FILE_MAX_CHUNKS || (!chunks && count)) return false;
    uint64_t lengths[255];
    return fs_manifest_extents_ok(chunks, count, lengths) &&
        fs_manifest_expected(chunks, count, total, lengths, expected);
}
#endif

#ifdef ZCL_TESTING
bool fs_test_inventory_complete(const char *dir, const uint64_t lengths[255])
{
    return fs_output_lengths_ok(dir, lengths) && fs_output_inventory(dir, lengths);
}


bool fs_test_receive_cancel_fd(void)
{
    struct file_manifest expected = {.num_chunks = 1};
    expected.chunks[0].size = 7;
    struct fs_receive_op *op = fs_receive_create(&expected);
    if (!op) return false;
    expected.chunks[0].size = 8;
    bool pinned = op->expected.chunks[0].size == 7;
    int fds[2] = {-1, -1};
    bool ok = pinned && socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0;
    if (ok) ok = fs_receive_adopt(op, 0, fds[0]);
    if (ok) {
        fs_receive_cancel(op);
        char byte;
        ok = recv(fds[1], &byte, 1, MSG_DONTWAIT) == 0 &&
            !fs_receive_adopt(op, 1, fds[1]);
    }
    if (fds[0] >= 0) fs_receive_close(op, 0, fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    fs_receive_destroy(op);
    return ok;
}
#endif


#else
typedef int file_service_receive_nonempty_translation_unit;
#endif
