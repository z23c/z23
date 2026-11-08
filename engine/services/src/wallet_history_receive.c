/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Receive, verify and publish immutable history under an exclusive lease. */
#include "services/wallet_history_receive.h"
#include "services/wallet_history_manifest.h"
#include "base/hex.h"
#include "crypto/sha3.h"
#include "net/file_service.h"
#include "platform/disk_space.h"
#include "platform/private_directory.h"
#include "util/safe_alloc.h"
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

enum { RECEIVE_PATH_MAX = 4096, RECEIVE_PEER_MAX = 256 };
struct wallet_history_receiver {
    pthread_mutex_t mutex;
    bool cancelled, used;
#if !defined(_WIN32)
    struct fs_receive_op *active;
#endif
    char peer[RECEIVE_PEER_MAX], parent_path[RECEIVE_PATH_MAX];
    char stage_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    char root_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    char lock_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    uint16_t port;
    uint8_t snapshot[32], history[32];
    uint64_t max_bytes, min_free, reserved;
#ifdef ZCL_TESTING
    void (*before_transfer)(void *);
    void *before_transfer_context;
#endif
};

#ifdef ZCL_TESTING
static void (*receiver_error_hook)(void *);
static void *receiver_error_context;
void wallet_history_receiver_error_hook_for_test(void (*hook)(void *), void *context);
void wallet_history_receiver_error_hook_for_test(void (*hook)(void *), void *context)
{
    receiver_error_hook = hook;
    receiver_error_context = context;
}
void wallet_history_receiver_before_transfer_for_test(struct wallet_history_receiver *r,
    void (*hook)(void *), void *context);
void wallet_history_receiver_before_transfer_for_test(struct wallet_history_receiver *r,
    void (*hook)(void *), void *context)
{
    if (!r) return;
    r->before_transfer = hook;
    r->before_transfer_context = context;
}
#endif

void wallet_history_receive_result_init(struct wallet_history_receive_result *result)
{
    if (!result) return;
    memset(result, 0, sizeof(*result));
    platform_directory_transaction_init(&result->parent);
    platform_directory_transaction_init(&result->root);
    platform_directory_lock_init(&result->lease);
    result->outcome = WALLET_HISTORY_RECEIVE_ERROR;
}

void wallet_history_receive_result_close(struct wallet_history_receive_result *result)
{
    if (!result) return;
    platform_directory_transaction_close(&result->root);
    platform_directory_lock_release(&result->lease);
    platform_directory_transaction_close(&result->parent);
    wallet_history_receive_result_init(result);
}

static void receiver_names(struct wallet_history_receiver *r)
{
    char identity[130];
    zcl_hex_encode(r->snapshot, sizeof(r->snapshot), identity);
    identity[64] = '-';
    zcl_hex_encode(r->history, sizeof(r->history), identity + 65);
    (void)snprintf(r->root_leaf, sizeof(r->root_leaf), "history-%s", identity);
    (void)snprintf(r->stage_leaf, sizeof(r->stage_leaf), ".history-%s-stage", identity);
    (void)snprintf(r->lock_leaf, sizeof(r->lock_leaf), ".history-%s-lock", identity);
}

static bool receiver_request_valid(const struct wallet_history_receive_request *request)
{
    return request && request->peer && request->peer[0] && request->port &&
        request->private_parent && request->private_parent[0] == '/' &&
        strlen(request->peer) < RECEIVE_PEER_MAX && strlen(request->private_parent) < RECEIVE_PATH_MAX &&
        request->max_bytes && request->min_free_bytes &&
        request->min_free_bytes <= UINT64_MAX - request->reserved_install_bytes;
}

struct zcl_result wallet_history_receiver_create(const struct wallet_history_receive_request *request,
                                                  struct wallet_history_receiver **out)
{
    if (!out || *out || !receiver_request_valid(request))
        return ZCL_ERR(-1, "history receive: invalid request");
    struct wallet_history_receiver *r = zcl_calloc(1, sizeof(*r), "history receiver");
    if (!r) return ZCL_ERR(-1, "history receive: allocation failed");
    if (pthread_mutex_init(&r->mutex, NULL) != 0) {
        free(r); return ZCL_ERR(-1, "history receive: mutex initialization failed");
    }
    memcpy(r->peer, request->peer, strlen(request->peer) + 1);
    memcpy(r->parent_path, request->private_parent, strlen(request->private_parent) + 1);
    memcpy(r->snapshot, request->snapshot_digest, 32);
    memcpy(r->history, request->history_root, 32);
    r->port = request->port; r->max_bytes = request->max_bytes;
    r->min_free = request->min_free_bytes; r->reserved = request->reserved_install_bytes;
    receiver_names(r); *out = r;
    return ZCL_OK;
}

void wallet_history_receiver_cancel(struct wallet_history_receiver *r)
{
    if (!r) return;
    pthread_mutex_lock(&r->mutex);
    r->cancelled = true;
#if !defined(_WIN32)
    if (r->active) fs_receive_cancel(r->active);
#endif
    pthread_mutex_unlock(&r->mutex);
}

void wallet_history_receiver_destroy(struct wallet_history_receiver **owner)
{
    if (!owner || !*owner) return;
    struct wallet_history_receiver *r = *owner;
    pthread_mutex_destroy(&r->mutex);
    free(r); *owner = NULL;
}

#if !defined(_WIN32)
struct receiver_work {
    struct platform_directory_transaction parent, stage, blocks;
    struct platform_directory_lock lease;
    struct file_manifest manifest;
    uint64_t lengths[254];
    unsigned block_files;
    uint32_t verified_chunks;
    uint64_t verified_bytes;
    bool stage_stopped, existing;
    char stage_path[RECEIVE_PATH_MAX];
};

static void receiver_work_init(struct receiver_work *w)
{
    memset(w, 0, sizeof(*w));
    platform_directory_transaction_init(&w->parent);
    platform_directory_transaction_init(&w->stage);
    platform_directory_transaction_init(&w->blocks);
    platform_directory_lock_init(&w->lease);
}

static void receiver_work_close(struct receiver_work *w)
{
    platform_directory_transaction_close(&w->blocks);
    platform_directory_transaction_close(&w->stage);
    platform_directory_lock_release(&w->lease);
    platform_directory_transaction_close(&w->parent);
}

static bool receiver_cancelled(struct wallet_history_receiver *r)
{
    pthread_mutex_lock(&r->mutex);
    bool cancelled = r->cancelled;
    pthread_mutex_unlock(&r->mutex);
    return cancelled;
}

static enum fs_receive_result receiver_transfer(struct wallet_history_receiver *r,
    const struct file_manifest *expected, uint32_t minimum, const char *path,
    struct file_manifest *out)
{
    struct fs_receive_op *op = expected ? fs_receive_create_with_prefix(expected, minimum) :
                                          fs_receive_create(NULL);
    if (!op) return FS_RECEIVE_ERROR;
    pthread_mutex_lock(&r->mutex);
    bool cancelled = r->cancelled;
    if (!cancelled) r->active = op;
    pthread_mutex_unlock(&r->mutex);
    static const uint8_t salt[32] = {0};
    enum fs_receive_result result = cancelled ? FS_RECEIVE_STOPPED : expected ?
        fs_receive_run(op, r->peer, r->port, path, salt) :
        fs_receive_probe(op, r->peer, r->port, salt, out);
    pthread_mutex_lock(&r->mutex);
    if (r->active == op) r->active = NULL;
    if (r->cancelled && result == FS_RECEIVE_COMPLETE) result = FS_RECEIVE_STOPPED;
    pthread_mutex_unlock(&r->mutex);
    fs_receive_destroy(op);
    return result;
}

static bool receiver_same_directory(const struct platform_directory_transaction *a,
                                    const struct platform_directory_transaction *b)
{
    struct stat first, second;
    return a->native != UINTPTR_MAX && b->native != UINTPTR_MAX &&
        fstat((int)a->native, &first) == 0 && fstat((int)b->native, &second) == 0 &&
        first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

static bool receiver_parent_bound(const struct wallet_history_receiver *r,
                                  const struct platform_directory_transaction *parent)
{
    uintptr_t native;
    if (!platform_private_directory_open_validated_traverse(r->parent_path, &native)) return false;
    struct platform_directory_transaction check = {.native = native};
    bool ok = receiver_same_directory(parent, &check);
    platform_directory_transaction_close(&check);
    return ok;
}

static bool receiver_stage_bound(struct receiver_work *w, const char *leaf)
{
    struct platform_directory_transaction named;
    platform_directory_transaction_init(&named);
    bool ok = platform_directory_transaction_open_child(&w->parent, leaf, false, &named) ==
        PLATFORM_DIRECTORY_OK && receiver_same_directory(&w->stage, &named);
    platform_directory_transaction_close(&named);
    return ok;
}

static bool receiver_extent(struct receiver_work *w, const struct file_chunk *c, uint64_t *sum)
{
    if (c->file_index > 253 || !c->size || c->size > FILE_CHUNK_SIZE ||
        c->offset != w->lengths[c->file_index] ||
        c->size > UINT64_MAX - c->offset || c->size > UINT64_MAX - *sum) return false;
    w->lengths[c->file_index] += c->size; *sum += c->size;
    if (c->file_index < 253 && c->file_index + 1u > w->block_files)
        w->block_files = c->file_index + 1u;
    return true;
}

static bool receiver_manifest(struct receiver_work *w, const struct wallet_history_receiver *r)
{
    const struct file_manifest *m = &w->manifest;
    if (!m->num_chunks || m->num_chunks > FILE_MAX_CHUNKS || !m->total_bytes ||
        m->total_bytes > r->max_bytes || memcmp(m->root_hash, r->history, 32)) return false;
    uint64_t sum = 0;
    for (uint32_t i = 0; i < m->num_chunks; i++) {
        if (!receiver_extent(w, &m->chunks[i], &sum)) return false;
    }
    if (sum != m->total_bytes || !w->block_files || !w->lengths[253]) return false;
    for (unsigned i = 0; i < w->block_files; i++) if (!w->lengths[i]) return false;
    return true;
}

static bool receiver_private_file(struct platform_directory_transaction *dir, const char *leaf,
                                  uint64_t expected, bool create, bool *complete)
{
    struct platform_directory_child file;
    struct platform_directory_child_info info;
    platform_directory_child_init(&file);
    bool ok = platform_directory_child_open_result(dir, leaf, create, true, &file, NULL) ==
        PLATFORM_DIRECTORY_OK && platform_directory_child_info(&file, &info) &&
        info.current_user_only && info.link_count == 1 && info.size <= expected;
    if (ok && info.size != expected) *complete = false;
    platform_directory_child_close(&file);
    return ok;
}

static bool receiver_files(struct receiver_work *w, bool create, bool *complete)
{
    *complete = true;
    if (platform_directory_transaction_open_child(&w->stage, "blocks", create, &w->blocks) !=
        PLATFORM_DIRECTORY_OK || !receiver_private_file(&w->stage, "block_index.bin", w->lengths[253], create, complete))
        return false;
    for (unsigned i = 0; i < w->block_files; i++) {
        char leaf[24];
        int n = snprintf(leaf, sizeof(leaf), "blk%05u.dat", i);
        if (n <= 0 || (size_t)n >= sizeof(leaf) ||
            !receiver_private_file(&w->blocks, leaf, w->lengths[i], create, complete)) return false;
    }
    return platform_directory_transaction_flush(&w->blocks) &&
           platform_directory_transaction_flush(&w->stage);
}

static bool receiver_manifest_equal(const struct file_manifest *a, const struct file_manifest *b)
{
    if (a->num_chunks != b->num_chunks || a->total_bytes != b->total_bytes ||
        memcmp(a->root_hash, b->root_hash, 32)) return false;
    for (uint32_t i = 0; i < a->num_chunks; i++) {
        const struct file_chunk *x = &a->chunks[i], *y = &b->chunks[i];
        if (x->file_index != y->file_index || x->offset != y->offset || x->size != y->size ||
            memcmp(x->sha3, y->sha3, 32)) return false;
    }
    return true;
}

enum receiver_chunk_result { RECEIVER_CHUNK_MATCH, RECEIVER_CHUNK_DIFFERENT,
                             RECEIVER_CHUNK_STOPPED, RECEIVER_CHUNK_IO };
enum { RECEIVER_SCAN_STOPPED = -3 };

static enum receiver_chunk_result receiver_hash_chunk(struct wallet_history_receiver *r,
    struct platform_directory_child *file, const struct file_chunk *chunk)
{
    uint8_t buffer[65536], digest[32];
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint32_t done = 0;
    while (done < chunk->size) {
        if (receiver_cancelled(r)) return RECEIVER_CHUNK_STOPPED;
        size_t wanted = chunk->size - done;
        if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
        int64_t got = platform_directory_child_read(file, buffer, wanted, chunk->offset + done);
        if (got <= 0 || (uint64_t)got > wanted) return RECEIVER_CHUNK_IO;
        sha3_256_write(&hash, buffer, (size_t)got);
        done += (uint32_t)got;
    }
    sha3_256_finalize(&hash, digest);
    return memcmp(digest, chunk->sha3, sizeof(digest)) == 0 ?
        RECEIVER_CHUNK_MATCH : RECEIVER_CHUNK_DIFFERENT;
}

static enum receiver_chunk_result receiver_check_chunk(struct wallet_history_receiver *r,
    struct receiver_work *w, const struct file_chunk *chunk)
{
    struct platform_directory_transaction *directory =
        chunk->file_index == 253 ? &w->stage : &w->blocks;
    char name[24];
    if (chunk->file_index == 253) {
        memcpy(name, "block_index.bin", sizeof("block_index.bin"));
    } else {
        int n = snprintf(name, sizeof(name), "blk%05u.dat", (unsigned)chunk->file_index);
        if (n <= 0 || (size_t)n >= sizeof(name)) return RECEIVER_CHUNK_IO;
    }
    struct platform_directory_child file;
    struct platform_directory_child_info info;
    platform_directory_child_init(&file);
    if (!platform_directory_child_open(directory, name, &file)) return RECEIVER_CHUNK_IO;
    enum receiver_chunk_result result = RECEIVER_CHUNK_IO;
    if (platform_directory_child_info(&file, &info)) {
        result = info.size < chunk->offset + chunk->size ? RECEIVER_CHUNK_DIFFERENT :
                 receiver_hash_chunk(r, &file, chunk);
    }
    platform_directory_child_close(&file);
    return result;
}

static struct zcl_result receiver_verified_prefix(struct wallet_history_receiver *r,
                                                   struct receiver_work *w)
{
    for (uint32_t i = 0; i < w->manifest.num_chunks; i++) {
        const struct file_chunk *chunk = &w->manifest.chunks[i];
        enum receiver_chunk_result checked = receiver_check_chunk(r, w, chunk);
        if (checked == RECEIVER_CHUNK_STOPPED)
            return ZCL_ERR(RECEIVER_SCAN_STOPPED, "history receive: prefix scan stopped");
        if (checked == RECEIVER_CHUNK_IO)
            return ZCL_ERR(-1, "history receive: prefix scan I/O failed");
        if (checked == RECEIVER_CHUNK_DIFFERENT) break;
        if (chunk->size > w->manifest.total_bytes - w->verified_bytes)
            return ZCL_ERR(-1, "history receive: verified prefix exceeds total");
        w->verified_bytes += chunk->size;
        w->verified_chunks++;
    }
    return ZCL_OK;
}

#ifdef ZCL_TESTING
struct zcl_result wallet_history_receiver_prefix_for_test(struct wallet_history_receiver *r,
    const char *path, const struct file_manifest *manifest, uint32_t *chunks, uint64_t *bytes);
struct zcl_result wallet_history_receiver_prefix_for_test(struct wallet_history_receiver *r,
    const char *path, const struct file_manifest *manifest, uint32_t *chunks, uint64_t *bytes)
{
    if (!r || !path || !manifest || !chunks || !bytes)
        return ZCL_ERR(-1, "history receive: invalid prefix fixture");
    struct receiver_work *w = zcl_calloc(1, sizeof(*w), "history receive work");
    if (!w) return ZCL_ERR(-1, "history receive: prefix fixture allocation failed");
    receiver_work_init(w); w->manifest = *manifest;
    bool complete = false;
    struct zcl_result result = receiver_manifest(w, r) &&
        platform_directory_transaction_open(&w->stage, path) && receiver_files(w, true, &complete) ?
        receiver_verified_prefix(r, w) : ZCL_ERR(-1, "history receive: prefix fixture setup failed");
    if (result.ok) { *chunks = w->verified_chunks; *bytes = w->verified_bytes; }
    receiver_work_close(w); free(w);
    return result;
}
#endif

static bool receiver_manifest_cancelled(void *context)
{
    return receiver_cancelled(context);
}

static struct zcl_result receiver_complete_stage(struct wallet_history_receiver *r,
    struct receiver_work *w, bool sizes_complete, bool *complete)
{
    *complete = false;
    if (!sizes_complete) return ZCL_OK;
    struct file_manifest rebuilt;
    struct zcl_result result = wallet_history_manifest_build_cancelable(
        &rebuilt, w->stage_path, w->block_files, receiver_manifest_cancelled, r);
    if (!result.ok) return result;
    *complete = receiver_manifest_equal(&w->manifest, &rebuilt);
    return ZCL_OK;
}

static bool receiver_inventory_name(const char *name, bool blocks, unsigned count)
{
    if (!strcmp(name, ".") || !strcmp(name, "..")) return true;
    if (!blocks) return !strcmp(name, "blocks") || !strcmp(name, "block_index.bin");
    unsigned index;
    char extra, canonical[16];
    return sscanf(name, "blk%5u.dat%c", &index, &extra) == 1 && index < count &&
        snprintf(canonical, sizeof(canonical), "blk%05u.dat", index) == 12 &&
        !strcmp(name, canonical);
}

static bool receiver_inventory_directory(struct platform_directory_transaction *directory,
                                         bool blocks, unsigned count)
{
    int fd = openat((int)directory->native, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return false; }
    bool ok = true;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!receiver_inventory_name(entry->d_name, blocks, count)) { ok = false; break; }
        errno = 0;
    }
    if (errno != 0) ok = false;
    if (closedir(dir) != 0) ok = false;
    return ok;
}

static bool receiver_flush_file(struct platform_directory_transaction *directory, const char *leaf)
{
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    bool ok = platform_directory_child_open(directory, leaf, &file) &&
              platform_directory_child_flush(&file);
    platform_directory_child_close(&file);
    return ok;
}

static bool receiver_flush_complete(struct receiver_work *w)
{
    if (!receiver_flush_file(&w->stage, "block_index.bin")) return false;
    for (unsigned i = 0; i < w->block_files; i++) {
        char name[24];
        int n = snprintf(name, sizeof(name), "blk%05u.dat", i);
        if (n <= 0 || (size_t)n >= sizeof(name) || !receiver_flush_file(&w->blocks, name)) return false;
    }
    return platform_directory_transaction_flush(&w->blocks) &&
           platform_directory_transaction_flush(&w->stage) &&
           platform_directory_transaction_flush(&w->parent);
}

static bool receiver_required_space(uint64_t min_free, uint64_t reserved, uint64_t total,
                                    uint64_t verified, uint64_t *required)
{
    if (!required || verified > total || min_free > UINT64_MAX - reserved) return false;
    uint64_t floor = min_free + reserved, extra = total - verified;
    if (extra > UINT64_MAX - floor) return false;
    *required = floor + extra;
    return true;
}

#ifdef ZCL_TESTING
struct zcl_result wallet_history_receiver_required_for_test(uint64_t min_free, uint64_t reserved,
    uint64_t total, uint64_t verified, uint64_t *required);
struct zcl_result wallet_history_receiver_required_for_test(uint64_t min_free, uint64_t reserved,
    uint64_t total, uint64_t verified, uint64_t *required)
{
    if (!receiver_required_space(min_free, reserved, total, verified, required))
        return ZCL_ERR(-1, "history receive: capacity sum overflow");
    return ZCL_OK;
}
#endif

static struct zcl_result receiver_capacity(struct wallet_history_receiver *r,
                                            struct receiver_work *w)
{
    uint64_t required, available = 0;
    if (!receiver_required_space(r->min_free, r->reserved, w->manifest.total_bytes,
                                 w->verified_bytes, &required))
        return ZCL_ERR(-1, "history receive: capacity sum overflow");
    if (!platform_disk_space_available(r->parent_path, &available))
        return ZCL_ERR(-1, "history receive: available space unavailable");
    if (available < required)
        return ZCL_ERR(-1, "history receive: need %" PRIu64 " bytes, available %" PRIu64,
                       required, available);
    return ZCL_OK;
}

static struct zcl_result receiver_open(struct wallet_history_receiver *r, struct receiver_work *w)
{
    if (!platform_directory_transaction_open(&w->parent, r->parent_path) ||
        !receiver_parent_bound(r, &w->parent) ||
        platform_directory_lock_acquire(&w->parent, r->lock_leaf, true,
            PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &w->lease) != PLATFORM_DIRECTORY_OK)
        return ZCL_ERR(-1, "history receive: parent or exclusive lease refused");
    return ZCL_OK;
}

static bool receiver_existing_verified(struct receiver_work *w, bool complete)
{
    return complete && receiver_inventory_directory(&w->stage, false, w->block_files) &&
        receiver_inventory_directory(&w->blocks, true, w->block_files) && receiver_flush_complete(w);
}

static struct zcl_result receiver_check_stage(struct wallet_history_receiver *r,
                                               struct receiver_work *w, bool *complete)
{
    bool sizes_complete = false;
    if (!receiver_files(w, !w->existing, &sizes_complete))
        return ZCL_ERR(-1, "history receive: private stage files refused");
    struct zcl_result checked = receiver_complete_stage(r, w, sizes_complete, complete);
    if (!checked.ok) {
        if (checked.code == WALLET_HISTORY_MANIFEST_CANCELLED) w->stage_stopped = true;
        return checked;
    }
    if (w->existing && !receiver_existing_verified(w, *complete))
        return ZCL_ERR(-1, "history receive: existing destination verification failed");
    if (*complete) {
        w->verified_chunks = w->manifest.num_chunks;
        w->verified_bytes = w->manifest.total_bytes;
    } else {
        checked = receiver_verified_prefix(r, w);
        if (!checked.ok) {
            if (checked.code == RECEIVER_SCAN_STOPPED) w->stage_stopped = true;
            return checked;
        }
    }
    if (receiver_cancelled(r)) {
        w->stage_stopped = true;
        return ZCL_ERR(-1, "history receive: stopped during stage check");
    }
    return ZCL_OK;
}

static struct zcl_result receiver_stage(struct wallet_history_receiver *r, struct receiver_work *w)
{
    enum platform_directory_result found = platform_directory_transaction_open_child(
        &w->parent, r->root_leaf, false, &w->stage);
    if (found != PLATFORM_DIRECTORY_MISSING && found != PLATFORM_DIRECTORY_OK)
        return ZCL_ERR(-1, "history receive: destination unavailable");
    w->existing = found == PLATFORM_DIRECTORY_OK;
    const char *leaf = w->existing ? r->root_leaf : r->stage_leaf;
    int n = snprintf(w->stage_path, sizeof(w->stage_path), "%s/%s", r->parent_path, leaf);
    if (n <= 0 || (size_t)n >= sizeof(w->stage_path) ||
        (!w->existing && platform_directory_transaction_open_child(
            &w->parent, leaf, true, &w->stage) != PLATFORM_DIRECTORY_OK) ||
        !receiver_stage_bound(w, leaf) || !platform_directory_transaction_flush(&w->parent))
        return ZCL_ERR(-1, "history receive: private stage unavailable");
    bool complete = false;
    struct zcl_result checked = receiver_check_stage(r, w, &complete);
    if (!checked.ok) return checked;
    return receiver_capacity(r, w);
}

static struct zcl_result receiver_publish(struct wallet_history_receiver *r, struct receiver_work *w,
                                          struct wallet_history_receive_result *out)
{
    pthread_mutex_lock(&r->mutex);
    if (r->cancelled) {
        out->outcome = WALLET_HISTORY_RECEIVE_STOPPED;
        pthread_mutex_unlock(&r->mutex);
        return ZCL_ERR(-1, "history receive: stopped before publication");
    }
    enum platform_directory_result moved = PLATFORM_DIRECTORY_OK;
    if (w->existing) {
        if (!receiver_parent_bound(r, &w->parent) || !receiver_stage_bound(w, r->root_leaf)) {
            pthread_mutex_unlock(&r->mutex);
            return ZCL_ERR(-1, "history receive: recovered destination identity changed");
        }
    } else {
        moved = platform_directory_transaction_move_directory(
            &w->parent, r->stage_leaf, &w->stage, &w->parent, r->root_leaf);
    }
    if (moved == PLATFORM_DIRECTORY_OUTCOME_UNKNOWN ||
        (moved == PLATFORM_DIRECTORY_OK && !receiver_parent_bound(r, &w->parent))) {
        out->outcome = WALLET_HISTORY_RECEIVE_UNKNOWN;
        pthread_mutex_unlock(&r->mutex);
        return ZCL_ERR(-1, "history receive: publication outcome unknown");
    }
    if (moved != PLATFORM_DIRECTORY_OK) {
        pthread_mutex_unlock(&r->mutex);
        return ZCL_ERR(-1, "history receive: publication refused");
    }
    out->parent = w->parent; platform_directory_transaction_init(&w->parent);
    out->root = w->stage; platform_directory_transaction_init(&w->stage);
    out->lease = w->lease; platform_directory_lock_init(&w->lease);
    memcpy(out->root_leaf, r->root_leaf, strlen(r->root_leaf) + 1);
    memcpy(out->lock_leaf, r->lock_leaf, strlen(r->lock_leaf) + 1);
    memcpy(out->snapshot_digest, r->snapshot, 32); memcpy(out->history_root, r->history, 32);
    out->manifest = w->manifest; out->block_files = w->block_files;
    out->outcome = WALLET_HISTORY_RECEIVE_COMPLETE;
    pthread_mutex_unlock(&r->mutex);
    return ZCL_OK;
}

static struct zcl_result receiver_probe_and_stage(struct wallet_history_receiver *r,
                                                  struct receiver_work *w,
                                                  enum fs_receive_result *received)
{
    struct zcl_result result = receiver_open(r, w);
    if (result.ok) *received = receiver_transfer(r, NULL, 0, NULL, &w->manifest);
    if (result.ok && *received != FS_RECEIVE_COMPLETE)
        result = ZCL_ERR(-1, "history receive: manifest probe stopped or failed");
    if (result.ok && !receiver_manifest(w, r))
        result = ZCL_ERR(-1, "history receive: advertised manifest refused");
    if (result.ok) result = receiver_stage(r, w);
    const char *leaf = w->existing ? r->root_leaf : r->stage_leaf;
    if (result.ok && (!receiver_parent_bound(r, &w->parent) || !receiver_stage_bound(w, leaf)))
        result = ZCL_ERR(-1, "history receive: stage identity changed");
    return result;
}

static struct zcl_result receiver_run(struct wallet_history_receiver *r,
                                      struct wallet_history_receive_result *out)
{
    struct receiver_work *w = zcl_calloc(1, sizeof(*w), "history receive work");
    if (!w) return ZCL_ERR(-1, "history receive: work allocation failed");
    receiver_work_init(w);
    enum fs_receive_result received = FS_RECEIVE_ERROR;
    struct zcl_result result = receiver_probe_and_stage(r, w, &received);
    if (result.ok && !w->existing) {
#ifdef ZCL_TESTING
        if (r->before_transfer) r->before_transfer(r->before_transfer_context);
#endif
        received = receiver_transfer(r, &w->manifest, w->verified_chunks, w->stage_path, NULL);
    }
    if (result.ok && received != FS_RECEIVE_COMPLETE)
        result = ZCL_ERR(-1, "history receive: transfer stopped or failed");
    const char *leaf = w->existing ? r->root_leaf : r->stage_leaf;
    if (result.ok && (!receiver_parent_bound(r, &w->parent) || !receiver_stage_bound(w, leaf)))
        result = ZCL_ERR(-1, "history receive: completed stage identity changed");
    if (result.ok) {
        result = receiver_publish(r, w, out);
    } else {
#ifdef ZCL_TESTING
        if (receiver_error_hook) receiver_error_hook(receiver_error_context);
#endif
        if (received == FS_RECEIVE_STOPPED || w->stage_stopped)
            out->outcome = WALLET_HISTORY_RECEIVE_STOPPED;
    }
    receiver_work_close(w); free(w);
    return result;
}
#endif

struct zcl_result wallet_history_receiver_run(struct wallet_history_receiver *r,
                                               struct wallet_history_receive_result *out)
{
    if (!r || !out || out->parent.native != UINTPTR_MAX || out->root.native != UINTPTR_MAX ||
        out->lease.native != UINTPTR_MAX || out->outcome != WALLET_HISTORY_RECEIVE_ERROR)
        return ZCL_ERR(-1, "history receive: receiver or result invalid");
    pthread_mutex_lock(&r->mutex);
    bool used = r->used, cancelled = r->cancelled;
    r->used = true;
    pthread_mutex_unlock(&r->mutex);
    if (cancelled) {
        out->outcome = WALLET_HISTORY_RECEIVE_STOPPED;
        return ZCL_ERR(-1, "history receive: stopped");
    }
    if (used) return ZCL_ERR(-1, "history receive: receiver already used");
#if !defined(_WIN32)
    return receiver_run(r, out);
#else
    return ZCL_ERR(-1, "history receive: platform unsupported");
#endif
}
