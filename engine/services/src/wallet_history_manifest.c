/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Build complete manifests for immutable history files. */
#include "services/wallet_history_manifest.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(_WIN32)
enum immutable_result { IMMUTABLE_OK, IMMUTABLE_CANCELLED, IMMUTABLE_ERROR };
struct immutable_cancel { bool (*check)(void *); void *context; };
static bool immutable_cancelled(const struct immutable_cancel *c)
{ return c->check && c->check(c->context); }

static bool immutable_same_file(const struct stat *a, const struct stat *b)
{
    if (a->st_dev != b->st_dev || a->st_ino != b->st_ino || a->st_size != b->st_size ||
        a->st_mode != b->st_mode || a->st_nlink != b->st_nlink) return false;
#if defined(__APPLE__)
    return a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    return a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
}

static enum immutable_result immutable_hash_chunk(FILE *f, struct file_chunk *chunk, uint32_t size,
                                                   const struct immutable_cancel *cancel)
{
    uint8_t buf[65536];
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    uint32_t done = 0;
    while (done < size) {
        if (immutable_cancelled(cancel)) return IMMUTABLE_CANCELLED;
        size_t want = size - done;
        if (want > sizeof(buf)) want = sizeof(buf);
        size_t got = fread(buf, 1, want, f);
        if (got != want) return IMMUTABLE_ERROR;
        sha3_256_write(&hash, buf, got);
        done += (uint32_t)got;
    }
    sha3_256_finalize(&hash, chunk->sha3);
    return IMMUTABLE_OK;
}

static enum immutable_result immutable_hash_file(FILE *f, struct file_manifest *fm, uint8_t index,
                                                   uint64_t size, const struct immutable_cancel *cancel)
{
    if (size > (uint64_t)(FILE_MAX_CHUNKS - fm->num_chunks) * FILE_CHUNK_SIZE) return IMMUTABLE_ERROR;
    for (uint64_t offset = 0; offset < size;) {
        uint64_t remaining = size - offset;
        uint32_t len = remaining < FILE_CHUNK_SIZE ? (uint32_t)remaining : FILE_CHUNK_SIZE;
        struct file_chunk *chunk = &fm->chunks[fm->num_chunks];
        enum immutable_result r = immutable_hash_chunk(f, chunk, len, cancel);
        if (r != IMMUTABLE_OK) return r;
        chunk->offset = offset; chunk->size = len; chunk->file_index = index;
        fm->total_bytes += len; fm->num_chunks++; offset += len;
    }
    return IMMUTABLE_OK;
}

static enum immutable_result immutable_manifest_file(struct file_manifest *fm, const char *path,
                                                       uint8_t index, const struct immutable_cancel *cancel)
{
    struct stat before = {0}, opened = {0}, after = {0};
    if (lstat(path, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0) return IMMUTABLE_ERROR;
    FILE *f = fopen(path, "rb");
    if (!f) return IMMUTABLE_ERROR;
    bool valid = fstat(fileno(f), &opened) == 0 && S_ISREG(opened.st_mode) &&
        immutable_same_file(&before, &opened);
    enum immutable_result r = valid ? immutable_hash_file(f, fm, index, (uint64_t)opened.st_size, cancel) : IMMUTABLE_ERROR;
    if (fstat(fileno(f), &after) != 0 || !valid || !immutable_same_file(&opened, &after)) r = IMMUTABLE_ERROR;
    if (fclose(f) != 0) r = IMMUTABLE_ERROR;
    return r;
}

static bool immutable_inventory_name(const char *name, unsigned count)
{
    if (strncmp(name, "blk", 3) != 0) return true;
    unsigned value; char extra, canonical[16];
    return sscanf(name, "blk%5u.dat%c", &value, &extra) == 1 &&
        snprintf(canonical, sizeof(canonical), "blk%05u.dat", value) == 12 &&
        strcmp(name, canonical) == 0 && value < count;
}

static enum immutable_result immutable_inventory(const char *datadir, unsigned count,
                                                   const struct immutable_cancel *cancel)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/blocks", datadir);
    if (n < 0 || (size_t)n >= sizeof(path)) return IMMUTABLE_ERROR;
    DIR *dir = opendir(path);
    if (!dir) return IMMUTABLE_ERROR;
    enum immutable_result r = IMMUTABLE_OK;
    for (;;) {
        if (immutable_cancelled(cancel)) { r = IMMUTABLE_CANCELLED; break; }
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno != 0) r = IMMUTABLE_ERROR; break; }
        if (!immutable_inventory_name(entry->d_name, count)) {
            LOG_WARN("file", "immutable manifest: unexpected block file %s", entry->d_name);
            r = IMMUTABLE_ERROR;
            break;
        }
    }
    if (closedir(dir) != 0) r = IMMUTABLE_ERROR;
    return r;
}

static enum immutable_result immutable_files(struct file_manifest *result, const char *datadir,
                                              unsigned count, const struct immutable_cancel *cancel)
{
    char path[1024];
    for (unsigned i = 0; i <= count; i++) {
        if (immutable_cancelled(cancel)) return IMMUTABLE_CANCELLED;
        int n = i == count ? snprintf(path, sizeof(path), "%s/block_index.bin", datadir) :
            snprintf(path, sizeof(path), "%s/blocks/blk%05u.dat", datadir, i);
        if (n < 0 || (size_t)n >= sizeof(path)) return IMMUTABLE_ERROR;
        enum immutable_result r = immutable_manifest_file(result, path, i == count ? 253 : (uint8_t)i, cancel);
        if (r != IMMUTABLE_OK) return r;
    }
    return IMMUTABLE_OK;
}
#endif

struct zcl_result wallet_history_manifest_build_cancelable(struct file_manifest *out, const char *datadir,
    unsigned block_files, bool (*cancelled)(void *), void *context)
{
#if !defined(_WIN32)
    if (!out || !datadir || !datadir[0] || !block_files || block_files > 253)
        return ZCL_ERR(-1, "immutable history manifest: invalid input");
    const struct immutable_cancel cancel = {cancelled, context};
    if (immutable_cancelled(&cancel)) return ZCL_ERR(WALLET_HISTORY_MANIFEST_CANCELLED, "immutable history manifest: cancelled");
    struct file_manifest result = {0};
    enum immutable_result r = immutable_inventory(datadir, block_files, &cancel);
    if (r == IMMUTABLE_OK) r = immutable_files(&result, datadir, block_files, &cancel);
    if (r == IMMUTABLE_CANCELLED) return ZCL_ERR(WALLET_HISTORY_MANIFEST_CANCELLED, "immutable history manifest: cancelled");
    if (r != IMMUTABLE_OK) return ZCL_ERR(-1, "immutable history manifest: inventory or hash failed for %s", datadir);
    if (immutable_cancelled(&cancel)) return ZCL_ERR(WALLET_HISTORY_MANIFEST_CANCELLED, "immutable history manifest: cancelled");
    struct sha3_256_ctx root;
    sha3_256_init(&root);
    for (uint32_t i = 0; i < result.num_chunks; i++) sha3_256_write(&root, result.chunks[i].sha3, 32);
    sha3_256_finalize(&root, result.root_hash);
    *out = result;
    return ZCL_OK;
#else
    (void)out; (void)datadir; (void)block_files; (void)cancelled; (void)context;
    return ZCL_ERR(-1, "immutable history manifest unsupported on Windows");
#endif
}

struct zcl_result wallet_history_manifest_build(struct file_manifest *out, const char *datadir,
                                               unsigned block_files)
{ return wallet_history_manifest_build_cancelable(out, datadir, block_files, NULL, NULL); }
