/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/wallet_history_export.h"
#include "services/wallet_history_manifest.h"
#include "services/block_index_loader.h"
#include "node_db_catchup_internal.h"
#include "platform/directory_transaction.h"
#include "platform/disk_space.h"
#include "platform/fd_path.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "primitives/block.h"
#include "core/uint256.h"
#include "base/serialize_le.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#if defined(__linux__)
enum { HISTORY_FILE_LIMIT = 253, HISTORY_COPY_BUFFER = 65536 };
struct history_export {
    const struct wallet_history_export_request *request;
    struct platform_directory_transaction parent, stage, blocks;
    struct platform_positioned_file files[HISTORY_FILE_LIMIT];
    uint64_t extent[HISTORY_FILE_LIMIT];
    unsigned file_count;
    uint64_t total;
    struct main_state *index;
    uintptr_t source_root;
    bool source_open;
    char source_path[128], parent_path[128], stage_path[128];
#ifdef ZCL_TESTING
    const struct uint256 *test_genesis;
#endif
};

static bool history_cancelled(const struct history_export *e)
{
    return e->request->cancelled && e->request->cancelled(e->request->cancel_context);
}
static bool history_leaf(const char *s)
{
    return s && s[0] && strcmp(s, ".") && strcmp(s, "..") && !strchr(s, '/');
}
static bool history_source_file(struct platform_positioned_file *file, const char *root, const char *leaf)
{
    if (!platform_positioned_file_open_beneath(file, root, leaf)) return false;
    struct stat st;
    return fstat((int)platform_positioned_file_native_fd(file), &st) == 0 &&
        S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1;
}
static bool history_capacity(const struct history_export *e, uint64_t extra)
{
    uint64_t available = 0;
    return extra <= e->request->max_bytes - e->total &&
        platform_disk_space_available(e->parent_path, &available) &&
        available >= e->request->min_free_bytes && extra <= available - e->request->min_free_bytes;
}
static bool history_copy_bytes(struct history_export *e, struct platform_positioned_file *src,
    struct platform_directory_child *file, uint64_t size)
{
    uint8_t buffer[HISTORY_COPY_BUFFER];
    for (uint64_t off = 0; off < size;) {
        size_t n = size - off < sizeof(buffer) ? (size_t)(size - off) : sizeof(buffer);
        if (history_cancelled(e) || platform_positioned_file_read(src, buffer, n, off) != (int64_t)n ||
            !platform_directory_child_write_exact(file, buffer, n, off)) return false;
        off += n;
    }
    return true;
}
static bool history_source_unchanged(struct platform_positioned_file *src,
    const struct platform_positioned_file_snapshot *before, uint64_t size, bool stable)
{
    struct platform_positioned_file_snapshot after;
    struct stat st;
    if (!platform_positioned_file_snapshot(src, &after) ||
        fstat((int)platform_positioned_file_native_fd(src), &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1) return false;
    return stable ? platform_positioned_file_snapshot_equal(before, &after) :
        before->volume == after.volume && before->file_low == after.file_low &&
        before->file_high == after.file_high && after.size >= size;
}
static bool history_copy(struct history_export *e, struct platform_positioned_file *src,
    struct platform_directory_transaction *dst, const char *leaf, uint64_t size, bool stable)
{
    struct platform_positioned_file_snapshot before;
    if (!history_capacity(e, size) || !platform_positioned_file_snapshot(src, &before) || before.size < size) {
        LOG_WARN("wallet_history_export", "source size or export capacity refused for %s", leaf);
        return false;
    }
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    if (!platform_directory_child_create(dst, leaf, &file)) return false;
    bool ok = history_copy_bytes(e, src, &file, size) && platform_directory_child_flush(&file) &&
        history_source_unchanged(src, &before, size, stable);
    platform_directory_child_close(&file);
    if (ok) e->total += size;
    return ok;
}
static bool history_open_block(struct history_export *e, unsigned index)
{
    if (index >= HISTORY_FILE_LIMIT) return false;
    if (platform_positioned_file_native_fd(&e->files[index]) != -1) return true;
    char leaf[32];
    int n = snprintf(leaf, sizeof(leaf), "blocks/blk%05u.dat", index);
    return n > 0 && (size_t)n < sizeof(leaf) &&
        history_source_file(&e->files[index], e->source_path, leaf);
}
static bool history_extent(struct history_export *e, const struct block_index *row)
{
    if (!row || row->nFile < 0 || row->nFile >= HISTORY_FILE_LIMIT || row->nDataPos < 8) return false;
    unsigned file = (unsigned)row->nFile;
    if (!history_open_block(e, file)) return false;
    uint8_t frame[8];
    if (platform_positioned_file_read(&e->files[file], frame, sizeof(frame), row->nDataPos - 8) != 8)
        return false;
    const struct chain_params *params = chain_params_get();
    if (!params || memcmp(frame, params->pchMessageStart, 4)) return false;
    uint32_t len = zcl_read_u32_le(frame + 4);
    if (!len || len > MAX_BLOCK_SIZE) return false;
    uint64_t end = (uint64_t)row->nDataPos + len;
    if (end > e->extent[file]) e->extent[file] = end;
    if (file + 1 > e->file_count) e->file_count = file + 1;
    return true;
}
static bool history_extents(struct history_export *e)
{
    struct uint256 hash;
    memcpy(hash.data, e->request->endpoint_hash, sizeof(hash.data));
    struct block_index *row = block_map_find(&e->index->map_block_index, &hash);
    for (int32_t h = e->request->endpoint_height; h >= 0; h--) {
        if (history_cancelled(e) || !row || row->nHeight != h || !history_extent(e, row)) return false;
        row = row->pprev;
    }
    for (unsigned i = 0; i < e->file_count; i++) if (!e->extent[i]) return false;
    return true;
}
static bool history_copy_blocks(struct history_export *e)
{
    for (unsigned i = 0; i < e->file_count; i++) {
        char leaf[24];
        int n = snprintf(leaf, sizeof(leaf), "blk%05u.dat", i);
        if (n < 0 || (size_t)n >= sizeof(leaf) ||
            !history_copy(e, &e->files[i], &e->blocks, leaf, e->extent[i], false)) return false;
    }
    return platform_directory_transaction_flush(&e->blocks);
}
static bool history_validate(struct history_export *e)
{
    main_state_free(e->index);
    free(e->index);
    e->index = NULL;
    struct main_state *verified = zcl_calloc(1, sizeof(*verified), "history export verified state");
    if (!verified) return false;
    main_state_init(verified);
#ifdef ZCL_TESTING
    struct zcl_result opened = e->test_genesis ?
        block_index_history_archive_test_open(verified, e->stage_path, e->request->max_rows,
            e->request->endpoint_height, e->request->endpoint_hash, e->test_genesis, NULL) :
        block_index_history_archive_open(verified, e->stage_path, e->request->max_rows,
            e->request->endpoint_height, e->request->endpoint_hash, NULL);
#else
    struct zcl_result opened = block_index_history_archive_open(verified, e->stage_path,
        e->request->max_rows, e->request->endpoint_height, e->request->endpoint_hash, NULL);
#endif
    bool ok = opened.ok;
    for (int64_t h = 0; ok && h <= e->request->endpoint_height; h++) {
        const struct block_index *row = active_chain_at(&verified->chain_active, (int)h);
        if (history_cancelled(e) || !row || !row->phashBlock) { ok = false; break; }
        struct block block;
        block_init(&block);
        struct zcl_result checked = node_db_catchup_read_authenticated_block(e->stage_path,
            row->nFile, row->nDataPos, row->phashBlock, &block);
        block_free(&block);
        ok = checked.ok;
    }
    main_state_free(verified);
    free(verified);
    return ok;
}
static void history_close(struct history_export *e)
{
    if (e->index) { main_state_free(e->index); free(e->index); }
    if (e->source_open) platform_private_directory_close(e->source_root);
    for (unsigned i = 0; i < HISTORY_FILE_LIMIT; i++) platform_positioned_file_close(&e->files[i]);
    platform_directory_transaction_close(&e->blocks);
    platform_directory_transaction_close(&e->stage);
    platform_directory_transaction_close(&e->parent);
}
static bool history_destination_outside_source(const struct history_export *e)
{
    struct stat source, current, parent;
    if (fstat((int)e->source_root, &source) != 0) return false;
    int fd = dup((int)e->parent.native);
    if (fd < 0) return false;
    bool outside = false;
    for (unsigned depth = 0; depth < 1024; depth++) {
        if (fstat(fd, &current) != 0 ||
            (current.st_dev == source.st_dev && current.st_ino == source.st_ino)) break;
        int next = openat(fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 || fstat(next, &parent) != 0) { if (next >= 0) close(next); break; }
        if (parent.st_dev == current.st_dev && parent.st_ino == current.st_ino) {
            close(next); outside = true; break;
        }
        close(fd); fd = next;
    }
    close(fd);
    return outside;
}
static bool history_setup(struct history_export *e)
{
    const struct wallet_history_export_request *r = e->request;
    if (!platform_private_directory_open_validated_traverse(r->source_datadir, &e->source_root)) return false;
    e->source_open = true;
    if (!platform_fd_path(e->source_path, sizeof(e->source_path), (int)e->source_root, ".")) return false;
    if (!platform_directory_transaction_open(&e->parent, r->private_parent) ||
        !platform_fd_path(e->parent_path, sizeof(e->parent_path), (int)e->parent.native, ".") ||
        !history_destination_outside_source(e)) return false;
    if (mkdirat((int)e->parent.native, r->staging_leaf, 0700) != 0) return false;
    if (platform_directory_transaction_open_child(&e->parent, r->staging_leaf, false, &e->stage) != PLATFORM_DIRECTORY_OK)
        return false;
    if (mkdirat((int)e->stage.native, "blocks", 0700) != 0 ||
        platform_directory_transaction_open_child(&e->stage, "blocks", false, &e->blocks) != PLATFORM_DIRECTORY_OK)
        return false;
    return platform_fd_path(e->stage_path, sizeof(e->stage_path), (int)e->stage.native, NULL);
}
static bool history_copy_index(struct history_export *e)
{
    struct platform_positioned_file index;
    platform_positioned_file_init(&index);
    bool ok = history_source_file(&index, e->source_path, "block_index.bin");
    uint64_t size = 0;
    ok = ok && platform_positioned_file_size(&index, &size) && size > 0 &&
        history_copy(e, &index, &e->stage, "block_index.bin", size, true);
    platform_positioned_file_close(&index);
    if (!ok) return false;
    e->index = zcl_calloc(1, sizeof(*e->index), "history export index state");
    if (!e->index) return false;
    main_state_init(e->index);
    return block_index_history_index_load(e->stage_path, e->index, e->request->max_rows).ok;
}
static bool history_request_valid(const struct wallet_history_export_request *r,
                                  const struct wallet_history_export_result *out)
{
    return r && out && r->source_datadir && r->source_datadir[0] && r->private_parent &&
        r->private_parent[0] && history_leaf(r->staging_leaf) && history_leaf(r->destination_leaf) &&
        strcmp(r->staging_leaf, r->destination_leaf) && r->endpoint_height >= 0 &&
        r->endpoint_height != INT_MAX && r->max_rows && r->max_bytes;
}
static bool history_prepare(struct history_export *e, struct file_manifest *manifest)
{
    return !history_cancelled(e) && history_setup(e) && history_copy_index(e) &&
        history_extents(e) && history_copy_blocks(e) && !history_cancelled(e) && history_validate(e) &&
        !history_cancelled(e) && wallet_history_manifest_build(manifest, e->stage_path, e->file_count).ok &&
        platform_directory_transaction_flush(&e->stage) && !history_cancelled(e);
}

#endif

static struct zcl_result history_run(const struct wallet_history_export_request *request,
    struct wallet_history_export_result *result, const struct uint256 *test_genesis)
{
    if (result) memset(result, 0, sizeof(*result));
#if !defined(__linux__)
    (void)request; (void)test_genesis;
    return ZCL_ERR(-1, "wallet history export is supported on Linux only");
#else
    if (!history_request_valid(request, result))
        return ZCL_ERR(-1, "wallet history export: invalid request");
    struct history_export e = {.request = request};
#ifdef ZCL_TESTING
    e.test_genesis = test_genesis;
#else
    (void)test_genesis;
#endif
    platform_directory_transaction_init(&e.parent); platform_directory_transaction_init(&e.stage);
    platform_directory_transaction_init(&e.blocks);
    for (unsigned i = 0; i < HISTORY_FILE_LIMIT; i++) platform_positioned_file_init(&e.files[i]);
    bool ok = history_prepare(&e, &result->manifest);
    enum platform_directory_result moved = PLATFORM_DIRECTORY_REFUSED;
    if (ok) moved = platform_directory_transaction_move_directory(&e.parent, request->staging_leaf,
        &e.stage, &e.parent, request->destination_leaf);
    if (moved == PLATFORM_DIRECTORY_OK) result->outcome = WALLET_HISTORY_EXPORT_PUBLISHED;
    else if (moved == PLATFORM_DIRECTORY_OUTCOME_UNKNOWN) result->outcome = WALLET_HISTORY_EXPORT_UNKNOWN;
    history_close(&e);
    if (moved == PLATFORM_DIRECTORY_OK) return ZCL_OK;
    memset(&result->manifest, 0, sizeof(result->manifest));
    return ZCL_ERR(-1, moved == PLATFORM_DIRECTORY_OUTCOME_UNKNOWN ?
        "wallet history export: publication outcome unknown" : "wallet history export: failed; staging may remain");
#endif
}

struct zcl_result wallet_history_export_run(const struct wallet_history_export_request *request,
    struct wallet_history_export_result *result)
{
    return history_run(request, result, NULL);
}
#ifdef ZCL_TESTING
struct zcl_result wallet_history_export_test_run(const struct wallet_history_export_request *request,
    struct wallet_history_export_result *result, const struct uint256 *genesis)
{
    return history_run(request, result, genesis);
}
#endif
